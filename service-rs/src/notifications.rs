//! Remontée des alertes vers un tiers (prestataire informatique, référent) : ntfy, Microsoft Teams
//! (webhook de flux de travail, carte adaptative) et e-mail (SMTP avec TLS). Les envois passent par
//! curl.exe (fourni par Windows), sur un fil dédié : les alertes arrivées en 15 s sont regroupées dans un
//! seul message ; un plafond par heure évite d'inonder le destinataire (le surplus non critique est résumé
//! sur minuterie), mais les alertes critiques passent toujours.
//! Les secrets (adresse ntfy et jeton, adresse du webhook Teams, mot de passe SMTP) sont rangés dans
//! secrets\notifications.json, lisible par SYSTEM et les administrateurs seulement ; les fichiers de
//! paramètres passés à curl (-K) y sont aussi écrits, jamais sur la ligne de commande.

use crate::commun::{self, Alerte, ConfigNotifications};
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Secrets {
    /// Adresse du sujet ntfy, par exemple https://ntfy.sh/mairie-x7k2 ou un serveur auto-hébergé
    pub ntfy_url: String,
    pub ntfy_jeton: String,
    pub teams_url: String,
    pub smtp_mot_de_passe: String,
}

/// État lisible par l'interface (sans secret)
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct Etat {
    ntfy_configure: bool,
    teams_configure: bool,
    smtp_mot_de_passe: bool,
    envoyes: u64,
    resumes: u64,
    dernier_envoi: String,
    derniere_erreur: String,
    /// Phase 4, PR 4.4b : heure du premier échec de remontée non résolu (vide sinon)
    echec_depuis: String,
    /// Alertes en attente de remontée (file de reprise, en mémoire)
    en_attente: usize,
    /// Alertes abandonnées par la file de reprise (pleine ou plus de 24 h) depuis le démarrage
    abandonnees: u64,
    /// Date locale (AAAA-MM-JJ) du dernier battement envoyé ; relue au démarrage
    dernier_battement: String,
}

/// Premier échec de remontée non résolu, en secondes (0 : aucun) ; lu par le fil « sante » (SAN-004)
static ECHEC_DEPUIS: AtomicI64 = AtomicI64::new(0);

/// Remontée en échec depuis (secondes), si elle est configurée et en échec
pub fn echec_depuis() -> Option<i64> {
    Some(ECHEC_DEPUIS.load(Ordering::Relaxed)).filter(|t| *t > 0)
}

fn secondes() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

// ------------------------------------------------------------ file de reprise (phase 4, PR 4.4b)

/// 100 alertes au plus, 24 h au plus (D4-8 : en mémoire ; un redémarrage la vide)
pub const REPRISE_MAX: usize = 100;
pub const REPRISE_DUREE_S: i64 = 86_400;
/// Essais à +1, +5, +15 et +60 min après l'échec, puis toutes les heures
pub const REPRISE_DELAIS_S: [i64; 4] = [60, 300, 900, 3600];

pub struct Reprise {
    pub alerte: Alerte,
    pub premier_echec: i64,
    pub essais: usize,
    pub prochain: i64,
}

/// File des alertes dont la remontée a échoué (décisions pures, testées)
#[derive(Default)]
pub struct FileReprise {
    pub entrees: VecDeque<Reprise>,
    pub abandonnees: u64,
}

/// Retentée après un échec : une alerte critique, ou un constat de santé (sauf SAN-004, local par nature)
pub fn a_retenter(a: &Alerte) -> bool {
    a.niveau == "Critique" || (a.regle.starts_with("SAN-") && a.regle != crate::regles::SAN_004)
}

impl FileReprise {
    /// Après de nouveaux réglages ou une relecture des secrets (pur, testé) : mêmes destinations (« Tester », niveau,
    /// plafond), la file reste ; changées, elle est vidée et ses alertes comptées abandonnées : elle ne part pas vers les
    /// nouvelles. Secrets illisibles (`None`) : la file et les destinations connues restent, la boucle ne l'envoie pas, et
    /// la comparaison se fait au retour (relecture de #100 : une lecture ratée ne perd pas la file)
    pub fn apres_reglages(&mut self, vers: &mut String, nouvelles: Option<String>) {
        let Some(nouvelles) = nouvelles else { return };
        if nouvelles != *vers {
            self.abandonnees += self.entrees.len() as u64;
            self.entrees.clear();
            *vers = nouvelles;
        }
    }

    /// Met en file les alertes à retenter d'un lot non remis, sans doublon (même Id). Pleine, la plus ancienne de la
    /// seconde moitié part : les 50 premières restent (audit de #99, S99-01 : sinon 100 alertes critiques provoquées
    /// pendant une panne chasseraient la vraie, qui est la première)
    pub fn ajouter(&mut self, lot: &[Alerte], t: i64) {
        for a in lot.iter().filter(|a| a_retenter(a)) {
            if self.entrees.iter().any(|r| r.alerte.id == a.id) {
                continue;
            }
            if self.entrees.len() >= REPRISE_MAX {
                self.entrees.remove(REPRISE_MAX / 2);
                self.abandonnees += 1;
            }
            self.entrees.push_back(Reprise { alerte: a.clone(), premier_echec: t, essais: 0, prochain: t + REPRISE_DELAIS_S[0] });
        }
    }

    /// Alertes dues à `t` ; celles en file depuis plus de 24 h sont abandonnées
    pub fn dues(&mut self, t: i64) -> Vec<Alerte> {
        let avant = self.entrees.len();
        self.entrees.retain(|r| t - r.premier_echec < REPRISE_DUREE_S);
        self.abandonnees += (avant - self.entrees.len()) as u64;
        self.entrees.iter().filter(|r| r.prochain <= t).map(|r| r.alerte.clone()).collect()
    }

    /// Résultat d'un nouvel essai : remises, elles sortent de la file ; sinon, essai suivant
    pub fn resultat(&mut self, ids: &[String], remis: bool, t: i64) {
        if remis {
            self.entrees.retain(|r| !ids.contains(&r.alerte.id));
            return;
        }
        for r in self.entrees.iter_mut().filter(|r| ids.contains(&r.alerte.id)) {
            r.essais += 1;
            r.prochain = t + REPRISE_DELAIS_S.get(r.essais).copied().unwrap_or(3600);
        }
    }
}

// ------------------------------------------------------------ battement quotidien (phase 4, PR 4.4b, D4-6)

/// Compteurs du battement, publiés par le fil « sante » : incidents non clos, collectes actives et indisponibles, et
/// identifiants des collectes critiques indisponibles (aucun nom de compte, de programme ni de ligne de commande)
#[derive(Clone, Default)]
pub struct Compteurs {
    pub incidents_non_clos: usize,
    pub collectes_actives: usize,
    pub collectes_indisponibles: usize,
    pub critiques_indisponibles: Vec<&'static str>,
}

static COMPTEURS: Mutex<Option<Compteurs>> = Mutex::new(None);

pub fn publier_compteurs(c: Compteurs) {
    *COMPTEURS.lock().unwrap_or_else(|e| e.into_inner()) = Some(c);
}

/// Battement dû (pur, testé) : une fois par jour, à partir de 09:00 locale ; `maintenant` au format de
/// `commun::maintenant` (« AAAA-MM-JJ HH:MM:SS »)
pub fn battement_du(dernier: &str, maintenant: &str) -> bool {
    let (Some(date), Some(heure)) = (maintenant.get(..10), maintenant.get(11..13).and_then(|h| h.parse::<u32>().ok())) else { return false };
    heure >= 9 && dernier != date
}

/// Texte du battement (pur, testé) : compteurs seulement
pub fn texte_battement(c: &Compteurs, en_attente: usize) -> String {
    let critiques = if c.critiques_indisponibles.is_empty() { String::new() } else { format!(" (critiques : {})", c.critiques_indisponibles.join(", ")) };
    format!("deR4Tizer actif : {} incident(s) non clos ; collectes : {} active(s), {} indisponible(s){critiques} ; {en_attente} alerte(s) en attente de remontée.",
        c.incidents_non_clos, c.collectes_actives, c.collectes_indisponibles)
}

enum Message {
    Alerte(Alerte),
    /// Réveil seulement : les réglages attendent dans `DERNIERS_REGLAGES` (audit de #100, S100-05)
    Reglages,
}

/// Derniers réglages demandés : une case écrasée, jamais perdue, même si la file des messages est pleine
#[derive(Default)]
pub struct CaseReglages(Mutex<Option<ConfigNotifications>>);

impl CaseReglages {
    pub const fn nouvelle() -> Self {
        CaseReglages(Mutex::new(None))
    }

    pub fn poser(&self, c: ConfigNotifications) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Some(c);
    }

    pub fn prendre(&self) -> Option<ConfigNotifications> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).take()
    }
}

static DERNIERS_REGLAGES: CaseReglages = CaseReglages::nouvelle();

static FILE: OnceLock<Mutex<SyncSender<Message>>> = OnceLock::new();

fn dossier_secrets() -> PathBuf {
    commun::dossier().join("secrets")
}

/// Dossier des secrets : SYSTEM et administrateurs seulement, sans héritage des droits de lecture accordés
/// aux comptes autorisés sur le dossier de données. Créé avec ses droits ; s'il existe avec d'autres droits,
/// ils sont réimposés puis relus. Erreur si les droits ne sont pas vérifiés : rien n'y est alors écrit.
const SDDL_SECRETS: &str = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

pub fn preparer_dossier() -> Result<(), String> {
    use crate::protection::{verifier, SID_ADMINISTRATEURS, SID_SYSTEME};
    let d = dossier_secrets();
    if !d.exists() && !crate::natif::creer_dossier_protege(&d, SDDL_SECRETS) {
        return Err("dossier des secrets impossible à créer avec ses droits".into());
    }
    // En mode console (tests), le propriétaire est l'utilisateur : pas de contrôle
    if !crate::natif::est_systeme() {
        return Ok(());
    }
    let complets = [SID_SYSTEME, SID_ADMINISTRATEURS];
    if verifier(&d, &complets, &[]).is_ok() {
        return Ok(());
    }
    crate::natif::poser_droits(&d, SDDL_SECRETS).map_err(|e| format!("droits du dossier des secrets refusés ({e})"))?;
    // Contenu : droits hérités (code d'icacls /C non probant ; la preuve est la relecture du dossier)
    crate::protection::icacls(&[&format!(r"{}\*", d.display()), "/reset", "/T", "/C", "/Q"]);
    verifier(&d, &complets, &[])
}

/// Secrets lus ; fichier absent : aucun secret ; illisible ou mal formé : `None` (audit de #100, S100-06)
fn lire_secrets_verifie() -> Option<Secrets> {
    let f = dossier_secrets().join("notifications.json");
    match fs::symlink_metadata(&f) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Some(Secrets::default()),
        Err(_) => return None,
        Ok(_) => {}
    }
    commun::lire_fichier(&f).and_then(|t| serde_json::from_str(&t).ok())
}

pub fn lire_secrets() -> Secrets {
    commun::lire_fichier(&dossier_secrets().join("notifications.json"))
        .and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

/// Contrôle d'une demande « notifications » ou « testerNotifications » avant lecture (décision pure, testée) : texte
/// illisible ou clé ambiguë par la casse refusés (AUD6-03, S58-01). Clés connues : « Config » et les secrets, à plat.
pub fn controler_demande(texte: &str) -> Result<(), String> {
    let mut modele = serde_json::to_value(Secrets::default()).unwrap_or_default();
    if let Some(o) = modele.as_object_mut() {
        o.insert("Config".into(), serde_json::to_value(crate::commun::ConfigNotifications::default()).unwrap_or_default());
    }
    match crate::commun::cle_ambigue(texte, &modele) {
        Some(k) => Err(crate::commun::raison_refus("réglages des notifications refusés", &k)),
        None => Ok(()),
    }
}

/// https://hôte[:port][/chemin] : hôte en lettres, chiffres, « . » et « - », port numérique
pub fn adresse_https_simple(u: &str) -> bool {
    let Some(reste) = u.strip_prefix("https://") else { return false };
    let autorite = reste.split(['/', '?', '#']).next().unwrap_or("");
    let (hote, port) = match autorite.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (autorite, None),
    };
    !hote.is_empty() && hote.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && port.is_none_or(|p| !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Raison de refuser un champ texte rempli pour cacher une partie de la confirmation : espace autre que l'espace
/// simple (insécable, idéographique, de largeur fixe…), plus de deux espaces à la suite, longueur au-delà de `max`
/// octets
pub fn remplissage(v: &str, max: usize) -> Option<String> {
    if v.len() > max {
        return Some(format!("trop long ({} caractères au plus)", max));
    }
    if v.chars().any(|c| c.is_whitespace() && c != ' ') || ['\u{115F}', '\u{1160}', '\u{3164}', '\u{FFA0}'].iter().any(|c| v.contains(*c)) {
        return Some("seulement des espaces simples".into());
    }
    if v.contains("   ") {
        return Some("trop d'espaces à la suite".into());
    }
    None
}

/// Caractère de contrôle (Cc) ou de mise en forme invisible (principaux Cf : sens d'écriture, largeur nulle, BOM)
pub fn caractere_interdit(c: char) -> bool {
    c.is_control() || matches!(c, '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206F}' | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}')
}

/// Avant d'enregistrer de nouveaux réglages de remontée (décision pure, audit AUD6-02 et AUD3-07) :
/// - aucun caractère de contrôle ni de mise en forme invisible dans les champs du courriel (sinon ajout d'en-têtes ou
///   de destinataires, ou adresse affichée à l'envers dans la confirmation : U+202E…) ;
/// - serveur, port, compte ou sécurité SMTP changé sans nouveau mot de passe : l'ancien est effacé, jamais envoyé au nouveau
///   serveur ; de même, jeton ntfy effacé si l'adresse ntfy change sans nouveau jeton.
pub fn preparer(actuelle: &ConfigNotifications, nouvelle: &ConfigNotifications, actuels: &Secrets, s: &mut Secrets) -> Result<(), String> {
    for (nom, v) in [("serveur SMTP", &nouvelle.smtp_serveur), ("compte SMTP", &nouvelle.smtp_utilisateur), ("expéditeur", &nouvelle.expediteur),
                     ("destinataires", &nouvelle.destinataires), ("sécurité SMTP", &nouvelle.smtp_securite), ("niveau", &nouvelle.niveau_min)] {
        if v.chars().any(caractere_interdit) {
            return Err(format!("{nom} : caractère de contrôle ou de mise en forme refusé"));
        }
        // Remplissage (audit de sécurité S58-05) : la confirmation montrait l'adresse légitime suivie de blanc et
        // repoussait hors de l'écran une adresse ajoutée. Espace simple seulement, jamais plus de deux à la suite,
        // longueur bornée
        if let Some(r) = remplissage(v, if nom == "destinataires" { 1000 } else { 254 }) {
            return Err(format!("{nom} : {r}"));
        }
        // ASCII imprimable seulement (S60-02) : les champs SMTP n'en demandent pas plus, et un caractère blanc qui n'est
        // pas une espace (U+2800, signes combinants, étiquettes) cachait une adresse ajoutée
        if !v.bytes().all(|b| b == b' ' || b.is_ascii_graphic()) {
            return Err(format!("{nom} : seulement des caractères ASCII"));
        }
    }
    // Destinataires (S60-01) : 10 au plus, chacun une adresse, sans doublon ; une suite collée sans espace cachait une
    // adresse ajoutée au bout d'une ligne trop large pour l'écran
    let liste: Vec<&str> = nouvelle.destinataires.split([',', ';', ' ']).filter(|d| !d.is_empty()).collect();
    if liste.len() > 10 {
        return Err("destinataires : 10 au plus".into());
    }
    if liste.iter().any(|d| !d.contains('@')) {
        return Err("destinataires : seulement des adresses de courriel".into());
    }
    let mut vues = std::collections::HashSet::new();
    if !liste.iter().all(|d| vues.insert(d.to_ascii_lowercase())) {
        return Err("destinataires : adresse en double".into());
    }
    // Adresses ntfy et Teams : ASCII imprimable seulement (homoglyphes, caractères invisibles : audit de sécurité, C1)
    for (nom, v) in [("adresse ntfy", &s.ntfy_url), ("adresse Teams", &s.teams_url)] {
        if v.chars().any(|c| !c.is_ascii_graphic()) {
            return Err(format!("{nom} : seulement des caractères ASCII visibles"));
        }
        // Longueur bornée : une adresse démesurée remplissait la confirmation et cachait ce qui la suivait (relecture
        // de #60)
        if v.len() > 600 {
            return Err(format!("{nom} : 600 caractères au plus"));
        }
        // Forme https://hôte[:port]/chemin : ni compte (« @ »), ni barre oblique inverse, ni autre caractère dans l'hôte.
        // Une adresse que l'interface ne sait pas lire s'affichait « ? » à la confirmation, et curl pouvait y voir un
        // autre hôte (relecture de #55)
        let v = v.trim();
        if !v.is_empty() && v != "-" && !adresse_https_simple(v) {
            return Err(format!("{nom} : adresse attendue de la forme https://hôte/chemin"));
        }
    }
    let compte_change = nouvelle.smtp_serveur.trim() != actuelle.smtp_serveur.trim() || nouvelle.smtp_port != actuelle.smtp_port
        || nouvelle.smtp_utilisateur.trim() != actuelle.smtp_utilisateur.trim()
        // Sécurité changée (TLS vers « aucune ») : le mot de passe partirait en clair (relecture de #52)
        || nouvelle.smtp_securite.trim() != actuelle.smtp_securite.trim();
    if compte_change && s.smtp_mot_de_passe.trim().is_empty() {
        s.smtp_mot_de_passe = "-".into();
    }
    let ntfy = s.ntfy_url.trim();
    if !ntfy.is_empty() && ntfy != "-" && ntfy != actuels.ntfy_url.trim() && s.ntfy_jeton.trim().is_empty() {
        s.ntfy_jeton = "-".into();
    }
    Ok(())
}

pub fn enregistrer_secrets(n: &Secrets) -> Result<(), String> {
    preparer_dossier()?;
    // Illisibles : refus, sinon les secrets absents de la demande seraient perdus (audit de #100, S100-16)
    let mut s = lire_secrets_verifie().ok_or("secrets illisibles : réglages non enregistrés")?;
    let maj = |ancien: &mut String, nouveau: &str| match nouveau.trim() {
        "" => {}
        "-" => ancien.clear(),
        v => *ancien = v.to_string(),
    };
    maj(&mut s.ntfy_url, &n.ntfy_url);
    maj(&mut s.ntfy_jeton, &n.ntfy_jeton);
    maj(&mut s.teams_url, &n.teams_url);
    maj(&mut s.smtp_mot_de_passe, &n.smtp_mot_de_passe);
    crate::natif::ecrire_fichier_protege(&dossier_secrets().join("notifications.json"),
        serde_json::to_string(&s).unwrap_or_default().as_bytes(), "D:P(A;;FA;;;SY)(A;;FA;;;BA)")
}

pub fn demarrer(config: &ConfigNotifications) {
    if let Err(e) = preparer_dossier() {
        commun::journal(&format!("remontée des alertes : {e}"));
    }
    let (tx, rx) = sync_channel(5000);
    if FILE.set(Mutex::new(tx)).is_err() {
        return configurer(config);
    }
    let config = config.clone();
    std::thread::Builder::new().name("notifications".into()).spawn(move || boucle(config, rx)).unwrap();
}

pub fn configurer(config: &ConfigNotifications) {
    DERNIERS_REGLAGES.poser(config.clone());
    if let Some(f) = FILE.get() {
        // File pleine : le réveil se perd, pas les réglages (la boucle regarde la case à chaque tour)
        let _ = f.lock().unwrap().try_send(Message::Reglages);
    }
}

pub fn alerte(a: &Alerte) {
    if let Some(f) = FILE.get() {
        let _ = f.lock().unwrap().try_send(Message::Alerte(a.clone()));
    }
}

fn actif(c: &ConfigNotifications) -> bool {
    c.ntfy || c.teams || c.smtp
}

fn boucle(mut config: ConfigNotifications, rx: Receiver<Message>) {
    // Dernier battement relu (propriétaire contrôlé) : pas un battement de plus à chaque redémarrage
    let mut etat = Etat { dernier_battement: commun::lire::<Etat>("notifications.json").map(|e| e.dernier_battement).unwrap_or_default(), ..Default::default() };
    let mut fenetre = Instant::now();
    let mut envois_heure = 0u32;
    let mut retenues = 0usize;
    let mut reprise = FileReprise::default();
    // Couple (réglages, secrets) de la boucle, remplacé d'un seul coup (audit de #100, S100-04) : jamais d'anciens réglages
    // avec de nouveaux secrets, qui enverraient un nouveau mot de passe à l'ancien serveur
    let mut secrets = Secrets::default();
    let mut vers = String::new();
    let depart = config.clone();
    let mut secrets_illisibles = nouveaux_reglages(&mut config, depart, &mut secrets, &mut reprise, &mut etat, &mut vers);
    ecrire_etat(&mut etat);
    loop {
        // Réglages en attente, avant tout envoi ; secrets illisibles (protection en échec au démarrage) : relus à chaque tour
        secrets_illisibles = si_reglages(&mut config, &mut secrets, &mut reprise, &mut etat, &mut vers, secrets_illisibles);
        // File de reprise : les alertes dues partent en un lot ; battement quotidien (D4-6), hors plafond et hors niveau
        // minimal. La boucle passe ici au moins une fois par minute (attente de 60 s au plus)
        if actif(&config) {
            let t = secondes();
            let dues = reprise.dues(t);
            // Secrets illisibles : la file attend (la purge des 24 h continue). Un serveur SMTP sans compte n'a pas besoin de
            // secret : sinon la file partirait vers de nouvelles destinations avant la comparaison (audit de #100, S100-13)
            if !dues.is_empty() && !secrets_illisibles {
                let ids: Vec<String> = dues.iter().map(|a| a.id.clone()).collect();
                let remis = envoyer_partout(&config, &secrets, &dues, &mut etat);
                reprise.resultat(&ids, remis, t);
            }
            let maintenant = commun::maintenant();
            if battement_du(&etat.dernier_battement, &maintenant) {
                etat.dernier_battement = maintenant.chars().take(10).collect();
                let compteurs = COMPTEURS.lock().unwrap_or_else(|e| e.into_inner()).clone().unwrap_or_default();
                let battement = Alerte {
                    niveau: "Info".into(),
                    heure: maintenant,
                    processus: "deR4Tizer".into(),
                    destination: "battement quotidien".into(),
                    raisons: texte_battement(&compteurs, reprise.entrees.len()),
                    ..Default::default()
                };
                envoyer_partout(&config, &secrets, &[battement], &mut etat);
            }
        }
        if etat.en_attente != reprise.entrees.len() || etat.abandonnees != reprise.abandonnees {
            etat.en_attente = reprise.entrees.len();
            etat.abandonnees = reprise.abandonnees;
            ecrire_etat(&mut etat);
        }
        // Résumé du surplus retenu, envoyé sur minuterie (même si aucune nouvelle alerte n'arrive)
        if fenetre.elapsed() > Duration::from_secs(3600) {
            fenetre = Instant::now();
            envois_heure = 0;
            if retenues > 0 {
                let resume = Alerte {
                    niveau: "Alerte".into(),
                    heure: commun::maintenant(),
                    processus: "deR4Tizer".into(),
                    destination: "résumé".into(),
                    raisons: format!("{retenues} autre(s) alerte(s) non critique(s) n'ont pas été envoyées pour ne pas vous inonder (plafond de {} message(s) par heure). Détail dans l'interface de deR4Tizer, page Alertes.", config.max_par_heure),
                    ..Default::default()
                };
                retenues = 0;
                etat.resumes += 1;
                envoyer_partout(&config, &secrets, &[resume], &mut etat);
            }
        }
        // Attente de la première alerte (une minute au plus, pour la minuterie du résumé)
        let premiere = match rx.recv_timeout(Duration::from_secs(60)) {
            // La case est lue en tête de boucle
            Ok(Message::Reglages) => continue,
            // SAN-004 (remontée en échec) : constat local, jamais remonté
            Ok(Message::Alerte(a)) if a.regle == crate::regles::SAN_004 => continue,
            Ok(Message::Alerte(a)) => a,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => return,
        };
        if !actif(&config) || crate::export::rang(&premiere.niveau) < crate::export::rang(&config.niveau_min) {
            continue;
        }
        // Regroupement des alertes des 15 secondes suivantes
        let mut lot = vec![premiere];
        let limite = Instant::now() + Duration::from_secs(15);
        loop {
            let reste = limite.saturating_duration_since(Instant::now());
            match rx.recv_timeout(reste) {
                Ok(Message::Alerte(a)) if a.regle != crate::regles::SAN_004 && crate::export::rang(&a.niveau) >= crate::export::rang(&config.niveau_min) => lot.push(a),
                Ok(Message::Alerte(_)) => {}
                // Même traitement qu'en tête de boucle (audit de #99, S99-04)
                Ok(Message::Reglages) => secrets_illisibles = si_reglages(&mut config, &mut secrets, &mut reprise, &mut etat, &mut vers, secrets_illisibles),
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) => return,
            }
        }
        // Réveil perdu (file pleine) : la case est relue avant d'envoyer. Remontée coupée pendant le regroupement : le lot
        // n'est pas envoyé (il reste dans alertes.json). Destinations changées : il part vers les nouvelles (alertes récentes)
        secrets_illisibles = si_reglages(&mut config, &mut secrets, &mut reprise, &mut etat, &mut vers, secrets_illisibles);
        if !actif(&config) {
            continue;
        }
        // Les critiques partent toujours : un attaquant ne doit pas pouvoir noyer la vraie alerte sous des
        // alertes provoquées ; seules les autres comptent dans le plafond par heure
        let (a_envoyer, n_retenues, compte) = repartir(lot, envois_heure, config.max_par_heure);
        retenues += n_retenues;
        if compte {
            envois_heure += 1;
        }
        if !a_envoyer.is_empty() && !envoyer_partout(&config, &secrets, &a_envoyer, &mut etat) {
            reprise.ajouter(&a_envoyer, secondes());
        }
    }
}

/// Destinations de la remontée (pur, testé) : canaux activés et leur adresse, en mémoire seulement, jamais écrites ni
/// journalisées (l'adresse ntfy ou Teams est un secret). Ni le niveau, ni le plafond, ni les jetons et mots de passe
/// n'en font partie : ils ne changent pas qui reçoit. La sécurité et le compte SMTP en font partie : passer de TLS à
/// sans TLS change ce qui protège la file
pub fn destinations(c: &ConfigNotifications, s: &Secrets) -> String {
    let mut d = Vec::new();
    if c.ntfy {
        d.push(format!("ntfy={}", s.ntfy_url));
    }
    if c.teams {
        d.push(format!("teams={}", s.teams_url));
    }
    if c.smtp {
        d.push(format!("smtp={}:{}|{}|{}|{}|{}", c.smtp_serveur, c.smtp_port, c.smtp_securite, c.smtp_utilisateur, c.expediteur, c.destinataires));
    }
    d.join("\n")
}

/// Nouveaux réglages de la remontée, en tête de boucle comme pendant le regroupement d'un lot (audit de #99, S99-03 et
/// S99-04) : destinations changées, la file n'est pas envoyée vers les nouvelles, ses alertes sont comptées abandonnées
/// et restent dans alertes.json ; remontée coupée, plus d'échec à signaler (SAN-004)
fn nouveaux_reglages(config: &mut ConfigNotifications, c: ConfigNotifications, secrets: &mut Secrets, reprise: &mut FileReprise, etat: &mut Etat, vers: &mut String) -> bool {
    *config = c;
    let lus = lire_secrets_verifie();
    reprise.apres_reglages(vers, lus.as_ref().map(|s| destinations(config, s)));
    let illisibles = lus.is_none();
    // Illisibles : aucun secret plutôt que les anciens (ntfy et Teams ne partent plus ; un serveur SMTP sans compte reste
    // joignable, sans mot de passe)
    *secrets = lus.unwrap_or_default();
    if !actif(config) {
        etat.echec_depuis.clear();
        ECHEC_DEPUIS.store(0, Ordering::Relaxed);
    }
    ecrire_etat(etat);
    illisibles
}

/// Secrets à recharger hors de tout réglage (pur, testé) : redevenus lisibles, ou retirés du fichier alors qu'ils servent
/// encore (audit de #100, S100-07 : supprimer le fichier coupe la remontée, comme quand il était relu à chaque envoi). Une
/// simple modification à la main n'est pas adoptée : elle attend le prochain réglage ou le redémarrage
pub fn secrets_a_recharger(illisibles: bool, memoire: &Secrets, lus: Option<&Secrets>) -> bool {
    let retire = |m: &str, f: &str| !m.is_empty() && f.is_empty();
    match lus {
        None => !illisibles,
        Some(_) if illisibles => true,
        Some(l) => retire(&memoire.ntfy_url, &l.ntfy_url) || retire(&memoire.teams_url, &l.teams_url) || retire(&memoire.smtp_mot_de_passe, &l.smtp_mot_de_passe) || retire(&memoire.ntfy_jeton, &l.ntfy_jeton),
    }
}

/// Applique les réglages en attente ; sinon recharge les secrets s'il le faut. Tant qu'ils restent illisibles, rien n'est
/// réécrit. Rend si les secrets sont illisibles
fn si_reglages(config: &mut ConfigNotifications, secrets: &mut Secrets, reprise: &mut FileReprise, etat: &mut Etat, vers: &mut String, illisibles: bool) -> bool {
    if let Some(c) = DERNIERS_REGLAGES.prendre() {
        return nouveaux_reglages(config, c, secrets, reprise, etat, vers);
    }
    if !secrets_a_recharger(illisibles, secrets, lire_secrets_verifie().as_ref()) {
        return illisibles;
    }
    let c = config.clone();
    nouveaux_reglages(config, c, secrets, reprise, etat, vers)
}

/// Les critiques partent toujours ; les autres seulement sous le plafond horaire.
/// Renvoie (à envoyer, nombre retenu, l'envoi compte dans le plafond)
pub fn repartir(lot: Vec<Alerte>, envois_heure: u32, max_par_heure: u32) -> (Vec<Alerte>, usize, bool) {
    let (mut a_envoyer, autres): (Vec<Alerte>, Vec<Alerte>) = lot.into_iter().partition(|a| a.niveau == "Critique");
    if autres.is_empty() {
        return (a_envoyer, 0, false);
    }
    if envois_heure < max_par_heure.max(1) {
        a_envoyer.extend(autres);
        (a_envoyer, 0, true)
    } else {
        let n = autres.len();
        (a_envoyer, n, false)
    }
}

/// Secrets utilisés pour un envoi (pur, testé) : aucun si la protection du dossier de données est en échec, comme quand
/// ils étaient relus à chaque envoi (l'alerte reste locale)
pub fn secrets_pour_envoi(echec_protection: bool, s: &Secrets) -> Secrets {
    if echec_protection { Secrets::default() } else { s.clone() }
}

/// Envoie un lot sur les canaux configurés, avec le couple (réglages, secrets) de la boucle ; remis si au moins un canal
/// tenté a réussi (pur, testé : `remis`). Un lot remis sur un seul canal n'est pas retenté : il y arriverait en double
fn envoyer_partout(config: &ConfigNotifications, secrets: &Secrets, lot: &[Alerte], etat: &mut Etat) -> bool {
    let s = secrets_pour_envoi(commun::echec_protection().is_some(), secrets);
    let mut erreurs = Vec::new();
    let mut tentes = 0;
    if config.ntfy && !s.ntfy_url.is_empty() {
        tentes += 1;
        if let Err(e) = ntfy(&s, lot) { erreurs.push(format!("ntfy : {e}")); }
    }
    if config.teams && !s.teams_url.is_empty() {
        tentes += 1;
        if let Err(e) = teams(&s, lot) { erreurs.push(format!("Teams : {e}")); }
    }
    if config.smtp && !config.smtp_serveur.is_empty() {
        tentes += 1;
        if let Err(e) = courriel(config, &s, lot) { erreurs.push(format!("e-mail : {e}")); }
    }
    if tentes == 0 {
        erreurs.push("aucun canal utilisable (adresse, secret ou serveur absent)".to_string());
    }
    let ok = remis(tentes, erreurs.len().min(tentes));
    etat.envoyes += 1;
    etat.dernier_envoi = commun::maintenant();
    etat.derniere_erreur = erreurs.join(" ; ");
    if !erreurs.is_empty() {
        commun::journal(&format!("notifications : {}", etat.derniere_erreur));
    }
    if ok {
        etat.echec_depuis.clear();
        ECHEC_DEPUIS.store(0, Ordering::Relaxed);
    } else if etat.echec_depuis.is_empty() {
        etat.echec_depuis = commun::maintenant();
        ECHEC_DEPUIS.store(secondes(), Ordering::Relaxed);
    }
    ecrire_etat(etat);
    ok
}

/// Lot remis : au moins un canal tenté, et au moins un a réussi (pur, testé)
pub fn remis(tentes: usize, erreurs: usize) -> bool {
    tentes > 0 && erreurs < tentes
}

fn ecrire_etat(etat: &mut Etat) {
    let s = lire_secrets();
    etat.ntfy_configure = !s.ntfy_url.is_empty();
    etat.teams_configure = !s.teams_url.is_empty();
    etat.smtp_mot_de_passe = !s.smtp_mot_de_passe.is_empty();
    let _ = commun::ecrire("notifications.json", etat);
}

/// Envoi immédiat d'un message de test sur les canaux activés ; renvoie le compte rendu
pub fn tester(config: &ConfigNotifications) -> Result<String, String> {
    if !actif(config) {
        return Err("aucun canal activé".into());
    }
    let test = Alerte {
        niveau: "Info".into(),
        heure: commun::maintenant(),
        processus: "deR4Tizer".into(),
        destination: "test".into(),
        raisons: "Message de test : les alertes de ce poste vous parviendront par ce canal.".into(),
        conseil: "Rien à faire.".into(),
        ..Default::default()
    };
    let s = lire_secrets();
    let mut ok = Vec::new();
    let mut erreurs = Vec::new();
    let mut essai = |nom: &str, r: Result<(), String>| match r {
        Ok(()) => ok.push(nom.to_string()),
        Err(e) => erreurs.push(format!("{nom} : {e}")),
    };
    if config.ntfy { essai("ntfy", if s.ntfy_url.is_empty() { Err("adresse du sujet non renseignée".into()) } else { ntfy(&s, &[test.clone()]) }); }
    if config.teams { essai("Teams", if s.teams_url.is_empty() { Err("adresse du webhook non renseignée".into()) } else { teams(&s, &[test.clone()]) }); }
    if config.smtp { essai("e-mail", courriel(config, &s, &[test.clone()])); }
    if erreurs.is_empty() { Ok(format!("Message de test envoyé : {}.", ok.join(", "))) } else { Err(format!("{}{}", erreurs.join(" ; "), if ok.is_empty() { String::new() } else { format!(" (réussi : {})", ok.join(", ")) })) }
}

// ------------------------------------------------------------ mise en forme

fn hote() -> String {
    crate::export::hote_local()
}

/// Groupe d'alertes de même nature dans un lot (même niveau, programme, technique et destination aux chiffres
/// près) : 300 « serveur DHCP 192.168.1.x » usurpés deviennent une ligne, et l'alerte unique reste visible
pub struct Groupe<'a> {
    pub alerte: &'a Alerte,
    pub nombre: usize,
    pub exemples: Vec<String>,
}

fn nature(a: &Alerte) -> String {
    // Chaque suite de chiffres devient « # » : 192.168.0.5 et 192.168.0.55 sont de même nature
    let mut destination = String::new();
    for c in a.destination.chars() {
        if c.is_ascii_digit() {
            if !destination.ends_with('#') {
                destination.push('#');
            }
        } else {
            destination.push(c);
        }
    }
    format!("{}|{}|{}|{}", a.niveau, a.processus, a.mitre, destination)
}

/// Groupes du lot : d'abord les alertes uniques (souvent la vraie), puis par gravité et score décroissants
pub fn regrouper(lot: &[Alerte]) -> Vec<Groupe<'_>> {
    let mut groupes: Vec<Groupe> = Vec::new();
    let mut index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for a in lot {
        let cle = nature(a);
        match index.get(&cle) {
            Some(&i) => {
                let g = &mut groupes[i];
                g.nombre += 1;
                if a.score > g.alerte.score {
                    g.alerte = a;
                }
                if g.exemples.len() < 3 && !a.destination.is_empty() {
                    g.exemples.push(a.destination.clone());
                }
            }
            None => {
                index.insert(cle, groupes.len());
                groupes.push(Groupe { alerte: a, nombre: 1, exemples: if a.destination.is_empty() { vec![] } else { vec![a.destination.clone()] } });
            }
        }
    }
    // Second niveau : des destinations textuelles toutes différentes (300 domaines listés) ne doivent pas
    // remplir le message de 300 groupes « uniques »
    let cle2 = |a: &Alerte| format!("{}|{}|{}", a.niveau, a.processus, a.mitre);
    let mut compte: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for g in &groupes {
        *compte.entry(cle2(g.alerte)).or_default() += 1;
    }
    let mut fusionnes: Vec<Groupe> = Vec::new();
    let mut index2: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for g in groupes {
        let k = cle2(g.alerte);
        if compte[&k] <= 5 {
            fusionnes.push(g);
            continue;
        }
        match index2.get(&k) {
            Some(&i) => {
                let f = &mut fusionnes[i];
                f.nombre += g.nombre;
                if g.alerte.score > f.alerte.score {
                    f.alerte = g.alerte;
                }
                for e in g.exemples {
                    if f.exemples.len() < 3 {
                        f.exemples.push(e);
                    }
                }
            }
            None => {
                index2.insert(k, fusionnes.len());
                fusionnes.push(Groupe { nombre: g.nombre.max(2), ..g });
            }
        }
    }
    let mut groupes = fusionnes;
    groupes.sort_by(|a, b| (a.nombre > 1).cmp(&(b.nombre > 1))
        .then(crate::export::rang(&b.alerte.niveau).cmp(&crate::export::rang(&a.alerte.niveau)))
        .then(b.alerte.score.cmp(&a.alerte.score)));
    groupes
}

fn titre(lot: &[Alerte]) -> String {
    let pire = lot.iter().max_by_key(|a| crate::export::rang(&a.niveau)).map(|a| a.niveau.clone()).unwrap_or_default();
    if lot.len() == 1 {
        format!("deR4Tizer · {} sur {} : {}", lot[0].niveau, hote(), if lot[0].destination.is_empty() { &lot[0].processus } else { &lot[0].destination })
    } else {
        format!("deR4Tizer · {} alertes sur {} (la plus grave : {pire})", lot.len(), hote())
    }
}

fn entete_groupe(g: &Groupe) -> String {
    if g.nombre == 1 {
        format!("[{}] {} — {}", g.alerte.niveau, g.alerte.heure, g.alerte.raisons)
    } else {
        format!("[{}] {} × {} ({}…) — {}", g.alerte.niveau, g.nombre, nature_lisible(g.alerte), g.exemples.join(", "), g.alerte.raisons)
    }
}

fn nature_lisible(a: &Alerte) -> String {
    let d: String = a.destination.split(|c: char| c.is_ascii_digit()).next().unwrap_or("").trim().to_string();
    if d.is_empty() { a.processus.clone() } else { d }
}

pub fn texte(lot: &[Alerte]) -> String {
    let groupes = regrouper(lot);
    groupes.iter().take(10).map(|g| {
        let a = g.alerte;
        let mut l = entete_groupe(g);
        if !a.processus.is_empty() {
            l.push_str(&format!("\nProgramme : {}", a.processus));
        }
        if !a.mitre.is_empty() {
            l.push_str(&format!("\nTechnique : {}", a.mitre));
        }
        if !a.conseil.is_empty() {
            l.push_str(&format!("\nQue faire : {}", a.conseil));
        }
        l
    }).collect::<Vec<_>>().join("\n\n")
        + &if groupes.len() > 10 { format!("\n\n… et {} autre(s) type(s) d'alerte, voir l'interface de deR4Tizer.", groupes.len() - 10) } else { String::new() }
}

// ------------------------------------------------------------ envoi (curl)

/// Valeur entre guillemets pour un fichier de paramètres curl (-K)
fn cite(v: &str) -> String {
    format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\"").replace(['\r', '\n'], " "))
}

/// Lance curl avec un fichier de paramètres et un corps écrits dans le dossier des secrets, puis les efface
fn curl(parametres: &str, corps: &[u8]) -> Result<(), String> {
    // Les paramètres contiennent jetons et mots de passe : jamais dans un dossier aux droits non vérifiés
    preparer_dossier()?;
    let d = dossier_secrets();
    let n = commun::nouvel_id();
    let (f_param, f_corps) = (d.join(format!("curl-{n}.txt")), d.join(format!("corps-{n}.bin")));
    let r = (|| {
        fs::write(&f_corps, corps).map_err(|e| e.to_string())?;
        fs::write(&f_param, format!("{parametres}\nsilent\nshow-error\nfail\nmax-time = 30\nproto = \"=https,smtps,smtp\"\n")).map_err(|e| e.to_string())?;
        // -q en premier : aucun fichier de réglages de curl lu (.curlrc), seulement le nôtre (-K)
        let sortie = Command::new(crate::natif::curl_exe())
            .arg("-q").arg("-K").arg(&f_param)
            .arg("--data-binary").arg(format!("@{}", f_corps.display()))
            .creation_flags(0x0800_0000)
            .output()
            .map_err(|e| e.to_string())?;
        if sortie.status.success() { Ok(()) } else { Err(String::from_utf8_lossy(&sortie.stderr).trim().chars().take(300).collect()) }
    })();
    let _ = fs::remove_file(&f_param);
    let _ = fs::remove_file(&f_corps);
    r
}

fn ntfy(s: &Secrets, lot: &[Alerte]) -> Result<(), String> {
    // Publication en JSON (https://serveur, {"topic": …}) : titre et texte en UTF-8 sans encodage d'en-tête
    let url = s.ntfy_url.trim().trim_end_matches('/');
    let (serveur, sujet) = url.rsplit_once('/').ok_or("adresse ntfy invalide (attendu : https://serveur/sujet)")?;
    if !serveur.starts_with("https://") {
        return Err("l'adresse ntfy doit commencer par https://".into());
    }
    let pire = lot.iter().map(|a| crate::export::rang(&a.niveau)).max().unwrap_or(0);
    let corps = serde_json::json!({
        "topic": sujet,
        "title": titre(lot),
        "message": texte(lot),
        "priority": match pire { 2 => 5, 1 => 4, _ => 3 },
        "tags": [match pire { 2 => "rotating_light", 1 => "warning", _ => "information_source" }],
    });
    let mut p = format!("url = {}\nheader = \"Content-Type: application/json\"", cite(serveur));
    if !s.ntfy_jeton.is_empty() {
        p.push_str(&format!("\nheader = {}", cite(&format!("Authorization: Bearer {}", s.ntfy_jeton))));
    }
    curl(&p, corps.to_string().as_bytes())
}

fn teams(s: &Secrets, lot: &[Alerte]) -> Result<(), String> {
    if !s.teams_url.starts_with("https://") {
        return Err("l'adresse du webhook doit commencer par https://".into());
    }
    let pire = lot.iter().map(|a| crate::export::rang(&a.niveau)).max().unwrap_or(0);
    let mut corps_carte = vec![serde_json::json!({
        "type": "TextBlock", "size": "Large", "weight": "Bolder", "wrap": true,
        "color": match pire { 2 => "Attention", 1 => "Warning", _ => "Default" }, "text": titre(lot),
    })];
    for g in regrouper(lot).iter().take(10) {
        let a = g.alerte;
        let mut faits = vec![serde_json::json!({"title": "Poste", "value": hote()}), serde_json::json!({"title": "Heure", "value": a.heure})];
        if g.nombre > 1 { faits.push(serde_json::json!({"title": "Occurrences", "value": format!("{} ({}…)", g.nombre, g.exemples.join(", "))})); }
        if !a.processus.is_empty() { faits.push(serde_json::json!({"title": "Programme", "value": a.processus})); }
        if !a.mitre.is_empty() { faits.push(serde_json::json!({"title": "Technique", "value": a.mitre})); }
        corps_carte.push(serde_json::json!({"type": "TextBlock", "wrap": true, "weight": "Bolder", "text": entete_groupe(g), "separator": true}));
        corps_carte.push(serde_json::json!({"type": "FactSet", "facts": faits}));
        if !a.conseil.is_empty() {
            corps_carte.push(serde_json::json!({"type": "TextBlock", "wrap": true, "text": format!("Que faire : {}", a.conseil)}));
        }
    }
    let corps = serde_json::json!({
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": { "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4", "body": corps_carte }
        }]
    });
    curl(&format!("url = {}\nheader = \"Content-Type: application/json\"", cite(&s.teams_url)), corps.to_string().as_bytes())
}

fn base64(d: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in d.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        s.push(T[(n >> 18) as usize & 63] as char);
        s.push(T[(n >> 12) as usize & 63] as char);
        s.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        s.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    s
}

/// Date d'en-tête de courriel (RFC 5322), en UTC
fn date_courriel() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    let jours = secs.div_euclid(86_400);
    let s = secs.rem_euclid(86_400);
    let jour_semaine = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][(jours.rem_euclid(7)) as usize];
    let iso = crate::export::horodatage_utc(SystemTime::now());
    let (a, m, j) = (&iso[0..4], iso[5..7].parse::<usize>().unwrap_or(1), &iso[8..10]);
    let mois = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][m.clamp(1, 12) - 1];
    format!("{jour_semaine}, {j} {mois} {a} {:02}:{:02}:{:02} +0000", s / 3600, s % 3600 / 60, s % 60)
}

fn courriel(c: &ConfigNotifications, s: &Secrets, lot: &[Alerte]) -> Result<(), String> {
    if c.smtp_serveur.trim().is_empty() || c.expediteur.trim().is_empty() || c.destinataires.trim().is_empty() {
        return Err("serveur, expéditeur ou destinataires non renseignés".into());
    }
    let destinataires: Vec<&str> = c.destinataires.split([',', ';', ' ']).map(str::trim).filter(|d| d.contains('@')).collect();
    if destinataires.is_empty() {
        return Err("aucun destinataire valide".into());
    }
    // SSL : connexion chiffrée d'emblée (port 465) ; STARTTLS : chiffrement exigé après connexion (port 587)
    let schema = if c.smtp_securite == "SSL" { "smtps" } else { "smtp" };
    let mut p = format!("url = {}\nssl-reqd\nmail-from = {}", cite(&format!("{schema}://{}:{}", c.smtp_serveur.trim(), c.smtp_port)), cite(c.expediteur.trim()));
    for d in &destinataires {
        p.push_str(&format!("\nmail-rcpt = {}", cite(d)));
    }
    if !c.smtp_utilisateur.is_empty() {
        p.push_str(&format!("\nuser = {}", cite(&format!("{}:{}", c.smtp_utilisateur, s.smtp_mot_de_passe))));
    }
    p.push_str("\nupload-file = -");
    let message = format!(
        "From: deR4Tizer <{}>\r\nTo: {}\r\nSubject: =?UTF-8?B?{}?=\r\nDate: {}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n",
        c.expediteur.trim(), destinataires.join(", "), base64(titre(lot).as_bytes()), date_courriel(),
        base64(texte(lot).replace('\n', "\r\n").as_bytes()).as_bytes().chunks(76).map(|l| String::from_utf8_lossy(l).into_owned()).collect::<Vec<_>>().join("\r\n"));
    courriel_curl(&p, message.as_bytes())
}

/// Le message passe par l'entrée standard (upload-file = -), pas par --data-binary
fn courriel_curl(parametres: &str, message: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let d = dossier_secrets();
    let f = d.join(format!("curl-{}.txt", commun::nouvel_id()));
    let r = (|| {
        fs::write(&f, format!("{parametres}\nsilent\nshow-error\nmax-time = 30\n")).map_err(|e| e.to_string())?;
        let mut enfant = Command::new(crate::natif::curl_exe())
            .arg("-q").arg("-K").arg(&f)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .creation_flags(0x0800_0000)
            .spawn()
            .map_err(|e| e.to_string())?;
        enfant.stdin.take().ok_or("entrée de curl indisponible")?.write_all(message).map_err(|e| e.to_string())?;
        let sortie = enfant.wait_with_output().map_err(|e| e.to_string())?;
        if sortie.status.success() { Ok(()) } else { Err(String::from_utf8_lossy(&sortie.stderr).trim().chars().take(300).collect()) }
    })();
    let _ = fs::remove_file(&f);
    r
}

#[cfg(test)]
pub fn base64_test(d: &[u8]) -> String {
    base64(d)
}
