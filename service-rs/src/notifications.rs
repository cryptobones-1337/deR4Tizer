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
#[derive(Serialize, Default)]
#[serde(rename_all = "PascalCase")]
struct Etat {
    ntfy_configure: bool,
    teams_configure: bool,
    smtp_mot_de_passe: bool,
    envoyes: u64,
    resumes: u64,
    dernier_envoi: String,
    derniere_erreur: String,
}

enum Message {
    Alerte(Alerte),
    Config(ConfigNotifications),
}

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

pub fn lire_secrets() -> Secrets {
    commun::lire_fichier(&dossier_secrets().join("notifications.json"))
        .and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

/// Caractère de contrôle (Cc) ou de mise en forme invisible (principaux Cf : sens d'écriture, largeur nulle, BOM)
pub fn caractere_interdit(c: char) -> bool {
    c.is_control() || matches!(c, '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206F}' | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}')
}

/// Avant d'enregistrer de nouveaux réglages de remontée (décision pure, audit AUD6-02 et AUD3-07) :
/// - aucun caractère de contrôle ni de mise en forme invisible dans les champs du courriel (sinon ajout d'en-têtes ou
///   de destinataires, ou adresse affichée à l'envers dans la confirmation : U+202E…) ;
/// - serveur, port ou compte SMTP changé sans nouveau mot de passe : l'ancien est effacé, jamais envoyé au nouveau
///   serveur ; de même, jeton ntfy effacé si l'adresse ntfy change sans nouveau jeton.
pub fn preparer(actuelle: &ConfigNotifications, nouvelle: &ConfigNotifications, actuels: &Secrets, s: &mut Secrets) -> Result<(), String> {
    for (nom, v) in [("serveur SMTP", &nouvelle.smtp_serveur), ("compte SMTP", &nouvelle.smtp_utilisateur), ("expéditeur", &nouvelle.expediteur),
                     ("destinataires", &nouvelle.destinataires), ("sécurité SMTP", &nouvelle.smtp_securite), ("niveau", &nouvelle.niveau_min)] {
        if v.chars().any(caractere_interdit) {
            return Err(format!("{nom} : caractère de contrôle ou de mise en forme refusé"));
        }
    }
    // Adresses ntfy et Teams : ASCII imprimable seulement (homoglyphes, caractères invisibles : audit de sécurité, C1)
    for (nom, v) in [("adresse ntfy", &s.ntfy_url), ("adresse Teams", &s.teams_url)] {
        if v.chars().any(|c| !c.is_ascii_graphic()) {
            return Err(format!("{nom} : seulement des caractères ASCII visibles"));
        }
    }
    let compte_change = nouvelle.smtp_serveur.trim() != actuelle.smtp_serveur.trim() || nouvelle.smtp_port != actuelle.smtp_port
        || nouvelle.smtp_utilisateur.trim() != actuelle.smtp_utilisateur.trim();
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
    let mut s = lire_secrets();
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
    if let Some(f) = FILE.get() {
        let _ = f.lock().unwrap().try_send(Message::Config(config.clone()));
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
    let mut etat = Etat::default();
    let mut fenetre = Instant::now();
    let mut envois_heure = 0u32;
    let mut retenues = 0usize;
    ecrire_etat(&mut etat);
    loop {
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
                envoyer_partout(&config, &[resume], &mut etat);
            }
        }
        // Attente de la première alerte (une minute au plus, pour la minuterie du résumé)
        let premiere = match rx.recv_timeout(Duration::from_secs(60)) {
            Ok(Message::Config(c)) => {
                config = c;
                ecrire_etat(&mut etat);
                continue;
            }
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
                Ok(Message::Alerte(a)) if crate::export::rang(&a.niveau) >= crate::export::rang(&config.niveau_min) => lot.push(a),
                Ok(Message::Alerte(_)) => {}
                Ok(Message::Config(c)) => config = c,
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) => return,
            }
        }
        // Les critiques partent toujours : un attaquant ne doit pas pouvoir noyer la vraie alerte sous des
        // alertes provoquées ; seules les autres comptent dans le plafond par heure
        let (a_envoyer, n_retenues, compte) = repartir(lot, envois_heure, config.max_par_heure);
        retenues += n_retenues;
        if compte {
            envois_heure += 1;
        }
        if !a_envoyer.is_empty() {
            envoyer_partout(&config, &a_envoyer, &mut etat);
        }
    }
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

fn envoyer_partout(config: &ConfigNotifications, lot: &[Alerte], etat: &mut Etat) {
    let s = lire_secrets();
    let mut erreurs = Vec::new();
    if config.ntfy && !s.ntfy_url.is_empty() {
        if let Err(e) = ntfy(&s, lot) { erreurs.push(format!("ntfy : {e}")); }
    }
    if config.teams && !s.teams_url.is_empty() {
        if let Err(e) = teams(&s, lot) { erreurs.push(format!("Teams : {e}")); }
    }
    if config.smtp && !config.smtp_serveur.is_empty() {
        if let Err(e) = courriel(config, &s, lot) { erreurs.push(format!("e-mail : {e}")); }
    }
    etat.envoyes += 1;
    etat.dernier_envoi = commun::maintenant();
    etat.derniere_erreur = erreurs.join(" ; ");
    if !erreurs.is_empty() {
        commun::journal(&format!("notifications : {}", etat.derniere_erreur));
    }
    ecrire_etat(etat);
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
        let sortie = Command::new("curl.exe")
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
        let mut enfant = Command::new("curl.exe")
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
