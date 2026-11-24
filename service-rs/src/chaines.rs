//! Arbre des processus et score cumulé (à la manière du « Storyline » des EDR) : chaque signal
//! (flux suspect, ligne de commande, vol de données…) est rattaché à son processus, puis on remonte
//! la chaîne des parents jusqu'à une racine (Explorateur, service…). Le score de la chaîne est la somme
//! des signaux de tous ses processus : une suite d'actions banales prises une à une devient visible.
//!
//! Audit du 2026-11-23, T-1 (faux positifs sur un poste de développement) : chaque processus porte son heure de
//! création (TimeCreated du 4688, au 100 ns près ; à défaut l'heure où la liste l'a vu pour la première fois, qui la
//! suit toujours) et l'heure où il a été vu terminé. Un parent n'est retenu que s'il est né avant l'enfant et vivait à
//! sa création : un PID de parent réutilisé (entrée gardée une heure) ne rattache plus un enfant à un inconnu. Un PID
//! repris repart sans signaux, même à nom égal. Les programmes lancés par le service sortent des chaînes.

use crate::commun::{self, Alerte};
use crate::natif::InfoListe;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant, SystemTime};

/// Noms des candidats racines : leur chemin est lu par `maj` (le nom seul ne décide rien, voir RACINES_CHEMINS)
const RACINES: &[&str] = &[
    "explorer", "services", "svchost", "wininit", "winlogon", "userinit", "smss", "csrss", "sihost", "runtimebroker", "taskhostw",
];

/// Processus où s'arrête la remontée : lanceurs du système, pas des maillons d'attaque, par chemin EXACT relatif au
/// dossier Windows. Avant, le nom suffisait : un svchost.exe ou taskhostw.exe déposé dans un dossier temporaire coupait
/// la chaîne et chaque étape restait seule avec son signal (audit du 2026-11-23, A-7-5). Chemin inconnu : pas une racine
const RACINES_CHEMINS: &[&str] = &[
    "explorer.exe", r"system32\services.exe", r"system32\svchost.exe", r"system32\wininit.exe", r"system32\winlogon.exe",
    r"system32\userinit.exe", r"system32\smss.exe", r"system32\csrss.exe", r"system32\sihost.exe", r"system32\runtimebroker.exe",
    r"system32\taskhostw.exe",
];

/// Remontée bornée (garde contre une chaîne géante quand des chemins manquent ; l'arbre réel est bien moins profond)
const PROFONDEUR_MAX: usize = 32;

/// Décision pure (testée) : ce programme est-il une racine des chaînes ? Seulement par son chemin exact sous le dossier
/// Windows (casse ignorée) ; chemin vide ou ailleurs : non (sens prudent, la chaîne continue)
pub(crate) fn racine(chemin: &str, dossier_windows: &str) -> bool {
    crate::reponse::chemin_exact_sous_windows(chemin, dossier_windows, RACINES_CHEMINS)
}
const SEUIL_CHAINE: i32 = 12;
const DUREE_SIGNAL: Duration = Duration::from_secs(3600);

/// Alertes CHA-001 au plus par chaîne et par heure (T-1) : au-delà, l'alerte n'est pas levée et elle est comptée
/// (`alertes_plafonnees`, publié dans mesures.json sous « chaines.alertes_plafonnees »)
pub const PLAFOND_ALERTES_PAR_HEURE: u32 = 3;

/// Programmes que le service lance lui-même (et la console de ses outils), par chemin EXACT relatif au dossier Windows :
/// seuls ceux-là, enfants directs du service, sortent des chaînes avec leurs descendants. Un autre enfant du service
/// (parent choisi à la création, T1134.004, par un administrateur) reste dans les chaînes et y porte un signal
const PROGRAMMES_DU_SERVICE: &[&str] = &[
    r"system32\auditpol.exe", r"system32\wevtutil.exe", r"system32\windowspowershell\v1.0\powershell.exe", r"system32\curl.exe",
    r"system32\icacls.exe", r"system32\netsh.exe", r"system32\gpupdate.exe", r"system32\schtasks.exe", r"system32\conhost.exe",
];

/// Décision pure (testée) : ce programme, enfant direct du service, est-il l'un de ceux que le service lance ? Par son
/// chemin exact sous le dossier Windows (règle 5) ; chemin inconnu : non (il reste dans les chaînes)
pub(crate) fn programme_du_service(chemin: &str, dossier_windows: &str) -> bool {
    crate::reponse::chemin_exact_sous_windows(chemin, dossier_windows, PROGRAMMES_DU_SERVICE)
}

/// Signal posé sur un enfant du service qui n'est pas l'un de ses programmes (parent usurpé probable)
const RAISON_PARENT_SERVICE: &str = "lancé avec le service de deR4Tizer pour parent sans être l'un de ses programmes (parent usurpé ?)";
const CODE_PARENT_SERVICE: &str = "CHA-001#parent-service";

/// Têtes de chaîne génériques (interpréteurs, lanceurs) : leur chemin ne désigne pas une chaîne précise (deux chaînes sans
/// lien partent de cmd.exe) ; l'entité d'incident prend alors le PID et l'heure de création (regroupement, jamais une
/// décision de confiance)
const TETES_GENERIQUES: &[&str] = &[
    "cmd", "powershell", "pwsh", "powershell_ise", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "conhost", "bash", "sh",
    "wsl", "python", "pythonw", "py", "node", "java", "javaw", "wmic", "msiexec", "dllhost", "svchost", "explorer",
];

/// Décision pure (testée) : un signal fort (document qui lance un interpréteur, suppression des sauvegardes, vidage de
/// LSASS par comsvcs, leurre touché) : une chaîne qui le reçoit alerte même au-delà du plafond
pub(crate) fn signal_fort(code: &str) -> bool {
    let c = code.to_ascii_lowercase();
    c.starts_with("prc-001") || c.starts_with("prc-005") || c.starts_with("leu-") || c.contains("comsvcs")
}

/// Unités FILETIME (100 ns) par seconde
const FT_SECONDE: u64 = 10_000_000;

/// Marge accordée à un parent dont l'heure de création n'est pas connue (vu d'abord par la liste, son 4688 manque) :
/// l'heure de première vue suit sa vraie création d'au plus quelques cycles de 3 s
const MARGE_PARENT_APPROCHE: u64 = 10 * FT_SECONDE;

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct NoeudChaine {
    pub profondeur: u32,
    pub pid: u32,
    pub nom: String,
    pub chemin: String,
    pub ligne_commande: String,
    pub score: i32,
    pub raisons: String,
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Chaine {
    pub racine: String,
    pub score: i32,
    pub resume: String,
    pub depuis: String,
    pub noeuds: Vec<NoeudChaine>,
}

struct Processus {
    nom: String,
    parent: u32,
    chemin: String,
    ligne: String,
    vu: Instant,
    /// Présent dans la dernière liste des processus (un 4688 en retard ne remplace jamais un processus vivant)
    vivant: bool,
    /// Heure de création (FILETIME) : exacte si lue dans le 4688, sinon heure de la première liste qui l'a montré
    naissance: u64,
    exacte: bool,
    /// Entrée posée par un 4688 (une seconde création du même PID est un autre processus)
    par_4688: bool,
    /// Borne haute de la fin : heure de la première liste où il manquait alors qu'il était né avant la liste
    fin: Option<u64>,
    /// Lancé par le service ou par l'un de ses descendants (fixé à l'entrée : un PID de parent repris plus tard ne le
    /// change pas)
    du_service: bool,
}

/// Ligne de commande gardée dans l'arbre et publiée dans les chaînes (etat.json) : bornée (audit de #244, S244-04, S244-05)
const LIGNE_GARDEE: usize = 1024;
const LIGNE_PUBLIEE: usize = 300;

/// Décision pure (testée) : code de comportement d'une chaîne (prérelecture de #255, D1) : codes de ses signaux, triés,
/// sans doublon ; un signal sans code y entre par le début de sa raison. Jamais les techniques. Long ou non ASCII :
/// remplacé par le début de son empreinte SHA-256 (même code pour les mêmes signaux, 100 caractères au plus)
pub(crate) fn code_chaine(signaux: &[(&str, &str)]) -> String {
    let mut codes: Vec<String> = signaux.iter().map(|(code, raison)| {
        if code.is_empty() { format!("r:{}", raison.chars().take(40).collect::<String>()) } else { code.to_string() }
    }).collect();
    codes.sort();
    codes.dedup();
    let c = codes.join("+");
    if c.len() <= 100 && c.chars().all(|x| x.is_ascii_graphic()) {
        c
    } else {
        let e = commun::empreinte_signature(&c);
        format!("sha:{}", &e["sha256:".len().."sha256:".len() + 16])
    }
}

fn borner(s: &str, n: usize) -> String {
    if s.chars().count() > n { s.chars().take(n).collect::<String>() + "…" } else { s.to_string() }
}

/// Décision pure (testée, torturée) : heure de création d'un événement du journal (attribut SystemTime de TimeCreated,
/// « 2020-01-02T03:04:05.1234567Z »), en FILETIME au 100 ns près. Illisible : None (le processus garde alors l'heure
/// de son traitement, qui suit sa création)
pub(crate) fn heure_4688(xml: &str) -> Option<u64> {
    let debut = xml.find("TimeCreated")?;
    let reste = xml.get(debut..)?;
    let a = reste.find("SystemTime=")? + "SystemTime=".len();
    let guillemet = *reste.as_bytes().get(a)?;
    if guillemet != b'\'' && guillemet != b'"' {
        return None;
    }
    let valeur = reste.get(a + 1..)?;
    let texte = valeur.get(..valeur.find(guillemet as char)?)?;
    let sans_z = texte.strip_suffix('Z')?;
    let (secondes, fraction) = match sans_z.split_once('.') {
        Some((s, f)) => (s, f),
        None => (sans_z, ""),
    };
    if fraction.len() > 9 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let s = u64::try_from(commun::secondes_utc(&format!("{secondes}Z"))?.checked_add(11_644_473_600)?).ok()?;
    // Fraction ramenée au 100 ns (7 chiffres ; au-delà, tronquée)
    let mut cent_ns: u64 = 0;
    for i in 0..7 {
        cent_ns = cent_ns * 10 + fraction.as_bytes().get(i).map(|b| u64::from(b - b'0')).unwrap_or(0);
    }
    s.checked_mul(FT_SECONDE)?.checked_add(cent_ns)
}

/// Décision pure (testée) : ce parent vivait-il à la création de l'enfant ? Né avant lui (heure exacte ou ordre des
/// 4688 : strictement pas après ; parent vu d'abord par la liste, heure approchée : marge de quelques cycles), et pas vu terminé avant
/// sa création. Sinon l'enfant est sa propre racine (PID de parent réutilisé, entrée périmée)
pub(crate) fn parent_vivait(naissance_parent: u64, parent_ordonne: bool, fin_parent: Option<u64>, naissance_enfant: u64) -> bool {
    let marge = if parent_ordonne { 0 } else { MARGE_PARENT_APPROCHE };
    naissance_parent <= naissance_enfant.saturating_add(marge) && fin_parent.is_none_or(|f| naissance_enfant <= f)
}

/// Décision pure (testée) : une création (4688) décrit-elle le même processus que l'entrée gardée pour ce PID ? Même
/// programme, parent compatible, et : deux heures exactes égales (le même 4688 lu deux fois) ; heure de l'entrée
/// approchée (vue par la liste) : création pas après la première vue et pas après sa fin. Sans heure : une entrée
/// posée par un 4688 ne reçoit pas un second 4688 (seconde création = autre processus)
#[allow(clippy::too_many_arguments)]
pub(crate) fn meme_processus(nom_entree: &str, parent_entree: u32, naissance_entree: u64, exacte_entree: bool, par_4688: bool,
    fin_entree: Option<u64>, nom: &str, parent: Option<u32>, heure: Option<u64>) -> bool {
    if !nom_entree.eq_ignore_ascii_case(nom) {
        return false;
    }
    if let Some(p) = parent {
        if parent_entree != 0 && p != parent_entree {
            return false;
        }
    }
    match heure {
        Some(t) if exacte_entree => t == naissance_entree,
        Some(t) => t <= naissance_entree && fin_entree.is_none_or(|f| t <= f) && !par_4688,
        None => !par_4688,
    }
}

struct Signal {
    score: i32,
    raison: String,
    /// Techniques ATT&CK de l'alerte d'origine (règle de la table, ou posées par son code) : celles de la chaîne
    techniques: Vec<String>,
    /// Code stable du signal (règle et code de comportement de l'alerte d'origine) : il entre dans le code de la chaîne
    code: String,
    vu: Instant,
    heure: String,
}

#[derive(Default)]
pub struct Arbre {
    processus: HashMap<u32, Processus>,
    signaux: HashMap<u32, Vec<Signal>>,
    /// Par chaîne (programme de tête, PID et heure de création) : score déjà alerté, et quand
    deja_alertees: HashMap<String, (i32, Instant)>,
    /// Par chaîne : début de la fenêtre d'une heure et alertes levées dans cette fenêtre (plafond)
    /// et apports déjà alertés (techniques, signaux forts) : une alerte qui en apporte un nouveau passe le plafond
    plafond: HashMap<String, (Instant, u32, HashSet<String>)>,
    /// Alertes CHA-001 levées au-delà du plafond parce qu'elles apportaient du nouveau
    hors_plafond: u64,
    /// Alertes CHA-001 retenues par le plafond depuis le démarrage
    plafonnees: u64,
    /// Heure (FILETIME) de la dernière lecture de la liste, et dernière heure donnée (horloge croissante)
    derniere_maj: u64,
    horloge: u64,
    /// PID du service (le processus qui tourne) : ses descendants sortent des chaînes ; None : `std::process::id()`
    service: Option<u32>,
}

impl Arbre {
    /// Heure présente en FILETIME, jamais en arrière ni répétée (deux entrées posées dans le même instant gardent leur
    /// ordre de traitement)
    fn tic(&mut self) -> u64 {
        let t = commun::filetime(SystemTime::now()).max(self.horloge.saturating_add(1));
        self.horloge = t;
        t
    }

    fn pid_service(&self) -> u32 {
        self.service.unwrap_or_else(std::process::id)
    }

    /// Tests : PID du service fixé. Sans lui, le service est le processus de test lui-même (`std::process::id()`), dont
    /// le PID change à chaque lancement et peut tomber sur un PID synthétique d'un scénario
    #[cfg(test)]
    pub(crate) fn fixer_pid_service(&mut self, pid: u32) {
        self.service = Some(pid);
    }

    /// Alertes CHA-001 retenues par le plafond (par chaîne et par heure) depuis le démarrage
    pub fn alertes_plafonnees(&self) -> u64 {
        self.plafonnees
    }

    /// Alertes CHA-001 levées au-delà du plafond (technique nouvelle ou signal fort) depuis le démarrage
    pub fn alertes_hors_plafond(&self) -> u64 {
        self.hors_plafond
    }

    /// Marque à l'entrée : descendant d'un programme du service (hors chaîne) ; enfant direct du service qui n'est pas
    /// l'un de ses programmes : signalé (parent usurpé probable), jamais exclu en silence
    fn marquer(&mut self, pid: u32, windows: &str) {
        let d = self.descend_du_service(pid, windows);
        let service = self.pid_service();
        let Some(e) = self.processus.get_mut(&pid) else { return };
        e.du_service = d;
        let usurpe = !d && e.parent == service && pid != service && !e.chemin.is_empty() && !programme_du_service(&e.chemin, windows);
        if usurpe {
            self.signaler_code(pid, 5, RAISON_PARENT_SERVICE, &["T1134.004".to_string()], CODE_PARENT_SERVICE);
        }
    }

    /// Met à jour la liste des processus ; garde 1 h les processus terminés pour reconstituer les chaînes
    pub fn maj(&mut self, liste: &HashMap<u32, InfoListe>) {
        self.maj_avec(liste, &crate::natif::chemin_processus);
    }

    /// `maj`, avec la lecture du chemin d'un programme vivant (`natif::chemin_processus` ; synthétique dans les tests) :
    /// le chemin d'un candidat racine (nom de RACINES) est lu tant qu'il manque, car c'est lui seul qui en fait une
    /// racine (audit du 2026-11-23, A-7-5). Un PID de la liste dont l'entrée a été vue terminée, ou dont le parent ou le
    /// nom diffère, est un autre processus : nouvelle entrée, sans les signaux de l'ancien (T-1)
    pub fn maj_avec(&mut self, liste: &HashMap<u32, InfoListe>, chemin_de: &dyn Fn(u32) -> String) {
        let maintenant = Instant::now();
        let heure = self.tic();
        let mut nouveaux: Vec<u32> = Vec::new();
        let service = self.pid_service();
        for (&pid, p) in liste {
            let neuf = || Processus {
                nom: p.nom.clone(), parent: p.parent, chemin: String::new(), ligne: String::new(), vu: maintenant, vivant: true,
                naissance: heure, exacte: false, par_4688: false, fin: None, du_service: false,
            };
            if !self.processus.contains_key(&pid) {
                nouveaux.push(pid);
            }
            let e = self.processus.entry(pid).or_insert_with(neuf);
            let autre = !e.nom.eq_ignore_ascii_case(&p.nom) || e.fin.is_some() || (e.parent != 0 && e.parent != p.parent);
            if autre {
                // Identifiant réutilisé par un autre programme, ou par le même programme relancé
                *e = neuf();
                self.signaux.remove(&pid);
                nouveaux.push(pid);
            }
            if e.parent == 0 {
                e.parent = p.parent;
            }
            e.vu = maintenant;
            // Chemin lu pour un candidat racine, et pour un enfant du service (c'est lui qui le fait sortir des chaînes)
            if e.chemin.is_empty() && (RACINES.iter().any(|r| r.eq_ignore_ascii_case(&e.nom)) || e.parent == service) {
                e.chemin = chemin_de(pid);
            }
        }
        // Ascendance figée à l'entrée : descendant du service ou non (parents et enfants d'une même liste, tout ordre)
        let windows = crate::natif::dossier_windows();
        for pid in nouveaux {
            self.marquer(pid, &windows);
        }
        let precedente = self.derniere_maj;
        for (pid, p) in self.processus.iter_mut() {
            let present = liste.contains_key(pid);
            // Absent : terminé avant cette liste s'il était dans la précédente, ou s'il est né avant elle (un processus
            // créé après la lecture de la liste, connu par son 4688, n'y est pas encore)
            if !present && p.fin.is_none() && (p.vivant || p.naissance <= precedente) {
                p.fin = Some(heure);
            }
            p.vivant = present;
        }
        self.derniere_maj = heure;
        self.processus.retain(|_, p| p.vu.elapsed() < DUREE_SIGNAL);
        for s in self.signaux.values_mut() {
            s.retain(|x| x.vu.elapsed() < DUREE_SIGNAL);
        }
        self.signaux.retain(|_, s| !s.is_empty());
        self.deja_alertees.retain(|_, (_, t)| t.elapsed() < DUREE_SIGNAL);
        self.plafond.retain(|_, (t, _, _)| t.elapsed() < DUREE_SIGNAL);
    }

    pub fn completer(&mut self, pid: u32, chemin: &str, ligne: Option<&str>) {
        if let Some(p) = self.processus.get_mut(&pid) {
            if p.chemin.is_empty() {
                p.chemin = chemin.to_string();
            }
            if p.ligne.is_empty() {
                if let Some(l) = ligne {
                    p.ligne = borner(l, LIGNE_GARDEE);
                }
            }
        }
    }

    /// Création vue par l'audit (4688), sans heure de création (tests) : voir `creation_a`
    pub fn creation(&mut self, pid: u32, parent: Option<u32>, chemin: &str, ligne: Option<&str>) {
        self.creation_a(pid, parent, chemin, ligne, None);
    }

    /// Création vue par l'audit (4688) avec son heure (TimeCreated, `heure_4688`) : un processus bref, terminé avant la
    /// lecture de la liste, garde sa place dans l'arbre et son parent. PID réutilisé (autre programme, ou même programme
    /// créé à une autre heure) : l'entrée est remplacée et ses signaux effacés (T-1), sauf si la création est plus
    /// ancienne que l'entrée (un 4688 en retard, d'un ancien processus de ce PID, n'efface jamais les signaux du processus
    /// qui tourne ; audit de #244, S244-01)
    pub fn creation_a(&mut self, pid: u32, parent: Option<u32>, chemin: &str, ligne: Option<&str>, heure: Option<u64>) {
        if pid <= 4 {
            return;
        }
        let nom = std::path::Path::new(chemin).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
        let maintenant = Instant::now();
        let t = match heure {
            Some(h) => h,
            None => self.tic(),
        };
        match self.processus.get_mut(&pid) {
            Some(e) if meme_processus(&e.nom, e.parent, e.naissance, e.exacte, e.par_4688, e.fin, &nom, parent, heure) => {
                if e.parent == 0 {
                    e.parent = parent.unwrap_or(0);
                }
                // Heure exacte connue : elle remplace l'heure de première vue (toujours plus tardive)
                if heure.is_some() && !e.exacte {
                    e.naissance = t;
                    e.exacte = true;
                }
                e.par_4688 = true;
                self.completer(pid, chemin, ligne);
            }
            // Création plus ancienne que l'entrée (4688 en retard) ; sans heure, entrée vivante (S244-01)
            Some(e) if heure.map_or(e.vivant, |h| h < e.naissance) => {}
            _ => {
                self.processus.insert(pid, Processus {
                    nom, parent: parent.unwrap_or(0), chemin: chemin.to_string(), ligne: borner(ligne.unwrap_or_default(), LIGNE_GARDEE),
                    vu: maintenant, vivant: false, naissance: t, exacte: heure.is_some(), par_4688: true, fin: None, du_service: false,
                });
                self.signaux.remove(&pid);
                self.marquer(pid, &crate::natif::dossier_windows());
            }
        }
    }

    /// Ajoute un signal à un processus (une même raison n'est comptée qu'une fois), sans technique
    pub fn signaler(&mut self, pid: u32, score: i32, raison: &str) {
        self.signaler_avec(pid, score, raison, &[]);
    }

    /// Ajoute un signal et les techniques de l'alerte qui le porte : la chaîne reçoit celles de ses signaux, jamais une
    /// technique par défaut (couverture ATT&CK, lot 2 : avant, toute chaîne recevait T1204)
    pub fn signaler_avec(&mut self, pid: u32, score: i32, raison: &str, techniques: &[String]) {
        self.signaler_code(pid, score, raison, techniques, "");
    }

    /// `signaler_avec` et le code stable du signal (« règle#comportement ») : la chaîne en tire son code de comportement
    /// (empreinte des exceptions ; prérelecture de #255, D1)
    pub fn signaler_code(&mut self, pid: u32, score: i32, raison: &str, techniques: &[String], code: &str) {
        if score <= 0 || pid <= 4 {
            return;
        }
        let s = self.signaux.entry(pid).or_default();
        if !s.iter().any(|x| x.raison == raison) {
            s.push(Signal { score, raison: raison.to_string(), techniques: techniques.to_vec(), code: code.to_string(), vu: Instant::now(), heure: commun::maintenant() });
        }
    }

    fn nom(&self, pid: u32) -> String {
        self.processus.get(&pid).map(|p| p.nom.clone()).unwrap_or_else(|| format!("PID {pid}"))
    }

    /// L'ascendance réelle de ce processus passe-t-elle par un programme du service ? Parent suivi seulement s'il vivait
    /// à la création de l'enfant ; un ancêtre déjà marqué suffit. Le service est reconnu par son propre PID (le processus
    /// qui exécute ce code), jamais par un nom ; son enfant direct doit être l'un de ses programmes, par chemin exact
    /// (règle 5 : un autre programme créé avec le service pour parent reste dans les chaînes)
    fn descend_du_service(&self, pid: u32, windows: &str) -> bool {
        let service = self.pid_service();
        let mut courant = pid;
        for _ in 0..PROFONDEUR_MAX {
            if courant == service {
                return true;
            }
            let Some(p) = self.processus.get(&courant) else { return false };
            if p.du_service {
                return true;
            }
            if p.parent == service {
                let service_vivait = self.processus.get(&service).is_none_or(|s| parent_vivait(s.naissance, s.exacte || s.par_4688, s.fin, p.naissance));
                return service_vivait && programme_du_service(&p.chemin, windows);
            }
            let Some(pp) = self.processus.get(&p.parent) else { return false };
            if p.parent == courant || !parent_vivait(pp.naissance, pp.exacte || pp.par_4688, pp.fin, p.naissance) {
                return false;
            }
            courant = p.parent;
        }
        false
    }

    /// Remonte jusqu'à la racine : liste [racine, …, pid], et vrai si l'ascendance réelle passe par le service. Un parent
    /// n'est suivi que s'il vivait à la création de l'enfant (`parent_vivait`) : sinon l'enfant est sa propre racine
    fn ascendance(&self, pid: u32) -> (Vec<u32>, bool) {
        let windows = crate::natif::dossier_windows();
        let service = self.pid_service();
        let mut chemin = vec![pid];
        let mut vus = HashSet::from([pid]);
        let mut courant = pid;
        if pid == service {
            return (chemin, true);
        }
        while let Some(p) = self.processus.get(&courant) {
            if p.du_service {
                return (chemin, true);
            }
            let parent = p.parent;
            let Some(pp) = self.processus.get(&parent) else { break };
            if !parent_vivait(pp.naissance, pp.exacte || pp.par_4688, pp.fin, p.naissance) {
                break;
            }
            // Le service n'est jamais un maillon : un enfant direct qui n'est pas l'un de ses programmes est sa propre tête
            if parent == service {
                break;
            }
            if racine(&pp.chemin, &windows) || !vus.insert(parent) || parent <= 4 || chemin.len() >= PROFONDEUR_MAX {
                break;
            }
            chemin.push(parent);
            courant = parent;
        }
        chemin.reverse();
        (chemin, false)
    }

    /// Chaînes ayant au moins un signal, triées par score décroissant. Hors chaîne : les programmes lancés par le service
    /// et un PID inconnu de l'arbre (ni nom ni chemin : pas de chaîne « PID n »). Le score compte une seule fois un même
    /// comportement (code du signal) répété au même endroit de la chaîne (même suite de programmes depuis la tête) :
    /// un outil qui relance cent fois la même commande ne fait pas monter le score cent fois (T-1)
    pub fn chaines(&self) -> Vec<Chaine> {
        let mut par_racine: HashMap<u32, Vec<Vec<u32>>> = HashMap::new();
        for &pid in self.signaux.keys() {
            if !self.processus.contains_key(&pid) {
                continue;
            }
            let (a, du_service) = self.ascendance(pid);
            if du_service {
                continue;
            }
            par_racine.entry(a[0]).or_default().push(a);
        }
        let mut chaines: Vec<Chaine> = par_racine
            .into_iter()
            .map(|(racine, chemins)| {
                // Arbre de la chaîne : ordre de parcours en profondeur depuis la racine
                let mut membres: Vec<(u32, u32)> = Vec::new(); // (pid, profondeur)
                for c in &chemins {
                    for (i, &pid) in c.iter().enumerate() {
                        if !membres.iter().any(|(p, _)| *p == pid) {
                            membres.push((pid, i as u32));
                        }
                    }
                }
                membres.sort_by_key(|(pid, prof)| (chemins.iter().position(|c| c.contains(pid)).unwrap_or(0), *prof));
                let noeuds: Vec<NoeudChaine> = membres
                    .iter()
                    .map(|&(pid, prof)| {
                        let p = self.processus.get(&pid);
                        let s = self.signaux.get(&pid);
                        NoeudChaine {
                            profondeur: prof,
                            pid,
                            nom: self.nom(pid),
                            chemin: p.map(|p| p.chemin.clone()).unwrap_or_default(),
                            ligne_commande: p.map(|p| borner(&p.ligne, LIGNE_PUBLIEE)).unwrap_or_default(),
                            score: s.map(|s| s.iter().map(|x| x.score).sum()).unwrap_or(0),
                            raisons: s.map(|s| s.iter().map(|x| x.raison.clone()).collect::<Vec<_>>().join(" ; ")).unwrap_or_default(),
                        }
                    })
                    .collect();
                // Score : chaque comportement compté une fois par place dans la chaîne (suite des noms depuis la tête)
                let mut comptes: HashSet<String> = HashSet::new();
                let mut score = 0;
                for &(pid, _) in &membres {
                    let place = chemins.iter().find_map(|c| c.iter().position(|p| *p == pid).map(|i| &c[..=i])).unwrap_or(&[]);
                    let place = place.iter().map(|&p| self.nom(p).to_lowercase()).collect::<Vec<_>>().join("/");
                    for s in self.signaux.get(&pid).into_iter().flatten() {
                        let comportement = if s.code.is_empty() { &s.raison } else { &s.code };
                        if comptes.insert(format!("{place}|{comportement}")) {
                            score += s.score;
                        }
                    }
                }
                let depuis = chemins.iter().flat_map(|c| c.iter()).filter_map(|p| self.signaux.get(p)).flatten().map(|s| s.heure.clone()).min().unwrap_or_default();
                let resume = chemins
                    .iter()
                    .max_by_key(|c| c.len())
                    .map(|c| c.iter().map(|&p| self.nom(p)).collect::<Vec<_>>().join(" → "))
                    .unwrap_or_default();
                Chaine { racine: self.nom(racine), score, resume, depuis, noeuds }
            })
            .collect();
        chaines.sort_by(|a, b| b.score.cmp(&a.score));
        chaines
    }

    /// Identité stable d'une chaîne (T-3) : son programme de tête, par PID et heure de création (jamais le texte de la
    /// chaîne, qui change quand elle grossit)
    fn identite(&self, c: &Chaine) -> String {
        let pid = c.noeuds.first().map(|n| n.pid).unwrap_or(0);
        let naissance = self.processus.get(&pid).map(|p| p.naissance).unwrap_or(0);
        format!("{}#{pid}@{naissance:x}", c.racine)
    }

    /// Alerte pour toute chaîne qui dépasse le seuil avec au moins deux signaux (une fois par niveau atteint ; au plus
    /// PLAFOND_ALERTES_PAR_HEURE par chaîne et par heure, le surplus compté). Entité d'incident : le programme de tête,
    /// par son chemin s'il est connu, sinon par son identité (PID et heure de création) : une chaîne qui grossit reste
    /// un seul incident (T-3)
    pub fn alertes(&mut self, chaines: &[Chaine]) -> Vec<Alerte> {
        let mut a = Vec::new();
        for c in chaines {
            let signaux = c.noeuds.iter().filter(|n| n.score > 0).map(|n| n.raisons.matches(" ; ").count() + 1).sum::<usize>();
            if c.score < SEUIL_CHAINE || signaux < 2 {
                continue;
            }
            let cle = self.identite(c);
            if self.deja_alertees.get(&cle).map(|&(s, _)| s >= c.score).unwrap_or(false) {
                continue;
            }
            self.deja_alertees.insert(cle.clone(), (c.score, Instant::now()));
            // Techniques de la chaîne : celles de ses signaux, dans l'ordre de la chaîne, sans doublon
            let mut techniques: Vec<String> = Vec::new();
            for t in c.noeuds.iter().filter_map(|n| self.signaux.get(&n.pid)).flatten().flat_map(|s| s.techniques.iter()) {
                if !techniques.contains(t) {
                    techniques.push(t.clone());
                }
            }
            let signaux: Vec<&Signal> = c.noeuds.iter().filter_map(|n| self.signaux.get(&n.pid)).flatten().collect();
            // Apports de l'alerte : techniques et signaux forts. Le plafond ne retient que l'alerte qui n'apporte rien de
            // nouveau (une hausse de score par des signaux déjà vus) ; la technique nouvelle ou le signal fort passe, compté
            let apports: Vec<String> = techniques.iter().map(|t| format!("t:{t}"))
                .chain(signaux.iter().filter(|s| signal_fort(&s.code)).map(|s| format!("f:{}", s.code))).collect();
            let fenetre = self.plafond.entry(cle.clone()).or_insert_with(|| (Instant::now(), 0, HashSet::new()));
            if fenetre.0.elapsed() >= DUREE_SIGNAL {
                *fenetre = (Instant::now(), 0, HashSet::new());
            }
            let nouveau = apports.iter().any(|x| !fenetre.2.contains(x));
            if fenetre.1 >= PLAFOND_ALERTES_PAR_HEURE {
                if !nouveau {
                    self.plafonnees += 1;
                    crate::mesure::compter("chaines.alertes_plafonnees");
                    continue;
                }
                self.hors_plafond += 1;
                crate::mesure::compter("chaines.alertes_hors_plafond");
            }
            fenetre.1 += 1;
            fenetre.2.extend(apports);
            let dernier = c.noeuds.iter().rev().find(|n| n.score > 0).cloned().unwrap_or_default();
            let tete = c.noeuds.first().map(|n| n.chemin.trim()).unwrap_or_default();
            let generique = std::path::Path::new(tete).file_stem().map(|n| n.to_string_lossy().to_lowercase())
                .is_some_and(|n| TETES_GENERIQUES.contains(&n.as_str()));
            let entite = if tete.is_empty() || generique { format!("chaine:{cle}") } else { format!("programme:{tete}") };
            a.push(Alerte {
                comportement: code_chaine(&signaux.iter().map(|s| (s.code.as_str(), s.raison.as_str())).collect::<Vec<_>>()),
                regle: crate::regles::CHA_001.into(),
                id: commun::nouvel_id(),
                heure: commun::maintenant(),
                niveau: "Critique".into(),
                score: c.score,
                processus: dernier.nom.clone(),
                chemin: dernier.chemin.clone(),
                destination: format!("chaîne : {}", c.resume),
                raisons: format!(
                    "CHAÎNE D'ATTAQUE PROBABLE (score cumulé {}) : {}",
                    c.score,
                    c.noeuds.iter().filter(|n| n.score > 0).map(|n| format!("{} [{}]", n.nom, n.raisons)).collect::<Vec<_>>().join(" → ")
                ),
                pid: Some(dernier.pid),
                mitre: techniques.join(" / "),
                entite,
                ..Default::default()
            });
        }
        a
    }
}
