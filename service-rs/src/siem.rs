//! Mini-SIEM local : événements normalisés, stockés un fichier NDJSON par jour (siem\evenements-AAAAMMJJ.ndjson,
//! 30 jours, 1 Go au plus), et corrélation de règles sur fenêtres de temps, qui produit des incidents
//! (incidents.json) et des alertes.
//!
//! Sources : alertes de deR4Tizer, nouvelles connexions sortantes, changements de règles du pare-feu,
//! journal Sécurité (sessions, comptes, groupes, processus, politique d'audit, effacement) et journal Système
//! (services installés, effacement).

use crate::commun::{self, Alerte};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

const JOURS_CONSERVES: u64 = 30;
const TAILLE_MAX: u64 = 1024 * 1024 * 1024;
const SID_ADMINISTRATEURS: &str = "S-1-5-32-544";

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Evenement {
    pub heure: String,
    /// alerte, connexion, parefeu, securite, processus, systeme
    pub source: String,
    /// type précis : ouverture-session, echec-session, compte-cree, processus-cree…
    #[serde(rename = "Type")]
    pub type_: String,
    /// Info, Alerte ou Critique
    pub niveau: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub utilisateur: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub processus: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub ip: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub port: u16,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub destination: String,
    pub message: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub mitre: String,
    /// Version du modèle d'événement (docs/detection/modele-evenement.md) : 0 pour une ligne d'avant la phase 3
    pub modele: u32,
    /// Règle de l'alerte d'origine (docs/detection/regles.md), vide pour un événement qui n'en vient pas
    #[serde(skip_serializing_if = "String::is_empty")]
    pub regle: String,
}

fn is_zero(p: &u16) -> bool {
    *p == 0
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Incident {
    pub id: String,
    pub heure: String,
    pub regle: String,
    pub titre: String,
    pub niveau: String,
    pub mitre: String,
    pub resume: String,
    /// Événements à l'origine de l'incident (heure, source, message)
    pub evenements: Vec<String>,
}

static FILE: OnceLock<Mutex<SyncSender<Evenement>>> = OnceLock::new();

pub fn dossier() -> PathBuf {
    commun::dossier().join("siem")
}

/// Ajoute un événement (perdu si la file est pleine : la surveillance passe avant)
pub fn enregistrer(mut e: Evenement) {
    if e.modele == 0 {
        e.modele = commun::MODELE_ALERTE;
    }
    if let Some(f) = FILE.get() {
        let _ = f.lock().unwrap().try_send(e);
    }
}

/// Lance l'écriture, la corrélation et l'abonnement aux journaux de Windows
pub fn demarrer(alertes: Arc<Mutex<Vec<Alerte>>>, journaux_windows: bool) {
    let premiere_fois = !dossier().exists();
    let _ = fs::create_dir_all(dossier());
    let (tx, rx) = sync_channel(20_000);
    if FILE.set(Mutex::new(tx)).is_err() {
        return;
    }
    std::thread::Builder::new().name("siem".into()).spawn(move || boucle(rx, alertes)).unwrap();
    if !journaux_windows {
        for c in [crate::collectes::Collecte::JournalSecurite, crate::collectes::Collecte::JournalSysteme] {
            crate::collectes::desactivee(c, "mode console : journaux Sécurité et Système non lus");
        }
        return;
    }
    // Journal Sécurité : sessions, comptes, groupes, politique d'audit, processus, effacement
    let securite = "*[System[(EventID=4624 or EventID=4625 or EventID=4634 or EventID=4648 or EventID=4672 or EventID=4688 \
        or EventID=4697 or EventID=4719 or EventID=4720 or EventID=4722 or EventID=4724 or EventID=4725 or EventID=4726 \
        or EventID=4728 or EventID=4732 or EventID=4740 or EventID=4756 or EventID=4798 or EventID=1102)]]";
    let systeme = "*[System[(EventID=7045 or EventID=104 or EventID=7036)]]";
    if premiere_fois {
        // Premier démarrage : les dernières 24 h, pour que la chronologie ne parte pas de rien
        for (canal, requete) in [("Security", securite), ("System", systeme)] {
            let r = requete.replacen("*[System[(", "*[System[TimeCreated[timediff(@SystemTime) <= 86400000] and (", 1);
            crate::evenements::historique(canal, &r, &mut |xml| {
                if let Some(e) = traduire(&xml) {
                    enregistrer(e);
                }
            });
        }
    }
    for (canal, requete, collecte) in [("Security", securite, crate::collectes::Collecte::JournalSecurite), ("System", systeme, crate::collectes::Collecte::JournalSysteme)] {
        let ok = crate::evenements::abonner(canal, requete, collecte, |xml| {
            if let Some(e) = traduire(&xml) {
                enregistrer(e);
            }
        });
        commun::journal(&format!("mini-SIEM : suivi du journal {canal} {}", if ok { "lancé (lecture : état des collectes)" } else { "IMPOSSIBLE" }));
    }
}

// ------------------------------------------------------------ sources internes

pub fn depuis_alerte(a: &Alerte) {
    enregistrer(evenement_de_alerte(a));
}

/// Règle du registre d'une corrélation (décision pure, testée) : « R1 » → « COR-R1 », vide si le numéro n'y est pas
pub fn regle_correlation(r: &str) -> String {
    crate::regles::regle(&format!("COR-{r}")).map(|x| x.id.to_string()).unwrap_or_default()
}

/// Événement SIEM d'une alerte (décision pure, testée) : la règle de l'alerte est reprise (phase 3.2)
pub fn evenement_de_alerte(a: &Alerte) -> Evenement {
    let incident = a.destination.starts_with("incident : ");
    Evenement {
        heure: a.heure.clone(),
        source: "alerte".into(),
        type_: if incident { "incident".into() } else if a.mitre.is_empty() { "detection".into() } else { a.mitre.split_whitespace().next().unwrap_or("").into() },
        niveau: a.niveau.clone(),
        processus: a.processus.clone(),
        pid: a.pid,
        ip: a.ip.clone().unwrap_or_default(),
        port: a.port,
        destination: a.destination.clone(),
        message: a.raisons.clone(),
        mitre: a.mitre.clone(),
        regle: a.regle.clone(),
        ..Default::default()
    }
}

pub fn connexion(processus: &str, pid: u32, ip: &str, port: u16, nom: Option<&str>) {
    enregistrer(Evenement {
        heure: commun::maintenant(),
        source: "connexion".into(),
        type_: "nouvelle-destination".into(),
        niveau: "Info".into(),
        processus: processus.into(),
        pid: Some(pid),
        ip: ip.into(),
        port,
        destination: nom.unwrap_or(ip).into(),
        message: format!("{processus} se connecte pour la première fois à {}:{port}", nom.unwrap_or(ip)),
        ..Default::default()
    });
}

pub fn regle_parefeu(operation: &str, regle: &str, sens: &str, action: &str, auteur: &str) {
    let processus = std::path::Path::new(auteur).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    enregistrer(Evenement {
        heure: commun::maintenant(),
        source: "parefeu".into(),
        type_: format!("regle-{}", operation.replace(' ', "-")),
        niveau: "Info".into(),
        processus,
        message: format!("règle « {regle} » {operation} ({sens}, {action})"),
        ..Default::default()
    });
}

// ------------------------------------------------------------ journaux de Windows

/// Heure locale d'un événement (attribut SystemTime, en UTC)
fn heure_evenement(xml: &str) -> String {
    let Some(i) = xml.find("SystemTime='").or_else(|| xml.find("SystemTime=\"")) else { return commun::maintenant() };
    let t = &xml[i + 12..];
    let n = |a: usize, b: usize| t.get(a..b).and_then(|s| s.parse::<i64>().ok());
    let (Some(an), Some(mo), Some(j), Some(h), Some(mi), Some(s)) = (n(0, 4), n(5, 7), n(8, 10), n(11, 13), n(14, 16), n(17, 19)) else {
        return commun::maintenant();
    };
    // Date civile vers jours depuis 1970 (algorithme de Howard Hinnant)
    let a = if mo <= 2 { an - 1 } else { an };
    let ere = a.div_euclid(400);
    let ade = a - ere * 400;
    let jda = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + j - 1;
    let jde = ade * 365 + ade / 4 - ade / 100 + jda;
    let jours = ere * 146_097 + jde - 719_468;
    let secs = jours * 86_400 + h * 3600 + mi * 60 + s;
    commun::heure_filetime(((secs + 11_644_473_600) * 10_000_000) as u64)
}

fn type_session(t: &str) -> &'static str {
    match t {
        "2" => "locale",
        "3" => "réseau",
        "4" => "tâche planifiée",
        "5" => "service",
        "7" => "déverrouillage",
        "8" => "réseau (mot de passe en clair)",
        "9" => "identifiants explicites",
        "10" => "bureau à distance",
        "11" => "hors ligne (cache)",
        _ => "autre",
    }
}

/// Compte système ou de machine : sans intérêt pour la chronologie
fn compte_systeme(sid: &str, nom: &str) -> bool {
    matches!(sid, "S-1-5-18" | "S-1-5-19" | "S-1-5-20" | "S-1-0-0") || nom.ends_with('$') || nom.starts_with("DWM-") || nom.starts_with("UMFD-")
        || nom.is_empty() || nom == "-"
}

fn ip_utile(ip: &str) -> String {
    if ip == "-" || ip == "::1" || ip == "127.0.0.1" { String::new() } else { ip.to_string() }
}

fn traduire(xml: &str) -> Option<Evenement> {
    static ID: OnceLock<regex::Regex> = OnceLock::new();
    let id: u32 = ID.get_or_init(|| regex::Regex::new(r"<EventID[^>]*>(\d+)</EventID>").unwrap()).captures(xml)?[1].parse().ok()?;
    let d = crate::evenements::donnees(xml);
    let v = |c: &str| d.get(c).cloned().unwrap_or_default();
    let compte = |dom: &str, nom: &str| if v(dom).is_empty() || v(dom) == "-" { v(nom) } else { format!("{}\\{}", v(dom), v(nom)) };
    let nom_fichier = |p: &str| std::path::Path::new(p).file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    let mut e = Evenement { heure: heure_evenement(xml), source: "securite".into(), niveau: "Info".into(), ..Default::default() };
    match id {
        4624 => {
            if compte_systeme(&v("TargetUserSid"), &v("TargetUserName")) || matches!(v("LogonType").as_str(), "0" | "4" | "5") {
                return None;
            }
            e.type_ = "ouverture-session".into();
            e.utilisateur = compte("TargetDomainName", "TargetUserName");
            e.ip = ip_utile(&v("IpAddress"));
            e.processus = nom_fichier(&v("ProcessName"));
            e.message = format!("ouverture de session {} de {}{}", type_session(&v("LogonType")), e.utilisateur,
                if e.ip.is_empty() { String::new() } else { format!(" depuis {}", e.ip) });
        }
        4625 => {
            e.type_ = "echec-session".into();
            e.niveau = "Alerte".into();
            e.utilisateur = compte("TargetDomainName", "TargetUserName");
            e.ip = ip_utile(&v("IpAddress"));
            e.processus = nom_fichier(&v("ProcessName"));
            e.mitre = "T1110".into();
            e.message = format!("échec d'ouverture de session {} pour {}{}", type_session(&v("LogonType")), e.utilisateur,
                if e.ip.is_empty() { String::new() } else { format!(" depuis {}", e.ip) });
        }
        4634 => return None,
        4648 => {
            if compte_systeme(&v("SubjectUserSid"), &v("SubjectUserName")) {
                return None;
            }
            e.type_ = "identifiants-explicites".into();
            e.utilisateur = compte("SubjectDomainName", "SubjectUserName");
            e.processus = nom_fichier(&v("ProcessName"));
            e.destination = v("TargetServerName");
            e.message = format!("{} utilise les identifiants de {} vers {}", e.utilisateur, compte("TargetDomainName", "TargetUserName"), e.destination);
        }
        4672 => {
            if compte_systeme(&v("SubjectUserSid"), &v("SubjectUserName")) {
                return None;
            }
            e.type_ = "privileges-speciaux".into();
            e.utilisateur = compte("SubjectDomainName", "SubjectUserName");
            e.message = format!("session de {} avec privilèges administrateur", e.utilisateur);
        }
        4688 => {
            e.source = "processus".into();
            e.type_ = "processus-cree".into();
            e.utilisateur = if compte_systeme(&v("SubjectUserSid"), &v("SubjectUserName")) { String::new() } else { compte("SubjectDomainName", "SubjectUserName") };
            e.processus = nom_fichier(&v("NewProcessName"));
            e.pid = u32::from_str_radix(v("NewProcessId").trim_start_matches("0x"), 16).ok();
            let ligne = v("CommandLine");
            e.message = format!("{} lancé par {}{}", e.processus, nom_fichier(&v("ParentProcessName")),
                if ligne.is_empty() { String::new() } else { format!(" : {}", ligne.chars().take(400).collect::<String>()) });
        }
        4697 | 7045 => {
            e.type_ = "service-installe".into();
            let (nom, fichier) = if id == 7045 { (v("ServiceName"), v("ImagePath")) } else { (v("ServiceName"), v("ServiceFileName")) };
            e.source = if id == 7045 { "systeme".into() } else { "securite".into() };
            e.processus = nom.clone();
            e.destination = fichier.clone();
            e.mitre = "T1543.003".into();
            e.message = format!("service installé : {nom} ({fichier})");
        }
        4719 => {
            if v("SubjectUserSid") == "S-1-5-18" {
                return None;
            }
            e.type_ = "politique-audit-modifiee".into();
            e.niveau = "Alerte".into();
            e.utilisateur = compte("SubjectDomainName", "SubjectUserName");
            e.mitre = "T1562.002".into();
            e.message = format!("politique d'audit modifiée par {} ({})", e.utilisateur, v("SubcategoryGuid"));
        }
        4720 | 4722 | 4724 | 4725 | 4726 => {
            e.type_ = match id { 4720 => "compte-cree", 4722 => "compte-active", 4724 => "mot-de-passe-reinitialise", 4725 => "compte-desactive", _ => "compte-supprime" }.into();
            e.niveau = if id == 4720 { "Alerte".into() } else { "Info".into() };
            e.utilisateur = compte("SubjectDomainName", "SubjectUserName");
            e.destination = compte("TargetDomainName", "TargetUserName");
            if id == 4720 {
                e.mitre = "T1136.001".into();
            }
            e.message = format!("{} : {} (par {})", e.type_.replace('-', " "), e.destination, e.utilisateur);
        }
        4728 | 4732 | 4756 => {
            e.type_ = "ajout-groupe".into();
            e.utilisateur = compte("SubjectDomainName", "SubjectUserName");
            e.destination = v("TargetUserName");
            let membre = if v("MemberName").is_empty() || v("MemberName") == "-" { v("MemberSid") } else { v("MemberName") };
            if v("TargetSid") == SID_ADMINISTRATEURS {
                e.niveau = "Alerte".into();
                e.mitre = "T1098".into();
                e.type_ = "ajout-administrateurs".into();
            }
            e.message = format!("{membre} ajouté au groupe {} (par {})", e.destination, e.utilisateur);
            e.ip = String::new();
            e.processus = membre;
        }
        4740 => {
            e.type_ = "compte-verrouille".into();
            e.niveau = "Alerte".into();
            e.destination = v("TargetUserName");
            e.message = format!("compte verrouillé : {} (poste {})", e.destination, v("TargetDomainName"));
        }
        4798 => {
            // Énumération des groupes d'un utilisateur : très fréquent, n'est gardé que hors programmes Windows
            let p = v("CallerProcessName").to_lowercase();
            if p.contains(r"\windows\") || p.is_empty() || p == "-" {
                return None;
            }
            e.type_ = "enumeration-groupes".into();
            e.processus = nom_fichier(&v("CallerProcessName"));
            e.mitre = "T1069.001".into();
            e.message = format!("{} énumère les groupes de {}", e.processus, v("TargetUserName"));
        }
        1102 | 104 => {
            e.type_ = "journal-efface".into();
            e.niveau = "Critique".into();
            e.source = if id == 104 { "systeme".into() } else { "securite".into() };
            e.mitre = "T1070.001".into();
            e.message = if id == 104 { format!("journal « {} » effacé", v("Channel")) } else { "journal Sécurité effacé".into() };
        }
        7036 => {
            // Démarrage / arrêt de services : seulement deR4Tizer et les services de sécurité
            let nom = v("param1");
            let suivi = ["deR4Tizer", "Microsoft Defender Antivirus Service", "Windows Defender Firewall", "Windows Event Log", "Security Center"];
            if !suivi.iter().any(|s| nom.eq_ignore_ascii_case(s)) {
                return None;
            }
            e.source = "systeme".into();
            e.type_ = "etat-service".into();
            e.processus = nom.clone();
            let arret = v("param2").to_lowercase().contains("stop") || v("param2").to_lowercase().contains("arr");
            if arret && nom != "deR4Tizer" {
                e.niveau = "Alerte".into();
                e.mitre = "T1562.001".into();
            }
            e.message = format!("service {nom} : {}", v("param2"));
        }
        _ => return None,
    }
    Some(e)
}

// ------------------------------------------------------------ recherche

pub struct Filtre {
    /// texte cherché dans tout l'événement (sans tenir compte de la casse)
    pub texte: String,
    pub source: String,
    pub type_: String,
    pub niveau_min: String,
    /// bornes « AAAA-MM-JJ HH:MM:SS » (ou le début seulement : « AAAA-MM-JJ »)
    pub depuis: String,
    pub jusqua: String,
    pub limite: usize,
}

/// Événements correspondants, du plus récent au plus ancien
pub fn rechercher(f: &Filtre) -> Vec<Evenement> {
    let jour = |h: &str| h.chars().filter(|c| c.is_ascii_digit()).take(8).collect::<String>();
    let (jour_min, jour_max) = (jour(&f.depuis), jour(&f.jusqua));
    let mut fichiers: Vec<(String, PathBuf)> = fs::read_dir(dossier()).into_iter().flatten().flatten()
        .filter_map(|e| {
            let nom = e.file_name().to_string_lossy().to_string();
            let j = nom.strip_prefix("evenements-")?.strip_suffix(".ndjson")?.to_string();
            (jour_min.is_empty() || j >= jour_min).then_some(())?;
            (jour_max.is_empty() || j <= jour_max).then_some(())?;
            Some((j, e.path()))
        })
        .collect();
    fichiers.sort_by(|a, b| b.0.cmp(&a.0));
    let texte = f.texte.to_lowercase();
    let rang = crate::export::rang(&f.niveau_min);
    let mut sortie = Vec::new();
    for (_, chemin) in fichiers {
        // Propriétaire contrôlé, comme tout fichier du dossier de données
        let Some(contenu) = commun::lire_fichier_proprietaire(&chemin) else { continue };
        for ligne in contenu.lines().rev() {
            if !texte.is_empty() && !ligne.to_lowercase().contains(&texte) {
                continue;
            }
            let Ok(e) = serde_json::from_str::<Evenement>(ligne) else { continue };
            if (!f.source.is_empty() && e.source != f.source)
                || (!f.type_.is_empty() && e.type_ != f.type_)
                || crate::export::rang(&e.niveau) < rang
                || (!f.depuis.is_empty() && e.heure.as_str() < f.depuis.as_str())
                || (!f.jusqua.is_empty() && e.heure.as_str() > f.jusqua.as_str() && !e.heure.starts_with(f.jusqua.as_str()))
            {
                continue;
            }
            sortie.push(e);
            if sortie.len() >= f.limite {
                return sortie;
            }
        }
    }
    sortie
}

// ------------------------------------------------------------ écriture et corrélation

fn boucle(rx: Receiver<Evenement>, alertes: Arc<Mutex<Vec<Alerte>>>) {
    let mut correlation = Correlation::default();
    let mut incidents: Vec<Incident> = commun::lire("incidents.json").unwrap_or_default();
    let mut fichier: Option<(String, fs::File)> = None;
    let mut dernier_menage = Instant::now() - Duration::from_secs(86_400);
    let mut ecrits = 0u64;
    while let Ok(e) = rx.recv() {
        ecrits += 1;
        if ecrits == 1 || ecrits % 5000 == 0 {
            commun::journal(&format!("mini-SIEM : {ecrits} événement(s) enregistré(s) depuis le démarrage"));
        }
        // Fichier du jour de l'événement (AAAAMMJJ)
        let jour: String = e.heure.chars().filter(|c| c.is_ascii_digit()).take(8).collect();
        if jour.len() == 8 {
            if fichier.as_ref().map(|(j, _)| j != &jour).unwrap_or(true) {
                fichier = fs::OpenOptions::new().create(true).append(true)
                    .open(dossier().join(format!("evenements-{jour}.ndjson"))).ok().map(|f| (jour.clone(), f));
            }
            if let Some((_, f)) = fichier.as_mut() {
                if let Ok(ligne) = serde_json::to_string(&e) {
                    let _ = writeln!(f, "{ligne}");
                }
            }
        }
        let nouveaux = correlation.analyser(&e);
        if !nouveaux.is_empty() {
            for i in &nouveaux {
                commun::journal(&format!("incident {} : {} — {}", i.niveau, i.titre, i.resume));
                alertes.lock().unwrap().push(Alerte {
                    // Corrélation R<n> : règle COR-R<n> du registre
                    regle: regle_correlation(&i.regle),
                    id: commun::nouvel_id(),
                    heure: i.heure.clone(),
                    niveau: i.niveau.clone(),
                    score: if i.niveau == "Critique" { 10 } else { 5 },
                    processus: "corrélation".into(),
                    destination: format!("incident : {}", i.titre),
                    raisons: i.resume.clone(),
                    mitre: i.mitre.clone(),
                    ..Default::default()
                });
            }
            incidents.extend(nouveaux);
            if incidents.len() > 500 {
                let surplus = incidents.len() - 500;
                incidents.drain(..surplus);
            }
            let _ = commun::ecrire("incidents.json", &incidents);
        }
        if dernier_menage.elapsed() > Duration::from_secs(3600) {
            menage();
            dernier_menage = Instant::now();
        }
    }
}

/// Supprime les fichiers de plus de 30 jours, puis les plus anciens au-delà de 1 Go
fn menage() {
    let Ok(lecture) = fs::read_dir(dossier()) else { return };
    let mut fichiers: Vec<(String, u64, PathBuf)> = lecture
        .flatten()
        .filter_map(|f| {
            let nom = f.file_name().to_string_lossy().to_string();
            let jour = nom.strip_prefix("evenements-")?.strip_suffix(".ndjson")?.to_string();
            Some((jour, f.metadata().ok()?.len(), f.path()))
        })
        .collect();
    fichiers.sort();
    let limite: String = {
        let t = std::time::SystemTime::now() - Duration::from_secs(JOURS_CONSERVES * 86_400);
        commun::heure(t).chars().filter(|c| c.is_ascii_digit()).take(8).collect()
    };
    let mut total: u64 = fichiers.iter().map(|f| f.1).sum();
    for (jour, taille, chemin) in &fichiers {
        if jour.as_str() < limite.as_str() || total > TAILLE_MAX {
            if fs::remove_file(chemin).is_ok() {
                total -= taille;
            }
        }
    }
}

/// Moteur de corrélation : règles à fenêtre de temps, chaque incident n'est levé qu'une fois par clé et par heure
#[derive(Default)]
pub(crate) struct Correlation {
    echecs: HashMap<String, VecDeque<(Instant, String)>>,
    comptes_crees: HashMap<String, Instant>,
    alertes_processus: HashMap<String, VecDeque<(Instant, String, String)>>,
    deja: HashMap<String, Instant>,
}

impl Correlation {
    fn une_fois(&mut self, cle: String) -> bool {
        self.deja.retain(|_, t| t.elapsed() < Duration::from_secs(3600));
        if self.deja.contains_key(&cle) {
            return false;
        }
        self.deja.insert(cle, Instant::now());
        true
    }

    /// Incidents levés par un événement (testé : tests_detection.rs, COR-R1 à COR-R9)
    pub(crate) fn analyser(&mut self, e: &Evenement) -> Vec<Incident> {
        let mut sortie = Vec::new();
        let mut incident = |regle: &str, titre: &str, niveau: &str, mitre: &str, resume: String, evenements: Vec<String>| {
            sortie.push(Incident {
                id: commun::nouvel_id(),
                heure: e.heure.clone(),
                regle: regle.into(),
                titre: titre.into(),
                niveau: niveau.into(),
                mitre: mitre.into(),
                resume,
                evenements,
            });
        };
        let trace = |e: &Evenement| format!("{} [{}] {}", e.heure, e.source, e.message);

        match e.type_.as_str() {
            // R1 / R2 : force brute, puis réussite depuis la même source
            "echec-session" => {
                let cle = if e.ip.is_empty() { format!("compte {}", e.utilisateur) } else { e.ip.clone() };
                let file = self.echecs.entry(cle.clone()).or_default();
                file.push_back((Instant::now(), trace(e)));
                file.retain(|(t, _)| t.elapsed() < Duration::from_secs(1800));
                let recents: Vec<String> = file.iter().filter(|(t, _)| t.elapsed() < Duration::from_secs(300)).map(|(_, s)| s.clone()).collect();
                if recents.len() >= 5 && self.une_fois(format!("R1|{cle}")) {
                    incident("R1", "Tentatives de mot de passe en série", "Alerte", "T1110",
                        format!("{} échecs d'ouverture de session en 5 minutes ({cle})", recents.len()), recents.into_iter().rev().take(20).collect());
                }
            }
            "ouverture-session" => {
                for cle in [e.ip.clone(), format!("compte {}", e.utilisateur)] {
                    let Some(file) = self.echecs.get(&cle) else { continue };
                    let n = file.len();
                    let mut evts: Vec<String> = file.iter().map(|(_, s)| s.clone()).rev().take(19).collect();
                    if n >= 5 && self.une_fois(format!("R2|{cle}")) {
                        evts.insert(0, trace(e));
                        incident("R2", "Session ouverte après une série d'échecs", "Critique", "T1110",
                            format!("{} a ouvert une session après {n} échecs depuis la même source ({cle}) : mot de passe probablement deviné",
                                e.utilisateur), evts);
                    }
                }
                // R9 : bureau à distance ou session réseau depuis une adresse publique
                if !e.ip.is_empty() && e.ip.parse().map(|a| crate::parefeu::publique(&a)).unwrap_or(false) && self.une_fois(format!("R9|{}|{}", e.ip, e.utilisateur)) {
                    let rdp = e.message.contains("bureau à distance");
                    incident("R9", if rdp { "Bureau à distance ouvert depuis Internet" } else { "Session ouverte depuis Internet" },
                        if rdp { "Critique" } else { "Alerte" }, "T1133", e.message.clone(), vec![trace(e)]);
                }
            }
            // R3 : compte créé puis ajouté aux administrateurs
            "compte-cree" => {
                self.comptes_crees.retain(|_, t| t.elapsed() < Duration::from_secs(1800));
                self.comptes_crees.insert(e.destination.rsplit('\\').next().unwrap_or("").to_lowercase(), Instant::now());
            }
            "ajout-administrateurs" => {
                let membre = e.processus.rsplit('\\').next().unwrap_or("").to_lowercase();
                let nouveau = self.comptes_crees.keys().any(|c| !c.is_empty() && membre.contains(c.as_str()));
                if self.une_fois(format!("R3|{membre}")) {
                    if nouveau {
                        incident("R3", "Nouveau compte administrateur", "Critique", "T1136.001",
                            format!("un compte créé il y a moins de 30 minutes a été ajouté aux Administrateurs : {}", e.message), vec![trace(e)]);
                    } else {
                        incident("R3b", "Ajout au groupe Administrateurs", "Alerte", "T1098", e.message.clone(), vec![trace(e)]);
                    }
                }
            }
            // R4 : effacement d'un journal
            "journal-efface" => {
                if self.une_fois(format!("R4|{}", e.message)) {
                    incident("R4", "Journal d'événements effacé", "Critique", "T1070.001",
                        format!("{} : technique classique pour effacer les traces d'une intrusion", e.message), vec![trace(e)]);
                }
            }
            // R5 : service installé depuis un dossier inscriptible par l'utilisateur
            "service-installe" => {
                // R10 : pilote vulnérable connu (BYOVD), où qu'il soit sur le disque
                let image = crate::hygiene::chemin_image(&e.destination);
                if image.extension().map(|x| x.eq_ignore_ascii_case("sys")).unwrap_or(false) {
                    if let Some(h) = crate::hygiene::pilote_vulnerable(&image) {
                        if self.une_fois(format!("R10|{h}")) {
                            incident("R10", "Pilote vulnérable installé (BYOVD)", "Critique", "T1068",
                                format!("{} : ce pilote figure dans LOLDrivers (SHA-256 {}…) ; il sert à désactiver les antivirus depuis le noyau",
                                    e.message, &h[..16]), vec![trace(e)]);
                        }
                    }
                }
                let m = e.message.to_lowercase();
                let suspect = [r"\temp\", r"\appdata\", r"\users\public\", r"\downloads\", r"\téléchargements\", r"\programdata\"]
                    .iter().any(|d| m.contains(d)) || m.contains("powershell") || m.contains("cmd.exe /c") || m.contains("cmd /c");
                if suspect && self.une_fois(format!("R5|{}", e.processus)) {
                    incident("R5", "Service installé depuis un emplacement suspect", "Critique", "T1543.003",
                        format!("{} : les services légitimes s'installent dans Program Files ou Windows", e.message), vec![trace(e)]);
                }
            }
            // R7 : service de sécurité arrêté, politique d'audit modifiée
            "etat-service" | "politique-audit-modifiee" if e.niveau != "Info" => {
                if self.une_fois(format!("R7|{}", e.message)) {
                    incident("R7", "Protection affaiblie", "Alerte", &e.mitre.clone(), e.message.clone(), vec![trace(e)]);
                }
            }
            _ => {}
        }

        // R6 : un même programme déclenche au moins 3 détections différentes en 10 minutes (attaque en plusieurs étapes)
        if e.source == "alerte" && e.type_ != "incident" && !e.processus.is_empty() && e.niveau != "Info" {
            let cle = e.processus.to_lowercase();
            let file = self.alertes_processus.entry(cle.clone()).or_default();
            let detection = if e.mitre.is_empty() { e.message.split(':').next().unwrap_or("").to_string() } else { e.mitre.clone() };
            file.push_back((Instant::now(), detection, trace(e)));
            file.retain(|(t, _, _)| t.elapsed() < Duration::from_secs(600));
            let distinctes: HashSet<&String> = file.iter().map(|(_, d, _)| d).collect();
            if distinctes.len() >= 3 {
                let evts: Vec<String> = file.iter().map(|(_, _, s)| s.clone()).collect();
                let n = distinctes.len();
                if self.une_fois(format!("R6|{cle}")) {
                    incident("R6", "Attaque en plusieurs étapes", "Critique", "",
                        format!("{} a déclenché {n} détections différentes en 10 minutes", e.processus), evts);
                }
            }
        }
        sortie
    }
}
