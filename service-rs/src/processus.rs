//! Origine des processus : qui a lancé quoi, avec quelle ligne de commande.
//! Source principale : Sysmon s'il est installé (création de processus, requêtes DNS avec le programme
//! demandeur). Sinon : événements 4688 du journal Sécurité (audit des créations de processus, lus même pour un
//! processus déjà terminé), puis traces de démarrage de processus de WMI. Applique quelques règles de détection
//! inspirées de Sigma (document Office qui lance un interpréteur, PowerShell obscurci, LOLBins, rançongiciels).

use crate::collectes::{self, Collecte, Note};
use crate::commun::{self, Alerte};
use crate::evenements;
use regex::Regex;
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use wmi::{COMLibrary, Variant, WMIConnection};

const JOURNAL_SYSMON: &str = "Microsoft-Windows-Sysmon/Operational";

const BUREAUTIQUE: &[&str] = &["winword", "excel", "powerpnt", "outlook", "onenote", "msaccess", "mspub", "visio", "acrord32", "acrobat", "foxitpdfreader", "hwp"];
const INTERPRETEURS: &[&str] = &[
    "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin", "msbuild",
    "installutil", "wmic", "schtasks", "curl", "bash",
];

#[derive(Clone)]
pub struct InfoProcessus {
    pub image: String,
    pub ligne_commande: Option<String>,
    pub parent: Option<String>,
    /// Chemin complet du programme parent (pour l'apprentissage : le nom seul s'usurpe)
    pub parent_chemin: Option<String>,
    vu: Instant,
}

#[cfg(test)]
impl InfoProcessus {
    /// Processus synthétique pour les tests des règles (tests_detection.rs)
    pub(crate) fn pour_test(image: &str, ligne_commande: Option<&str>, parent_chemin: Option<&str>) -> InfoProcessus {
        InfoProcessus {
            image: image.into(),
            ligne_commande: ligne_commande.map(Into::into),
            parent: parent_chemin.map(|p| Path::new(p).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default()),
            parent_chemin: parent_chemin.map(Into::into),
            vu: Instant::now(),
        }
    }
}

#[derive(Clone)]
pub struct Processus {
    infos: Arc<Mutex<HashMap<u32, InfoProcessus>>>,
    pub detections: Arc<Mutex<Vec<Alerte>>>,
    pub source: Arc<Mutex<String>>,
    /// État de l'audit des créations de processus (`Note` en u8) : décide qui analyse, l'audit ou WMI
    audit: Arc<AtomicU8>,
    /// Alertes de processus déjà levées (PID, programme, règle) : une seule par création, quelle que soit la source
    signales: Arc<Mutex<HashMap<(u32, String, String), Instant>>>,
    /// Créations vues par l'audit, pour l'arbre des chaînes (vidées par le moniteur à chaque cycle)
    pub creations: Arc<Mutex<std::collections::VecDeque<Creation4688>>>,
    /// 4688 lus avec et sans ligne de commande depuis le dernier relevé de l'état de l'audit
    lignes: Arc<Mutex<(u32, u32)>>,
    /// Un 4688 est arrivé alors que l'audit était noté inactif : l'état est relu sans attendre les 5 min (la baseline
    /// active l'audit juste après l'installation ; la page Santé disait « non activé » jusqu'au relevé suivant)
    reveil: Arc<AtomicBool>,
}

fn regles() -> &'static [(Regex, &'static str, &'static str)] {
    static R: OnceLock<Vec<(Regex, &'static str, &'static str)>> = OnceLock::new();
    R.get_or_init(|| {
        vec![
            (Regex::new(r"(?i)(powershell|pwsh).*(\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}|frombase64string|downloadstring|downloadfile|net\.webclient|invoke-expression|\biex\b.*(http|\$)|-w(indowstyle)?\s+h(idden)?.*(http|iex|-enc))").unwrap(),
             "PowerShell obscurci ou qui télécharge du code", crate::regles::PRC_002),
            (Regex::new(&format!("(?i){}", OUTILS_PRC003.iter().map(|(_, m, _)| *m).collect::<Vec<_>>().join("|"))).unwrap(),
             "détournement d'outil Windows (LOLBin)", crate::regles::PRC_003),
            (Regex::new(r#"(?i)(^|[\\/"\s])(chrome|msedge|brave)\.exe"?\s.*--remote-debugging-(port|pipe)"#).unwrap(),
             "navigateur lancé en débogage à distance : technique de vol de cookies (contourne le chiffrement des navigateurs)", crate::regles::PRC_004),
            (Regex::new(r"(?i)vssadmin.*delete\s+shadows|wbadmin.*delete\s+(catalog|systemstatebackup)|bcdedit.*recoveryenabled\s+no|wmic.*shadowcopy\s+delete").unwrap(),
             "suppression des sauvegardes (typique d'un rançongiciel)", crate::regles::PRC_005),
        ]
    })
}

pub fn suspicion(ligne: &str) -> Option<&'static str> {
    suspicion_regle(ligne).map(|(n, _)| n)
}

/// Règle portée par une alerte de processus (décision pure, testée) : la plus forte qu'elle contient. Le document qui
/// lance un interpréteur (PRC-001), puis la suppression des sauvegardes (PRC-005), puis le premier motif de la ligne de
/// commande (PR 3.7 : une ligne qui télécharge du code et supprime les sauvegardes porte PRC-005, au niveau Critique)
pub fn regle_retenue(document_interpreteur: bool, motifs: &[&'static str]) -> &'static str {
    if document_interpreteur {
        crate::regles::PRC_001
    } else if motifs.contains(&crate::regles::PRC_005) {
        crate::regles::PRC_005
    } else {
        motifs.first().copied().unwrap_or("")
    }
}

/// Premier motif trouvé dans une ligne de commande, avec l'identifiant de sa règle (docs/detection/regles.md)
pub fn suspicion_regle(ligne: &str) -> Option<(&'static str, &'static str)> {
    regles().iter().find(|(r, _, _)| r.is_match(ligne)).map(|(_, n, id)| (*n, *id))
}

/// Tous les motifs trouvés dans une ligne de commande, dans l'ordre de la table, avec l'identifiant de leur règle
pub fn suspicions_regles(ligne: &str) -> Vec<(&'static str, &'static str)> {
    regles().iter().filter(|(r, _, _)| r.is_match(ligne)).map(|(_, n, id)| (*n, *id)).collect()
}

/// Alerte d'un processus qui vient de démarrer (décision pure, testée : docs/detection/regles.md, PRC-001 à PRC-005), ou
/// rien. Document bureautique qui lance un interpréteur, et motifs de la ligne de commande ; signaux forts (document,
/// suppression des sauvegardes) au niveau Critique, jamais adoucis
pub(crate) fn alerte_processus(pid: u32, p: &InfoProcessus) -> Option<Alerte> {
    let exe = Path::new(&p.image).file_stem().map(|s| s.to_string_lossy().to_lowercase()).unwrap_or_default();
    let mut raisons = Vec::new();
    let mut document = false;
    if let Some(parent) = &p.parent {
        let pb = parent.to_lowercase();
        if BUREAUTIQUE.contains(&pb.as_str()) && INTERPRETEURS.contains(&exe.as_str()) {
            raisons.push(format!("document {parent} qui lance {exe} (macro ou exploit probable)"));
            document = true;
        }
    }
    let motifs = p.ligne_commande.as_deref().map(suspicions_regles).unwrap_or_default();
    raisons.extend(motifs.iter().map(|(r, _)| r.to_string()));
    if raisons.is_empty() {
        return None;
    }
    let ids: Vec<&'static str> = motifs.iter().map(|(_, id)| *id).collect();
    let regle = regle_retenue(document, &ids);
    let ligne = p.ligne_commande.clone().unwrap_or_default();
    let ligne: String = if ligne.chars().count() > 300 { ligne.chars().take(300).collect::<String>() + "…" } else { ligne };
    // Signaux forts, jamais adoucis : suppression des sauvegardes (étape juste avant un chiffrement),
    // document bureautique qui lance un interpréteur (macro ou exploit)
    let fort = document || ids.contains(&crate::regles::PRC_005);
    Some(Alerte {
        regle: regle.into(),
        id: commun::nouvel_id(),
        heure: commun::maintenant(),
        niveau: if fort { "Critique" } else { "Alerte" }.into(),
        score: if fort { 10 } else { 5 },
        parent: p.parent_chemin.clone().unwrap_or_default(),
        processus: exe,
        chemin: p.image.clone(),
        destination: format!("lancé par {}", p.parent.as_deref().unwrap_or("?")),
        raisons: format!("{} : {ligne}", raisons.join(", ")),
        pid: Some(pid),
        comportement: code_comportement(document, &ids, p.ligne_commande.as_deref().unwrap_or("")),
        // PRC-003 : la technique de l'outil vu (règle à plusieurs comportements, posée par l'alerte)
        mitre: if regle == crate::regles::PRC_003 { technique_prc003(p.ligne_commande.as_deref().unwrap_or("")).to_string() } else { String::new() },
        ..Default::default()
    })
}

/// Création de processus lue dans un événement 4688 du journal Sécurité (audit des créations de processus)
#[derive(Clone, Debug, PartialEq)]
pub struct Creation4688 {
    pub pid: u32,
    pub image: String,
    pub ligne_commande: Option<String>,
    /// Processus créateur (champ ProcessId du 4688)
    pub ppid: Option<u32>,
    pub parent_image: Option<String>,
}

/// Longueur gardée d'une ligne de commande (Windows : 32 767 caractères au plus)
pub(crate) const LIGNE_MAX: usize = 32_768;

/// Sous-catégorie « Audit Process Creation » (baseline, `audit.processus`)
const GUID_AUDIT_PROCESSUS: &str = "{0CCE922B-69AE-11D9-BED3-505054503030}";

/// Décision pure (testée) : PID d'un 4688, que Windows écrit en hexadécimal préfixé (« 0x1a2c »). Sans préfixe, vide,
/// nul, trop long ou avec un caractère qui n'est pas hexadécimal : None
pub(crate) fn pid_4688(v: &str) -> Option<u32> {
    let v = v.trim();
    let h = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X"))?;
    if h.is_empty() || h.len() > 8 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(h, 16).ok().filter(|p| *p != 0)
}

fn champ(d: &HashMap<String, String>, cle: &str) -> Option<String> {
    d.get(cle).map(|s| s.trim()).filter(|s| !s.is_empty()).map(String::from)
}

/// Décision pure (testée) : champs d'un 4688 (rendus par `evenements::donnees`). Sans PID lisible ni programme : None.
/// Ligne de commande vide ou absente (réglage « ligne de commande dans les 4688 » coupé) : None ; très longue : bornée
pub(crate) fn lire_4688(d: &HashMap<String, String>) -> Option<Creation4688> {
    let pid = pid_4688(d.get("NewProcessId")?)?;
    let image = champ(d, "NewProcessName")?;
    Some(Creation4688 {
        pid,
        image,
        ligne_commande: champ(d, "CommandLine").map(|l| if l.chars().count() > LIGNE_MAX { l.chars().take(LIGNE_MAX).collect() } else { l }),
        ppid: d.get("ProcessId").and_then(|p| pid_4688(p)),
        parent_image: champ(d, "ParentProcessName"),
    })
}

/// Décision pure (testée) : source publiée sans Sysmon, l'audit (4688) s'il est actif ou partiel, sinon WMI. Les deux
/// sources analysent toujours chaque création (aucune fenêtre sans analyse quand l'audit est coupé ou le journal
/// Sécurité bloqué, prérelecture de #244, D1) ; `deja_signale` fusionne leurs doublons
pub(crate) fn audit_analyse(note_audit: u8) -> bool {
    note_audit == Note::Active as u8 || note_audit == Note::Partielle as u8
}

fn nom_fichier_min(chemin: &str) -> String {
    Path::new(chemin).file_name().map(|s| s.to_string_lossy().to_lowercase()).unwrap_or_default()
}

fn nom_sans_extension(chemin: &str) -> String {
    Path::new(chemin).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default()
}

/// Décision pure (testée) : description d'un processus d'après son 4688. Une ligne de commande absente du 4688 est prise
/// dans le cache (trace WMI, lue pendant que le processus vivait), seulement si le cache décrit le même programme
pub(crate) fn info_depuis_4688(c: &Creation4688, cache: Option<&InfoProcessus>) -> InfoProcessus {
    // Cache récent seulement : une ligne d'un ancien processus du même PID n'est jamais prêtée (audit de #244, S244-06)
    let meme = cache.filter(|i| nom_fichier_min(&i.image) == nom_fichier_min(&c.image) && i.vu.elapsed() < Duration::from_secs(120));
    let parent_chemin = c.parent_image.clone().or_else(|| meme.and_then(|i| i.parent_chemin.clone()));
    InfoProcessus {
        image: c.image.clone(),
        ligne_commande: c.ligne_commande.clone().or_else(|| meme.and_then(|i| i.ligne_commande.clone())),
        parent: parent_chemin.as_deref().map(nom_sans_extension).or_else(|| meme.and_then(|i| i.parent.clone())),
        parent_chemin,
        vu: Instant::now(),
    }
}

/// Fenêtre de fusion des doublons : la trace WMI et le 4688 d'une même création arrivent à quelques secondes d'écart
/// (journal relu toutes les 2 s) ; au-delà, une création nouvelle sous le même PID alerte (prérelecture de #244, D2)
const DUREE_SIGNALE: Duration = Duration::from_secs(30);

/// Décision pure (testée) : une seule alerte par création de processus et par règle, quelle que soit la source (trace
/// WMI et 4688 d'une même création). Vrai si ce PID a levé la même règle pour le même programme depuis moins de 30 s ;
/// sinon la création est notée. Une règle plus forte vue par l'autre source (ligne de commande du 4688 absente de la
/// trace WMI) alerte quand même. Table bornée : pleine, l'alerte part sans être notée (jamais de silence)
pub(crate) fn deja_signale(vus: &mut HashMap<(u32, String, String), Instant>, pid: u32, image: &str, regle: &str, maintenant: Instant) -> bool {
    vus.retain(|_, t| maintenant.saturating_duration_since(*t) < DUREE_SIGNALE);
    let cle = (pid, nom_fichier_min(image), regle.to_string());
    if vus.contains_key(&cle) {
        return true;
    }
    if vus.len() < 10_000 {
        vus.insert(cle, maintenant);
    }
    false
}

/// Décision pure (testée) : état de la collecte « audit des créations de processus ». Le repli sur WMI est toujours
/// dit ; jamais « rien de suspect » quand l'audit manque. Non activé (la baseline n'a pas été appliquée) : désactivée,
/// comme Sysmon absent ; coupé après avoir été actif : indisponible. Poste géré (baseline en lecture seule) : dit
pub(crate) fn note_audit(journal_lu: bool, audit: Option<u32>, ligne_reglee: bool, lignes: (u32, u32), deja_actif: bool,
    gestion: &dyn Fn() -> Option<String>) -> (Note, String) {
    const REPLI: &str = "les créations de processus passent par WMI (processus brefs manqués, PRC-001 à PRC-005 dégradées)";
    let avec_gestion = |r: String| match gestion() {
        Some(g) => format!("{r} ; {g}"),
        None => r,
    };
    if !journal_lu {
        return (Note::Indisponible, format!("journal Sécurité illisible : {REPLI}"));
    }
    let Some(a) = audit else {
        return (Note::Indisponible, format!("réglage de l'audit des créations de processus illisible : {REPLI}"));
    };
    if a & 1 == 0 {
        return if deja_actif {
            (Note::Indisponible, avec_gestion(format!("audit des créations de processus coupé : {REPLI}")))
        } else {
            (Note::Desactivee, avec_gestion(format!("audit des créations de processus non activé (profil « journalisation » de la baseline) : {REPLI}")))
        };
    }
    let (avec, sans) = lignes;
    if !ligne_reglee || (sans > 0 && avec == 0) {
        return (Note::Partielle, avec_gestion("ligne de commande absente des événements 4688 : PRC-002 à PRC-005 la prennent dans WMI (processus brefs manqués)".into()));
    }
    (Note::Active, String::new())
}

/// Réglage « ligne de commande dans les événements 4688 » (baseline, `journal.ligne-commande`)
fn ligne_commande_reglee() -> bool {
    winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit")
        .and_then(|k| k.get_value::<u32, _>("ProcessCreationIncludeCmdLine_Enabled"))
        .is_ok_and(|v| v != 0)
}

/// PRC-003 : (outil, motif de la ligne de commande, technique ATT&CK de ce que l'outil fait). Le motif de la règle est la
/// réunion de ces motifs : l'outil et sa technique viennent du motif qui a correspondu, jamais d'un nom vu ailleurs dans
/// la ligne (revue de l'auditeur du 2026-11-22, point 1 : certutil ne porte plus T1047)
const OUTILS_PRC003: &[(&str, &str, &str)] = &[
    ("certutil", r"certutil.*(-urlcache|-decode|-f\s+http)", "T1105"),
    ("bitsadmin", r"bitsadmin.*/transfer", "T1197"),
    ("mshta", r"mshta.*(http|javascript:|vbscript:)", "T1218"),
    ("regsvr32", r"regsvr32.*/i:http", "T1218"),
    ("rundll32", r"rundll32.*javascript:", "T1218"),
    ("wmic", r"wmic.*process\s+call\s+create", "T1047"),
];

fn motifs_outils() -> &'static [(Regex, &'static str, &'static str)] {
    static M: OnceLock<Vec<(Regex, &'static str, &'static str)>> = OnceLock::new();
    M.get_or_init(|| OUTILS_PRC003.iter().map(|(o, m, t)| (Regex::new(&format!("(?i){m}")).unwrap(), *o, *t)).collect())
}

/// Outil Windows détourné dont le motif PRC-003 correspond à la ligne de commande (premier de la table) ; vide sinon
pub(crate) fn outil_lolbin(ligne: &str) -> &'static str {
    motifs_outils().iter().find(|(r, _, _)| r.is_match(ligne)).map(|(_, o, _)| *o).unwrap_or("")
}

/// Décision pure (testée) : technique ATT&CK d'une alerte PRC-003, celle de l'outil vu ; vide sinon
pub(crate) fn technique_prc003(ligne: &str) -> &'static str {
    motifs_outils().iter().find(|(r, _, _)| r.is_match(ligne)).map(|(_, _, t)| *t).unwrap_or("")
}

/// Décision pure (testée) : code stable du comportement d'une alerte de processus (empreinte des exceptions) : document
/// qui lance un interpréteur, règles des motifs vus (triées), et l'outil pour PRC-003
pub(crate) fn code_comportement(document: bool, ids: &[&'static str], ligne: &str) -> String {
    let mut c: Vec<String> = Vec::new();
    if document { c.push("document".into()); }
    let mut r: Vec<&str> = ids.to_vec();
    r.sort_unstable();
    r.dedup();
    for id in r {
        if id == crate::regles::PRC_003 {
            c.push(format!("{id}:{}", outil_lolbin(ligne)));
        } else {
            c.push(id.to_string());
        }
    }
    c.join("+")
}

thread_local! {
    static CONNEXION_WMI: RefCell<Option<WMIConnection>> = const { RefCell::new(None) };
}

/// Requête WMI sur le fil courant (la connexion est créée une fois par fil)
fn requete(sql: &str) -> Option<Vec<HashMap<String, Variant>>> {
    CONNEXION_WMI.with(|c| {
        let mut c = c.borrow_mut();
        if c.is_none() {
            let com = COMLibrary::without_security().ok()?;
            *c = WMIConnection::new(com).ok();
        }
        c.as_ref()?.raw_query(sql).ok()
    })
}

fn texte(o: &HashMap<String, Variant>, cle: &str) -> Option<String> {
    match o.get(cle) {
        Some(Variant::String(s)) => Some(s.clone()),
        _ => None,
    }
}

fn nombre(o: &HashMap<String, Variant>, cle: &str) -> Option<u32> {
    match o.get(cle) {
        Some(Variant::UI4(n)) => Some(*n),
        Some(Variant::I4(n)) => Some(*n as u32),
        Some(Variant::UI8(n)) => Some(*n as u32),
        Some(Variant::I8(n)) => Some(*n as u32),
        _ => None,
    }
}

impl Processus {
    pub fn nouveau() -> Processus {
        Processus {
            infos: Arc::new(Mutex::new(HashMap::new())),
            detections: Arc::new(Mutex::new(Vec::new())),
            source: Arc::new(Mutex::new("aucune".into())),
            audit: Arc::new(AtomicU8::new(Note::Inconnue as u8)),
            signales: Arc::new(Mutex::new(HashMap::new())),
            creations: Arc::new(Mutex::new(std::collections::VecDeque::new())),
            lignes: Arc::new(Mutex::new((0, 0))),
            reveil: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Démarre l'écoute des créations de processus ; `sur_dns` reçoit les requêtes DNS vues par Sysmon. Sysmon s'il est
    /// lu ; sinon l'audit (4688) et WMI analysent tous deux chaque création, doublons fusionnés
    pub fn demarrer(&self, journaux_windows: bool, sur_dns: impl Fn(&str, &str) + Send + 'static) {
        // Sysmon illisible maintenant : WMI à la place (abonner suivrait le journal quand même, sans source entre-temps)
        if evenements::journal_actif(JOURNAL_SYSMON) == Some(true) && evenements::lisible(JOURNAL_SYSMON) {
            let moi = self.clone();
            if evenements::abonner(JOURNAL_SYSMON, "*[System[(EventID=1 or EventID=22)]]", Collecte::Sysmon, move |xml| moi.traiter_sysmon(&xml, &sur_dns)) {
                *self.source.lock().unwrap() = "Sysmon".into();
                collectes::desactivee(Collecte::WmiProcessus, "inutile : Sysmon est lu");
                collectes::desactivee(Collecte::AuditProcessus, "inutile : Sysmon est lu");
                return;
            }
        } else if evenements::journal_actif(JOURNAL_SYSMON) == Some(true) {
            collectes::echec(Collecte::Sysmon, "journal Sysmon illisible au démarrage : WMI à la place");
        } else {
            collectes::desactivee(Collecte::Sysmon, "Sysmon absent ou son journal inactif");
        }
        if journaux_windows {
            self.demarrer_audit();
        } else {
            collectes::desactivee(Collecte::AuditProcessus, "mode console : journal Sécurité non lu");
        }
        let moi = self.clone();
        let _ = std::thread::Builder::new().name("traces de processus".into()).spawn(move || {
            let Ok(com) = COMLibrary::without_security() else {
                collectes::echec(Collecte::WmiProcessus, "COM indisponible");
                return;
            };
            let Ok(con) = WMIConnection::new(com) else {
                collectes::echec(Collecte::WmiProcessus, "connexion WMI impossible");
                return;
            };
            let flux = match con.raw_notification::<HashMap<String, Variant>>("SELECT * FROM Win32_ProcessStartTrace") {
                Ok(f) => f,
                Err(e) => {
                    commun::journal(&format!("traces de processus WMI indisponibles : {e}"));
                    collectes::echec(Collecte::WmiProcessus, "abonnement WMI aux créations de processus refusé");
                    return;
                }
            };
            *moi.source.lock().unwrap() = "WMI".into();
            // WMI ne décrit (parent, ligne de commande) qu'un processus encore vivant : PRC-001 à PRC-005 peuvent
            // manquer un processus bref
            collectes::partielle(Collecte::WmiProcessus, "WMI : processus brefs manqués (parent ou ligne de commande absents)");
            for evenement in flux.flatten() {
                let (Some(pid), Some(ppid)) = (nombre(&evenement, "ProcessID"), nombre(&evenement, "ParentProcessID")) else { continue };
                let mut info = moi.interroger(pid).unwrap_or(InfoProcessus {
                    image: texte(&evenement, "ProcessName").unwrap_or_default(),
                    ligne_commande: None,
                    parent: None,
                    parent_chemin: None,
                    vu: Instant::now(),
                });
                if info.parent.is_none() {
                    info.parent = nom_de(ppid);
                }
                if info.parent_chemin.is_none() {
                    info.parent_chemin = Some(crate::natif::chemin_processus(ppid)).filter(|c| !c.is_empty());
                }
                // Toujours analysée, même audit actif : un audit coupé ou un journal Sécurité bloqué ne laisse aucune
                // fenêtre sans analyse (prérelecture de #244, D1) ; le 4688 de la même création est fusionné
                moi.analyser(pid, &info);
            }
            // Flux terminé : plus aucune création de processus n'est vue
            commun::journal("traces de processus WMI interrompues");
            collectes::echec(Collecte::WmiProcessus, "flux WMI des créations de processus interrompu");
            *moi.source.lock().unwrap() = "aucune".into();
        });
        // La source passe à « WMI » dès que l'abonnement est établi ; on lui laisse un instant
        std::thread::sleep(Duration::from_millis(500));
    }

    /// Infos d'un processus : depuis le cache (Sysmon ou trace), sinon interrogation WMI
    pub fn infos(&self, pid: u32) -> Option<InfoProcessus> {
        if let Some(i) = self.infos.lock().unwrap().get(&pid) {
            return Some(i.clone());
        }
        self.interroger(pid)
    }

    fn interroger(&self, pid: u32) -> Option<InfoProcessus> {
        let r = requete(&format!("SELECT ExecutablePath, CommandLine, ParentProcessId FROM Win32_Process WHERE ProcessId = {pid}"))?;
        let o = r.first()?;
        let info = InfoProcessus {
            image: texte(o, "ExecutablePath").unwrap_or_default(),
            ligne_commande: texte(o, "CommandLine"),
            parent: nombre(o, "ParentProcessId").and_then(nom_de),
            parent_chemin: nombre(o, "ParentProcessId").map(crate::natif::chemin_processus).filter(|c| !c.is_empty()),
            vu: Instant::now(),
        };
        self.infos.lock().unwrap().insert(pid, info.clone());
        Some(info)
    }

    fn traiter_sysmon(&self, xml: &str, sur_dns: &dyn Fn(&str, &str)) {
        let d = evenements::donnees(xml);
        if xml.contains("<EventID>22</EventID>") {
            if let (Some(n), Some(r)) = (d.get("QueryName"), d.get("QueryResults")) {
                sur_dns(n, r);
            }
            return;
        }
        let Some(pid) = d.get("ProcessId").and_then(|p| p.parse::<u32>().ok()) else { return };
        let info = InfoProcessus {
            image: d.get("Image").cloned().unwrap_or_default(),
            ligne_commande: d.get("CommandLine").cloned(),
            parent: d.get("ParentImage").map(|p| Path::new(p).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default()),
            parent_chemin: d.get("ParentImage").cloned(),
            vu: Instant::now(),
        };
        self.infos.lock().unwrap().insert(pid, info.clone());
        self.analyser(pid, &info);
    }

    /// Audit des créations de processus (4688, journal Sécurité), lu par son propre abonnement. Son état, relu toutes
    /// les 5 min (réglage d'audit effectif, ligne de commande, lignes vues), décide qui analyse : l'audit s'il est actif
    /// ou partiel, sinon WMI ; le repli est dit dans la raison de la collecte
    fn demarrer_audit(&self) {
        let moi = self.clone();
        if !evenements::abonner("Security", "*[System[(EventID=4688)]]", Collecte::JournalSecurite, move |xml| moi.traiter_4688(&xml)) {
            collectes::echec(Collecte::AuditProcessus, "abonnement au journal Sécurité impossible : les créations de processus passent par WMI");
            return;
        }
        let moi = self.clone();
        let _ = std::thread::Builder::new().name("audit des processus".into()).spawn(move || {
            let mut deja_actif = false;
            loop {
                let lignes = std::mem::take(&mut *moi.lignes.lock().unwrap());
                let (note, raison) = note_audit(evenements::lisible("Security"), crate::gpo::audit_effectif(GUID_AUDIT_PROCESSUS),
                    ligne_commande_reglee(), lignes, deja_actif, &crate::baseline::gestion);
                deja_actif |= matches!(note, Note::Active | Note::Partielle);
                moi.audit.store(note as u8, Ordering::Relaxed);
                match note {
                    Note::Active => collectes::succes(Collecte::AuditProcessus),
                    Note::Partielle => collectes::partielle(Collecte::AuditProcessus, &raison),
                    Note::Desactivee => collectes::desactivee(Collecte::AuditProcessus, &raison),
                    _ => collectes::echec(Collecte::AuditProcessus, &raison),
                }
                // 5 min, ou plus tôt si un 4688 contredit l'état noté (une relecture par minute au plus : auditpol est un
                // processus lancé à chaque relevé)
                let debut = Instant::now();
                while debut.elapsed() < Duration::from_secs(300) {
                    std::thread::sleep(Duration::from_secs(5));
                    if debut.elapsed() >= Duration::from_secs(60) && moi.reveil.swap(false, Ordering::Relaxed) {
                        break;
                    }
                }
            }
        });
    }

    /// Un 4688 : la création va à l'arbre des chaînes (un processus bref y garde son parent) et elle est analysée (la
    /// trace WMI de la même création, si elle a déjà alerté pour la même règle, est fusionnée)
    pub(crate) fn traiter_4688(&self, xml: &str) {
        let Some(c) = lire_4688(&evenements::donnees(xml)) else { return };
        {
            let mut l = self.lignes.lock().unwrap();
            if c.ligne_commande.is_some() { l.0 = l.0.saturating_add(1) } else { l.1 = l.1.saturating_add(1) }
        }
        if !audit_analyse(self.audit.load(Ordering::Relaxed)) {
            self.reveil.store(true, Ordering::Relaxed);
        }
        {
            let mut v = self.creations.lock().unwrap();
            if v.len() >= 5_000 {
                v.pop_front();
            }
            // Copie pour l'arbre : ligne bornée (l'analyse, elle, lit la ligne entière ; audit de #244, S244-04)
            let mut pour_arbre = c.clone();
            pour_arbre.ligne_commande = pour_arbre.ligne_commande.map(|l| l.chars().take(1024).collect());
            v.push_back(pour_arbre);
        }
        let cache = self.infos.lock().unwrap().get(&c.pid).cloned();
        let info = info_depuis_4688(&c, cache.as_ref());
        self.analyser(c.pid, &info);
        // Cache (origine des connexions, gardé une heure) : ligne bornée à 8 192 caractères (audit de #244, S244-04)
        let mut garde = info;
        garde.ligne_commande = garde.ligne_commande.map(|l| l.chars().take(8192).collect());
        self.infos.lock().unwrap().insert(c.pid, garde);
    }

    /// Source publiée dans etat.json : l'audit quand il analyse, sinon la source notée (Sysmon, WMI ou aucune)
    pub fn source_publiee(&self) -> String {
        if audit_analyse(self.audit.load(Ordering::Relaxed)) { "Audit 4688".into() } else { self.source.lock().unwrap().clone() }
    }

    #[cfg(test)]
    pub(crate) fn reveil_demande_test(&self) -> bool {
        self.reveil.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn regler_audit_test(&self, note: Note) {
        self.audit.store(note as u8, Ordering::Relaxed);
    }

    pub(crate) fn analyser(&self, pid: u32, p: &InfoProcessus) {
        if let Some(a) = alerte_processus(pid, p) {
            if deja_signale(&mut self.signales.lock().unwrap(), pid, &p.image, &a.regle, Instant::now()) {
                return;
            }
            self.detections.lock().unwrap().push(a);
        }
    }

    pub fn nettoyer(&self) {
        self.infos.lock().unwrap().retain(|_, i| i.vu.elapsed() < Duration::from_secs(3600));
    }
}

fn nom_de(pid: u32) -> Option<String> {
    crate::natif::processus().remove(&pid).map(|p| p.nom)
}
