//! Origine des processus : qui a lancé quoi, avec quelle ligne de commande.
//! Source principale : Sysmon s'il est installé (création de processus, requêtes DNS avec le programme
//! demandeur). Sinon : traces de démarrage de processus de WMI. Applique quelques règles de détection
//! inspirées de Sigma (document Office qui lance un interpréteur, PowerShell obscurci, LOLBins, rançongiciels).

use crate::collectes::{self, Collecte};
use crate::commun::{self, Alerte};
use crate::evenements;
use regex::Regex;
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::Path;
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
}

fn regles() -> &'static [(Regex, &'static str, &'static str)] {
    static R: OnceLock<Vec<(Regex, &'static str, &'static str)>> = OnceLock::new();
    R.get_or_init(|| {
        vec![
            (Regex::new(r"(?i)(powershell|pwsh).*(\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}|frombase64string|downloadstring|downloadfile|net\.webclient|invoke-expression|\biex\b.*(http|\$)|-w(indowstyle)?\s+h(idden)?.*(http|iex|-enc))").unwrap(),
             "PowerShell obscurci ou qui télécharge du code", crate::regles::PRC_002),
            (Regex::new(r"(?i)certutil.*(-urlcache|-decode|-f\s+http)|bitsadmin.*/transfer|mshta.*(http|javascript:|vbscript:)|regsvr32.*/i:http|rundll32.*javascript:|wmic.*process\s+call\s+create").unwrap(),
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
        ..Default::default()
    })
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
        }
    }

    /// Démarre l'écoute des créations de processus ; `sur_dns` reçoit les requêtes DNS vues par Sysmon
    pub fn demarrer(&self, sur_dns: impl Fn(&str, &str) + Send + 'static) {
        // Sysmon illisible maintenant : WMI à la place (abonner suivrait le journal quand même, sans source entre-temps)
        if evenements::journal_actif(JOURNAL_SYSMON) == Some(true) && evenements::lisible(JOURNAL_SYSMON) {
            let moi = self.clone();
            if evenements::abonner(JOURNAL_SYSMON, "*[System[(EventID=1 or EventID=22)]]", Collecte::Sysmon, move |xml| moi.traiter_sysmon(&xml, &sur_dns)) {
                *self.source.lock().unwrap() = "Sysmon".into();
                collectes::desactivee(Collecte::WmiProcessus, "inutile : Sysmon est lu");
                return;
            }
        } else if evenements::journal_actif(JOURNAL_SYSMON) == Some(true) {
            collectes::echec(Collecte::Sysmon, "journal Sysmon illisible au démarrage : WMI à la place");
        } else {
            collectes::desactivee(Collecte::Sysmon, "Sysmon absent ou son journal inactif");
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

    fn analyser(&self, pid: u32, p: &InfoProcessus) {
        if let Some(a) = alerte_processus(pid, p) {
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
