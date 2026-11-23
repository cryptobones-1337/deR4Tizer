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

/// Documents (PRC-001). olk : le nouvel Outlook (audit du 2026-11-23, A-7-8)
const BUREAUTIQUE: &[&str] = &["winword", "excel", "powerpnt", "outlook", "olk", "onenote", "msaccess", "mspub", "visio", "acrord32", "acrobat", "foxitpdfreader", "hwp"];
/// Programmes qu'un document piégé lance pour exécuter du code (PRC-001). Depuis A-7-8 (audit du 2026-11-23) : aide
/// compilée (hh), paquet MSI (msiexec), forfiles, cmstp, odbcconf, regasm, regsvcs, msxsl ; conhost n'y est pas
/// (Windows le crée pour toute console : faux positif Critique), justification de chacun dans la fiche PRC-001
const INTERPRETEURS: &[&str] = &[
    "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin", "msbuild",
    "installutil", "wmic", "schtasks", "curl", "bash", "hh", "msiexec", "forfiles", "cmstp", "odbcconf", "regasm", "regsvcs",
    "msxsl",
];

#[derive(Clone)]
pub struct InfoProcessus {
    pub image: String,
    pub ligne_commande: Option<String>,
    pub parent: Option<String>,
    /// Chemin complet du programme parent (pour l'apprentissage : le nom seul s'usurpe)
    pub parent_chemin: Option<String>,
    /// Nom d'origine du fichier (ressource de version), lu dans le champ OriginalFileName de Sysmon 1 : reconnaît une
    /// copie renommée de PowerShell (audit du 2026-11-23, A-7-1). Absent des 4688 et de WMI
    pub nom_origine: Option<String>,
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
            nom_origine: None,
            vu: Instant::now(),
        }
    }

    /// Même processus, avec le nom d'origine du fichier que Sysmon aurait lu
    pub(crate) fn avec_nom_origine(mut self, nom: &str) -> InfoProcessus {
        self.nom_origine = Some(nom.into());
        self
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

const NOM_PRC002: &str = "PowerShell obscurci ou qui télécharge du code";
const NOM_PRC003: &str = "détournement d'outil Windows (LOLBin)";
const NOM_PRC004: &str = "navigateur lancé en débogage à distance : technique de vol de cookies (contourne le chiffrement des navigateurs)";
const NOM_PRC005: &str = "suppression des sauvegardes (typique d'un rançongiciel)";

/// Motifs lus dans le texte de la ligne : PRC-002 (l'interpréteur PowerShell est cherché dans la ligne) et PRC-004 (le
/// navigateur est ancré sur son exécutable). PRC-003 et PRC-005 sont liés au programme lancé (`MOTIFS_PROGRAMMES`)
fn regles_texte() -> &'static (Regex, Regex) {
    static R: OnceLock<(Regex, Regex)> = OnceLock::new();
    R.get_or_init(|| {
        (
            Regex::new(&format!("(?i){INTERPRETEUR_PRC002}({})", MOTIFS_PRC002.iter().map(|(_, m, _)| *m).collect::<Vec<_>>().join("|"))).unwrap(),
            // Navigateurs Chromium (audit du 2026-11-23, A-7-9 : Vivaldi, Opera, Arc, Yandex dont le programme s'appelle
            // browser.exe, reconnu dans son seul dossier ; Chromium s'appelle chrome.exe). Firefox n'est pas retenu
            Regex::new(r#"(?i)((^|[\\/"\s])(chrome|msedge|brave|vivaldi|opera|arc)\.exe|\\yandexbrowser\\application\\browser\.exe)"?\s.*--remote-debugging-(port|pipe)"#).unwrap(),
        )
    })
}

/// Noms d'origine (ressource de version, champ OriginalFileName de Sysmon 1) de PowerShell : Windows PowerShell et
/// PowerShell 7 (pwsh.exe porte le nom d'origine de sa bibliothèque, pwsh.dll)
const NOMS_ORIGINE_POWERSHELL: &[&str] = &["powershell.exe", "pwsh.dll", "pwsh.exe", "powershell_ise.exe"];

/// Décision pure (testée) : ligne lue par les motifs. Copie renommée de PowerShell reconnue par son nom d'origine
/// (Sysmon) : la ligne est lue comme celle de PowerShell, préfixée de son nom (PRC-002 cherche l'interpréteur dans la
/// ligne) ; la ligne montrée dans l'alerte reste la vraie. Sans nom d'origine (4688, WMI) : la ligne seule (A-7-1)
pub(crate) fn ligne_pour_motifs(p: &InfoProcessus) -> Option<String> {
    let ligne = p.ligne_commande.as_deref()?;
    let powershell = p.nom_origine.as_deref().is_some_and(|n| NOMS_ORIGINE_POWERSHELL.iter().any(|x| x.eq_ignore_ascii_case(n.trim())));
    Some(if powershell { format!("powershell {ligne}") } else { ligne.to_string() })
}

/// Décision pure (testée) : nom d'un programme d'après un chemin, un mot de ligne de commande ou un nom d'origine :
/// dernier élément du chemin, sans guillemets, en minuscules, sans « .exe » ni « .dll » (pwsh.dll : nom d'origine de
/// pwsh.exe). Constat T-2 : les motifs de PRC-003 et PRC-005 sont liés à ce nom
pub(crate) fn nom_programme(jeton: &str) -> String {
    let base = jeton.trim().trim_matches(['"', '\'']).rsplit(['\\', '/']).next().unwrap_or("");
    let base = base.trim_matches(['"', '\'']).to_lowercase();
    base.strip_suffix(".exe").or_else(|| base.strip_suffix(".dll")).unwrap_or(&base).to_string()
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

/// Premier motif trouvé dans une ligne de commande, avec l'identifiant de sa règle (docs/detection/regles.md). Le
/// programme lancé est le premier mot de la ligne (commande d'un démarrage automatique, constat T-2)
pub fn suspicion_regle(ligne: &str) -> Option<(&'static str, &'static str)> {
    suspicions_regles(ligne).first().copied()
}

/// Tous les motifs trouvés dans une ligne de commande, dans l'ordre de la table, avec l'identifiant de leur règle ; le
/// programme lancé est le premier mot de la ligne (constat T-2)
pub fn suspicions_regles(ligne: &str) -> Vec<(&'static str, &'static str)> {
    suspicions_programme(&programmes_de_la_ligne(ligne), ligne)
}

/// Décision pure (testée) : motifs vus pour un programme (`programmes` : noms donnés par `nom_programme`, image et nom
/// d'origine) et sa ligne de commande, dans l'ordre PRC-002, PRC-003, PRC-004, PRC-005. PRC-002 et PRC-004 lisent la
/// ligne ; PRC-003 et PRC-005 seulement pour le programme visé ou l'outil qu'un interpréteur lance en tête (T-2)
pub(crate) fn suspicions_programme(programmes: &[String], ligne: &str) -> Vec<(&'static str, &'static str)> {
    let (prc002, prc004) = regles_texte();
    let vus = motifs_programme(programmes, ligne);
    let vu = |id: &str| vus.iter().any(|m| m.regle == id);
    let mut r = Vec::new();
    if prc002.is_match(ligne) {
        r.push((NOM_PRC002, crate::regles::PRC_002));
    }
    if vu(crate::regles::PRC_003) {
        r.push((NOM_PRC003, crate::regles::PRC_003));
    }
    if prc004.is_match(ligne) {
        r.push((NOM_PRC004, crate::regles::PRC_004));
    }
    if vu(crate::regles::PRC_005) {
        r.push((NOM_PRC005, crate::regles::PRC_005));
    }
    r
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
    let analysee = ligne_pour_motifs(p).unwrap_or_default();
    let programmes = programmes_du_processus(&p.image, p.nom_origine.as_deref());
    let motifs = suspicions_programme(&programmes, &analysee);
    raisons.extend(motifs.iter().map(|(r, _)| r.to_string()));
    if raisons.is_empty() {
        return None;
    }
    let ids: Vec<&'static str> = motifs.iter().map(|(_, id)| *id).collect();
    let regle = regle_retenue(document, &ids);
    let ligne = p.ligne_commande.clone().unwrap_or_default();
    let ligne: String = if ligne.chars().count() > 300 { ligne.chars().take(300).collect::<String>() + "…" } else { ligne };
    // Signaux forts, jamais adoucis : suppression des sauvegardes (étape juste avant un chiffrement),
    // document bureautique qui lance un interpréteur (macro ou exploit), vidage de la mémoire de LSASS par comsvcs.dll
    // (vol d'identifiants, A-7-7)
    let fort = document || ids.contains(&crate::regles::PRC_005) || (ids.contains(&crate::regles::PRC_003) && outils_programme(&programmes, &analysee).contains(&"comsvcs"));
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
        comportement: code_comportement_programme(document, &ids, &programmes, &analysee),
        // PRC-002 et PRC-003 : les techniques des motifs vus (règles à plusieurs comportements, posées par l'alerte)
        mitre: match regle {
            crate::regles::PRC_002 => technique_prc002(&analysee),
            crate::regles::PRC_003 => technique_prc003_programme(&programmes, &analysee),
            _ => String::new(),
        },
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

/// Décision pure (testée) : une entrée du cache décrit le programme qui tient la connexion. Chemins complets identiques
/// (casse ignorée) ; un nom seul (trace WMI sans chemin) ou un chemin vide ne se vérifient pas : faux (constat T-2)
pub(crate) fn meme_programme(image_du_cache: &str, chemin: &str) -> bool {
    let (a, b) = (image_du_cache.trim(), chemin.trim());
    !a.is_empty() && a.contains('\\') && a.eq_ignore_ascii_case(b)
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
        nom_origine: meme.and_then(|i| i.nom_origine.clone()),
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

/// PRC-002 : interpréteur qui précède les motifs (le motif de la règle est cet interpréteur suivi de la réunion des motifs)
const INTERPRETEUR_PRC002: &str = r"(powershell|pwsh).*";

/// PRC-002 : (code du comportement, motif de la ligne de commande, techniques ATT&CK). T1027 Code obscurci ne vient que
/// des motifs d'obscurcissement ; un téléchargement, l'exécution d'une chaîne ou une fenêtre cachée portent T1059.001
/// seul (revue externe du 2026-11-22, point mineur : « code obscurci » sur un simple téléchargement).
/// Audit du 2026-11-23, A-7-1 : `obscurci` reconnaît toute abréviation de -EncodedCommand que PowerShell accepte (-e,
/// -ec, -en, -enc, -enco…, préfixe « - », « / » ou tiret typographique, charge entre guillemets) ; `telecharge`
/// reconnaît iex avec un téléchargement dans l'ordre qu'on veut, et irm, iwr, Invoke-WebRequest, Invoke-RestMethod ou
/// Start-BitsTransfer suivis d'une adresse http(s). Motifs sans imbrication de répétitions (crate regex : temps linéaire)
const MOTIFS_PRC002: &[(&str, &str, &[&str])] = &[
    ("obscurci", r#"\s[-/\x{2013}\x{2014}\x{2015}]e(?:c|n[a-z]*)?\s+["']?[A-Za-z0-9+/=]{40,}|frombase64string"#, &["T1059.001", "T1027"]),
    ("telecharge", concat!(
        r"downloadstring|downloadfile|net\.webclient|invoke-expression",
        r"|\biex\b.*(?:http|\$|\b(?:irm|iwr|invoke-webrequest|invoke-restmethod|start-bitstransfer)\b)",
        r"|(?:https?://|\b(?:irm|iwr|invoke-webrequest|invoke-restmethod|start-bitstransfer)\b).*\biex\b",
        r"|\b(?:irm|iwr|invoke-webrequest|invoke-restmethod|start-bitstransfer)\b.*https?://",
        r"|-w(?:indowstyle)?\s+h(?:idden)?.*(?:http|iex|-enc)"), &["T1059.001"]),
];

fn motifs_prc002() -> &'static [(Regex, &'static str, &'static [&'static str])] {
    static M: OnceLock<Vec<(Regex, &'static str, &'static [&'static str])>> = OnceLock::new();
    M.get_or_init(|| MOTIFS_PRC002.iter().map(|(c, m, t)| (Regex::new(&format!("(?i){INTERPRETEUR_PRC002}(?:{m})")).unwrap(), *c, *t)).collect())
}

/// Codes des motifs PRC-002 qui correspondent, dans l'ordre de la table (`obscurci`, `telecharge`)
pub(crate) fn codes_prc002(ligne: &str) -> Vec<&'static str> {
    motifs_prc002().iter().filter(|(r, _, _)| r.is_match(ligne)).map(|(_, c, _)| *c).collect()
}

/// Décision pure (testée) : techniques ATT&CK d'une alerte PRC-002, celles de chaque motif qui correspond (sans doublon,
/// dans l'ordre de la table, séparées par « / ») ; vide sinon
pub(crate) fn technique_prc002(ligne: &str) -> String {
    let mut t: Vec<&str> = Vec::new();
    for (_, _, ids) in motifs_prc002().iter().filter(|(r, _, _)| r.is_match(ligne)) {
        for id in ids.iter() {
            if !t.contains(id) {
                t.push(id);
            }
        }
    }
    t.join(" / ")
}

/// Portée d'un motif de PRC-003 ou PRC-005. Constat T-2 (2026-11-23) : ces motifs se levaient sur tout programme dont
/// la ligne contenait leurs mots (bash qui lance git, grep ou echo avec « vssadmin delete shadows » en argument)
#[derive(Clone, Copy, PartialEq)]
enum Portee {
    /// Ligne du programme nommé (image, ou nom d'origine du fichier lu par Sysmon), ou commande que cmd, PowerShell ou
    /// pwsh lance en tête (`commandes_en_tete`)
    Programme,
    /// Ligne entière d'un interpréteur nommé : motif propre à cet interpréteur (clichés supprimés par WMI ou CIM depuis
    /// PowerShell, texte passé à diskshadow par un tube ou un fichier écrit dans la même ligne)
    Interpreteur,
}

/// Motif de PRC-003 ou de PRC-005, lié aux programmes qui le font
pub(crate) struct MotifProgramme {
    pub regle: &'static str,
    /// Code de l'outil (PRC-003 : code de comportement `PRC-003:<outils vus>`)
    pub code: &'static str,
    /// Noms des programmes (`nom_programme`) dont la ligne est lue
    programmes: &'static [&'static str],
    portee: Portee,
    motif: &'static str,
    /// Technique ATT&CK de ce que l'outil fait (PRC-003) ; vide pour PRC-005 (T1490, fixée par la règle)
    pub technique: &'static str,
}

const fn motif(regle: &'static str, code: &'static str, programmes: &'static [&'static str], portee: Portee, motif: &'static str,
               technique: &'static str) -> MotifProgramme {
    MotifProgramme { regle, code, programmes, portee, motif, technique }
}

const POWERSHELLS: &[&str] = &["powershell", "pwsh", "powershell_ise"];

/// PRC-003 et PRC-005, liés au programme lancé (constat T-2) : le motif n'est lu que sur la ligne de ce programme
/// (reconnu par le nom de son image, ou par le nom d'origine du fichier que donne Sysmon pour une copie renommée), ou
/// sur la commande qu'un interpréteur Windows lance en tête ; un texte en argument d'un autre programme n'alerte pas.
/// La copie renommée d'un outil sans Sysmon (4688, WMI : pas de nom d'origine) est un angle mort déclaré.
/// PRC-003 : l'outil et sa technique viennent du motif qui a correspondu, jamais d'un nom vu ailleurs dans la ligne
/// (revue de l'auditeur du 2026-11-22, point 1 : certutil ne porte plus T1047). Audit du 2026-11-23, A-7-7 : certutil
/// qui récupère une adresse par -f ou -verifyctl, mshta et regsvr32 sur un chemin réseau (UNC) ou avec « -i: »,
/// rundll32 d'une DLL d'un dossier où l'utilisateur écrit (T1218.011), vidage de la mémoire d'un processus par
/// comsvcs.dll lancé par rundll32 (LSASS, T1003.001, signal fort), paquet MSI installé depuis une adresse http(s)
/// (T1218.007 ; un paquet local ou sur un partage, déploiement ordinaire, n'est pas visé).
/// PRC-005 : suppression des clichés ou des sauvegardes, et démarrage sans récupération. Depuis A-7-3 (audit du
/// 2026-11-23) : clichés supprimés par WMI ou CIM depuis PowerShell, espace des clichés réduit à moins de 1 000 Mo
/// (Windows efface alors les clichés ; une taille en Go, en % ou illimitée n'est pas visée), `wbadmin delete backup`,
/// `bootstatuspolicy ignoreallfailures`, et diskshadow dont la ligne dit `delete shadows` (diskshadow /s seul : le
/// script n'est pas lu, la ligne ne dit pas s'il supprime)
const MOTIFS_PROGRAMMES: &[MotifProgramme] = &[
    motif(crate::regles::PRC_003, "certutil", &["certutil"], Portee::Programme, r"[-/](?:urlcache|decode)|[-/](?:verifyctl|f)\b.*https?://", "T1105"),
    motif(crate::regles::PRC_003, "bitsadmin", &["bitsadmin"], Portee::Programme, r"/transfer", "T1197"),
    motif(crate::regles::PRC_003, "mshta", &["mshta"], Portee::Programme, r"http|javascript:|vbscript:|\\\\", "T1218"),
    motif(crate::regles::PRC_003, "regsvr32", &["regsvr32"], Portee::Programme, r"[/-]i:\s*(?:http|\\\\)", "T1218"),
    motif(crate::regles::PRC_003, "rundll32", &["rundll32"], Portee::Programme, r"javascript:", "T1218"),
    motif(crate::regles::PRC_003, "rundll32_dll", &["rundll32"], Portee::Programme, r"(?:\\users\\public\\|\\appdata\\|\\temp\\|\\programdata\\)[^,]*\.dll", "T1218.011"),
    motif(crate::regles::PRC_003, "comsvcs", &["rundll32"], Portee::Programme, r"comsvcs.*(?:minidump|#\s*\+?0*24\b)", "T1003.001"),
    motif(crate::regles::PRC_003, "msiexec", &["msiexec"], Portee::Programme, r"https?://", "T1218.007"),
    motif(crate::regles::PRC_003, "wmic", &["wmic"], Portee::Programme, r"process\s+call\s+create", "T1047"),
    motif(crate::regles::PRC_005, "vssadmin", &["vssadmin"], Portee::Programme, r"delete\s+shadows", ""),
    motif(crate::regles::PRC_005, "vssadmin_taille", &["vssadmin"], Portee::Programme, r#"resize\s+shadowstorage.*/maxsize=\d{1,3}(?:mb|kb|b)?(?:[\s"]|$)"#, ""),
    motif(crate::regles::PRC_005, "wbadmin", &["wbadmin"], Portee::Programme, r"delete\s+(?:catalog|systemstatebackup|backup)", ""),
    motif(crate::regles::PRC_005, "bcdedit", &["bcdedit"], Portee::Programme, r"recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures", ""),
    motif(crate::regles::PRC_005, "wmic_cliches", &["wmic"], Portee::Programme, r"shadowcopy\s+delete", ""),
    motif(crate::regles::PRC_005, "diskshadow", &["diskshadow"], Portee::Programme, r"delete\s+shadows", ""),
    motif(crate::regles::PRC_005, "powershell_wmi", POWERSHELLS, Portee::Interpreteur, r"win32_shadowcopy.*(?:remove-(?:wmiobject|ciminstance)|\.delete\(\))", ""),
    // Texte passé à diskshadow lancé après un séparateur (tube, ou script écrit puis lu par /s dans la même ligne)
    motif(crate::regles::PRC_005, "diskshadow_texte", &["cmd", "powershell", "pwsh"], Portee::Interpreteur,
          r#"delete\s+shadows.*[|&]\s*["']?(?:[^\s"'|&]*[\\/])?diskshadow(?:\.exe)?(?:[\s"']|$)"#, ""),
];

fn motifs_programmes() -> &'static [(Regex, &'static MotifProgramme)] {
    static M: OnceLock<Vec<(Regex, &'static MotifProgramme)>> = OnceLock::new();
    M.get_or_init(|| MOTIFS_PROGRAMMES.iter().map(|m| (Regex::new(&format!("(?i){}", m.motif)).unwrap(), m)).collect())
}

/// Noms (`nom_programme`) d'un processus : son image, et le nom d'origine du fichier lu par Sysmon (copie renommée)
pub(crate) fn programmes_du_processus(image: &str, nom_origine: Option<&str>) -> Vec<String> {
    let mut v = vec![nom_programme(image)];
    if let Some(o) = nom_origine.map(nom_programme).filter(|o| !o.is_empty() && !v.contains(o)) {
        v.push(o);
    }
    v
}

/// Programme d'une ligne de commande seule (commande d'un démarrage automatique, tests) : son premier mot
fn programmes_de_la_ligne(ligne: &str) -> Vec<String> {
    programme_en_tete(ligne).map(|(p, _)| vec![p]).unwrap_or_default()
}

/// Option qui passe une commande à PowerShell : -Command et toutes ses abréviations (-c, -co…), préfixe « - », « / »
/// ou tiret typographique
fn option_commande_powershell(jeton: &str) -> bool {
    let j = jeton.to_lowercase();
    j.strip_prefix(['-', '/', '\u{2013}', '\u{2014}', '\u{2015}']).is_some_and(|r| !r.is_empty() && "command".starts_with(r))
}

/// Texte qui suit l'option de commande de l'interpréteur (cmd : /c, /k ou /r, éventuellement collée à un guillemet ;
/// PowerShell : -Command abrégée ou non), ou rien
fn apres_option_commande(segment: &str, cmd: bool) -> Option<&str> {
    let mut reste = segment;
    loop {
        let t = reste.trim_start();
        if t.is_empty() {
            return None;
        }
        let fin = t.find(char::is_whitespace).unwrap_or(t.len());
        let jeton = t.get(..fin)?;
        if cmd {
            let j = jeton.as_bytes();
            let option = j.first() == Some(&b'/') && j.get(1).is_some_and(|b| matches!(b.to_ascii_lowercase(), b'c' | b'k' | b'r'));
            if option && (j.len() == 2 || j.get(2) == Some(&b'"')) {
                return t.get(2..);
            }
        } else if option_commande_powershell(jeton) {
            return t.get(fin..);
        }
        reste = t.get(fin..)?;
    }
}

/// Programme en tête d'une commande (`nom_programme` de son premier mot, chemin entre guillemets compris) et le texte
/// de la commande à partir de ce mot ; `call` et `start` (et ses options /x) sont sautés
fn programme_en_tete(commande: &str) -> Option<(String, &str)> {
    let mut c = commande;
    for _ in 0..4 {
        let t = c.trim_start_matches(|x: char| x.is_whitespace() || matches!(x, '@' | '{' | '"' | '\''));
        let guillemet = c.get(..c.len() - t.len()).is_some_and(|p| p.contains(['"', '\'']));
        let fin_mot = t.find(|x: char| x.is_whitespace() || matches!(x, '"' | '\'' | ')')).unwrap_or(t.len());
        let fin_guillemet = t.find(['"', '\'']).unwrap_or(t.len());
        // Chemin entre guillemets (avec des espaces) : jusqu'au guillemet s'il nomme un .exe ; sinon (« cmd /c "vssadmin
        // delete shadows" ») jusqu'au premier blanc
        let exe = t.get(..fin_guillemet).is_some_and(|e| e.to_ascii_lowercase().ends_with(".exe"));
        let fin = if guillemet && exe { fin_guillemet } else { fin_mot };
        let jeton = t.get(..fin).filter(|j| !j.is_empty())?;
        let suite = t.get(fin..).unwrap_or("");
        match nom_programme(jeton).as_str() {
            "call" => c = suite,
            "start" => {
                let mut s = suite.trim_start();
                while s.starts_with('/') {
                    s = s.get(s.find(char::is_whitespace).unwrap_or(s.len())..).unwrap_or("").trim_start();
                }
                c = s;
            }
            nom => return Some((nom.to_string(), t)),
        }
    }
    None
}

/// Décision pure (testée) : commandes qu'un interpréteur Windows lance en tête : le programme (`nom_programme`) et le
/// texte de sa commande, jusqu'au séparateur suivant. Têtes : après l'option de commande (cmd /c, /k ou /r ; PowerShell
/// -Command ou une abréviation), puis après chaque séparateur & | ; ( ou fin de ligne. Les guillemets ne sont pas
/// interprétés : un séparateur entre guillemets coupe aussi (sens prudent : `cmd /c "a & b"` lance bien b)
pub(crate) fn commandes_en_tete(ligne: &str, cmd: bool) -> Vec<(String, &str)> {
    let mut tetes = Vec::new();
    let mut debut = 0;
    let mut premier = true;
    for (i, c) in ligne.char_indices().chain(std::iter::once((ligne.len(), '\n'))) {
        if !matches!(c, '&' | '|' | ';' | '(' | '\n' | '\r') {
            continue;
        }
        let segment = ligne.get(debut..i).unwrap_or("");
        let commande = if premier { apres_option_commande(segment, cmd) } else { Some(segment) };
        if let Some(t) = commande.and_then(programme_en_tete) {
            tetes.push(t);
        }
        premier = false;
        debut = i + c.len_utf8();
    }
    tetes
}

/// Décision pure (testée) : motifs de PRC-003 et PRC-005 vus pour un programme (noms de son image et de son nom
/// d'origine) et sa ligne, dans l'ordre de la table. Programme visé : sa ligne. cmd, PowerShell ou pwsh : leur ligne
/// pour leurs motifs propres, et chaque commande lancée en tête pour le motif de son programme (en plus de l'alerte du
/// processus enfant, que Windows crée aussi : défense en profondeur quand le processus bref est manqué par WMI)
pub(crate) fn motifs_programme(programmes: &[String], ligne: &str) -> Vec<&'static MotifProgramme> {
    let est = |noms: &[&str]| programmes.iter().any(|p| noms.contains(&p.as_str()));
    let tetes = if est(&["cmd"]) {
        commandes_en_tete(ligne, true)
    } else if est(&["powershell", "pwsh"]) {
        commandes_en_tete(ligne, false)
    } else {
        Vec::new()
    };
    motifs_programmes()
        .iter()
        .filter(|(r, m)| {
            (est(m.programmes) && r.is_match(ligne))
                || (m.portee == Portee::Programme && tetes.iter().any(|(p, t)| m.programmes.contains(&p.as_str()) && r.is_match(t)))
        })
        .map(|(_, m)| *m)
        .collect()
}

/// Outils de PRC-003 vus pour un programme et sa ligne, dans l'ordre de la table
pub(crate) fn outils_programme(programmes: &[String], ligne: &str) -> Vec<&'static str> {
    motifs_programme(programmes, ligne).iter().filter(|m| m.regle == crate::regles::PRC_003).map(|m| m.code).collect()
}

/// Tous les outils dont le motif PRC-003 correspond, dans l'ordre de la table (prérelecture de #258, remarque : le code
/// de comportement nomme chaque outil vu, comme les techniques) ; programme : le premier mot de la ligne (T-2)
#[cfg(test)]
pub(crate) fn outils_lolbin(ligne: &str) -> Vec<&'static str> {
    outils_programme(&programmes_de_la_ligne(ligne), ligne)
}

/// Décision pure (testée) : techniques ATT&CK d'une alerte PRC-003, celles de chaque outil dont le motif correspond
/// (sans doublon, dans l'ordre de la table, séparées par « / ») ; vide sinon (prérelecture de #258, réserve 1)
pub(crate) fn technique_prc003_programme(programmes: &[String], ligne: &str) -> String {
    let mut t: Vec<&str> = Vec::new();
    for m in motifs_programme(programmes, ligne).iter().filter(|m| m.regle == crate::regles::PRC_003) {
        if !t.contains(&m.technique) {
            t.push(m.technique);
        }
    }
    t.join(" / ")
}

/// Même décision, le programme étant le premier mot de la ligne
#[cfg(test)]
pub(crate) fn technique_prc003(ligne: &str) -> String {
    technique_prc003_programme(&programmes_de_la_ligne(ligne), ligne)
}

/// Décision pure (testée) : code stable du comportement d'une alerte de processus (empreinte des exceptions) : document
/// qui lance un interpréteur, règles des motifs vus (triées), les motifs vus pour PRC-002 et l'outil pour PRC-003
#[cfg(test)]
pub(crate) fn code_comportement(document: bool, ids: &[&'static str], ligne: &str) -> String {
    code_comportement_programme(document, ids, &programmes_de_la_ligne(ligne), ligne)
}

/// Même code, pour un programme connu (image et nom d'origine) : l'outil de PRC-003 vient de ce programme (T-2)
pub(crate) fn code_comportement_programme(document: bool, ids: &[&'static str], programmes: &[String], ligne: &str) -> String {
    let mut c: Vec<String> = Vec::new();
    if document { c.push("document".into()); }
    let mut r: Vec<&str> = ids.to_vec();
    r.sort_unstable();
    r.dedup();
    for id in r {
        if id == crate::regles::PRC_003 {
            c.push(format!("{id}:{}", outils_programme(programmes, ligne).join(",")));
        } else if id == crate::regles::PRC_002 {
            c.push(format!("{id}:{}", codes_prc002(ligne).join(",")));
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
                    nom_origine: None,
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

    /// Infos du processus `pid` dont le programme est `chemin` (chemin complet, celui qui tient la connexion) : depuis le
    /// cache (Sysmon, 4688 ou trace), sinon interrogation WMI. Une entrée d'un autre programme (PID réutilisé, entrée
    /// gardée une heure) n'est jamais prêtée ; chemin inconnu : rien (constat T-2, cause établie par T-1 : la ligne
    /// d'un ancien cmd sous le même PID donnait « PowerShell obscurci » à une connexion de gh)
    pub fn infos(&self, pid: u32, chemin: &str) -> Option<InfoProcessus> {
        let cache = self.infos.lock().unwrap().get(&pid).cloned();
        if let Some(i) = cache.filter(|i| meme_programme(&i.image, chemin)) {
            return Some(i);
        }
        self.interroger(pid).filter(|i| meme_programme(&i.image, chemin))
    }

    fn interroger(&self, pid: u32) -> Option<InfoProcessus> {
        let r = requete(&format!("SELECT ExecutablePath, CommandLine, ParentProcessId FROM Win32_Process WHERE ProcessId = {pid}"))?;
        let o = r.first()?;
        let info = InfoProcessus {
            image: texte(o, "ExecutablePath").unwrap_or_default(),
            ligne_commande: texte(o, "CommandLine"),
            parent: nombre(o, "ParentProcessId").and_then(nom_de),
            parent_chemin: nombre(o, "ParentProcessId").map(crate::natif::chemin_processus).filter(|c| !c.is_empty()),
            nom_origine: None,
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
            nom_origine: d.get("OriginalFileName").map(|s| s.trim()).filter(|s| !s.is_empty() && *s != "-").map(String::from),
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
