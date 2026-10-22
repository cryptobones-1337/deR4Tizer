//! Origine des fichiers et actions de réponse :
//!   - origine : marque « Mark of the Web » posée par Windows sur les fichiers téléchargés (flux Zone.Identifier),
//!     âge du fichier ;
//!   - réponse : tuer, suspendre ou reprendre un processus, mettre un fichier en quarantaine (et le restaurer),
//!     isoler un programme du réseau, mode panique (tout le trafic sortant bloqué sauf Windows).

use crate::blocage;
use crate::commun;
use crate::natif::{self, large};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use windows::core::{BSTR, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, VARIANT_TRUE};
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, NetFwPolicy2, NetFwRule, NET_FW_ACTION_BLOCK, NET_FW_PROFILE2_DOMAIN,
    NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC, NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT,
};
use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE};

// ------------------------------------------------------------ origine des fichiers

#[derive(Clone, Default)]
pub struct Origine {
    /// 3 = Internet, 4 = sites non fiables
    pub zone: u32,
    pub source: String,
    pub age_jours: u64,
}

/// Lit la marque « téléchargé depuis Internet » (flux de données alternatif Zone.Identifier) et l'âge du fichier
pub fn origine(chemin: &str) -> Option<Origine> {
    if chemin.is_empty() {
        return None;
    }
    let age_jours = fs::metadata(chemin)
        .and_then(|m| m.created())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .map(|d| d.as_secs() / 86400)
        .unwrap_or(9999);
    let mut o = Origine { age_jours, ..Default::default() };
    if let Ok(t) = fs::read_to_string(format!("{chemin}:Zone.Identifier")) {
        for l in t.lines() {
            if let Some(z) = l.strip_prefix("ZoneId=") {
                o.zone = z.trim().parse().unwrap_or(0);
            } else if let Some(u) = l.strip_prefix("HostUrl=") {
                o.source = u.trim().to_string();
            } else if let Some(u) = l.strip_prefix("ReferrerUrl=") {
                if o.source.is_empty() {
                    o.source = u.trim().to_string();
                }
            }
        }
    }
    Some(o)
}

impl Origine {
    pub fn texte(&self) -> Option<String> {
        if self.zone < 3 {
            return None;
        }
        let source = if self.source.is_empty() { "Internet".to_string() } else { self.source.chars().take(120).collect() };
        Some(format!("téléchargé depuis {source}{}", if self.age_jours < 2 { " (il y a moins de 2 jours)" } else { "" }))
    }
}

// ------------------------------------------------------------ processus

/// Processus dont l'arrêt ou la suspension fige ou fait planter Windows (vérifiés : binaire de Windows)
const CRITIQUES: &[&str] = &[
    "csrss", "wininit", "winlogon", "lsass", "lsaiso", "services", "smss", "svchost", "dwm", "fontdrvhost", "registry",
    "memory compression", "secure system", "msmpeng", "mpdefendercoreservice", "explorer",
];

/// Raison de refuser d'agir sur ce processus, s'il y en a une
pub fn protege(pid: u32) -> Option<String> {
    if pid <= 4 || pid == std::process::id() {
        return Some("processus du système ou de deR4Tizer".into());
    }
    let chemin = natif::chemin_processus(pid);
    let nom = Path::new(&chemin).file_stem().map(|s| s.to_string_lossy().to_lowercase()).unwrap_or_default();
    (CRITIQUES.contains(&nom.as_str()) && natif::binaire_windows(&chemin))
        .then(|| format!("{nom} est un processus critique de Windows (le système ou le réseau se figerait)"))
}

pub fn tuer(pid: u32) -> Result<(), String> {
    if let Some(r) = protege(pid) {
        return Err(format!("refusé : {r}"));
    }
    unsafe {
        let h = OpenProcess(PROCESS_TERMINATE, false, pid).map_err(|e| e.to_string())?;
        let r = TerminateProcess(h, 1).map_err(|e| e.to_string());
        let _ = CloseHandle(h);
        r
    }
}

/// Suspend ou reprend tous les fils d'un processus (fonctions NtSuspendProcess / NtResumeProcess de ntdll)
pub fn suspendre(pid: u32, suspendre: bool) -> Result<(), String> {
    if suspendre {
        if let Some(r) = protege(pid) {
            return Err(format!("refusé : {r}"));
        }
    }
    unsafe {
        let nom = large("ntdll.dll");
        let module = LoadLibraryW(PCWSTR(nom.as_ptr())).map_err(|e| e.to_string())?;
        let fonction = if suspendre { windows::core::s!("NtSuspendProcess") } else { windows::core::s!("NtResumeProcess") };
        let f = GetProcAddress(module, fonction).ok_or("fonction introuvable")?;
        let f: extern "system" fn(windows::Win32::Foundation::HANDLE) -> i32 = std::mem::transmute(f);
        let h = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid).map_err(|e| e.to_string())?;
        let statut = f(h);
        let _ = CloseHandle(h);
        if statut == 0 { Ok(()) } else { Err(format!("statut NT 0x{statut:08X}")) }
    }
}

// ------------------------------------------------------------ quarantaine

#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq)]
#[serde(rename_all = "PascalCase", default)]
pub struct ElementQuarantaine {
    pub id: String,
    pub chemin_origine: String,
    pub date: String,
    pub raison: String,
    pub taille: u64,
    /// Nom du fichier dans quarantaine\ (vide : « <id>.quarantaine », éléments d'avant la 4.3)
    pub fichier: String,
    /// Empreinte SHA-256 de la copie, vérifiée à la restauration (vide : élément pas encore migré)
    pub sha256: String,
    /// « en_cours », « terminee » ou « restauree » (vide : éléments d'avant la 4.3, terminés)
    pub etat: String,
    /// Marque Internet de l'original (flux Zone.Identifier), réécrite à la restauration
    pub zone_identifier: String,
}

/// État d'un élément de quarantaine (transaction)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EtatQuarantaine {
    /// Copie faite et enregistrée, original pas encore supprimé
    EnCours,
    Terminee,
    /// Fichier restauré et vérifié, copie pas encore retirée
    Restauree,
}

impl ElementQuarantaine {
    pub fn nom_fichier(&self) -> String {
        if self.fichier.is_empty() { format!("{}.quarantaine", self.id) } else { self.fichier.clone() }
    }

    pub fn etat(&self) -> EtatQuarantaine {
        match self.etat.as_str() {
            "en_cours" => EtatQuarantaine::EnCours,
            "restauree" => EtatQuarantaine::Restauree,
            _ => EtatQuarantaine::Terminee,
        }
    }

    fn marquer(&mut self, etat: EtatQuarantaine) {
        self.etat = match etat {
            EtatQuarantaine::EnCours => "en_cours",
            EtatQuarantaine::Terminee => "terminee",
            EtatQuarantaine::Restauree => "restauree",
        }.into();
    }
}

/// Copie en quarantaine : fichier créé par le service avec ses droits (propriétaire SYSTEM, SYSTEM et
/// administrateurs seulement), jamais lisible par les comptes autorisés. Un déplacement garderait le
/// propriétaire d'origine (l'utilisateur) : la copie serait écartée au démarrage suivant.
pub const SDDL_QUARANTAINE: &str = "O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)";

/// Écriture du manifeste (quarantaine.json en service ; injectée dans les tests pour simuler un échec)
pub type EcrireManifeste<'a> = &'a dyn Fn(&[ElementQuarantaine]) -> Result<(), String>;

fn dossier_quarantaine() -> PathBuf {
    commun::dossier().join("quarantaine")
}

/// Marque Internet (flux Zone.Identifier) d'un fichier, 4 Ko au plus ; vide s'il n'en a pas
pub fn lire_marque_internet(chemin: &Path) -> String {
    use std::io::Read;
    let mut t = String::new();
    if let Ok(f) = fs::File::open(format!("{}:Zone.Identifier", chemin.display())) {
        let _ = f.take(4096).read_to_string(&mut t);
    }
    t
}

fn ecrire_marque_internet(chemin: &Path, marque: &str) -> Result<(), String> {
    if marque.is_empty() {
        return Ok(());
    }
    fs::write(format!("{}:Zone.Identifier", chemin.display()), marque).map_err(|e| format!("marque Internet : {e}"))
}

/// Copie protégée de `source` dans `dossier`, empreinte relue. Renvoie (nom du fichier, empreinte)
fn copier_verifie(dossier: &Path, source: &Path, fichier: &str, sddl: &str) -> Result<String, String> {
    fs::create_dir_all(dossier).map_err(|e| e.to_string())?;
    let copie = dossier.join(fichier);
    let sha = natif::copier_protege(source, &copie, sddl)?;
    if crate::hygiene::empreinte_fichier(&copie).is_none_or(|h| !h.eq_ignore_ascii_case(&sha)) {
        let _ = fs::remove_file(&copie);
        return Err("copie en quarantaine illisible ou différente de l'original".into());
    }
    Ok(sha)
}

/// Mise en quarantaine transactionnelle : copie protégée vérifiée, entrée « en_cours » ENREGISTRÉE, puis
/// seulement suppression de l'original, puis « terminee ». Échec d'enregistrement : copie retirée, original
/// intact. Original impossible à supprimer : entrée et copie retirées, original intact. Échec du dernier
/// enregistrement : l'original est déjà supprimé, la copie est en place ; la reprise au démarrage termine.
pub fn quarantaine_transaction(dossier: &Path, liste: &mut Vec<ElementQuarantaine>, source: &Path, id: &str, raison: &str,
                               sddl: &str, ecrire: EcrireManifeste) -> Result<(), String> {
    let fichier = format!("{id}.quarantaine");
    let zone_identifier = lire_marque_internet(source);
    let taille = fs::metadata(source).map(|m| m.len()).unwrap_or(0);
    let sha256 = copier_verifie(dossier, source, &fichier, sddl)?;
    let copie = dossier.join(&fichier);
    let mut e = ElementQuarantaine { id: id.into(), chemin_origine: source.display().to_string(), date: commun::maintenant(),
        raison: raison.into(), taille, fichier, sha256, zone_identifier, ..Default::default() };
    e.marquer(EtatQuarantaine::EnCours);
    liste.push(e);
    if let Err(x) = ecrire(liste) {
        liste.pop();
        let _ = fs::remove_file(&copie);
        return Err(format!("quarantaine non enregistrée ({x}) : original intact"));
    }
    if let Err(x) = fs::remove_file(source) {
        liste.pop();
        if ecrire(liste).is_ok() {
            let _ = fs::remove_file(&copie);
        }
        return Err(format!("suppression de l'original impossible : {x}"));
    }
    if let Some(e) = liste.last_mut() {
        e.marquer(EtatQuarantaine::Terminee);
    }
    // Échec ici : original supprimé, copie et entrée « en_cours » en place, la reprise passera à « terminee »
    let _ = ecrire(liste);
    Ok(())
}

/// Lit le manifeste. Absent : liste vide. Présent mais illisible (protection en échec, propriétaire non
/// vérifié, contenu invalide) : erreur, pour ne jamais le réécrire avec une liste incomplète.
fn charger_liste() -> Result<Vec<ElementQuarantaine>, String> {
    let f = commun::dossier().join("quarantaine.json");
    if fs::symlink_metadata(&f).is_err() {
        return Ok(Vec::new());
    }
    commun::lire::<Vec<ElementQuarantaine>>("quarantaine.json")
        .ok_or_else(|| "manifeste de quarantaine illisible ou protection du dossier non vérifiée".to_string())
}

fn ecrire_manifeste_service(liste: &[ElementQuarantaine]) -> Result<(), String> {
    commun::ecrire("quarantaine.json", liste)
}

/// Tue les processus qui exécutent ce fichier, puis le met en quarantaine (copie protégée, inexécutable)
pub fn mettre_en_quarantaine(chemin: &str, raison: &str) -> Result<String, String> {
    let p = Path::new(chemin);
    if !p.is_file() {
        return Err(format!("fichier introuvable : {chemin}"));
    }
    let bas = chemin.to_lowercase();
    if bas.starts_with(&natif::dossier_windows().to_lowercase()) {
        return Err("refusé : fichier du système Windows".into());
    }
    let mut liste = charger_liste()?;
    for (pid, _) in natif::processus() {
        if natif::chemin_processus(pid).eq_ignore_ascii_case(chemin) {
            let _ = tuer(pid);
        }
    }
    std::thread::sleep(std::time::Duration::from_millis(500));
    quarantaine_transaction(&dossier_quarantaine(), &mut liste, p, &commun::nouvel_id(), raison, SDDL_QUARANTAINE, &ecrire_manifeste_service)?;
    Ok(format!("{} placé en quarantaine.", p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()))
}

/// Restauration transactionnelle : empreinte de la copie vérifiée (refus si absente ou différente), dossier
/// d'origine créé (échec = erreur avant toute copie), refus si l'emplacement est occupé, recopie, empreinte
/// vérifiée, marque Internet réécrite, état « restauree » ENREGISTRÉ, puis seulement retrait de la copie et
/// de l'entrée. Échec d'enregistrement : fichier restauré retiré, copie et entrée intactes.
pub fn restaurer_transaction(dossier: &Path, liste: &mut Vec<ElementQuarantaine>, id: &str, ecrire: EcrireManifeste) -> Result<String, String> {
    let i = liste.iter().position(|e| e.id == id).ok_or("élément introuvable")?;
    let e = liste[i].clone();
    let source = dossier.join(e.nom_fichier());
    if e.sha256.len() != 64 {
        return Err("empreinte de la copie inconnue : restauration refusée".into());
    }
    match crate::hygiene::empreinte_fichier(&source) {
        Some(h) if h.eq_ignore_ascii_case(&e.sha256) => {}
        Some(_) => return Err("la copie en quarantaine a été modifiée : restauration refusée".into()),
        None => return Err("copie en quarantaine introuvable ou illisible".into()),
    }
    let cible = Path::new(&e.chemin_origine);
    if fs::symlink_metadata(cible).is_ok() {
        return Err(format!("{} existe déjà : restauration refusée", e.chemin_origine));
    }
    if let Some(d) = cible.parent() {
        fs::create_dir_all(d).map_err(|x| format!("dossier d'origine impossible à créer : {x}"))?;
    }
    let annuler = |raison: String| {
        let _ = fs::remove_file(cible);
        Err(raison)
    };
    if let Err(x) = fs::copy(&source, cible) {
        return annuler(format!("copie impossible : {x}"));
    }
    if crate::hygiene::empreinte_fichier(cible).is_none_or(|h| !h.eq_ignore_ascii_case(&e.sha256)) {
        return annuler("restauration incomplète : fichier restauré retiré, copie conservée".into());
    }
    if let Err(x) = ecrire_marque_internet(cible, &e.zone_identifier) {
        return annuler(x);
    }
    liste[i].marquer(EtatQuarantaine::Restauree);
    if let Err(x) = ecrire(liste) {
        liste[i].marquer(e.etat());
        return annuler(format!("restauration non enregistrée ({x}) : fichier restauré retiré, copie conservée"));
    }
    // Échecs suivants sans gravité : la reprise au démarrage retire la copie et l'entrée
    let _ = fs::remove_file(&source);
    liste.remove(i);
    let _ = ecrire(liste);
    Ok(e.chemin_origine)
}

pub fn restaurer(id: &str) -> Result<String, String> {
    let mut liste = charger_liste()?;
    let chemin = restaurer_transaction(&dossier_quarantaine(), &mut liste, id, &ecrire_manifeste_service)?;
    Ok(format!("{chemin} restauré."))
}

/// Action de reprise au démarrage d'une entrée, selon son état et la présence de l'original et de la copie.
/// Ne supprime jamais un original.
#[derive(Debug, PartialEq)]
pub enum Reprise {
    Rien,
    /// Quarantaine non aboutie (original intact) : copie et entrée retirées
    RetirerCopieEtEntree,
    /// Original supprimé, copie en place : la quarantaine est terminée
    MarquerTerminee,
    RetirerEntree,
    /// Restauration enregistrée : copie retirée si le fichier restauré a la bonne empreinte, puis entrée
    FinirRestauration,
    /// Fichier restauré disparu, copie en place : de nouveau en quarantaine
    RemettreTerminee,
    /// Anomalie journalisée, entrée conservée
    Signaler(&'static str),
}

pub fn decision_reprise(etat: EtatQuarantaine, original: bool, copie: bool) -> Reprise {
    use EtatQuarantaine::*;
    match (etat, original, copie) {
        (EnCours, true, true) => Reprise::RetirerCopieEtEntree,
        (EnCours, false, true) => Reprise::MarquerTerminee,
        (EnCours, true, false) => Reprise::RetirerEntree,
        (EnCours, false, false) => Reprise::Signaler("quarantaine interrompue : ni original ni copie"),
        (Terminee, _, true) => Reprise::Rien,
        (Terminee, _, false) => Reprise::Signaler("copie en quarantaine manquante"),
        (Restauree, true, true) => Reprise::FinirRestauration,
        (Restauree, true, false) => Reprise::RetirerEntree,
        (Restauree, false, true) => Reprise::RemettreTerminee,
        (Restauree, false, false) => Reprise::Signaler("restauration interrompue : ni fichier restauré ni copie"),
    }
}

/// Applique la reprise à chaque entrée, puis signale les copies orphelines (sans entrée), conservées.
/// Renvoie les messages pour le journal ; `liste` est mise à jour (à enregistrer par l'appelant).
pub fn reprendre_quarantaine(dossier: &Path, liste: &mut Vec<ElementQuarantaine>) -> Vec<String> {
    let mut messages = Vec::new();
    let mut garder = Vec::new();
    for mut e in liste.drain(..) {
        let copie = dossier.join(e.nom_fichier());
        let original = fs::symlink_metadata(&e.chemin_origine).is_ok();
        let decision = decision_reprise(e.etat(), original, fs::symlink_metadata(&copie).is_ok());
        let garde = match decision {
            Reprise::Rien => true,
            Reprise::RetirerCopieEtEntree => {
                let _ = fs::remove_file(&copie);
                false
            }
            Reprise::MarquerTerminee | Reprise::RemettreTerminee => {
                e.marquer(EtatQuarantaine::Terminee);
                true
            }
            Reprise::RetirerEntree => false,
            Reprise::FinirRestauration => {
                let intact = crate::hygiene::empreinte_fichier(Path::new(&e.chemin_origine)).is_some_and(|h| h.eq_ignore_ascii_case(&e.sha256));
                if intact {
                    let _ = fs::remove_file(&copie);
                    false
                } else {
                    messages.push(format!("quarantaine : {} restauré mais différent de la copie : copie conservée", e.chemin_origine));
                    e.marquer(EtatQuarantaine::Terminee);
                    true
                }
            }
            Reprise::Signaler(m) => {
                messages.push(format!("quarantaine : {} : {m}", e.chemin_origine));
                true
            }
        };
        if !matches!(decision, Reprise::Rien | Reprise::Signaler(_)) {
            messages.push(format!("quarantaine : reprise de {} ({decision:?})", e.chemin_origine));
        }
        if garde {
            garder.push(e);
        }
    }
    *liste = garder;
    let connus: std::collections::HashSet<String> = liste.iter().map(|e| e.nom_fichier().to_lowercase()).collect();
    for f in fs::read_dir(dossier).into_iter().flatten().flatten() {
        let n = f.file_name().to_string_lossy().to_string();
        if !connus.contains(&n.to_lowercase()) {
            messages.push(format!("quarantaine : copie orpheline conservée : {n}"));
        }
    }
    messages
}

/// Migration au démarrage (avant le tri du dossier de données) : une copie qui n'appartient pas à SYSTEM ou aux
/// administrateurs (déplacée avant la 4.3, elle garde le propriétaire de l'utilisateur) serait écartée par le
/// tri. Elle est recopiée de façon protégée (marque Internet relevée sur l'ancienne), la nouvelle copie est
/// ENREGISTRÉE, puis seulement l'ancienne est supprimée (sinon laissée au tri, jamais perdue). Une copie de
/// confiance sans empreinte reçoit la sienne. Renvoie les messages pour le journal.
pub fn migrer_quarantaine(dossier: &Path, liste: &mut Vec<ElementQuarantaine>, sddl: &str,
                          de_confiance: impl Fn(&Path) -> Option<bool>, ecrire: EcrireManifeste) -> Vec<String> {
    let mut messages = Vec::new();
    let mut empreintes_ajoutees = false;
    for i in 0..liste.len() {
        let ancien = dossier.join(liste[i].nom_fichier());
        if fs::symlink_metadata(&ancien).is_err() {
            continue;
        }
        if de_confiance(&ancien) == Some(true) {
            if liste[i].sha256.is_empty() {
                if let Some(h) = crate::hygiene::empreinte_fichier(&ancien) {
                    liste[i].sha256 = h;
                    empreintes_ajoutees = true;
                }
            }
            continue;
        }
        let avant = liste[i].clone();
        let fichier = format!("{}-{}.quarantaine", avant.id, commun::nouvel_id());
        let sha = match copier_verifie(dossier, &ancien, &fichier, sddl) {
            Ok(s) => s,
            Err(x) => {
                messages.push(format!("quarantaine : {} NON migrée ({x}) ; ancienne copie laissée au tri", avant.chemin_origine));
                continue;
            }
        };
        let e = &mut liste[i];
        e.fichier = fichier.clone();
        e.sha256 = sha;
        if e.zone_identifier.is_empty() {
            e.zone_identifier = lire_marque_internet(&ancien);
        }
        if let Err(x) = ecrire(liste) {
            liste[i] = avant.clone();
            let _ = fs::remove_file(dossier.join(&fichier));
            messages.push(format!("quarantaine : {} NON migrée (manifeste : {x}) ; ancienne copie laissée au tri", avant.chemin_origine));
            continue;
        }
        let supprime = fs::remove_file(&ancien).is_ok();
        messages.push(format!("quarantaine : {} recopiée avec ses droits{}", avant.chemin_origine,
            if supprime { "" } else { " (ancienne copie laissée au tri du démarrage)" }));
    }
    if empreintes_ajoutees {
        if let Err(x) = ecrire(liste) {
            messages.push(format!("quarantaine : empreintes non enregistrées ({x})"));
        }
    }
    messages
}

/// Reprise puis migration, appliquées au dossier de données du service (appelé par protection::imposer)
pub fn reprendre_et_migrer_quarantaine_service() -> Vec<String> {
    let f = commun::dossier().join("quarantaine.json");
    if fs::symlink_metadata(&f).is_err() {
        return Vec::new();
    }
    let Some(mut liste) = commun::lire_fichier_proprietaire(&f)
        .and_then(|t| serde_json::from_str::<Vec<ElementQuarantaine>>(t.trim_start_matches('\u{feff}')).ok()) else {
        return vec!["quarantaine : manifeste illisible ou au propriétaire non vérifié : reprise et migration non faites".into()];
    };
    let avant = liste.clone();
    let mut messages = reprendre_quarantaine(&dossier_quarantaine(), &mut liste);
    if liste != avant {
        if let Err(x) = ecrire_manifeste_service(&liste) {
            messages.push(format!("quarantaine : reprise non enregistrée ({x})"));
            return messages;
        }
    }
    messages.extend(migrer_quarantaine(&dossier_quarantaine(), &mut liste, SDDL_QUARANTAINE, natif::proprietaire_de_confiance, &ecrire_manifeste_service));
    messages
}

// ------------------------------------------------------------ pare-feu : programme isolé et mode panique

fn politique() -> windows::core::Result<INetFwPolicy2> {
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER)
    }
}

pub fn nom_regle_programme(chemin: &str, entrant: bool) -> String {
    format!("deR4Tizer - isole {} ({})", chemin, if entrant { "entrant" } else { "sortant" })
}

/// Bloque tout le trafic, entrant et sortant, d'un programme précis
pub fn isoler_programme(chemin: &str) -> Result<(), String> {
    unsafe {
        let p = politique().map_err(|e| e.to_string())?;
        for entrant in [false, true] {
            let r: INetFwRule = CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER).map_err(|e| e.to_string())?;
            r.SetName(&BSTR::from(nom_regle_programme(chemin, entrant))).map_err(|e| e.to_string())?;
            r.SetDescription(&BSTR::from("Programme isolé par deR4Tizer")).map_err(|e| e.to_string())?;
            r.SetGrouping(&BSTR::from(blocage::GROUPE)).map_err(|e| e.to_string())?;
            r.SetApplicationName(&BSTR::from(chemin)).map_err(|e| e.to_string())?;
            r.SetDirection(if entrant { NET_FW_RULE_DIR_IN } else { NET_FW_RULE_DIR_OUT }).map_err(|e| e.to_string())?;
            r.SetAction(NET_FW_ACTION_BLOCK).map_err(|e| e.to_string())?;
            r.SetProfiles(0x7FFF_FFFF).map_err(|e| e.to_string())?;
            r.SetEnabled(VARIANT_TRUE).map_err(|e| e.to_string())?;
            p.Rules().and_then(|rs| rs.Add(&r)).map_err(|e| e.to_string())?;
        }
    }
    // Coupe aussi les connexions déjà ouvertes par ce programme
    for c in natif::lister_tcp() {
        if c.etat == 5 && natif::chemin_processus(c.pid).eq_ignore_ascii_case(chemin) {
            natif::couper(&c);
        }
    }
    Ok(())
}

pub fn liberer_programme(chemin: &str) -> usize {
    let Ok(p) = politique() else { return 0 };
    let mut n = 0;
    unsafe {
        let Ok(regles) = p.Rules() else { return 0 };
        for entrant in [false, true] {
            let nom = BSTR::from(nom_regle_programme(chemin, entrant));
            while regles.Item(&nom).is_ok() && n < 20 && regles.Remove(&nom).is_ok() {
                n += 1;
            }
        }
    }
    n
}

const PROFILS: [windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_PROFILE_TYPE2; 3] =
    [NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC];

const PANIQUE_SORTANT: &str = "deR4Tizer PANIQUE (sortant)";
const PANIQUE_ENTRANT: &str = "deR4Tizer PANIQUE (entrant)";

/// Réseaux privés et réservés, jamais bloqués par le mode panique (le réseau local reste joignable)
const RESERVES: &[(u32, u32)] = &[
    (0x0000_0000, 0x00FF_FFFF), (0x0A00_0000, 0x0AFF_FFFF), (0x6440_0000, 0x647F_FFFF), (0x7F00_0000, 0x7FFF_FFFF),
    (0xA9FE_0000, 0xA9FE_FFFF), (0xAC10_0000, 0xAC1F_FFFF), (0xC0A8_0000, 0xC0A8_FFFF), (0xE000_0000, 0xFFFF_FFFF),
];

/// Plages IPv4 publiques privées des adresses à épargner, au format du pare-feu (« a.b.c.d-e.f.g.h »)
pub fn plages_internet(epargnees: &[std::net::Ipv4Addr]) -> Vec<String> {
    let mut trous: Vec<(u32, u32)> = RESERVES.to_vec();
    trous.extend(epargnees.iter().map(|ip| (u32::from(*ip), u32::from(*ip))));
    trous.sort();
    let mut plages = Vec::new();
    let mut debut: u64 = 0;
    for (d, f) in trous {
        if (d as u64) > debut {
            plages.push((debut as u32, d - 1));
        }
        debut = debut.max(f as u64 + 1);
    }
    if debut <= u32::MAX as u64 {
        plages.push((debut as u32, u32::MAX));
    }
    plages.iter().map(|(d, f)| format!("{}-{}", std::net::Ipv4Addr::from(*d), std::net::Ipv4Addr::from(*f))).collect()
}

/// Adresses à épargner : serveurs DNS de la machine et serveurs de notification (pour que l'alerte parte)
fn epargnees() -> Vec<std::net::Ipv4Addr> {
    use std::net::ToSocketAddrs;
    let mut l = Vec::new();
    let dns = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", "(Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses -join ','"])
        .output().map(|s| String::from_utf8_lossy(&s.stdout).trim().to_string()).unwrap_or_default();
    l.extend(dns.split(',').filter_map(|x| x.trim().parse::<std::net::Ipv4Addr>().ok()));
    let config: commun::Config = commun::lire("config.json").unwrap_or_default();
    let secrets = crate::notifications::lire_secrets();
    let mut hotes = Vec::new();
    for url in [&secrets.ntfy_url, &secrets.teams_url] {
        if let Some(h) = url.strip_prefix("https://").and_then(|r| r.split(['/', ':']).next()) {
            hotes.push(format!("{h}:443"));
        }
    }
    if config.notifications.smtp && !config.notifications.smtp_serveur.is_empty() {
        hotes.push(format!("{}:{}", config.notifications.smtp_serveur, config.notifications.smtp_port));
    }
    for h in hotes {
        if let Ok(a) = h.to_socket_addrs() {
            l.extend(a.filter_map(|x| match x.ip() { std::net::IpAddr::V4(v) => Some(v), _ => None }));
        }
    }
    l.sort();
    l.dedup();
    l
}

fn regle_blocage(p: &INetFwPolicy2, nom: &str, sortant: bool, adresses: &str) -> windows::core::Result<()> {
    unsafe {
        let r: INetFwRule = CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER)?;
        r.SetName(&BSTR::from(nom))?;
        r.SetDescription(&BSTR::from("Mode panique de deR4Tizer : Internet coupé, réseau local et alertes conservés"))?;
        r.SetGrouping(&BSTR::from(blocage::GROUPE))?;
        r.SetDirection(if sortant { NET_FW_RULE_DIR_OUT } else { NET_FW_RULE_DIR_IN })?;
        r.SetAction(NET_FW_ACTION_BLOCK)?;
        r.SetProtocol(256)?;
        r.SetRemoteAddresses(&BSTR::from(adresses))?;
        r.SetProfiles(0x7FFF_FFFF)?;
        r.SetEnabled(VARIANT_TRUE)?;
        p.Rules()?.Add(&r)
    }
}

/// Mode panique : deux règles de BLOCAGE (qui priment sur toutes les règles d'autorisation, y compris celles
/// qu'un programme malveillant aurait créées) vers tout Internet, IPv4 et IPv6 globales ; le réseau local, les
/// serveurs DNS et les serveurs de notification restent joignables. Rien d'autre n'est modifié : la sortie
/// du mode retire simplement les deux règles.
pub fn panique(activer: bool) -> Result<String, String> {
    let p = politique().map_err(|e| e.to_string())?;
    unsafe {
        if let Ok(regles) = p.Rules() {
            for nom in [PANIQUE_SORTANT, PANIQUE_ENTRANT] {
                let b = BSTR::from(nom);
                let mut n = 0;
                while regles.Item(&b).is_ok() && n < 10 && regles.Remove(&b).is_ok() {
                    n += 1;
                }
            }
        }
    }
    if !activer {
        let _ = fs::remove_file(commun::dossier().join("panique-active"));
        return Ok("Mode panique désactivé : Internet de nouveau accessible.".into());
    }
    let epargnees = epargnees();
    let mut adresses = plages_internet(&epargnees);
    adresses.push("2000::-3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".into());
    let liste = adresses.join(",");
    regle_blocage(&p, PANIQUE_SORTANT, true, &liste).map_err(|e| e.to_string())?;
    regle_blocage(&p, PANIQUE_ENTRANT, false, &liste).map_err(|e| e.to_string())?;
    unsafe {
        for profil in PROFILS {
            let _ = p.put_FirewallEnabled(profil, VARIANT_TRUE);
        }
    }
    // Coupe immédiatement les connexions vers Internet en cours (les règles ne s'appliquent qu'aux nouvelles)
    let n = natif::lister_tcp().iter()
        .filter(|c| c.etat == 5 && c.ip.parse().map(|a| crate::parefeu::publique(&a)).unwrap_or(false))
        .filter(|c| !c.ip.parse::<std::net::Ipv4Addr>().map(|a| epargnees.contains(&a)).unwrap_or(false))
        .filter(|c| natif::couper(c)).count();
    fs::write(commun::dossier().join("panique-active"), commun::maintenant()).map_err(|e| e.to_string())?;
    Ok(format!("MODE PANIQUE : Internet coupé pour tous les programmes ; réseau local, DNS et {} serveur(s) de notification conservés ; {n} connexion(s) coupée(s).",
        epargnees.len()))
}

pub fn panique_active() -> bool {
    commun::dossier().join("panique-active").exists()
}
