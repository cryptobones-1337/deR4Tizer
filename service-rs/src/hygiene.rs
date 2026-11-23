//! Hygiène et pièges :
//!   - leurres anti-rançongiciel : fichiers cachés placés en tête de Documents, Images et Bureau (leur emplacement réel :
//!     OneDrive, redirection) ;
//!     un rançongiciel les chiffre en premier. Audit d'écriture (4663) pour savoir qui les touche ;
//!   - pilotes vulnérables ou malveillants connus (liste LOLDrivers, technique BYOVD) ;
//!   - extensions de navigateur : inventaire, permissions dangereuses, nouvelles extensions.

use crate::commun::{self, Alerte};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn alerte(regle: &str, niveau: &str, score: i32, processus: &str, chemin: &str, destination: &str, raisons: String) -> Alerte {
    Alerte {
        regle: regle.into(),
        id: commun::nouvel_id(),
        heure: commun::maintenant(),
        niveau: niveau.into(),
        score,
        processus: processus.into(),
        chemin: chemin.into(),
        destination: destination.into(),
        raisons,
        ..Default::default()
    }
}

/// Profils des modèles de Windows : jamais de leurres ni d'inventaire dedans
const PROFILS_MODELES: &[&str] = &["default", "default user", "public", "all users", "defaultapppool"];

fn profils_modeles() -> Vec<PathBuf> {
    let racine = format!(r"{}\Users", &crate::natif::dossier_windows()[..2]);
    PROFILS_MODELES.iter().map(|n| Path::new(&racine).join(n)).collect()
}

fn profils() -> Vec<PathBuf> {
    let racine = format!(r"{}\Users", &crate::natif::dossier_windows()[..2]);
    fs::read_dir(racine)
        .map(|d| {
            d.map_while(Result::ok)
                .filter(|e| !PROFILS_MODELES.contains(&e.file_name().to_string_lossy().to_lowercase().as_str()))
                .map(|e| e.path())
                .filter(|p| p.join("NTUSER.DAT").exists())
                .collect()
        })
        .unwrap_or_default()
}

/// Retire les leurres posés par erreur dans les profils modèles (versions précédentes). Public est modifiable par
/// tous les utilisateurs : retrait par handle seulement, sans suivre de lien, chemin final vérifié
fn retirer_leurres_modeles() {
    for profil in profils_modeles() {
        for (dossier, nom) in ANCIENS_LEURRES.iter().map(|(d, n)| (d.to_string(), n.to_string())).chain(noms_leurres()) {
            retirer_leurre(&profil.join(dossier).join(nom));
        }
    }
}

/// Dossier d'un profil d'après ProfileImagePath (« %SystemDrive% » remplacé par le lecteur de Windows)
pub fn chemin_image_profil(image: &str, lecteur: &str) -> PathBuf {
    let bas = image.to_ascii_lowercase();
    match bas.find("%systemdrive%") {
        Some(i) => PathBuf::from(format!("{}{}{}", &image[..i], lecteur, &image[i + "%systemdrive%".len()..])),
        None => PathBuf::from(image),
    }
}

/// Profils des comptes d'utilisateur (S-1-5-21-…) d'après ProfileList : (dossier du profil, SID du propriétaire).
/// Le SID sert à agir sous l'identité de l'utilisateur dans ses propres dossiers.
fn profils_proprietaires() -> Vec<(PathBuf, String)> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let lecteur = crate::natif::dossier_windows()[..2].to_string();
    let Ok(liste) = winreg::RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList") else {
        return Vec::new();
    };
    liste.enum_keys().map_while(Result::ok)
        .filter(|sid| sid.starts_with("S-1-5-21-") && sid[2..].chars().all(|c| c.is_ascii_digit() || c == '-'))
        .filter_map(|sid| {
            let image: String = liste.open_subkey(&sid).ok()?.get_value("ProfileImagePath").ok()?;
            let profil = chemin_image_profil(&image, &lecteur);
            let nom = profil.file_name()?.to_string_lossy().to_lowercase();
            (!PROFILS_MODELES.contains(&nom.as_str())).then_some((profil, sid))
        })
        .collect()
}

// ------------------------------------------------------------ leurres
//
// Les leurres vivent dans Documents, Pictures et Desktop des profils (ou leur emplacement réel, A-7-2), dossiers que
// l'utilisateur contrôle : il peut
// les remplacer par une jonction (vers un dossier protégé ou vers \RPC Control et ses liens). Aucune opération par
// chemin : tout passe par un handle ouvert sans suivre de lien, chemin final vérifié (natif::ouvrir_verifie,
// creer_verifie, supprimer_par_handle), et la création se fait sous l'identité du propriétaire du profil.

/// Contenu d'un leurre : sans importance mais stable ; taille réaliste
fn contenu_leurre() -> Vec<u8> {
    (0..24_576u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect()
}

/// Audit d'écriture et de suppression pour tous (l'événement 4663 dira quel programme a touché le leurre)
const SDDL_AUDIT_LEURRE: &str = "S:(AU;SA;0x10006;;;WD)";

/// Crée un leurre (caché, système) au chemin exact, jamais à travers un lien ; jamais d'écrasement d'un fichier
/// existant. En cas d'échec après la création, le fichier créé est supprimé par son handle.
pub fn creer_leurre(chemin: &Path) -> Result<(), String> {
    use std::io::Write;
    let mut f = crate::natif::creer_verifie(chemin).map_err(|e| format!("{} : {e}", chemin.display()))?;
    let r = f.write_all(&contenu_leurre()).map_err(|e| e.to_string())
        .and_then(|_| crate::natif::ajouter_attributs(&f, 0x2 | 0x4)); // FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
    if r.is_err() {
        let _ = crate::natif::supprimer_par_handle(&f);
    }
    r
}

/// Retire un leurre par son handle, ouvert sans suivre de lien et chemin final vérifié : rien n'est supprimé
/// ailleurs qu'au chemin attendu. Renvoie true si le leurre a été supprimé.
pub fn retirer_leurre(chemin: &Path) -> bool {
    // DELETE | SYNCHRONIZE | FILE_READ_ATTRIBUTES, tout partage
    match crate::natif::ouvrir_verifie(chemin, 0x0001_0000 | 0x0010_0000 | 0x80, 0x7, false) {
        Ok(f) => crate::natif::supprimer_par_handle(&f).is_ok(),
        Err(_) => false,
    }
}

/// Empreinte d'un leurre lue par son handle (sans suivre de lien, chemin final vérifié) ; None s'il est absent,
/// illisible ou détourné
pub fn empreinte_verifiee(chemin: &Path) -> Option<String> {
    // GENERIC_READ | SYNCHRONIZE, tout partage
    let mut f = crate::natif::ouvrir_verifie(chemin, 0x8000_0000 | 0x0010_0000, 0x7, false).ok()?;
    empreinte_lue(&mut f)
}

/// SHA-256 du contenu lu depuis la position courante d'un handle déjà ouvert ; None si une lecture échoue
fn empreinte_lue(f: &mut impl Read) -> Option<String> {
    let mut h = Sha256::new();
    let mut tampon = [0u8; 65536];
    loop {
        let n = f.read(&mut tampon).ok()?;
        if n == 0 {
            break;
        }
        h.update(&tampon[..n]);
    }
    Some(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Empreinte vérifiée (sans suivre de lien) à échéance
fn empreinte_a_echeance(f: &Path) -> Result<Option<String>, crate::natif::HorsDelai> {
    let c = f.to_path_buf();
    crate::natif::lecture_fichier("leurre", &f.to_string_lossy(), move || empreinte_verifiee(&c))
}

/// Issue de la pose d'un leurre sur un seul handle (S268-04)
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum IssuePose {
    /// Un seul nom : audit tenté (son échec éventuel) et empreinte lue par ce même handle
    Suivi { empreinte: String, audit: Option<String> },
    /// Plus d'un nom (lien dur) ou nombre illisible : ni audité ni suivi
    Liens(Option<u32>),
    /// Absent, lien, chemin détourné, ou contenu illisible
    Illisible,
}

/// Décision pure (testée) : issue d'après le texte rendu par le lecteur à échéance (qui ne transporte que du texte) ;
/// rien ou un texte inattendu : illisible
pub fn issue_pose(texte: Option<&str>) -> IssuePose {
    texte.and_then(|t| serde_json::from_str(t).ok()).unwrap_or(IssuePose::Illisible)
}

/// Contrôle du nombre de liens, pose de l'audit et lecture de l'empreinte sur UN SEUL handle (S268-04 : un lien dur
/// glissé entre un premier contrôle et la réouverture par chemin recevait l'audit), à échéance
fn poser_a_echeance(f: &Path) -> Result<IssuePose, crate::natif::HorsDelai> {
    use crate::natif::RefusAudit;
    let c = f.to_path_buf();
    // Clé distincte de l'empreinte et des liens : le lecteur garde un résultat tardif par quoi, chemin et date
    let lu = crate::natif::lecture_fichier("pose de leurre", &f.to_string_lossy(), move || {
        let issue = match crate::natif::poser_audit_par_handle(&c, SDDL_AUDIT_LEURRE,
            |h| {
                let n = crate::natif::nombre_de_liens(h);
                if leurre_existant_admis(n) { Ok(()) } else { Err(n) }
            },
            empreinte_lue) {
            Ok((audit, Some(empreinte))) => IssuePose::Suivi { empreinte, audit: audit.err() },
            Ok((_, None)) | Err(RefusAudit::Ouverture(_)) => IssuePose::Illisible,
            Err(RefusAudit::Refuse(n)) => IssuePose::Liens(n),
        };
        serde_json::to_string(&issue).ok()
    })?;
    Ok(issue_pose(lu.as_deref()))
}

/// Ancien emplacement : à garder, à oublier sans bruit (absent ou illisible), ou à abandonner (journalisé)
#[derive(Debug, PartialEq)]
pub enum SuiteAncien {
    Garder,
    Oublier,
    Abandonner,
}

/// Décision pure (testée, S268-05) : un leurre d'un ancien emplacement repasse le contrôle des liens ; un seul nom ou
/// lecture hors délai, gardé ; absent ou illisible, oublié ; plusieurs noms, suivi abandonné
pub fn suite_ancien(liens: Result<Option<u32>, crate::natif::HorsDelai>) -> SuiteAncien {
    match liens {
        Err(_) => SuiteAncien::Garder,
        Ok(None) => SuiteAncien::Oublier,
        Ok(l) if leurre_existant_admis(l) => SuiteAncien::Garder,
        Ok(_) => SuiteAncien::Abandonner,
    }
}

/// Texte d'un fichier des profils lu en SYSTEM (audit du 2026-11-14, A3) : sans suivre de lien (chemin final vérifié)
/// et borné à `max` octets ; au-delà, None (un fichier tronqué ne donnerait qu'un JSON invalide)
pub(crate) fn lire_profil_borne(chemin: &Path, max: u64) -> Option<String> {
    // GENERIC_READ | SYNCHRONIZE, tout partage
    let f = crate::natif::ouvrir_verifie(chemin, 0x8000_0000 | 0x0010_0000, 0x7, false).ok()?;
    let mut t = String::new();
    let lus = f.take(max + 1).read_to_string(&mut t).ok()?;
    (lus as u64 <= max).then_some(t)
}

/// Exécute `f` sous l'identité du propriétaire du profil s'il a une session ouverte (ses droits s'appliquent : une
/// jonction vers un dossier protégé échoue en plus du contrôle du chemin final) ; None sans session
fn sous_l_identite<T>(sid: &str, f: impl FnOnce() -> T) -> Option<T> {
    crate::natif::avec_jeton_de(sid, f).ok()
}

/// Retire un leurre d'un profil : sous l'identité de son propriétaire s'il a une session, sinon par SYSTEM, par
/// handle vérifié dans les deux cas
fn retirer_leurre_du_profil(sid: &str, chemin: &Path) -> bool {
    sous_l_identite(sid, || retirer_leurre(chemin)).unwrap_or_else(|| retirer_leurre(chemin))
}

/// Retire des leurres (nettoyage de la désinstallation) ; renvoie le nombre retiré. Sous l'identité du propriétaire
/// mémorisée avec le leurre (dossier redirigé hors du profil compris, A-7-2), sinon d'après le dossier du profil (listes
/// des versions précédentes, sans SID)
pub fn retirer_leurres(leurres: &[Leurre]) -> usize {
    let profils = profils_proprietaires();
    leurres.iter().filter(|l| {
        let p = Path::new(l.chemin.as_str());
        if !l.sid.is_empty() && profils.iter().any(|(_, sid)| *sid == l.sid) {
            return retirer_leurre_du_profil(&l.sid, p);
        }
        match profils.iter().find(|(profil, _)| p.starts_with(profil)) {
            Some((_, sid)) => retirer_leurre_du_profil(sid, p),
            None => retirer_leurre(p),
        }
    }).count()
}

// Emplacement réel des dossiers des leurres (audit du 2026-11-23, A-7-2). Avec la sauvegarde OneDrive des dossiers (que
// Windows 11 propose par défaut) ou une redirection, Documents, Images et Bureau ne sont plus dans le profil : les leurres
// posés dans profil\Documents ne voyaient rien. L'emplacement est lu dans « User Shell Folders » de la ruche de
// l'utilisateur (chargée quand il a une session) ; ruche absente ou valeur illisible : dossier par défaut. La valeur
// est écrite par l'utilisateur : elle n'est admise que sous son profil ou sur un lecteur local fixe, jamais sur un
// partage réseau, et la création reste par handle, sans suivre de lien, sous son identité.

/// Dossier par défaut des leurres et nom de sa valeur dans « User Shell Folders »
const DOSSIERS_LEURRES: &[(&str, &str)] = &[("Documents", "Personal"), ("Pictures", "My Pictures"), ("Desktop", "Desktop")];
const CLE_DOSSIERS: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders";

/// Emplacement d'un dossier des leurres (décision pure `resoudre_dossier`)
#[derive(Debug, PartialEq, Eq)]
pub enum DossierLeurre {
    /// Dossier par défaut du profil (valeur absente, vide ou égale à profil\<dossier>)
    Defaut,
    /// Dossier redirigé (OneDrive, autre lecteur…), à faire admettre par `destination_admise`
    Redirige(PathBuf),
    /// Valeur refusée : le dossier par défaut est gardé et le refus journalisé
    Refuse(&'static str),
}

/// Développe %USERPROFILE% (le profil de CET utilisateur, jamais celui du service) et %OneDrive% (sa ruche Environment,
/// déjà développée) ; toute autre variable est refusée : rien n'est deviné. Découpage par get() : la valeur vient de
/// l'utilisateur (règle 4)
fn developper(valeur: &str, profil: &Path, onedrive: Option<&str>) -> Result<String, &'static str> {
    let mut sortie = String::new();
    let mut reste = valeur;
    while let Some(i) = reste.find('%') {
        sortie.push_str(reste.get(..i).unwrap_or(""));
        let apres = reste.get(i + 1..).unwrap_or("");
        let Some(j) = apres.find('%') else { return Err("variable non terminée") };
        match apres.get(..j).unwrap_or("").to_ascii_lowercase().as_str() {
            "userprofile" => sortie.push_str(&profil.to_string_lossy()),
            "onedrive" => sortie.push_str(onedrive.ok_or("%OneDrive% inconnu ou refusé pour cet utilisateur")?),
            _ => return Err("variable inconnue"),
        }
        reste = apres.get(j + 1..).unwrap_or("");
    }
    sortie.push_str(reste);
    Ok(sortie)
}

/// Chemin absolu sur un lecteur à lettre (« X:\… »), normalisé ; refusés : partage réseau et préfixes de périphérique
/// (« \\… »), chemin relatif, « . » ou « .. », flux de données (« : »), jokers, caractères de contrôle
fn forme_locale(chemin: &str) -> Result<PathBuf, &'static str> {
    let c = chemin.trim().replace('/', "\\");
    if c.starts_with(r"\\") {
        return Err("chemin réseau ou de périphérique");
    }
    if c.chars().any(|x| x.is_control() || matches!(x, '*' | '?' | '"' | '<' | '>' | '|')) {
        return Err("caractère interdit");
    }
    let b = c.as_bytes();
    if !(b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\') {
        return Err("chemin non absolu");
    }
    let reste = c.get(3..).unwrap_or("");
    if reste.contains(':') {
        return Err("flux de données");
    }
    let morceaux: Vec<&str> = reste.split('\\').filter(|m| !m.is_empty()).collect();
    if morceaux.iter().any(|m| *m == "." || *m == "..") {
        return Err("« . » ou « .. »");
    }
    Ok(PathBuf::from(format!("{}\\{}", c.get(..2).unwrap_or(""), morceaux.join("\\"))))
}

/// Même chemin, sans tenir compte de la casse ni d'un séparateur final
fn meme_dossier(a: &Path, b: &Path) -> bool {
    let n = |p: &Path| p.to_string_lossy().trim_end_matches('\\').to_lowercase();
    n(a) == n(b)
}

/// Dossier `d` égal au profil ou dessous (comparaison par élément entier : C:\Users\marie2 n'est pas sous C:\Users\marie)
fn sous_profil(d: &Path, profil: &Path) -> bool {
    let p = profil.to_string_lossy().trim_end_matches('\\').to_lowercase();
    let d = d.to_string_lossy().to_lowercase();
    !p.is_empty() && (d.trim_end_matches('\\') == p || d.starts_with(&format!("{p}\\")))
}

/// Décision pure (testée, A-7-2) : emplacement d'un dossier des leurres d'après la valeur lue dans « User Shell Folders »
/// (None : ruche non chargée ou valeur absente), le profil de l'utilisateur, le nom du dossier par défaut et la valeur
/// OneDrive de sa ruche Environment
pub fn resoudre_dossier(valeur: Option<&str>, profil: &Path, defaut: &str, onedrive: Option<&str>) -> DossierLeurre {
    let Some(v) = valeur.map(str::trim).filter(|v| !v.is_empty()) else { return DossierLeurre::Defaut };
    // %OneDrive% lui-même développé (profil seulement) et local, sinon inconnu
    let od = onedrive.and_then(|o| developper(o.trim(), profil, None).and_then(|o| forme_locale(&o)).ok()).map(|o| o.to_string_lossy().to_string());
    match developper(v, profil, od.as_deref()).and_then(|c| forme_locale(&c)) {
        Ok(c) if meme_dossier(&c, &profil.join(defaut)) => DossierLeurre::Defaut,
        Ok(c) => DossierLeurre::Redirige(c),
        Err(r) => DossierLeurre::Refuse(r),
    }
}

/// Décision pure (testée, A-7-2, S268-01) : un dossier redirigé est admis sous le profil de l'utilisateur, ou ailleurs
/// sur un lecteur local fixe (DRIVE_FIXED) dans un dossier dont l'utilisateur `sid` est le propriétaire (lu par handle) ;
/// jamais sur un lecteur amovible, réseau ou inconnu, ni dans un dossier d'un autre propriétaire (un dossier partagé
/// inscriptible ferait poser par SYSTEM un audit sur un fichier choisi par l'utilisateur, ou sur tout volume fixe).
/// `type_lecteur` reçoit « X:\ » et juge la lettre dans l'espace de noms de SYSTEM (`natif::type_lecteur`) : un lecteur
/// mappé ou une lettre SUBST propre à la session de l'utilisateur n'y existe pas (inconnu : refusé) ; une lettre globale
/// qui différerait de celle de sa session ne fait rien écrire ailleurs, la création sous son identité vérifiant le
/// chemin final (`creer_verifie`). Lettre inconnue ou non fixe pour SYSTEM : refus
pub fn destination_admise(d: &Path, profil: &Path, sid: &str, type_lecteur: &dyn Fn(&str) -> u32, proprietaire: &dyn Fn(&Path) -> Option<String>)
    -> Result<(), &'static str> {
    if sous_profil(d, profil) {
        return Ok(());
    }
    let texte = d.to_string_lossy();
    match texte.get(..3) {
        Some(r) if type_lecteur(r) == 3 => {}
        _ => return Err("hors du profil et pas sur un lecteur local fixe"),
    }
    match proprietaire(d) {
        Some(p) if !sid.is_empty() && p.eq_ignore_ascii_case(sid) => Ok(()),
        _ => Err("hors du profil, dossier dont l'utilisateur n'est pas propriétaire"),
    }
}

/// Propriétaire (SID) d'un dossier, lu par un handle ouvert sans suivre de lien, chemin final vérifié ; None s'il est
/// absent, illisible ou détourné
fn proprietaire_dossier(d: &Path) -> Option<String> {
    // READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE, tout partage
    let f = crate::natif::ouvrir_verifie(d, 0x0002_0000 | 0x80 | 0x0010_0000, 0x7, true).ok()?;
    crate::natif::proprietaire_par_handle(&f)
}

/// Décision pure (testée, S268-01) : un leurre n'est audité et suivi que s'il a un seul nom (nombre de liens lu par son
/// handle vérifié). Un lien dur portant le nom d'un leurre désigne un autre fichier : SYSTEM y poserait un audit
/// d'écriture et lèverait de fausses LEU-001 à chaque changement de ce fichier. Nombre illisible : refusé
pub fn leurre_existant_admis(liens: Option<u32>) -> bool {
    liens == Some(1)
}

/// Nombre de liens d'un leurre, lu par son handle (sans suivre de lien, chemin final vérifié), à échéance
fn liens_a_echeance(f: &Path) -> Result<Option<u32>, crate::natif::HorsDelai> {
    let c = f.to_path_buf();
    // Clé distincte de l'empreinte (« leurre ») : le lecteur à échéance garde ses résultats par quoi, chemin et date
    crate::natif::lecture_fichier("liens de leurre", &f.to_string_lossy(), move || {
        // FILE_READ_ATTRIBUTES | SYNCHRONIZE, tout partage
        let h = crate::natif::ouvrir_verifie(&c, 0x80 | 0x0010_0000, 0x7, false).ok()?;
        crate::natif::nombre_de_liens(&h).map(|n| n.to_string())
    }).map(|l| l.and_then(|n| n.parse().ok()))
}

/// Anciens emplacements suivis au plus, par profil et par leurre (S268-02)
pub const ANCIENS_MAX: usize = 3;

/// Décision pure (testée, S268-02) : anciens leurres gardés, au plus `max` par profil (SID) et par nom de leurre, dans
/// l'ordre de la liste (le plus récent d'abord : chaque pose écrit les emplacements visés, puis les anciens) ; renvoie
/// (gardés, en trop). Sans borne, chaque redirection ajoutait une entrée à leurres.json pour toujours
pub fn borner_anciens(anciens: Vec<Leurre>, max: usize) -> (Vec<Leurre>, Vec<Leurre>) {
    let mut comptes: HashMap<(String, String), usize> = HashMap::new();
    let (mut gardes, mut en_trop) = (Vec::new(), Vec::new());
    for l in anciens {
        let nom = Path::new(&l.chemin).file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
        let n = comptes.entry((l.sid.to_lowercase(), nom)).or_insert(0);
        *n += 1;
        if *n <= max { gardes.push(l) } else { en_trop.push(l) }
    }
    (gardes, en_trop)
}

/// Valeur texte de la ruche d'un utilisateur (HKU\<SID>) ; None si la ruche n'est pas chargée (pas de session) ou la
/// valeur absente. REG_EXPAND_SZ rendu tel quel (jamais développé avec l'environnement du service)
fn valeur_ruche(sid: &str, cle: &str, valeur: &str) -> Option<String> {
    use winreg::enums::HKEY_USERS;
    winreg::RegKey::predef(HKEY_USERS).open_subkey(format!(r"{sid}\{cle}")).ok()?.get_value::<String, _>(valeur).ok()
}

/// Dossier où poser le leurre `dossier` d'un profil : emplacement réel admis, sinon dossier par défaut (refus compté
/// et journalisé une fois)
fn dossier_des_leurres(sid: &str, profil: &Path, dossier: &str, onedrive: Option<&str>, bilan: &mut BilanLeurres) -> PathBuf {
    let defaut = profil.join(dossier);
    let cle = format!("refus {sid} {dossier}");
    let Some(nom_valeur) = DOSSIERS_LEURRES.iter().find(|(d, _)| *d == dossier).map(|(_, v)| *v) else { return defaut };
    let raison = match resoudre_dossier(valeur_ruche(sid, CLE_DOSSIERS, nom_valeur).as_deref(), profil, dossier, onedrive) {
        DossierLeurre::Defaut => {
            oublier_signalement(&cle);
            return defaut;
        }
        DossierLeurre::Redirige(r) => match destination_admise(&r, profil, sid, &crate::natif::type_lecteur, &proprietaire_dossier) {
            Ok(()) => {
                oublier_signalement(&cle);
                return r;
            }
            Err(x) => x,
        },
        DossierLeurre::Refuse(x) => x,
    };
    bilan.refus += 1;
    journal_une_fois(cle, &format!("leurres : dossier {dossier} redirigé refusé ({raison}) : leurre posé dans le dossier par défaut du profil"));
    defaut
}

/// Leurres d'avant (liste mémorisée) hors des emplacements visés par cette pose (décision pure, testée) : dossier
/// redirigé depuis la pose précédente. Ils restent suivis tant qu'ils existent : un rançongiciel qui les touche est
/// toujours vu, et la désinstallation les retire
pub fn precedents_hors_cibles(precedents: &[Leurre], cibles: &[PathBuf]) -> Vec<Leurre> {
    precedents.iter().filter(|p| !cibles.iter().any(|c| meme_dossier(Path::new(&p.chemin), c))).cloned().collect()
}

/// Bilan d'une pose des leurres, publié dans l'état de santé (collecte Leurres, champ Detail)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BilanLeurres {
    /// Leurres posés (ou déjà présents) et suivis aux emplacements visés
    pub poses: usize,
    /// Profils d'utilisateur × noms de leurres
    pub attendus: usize,
    /// Créations en échec dans un profil ouvert (journalisées)
    pub echecs: usize,
    /// Profils sans session dont un leurre manque : posé à leur prochaine connexion
    pub sans_session: usize,
    /// Dossiers redirigés refusés (réseau, lecteur non fixe, valeur illisible) : dossier par défaut gardé
    pub refus: usize,
}

impl BilanLeurres {
    /// Note de la collecte (pure, testée) d'après le nombre de leurres suivis : aucun, indisponible ; une création en
    /// échec dans un profil ouvert, partielle ; sinon active
    pub fn note(&self, suivis: usize) -> crate::collectes::Note {
        use crate::collectes::Note;
        if suivis == 0 {
            Note::Indisponible
        } else if self.echecs > 0 {
            Note::Partielle
        } else {
            Note::Active
        }
    }

    /// « leurres : n posés sur m attendus », et ce qui manque
    pub fn texte(&self) -> String {
        let mut t = format!("leurres : {} posés sur {} attendus", self.poses, self.attendus);
        if self.echecs > 0 {
            t.push_str(&format!(", {} en échec (voir journal.txt)", self.echecs));
        }
        if self.sans_session > 0 {
            t.push_str(&format!(", {} profil(s) sans session (pose à la connexion)", self.sans_session));
        }
        if self.refus > 0 {
            t.push_str(&format!(", {} dossier(s) redirigé(s) refusé(s) : dossier par défaut", self.refus));
        }
        t
    }
}

static BILAN: std::sync::Mutex<BilanLeurres> = std::sync::Mutex::new(BilanLeurres { poses: 0, attendus: 0, echecs: 0, sans_session: 0, refus: 0 });

/// Bilan de la dernière pose
pub fn bilan_leurres() -> BilanLeurres {
    *BILAN.lock().unwrap_or_else(|e| e.into_inner())
}

/// Échecs déjà écrits dans journal.txt : une ligne par échec, pas une par pose (toutes les 15 min)
static SIGNALES: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

fn journal_une_fois(cle: String, message: &str) {
    let mut s = SIGNALES.lock().unwrap_or_else(|e| e.into_inner());
    if s.contains(&cle) {
        return;
    }
    if s.len() >= 64 {
        s.clear();
    }
    s.push(cle);
    drop(s);
    commun::journal(message);
}

fn oublier_signalement(cle: &str) {
    SIGNALES.lock().unwrap_or_else(|e| e.into_inner()).retain(|c| c != cle);
}

/// Texte pour journal.txt sans nom de compte ni nom de leurre (les noms sont secrets : rangés dans secrets\, pour qu'un
/// rançongiciel lancé sous le compte connecté ne les évite pas) : le nom du leurre devient « <leurre> », un dossier
/// redirigé hors du profil « <dossier redirigé> », le profil %USERPROFILE%, puis tout autre chemin de profil est masqué
pub(crate) fn sans_profil(texte: &str, profil: &Path, dossier: &Path, nom: &str) -> String {
    let remplacer = |t: &str, motif: &str, par: &str| match Regex::new(&format!("(?i){}", regex::escape(motif))) {
        Ok(r) if !motif.is_empty() => r.replace_all(t, regex::NoExpand(par)).into_owned(),
        _ => t.to_string(),
    };
    let mut t = remplacer(texte, nom, "<leurre>");
    if !sous_profil(dossier, profil) {
        t = remplacer(&t, &dossier.to_string_lossy(), "<dossier redirigé>");
    }
    t = remplacer(&t, &profil.to_string_lossy(), "%USERPROFILE%");
    commun::masquer_chemin(&t)
}

/// Anciens noms fixes (publiés dans le code) : retirés et remplacés
const ANCIENS_LEURRES: &[(&str, &str)] = &[
    (r"Documents", "!000-deR4Tizer-leurre.docx"),
    (r"Pictures", "!000-deR4Tizer-leurre.jpg"),
    (r"Desktop", "!000-deR4Tizer-leurre.xlsx"),
];

/// Noms des leurres, tirés au hasard à l'installation (leurres-noms.json) : un rançongiciel qui lit ce code
/// ne peut pas les reconnaître. Ils commencent par « 0 » pour être parmi les premiers fichiers parcourus.
pub fn noms_leurres() -> Vec<(String, String)> {
    if let Some(l) = commun::lire::<Vec<(String, String)>>(FICHIER_NOMS).filter(|l| !l.is_empty()) {
        return l;
    }
    let _ = crate::notifications::preparer_dossier();
    let mut graine = commun::filetime(std::time::SystemTime::now()) ^ ((std::process::id() as u64) << 32);
    let mut hasard = |n: u64| {
        graine ^= graine << 13;
        graine ^= graine >> 7;
        graine ^= graine << 17;
        graine % n
    };
    let docs = ["0 Factures {}.docx", "0 Contrat {}.docx", "0 Devis {}.docx", "0 Archives {}.docx"];
    let images = ["0 IMG_{}.jpg", "0 Scan_{}.jpg", "0 Photo {}.jpg"];
    let bureau = ["0 Comptabilité {}.xlsx", "0 Budget {}.xlsx", "0 Clients {}.xlsx"];
    let mut l = Vec::new();
    for (dossier, modeles) in [("Documents", &docs[..]), ("Pictures", &images[..]), ("Desktop", &bureau[..])] {
        let modele = modeles[hasard(modeles.len() as u64) as usize];
        l.push((dossier.to_string(), modele.replace("{}", &(1000 + hasard(9000)).to_string())));
    }
    let _ = commun::ecrire(FICHIER_NOMS, &l);
    l
}

/// Noms et chemins des leurres : dans secrets\ (SYSTEM et administrateurs seulement). Dans le dossier de
/// données, le compte connecté pourrait les lire, et un rançongiciel lancé sous ce compte les éviterait.
pub const FICHIER_NOMS: &str = r"secrets\leurres-noms.json";
pub const FICHIER_LEURRES: &str = r"secrets\leurres.json";

/// Anciennes listes lisibles (versions précédentes) : leurres retirés et renommés, listes effacées
pub fn migrer_leurres() {
    let anciens: Vec<(String, String)> = commun::lire("leurres-noms.json").unwrap_or_default();
    if anciens.is_empty() && fs::symlink_metadata(commun::dossier().join("leurres.json")).is_err() {
        return;
    }
    for (profil, sid) in profils_proprietaires() {
        for (dossier, nom) in &anciens {
            retirer_leurre_du_profil(&sid, &profil.join(dossier).join(nom));
        }
    }
    let _ = fs::remove_file(commun::dossier().join("leurres-noms.json"));
    let _ = fs::remove_file(commun::dossier().join("leurres.json"));
    commun::journal("leurres : anciens noms (lisibles par le compte connecté) remplacés par de nouveaux, rangés dans secrets\\");
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(default)]
pub struct Leurre {
    pub chemin: String,
    pub empreinte: String,
    /// SID du propriétaire du profil (A-7-2) : retrait sous son identité, même dans un dossier redirigé hors du profil ;
    /// vide dans les listes des versions précédentes
    pub sid: String,
}

pub fn empreinte_fichier(chemin: &Path) -> Option<String> {
    let mut f = fs::OpenOptions::new().read(true).share_mode(7).open(chemin).ok()?;
    let mut h = Sha256::new();
    let mut tampon = [0u8; 65536];
    loop {
        let n = f.read(&mut tampon).ok()?;
        if n == 0 {
            break;
        }
        h.update(&tampon[..n]);
    }
    Some(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Crée les leurres manquants (cachés) sous l'identité du propriétaire de chaque profil, leur pose un audit
/// d'écriture par handle, et renvoie la liste. Dossiers à leur emplacement réel (A-7-2, `dossier_des_leurres`). Profil
/// sans session ouverte : aucune création (SYSTEM n'écrit jamais
/// dans les dossiers de l'utilisateur) ; ses leurres déjà présents sont gardés et audités. Rappelée régulièrement
/// par le moniteur, pour les utilisateurs qui ouvrent une session plus tard.
pub fn poser_leurres() -> Vec<Leurre> {
    migrer_leurres();
    retirer_leurres_modeles();
    let profils = profils_proprietaires();
    // Anciens leurres à nom fixe : retirés des profils
    for (profil, sid) in &profils {
        for (dossier, nom) in ANCIENS_LEURRES {
            retirer_leurre_du_profil(sid, &profil.join(dossier).join(nom));
        }
    }
    let noms = noms_leurres();
    // Liste précédente : un leurre hors délai garde son entrée, sinon il ne serait plus retiré à la désinstallation
    // (audit de #175, S175-01)
    let precedents: Vec<Leurre> = commun::lire(FICHIER_LEURRES).unwrap_or_default();
    let garder_precedent = |liste: &mut Vec<Leurre>, f: &Path| {
        if let Some(p) = precedents.iter().find(|p| Path::new(&p.chemin) == f) {
            liste.push(p.clone());
        }
    };
    let mut liste = Vec::new();
    let mut bilan = BilanLeurres { attendus: profils.len() * noms.len(), ..Default::default() };
    // Emplacements visés par cette pose : un leurre précédent ailleurs (dossier redirigé depuis) reste suivi plus bas
    let mut cibles = Vec::new();
    for (profil, sid) in &profils {
        let mut sans_session = false;
        // %OneDrive% de CET utilisateur (ruche Environment), jamais celui du service ; ruche non chargée : inconnu
        let onedrive = valeur_ruche(sid, "Environment", "OneDrive");
        for (dossier, nom) in &noms {
            // Emplacement réel (A-7-2) : OneDrive ou redirection lus dans la ruche de l'utilisateur, sinon par défaut
            let rep = dossier_des_leurres(sid, profil, dossier, onedrive.as_deref(), &mut bilan);
            let f = rep.join(nom);
            cibles.push(f.clone());
            // Empreinte à échéance (audit du 2026-11-14, A8, famille S103-07) : un leurre tenu par un verrou ne fige plus
            // la pose ; hors délai, ce leurre est laissé pour le prochain passage (jamais recréé à l'aveugle)
            let Ok(presente) = empreinte_a_echeance(&f) else {
                garder_precedent(&mut liste, &f);
                continue;
            };
            if presente.is_none() {
                // Absent (ou détourné : alors la création à travers le lien est refusée elle aussi). Échec journalisé,
                // une fois par leurre (A-7-2), sans nom de compte
                let cle = format!("création {}", f.to_string_lossy().to_lowercase());
                match sous_l_identite(sid, || creer_leurre(&f)) {
                    Some(Ok(())) => oublier_signalement(&cle),
                    Some(Err(x)) => {
                        bilan.echecs += 1;
                        journal_une_fois(cle, &sans_profil(&format!("leurres : création refusée dans {dossier} ({}) : {x}", rep.display()), profil, &rep, nom));
                        continue;
                    }
                    None => {
                        sans_session = true;
                        continue;
                    }
                }
            }
            // Un seul handle (S268-04) : nombre de liens contrôlé (S268-01 : un lien dur portant le nom du leurre n'est
            // ni audité ni suivi, refus journalisé), puis audit posé dès que le leurre existe (S175-01 : LEU-002 jamais
            // aveugle sur un leurre neuf), puis empreinte lue, sans réouverture par chemin. Hors délai : laissé pour le
            // prochain passage, l'entrée précédente gardée
            let cle_liens = format!("liens {}", f.to_string_lossy().to_lowercase());
            let e = match poser_a_echeance(&f) {
                Ok(IssuePose::Suivi { empreinte, audit }) => {
                    oublier_signalement(&cle_liens);
                    if let Some(x) = audit {
                        commun::journal(&sans_profil(&format!("leurres : audit non posé sur {} ({x})", f.display()), profil, &rep, nom));
                    }
                    empreinte
                }
                Ok(IssuePose::Liens(l)) => {
                    bilan.echecs += 1;
                    let n = l.map_or_else(|| "illisible".to_string(), |n| n.to_string());
                    journal_une_fois(cle_liens, &sans_profil(&format!("leurres : {} refusé (nombre de liens {n}) : ni audité ni suivi", f.display()), profil, &rep, nom));
                    continue;
                }
                Ok(IssuePose::Illisible) => continue,
                Err(_) => {
                    garder_precedent(&mut liste, &f);
                    continue;
                }
            };
            liste.push(Leurre { chemin: f.to_string_lossy().to_string(), empreinte: e, sid: sid.clone() });
            bilan.poses += 1;
        }
        bilan.sans_session += usize::from(sans_session);
    }
    // Leurres d'un ancien emplacement (dossier redirigé depuis la pose précédente) : suivis tant qu'ils existent (ou
    // illisibles à échéance), avec leur empreinte d'origine : modifiés, ils lèvent LEU-001 ; la désinstallation les retire.
    // Ils repassent le contrôle des liens (S268-05) : un ancien leurre devenu lien dur n'est plus suivi (ni retiré : son
    // nom désigne un autre fichier), journalisé
    let mut existants = Vec::new();
    for p in precedents_hors_cibles(&precedents, &cibles) {
        match suite_ancien(liens_a_echeance(Path::new(&p.chemin))) {
            SuiteAncien::Garder => existants.push(p),
            SuiteAncien::Oublier => {}
            SuiteAncien::Abandonner => commun::journal("leurres : un ancien emplacement a plus d'un nom (lien dur) : suivi abandonné"),
        }
    }
    // Au plus ANCIENS_MAX anciens emplacements par profil et par leurre (S268-02) : au-delà, le leurre est retiré par handle
    // (sous l'identité de son propriétaire s'il a une session) et son suivi abandonné, journalisé
    let (gardes, en_trop) = borner_anciens(existants, ANCIENS_MAX);
    liste.extend(gardes);
    for p in en_trop {
        let chemin = Path::new(&p.chemin);
        let retire = if p.sid.is_empty() { retirer_leurre(chemin) } else { retirer_leurre_du_profil(&p.sid, chemin) };
        commun::journal(&format!("leurres : un ancien emplacement au-delà de {ANCIENS_MAX} pour le même leurre : {}, suivi abandonné",
            if retire { "leurre retiré" } else { "retrait impossible" }));
    }
    *BILAN.lock().unwrap_or_else(|e| e.into_inner()) = bilan;
    let _ = commun::ecrire(FICHIER_LEURRES, &liste);
    liste
}

/// Vérifie les leurres : modifié ou disparu = rançongiciel probable
pub fn verifier_leurres(liste: &mut Vec<Leurre>) -> Vec<Alerte> {
    let mut a = Vec::new();
    for l in liste.iter_mut() {
        // Par handle vérifié : un leurre remplacé par un lien compte comme supprimé, rien n'est lu ailleurs
        // Lecture hors délai : le propriétaire du profil peut y poser un verrou opportuniste. Ni alerte ni blocage : l'audit des accès (LEU-002)
        // voit les fichiers touchés, et la vérification reprend quand la lecture aboutit
        let chemin = l.chemin.clone();
        let Ok(lue) = crate::natif::lecture_fichier("leurre", &l.chemin, move || empreinte_verifiee(Path::new(&chemin))) else { continue };
        let etat = match lue {
            None => Some("SUPPRIMÉ, RENOMMÉ ou REMPLACÉ PAR UN LIEN"),
            Some(e) if e != l.empreinte => Some("MODIFIÉ"),
            Some(_) => None,
        };
        if let Some(e) = etat {
            a.push(alerte(crate::regles::LEU_001, "Critique", 15, "?", "", "leurre anti-rançongiciel",
                format!("fichier leurre {e} : {} — un RANÇONGICIEL est probablement en train de chiffrer vos fichiers. Utilisez le bouton PANIQUE et éteignez le PC si nécessaire.", l.chemin)));
            l.empreinte = String::from("alerte");
        }
    }
    liste.retain(|l| l.empreinte != "alerte");
    a
}

/// Événement 4663 sur un leurre : renvoie le PID du programme qui l'a touché
pub fn pid_touchant_leurre(xml: &str) -> Option<(u32, String, String)> {
    pid_touchant_leurre_parmi(xml, &noms_leurres())
}

/// Décision pure (testée, LEU-002) : événement 4663 sur un fichier qui porte l'un des noms de leurres donnés : (PID,
/// programme, fichier)
pub(crate) fn pid_touchant_leurre_parmi(xml: &str, noms: &[(String, String)]) -> Option<(u32, String, String)> {
    let d = crate::evenements::donnees(xml);
    let objet = d.get("ObjectName")?;
    let nom = Path::new(objet.as_str()).file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
    if !noms.iter().any(|(_, n)| n.to_lowercase() == nom) {
        return None;
    }
    let pid = u32::from_str_radix(d.get("ProcessId")?.trim_start_matches("0x"), 16).ok()?;
    Some((pid, d.get("ProcessName").cloned().unwrap_or_default(), objet.clone()))
}

/// Heure d'un événement du journal, en FILETIME, arrondie à la seconde suivante : un programme créé avant l'événement ne
/// doit jamais être écarté par la troncature (pur, testé). `None` si l'heure est illisible
pub(crate) fn heure_evenement(xml: &str) -> Option<u64> {
    let a = xml.find("SystemTime=")? + "SystemTime=".len();
    let reste = xml.get(a + 1..)?;
    let texte = reste.get(..reste.find(['\'', '"'])?)?;
    let secondes = commun::secondes_utc(&format!("{}Z", texte.split(['.', 'Z']).next()?))?;
    u64::try_from(secondes + 1 + 11_644_473_600).ok()?.checked_mul(10_000_000)
}

// ------------------------------------------------------------ pilotes vulnérables (LOLDrivers)

/// Télécharge la liste LOLDrivers (une fois par jour) et renvoie l'ensemble des empreintes SHA-256
pub fn liste_loldrivers() -> HashSet<String> {
    let f = commun::dossier().join(r"menaces\loldrivers.json");
    let recent = fs::metadata(&f).and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).map(|d| d.as_secs() < 86400).unwrap_or(false);
    if !recent {
        let _ = fs::create_dir_all(commun::dossier().join("menaces"));
        let _ = Command::new(crate::natif::curl_exe())
            .args(["-q", "-sSL", "--fail", "--proto", "=https", "--proto-redir", "=https", "--max-filesize", "104857600", "--max-time", "300", "-o"])
            .arg(f.with_extension("tmp"))
            .arg("https://www.loldrivers.io/api/drivers.json")
            .creation_flags(0x0800_0000)
            .output()
            .ok()
            .filter(|s| s.status.success())
            .and_then(|_| fs::rename(f.with_extension("tmp"), &f).ok());
    }
    // Propriétaire contrôlé, comme tout fichier du dossier de données
    let lu = empreintes_loldrivers(commun::lire_fichier_proprietaire(&f).as_deref());
    match &lu {
        Ok(_) => crate::collectes::succes(crate::collectes::Collecte::Loldrivers),
        Err(raison) => crate::collectes::echec(crate::collectes::Collecte::Loldrivers, raison),
    }
    lu.unwrap_or_default()
}

/// Empreintes de la liste LOLDrivers (décision pure, testée) : une liste absente, illisible ou sans empreinte est une
/// collecte indisponible, pas « aucun pilote vulnérable »
pub fn empreintes_loldrivers(texte: Option<&str>) -> Result<HashSet<String>, &'static str> {
    let Some(t) = texte else { return Err("liste LOLDrivers absente ou illisible") };
    let e: HashSet<String> = Regex::new(r#""SHA256":\s*"([0-9a-fA-F]{64})""#).unwrap().captures_iter(t).map(|c| c[1].to_lowercase()).collect();
    if e.is_empty() { Err("liste LOLDrivers sans aucune empreinte") } else { Ok(e) }
}

/// Chemin d'un ImagePath de service ou de pilote (« \\SystemRoot\\… », « \\??\\C:\\… », « System32\\… »)
pub fn chemin_image(image: &str) -> PathBuf {
    let windows = crate::natif::dossier_windows();
    let i = image.trim().trim_matches('"');
    let i = i.strip_prefix(r"\??\").unwrap_or(i);
    // get() et non [..] : l'ImagePath vient d'un service installé par n'importe quel programme administrateur ;
    // un découpage au milieu d'un caractère UTF-8 ferait paniquer le service
    if i.get(..11).is_some_and(|p| p.eq_ignore_ascii_case(r"\SystemRoot")) {
        return PathBuf::from(format!("{windows}{}", &i[11..]));
    }
    if i.len() > 9 && i.get(..9).is_some_and(|p| p.eq_ignore_ascii_case(r"System32\")) {
        return PathBuf::from(&windows).join(i);
    }
    PathBuf::from(i)
}

/// Pilote connu de LOLDrivers. La liste est gardée en mémoire et rechargée une fois par jour par un fil à part :
/// l'appelant (le fil de corrélation du SIEM) n'attend jamais un téléchargement.
pub fn pilote_vulnerable(chemin: &Path) -> Option<String> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::{Duration, Instant};
    static CACHE: OnceLock<Arc<Mutex<(Option<Instant>, Arc<HashSet<String>>)>>> = OnceLock::new();
    static EN_COURS: AtomicBool = AtomicBool::new(false);
    let cache = CACHE.get_or_init(|| Arc::new(Mutex::new((None, Arc::new(HashSet::new()))))).clone();
    let (perime, liste) = {
        let c = cache.lock().unwrap();
        (c.0.map(|t| t.elapsed() > Duration::from_secs(86_400)).unwrap_or(true), c.1.clone())
    };
    if perime && !EN_COURS.swap(true, Ordering::SeqCst) {
        let c = cache.clone();
        std::thread::spawn(move || {
            // Arrière-plan (A-8-1) : téléchargement et lecture de la liste
            crate::natif::fil_priorite(crate::natif::Priorite::Arriere);
            let nouvelle = Arc::new(liste_loldrivers());
            *c.lock().unwrap() = (Some(Instant::now()), nouvelle);
            EN_COURS.store(false, Ordering::SeqCst);
        });
    }
    let h = empreinte_fichier(chemin)?;
    liste.contains(&h).then_some(h)
}

/// Pilotes déclarés dans le registre (services de type 1 ou 2), y compris en démarrage manuel et hors du
/// dossier drivers (un .sys posé dans %TEMP% puis lancé par « sc start »)
fn pilotes_declares() -> Vec<PathBuf> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let mut l = Vec::new();
    let Ok(services) = winreg::RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(r"SYSTEM\CurrentControlSet\Services") else { return l };
    for nom in services.enum_keys().map_while(Result::ok) {
        let Ok(k) = services.open_subkey(&nom) else { continue };
        let type_: u32 = k.get_value("Type").unwrap_or(0);
        if type_ != 1 && type_ != 2 {
            continue;
        }
        if let Ok(image) = k.get_value::<String, _>("ImagePath") {
            let p = chemin_image(&image);
            if p.is_file() {
                l.push(p);
            }
        }
    }
    l
}

/// Compare les pilotes présents (dossier drivers et pilotes déclarés) à la liste
pub fn verifier_pilotes(connus: &HashSet<String>, deja: &mut HashSet<String>) -> Vec<Alerte> {
    if connus.is_empty() {
        return Vec::new();
    }
    let dossier = PathBuf::from(crate::natif::dossier_systeme()).join("drivers");
    let mut chemins: Vec<PathBuf> = fs::read_dir(&dossier).map(|d| d.map_while(Result::ok).map(|e| e.path()).collect()).unwrap_or_default();
    for p in pilotes_declares() {
        if !chemins.iter().any(|c| c.as_os_str().eq_ignore_ascii_case(p.as_os_str())) {
            chemins.push(p);
        }
    }
    pilotes_vulnerables(chemins, connus, deja)
}

/// Décision testée (PIL-001) : parmi ces fichiers, les pilotes (.sys) dont l'empreinte SHA-256 est dans la liste ; un
/// pilote déjà signalé ne l'est plus (`deja`)
pub(crate) fn pilotes_vulnerables(chemins: Vec<PathBuf>, connus: &HashSet<String>, deja: &mut HashSet<String>) -> Vec<Alerte> {
    let mut a = Vec::new();
    for p in chemins {
        if p.extension().map(|x| !x.eq_ignore_ascii_case("sys")).unwrap_or(true) {
            continue;
        }
        let Some(h) = empreinte_fichier(&p) else { continue };
        if connus.contains(&h) && deja.insert(h.clone()) {
            a.push(alerte(crate::regles::PIL_001, "Critique", 10, &p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(),
                &p.to_string_lossy(), "pilote vulnérable",
                format!("PILOTE VULNÉRABLE OU MALVEILLANT CONNU (LOLDrivers, SHA-256 {}…) : technique « BYOVD » utilisée pour désactiver les antivirus  [MITRE T1068]", &h[..16])));
        }
    }
    a
}

// ------------------------------------------------------------ extensions de navigateur

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Extension {
    pub navigateur: String,
    pub id: String,
    pub nom: String,
    pub version: String,
    pub permissions: String,
    pub dangereuse: bool,
    pub depuis: String,
}

const PERMISSIONS_DANGEREUSES: &[&str] = &[
    "<all_urls>", "*://*/*", "http://*/*", "https://*/*", "cookies", "webRequest", "webRequestBlocking", "declarativeNetRequest",
    "clipboardRead", "nativeMessaging", "debugger", "proxy", "management", "history", "downloads", "scripting",
];

fn texte_json(v: &serde_json::Value) -> Vec<String> {
    v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
}

/// Nom lisible d'une extension Chromium (« __MSG_nom__ » renvoie vers _locales)
fn nom_chromium(dossier: &Path, manifeste: &serde_json::Value) -> String {
    let nom = manifeste["name"].as_str().unwrap_or("").to_string();
    let Some(cle) = nom.strip_prefix("__MSG_").and_then(|n| n.strip_suffix("__")) else { return nom };
    for langue in ["fr", "en", "en_US"] {
        if let Some(t) = lire_profil_borne(&dossier.join("_locales").join(langue).join("messages.json"), TAILLE_MAX_MANIFESTE) {
            if let Ok(m) = serde_json::from_str::<serde_json::Value>(t.trim_start_matches('\u{feff}')) {
                if let Some(obj) = m.as_object() {
                    if let Some((_, v)) = obj.iter().find(|(k, _)| k.eq_ignore_ascii_case(cle)) {
                        return v["message"].as_str().unwrap_or(&nom).to_string();
                    }
                }
            }
        }
    }
    nom
}

/// Bornes des fichiers d'extensions lus en SYSTEM (A3) : un manifeste réel fait quelques Ko, extensions.json de
/// Firefox quelques centaines de Ko
const TAILLE_MAX_MANIFESTE: u64 = 1 << 20;
const TAILLE_MAX_EXTENSIONS_FIREFOX: u64 = 16 << 20;
/// Plafonds d'entrées (audit de #175, S175-03, S175-04) : par profil et pendant l'énumération, pour qu'un compte
/// standard qui crée des milliers de dossiers d'extension ne masque ni les extensions des autres profils ni les
/// 1 000 alertes gardées ; au-delà, les manifestes ne sont plus lus et la troncature est signalée par une alerte
const MAX_EXTENSIONS_PAR_PROFIL: usize = 500;
/// Dossiers d'extension examinés par profil, valides ou non (audit v3 de #175, S175-07) : des milliers de dossiers au
/// manifeste invalide ne rendent plus le travail de chaque relevé illimité
const MAX_DOSSIERS_PAR_PROFIL: usize = 2000;
const MAX_ALERTES_EXTENSIONS: usize = 20;

pub fn inventaire_extensions() -> Vec<Extension> {
    inventaire_extensions_borne().0
}

/// Inventaire plafonné par profil ; rend aussi le nombre d'extensions non examinées au-delà du plafond
pub(crate) fn inventaire_extensions_borne() -> (Vec<Extension>, usize) {
    let mut l = Vec::new();
    let mut tronquees = 0usize;
    let navigateurs = [
        ("Chrome", r"AppData\Local\Google\Chrome\User Data"),
        ("Brave", r"AppData\Local\BraveSoftware\Brave-Browser\User Data"),
        ("Edge", r"AppData\Local\Microsoft\Edge\User Data"),
    ];
    for profil in profils() {
        let debut_profil = l.len();
        let mut examines = 0usize;
        for (nav, rel) in navigateurs {
            let donnees = profil.join(rel);
            let Ok(sous) = fs::read_dir(&donnees) else { continue };
            for p in sous.map_while(Result::ok).map(|e| e.path()).filter(|p| p.join("Extensions").is_dir()) {
                let Ok(exts) = fs::read_dir(p.join("Extensions")) else { continue };
                for ext in exts.map_while(Result::ok) {
                    examines += 1;
                    if l.len() - debut_profil >= MAX_EXTENSIONS_PAR_PROFIL || examines > MAX_DOSSIERS_PAR_PROFIL {
                        tronquees += 1;
                        continue;
                    }
                    let id = ext.file_name().to_string_lossy().to_string();
                    // Dernière version installée
                    let Some(version) = fs::read_dir(ext.path()).ok().and_then(|v| v.map_while(Result::ok).map(|e| e.path()).filter(|p| p.join("manifest.json").exists()).max()) else { continue };
                    let Some(t) = lire_profil_borne(&version.join("manifest.json"), TAILLE_MAX_MANIFESTE) else { continue };
                    let Ok(m) = serde_json::from_str::<serde_json::Value>(t.trim_start_matches('\u{feff}')) else { continue };
                    let mut perms = texte_json(&m["permissions"]);
                    perms.extend(texte_json(&m["host_permissions"]));
                    if let Some(cs) = m["content_scripts"].as_array() {
                        perms.extend(cs.iter().flat_map(|c| texte_json(&c["matches"])));
                    }
                    perms.sort();
                    perms.dedup();
                    let dangereuse = perms.iter().any(|x| PERMISSIONS_DANGEREUSES.contains(&x.as_str()));
                    l.push(Extension {
                        navigateur: format!("{nav} ({})", p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()),
                        id: id.clone(),
                        nom: nom_chromium(&version, &m),
                        version: m["version"].as_str().unwrap_or("").into(),
                        permissions: perms.join(", "),
                        dangereuse,
                        depuis: String::new(),
                    });
                }
            }
        }
        // Firefox : extensions.json de chaque profil
        if let Ok(pf) = fs::read_dir(profil.join(r"AppData\Roaming\Mozilla\Firefox\Profiles")) {
            for p in pf.map_while(Result::ok) {
                let Some(t) = lire_profil_borne(&p.path().join("extensions.json"), TAILLE_MAX_EXTENSIONS_FIREFOX) else { continue };
                let Ok(m) = serde_json::from_str::<serde_json::Value>(&t) else { continue };
                for a in m["addons"].as_array().cloned().unwrap_or_default() {
                    if a["location"].as_str() != Some("app-profile") {
                        continue; // extensions intégrées à Firefox
                    }
                    examines += 1;
                    if l.len() - debut_profil >= MAX_EXTENSIONS_PAR_PROFIL || examines > MAX_DOSSIERS_PAR_PROFIL {
                        tronquees += 1;
                        continue;
                    }
                    let mut perms = texte_json(&a["userPermissions"]["permissions"]);
                    perms.extend(texte_json(&a["userPermissions"]["origins"]));
                    let dangereuse = perms.iter().any(|x| PERMISSIONS_DANGEREUSES.contains(&x.as_str()));
                    l.push(Extension {
                        navigateur: "Firefox".into(),
                        id: a["id"].as_str().unwrap_or("").into(),
                        nom: a["defaultLocale"]["name"].as_str().unwrap_or("").into(),
                        version: a["version"].as_str().unwrap_or("").into(),
                        permissions: perms.join(", "),
                        dangereuse,
                        depuis: String::new(),
                    });
                }
            }
        }
    }
    (l, tronquees)
}

/// Compare à l'inventaire précédent : alerte sur chaque nouvelle extension (sauf au premier relevé)
pub fn verifier_extensions() -> (Vec<Extension>, Vec<Alerte>) {
    // Dossier des profils illisible : aucune extension n'est vue, EXT-001 est muette
    let racine = format!(r"{}\Users", crate::natif::dossier_windows().get(..2).unwrap_or("C:"));
    match fs::read_dir(&racine) {
        Ok(_) => crate::collectes::succes(crate::collectes::Collecte::Extensions),
        Err(_) => crate::collectes::echec(crate::collectes::Collecte::Extensions, "dossier des profils illisible"),
    }
    let connues: Option<HashMap<String, String>> = commun::lire("extensions-connues.json");
    let apprentissage = connues.is_none();
    let mut connues = connues.unwrap_or_default();
    let (mut liste, tronquees) = inventaire_extensions_borne();
    let mut alertes = nouvelles_extensions(&mut liste, &mut connues, apprentissage);
    if tronquees > 0 {
        alertes.push(alerte_inventaire_tronque(tronquees));
    }
    let _ = commun::ecrire("extensions-connues.json", &connues);
    liste.sort_by(|a, b| b.dangereuse.cmp(&a.dangereuse).then(a.nom.to_lowercase().cmp(&b.nom.to_lowercase())));
    let _ = commun::ecrire("extensions.json", &liste);
    (liste, alertes)
}

/// Inventaire tronqué (S175-04) : signalé, jamais muet
pub(crate) fn alerte_inventaire_tronque(tronquees: usize) -> Alerte {
    commun::journal(&format!("extensions : {tronquees} extension(s) non examinée(s) au-delà de {MAX_EXTENSIONS_PAR_PROFIL} extensions ou {MAX_DOSSIERS_PAR_PROFIL} dossiers par profil"));
    alerte(crate::regles::EXT_001, "Alerte", 4, "extensions", "", "extensions de navigateur",
        format!("Inventaire des extensions PARTIEL : {tronquees} extension(s) non examinée(s), au-delà de {MAX_EXTENSIONS_PAR_PROFIL} extensions ou {MAX_DOSSIERS_PAR_PROFIL} dossiers dans un même profil (nombre anormal de dossiers d'extension) : vérifiez les profils  [MITRE T1176.001]"))
}

/// Décision pure (testée, EXT-001) : extensions absentes de l'inventaire précédent, notées connues ; alerte pour
/// chacune, sauf au premier relevé (apprentissage) ; Alerte si ses permissions sont sensibles, sinon Info
pub(crate) fn nouvelles_extensions(liste: &mut [Extension], connues: &mut HashMap<String, String>, apprentissage: bool) -> Vec<Alerte> {
    let mut alertes = Vec::new();
    let mut en_plus = 0usize;
    for e in liste.iter_mut() {
        let cle = format!("{}|{}", e.navigateur, e.id);
        match connues.get(&cle) {
            Some(d) => e.depuis = d.clone(),
            None => {
                e.depuis = commun::maintenant();
                connues.insert(cle, e.depuis.clone());
                if !apprentissage && alertes.len() >= MAX_ALERTES_EXTENSIONS {
                    en_plus += 1;
                } else if !apprentissage {
                    alertes.push(alerte(crate::regles::EXT_001, if e.dangereuse { "Alerte" } else { "Info" }, if e.dangereuse { 4 } else { 0 }, &e.nom, "",
                        &format!("extension {}", e.navigateur),
                        format!("NOUVELLE extension de navigateur « {} » {}{}", e.nom, e.version,
                            if e.dangereuse { format!(" avec des permissions sensibles ({}) : vérifiez que vous l'avez installée vous-même  [MITRE T1176.001]", e.permissions) } else { String::new() })));
                }
            }
        }
    }
    if en_plus > 0 {
        alertes.push(alerte(crate::regles::EXT_001, "Alerte", 4, "extensions", "", "extensions de navigateur",
            format!("{en_plus} autre(s) NOUVELLE(S) extension(s) de navigateur au même relevé (au-delà de {MAX_ALERTES_EXTENSIONS} alertes) : vérifiez la liste des extensions  [MITRE T1176.001]")));
    }
    alertes
}
