//! Protection des données : le dossier de deR4Tizer (événements du SIEM, sessions DPI, trafic, appareils
//! du réseau, alertes avec lignes de commande…) n'est lisible que par SYSTEM, les administrateurs et les
//! comptes autorisés (lecteurs.json), plus par tous les utilisateurs du PC. Par défaut, le compte connecté
//! à la console au premier démarrage ; d'autres comptes s'ajoutent depuis l'interface (avec l'UAC).
//! Les droits sont reposés au démarrage puis toutes les heures.
//!
//! Au démarrage du service, AVANT toute lecture (securiser) : le dossier est créé avec ses droits dès la
//! création ; s'il existait déjà sans appartenir à SYSTEM ou aux administrateurs (créé d'avance par un compte
//! standard, qui pourrait sinon réécrire les droits), il est écarté. Dans le dossier, les liens (jonctions,
//! liens symboliques) sont supprimés et les fichiers d'un autre propriétaire mis de côté dans « ecartes »,
//! puis propriétaire et droits sont imposés à tout le contenu. Le paquet MSI crée aussi le dossier avec ces
//! droits (installeur\deR4Tizer.wxs).

use crate::commun;
use serde::{Deserialize, Serialize};
use std::os::windows::process::CommandExt;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// SYSTEM et administrateurs, propriétaire Administrateurs, sans héritage du dossier ProgramData
const SDDL_DOSSIER: &str = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

pub const SID_SYSTEME: &str = "S-1-5-18";
pub const SID_ADMINISTRATEURS: &str = "S-1-5-32-544";

/// Droits qui permettent d'écrire, de supprimer ou de changer les droits (fichiers et dossiers)
const DROITS_ECRITURE: u32 = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 // données, ajout, attributs étendus, suppression d'enfants, attributs
    | 0x1_0000 | 0x4_0000 | 0x8_0000 // DELETE, WRITE_DAC, WRITE_OWNER
    | 0x0200_0000 | 0x1000_0000 | 0x4000_0000; // MAXIMUM_ALLOWED, GENERIC_ALL, GENERIC_WRITE

/// Décision pure : un fichier du dossier de données n'est cru que s'il appartient à SYSTEM ou aux
/// administrateurs (tout autre compte pourrait en réécrire le contenu ou les droits)
pub fn proprietaire_acceptable(sid: &str) -> bool {
    sid == SID_SYSTEME || sid == SID_ADMINISTRATEURS
}

/// Décision pure sur des droits relus : propriétaire acceptable, héritage coupé, contrôle total pour les
/// seuls comptes de `complets`, lecture seule pour les `lecteurs`, rien pour les autres
pub fn droits_conformes(s: &crate::natif::Securite, complets: &[&str], lecteurs: &[&str]) -> Result<(), String> {
    if !proprietaire_acceptable(&s.proprietaire) {
        return Err(format!("propriétaire {} (ni SYSTEM ni Administrateurs)", if s.proprietaire.is_empty() { "illisible" } else { &s.proprietaire }));
    }
    if !s.protege {
        return Err("droits hérités du dossier parent".into());
    }
    if s.ace_inconnue {
        return Err("entrée de droits d'un type inattendu".into());
    }
    for a in s.aces.iter().filter(|a| a.autorise) {
        let ok = complets.contains(&a.sid.as_str()) || (lecteurs.contains(&a.sid.as_str()) && a.masque & DROITS_ECRITURE == 0);
        if !ok {
            return Err(format!("droits accordés à {} (masque {:#x})", a.sid, a.masque));
        }
    }
    Ok(())
}

/// Relit les droits d'un chemin et les compare à l'attendu
pub fn verifier(chemin: &Path, complets: &[&str], lecteurs: &[&str]) -> Result<(), String> {
    let s = crate::natif::lire_securite(chemin).ok_or_else(|| format!("droits de {} illisibles", chemin.display()))?;
    droits_conformes(&s, complets, lecteurs).map_err(|e| format!("{} : {e}", chemin.display()))
}

#[derive(Serialize, Deserialize, Clone, Default, PartialEq)]
#[serde(rename_all = "PascalCase", default)]
pub struct Lecteur {
    pub sid: String,
    pub nom: String,
}

fn powershell(script: &str) -> String {
    Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .creation_flags(0x0800_0000)
        .output()
        .map(|s| String::from_utf8_lossy(&s.stdout).trim().to_string())
        .unwrap_or_default()
}

/// SID d'un compte utilisateur local ou de domaine : S-1-5-21-…
fn sid_valide(sid: &str) -> bool {
    sid.starts_with("S-1-5-21-") && sid.len() < 80 && sid[2..].chars().all(|c| c.is_ascii_digit() || c == '-')
}

/// Compte connecté à la console (session interactive) : (SID, nom)
fn utilisateur_console() -> Option<Lecteur> {
    let sortie = powershell("$u = (Get-CimInstance Win32_ComputerSystem).UserName; if ($u) { \
        (New-Object Security.Principal.NTAccount($u)).Translate([Security.Principal.SecurityIdentifier]).Value + '|' + $u }");
    let (sid, nom) = sortie.split_once('|')?;
    sid_valide(sid).then(|| Lecteur { sid: sid.into(), nom: nom.into() })
}

fn nom_de(sid: &str) -> String {
    powershell(&format!("try {{ (New-Object Security.Principal.SecurityIdentifier '{sid}').Translate([Security.Principal.NTAccount]).Value }} catch {{ }}"))
}

/// Comptes autorisés. Lu avec le seul contrôle du propriétaire (pas le verrou d'échec de la protection),
/// pour que la reprise après un échec retrouve les lecteurs
pub fn lecteurs() -> Vec<Lecteur> {
    commun::lire_fichier_proprietaire(&commun::dossier().join("lecteurs.json"))
        .and_then(|t| serde_json::from_str(t.trim_start_matches('\u{feff}')).ok())
        .unwrap_or_default()
}

fn sids_lecteurs(l: &[Lecteur]) -> Vec<&str> {
    l.iter().filter(|x| sid_valide(&x.sid)).map(|x| x.sid.as_str()).collect()
}

/// Pose les droits : SYSTEM et administrateurs en contrôle total, lecteurs en lecture, rien d'autre. La DACL
/// est remplacée en entier (une entrée posée par quelqu'un d'autre ne survit pas)
fn appliquer(lecteurs: &[Lecteur]) -> bool {
    let mut sddl = SDDL_DOSSIER.to_string();
    for l in lecteurs.iter().filter(|l| sid_valide(&l.sid)) {
        sddl.push_str(&format!("(A;OICI;0x1200a9;;;{})", l.sid)); // lecture et parcours
    }
    crate::natif::poser_droits(commun::dossier(), &sddl).is_ok()
}

/// icacls : avec /C (continuer sur erreur), le code de retour vaut 0 même quand un élément a échoué ;
/// ne jamais s'en servir comme preuve, relire les droits
pub fn icacls(args: &[&str]) -> bool {
    Command::new("icacls.exe").args(args).creation_flags(0x0800_0000).output().map(|s| s.status.success()).unwrap_or(false)
}

fn est_lien(m: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    m.file_attributes() & 0x400 != 0 // FILE_ATTRIBUTE_REPARSE_POINT
}

fn supprimer_lien(p: &Path) {
    // Un lien vers un dossier se supprime comme un dossier vide, sans toucher à sa cible
    let _ = fs::remove_dir(p).or_else(|_| fs::remove_file(p));
}

/// Sort d'un élément du dossier de données au démarrage
#[derive(Debug, PartialEq)]
pub enum Tri {
    Garder,
    SupprimerLien,
    Ecarter,
}

/// Décision pure : seul un élément dont le propriétaire est LU et acceptable est gardé. Un propriétaire
/// illisible (None) ne vaut pas confiance : un compte standard peut le rendre illisible pour SYSTEM (DACL
/// vide), alors que la prise de possession qui suit le rendrait ensuite « propre ».
pub fn trier_element(lien: bool, proprietaire_ok: Option<bool>) -> Tri {
    if lien {
        Tri::SupprimerLien
    } else if proprietaire_ok == Some(true) {
        Tri::Garder
    } else {
        Tri::Ecarter
    }
}

/// Parcourt le contenu sans suivre les liens : liens supprimés, éléments au propriétaire non vérifié mis de
/// côté. Renvoie les chemins écartés (relatifs)
fn trier(dossier: &Path, racine: &Path, quarantaine: &Path, ecartes: &mut Vec<String>) {
    let Ok(lecture) = fs::read_dir(dossier) else { return };
    for e in lecture.flatten() {
        let p = e.path();
        if p == quarantaine {
            continue;
        }
        let Ok(m) = fs::symlink_metadata(&p) else { continue };
        let relatif = p.strip_prefix(racine).unwrap_or(&p).display().to_string();
        match trier_element(est_lien(&m), crate::natif::proprietaire_de_confiance(&p)) {
            Tri::SupprimerLien => {
                supprimer_lien(&p);
                let ok = fs::symlink_metadata(&p).is_err();
                ecartes.push(format!("{relatif} (lien supprimé){}", if ok { "" } else { " (IMPOSSIBLE À ÉCARTER)" }));
            }
            Tri::Ecarter => {
                let _ = fs::create_dir_all(quarantaine);
                let dest = quarantaine.join(format!("{}-{}", commun::nouvel_id(), relatif.replace(['\\', '/'], "_")));
                // Chaque étape note son erreur : le journal dit pourquoi un élément n'a pas pu être écarté
                let mut erreurs = Vec::new();
                let mut ok = fs::rename(&p, &dest).map_err(|e| erreurs.push(format!("déplacement : {e}"))).is_ok();
                if !ok {
                    // Droits verrouillés par leur propriétaire (DACL vide d'un dossier, par exemple) : prise de
                    // possession de CET élément seul, puis mise de côté. Rien n'est jamais chargé depuis ecartes :
                    // ce n'est pas un blanchiment.
                    // (icacls /setowner échoue ici en rendant 0 : appel Windows direct, privilèges activés)
                    match crate::natif::poser_droits(&p, "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)") {
                        Err(e) => erreurs.push(format!("prise de possession : {e}")),
                        Ok(()) => ok = fs::rename(&p, &dest).map_err(|e| erreurs.push(format!("déplacement après prise de possession : {e}"))).is_ok(),
                    }
                }
                if !ok {
                    ok = (if m.is_dir() { fs::remove_dir_all(&p) } else { fs::remove_file(&p) })
                        .map_err(|e| erreurs.push(format!("suppression : {e}"))).is_ok();
                }
                ecartes.push(format!("{relatif}{}", if ok { String::new() } else { format!(" (IMPOSSIBLE À ÉCARTER : {})", erreurs.join(" ; ")) }));
            }
            Tri::Garder if m.is_dir() => trier(&p, racine, quarantaine, ecartes),
            Tri::Garder => {}
        }
    }
}

/// Dossier « ecartes » : lui-même soumis à la règle (un compte standard pourrait l'avoir créé d'avance, ou en
/// avoir fait un lien). S'il n'est pas sûr, il est supprimé (sans suivre de lien)
fn preparer_quarantaine(q: &Path) -> Result<(), String> {
    let Ok(m) = fs::symlink_metadata(q) else { return Ok(()) };
    match trier_element(est_lien(&m), crate::natif::proprietaire_de_confiance(q)) {
        Tri::Garder => Ok(()),
        Tri::SupprimerLien => {
            supprimer_lien(q);
            if fs::symlink_metadata(q).is_ok() { Err("le dossier ecartes est un lien impossible à supprimer".into()) } else { Ok(()) }
        }
        Tri::Ecarter => fs::remove_dir_all(q).map_err(|e| format!("dossier ecartes au propriétaire non vérifié, impossible à supprimer ({e})")),
    }
}

/// Échec constaté au démarrage (dossier impossible à écarter…) : la vérification horaire ne peut pas le lever,
/// seul un redémarrage réussi du service le fait
static ECHEC_DEMARRAGE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Démarrage du service, avant toute lecture du dossier de données
pub fn securiser() {
    if !crate::natif::est_systeme() {
        let _ = fs::create_dir_all(commun::dossier());
        return;
    }
    let racine = commun::dossier().clone();
    let mut messages = Vec::new();
    let mut echec = None;
    if let Err(e) = crate::natif::activer_privileges() {
        messages.push(format!("privilèges de prise de possession indisponibles ({e})"));
    }
    if let Ok(m) = fs::symlink_metadata(&racine) {
        match trier_element(est_lien(&m), crate::natif::proprietaire_de_confiance(&racine)) {
            Tri::Garder => {}
            Tri::SupprimerLien => {
                supprimer_lien(&racine);
                if fs::symlink_metadata(&racine).is_ok() {
                    echec = Some("le dossier de données est un lien impossible à supprimer".to_string());
                } else {
                    messages.push("le dossier de données était un lien : supprimé".to_string());
                }
            }
            Tri::Ecarter => {
                let ecarte = racine.with_file_name(format!("deR4Tizer.ecarte-{}", commun::maintenant().replace([':', ' '], "-")));
                if fs::rename(&racine, &ecarte).is_ok() {
                    messages.push(format!("le dossier de données n'appartenait pas (de façon vérifiable) à SYSTEM ou aux administrateurs : écarté vers {}", ecarte.display()));
                } else {
                    echec = Some("le dossier de données n'appartient pas (de façon vérifiable) à SYSTEM ou aux administrateurs et n'a pas pu être écarté".to_string());
                }
            }
        }
    }
    // Échec fermé : rien n'est imposé sur un dossier qu'on n'a pas pu écarter ni sur un lien (ce serait le
    // blanchir) ; le service tourne avec ses valeurs par défaut
    let resultat = match echec {
        Some(e) => Err(e),
        None => imposer(&racine, &mut messages),
    };
    // Tout échec du démarrage reste acquis jusqu'au prochain démarrage : la vérification horaire, qui ne revoit
    // que la racine, ne doit pas le lever (le contenu, lui, n'a pas été traité)
    if let Err(e) = &resultat {
        *ECHEC_DEMARRAGE.lock().unwrap() = Some(e.clone());
    }
    for m in messages {
        commun::journal(&format!("protection des données : {m}"));
    }
    publier(resultat);
}

/// Échec fermé : tant que la protection n'est pas vérifiée, aucun fichier de configuration ou de secret n'est
/// chargé (commun::lire_fichier), et l'échec est affiché dans l'interface (etat.json)
/// Décision pure : un échec du démarrage l'emporte sur le résultat d'une vérification ultérieure
pub fn combiner(echec_demarrage: Option<String>, resultat: Result<(), String>) -> Result<(), String> {
    match echec_demarrage {
        Some(e) => Err(e),
        None => resultat,
    }
}

fn publier(resultat: Result<(), String>) {
    match combiner(ECHEC_DEMARRAGE.lock().unwrap().clone(), resultat) {
        Ok(()) => commun::definir_echec_protection(None),
        Err(e) => {
            commun::journal(&format!("protection des données : ÉCHEC ({e}) : configuration et secrets ignorés, valeurs par défaut"));
            commun::definir_echec_protection(Some(e));
        }
    }
}

fn imposer(racine: &Path, messages: &mut Vec<String>) -> Result<(), String> {
    if !racine.exists() && !crate::natif::creer_dossier_protege(racine, SDDL_DOSSIER) {
        return Err(format!("impossible de créer {} avec ses droits", racine.display()));
    }
    // D'abord le dossier racine, propriétaire compris (plus personne d'autre ne peut y créer quoi que ce soit),
    // puis le contenu
    if !appliquer(&[]) {
        return Err("pose du propriétaire ou des droits du dossier refusée".into());
    }
    let quarantaine = racine.join("ecartes");
    preparer_quarantaine(&quarantaine)?;
    let mut ecartes = Vec::new();
    trier(racine, racine, &quarantaine, &mut ecartes);
    if !ecartes.is_empty() {
        messages.push(format!("{} élément(s) d'un autre propriétaire ou lien(s) écarté(s) vers ecartes : {}", ecartes.len(),
            ecartes.iter().take(20).cloned().collect::<Vec<_>>().join(", ")));
    }
    if ecartes.iter().any(|e| e.contains("IMPOSSIBLE")) {
        return Err("un élément d'un autre propriétaire n'a pas pu être écarté".into());
    }
    // Tout ce qui reste appartient à SYSTEM ou aux administrateurs (vérifié par trier). Contenu : droits
    // hérités du dossier, sauf le jeton de l'API et les secrets, qui ont leurs propres droits (posés à la
    // création, à ne pas réinitialiser). Avec /C, icacls rend 0 même en cas d'échec : son code n'est pas
    // une preuve, seules les relectures de droits en sont une (racine, secrets, jeton ci-dessous)
    for e in fs::read_dir(racine).map_err(|e| e.to_string())?.flatten() {
        let n = e.file_name().to_string_lossy().to_string();
        if n != crate::api::FICHIER_JETON && n != "secrets" {
            icacls(&[&e.path().to_string_lossy(), "/reset", "/T", "/C", "/Q"]);
        }
    }
    crate::notifications::preparer_dossier()?;
    crate::api::proteger_jeton()?;
    let l = lecteurs();
    if !appliquer(&l) {
        return Err("pose des droits des comptes autorisés refusée".into());
    }
    verifier(racine, &[SID_SYSTEME, SID_ADMINISTRATEURS], &sids_lecteurs(&l))
}

/// Ajoute un compte autorisé (commande de l'interface) ; renvoie son nom
pub fn autoriser(sid: &str) -> Result<String, String> {
    if !sid_valide(sid) {
        return Err("identifiant de compte invalide".into());
    }
    let mut l = lecteurs();
    let nom = nom_de(sid);
    if !l.iter().any(|x| x.sid == sid) {
        l.push(Lecteur { sid: sid.into(), nom: if nom.is_empty() { sid.into() } else { nom.clone() } });
        commun::ecrire("lecteurs.json", &l);
    }
    if !appliquer(&l) {
        return Err("pose des droits refusée par Windows".into());
    }
    commun::journal(&format!("protection des données : accès en lecture accordé à {}", if nom.is_empty() { sid } else { &nom }));
    Ok(if nom.is_empty() { sid.into() } else { nom })
}

pub fn demarrer() {
    std::thread::Builder::new().name("protection".into()).spawn(|| {
        let mut annonce = false;
        loop {
            let mut l = lecteurs();
            if l.is_empty() {
                if let Some(u) = utilisateur_console() {
                    l.push(u);
                    commun::ecrire("lecteurs.json", &l);
                }
            }
            let resultat = if appliquer(&l) {
                verifier(commun::dossier(), &[SID_SYSTEME, SID_ADMINISTRATEURS], &sids_lecteurs(&l))
            } else {
                Err("pose des droits du dossier refusée".into())
            };
            if !l.is_empty() && !annonce && resultat.is_ok() {
                commun::journal(&format!("protection des données : lecture réservée à SYSTEM, aux administrateurs et à {}",
                    l.iter().map(|x| x.nom.as_str()).collect::<Vec<_>>().join(", ")));
                annonce = true;
            }
            publier(resultat);
            // Personne n'est encore connecté (démarrage du PC) : on réessaie bientôt
            std::thread::sleep(Duration::from_secs(if l.is_empty() { 60 } else { 3600 }));
        }
    }).unwrap();
}
