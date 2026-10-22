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

pub fn lecteurs() -> Vec<Lecteur> {
    commun::lire("lecteurs.json").unwrap_or_default()
}

/// Pose les droits : SYSTEM et administrateurs en contrôle total, lecteurs en lecture, rien d'autre
fn appliquer(lecteurs: &[Lecteur]) -> bool {
    let dossier = commun::dossier().to_string_lossy().to_string();
    let mut args = vec![dossier.clone(), "/inheritance:r".into(), "/grant:r".into(), "*S-1-5-18:(OI)(CI)F".into(), "*S-1-5-32-544:(OI)(CI)F".into()];
    args.extend(lecteurs.iter().filter(|l| sid_valide(&l.sid)).map(|l| format!("*{}:(OI)(CI)RX", l.sid)));
    let ok = Command::new("icacls.exe").args(&args).creation_flags(0x0800_0000).output().map(|s| s.status.success()).unwrap_or(false);
    // Utilisateurs (S-1-5-32-545) et Utilisateurs authentifiés (S-1-5-11) : retirés
    let _ = Command::new("icacls.exe").args([dossier.as_str(), "/remove:g", "*S-1-5-32-545", "*S-1-5-11"])
        .creation_flags(0x0800_0000).output();
    ok
}

fn icacls(args: &[&str]) -> bool {
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

/// Parcourt le contenu sans suivre les liens : liens supprimés, éléments d'un autre propriétaire mis de côté.
/// Renvoie les chemins écartés (relatifs)
fn trier(dossier: &Path, racine: &Path, quarantaine: &Path, ecartes: &mut Vec<String>) {
    let Ok(lecture) = fs::read_dir(dossier) else { return };
    for e in lecture.flatten() {
        let p = e.path();
        if p == quarantaine || p.starts_with(quarantaine) {
            continue;
        }
        let Ok(m) = fs::symlink_metadata(&p) else { continue };
        let relatif = p.strip_prefix(racine).unwrap_or(&p).display().to_string();
        if est_lien(&m) {
            supprimer_lien(&p);
            ecartes.push(format!("{relatif} (lien supprimé)"));
        } else if crate::natif::proprietaire_de_confiance(&p) == Some(false) {
            let _ = fs::create_dir_all(quarantaine);
            let dest = quarantaine.join(relatif.replace(['\\', '/'], "_"));
            let ok = fs::rename(&p, &dest).is_ok() || (if m.is_dir() { fs::remove_dir_all(&p) } else { fs::remove_file(&p) }).is_ok();
            ecartes.push(format!("{relatif}{}", if ok { "" } else { " (IMPOSSIBLE À ÉCARTER)" }));
        } else if m.is_dir() {
            trier(&p, racine, quarantaine, ecartes);
        }
    }
}

/// Démarrage du service, avant toute lecture du dossier de données
pub fn securiser() {
    if !crate::natif::est_systeme() {
        let _ = fs::create_dir_all(commun::dossier());
        return;
    }
    let racine = commun::dossier().clone();
    let mut messages = Vec::new();
    if let Ok(m) = fs::symlink_metadata(&racine) {
        if est_lien(&m) {
            supprimer_lien(&racine);
            messages.push("le dossier de données était un lien : supprimé".to_string());
        } else if crate::natif::proprietaire_de_confiance(&racine) != Some(true) {
            let ecarte = racine.with_file_name(format!("deR4Tizer.ecarte-{}", commun::maintenant().replace([':', ' '], "-")));
            if fs::rename(&racine, &ecarte).is_ok() {
                messages.push(format!("le dossier de données n'appartenait ni à SYSTEM ni aux administrateurs : écarté vers {}", ecarte.display()));
            } else {
                messages.push("le dossier de données n'appartenait ni à SYSTEM ni aux administrateurs et n'a pas pu être écarté : propriétaire imposé".into());
            }
        }
    }
    if !racine.exists() && !crate::natif::creer_dossier_protege(&racine, SDDL_DOSSIER) {
        let _ = fs::create_dir_all(&racine);
    }
    let r = racine.to_string_lossy().to_string();
    // D'abord le dossier racine (plus personne d'autre ne peut y créer quoi que ce soit), puis le contenu
    icacls(&[&r, "/setowner", "*S-1-5-32-544", "/C", "/Q"]);
    appliquer(&[]);
    let quarantaine = racine.join("ecartes");
    let mut ecartes = Vec::new();
    trier(&racine, &racine, &quarantaine, &mut ecartes);
    icacls(&[&r, "/setowner", "*S-1-5-32-544", "/T", "/C", "/Q"]);
    icacls(&[&format!("{r}\\*"), "/reset", "/T", "/C", "/Q"]);
    if !ecartes.is_empty() {
        messages.push(format!("{} élément(s) d'un autre propriétaire ou lien(s) écarté(s) vers ecartes : {}", ecartes.len(),
            ecartes.iter().take(20).cloned().collect::<Vec<_>>().join(", ")));
    }
    // Droits définitifs : secrets réservés aux administrateurs, lecteurs autorisés (lecteurs.json vérifié)
    crate::notifications::preparer_dossier();
    crate::api::proteger_jeton();
    if racine.join("maj").join("installation").exists() {
        crate::maj::dossier_installation();
    }
    appliquer(&lecteurs());
    for m in messages {
        commun::journal(&format!("protection des données : {m}"));
    }
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
    appliquer(&l);
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
            let ok = appliquer(&l);
            if !l.is_empty() {
                if !annonce {
                    commun::journal(&format!("protection des données : lecture réservée à SYSTEM, aux administrateurs et à {}{}",
                        l.iter().map(|x| x.nom.as_str()).collect::<Vec<_>>().join(", "), if ok { "" } else { " (ÉCHEC de la pose des droits)" }));
                    annonce = true;
                }
                std::thread::sleep(Duration::from_secs(3600));
            } else {
                // Personne n'est encore connecté (démarrage du PC) : on réessaie bientôt
                std::thread::sleep(Duration::from_secs(60));
            }
        }
    }).unwrap();
}
