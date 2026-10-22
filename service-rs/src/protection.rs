//! Protection des données : le dossier de deR4Tizer (événements du SIEM, sessions DPI, trafic, appareils
//! du réseau, alertes avec lignes de commande…) n'est lisible que par SYSTEM, les administrateurs et les
//! comptes autorisés (lecteurs.json), plus par tous les utilisateurs du PC. Par défaut, le compte connecté
//! à la console au premier démarrage ; d'autres comptes s'ajoutent depuis l'interface (avec l'UAC).
//! Les droits sont reposés au démarrage puis toutes les heures.

use crate::commun;
use serde::{Deserialize, Serialize};
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::time::Duration;

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
            if !l.is_empty() {
                let ok = appliquer(&l);
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
