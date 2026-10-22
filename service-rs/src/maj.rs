//! Mise à jour automatique du service et de l'interface. Une fois par jour : lecture du manifeste de la
//! dernière version publiée (HTTPS), téléchargement des fichiers, contrôle de leur empreinte SHA-256, puis de
//! leur signature Authenticode, qui doit venir du même éditeur que les binaires installés. Un binaire non
//! signé n'est jamais installé automatiquement, sauf réglage explicite (accepter_non_signe), à réserver aux
//! essais : sans signature, l'empreinte ne prouve que l'intégrité du téléchargement, pas son origine.
//! Installation : le paquet MSI publié (msiexec /qn), ou à défaut un script lancé à part qui remplace les fichiers.
//!
//! Manifeste (manifeste.json, publié avec chaque version par la CI) :
//!   { "Version": "4.1", "Fichiers": [ { "Nom": "deR4TizerSvc.exe", "Url": "https://…", "Sha256": "…" }, … ] }

use crate::commun::{self, ConfigMaj};
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct Fichier {
    nom: String,
    url: String,
    sha256: String,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct Manifeste {
    version: String,
    fichiers: Vec<Fichier>,
}

/// État lisible par l'interface (maj.json)
#[derive(Serialize, Default)]
#[serde(rename_all = "PascalCase")]
struct Etat {
    verifie_le: String,
    version_installee: String,
    version_disponible: String,
    statut: String,
}

const NOMS_AUTORISES: &[&str] = &["deR4Tizer.msi", "deR4TizerSvc.exe", "deR4Tizer.exe"];

/// « 4.10 » > « 4.9 » : comparaison numérique des composantes
pub fn plus_recente(disponible: &str, installee: &str) -> bool {
    let v = |s: &str| s.trim_start_matches('v').split('.').map(|x| x.parse::<u64>().unwrap_or(0)).collect::<Vec<_>>();
    let (a, b) = (v(disponible), v(installee));
    for i in 0..a.len().max(b.len()) {
        let (x, y) = (a.get(i).copied().unwrap_or(0), b.get(i).copied().unwrap_or(0));
        if x != y {
            return x > y;
        }
    }
    false
}

fn telecharger(url: &str, destination: &PathBuf) -> Result<(), String> {
    let sortie = Command::new("curl.exe")
        .args(["-sSL", "--fail", "--proto", "=https", "--proto-redir", "=https", "--max-filesize", "52428800", "--max-time", "300",
            "-A", &format!("deR4Tizer/{}", commun::VERSION), "-o"])
        .arg(destination)
        .arg(url)
        .creation_flags(0x0800_0000)
        .output()
        .map_err(|e| e.to_string())?;
    if sortie.status.success() { Ok(()) } else { Err(String::from_utf8_lossy(&sortie.stderr).trim().chars().take(200).collect()) }
}

/// Décision pure sur la signature d'un fichier téléchargé
pub fn signature_acceptable(signataire_nouveau: Option<&str>, signataire_installe: Option<&str>, accepter_non_signe: bool) -> Result<(), String> {
    match (signataire_nouveau, signataire_installe) {
        (Some(n), Some(i)) if n == i => Ok(()),
        (Some(n), Some(i)) => Err(format!("signé par « {n} » au lieu de « {i} »")),
        (Some(_), None) => Ok(()), // première version signée : l'installée ne l'était pas
        (None, Some(i)) => Err(format!("non signé alors que la version installée est signée par « {i} »")),
        (None, None) if accepter_non_signe => Ok(()),
        (None, None) => Err("binaires non signés : mise à jour signalée mais pas installée automatiquement".into()),
    }
}

/// Vérifie et, si tout est en ordre, installe ; renvoie le statut affiché
fn verifier(config: &ConfigMaj, installer: bool) -> (String, String) {
    let dossier = commun::dossier().join("maj");
    let _ = fs::create_dir_all(&dossier);
    let f_manifeste = dossier.join("manifeste.json");
    if let Err(e) = telecharger(&config.url, &f_manifeste) {
        return (String::new(), format!("manifeste illisible ({e})"));
    }
    let Some(m) = fs::read_to_string(&f_manifeste).ok().and_then(|t| serde_json::from_str::<Manifeste>(&t).ok()) else {
        return (String::new(), "manifeste invalide".into());
    };
    if !plus_recente(&m.version, commun::VERSION) {
        return (m.version, "à jour".into());
    }
    if !installer {
        return (m.version.clone(), format!("version {} disponible", m.version));
    }
    let actuel = std::env::current_exe().unwrap_or_default();
    let signataire_installe = crate::natif::signataire_valide(&actuel.to_string_lossy());
    let cible = dossier.join(&m.version);
    let _ = fs::create_dir_all(&cible);
    for f in &m.fichiers {
        if !NOMS_AUTORISES.contains(&f.nom.as_str()) || f.sha256.len() != 64 {
            return (m.version, format!("fichier inattendu dans le manifeste : {}", f.nom));
        }
        let chemin = cible.join(&f.nom);
        if let Err(e) = telecharger(&f.url, &chemin) {
            return (m.version, format!("téléchargement de {} impossible ({e})", f.nom));
        }
        let h = crate::hygiene::empreinte_fichier(&chemin).unwrap_or_default();
        if !h.eq_ignore_ascii_case(&f.sha256) {
            let _ = fs::remove_file(&chemin);
            return (m.version, format!("empreinte de {} incorrecte : fichier rejeté", f.nom));
        }
        let signataire = crate::natif::signataire_valide(&chemin.to_string_lossy());
        if let Err(e) = signature_acceptable(signataire.as_deref(), signataire_installe.as_deref(), config.accepter_non_signe) {
            return (m.version.clone(), format!("version {} disponible, {e}", m.version));
        }
    }
    // Paquet MSI (installation normale) : Windows Installer arrête le service, remplace les fichiers, le relance
    if m.fichiers.iter().any(|f| f.nom == "deR4Tizer.msi") {
        let msi = cible.join("deR4Tizer.msi");
        let journal = dossier.join("installation.log");
        let lance = Command::new("msiexec.exe")
            .arg("/i").arg(&msi).args(["/qn", "/norestart", "/l*v"]).arg(&journal)
            .creation_flags(0x0800_0000 | 0x0000_0008)
            .spawn();
        return match lance {
            Ok(_) => {
                commun::journal(&format!("mise à jour vers la version {} : installation du paquet MSI lancée", m.version));
                (m.version.clone(), format!("installation de la version {} en cours", m.version))
            }
            Err(e) => (m.version, format!("installation impossible ({e})")),
        };
    }
    if m.fichiers.iter().all(|f| f.nom != "deR4TizerSvc.exe") {
        return (m.version, "manifeste sans le service".into());
    }
    // Remplacement par un script à part : le service ne peut pas écraser son propre exécutable
    let installation = actuel.parent().map(|p| p.to_path_buf()).unwrap_or_default();
    let script = format!(
        "Start-Sleep 3; Get-Process deR4Tizer -ErrorAction SilentlyContinue | Stop-Process -Force; \
         Stop-Service deR4Tizer -Force; (Get-Service deR4Tizer).WaitForStatus('Stopped', '00:00:30'); \
         Copy-Item -Path '{}\\*.exe' -Destination '{}' -Force; Start-Service deR4Tizer",
        cible.display().to_string().replace('\'', "''"), installation.display().to_string().replace('\'', "''"));
    let lance = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", &script])
        .creation_flags(0x0800_0000 | 0x0000_0008) // sans fenêtre, détaché
        .spawn();
    match lance {
        Ok(_) => {
            commun::journal(&format!("mise à jour vers la version {} : installation lancée", m.version));
            (m.version.clone(), format!("installation de la version {} en cours", m.version))
        }
        Err(e) => (m.version, format!("installation impossible ({e})")),
    }
}

fn publier(disponible: String, statut: String) {
    commun::ecrire("maj.json", &Etat {
        verifie_le: commun::maintenant(),
        version_installee: commun::VERSION.into(),
        version_disponible: disponible,
        statut,
    });
}

/// Vérification à la demande (bouton de l'interface)
pub fn verifier_maintenant(config: &ConfigMaj) -> String {
    let (v, s) = verifier(config, config.auto);
    publier(v, s.clone());
    s
}

/// Vérification quotidienne, à partir de 10 minutes après le démarrage
pub fn demarrer() {
    std::thread::Builder::new().name("mise à jour".into()).spawn(|| {
        std::thread::sleep(Duration::from_secs(600));
        loop {
            let config: commun::Config = commun::lire("config.json").unwrap_or_default();
            if !config.maj.url.is_empty() {
                let (v, s) = verifier(&config.maj, config.maj.auto);
                publier(v, s);
            }
            std::thread::sleep(Duration::from_secs(86_400));
        }
    }).unwrap();
}
