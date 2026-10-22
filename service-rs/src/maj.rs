//! Mise à jour automatique du service et de l'interface. Une fois par jour : lecture du manifeste de la
//! dernière version publiée (HTTPS), téléchargement, contrôle de l'empreinte SHA-256, puis de la signature
//! Authenticode AVEC contrôle de révocation, et comparaison de la clé publique du signataire à la clé
//! ÉPINGLÉE dans ce binaire à la compilation (variable DER4TIZER_CLE_SIGNATURE, fournie par la CI de
//! publication). Sans clé épinglée, une nouvelle version est seulement signalée, jamais installée : un compte
//! GitHub compromis ne suffit pas à faire exécuter un binaire en SYSTEM sur tout le parc.
//! Installation : un script à part sauvegarde les exécutables, installe (MSI ou copie), puis vérifie que le
//! service répond sur son canal dans les 60 s ; sinon il remet l'ancienne version.
//!
//! Manifeste (manifeste.json, publié avec chaque version par la CI) :
//!   { "Version": "4.2", "Fichiers": [ { "Nom": "deR4Tizer.msi", "Url": "https://…", "Sha256": "…" }, … ] }

use crate::commun::{self, ConfigMaj};
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// Empreinte SHA-256 (hexadécimale) de la clé publique du certificat de signature attendu
const CLE_EPINGLEE: Option<&str> = option_env!("DER4TIZER_CLE_SIGNATURE");

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
    cle_epinglee: bool,
}

const NOMS_AUTORISES: &[&str] = &["deR4Tizer.msi", "deR4TizerSvc.exe", "deR4Tizer.exe"];

/// Numéro de version valide (sert aussi de nom de dossier) : chiffres séparés par des points
pub fn version_valide(v: &str) -> bool {
    !v.is_empty() && v.len() <= 20 && v.split('.').all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

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

/// Décision pure : la clé du fichier (vérifié, révocation comprise) doit être exactement la clé épinglée
pub fn installation_autorisee(cle_fichier: Option<&str>, cle_epinglee: Option<&str>) -> Result<(), String> {
    let Some(attendue) = cle_epinglee.filter(|c| c.len() == 64) else {
        return Err("cette version n'a pas de clé de signature épinglée : mise à jour signalée, pas installée".into());
    };
    match cle_fichier {
        None => Err("signature absente, invalide ou révoquée".into()),
        Some(c) if c.eq_ignore_ascii_case(attendue) => Ok(()),
        Some(_) => Err("signé par une autre clé que celle de deR4Tizer".into()),
    }
}

fn telecharger(url: &str, destination: &Path) -> Result<(), String> {
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

/// Vérifie et, si tout est en ordre (et si l'installation automatique est permise), installe
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
    if !version_valide(&m.version) {
        return (String::new(), "numéro de version invalide dans le manifeste".into());
    }
    if !plus_recente(&m.version, commun::VERSION) {
        return (m.version, "à jour".into());
    }
    if !installer {
        return (m.version.clone(), format!("version {} disponible (installation automatique désactivée)", m.version));
    }
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
        let cle = crate::natif::cle_signataire_verifiee(&chemin.to_string_lossy());
        if let Err(e) = installation_autorisee(cle.as_deref(), CLE_EPINGLEE) {
            let _ = fs::remove_file(&chemin);
            return (m.version.clone(), format!("version {} disponible : {e}", m.version));
        }
    }
    lancer_installation(&m, &cible)
}

/// Script à part (le service ne peut pas se remplacer lui-même) : sauvegarde, installation, contrôle du
/// canal du service pendant 60 s, retour à l'ancienne version en cas d'échec
fn lancer_installation(m: &Manifeste, cible: &Path) -> (String, String) {
    let installation = std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)).unwrap_or_default();
    let sauvegarde = commun::dossier().join("maj").join("sauvegarde");
    let _ = fs::create_dir_all(&sauvegarde);
    for n in ["deR4TizerSvc.exe", "deR4Tizer.exe"] {
        let _ = fs::copy(installation.join(n), sauvegarde.join(n));
    }
    let q = |p: &Path| p.display().to_string().replace('\'', "''");
    let msi = cible.join("deR4Tizer.msi");
    let etape = if msi.exists() {
        format!("Start-Process msiexec.exe -Wait -ArgumentList '/i', '\"{}\"', '/qn', '/norestart', '/l*v', '\"{}\"'",
            q(&msi), q(&commun::dossier().join("maj").join("installation.log")))
    } else {
        format!("Get-Process deR4Tizer -ErrorAction SilentlyContinue | Stop-Process -Force; Stop-Service deR4Tizer -Force; \
                 (Get-Service deR4Tizer).WaitForStatus('Stopped', '00:00:30'); Copy-Item -Path '{}\\*.exe' -Destination '{}' -Force; Start-Service deR4Tizer",
            q(cible), q(&installation))
    };
    let script = format!(
        "Start-Sleep 3; {etape}; \
         $ok = $false; for ($i = 0; $i -lt 60 -and -not $ok; $i++) {{ Start-Sleep 1; \
           $ok = ((Get-Service deR4Tizer -ErrorAction SilentlyContinue).Status -eq 'Running') -and ([IO.Directory]::GetFiles('\\\\.\\pipe\\') -contains '\\\\.\\pipe\\deR4Tizer') }}; \
         if (-not $ok) {{ \
           Stop-Service deR4Tizer -Force -ErrorAction SilentlyContinue; Start-Sleep 2; \
           Copy-Item -Path '{sv}\\*.exe' -Destination '{inst}' -Force; Start-Service deR4Tizer; \
           Set-Content -Path '{echec}' -Value ('échec de la version {v} : ancienne version restaurée le ' + (Get-Date)) }}",
        sv = q(&sauvegarde), inst = q(&installation), v = m.version,
        echec = q(&commun::dossier().join("maj").join("echec.txt")));
    match Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", &script])
        .creation_flags(0x0800_0000 | 0x0000_0008) // sans fenêtre, détaché
        .spawn()
    {
        Ok(_) => {
            commun::journal(&format!("mise à jour vers la version {} : installation lancée (retour arrière si le service ne répond pas)", m.version));
            (m.version.clone(), format!("installation de la version {} en cours", m.version))
        }
        Err(e) => (m.version.clone(), format!("installation impossible ({e})")),
    }
}

fn publier(disponible: String, mut statut: String) {
    if let Ok(e) = fs::read_to_string(commun::dossier().join("maj").join("echec.txt")) {
        statut = format!("{statut} · {}", e.trim());
    }
    commun::ecrire("maj.json", &Etat {
        verifie_le: commun::maintenant(),
        version_installee: commun::VERSION.into(),
        version_disponible: disponible,
        statut,
        cle_epinglee: CLE_EPINGLEE.is_some(),
    });
}

/// Vérification à la demande (bouton de l'interface), dans un fil : la surveillance continue pendant le
/// téléchargement
pub fn verifier_maintenant(config: ConfigMaj) {
    std::thread::spawn(move || {
        let (v, s) = verifier(&config, config.auto);
        publier(v, s);
    });
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
