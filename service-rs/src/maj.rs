//! Mise à jour automatique du service et de l'interface. Une fois par jour : lecture du manifeste de la
//! dernière version publiée (HTTPS), téléchargement, contrôle de l'empreinte SHA-256, puis de la signature
//! Authenticode AVEC contrôle de révocation, et comparaison de la clé publique du signataire aux clés
//! ÉPINGLÉES dans ce binaire à la compilation (variable DER4TIZER_CLE_SIGNATURE, fournie par la CI de
//! publication : la clé actuelle et la suivante, séparées par des virgules, pour survivre au renouvellement
//! du certificat). Sans clé épinglée, une nouvelle version est seulement signalée, jamais installée : un
//! compte GitHub compromis ne suffit pas à faire exécuter un binaire en SYSTEM sur tout le parc.
//!
//! Les fichiers sont téléchargés et vérifiés dans %ProgramFiles%\deR4Tizer\maj, réservé à SYSTEM (propriétaire
//! et droits vérifiés avant chaque usage, mise à jour refusée sinon) : aucun autre compte ne peut les remplacer
//! entre la vérification et l'exécution. Le dossier est supprimé à la désinstallation (--nettoyer).
//! Installation : un script à part sauvegarde les exécutables, revérifie l'empreinte juste avant d'exécuter,
//! installe (MSI ou copie), puis envoie la commande « verification » sur le canal du service pendant 60 s.
//! Sans réponse de la nouvelle version : réinstallation du paquet MSI de la version précédente s'il a été
//! gardé (base Windows Installer cohérente), sinon remise des anciens exécutables.
//!
//! Manifeste (manifeste.json, publié avec chaque version par la CI) :
//!   { "Version": "4.2", "Fichiers": [ { "Nom": "deR4Tizer.msi", "Url": "https://…", "Sha256": "…" }, … ] }

use crate::commun::{self, ConfigMaj};
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// Empreintes SHA-256 (hexadécimales) des clés publiques des certificats de signature acceptés
const CLES_EPINGLEES: Option<&str> = option_env!("DER4TIZER_CLE_SIGNATURE");

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

fn hexa_64(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Liste des clés épinglées : empreintes de 64 caractères hexadécimaux, séparées par des virgules, des
/// points-virgules ou des espaces ; tout le reste (variable vide, valeur tronquée) est ignoré
pub fn cles_epinglees(brut: Option<&str>) -> Vec<String> {
    brut.unwrap_or("").split([',', ';', ' ', '\n', '\r', '\t']).map(str::trim).filter(|c| hexa_64(c)).map(str::to_lowercase).collect()
}

/// Décision pure : la clé du fichier (vérifié, révocation comprise) doit être l'une des clés épinglées
pub fn installation_autorisee(cle_fichier: Option<&str>, cles: &[String]) -> Result<(), String> {
    if cles.is_empty() {
        return Err("cette version n'a pas de clé de signature épinglée : mise à jour signalée, pas installée".into());
    }
    match cle_fichier {
        None => Err("signature absente, invalide ou révoquée".into()),
        Some(c) if cles.iter().any(|k| k.eq_ignore_ascii_case(c)) => Ok(()),
        Some(_) => Err("signé par une autre clé que celles de deR4Tizer".into()),
    }
}


/// Dossier de travail : %ProgramFiles%\deR4Tizer\maj (à côté des exécutables, hors du dossier de données),
/// SYSTEM seul. Les administrateurs en sont exclus aussi : seul le service y écrit.
pub fn dossier_travail() -> PathBuf {
    std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("maj"))).unwrap_or_else(|| PathBuf::from("maj"))
}

const SDDL_TRAVAIL: &str = "O:SYD:PAI(A;OICI;FA;;;SY)";

/// Prépare le dossier de travail et vérifie propriétaire et droits ; Err : mise à jour refusée (échec fermé)
pub fn preparer_dossier_travail() -> Result<PathBuf, String> {
    use crate::protection::{verifier, SID_SYSTEME};
    let d = dossier_travail();
    if fs::symlink_metadata(&d).is_ok_and(|m| { use std::os::windows::fs::MetadataExt; m.file_attributes() & 0x400 != 0 }) {
        return Err(format!("{} est un lien : mise à jour refusée", d.display()));
    }
    if !d.exists() && !crate::natif::creer_dossier_protege(&d, SDDL_TRAVAIL) {
        return Err(format!("{} impossible à créer avec ses droits", d.display()));
    }
    if !crate::natif::est_systeme() {
        return Err("mise à jour réservée au service (SYSTEM)".into());
    }
    if verifier(&d, &[SID_SYSTEME], &[]).is_err() {
        crate::natif::poser_droits(&d, SDDL_TRAVAIL).map_err(|e| format!("droits du dossier de mise à jour refusés ({e})"))?;
    }
    // Contenu : droits hérités du dossier (aucun droit explicite laissé par quelqu'un d'autre)
    // (code d'icacls /C non probant : la preuve est la relecture ci-dessous, et l'empreinte revérifiée avant
    // exécution)
    crate::protection::icacls(&[&format!(r"{}\*", d.display()), "/reset", "/T", "/C", "/Q"]);
    verifier(&d, &[SID_SYSTEME], &[])?;
    Ok(d)
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
    let Some(m) = commun::lire_fichier(&f_manifeste).and_then(|t| serde_json::from_str::<Manifeste>(&t).ok()) else {
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
    let cles = cles_epinglees(CLES_EPINGLEES);
    let installation = match preparer_dossier_travail() {
        Ok(d) => d,
        Err(e) => return (m.version.clone(), format!("version {} disponible : {e}", m.version)),
    };
    // Anciennes dispositions (4.2, 4.3) : téléchargements et sauvegarde dans le dossier de données
    for ancien in ["sauvegarde", "installation", m.version.as_str()] {
        let _ = fs::remove_dir_all(dossier.join(ancien));
    }
    // On garde le paquet de la version installée (retour arrière) et rien d'autre
    for e in fs::read_dir(&installation).into_iter().flatten().flatten() {
        let n = e.file_name().to_string_lossy().to_string();
        if n != commun::VERSION && n != "sauvegarde" {
            let _ = fs::remove_dir_all(e.path()).or_else(|_| fs::remove_file(e.path()));
        }
    }
    let cible = installation.join(&m.version);
    let _ = fs::create_dir_all(&cible);
    let mut verifies = Vec::new();
    for f in &m.fichiers {
        if !NOMS_AUTORISES.contains(&f.nom.as_str()) || !hexa_64(&f.sha256) {
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
        if let Err(e) = installation_autorisee(cle.as_deref(), &cles) {
            let _ = fs::remove_file(&chemin);
            return (m.version.clone(), format!("version {} disponible : {e}", m.version));
        }
        verifies.push((chemin, f.sha256.to_lowercase()));
    }
    if verifies.is_empty() {
        return (m.version, "manifeste sans fichier".into());
    }
    lancer_installation(&m.version, &installation, &verifies)
}

/// Script à part (le service ne peut pas se remplacer lui-même) : sauvegarde, contrôle des empreintes juste
/// avant l'exécution, installation, contrôle du service par son canal, retour arrière en cas d'échec
fn lancer_installation(version: &str, installation: &Path, fichiers: &[(PathBuf, String)]) -> (String, String) {
    let programme = std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)).unwrap_or_default();
    let sauvegarde = installation.join("sauvegarde");
    let _ = fs::create_dir_all(&sauvegarde);
    for n in ["deR4TizerSvc.exe", "deR4Tizer.exe"] {
        let _ = fs::copy(programme.join(n), sauvegarde.join(n));
    }
    let script = script_installation(version, installation, &programme, fichiers);
    match Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", &script])
        .creation_flags(0x0800_0000 | 0x0000_0008) // sans fenêtre, détaché
        .spawn()
    {
        Ok(_) => {
            let _ = fs::remove_file(commun::dossier().join("maj").join("echec.txt"));
            commun::journal(&format!("mise à jour vers la version {version} : installation lancée (retour arrière si le service ne répond pas)"));
            (version.to_string(), format!("installation de la version {version} en cours"))
        }
        Err(e) => (version.to_string(), format!("installation impossible ({e})")),
    }
}

/// Texte du script d'installation (fonction à part pour le tester)
pub fn script_installation(version: &str, installation: &Path, programme: &Path, fichiers: &[(PathBuf, String)]) -> String {
    let sauvegarde = installation.join("sauvegarde");
    let q = |p: &Path| p.display().to_string().replace('\'', "''");
    let journal_msi = commun::dossier().join("maj").join("installation.log");
    let controle = fichiers.iter()
        .map(|(p, h)| format!("((Get-FileHash -Algorithm SHA256 -LiteralPath '{}').Hash -eq '{h}')", q(p)))
        .collect::<Vec<_>>().join(" -and ");
    let msiexec = |paquet: &Path, journal: &Path| format!(
        "Start-Process msiexec.exe -Wait -ArgumentList '/i', '\"{}\"', '/qn', '/norestart', '/l*v', '\"{}\"'", q(paquet), q(journal));
    let etape = match fichiers.iter().find(|(p, _)| p.file_name().is_some_and(|n| n == "deR4Tizer.msi")) {
        Some((msi, _)) => msiexec(msi, &journal_msi),
        None => {
            let dossier = fichiers[0].0.parent().unwrap_or(installation);
            format!("Get-Process deR4Tizer -ErrorAction SilentlyContinue | Stop-Process -Force; Stop-Service deR4Tizer -Force; \
                     (Get-Service deR4Tizer).WaitForStatus('Stopped', '00:00:30'); Copy-Item -Path '{}\\*.exe' -Destination '{}' -Force; Start-Service deR4Tizer",
                q(dossier), q(programme))
        }
    };
    // Paquet de la version installée, gardé si elle-même est arrivée par mise à jour
    let ancien_msi = installation.join(commun::VERSION).join("deR4Tizer.msi");
    let retour = format!(
        "if (Test-Path -LiteralPath '{a}') {{ {reinstaller}; $mode = 'paquet de la version {va} réinstallé' }} \
         else {{ Stop-Service deR4Tizer -Force -ErrorAction SilentlyContinue; Start-Sleep 2; \
           Copy-Item -Path '{sv}\\*.exe' -Destination '{prog}' -Force; Start-Service deR4Tizer; \
           $mode = 'anciens exécutables remis (Windows Installer indique encore la version {v})' }}",
        a = q(&ancien_msi), reinstaller = msiexec(&ancien_msi, &commun::dossier().join("maj").join("retour.log")),
        va = commun::VERSION, sv = q(&sauvegarde), prog = q(programme), v = version);
    let echec = q(&commun::dossier().join("maj").join("echec.txt"));
    format!(
        "function Repond {{ try {{ $c = New-Object IO.Pipes.NamedPipeClientStream('.', 'deR4Tizer', [IO.Pipes.PipeDirection]::InOut); \
           $c.Connect(2000); $w = New-Object IO.StreamWriter($c); $w.AutoFlush = $true; $r = New-Object IO.StreamReader($c); \
           $w.WriteLine('{{\"Action\":\"verification\"}}'); $l = $r.ReadLine(); $c.Dispose(); \
           return ($l -match '\"Ok\":true' -and $l -match 'deR4Tizer {ve}\"') }} catch {{ return $false }} }}; \
         Start-Sleep 3; \
         if (-not ({controle})) {{ Set-Content -Path '{echec}' -Value ('version {v} : fichier modifié après vérification, installation abandonnée le ' + (Get-Date)); exit }}; \
         {etape}; \
         $ok = $false; for ($i = 0; $i -lt 30 -and -not $ok; $i++) {{ Start-Sleep 2; $ok = Repond }}; \
         if (-not $ok) {{ {retour}; \
           Set-Content -Path '{echec}' -Value ('échec de la version {v} (pas de réponse du service) : ' + $mode + ' le ' + (Get-Date)) }}",
        ve = version.replace('.', "\\."), v = version)
}

fn publier(disponible: String, mut statut: String) {
    if let Some(e) = commun::lire_fichier(&commun::dossier().join("maj").join("echec.txt")) {
        statut = format!("{statut} · {}", e.trim());
    }
    commun::ecrire("maj.json", &Etat {
        verifie_le: commun::maintenant(),
        version_installee: commun::VERSION.into(),
        version_disponible: disponible,
        statut,
        cle_epinglee: !cles_epinglees(CLES_EPINGLEES).is_empty(),
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
