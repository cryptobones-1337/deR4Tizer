//! Mise à jour automatique du service et de l'interface. Une fois par jour : lecture du manifeste de la
//! dernière version publiée (HTTPS), téléchargement du paquet MSI, contrôle de l'empreinte SHA-256, puis de la
//! signature Authenticode AVEC contrôle de révocation, comparaison de la clé publique du signataire aux clés
//! ÉPINGLÉES dans ce binaire à la compilation (variable DER4TIZER_CLES_SIGNATURE, fournie par la CI de
//! publication : la clé actuelle et la suivante, séparées par des virgules, pour survivre au renouvellement
//! du certificat), et enfin lecture de la version RÉELLE dans le paquet signé (ProductVersion, UpgradeCode).
//! Le manifeste n'étant pas signé, il ne fait jamais foi seul : un manifeste annonçant « 99.0 » pour une
//! ancienne version signée est refusé, puisque la version du paquet doit être celle du manifeste et
//! strictement plus récente que la version installée. Sans clé épinglée, une nouvelle version est seulement
//! signalée, jamais installée.
//!
//! Les fichiers sont téléchargés et vérifiés dans %ProgramFiles%\deR4Tizer\maj, réservé à SYSTEM (propriétaire
//! et droits vérifiés avant chaque usage, mise à jour refusée sinon). Le dossier est supprimé à la
//! désinstallation (--nettoyer).
//!
//! Retour arrière : avant toute installation, le service se procure le paquet MSI de SA PROPRE version (sur la
//! version GitHub correspondante), vérifié comme le nouveau (signature, clé épinglée, version, UpgradeCode), et
//! le garde dans le dossier de travail ; sans lui, rien n'est installé. Un script à part revérifie les deux
//! empreintes juste avant d'exécuter, installe, puis envoie la commande « verification » sur le canal du
//! service et exige une réponse JSON valide de la nouvelle version ; à défaut, il réinstalle le paquet de la
//! version précédente (base Windows Installer cohérente). Jamais de copie d'exécutables.
//!
//! Manifeste (manifeste.json, publié avec chaque version par la CI), strict : champs connus seulement, 64 Ko
//! au plus, exactement un fichier, le paquet MSI :
//!   { "Version": "4.3", "Fichiers": [ { "Nom": "deR4Tizer.msi", "Url": "https://…", "Sha256": "…" } ] }

use crate::commun::{self, ConfigMaj};
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// Empreintes SHA-256 (hexadécimales) des clés publiques des certificats de signature acceptés
const CLES_EPINGLEES: Option<&str> = option_env!("DER4TIZER_CLES_SIGNATURE");

/// UpgradeCode du paquet MSI de deR4Tizer (installeur\deR4Tizer.wxs) : un paquet signé d'un autre produit
/// est refusé
pub const UPGRADE_CODE: &str = "{6F1E2B47-9C3A-4D58-8E21-4B7D0C9A3F15}";
pub const NOM_PAQUET: &str = "deR4Tizer.msi";
const TAILLE_MAX_MANIFESTE: usize = 64 * 1024;

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct Fichier {
    pub nom: String,
    pub url: String,
    pub sha256: String,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct Manifeste {
    pub version: String,
    pub fichiers: Vec<Fichier>,
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

/// « 4.3 » et « 4.3.0 » désignent la même version (Windows Installer exige trois nombres)
pub fn meme_version(a: &str, b: &str) -> bool {
    version_valide(a) && version_valide(b) && !plus_recente(a, b) && !plus_recente(b, a)
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

/// Décision pure : lecture stricte du manifeste. Taille bornée, champs connus seulement, version valide,
/// exactement un fichier, le paquet MSI, empreinte hexadécimale, URL HTTPS
pub fn lire_manifeste(octets: &[u8]) -> Result<Manifeste, String> {
    if octets.len() > TAILLE_MAX_MANIFESTE {
        return Err(format!("manifeste trop gros ({} octets)", octets.len()));
    }
    let texte = std::str::from_utf8(octets).map_err(|_| "manifeste illisible (UTF-8 attendu)".to_string())?;
    let m: Manifeste = serde_json::from_str(texte.trim_start_matches('\u{feff}')).map_err(|e| format!("manifeste invalide ({e})"))?;
    if !version_valide(&m.version) {
        return Err("numéro de version invalide dans le manifeste".into());
    }
    let paquets = m.fichiers.iter().filter(|f| f.nom == NOM_PAQUET).count();
    if let Some(f) = m.fichiers.iter().find(|f| f.nom != NOM_PAQUET) {
        return Err(format!("fichier inattendu dans le manifeste : {}", f.nom));
    }
    match paquets {
        0 => return Err("paquet MSI absent du manifeste".into()),
        1 => {}
        _ => return Err("paquet MSI en double dans le manifeste".into()),
    }
    let f = &m.fichiers[0];
    if !hexa_64(&f.sha256) {
        return Err("empreinte du paquet invalide dans le manifeste".into());
    }
    if !f.url.starts_with("https://") || f.url.len() > 2048 || f.url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("adresse du paquet invalide dans le manifeste".into());
    }
    Ok(m)
}

/// Constat sur un paquet téléchargé, établi par l'appelant dans cet ordre : empreinte, signature (clé du
/// signataire, révocation comprise), puis seulement propriétés lues dans le paquet signé
#[derive(Debug, Clone, Default)]
pub struct Artefact {
    pub sha256: String,
    pub cle: Option<String>,
    /// (ProductVersion, UpgradeCode)
    pub proprietes: Option<(String, String)>,
}

/// Décision pure : un paquet signé par une clé épinglée, de deR4Tizer (UpgradeCode), et dont la version réelle
/// est `version_attendue`
pub fn verifier_artefact(a: &Artefact, version_attendue: &str, cles: &[String]) -> Result<(), String> {
    installation_autorisee(a.cle.as_deref(), cles)?;
    let (version, code) = a.proprietes.as_ref().ok_or("propriétés du paquet illisibles")?;
    if !code.eq_ignore_ascii_case(UPGRADE_CODE) {
        return Err(format!("paquet d'un autre produit (UpgradeCode {code})"));
    }
    if !meme_version(version, version_attendue) {
        return Err(format!("version du paquet ({version}) différente de celle attendue ({version_attendue})"));
    }
    Ok(())
}

/// Décision pure d'installation du nouveau paquet : empreinte du manifeste, artefact vérifié pour la version
/// du manifeste, et version strictement plus récente que la version installée
pub fn decision_installation(m: &Manifeste, a: &Artefact, installee: &str, cles: &[String]) -> Result<(), String> {
    let f = m.fichiers.first().ok_or("manifeste sans fichier")?;
    if !a.sha256.eq_ignore_ascii_case(&f.sha256) {
        return Err("empreinte du paquet différente de celle du manifeste".into());
    }
    verifier_artefact(a, &m.version, cles)?;
    if !plus_recente(&m.version, installee) {
        return Err(format!("version {} pas plus récente que la version installée ({installee})", m.version));
    }
    Ok(())
}

/// Adresse du paquet d'une version donnée, dérivée de celle du manifeste :
/// …/releases/latest/download/manifeste.json → …/releases/download/v<version>/deR4Tizer.msi
pub fn url_paquet_version(url_manifeste: &str, version: &str) -> Option<String> {
    let (base, reste) = url_manifeste.split_once("/releases/latest/download/")?;
    (base.starts_with("https://") && reste == "manifeste.json" && version_valide(version))
        .then(|| format!("{base}/releases/download/v{version}/{NOM_PAQUET}"))
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

fn telecharger(url: &str, destination: &Path, taille_max: usize) -> Result<(), String> {
    let sortie = Command::new("curl.exe")
        .args(["-sSL", "--fail", "--proto", "=https", "--proto-redir", "=https", "--max-filesize", &taille_max.to_string(), "--max-time", "300",
            "-A", &format!("deR4Tizer/{}", commun::VERSION), "-o"])
        .arg(destination)
        .arg(url)
        .creation_flags(0x0800_0000)
        .output()
        .map_err(|e| e.to_string())?;
    if sortie.status.success() { Ok(()) } else { Err(String::from_utf8_lossy(&sortie.stderr).trim().chars().take(200).collect()) }
}

/// Constat sur un paquet présent sur le disque : empreinte, signature, puis propriétés (lues seulement si la
/// signature est celle d'une clé épinglée)
fn constater(chemin: &Path, cles: &[String]) -> Artefact {
    let sha256 = crate::hygiene::empreinte_fichier(chemin).unwrap_or_default();
    let cle = crate::natif::cle_signataire_verifiee(&chemin.to_string_lossy());
    let proprietes = if installation_autorisee(cle.as_deref(), cles).is_ok() { crate::natif::proprietes_msi(chemin).ok() } else { None };
    Artefact { sha256, cle, proprietes }
}

/// Paquet de la version installée, pour le retour arrière : gardé dans maj\<version>\, revérifié à chaque
/// usage, téléchargé depuis la version GitHub correspondante s'il manque ou n'est pas valide. Renvoie son
/// chemin et son empreinte ; sans lui, aucune installation.
fn preparer_paquet_retour(travail: &Path, url_manifeste: &str, cles: &[String]) -> Result<(PathBuf, String), String> {
    let dossier = travail.join(commun::VERSION);
    let paquet = dossier.join(NOM_PAQUET);
    if paquet.exists() {
        let a = constater(&paquet, cles);
        if verifier_artefact(&a, commun::VERSION, cles).is_ok() {
            return Ok((paquet, a.sha256));
        }
        let _ = fs::remove_file(&paquet);
    }
    let url = url_paquet_version(url_manifeste, commun::VERSION)
        .ok_or("adresse du paquet de la version installée impossible à déduire du manifeste")?;
    fs::create_dir_all(&dossier).map_err(|e| e.to_string())?;
    telecharger(&url, &paquet, 52_428_800).map_err(|e| format!("paquet de la version installée ({}) introuvable : {e}", commun::VERSION))?;
    let a = constater(&paquet, cles);
    if let Err(e) = verifier_artefact(&a, commun::VERSION, cles) {
        let _ = fs::remove_file(&paquet);
        return Err(format!("paquet de la version installée refusé : {e}"));
    }
    Ok((paquet, a.sha256))
}

/// Vérifie et, si tout est en ordre (et si l'installation automatique est permise), installe
fn verifier(config: &ConfigMaj, installer: bool) -> (String, String) {
    let dossier = commun::dossier().join("maj");
    let _ = fs::create_dir_all(&dossier);
    let f_manifeste = dossier.join("manifeste.json");
    if let Err(e) = telecharger(&config.url, &f_manifeste, TAILLE_MAX_MANIFESTE) {
        return (String::new(), format!("manifeste illisible ({e})"));
    }
    // Lu avec le contrôle du propriétaire, comme tout fichier du dossier de données (la confiance vient de
    // toute façon du paquet signé)
    let lu = commun::lire_fichier(&f_manifeste).ok_or_else(|| "manifeste illisible ou protection du dossier non vérifiée".to_string());
    let m = match lu.and_then(|t| lire_manifeste(t.as_bytes())) {
        Ok(m) => m,
        Err(e) => return (String::new(), e),
    };
    if !plus_recente(&m.version, commun::VERSION) {
        return (m.version, "à jour".into());
    }
    if !installer {
        return (m.version.clone(), format!("version {} disponible (installation automatique désactivée)", m.version));
    }
    let v = m.version.clone();
    let refus = |e: String| (v.clone(), format!("version {v} disponible : {e}"));
    let cles = cles_epinglees(CLES_EPINGLEES);
    // Sans clé épinglée, rien ne sera jamais installé : inutile de télécharger
    if cles.is_empty() {
        return refus("cette version n'a pas de clé de signature épinglée : mise à jour signalée, pas installée".into());
    }
    let travail = match preparer_dossier_travail() {
        Ok(d) => d,
        Err(e) => return refus(e),
    };
    // Anciennes dispositions (4.2, 4.3) : téléchargements et sauvegarde dans le dossier de données
    for ancien in ["sauvegarde", "installation", m.version.as_str()] {
        let _ = fs::remove_dir_all(dossier.join(ancien));
    }
    // On garde le paquet de la version installée (retour arrière) et rien d'autre
    for e in fs::read_dir(&travail).into_iter().flatten().flatten() {
        if e.file_name().to_string_lossy() != commun::VERSION {
            let _ = fs::remove_dir_all(e.path()).or_else(|_| fs::remove_file(e.path()));
        }
    }
    let (retour, sha_retour) = match preparer_paquet_retour(&travail, &config.url, &cles) {
        Ok(r) => r,
        Err(e) => return refus(format!("{e} ; pas d'installation sans retour arrière possible")),
    };
    let cible = travail.join(&m.version);
    let _ = fs::create_dir_all(&cible);
    let paquet = cible.join(NOM_PAQUET);
    if let Err(e) = telecharger(&m.fichiers[0].url, &paquet, 52_428_800) {
        return refus(format!("téléchargement du paquet impossible ({e})"));
    }
    let a = constater(&paquet, &cles);
    if let Err(e) = decision_installation(&m, &a, commun::VERSION, &cles) {
        let _ = fs::remove_file(&paquet);
        return refus(e);
    }
    lancer_installation(&ParametresScript {
        version: &m.version,
        paquet: &paquet,
        sha_paquet: &a.sha256,
        retour: &retour,
        sha_retour: &sha_retour,
        journaux: &dossier,
        simulation: None,
    })
}

/// Paramètres du script d'installation
pub struct ParametresScript<'a> {
    pub version: &'a str,
    pub paquet: &'a Path,
    pub sha_paquet: &'a str,
    /// Paquet de la version installée (retour arrière)
    pub retour: &'a Path,
    pub sha_retour: &'a str,
    /// Dossier des journaux d'installation et du fichier echec.txt
    pub journaux: &'a Path,
    /// Tests : (journal des actions simulées, réponse simulée du service) ; ni msiexec ni canal
    pub simulation: Option<Simulation<'a>>,
}

/// Simulation du script (tests) : actions consignées dans `journal`, ni msiexec ni canal
pub struct Simulation<'a> {
    pub journal: &'a Path,
    /// Réponse du « service » sur le canal
    pub reponse: &'a str,
    /// Processus qui tient le tube, et processus du service
    pub pid_serveur: u32,
    pub pid_service: u32,
}

/// PowerShell : PID du processus serveur d'un tube nommé ouvert ($c, NamedPipeClientStream connecté)
pub const PS_PID_SERVEUR: &str = "Add-Type -Namespace D4T -Name Tube -MemberDefinition \
    '[DllImport(\"kernel32.dll\", SetLastError = true)] public static extern bool GetNamedPipeServerProcessId(IntPtr p, out uint id);'; \
    function Pid-Serveur($c) { [uint32]$p = 0; [void][D4T.Tube]::GetNamedPipeServerProcessId($c.SafePipeHandle.DangerousGetHandle(), [ref]$p); return $p }";

/// Script à part (le service ne peut pas se remplacer lui-même) : empreintes revérifiées juste avant
/// l'exécution, installation, contrôle du service par son canal, retour arrière par le paquet précédent
fn lancer_installation(p: &ParametresScript) -> (String, String) {
    let script = script_installation(p);
    match Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", &script])
        .creation_flags(0x0800_0000 | 0x0000_0008) // sans fenêtre, détaché
        .spawn()
    {
        Ok(_) => {
            let _ = fs::remove_file(p.journaux.join("echec.txt"));
            commun::journal(&format!("mise à jour vers la version {} : installation lancée (retour arrière si le service ne répond pas)", p.version));
            (p.version.to_string(), format!("installation de la version {} en cours", p.version))
        }
        Err(e) => (p.version.to_string(), format!("installation impossible ({e})")),
    }
}

/// PowerShell : interrogation du service par son canal, code exact du script de production (testé tel quel
/// sur un vrai tube). Pid-Service : processus du service `service` ; Lire-Reponse : $null si le tube `tube`
/// n'est pas tenu par ce processus, sinon la réponse à {"Action":"verification"}.
pub fn ps_canal(tube: &str, service: &str) -> String {
    format!(
        "{PS_PID_SERVEUR}; \
         function Pid-Service {{ [uint32](Get-CimInstance Win32_Service -Filter \"Name='{service}'\").ProcessId }}; \
         function Lire-Reponse {{ $c = New-Object IO.Pipes.NamedPipeClientStream('.', '{tube}', [IO.Pipes.PipeDirection]::InOut); $c.Connect(2000); \
           $ps = Pid-Serveur $c; $pv = Pid-Service; if ($pv -eq 0 -or $ps -ne $pv) {{ $c.Dispose(); return $null }}; \
           $w = New-Object IO.StreamWriter($c); $w.AutoFlush = $true; $r = New-Object IO.StreamReader($c); \
           $w.WriteLine('{{\"Action\":\"verification\"}}'); $l = $r.ReadLine(); $c.Dispose(); return $l }}"
    )
}

/// Texte du script d'installation (fonction à part pour le tester, en simulation)
pub fn script_installation(p: &ParametresScript) -> String {
    let q = |c: &Path| c.display().to_string().replace('\'', "''");
    let echec = q(&p.journaux.join("echec.txt"));
    // Lire-Reponse : $null si le tube n'est pas tenu par le processus du service (un compte standard peut
    // créer le tube pendant que l'ancien service est arrêté et répondre à sa place)
    let (definitions, installer, essais, pause) = match &p.simulation {
        Some(s) => (
            format!("function Lire-Reponse {{ Add-Content -LiteralPath '{}' -Value 'canal'; if ({} -ne {}) {{ return $null }}; return '{}' }}; ",
                q(s.journal), s.pid_serveur, s.pid_service, s.reponse.replace('\'', "''")),
            format!("Add-Content -LiteralPath '{}' -Value ('installer ' + $paquet)", q(s.journal)),
            2,
            0,
        ),
        None => (
            format!("{}; ", ps_canal(commun::NOM_SERVICE, commun::NOM_SERVICE)),
            "Start-Process msiexec.exe -Wait -ArgumentList '/i', ('\"' + $paquet + '\"'), '/qn', '/norestart', '/l*v', ('\"' + $journal + '\"')".to_string(),
            30,
            2,
        ),
    };
    format!(
        "{definitions}function Installer($paquet, $journal) {{ {installer} }}; \
         function Repond {{ try {{ $l = Lire-Reponse; if ($null -eq $l) {{ return $false }}; $j = $l | ConvertFrom-Json -ErrorAction Stop; \
           return ($j.Ok -eq $true -and $j.Message -eq 'deR4Tizer {v}') }} catch {{ return $false }} }}; \
         function Echec($t) {{ Set-Content -LiteralPath '{echec}' -Encoding UTF8 -Value ($t + ' le ' + (Get-Date)) }}; \
         function Empreinte($f) {{ try {{ (Get-FileHash -Algorithm SHA256 -LiteralPath $f -ErrorAction Stop).Hash }} catch {{ '' }} }}; \
         Start-Sleep {attente}; \
         if ((Empreinte '{paquet}') -ne '{sha_paquet}') {{ Echec 'version {v} : paquet modifié après vérification, installation abandonnée'; exit }}; \
         if ((Empreinte '{retour}') -ne '{sha_retour}') {{ Echec 'version {v} : paquet de retour arrière modifié, installation abandonnée'; exit }}; \
         Installer '{paquet}' '{journal_installation}'; \
         $ok = $false; for ($i = 0; $i -lt {essais} -and -not $ok; $i++) {{ Start-Sleep {pause}; $ok = Repond }}; \
         if (-not $ok) {{ Installer '{retour}' '{journal_retour}'; \
           Echec 'échec de la version {v} (pas de réponse JSON valide du service) : paquet de la version {va} réinstallé' }}",
        v = p.version,
        va = commun::VERSION,
        attente = if p.simulation.is_some() { 0 } else { 3 },
        paquet = q(p.paquet),
        retour = q(p.retour),
        sha_paquet = p.sha_paquet.to_uppercase(),
        sha_retour = p.sha_retour.to_uppercase(),
        journal_installation = q(&p.journaux.join("installation.log")),
        journal_retour = q(&p.journaux.join("retour.log")),
    )
}

fn publier(disponible: String, mut statut: String) {
    // Écrit par le script en UTF-8 avec BOM (PowerShell 5) ; sans -Encoding, il l'était en Windows-1252 et sa
    // lecture échouait : l'échec n'apparaissait jamais dans l'interface
    if let Some(e) = commun::lire_fichier(&commun::dossier().join("maj").join("echec.txt")) {
        statut = format!("{statut} · {}", e.trim_start_matches('\u{feff}').trim());
    }
    let _ = commun::ecrire("maj.json", &Etat {
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
