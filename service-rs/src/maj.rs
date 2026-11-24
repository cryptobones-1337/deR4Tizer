//! Mise à jour automatique du service et de l'interface. Une fois par jour (après un manifeste non obtenu : nouvel
//! essai à 15 min, puis 1 h ; série d'échecs de 24 h ou plus dite en page Santé) : lecture du manifeste de la
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

/// État lisible par l'interface (maj.json). Relu par le service au contrôle suivant pour le seul début de la série
/// d'échecs (`EchecDepuisS`), borné par `debut_echecs` : un fichier modifié ne peut que décaler l'avertissement de la
/// page Santé, rien d'autre
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct Etat {
    verifie_le: String,
    version_installee: String,
    version_disponible: String,
    statut: String,
    cle_epinglee: bool,
    /// Code du contrôle pour la page Santé (`code_controle`), traduit par l'interface
    controle: String,
    /// Début de la série de contrôles en échec (vide, ou date lisible), et le même en secondes Unix (0 : aucun échec)
    echec_depuis: String,
    echec_depuis_s: i64,
    /// Issue du contrôle en code stable (`StatutMaj::code`, T-18) ; le texte de `statut` reste pour l'existant. Vide dans
    /// un fichier écrit avant
    statut_code: String,
    /// Installation automatique appliquée par ce contrôle (réglage lu au moment du contrôle, pas le réglage actuel)
    auto_applique: bool,
    /// Version plus récente que le service installerait (`installable`) : annoncée et clé épinglée, ou installation lancée
    installable: bool,
}

/// Issue d'un contrôle en code stable (T-18), publiée dans maj.json (`StatutCode`) et traduite par l'interface
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatutMaj {
    /// Adresse du manifeste refusée (config.json) : aucune vérification
    AdresseRefusee,
    /// Manifeste non téléchargé (404, réseau, DNS…)
    ManifesteNonObtenu,
    /// Manifeste téléchargé mais illisible ou refusé par `lire_manifeste`
    ManifesteInvalide,
    AJour,
    /// Manifeste plus ancien que la version installée (A-3-2)
    ManifesteAncien,
    /// Version plus récente annoncée, installation automatique désactivée : signalée seulement
    Disponible,
    /// Version plus récente, installation automatique activée, mais ce binaire n'a pas de clé épinglée
    SansCleEpinglee,
    /// Version plus récente refusée avant l'installation (retour arrière impossible, téléchargement, signature, version
    /// ou propriétaire du paquet) : le texte de `Statut` dit pourquoi
    InstallationRefusee,
    InstallationLancee,
    /// Script d'installation impossible à lancer
    InstallationImpossible,
}

impl StatutMaj {
    pub fn code(self) -> &'static str {
        match self {
            StatutMaj::AdresseRefusee => "AdresseRefusee",
            StatutMaj::ManifesteNonObtenu => "ManifesteNonObtenu",
            StatutMaj::ManifesteInvalide => "ManifesteInvalide",
            StatutMaj::AJour => "AJour",
            StatutMaj::ManifesteAncien => "ManifesteAncien",
            StatutMaj::Disponible => "Disponible",
            StatutMaj::SansCleEpinglee => "SansCleEpinglee",
            StatutMaj::InstallationRefusee => "InstallationRefusee",
            StatutMaj::InstallationLancee => "InstallationLancee",
            StatutMaj::InstallationImpossible => "InstallationImpossible",
        }
    }

    /// Issue pour le calendrier des essais et la page Santé (inchangée : manifeste non obtenu ou refusé, plus ancien, lu)
    pub fn issue(self) -> Issue {
        match self {
            StatutMaj::AdresseRefusee | StatutMaj::ManifesteNonObtenu | StatutMaj::ManifesteInvalide => Issue::Echec,
            StatutMaj::ManifesteAncien => Issue::ManifesteAncien,
            _ => Issue::Lu,
        }
    }
}

/// Décision pure (T-18) : la version annoncée serait-elle installée par le service ? Annoncée avec l'installation
/// automatique coupée : oui si ce binaire a une clé épinglée (rien n'est vérifié du paquet tant qu'il n'est pas
/// téléchargé) ; installation lancée : oui ; tout autre cas : non
pub fn installable(statut: StatutMaj, cle_epinglee: bool) -> bool {
    match statut {
        StatutMaj::Disponible => cle_epinglee,
        StatutMaj::InstallationLancee => true,
        _ => false,
    }
}

// ------------------------------------------------------------ calendrier et issue des contrôles (audit du 2026-11-23,
// A-3-2 et T-12). Décisions pures, testées (tests.rs, audit_a32_*, audit_t12_*)

/// Période normale des contrôles : une fois par jour
pub const PERIODE_S: u64 = 86_400;
/// Nouveaux essais après un manifeste non obtenu : 15 min, puis 1 h, puis de nouveau la période normale. Une coupure
/// passagère (réseau au démarrage, DNS, version en cours de publication dont le manifeste n'est pas encore joint) est
/// rattrapée dans l'heure au lieu de 24 h ; une panne qui dure ne coûte que deux requêtes de plus par jour, et
/// l'avertissement de la page Santé (ECHEC_PROLONGE_S) prend le relais
pub const RELANCES_S: [u64; 2] = [900, 3_600];
/// Série de contrôles en échec depuis 24 h ou plus : dite en page Santé (« à vérifier »)
pub const ECHEC_PROLONGE_S: i64 = 86_400;

/// Comparaison de la version du manifeste à la version installée
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparaison {
    PlusRecente,
    Egale,
    PlusAncienne,
}

/// Issue d'un contrôle : calendrier des essais et code de la page Santé
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Issue {
    /// Manifeste lu (à jour, version disponible, installation lancée ou refusée après lecture)
    Lu,
    /// Manifeste lu, mais plus ancien que la version installée : un manifeste remplacé peut geler les mises à jour
    ManifesteAncien,
    /// Manifeste non obtenu ou refusé (adresse refusée, téléchargement en échec, contenu invalide)
    Echec,
}

/// Décision pure : « 4.3 » et « 4.3.0 » sont égales, « 4.10 » plus récente que « 4.9 »
pub fn comparer_versions(manifeste: &str, installee: &str) -> Comparaison {
    if plus_recente(manifeste, installee) {
        Comparaison::PlusRecente
    } else if plus_recente(installee, manifeste) {
        Comparaison::PlusAncienne
    } else {
        Comparaison::Egale
    }
}

/// Décision pure (A-3-2) : statut et issue d'un manifeste lu qui n'annonce pas de version plus récente ; None : version
/// plus récente, la vérification du paquet continue. Un manifeste plus ancien n'est plus « à jour »
pub fn statut_comparaison(manifeste: &str, installee: &str) -> Option<(String, Issue)> {
    match comparer_versions(manifeste, installee) {
        Comparaison::PlusRecente => None,
        Comparaison::Egale => Some(("à jour".into(), Issue::Lu)),
        Comparaison::PlusAncienne => Some((
            format!("manifeste plus ancien que la version installée (manifeste {manifeste}, installée {installee}) : un manifeste remplacé peut geler les mises à jour"),
            Issue::ManifesteAncien,
        )),
    }
}

/// Décision pure (T-12) : texte d'un manifeste non téléchargé. curl --fail écrit « curl: (22) The requested URL
/// returned error: 404 » : dit « manifeste introuvable (404) » ; le reste garde le texte de curl (200 caractères au plus)
pub fn texte_echec_manifeste(erreur_curl: &str) -> String {
    let code: String = erreur_curl
        .split("returned error: ")
        .nth(1)
        .map(|r| r.chars().take_while(|c| c.is_ascii_digit()).collect())
        .unwrap_or_default();
    if code == "404" { "manifeste introuvable (404)".into() } else { format!("manifeste illisible ({erreur_curl})") }
}

/// Décision pure (T-12) : délai avant le prochain contrôle, selon le nombre de contrôles en échec d'affilée (manifeste
/// non obtenu ou refusé)
pub fn delai_avant_controle(echecs_consecutifs: u32) -> u64 {
    match echecs_consecutifs {
        0 => PERIODE_S,
        n => RELANCES_S.get(n as usize - 1).copied().unwrap_or(PERIODE_S),
    }
}

/// Décision pure (T-12) : début de la série d'échecs (secondes Unix, 0 : aucun) après un contrôle d'issue `issue` à
/// l'heure `t`, `precedent` étant le début publié au contrôle d'avant. Gardé au-delà des redémarrages ; une date future
/// (horloge changée, fichier modifié) repart de `t`
pub fn debut_echecs(issue: Issue, precedent: i64, t: i64) -> i64 {
    match issue {
        Issue::Echec if precedent > 0 && precedent <= t => precedent,
        Issue::Echec => t,
        Issue::Lu | Issue::ManifesteAncien => 0,
    }
}

/// Décision pure (S294-01) : `EchecDepuisS` du maj.json précédent (texte lu tel quel) ; absent, mal formé ou de mauvais
/// type : 0 (aucune série en cours)
pub fn echec_depuis_publie(texte: Option<&str>) -> i64 {
    texte.and_then(|t| serde_json::from_str::<Etat>(t.trim_start_matches('\u{feff}')).ok()).map_or(0, |e| e.echec_depuis_s)
}

/// Décision pure (A-3-2, T-12) : code du contrôle pour la page Santé, traduit par l'interface. "" : rien à signaler ;
/// « ManifesteAncien » et « EchecProlonge » : à vérifier ; « EchecRecent » : dernier contrôle en échec, essai rapproché
pub fn code_controle(issue: Issue, echec_depuis: i64, t: i64) -> &'static str {
    match issue {
        Issue::Lu => "",
        Issue::ManifesteAncien => "ManifesteAncien",
        Issue::Echec if echec_depuis > 0 && t - echec_depuis >= ECHEC_PROLONGE_S => "EchecProlonge",
        Issue::Echec => "EchecRecent",
    }
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
    // Dossier des exécutables lui-même : modifiable par un autre compte (dossier d'installation redirigé), rien n'y est
    // préparé ni installé (audit du 2026-11-23, A-4-1)
    crate::protection::verifier_installation().map_err(|e| format!("dossier d'installation non conforme ({e}) : mise à jour refusée"))?;
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

/// Contenu du dossier de travail : propriétaire SYSTEM. Ce que le service crée (sous-dossiers de version,
/// téléchargements) a sinon Administrateurs pour propriétaire (propriétaire par défaut du jeton SYSTEM), et le
/// propriétaire garde le droit de réécrire les droits ; icacls /reset ne touche pas au propriétaire.
/// (code d'icacls non probant : proprietaires_verifies fait foi avant toute exécution)
fn proprietaire_systeme(travail: &Path) {
    crate::protection::icacls(&[&format!(r"{}\*", travail.display()), "/setowner", "*S-1-5-18", "/T", "/C", "/Q"]);
}

/// Paquets à exécuter : propriétaire SYSTEM, sinon pas d'installation (échec fermé)
fn proprietaires_verifies(paquets: &[&Path]) -> Result<(), String> {
    for p in paquets {
        let s = crate::natif::lire_securite(p).ok_or_else(|| format!("droits de {} illisibles", p.display()))?;
        if s.proprietaire != crate::protection::SID_SYSTEME {
            return Err(format!("{} : propriétaire {} au lieu de SYSTEM, installation refusée", p.display(), s.proprietaire));
        }
    }
    Ok(())
}

fn telecharger(url: &str, destination: &Path, taille_max: usize) -> Result<(), String> {
    // -g : pas de motifs (« [1-99] », « {a,b} ») dans l'adresse, un seul transfert (audit de sécurité de #68, S68-03)
    let sortie = Command::new(crate::natif::curl_exe())
        .args(["-q", "-g", "-sSL", "--fail", "--proto", "=https", "--proto-redir", "=https", "--max-filesize", &taille_max.to_string(), "--max-time", "300",
            "-A", &format!("deR4Tizer/{}", commun::VERSION), "-o"])
        .arg(destination)
        // Par --url : une adresse qui commencerait par « - » ne peut pas devenir une option (audit du 2026-11-14, B2)
        .arg("--url")
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
    crate::commun::creer_dossiers(&dossier).map_err(|e| e.to_string())?;
    let telechargement = telecharger(&url, &paquet, 52_428_800);
    proprietaire_systeme(travail);
    telechargement.map_err(|e| format!("paquet de la version installée ({}) introuvable : {e}", commun::VERSION))?;
    let a = constater(&paquet, cles);
    if let Err(e) = verifier_artefact(&a, commun::VERSION, cles) {
        let _ = fs::remove_file(&paquet);
        return Err(format!("paquet de la version installée refusé : {e}"));
    }
    Ok((paquet, a.sha256))
}

/// Vérifie et, si tout est en ordre (et si l'installation automatique est permise), installe. Rend la version du
/// manifeste, le statut et son code (d'où l'issue du contrôle : calendrier des essais, page Santé)
fn verifier(config: &ConfigMaj, installer: bool) -> (String, String, StatutMaj) {
    let dossier = commun::dossier().join("maj");
    let _ = crate::commun::creer_dossiers(&dossier);
    let f_manifeste = dossier.join("manifeste.json");
    // config.json relu du disque : l'adresse est revalidée ici, pas seulement à la commande majConfig (B2)
    if !commun::adresse_manifeste_simple(&config.url) {
        return (String::new(), "adresse du manifeste refusée (config.json) : aucune vérification".into(), StatutMaj::AdresseRefusee);
    }
    if let Err(e) = telecharger(&config.url, &f_manifeste, TAILLE_MAX_MANIFESTE) {
        return (String::new(), texte_echec_manifeste(&e), StatutMaj::ManifesteNonObtenu);
    }
    // Lu avec le contrôle du propriétaire, comme tout fichier du dossier de données (la confiance vient de
    // toute façon du paquet signé)
    let lu = commun::lire_fichier(&f_manifeste).ok_or_else(|| "manifeste illisible ou protection du dossier non vérifiée".to_string());
    let m = match lu.and_then(|t| lire_manifeste(t.as_bytes())) {
        Ok(m) => m,
        Err(e) => return (String::new(), e, StatutMaj::ManifesteInvalide),
    };
    // Égale : à jour ; plus ancienne : statut distinct (A-3-2) ; plus récente : vérification du paquet
    if let Some((statut, issue)) = statut_comparaison(&m.version, commun::VERSION) {
        let code = if issue == Issue::ManifesteAncien { StatutMaj::ManifesteAncien } else { StatutMaj::AJour };
        return (m.version, statut, code);
    }
    installer_version(config, &m, installer, &dossier)
}

/// Version plus récente annoncée par un manifeste lu : signalée, ou vérifiée puis installée si c'est permis
fn installer_version(config: &ConfigMaj, m: &Manifeste, installer: bool, dossier: &Path) -> (String, String, StatutMaj) {
    if !installer {
        return (m.version.clone(), format!("version {} disponible (installation automatique désactivée)", m.version), StatutMaj::Disponible);
    }
    let v = m.version.clone();
    let refus = |e: String| (v.clone(), format!("version {v} disponible : {e}"), StatutMaj::InstallationRefusee);
    let cles = cles_epinglees(CLES_EPINGLEES);
    // Sans clé épinglée, rien ne sera jamais installé : inutile de télécharger (même texte qu'avant, code distinct)
    if cles.is_empty() {
        return (v.clone(), format!("version {v} disponible : cette version n'a pas de clé de signature épinglée : mise à jour signalée, pas installée"), StatutMaj::SansCleEpinglee);
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
    let _ = crate::commun::creer_dossiers(&cible);
    let paquet = cible.join(NOM_PAQUET);
    let telechargement = telecharger(&m.fichiers[0].url, &paquet, 52_428_800);
    proprietaire_systeme(&travail);
    if let Err(e) = telechargement {
        return refus(format!("téléchargement du paquet impossible ({e})"));
    }
    let a = constater(&paquet, &cles);
    if let Err(e) = decision_installation(&m, &a, commun::VERSION, &cles) {
        let _ = fs::remove_file(&paquet);
        return refus(e);
    }
    if let Err(e) = proprietaires_verifies(&[paquet.as_path(), retour.as_path()]) {
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

/// Commande qui lance le script d'installation (partagée avec son test). Sans fenêtre (CREATE_NO_WINDOW : console
/// cachée), jamais DETACHED_PROCESS : sans console, Windows PowerShell 5.1 sort avec le code 0 sans rien exécuter
/// (constaté en Windows Sandbox, scénario 3c : aucune mise à jour ni aucun retour arrière n'avait lieu). Le processus
/// n'est dans aucun objet tâche du service : il survit à l'arrêt du service par msiexec.
pub fn commande_script(script: &str) -> Command {
    crate::mesure::powershell("maj");
    let mut c = Command::new(crate::natif::powershell_exe());
    c.args(["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script])
        // Un PSModulePath hérité de PowerShell 7 fait charger à Windows PowerShell des modules incompatibles
        // (Get-FileHash introuvable, constaté en CI) : powershell.exe reprend alors le sien
        .env_remove("PSModulePath")
        .creation_flags(0x0800_0000);
    c
}

/// Script à part (le service ne peut pas se remplacer lui-même) : empreintes revérifiées juste avant
/// l'exécution, installation, contrôle du service par son canal, retour arrière par le paquet précédent
fn lancer_installation(p: &ParametresScript) -> (String, String, StatutMaj) {
    match commande_script(&script_installation(p)).spawn() {
        Ok(_) => {
            let _ = fs::remove_file(p.journaux.join("echec.txt"));
            commun::journal(&format!("mise à jour vers la version {} : installation lancée (retour arrière si le service ne répond pas)", p.version));
            (p.version.to_string(), format!("installation de la version {} en cours", p.version), StatutMaj::InstallationLancee)
        }
        Err(e) => (p.version.to_string(), format!("installation impossible ({e})"), StatutMaj::InstallationImpossible),
    }
}

/// PowerShell : interrogation du service par son canal, code exact du script de production (testé tel quel
/// sur un vrai tube). Pid-Service : processus du service `service` ; Lire-Reponse : $null si le tube `tube`
/// n'est pas tenu par ce processus, sinon la réponse à {"Action":"verification"}. Connexion au niveau Identification :
/// le service lit le jeton pour identifier le client, sans pouvoir agir avec (durcissement du canal). Lecture et écriture
/// des données seulement (A-1-4) : les droits du tube refusent GENERIC_WRITE (sens « InOut ») hors SYSTEM.
pub fn ps_canal(tube: &str, service: &str) -> String {
    format!(
        "{PS_PID_SERVEUR}; \
         function Pid-Service {{ [uint32](Get-CimInstance Win32_Service -Filter \"Name='{service}'\").ProcessId }}; \
         function Lire-Reponse {{ $c = New-Object IO.Pipes.NamedPipeClientStream('.', '{tube}', [IO.Pipes.PipeAccessRights]'ReadData, WriteData', [IO.Pipes.PipeOptions]::None, [Security.Principal.TokenImpersonationLevel]::Identification, [IO.HandleInheritability]::None); $c.Connect(2000); \
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
            "Start-Process (Join-Path ([Environment]::SystemDirectory) 'msiexec.exe') -Wait -ArgumentList '/i', ('\"' + $paquet + '\"'), '/qn', '/norestart', '/l*v', ('\"' + $journal + '\"')".to_string(),
            30,
            2,
        ),
    };
    format!(
        "{definitions}function Installer($paquet, $journal) {{ {installer} }}; \
         function Repond {{ try {{ $l = Lire-Reponse; if ($null -eq $l) {{ return $false }}; $j = $l | ConvertFrom-Json -ErrorAction Stop; \
           return ($j.Ok -eq $true -and $j.Message -eq 'deR4Tizer {v}') }} catch {{ return $false }} }}; \
         function Echec($t) {{ Set-Content -LiteralPath '{echec}' -Encoding UTF8 -Value ($t + ' le ' + (Get-Date)) }}; \
         function Empreinte($f) {{ try {{ $s = [IO.File]::OpenRead($f); try {{ [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($s)).Replace('-', '') }} finally {{ $s.Dispose() }} }} catch {{ '' }} }}; \
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

fn publier(disponible: String, mut statut: String, code: StatutMaj, auto: bool) {
    // Écrit par le script en UTF-8 avec BOM (PowerShell 5) ; sans -Encoding, il l'était en Windows-1252 et sa
    // lecture échouait : l'échec n'apparaissait jamais dans l'interface
    if let Some(e) = commun::lire_fichier(&commun::dossier().join("maj").join("echec.txt")) {
        statut = format!("{statut} · {}", e.trim_start_matches('\u{feff}').trim());
    }
    let _ = publier_vers("maj.json", &commun::dossier().join("maj.json"), disponible, statut, code, auto, crate::sante::secondes());
}

/// Écrit l'état du contrôle dans `chemin` (suivi sous le nom `nom` ; tests : dossier de travail). Le début de la série
/// d'échecs est repris du fichier précédent par une lecture contrôlée brute (`lire_fichier` : propriétaire, liens
/// physiques et lien vérifiés sur le handle), SANS `lire`/`lire_etat` : ceux-ci marquent un fichier mal formé « non
/// chargé », et `ecrire` refuse ensuite de le remplacer ; le statut restait alors figé alors que les contrôles suivants
/// échouaient (audit de #294, S294-01). Illisible, refusé ou mal formé : la série repart de `t`, et le fichier est
/// réécrit. Aucune confiance n'est portée par maj.json : seul `EchecDepuisS` est repris, borné par `debut_echecs`.
/// `code` : issue du contrôle (`StatutMaj`) ; `auto` : installation automatique appliquée par ce contrôle (T-18)
pub fn publier_vers(nom: &str, chemin: &Path, disponible: String, statut: String, code: StatutMaj, auto: bool, t: i64) -> Result<(), String> {
    let issue = code.issue();
    let precedent = echec_depuis_publie(commun::lire_fichier(chemin).as_deref());
    let depuis = debut_echecs(issue, precedent, t);
    let cle_epinglee = !cles_epinglees(CLES_EPINGLEES).is_empty();
    commun::ecrire_suivi(nom, chemin, &Etat {
        verifie_le: commun::maintenant(),
        version_installee: commun::VERSION.into(),
        version_disponible: disponible,
        statut,
        cle_epinglee,
        controle: code_controle(issue, depuis, t).into(),
        echec_depuis: if depuis > 0 { commun::heure(std::time::UNIX_EPOCH + Duration::from_secs(depuis as u64)) } else { String::new() },
        echec_depuis_s: depuis,
        statut_code: code.code().into(),
        auto_applique: auto,
        installable: installable(code, cle_epinglee),
    })
}

/// Vérification à la demande (bouton de l'interface), dans un fil : la surveillance continue pendant le
/// téléchargement
pub fn verifier_maintenant(config: ConfigMaj) {
    std::thread::spawn(move || {
        let (v, s, code) = verifier(&config, config.auto);
        publier(v, s, code, config.auto);
    });
}

/// Vérification quotidienne, à partir de 10 minutes après le démarrage ; après un manifeste non obtenu ou refusé,
/// nouveaux essais à 15 min puis 1 h (delai_avant_controle, T-12)
pub fn demarrer() {
    std::thread::Builder::new().name("mise à jour".into()).spawn(|| {
        std::thread::sleep(Duration::from_secs(600));
        let mut echecs: u32 = 0;
        loop {
            let config: commun::Config = commun::lire("config.json").unwrap_or_default();
            if config.maj.url.is_empty() {
                echecs = 0;
            } else {
                let (v, s, code) = verifier(&config.maj, config.maj.auto);
                echecs = if code.issue() == Issue::Echec { echecs.saturating_add(1) } else { 0 };
                publier(v, s, code, config.maj.auto);
            }
            std::thread::sleep(Duration::from_secs(delai_avant_controle(echecs)));
        }
    }).unwrap();
}
