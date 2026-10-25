//! Types et fichiers partagés avec l'interface C# (deR4Tizer.exe) : mêmes noms de champs JSON
//! (PascalCase), mêmes fichiers dans C:\ProgramData\deR4Tizer.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

pub const VERSION: &str = "4.3";
pub const NOM_SERVICE: &str = "deR4Tizer";
pub const NOM_PIPE: &str = r"\\.\pipe\deR4Tizer";
pub const SEUIL_ALERTE: i32 = 3;

static DOSSIER: OnceLock<PathBuf> = OnceLock::new();

pub fn definir_dossier(p: PathBuf) {
    let _ = DOSSIER.set(p);
}

pub fn dossier() -> &'static PathBuf {
    DOSSIER.get_or_init(|| {
        PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into())).join("deR4Tizer")
    })
}

/// Les fichiers écrits par l'ancien service C# peuvent contenir `null` là où on attend une chaîne
fn nul_vide<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    Ok(Option::<String>::deserialize(d)?.unwrap_or_default())
}

/// Bloc de réglages à `null` (l'interface ne crée pas les blocs absents de config.json) : valeurs par défaut
fn nul_par_defaut<'de, D: Deserializer<'de>, T: Deserialize<'de> + Default>(d: D) -> Result<T, D::Error> {
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
#[serde(rename_all = "PascalCase", default)]
pub struct FluxInfo {
    pub cle: String,
    pub score: i32,
    pub processus: String,
    pub pid: u32,
    pub chemin: String,
    pub signataire: String,
    pub ip: String,
    pub nom_dns: Option<String>,
    pub port: u16,
    pub raisons: String,
    pub premiere_vue: String,
    pub connexions: usize,
    pub parent: Option<String>,
    pub ligne_commande: Option<String>,
    /// « téléchargé depuis … » (marque Mark of the Web), s'il y a lieu
    pub origine: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Etat {
    pub mis_a_jour: String,
    pub demarrage: String,
    pub version: String,
    pub journal_dns_actif: bool,
    pub ip_connues: usize,
    pub source_processus: String,
    pub bureau_a_distance: bool,
    pub flux: Vec<FluxInfo>,
    pub peripheriques: Vec<UsagePeripherique>,
    pub outils_distants: Vec<OutilDistant>,
    pub ecoutes: Vec<Ecoute>,
    pub defender: crate::defender::EtatDefender,
    pub chaines: Vec<crate::chaines::Chaine>,
    pub panique: bool,
    pub exposition: crate::parefeu::Exposition,
    /// Vide si la protection du dossier de données est vérifiée ; sinon la raison de l'échec
    pub protection_donnees: String,
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct EntreeDemarrage {
    #[serde(deserialize_with = "nul_vide")]
    pub cle: String,
    #[serde(deserialize_with = "nul_vide")]
    pub categorie: String,
    #[serde(deserialize_with = "nul_vide")]
    pub nom: String,
    #[serde(deserialize_with = "nul_vide")]
    pub commande: String,
    #[serde(deserialize_with = "nul_vide")]
    pub cible: String,
    #[serde(deserialize_with = "nul_vide")]
    pub signataire: String,
    #[serde(deserialize_with = "nul_vide")]
    pub remarque: String,
    #[serde(deserialize_with = "nul_vide")]
    pub depuis: String,
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct UsagePeripherique {
    pub peripherique: String,
    pub programme: String,
    pub chemin: String,
    pub dernier_debut: String,
    pub derniere_fin: String,
    pub en_cours: bool,
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct OutilDistant {
    pub nom: String,
    pub pid: u32,
    pub chemin: String,
    pub signataire: String,
    pub depuis: String,
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Ecoute {
    pub programme: String,
    pub chemin: String,
    pub pid: u32,
    pub adresse: String,
    pub port: u16,
    pub signataire: String,
    pub depuis: String,
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct SourceMenace {
    pub nom: String,
    #[serde(rename = "Type")]
    pub type_: String,
    pub confiance: String,
    pub entrees: usize,
    pub statut: String,
    pub mis_a_jour: Option<String>,
    pub licence: String,
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct InfosMenaces {
    pub mis_a_jour: String,
    pub total_ip: usize,
    pub total_reseaux: usize,
    pub total_domaines: usize,
    pub sources: Vec<SourceMenace>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase", default)]
pub struct Config {
    /// Bloque au pare-feu, dès qu'une connexion est vue, les IP des listes de confiance haute
    pub blocage_auto_menaces: bool,
    /// Suspend aussitôt le programme qui modifie un fichier leurre (rançongiciel probable)
    pub reponse_auto_rancongiciel: bool,
    /// Langue de l'interface : "fr" ou "en"
    #[serde(deserialize_with = "nul_vide")]
    pub langue: String,
    #[serde(deserialize_with = "nul_par_defaut")]
    pub syslog: ConfigSyslog,
    #[serde(deserialize_with = "nul_par_defaut")]
    pub api: ConfigApi,
    /// Prévention d'intrusion : l'IDS bloque au pare-feu l'adresse distante des règles « drop » ou de priorité 1
    pub ips: bool,
    /// Utiliser aussi les listes de menaces non commerciales ou aux conditions non vérifiées (usage personnel)
    pub listes_restreintes: bool,
    #[serde(deserialize_with = "nul_par_defaut")]
    pub notifications: ConfigNotifications,
    #[serde(deserialize_with = "nul_par_defaut")]
    pub maj: ConfigMaj,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            blocage_auto_menaces: true,
            reponse_auto_rancongiciel: true,
            langue: "fr".into(),
            syslog: ConfigSyslog::default(),
            api: ConfigApi::default(),
            ips: false,
            listes_restreintes: false,
            notifications: ConfigNotifications::default(),
            maj: ConfigMaj::default(),
        }
    }
}

/// Envoi des alertes à un serveur syslog (SIEM, collecteur)
#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "PascalCase", default)]
pub struct ConfigSyslog {
    pub actif: bool,
    pub hote: String,
    pub port: u16,
    /// "UDP" ou "TCP"
    pub protocole: String,
    /// "JSON" (RFC 5424 avec le détail en JSON) ou "CEF" (ArcSight, accepté par la plupart des SIEM)
    pub format: String,
    /// Niveau minimal envoyé : "Info", "Alerte" ou "Critique"
    pub niveau_min: String,
}

impl Default for ConfigSyslog {
    fn default() -> Self {
        ConfigSyslog { actif: false, hote: String::new(), port: 514, protocole: "UDP".into(), format: "JSON".into(), niveau_min: "Alerte".into() }
    }
}

/// Remontée des alertes vers un tiers (prestataire, référent) ; les secrets sont rangés à part
#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "PascalCase", default)]
pub struct ConfigNotifications {
    /// Niveau minimal envoyé : "Info", "Alerte" ou "Critique"
    pub niveau_min: String,
    pub max_par_heure: u32,
    pub ntfy: bool,
    pub teams: bool,
    pub smtp: bool,
    pub smtp_serveur: String,
    pub smtp_port: u16,
    /// "SSL" (port 465) ou "STARTTLS" (port 587)
    pub smtp_securite: String,
    pub smtp_utilisateur: String,
    pub expediteur: String,
    /// Adresses séparées par des virgules
    pub destinataires: String,
}

impl Default for ConfigNotifications {
    fn default() -> Self {
        ConfigNotifications {
            niveau_min: "Critique".into(), max_par_heure: 10, ntfy: false, teams: false, smtp: false,
            smtp_serveur: String::new(), smtp_port: 465, smtp_securite: "SSL".into(), smtp_utilisateur: String::new(),
            expediteur: String::new(), destinataires: String::new(),
        }
    }
}

/// Mise à jour automatique (maj.rs)
#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "PascalCase", default)]
pub struct ConfigMaj {
    /// Installer automatiquement une version vérifiée (sinon : seulement la signaler)
    pub auto: bool,
    /// Manifeste de la dernière version publiée
    pub url: String,
}

impl Default for ConfigMaj {
    fn default() -> Self {
        // Désactivée par défaut : l'installation automatique n'a de sens qu'avec des versions signées par la clé
        // épinglée dans le binaire (voir maj.rs)
        ConfigMaj { auto: false, url: "https://github.com/cryptobones-1337/deR4Tizer/releases/latest/download/manifeste.json".into() }
    }
}

/// Chemin d'un profil utilisateur masqué (« C:\Users\marie\… » → « %USERPROFILE%\… ») : un poste partagé ne
/// montre pas les noms des comptes ni leurs dossiers
pub fn masquer_chemin(chemin: &str) -> String {
    static R: OnceLock<regex::Regex> = OnceLock::new();
    R.get_or_init(|| regex::Regex::new(r"(?i)^[a-z]:\\users\\[^\\]+").unwrap()).replace(chemin, "%USERPROFILE%").into_owned()
}

/// API HTTP d'export (lecture seule), protégée par un jeton
#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "PascalCase", default)]
pub struct ConfigApi {
    pub actif: bool,
    pub port: u16,
    /// Écoute sur le réseau local (sinon 127.0.0.1 seulement)
    pub reseau: bool,
    /// Adresses autorisées sur le réseau (SIEM), séparées par des virgules : obligatoires avec « reseau »
    #[serde(deserialize_with = "nul_vide")]
    pub adresses: String,
}

impl Default for ConfigApi {
    fn default() -> Self {
        ConfigApi { actif: false, port: 8642, reseau: false, adresses: String::new() }
    }
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Alerte {
    #[serde(deserialize_with = "nul_vide")]
    pub id: String,
    #[serde(deserialize_with = "nul_vide")]
    pub heure: String,
    /// "Critique", "Alerte" ou "Info"
    #[serde(deserialize_with = "nul_vide")]
    pub niveau: String,
    pub score: i32,
    #[serde(deserialize_with = "nul_vide")]
    pub processus: String,
    #[serde(deserialize_with = "nul_vide")]
    pub chemin: String,
    #[serde(deserialize_with = "nul_vide")]
    pub destination: String,
    pub ip: Option<String>,
    pub nom_dns: Option<String>,
    pub port: u16,
    #[serde(deserialize_with = "nul_vide")]
    pub raisons: String,
    /// Processus concerné, s'il est connu (sert à l'arbre des processus et aux actions de réponse)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// Technique MITRE ATT&CK et conseil « Que faire ? »
    #[serde(deserialize_with = "nul_vide")]
    pub mitre: String,
    #[serde(deserialize_with = "nul_vide")]
    pub conseil: String,
    /// Chemin du programme parent, s'il est connu (détections de processus)
    #[serde(default, deserialize_with = "nul_vide", skip_serializing_if = "String::is_empty")]
    pub parent: String,
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Blocage {
    /// "hosts" ou "parefeu"
    #[serde(rename = "Type", deserialize_with = "nul_vide")]
    pub type_: String,
    #[serde(deserialize_with = "nul_vide")]
    pub cible: String,
    #[serde(deserialize_with = "nul_vide")]
    pub raison: String,
    #[serde(deserialize_with = "nul_vide")]
    pub date: String,
    /// Fin du blocage (« aaaa-mm-jj hh:mm:ss ») pour les blocages automatiques ; vide : permanent
    #[serde(default, deserialize_with = "nul_vide")]
    pub expire: String,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Commande {
    /// bloquer, bloquerIp, debloquer, toutDebloquer, config, majMenaces, reglages, notifications…
    pub action: Option<String>,
    pub valeur: Option<String>,
    pub ip: Option<String>,
    pub nom_dns: Option<String>,
    #[serde(rename = "Type")]
    pub type_: Option<String>,
    pub cible: Option<String>,
    pub raison: Option<String>,
    pub categories: Option<Vec<String>>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Reponse {
    pub ok: bool,
    pub message: String,
}

impl Reponse {
    pub fn ok(m: impl Into<String>) -> Self {
        Reponse { ok: true, message: m.into() }
    }
    pub fn erreur(m: impl Into<String>) -> Self {
        Reponse { ok: false, message: m.into() }
    }
}

/// Domaines de télémétrie connus, par éditeur (mêmes catégories que l'interface)
pub fn telemetrie() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        ("Microsoft / Windows", vec![
            "vortex.data.microsoft.com", "vortex-win.data.microsoft.com", "settings-win.data.microsoft.com",
            "v10.events.data.microsoft.com", "v20.events.data.microsoft.com", "self.events.data.microsoft.com",
            "mobile.events.data.microsoft.com", "umwatson.events.data.microsoft.com", "watson.events.data.microsoft.com",
            "watson.telemetry.microsoft.com", "telecommand.telemetry.microsoft.com", "oca.telemetry.microsoft.com",
            "sqm.telemetry.microsoft.com",
        ]),
        ("NVIDIA", vec!["telemetry.gfe.nvidia.com", "events.gfe.nvidia.com"]),
        ("Mozilla", vec!["incoming.telemetry.mozilla.org"]),
        ("Adobe", vec!["cc-api-data.adobe.io"]),
    ]
}

// ------------------------------------------------------------ fichiers

/// Échec de la protection du dossier de données (None : protection vérifiée)
static ECHEC_PROTECTION: Mutex<Option<String>> = Mutex::new(None);

pub fn definir_echec_protection(e: Option<String>) {
    *ECHEC_PROTECTION.lock().unwrap() = e;
}

pub fn echec_protection() -> Option<String> {
    ECHEC_PROTECTION.lock().unwrap().clone()
}

fn signaler_une_fois(chemin: &Path, raison: &str) {
    static SIGNALES: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    let cle = format!("{}|{raison}", chemin.display());
    if SIGNALES.get_or_init(|| Mutex::new(HashSet::new())).lock().unwrap().insert(cle) {
        journal(&format!("protection des données : {} ignoré ({raison})", chemin.display()));
    }
}

/// Décision pure de lecture d'un fichier du dossier de données. Hors service (tests, console), pas de
/// contrôle. En service : refus tant que la protection du dossier n'est pas vérifiée (si `avec_verrou`), et
/// refus d'un fichier dont le propriétaire n'est ni SYSTEM ni Administrateurs : posé par un compte standard,
/// il ne doit jamais être cru. Un propriétaire illisible n'est admis que si le fichier n'existe pas (la
/// lecture échoue alors d'elle-même).
pub fn lecture_autorisee(systeme: bool, avec_verrou: bool, echec_protection: bool, existe: bool, proprietaire_ok: Option<bool>) -> Result<(), &'static str> {
    if !systeme {
        return Ok(());
    }
    if avec_verrou && echec_protection {
        return Err("protection du dossier non vérifiée");
    }
    match proprietaire_ok {
        Some(true) => Ok(()),
        Some(false) => Err("propriétaire ni SYSTEM ni Administrateurs"),
        None if existe => Err("propriétaire illisible"),
        None => Ok(()),
    }
}

fn lire_controle(chemin: &Path, avec_verrou: bool) -> Option<String> {
    let systeme = crate::natif::est_systeme();
    let proprietaire = if systeme { crate::natif::proprietaire_de_confiance(chemin) } else { None };
    let existe = fs::symlink_metadata(chemin).is_ok();
    if let Err(raison) = lecture_autorisee(systeme, avec_verrou, echec_protection().is_some(), existe, proprietaire) {
        signaler_une_fois(chemin, raison);
        return None;
    }
    fs::read_to_string(chemin).ok()
}

/// Lecture avec le seul contrôle du propriétaire (lecteurs.json, pour reprendre après un échec)
pub fn lire_fichier_proprietaire(chemin: &Path) -> Option<String> {
    lire_controle(chemin, false)
}

/// Décision pure : fichier encore lisible quand la protection du dossier est en échec (chemin relatif au
/// dossier de données). Liste d'autorisation, le reste est refusé par défaut : seules les données que le
/// service retélécharge lui-même (GeoIP) et l'historique qu'il écrit (alertes, incidents, journal), qui
/// n'accordent aucune confiance et ne changent pas son comportement. Le cache DNS (dns.json) n'en fait plus
/// partie : il nomme les destinations des alertes et du trafic, un fichier piégé pourrait les maquiller. Tout ce qui le fait
/// (configuration, comptes autorisés, apprentissage, blocages, quarantaine, bases « connues », secrets,
/// jeton) reste refusé. Le contrôle du propriétaire s'applique dans tous les cas.
pub fn lisible_en_echec(relatif: &str) -> bool {
    let r = relatif.replace('/', "\\").to_ascii_lowercase();
    if let Some(nom) = r.strip_prefix("geoip\\") {
        return !nom.is_empty() && !nom.contains('\\') && nom.ends_with(".txt");
    }
    matches!(r.as_str(), "alertes.json" | "incidents.json" | "journal.txt")
}

/// Lecture d'un fichier du dossier de données : propriétaire contrôlé, et refus tant que la protection du
/// dossier n'est pas vérifiée, sauf pour les fichiers de `lisible_en_echec` (échec fermé : le service garde
/// ses valeurs par défaut, la détection continue)
pub fn lire_fichier(chemin: &Path) -> Option<String> {
    let relatif = chemin.strip_prefix(dossier()).map(|r| r.to_string_lossy().to_string()).unwrap_or_default();
    lire_controle(chemin, !lisible_en_echec(&relatif))
}

pub fn lire<T: DeserializeOwned>(nom: &str) -> Option<T> {
    let texte = lire_fichier(&dossier().join(nom))?;
    serde_json::from_str(texte.trim_start_matches('\u{feff}')).ok()
}

/// Écriture atomique : fichier temporaire synchronisé sur le disque, puis remplacement (écriture immédiate),
/// pour que l'interface ne lise jamais un fichier à moitié écrit. Erreur si le fichier n'a pas été remplacé :
/// les appelants pour qui l'écriture fait partie d'une transaction (quarantaine) la vérifient.
pub fn ecrire<T: Serialize + ?Sized>(nom: &str, donnees: &T) -> Result<(), String> {
    ecrire_dans(&dossier().join(nom), donnees)
}

/// `ecrire` vers un chemin quelconque (tests, dossiers de travail)
pub fn ecrire_dans<T: Serialize + ?Sized>(f: &Path, donnees: &T) -> Result<(), String> {
    let nom = f.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let tmp = f.with_file_name(format!("{nom}.tmp"));
    let json = serde_json::to_vec(donnees).map_err(|e| format!("{nom} : {e}"))?;
    let ecrit = (|| -> std::io::Result<()> {
        let mut h = fs::File::create(&tmp)?;
        h.write_all(&json)?;
        h.sync_all()
    })();
    if let Err(e) = ecrit {
        let _ = fs::remove_file(&tmp);
        return Err(format!("{nom} : écriture : {e}"));
    }
    let mut derniere = String::new();
    for _ in 0..5 {
        match crate::natif::remplacer_fichier(&tmp, f) {
            Ok(()) => return Ok(()),
            Err(e) => derniere = e,
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let _ = fs::remove_file(&tmp);
    Err(format!("{nom} : remplacement : {derniere}"))
}

pub fn lire_carte(nom: &str) -> Option<HashMap<String, String>> {
    lire(nom)
}

// ------------------------------------------------------------ heure locale

/// Instant (UTC, en FILETIME) vers "aaaa-mm-jj hh:mm:ss" à l'heure locale
pub fn heure_filetime(filetime: u64) -> String {
    use windows::Win32::Foundation::{FILETIME, SYSTEMTIME};
    use windows::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};
    let ft = FILETIME { dwLowDateTime: filetime as u32, dwHighDateTime: (filetime >> 32) as u32 };
    let mut utc = SYSTEMTIME::default();
    let mut local = SYSTEMTIME::default();
    unsafe {
        if FileTimeToSystemTime(&ft, &mut utc).is_err() || SystemTimeToTzSpecificLocalTime(None, &utc, &mut local).is_err() {
            return String::new();
        }
    }
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", local.wYear, local.wMonth, local.wDay, local.wHour, local.wMinute, local.wSecond)
}

pub fn filetime(t: SystemTime) -> u64 {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    (d.as_secs() + 11_644_473_600) * 10_000_000 + d.subsec_nanos() as u64 / 100
}

pub fn heure(t: SystemTime) -> String {
    heure_filetime(filetime(t))
}

pub fn maintenant() -> String {
    heure(SystemTime::now())
}

// ------------------------------------------------------------ journal

/// Message ramené à une seule ligne de journal (pur, testé)
pub fn ligne_de_journal(message: &str) -> String {
    message.chars().map(|c| if c.is_control() || c == '\u{2028}' || c == '\u{2029}' { ' ' } else { c }).collect()
}

pub fn journal(message: &str) {
    let f = dossier().join("journal.txt");
    // Rotation : au-delà de 2 Mo, l'ancien journal devient journal.1.txt (un bruit provoqué n'efface pas tout)
    if fs::metadata(&f).map(|m| m.len() > 2 * 1024 * 1024).unwrap_or(false) {
        let _ = fs::rename(&f, dossier().join("journal.1.txt"));
    }
    // Une ligne par message : caractères de contrôle et séparateurs de ligne Unicode remplacés par une espace (noms
    // DNS, NBNS, UPnP, lignes de commande venus du poste ou du réseau ajoutaient de fausses lignes horodatées,
    // audit AUD4-05)
    let propre = ligne_de_journal(message);
    if let Ok(mut fichier) = fs::OpenOptions::new().create(true).append(true).open(&f) {
        let _ = writeln!(fichier, "{}  {}\r", maintenant(), propre);
    }
}

/// Table de déduplication (clé → dernière fois) bornée : entrées plus anciennes que `age` retirées, puis, au-delà de
/// `max`, les plus anciennes (audit AUD4-02, AUD4-03 : des sources usurpées faisaient grossir ces tables sans fin)
pub fn purger_anciens<K: std::hash::Hash + Eq + Clone>(m: &mut HashMap<K, std::time::Instant>, age: std::time::Duration, max: usize) {
    m.retain(|_, t| t.elapsed() < age);
    if m.len() > max {
        let mut v: Vec<(K, std::time::Instant)> = m.iter().map(|(k, t)| (k.clone(), *t)).collect();
        v.sort_by_key(|x| x.1);
        for (k, _) in v.into_iter().take(m.len() - max) {
            m.remove(&k);
        }
    }
}

pub fn nouvel_id() -> String {
    // Identifiant unique suffisant pour distinguer les alertes (pas de dépendance à une bibliothèque UUID)
    use std::sync::atomic::{AtomicU64, Ordering};
    static COMPTEUR: AtomicU64 = AtomicU64::new(0);
    let n = COMPTEUR.fetch_add(1, Ordering::Relaxed);
    format!("{:016x}-{:08x}-{:04x}", filetime(SystemTime::now()), std::process::id(), n & 0xFFFF)
}
