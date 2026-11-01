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
    /// État de chaque collecte (phase 3.3) et règles dont la télémétrie n'est pas lue (ou ne l'est qu'en partie)
    pub collectes: Vec<crate::collectes::EtatCollecte>,
    pub regles_sans_collecte: Vec<String>,
    pub regles_degradees: Vec<String>,
    /// Pour chaque règle sans collecte, les sources dont l'une au moins manque (phase 3.3d, lues par l'interface)
    pub causes_sans_collecte: Vec<crate::collectes::CauseSansCollecte>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct EntreeDemarrage {
    /// Anomalie du relevé des tâches, posée par le service seul : jamais déduite du texte de la commande, qu'une tâche choisit (relecture de #106, R3)
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub anomalie: bool,
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

/// Clé d'une commande reçue qui diffère d'une clé connue par la seule casse (« langue » à côté de « Langue ») :
/// l'interface (.NET, clés lues sans tenir compte de la casse) en afficherait la valeur à la confirmation, alors que le
/// service (serde, sensible à la casse) l'ignorerait et appliquerait l'autre (audit AUD6-03). `modele` : la valeur par
/// défaut sérialisée, qui donne les clés connues à chaque niveau. Une clé inconnue sans homonyme reste ignorée des deux
/// côtés, comme avant.
/// Texte illisible comme valeur JSON : refusé (Some), jamais laissé passer : serde_json peut lire comme Config un texte
/// qu'il refuse comme valeur (surrogat isolé ou nombre hors plage dans un champ ignoré : audit de sécurité S58-01).
pub fn cle_ambigue(texte: &str, modele: &serde_json::Value) -> Option<String> {
    fn chercher(v: &serde_json::Value, m: &serde_json::Value, chemin: &str) -> Option<String> {
        let (serde_json::Value::Object(v), serde_json::Value::Object(m)) = (v, m) else { return None };
        for (k, sous) in v {
            let nom = if chemin.is_empty() { k.clone() } else { format!("{chemin}.{k}") };
            match m.get(k) {
                Some(sm) => {
                    if let Some(c) = chercher(sous, sm, &nom) {
                        return Some(c);
                    }
                }
                None if m.keys().any(|c| c.eq_ignore_ascii_case(k)) => return Some(nom),
                None => {}
            }
        }
        None
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(texte) else { return Some("(texte illisible)".into()) };
    chercher(&v, modele, "")
}

/// Message de refus : texte illisible, ou clé ambiguë par la casse (nommée)
pub fn raison_refus(prefixe: &str, k: &str) -> String {
    if k == "(texte illisible)" { format!("{prefixe} : texte illisible") } else { format!("{prefixe} : clé « {} » ambiguë (casse)", ligne_de_journal(k)) }
}

/// Lecture complète d'une commande « reglages » (décision pure, testée) : texte illisible ou clé ambiguë refusés
/// (AUD6-03, S58-01), puis lecture, puis champs texte en listes fermées (S58-02). Seul chemin du service pour cette
/// commande.
pub fn lire_reglages(texte: &str) -> Result<Config, String> {
    if let Some(k) = cle_ambigue(texte, &serde_json::to_value(Config::default()).unwrap_or_default()) {
        return Err(raison_refus("réglages refusés", &k));
    }
    let n: Config = serde_json::from_str(texte).map_err(|_| "réglages illisibles".to_string())?;
    match reglages_invalides(&n) {
        Some(r) => Err(format!("réglages refusés : {r}")),
        None => Ok(n),
    }
}

/// Lecture d'une commande « majConfig » (décision pure, testée ; audits de sécurité de #67 et #68) : objet JSON
/// seulement (S68-04), clé ambiguë refusée (S67-01, comme les réglages), adresse du manifeste de forme simple
/// (`adresse_manifeste_simple`) ; adresse vide remplacée par l'adresse par défaut (S68-02 : vide, elle coupait la
/// vérification des mises à jour sans que la confirmation le dise)
pub fn lire_config_maj(texte: &str) -> Result<ConfigMaj, String> {
    if !texte.trim_start().starts_with('{') {
        return Err("réglages de mise à jour illisibles".into());
    }
    if let Some(k) = cle_ambigue(texte, &serde_json::to_value(ConfigMaj::default()).unwrap_or_default()) {
        return Err(raison_refus("réglages de mise à jour refusés", &k));
    }
    let mut m: ConfigMaj = serde_json::from_str(texte).map_err(|_| "réglages de mise à jour illisibles".to_string())?;
    if m.url.is_empty() {
        m.url = ConfigMaj::default().url;
    }
    if !adresse_manifeste_simple(&m.url) {
        return Err("adresse du manifeste refusée : https://hôte[:port]/chemin, lettres, chiffres, « . », « - », « _ », « ~ » et « / » seulement, sans segment « . » ni « .. », 600 caractères au plus".into());
    }
    Ok(m)
}

/// Adresse du manifeste lisible telle qu'elle sera suivie : https://hôte[:port]/chemin ; hôte en lettres, chiffres,
/// « . » et « - » (S67-02 : pas d'homoglyphe) ; port de 1 à 65535 ; chemin non vide en lettres, chiffres, « . », « - »,
/// « _ », « ~ » et « / », sans segment « . » ni « .. » (S68-01 : ni « ../ » derrière le début habituel, ni « @ », ni
/// « % », ni « \ ») ; ni « [ ] { } » (S68-03 : motifs de curl) ; 600 caractères au plus
pub fn adresse_manifeste_simple(url: &str) -> bool {
    let Some(reste) = url.strip_prefix("https://") else { return false };
    if url.len() > 600 {
        return false;
    }
    let Some((autorite, chemin)) = reste.split_once('/') else { return false };
    let (hote, port) = match autorite.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (autorite, None),
    };
    let hote_ok = !hote.is_empty() && hote.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    let port_ok = port.is_none_or(|p| !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()) && matches!(p.parse::<u32>(), Ok(1..=65535)));
    let chemin_ok = !chemin.is_empty()
        && chemin.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-~/".contains(&b))
        && chemin.split('/').all(|s| s != "." && s != "..");
    hote_ok && port_ok && chemin_ok
}

/// Lecture d'une commande « testerSyslog » (décision pure, testée) : mêmes contrôles que les réglages
pub fn lire_syslog_test(texte: &str) -> Result<ConfigSyslog, String> {
    if let Some(k) = cle_ambigue(texte, &serde_json::to_value(ConfigSyslog::default()).unwrap_or_default()) {
        return Err(raison_refus("test refusé", &k));
    }
    let s: ConfigSyslog = serde_json::from_str(texte).map_err(|_| "réglages syslog illisibles".to_string())?;
    match reglages_invalides(&Config { syslog: s.clone(), langue: "fr".into(), ..Config::default() }) {
        Some(r) => Err(format!("test refusé : {r}")),
        None => Ok(s),
    }
}

/// Raison de refuser des réglages reçus : champs texte en listes fermées (langue, protocole, format, niveau) et hôte
/// syslog en lettres, chiffres, « . », « - » et « : » (nom, IPv4 ou IPv6), même désactivé (il reste en configuration).
/// Avant, ces champs étaient affichés bruts à la confirmation en administrateur : un texte long ou inversé pouvait en
/// cacher le vrai contenu (audit de sécurité S58-02).
pub fn reglages_invalides(n: &Config) -> Option<String> {
    if !["fr", "en"].contains(&n.langue.as_str()) {
        return Some("langue inconnue".into());
    }
    let s = &n.syslog;
    if !["UDP", "TCP"].contains(&s.protocole.as_str()) || !["JSON", "CEF"].contains(&s.format.as_str())
        || !["Info", "Alerte", "Critique"].contains(&s.niveau_min.as_str()) {
        return Some("protocole, format ou niveau syslog inconnu".into());
    }
    // « : » seulement dans une adresse IPv6 valide : « 10.0.0.5:25 » s'affichait « 10.0.0.5:25:514 » (S58-07)
    if s.hote.len() > 253 || !s.hote.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b':')
        || (s.hote.contains(':') && s.hote.parse::<std::net::Ipv6Addr>().is_err()) {
        return Some("serveur syslog : seulement un nom ou une adresse".into());
    }
    // Adresses autorisées de l'API (S58-06) : chiffres, « . », « / », « , », « ; » et espaces simples, longueur bornée
    // (un remplissage d'espaces cachait à la confirmation un réseau ouvert au pare-feu)
    let a = &n.api.adresses;
    if a.len() > 1000 || !a.bytes().all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'/' | b',' | b';' | b' ')) || a.contains("   ") {
        return Some("adresses autorisées de l'API : adresses IPv4 ou réseaux, séparés par des virgules".into());
    }
    // 16 au plus (S60-03), affichées une par ligne à la confirmation
    if a.split([',', ';', ' ']).filter(|x| !x.is_empty()).count() > 16 {
        return Some("adresses autorisées de l'API : 16 au plus".into());
    }
    None
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
    /// Version du modèle d'événement (docs/detection/modele-evenement.md) : 0 pour une alerte d'avant la phase 3,
    /// MODELE_ALERTE pour une alerte créée par cette version ; jamais réécrite pour une alerte relue
    pub modele: u32,
    /// Identifiant de la règle (docs/detection/regles.md), vide si l'alerte n'est rattachée à aucune (PR 3.2)
    #[serde(default, deserialize_with = "nul_vide", skip_serializing_if = "String::is_empty")]
    pub regle: String,
    /// Collecteur d'où vient l'alerte (état des collectes, PR 3.3)
    #[serde(default, deserialize_with = "nul_vide", skip_serializing_if = "String::is_empty")]
    pub collecte: String,
    /// Empreinte (« sha256:… ») du comportement, calculée sur le texte entier avant le bornage : c'est elle qu'une
    /// exception posée depuis cette alerte vise (audit de sécurité de #72, S72-10)
    #[serde(default, deserialize_with = "nul_vide", skip_serializing_if = "String::is_empty")]
    pub signature: String,
    /// Heure UTC (RFC 3339, « …Z ») et numéro d'ordre de création (phase 4, PR 4.1, D4-4) : l'heure locale est ambiguë
    /// pendant l'heure répétée du passage à l'heure d'hiver ; la chronologie ordonne sur (`HeureUtc`, `Seq`)
    #[serde(default, deserialize_with = "nul_vide", skip_serializing_if = "String::is_empty")]
    pub heure_utc: String,
    #[serde(default, skip_serializing_if = "est_zero")]
    pub seq: u64,
    /// Entité du suivi des incidents, quand le producteur la connaît mieux que le chemin ou la destination (phase 4,
    /// PR 4.3 : la source ou le compte d'une corrélation du SIEM) ; vide sinon
    #[serde(default, deserialize_with = "nul_vide", skip_serializing_if = "String::is_empty")]
    pub entite: String,
}

fn est_zero(n: &u64) -> bool {
    *n == 0
}

/// Empreinte d'une signature de comportement (apprentissage, exceptions) : taille fixe, quel que soit le texte
pub fn empreinte_signature(sig: &str) -> String {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(sig.as_bytes());
    format!("sha256:{}", h.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

/// Version actuelle du modèle d'événement des alertes
pub const MODELE_ALERTE: u32 = 1;

/// Pose le modèle actuel sur une alerte qui n'en a pas (appelé à un seul endroit : ajouter_alerte_brute)
pub fn marquer_modele(a: &mut Alerte) {
    if a.modele == 0 {
        a.modele = MODELE_ALERTE;
    }
    horodater(&mut a.heure_utc, &mut a.seq);
}

/// Numéro d'ordre de création des alertes et des événements, croissant depuis le démarrage du service (remis à zéro à
/// chaque démarrage ; `Etat.Demarrage` dit lequel)
static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Pose l'heure UTC et le numéro d'ordre s'ils manquent (une alerte relue d'un ancien fichier garde les siens, vides :
/// son histoire n'est pas réécrite ; elle n'est horodatée qu'à sa création, par l'appelant de `marquer_modele`)
pub fn horodater(heure_utc: &mut String, seq: &mut u64) {
    if heure_utc.is_empty() {
        *heure_utc = heure_utc_de(SystemTime::now());
    }
    if *seq == 0 {
        *seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    }
}

/// Secondes depuis 1970 d'une heure UTC au format de `heure_utc_de` (« AAAA-MM-JJTHH:MM:SSZ »), None sinon (pur, testé)
pub fn secondes_utc(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' || b[19] != b'Z' {
        return None;
    }
    let n = |a: usize, z: usize| s.get(a..z).filter(|t| t.bytes().all(|c| c.is_ascii_digit())).and_then(|t| t.parse::<i64>().ok());
    let (an, mo, j, h, mi, se) = (n(0, 4)?, n(5, 7)?, n(8, 10)?, n(11, 13)?, n(14, 16)?, n(17, 19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&j) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    let a = if mo <= 2 { an - 1 } else { an };
    let ere = a.div_euclid(400);
    let ade = a - ere * 400;
    let jda = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + j - 1;
    let jde = ade * 365 + ade / 4 - ade / 100 + jda;
    Some((ere * 146_097 + jde - 719_468) * 86_400 + h * 3600 + mi * 60 + se)
}

/// Heure UTC au format RFC 3339 à la seconde (« 2026-10-25T01:30:00Z »), sans dépendance (pur, testé) ; jours civils
/// par l'algorithme de Howard Hinnant
pub fn heure_utc_de(t: SystemTime) -> String {
    let secs = t.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let (jours, reste) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = jours + 719_468;
    let ere = z.div_euclid(146_097);
    let jde = z - ere * 146_097;
    let ade = (jde - jde / 1460 + jde / 36_524 - jde / 146_096) / 365;
    let jda = jde - (365 * ade + ade / 4 - ade / 100);
    let mp = (5 * jda + 2) / 153;
    let jour = jda - (153 * mp + 2) / 5 + 1;
    let mois = if mp < 10 { mp + 3 } else { mp - 9 };
    let an = ade + ere * 400 + if mois <= 2 { 1 } else { 0 };
    format!("{an:04}-{mois:02}-{jour:02}T{:02}:{:02}:{:02}Z", reste / 3600, reste % 3600 / 60, reste % 60)
}

/// Longueurs maximales (caractères) des champs d'une alerte qui peuvent venir de l'extérieur (audit de sécurité de #72,
/// S72-01 : une valeur Run d'1 Mo faisait une alerte de 6 Mo, trois suffisaient à faire mettre de côté l'historique) ;
/// caractères de contrôle remplacés par « ? ». En UTF-8, 4 octets au plus par caractère une fois écrit : une alerte
/// bornée tient en moins de 16 Ko, 1000 alertes en moins de TAILLE_MAX_ALERTES
pub const MAX_RAISONS_ALERTE: usize = 1000;
pub const MAX_CHEMIN_ALERTE: usize = 520;
pub const MAX_CHAMP_ALERTE: usize = 256;

/// Garde le début et la fin (moitié chacun, « … » entre les deux) : la conclusion d'une alerte (remarque, motif) est
/// souvent à la fin, après une donnée externe longue (audit de sécurité de #72, S72-06)
fn borner(s: &mut String, max: usize) {
    let n = s.chars().count();
    if n > max || s.chars().any(|c| c.is_control()) {
        let propre = |c: char| if c.is_control() { '?' } else { c };
        *s = if n > max {
            let debut: String = s.chars().take(max / 2).map(propre).collect();
            let fin: String = s.chars().skip(n - (max - max / 2)).map(propre).collect();
            format!("{debut} … {fin}")
        } else {
            s.chars().map(propre).collect()
        };
    }
}

/// Borne les champs d'une alerte (à la création, dans ajouter_alerte_brute, et à la relecture d'alertes.json depuis
/// l'audit de #94, S94-02 ; à la création, APRÈS les décisions prises sur le
/// texte entier : MITRE, signal fort, apprentissage ; AVANT tout usage : journal, export, notifications, SIEM,
/// alertes.json). Les champs posés par le code (Mitre, Conseil, Regle, Collecte) sont bornés aussi, pour que la borne
/// de taille reste vraie quand ils s'allongent (S72-07)
pub fn borner_alerte(a: &mut Alerte) {
    borner(&mut a.raisons, MAX_RAISONS_ALERTE);
    borner(&mut a.chemin, MAX_CHEMIN_ALERTE);
    borner(&mut a.parent, MAX_CHEMIN_ALERTE);
    // Heure UTC : 20 caractères quand le service la pose
    borner(&mut a.heure_utc, 32);
    borner(&mut a.entite, 160);
    for s in [&mut a.processus, &mut a.destination, &mut a.conseil] {
        borner(s, MAX_CHAMP_ALERTE);
    }
    // Champs posés par le code, courts par nature : bornes serrées, pour que la taille vaille dans le pire cas (S72-11)
    for (s, max) in [(&mut a.mitre, 128), (&mut a.regle, 64), (&mut a.collecte, 64), (&mut a.niveau, 16), (&mut a.heure, 32),
                     (&mut a.id, 64), (&mut a.signature, 80)] {
        borner(s, max);
    }
    for o in [&mut a.ip, &mut a.nom_dns] {
        if let Some(s) = o {
            borner(s, MAX_CHAMP_ALERTE);
        }
    }
}

/// Taille maximale d'alertes.json lue (1000 alertes bornées par borner_alerte en font moins) : au-delà, rien n'est lu
pub const TAILLE_MAX_ALERTES: u64 = 16 * 1024 * 1024;

/// Lecture tolérante d'alertes.json (décision pure, testée) : chaque élément du tableau est lu à part, un élément
/// illisible est écarté et compté, les autres sont gardés. None si le texte n'est pas un tableau JSON. Avant : une seule
/// alerte mal formée faisait perdre tout l'historique, puis le premier ajout réécrivait un fichier vide
pub fn lire_alertes_texte(texte: &str) -> Option<(Vec<Alerte>, usize)> {
    let serde_json::Value::Array(elements) = serde_json::from_str::<serde_json::Value>(texte).ok()? else { return None };
    let mut ecartees = 0;
    let mut alertes = Vec::with_capacity(elements.len());
    for e in elements {
        match serde_json::from_value::<Alerte>(e) {
            // Bornée à la relecture aussi (audit de #94, S94-02) : un fichier altéré par un administrateur ne fait plus
            // passer de champ démesuré vers l'interface et l'API ; sans effet sur une alerte écrite par le service
            Ok(mut a) => {
                borner_alerte(&mut a);
                alertes.push(a)
            }
            Err(_) => ecartees += 1,
        }
    }
    Some((alertes, ecartees))
}

/// Ce que le service fait d'alertes.json au démarrage (décision pure, testée ; relecture de #72)
pub enum DecisionAlertes {
    /// Lecture refusée (propriétaire, lien, protection) ou fichier absent : rien n'est lu, rien n'est déplacé
    Rien,
    /// Fichier gardé à part sous ce nom de raison, historique repris à vide (jamais écrasé)
    MettreDeCote(&'static str),
    /// Alertes lues ; si des éléments ont été écartés (nombre), une copie du fichier d'origine est gardée d'abord
    Lire(Vec<Alerte>, usize),
}

/// Ordre des contrôles : autorisation de lecture d'abord (un fichier refusé n'est jamais déplacé, même trop grand),
/// puis taille, puis contenu. Un contenu qui n'est pas de l'UTF-8 est mis de côté comme illisible (avant, il passait
/// pour « lecture refusée » et le premier ajout l'écrasait)
pub fn decision_alertes(autorisee: bool, taille: u64, contenu: Option<&[u8]>) -> DecisionAlertes {
    if !autorisee {
        return DecisionAlertes::Rien;
    }
    if taille > TAILLE_MAX_ALERTES {
        return DecisionAlertes::MettreDeCote("trop-grand");
    }
    let Some(octets) = contenu else { return DecisionAlertes::Rien };
    let Ok(texte) = std::str::from_utf8(octets) else { return DecisionAlertes::MettreDeCote("illisible") };
    match lire_alertes_texte(texte.trim_start_matches('\u{feff}')) {
        Some((a, n)) => DecisionAlertes::Lire(a, n),
        None => DecisionAlertes::MettreDeCote("illisible"),
    }
}

/// Lecture contrôlée autorisée (mêmes règles que lire_fichier), sans rien lire
pub(crate) fn lecture_fichier_autorisee(chemin: &Path) -> bool {
    let relatif = chemin.strip_prefix(dossier()).map(|r| r.to_string_lossy().to_string()).unwrap_or_default();
    let systeme = crate::natif::est_systeme();
    let proprietaire = if systeme { crate::natif::proprietaire_de_confiance(chemin) } else { None };
    let existe = fs::symlink_metadata(chemin).is_ok();
    match lecture_autorisee(systeme, !lisible_en_echec(&relatif), echec_protection().is_some(), existe, proprietaire) {
        Ok(()) => true,
        Err(raison) => {
            signaler_une_fois(chemin, raison);
            false
        }
    }
}

/// alertes.json du dossier de données, par la lecture tolérante (decision_alertes). Trop grand, pas en UTF-8 ou pas un
/// tableau : mis de côté (alertes-<raison>-<horodatage>.json, dans le dossier de données) au lieu d'être écrasé au
/// premier ajout. Éléments écartés : copie du fichier d'origine gardée (alertes-partiel-<horodatage>.json). Limites :
/// une erreur de lecture passagère (fichier tenu ailleurs) reprend à vide et le premier ajout réécrit le fichier ; les
/// fichiers mis de côté ne sont jamais purgés
pub fn lire_alertes() -> Vec<Alerte> {
    let f = dossier().join("alertes.json");
    let Ok(m) = fs::symlink_metadata(&f) else { return Vec::new() };
    let autorisee = lecture_fichier_autorisee(&f);
    let contenu = if autorisee && m.len() <= TAILLE_MAX_ALERTES { fs::read(&f).ok() } else { None };
    match decision_alertes(autorisee, m.len(), contenu.as_deref()) {
        DecisionAlertes::Rien => Vec::new(),
        DecisionAlertes::MettreDeCote(raison) => {
            if !mettre_alertes_de_cote(&f, raison, false) {
                *MISE_DE_COTE_EN_ATTENTE.lock().unwrap() = Some((raison, false));
            }
            Vec::new()
        }
        DecisionAlertes::Lire(a, 0) => a,
        DecisionAlertes::Lire(a, n) => {
            if !mettre_alertes_de_cote(&f, "partiel", true) {
                *MISE_DE_COTE_EN_ATTENTE.lock().unwrap() = Some(("partiel", true));
            }
            journal(&format!("alertes.json : {n} alerte(s) illisible(s) écartée(s), {} gardée(s)", a.len()));
            a
        }
    }
}

/// Mise de côté d'alertes.json qui a échoué au démarrage (fichier tenu ouvert ailleurs) : raison et copie ou renommage
static MISE_DE_COTE_EN_ATTENTE: std::sync::Mutex<Option<(&'static str, bool)>> = std::sync::Mutex::new(None);

/// Le service peut-il réécrire alertes.json ? Non tant qu'une mise de côté a échoué : elle est retentée à chaque appel,
/// les nouvelles alertes restent en mémoire jusque-là (audit de sécurité de #72, S72-02 : le premier ajout écrasait
/// l'historique qu'on n'avait pas pu mettre de côté)
pub fn ecriture_alertes_permise() -> bool {
    let mut attente = MISE_DE_COTE_EN_ATTENTE.lock().unwrap();
    let Some((raison, copie)) = *attente else { return true };
    let f = dossier().join("alertes.json");
    if fs::symlink_metadata(&f).is_err() || mettre_alertes_de_cote(&f, raison, copie) {
        *attente = None;
        return true;
    }
    false
}

/// Lecture d'alertes.json sans aucun effet (API) : lecture contrôlée et tolérante, rien n'est déplacé
pub fn lire_alertes_sans_effet() -> Vec<Alerte> {
    lire_fichier(&dossier().join("alertes.json"))
        .and_then(|t| lire_alertes_texte(t.trim_start_matches('\u{feff}')))
        .map(|(a, _)| a)
        .unwrap_or_default()
}

/// Garde alertes.json à part sous un nom neuf (jamais un fichier existant : horodatage, puis numéro), par renommage, ou
/// par copie si `copie` (le fichier d'origine reste en place). Vrai si c'est fait
fn mettre_alertes_de_cote(f: &Path, raison: &str, copie: bool) -> bool {
    let horodatage: String = maintenant().chars().filter(|c| c.is_ascii_digit()).collect();
    let Some(dest) = (0..100).map(|i| f.with_file_name(if i == 0 { format!("alertes-{raison}-{horodatage}.json") } else { format!("alertes-{raison}-{horodatage}-{i}.json") }))
        .find(|d| fs::symlink_metadata(d).is_err()) else {
        journal(&format!("alertes.json {raison} : aucun nom libre pour la mise de côté"));
        return false;
    };
    // Copie : destination créée neuve (create_new), jamais un fichier ou un lien posé entre-temps (relecture de #72, R4)
    let r = if copie {
        fs::OpenOptions::new().write(true).create_new(true).open(&dest)
            .and_then(|mut d| fs::File::open(f).and_then(|mut s| std::io::copy(&mut s, &mut d)).map(|_| ()))
    } else {
        fs::rename(f, &dest)
    };
    static ECHEC_SIGNALE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    match r {
        Ok(()) => {
            journal(&format!("alertes.json {raison} : {} ({})", if copie { "copie gardée" } else { "mis de côté, historique repris à vide" }, dest.display()));
            ECHEC_SIGNALE.store(false, std::sync::atomic::Ordering::Relaxed);
            true
        }
        Err(e) => {
            // Une ligne au journal par série d'échecs, pas une par alerte (audit de sécurité de #72, S72-08)
            if !ECHEC_SIGNALE.swap(true, std::sync::atomic::Ordering::Relaxed) {
                journal(&format!("alertes.json {raison} : mise de côté impossible ({e}), écriture retenue jusqu'à ce qu'elle réussisse"));
            }
            false
        }
    }
}

/// Un historique d'alertes existe-t-il (décision pure, testée) ? alertes.json, ou un fichier mis de côté
/// (alertes-<raison>-…json) : sert à ne pas prendre un poste déjà en service pour une première installation (relecture
/// de #72, D7 : une mise de côté renommait alertes.json et pouvait relancer l'apprentissage)
pub fn historique_alertes_existe(noms: &[String]) -> bool {
    noms.iter().any(|n| {
        let n = n.to_ascii_lowercase();
        n == "alertes.json" || (n.starts_with("alertes-") && n.ends_with(".json"))
    })
}

/// Noms des fichiers du dossier de données (premier niveau)
pub fn noms_du_dossier() -> Vec<String> {
    fs::read_dir(dossier()).map(|l| l.flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect()).unwrap_or_default()
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
    /// SID du client du tube, posé par le canal après l'admission (jamais lu dans la commande) : auteur des
    /// transitions d'incident (phase 4, PR 4.2)
    #[serde(skip)]
    pub auteur: String,
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

/// `f` dans un fil, attendu `duree` au plus : au-delà, rend None et laisse le fil, qui peut rester bloqué. Lecture ou suppression
/// d'un élément qu'un compte standard peut verrouiller, sans délai maximal connu (audit de #103, S103-01)
pub fn avec_echeance<T: Send + 'static>(duree: std::time::Duration, f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    let (envoi, reception) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = envoi.send(f());
    });
    reception.recv_timeout(duree).ok()
}

/// Comme `avec_echeance`, un seul fil à la fois par `garde` : tant que le précédent reste bloqué, `f` n'est pas lancée et rend None.
/// Le nombre de fils abandonnés reste borné
pub fn avec_echeance_unique<T: Send + 'static>(garde: &'static std::sync::atomic::AtomicBool, duree: std::time::Duration,
                                               f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    use std::sync::atomic::Ordering;
    if garde.swap(true, Ordering::SeqCst) {
        return None;
    }
    avec_echeance(duree, move || {
        let r = f();
        garde.store(false, Ordering::SeqCst);
        r
    })
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
