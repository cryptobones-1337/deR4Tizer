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
    /// Codes stables des indices du score (comportement de l'alerte : empreinte des exceptions), hors etat.json
    #[serde(skip)]
    pub codes: String,
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
    /// Vrai si le budget de `chaines` (`chaines::BUDGET_CHAINES`) a fait retirer des signaux, des nœuds ou des chaînes
    /// (audit de #323, S323-01)
    pub chaines_tronquees: bool,
    /// Vrai dès que le mode panique n'est pas proprement inactif (actif ou incertain) : « Rétablir Internet » reste offert
    pub panique: bool,
    /// « active », « inactive » ou « incertaine » : compté sur les règles du pare-feu, pas sur le drapeau seul (PR 6.5)
    pub panique_etat: String,
    pub exposition: crate::parefeu::Exposition,
    /// Vide si la protection du dossier de données est vérifiée ; sinon la raison de l'échec
    pub protection_donnees: String,
    /// Registre des réponses (reponses.json) : vide s'il est écrit normalement ; sinon « EcritureEnEchec » (avec le début
    /// de l'échec), « LectureRefusee », « ContenuIllisible » ou « ProtectionEnEchec » (échéances de la session perdues au
    /// redémarrage). Code traduit par l'interface
    pub registre_reponses: String,
    pub registre_reponses_depuis: String,
    /// Exceptions et comportements appris d'un format d'empreinte précédent, qui ne s'appliquent plus (jamais perdus en
    /// silence : dits dans la page Santé ; revue de l'auditeur du 2026-11-22, point 2)
    pub exceptions_perimees: u32,
    pub appris_perimes: u32,
    /// apprentissage.json présent mais non chargé au démarrage (droits, verrou, contenu mal formé non mis de côté) : les
    /// exceptions posées depuis tiennent en mémoire seulement (page Santé)
    pub apprentissage_non_charge: bool,
    /// config.json présent mais non chargé (lecture refusée, impossible ou contenu mal formé ; audit du 2026-11-23, C-3) :
    /// le service tourne avec la configuration par défaut et ne réécrit jamais le fichier (page Santé, SAN-014)
    pub configuration_non_chargee: bool,
    /// État de chaque collecte (phase 3.3) et règles dont la télémétrie n'est pas lue (ou ne l'est qu'en partie)
    pub collectes: Vec<crate::collectes::EtatCollecte>,
    pub regles_sans_collecte: Vec<String>,
    pub regles_degradees: Vec<String>,
    /// Pour chaque règle sans collecte, les sources dont l'une au moins manque (phase 3.3d, lues par l'interface)
    pub causes_sans_collecte: Vec<crate::collectes::CauseSansCollecte>,
    /// États effectifs des réponses automatiques (T-18) : ce qui agirait vraiment, pas seulement le réglage
    pub reponses_auto: EtatReponsesAuto,
    /// États effectifs de l'export syslog et de l'API d'export (T-18)
    pub syslog: EtatSortie,
    pub api: EtatSortie,
}

/// États effectifs des réponses automatiques (T-18, décisions pures de `politique.rs`), en codes stables traduits par
/// l'interface : « Desactive », « Actif », « Partiel », « SansEffet », « NonVerifiable ». Vides dans un etat.json écrit
/// avant
#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq, Eq)]
#[serde(rename_all = "PascalCase", default)]
pub struct EtatReponsesAuto {
    /// Suspension d'un programme qui touche un leurre (`politique::etat_rancongiciel`)
    pub rancongiciel: String,
    /// Blocage au pare-feu des adresses du niveau 3 (`politique::etat_blocage_listes`)
    pub blocage_listes: String,
}

/// État effectif d'une sortie vers un tiers (T-18) : réglage, et code « Desactive », « Joignable », « EnEchec » ou
/// « NonVerifiable » (`export::etat_syslog`, `api::etat_api`). Ni hôte, ni port, ni adresse
#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq, Eq)]
#[serde(rename_all = "PascalCase", default)]
pub struct EtatSortie {
    pub actif: bool,
    pub etat: String,
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
    /// Bloque au pare-feu, dès qu'une connexion est vue, les IP de Spamhaus DROP et de Feodo Tracker
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
    /// Filtrage par nom de domaine (phase 7) : catégories actives (vide par défaut : rien n'est téléchargé ni bloqué)
    /// et domaines autorisés par l'utilisateur
    #[serde(deserialize_with = "nul_par_defaut")]
    pub filtrage: ConfigFiltrage,
}

/// Filtrage par nom de domaine (phase 7, PR 7.2, `filtrage.rs`). Aucun effet réseau avant le résolveur local (7.3, 7.4)
#[derive(Serialize, Deserialize, Clone, Default, PartialEq)]
#[serde(rename_all = "PascalCase", default)]
pub struct ConfigFiltrage {
    /// « securite », « publicite » ; noms inconnus ignorés
    pub categories: Vec<String>,
    /// Domaines jamais bloqués (et leurs sous-domaines), `filtrage::MAX_AUTORISES` au plus ; commandes
    /// filtrageAutoriser et filtrageRetirer
    pub autorises: Vec<String>,
    /// Filtrage activé sur les cartes (PR 7.4, commande `filtrage`) : repris au démarrage du service
    pub actif: bool,
    /// Résolveur d'amont : vide, celui du réseau (défaut) ; sinon la clé d'un résolveur tiers compilé (« quad9 ») (PR 7.6)
    pub amont: String,
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
            filtrage: ConfigFiltrage::default(),
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
    // Toutes les formes d'un dossier de profil, où qu'elles soient dans le texte : « C:\Users\nom », « C:/Users/nom »,
    // « \\?\C:\Users\nom », « %SystemDrive%\Users\nom » (audit de #221, S221-01)
    static R: OnceLock<regex::Regex> = OnceLock::new();
    R.get_or_init(|| regex::Regex::new(r"(?i)(?:\\\\\?\\)?(?:[a-z]:|%systemdrive%)[\\/]users[\\/][^\\/:;,\r\n]+").unwrap())
        .replace_all(chemin, "%USERPROFILE%").into_owned()
}

/// Texte venu d'un fichier que seul un administrateur peut écrire, recopié dans un message : chemin de profil masqué et
/// longueur bornée (audit de #221, S221-02)
pub fn borner_texte(texte: &str, max: usize) -> String {
    let t = masquer_chemin(texte);
    if t.chars().count() <= max { t } else { format!("{}…", t.chars().take(max).collect::<String>()) }
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
    /// Code stable du comportement, posé par le code qui produit l'alerte (outil vu, type d'entrée, indices d'une
    /// connexion, règle IDS…) ; avec l'identifiant de règle, il fait la nature de l'empreinte des exceptions et de
    /// l'apprentissage, indépendante des techniques ATT&CK et des conseils (revue de l'auditeur du 2026-11-22, point 2).
    /// Vide : la nature retombe sur le début des raisons
    #[serde(default, deserialize_with = "nul_vide", skip_serializing_if = "String::is_empty")]
    pub comportement: String,
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

/// Entité d'alerte, bornée comme dans `borner_alerte` (160 caractères, début « … » fin, contrôles remplacés) : partagée
/// avec les chaînes d'etat.json, qui publient ainsi le même texte que l'alerte CHA-001 (prérelecture de #323, D1)
pub const MAX_ENTITE_ALERTE: usize = 160;
pub fn entite_bornee(entite: &str) -> String {
    let mut e = entite.to_string();
    borner(&mut e, MAX_ENTITE_ALERTE);
    e
}

/// Borne les champs d'une alerte (à la création, dans ajouter_alerte_brute, et à la relecture d'alertes.json depuis
/// l'audit de #94, S94-02 ; à la création, APRÈS les décisions prises sur le
/// texte entier : MITRE, signal fort, apprentissage ; AVANT tout usage : journal, export, notifications, SIEM,
/// alertes.json). Les champs posés par le code (Mitre, Conseil, Regle, Collecte) sont bornés aussi, pour que la borne
/// de taille reste vraie quand ils s'allongent (S72-07). Secrets des lignes de commande masqués dans les raisons et la
/// destination (audit du 2026-11-23, A-6-1) : ici, après les décisions et avant tout usage, alertes relues comprises
pub fn borner_alerte(a: &mut Alerte) {
    a.raisons = masquer_secrets(&a.raisons);
    a.destination = masquer_secrets(&a.destination);
    borner(&mut a.raisons, MAX_RAISONS_ALERTE);
    borner(&mut a.chemin, MAX_CHEMIN_ALERTE);
    borner(&mut a.parent, MAX_CHEMIN_ALERTE);
    // Heure UTC : 20 caractères quand le service la pose
    borner(&mut a.heure_utc, 32);
    a.entite = entite_bornee(&a.entite);
    for s in [&mut a.processus, &mut a.destination, &mut a.conseil] {
        borner(s, MAX_CHAMP_ALERTE);
    }
    // Champs posés par le code, courts par nature : bornes serrées, pour que la taille vaille dans le pire cas (S72-11)
    for (s, max) in [(&mut a.mitre, 128), (&mut a.regle, 64), (&mut a.collecte, 64), (&mut a.niveau, 16), (&mut a.heure, 32),
                     (&mut a.id, 64), (&mut a.signature, 80)] {
        borner(s, max);
    }
    // Code de comportement (revue de l'auditeur du 2026-11-22, point 2) : codes ASCII posés par le producteur ; tout
    // autre caractère est retiré (la même alerte donne toujours le même code), 120 octets au plus (pire cas, S72-11)
    a.comportement.retain(|c| c.is_ascii_graphic());
    a.comportement.truncate(120);
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

/// Lecture contrôlée autorisée (mêmes règles que lire_fichier, contrôles faits sur le handle), sans rien lire au-delà
/// d'un octet
pub(crate) fn lecture_fichier_autorisee(chemin: &Path) -> bool {
    let relatif = chemin.strip_prefix(dossier()).map(|r| r.to_string_lossy().to_string()).unwrap_or_default();
    matches!(lire_controle_detail(chemin, !lisible_en_echec(&relatif), 0), Lecture::Absent | Lecture::Octets(_) | Lecture::TropGrand)
}

/// alertes.json du dossier de données, par la lecture tolérante (decision_alertes). Trop grand, pas en UTF-8 ou pas un
/// tableau : mis de côté (alertes-<raison>-<horodatage>.json, dans le dossier de données) au lieu d'être écrasé au
/// premier ajout. Éléments écartés : copie du fichier d'origine gardée (alertes-partiel-<horodatage>.json). Limites :
/// une erreur de lecture passagère (fichier tenu ailleurs) reprend à vide et le premier ajout réécrit le fichier ; les
/// fichiers mis de côté ne sont jamais purgés
pub fn lire_alertes() -> Vec<Alerte> {
    let f = dossier().join("alertes.json");
    // Contrôles et contenu par un seul handle (C-8) ; absent à l'ouverture : rien n'est lu
    let (autorisee, taille, contenu) = match lire_controle_detail(&f, !lisible_en_echec("alertes.json"), TAILLE_MAX_ALERTES) {
        Lecture::Absent => return Vec::new(),
        Lecture::Refusee(_) => (false, 0, None),
        Lecture::TropGrand => (true, TAILLE_MAX_ALERTES + 1, None),
        Lecture::Erreur(_) => (true, 0, None),
        Lecture::Octets(o) => (true, o.len() as u64, Some(o)),
    };
    match decision_alertes(autorisee, taille, contenu.as_deref()) {
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
        ouvrir_pour_ecrire(fs::OpenOptions::new().write(true).create_new(true), &dest)
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
    /// Identité du processus visé, telle qu'elle a été montrée à l'administrateur (tuer, suspendre, reprendre, tuerChaine)
    pub chemin: Option<String>,
    pub creation: Option<u64>,
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
/// lecture échoue alors d'elle-même). Un fichier à plusieurs liens physiques (`liens`, lu sur le handle) est refusé :
/// un lien dur vers un fichier de SYSTEM pris ailleurs porte le propriétaire de ce fichier (audit du 2026-11-23, C-2) ;
/// un nombre de liens illisible aussi (échec fermé).
pub fn lecture_autorisee(systeme: bool, avec_verrou: bool, echec_protection: bool, existe: bool, proprietaire_ok: Option<bool>, liens: Option<u32>) -> Result<(), &'static str> {
    if !systeme {
        return Ok(());
    }
    if avec_verrou && echec_protection {
        return Err("protection du dossier non vérifiée");
    }
    match proprietaire_ok {
        Some(true) => {}
        Some(false) => return Err("propriétaire ni SYSTEM ni Administrateurs"),
        None if existe => return Err("propriétaire illisible"),
        None => return Ok(()),
    }
    match liens {
        Some(1) => Ok(()),
        _ if !existe => Ok(()),
        Some(_) => Err("plusieurs liens physiques (lien dur)"),
        None => Err("nombre de liens physiques illisible"),
    }
}

/// Résultat d'une lecture contrôlée d'un fichier du dossier de données (C-3 : absent n'est pas illisible)
#[derive(Debug, PartialEq)]
pub enum Lecture {
    /// Le fichier n'existe pas : rien n'a été lu
    Absent,
    /// Présent, lecture refusée par le contrôle (protection, propriétaire, lien, liens physiques)
    Refusee(&'static str),
    /// Présent, ouverture ou lecture impossible (verrou, droits)
    Erreur(String),
    /// Présent, plus grand que la taille lue au plus (rien n'est rendu)
    TropGrand,
    Octets(Vec<u8>),
}

/// Accès de lecture du handle : GENERIC_READ (READ_CONTROL compris, pour lire le propriétaire sur le même handle)
const LECTURE_HANDLE: u32 = 0x8000_0000;

/// Lecture contrôlée (audit du 2026-11-23, C-8) : en service, le fichier est ouvert UNE fois, sans suivre de lien, et
/// propriétaire, nombre de liens physiques et contenu sont lus sur ce même handle ; un fichier absent à l'ouverture n'est
/// jamais lu (avant : propriétaire lu par le chemin, puis contenu relu par le chemin, deux accès entre lesquels le
/// fichier pouvait changer). Au plus `max` octets (au-delà : TropGrand). `de_confiance` : règle d'acceptation du
/// propriétaire (SYSTEM et Administrateurs en service ; fournie par les tests)
pub fn lire_controle_avec(chemin: &Path, systeme: bool, avec_verrou: bool, echec: bool, max: u64, de_confiance: &dyn Fn(&str) -> bool) -> Lecture {
    use std::io::Read;
    let f = if systeme {
        match crate::natif::ouvrir_sans_lien(chemin, LECTURE_HANDLE, 0x7, false) {
            Ok(f) => f,
            Err(crate::natif::ErreurOuverture::Absent) => return Lecture::Absent,
            Err(crate::natif::ErreurOuverture::Lien) => return Lecture::Refusee("lien (jonction ou lien symbolique)"),
            Err(e) => return Lecture::Erreur(e.to_string()),
        }
    } else {
        match fs::File::open(chemin) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Lecture::Absent,
            Err(e) => return Lecture::Erreur(e.to_string()),
        }
    };
    let (proprietaire, liens) = if systeme {
        (crate::natif::proprietaire_par_handle(&f).map(|s| de_confiance(&s)), crate::natif::nombre_de_liens(&f))
    } else {
        (None, None)
    };
    if let Err(raison) = lecture_autorisee(systeme, avec_verrou, echec, true, proprietaire, liens) {
        return Lecture::Refusee(raison);
    }
    let mut octets = Vec::new();
    match (&f).take(max.saturating_add(1)).read_to_end(&mut octets) {
        Ok(_) if octets.len() as u64 > max => Lecture::TropGrand,
        Ok(_) => Lecture::Octets(octets),
        Err(e) => Lecture::Erreur(e.to_string()),
    }
}

/// `lire_controle_avec` du service : refus signalés une fois au journal
fn lire_controle_detail(chemin: &Path, avec_verrou: bool, max: u64) -> Lecture {
    let l = lire_controle_avec(chemin, crate::natif::est_systeme(), avec_verrou, echec_protection().is_some(), max,
        &crate::protection::proprietaire_acceptable);
    if let Lecture::Refusee(raison) = &l {
        signaler_une_fois(chemin, raison);
    }
    l
}

fn lire_controle(chemin: &Path, avec_verrou: bool) -> Option<String> {
    match lire_controle_detail(chemin, avec_verrou, u64::MAX) {
        Lecture::Octets(o) => String::from_utf8(o).ok(),
        _ => None,
    }
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

/// Fichier du dossier de données lu par `lire_etat` (audit du 2026-11-23, C-3) : absent, présent mais non chargé
/// (lecture refusée, impossible ou contenu mal formé, avec la raison), ou chargé
#[derive(Debug, PartialEq)]
pub enum Lu<T> {
    Absent,
    NonCharge(String),
    Valeur(T),
}

/// Essais de lecture d'un fichier présent mais impossible à lire (verrou passager) avant de le dire non chargé
pub const ESSAIS_LECTURE: u32 = 3;

/// Décision pure (C-3) à partir des lectures successives d'un même fichier : la première lecture qui aboutit (absent,
/// refus de contrôle, contenu) décide ; une erreur d'ouverture ou de lecture est réessayée, `ESSAIS_LECTURE` fois en tout.
/// Contenu mal formé : non chargé, sans nouvel essai
pub fn lu_de<T: DeserializeOwned>(lire: &mut dyn FnMut() -> Lecture) -> Lu<T> {
    let mut derniere = String::new();
    for _ in 0..ESSAIS_LECTURE {
        match lire() {
            Lecture::Absent => return Lu::Absent,
            Lecture::Refusee(r) => return Lu::NonCharge(format!("lecture refusée : {r}")),
            Lecture::TropGrand => return Lu::NonCharge("trop grand".into()),
            Lecture::Octets(o) => {
                return match std::str::from_utf8(&o).map_err(|e| e.to_string())
                    .and_then(|t| serde_json::from_str(t.trim_start_matches('\u{feff}')).map_err(|e| e.to_string())) {
                    Ok(v) => Lu::Valeur(v),
                    Err(e) => Lu::NonCharge(format!("contenu mal formé : {e}")),
                };
            }
            Lecture::Erreur(e) => derniere = format!("lecture impossible : {e}"),
        }
    }
    Lu::NonCharge(derniere)
}

/// Fichiers présents mais non chargés à leur dernière lecture par `lire_etat` (C-3), en minuscules : jamais réécrits par
/// `ecrire` tant qu'une lecture ne les a pas chargés ou vus absents. Avant : illisible valait absent, et la première
/// écriture remplaçait le fichier légitime par les valeurs par défaut (configuration, blocages, bases « connues »)
static NON_CHARGES: Mutex<Option<HashSet<String>>> = Mutex::new(None);

fn cle_fichier(nom: &str) -> String {
    nom.replace('/', "\\").to_lowercase()
}

/// Le fichier `nom` (relatif au dossier de données) était-il présent mais non chargé à sa dernière lecture ?
pub fn non_charge(nom: &str) -> bool {
    NON_CHARGES.lock().unwrap_or_else(|e| e.into_inner()).as_ref().is_some_and(|s| s.contains(&cle_fichier(nom)))
}

fn noter_lecture(nom: &str, charge_ou_absent: bool) {
    let mut g = NON_CHARGES.lock().unwrap_or_else(|e| e.into_inner());
    let s = g.get_or_insert_with(HashSet::new);
    if charge_ou_absent {
        s.remove(&cle_fichier(nom));
    } else {
        s.insert(cle_fichier(nom));
    }
}

/// Lecture d'un fichier JSON du dossier de données qui distingue « absent » de « présent mais non chargé » (C-3) ; un
/// fichier non chargé n'est plus réécrit (`ecrire`) jusqu'à une lecture qui le charge ou le voit absent
pub fn lire_etat<T: DeserializeOwned>(nom: &str) -> Lu<T> {
    lire_etat_de(nom, &dossier().join(nom))
}

/// `lire_etat` du fichier `chemin`, suivi sous le nom `nom` (tests : dossier de travail)
pub fn lire_etat_de<T: DeserializeOwned>(nom: &str, chemin: &Path) -> Lu<T> {
    let relatif = nom.to_string();
    let mut premiere = true;
    let lu = lu_de(&mut || {
        if !premiere {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        premiere = false;
        lire_controle_detail(chemin, !lisible_en_echec(&relatif), u64::MAX)
    });
    match &lu {
        Lu::NonCharge(raison) => {
            if !non_charge(nom) {
                journal(&format!("{nom} présent mais non chargé ({raison}) : il n'est pas réécrit tant qu'il n'a pas été relu"));
            }
            noter_lecture(nom, false);
        }
        _ => noter_lecture(nom, true),
    }
    lu
}

pub fn lire<T: DeserializeOwned>(nom: &str) -> Option<T> {
    match lire_etat(nom) {
        Lu::Valeur(v) => Some(v),
        _ => None,
    }
}

/// Écriture atomique : fichier temporaire synchronisé sur le disque, puis remplacement (écriture immédiate),
/// pour que l'interface ne lise jamais un fichier à moitié écrit. Erreur si le fichier n'a pas été remplacé :
/// les appelants pour qui l'écriture fait partie d'une transaction (quarantaine) la vérifient. Un fichier présent mais
/// non chargé à sa dernière lecture n'est jamais remplacé (C-3)
pub fn ecrire<T: Serialize + ?Sized>(nom: &str, donnees: &T) -> Result<(), String> {
    ecrire_suivi(nom, &dossier().join(nom), donnees)
}

/// `ecrire` vers `chemin`, suivi sous le nom `nom` (tests : dossier de travail)
pub fn ecrire_suivi<T: Serialize + ?Sized>(nom: &str, chemin: &Path, donnees: &T) -> Result<(), String> {
    if non_charge(nom) {
        return Err(format!("{nom} présent mais non chargé : il n'est pas réécrit"));
    }
    ecrire_dans(chemin, donnees)
}

// ------------------------------------------------------------ racine du dossier de données (C-1)

/// Racine du dossier de données vérifiée par handle (audit du 2026-11-23, C-1) : ouverte sans suivre de lien, chemin final
/// vérifié, propriétaire et droits relus sur ce handle (protection::securiser au démarrage du service, et toutes les heures ;
/// protection::verifier_racine pour les actions du MSI lancées en SYSTEM)
static RACINE_VERIFIEE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn definir_racine_verifiee(v: bool) {
    RACINE_VERIFIEE.store(v, std::sync::atomic::Ordering::SeqCst);
}

/// Décision pure (C-1), seule réponse à « racine sûre ? » : hors SYSTEM (tests, console), oui ; en SYSTEM, seulement une
/// racine vérifiée par handle. Une jonction à la racine posée par un compte standard faisait écrire le service, en SYSTEM,
/// dans le dossier de ce compte (essai en VM du 2026-11-23 : journal, état, alertes, SIEM, secrets, 42 éléments)
pub fn ecriture_permise(systeme: bool, racine_verifiee: bool) -> bool {
    !systeme || racine_verifiee
}

pub fn racine_sure() -> bool {
    ecriture_permise(crate::natif::est_systeme(), RACINE_VERIFIEE.load(std::sync::atomic::Ordering::SeqCst))
}

/// Chemin dans le dossier de données (racine comprise), comparé élément par élément sans tenir compte de la casse (pur, testé)
pub fn dans_le_dossier(f: &Path, racine: &Path) -> bool {
    let bas = |p: &Path| p.components().map(|c| c.as_os_str().to_string_lossy().to_lowercase()).collect::<Vec<_>>();
    let (f, r) = (bas(f), bas(racine));
    !r.is_empty() && f.get(..r.len()) == Some(&r[..])
}

/// Décision pure (audit de #287, S287-01) : écriture directe permise sur `f` ? Refusée seulement pour un chemin SOUS la
/// racine du dossier de données (la racine elle-même exclue : protection.rs la crée par son chemin quand elle est absente,
/// puis la vérifie par handle) tant que la racine n'est pas sûre
pub fn ecriture_directe_permise(f: &Path, racine: &Path, sure: bool) -> bool {
    sure || !dans_le_dossier(f, racine) || dans_le_dossier(racine, f)
}

/// Garde de toutes les écritures directes (fichier, dossier, ouverture en écriture) dans le dossier de données (S287-01) :
/// les modules ne passent jamais par std::fs pour écrire dessous, mais par ecrire_fichier, creer_dossiers ou
/// ouvrir_pour_ecrire (test de structure lot_a_ecritures_directes_par_la_garde)
pub fn garde_racine(f: &Path) -> std::io::Result<()> {
    if ecriture_directe_permise(f, dossier(), racine_sure()) {
        Ok(())
    } else {
        Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied,
            format!("{} : racine du dossier de données non vérifiée, rien n'est écrit", f.display())))
    }
}

/// `std::fs::write` sous la garde de la racine (S287-01)
pub fn ecrire_fichier<P: AsRef<Path>, C: AsRef<[u8]>>(f: P, contenu: C) -> std::io::Result<()> {
    garde_racine(f.as_ref())?;
    fs::write(f, contenu)
}

/// `std::fs::create_dir_all` sous la garde de la racine (S287-01)
pub fn creer_dossiers<P: AsRef<Path>>(d: P) -> std::io::Result<()> {
    garde_racine(d.as_ref())?;
    fs::create_dir_all(d)
}

/// `std::fs::create_dir` (un seul niveau : le parent doit exister) sous la garde de la racine (S287-01)
pub fn creer_dossier<P: AsRef<Path>>(d: P) -> std::io::Result<()> {
    garde_racine(d.as_ref())?;
    fs::create_dir(d)
}

/// Ouverture en écriture (création, ajout, remplacement) sous la garde de la racine (S287-01)
pub fn ouvrir_pour_ecrire<P: AsRef<Path>>(options: &fs::OpenOptions, f: P) -> std::io::Result<fs::File> {
    garde_racine(f.as_ref())?;
    options.open(f)
}

/// `ecrire` vers un chemin quelconque (tests, dossiers de travail). Rien sous le dossier de données tant que sa racine
/// n'est pas sûre (C-1)
pub fn ecrire_dans<T: Serialize + ?Sized>(f: &Path, donnees: &T) -> Result<(), String> {
    if dans_le_dossier(f, dossier()) && !racine_sure() {
        return Err(format!("{} : racine du dossier de données non vérifiée, rien n'est écrit", f.display()));
    }
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

/// Admission d'une clé de déduplication d'alertes (audit du 2026-11-14, A6, A7 ; audit de #176, S176-01)
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Admission {
    /// Nouvelle clé : alerter
    Nouvelle,
    /// Déjà alertée dans la fenêtre
    Deja,
    /// Budget de la catégorie épuisé : une seule alerte de synthèse par catégorie et par fenêtre
    PlafondAtteint(String),
    /// Budget épuisé, synthèse de cette catégorie déjà émise dans la fenêtre
    PlafondDejaSignale,
}

/// Catégorie d'une clé : ce qui précède le premier « | » (« dhcp|10.0.0.9 » → « dhcp »)
fn categorie_cle(cle: &str) -> &str {
    cle.split('|').next().unwrap_or(cle)
}

/// Table `deja` bornée par catégorie (pur, testé) : au plus `par_categorie` clés vivantes par catégorie ; au-delà,
/// cette catégorie seule cesse d'alerter une à une, avec une synthèse par fenêtre. Une inondation dans une catégorie
/// (options DHCP variées, ports sortants) ne tait donc jamais les autres (usurpation de passerelle, JA3, serveur de
/// contrôle : S176-01). Les marques de synthèse commencent par U+0000, qu'aucune clé construite par les modules ne
/// porte (préfixes ASCII fixes)
pub(crate) fn admettre_cle(deja: &mut HashMap<String, std::time::Instant>, cle: String, fenetre: std::time::Duration, par_categorie: usize) -> Admission {
    if deja.get(&cle).is_some_and(|t| t.elapsed() < fenetre) {
        return Admission::Deja;
    }
    // Purge des clés expirées dès que la table dépasse ce que 16 catégories pleines occuperaient : une catégorie
    // maintenue sous son budget ne la fait plus grossir sans fin (audit v2 de #176, S176-04)
    if deja.len() > par_categorie.saturating_mul(16) {
        deja.retain(|_, t| t.elapsed() < fenetre);
    }
    let cat = categorie_cle(&cle).to_string();
    let prefixe = format!("{cat}|");
    let compter = |d: &HashMap<String, std::time::Instant>| d.iter().filter(|(k, t)| (k.starts_with(&prefixe) || **k == cat) && t.elapsed() < fenetre).count();
    if compter(deja) >= par_categorie {
        deja.retain(|_, t| t.elapsed() < fenetre);
        if compter(deja) >= par_categorie {
            let marque = format!("\u{0}plafond|{cat}");
            if deja.get(&marque).is_some_and(|t| t.elapsed() < fenetre) {
                return Admission::PlafondDejaSignale;
            }
            deja.insert(marque, std::time::Instant::now());
            return Admission::PlafondAtteint(cat);
        }
    }
    deja.insert(cle, std::time::Instant::now());
    Admission::Nouvelle
}

// ------------------------------------------------------------ secrets des lignes de commande

/// Ce qui remplace une valeur secrète (audit du 2026-11-23, A-6-1)
pub const MASQUE: &str = "***";

/// Options suivies de leur valeur secrète quel que soit l'outil, comparées sans tenir compte de la casse : --password,
/// -Password, -Credential et -SecurePassword de PowerShell…
const OPTIONS_SUIVIES_DU_SECRET: &[&str] = &["--password", "-password", "--pass", "--passwd", "-pwd", "-credential", "-securepassword"];

/// Options dont la valeur secrète est collée, quel que soit l'outil (casse ignorée) : /p:x (xfreerdp, wevtutil), /pass:x
/// (cmdkey), /password:x (wmic), --password=x (mysql, wget), -Password:x (PowerShell), et les variables d'environnement
/// qui portent un mot de passe (PGPASSWORD=x psql, set MYSQL_PWD=x, $env:SSHPASS='x')
const PREFIXES_DU_SECRET: &[&str] = &["/p:", "/pass:", "/password:", "/pwd:", "--password=", "-password=", "--pass=", "--passwd=",
    "-password:", "--http-password=", "--ftp-password=", "--proxy-password=", "pgpassword=", "mysql_pwd=", "sshpass=",
    "$env:pgpassword=", "$env:mysql_pwd=", "$env:sshpass="];

/// Où est le secret d'une option : dans le mot suivant (en entier, ou après le séparateur `compte<sep>motdepasse`), ou
/// collé à l'option
#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum Forme {
    Suivie,
    Collee,
    CompteSuivi(char),
    CompteColle(char),
}

/// Outils Windows d'administration à distance dont `/p <mot de passe>` suit `/s <poste> /u <compte>`
const OUTILS_SLASH_P: &[&str] = &["schtasks", "gpresult", "systeminfo", "tasklist", "taskkill", "eventcreate", "getmac", "openfiles",
    "driverquery", "eventtriggers", "waitfor"];

/// Options qui ne portent un secret que pour certains outils (revue de #269) : ailleurs, `/p` est un drapeau sans valeur
/// (xcopy, del, findstr) et `-p` ou `-P` un port (ssh, scp, nc). Les options en `/` se comparent sans la casse, celles en
/// `-` avec (sqlcmd -P mot de passe, mais ssh -P port n'est pas listé)
const OPTIONS_PAR_OUTIL: &[(&[&str], &str, Forme)] = &[
    (OUTILS_SLASH_P, "/p", Forme::Suivie),
    (&["schtasks"], "/rp", Forme::Suivie),
    (&["mysql", "mysqldump", "mysqladmin", "mysqlimport", "mysqlshow", "mariadb", "mariadb-dump"], "-p", Forme::Collee),
    (&["psexec", "psexec64", "paexec", "sshpass", "rdesktop"], "-p", Forme::Suivie),
    (&["sshpass"], "-p", Forme::Collee),
    (&["7z", "7za", "7zr", "7zg", "rar", "winrar", "unrar"], "-p", Forme::Collee),
    (&["plink", "pscp", "psftp", "putty", "winscp"], "-pw", Forme::Suivie),
    (&["unzip", "zip", "pkzipc"], "-P", Forme::Suivie),
    (&["sqlcmd", "osql", "isql", "bcp"], "-P", Forme::Suivie),
    (&["sqlcmd", "osql", "isql", "bcp"], "-P", Forme::Collee),
    (&["openssl"], "-pass", Forme::Suivie),
    (&["openssl"], "-passin", Forme::Suivie),
    (&["openssl"], "-passout", Forme::Suivie),
    (&["openssl"], "-k", Forme::Suivie),
    (&["curl"], "-u", Forme::CompteSuivi(':')),
    (&["curl"], "--user", Forme::CompteSuivi(':')),
    (&["curl"], "--proxy-user", Forme::CompteSuivi(':')),
    (&["curl"], "-u", Forme::CompteColle(':')),
    (&["smbclient", "rpcclient", "smbmap"], "-U", Forme::CompteSuivi('%')),
    (&["smbclient", "rpcclient"], "--user", Forme::CompteSuivi('%')),
];

/// Nom d'outil d'un mot (sans guillemets, chemin ni « .exe », en minuscules)
fn nom_outil(v: &str) -> String {
    // `sch^tasks` (échappement de cmd) et `@schtasks` (écho coupé) désignent le même outil
    let v = v.replace('^', "");
    let v = v.trim_matches(|c| c == '"' || c == '\'' || c == '(');
    let v = v.strip_prefix('@').unwrap_or(v);
    let n = v.rsplit(['\\', '/']).next().unwrap_or("").to_ascii_lowercase();
    n.strip_suffix(".exe").map(str::to_string).unwrap_or(n)
}

/// Outil qui porte un secret dans ses options (`OPTIONS_PAR_OUTIL`)
pub(crate) fn outil_a_secret(nom: &str) -> bool {
    OPTIONS_PAR_OUTIL.iter().any(|(outils, _, _)| outils.contains(&nom))
}

/// Lanceurs dont la commande suit une option : `cmd /c …`, `powershell -c …`. Après cette option, le mot suivant est en tête
/// de commande
const LANCEURS_PAR_OPTION: &[(&[&str], &[&str])] = &[
    (&["cmd"], &["/c", "/k", "/r"]),
    (&["powershell", "pwsh"], &["-c", "-command", "/c", "/command"]),
];

/// Lanceurs dont la commande est le premier mot qui n'est ni une option, ni la valeur d'une option, ni un poste (`\\srv`),
/// ni un titre entre guillemets : `start "" ssh …`, `sshpass -p x ssh …`, `psexec \\srv -u a cmd …`
const LANCEURS_DIRECTS: &[&str] = &["start", "call", "sshpass", "psexec", "psexec64", "paexec", "runas", "nohup", "sudo", "start-process", "saps"];

/// Options d'un lanceur direct suivies d'une valeur (le mot suivant n'est pas la commande) ; les autres options sont des
/// drapeaux (psexec -d, -s, -i, -h, -accepteula ; start /b, /min, /wait…), sautés
const OPTIONS_A_VALEUR_DES_LANCEURS: &[(&[&str], &[&str])] = &[
    (&["psexec", "psexec64", "paexec"], &["-u", "-p", "-w", "-n", "-a", "-cpu", "-r", "-f"]),
    (&["sshpass"], &["-p", "-f", "-d"]),
    (&["start"], &["/d", "/node", "/affinity"]),
    (&["sudo"], &["-u", "-g"]),
    (&["start-process", "saps"], &["-argumentlist", "-args", "-windowstyle", "-workingdirectory", "-credential", "-verb",
        "-redirectstandardoutput", "-redirectstandarderror", "-redirectstandardinput"]),
];

/// Le mot qui suit `mot` est-il en tête de commande, pour l'outil courant `outil` (décision pure, testée) ? Après un
/// séparateur, après « : » seul ou collé à un mot (« Processus créé: <ligne> », raisons d'une alerte), après `cmd /c` ou
/// `powershell -c`
pub(crate) fn tete_apres(outil: &str, mot: &str) -> bool {
    let fin_de_prefixe = mot == ":" || (mot.ends_with(':') && mot.chars().count() > 2 && !mot.starts_with('-') && !mot.starts_with('/'));
    separateur_de_commandes(mot) || fin_de_prefixe
        || LANCEURS_PAR_OPTION.iter().any(|(outils, options)| outils.contains(&outil) && options.iter().any(|o| mot.eq_ignore_ascii_case(o)))
}

/// `mot` (précédé de `precedent`) est-il la commande lancée par le lanceur direct `outil` (décision pure, testée) ? Ni une
/// option, ni la valeur d'une option du lanceur, ni un poste (`\\srv`), ni un titre entre guillemets
pub(crate) fn commande_lancee(outil: &str, mot: &str, precedent: &str) -> bool {
    let option = |m: &str| m.starts_with('-') || m.starts_with('/');
    let valeur = OPTIONS_A_VALEUR_DES_LANCEURS.iter()
        .any(|(lanceurs, options)| lanceurs.contains(&outil) && options.iter().any(|o| precedent.eq_ignore_ascii_case(o)));
    LANCEURS_DIRECTS.contains(&outil) && !mot.is_empty() && !option(mot) && !mot.starts_with("\\\\") && !mot.starts_with('"')
        && !mot.starts_with('\'') && !valeur
}

/// Ce qu'il faut masquer pour le mot `mot` d'une ligne dont l'outil courant est `outil` (décision pure, testée) :
/// `Dans(o)` masque le mot à partir de l'octet `o` ; `Suivant(None)` le mot suivant en entier ; `Suivant(Some(c))` le mot
/// suivant après le séparateur `c`
#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum Masque {
    Dans(usize),
    Suivant(Option<char>),
}

pub(crate) fn secret_d_option(outil: &str, mot: &str) -> Option<Masque> {
    let commence = |o: &str, casse: bool| mot.len() > o.len() && mot.get(..o.len()).is_some_and(|x| if casse { x == o } else { x.eq_ignore_ascii_case(o) });
    if let Some(p) = PREFIXES_DU_SECRET.iter().find(|p| commence(p, false)) {
        return Some(Masque::Dans(p.len()));
    }
    if OPTIONS_SUIVIES_DU_SECRET.iter().any(|o| mot.eq_ignore_ascii_case(o)) {
        return Some(Masque::Suivant(None));
    }
    for (outils, option, forme) in OPTIONS_PAR_OUTIL {
        if !outils.contains(&outil) {
            continue;
        }
        let sans_casse = option.starts_with('/');
        let egal = if sans_casse { mot.eq_ignore_ascii_case(option) } else { mot == *option };
        match forme {
            Forme::Suivie if egal => return Some(Masque::Suivant(None)),
            Forme::CompteSuivi(c) if egal => return Some(Masque::Suivant(Some(*c))),
            Forme::Collee if commence(option, !sans_casse) => return Some(Masque::Dans(option.len())),
            Forme::CompteColle(c) if commence(option, !sans_casse) => {
                let reste = mot.get(option.len()..).unwrap_or("");
                if let Some(i) = reste.find(*c).filter(|i| i + 1 < reste.len()) {
                    return Some(Masque::Dans(option.len() + i + 1));
                }
            }
            _ => {}
        }
    }
    None
}

/// Ligne de commande secrets masqués, pour tout ce qui est stocké ou publié (SIEM, alertes, etat.json, exports) ; jamais pour
/// la détection, qui analyse la ligne entière (pur, testé ; audit du 2026-11-23, A-6-1). Remplace par `***` : la valeur des
/// options de `OPTIONS_SUIVIES_DU_SECRET` et `PREFIXES_DU_SECRET` (tout outil), celle des options de `OPTIONS_PAR_OUTIL` pour
/// leurs seuls outils (`secret_d_option`, revue de #269), la valeur de `ConvertTo-SecureString`, les mots de passe
/// de `net use` (tout argument qui n'est ni une option, ni un lecteur, ni un chemin réseau, ni `*`) et de `net user <compte>
/// <mot de passe>`, et le mot de passe d'une adresse `schéma://compte:motdepasse@hôte`. Une valeur entre guillemets est
/// masquée en entier ; une valeur qui est une expression PowerShell (`$variable`, `(…)`) ne l'est pas. Le texte entre
/// guillemets est aussi lu comme une ligne (powershell -c "…"). Aucune indexation qui puisse paniquer (règle 4)
pub fn masquer_secrets(ligne: &str) -> String {
    masquer_mots(&masquer_urls(ligne), 0, &[])
}

/// Mots d'une ligne de commande, en octets (début, fin), séparés par des blancs ; un mot entre guillemets doubles (où qu'ils
/// s'ouvrent) ou simples (ouverts en début de mot, ou après « : », « = », « ( » ou « , ») garde ses blancs. Une virgule qui
/// suit un guillemet fermant sépare deux mots (tableau PowerShell `@('/p','x')`, revue de #269) ; une virgule dans un mot
/// nu (`/p pa,ss`) ne sépare rien
fn mots_de_commande(s: &str) -> Vec<(usize, usize)> {
    let mut mots = Vec::new();
    let (mut debut, mut guillemet, mut precedent): (Option<usize>, Option<char>, Option<char>) = (None, None, None);
    for (i, c) in s.char_indices() {
        match guillemet {
            Some(q) => {
                if c == q {
                    guillemet = None;
                }
            }
            None if c.is_whitespace() => {
                if let Some(d) = debut.take() {
                    mots.push((d, i));
                }
            }
            // Séparateur collé (`echo x&&schtasks`, revue de #269) : un mot à lui seul, hors guillemets
            None if c == '&' || c == '|' => {
                if let Some(d) = debut.take() {
                    mots.push((d, i));
                }
                mots.push((i, i + 1));
            }
            None if c == ',' && matches!(precedent, Some('\'' | '"')) => {
                if let Some(d) = debut.take() {
                    mots.push((d, i));
                }
            }
            None => {
                let d = *debut.get_or_insert(i);
                if c == '"' || (c == '\'' && (d == i || matches!(precedent, Some(':' | '=' | '(' | ',')))) {
                    guillemet = Some(c);
                }
            }
        }
        precedent = Some(c);
    }
    if let Some(d) = debut {
        mots.push((d, s.len()));
    }
    mots
}

/// Partie utile d'un mot, en octets (début, fin) : sans `@(` ou `(` de tête, sans `)`, `,` ou `;` de fin, ni les guillemets
/// qui l'entourent (`@('/p'` → `/p`, `'x')` → `x`) ; seuls des caractères ASCII sont retirés (bornes de caractère sûres)
fn interieur(t: &str) -> (usize, usize) {
    let o = t.as_bytes();
    let (mut a, mut b) = (0, o.len());
    if o.first() == Some(&b'@') && o.get(1) == Some(&b'(') {
        a = 2;
    } else if o.first() == Some(&b'(') {
        a = 1;
    }
    while b > a && matches!(o.get(b - 1), Some(b')' | b',' | b';')) {
        b -= 1;
    }
    if let Some(&q) = o.get(a).filter(|q| matches!(q, b'\'' | b'"')) {
        a += 1;
        if b > a && o.get(b - 1) == Some(&q) {
            b -= 1;
        }
    }
    (a, b.max(a))
}

/// Valeur littérale (à masquer) : ni vide, ni une expression PowerShell, ni un séparateur de commandes
fn valeur_litterale(v: &str) -> bool {
    !v.is_empty() && !v.starts_with('$') && !v.starts_with('(') && !separateur_de_commandes(v)
}

fn separateur_de_commandes(v: &str) -> bool {
    matches!(v, "&" | "&&" | "|" | "||" | ";")
}

/// `net`, `net1`, avec ou sans chemin ni extension
fn est_net(v: &str) -> bool {
    let v = v.trim_matches('"').to_ascii_lowercase();
    matches!(v.rsplit(['\\', '/']).next().unwrap_or(""), "net" | "net.exe" | "net1" | "net1.exe")
}

/// `herites` : outils à secret actifs là où ce texte est cité (`Start-Process schtasks -ArgumentList '/p x'`, revue de #269)
fn masquer_mots(s: &str, profondeur: u8, herites: &[String]) -> String {
    let mots = mots_de_commande(s);
    let texte = |k: usize| mots.get(k).and_then(|&(a, b)| s.get(a..b)).unwrap_or("");
    // Pour chaque mot : partie masquée (octets du mot, début et fin) ; outils à secret actifs pour un mot entre guillemets
    let mut masques: Vec<Option<(usize, usize)>> = vec![None; mots.len()];
    let mut contextes: Vec<Vec<String>> = vec![Vec::new(); mots.len()];
    // Deux états (revue de #269, D2 et D3). `actifs` : les outils qui portent un secret vus dans la commande ; le passage vers
    // l'un d'eux est permis sur n'importe quel mot (`start /b schtasks`, `call schtasks`, `psexec … -d schtasks`, « Processus
    // créé: schtasks ») et reste acquis jusqu'au séparateur suivant (verrou : au pire on masque trop). `outil` : l'outil
    // courant, qui ne passe à un outil sans secret qu'en tête de commande (premier mot, après un séparateur, après « : »,
    // après `cmd /c` ou `powershell -c`) ou comme commande d'un lanceur direct, jamais sur la valeur d'une option (`/tr
    // cmd.exe`). La commande d'un lanceur met fin à ses options : le lanceur quitte `actifs` (`sshpass -p x ssh -p 22`)
    let mut actifs: Vec<String> = herites.to_vec();
    let mut outil = String::new();
    let mut tete = true;
    for k in 0..mots.len() {
        let brut = texte(k);
        // Mot sans parenthèses ni guillemets de tableau (`@('/p'` → `/p`) ; `a` : décalage de sa partie utile
        let (a, z) = interieur(brut);
        let t = brut.get(a..z).unwrap_or("");
        if separateur_de_commandes(brut) {
            actifs.clear();
            outil.clear();
            tete = true;
            continue;
        }
        let nom = nom_outil(t);
        let precedent = if k > 0 { texte(k - 1).get(interieur(texte(k - 1)).0..interieur(texte(k - 1)).1).unwrap_or("") } else { "" };
        let lancee = commande_lancee(&outil, brut, precedent);
        if lancee {
            actifs.retain(|a| *a != outil);
        }
        if outil_a_secret(&nom) {
            if !actifs.contains(&nom) {
                actifs.push(nom.clone());
            }
            outil = nom;
            tete = false;
        } else if tete {
            // Affectation en tête (PGPASSWORD=x psql) : la commande suit
            if !(brut.contains('=') && !brut.starts_with('-') && !brut.starts_with('/')) {
                outil = nom;
                tete = false;
            }
        } else if lancee {
            outil = nom;
        }
        if tete_apres(&outil, t) {
            tete = true;
        }
        if brut.starts_with('"') || brut.starts_with('\'') {
            contextes[k] = actifs.clone();
        }
        let masque = actifs.iter().map(String::as_str).chain([""]).find_map(|o| secret_d_option(o, t));
        match masque {
            Some(Masque::Dans(o)) => masques[k] = Some((a + o, z)),
            Some(Masque::Suivant(separateur)) => {
                let brut_v = texte(k + 1);
                let (va, vz) = interieur(brut_v);
                let v = brut_v.get(va..vz).unwrap_or("");
                let depuis = match separateur {
                    None => Some(va),
                    Some(c) => v.find(c).filter(|i| i + 1 < v.len()).map(|i| va + i + 1),
                };
                if let (true, Some(o), Some(m)) = (valeur_litterale(brut_v) && !v.is_empty(), depuis, masques.get_mut(k + 1)) {
                    *m = Some((o, vz));
                }
            }
            None => {}
        }
        if t.trim_start_matches('(').eq_ignore_ascii_case("convertto-securestring") {
            let j = if texte(k + 1).eq_ignore_ascii_case("-string") { k + 2 } else { k + 1 };
            if valeur_litterale(texte(j)) && !texte(j).starts_with('-') {
                if let Some(m) = masques.get_mut(j) {
                    *m = Some((0, texte(j).len()));
                }
            }
        }
        if est_net(t) && (texte(k + 1).eq_ignore_ascii_case("use") || texte(k + 1).eq_ignore_ascii_case("user")) {
            let user = texte(k + 1).eq_ignore_ascii_case("user");
            let mut positionnels = 0;
            for j in k + 2..mots.len() {
                let v = texte(j);
                if separateur_de_commandes(v) {
                    break;
                }
                if v.starts_with('/') || v == "*" {
                    continue;
                }
                positionnels += 1;
                let lecteur = v.len() == 2 && v.as_bytes().first().is_some_and(u8::is_ascii_alphabetic) && v.ends_with(':');
                let reseau = v.trim_start_matches('"').starts_with("\\\\") || v.contains("://");
                // net use : tout sauf le lecteur et le chemin réseau ; net user : le mot de passe suit le nom du compte
                if (!user && !lecteur && !reseau) || (user && positionnels >= 2) {
                    masques[j] = Some((0, v.len()));
                }
            }
        }
    }
    let mut sortie = String::with_capacity(s.len());
    let mut position = 0;
    for (k, &(a, b)) in mots.iter().enumerate() {
        let remplacement = match masques[k] {
            Some((o, z)) => Some(format!("{}{MASQUE}{}", s.get(a..a + o).unwrap_or(""), s.get(a + z..b).unwrap_or(""))),
            None => {
                // Texte entre guillemets : lu comme une ligne (powershell -c "…"), trois niveaux au plus
                let t = texte(k);
                let q = t.chars().next().filter(|c| *c == '"' || *c == '\'');
                match q {
                    Some(q) if profondeur < 3 => {
                        let ferme = t.len() > 1 && t.ends_with(q);
                        let dedans = t.get(1..if ferme { t.len() - 1 } else { t.len() }).unwrap_or("");
                        let m = masquer_mots(dedans, profondeur + 1, &contextes[k]);
                        (m != dedans).then(|| format!("{q}{m}{}", if ferme { q.to_string() } else { String::new() }))
                    }
                    _ => None,
                }
            }
        };
        if let Some(r) = remplacement {
            sortie.push_str(s.get(position..a).unwrap_or(""));
            sortie.push_str(&r);
            position = b;
        }
    }
    sortie.push_str(s.get(position..).unwrap_or(""));
    sortie
}

/// Mot de passe d'une adresse `schéma://compte:motdepasse@hôte` masqué
fn masquer_urls(s: &str) -> String {
    let mut sortie = String::with_capacity(s.len());
    let mut reste = s;
    while let Some(i) = reste.find("://") {
        let (avant, apres) = (reste.get(..i + 3).unwrap_or(""), reste.get(i + 3..).unwrap_or(""));
        sortie.push_str(avant);
        let fin = apres.find(|c: char| c == '/' || c.is_whitespace() || c == '"' || c == '\'').unwrap_or(apres.len());
        let autorite = apres.get(..fin).unwrap_or("");
        let compte = autorite.rfind('@').and_then(|at| autorite.get(..at).and_then(|u| u.find(':')).map(|c| (c, at)));
        match compte {
            Some((c, at)) if at > c + 1 => {
                sortie.push_str(autorite.get(..=c).unwrap_or(""));
                sortie.push_str(MASQUE);
                sortie.push_str(autorite.get(at..).unwrap_or(""));
            }
            _ => sortie.push_str(autorite),
        }
        reste = apres.get(fin..).unwrap_or("");
    }
    sortie.push_str(reste);
    sortie
}

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

/// Taille au-delà de laquelle journal.txt tourne, et générations gardées : journal.1.txt (la plus récente) à journal.5.txt,
/// 12 Mo au plus en tout (audit du 2026-11-23, A-8-3 : une seule génération, un bruit provoqué effaçait l'historique en
/// deux rotations)
pub const TAILLE_JOURNAL: u64 = 2 * 1024 * 1024;
pub const GENERATIONS_JOURNAL: usize = 5;

/// Rotation due (pure, testée)
pub fn rotation_due(taille: u64) -> bool {
    taille > TAILLE_JOURNAL
}

/// Heure en tête d'une ligne de journal (« AAAA-MM-JJ HH:MM:SS »), si elle y est
fn heure_de_ligne(l: &str) -> Option<&str> {
    let h = l.get(..19)?;
    h.bytes().enumerate().all(|(i, b)| match i { 4 | 7 => b == b'-', 10 => b == b' ', 13 | 16 => b == b':', _ => b.is_ascii_digit() }).then_some(h)
}

/// Heures de la première et de la dernière ligne d'un journal, lues au début et à la fin du fichier (jamais les 2 Mo) ;
/// « inconnu » si elles ne s'y lisent pas
fn bornes_journal(f: &Path) -> (String, String) {
    use std::io::{Read, Seek, SeekFrom};
    let mut debut = None;
    let mut fin = None;
    if let Ok(mut fichier) = fs::File::open(f) {
        let mut tete = [0u8; 64];
        let n = fichier.read(&mut tete).unwrap_or(0);
        debut = heure_de_ligne(&String::from_utf8_lossy(tete.get(..n).unwrap_or(&[]))).map(String::from);
        let taille = fichier.metadata().map(|m| m.len()).unwrap_or(0);
        let mut queue = Vec::new();
        if fichier.seek(SeekFrom::Start(taille.saturating_sub(1024))).is_ok() && fichier.take(1024).read_to_end(&mut queue).is_ok() {
            fin = String::from_utf8_lossy(&queue).lines().rev().find_map(|l| heure_de_ligne(l).map(String::from));
        }
    }
    (debut.unwrap_or_else(|| "inconnu".into()), fin.unwrap_or_else(|| "inconnu".into()))
}

/// Fait tourner journal.txt du dossier `d` : journal.4 → journal.5 (l'ancien journal.5 est remplacé), …, journal.txt →
/// journal.1 ; rend la ligne qui dit l'intervalle couvert par journal.1, écrite en tête du nouveau journal ; None sans
/// journal.txt ou si son renommage échoue (testé). Un renommage dans le même dossier garde les droits du fichier, hérités du
/// dossier de données (lecteurs compris) ; la désinstallation efface tout le contenu du dossier
pub fn tourner_journal(d: &Path) -> Option<String> {
    let f = d.join("journal.txt");
    fs::metadata(&f).ok()?;
    let (debut, fin) = bornes_journal(&f);
    for g in (1..GENERATIONS_JOURNAL).rev() {
        let _ = fs::rename(d.join(format!("journal.{g}.txt")), d.join(format!("journal.{}.txt", g + 1)));
    }
    fs::rename(&f, d.join("journal.1.txt")).ok()?;
    Some(format!("journal : rotation au-delà de {} Mo ; journal.1.txt couvre {debut} à {fin} ; générations gardées : journal.1 à journal.{GENERATIONS_JOURNAL}",
        TAILLE_JOURNAL / (1024 * 1024)))
}

pub fn journal(message: &str) {
    // Un seul écrivain à la fois : deux fils ne font jamais tourner le journal deux fois de suite
    static VERROU: Mutex<()> = Mutex::new(());
    let _garde = VERROU.lock().unwrap_or_else(|e| e.into_inner());
    // Une ligne par message : caractères de contrôle et séparateurs de ligne Unicode remplacés par une espace (noms
    // DNS, NBNS, UPnP, lignes de commande venus du poste ou du réseau ajoutaient de fausses lignes horodatées,
    // audit AUD4-05)
    let propre = ligne_de_journal(message);
    // Racine du dossier de données non vérifiée (C-1) : rien n'est écrit dessous, la ligne va au journal d'événements de
    // Windows (journal Application, source « deR4Tizer », sans enregistrement de source)
    if !racine_sure() {
        crate::natif::journal_evenements(&propre, false);
        return;
    }
    let d = dossier();
    let f = d.join("journal.txt");
    // Rotation : au-delà de 2 Mo, sur 5 générations (un bruit provoqué n'efface pas tout)
    let rotation = if fs::metadata(&f).map(|m| rotation_due(m.len())).unwrap_or(false) { tourner_journal(&d) } else { None };
    if let Ok(mut fichier) = fs::OpenOptions::new().create(true).append(true).open(&f) {
        if let Some(r) = rotation {
            let _ = writeln!(fichier, "{}  {}\r", maintenant(), r);
        }
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
