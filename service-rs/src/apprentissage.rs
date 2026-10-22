//! Moins de bruit, sans masquer les menaces :
//!   - mode apprentissage : pendant les premiers jours (7 par défaut), les alertes non critiques sont notées
//!     en information et leur « comportement » est mémorisé (le RMM du prestataire, les scripts d'inventaire,
//!     l'agent du logiciel de caisse, les outils de développement…) ; ensuite, un comportement appris ne
//!     déclenche plus qu'une information ;
//!   - exceptions : « ne plus alerter pour ce comportement », depuis l'interface (avec l'UAC).
//! Un comportement = chemin complet du programme + son éditeur + chemin du parent + destination (le domaine,
//! sinon l'adresse exacte) + technique : un « keepass.exe » posé ailleurs n'hérite pas de l'apprentissage du
//! vrai, et un programme n'apprend pas à contacter « n'importe quelle IP ».
//! Jamais adoucis : les alertes critiques, et les signaux forts même au niveau « Alerte » (code téléchargé par
//! PowerShell ou un outil Windows détourné, navigateur en débogage à distance, détections IDS).
//! L'apprentissage ne démarre qu'à la première installation, pas sur un poste déjà en service (peut-être déjà
//! compromis).

use crate::commun::{self, Alerte};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime};

const FICHIER: &str = "apprentissage.json";
pub const JOURS_PAR_DEFAUT: u64 = 7;

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Exception {
    pub signature: String,
    pub description: String,
    pub date: String,
}

/// Format des signatures : un changement de format oublie les comportements appris avec l'ancien
const FORMAT: u32 = 2;

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Etat {
    pub format: u32,
    pub debut: String,
    /// Fin du mode apprentissage (« aaaa-mm-jj hh:mm:ss ») ; passée : apprentissage terminé
    pub fin: String,
    pub appris: BTreeSet<String>,
    pub exceptions: Vec<Exception>,
}

fn etat() -> &'static Mutex<Etat> {
    static E: OnceLock<Mutex<Etat>> = OnceLock::new();
    E.get_or_init(|| {
        let mut e: Etat = commun::lire(FICHIER).unwrap_or_default();
        if e.debut.is_empty() {
            e.debut = commun::maintenant();
            // Première installation : apprentissage de 7 jours. Poste déjà en service (des alertes existent) : pas
            // d'apprentissage automatique, il peut être relancé depuis les réglages
            let deja_en_service = commun::dossier().join("alertes.json").exists();
            e.fin = if deja_en_service { e.debut.clone() } else { commun::heure(SystemTime::now() + Duration::from_secs(JOURS_PAR_DEFAUT * 86_400)) };
        }
        if e.format != FORMAT {
            e.format = FORMAT;
            e.appris.clear();
            e.exceptions.clear();
        }
        commun::ecrire(FICHIER, &e);
        Mutex::new(e)
    })
}

/// Éditeur d'un exécutable (signature intégrée ou catalogue de Windows), en cache
fn editeur(chemin: &str) -> String {
    static CACHE: OnceLock<Mutex<std::collections::HashMap<String, String>>> = OnceLock::new();
    if chemin.is_empty() {
        return String::new();
    }
    let cache = CACHE.get_or_init(|| Mutex::new(std::collections::HashMap::new()));
    // Clé : chemin et date de modification, pour qu'un exécutable remplacé (AppData) soit revérifié
    let date = std::fs::metadata(chemin).and_then(|m| m.modified()).map(crate::commun::filetime).unwrap_or(0);
    let cle = format!("{chemin}|{date}");
    if let Some(e) = cache.lock().unwrap().get(&cle) {
        return e.clone();
    }
    let e = crate::natif::signataire_valide(chemin)
        .or_else(|| crate::natif::signe_par_catalogue(chemin).then(|| "Windows (catalogue)".to_string()))
        .unwrap_or_else(|| "non signé".into());
    let mut c = cache.lock().unwrap();
    if c.len() > 2000 {
        c.clear();
    }
    c.insert(cle, e.clone());
    e
}

/// Comportement d'une alerte (fonction pure : l'éditeur est fourni)
pub fn signature_avec(a: &Alerte, editeur: &str) -> String {
    let nature = if a.mitre.is_empty() {
        a.raisons.split([':', '(', '[']).next().unwrap_or("").trim().chars().take(60).collect::<String>()
    } else {
        a.mitre.clone()
    };
    // Le domaine plutôt que l'adresse ; sans domaine, l'adresse exacte (jamais « n'importe quelle IP »)
    let destination = a.nom_dns.clone().filter(|n| !n.is_empty()).unwrap_or_else(|| a.destination.clone());
    format!("{}|{}|{}|{}|{}", a.chemin.to_lowercase(), editeur.to_lowercase(), a.parent.to_lowercase(), destination.to_lowercase(), nature.to_lowercase())
}

pub fn signature(a: &Alerte) -> String {
    signature_avec(a, &editeur(&a.chemin))
}

/// Signaux forts : jamais appris ni adoucis par l'apprentissage, même au niveau « Alerte »
pub fn signal_fort(a: &Alerte) -> bool {
    let r = a.raisons.to_lowercase();
    a.destination.starts_with("IDS :")
        || ["télécharge du code", "lolbin", "débogage à distance", "suppression des sauvegardes", "macro ou exploit"].iter().any(|m| r.contains(m))
}

/// Décision pure : (nouveau niveau, mention ajoutée, à mémoriser)
pub fn decider(niveau: &str, signature: &str, en_apprentissage: bool, appris: &BTreeSet<String>, exceptions: &[Exception]) -> Option<(&'static str, &'static str, bool)> {
    if niveau == "Critique" || niveau == "Info" {
        return None;
    }
    if exceptions.iter().any(|e| e.signature == signature) {
        return Some(("Info", " [exception enregistrée]", false));
    }
    if appris.contains(signature) {
        return Some(("Info", " [comportement appris]", false));
    }
    if en_apprentissage {
        return Some(("Info", " [mode apprentissage : comportement mémorisé]", true));
    }
    None
}

/// Appliqué à chaque alerte avant son enregistrement
pub fn filtrer(a: &mut Alerte) {
    if a.niveau == "Critique" || a.niveau == "Info" {
        return;
    }
    let fort = signal_fort(a);
    let sig = signature(a);
    let mut e = etat().lock().unwrap();
    let en_cours = commun::maintenant() < e.fin;
    // Signal fort : seule une exception explicite (posée par un administrateur, avec confirmation) peut l'adoucir
    let en_cours = en_cours && !fort;
    let vide = BTreeSet::new();
    let decision = decider(&a.niveau, &sig, en_cours, if fort { &vide } else { &e.appris }, &e.exceptions);
    if let Some((niveau, mention, memoriser)) = decision {
        a.niveau = niveau.into();
        a.score = a.score.min(1);
        a.raisons.push_str(mention);
        if memoriser && e.appris.len() < 5000 && e.appris.insert(sig) {
            commun::ecrire(FICHIER, &*e);
        }
    }
}

pub fn ajouter_exception(a: &Alerte) -> String {
    let mut e = etat().lock().unwrap();
    let sig = signature(a);
    let description = format!("{} — {} — {}", a.processus, a.destination, a.raisons.chars().take(120).collect::<String>());
    if !e.exceptions.iter().any(|x| x.signature == sig) {
        e.exceptions.push(Exception { signature: sig, description: description.clone(), date: commun::maintenant() });
        commun::ecrire(FICHIER, &*e);
    }
    description
}

/// « terminer », « recommencer » (7 jours, comportements appris oubliés) ou « oublier » (exceptions)
pub fn commande(quoi: &str) -> Result<String, String> {
    let mut e = etat().lock().unwrap();
    let m = match quoi {
        "terminer" => {
            e.fin = commun::maintenant();
            format!("Mode apprentissage terminé : {} comportement(s) appris ne déclencheront plus qu'une information.", e.appris.len())
        }
        "recommencer" => {
            e.debut = commun::maintenant();
            e.fin = commun::heure(SystemTime::now() + Duration::from_secs(JOURS_PAR_DEFAUT * 86_400));
            e.appris.clear();
            format!("Mode apprentissage relancé pour {JOURS_PAR_DEFAUT} jours ; les comportements appris ont été oubliés.")
        }
        "oublier" => {
            let n = e.exceptions.len();
            e.exceptions.clear();
            format!("{n} exception(s) supprimée(s).")
        }
        _ => return Err("commande d'apprentissage inconnue".into()),
    };
    commun::ecrire(FICHIER, &*e);
    Ok(m)
}
