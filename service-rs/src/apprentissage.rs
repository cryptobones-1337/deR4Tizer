//! Moins de bruit, sans masquer les menaces :
//!   - mode apprentissage : pendant les premiers jours (7 par défaut), les alertes non critiques sont notées
//!     en information et leur « comportement » est mémorisé (le RMM du prestataire, les scripts d'inventaire,
//!     l'agent du logiciel de caisse, les outils de développement…) ; ensuite, un comportement appris ne
//!     déclenche plus qu'une information ;
//!   - exceptions : « ne plus alerter pour ce comportement », depuis l'interface (avec l'UAC).
//! Un comportement = programme + ce qu'il fait (destination ou parent, chiffres neutralisés) + technique.
//! Les alertes critiques (listes de menaces, rançongiciel, vol de données, IDS…) ne sont jamais adoucies.

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

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Etat {
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
            // Première version avec l'apprentissage : il commence maintenant
            e.debut = commun::maintenant();
            e.fin = commun::heure(SystemTime::now() + Duration::from_secs(JOURS_PAR_DEFAUT * 86_400));
            commun::ecrire(FICHIER, &e);
        }
        Mutex::new(e)
    })
}

/// Comportement d'une alerte : programme, ce qu'il fait (chiffres neutralisés : une IP ou un port de plus ne
/// fait pas un nouveau comportement), technique ou nature de la détection
pub fn signature(a: &Alerte) -> String {
    let neutre = |t: &str| {
        let mut s = String::new();
        for c in t.to_lowercase().chars() {
            if c.is_ascii_digit() {
                if !s.ends_with('#') {
                    s.push('#');
                }
            } else {
                s.push(c);
            }
        }
        s
    };
    let nature = if a.mitre.is_empty() {
        a.raisons.split([':', '(', '[']).next().unwrap_or("").trim().chars().take(60).collect::<String>()
    } else {
        a.mitre.clone()
    };
    format!("{}|{}|{}", a.processus.to_lowercase(), neutre(&a.destination), neutre(&nature))
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
    let sig = signature(a);
    let mut e = etat().lock().unwrap();
    let en_cours = commun::maintenant() < e.fin;
    if let Some((niveau, mention, memoriser)) = decider(&a.niveau, &sig, en_cours, &e.appris, &e.exceptions) {
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
