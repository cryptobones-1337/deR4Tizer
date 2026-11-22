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

/// Format des signatures. Un changement de format rend inapplicables les exceptions et les comportements appris de
/// l'ancien (empreintes à sens unique, non convertibles) : ils sont comptés, gardés pour les exceptions, et dits dans
/// la page Santé, jamais perdus en silence (revue de l'auditeur du 2026-11-22, point 2). Format 3 : nature = règle et
/// code de comportement posé par le producteur, indépendante des techniques ATT&CK et des conseils
const FORMAT: u32 = 3;

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Etat {
    pub format: u32,
    pub debut: String,
    /// Fin du mode apprentissage (« aaaa-mm-jj hh:mm:ss ») ; passée : apprentissage terminé
    pub fin: String,
    pub appris: BTreeSet<String>,
    pub exceptions: Vec<Exception>,
    /// Exceptions d'un format précédent, qui ne s'appliquent plus : gardées (description, date) pour être reposées
    pub exceptions_perimees: Vec<Exception>,
    /// Nombre de comportements appris d'un format précédent, qui ne s'appliquent plus
    pub appris_perimes: u32,
}

/// Décision pure (testée) : migration d'un état lu d'un autre format. Les exceptions passent dans les périmées (gardées),
/// les comportements appris sont comptés puis oubliés ; rend vrai si l'état a changé
pub fn migrer(e: &mut Etat) -> bool {
    if e.format == FORMAT {
        return false;
    }
    let n_exceptions = e.exceptions.len();
    let n_appris = e.appris.len();
    e.exceptions_perimees.append(&mut e.exceptions);
    e.appris_perimes = e.appris_perimes.saturating_add(n_appris as u32);
    e.appris.clear();
    e.format = FORMAT;
    if n_exceptions + n_appris > 0 {
        commun::journal(&format!("empreinte des exceptions au format {FORMAT} : {n_exceptions} exception(s) et {n_appris} comportement(s) appris d'un format précédent ne s'appliquent plus (dit dans la page Santé)"));
    }
    true
}

/// Exceptions et comportements appris d'un format précédent qui ne s'appliquent plus (page Santé)
pub fn perimes() -> (u32, u32) {
    let e = etat().lock().unwrap();
    (e.exceptions_perimees.len() as u32, e.appris_perimes)
}

fn etat() -> &'static Mutex<Etat> {
    static E: OnceLock<Mutex<Etat>> = OnceLock::new();
    E.get_or_init(|| {
        let chemin = commun::dossier().join(FICHIER);
        let lu: Option<Etat> = commun::lire(FICHIER);
        if lu.is_none() && chemin.is_file() {
            // Fichier présent mais illisible : gardé de côté, jamais écrasé sans trace (audit de #255, S255-03)
            let cote = commun::dossier().join("apprentissage-illisible.json");
            let r = std::fs::rename(&chemin, &cote);
            commun::journal(&format!("apprentissage.json illisible : gardé sous {} ({}) ; exceptions et apprentissage repartent de zéro",
                cote.display(), if r.is_ok() { "renommé" } else { "renommage en échec" }));
        }
        let mut e: Etat = lu.unwrap_or_default();
        if e.format != FORMAT && (!e.exceptions.is_empty() || !e.appris.is_empty()) {
            // Copie de côté avant la migration (audit de #255, S255-02) : une version précédente, après un retour arrière,
            // effacerait les exceptions du format 3 ; cette copie permet de les retrouver
            let cote = commun::dossier().join(format!("apprentissage-format{}.json", e.format));
            if std::fs::copy(&chemin, &cote).is_ok() {
                commun::journal(&format!("apprentissage.json au format {} copié sous {} avant la migration", e.format, cote.display()));
            }
        }
        if e.debut.is_empty() {
            e.debut = commun::maintenant();
            // Première installation : apprentissage de 7 jours. Poste déjà en service (des alertes existent) : pas
            // d'apprentissage automatique, il peut être relancé depuis les réglages
            let deja_en_service = commun::historique_alertes_existe(&commun::noms_du_dossier());
            e.fin = if deja_en_service { e.debut.clone() } else { commun::heure(SystemTime::now() + Duration::from_secs(JOURS_PAR_DEFAUT * 86_400)) };
        }
        migrer(&mut e);
        let _ = commun::ecrire(FICHIER, &e);
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
    // Hors délai : réponse du moment, pas de cache : la signature d'une alerte ne doit pas changer durablement (relecture de #104, D2)
    let Ok(lue) = crate::natif::signataire_a_echeance(chemin) else { return "non signé".into() };
    let e = match lue {
        Some(s) => s,
        None => match crate::natif::catalogue_a_echeance(chemin) {
            Ok(true) => "Windows (catalogue)".to_string(),
            Ok(false) => "non signé".into(),
            Err(_) => return "non signé".into(),
        },
    };
    let mut c = cache.lock().unwrap();
    if c.len() > 2000 {
        c.clear();
    }
    c.insert(cle, e.clone());
    e
}

/// Comportement d'une alerte (fonction pure : l'éditeur est fourni)
pub fn signature_avec(a: &Alerte, editeur: &str) -> String {
    // Nature du comportement (format 3, revue de l'auditeur du 2026-11-22, point 2) : l'identifiant de règle et le code de
    // comportement posé par le code qui produit l'alerte (outil vu, type d'entrée, indices d'une connexion, règle IDS…),
    // indépendants des techniques ATT&CK et des conseils : retoucher ces tables, ou changer de version d'ATT&CK, ne rend
    // plus aucune exception caduque. Sans code : le début des raisons, comme avant la couverture ATT&CK
    let debut_raisons = || a.raisons.split([':', '(', '[']).next().unwrap_or("").trim().chars().take(60).collect::<String>();
    let nature = if a.regle.is_empty() {
        debut_raisons()
    } else if !a.comportement.is_empty() {
        format!("{}#{}", a.regle, a.comportement)
    } else {
        format!("{}#{}", a.regle, debut_raisons())
    };
    // Le domaine plutôt que l'adresse ; sans domaine, l'adresse exacte (jamais « n'importe quelle IP »)
    let destination = a.nom_dns.clone().filter(|n| !n.is_empty()).unwrap_or_else(|| a.destination.clone());
    format!("{}|{}|{}|{}|{}", a.chemin.to_lowercase(), editeur.to_lowercase(), a.parent.to_lowercase(), destination.to_lowercase(), nature.to_lowercase())
}

pub fn signature(a: &Alerte) -> String {
    signature_avec(a, &editeur(&a.chemin))
}

#[cfg(test)]
pub fn editeur_pour_test(chemin: &str) -> String {
    editeur(chemin)
}

/// Signaux forts : jamais appris ni adoucis par l'apprentissage, même au niveau « Alerte »
pub fn signal_fort(a: &Alerte) -> bool {
    let r = a.raisons.to_lowercase();
    // Constats de santé (SAN-*, phase 4) : jamais appris, sinon une collecte muette pendant l'apprentissage ne serait
    // plus jamais signalée. Actions de réponse (REP-*, phase 6) : une relance ou une isolation invérifiable ne tombe
    // jamais en « Info » (audit de #121, S121-01)
    // DNS-002 (phase 7) : un serveur DNS changé n'est jamais appris, sinon un premier changement pendant l'apprentissage
    // ferait taire tous les suivants sur la carte (relecture de #159, constat 1)
    a.regle.starts_with("SAN-")
        || a.regle.starts_with("REP-")
        || a.regle == crate::regles::DNS_002
        || a.destination.starts_with("IDS :")
        || ["télécharge du code", "lolbin", "débogage à distance", "suppression des sauvegardes", "macro ou exploit", crate::persistance::REMARQUE_ANOMALIE_TACHES].iter().any(|m| r.contains(m))
}

/// Décision pure : (nouveau niveau, mention ajoutée, à mémoriser)
pub fn decider(niveau: &str, signature: &str, en_apprentissage: bool, appris: &BTreeSet<String>, exceptions: &[Exception]) -> Option<(&'static str, &'static str, bool)> {
    if niveau == "Critique" || niveau == "Info" {
        return None;
    }
    // Exceptions et comportements appris : par empreinte (format actuel) ou par signature en clair (anciens fichiers)
    let empreinte = commun::empreinte_signature(signature);
    if exceptions.iter().any(|e| e.signature == signature || e.signature == empreinte) {
        return Some(("Info", " [exception enregistrée]", false));
    }
    if appris.contains(signature) || appris.contains(&empreinte) {
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
        // Mémorisé par son empreinte : taille fixe, apprentissage.json borné (relecture de #72, R7)
        if memoriser && e.appris.len() < 5000 && e.appris.insert(commun::empreinte_signature(&sig)) {
            let _ = commun::ecrire(FICHIER, &*e);
        }
    }
}

/// Signature visée par une exception posée depuis une alerte enregistrée (décision pure, testée ; audit de sécurité de
/// #73) : son empreinte, si elle a la forme attendue (S73-02) ; sans empreinte, l'ancienne signature seulement si
/// l'alerte est de niveau « Alerte » et qu'aucun champ de la signature n'a été borné (S73-01 : sinon, la signature du
/// texte borné couvrirait un programme posé au chemin borné littéral, pas le programme légitime)
pub fn cible_exception(a: &Alerte) -> Result<String, &'static str> {
    if !a.signature.is_empty() {
        let hex = a.signature.strip_prefix("sha256:").unwrap_or("");
        return if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            Ok(a.signature.clone())
        } else {
            Err("empreinte de l'alerte illisible")
        };
    }
    if a.niveau == "Critique" || a.niveau == "Info" {
        return Err("une exception ne s'applique qu'à une alerte de niveau « Alerte »");
    }
    let borne = [&a.chemin, &a.parent, &a.destination].iter().any(|s| s.contains(" … "))
        || a.nom_dns.as_deref().is_some_and(|s| s.contains(" … "));
    if borne {
        return Err("alerte trop ancienne et tronquée : posez l'exception depuis une nouvelle alerte de ce comportement");
    }
    Ok(signature(a))
}

pub fn ajouter_exception(a: &Alerte) -> Result<String, String> {
    let sig = cible_exception(a).map_err(|r| format!("Exception refusée : {r}."))?;
    let mut e = etat().lock().unwrap();
    let description = format!("{} — {} — {}", a.processus, a.destination, a.raisons.chars().take(120).collect::<String>());
    if !e.exceptions.iter().any(|x| x.signature == sig) {
        e.exceptions.push(Exception { signature: sig, description: description.clone(), date: commun::maintenant() });
        let _ = commun::ecrire(FICHIER, &*e);
    }
    Ok(description)
}

/// « terminer », « recommencer » (7 jours, comportements appris oubliés), « oublier » (exceptions) ou
/// « oublier-perimees » (exceptions d'un format précédent seulement, prérelecture de #255, R1)
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
        "oublier-perimees" => {
            let n = e.exceptions_perimees.len();
            e.exceptions_perimees.clear();
            e.appris_perimes = 0;
            format!("{n} exception(s) d'une version précédente supprimée(s) ; les exceptions actuelles sont gardées.")
        }
        "oublier" => {
            let n = e.exceptions.len() + e.exceptions_perimees.len();
            e.exceptions.clear();
            e.exceptions_perimees.clear();
            e.appris_perimes = 0;
            format!("{n} exception(s) supprimée(s).")
        }
        _ => return Err("commande d'apprentissage inconnue".into()),
    };
    let _ = commun::ecrire(FICHIER, &*e);
    Ok(m)
}
