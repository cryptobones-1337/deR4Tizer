//! Phase 4 : suivi des incidents (cycle de vie). Chaque alerte de niveau « Alerte » ou « Critique » ouvre un incident ou
//! rejoint l'incident non clos de la même entité ; l'état (Ouvert, PrisEnCharge, Clos avec un motif) ne change que par
//! la commande `incident` d'un administrateur, et chaque changement est historisé (`docs/roadmap/phase4.md`, D4-2, D4-3,
//! D4-10). Décisions pures, testées ; le moniteur seul écrit `suivi-incidents.json`, sous son verrou.

use crate::commun::{self, Alerte};
use serde::{Deserialize, Serialize};

/// Incidents suivis au plus ; au-delà, les plus anciens clos partent les premiers, un incident non clos jamais
pub const MAX_INCIDENTS: usize = 500;
/// Résumés d'alertes gardés par incident : les premiers et les derniers
const RESUMES_DEBUT: usize = 5;
const RESUMES_FIN: usize = 5;
// Bornes choisies pour que 500 incidents au pire (caractères de 4 octets partout) tiennent sous TAILLE_MAX_SUIVI
// (audit de #95, S95-01 ; test incident_suivi_plein_pire_cas)
const MAX_REGLES: usize = 16;
const MAX_TRANSITIONS: usize = 20;
pub const MAX_NOTE: usize = 300;
const MAX_RAISONS_RESUME: usize = 200;
const MAX_CHEMIN_RESUME: usize = 260;
const MAX_PROCESSUS_RESUME: usize = 64;
const MAX_DESTINATION_RESUME: usize = 128;
const MAX_ENTITE: usize = 280;
/// Une alerte rejoint l'incident non clos de son entité si sa dernière activité date de moins de 24 h
const FENETRE_RATTACHEMENT_S: i64 = 24 * 3600;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum EtatIncident {
    #[default]
    Ouvert,
    PrisEnCharge,
    Clos,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq)]
#[serde(rename_all = "PascalCase", default)]
pub struct ResumeAlerte {
    pub id: String,
    pub heure: String,
    pub heure_utc: String,
    pub niveau: String,
    pub regle: String,
    pub processus: String,
    pub chemin: String,
    pub destination: String,
    pub raisons: String,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq)]
#[serde(rename_all = "PascalCase", default)]
pub struct Transition {
    pub heure: String,
    pub heure_utc: String,
    pub de: EtatIncident,
    pub vers: EtatIncident,
    pub motif: String,
    /// SID de l'administrateur, lu sur le jeton du client du tube
    pub auteur: String,
    pub note: String,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq)]
#[serde(rename_all = "PascalCase", default)]
pub struct IncidentSuivi {
    pub modele: u32,
    pub id: String,
    pub ouverture: String,
    pub ouverture_utc: String,
    pub derniere_activite_utc: String,
    /// Le plus haut des alertes jointes ; ne baisse jamais
    pub niveau: String,
    pub entite: String,
    pub regles: Vec<String>,
    pub etat: EtatIncident,
    /// Resolu, FauxPositif ou Accepte pour un incident clos ; vide sinon
    pub motif_cloture: String,
    /// Incident clos de la même entité, s'il y en a un (récidive)
    pub precedent: String,
    pub alertes: Vec<ResumeAlerte>,
    pub nombre_alertes: u32,
    pub transitions: Vec<Transition>,
}

/// Entité d'une alerte (pure, testée) : chemin complet du programme s'il est connu ; sinon la destination ; sinon la
/// règle. Jamais un nom de programme seul : deux programmes de même nom à des chemins différents font deux entités
pub fn entite(a: &Alerte) -> String {
    let chemin = a.chemin.trim();
    // Entité nommée par le producteur (corrélations du SIEM, PR 4.3) : prioritaire
    let e = if !a.entite.trim().is_empty() {
        a.entite.trim().to_lowercase()
    } else if !chemin.is_empty() && chemin != "?" {
        format!("programme:{}", chemin.to_lowercase())
    } else {
        let dest = a.destination.trim();
        if !dest.is_empty() && dest != "?" { format!("destination:{}", dest.to_lowercase()) } else { format!("regle:{}", a.regle) }
    };
    // Bornée et nettoyée dès la création, comme à la relecture : l'entité d'une alerte et celle d'un incident relu sont
    // identiques (audit de #95, S95-02). Trop longue : le début, puis l'empreinte du texte entier, pour que deux chemins
    // qui ne diffèrent qu'à la fin restent deux entités (audit de #95, S95-05)
    let e = crate::siem::texte_sur(&e, usize::MAX);
    if e.chars().count() <= MAX_ENTITE {
        return e;
    }
    let empreinte = commun::empreinte_signature(&e);
    format!("{}…{}", e.chars().take(MAX_ENTITE - 82).collect::<String>(), &empreinte[..80.min(empreinte.len())])
}

fn rang(niveau: &str) -> u8 {
    match niveau {
        "Critique" => 2,
        "Alerte" => 1,
        _ => 0,
    }
}

fn resume(a: &Alerte) -> ResumeAlerte {
    let mut r = ResumeAlerte {
        id: a.id.clone(),
        heure: a.heure.clone(),
        heure_utc: a.heure_utc.clone(),
        niveau: a.niveau.clone(),
        regle: a.regle.clone(),
        processus: a.processus.clone(),
        chemin: a.chemin.clone(),
        destination: a.destination.clone(),
        raisons: a.raisons.clone(),
    };
    // Mêmes bornes et même nettoyage qu'à la relecture (S95-02 : un nom de fichier avec un caractère de sens d'écriture
    // ne s'affiche pas trompeusement)
    borner_resume(&mut r);
    r
}

fn borner_resume(a: &mut ResumeAlerte) {
    for (s, max) in [(&mut a.id, 64), (&mut a.heure, 32), (&mut a.heure_utc, 32), (&mut a.niveau, 16), (&mut a.regle, 64),
                     (&mut a.processus, MAX_PROCESSUS_RESUME), (&mut a.chemin, MAX_CHEMIN_RESUME), (&mut a.destination, MAX_DESTINATION_RESUME),
                     (&mut a.raisons, MAX_RAISONS_RESUME)] {
        borne(s, max);
    }
}

/// Ce que devient une alerte (pure, testée)
#[derive(Debug, PartialEq)]
pub enum Rattachement {
    /// Alerte « Info » : aucun incident
    Rien,
    /// Rejoint l'incident non clos de cet indice
    Rejoint(usize),
    /// Ouvre un nouvel incident ; `precedent` : incident clos de la même entité
    Nouveau { precedent: String },
}

pub fn rattacher(suivis: &[IncidentSuivi], a: &Alerte, maintenant_utc: i64) -> Rattachement {
    if rang(&a.niveau) == 0 {
        return Rattachement::Rien;
    }
    let e = entite(a);
    let ouvert = suivis.iter().position(|i| {
        i.entite == e && i.etat != EtatIncident::Clos
            && commun::secondes_utc(&i.derniere_activite_utc).is_some_and(|t| maintenant_utc - t < FENETRE_RATTACHEMENT_S)
    });
    match ouvert {
        Some(n) => Rattachement::Rejoint(n),
        None => Rattachement::Nouveau {
            precedent: suivis.iter().rev().find(|i| i.entite == e && i.etat == EtatIncident::Clos).map(|i| i.id.clone()).unwrap_or_default(),
        },
    }
}

/// Effet d'une alerte sur le suivi
#[derive(Debug, PartialEq)]
pub enum Effet {
    /// Alerte « Info » : rien
    Rien,
    /// Incident ouvert ou complété
    Suivi,
    /// Plafond atteint, uniquement des incidents non clos : l'alerte n'est pas suivie (elle reste dans alertes.json)
    NonSuivi,
}

/// Applique une alerte au suivi (pure, testée), plafond tenu
pub fn appliquer(suivis: &mut Vec<IncidentSuivi>, a: &Alerte, maintenant_utc: i64) -> Effet {
    match rattacher(suivis, a, maintenant_utc) {
        Rattachement::Rien => Effet::Rien,
        Rattachement::Rejoint(n) => {
            let i = &mut suivis[n];
            if rang(&a.niveau) > rang(&i.niveau) {
                i.niveau = a.niveau.clone();
            }
            if !a.regle.is_empty() && !i.regles.contains(&a.regle) && i.regles.len() < MAX_REGLES {
                i.regles.push(a.regle.clone());
            }
            i.derniere_activite_utc = a.heure_utc.clone();
            i.nombre_alertes += 1;
            if i.alertes.len() >= RESUMES_DEBUT + RESUMES_FIN {
                i.alertes.remove(RESUMES_DEBUT);
            }
            i.alertes.push(resume(a));
            Effet::Suivi
        }
        Rattachement::Nouveau { precedent } => {
            // Plafond : un clos part d'abord ; s'il n'y a que des incidents non clos, celui-ci n'est pas suivi (compté par
            // l'appelant, SAN-012) ; l'alerte reste dans alertes.json
            purger(suivis);
            if suivis.len() >= MAX_INCIDENTS {
                if let Some(n) = suivis.iter().position(|i| i.etat == EtatIncident::Clos) {
                    suivis.remove(n);
                } else {
                    return Effet::NonSuivi;
                }
            }
            suivis.push(IncidentSuivi {
                modele: commun::MODELE_ALERTE,
                id: commun::nouvel_id(),
                ouverture: a.heure.clone(),
                ouverture_utc: a.heure_utc.clone(),
                derniere_activite_utc: a.heure_utc.clone(),
                niveau: a.niveau.clone(),
                entite: entite(a),
                regles: if a.regle.is_empty() { Vec::new() } else { vec![a.regle.clone()] },
                etat: EtatIncident::Ouvert,
                precedent,
                alertes: vec![resume(a)],
                nombre_alertes: 1,
                ..Default::default()
            });
            Effet::Suivi
        }
    }
}

/// Transitions permises : Ouvert vers PrisEnCharge ou Clos ; PrisEnCharge vers Clos ; Clos vers Ouvert (réouverture
/// explicite). Clore demande un motif connu ; la note est bornée et sans caractère de contrôle ni de mise en forme. Rien
/// n'est changé en cas de refus (pure, testée)
pub fn transition(i: &mut IncidentSuivi, vers: EtatIncident, motif: &str, note: &str, auteur: &str, heure: &str, heure_utc: &str) -> Result<(), String> {
    use EtatIncident::*;
    let permise = matches!((i.etat, vers), (Ouvert, PrisEnCharge) | (Ouvert, Clos) | (PrisEnCharge, Clos) | (Clos, Ouvert));
    if !permise {
        return Err(format!("transition refusée : {:?} vers {:?}", i.etat, vers));
    }
    if vers == Clos && !matches!(motif, "Resolu" | "FauxPositif" | "Accepte") {
        return Err("motif de clôture attendu : Resolu, FauxPositif ou Accepte".into());
    }
    if vers != Clos && !motif.is_empty() {
        return Err("motif seulement pour une clôture".into());
    }
    // Échec fermé pour l'historique : pas de transition sans auteur connu (audit de #95, S95-03)
    if auteur.is_empty() {
        return Err("auteur inconnu (jeton du client illisible)".into());
    }
    if note.chars().count() > MAX_NOTE || note.chars().any(|c| c.is_control() || crate::siem::mise_en_forme(c)) {
        return Err(format!("note refusée : {MAX_NOTE} caractères au plus, sans caractère de contrôle ni de mise en forme"));
    }
    if i.transitions.len() >= MAX_TRANSITIONS {
        i.transitions.remove(0);
    }
    i.transitions.push(Transition { heure: heure.into(), heure_utc: heure_utc.into(), de: i.etat, vers, motif: motif.into(), auteur: auteur.into(), note: note.into() });
    i.etat = vers;
    i.motif_cloture = if vers == Clos { motif.into() } else { String::new() };
    Ok(())
}

/// Tient le plafond : retire les plus anciens incidents clos ; un incident non clos n'est jamais retiré. Rend le nombre
/// d'incidents non clos au-delà du plafond (constat SAN-012) (pure, testée)
pub fn purger(suivis: &mut Vec<IncidentSuivi>) -> usize {
    while suivis.len() > MAX_INCIDENTS {
        match suivis.iter().position(|i| i.etat == EtatIncident::Clos) {
            Some(n) => {
                suivis.remove(n);
            }
            None => break,
        }
    }
    suivis.len().saturating_sub(MAX_INCIDENTS)
}

fn borne(s: &mut String, max: usize) {
    if s.chars().count() > max || s.chars().any(|c| c.is_control() || crate::siem::mise_en_forme(c)) {
        *s = crate::siem::texte_sur(s, max);
    }
}

/// Bornes d'un incident relu (fichier altéré : il faut être administrateur) : listes et textes ramenés à leurs maxima
pub fn borner_incident(i: &mut IncidentSuivi) {
    for (s, max) in [(&mut i.id, 64), (&mut i.ouverture, 32), (&mut i.ouverture_utc, 32), (&mut i.derniere_activite_utc, 32),
                     (&mut i.niveau, 16), (&mut i.entite, MAX_ENTITE), (&mut i.motif_cloture, 16), (&mut i.precedent, 64)] {
        borne(s, max);
    }
    i.regles.truncate(MAX_REGLES);
    for r in &mut i.regles {
        borne(r, 64);
    }
    if i.alertes.len() > RESUMES_DEBUT + RESUMES_FIN {
        let fin = i.alertes.split_off(i.alertes.len() - RESUMES_FIN);
        i.alertes.truncate(RESUMES_DEBUT);
        i.alertes.extend(fin);
    }
    for a in &mut i.alertes {
        borner_resume(a);
    }
    if i.transitions.len() > MAX_TRANSITIONS {
        i.transitions.drain(..i.transitions.len() - MAX_TRANSITIONS);
    }
    for t in &mut i.transitions {
        for (s, max) in [(&mut t.heure, 32), (&mut t.heure_utc, 32), (&mut t.motif, 16), (&mut t.auteur, 80), (&mut t.note, MAX_NOTE)] {
            borne(s, max);
        }
    }
}

/// Lecture tolérante du suivi (pure, testée), comme alertes.json : un élément illisible est écarté et compté, les
/// autres sont gardés et bornés. None si le texte n'est pas un tableau JSON
pub fn lire_suivi_texte(texte: &str) -> Option<(Vec<IncidentSuivi>, usize)> {
    let serde_json::Value::Array(elements) = serde_json::from_str::<serde_json::Value>(texte.trim_start_matches('\u{feff}')).ok()? else { return None };
    let mut ecartes = 0;
    let mut suivis = Vec::with_capacity(elements.len());
    for e in elements {
        match serde_json::from_value::<IncidentSuivi>(e) {
            Ok(mut i) => {
                borner_incident(&mut i);
                suivis.push(i);
            }
            Err(_) => ecartes += 1,
        }
    }
    Some((suivis, ecartes))
}

pub const FICHIER_SUIVI: &str = "suivi-incidents.json";
/// Au-delà, le fichier n'est pas lu : il est mis de côté. 500 incidents au pire, toutes bornes atteintes en caractères de
/// 4 octets, tiennent en dessous (test incident_suivi_plein_pire_cas)
pub const TAILLE_MAX_SUIVI: u64 = 64 * 1024 * 1024;

/// Ce que le service fait de `suivi-incidents.json` au démarrage (décision pure, testée)
#[derive(Debug, PartialEq)]
pub enum DecisionSuivi {
    /// Fichier absent : suivi vide, écriture permise
    Vide,
    /// Lu entièrement : écriture permise
    Lire(Vec<IncidentSuivi>),
    /// Lu en partie (éléments écartés, comptés) : copie mise de côté avant d'autoriser la réécriture (relecture de #95,
    /// D1), sinon les éléments écartés seraient perdus à la première écriture
    LirePartiel(Vec<IncidentSuivi>, usize),
    /// Trop grand (audit de #95, S95-01) : mis de côté, suivi repris à vide
    TropGrand,
    /// Illisible (droits, pas un tableau JSON) : vide, jamais réécrit, commande `incident` refusée
    Illisible,
}

pub fn decision_suivi(present: bool, taille: u64, texte: Option<&str>) -> DecisionSuivi {
    if !present {
        return DecisionSuivi::Vide;
    }
    if taille > TAILLE_MAX_SUIVI {
        return DecisionSuivi::TropGrand;
    }
    match texte.and_then(lire_suivi_texte) {
        Some((s, 0)) => DecisionSuivi::Lire(s),
        Some((s, n)) => DecisionSuivi::LirePartiel(s, n),
        None => DecisionSuivi::Illisible,
    }
}

/// Copie (ou déplacement) du suivi de côté, dans le dossier de données, sous un nom neuf
/// (`suivi-incidents-<raison>-<horodatage>[-<n>].json`) ; la copie crée sa destination neuve (`create_new`), jamais un
/// fichier ou un lien posé à ce nom (audit de #95, S95-04, comme pour alertes.json)
fn mettre_de_cote(f: &std::path::Path, raison: &str, copier: bool) -> bool {
    if !commun::lecture_fichier_autorisee(f) {
        return false;
    }
    let horodatage = commun::filetime(std::time::SystemTime::now());
    let Some(cote) = (0..100)
        .map(|n| f.with_file_name(if n == 0 { format!("suivi-incidents-{raison}-{horodatage}.json") } else { format!("suivi-incidents-{raison}-{horodatage}-{n}.json") }))
        .find(|d| std::fs::symlink_metadata(d).is_err()) else { return false };
    if copier {
        std::fs::OpenOptions::new().write(true).create_new(true).open(&cote)
            .and_then(|mut d| std::fs::File::open(f).and_then(|mut s| std::io::copy(&mut s, &mut d)).map(|_| ()))
            .is_ok()
    } else {
        std::fs::rename(f, &cote).is_ok()
    }
}

/// Suivi au démarrage : (incidents, écriture permise), d'après `decision_suivi`. Une mise de côté qui échoue retient la
/// réécriture (l'historique n'est jamais écrasé)
pub fn lire_suivi() -> (Vec<IncidentSuivi>, bool) {
    let f = commun::dossier().join(FICHIER_SUIVI);
    let m = std::fs::symlink_metadata(&f).ok();
    let taille = m.as_ref().map(|m| m.len()).unwrap_or(0);
    let texte = if m.is_some() && taille <= TAILLE_MAX_SUIVI { commun::lire_fichier(&f) } else { None };
    match decision_suivi(m.is_some(), taille, texte.as_deref()) {
        DecisionSuivi::Vide => (Vec::new(), true),
        DecisionSuivi::Lire(s) => (s, true),
        DecisionSuivi::LirePartiel(s, n) => {
            let ok = mettre_de_cote(&f, "partiel", true);
            commun::journal(&format!("suivi des incidents : {n} élément(s) illisible(s) écarté(s) ; {}",
                if ok { "copie d'origine mise de côté" } else { "copie impossible, suivi non réécrit" }));
            (s, ok)
        }
        DecisionSuivi::TropGrand => {
            let ok = mettre_de_cote(&f, "trop-grand", false);
            commun::journal(&format!("suivi des incidents de {taille} octets, au-delà de la limite : {}",
                if ok { "mis de côté, suivi repris à vide" } else { "mise de côté impossible, non réécrit" }));
            (Vec::new(), ok)
        }
        DecisionSuivi::Illisible => {
            commun::journal("suivi des incidents illisible (droits ou format) : non réécrit, transitions refusées jusqu'à une intervention");
            (Vec::new(), false)
        }
    }
}

/// États nommés de la commande `incident` (champ Valeur)
pub fn etat_de(nom: &str) -> Option<EtatIncident> {
    match nom {
        "Ouvert" => Some(EtatIncident::Ouvert),
        "PrisEnCharge" => Some(EtatIncident::PrisEnCharge),
        "Clos" => Some(EtatIncident::Clos),
        _ => None,
    }
}

// ------------------------------------------------------------ chronologie (phase 4, PR 4.3)

/// Élément d'une chronologie : alerte jointe, événement du SIEM (dont les actions de réponse et la santé) ou transition
#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq)]
#[serde(rename_all = "PascalCase", default)]
pub struct ElementChronologie {
    pub heure: String,
    pub heure_utc: String,
    pub seq: u64,
    /// alerte, transition, ou la source de l'événement du SIEM (reponse, sante, securite, systeme, connexion…)
    pub source: String,
    #[serde(rename = "Type")]
    pub type_: String,
    pub niveau: String,
    pub texte: String,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq)]
#[serde(rename_all = "PascalCase", default)]
pub struct Chronologie {
    pub modele: u32,
    pub incident: String,
    pub entite: String,
    pub calculee_utc: String,
    /// Fenêtre des événements du SIEM : de 30 min avant l'ouverture à 30 min après la dernière activité
    pub depuis_utc: String,
    pub jusqua_utc: String,
    pub elements: Vec<ElementChronologie>,
    /// Plus de MAX_ELEMENTS : les premiers et les derniers sont gardés
    pub tronquee: bool,
    /// Événements du SIEM sans heure UTC (antérieurs à la phase 4) : non placés, comptés
    pub sans_heure_utc: usize,
    /// Événements perdus par le SIEM (file pleine) depuis le démarrage du service : des étapes peuvent manquer
    pub pertes_siem: u64,
}

pub const MAX_ELEMENTS: usize = 2000;
const MARGE_FENETRE_S: i64 = 1800;
const MAX_TEXTE_ELEMENT: usize = 400;

/// Un événement du SIEM concerne-t-il cet incident (pur, testé) ? Selon l'entité : programme (nom du fichier, ou chemin
/// complet cité), destination (destination, adresse ou texte), source d'une corrélation (adresse ou compte), compte, ou
/// règle. La santé des collectes concerne tous les incidents de la fenêtre (trous de collecte)
pub fn concerne(i: &IncidentSuivi, e: &crate::siem::Evenement) -> bool {
    if e.source == "sante" {
        return true;
    }
    let message = e.message.to_lowercase();
    if let Some(chemin) = i.entite.strip_prefix("programme:") {
        let nom = std::path::Path::new(chemin).file_stem().map(|s| s.to_string_lossy().to_lowercase()).unwrap_or_default();
        let proc_ = e.processus.to_lowercase();
        let proc_ = proc_.strip_suffix(".exe").unwrap_or(&proc_);
        return (!nom.is_empty() && proc_ == nom) || message.contains(chemin) || e.destination.to_lowercase() == chemin;
    }
    if let Some(d) = i.entite.strip_prefix("destination:") {
        return e.destination.to_lowercase() == d || e.ip.to_lowercase() == d || (d.len() >= 4 && message.contains(d));
    }
    if let Some(s) = i.entite.strip_prefix("source:") {
        return match s.strip_prefix("compte ") {
            Some(compte) => e.utilisateur.to_lowercase() == compte || e.utilisateur.to_lowercase().ends_with(&format!("\\{compte}")),
            None => !s.is_empty() && e.ip.to_lowercase() == s,
        };
    }
    if let Some(c) = i.entite.strip_prefix("compte:") {
        return !c.is_empty() && (e.utilisateur.to_lowercase().contains(c) || e.processus.to_lowercase().contains(c));
    }
    if let Some(r) = i.entite.strip_prefix("regle:") {
        return !r.is_empty() && e.regle.eq_ignore_ascii_case(r);
    }
    false
}

/// Chronologie d'un incident (pure, testée) : résumés des alertes jointes, transitions, et événements du SIEM de l'entité
/// dans la fenêtre, ordonnés par (heure UTC, numéro d'ordre) ; les alertes du SIEM (`Source` « alerte ») sont écartées,
/// déjà présentes par les résumés
pub fn construire(i: &IncidentSuivi, evenements: &[crate::siem::Evenement], pertes_siem: u64, calculee_utc: &str) -> Chronologie {
    let debut = commun::secondes_utc(&i.ouverture_utc).map(|t| t - MARGE_FENETRE_S);
    let fin = commun::secondes_utc(&i.derniere_activite_utc).map(|t| t + MARGE_FENETRE_S);
    let mut elements: Vec<(i64, ElementChronologie)> = Vec::new();
    let texte = |s: &str| crate::siem::texte_sur(s, MAX_TEXTE_ELEMENT);
    for a in &i.alertes {
        elements.push((commun::secondes_utc(&a.heure_utc).unwrap_or(i64::MIN), ElementChronologie {
            heure: a.heure.clone(), heure_utc: a.heure_utc.clone(), seq: 0, source: "alerte".into(), type_: a.regle.clone(),
            niveau: a.niveau.clone(), texte: texte(&format!("{} : {}", if a.processus.is_empty() { &a.destination } else { &a.processus }, a.raisons)),
        }));
    }
    for tr in &i.transitions {
        elements.push((commun::secondes_utc(&tr.heure_utc).unwrap_or(i64::MIN), ElementChronologie {
            heure: tr.heure.clone(), heure_utc: tr.heure_utc.clone(), seq: 0, source: "transition".into(), type_: format!("{:?}", tr.vers),
            niveau: "Info".into(),
            texte: texte(&format!("{:?} vers {:?}{}{} (par {})", tr.de, tr.vers, if tr.motif.is_empty() { String::new() } else { format!(", {}", tr.motif) },
                if tr.note.is_empty() { String::new() } else { format!(" : {}", tr.note) }, tr.auteur)),
        }));
    }
    let mut sans_heure_utc = 0;
    for e in evenements.iter().filter(|e| e.source != "alerte" && concerne(i, e)) {
        let Some(t) = commun::secondes_utc(&e.heure_utc) else {
            sans_heure_utc += 1;
            continue;
        };
        if debut.is_some_and(|d| t < d) || fin.is_some_and(|f| t > f) {
            continue;
        }
        elements.push((t, ElementChronologie {
            heure: e.heure.clone(), heure_utc: e.heure_utc.clone(), seq: e.seq, source: e.source.clone(), type_: e.type_.clone(),
            niveau: e.niveau.clone(), texte: texte(&e.message),
        }));
    }
    elements.sort_by(|a, b| (a.0, a.1.seq).cmp(&(b.0, b.1.seq)));
    let mut elements: Vec<ElementChronologie> = elements.into_iter().map(|(_, e)| e).collect();
    let tronquee = elements.len() > MAX_ELEMENTS;
    if tronquee {
        let fin = elements.split_off(elements.len() - MAX_ELEMENTS / 2);
        elements.truncate(MAX_ELEMENTS / 2);
        elements.extend(fin);
    }
    Chronologie {
        modele: commun::MODELE_ALERTE,
        incident: i.id.clone(),
        entite: i.entite.clone(),
        calculee_utc: calculee_utc.into(),
        depuis_utc: debut.map(|d| commun::heure_utc_de(std::time::UNIX_EPOCH + std::time::Duration::from_secs(d.max(0) as u64))).unwrap_or_default(),
        jusqua_utc: fin.map(|f| commun::heure_utc_de(std::time::UNIX_EPOCH + std::time::Duration::from_secs(f.max(0) as u64))).unwrap_or_default(),
        elements,
        tronquee,
        sans_heure_utc,
        pertes_siem,
    }
}

/// Repère d'un incident pour savoir si sa chronologie est à recalculer : sa dernière activité et ses transitions
pub fn repere(i: &IncidentSuivi) -> String {
    format!("{}|{}|{}", i.derniere_activite_utc, i.transitions.len(), i.nombre_alertes)
}

/// Incidents dont la chronologie est à (re)calculer (pure, testée) : repère changé depuis le dernier calcul ; `max` au
/// plus par tour, les plus récents d'abord
pub fn a_recalculer(suivis: &[IncidentSuivi], calcules: &std::collections::HashMap<String, String>, max: usize) -> Vec<IncidentSuivi> {
    suivis.iter().rev().filter(|i| calcules.get(&i.id) != Some(&repere(i))).take(max).cloned().collect()
}

/// Dossier des chronologies, dans le dossier de données (mêmes droits)
pub const DOSSIER_CHRONOLOGIES: &str = "chronologies";

/// Un tour du calcul des chronologies, HORS du verrou du moniteur : `a_faire` (copie des incidents à recalculer, 50 au
/// plus, prise sous le verrou par `a_recalculer`) et `suivis_ids` (identifiants suivis). Les événements du SIEM sont lus
/// sur les 3 derniers jours de fichiers au plus (20 000 au plus) ; les fichiers des incidents qui ne sont plus suivis
/// sont effacés
pub fn calculer_chronologies(a_faire: &[IncidentSuivi], suivis_ids: &std::collections::HashSet<String>,
                             calcules: &mut std::collections::HashMap<String, String>) {
    let dossier = commun::dossier().join(DOSSIER_CHRONOLOGIES);
    if !a_faire.is_empty() {
        let _ = std::fs::create_dir_all(&dossier);
        let maintenant = std::time::SystemTime::now();
        let depuis = commun::heure(maintenant - std::time::Duration::from_secs(2 * 86_400)).chars().take(10).collect::<String>();
        let evenements = crate::siem::rechercher(&crate::siem::Filtre { depuis, limite: 20_000, ..Default::default() });
        let pertes = crate::siem::pertes();
        let calculee = commun::heure_utc_de(maintenant);
        for i in a_faire {
            let c = construire(i, &evenements, pertes, &calculee);
            if commun::ecrire(&format!("{DOSSIER_CHRONOLOGIES}\\{}.json", i.id), &c).is_ok() {
                calcules.insert(i.id.clone(), repere(i));
            }
        }
    }
    // Ménage : chronologies d'incidents purgés
    calcules.retain(|id, _| suivis_ids.contains(id));
    for f in std::fs::read_dir(&dossier).into_iter().flatten().flatten() {
        let nom = f.file_name().to_string_lossy().to_string();
        if let Some(id) = nom.strip_suffix(".json") {
            if !suivis_ids.contains(id) && f.file_type().is_ok_and(|t| t.is_file()) {
                let _ = std::fs::remove_file(f.path());
            }
        }
    }
}
