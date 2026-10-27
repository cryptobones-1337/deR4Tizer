//! Santé des collectes (phase 4, PR 4.4a) : historique des changements d'état des collectes dans le SIEM (source
//! « sante ») et constats SAN-001, SAN-002, SAN-003 et SAN-012. La décision (`Sante::observer`) est pure et testée ;
//! le fil « sante » du moniteur l'applique toutes les 30 s, hors du verrou du moniteur, qu'il ne prend que pour lire le
//! compteur des alertes non suivies.

use crate::collectes::{Collecte, EtatPublie};
use crate::commun::{self, Alerte};
use crate::regles;
use std::collections::{HashMap, VecDeque};

/// Collectes critiques pour SAN-001 (D4-5)
pub const CRITIQUES: [Collecte; 6] = [
    Collecte::JournalDefender, Collecte::EtatDefender, Collecte::JournalSecurite, Collecte::Connexions, Collecte::Processus,
    Collecte::ListesMenaces,
];
/// Indisponible depuis plus de 30 min : constat
pub const DELAI_S: i64 = 1800;
/// Un constat par collecte (ou par règle, pour SAN-003 et SAN-012) et par 24 h au plus
pub const RAPPEL_S: i64 = 86_400;
/// Plus de 6 changements en une heure : collecte « instable », une ligne par heure au plus dans le SIEM
pub const MAX_CHANGEMENTS_HEURE: usize = 6;
const HEURE_S: i64 = 3600;
/// Période du fil « sante »
pub const PERIODE_S: u64 = 30;

#[derive(Default)]
struct Suivi {
    etat: String,
    raison: String,
    indisponible_depuis: Option<i64>,
    changements: VecDeque<i64>,
    derniere_ligne_instable: Option<i64>,
    dernier_constat: Option<i64>,
    /// Début de la panne signalée (SAN-001 ou SAN-003), en attente de SAN-002
    signalee: Option<i64>,
}

/// Changement d'état d'une collecte, écrit dans le SIEM (`Source` « sante », `Type` « collecte »)
#[derive(Debug, PartialEq)]
pub struct Changement {
    pub collecte: &'static str,
    pub avant: String,
    pub apres: String,
    pub raison: String,
    /// Plus de 6 changements dans l'heure : cette ligne est la seule de l'heure
    pub instable: bool,
}

/// État de la décision, gardé par le fil « sante » (en mémoire : un redémarrage repart de zéro, et une panne déjà
/// signalée peut l'être une fois de plus)
#[derive(Default)]
pub struct Sante {
    suivis: HashMap<&'static str, Suivi>,
    san003: Option<i64>,
    san012: Option<i64>,
    non_suivies_signalees: u64,
}

/// `Inconnue` compte comme indisponible (échec fermé) ; `Desactivee` (par choix) jamais
fn indisponible(e: &EtatPublie) -> bool {
    matches!(e, EtatPublie::Indisponible(_) | EtatPublie::Inconnue)
}

fn constat(regle: &str, niveau: &str, destination: &str, raisons: String) -> Alerte {
    Alerte {
        regle: regle.into(),
        id: commun::nouvel_id(),
        heure: commun::maintenant(),
        niveau: niveau.into(),
        score: match niveau { "Critique" => 10, "Alerte" => 5, _ => 0 },
        processus: "deR4Tizer (santé)".into(),
        destination: destination.into(),
        raisons,
        ..Default::default()
    }
}

fn minutes(s: i64) -> i64 {
    s.max(0) / 60
}

impl Sante {
    /// Décision pure (testée) : à partir de l'état publié de chaque collecte (`etats`), du nombre d'alertes non suivies
    /// depuis le démarrage (`non_suivies`) et de l'heure `t` (secondes), les changements à écrire dans le SIEM et les
    /// constats à lever
    pub fn observer(&mut self, etats: &[(Collecte, EtatPublie)], non_suivies: u64, t: i64) -> (Vec<Changement>, Vec<Alerte>) {
        let mut changements = Vec::new();
        let mut constats = Vec::new();
        // 1. Historique : écrit au changement seulement ; le passage d'« Inconnue » à « Active » (démarrage) est tu
        for (c, e) in etats {
            let s = self.suivis.entry(c.id()).or_default();
            let nom = e.nom();
            if s.etat != nom {
                let avant = std::mem::replace(&mut s.etat, nom.to_string());
                if !avant.is_empty() && !(avant == "Inconnue" && nom == "Active") {
                    s.changements.push_back(t);
                    while s.changements.front().is_some_and(|x| t - x >= HEURE_S) {
                        s.changements.pop_front();
                    }
                    let instable = s.changements.len() > MAX_CHANGEMENTS_HEURE;
                    if !instable || s.derniere_ligne_instable.is_none_or(|d| t - d >= HEURE_S) {
                        if instable {
                            s.derniere_ligne_instable = Some(t);
                        }
                        changements.push(Changement { collecte: c.id(), avant, apres: nom.to_string(), raison: e.raison().to_string(), instable });
                    }
                }
            }
            s.raison = e.raison().to_string();
            s.indisponible_depuis = if indisponible(e) { Some(s.indisponible_depuis.unwrap_or(t)) } else { None };
        }
        // 2. SAN-003 : Defender aveugle (journal et état) plus de 30 min ; remplace SAN-001 pour ces deux collectes
        let depuis = |s: &HashMap<&'static str, Suivi>, c: Collecte| s.get(c.id()).and_then(|x| x.indisponible_depuis);
        let aveugle = match (depuis(&self.suivis, Collecte::JournalDefender), depuis(&self.suivis, Collecte::EtatDefender)) {
            (Some(a), Some(b)) => Some(a.max(b)).filter(|d| t - d >= DELAI_S),
            _ => None,
        };
        if let Some(d) = aveugle {
            if self.san003.is_none_or(|x| t - x >= RAPPEL_S) {
                self.san003 = Some(t);
                constats.push(constat(regles::SAN_003, "Critique", "Microsoft Defender",
                    format!("journal et état de Defender illisibles depuis {} min : ni ses détections ni ses réglages ne sont plus vus", minutes(t - d))));
                for c in [Collecte::JournalDefender, Collecte::EtatDefender] {
                    if let Some(s) = self.suivis.get_mut(c.id()) {
                        s.signalee = s.signalee.or(s.indisponible_depuis);
                    }
                }
            }
        }
        // 3. SAN-001 (indisponible plus de 30 min) et SAN-002 (rétablie après un constat)
        for c in CRITIQUES {
            let Some(s) = self.suivis.get_mut(c.id()) else { continue };
            let defender = matches!(c, Collecte::JournalDefender | Collecte::EtatDefender);
            if let Some(d) = s.indisponible_depuis {
                if t - d >= DELAI_S && !(defender && aveugle.is_some()) && s.dernier_constat.is_none_or(|x| t - x >= RAPPEL_S) {
                    s.dernier_constat = Some(t);
                    s.signalee = s.signalee.or(Some(d));
                    let raison = if s.raison.is_empty() { String::new() } else { format!(" ({})", s.raison) };
                    constats.push(constat(regles::SAN_001, "Alerte", c.id(),
                        format!("collecte {} {} depuis {} min{raison} : les règles qui en dépendent se taisent", c.id(),
                            if s.etat == "Inconnue" { "jamais lue" } else { "indisponible" }, minutes(t - d))));
                }
            } else if s.etat == "Active" {
                if let Some(d) = s.signalee.take() {
                    constats.push(constat(regles::SAN_002, "Info", c.id(), format!("collecte {} rétablie après {} min", c.id(), minutes(t - d))));
                }
            }
        }
        // 4. SAN-012 : alertes non suivies faute de place (500 incidents non clos), une fois par 24 h
        if non_suivies > self.non_suivies_signalees && self.san012.is_none_or(|x| t - x >= RAPPEL_S) {
            self.san012 = Some(t);
            self.non_suivies_signalees = non_suivies;
            constats.push(constat(regles::SAN_012, "Critique", "suivi des incidents",
                format!("{non_suivies} alerte(s) non suivie(s) depuis le démarrage : 500 incidents non clos ; elles restent dans la liste des alertes")));
        }
        (changements, constats)
    }
}

/// Événement du SIEM d'un changement d'état de collecte (pur, testé)
pub fn evenement(c: &Changement) -> crate::siem::Evenement {
    let raison = if c.raison.is_empty() { String::new() } else { format!(" ({})", c.raison) };
    let instable = if c.instable { " ; collecte instable : plus de 6 changements dans l'heure, une ligne par heure" } else { "" };
    crate::siem::Evenement {
        heure: commun::maintenant(),
        source: "sante".into(),
        type_: "collecte".into(),
        niveau: if c.apres == "Indisponible" { "Alerte" } else { "Info" }.into(),
        destination: c.collecte.into(),
        message: crate::siem::texte_sur(&format!("collecte {} : {} → {}{raison}{instable}", c.collecte, c.avant, c.apres), 400),
        ..Default::default()
    }
}

/// Secondes depuis l'époque Unix
pub fn secondes() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}
