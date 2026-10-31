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

/// Une collecte relue moins souvent que toutes les 15 min (moitié du délai) rattrape son silence après une veille en
/// temps d'éveil, jusqu'à une période (listes de menaces : 1 h) : pour SAN-001, seule compte alors l'indisponibilité
/// notée par la source elle-même, pas son seul silence (relecture de #98, D1 : fausse SAN-001 après chaque nuit)
pub fn silence_compte(c: Collecte) -> bool {
    (c.periode() as i64) <= DELAI_S / 2
}

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
    san004: Option<i64>,
}

/// Remontée en échec depuis plus d'une heure : constat SAN-004
pub const DELAI_REMONTEE_S: i64 = 3600;

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
    pub fn observer(&mut self, etats: &[(Collecte, EtatPublie, bool)], non_suivies: u64, t: i64) -> (Vec<Changement>, Vec<Alerte>) {
        let mut changements = Vec::new();
        let mut constats = Vec::new();
        // 1. Historique : écrit au changement seulement ; le passage d'« Inconnue » à « Active » (démarrage) est tu
        for (c, e, muette) in etats {
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
            let compte = indisponible(e) && !(*muette && !silence_compte(*c));
            s.indisponible_depuis = if compte { Some(s.indisponible_depuis.unwrap_or(t)) } else { None };
            // Audit de #98, S98-01 : le rappel de 24 h vaut pour un épisode ; rétablie, la collecte peut de nouveau être
            // signalée (sinon une panne d'essai rendrait la vraie panne muette pendant 24 h)
            if !indisponible(e) {
                s.dernier_constat = None;
            }
        }
        // 2. SAN-003 : Defender aveugle (journal et état) plus de 30 min ; remplace SAN-001 pour ces deux collectes
        let depuis = |s: &HashMap<&'static str, Suivi>, c: Collecte| s.get(c.id()).and_then(|x| x.indisponible_depuis);
        let aveugle = match (depuis(&self.suivis, Collecte::JournalDefender), depuis(&self.suivis, Collecte::EtatDefender)) {
            (Some(a), Some(b)) => Some(a.max(b)).filter(|d| t - d >= DELAI_S),
            _ => None,
        };
        if depuis(&self.suivis, Collecte::JournalDefender).is_none() || depuis(&self.suivis, Collecte::EtatDefender).is_none() {
            self.san003 = None;
        }
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

impl Sante {
    /// SAN-004 (pure, testée) : remontée configurée et en échec depuis `echec_depuis` (secondes) ; une fois par panne et
    /// par 24 h au plus. Constat local : la boucle des notifications ne le remonte jamais (on ne peut pas)
    pub fn observer_remontee(&mut self, echec_depuis: Option<i64>, t: i64) -> Option<Alerte> {
        let Some(d) = echec_depuis else {
            self.san004 = None;
            return None;
        };
        if t - d < DELAI_REMONTEE_S || self.san004.is_some_and(|x| t - x < RAPPEL_S) {
            return None;
        }
        self.san004 = Some(t);
        Some(constat(regles::SAN_004, "Alerte", "remontée des alertes",
            format!("les alertes ne parviennent plus au prestataire depuis {} min (voir la page Santé) : elles restent dans la liste des alertes", minutes(t - d))))
    }
}

/// Compteurs du battement quotidien (pur, testé) : collectes actives et indisponibles (Inconnue comptée indisponible ;
/// désactivées ni l'un ni l'autre), et collectes critiques indisponibles
pub fn compteurs(etats: &[(Collecte, EtatPublie, bool)], incidents_non_clos: usize) -> crate::notifications::Compteurs {
    crate::notifications::Compteurs {
        incidents_non_clos,
        collectes_actives: etats.iter().filter(|(_, e, _)| matches!(e, EtatPublie::Active | EtatPublie::Partielle(_))).count(),
        collectes_indisponibles: etats.iter().filter(|(_, e, _)| indisponible(e)).count(),
        critiques_indisponibles: etats.iter().filter(|(c, e, _)| CRITIQUES.contains(c) && indisponible(e)).map(|(c, _, _)| c.id()).collect(),
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

// ------------------------------------------------------------ santé de l'interface (phase 4, PR 4.5a)

/// Délai de grâce après l'ouverture d'une session (ou le démarrage du service) : lancement par la clé Run
pub const GRACE_INTERFACE_S: i64 = 300;
/// Interface absente plus de 15 min d'une session active : SAN-010
pub const ABSENCE_INTERFACE_S: i64 = 900;
/// 3 disparitions en une heure dans une même session : SAN-011
pub const MAX_DISPARITIONS_HEURE: usize = 3;
/// SAN-010 est critique, donc hors du plafond de la remontée : 3 constats au plus par session et par 24 h. Sinon un programme
/// du compte, qui alterne arrêt et retour de l'interface, en ferait 90 par jour (audit de #101, S101-15)
pub const MAX_SAN010_JOUR: usize = 3;

#[derive(Default)]
struct SuiviSession {
    vue_depuis: i64,
    presente: bool,
    /// Début de l'absence comptée (disparition, ou fin du délai de grâce si jamais vue)
    absente_depuis: Option<i64>,
    disparitions: VecDeque<i64>,
    san010: Option<i64>,
    san011: Option<i64>,
    /// Constats SAN-010 des dernières 24 h, et plafond déjà signalé
    constats_san010: VecDeque<i64>,
    plafond_signale: bool,
}

/// Événement de l'interface, écrit dans le SIEM (`Source` « sante », `Type` « interface »)
#[derive(Debug, PartialEq)]
pub struct EvenementInterface {
    pub session: u32,
    pub texte: String,
    pub niveau: &'static str,
}

/// État des interfaces par session, gardé par le fil « sante » (en mémoire)
#[derive(Default)]
pub struct Interfaces {
    sessions: HashMap<u32, SuiviSession>,
}

impl Interfaces {
    /// Décision pure (testée) : `actives` (sessions actives avec un utilisateur) et `avec_interface` (sessions où tourne
    /// l'interface installée, chemin exact) à l'heure `t`. Le service ne relance rien : il repère et signale. Il ne
    /// distingue pas un « Quitter » volontaire d'un arrêt forcé (un programme sous le même compte ferait pareil)
    pub fn observer(&mut self, actives: &[u32], avec_interface: &[u32], t: i64) -> (Vec<EvenementInterface>, Vec<Alerte>) {
        let (mut evenements, mut constats) = (Vec::new(), Vec::new());
        // Sessions fermées : oubliées
        self.sessions.retain(|s, _| actives.contains(s));
        for &id in actives {
            let s = self.sessions.entry(id).or_insert_with(|| SuiviSession { vue_depuis: t, ..Default::default() });
            if avec_interface.contains(&id) {
                if !s.presente && s.absente_depuis.is_some() {
                    evenements.push(EvenementInterface { session: id, texte: format!("interface de nouveau présente dans la session {id}"), niveau: "Info" });
                }
                s.presente = true;
                s.absente_depuis = None;
                s.san010 = None;
                continue;
            }
            if s.presente {
                s.presente = false;
                s.absente_depuis = Some(t);
                s.disparitions.push_back(t);
                evenements.push(EvenementInterface { session: id, texte: format!("interface disparue de la session {id}"), niveau: "Alerte" });
            } else if s.absente_depuis.is_none() && t - s.vue_depuis >= GRACE_INTERFACE_S {
                s.absente_depuis = Some(s.vue_depuis + GRACE_INTERFACE_S);
                evenements.push(EvenementInterface { session: id, texte: format!("interface absente de la session {id} après le délai de grâce"), niveau: "Alerte" });
            }
            while s.disparitions.front().is_some_and(|x| t - x >= 3600) {
                s.disparitions.pop_front();
            }
            if let Some(d) = s.absente_depuis {
                if t - d >= ABSENCE_INTERFACE_S && s.san010.is_none_or(|x| t - x >= RAPPEL_S) {
                    s.san010 = Some(t);
                    while s.constats_san010.front().is_some_and(|x| t - x >= RAPPEL_S) {
                        s.constats_san010.pop_front();
                    }
                    if s.constats_san010.len() >= MAX_SAN010_JOUR {
                        if !s.plafond_signale {
                            s.plafond_signale = true;
                            evenements.push(EvenementInterface { session: id, texte: format!("interface absente de la session {id} : plafond de {MAX_SAN010_JOUR} constats par 24 h atteint, les suivants ne sont plus levés"), niveau: "Alerte" });
                        }
                    } else {
                        s.plafond_signale = false;
                        s.constats_san010.push_back(t);
                        // Critique (décision du mainteneur, 2026-10-31) : constat local que personne ne voit, l'interface étant absente
                        constats.push(constat(regles::SAN_010, "Critique", &format!("session {id}"),
                            format!("interface de deR4Tizer absente de la session {id} depuis {} min : plus de notification locale ; la surveillance et la remontée continuent", minutes(t - d))));
                    }
                }
            }
            if s.disparitions.len() >= MAX_DISPARITIONS_HEURE && s.san011.is_none_or(|x| t - x >= RAPPEL_S) {
                s.san011 = Some(t);
                constats.push(constat(regles::SAN_011, "Alerte", &format!("session {id}"),
                    format!("interface de deR4Tizer arrêtée {} fois en une heure dans la session {id}", s.disparitions.len())));
            }
        }
        (evenements, constats)
    }
}

/// Sessions où l'interface est attendue (pur, testé) : aucune si le lancement a été refusé à l'installation
/// (`LANCEMENT_SESSION=0` : une session sans interface est le choix de l'administrateur, SAN-010 serait faux)
pub fn sessions_attendues(lancement_pose: bool, actives: Vec<u32>) -> Vec<u32> {
    if lancement_pose { actives } else { Vec::new() }
}

/// Événement du SIEM de l'interface (pur, testé)
pub fn evenement_interface(e: &EvenementInterface) -> crate::siem::Evenement {
    crate::siem::Evenement {
        heure: commun::maintenant(),
        source: "sante".into(),
        type_: "interface".into(),
        niveau: e.niveau.into(),
        destination: format!("session {}", e.session),
        message: crate::siem::texte_sur(&e.texte, 400),
        ..Default::default()
    }
}

/// Chemin installé de l'interface : `deR4Tizer.exe` à côté du service
pub fn chemin_interface() -> Option<String> {
    let service = std::env::current_exe().ok()?;
    Some(service.parent()?.join("deR4Tizer.exe").to_string_lossy().to_string())
}

