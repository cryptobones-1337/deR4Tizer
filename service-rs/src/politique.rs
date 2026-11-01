//! Point de décision unique des actions de réponse (phase 6, PR 6.2, `docs/reponse/politique.md`) : `decider` applique
//! les niveaux de la politique, `Historique` la garde contre les boucles. Décisions pures et testées ; l'état partagé
//! entre le moniteur et le fil des leurres est en bas du fichier. Aucune action sans une `Autorisation`, que seul
//! `decider` fabrique (`execution.rs`).

use crate::commun::{self, Alerte};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Mutex;

/// Fichier de l'historique, dans le dossier de données
pub const FICHIER: &str = "reponses.json";

const JOUR: u64 = 86_400;
const HEURE: u64 = 3_600;
/// Même action automatique sur la même cible, par 24 h
const PAR_CIBLE: usize = 3;
/// Toutes cibles confondues, par heure
const BLOCAGES_LISTES: usize = 30;
const SUSPENSIONS: usize = 3;
const ADRESSES_IPS: usize = 50;
const PRIORITE_HUMAINE: u64 = 7 * JOUR;
/// Bornes de l'historique : le fichier reste petit, quoi qu'un attaquant provoque
const MAX_TRACES: usize = 2000;
const MAX_HUMAINES: usize = 500;
const MAX_SIGNALES: usize = 500;
/// Une suspension reste connue 7 jours : une reprise tardive reste une décision humaine sur une action automatique
const GARDE_SUSPENSION: u64 = PRIORITE_HUMAINE;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    BloquerIp,
    Suspendre,
    Reprendre,
    Tuer,
    TuerChaine,
    Isoler,
    Panique,
    FinPanique,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SourceAuto {
    /// Liste de menaces ; `niveau3` : Spamhaus DROP ou Feodo Tracker (`menaces::Correspondance::auto`)
    Liste { niveau3: bool },
    Ips,
    Leurre,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Declencheur {
    /// Commande d'un administrateur (canal) ; les refus propres à l'action restent dans son code
    Humain,
    Automatique(SourceAuto),
}

/// Réglages et état lus par la décision
#[derive(Clone, Copy, Default)]
pub struct Contexte {
    pub echec_protection: bool,
    pub blocage_menaces: bool,
    pub ips: bool,
    pub rancongiciel: bool,
}

/// Preuve qu'une décision a été prise : le champ privé réserve sa fabrication à ce module
#[derive(Debug)]
pub struct Autorisation {
    _prive: (),
}

#[derive(Debug)]
pub enum Decision {
    Autorisee(Autorisation),
    /// Jamais exécutée
    Refusee(String),
    /// L'alerte part, l'action non
    AlerteSeulement(String),
}

/// Décision pure. Une action automatique n'est permise que dans les cas écrits par la politique : tout le reste est
/// refusé, en particulier un arrêt de processus (D6-9). En échec de la protection du dossier de données, les actions
/// alimentées par ses fichiers sont refusées ; la suspension sur leurre, alimentée par le journal Sécurité, reste (D6-10)
pub fn decider(action: Action, declencheur: Declencheur, c: &Contexte) -> Decision {
    let autorisee = Decision::Autorisee(Autorisation { _prive: () });
    let source = match declencheur {
        Declencheur::Humain => return autorisee,
        Declencheur::Automatique(s) => s,
    };
    match (action, source) {
        (Action::BloquerIp, SourceAuto::Liste { niveau3 }) => {
            if !niveau3 {
                Decision::AlerteSeulement("liste hors du niveau 3".into())
            } else if c.echec_protection {
                Decision::Refusee("protection du dossier de données en échec".into())
            } else if !c.blocage_menaces {
                Decision::AlerteSeulement("blocage automatique désactivé".into())
            } else {
                autorisee
            }
        }
        (Action::BloquerIp, SourceAuto::Ips) => {
            if c.echec_protection {
                Decision::Refusee("protection du dossier de données en échec".into())
            } else if !c.ips {
                Decision::AlerteSeulement("IPS désactivé".into())
            } else {
                autorisee
            }
        }
        (Action::Suspendre, SourceAuto::Leurre) => {
            if c.rancongiciel {
                autorisee
            } else {
                Decision::AlerteSeulement("réponse automatique aux rançongiciels désactivée".into())
            }
        }
        _ => Decision::Refusee("action automatique hors de la politique".into()),
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Genre {
    BlocageListe,
    BlocageIps,
    Suspension,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Trace {
    pub t: u64,
    pub genre: Genre,
    pub cible: String,
}

/// Décision humaine contraire à une action automatique. Programme : avec l'empreinte de l'exécutable, pour qu'un fichier
/// remplacé au même chemin n'en hérite pas (D6-2)
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Humaine {
    pub cible: String,
    pub empreinte: Option<String>,
    pub jusqua: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Passage {
    Passe,
    /// `alerte` : texte de l'alerte REP-002, une fois par arrêt
    Retenue { raison: String, alerte: Option<String> },
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct Historique {
    pub traces: VecDeque<Trace>,
    pub humaines: Vec<Humaine>,
    pub pause_listes: u64,
    pub pause_suspensions: u64,
    pub signal_ips: u64,
    /// Cibles dont la boucle a été signalée : (cible, heure)
    pub signales: VecDeque<(String, u64)>,
}

fn cle(cible: &str) -> String {
    cible.to_lowercase()
}

impl Historique {
    fn nombre(&self, genre: Genre, depuis: u64) -> usize {
        self.traces.iter().filter(|x| x.genre == genre && x.t >= depuis).count()
    }

    /// La garde : seulement pour les actions automatiques, et l'alerte d'origine part toujours. `empreinte` n'est lue
    /// que si une décision humaine porte sur ce chemin. Une empreinte illisible ne prouve pas que c'est le même
    /// programme : la décision humaine ne s'applique pas
    pub fn examiner(&mut self, genre: Genre, cible: &str, t: u64, empreinte: &mut dyn FnMut() -> Option<String>) -> Passage {
        let c = cle(cible);
        if let Some(h) = self.humaines.iter().find(|h| h.cible == c && h.jusqua > t) {
            if h.empreinte.is_none() || h.empreinte == empreinte() {
                return Passage::Retenue { raison: "décision humaine contraire, 7 jours".into(), alerte: None };
            }
        }
        let pause = match genre {
            Genre::BlocageListe => self.pause_listes,
            Genre::Suspension => self.pause_suspensions,
            Genre::BlocageIps => 0,
        };
        if pause > t {
            return Passage::Retenue { raison: "actions automatiques arrêtées pour une heure".into(), alerte: None };
        }
        let debut_jour = t.saturating_sub(JOUR);
        let sur_cible = self.traces.iter().filter(|x| x.genre == genre && x.cible == c && x.t >= debut_jour).count();
        if sur_cible >= PAR_CIBLE {
            let deja = self.signales.iter().any(|(s, h)| *s == c && *h >= debut_jour);
            if !deja {
                self.signales.push_back((c.clone(), t));
                while self.signales.len() > MAX_SIGNALES {
                    self.signales.pop_front();
                }
            }
            let alerte = (!deja).then(|| format!("boucle d'actions arrêtée : {cible} a déjà subi {PAR_CIBLE} actions automatiques en 24 h ; vérifiez ce programme ou cette adresse"));
            return Passage::Retenue { raison: format!("déjà {PAR_CIBLE} actions sur cette cible en 24 h"), alerte };
        }
        let debut_heure = t.saturating_sub(HEURE);
        match genre {
            Genre::BlocageListe if self.nombre(genre, debut_heure) >= BLOCAGES_LISTES => {
                self.pause_listes = t + HEURE;
                Passage::Retenue {
                    raison: format!("plus de {BLOCAGES_LISTES} blocages en une heure"),
                    alerte: Some(format!("blocages automatiques arrêtés pour une heure : {BLOCAGES_LISTES} en une heure ; une liste de menaces peut être corrompue")),
                }
            }
            Genre::Suspension if self.nombre(genre, debut_heure) >= SUSPENSIONS => {
                self.pause_suspensions = t + HEURE;
                Passage::Retenue {
                    raison: format!("plus de {SUSPENSIONS} suspensions en une heure"),
                    alerte: Some(format!("suspensions automatiques arrêtées pour une heure : {SUSPENSIONS} en une heure ; attaque à plusieurs programmes ou faux positif répété, vérifiez le poste sans attendre")),
                }
            }
            Genre::BlocageIps => {
                let mut adresses: Vec<&str> = self.traces.iter().filter(|x| x.genre == genre && x.t >= debut_heure).map(|x| x.cible.as_str()).collect();
                adresses.sort_unstable();
                adresses.dedup();
                if adresses.len() < ADRESSES_IPS || adresses.contains(&c.as_str()) {
                    return Passage::Passe;
                }
                let signal = self.signal_ips <= debut_heure;
                if signal {
                    self.signal_ips = t;
                }
                Passage::Retenue {
                    raison: format!("plus de {ADRESSES_IPS} adresses par l'IPS en une heure"),
                    alerte: signal.then(|| format!("blocages de l'IPS retenus : {ADRESSES_IPS} adresses en une heure ; salve probable")),
                }
            }
            _ => Passage::Passe,
        }
    }

    pub fn noter(&mut self, genre: Genre, cible: &str, t: u64) {
        self.traces.push_back(Trace { t, genre, cible: cle(cible) });
        self.traces.retain(|x| x.t + if x.genre == Genre::Suspension { GARDE_SUSPENSION } else { JOUR } > t);
        while self.traces.len() > MAX_TRACES {
            self.traces.pop_front();
        }
    }

    /// Ce programme a-t-il été suspendu automatiquement ces 7 derniers jours ?
    pub fn suspendu_automatiquement(&self, chemin: &str, t: u64) -> bool {
        let c = cle(chemin);
        self.traces.iter().any(|x| x.genre == Genre::Suspension && x.cible == c && x.t + GARDE_SUSPENSION > t)
    }

    pub fn decision_humaine(&mut self, cible: &str, empreinte: Option<String>, t: u64) {
        let c = cle(cible);
        self.humaines.retain(|h| h.cible != c && h.jusqua > t);
        self.humaines.push(Humaine { cible: c, empreinte, jusqua: t + PRIORITE_HUMAINE });
        if self.humaines.len() > MAX_HUMAINES {
            let trop = self.humaines.len() - MAX_HUMAINES;
            self.humaines.drain(..trop);
        }
    }
}

/// Alerte de la garde : REP-002, jamais adoucie
pub fn alerte_garde(texte: &str) -> Alerte {
    Alerte {
        regle: crate::regles::REP_002.into(),
        id: commun::nouvel_id(),
        heure: commun::maintenant(),
        niveau: "Critique".into(),
        score: 10,
        processus: "deR4Tizer".into(),
        destination: "garde contre les boucles d'actions".into(),
        raisons: texte.into(),
        ..Default::default()
    }
}

// ------------------------------------------------------------ état partagé

struct Etat {
    h: Historique,
    /// Fichier présent mais illisible : aucune action automatique, alerte seulement (échec fermé). Le fichier n'est pas écrasé
    illisible: bool,
    signale: bool,
}

/// Décision pure. Protection en échec : la lecture est refusée, ce qui ne dit rien du fichier ; la garde repart en mémoire
fn etat_initial(existe: bool, lu: Option<Historique>, echec_protection: bool) -> Etat {
    match lu {
        Some(h) => Etat { h, illisible: false, signale: false },
        None => Etat { h: Historique::default(), illisible: existe && !echec_protection, signale: false },
    }
}

static ETAT: Mutex<Option<Etat>> = Mutex::new(None);

fn avec<R>(f: impl FnOnce(&mut Etat) -> R) -> R {
    let mut g = ETAT.lock().unwrap_or_else(|e| e.into_inner());
    let e = g.get_or_insert_with(|| {
        let existe = commun::dossier().join(FICHIER).exists();
        etat_initial(existe, commun::lire::<Historique>(FICHIER), commun::echec_protection().is_some())
    });
    f(e)
}

fn enregistrer(e: &Etat) {
    if !e.illisible && commun::echec_protection().is_none() {
        let _ = commun::ecrire(FICHIER, &e.h);
    }
}

fn maintenant() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// La garde, pour une action automatique déjà autorisée
pub fn passer(genre: Genre, cible: &str, empreinte: &mut dyn FnMut() -> Option<String>) -> Passage {
    avec(|e| {
        if e.illisible {
            let alerte = (!e.signale).then(|| format!("{FICHIER} illisible : aucune action automatique, alerte seulement ; retirez ce fichier du dossier de données pour rétablir la réponse automatique, puis redémarrez le service"));
            e.signale = true;
            return Passage::Retenue { raison: format!("{FICHIER} illisible"), alerte };
        }
        let p = e.h.examiner(genre, cible, maintenant(), empreinte);
        if matches!(p, Passage::Retenue { alerte: Some(_), .. }) {
            enregistrer(e);
        }
        p
    })
}

/// Une action automatique a eu lieu
pub fn noter(genre: Genre, cible: &str) {
    avec(|e| {
        e.h.noter(genre, cible, maintenant());
        enregistrer(e);
    })
}

pub fn suspendu_automatiquement(chemin: &str) -> bool {
    avec(|e| e.h.suspendu_automatiquement(chemin, maintenant()))
}

/// Un administrateur a levé ou repris une action automatique
pub fn decision_humaine(cible: &str, empreinte: Option<String>) {
    avec(|e| {
        e.h.decision_humaine(cible, empreinte, maintenant());
        enregistrer(e);
    })
}

#[cfg(test)]
pub(crate) fn etat_initial_test(existe: bool, lu: Option<Historique>, echec: bool) -> (bool, usize) {
    let e = etat_initial(existe, lu, echec);
    (e.illisible, e.h.traces.len())
}
