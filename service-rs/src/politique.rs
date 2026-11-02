//! Point de décision des actions de réponse (phase 6, PR 6.2, `docs/reponse/politique.md`) : blocage d'adresse, suspension,
//! reprise, arrêt, isolation, mode panique. Hors de lui : blocage par domaine, quarantaine, restauration, déblocage, tous
//! manuels. `decider` applique les niveaux de la politique, `Historique` la garde contre les boucles. Décisions pures et testées ; l'état partagé
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
    /// Programme signé installé dans Program Files : seuil par programme, un logiciel installé ne doit pas être suspendu sans fin
    Suspension,
    /// Tout autre programme (décision du mainteneur, audit de #110, S110-11) : examiné sans seuil, noté en `Suspension`.
    /// Sinon, un rançongiciel lancé quatre fois, ou trois touches par powershell.exe, s'exempteraient de la suspension
    SuspensionSansSeuil,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Trace {
    pub t: u64,
    pub genre: Genre,
    pub cible: String,
    /// Suspension : empreinte de l'exécutable juste après l'action (audit de #110, S110-05)
    #[serde(default)]
    pub empreinte: Option<String>,
    /// Suspension : heure de création du processus, pour retrouver celui qui est repris (audit de #113, S113-06)
    #[serde(default)]
    pub creation: Option<u64>,
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

/// Action de réponse qui dure (phase 6, PR 6.4) : une échéance est un rendez-vous de relance, jamais une levée
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Sorte {
    SuspensionAuto,
    Suspension,
    Isolation,
    Panique,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum EtatAction {
    Active,
    /// Levée par un administrateur
    Levee,
    /// Le processus n'existe plus, ou il a été arrêté
    Terminee,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ActionEnCours {
    pub id: String,
    pub sorte: Sorte,
    pub cible: String,
    pub pid: Option<u32>,
    pub creation: Option<u64>,
    pub debut: u64,
    pub echeance: u64,
    pub relances: u32,
    pub derniere_relance: u64,
    pub etat: EtatAction,
}

/// (première échéance, puis période de relance) en secondes, et niveau de l'alerte REP-001 (D6-3)
pub fn calendrier(sorte: Sorte) -> (u64, u64, &'static str) {
    match sorte {
        Sorte::SuspensionAuto => (2 * HEURE, JOUR, "Critique"),
        Sorte::Suspension => (JOUR, JOUR, "Alerte"),
        Sorte::Isolation => (7 * JOUR, 7 * JOUR, "Alerte"),
        Sorte::Panique => (4 * HEURE, JOUR, "Critique"),
    }
}

/// Procédure de récupération dite dans chaque relance (`docs/reponse/politique.md`)
pub fn recuperation(sorte: Sorte) -> &'static str {
    match sorte {
        Sorte::SuspensionAuto | Sorte::Suspension => "« Reprendre » ou « Tuer » dans deR4Tizer ; service arrêté : Moniteur de ressources (resmon), « Reprendre le processus », ou arrêt dans le Gestionnaire des tâches",
        Sorte::Isolation => "« Débloquer » dans deR4Tizer ; service arrêté : supprimer les règles « deR4Tizer - isole … » du pare-feu (groupe deR4Tizer)",
        Sorte::Panique => "« Désactiver le mode panique » dans deR4Tizer ; service arrêté : supprimer les règles « deR4Tizer PANIQUE » du pare-feu",
    }
}

/// Seul effet d'une échéance : relancer. Aucune variante ne lève une action : la récupération reste humaine
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effet {
    Relancer { niveau: &'static str },
}

const MAX_ACTIVES: usize = 500;
const MAX_CLOSES: usize = 100;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct Historique {
    /// Registre des actions en cours, et les dernières closes (page « Réponses en cours », PR 6.7)
    pub actions: Vec<ActionEnCours>,
    pub traces: VecDeque<Trace>,
    pub humaines: Vec<Humaine>,
    pub pause_listes: u64,
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
        if genre == Genre::BlocageListe && self.pause_listes > t {
            return Passage::Retenue { raison: "actions automatiques arrêtées pour une heure".into(), alerte: None };
        }
        let debut_jour = t.saturating_sub(JOUR);
        let sur_cible = self.traces.iter().filter(|x| x.genre == genre && x.cible == c && x.t >= debut_jour).count();
        // SuspensionSansSeuil n'a jamais de trace à son nom : le seuil ne la concerne pas
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

    /// Une décision humaine liée à une empreinte porte-t-elle sur ce chemin ? (l'empreinte est alors à lire)
    fn empreinte_utile(&self, cible: &str, t: u64) -> bool {
        let c = cle(cible);
        self.humaines.iter().any(|h| h.cible == c && h.jusqua > t && h.empreinte.is_some())
    }

    pub fn noter(&mut self, genre: Genre, cible: &str, t: u64) {
        self.noter_avec(genre, cible, None, None, t);
    }

    pub fn noter_avec(&mut self, genre: Genre, cible: &str, empreinte: Option<String>, creation: Option<u64>, t: u64) {
        self.traces.push_back(Trace { t, genre, cible: cle(cible), empreinte, creation });
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

    /// Empreinte notée à la suspension de CE processus : un autre, au même chemin, ne donne pas d'exception
    pub fn empreinte_suspension(&self, chemin: &str, creation: u64) -> Option<String> {
        let c = cle(chemin);
        self.traces.iter().rev().find(|x| x.genre == Genre::Suspension && x.cible == c && x.creation == Some(creation)).and_then(|x| x.empreinte.clone())
    }

    /// Inscrit une action ; une action active de même sorte et de même cible (et même processus) n'est pas dédoublée
    pub fn ouvrir(&mut self, sorte: Sorte, cible: &str, pid: Option<u32>, creation: Option<u64>, t: u64) {
        let c = cle(cible);
        if self.actions.iter().any(|a| a.etat == EtatAction::Active && a.sorte == sorte && a.cible == c && a.pid == pid && a.creation == creation) {
            return;
        }
        let (premiere, _, _) = calendrier(sorte);
        self.actions.push(ActionEnCours { id: commun::nouvel_id(), sorte, cible: c, pid, creation, debut: t, echeance: t + premiere, relances: 0, derniere_relance: 0, etat: EtatAction::Active });
        self.borner();
    }

    /// Clôt les actions actives qui correspondent ; renvoie leur nombre
    pub fn clore(&mut self, sortes: &[Sorte], cible: Option<&str>, processus: Option<(u32, u64)>, etat: EtatAction) -> usize {
        let c = cible.map(cle);
        let mut n = 0;
        for a in self.actions.iter_mut().filter(|a| a.etat == EtatAction::Active && sortes.contains(&a.sorte)) {
            let meme_cible = c.as_ref().is_none_or(|c| a.cible == *c);
            let meme_processus = processus.is_none_or(|(p, cr)| a.pid == Some(p) && a.creation == Some(cr));
            if meme_cible && meme_processus {
                a.etat = etat;
                n += 1;
            }
        }
        self.borner();
        n
    }

    /// Fin naturelle : un processus suspendu qui n'existe plus (arrêté, poste redémarré) ; noté, sans alerte
    pub fn terminer_disparus(&mut self, vivant: &dyn Fn(u32, u64) -> bool) -> usize {
        let mut n = 0;
        // Seules les suspensions portent un processus : isolation et panique ne disparaissent pas d'elles-mêmes
        for a in self.actions.iter_mut().filter(|a| a.etat == EtatAction::Active) {
            if let (Some(p), Some(c)) = (a.pid, a.creation) {
                if !vivant(p, c) {
                    a.etat = EtatAction::Terminee;
                    n += 1;
                }
            }
        }
        self.borner();
        n
    }

    /// Relances dues : une à l'échéance, puis une par période, sans doublon. L'action reste active
    pub fn relances(&mut self, t: u64) -> Vec<(ActionEnCours, Effet)> {
        let mut dues = Vec::new();
        for a in self.actions.iter_mut().filter(|a| a.etat == EtatAction::Active) {
            let (_, periode, niveau) = calendrier(a.sorte);
            let prochaine = if a.relances == 0 { a.echeance } else { a.derniere_relance + periode };
            if t >= prochaine {
                a.relances += 1;
                a.derniere_relance = t;
                dues.push((a.clone(), Effet::Relancer { niveau }));
            }
        }
        dues
    }

    /// Bornes : 500 actives au plus (les plus anciennes sortent, l'alerte d'origine reste), 100 closes gardées
    fn borner(&mut self) {
        let actives = self.actions.iter().filter(|a| a.etat == EtatAction::Active).count();
        if actives > MAX_ACTIVES {
            let mut trop = actives - MAX_ACTIVES;
            self.actions.retain(|a| {
                if trop > 0 && a.etat == EtatAction::Active {
                    trop -= 1;
                    false
                } else {
                    true
                }
            });
        }
        let closes = self.actions.iter().filter(|a| a.etat != EtatAction::Active).count();
        if closes > MAX_CLOSES {
            let mut trop = closes - MAX_CLOSES;
            self.actions.retain(|a| {
                if trop > 0 && a.etat != EtatAction::Active {
                    trop -= 1;
                    false
                } else {
                    true
                }
            });
        }
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

/// Sous l'un de ces dossiers, sans remontée. Testé d'abord : hors de Program Files, la signature n'est pas lue, et un
/// programme qui ferait traîner sa lecture ne retarde pas sa suspension (audit de #110, S110-15)
pub fn installe_dans(chemin: &str, program_files: &[String]) -> bool {
    let c = chemin.to_lowercase();
    !c.contains("..") && program_files.iter().any(|d| !d.is_empty() && c.starts_with(&format!("{}\\", d.trim_end_matches('\\').to_lowercase())))
}

/// Interpréteurs qu'une installation place dans Program Files : ils exécutent n'importe quel script, le seuil ne les couvre pas
const INTERPRETES: &[&str] = &["pwsh.exe", "python.exe", "pythonw.exe", "node.exe", "perl.exe", "ruby.exe", "php.exe", "bash.exe", "sh.exe", "java.exe", "javaw.exe", "wscript.exe", "cscript.exe"];

/// Décision pure : le seuil par programme ne vaut que pour un programme signé, installé dans Program Files (un compte
/// standard n'y écrit pas), et qui n'est pas un interpréteur
pub fn genre_suspension(chemin: &str, signe: bool, program_files: &[String]) -> Genre {
    let c = chemin.to_lowercase();
    let installe = installe_dans(chemin, program_files);
    let interprete = INTERPRETES.iter().any(|i| c.rsplit('\\').next() == Some(*i));
    if signe && installe && !interprete {
        Genre::Suspension
    } else {
        Genre::SuspensionSansSeuil
    }
}

/// Relance d'une action toujours en cours : REP-001 (jamais une levée)
pub fn alerte_relance(a: &ActionEnCours, niveau: &str, t: u64) -> Alerte {
    let quoi = match a.sorte {
        Sorte::SuspensionAuto => "programme suspendu automatiquement (leurre touché)",
        Sorte::Suspension => "programme suspendu par un administrateur",
        Sorte::Isolation => "programme coupé du réseau",
        Sorte::Panique => "mode panique actif : le poste n'a plus accès à Internet",
    };
    let duree = t.saturating_sub(a.debut);
    Alerte {
        regle: crate::regles::REP_001.into(),
        id: commun::nouvel_id(),
        heure: commun::maintenant(),
        niveau: niveau.into(),
        processus: "deR4Tizer".into(),
        chemin: a.cible.clone(),
        pid: a.pid,
        destination: "action de réponse toujours en cours".into(),
        raisons: format!("{quoi} depuis {} h {:02} min ({}) — jamais levé automatiquement ; décision humaine attendue. Récupération : {}",
            duree / HEURE, (duree % HEURE) / 60, a.cible, recuperation(a.sorte)),
        ..Default::default()
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

/// Décision pure. Seul un contenu mal formé coupe la réponse automatique, et seul un administrateur peut l'écrire. Une
/// lecture refusée (fichier absent, tenu ouvert par un compte autorisé, protection en échec) ne dit rien du contenu : la
/// garde repart en mémoire, et la réponse reste (audit de #110, S110-03)
fn etat_initial(texte: Option<&str>) -> Etat {
    match texte.map(|t| serde_json::from_str::<Historique>(t.trim_start_matches('\u{feff}'))) {
        Some(Ok(h)) => Etat { h, illisible: false, signale: false },
        Some(Err(_)) => Etat { h: Historique::default(), illisible: true, signale: false },
        None => Etat { h: Historique::default(), illisible: false, signale: false },
    }
}

impl Etat {
    fn passage(&mut self, genre: Genre, cible: &str, t: u64, empreinte: &mut dyn FnMut() -> Option<String>) -> Passage {
        if self.illisible {
            let alerte = (!self.signale).then(|| format!("{FICHIER} illisible : aucune action automatique, alerte seulement ; retirez ce fichier du dossier de données pour rétablir la réponse automatique, puis redémarrez le service"));
            self.signale = true;
            return Passage::Retenue { raison: format!("{FICHIER} illisible"), alerte };
        }
        self.h.examiner(genre, cible, t, empreinte)
    }
}

/// Une ligne au SIEM par cible et par motif et par heure : une action retenue revient à chaque cycle tant que la connexion
/// vit, et un flot de lignes chasserait les jours les plus anciens du SIEM (décision pure, relecture de #110, F2)
pub fn retenue_a_journaliser(vues: &mut std::collections::HashMap<String, u64>, cle: &str, t: u64) -> bool {
    if vues.get(cle).is_some_and(|h| *h + HEURE > t) {
        return false;
    }
    if vues.len() >= MAX_SIGNALES {
        vues.retain(|_, h| *h + HEURE > t);
        // Table pleine de cibles récentes : pas de ligne de plus, plutôt que de tout réécrire à chaque cycle
        if vues.len() >= MAX_SIGNALES {
            return false;
        }
    }
    vues.insert(cle.to_string(), t);
    true
}

static ETAT: Mutex<Option<Etat>> = Mutex::new(None);

fn avec<R>(f: impl FnOnce(&mut Etat) -> R) -> R {
    let mut g = ETAT.lock().unwrap_or_else(|e| e.into_inner());
    let e = g.get_or_insert_with(|| {
        let texte = commun::lire_fichier(&commun::dossier().join(FICHIER));
        etat_initial(texte.as_deref())
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

/// La garde, pour une action automatique déjà autorisée. L'empreinte est lue hors du verrou : le cycle n'attend pas le fil
/// des leurres
pub fn passer(genre: Genre, cible: &str, empreinte: &mut dyn FnMut() -> Option<String>) -> Passage {
    let t = maintenant();
    let lue = if avec(|e| e.h.empreinte_utile(cible, t)) { empreinte() } else { None };
    avec(|e| {
        let p = e.passage(genre, cible, t, &mut || lue.clone());
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

/// Une suspension automatique a eu lieu : avec l'empreinte de l'exécutable
pub fn noter_suspension(chemin: &str, empreinte: Option<String>, creation: u64) {
    avec(|e| {
        e.h.noter_avec(Genre::Suspension, chemin, empreinte, Some(creation), maintenant());
        enregistrer(e);
    })
}

pub fn empreinte_suspension(chemin: &str, creation: u64) -> Option<String> {
    avec(|e| e.h.empreinte_suspension(chemin, creation))
}

pub fn suspendu_automatiquement(chemin: &str) -> bool {
    avec(|e| e.h.suspendu_automatiquement(chemin, maintenant()))
}

pub fn ouvrir(sorte: Sorte, cible: &str, pid: Option<u32>, creation: Option<u64>) {
    avec(|e| {
        e.h.ouvrir(sorte, cible, pid, creation, maintenant());
        enregistrer(e);
    })
}

pub fn clore(sortes: &[Sorte], cible: Option<&str>, processus: Option<(u32, u64)>, etat: EtatAction) {
    avec(|e| {
        if e.h.clore(sortes, cible, processus, etat) > 0 {
            enregistrer(e);
        }
    })
}

/// Fin naturelle et relances dues ; appelé par le moniteur toutes les minutes. Le contrôle de vie se fait hors du verrou
pub fn echeances(vivant: &dyn Fn(u32, u64) -> bool) -> Vec<Alerte> {
    let suivies: Vec<(u32, u64)> = avec(|e| e.h.actions.iter().filter(|a| a.etat == EtatAction::Active).filter_map(|a| a.pid.zip(a.creation)).collect());
    let morts: Vec<(u32, u64)> = suivies.into_iter().filter(|(p, c)| !vivant(*p, *c)).collect();
    avec(|e| {
        let t = maintenant();
        let n = e.h.terminer_disparus(&|p, c| !morts.contains(&(p, c)));
        let dues = e.h.relances(t);
        if n > 0 || !dues.is_empty() {
            enregistrer(e);
        }
        dues.iter().map(|(a, Effet::Relancer { niveau })| alerte_relance(a, niveau, t)).collect()
    })
}

/// Un administrateur a levé ou repris une action automatique
pub fn decision_humaine(cible: &str, empreinte: Option<String>) {
    avec(|e| {
        e.h.decision_humaine(cible, empreinte, maintenant());
        enregistrer(e);
    })
}

#[cfg(test)]
pub(crate) fn etat_initial_test(texte: Option<&str>) -> (bool, usize) {
    let e = etat_initial(texte);
    (e.illisible, e.h.traces.len())
}

/// Deux passages de suite sur un état chargé de ce texte
#[cfg(test)]
pub(crate) fn passages_test(texte: Option<&str>) -> (Passage, Passage) {
    let mut e = etat_initial(texte);
    let mut sans = || None;
    (e.passage(Genre::Suspension, "c", 1_800_000_000, &mut sans), e.passage(Genre::Suspension, "c", 1_800_000_001, &mut sans))
}

#[cfg(test)]
pub(crate) fn empreinte_utile_test(h: &Historique, cible: &str, t: u64) -> bool {
    h.empreinte_utile(cible, t)
}
