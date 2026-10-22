//! Arbre des processus et score cumulé (à la manière du « Storyline » des EDR) : chaque signal
//! (flux suspect, ligne de commande, vol de données…) est rattaché à son processus, puis on remonte
//! la chaîne des parents jusqu'à une racine (Explorateur, service…). Le score de la chaîne est la somme
//! des signaux de tous ses processus : une suite d'actions banales prises une à une devient visible.

use crate::commun::{self, Alerte};
use crate::natif::InfoListe;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Processus où s'arrête la remontée : lanceurs du système, pas des maillons d'attaque
const RACINES: &[&str] = &[
    "explorer", "services", "svchost", "wininit", "winlogon", "userinit", "system", "smss", "csrss", "sihost", "runtimebroker", "taskhostw",
];
const SEUIL_CHAINE: i32 = 12;
const DUREE_SIGNAL: Duration = Duration::from_secs(3600);

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct NoeudChaine {
    pub profondeur: u32,
    pub pid: u32,
    pub nom: String,
    pub chemin: String,
    pub ligne_commande: String,
    pub score: i32,
    pub raisons: String,
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Chaine {
    pub racine: String,
    pub score: i32,
    pub resume: String,
    pub depuis: String,
    pub noeuds: Vec<NoeudChaine>,
}

struct Processus {
    nom: String,
    parent: u32,
    chemin: String,
    ligne: String,
    vu: Instant,
}

struct Signal {
    score: i32,
    raison: String,
    vu: Instant,
    heure: String,
}

#[derive(Default)]
pub struct Arbre {
    processus: HashMap<u32, Processus>,
    signaux: HashMap<u32, Vec<Signal>>,
    deja_alertees: HashMap<String, i32>,
}

impl Arbre {
    /// Met à jour la liste des processus ; garde 1 h les processus terminés pour reconstituer les chaînes
    pub fn maj(&mut self, liste: &HashMap<u32, InfoListe>) {
        let maintenant = Instant::now();
        for (&pid, p) in liste {
            let e = self.processus.entry(pid).or_insert_with(|| Processus {
                nom: p.nom.clone(), parent: p.parent, chemin: String::new(), ligne: String::new(), vu: maintenant,
            });
            if e.nom != p.nom {
                // Identifiant réutilisé par un autre programme
                *e = Processus { nom: p.nom.clone(), parent: p.parent, chemin: String::new(), ligne: String::new(), vu: maintenant };
                self.signaux.remove(&pid);
            }
            e.vu = maintenant;
        }
        self.processus.retain(|_, p| p.vu.elapsed() < DUREE_SIGNAL);
        for s in self.signaux.values_mut() {
            s.retain(|x| x.vu.elapsed() < DUREE_SIGNAL);
        }
        self.signaux.retain(|_, s| !s.is_empty());
    }

    pub fn completer(&mut self, pid: u32, chemin: &str, ligne: Option<&str>) {
        if let Some(p) = self.processus.get_mut(&pid) {
            if p.chemin.is_empty() {
                p.chemin = chemin.to_string();
            }
            if p.ligne.is_empty() {
                if let Some(l) = ligne {
                    p.ligne = l.to_string();
                }
            }
        }
    }

    /// Ajoute un signal à un processus (une même raison n'est comptée qu'une fois)
    pub fn signaler(&mut self, pid: u32, score: i32, raison: &str) {
        if score <= 0 || pid <= 4 {
            return;
        }
        let s = self.signaux.entry(pid).or_default();
        if !s.iter().any(|x| x.raison == raison) {
            s.push(Signal { score, raison: raison.to_string(), vu: Instant::now(), heure: commun::maintenant() });
        }
    }

    fn nom(&self, pid: u32) -> String {
        self.processus.get(&pid).map(|p| p.nom.clone()).unwrap_or_else(|| format!("PID {pid}"))
    }

    /// Remonte jusqu'à la racine : liste [racine, …, pid]
    fn ascendance(&self, pid: u32) -> Vec<u32> {
        let mut chemin = vec![pid];
        let mut vus = HashSet::from([pid]);
        let mut courant = pid;
        while let Some(p) = self.processus.get(&courant) {
            let parent = p.parent;
            let Some(pp) = self.processus.get(&parent) else { break };
            if RACINES.contains(&pp.nom.to_lowercase().as_str()) || !vus.insert(parent) || parent <= 4 {
                break;
            }
            chemin.push(parent);
            courant = parent;
        }
        chemin.reverse();
        chemin
    }

    /// Chaînes ayant au moins un signal, triées par score décroissant
    pub fn chaines(&self) -> Vec<Chaine> {
        let mut par_racine: HashMap<u32, Vec<Vec<u32>>> = HashMap::new();
        for &pid in self.signaux.keys() {
            let a = self.ascendance(pid);
            par_racine.entry(a[0]).or_default().push(a);
        }
        let mut chaines: Vec<Chaine> = par_racine
            .into_iter()
            .map(|(racine, chemins)| {
                // Arbre de la chaîne : ordre de parcours en profondeur depuis la racine
                let mut membres: Vec<(u32, u32)> = Vec::new(); // (pid, profondeur)
                for c in &chemins {
                    for (i, &pid) in c.iter().enumerate() {
                        if !membres.iter().any(|(p, _)| *p == pid) {
                            membres.push((pid, i as u32));
                        }
                    }
                }
                membres.sort_by_key(|(pid, prof)| (chemins.iter().position(|c| c.contains(pid)).unwrap_or(0), *prof));
                let noeuds: Vec<NoeudChaine> = membres
                    .iter()
                    .map(|&(pid, prof)| {
                        let p = self.processus.get(&pid);
                        let s = self.signaux.get(&pid);
                        NoeudChaine {
                            profondeur: prof,
                            pid,
                            nom: self.nom(pid),
                            chemin: p.map(|p| p.chemin.clone()).unwrap_or_default(),
                            ligne_commande: p.map(|p| p.ligne.clone()).unwrap_or_default(),
                            score: s.map(|s| s.iter().map(|x| x.score).sum()).unwrap_or(0),
                            raisons: s.map(|s| s.iter().map(|x| x.raison.clone()).collect::<Vec<_>>().join(" ; ")).unwrap_or_default(),
                        }
                    })
                    .collect();
                let score = noeuds.iter().map(|n| n.score).sum();
                let depuis = chemins.iter().flat_map(|c| c.iter()).filter_map(|p| self.signaux.get(p)).flatten().map(|s| s.heure.clone()).min().unwrap_or_default();
                let resume = chemins
                    .iter()
                    .max_by_key(|c| c.len())
                    .map(|c| c.iter().map(|&p| self.nom(p)).collect::<Vec<_>>().join(" → "))
                    .unwrap_or_default();
                Chaine { racine: self.nom(racine), score, resume, depuis, noeuds }
            })
            .collect();
        chaines.sort_by(|a, b| b.score.cmp(&a.score));
        chaines
    }

    /// Alerte pour toute chaîne qui dépasse le seuil avec au moins deux signaux (une fois par niveau atteint)
    pub fn alertes(&mut self, chaines: &[Chaine]) -> Vec<Alerte> {
        let mut a = Vec::new();
        for c in chaines {
            let signaux = c.noeuds.iter().filter(|n| n.score > 0).map(|n| n.raisons.matches(" ; ").count() + 1).sum::<usize>();
            if c.score < SEUIL_CHAINE || signaux < 2 {
                continue;
            }
            let cle = format!("{}|{}", c.racine, c.noeuds.first().map(|n| n.pid).unwrap_or(0));
            if self.deja_alertees.get(&cle).map(|&s| s >= c.score).unwrap_or(false) {
                continue;
            }
            self.deja_alertees.insert(cle, c.score);
            let dernier = c.noeuds.iter().rev().find(|n| n.score > 0).cloned().unwrap_or_default();
            a.push(Alerte {
                id: commun::nouvel_id(),
                heure: commun::maintenant(),
                niveau: "Critique".into(),
                score: c.score,
                processus: dernier.nom.clone(),
                chemin: dernier.chemin.clone(),
                destination: format!("chaîne : {}", c.resume),
                raisons: format!(
                    "CHAÎNE D'ATTAQUE PROBABLE (score cumulé {}) : {}",
                    c.score,
                    c.noeuds.iter().filter(|n| n.score > 0).map(|n| format!("{} [{}]", n.nom, n.raisons)).collect::<Vec<_>>().join(" → ")
                ),
                pid: Some(dernier.pid),
                ..Default::default()
            });
        }
        a
    }
}
