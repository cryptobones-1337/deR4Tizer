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
    /// Présent dans la dernière liste des processus (un 4688 en retard ne remplace jamais un processus vivant)
    vivant: bool,
}

/// Ligne de commande gardée dans l'arbre et publiée dans les chaînes (etat.json) : bornée (audit de #244, S244-04, S244-05)
const LIGNE_GARDEE: usize = 1024;
const LIGNE_PUBLIEE: usize = 300;

/// Décision pure (testée) : code de comportement d'une chaîne (prérelecture de #255, D1) : codes de ses signaux, triés,
/// sans doublon ; un signal sans code y entre par le début de sa raison. Jamais les techniques. Long ou non ASCII :
/// remplacé par le début de son empreinte SHA-256 (même code pour les mêmes signaux, 100 caractères au plus)
pub(crate) fn code_chaine(signaux: &[(&str, &str)]) -> String {
    let mut codes: Vec<String> = signaux.iter().map(|(code, raison)| {
        if code.is_empty() { format!("r:{}", raison.chars().take(40).collect::<String>()) } else { code.to_string() }
    }).collect();
    codes.sort();
    codes.dedup();
    let c = codes.join("+");
    if c.len() <= 100 && c.chars().all(|x| x.is_ascii_graphic()) {
        c
    } else {
        let e = commun::empreinte_signature(&c);
        format!("sha:{}", &e["sha256:".len().."sha256:".len() + 16])
    }
}

fn borner(s: &str, n: usize) -> String {
    if s.chars().count() > n { s.chars().take(n).collect::<String>() + "…" } else { s.to_string() }
}

struct Signal {
    score: i32,
    raison: String,
    /// Techniques ATT&CK de l'alerte d'origine (règle de la table, ou posées par son code) : celles de la chaîne
    techniques: Vec<String>,
    /// Code stable du signal (règle et code de comportement de l'alerte d'origine) : il entre dans le code de la chaîne
    code: String,
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
                nom: p.nom.clone(), parent: p.parent, chemin: String::new(), ligne: String::new(), vu: maintenant, vivant: true,
            });
            if !e.nom.eq_ignore_ascii_case(&p.nom) {
                // Identifiant réutilisé par un autre programme
                *e = Processus { nom: p.nom.clone(), parent: p.parent, chemin: String::new(), ligne: String::new(), vu: maintenant, vivant: true };
                self.signaux.remove(&pid);
            }
            e.vu = maintenant;
        }
        for (pid, p) in self.processus.iter_mut() {
            p.vivant = liste.contains_key(pid);
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
                    p.ligne = borner(l, LIGNE_GARDEE);
                }
            }
        }
    }

    /// Création vue par l'audit (4688) : un processus bref, terminé avant la lecture de la liste, garde sa place dans
    /// l'arbre et son parent ; PID réutilisé par un autre programme : l'entrée est remplacée et ses signaux effacés, sauf
    /// si elle est vivante (dans la dernière liste) : un 4688 en retard, d'un ancien processus de ce PID, ne peut pas
    /// effacer les signaux du processus qui tourne (audit de #244, S244-01)
    pub fn creation(&mut self, pid: u32, parent: Option<u32>, chemin: &str, ligne: Option<&str>) {
        if pid <= 4 {
            return;
        }
        let nom = std::path::Path::new(chemin).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
        let maintenant = Instant::now();
        match self.processus.get_mut(&pid) {
            Some(e) if e.nom.eq_ignore_ascii_case(&nom) => {
                if e.parent == 0 {
                    e.parent = parent.unwrap_or(0);
                }
                self.completer(pid, chemin, ligne);
            }
            Some(e) if e.vivant => {}
            _ => {
                self.processus.insert(pid, Processus {
                    nom, parent: parent.unwrap_or(0), chemin: chemin.to_string(), ligne: borner(ligne.unwrap_or_default(), LIGNE_GARDEE), vu: maintenant, vivant: false,
                });
                self.signaux.remove(&pid);
            }
        }
    }

    /// Ajoute un signal à un processus (une même raison n'est comptée qu'une fois), sans technique
    pub fn signaler(&mut self, pid: u32, score: i32, raison: &str) {
        self.signaler_avec(pid, score, raison, &[]);
    }

    /// Ajoute un signal et les techniques de l'alerte qui le porte : la chaîne reçoit celles de ses signaux, jamais une
    /// technique par défaut (couverture ATT&CK, lot 2 : avant, toute chaîne recevait T1204)
    pub fn signaler_avec(&mut self, pid: u32, score: i32, raison: &str, techniques: &[String]) {
        self.signaler_code(pid, score, raison, techniques, "");
    }

    /// `signaler_avec` et le code stable du signal (« règle#comportement ») : la chaîne en tire son code de comportement
    /// (empreinte des exceptions ; prérelecture de #255, D1)
    pub fn signaler_code(&mut self, pid: u32, score: i32, raison: &str, techniques: &[String], code: &str) {
        if score <= 0 || pid <= 4 {
            return;
        }
        let s = self.signaux.entry(pid).or_default();
        if !s.iter().any(|x| x.raison == raison) {
            s.push(Signal { score, raison: raison.to_string(), techniques: techniques.to_vec(), code: code.to_string(), vu: Instant::now(), heure: commun::maintenant() });
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
                            ligne_commande: p.map(|p| borner(&p.ligne, LIGNE_PUBLIEE)).unwrap_or_default(),
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
            // Techniques de la chaîne : celles de ses signaux, dans l'ordre de la chaîne, sans doublon
            let mut techniques: Vec<String> = Vec::new();
            for t in c.noeuds.iter().filter_map(|n| self.signaux.get(&n.pid)).flatten().flat_map(|s| s.techniques.iter()) {
                if !techniques.contains(t) {
                    techniques.push(t.clone());
                }
            }
            let signaux: Vec<&Signal> = c.noeuds.iter().filter_map(|n| self.signaux.get(&n.pid)).flatten().collect();
            a.push(Alerte {
                comportement: code_chaine(&signaux.iter().map(|s| (s.code.as_str(), s.raison.as_str())).collect::<Vec<_>>()),
                regle: crate::regles::CHA_001.into(),
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
                mitre: techniques.join(" / "),
                ..Default::default()
            });
        }
        a
    }
}
