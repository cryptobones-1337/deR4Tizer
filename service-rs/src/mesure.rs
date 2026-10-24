//! Phase 1, condition préalable à tout découpage de `Moniteur` : mesure du cycle de surveillance. Durée de chaque
//! étape du cycle de 3 s, attente et tenue du verrou du moniteur, durée de chaque commande, PowerShell lancés.
//! Écrit dans `mesures.json` toutes les 10 minutes : cumul depuis le démarrage du service et dernière fenêtre.
//! Lecture seule pour le reste du service : aucune décision n'en dépend.

use crate::commun;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Bornes supérieures (ms) des classes de la répartition ; la dernière classe compte tout ce qui les dépasse
pub const SEUILS_MS: [u64; 8] = [1, 5, 10, 50, 100, 500, 1000, 5000];

#[derive(Clone, Default, Serialize, Debug, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct Stat {
    pub nombre: u64,
    pub total_ms: f64,
    pub max_ms: f64,
    pub dernier_ms: f64,
    /// Nombre de mesures par classe : ≤ 1, ≤ 5, ≤ 10, ≤ 50, ≤ 100, ≤ 500, ≤ 1000, ≤ 5000 ms, au-delà
    pub repartition: [u64; 9],
}

impl Stat {
    pub fn ajouter(&mut self, d: Duration) {
        let ms = d.as_secs_f64() * 1000.0;
        self.nombre += 1;
        self.total_ms += ms;
        self.dernier_ms = ms;
        if ms > self.max_ms {
            self.max_ms = ms;
        }
        let classe = SEUILS_MS.iter().position(|s| ms <= *s as f64).unwrap_or(SEUILS_MS.len());
        self.repartition[classe] += 1;
    }
}

#[derive(Clone, Default, Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Mesures {
    pub depuis: String,
    pub etapes: BTreeMap<String, Stat>,
    /// PowerShell lancés par le service, par contexte
    pub powershell: BTreeMap<String, u64>,
}

impl Mesures {
    fn nouvelles() -> Self {
        Mesures { depuis: commun::maintenant(), ..Default::default() }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Fichier<'a> {
    ecrit: String,
    cumul: &'a Mesures,
    fenetre: &'a Mesures,
}

fn etat() -> &'static Mutex<(Mesures, Mesures)> {
    static E: OnceLock<Mutex<(Mesures, Mesures)>> = OnceLock::new();
    E.get_or_init(|| Mutex::new((Mesures::nouvelles(), Mesures::nouvelles())))
}

/// Durée d'une étape (cumul et fenêtre)
pub fn duree(etape: &str, d: Duration) {
    if let Ok(mut e) = etat().lock() {
        e.0.etapes.entry(etape.to_string()).or_default().ajouter(d);
        e.1.etapes.entry(etape.to_string()).or_default().ajouter(d);
    }
}

/// Durée écoulée depuis `debut` ; renvoie l'instant présent, début de l'étape suivante
pub fn noter(etape: &str, debut: Instant) -> Instant {
    duree(etape, debut.elapsed());
    Instant::now()
}

/// Un PowerShell lancé par le service (contexte : module ou action)
pub fn powershell(contexte: &str) {
    if let Ok(mut e) = etat().lock() {
        *e.0.powershell.entry(contexte.to_string()).or_default() += 1;
        *e.1.powershell.entry(contexte.to_string()).or_default() += 1;
    }
}

/// Copie du cumul et de la fenêtre en cours (tests)
#[cfg(test)]
pub fn instantane() -> (Mesures, Mesures) {
    etat().lock().map(|e| (e.0.clone(), e.1.clone())).unwrap_or_default()
}

/// Écrit mesures.json (cumul et dernière fenêtre), puis ouvre une nouvelle fenêtre
pub fn ecrire() {
    let Ok(mut e) = etat().lock() else { return };
    let _ = commun::ecrire("mesures.json", &Fichier { ecrit: commun::maintenant(), cumul: &e.0, fenetre: &e.1 });
    e.1 = Mesures::nouvelles();
}
