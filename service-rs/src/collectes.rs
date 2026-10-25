//! État des collectes (phase 3, PR 3.3) : distinguer « rien de suspect » de « collecte indisponible ». Chaque source
//! de télémétrie (table des connexions, journaux, état de Defender, listes…) note ses lectures réussies ou en échec ;
//! `evaluer` en tire l'état publié et `couverture` dit, pour chaque règle du registre, si la télémétrie dont elle dépend
//! est lue. Une collecte jamais notée reste « Inconnue », qui ne vaut jamais « rien de suspect » (échec fermé de la
//! réassurance). Aucune alerte n'est levée quand une collecte tombe (décision D5 : phase 4).
//!
//! Un succès est une lecture réussie, pas un événement reçu : un journal sans nouvel événement reste actif tant que sa
//! lecture répond. Stockage en tableau fixe d'atomiques : rien ne croît avec le nombre d'événements, et un succès
//! répété (fil DNS, cycle) ne prend aucun verrou.

use serde::Serialize;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Mutex;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Collecte {
    Connexions,
    Processus,
    Sysmon,
    WmiProcessus,
    JournalDns,
    JournalDefender,
    EtatDefender,
    JournalSecurite,
    AuditDonnees,
    JournalSysteme,
    JournalParefeu,
    PaquetsParefeu,
    Persistance,
    Baseline,
    ListesMenaces,
    ListesDomaines,
    Loldrivers,
    Leurres,
    Extensions,
    Peripheriques,
    Capture,
}

use Collecte::*;

pub const TOUTES: [Collecte; 21] = [
    Connexions, Processus, Sysmon, WmiProcessus, JournalDns, JournalDefender, EtatDefender, JournalSecurite, AuditDonnees,
    JournalSysteme, JournalParefeu, PaquetsParefeu, Persistance, Baseline, ListesMenaces, ListesDomaines, Loldrivers, Leurres,
    Extensions, Peripheriques, Capture,
];

impl Collecte {
    pub fn id(self) -> &'static str {
        match self {
            Connexions => "Connexions",
            Processus => "Processus",
            Sysmon => "Sysmon",
            WmiProcessus => "WmiProcessus",
            JournalDns => "JournalDns",
            JournalDefender => "JournalDefender",
            EtatDefender => "EtatDefender",
            JournalSecurite => "JournalSecurite",
            AuditDonnees => "AuditDonnees",
            JournalSysteme => "JournalSysteme",
            JournalParefeu => "JournalParefeu",
            PaquetsParefeu => "PaquetsParefeu",
            Persistance => "Persistance",
            Baseline => "Baseline",
            ListesMenaces => "ListesMenaces",
            ListesDomaines => "ListesDomaines",
            Loldrivers => "Loldrivers",
            Leurres => "Leurres",
            Extensions => "Extensions",
            Peripheriques => "Peripheriques",
            Capture => "Capture",
        }
    }

    /// Intervalle attendu entre deux lectures, en secondes ; muette plus de trois intervalles, la collecte est
    /// indisponible. 0 : source à événements (flux WMI), dont le silence n'est pas un échec ; sa fin est notée.
    pub fn periode(self) -> u64 {
        match self {
            // Journaux relus toutes les 2 s (evenements::abonner), table des connexions à chaque cycle : marge pour
            // un lot d'événements long à traiter
            Connexions | Sysmon | JournalDns | JournalDefender | JournalSecurite | JournalSysteme | JournalParefeu => 30,
            WmiProcessus => 0,
            // Fil « contrôles » : toutes les 10 min (relectures au démarrage du PC comprises, 10 min au plus)
            EtatDefender | Extensions => 600,
            // Rechargées toutes les heures
            ListesMenaces | ListesDomaines => 3600,
            Loldrivers => 86_400,
            Processus | AuditDonnees | PaquetsParefeu | Persistance | Baseline | Leurres | Peripheriques | Capture => 600,
        }
    }

    fn index(self) -> usize {
        TOUTES.iter().position(|c| *c == self).unwrap_or(0)
    }
}

/// État noté par la source elle-même
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Note {
    Inconnue = 0,
    Active = 1,
    Indisponible = 2,
    Desactivee = 3,
    Partielle = 4,
}

impl Note {
    fn depuis_u8(n: u8) -> Note {
        match n {
            1 => Note::Active,
            2 => Note::Indisponible,
            3 => Note::Desactivee,
            4 => Note::Partielle,
            _ => Note::Inconnue,
        }
    }
}

/// État publié (décision pure `evaluer`)
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum EtatPublie {
    Inconnue,
    Active,
    Indisponible(String),
    Desactivee(String),
    Partielle(String),
}

impl EtatPublie {
    pub fn nom(&self) -> &'static str {
        match self {
            EtatPublie::Inconnue => "Inconnue",
            EtatPublie::Active => "Active",
            EtatPublie::Indisponible(_) => "Indisponible",
            EtatPublie::Desactivee(_) => "Desactivee",
            EtatPublie::Partielle(_) => "Partielle",
        }
    }

    pub fn raison(&self) -> &str {
        match self {
            EtatPublie::Indisponible(r) | EtatPublie::Desactivee(r) | EtatPublie::Partielle(r) => r,
            _ => "",
        }
    }
}

/// Décision pure : état publié d'une collecte d'après sa note, son dernier succès et son intervalle (FILETIME, unités
/// de 100 ns). Une collecte active ou partielle muette plus de trois intervalles devient indisponible.
pub fn evaluer(note: Note, raison: &str, dernier_succes: u64, periode: u64, maintenant: u64) -> EtatPublie {
    let muette = periode > 0 && maintenant.saturating_sub(dernier_succes) > 3 * periode * 10_000_000;
    match note {
        Note::Inconnue => EtatPublie::Inconnue,
        Note::Indisponible => EtatPublie::Indisponible(raison.to_string()),
        Note::Desactivee => EtatPublie::Desactivee(raison.to_string()),
        Note::Active | Note::Partielle if muette => {
            EtatPublie::Indisponible(format!("aucune lecture réussie depuis plus de {} s", 3 * periode))
        }
        Note::Active => EtatPublie::Active,
        Note::Partielle => EtatPublie::Partielle(raison.to_string()),
    }
}

/// Couverture d'une règle par ses collectes
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Couverture {
    Assuree,
    /// Lue, mais par une source partielle seulement
    Degradee,
    /// Au moins une télémétrie nécessaire n'est pas lue : l'absence d'alerte ne vaut pas « rien de suspect »
    Indisponible,
}

/// Décision pure : `besoins` est un ET de OU (chaque groupe doit avoir une source lue). Dans un groupe, une source
/// active suffit ; à défaut, une source partielle rend la règle dégradée ; sinon (inconnue, indisponible, désactivée)
/// la règle n'a pas de collecte. « Inconnue » compte comme indisponible : échec fermé de la réassurance.
pub fn couverture(besoins: &[&[Collecte]], etat: &dyn Fn(Collecte) -> EtatPublie) -> Couverture {
    let mut degradee = false;
    for groupe in besoins {
        let etats: Vec<EtatPublie> = groupe.iter().map(|c| etat(*c)).collect();
        if etats.contains(&EtatPublie::Active) {
            continue;
        }
        if etats.iter().any(|e| matches!(e, EtatPublie::Partielle(_))) {
            degradee = true;
            continue;
        }
        return Couverture::Indisponible;
    }
    if degradee { Couverture::Degradee } else { Couverture::Assuree }
}

/// Télémétrie dont dépend chaque règle du registre (docs/detection/regles.md, « Télémétrie »). Vide : aucune collecte
/// externe suivie (contrôles du service lui-même, empreinte du fichier hosts, adresses des cartes, registre).
pub fn besoins(regle: &str) -> &'static [&'static [Collecte]] {
    const PROCESSUS_CREES: &[Collecte] = &[Sysmon, WmiProcessus];
    const DNS: &[Collecte] = &[JournalDns, Sysmon];
    const SECURITE_OU_SYSTEME: &[Collecte] = &[JournalSecurite, JournalSysteme];
    match regle {
        "RES-001" => &[&[Connexions], &[ListesMenaces]],
        "RES-002" => &[&[Connexions], &[Processus]],
        "RES-003" | "RES-006" | "RES-007" => &[&[Connexions]],
        "RES-005" => &[&[PaquetsParefeu]],
        "DNS-001" => &[DNS, &[ListesDomaines]],
        "PRC-001" | "PRC-002" | "PRC-003" | "PRC-004" | "PRC-005" => &[PROCESSUS_CREES],
        "CHA-001" => &[&[Processus]],
        "PER-001" | "PER-002" => &[&[Persistance]],
        "DEF-001" | "DEF-002" | "DEF-003" | "DEF-004" | "DEF-005" | "DEF-006" | "DEF-007" | "DEF-008" | "DEF-009" => &[&[JournalDefender]],
        "DEF-010" | "DEF-011" | "DEF-012" => &[&[EtatDefender]],
        "LEU-001" => &[&[Leurres]],
        "LEU-002" => &[&[Leurres], &[JournalSecurite], &[AuditDonnees]],
        "VOL-001" => &[&[JournalSecurite], &[AuditDonnees]],
        "SYS-002" | "SYS-003" => &[&[JournalParefeu]],
        "PIL-001" => &[&[Loldrivers]],
        "EXT-001" => &[&[Extensions]],
        "VIE-001" => &[&[Peripheriques]],
        "VIE-002" => &[&[Processus]],
        "BAS-001" => &[&[Baseline]],
        "COR-R1" | "COR-R2" | "COR-R3" | "COR-R3b" | "COR-R9" => &[&[JournalSecurite]],
        "COR-R4" | "COR-R5" => &[SECURITE_OU_SYSTEME],
        "COR-R7" => &[&[JournalSecurite], &[JournalSysteme]],
        "COR-R10" => &[SECURITE_OU_SYSTEME, &[Loldrivers]],
        "EXP-IDS-001" | "EXP-DPI-001" | "EXP-NDR-001" => &[&[Capture]],
        // RES-004, SYS-001, VIE-003, CHA… : lectures locales du service, non suivies ici ; INT-* : contrôles internes ;
        // COR-R6 : tiré des alertes elles-mêmes
        _ => &[],
    }
}

/// Listes de menaces chargées : aucune adresse ni réseau, RES-001 est muette ; aucun domaine, DNS-001 l'est. Une
/// liste vide est une collecte indisponible, pas « aucune menace connue ».
pub fn noter_listes(ip_et_reseaux: usize, domaines: usize) {
    for (c, n, raison) in [(ListesMenaces, ip_et_reseaux, "aucune adresse de menace chargée"), (ListesDomaines, domaines, "aucun domaine de menace chargé")] {
        if n == 0 {
            echec(c, raison);
        } else {
            succes(c);
        }
    }
}

// ------------------------------------------------------------ état global

struct Case {
    note: AtomicU8,
    dernier_succes: AtomicU64,
    depuis: AtomicU64,
    raison: Mutex<String>,
}

#[allow(clippy::declare_interior_mutable_const)]
const CASE: Case = Case { note: AtomicU8::new(0), dernier_succes: AtomicU64::new(0), depuis: AtomicU64::new(0), raison: Mutex::new(String::new()) };
static CASES: [Case; 21] = [CASE; 21];

fn maintenant() -> u64 {
    crate::commun::filetime(std::time::SystemTime::now())
}

fn noter(c: Collecte, note: Note, raison: &str, succes: bool) {
    let case = &CASES[c.index()];
    let t = maintenant();
    if succes {
        case.dernier_succes.store(t, Ordering::Relaxed);
    }
    // Le verrou n'est pris qu'à un changement d'état (ou de raison) : un succès répété n'est qu'un store
    let avant = Note::depuis_u8(case.note.load(Ordering::Relaxed));
    if avant == note && (note == Note::Active || note == Note::Inconnue) {
        return;
    }
    let raison = borner(raison);
    let mut r = case.raison.lock().unwrap_or_else(|e| e.into_inner());
    if avant != note || *r != raison {
        if avant != note {
            case.depuis.store(t, Ordering::Relaxed);
            crate::commun::journal(&format!("collecte {} : {}{}", c.id(), nom_note(note), if raison.is_empty() { String::new() } else { format!(" ({raison})") }));
        }
        *r = raison;
        case.note.store(note as u8, Ordering::Relaxed);
    }
}

fn nom_note(n: Note) -> &'static str {
    match n {
        Note::Inconnue => "inconnue",
        Note::Active => "active",
        Note::Indisponible => "indisponible",
        Note::Desactivee => "désactivée",
        Note::Partielle => "partielle",
    }
}

/// Raison publiée : sans nom de compte (tout chemin de profil, où qu'il soit dans le texte), sans caractère de contrôle,
/// 200 caractères au plus
pub fn borner(raison: &str) -> String {
    static PROFIL: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let profil = PROFIL.get_or_init(|| regex::Regex::new(r"(?i)[a-z]:\\users\\[^\\\s]+").unwrap());
    profil.replace_all(raison, "%USERPROFILE%").chars().map(|c| if c.is_control() { '?' } else { c }).take(200).collect()
}

/// Lecture réussie
pub fn succes(c: Collecte) {
    noter(c, Note::Active, "", true);
}

/// Lecture impossible
pub fn echec(c: Collecte, raison: &str) {
    noter(c, Note::Indisponible, raison, false);
}

/// Source absente par choix ou par réglage (Sysmon non installé…)
pub fn desactivee(c: Collecte, raison: &str) {
    noter(c, Note::Desactivee, raison, false);
}

/// Lecture réussie mais incomplète
pub fn partielle(c: Collecte, raison: &str) {
    noter(c, Note::Partielle, raison, true);
}

fn etat_a(c: Collecte, t: u64) -> EtatPublie {
    let case = &CASES[c.index()];
    let note = Note::depuis_u8(case.note.load(Ordering::Relaxed));
    let raison = if matches!(note, Note::Active | Note::Inconnue) { String::new() } else { case.raison.lock().unwrap_or_else(|e| e.into_inner()).clone() };
    evaluer(note, &raison, case.dernier_succes.load(Ordering::Relaxed), c.periode(), t)
}

#[derive(Serialize, serde::Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct EtatCollecte {
    pub id: String,
    pub etat: String,
    pub depuis: String,
    pub dernier_succes: String,
    pub raison: String,
}

/// Publication dans etat.json : l'état de chaque collecte, les règles sans collecte et les règles dégradées
pub fn publier() -> (Vec<EtatCollecte>, Vec<String>, Vec<String>) {
    let t = maintenant();
    let etats: Vec<EtatPublie> = TOUTES.iter().map(|c| etat_a(*c, t)).collect();
    let heure = |f: u64| if f == 0 { String::new() } else { crate::commun::heure_filetime(f) };
    let collectes = TOUTES
        .iter()
        .zip(&etats)
        .map(|(c, e)| {
            let case = &CASES[c.index()];
            EtatCollecte {
                id: c.id().into(),
                etat: e.nom().into(),
                depuis: heure(case.depuis.load(Ordering::Relaxed)),
                dernier_succes: heure(case.dernier_succes.load(Ordering::Relaxed)),
                raison: e.raison().to_string(),
            }
        })
        .collect();
    let lire = |c: Collecte| etats[c.index()].clone();
    let (mut sans, mut degradees) = (Vec::new(), Vec::new());
    for r in crate::regles::REGLES {
        match couverture(besoins(r.id), &lire) {
            Couverture::Indisponible => sans.push(r.id.to_string()),
            Couverture::Degradee => degradees.push(r.id.to_string()),
            Couverture::Assuree => {}
        }
    }
    (collectes, sans, degradees)
}
