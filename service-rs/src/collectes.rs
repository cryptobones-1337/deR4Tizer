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
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::Mutex;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
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
    /// Capture des paquets de la route par défaut (trafic, DPI, IDS)
    CaptureTrafic,
    /// Capture des paquets du réseau local (NDR)
    CaptureReseauLocal,
}

use Collecte::*;

pub const TOUTES: [Collecte; 22] = [
    Connexions, Processus, Sysmon, WmiProcessus, JournalDns, JournalDefender, EtatDefender, JournalSecurite, AuditDonnees,
    JournalSysteme, JournalParefeu, PaquetsParefeu, Persistance, Baseline, ListesMenaces, ListesDomaines, Loldrivers, Leurres,
    Extensions, Peripheriques, CaptureTrafic, CaptureReseauLocal,
];

// TOUTES liste chaque collecte une fois, dans l'ordre de l'énumération : l'indice d'une case est son numéro. Une
// collecte ajoutée sans être mise dans TOUTES ne compile pas (elle ne partagerait jamais la case d'une autre).
const _: () = {
    assert!(TOUTES.len() == CaptureReseauLocal as usize + 1);
    let mut i = 0;
    while i < TOUTES.len() {
        assert!(TOUTES[i] as usize == i);
        i += 1;
    }
};

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
            CaptureTrafic => "CaptureTrafic",
            CaptureReseauLocal => "CaptureReseauLocal",
        }
    }

    /// Intervalle attendu entre deux lectures, en secondes ; muette plus de trois intervalles, la collecte est
    /// indisponible. 0 : source à événements (flux WMI), dont le silence n'est pas un échec ; sa fin est notée.
    pub fn periode(self) -> u64 {
        match self {
            // Journaux relus toutes les 2 s (evenements::abonner), table des connexions à chaque cycle : marge pour
            // un lot d'événements long à traiter
            Connexions | Sysmon | JournalDns | JournalDefender | JournalSecurite | JournalSysteme | JournalParefeu => 30,
            // Relus à chaque cycle de surveillance
            Processus | PaquetsParefeu | Leurres | Peripheriques => 30,
            // Capture : notée à chaque seconde (tic des analyseurs) ; réouverture toutes les 30 s en cas d'échec
            CaptureTrafic | CaptureReseauLocal => 60,
            WmiProcessus => 0,
            // Relevé des démarrages automatiques toutes les minutes (11 s au plus mesurées)
            Persistance => 120,
            // Fil « contrôles » : toutes les 10 min (relectures au démarrage du PC comprises, 10 min au plus)
            EtatDefender | Extensions | Baseline => 600,
            // Audit des données reposé toutes les heures ; listes rechargées toutes les heures
            AuditDonnees | ListesMenaces | ListesDomaines => 3600,
            Loldrivers => 86_400,
        }
    }

    fn index(self) -> usize {
        self as usize
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
        "EXP-IDS-001" | "EXP-DPI-001" => &[&[CaptureTrafic]],
        "EXP-NDR-001" => &[&[CaptureReseauLocal]],
        // RES-004, SYS-001, VIE-003, CHA… : lectures locales du service, non suivies ici ; INT-* : contrôles internes ;
        // COR-R6 : tiré des alertes elles-mêmes
        _ => &[],
    }
}

/// Décision pure (testée) : note d'un type de listes de menaces. Aucune source activée (réglage : listes à licence
/// restreinte coupées) : désactivée ; des sources activées sans aucune entrée chargée : indisponible, pas « aucune
/// menace connue ». Une copie locale ancienne compte comme chargée (son âge n'est pas suivi ici).
pub fn decision_listes(sources_actives: usize, entrees: usize) -> Note {
    if sources_actives == 0 {
        Note::Desactivee
    } else if entrees == 0 {
        Note::Indisponible
    } else {
        Note::Active
    }
}

/// Décision pure (testée) : note d'une lecture faite sur plusieurs éléments (dossiers audités, règles de la baseline) :
/// aucun élément à lire, désactivée ; aucun lu, indisponible ; une partie seulement, partielle ; tous, active
pub fn decision_comptes(lus: usize, en_echec: usize) -> Note {
    match (lus, en_echec) {
        (0, 0) => Note::Desactivee,
        (0, _) => Note::Indisponible,
        (_, 0) => Note::Active,
        _ => Note::Partielle,
    }
}

/// Note une lecture faite sur plusieurs éléments (`decision_comptes`) ; `quoi` nomme les éléments dans la raison
pub fn noter_comptes(c: Collecte, lus: usize, en_echec: usize, quoi: &str) {
    match decision_comptes(lus, en_echec) {
        Note::Desactivee => desactivee(c, &format!("aucun {quoi} à lire")),
        Note::Indisponible => echec(c, &format!("{en_echec} {quoi}(s), aucun lu")),
        Note::Partielle => partielle(c, &format!("{en_echec} {quoi}(s) sur {} non lu(s)", lus + en_echec)),
        _ => succes(c),
    }
}

/// La collecte est-elle lue maintenant (« Active ») ?
pub fn est_active(c: Collecte) -> bool {
    etat_a(c, maintenant()) == EtatPublie::Active
}

/// Listes chargées : adresses et réseaux (RES-001), domaines (DNS-001)
pub fn noter_listes(ip_actives: usize, ip_et_reseaux: usize, domaines_actives: usize, domaines: usize) {
    for (c, actives, n, quoi) in [(ListesMenaces, ip_actives, ip_et_reseaux, "adresse"), (ListesDomaines, domaines_actives, domaines, "domaine")] {
        match decision_listes(actives, n) {
            Note::Desactivee => desactivee(c, &format!("aucune liste de {quoi}s activée (listes à licence restreinte coupées)")),
            Note::Indisponible => echec(c, &format!("aucun {quoi} de menace chargé")),
            _ => succes(c),
        }
    }
}

// ------------------------------------------------------------ état global

struct Case {
    note: AtomicU8,
    dernier_succes: AtomicU64,
    depuis: AtomicU64,
    raison: Mutex<String>,
    /// Dernière ligne écrite dans journal.txt pour cette collecte, et changements tus depuis (une ligne par minute au
    /// plus : une collecte qui oscille ne chasse pas l'historique utile)
    journal: AtomicU64,
    tus: AtomicU32,
    /// Muette (plus de trois intervalles sans lecture réussie) au dernier relevé publié
    muette: AtomicBool,
}

#[allow(clippy::declare_interior_mutable_const)]
const CASE: Case = Case {
    note: AtomicU8::new(0),
    dernier_succes: AtomicU64::new(0),
    depuis: AtomicU64::new(0),
    raison: Mutex::new(String::new()),
    journal: AtomicU64::new(0),
    tus: AtomicU32::new(0),
    muette: AtomicBool::new(false),
};
static CASES: [Case; 22] = [CASE; 22];

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
    let mut message = None;
    {
        let mut r = case.raison.lock().unwrap_or_else(|e| e.into_inner());
        if avant != note || *r != raison {
            if avant != note {
                case.depuis.store(t, Ordering::Relaxed);
                message = Some(format!("{}{}", nom_note(note), if raison.is_empty() { String::new() } else { format!(" ({raison})") }));
            }
            *r = raison;
            case.note.store(note as u8, Ordering::Relaxed);
        }
    }
    // Hors du verrou : l'écriture dans journal.txt ne retient pas la publication
    if let Some(m) = message {
        journaliser(c, &m, t);
    }
}

/// Une ligne par collecte et par minute au plus ; les changements tus entre-temps sont comptés dans la ligne suivante
fn journaliser(c: Collecte, message: &str, t: u64) {
    let case = &CASES[c.index()];
    let avant = case.journal.load(Ordering::Relaxed);
    if avant != 0 && t.saturating_sub(avant) < 60 * 10_000_000 {
        case.tus.fetch_add(1, Ordering::Relaxed);
        return;
    }
    case.journal.store(t, Ordering::Relaxed);
    let tus = case.tus.swap(0, Ordering::Relaxed);
    let suite = if tus > 0 { format!(" ; {tus} changement(s) tu(s) dans la minute précédente") } else { String::new() };
    crate::commun::journal(&format!("collecte {} : {message}{suite}", c.id()));
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

/// Raison publiée : sans nom de compte (tout chemin de profil, où qu'il soit dans le texte : « C:\Users\… », « C:/Users/… »,
/// « \\?\C:\Users\… », « \Device\HarddiskVolumeN\Users\… », partage administratif « \\serveur\c$\Users\… » ; le nom va
/// jusqu'au séparateur suivant, espaces compris),
/// sans caractère de contrôle, 200 caractères au plus
pub fn borner(raison: &str) -> String {
    static PROFIL: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let profil = PROFIL.get_or_init(|| regex::Regex::new(r"(?i)(?:[a-z][:$]|\\device\\harddiskvolume\d+)[\\/]+users[\\/]+[^\\/]+").unwrap());
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
            let note = Note::depuis_u8(case.note.load(Ordering::Relaxed));
            let succes = case.dernier_succes.load(Ordering::Relaxed);
            // Muette : « Depuis » est la fin du délai de trois intervalles, et le passage est journalisé
            let muette = matches!(note, Note::Active | Note::Partielle) && matches!(e, EtatPublie::Indisponible(_));
            if case.muette.swap(muette, Ordering::Relaxed) != muette {
                journaliser(*c, if muette { e.raison() } else { "de nouveau lue" }, t);
            }
            let depuis = if muette { succes + 3 * c.periode() * 10_000_000 } else { case.depuis.load(Ordering::Relaxed) };
            // Changements tus et minute écoulée : l'état actuel est écrit, journal.txt ne reste pas sur un état périmé
            if case.tus.load(Ordering::Relaxed) > 0 && t.saturating_sub(case.journal.load(Ordering::Relaxed)) >= 60 * 10_000_000 {
                let r = e.raison();
                journaliser(*c, &format!("état actuel {}{}", e.nom(), if r.is_empty() { String::new() } else { format!(" ({r})") }), t);
            }
            EtatCollecte {
                id: c.id().into(),
                etat: e.nom().into(),
                depuis: heure(depuis),
                dernier_succes: heure(succes),
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
