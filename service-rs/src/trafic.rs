//! Analyse du trafic : débit, programmes, destinations, pays et ports, depuis minuit (trafic.json).
//! Le programme est retrouvé par le port local (tables TCP et UDP de Windows), le nom par le cache DNS
//! du service, le pays par geoip.rs.

use crate::capture::{Analyseur, Contexte, Paquet, TCP, UDP};
use crate::commun;
use crate::geoip::GeoIp;
use crate::moniteur::Partage;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "PascalCase", default)]
struct Point {
    heure: String,
    entrant: u64,
    sortant: u64,
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "PascalCase", default)]
struct LigneApplication {
    nom: String,
    entrant: u64,
    sortant: u64,
    destinations: usize,
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "PascalCase", default)]
struct LigneDestination {
    ip: String,
    nom: String,
    pays: String,
    programme: String,
    port: u16,
    entrant: u64,
    sortant: u64,
    /// Échange dans les 10 dernières secondes
    active: bool,
}

/// Ligne d'un pays. Champs T-19 (carte du trafic, lecture seulement) : absents des fichiers écrits avant, relus vides
#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "PascalCase", default)]
pub struct LignePays {
    pub code: String,
    pub entrant: u64,
    pub sortant: u64,
    pub destinations: usize,
    /// Noms des programmes (8 au plus), sans volume ; gardé tel quel pour les lecteurs existants
    pub programmes: Vec<String>,
    pub active: bool,
    /// T-19 : programmes du pays avec leurs octets depuis minuit, le plus gros d'abord (MAX_PROGRAMMES_PAYS au plus ;
    /// vide au-delà des MAX_PAYS_DETAILLES pays les plus gros)
    pub programmes_volumes: Vec<VolumeProgramme>,
    /// T-19 : destinations principales du pays, la plus grosse d'abord (MAX_DESTINATIONS_PAYS au plus ; vide au-delà
    /// des MAX_PAYS_DETAILLES pays les plus gros)
    pub destinations_principales: Vec<DestinationPays>,
    /// T-19 : débit récent du pays en octets par seconde, moyenne sur les deux dernières écritures (10 s environ)
    pub debit_entrant_recent: u64,
    pub debit_sortant_recent: u64,
}

/// T-19 : volume d'un programme dans un pays (nom comme dans `Applications` : nom, « System », « PID n » ou « ? »)
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "PascalCase", default)]
pub struct VolumeProgramme {
    pub nom: String,
    pub entrant: u64,
    pub sortant: u64,
}

/// T-19 : destination principale d'un pays ; mêmes champs que les lignes de `Destinations` (adresse distante publique,
/// nom tiré du cache DNS du service ou vide, programme comme dans `Applications`)
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "PascalCase", default)]
pub struct DestinationPays {
    pub ip: String,
    pub nom: String,
    pub programme: String,
    pub entrant: u64,
    pub sortant: u64,
}

/// T-19 : bornes de la carte, pour que trafic.json reste petit : 250 pays, dont 30 avec 10 programmes et 10 destinations.
/// Liste Pays : moins d'1 Mo au pire (noms DNS et de programmes de plus de 250 caractères, liste Programmes existante
/// comprise : environ 880 Ko mesurés par l'audit de #311, S311-01), quelques dizaines de Ko en pratique
pub const MAX_PAYS: usize = 250;
pub const MAX_PAYS_DETAILLES: usize = 30;
pub const MAX_PROGRAMMES_PAYS: usize = 10;
pub const MAX_DESTINATIONS_PAYS: usize = 10;
pub const MAX_PAYS_SIGNALES: usize = 50;

/// T-19 : une destination suivie, telle que la voit la décision des lignes de pays (pure)
pub struct VueDestination<'a> {
    pub ip: Ipv4Addr,
    /// Nom du cache DNS, ou vide
    pub nom: &'a str,
    /// Code pays, vide si inconnu (la destination n'entre alors dans aucun pays)
    pub pays: &'a str,
    pub programme: &'a str,
    pub entrant: u64,
    pub sortant: u64,
    /// Octets (entrant, sortant) échangés depuis l'avant-dernière écriture (`decaler_cliches`)
    pub recent: (u64, u64),
    pub active: bool,
}

/// T-19, décision pure : octets par seconde sur `duree` (une seconde au moins : jamais de division par zéro)
pub fn debit_recent(octets: u64, duree: Duration) -> u64 {
    let ms = duree.as_millis().max(1_000);
    u64::try_from(u128::from(octets) * 1_000 / ms).unwrap_or(u64::MAX)
}

/// T-19, décision pure : octets échangés depuis l'avant-dernière écriture (10 s environ), puis instantanés décalés.
/// Une destination nouvelle (instantanés à zéro) compte tout ce qu'elle a échangé ; jamais négatif
pub fn decaler_cliches(cliches: &mut [(u64, u64); 2], total: (u64, u64)) -> (u64, u64) {
    let recent = (total.0.saturating_sub(cliches[0].0), total.1.saturating_sub(cliches[0].1));
    cliches[0] = cliches[1];
    cliches[1] = total;
    recent
}

fn volume(e: u64, s: u64) -> u64 {
    e.saturating_add(s)
}

/// T-19, décision pure : lignes des pays qui ont du trafic, la plus grosse d'abord (MAX_PAYS au plus) ; champs
/// existants calculés comme avant, programmes avec volumes et destinations principales pour les MAX_PAYS_DETAILLES
/// plus gros, débit récent par pays sur `duree_recente`
pub fn lignes_pays(vues: &[VueDestination], duree_recente: Duration) -> Vec<LignePays> {
    let mut groupes: HashMap<&str, Vec<&VueDestination>> = HashMap::new();
    for v in vues.iter().filter(|v| !v.pays.is_empty()) {
        groupes.entry(v.pays).or_default().push(v);
    }
    let mut lignes: Vec<(LignePays, Vec<&VueDestination>)> = groupes.into_iter().map(|(code, mut ds)| {
        // La plus grosse d'abord (adresse à égalité) : ordre stable des listes
        ds.sort_by(|a, b| volume(b.entrant, b.sortant).cmp(&volume(a.entrant, a.sortant)).then_with(|| a.ip.cmp(&b.ip)));
        let mut l = LignePays { code: code.to_string(), destinations: ds.len(), ..Default::default() };
        let mut recent = (0u64, 0u64);
        for d in &ds {
            l.entrant = l.entrant.saturating_add(d.entrant);
            l.sortant = l.sortant.saturating_add(d.sortant);
            l.active |= d.active;
            if l.programmes.len() < 8 && !l.programmes.iter().any(|p| p == d.programme) {
                l.programmes.push(d.programme.to_string());
            }
            recent = (recent.0.saturating_add(d.recent.0), recent.1.saturating_add(d.recent.1));
        }
        l.debit_entrant_recent = debit_recent(recent.0, duree_recente);
        l.debit_sortant_recent = debit_recent(recent.1, duree_recente);
        (l, ds)
    }).collect();
    lignes.sort_by(|a, b| volume(b.0.entrant, b.0.sortant).cmp(&volume(a.0.entrant, a.0.sortant)).then_with(|| a.0.code.cmp(&b.0.code)));
    lignes.truncate(MAX_PAYS);
    for (l, ds) in lignes.iter_mut().take(MAX_PAYS_DETAILLES) {
        let mut programmes: HashMap<&str, (u64, u64)> = HashMap::new();
        for d in ds.iter() {
            let p = programmes.entry(d.programme).or_default();
            *p = (p.0.saturating_add(d.entrant), p.1.saturating_add(d.sortant));
        }
        let mut programmes: Vec<VolumeProgramme> = programmes.into_iter()
            .map(|(nom, (e, s))| VolumeProgramme { nom: nom.to_string(), entrant: e, sortant: s }).collect();
        programmes.sort_by(|a, b| volume(b.entrant, b.sortant).cmp(&volume(a.entrant, a.sortant)).then_with(|| a.nom.cmp(&b.nom)));
        programmes.truncate(MAX_PROGRAMMES_PAYS);
        l.programmes_volumes = programmes;
        l.destinations_principales = ds.iter().take(MAX_DESTINATIONS_PAYS).map(|d| DestinationPays {
            ip: d.ip.to_string(), nom: d.nom.to_string(), programme: d.programme.to_string(), entrant: d.entrant, sortant: d.sortant,
        }).collect();
    }
    lignes.into_iter().map(|(l, _)| l).collect()
}

/// T-19, décision pure : pays des connexions signalées par le moniteur (`moniteur::ips_signalees`), triés, sans doublon
/// ni pays inconnu, MAX_PAYS_SIGNALES au plus
pub fn pays_signales(ips: &[Ipv4Addr], pays: impl Fn(Ipv4Addr) -> Option<String>) -> Vec<String> {
    let mut v: Vec<String> = ips.iter().filter_map(|ip| pays(*ip)).filter(|c| !c.is_empty()).collect();
    v.sort();
    v.dedup();
    v.truncate(MAX_PAYS_SIGNALES);
    v
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "PascalCase", default)]
struct LignePort {
    port: String,
    octets: u64,
}

/// Trafic sans programme nommé, par raison (T-4) : code stable (`capture::NonAttribue::code`) et octets depuis minuit.
/// La somme des raisons HorsTcpUdp, SansPort et SansProprietaire est la ligne « ? » des programmes ; ProcessusTermine
/// est la somme des lignes « PID n »
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "PascalCase", default)]
pub struct LigneNonAttribue {
    pub raison: String,
    pub entrant: u64,
    pub sortant: u64,
}

/// Décision pure (T-4) : lignes publiées, raisons sans octet omises, la plus grosse d'abord (ordre fixe à égalité)
pub fn lignes_non_attribuees(compteurs: &[(u64, u64); 4]) -> Vec<LigneNonAttribue> {
    let mut v: Vec<LigneNonAttribue> = crate::capture::NonAttribue::TOUTES.iter().zip(compteurs)
        .filter(|(_, (e, s))| e.saturating_add(*s) > 0)
        .map(|(r, (e, s))| LigneNonAttribue { raison: r.code().into(), entrant: *e, sortant: *s })
        .collect();
    v.sort_by_key(|l| std::cmp::Reverse(l.entrant.saturating_add(l.sortant)));
    v
}

/// Compte les octets d'un paquet sans programme nommé dans la case de sa raison (pur ; compteurs saturés)
pub fn noter_non_attribue(compteurs: &mut [(u64, u64); 4], raison: crate::capture::NonAttribue, entrant: bool, octets: u64) {
    if let Some(c) = compteurs.get_mut(raison as usize) {
        if entrant { c.0 = c.0.saturating_add(octets) } else { c.1 = c.1.saturating_add(octets) }
    }
}

/// Contenu de trafic.json (relisible pour les tests : un champ absent, d'un fichier écrit avant, est relu vide)
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Etat {
    mis_a_jour: String,
    depuis: String,
    interface: String,
    debit_entrant: u64,
    debit_sortant: u64,
    total_entrant: u64,
    total_sortant: u64,
    paquets: u64,
    plages_geoip: usize,
    serie: Vec<Point>,
    applications: Vec<LigneApplication>,
    destinations: Vec<LigneDestination>,
    pays: Vec<LignePays>,
    ports: Vec<LignePort>,
    /// Trafic sans programme nommé, par raison (T-4) ; absent des fichiers écrits avant : liste vide
    non_attribue: Vec<LigneNonAttribue>,
    /// Pays des connexions signalées (T-19, `pays_signales`) ; absent des fichiers écrits avant : liste vide
    pays_signales: Vec<String>,
}

#[derive(Default)]
struct Destination {
    entrant: u64,
    sortant: u64,
    programme: String,
    port: u16,
    pays: Option<String>,
    derniere: Option<Instant>,
    /// Totaux (entrant, sortant) aux deux écritures précédentes de trafic.json, pour le débit récent (T-19)
    cliches: [(u64, u64); 2],
}

/// Nombre maximal de destinations suivies : au-delà de 5000, les 1000 plus petites sont retirées (toutes les 5 s) ;
/// aucune adresse nouvelle n'est acceptée au-delà de MAX_DESTINATIONS entre deux élagages
pub const MAX_DESTINATIONS: usize = 6000;

pub struct Trafic {
    partage: Arc<Partage>,
    geoip: Arc<RwLock<GeoIp>>,
    jour: String,
    depuis: String,
    interface: String,
    applications: HashMap<String, (u64, u64, HashSet<Ipv4Addr>)>,
    destinations: HashMap<Ipv4Addr, Destination>,
    ports: HashMap<String, u64>,
    /// Octets (entrant, sortant) sans programme nommé, dans l'ordre de `capture::NonAttribue::TOUTES` (T-4)
    non_attribue: [(u64, u64); 4],
    total: (u64, u64),
    paquets: u64,
    seconde: (u64, u64),
    fenetre: VecDeque<(u64, u64)>,
    serie: VecDeque<Point>,
    tics: u64,
    /// Instants des deux écritures précédentes : fenêtre du débit récent par pays (T-19)
    instants_cliches: [Instant; 2],
}

fn privee(ip: Ipv4Addr) -> bool {
    !crate::parefeu::publique(&IpAddr::V4(ip))
}

impl Trafic {
    pub fn nouveau(partage: Arc<Partage>) -> Trafic {
        let geoip = Arc::new(RwLock::new(GeoIp::default()));
        {
            // Chargement en arrière-plan, puis mise à jour chaque semaine
            let g = geoip.clone();
            std::thread::Builder::new().name("geoip".into()).spawn(move || loop {
                GeoIp::telecharger();
                let charge = GeoIp::charger();
                commun::journal(&format!("géolocalisation : {} plages d'adresses chargées (registres Internet régionaux)", charge.taille()));
                *g.write().unwrap() = charge;
                std::thread::sleep(Duration::from_secs(7 * 86_400));
            }).unwrap();
        }
        Trafic {
            partage,
            geoip,
            jour: String::new(),
            depuis: commun::maintenant(),
            interface: crate::capture::adresse_locale().map(|a| a.to_string()).unwrap_or_default(),
            applications: HashMap::new(),
            destinations: HashMap::new(),
            ports: HashMap::new(),
            non_attribue: [(0, 0); 4],
            total: (0, 0),
            paquets: 0,
            seconde: (0, 0),
            fenetre: VecDeque::new(),
            serie: VecDeque::new(),
            tics: 0,
            instants_cliches: [Instant::now(); 2],
        }
    }

    fn ecrire(&mut self) {
        let geo = self.geoip.read().unwrap();
        let dns = self.partage.dns.lock().unwrap().clone();
        let maintenant = Instant::now();
        let actif = |d: &Destination| d.derniere.map(|t| maintenant.duration_since(t) < Duration::from_secs(10)).unwrap_or(false);
        // Pays des destinations (calculé une fois par adresse, après chargement des plages)
        if geo.taille() > 0 {
            for (ip, d) in self.destinations.iter_mut() {
                if d.pays.is_none() {
                    d.pays = Some(geo.pays(*ip).unwrap_or_default());
                }
            }
        }
        // Débit récent (T-19) : octets depuis l'avant-dernière écriture, sur la durée mesurée depuis
        let duree_recente = maintenant.duration_since(self.instants_cliches[0]);
        self.instants_cliches = [self.instants_cliches[1], maintenant];
        let mut recents: HashMap<Ipv4Addr, (u64, u64)> = HashMap::with_capacity(self.destinations.len());
        for (ip, d) in self.destinations.iter_mut() {
            recents.insert(*ip, decaler_cliches(&mut d.cliches, (d.entrant, d.sortant)));
        }
        let vues: Vec<VueDestination> = self.destinations.iter().map(|(ip, d)| VueDestination {
            ip: *ip,
            nom: dns.get(&ip.to_string()).map(String::as_str).unwrap_or(""),
            pays: d.pays.as_deref().unwrap_or(""),
            programme: &d.programme,
            entrant: d.entrant,
            sortant: d.sortant,
            recent: recents.get(ip).copied().unwrap_or_default(),
            active: actif(d),
        }).collect();
        let pays = lignes_pays(&vues, duree_recente);
        drop(vues);
        // Pays des connexions signalées par le moniteur (T-19)
        let signalees = self.partage.ips_signalees.lock().unwrap().clone();

        let mut destinations: Vec<LigneDestination> = self.destinations.iter().map(|(ip, d)| LigneDestination {
            ip: ip.to_string(),
            nom: dns.get(&ip.to_string()).cloned().unwrap_or_default(),
            pays: d.pays.clone().unwrap_or_default(),
            programme: d.programme.clone(),
            port: d.port,
            entrant: d.entrant,
            sortant: d.sortant,
            active: actif(d),
        }).collect();
        destinations.sort_by_key(|d| std::cmp::Reverse(d.entrant + d.sortant));
        destinations.truncate(100);

        let mut applications: Vec<LigneApplication> = self.applications.iter()
            .map(|(nom, (e, s, ips))| LigneApplication { nom: nom.clone(), entrant: *e, sortant: *s, destinations: ips.len() }).collect();
        applications.sort_by_key(|a| std::cmp::Reverse(a.entrant + a.sortant));
        applications.truncate(30);

        let mut ports: Vec<LignePort> = self.ports.iter().map(|(p, o)| LignePort { port: p.clone(), octets: *o }).collect();
        ports.sort_by_key(|p| std::cmp::Reverse(p.octets));
        ports.truncate(15);

        let n = self.fenetre.len().max(1) as u64;
        let etat = Etat {
            mis_a_jour: commun::maintenant(),
            depuis: self.depuis.clone(),
            interface: self.interface.clone(),
            debit_entrant: self.fenetre.iter().map(|f| f.0).sum::<u64>() / n,
            debit_sortant: self.fenetre.iter().map(|f| f.1).sum::<u64>() / n,
            total_entrant: self.total.0,
            total_sortant: self.total.1,
            paquets: self.paquets,
            plages_geoip: geo.taille(),
            serie: self.serie.iter().cloned().collect(),
            applications,
            destinations,
            pays,
            ports,
            non_attribue: lignes_non_attribuees(&self.non_attribue),
            pays_signales: pays_signales(&signalees, |ip| geo.pays(ip)),
        };
        drop(geo);
        let _ = commun::ecrire("trafic.json", &etat);
    }
}

impl Analyseur for Trafic {
    fn paquet(&mut self, p: &Paquet, contexte: &Contexte) {
        let octets = p.longueur as u64;
        self.paquets += 1;
        if p.entrant {
            self.total.0 += octets;
            self.seconde.0 += octets;
        } else {
            self.total.1 += octets;
            self.seconde.1 += octets;
        }
        let (ip, port_distant, _) = p.distant();
        if privee(ip) {
            return;
        }
        let (programme, raison) = contexte.attribution(p);
        if let Some(r) = raison {
            noter_non_attribue(&mut self.non_attribue, r, p.entrant, octets);
        }
        let a = self.applications.entry(programme.clone()).or_default();
        if p.entrant { a.0 += octets } else { a.1 += octets }
        if a.2.len() < 2000 {
            a.2.insert(ip);
        }
        // Destinations bornées entre deux élagages : au-delà, une adresse nouvelle n'est comptée que dans les totaux
        // (des sources usurpées faisaient grossir la table jusqu'à minuit, audit AUD4-01)
        if !self.destinations.contains_key(&ip) && self.destinations.len() >= MAX_DESTINATIONS {
            return;
        }
        let d = self.destinations.entry(ip).or_default();
        if p.entrant { d.entrant += octets } else { d.sortant += octets }
        if d.programme.is_empty() || d.programme == "?" {
            d.programme = programme;
        }
        if d.port == 0 {
            d.port = port_distant;
        }
        d.derniere = Some(Instant::now());
        let nom_port = match p.proto {
            TCP => format!("TCP {port_distant}"),
            UDP => format!("UDP {port_distant}"),
            x => format!("IP proto {x}"),
        };
        *self.ports.entry(nom_port).or_default() += octets;
    }

    fn tic(&mut self) {
        self.tics += 1;
        self.fenetre.push_back(std::mem::take(&mut self.seconde));
        while self.fenetre.len() > 5 {
            self.fenetre.pop_front();
        }
        // Nouveau jour : les compteurs repartent de zéro
        let jour: String = commun::maintenant().chars().take(10).collect();
        if jour != self.jour {
            if !self.jour.is_empty() {
                self.applications.clear();
                self.destinations.clear();
                self.ports.clear();
                self.non_attribue = [(0, 0); 4];
                self.total = (0, 0);
                self.depuis = commun::maintenant();
            }
            self.jour = jour;
        }
        if self.tics % 5 == 0 {
            let n = self.fenetre.len().max(1) as u64;
            self.serie.push_back(Point {
                heure: commun::maintenant().chars().skip(11).collect(),
                entrant: self.fenetre.iter().map(|f| f.0).sum::<u64>() / n,
                sortant: self.fenetre.iter().map(|f| f.1).sum::<u64>() / n,
            });
            while self.serie.len() > 120 {
                self.serie.pop_front();
            }
            // Trop de destinations : on oublie les plus petites
            if self.destinations.len() > 5000 {
                let mut v: Vec<(Ipv4Addr, u64)> = self.destinations.iter().map(|(ip, d)| (*ip, d.entrant + d.sortant)).collect();
                v.sort_by_key(|x| x.1);
                for (ip, _) in v.into_iter().take(1000) {
                    self.destinations.remove(&ip);
                }
            }
            self.interface = crate::capture::adresse_locale().map(|a| a.to_string()).unwrap_or_default();
            self.ecrire();
        }
    }
}
