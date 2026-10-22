//! Analyse du trafic : débit, programmes, destinations, pays et ports, depuis minuit (trafic.json).
//! Le programme est retrouvé par le port local (tables TCP et UDP de Windows), le nom par le cache DNS
//! du service, le pays par geoip.rs.

use crate::capture::{Analyseur, Contexte, Paquet, TCP, UDP};
use crate::commun;
use crate::geoip::GeoIp;
use crate::moniteur::Partage;
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

#[derive(Serialize, Default, Clone)]
#[serde(rename_all = "PascalCase")]
struct Point {
    heure: String,
    entrant: u64,
    sortant: u64,
}

#[derive(Serialize, Default, Clone)]
#[serde(rename_all = "PascalCase")]
struct LigneApplication {
    nom: String,
    entrant: u64,
    sortant: u64,
    destinations: usize,
}

#[derive(Serialize, Default, Clone)]
#[serde(rename_all = "PascalCase")]
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

#[derive(Serialize, Default, Clone)]
#[serde(rename_all = "PascalCase")]
struct LignePays {
    code: String,
    entrant: u64,
    sortant: u64,
    destinations: usize,
    programmes: Vec<String>,
    active: bool,
}

#[derive(Serialize, Default, Clone)]
#[serde(rename_all = "PascalCase")]
struct LignePort {
    port: String,
    octets: u64,
}

#[derive(Serialize, Default)]
#[serde(rename_all = "PascalCase")]
struct Etat {
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
}

#[derive(Default)]
struct Destination {
    entrant: u64,
    sortant: u64,
    programme: String,
    port: u16,
    pays: Option<String>,
    derniere: Option<Instant>,
}

pub struct Trafic {
    partage: Arc<Partage>,
    geoip: Arc<RwLock<GeoIp>>,
    jour: String,
    depuis: String,
    interface: String,
    applications: HashMap<String, (u64, u64, HashSet<Ipv4Addr>)>,
    destinations: HashMap<Ipv4Addr, Destination>,
    ports: HashMap<String, u64>,
    total: (u64, u64),
    paquets: u64,
    seconde: (u64, u64),
    fenetre: VecDeque<(u64, u64)>,
    serie: VecDeque<Point>,
    tics: u64,
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
            total: (0, 0),
            paquets: 0,
            seconde: (0, 0),
            fenetre: VecDeque::new(),
            serie: VecDeque::new(),
            tics: 0,
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
        let mut pays: HashMap<String, LignePays> = HashMap::new();
        for (ip, d) in &self.destinations {
            let code = d.pays.clone().unwrap_or_default();
            if code.is_empty() {
                continue;
            }
            let l = pays.entry(code.clone()).or_insert_with(|| LignePays { code, ..Default::default() });
            l.entrant += d.entrant;
            l.sortant += d.sortant;
            l.destinations += 1;
            l.active |= actif(d);
            if !l.programmes.contains(&d.programme) && l.programmes.len() < 8 {
                l.programmes.push(d.programme.clone());
            }
            let _ = ip;
        }
        let mut pays: Vec<LignePays> = pays.into_values().collect();
        pays.sort_by_key(|p| std::cmp::Reverse(p.entrant + p.sortant));

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
        };
        drop(geo);
        commun::ecrire("trafic.json", &etat);
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
        let programme = contexte.programme(p);
        let a = self.applications.entry(programme.clone()).or_default();
        if p.entrant { a.0 += octets } else { a.1 += octets }
        if a.2.len() < 2000 {
            a.2.insert(ip);
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
