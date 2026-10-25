//! Inspection des paquets (DPI), en local uniquement, sur les paquets émis par ce PC :
//!   - TLS : nom du site demandé (SNI) et empreinte du client (JA3, comparée à la liste SSLBL d'abuse.ch) ;
//!   - HTTP en clair : hôte, chemin, agent ; identifiants en clair (Authorization: Basic, mot de passe envoyé) ;
//!   - DNS : noms demandés ; tunnel DNS (beaucoup de sous-domaines longs et aléatoires vers un même domaine) ;
//!   - protocoles en clair ou risqués vers Internet (Telnet, FTP, SMB).
//! Les noms (SNI, Host, DNS) sont comparés aux listes de domaines malveillants. État dans dpi.json.

use crate::capture::{Analyseur, Contexte, Paquet, TCP, UDP};
use crate::commun::{self, Alerte};
use crate::moniteur::Partage;
use md5::{Digest, Md5};
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};

const URL_JA3: &str = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv";

#[derive(Serialize, Clone, Default)]
#[serde(rename_all = "PascalCase")]
struct Session {
    heure: String,
    programme: String,
    ip: String,
    port: u16,
    nom: String,
    ja3: String,
    remarque: String,
}

#[derive(Serialize, Default)]
#[serde(rename_all = "PascalCase")]
struct Empreinte {
    ja3: String,
    nombre: usize,
    programmes: Vec<String>,
}

#[derive(Serialize, Default)]
#[serde(rename_all = "PascalCase")]
struct Etat {
    mis_a_jour: String,
    sessions_tls: usize,
    requetes_http: usize,
    requetes_dns: usize,
    empreintes_ja3_connues: usize,
    tls: Vec<Session>,
    http: Vec<Session>,
    dns: Vec<Session>,
    empreintes: Vec<Empreinte>,
}

pub struct Dpi {
    partage: Arc<Partage>,
    alertes: Arc<std::sync::Mutex<Vec<Alerte>>>,
    ja3_malveillants: Arc<RwLock<HashMap<String, String>>>,
    tls: VecDeque<Session>,
    http: VecDeque<Session>,
    dns: VecDeque<Session>,
    compteurs: (usize, usize, usize),
    /// Empreinte JA3 → (nombre, programmes)
    empreintes: HashMap<String, (usize, HashSet<String>)>,
    /// Domaine de base → (sous-domaines distincts, instant du premier)
    sous_domaines: HashMap<String, (HashSet<String>, Instant)>,
    deja: HashMap<String, Instant>,
    /// ClientHello en cours de réassemblage (découpé sur plusieurs segments TCP, par exemple avec ML-KEM) :
    /// (port local, adresse et port distants) → (octets reçus, début)
    partiels: HashMap<(u16, std::net::Ipv4Addr, u16), (Vec<u8>, Instant)>,
    tics: u64,
}

fn publique(ip: std::net::Ipv4Addr) -> bool {
    crate::parefeu::publique(&IpAddr::V4(ip))
}

impl Dpi {
    pub fn nouveau(partage: Arc<Partage>) -> Dpi {
        let ja3 = Arc::new(RwLock::new(HashMap::new()));
        {
            let j = ja3.clone();
            std::thread::Builder::new().name("ja3".into()).spawn(move || loop {
                let f = commun::dossier().join("menaces").join("ja3-sslbl.csv");
                let _ = std::fs::create_dir_all(commun::dossier().join("menaces"));
                let recent = std::fs::metadata(&f).and_then(|m| m.modified())
                    .map(|t| SystemTime::now().duration_since(t).unwrap_or_default() < Duration::from_secs(86_400)).unwrap_or(false);
                if !recent {
                    let _ = Command::new("curl.exe")
                        .args(["-q", "-sSL", "--fail", "--proto", "=https", "--proto-redir", "=https", "--max-filesize", "52428800",
                            "--max-time", "120", "-A", &format!("deR4Tizer/{}", commun::VERSION), "-o"])
                        .arg(&f).arg(URL_JA3).creation_flags(0x0800_0000).output();
                }
                // ja3_md5,Firstseen,Lastseen,Listingreason
                // Propriétaire contrôlé, comme tout fichier du dossier de données
                let carte: HashMap<String, String> = commun::lire_fichier_proprietaire(&f).unwrap_or_default().lines()
                    .filter(|l| !l.starts_with('#'))
                    .filter_map(|l| { let c: Vec<&str> = l.split(',').collect(); (c.len() >= 4 && c[0].len() == 32).then(|| (c[0].to_lowercase(), c[3].trim().to_string())) })
                    .collect();
                *j.write().unwrap() = carte;
                std::thread::sleep(Duration::from_secs(86_400));
            }).unwrap();
        }
        let alertes = partage.alertes_externes.clone();
        Dpi {
            partage,
            alertes,
            ja3_malveillants: ja3,
            tls: VecDeque::new(),
            http: VecDeque::new(),
            dns: VecDeque::new(),
            compteurs: (0, 0, 0),
            empreintes: HashMap::new(),
            sous_domaines: HashMap::new(),
            deja: HashMap::new(),
            partiels: HashMap::new(),
            tics: 0,
        }
    }

    fn alerter(&mut self, cle: String, niveau: &str, score: i32, programme: &str, ip: String, port: u16, destination: String, raisons: String, mitre: &str) {
        if self.deja.get(&cle).map(|t| t.elapsed() < Duration::from_secs(3600)).unwrap_or(false) {
            return;
        }
        self.deja.insert(cle, Instant::now());
        self.alertes.lock().unwrap().push(Alerte {
            regle: crate::regles::EXP_DPI_001.into(),
            id: commun::nouvel_id(),
            heure: commun::maintenant(),
            niveau: niveau.into(),
            score,
            processus: programme.into(),
            destination,
            ip: Some(ip),
            port,
            raisons: format!("{raisons}  [MITRE {mitre}]"),
            mitre: mitre.into(),
            ..Default::default()
        });
    }

    fn menace(&self, nom: &str) -> Option<String> {
        self.partage.menaces.read().unwrap().chercher_domaine(nom).map(|c| c.source)
    }

    fn noter(file: &mut VecDeque<Session>, s: Session) {
        file.push_front(s);
        file.truncate(200);
    }

    fn tls_brut(&mut self, donnees: &[u8], p: &Paquet, programme: &str) {
        let Some((sni, ja3)) = client_hello(donnees) else { return };
        self.compteurs.0 += 1;
        let (ip, port, _) = p.distant();
        if self.empreintes.len() >= 1000 && !self.empreintes.contains_key(&ja3) {
            self.empreintes.clear();
        }
        let e = self.empreintes.entry(ja3.clone()).or_default();
        e.0 += 1;
        if e.1.len() < 10 {
            e.1.insert(programme.to_string());
        }
        let mut remarque = String::new();
        let malveillant = self.ja3_malveillants.read().unwrap().get(&ja3).cloned();
        if let Some(raison) = malveillant {
            remarque = format!("empreinte JA3 malveillante : {raison}");
            self.alerter(format!("ja3|{ja3}|{programme}"), "Critique", 12, programme, ip.to_string(), port, sni.clone().unwrap_or(ip.to_string()),
                format!("le client TLS de {programme} a l'empreinte d'un logiciel malveillant connu ({raison}, JA3 {ja3}, liste SSLBL d'abuse.ch)"), "T1071.001");
        }
        if let Some(n) = sni.as_deref() {
            if let Some(source) = self.menace(n) {
                remarque = format!("domaine malveillant ({source})");
                self.alerter(format!("sni|{n}"), "Critique", 10, programme, ip.to_string(), port, n.to_string(),
                    format!("{programme} ouvre une connexion chiffrée vers {n}, listé par {source}"), "T1071.001");
            }
        }
        Self::noter(&mut self.tls, Session { heure: commun::maintenant(), programme: programme.into(), ip: ip.to_string(), port, nom: sni.unwrap_or_default(), ja3, remarque });
    }

    fn http(&mut self, p: &Paquet, programme: &str) {
        let c = p.charge;
        let methodes: [&[u8]; 7] = [b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH "];
        if !methodes.iter().any(|m| c.starts_with(m)) {
            return;
        }
        self.compteurs.1 += 1;
        let texte = String::from_utf8_lossy(&c[..c.len().min(4096)]);
        let mut lignes = texte.split("\r\n");
        let premiere = lignes.next().unwrap_or("");
        let chemin: String = premiere.split_whitespace().nth(1).unwrap_or("").chars().take(200).collect();
        let mut hote = String::new();
        let mut agent = String::new();
        let mut basic = false;
        for l in lignes.by_ref() {
            if l.is_empty() {
                break;
            }
            let Some((n, v)) = l.split_once(':') else { continue };
            match n.trim().to_ascii_lowercase().as_str() {
                "host" => hote = v.trim().to_string(),
                "user-agent" => agent = v.trim().chars().take(150).collect(),
                "authorization" if v.trim().to_ascii_lowercase().starts_with("basic") => basic = true,
                _ => {}
            }
        }
        let (ip, port, _) = p.distant();
        let corps = texte.split_once("\r\n\r\n").map(|x| x.1.to_lowercase()).unwrap_or_default();
        let mot_de_passe = premiere.starts_with("POST") && ["password=", "passwd=", "pwd=", "pass=", "motdepasse="].iter().any(|m| corps.contains(m));
        let mut remarque = String::new();
        if publique(ip) && (basic || mot_de_passe) {
            remarque = "identifiants en clair".into();
            self.alerter(format!("clair|{hote}"), "Alerte", 6, programme, ip.to_string(), port, hote.clone(),
                format!("{programme} envoie un {} sans chiffrement (HTTP) à {hote} : il peut être lu sur le réseau",
                    if basic { "identifiant (Authorization: Basic)" } else { "mot de passe" }), "T1552");
        }
        let nom_hote = hote.split(':').next().unwrap_or("").to_string();
        if let Some(source) = self.menace(&nom_hote) {
            remarque = format!("domaine malveillant ({source})");
            self.alerter(format!("http|{nom_hote}"), "Critique", 10, programme, ip.to_string(), port, nom_hote.clone(),
                format!("{programme} fait une requête HTTP vers {nom_hote}, listé par {source}"), "T1071.001");
        }
        let detail = if agent.is_empty() { chemin } else { format!("{chemin}  ({agent})") };
        Self::noter(&mut self.http, Session { heure: commun::maintenant(), programme: programme.into(), ip: ip.to_string(), port, nom: format!("{hote}{detail}"), ja3: String::new(), remarque });
    }

    fn dns(&mut self, p: &Paquet, programme: &str) {
        let m = p.charge;
        if m.len() < 13 || m[2] & 0x80 != 0 {
            return;
        }
        let Some(nom) = nom_question(m) else { return };
        self.compteurs.2 += 1;
        let (ip, port, _) = p.distant();
        let parties: Vec<&str> = nom.split('.').collect();
        // Tunnel DNS : nombreux sous-domaines longs et différents sous un même domaine
        if parties.len() >= 3 {
            let base = parties[parties.len() - 2..].join(".");
            let sous = parties[..parties.len() - 2].join(".");
            if sous.len() >= 25 && entropie(&sous) > 3.5 {
                if self.sous_domaines.len() > 2000 && !self.sous_domaines.contains_key(&base) {
                    self.sous_domaines.retain(|_, (_, t)| t.elapsed() < Duration::from_secs(300));
                    if self.sous_domaines.len() > 2000 {
                        return;
                    }
                }
                let e = self.sous_domaines.entry(base.clone()).or_insert_with(|| (HashSet::new(), Instant::now()));
                if e.1.elapsed() > Duration::from_secs(300) {
                    *e = (HashSet::new(), Instant::now());
                }
                if e.0.len() < 500 {
                    e.0.insert(sous);
                }
                let n = e.0.len();
                if n >= 30 {
                    self.alerter(format!("tunnel|{base}"), "Alerte", 7, programme, ip.to_string(), port, base.clone(),
                        format!("{programme} envoie {n} requêtes DNS aux sous-domaines longs et aléatoires de {base} en moins de 5 minutes : tunnel DNS (exfiltration ou contrôle à distance)"), "T1071.004");
                }
            }
        }
        if let Some(source) = self.menace(&nom) {
            self.alerter(format!("dns|{nom}"), "Alerte", 6, programme, ip.to_string(), port, nom.clone(),
                format!("{programme} demande l'adresse de {nom}, listé par {source}"), "T1071.004");
        }
        Self::noter(&mut self.dns, Session { heure: commun::maintenant(), programme: programme.into(), ip: ip.to_string(), port, nom, ja3: String::new(), remarque: String::new() });
    }

    fn ecrire(&self) {
        let mut empreintes: Vec<Empreinte> = self.empreintes.iter()
            .map(|(j, (n, p))| Empreinte { ja3: j.clone(), nombre: *n, programmes: p.iter().cloned().collect() }).collect();
        empreintes.sort_by_key(|e| std::cmp::Reverse(e.nombre));
        empreintes.truncate(50);
        let _ = commun::ecrire("dpi.json", &Etat {
            mis_a_jour: commun::maintenant(),
            sessions_tls: self.compteurs.0,
            requetes_http: self.compteurs.1,
            requetes_dns: self.compteurs.2,
            empreintes_ja3_connues: self.ja3_malveillants.read().unwrap().len(),
            tls: self.tls.iter().cloned().collect(),
            http: self.http.iter().cloned().collect(),
            dns: self.dns.iter().take(100).cloned().collect(),
            empreintes,
        });
    }
}

impl Analyseur for Dpi {
    fn paquet(&mut self, p: &Paquet, contexte: &Contexte) {
        if p.entrant {
            return;
        }
        let (ip, port, _) = p.distant();
        // Protocoles en clair ou risqués vers Internet (une fois par heure et par destination)
        if p.proto == TCP && p.drapeaux & 0x12 == 0x02 && publique(ip) {
            let (niveau, score, quoi, mitre) = match port {
                445 | 139 => ("Alerte", 6, "partage de fichiers Windows (SMB) directement sur Internet : fuite possible du hachage du mot de passe", "T1187"),
                23 => ("Alerte", 4, "Telnet (non chiffré) vers Internet", "T1021"),
                21 => ("Info", 0, "FTP (non chiffré) vers Internet", "T1048.003"),
                _ => ("", 0, "", ""),
            };
            if !niveau.is_empty() {
                let programme = contexte.programme(p);
                self.alerter(format!("port|{ip}|{port}"), niveau, score, &programme, ip.to_string(), port, format!("{ip}:{port}"),
                    format!("{programme} : {quoi} ({ip}:{port})"), mitre);
            }
        }
        if p.charge.is_empty() {
            return;
        }
        match p.proto {
            TCP if p.charge[0] == 0x16 || self.partiels.contains_key(&(p.port_source, p.destination, p.port_destination)) => {
                // Longueur annoncée par l'enregistrement TLS : le ClientHello peut tenir sur plusieurs segments
                let cle = (p.port_source, p.destination, p.port_destination);
                let mut donnees = match self.partiels.remove(&cle) {
                    Some((mut d, _)) => {
                        d.extend_from_slice(p.charge);
                        d
                    }
                    None => p.charge.to_vec(),
                };
                let attendu = if donnees.len() >= 5 && donnees[0] == 0x16 { 5 + u16::from_be_bytes([donnees[3], donnees[4]]) as usize } else { 0 };
                if attendu > donnees.len() && attendu <= 16_384 + 5 {
                    if self.partiels.len() >= 500 {
                        self.partiels.retain(|_, (_, t)| t.elapsed() < Duration::from_secs(5));
                    }
                    if self.partiels.len() < 500 {
                        self.partiels.insert(cle, (std::mem::take(&mut donnees), Instant::now()));
                    }
                    return;
                }
                let programme = contexte.programme(p);
                self.tls_brut(&donnees, p, &programme);
            }
            TCP if p.charge[0].is_ascii_uppercase() => self.http(p, &contexte.programme(p)),
            UDP if port == 53 => self.dns(p, &contexte.programme(p)),
            _ => {}
        }
    }

    fn tic(&mut self) {
        self.tics += 1;
        if self.tics % 5 == 0 {
            self.deja.retain(|_, t| t.elapsed() < Duration::from_secs(3600));
            self.partiels.retain(|_, (_, t)| t.elapsed() < Duration::from_secs(5));
            self.ecrire();
        }
    }
}

// ------------------------------------------------------------ décodage

fn entropie(s: &str) -> f64 {
    let mut n = [0usize; 256];
    for b in s.bytes() {
        n[b as usize] += 1;
    }
    let l = s.len() as f64;
    n.iter().filter(|&&c| c > 0).map(|&c| { let p = c as f64 / l; -p * p.log2() }).sum()
}

fn nom_question(m: &[u8]) -> Option<String> {
    let mut p = 12;
    let mut parties = Vec::new();
    while p < m.len() && m[p] != 0 && parties.len() < 40 {
        let l = m[p] as usize;
        if l & 0xC0 != 0 || p + 1 + l > m.len() {
            return None;
        }
        parties.push(String::from_utf8_lossy(&m[p + 1..p + 1 + l]).to_lowercase());
        p += 1 + l;
    }
    (!parties.is_empty()).then(|| parties.join("."))
}

/// Valeurs GREASE (RFC 8701) : ignorées par JA3
fn grease(v: u16) -> bool {
    v & 0x0F0F == 0x0A0A && (v >> 8) == (v & 0xFF)
}

/// Message TLS ClientHello : (SNI, empreinte JA3 en MD5)
fn client_hello(d: &[u8]) -> Option<(Option<String>, String)> {
    // Enregistrement TLS : type 22, puis message de négociation de type 1 (ClientHello)
    if d.len() < 43 || d[0] != 0x16 || d[5] != 0x01 {
        return None;
    }
    let u16_ = |p: usize| -> Option<u16> { Some(u16::from_be_bytes([*d.get(p)?, *d.get(p + 1)?])) };
    let version = u16_(9)?;
    let mut p = 11 + 32;
    let lsession = *d.get(p)? as usize;
    p += 1 + lsession;
    let lchiffres = u16_(p)? as usize;
    p += 2;
    let chiffres: Vec<u16> = (0..lchiffres / 2).filter_map(|i| u16_(p + 2 * i)).filter(|v| !grease(*v)).collect();
    p += lchiffres;
    let lcompression = *d.get(p)? as usize;
    p += 1 + lcompression;
    let mut extensions = Vec::new();
    let mut courbes = Vec::new();
    let mut formats = Vec::new();
    let mut sni = None;
    if let Some(lext) = u16_(p) {
        p += 2;
        let fin = (p + lext as usize).min(d.len());
        while p + 4 <= fin {
            let (t, l) = (u16_(p)?, u16_(p + 2)? as usize);
            let donnees = d.get(p + 4..(p + 4 + l).min(d.len()))?;
            if !grease(t) {
                extensions.push(t);
            }
            match t {
                0 if donnees.len() > 5 && donnees[2] == 0 => {
                    let ln = u16::from_be_bytes([donnees[3], donnees[4]]) as usize;
                    if let Some(n) = donnees.get(5..5 + ln) {
                        sni = Some(String::from_utf8_lossy(n).to_lowercase());
                    }
                }
                10 if donnees.len() >= 2 => {
                    courbes = donnees[2..].chunks(2).filter(|c| c.len() == 2).map(|c| u16::from_be_bytes([c[0], c[1]])).filter(|v| !grease(*v)).collect();
                }
                11 if !donnees.is_empty() => formats = donnees[1..].to_vec(),
                _ => {}
            }
            p += 4 + l;
        }
    }
    let liste = |v: &[u16]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("-");
    let chaine = format!("{version},{},{},{},{}", liste(&chiffres), liste(&extensions), liste(&courbes),
        formats.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("-"));
    let empreinte = Md5::digest(chaine.as_bytes()).iter().map(|o| format!("{o:02x}")).collect();
    Some((sni, empreinte))
}

#[cfg(test)]
pub fn client_hello_test(d: &[u8]) -> Option<(Option<String>, String)> {
    client_hello(d)
}

#[cfg(test)]
pub fn nom_question_test(m: &[u8]) -> Option<String> {
    nom_question(m)
}
