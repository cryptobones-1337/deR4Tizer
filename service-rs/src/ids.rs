//! Détection d'intrusion (IDS) et prévention (IPS) sur les paquets capturés, avec des règles au format
//! Suricata / Snort : règles intégrées + fichiers *.rules du dossier regles\ (par exemple Emerging Threats
//! Open). Sous-ensemble pris en charge :
//!   en-tête   action (alert, drop, reject, pass) proto (tcp, udp, icmp, ip, http, tls, dns…) adresses, ports,
//!             variables $HOME_NET, $EXTERNAL_NET, $HTTP_PORTS… ; listes, plages, négations
//!   options   msg, content (|hex|, négation), nocase, offset, depth, distance, within, flags, dsize, sid,
//!             priority, classtype ; flow, metadata, reference, http_* et tampons http.* sont acceptés
//!             (le contenu est cherché dans toute la charge utile)
//! Une règle qui utilise une option non prise en charge (pcre, byte_test…) est ignorée plutôt que mal
//! appliquée. Les motifs sont cherchés en une passe (Aho-Corasick). En mode IPS (réglage), une règle
//! « drop » ou de priorité 1 bloque l'adresse distante au pare-feu, seulement pour une connexion TCP établie
//! (adresse non usurpable) et pour 7 jours.

use crate::capture::{Analyseur, Contexte, Paquet, TCP, UDP};
use crate::commun::{self, Alerte};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Règles intégrées : signatures génériques, sans faux positif courant
pub(crate) const REGLES_INTEGREES: &str = r#"
alert udp any any -> any any (msg:"deR4Tizer : paquet de test de l'IDS"; content:"deR4Tizer-test-IDS-7f3a"; priority:3; classtype:misc-activity; sid:9000000; rev:1;)
alert tcp any any -> any any (msg:"Fichier de test antivirus EICAR transféré en clair"; content:"X5O!P%@AP[4|5c|PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"; priority:2; classtype:misc-activity; sid:9000001; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Tentative Log4Shell (JNDI) reçue"; content:"${jndi:"; nocase; priority:1; classtype:attempted-admin; sid:9000010; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Tentative Shellshock reçue"; content:"() {"; content:"};"; distance:0; priority:1; classtype:attempted-admin; sid:9000011; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Remontée de répertoires (../) reçue"; content:"../../../../"; priority:2; classtype:web-application-attack; sid:9000012; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Scanner de vulnérabilités sqlmap"; content:"User-Agent: sqlmap"; nocase; priority:2; classtype:web-application-attack; sid:9000013; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Scanner Nmap (moteur de scripts)"; content:"Nmap Scripting Engine"; nocase; priority:2; classtype:attempted-recon; sid:9000014; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Scanner Nikto"; content:"Nikto"; nocase; content:"User-Agent"; nocase; priority:2; classtype:attempted-recon; sid:9000015; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Script PowerShell de téléchargement reçu en clair"; content:"Net.WebClient"; nocase; content:"Download"; nocase; distance:0; priority:1; classtype:trojan-activity; sid:9000020; rev:1;)
alert tcp any any -> any any (msg:"Commande Mimikatz transférée en clair"; content:"sekurlsa::"; nocase; priority:1; classtype:trojan-activity; sid:9000021; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Minage de cryptomonnaie (protocole Stratum)"; content:"mining.subscribe"; priority:2; classtype:policy-violation; sid:9000030; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Mineur XMRig"; content:"\"agent\":\"XMRig"; nocase; priority:2; classtype:policy-violation; sid:9000031; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET [9001,9030,9050,9150] (msg:"Connexion vers un port usuel du réseau Tor"; flags:S; priority:3; classtype:policy-violation; sid:9000040; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET 3389 (msg:"Bureau à distance (RDP) sollicité depuis Internet"; flags:S; priority:2; classtype:attempted-admin; sid:9000041; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET [22,23,5900] (msg:"Accès à distance (SSH, Telnet, VNC) sollicité depuis Internet"; flags:S; priority:2; classtype:attempted-admin; sid:9000042; rev:1;)
"#;

#[derive(Clone, Debug)]
enum Adresses {
    Toutes,
    Liste(Vec<(u32, u32)>, bool),
}

#[derive(Clone, Debug)]
enum Ports {
    Tous,
    Liste(Vec<(u16, u16)>, bool),
}

#[derive(Clone, Debug, Default)]
struct Contenu {
    motif: Vec<u8>,
    nocase: bool,
    negation: bool,
    offset: Option<usize>,
    depth: Option<usize>,
    distance: Option<i64>,
    within: Option<usize>,
}

#[derive(Clone, Debug)]
struct Regle {
    action: String,
    proto: Option<u8>,
    source: (Adresses, Ports),
    destination: (Adresses, Ports),
    bidirectionnelle: bool,
    msg: String,
    sid: u64,
    priorite: u8,
    classe: String,
    contenus: Vec<Contenu>,
    syn: bool,
    dsize: Option<(usize, usize)>,
    fichier: String,
}

#[derive(Serialize, Clone, Default)]
#[serde(rename_all = "PascalCase")]
struct Detection {
    heure: String,
    sid: u64,
    message: String,
    classe: String,
    niveau: String,
    source: String,
    destination: String,
    programme: String,
    bloque: bool,
}

#[derive(Serialize, Default)]
#[serde(rename_all = "PascalCase")]
struct Etat {
    mis_a_jour: String,
    regles: usize,
    ignorees: usize,
    fichiers: Vec<String>,
    ips: bool,
    paquets_analyses: u64,
    detections: Vec<Detection>,
}

pub struct Ids {
    regles: Vec<Regle>,
    sans_contenu: Vec<usize>,
    automate: Option<AhoCorasick>,
    /// Numéro de motif Aho-Corasick → règle
    motif_regle: Vec<usize>,
    ignorees: usize,
    fichiers: Vec<String>,
    alertes: Arc<Mutex<Vec<Alerte>>>,
    blocages: Arc<Mutex<Vec<(String, String)>>>,
    detections: VecDeque<Detection>,
    deja: HashMap<(u64, Ipv4Addr), Instant>,
    ips: bool,
    paquets: u64,
    tics: u64,
}

// ------------------------------------------------------------ lecture des règles

fn plage_ip(t: &str) -> Option<(u32, u32)> {
    let (ip, masque) = t.split_once('/').unwrap_or((t, "32"));
    let ip: Ipv4Addr = ip.parse().ok()?;
    let m: u32 = masque.parse().ok().filter(|m| *m <= 32)?;
    let masque = if m == 0 { 0 } else { u32::MAX << (32 - m) };
    let d = u32::from(ip) & masque;
    Some((d, d | !masque))
}

const RESEAUX_LOCAUX: &[&str] = &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10"];

fn adresses(t: &str) -> Option<Adresses> {
    let (t, negation) = match t.strip_prefix('!') { Some(r) => (r, true), None => (t, false) };
    let t = t.trim_start_matches('[').trim_end_matches(']');
    if t == "any" {
        return Some(if negation { Adresses::Liste(vec![], false) } else { Adresses::Toutes });
    }
    let mut plages = Vec::new();
    let mut neg = negation;
    for partie in t.split(',') {
        match partie.trim() {
            "$HOME_NET" => plages.extend(RESEAUX_LOCAUX.iter().filter_map(|r| plage_ip(r))),
            "$EXTERNAL_NET" | "!$HOME_NET" => {
                plages.extend(RESEAUX_LOCAUX.iter().filter_map(|r| plage_ip(r)));
                neg = !neg;
            }
            p if p.starts_with('$') => return Some(Adresses::Toutes),
            p => plages.push(plage_ip(p)?),
        }
    }
    Some(Adresses::Liste(plages, neg))
}

fn ports(t: &str) -> Option<Ports> {
    let (t, negation) = match t.strip_prefix('!') { Some(r) => (r, true), None => (t, false) };
    let t = t.trim_start_matches('[').trim_end_matches(']');
    if t == "any" {
        return Some(Ports::Tous);
    }
    let mut l = Vec::new();
    for p in t.split(',') {
        let p = p.trim();
        match p {
            "$HTTP_PORTS" => l.extend([(80, 80), (8080, 8080), (8000, 8000), (8008, 8008), (8888, 8888)]),
            "$SSH_PORTS" => l.push((22, 22)),
            "$FILE_DATA_PORTS" => l.extend([(80, 80), (110, 110), (143, 143)]),
            "$ORACLE_PORTS" => l.push((1521, 1521)),
            v if v.starts_with('$') => return Some(Ports::Tous),
            v => match v.split_once(':') {
                Some((a, b)) => l.push((a.parse().unwrap_or(0), b.parse().unwrap_or(u16::MAX))),
                None => {
                    let n: u16 = v.parse().ok()?;
                    l.push((n, n));
                }
            },
        }
    }
    Some(Ports::Liste(l, negation))
}

/// Contenu Suricata : texte avec |41 42| en hexadécimal et \" \; \\ échappés
fn contenu(t: &str) -> Vec<u8> {
    let mut sortie = Vec::new();
    let mut hex = false;
    let mut chars = t.chars().peekable();
    let mut tampon_hex = String::new();
    while let Some(c) = chars.next() {
        match c {
            '|' => {
                if hex {
                    for o in tampon_hex.split_whitespace() {
                        if let Ok(b) = u8::from_str_radix(o, 16) {
                            sortie.push(b);
                        }
                    }
                    tampon_hex.clear();
                }
                hex = !hex;
            }
            _ if hex => tampon_hex.push(c),
            '\\' => {
                if let Some(n) = chars.next() {
                    let mut b = [0u8; 4];
                    sortie.extend_from_slice(n.encode_utf8(&mut b).as_bytes());
                }
            }
            _ => {
                let mut b = [0u8; 4];
                sortie.extend_from_slice(c.encode_utf8(&mut b).as_bytes());
            }
        }
    }
    sortie
}

/// Découpe « clé:valeur; clé; … » en tenant compte des guillemets et des échappements
fn options(t: &str) -> Vec<(String, String)> {
    let mut l = Vec::new();
    let (mut courant, mut guillemets, mut echappe) = (String::new(), false, false);
    for c in t.chars() {
        if echappe {
            courant.push('\\');
            courant.push(c);
            echappe = false;
            continue;
        }
        match c {
            '\\' => echappe = true,
            '"' => {
                guillemets = !guillemets;
                courant.push(c);
            }
            ';' if !guillemets => {
                let o = courant.trim().to_string();
                if !o.is_empty() {
                    let (k, v) = o.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())).unwrap_or((o.clone(), String::new()));
                    l.push((k, v));
                }
                courant.clear();
            }
            _ => courant.push(c),
        }
    }
    l
}

fn sans_guillemets(v: &str) -> &str {
    v.trim().trim_start_matches('!').trim().trim_matches('"')
}

const OPTIONS_IGNOREES: &[&str] = &[
    "flow", "metadata", "reference", "rev", "target", "threshold", "detection_filter", "fast_pattern", "gid", "flowbits",
    "http_uri", "http_raw_uri", "http_header", "http_raw_header", "http_client_body", "http_server_body", "http_method",
    "http_cookie", "http_user_agent", "http_host", "http_stat_code", "http_stat_msg", "file_data", "pkt_data", "tag",
    "app-layer-event", "noalert", "nocase_fast", "bsize",
];

fn lire_regle(ligne: &str, fichier: &str) -> Result<Option<Regle>, ()> {
    let ligne = ligne.trim();
    if ligne.is_empty() || ligne.starts_with('#') {
        return Ok(None);
    }
    let (entete, opts) = ligne.split_once('(').ok_or(())?;
    let opts = opts.trim_end().strip_suffix(')').ok_or(())?;
    let e: Vec<&str> = entete.split_whitespace().collect();
    if e.len() < 7 {
        return Err(());
    }
    let action = e[0].to_string();
    if !["alert", "drop", "reject", "pass"].contains(&action.as_str()) {
        return Err(());
    }
    let proto = match e[1] {
        "tcp" | "http" | "http1" | "http2" | "tls" | "ssh" | "smb" | "ftp" | "smtp" | "imap" | "pop3" | "rdp" | "dcerpc" | "ftp-data" => Some(TCP),
        "udp" | "dns" | "ntp" | "dhcp" | "snmp" | "tftp" | "sip" => Some(UDP),
        "icmp" => Some(1),
        "ip" | "pkthdr" => None,
        _ => return Err(()),
    };
    let mut r = Regle {
        action,
        proto,
        source: (adresses(e[2]).ok_or(())?, ports(e[3]).ok_or(())?),
        destination: (adresses(e[5]).ok_or(())?, ports(e[6]).ok_or(())?),
        bidirectionnelle: e[4] == "<>",
        msg: String::new(),
        sid: 0,
        priorite: 3,
        classe: String::new(),
        contenus: Vec::new(),
        syn: false,
        dsize: None,
        fichier: fichier.to_string(),
    };
    for (k, v) in options(opts) {
        let dernier = r.contenus.last_mut();
        match k.as_str() {
            "msg" => r.msg = sans_guillemets(&v).replace("\\\"", "\"").replace("\\;", ";"),
            "sid" => r.sid = v.parse().map_err(|_| ())?,
            "priority" => r.priorite = v.parse().unwrap_or(3),
            "classtype" => {
                r.classe = v.clone();
                if r.priorite == 3 && ["trojan-activity", "attempted-admin", "successful-admin", "exploit-kit", "command-and-control"].contains(&v.as_str()) {
                    r.priorite = 1;
                } else if r.priorite == 3 && (v.contains("attack") || v.contains("attempted") || v == "bad-unknown" || v == "policy-violation") {
                    r.priorite = 2;
                }
            }
            "content" => {
                let negation = v.trim().starts_with('!');
                let motif = contenu(sans_guillemets(&v));
                if motif.is_empty() {
                    return Err(());
                }
                r.contenus.push(Contenu { motif, negation, ..Default::default() });
            }
            "nocase" => dernier.ok_or(())?.nocase = true,
            "offset" => dernier.ok_or(())?.offset = Some(v.parse().map_err(|_| ())?),
            "depth" => dernier.ok_or(())?.depth = Some(v.parse().map_err(|_| ())?),
            "distance" => dernier.ok_or(())?.distance = Some(v.parse().map_err(|_| ())?),
            "within" => dernier.ok_or(())?.within = Some(v.parse().map_err(|_| ())?),
            "flags" => {
                let f = v.split(',').next().unwrap_or("").trim();
                if f == "S" || f == "S+" || f == "S*" {
                    r.syn = true;
                } else {
                    return Err(());
                }
            }
            "dsize" => {
                let v = v.replace(' ', "");
                r.dsize = Some(if let Some(n) = v.strip_prefix('>') {
                    (n.parse::<usize>().map_err(|_| ())? + 1, usize::MAX)
                } else if let Some(n) = v.strip_prefix('<') {
                    (0, n.parse::<usize>().map_err(|_| ())?.saturating_sub(1))
                } else if let Some((a, b)) = v.split_once("<>") {
                    (a.parse::<usize>().map_err(|_| ())? + 1, b.parse::<usize>().map_err(|_| ())?.saturating_sub(1))
                } else {
                    let n = v.parse().map_err(|_| ())?;
                    (n, n)
                });
            }
            k if OPTIONS_IGNOREES.contains(&k) || k.starts_with("http.") || k.starts_with("tls.") || k.starts_with("dns.") || k.starts_with("ja3") => {}
            _ => return Err(()),
        }
    }
    if r.sid == 0 {
        return Err(());
    }
    Ok(Some(r))
}

// ------------------------------------------------------------ correspondance

fn dans_adresses(a: &Adresses, ip: Ipv4Addr) -> bool {
    match a {
        Adresses::Toutes => true,
        Adresses::Liste(l, negation) => {
            let v = u32::from(ip);
            l.iter().any(|(d, f)| v >= *d && v <= *f) != *negation
        }
    }
}

fn dans_ports(p: &Ports, port: u16) -> bool {
    match p {
        Ports::Tous => true,
        Ports::Liste(l, negation) => l.iter().any(|(d, f)| port >= *d && port <= *f) != *negation,
    }
}

fn chercher(foin: &[u8], motif: &[u8], nocase: bool) -> Option<usize> {
    if motif.len() > foin.len() {
        return None;
    }
    foin.windows(motif.len()).position(|w| if nocase { w.eq_ignore_ascii_case(motif) } else { w == motif })
}

impl Regle {
    fn entete(&self, p: &Paquet) -> bool {
        if self.proto.is_some_and(|x| x != p.proto) || (self.syn && p.drapeaux & 0x12 != 0x02) {
            return false;
        }
        if let Some((a, b)) = self.dsize {
            if p.charge.len() < a || p.charge.len() > b {
                return false;
            }
        }
        let sens = |s: &(Adresses, Ports), d: &(Adresses, Ports), ps: &Paquet| {
            dans_adresses(&s.0, ps.source) && dans_ports(&s.1, ps.port_source) && dans_adresses(&d.0, ps.destination) && dans_ports(&d.1, ps.port_destination)
        };
        sens(&self.source, &self.destination, p) || (self.bidirectionnelle && sens(&self.destination, &self.source, p))
    }

    fn charge(&self, d: &[u8]) -> bool {
        let mut fin_precedente = 0usize;
        for c in &self.contenus {
            let relatif = c.distance.is_some() || c.within.is_some();
            let debut = if relatif {
                (fin_precedente as i64 + c.distance.unwrap_or(0)).max(0) as usize
            } else {
                c.offset.unwrap_or(0)
            };
            let mut fin = d.len();
            if let Some(depth) = c.depth {
                fin = fin.min(debut + depth);
            }
            if let Some(w) = c.within {
                fin = fin.min(debut + w);
            }
            let trouve = if debut >= fin || debut > d.len() { None } else { chercher(&d[debut..fin], &c.motif, c.nocase).map(|i| debut + i) };
            match (trouve, c.negation) {
                (Some(i), false) => fin_precedente = i + c.motif.len(),
                (None, true) => {}
                _ => return false,
            }
        }
        true
    }
}

impl Ids {
    pub fn nouveau(alertes: Arc<Mutex<Vec<Alerte>>>, blocages: Arc<Mutex<Vec<(String, String)>>>) -> Ids {
        let mut regles = Vec::new();
        let mut ignorees = 0;
        let mut fichiers = vec!["règles intégrées".to_string()];
        let mut sources: Vec<(String, String)> = vec![("intégrées".into(), REGLES_INTEGREES.to_string())];
        let dossier = commun::dossier().join("regles");
        let _ = std::fs::create_dir_all(&dossier);
        if let Ok(l) = std::fs::read_dir(&dossier) {
            for f in l.flatten() {
                let nom = f.file_name().to_string_lossy().to_string();
                if nom.ends_with(".rules") {
                    if let Ok(t) = std::fs::read_to_string(f.path()) {
                        fichiers.push(nom.clone());
                        sources.push((nom, t));
                    }
                }
            }
        }
        for (fichier, texte) in &sources {
            for ligne in texte.lines() {
                match lire_regle(ligne, fichier) {
                    Ok(Some(r)) if r.action != "pass" => regles.push(r),
                    Ok(_) => {}
                    Err(()) => ignorees += 1,
                }
            }
        }
        // Motif le plus long de chaque règle (hors négation) pour la recherche en une passe
        let mut motifs = Vec::new();
        let mut motif_regle = Vec::new();
        let mut sans_contenu = Vec::new();
        for (i, r) in regles.iter().enumerate() {
            match r.contenus.iter().filter(|c| !c.negation).max_by_key(|c| c.motif.len()) {
                Some(c) => {
                    motifs.push(c.motif.to_ascii_lowercase());
                    motif_regle.push(i);
                }
                None => sans_contenu.push(i),
            }
        }
        let automate = (!motifs.is_empty()).then(|| AhoCorasickBuilder::new().ascii_case_insensitive(true).build(&motifs).ok()).flatten();
        commun::journal(&format!("IDS : {} règle(s) chargée(s), {ignorees} ignorée(s) (options non prises en charge)", regles.len()));
        Ids {
            regles, sans_contenu, automate, motif_regle, ignorees, fichiers, alertes, blocages,
            detections: VecDeque::new(), deja: HashMap::new(), ips: false, paquets: 0, tics: 0,
        }
    }

    fn detecter(&mut self, i: usize, p: &Paquet, contexte: &Contexte) {
        let r = &self.regles[i];
        let (distant, port_distant, _) = p.distant();
        let cle = (r.sid, distant);
        if self.deja.get(&cle).map(|t| t.elapsed() < Duration::from_secs(3600)).unwrap_or(false) {
            return;
        }
        if self.deja.len() > 20_000 {
            self.deja.clear();
        }
        self.deja.insert(cle, Instant::now());
        let niveau = match r.priorite { 1 => "Critique", 2 => "Alerte", _ => "Info" };
        let externe = crate::parefeu::publique(&IpAddr::V4(distant));
        // Un paquet isolé peut porter une adresse source usurpée : on ne bloque qu'une connexion TCP établie
        let bloquer = self.ips && externe && (r.action == "drop" || r.action == "reject" || r.priorite == 1) && contexte.etablie(p);
        if bloquer {
            self.blocages.lock().unwrap().push((distant.to_string(), format!("IPS : {}", r.msg)));
        }
        let programme = contexte.programme(p);
        let d = Detection {
            heure: commun::maintenant(),
            sid: r.sid,
            message: r.msg.clone(),
            classe: r.classe.clone(),
            niveau: niveau.into(),
            source: format!("{}:{}", p.source, p.port_source),
            destination: format!("{}:{}", p.destination, p.port_destination),
            programme: programme.clone(),
            bloque: bloquer,
        };
        self.alertes.lock().unwrap().push(Alerte {
            id: commun::nouvel_id(),
            heure: d.heure.clone(),
            niveau: niveau.into(),
            score: match r.priorite { 1 => 10, 2 => 6, _ => 2 },
            processus: programme,
            destination: format!("IDS : {}", r.msg),
            ip: Some(distant.to_string()),
            port: port_distant,
            raisons: format!("règle {} ({}{}) : {} → {}{}", r.sid, r.fichier, if r.classe.is_empty() { String::new() } else { format!(", {}", r.classe) },
                d.source, d.destination, if bloquer { " — adresse BLOQUÉE au pare-feu (IPS)" } else { "" }),
            ..Default::default()
        });
        self.detections.push_front(d);
        self.detections.truncate(300);
    }
}

impl Analyseur for Ids {
    fn paquet(&mut self, p: &Paquet, contexte: &Contexte) {
        self.paquets += 1;
        let mut touchees: Vec<usize> = Vec::new();
        if !p.charge.is_empty() {
            if let Some(a) = &self.automate {
                for m in a.find_overlapping_iter(p.charge) {
                    let i = self.motif_regle[m.pattern().as_usize()];
                    if !touchees.contains(&i) {
                        touchees.push(i);
                    }
                }
            }
        }
        let candidates: Vec<usize> = touchees.into_iter()
            .filter(|&i| self.regles[i].entete(p) && self.regles[i].charge(p.charge))
            .chain(self.sans_contenu.iter().copied().filter(|&i| self.regles[i].entete(p)))
            .collect();
        for i in candidates {
            self.detecter(i, p, contexte);
        }
    }

    fn tic(&mut self) {
        self.tics += 1;
        if self.tics % 5 == 0 {
            self.ips = commun::lire::<commun::Config>("config.json").map(|c| c.ips).unwrap_or(false);
            self.deja.retain(|_, t| t.elapsed() < Duration::from_secs(3600));
            let _ = commun::ecrire("ids.json", &Etat {
                mis_a_jour: commun::maintenant(),
                regles: self.regles.len(),
                ignorees: self.ignorees,
                fichiers: self.fichiers.clone(),
                ips: self.ips,
                paquets_analyses: self.paquets,
                detections: self.detections.iter().cloned().collect(),
            });
        }
    }
}

#[cfg(test)]
pub fn lire_texte_test(texte: &str) -> (usize, usize) {
    let (mut n, mut ignorees) = (0, 0);
    for l in texte.lines() {
        match lire_regle(l, "test") {
            Ok(Some(_)) => n += 1,
            Ok(None) => {}
            Err(()) => ignorees += 1,
        }
    }
    (n, ignorees)
}

#[cfg(test)]
pub fn correspond_test(regle: &str, charge: &[u8]) -> Option<bool> {
    lire_regle(regle, "test").ok().flatten().map(|r| r.charge(charge))
}
