//! NDR local (détection d'attaques sur le réseau local), sans pilote :
//!   - table ARP (toutes les 10 s) : changement de l'adresse MAC de la passerelle, MAC de la passerelle
//!     portée par un autre appareil (usurpation ARP, homme du milieu), nouveaux appareils ;
//!   - DHCP (paquets capturés) : serveur DHCP autre que celui de l'interface (serveur pirate) ;
//!   - LLMNR / NBNS / mDNS (paquets capturés) : machine qui répond pour de nombreux noms (Responder) ;
//!   - le tout sur la carte reliée au réseau local, même quand un VPN porte la route par défaut ;
//!   - leurre actif (toutes les 10 min) : question LLMNR et NBNS pour un nom qui n'existe pas ; toute
//!     réponse trahit un empoisonneur.
//! État dans reseau.json.

use crate::capture::{Analyseur, Contexte, Paquet, UDP};
use crate::commun::{self, Alerte};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use windows::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetAdaptersInfo, GetIpNetTable2, IP_ADAPTER_INFO, IP_ADDR_STRING, MIB_IPNET_TABLE2};
use windows::Win32::Networking::WinSock::AF_INET;

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Appareil {
    pub ip: String,
    pub mac: String,
    pub premiere_vue: String,
    pub derniere_vue: String,
    pub passerelle: bool,
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Repondeur {
    pub ip: String,
    pub protocole: String,
    pub noms: Vec<String>,
    pub derniere: String,
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct ServeurDhcp {
    pub ip: String,
    pub vu: String,
    pub legitime: bool,
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct EtatReseau {
    pub mis_a_jour: String,
    pub interface: String,
    pub masque: String,
    pub passerelle: String,
    pub mac_passerelle: String,
    /// MAC de la passerelle mémorisée (référence pour détecter un changement)
    pub mac_passerelle_connue: String,
    pub dhcp_interface: String,
    pub appareils: Vec<Appareil>,
    pub serveurs_dhcp: Vec<ServeurDhcp>,
    pub repondeurs: Vec<Repondeur>,
    pub dernier_leurre: String,
    pub resultat_leurre: String,
}

struct Interne {
    etat: EtatReseau,
    alertes: Arc<Mutex<Vec<Alerte>>>,
    deja: HashMap<String, Instant>,
    /// Noms auxquels chaque machine a répondu (10 dernières minutes)
    reponses: HashMap<(String, &'static str), Vec<(Instant, String)>>,
}

impl Interne {
    fn alerter(&mut self, cle: String, niveau: &str, score: i32, destination: String, raisons: String, mitre: &str) {
        self.deja.retain(|_, t| t.elapsed() < Duration::from_secs(3600));
        if self.deja.contains_key(&cle) {
            return;
        }
        self.deja.insert(cle, Instant::now());
        self.alertes.lock().unwrap().push(Alerte {
            id: commun::nouvel_id(),
            heure: commun::maintenant(),
            niveau: niveau.into(),
            score,
            processus: "réseau local".into(),
            destination,
            raisons: format!("{raisons}  [MITRE {mitre}]"),
            mitre: mitre.into(),
            ..Default::default()
        });
    }
}

fn texte_ip(s: &IP_ADDR_STRING) -> String {
    let octets: Vec<u8> = s.IpAddress.String.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
    String::from_utf8_lossy(&octets).into_owned()
}

fn texte_masque(s: &IP_ADDR_STRING) -> String {
    let octets: Vec<u8> = s.IpMask.String.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
    String::from_utf8_lossy(&octets).into_owned()
}

/// Adresse IPv4 de la carte réseau physique reliée au réseau local (Ethernet ou Wi-Fi avec une passerelle) :
/// avec un VPN, la route par défaut passe par le tunnel, mais l'ARP et le DHCP se jouent sur cette carte
pub fn adresse_lan() -> Option<Ipv4Addr> {
    let mut taille = 0u32;
    unsafe {
        GetAdaptersInfo(None, &mut taille);
        let mut tampon = vec![0u8; taille as usize + 1024];
        let premier = tampon.as_mut_ptr() as *mut IP_ADAPTER_INFO;
        if GetAdaptersInfo(Some(premier), &mut taille) != 0 {
            return None;
        }
        let mut a = premier;
        while !a.is_null() {
            let info = &*a;
            // 6 : Ethernet, 71 : Wi-Fi
            let passerelle = texte_ip(&info.GatewayList);
            if (info.Type == 6 || info.Type == 71) && !passerelle.is_empty() && passerelle != "0.0.0.0" {
                if let Ok(ip) = texte_ip(&info.IpAddressList).parse::<Ipv4Addr>() {
                    if !ip.is_unspecified() {
                        return Some(ip);
                    }
                }
            }
            a = info.Next;
        }
    }
    None
}

/// (passerelle, serveur DHCP, masque, index d'interface) de l'interface qui porte l'adresse locale
fn infos_interface(locale: Ipv4Addr) -> Option<(String, String, String, u32)> {
    let mut taille = 0u32;
    unsafe {
        GetAdaptersInfo(None, &mut taille);
        let mut tampon = vec![0u8; taille as usize + 1024];
        let premier = tampon.as_mut_ptr() as *mut IP_ADAPTER_INFO;
        if GetAdaptersInfo(Some(premier), &mut taille) != 0 {
            return None;
        }
        let mut a = premier;
        while !a.is_null() {
            let info = &*a;
            let mut adresse: *const IP_ADDR_STRING = &info.IpAddressList;
            while !adresse.is_null() {
                if texte_ip(&*adresse) == locale.to_string() {
                    let dhcp = if info.DhcpEnabled != 0 { texte_ip(&info.DhcpServer) } else { String::new() };
                    return Some((texte_ip(&info.GatewayList), dhcp, texte_masque(&*adresse), info.Index));
                }
                adresse = (*adresse).Next;
            }
            a = info.Next;
        }
    }
    None
}

/// Voisins IPv4 connus de Windows sur l'interface : (IP, MAC)
fn table_arp(index: u32) -> Vec<(Ipv4Addr, String)> {
    let mut l = Vec::new();
    unsafe {
        let mut table: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();
        if GetIpNetTable2(AF_INET, &mut table).is_err() || table.is_null() {
            return l;
        }
        let n = (*table).NumEntries as usize;
        let lignes = std::slice::from_raw_parts((*table).Table.as_ptr(), n);
        for r in lignes {
            // 0 injoignable, 1 incomplet : pas d'adresse MAC fiable
            if r.InterfaceIndex != index || r.PhysicalAddressLength != 6 || r.State.0 < 2 {
                continue;
            }
            let ip = Ipv4Addr::from(u32::from_be(r.Address.Ipv4.sin_addr.S_un.S_addr));
            let m = &r.PhysicalAddress[..6];
            if ip.is_multicast() || ip.is_broadcast() || ip.octets()[3] == 255 || m == [0xff; 6] || m == [0; 6] || m[0] & 1 == 1 {
                continue;
            }
            l.push((ip, m.iter().map(|o| format!("{o:02X}")).collect::<Vec<_>>().join("-")));
        }
        FreeMibTable(table as *const _);
    }
    l
}

// ------------------------------------------------------------ surveillance (fil dédié)

#[derive(Clone)]
pub struct Ndr {
    interne: Arc<Mutex<Interne>>,
}

pub fn demarrer(alertes: Arc<Mutex<Vec<Alerte>>>) -> Ndr {
    let etat: EtatReseau = commun::lire("reseau.json").unwrap_or_default();
    let interne = Arc::new(Mutex::new(Interne { etat, alertes, deja: HashMap::new(), reponses: HashMap::new() }));
    let i = interne.clone();
    std::thread::Builder::new().name("ndr".into()).spawn(move || {
        let mut premier = true;
        let mut dernier_leurre = Instant::now();
        let mut leurre_fait = false;
        loop {
            if let Some(locale) = adresse_lan() {
                analyser_arp(&i, locale, premier);
                premier = false;
                if !leurre_fait || dernier_leurre.elapsed() > Duration::from_secs(600) {
                    leurre(&i, locale);
                    dernier_leurre = Instant::now();
                    leurre_fait = true;
                }
            }
            {
                let mut g = i.lock().unwrap();
                g.etat.mis_a_jour = commun::maintenant();
                commun::ecrire("reseau.json", &g.etat);
            }
            std::thread::sleep(Duration::from_secs(10));
        }
    }).unwrap();
    Ndr { interne }
}

fn analyser_arp(i: &Arc<Mutex<Interne>>, locale: Ipv4Addr, premier: bool) {
    let Some((passerelle, dhcp, masque, index)) = infos_interface(locale) else { return };
    let voisins = table_arp(index);
    let mut g = i.lock().unwrap();
    let nouveau_reseau = g.etat.interface != locale.to_string() || g.etat.passerelle != passerelle;
    if nouveau_reseau {
        // Autre réseau (Wi-Fi différent…) : on repart d'une référence neuve
        g.etat.appareils.clear();
        g.etat.mac_passerelle_connue.clear();
        g.etat.serveurs_dhcp.clear();
    }
    g.etat.interface = locale.to_string();
    g.etat.masque = masque;
    g.etat.passerelle = passerelle.clone();
    g.etat.dhcp_interface = dhcp;
    let maintenant = commun::maintenant();
    let mac_passerelle = voisins.iter().find(|(ip, _)| ip.to_string() == passerelle).map(|(_, m)| m.clone()).unwrap_or_default();
    g.etat.mac_passerelle = mac_passerelle.clone();

    // Usurpation ARP : la MAC de la passerelle est aussi celle d'un autre appareil
    if !mac_passerelle.is_empty() {
        let autres: Vec<String> = voisins.iter().filter(|(ip, m)| *m == mac_passerelle && ip.to_string() != passerelle).map(|(ip, _)| ip.to_string()).collect();
        if !autres.is_empty() {
            g.alerter(format!("arp-double|{mac_passerelle}"), "Critique", 12, format!("passerelle {passerelle}"),
                format!("USURPATION ARP probable : la MAC de la passerelle ({mac_passerelle}) est aussi annoncée par {} — le trafic peut être intercepté (homme du milieu)", autres.join(", ")),
                "T1557.002");
        }
        let connue = g.etat.mac_passerelle_connue.clone();
        if connue.is_empty() {
            g.etat.mac_passerelle_connue = mac_passerelle.clone();
        } else if connue != mac_passerelle {
            g.alerter(format!("arp-change|{mac_passerelle}"), "Alerte", 6, format!("passerelle {passerelle}"),
                format!("l'adresse MAC de la passerelle a changé ({connue} → {mac_passerelle}) : nouvelle box ou routeur, sinon usurpation ARP"),
                "T1557.002");
            g.etat.mac_passerelle_connue = mac_passerelle.clone();
        }
    }

    // Inventaire des appareils ; un nouvel appareil est signalé (sauf au premier passage)
    for (ip, mac) in &voisins {
        let ip = ip.to_string();
        let est_passerelle = ip == passerelle;
        match g.etat.appareils.iter_mut().find(|a| a.ip == ip && a.mac == *mac) {
            Some(a) => {
                a.derniere_vue = maintenant.clone();
                a.passerelle = est_passerelle;
            }
            None => {
                let connu_mac = g.etat.appareils.iter().any(|a| a.mac == *mac);
                g.etat.appareils.push(Appareil { ip: ip.clone(), mac: mac.clone(), premiere_vue: maintenant.clone(), derniere_vue: maintenant.clone(), passerelle: est_passerelle });
                if !premier && !nouveau_reseau && !connu_mac {
                    g.alerter(format!("appareil|{mac}"), "Info", 0, format!("appareil {ip}"),
                        format!("nouvel appareil sur le réseau local : {ip} (MAC {mac})"), "T1200");
                }
            }
        }
    }
    if g.etat.appareils.len() > 500 {
        g.etat.appareils.sort_by(|a, b| b.derniere_vue.cmp(&a.derniere_vue));
        g.etat.appareils.truncate(500);
    }
}

// ------------------------------------------------------------ leurre LLMNR / NBNS

fn nom_aleatoire() -> String {
    let n = commun::filetime(std::time::SystemTime::now()) ^ (std::process::id() as u64) << 20;
    format!("srv-{:08x}", (n.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 32) as u32)
}

fn question_llmnr(nom: &str, id: u16) -> Vec<u8> {
    let mut q = Vec::new();
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    q.push(nom.len() as u8);
    q.extend_from_slice(nom.as_bytes());
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    q
}

/// Nom NetBIOS encodé (« first-level encoding », 32 octets)
fn nom_netbios(nom: &str) -> Vec<u8> {
    let mut brut = nom.to_uppercase().into_bytes();
    brut.resize(15, b' ');
    brut.push(0x20);
    let mut e = vec![32u8];
    for o in brut {
        e.push(b'A' + (o >> 4));
        e.push(b'A' + (o & 0x0F));
    }
    e.push(0);
    e
}

fn question_nbns(nom: &str, id: u16) -> Vec<u8> {
    let mut q = Vec::new();
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x10, 0, 1, 0, 0, 0, 0, 0, 0]);
    q.extend_from_slice(&nom_netbios(nom));
    q.extend_from_slice(&[0, 0x20, 0, 1]);
    q
}

fn diffusion(locale: Ipv4Addr, masque: &str) -> Option<Ipv4Addr> {
    let m: Ipv4Addr = masque.parse().ok()?;
    Some(Ipv4Addr::from(u32::from(locale) | !u32::from(m)))
}

fn leurre(i: &Arc<Mutex<Interne>>, locale: Ipv4Addr) {
    let nom = nom_aleatoire();
    let masque = i.lock().unwrap().etat.masque.clone();
    let Ok(s) = UdpSocket::bind(SocketAddr::from((locale, 0))) else { return };
    let _ = s.set_multicast_ttl_v4(1);
    let _ = s.set_broadcast(true);
    let _ = s.set_read_timeout(Some(Duration::from_millis(500)));
    let id = (u32::from(locale) as u16) ^ 0x5A5A;
    let _ = s.send_to(&question_llmnr(&nom, id), "224.0.0.252:5355");
    if let Some(b) = diffusion(locale, &masque) {
        let _ = s.send_to(&question_nbns(&nom, id), SocketAddr::from((b, 137)));
    }
    let debut = Instant::now();
    let mut repondeurs: HashSet<String> = HashSet::new();
    let mut tampon = [0u8; 1500];
    while debut.elapsed() < Duration::from_secs(3) {
        if let Ok((n, de)) = s.recv_from(&mut tampon) {
            // Une réponse (bit QR) à notre question, venant d'une autre machine
            if n >= 12 && tampon[2] & 0x80 != 0 && de.ip() != std::net::IpAddr::V4(locale) {
                repondeurs.insert(format!("{} ({})", de.ip(), if de.port() == 137 { "NBNS" } else { "LLMNR" }));
            }
        }
    }
    let mut g = i.lock().unwrap();
    g.etat.dernier_leurre = commun::maintenant();
    if repondeurs.is_empty() {
        g.etat.resultat_leurre = format!("aucune réponse pour le nom inexistant « {nom} » : pas d'empoisonneur détecté");
    } else {
        let liste: Vec<String> = repondeurs.into_iter().collect();
        g.etat.resultat_leurre = format!("RÉPONSE pour le nom inexistant « {nom} » : {}", liste.join(", "));
        g.alerter(format!("leurre|{}", liste.join(",")), "Critique", 12, liste.join(", "),
            format!("EMPOISONNEMENT LLMNR/NBNS : {} a répondu pour le nom inexistant « {nom} » — outil de type Responder, qui vole les identifiants Windows du réseau", liste.join(", ")),
            "T1557.001");
    }
}

// ------------------------------------------------------------ analyse des paquets capturés

/// Nom de la première question d'un message au format DNS (LLMNR, mDNS)
fn nom_dns(m: &[u8]) -> Option<String> {
    let mut p = 12;
    let mut parties = Vec::new();
    while p < m.len() && m[p] != 0 && parties.len() < 20 {
        let l = m[p] as usize;
        if l & 0xC0 != 0 || p + 1 + l > m.len() {
            return None;
        }
        parties.push(String::from_utf8_lossy(&m[p + 1..p + 1 + l]).to_lowercase());
        p += 1 + l;
    }
    (!parties.is_empty()).then(|| parties.join("."))
}

fn nom_nbns(m: &[u8]) -> Option<String> {
    if m.len() < 12 + 34 || m[12] != 32 {
        return None;
    }
    let e = &m[13..45];
    let octets: Vec<u8> = e.chunks(2).map(|c| ((c[0].wrapping_sub(b'A')) << 4) | (c[1].wrapping_sub(b'A') & 0x0F)).collect();
    Some(String::from_utf8_lossy(&octets[..15]).trim().to_lowercase())
}

impl Analyseur for Ndr {
    fn paquet(&mut self, p: &Paquet, _: &Contexte) {
        if p.proto != UDP || !p.entrant || p.charge.len() < 12 {
            return;
        }
        let m = p.charge;
        match p.port_source {
            // Réponse DHCP (offre, accusé) : serveur identifié par l'option 54
            67 if p.port_destination == 68 && m.len() > 240 && m[0] == 2 && m[236..240] == [0x63, 0x82, 0x53, 0x63] => {
                let mut serveur = p.source.to_string();
                let mut o = 240;
                while o + 1 < m.len() && m[o] != 255 {
                    if m[o] == 0 {
                        o += 1;
                        continue;
                    }
                    let l = m[o + 1] as usize;
                    if m[o] == 54 && l == 4 && o + 6 <= m.len() {
                        serveur = Ipv4Addr::new(m[o + 2], m[o + 3], m[o + 4], m[o + 5]).to_string();
                    }
                    o += 2 + l;
                }
                let mut g = self.interne.lock().unwrap();
                let legitime = g.etat.dhcp_interface.is_empty() || g.etat.dhcp_interface == serveur;
                let vu = commun::maintenant();
                let plein = g.etat.serveurs_dhcp.len() >= 50;
                match g.etat.serveurs_dhcp.iter_mut().find(|s| s.ip == serveur) {
                    Some(s) => s.vu = vu,
                    None if !plein => g.etat.serveurs_dhcp.push(ServeurDhcp { ip: serveur.clone(), vu, legitime }),
                    None => {}
                }
                if !legitime {
                    let attendu = g.etat.dhcp_interface.clone();
                    g.alerter(format!("dhcp|{serveur}"), "Critique", 12, format!("serveur DHCP {serveur}"),
                        format!("SERVEUR DHCP PIRATE probable : {serveur} distribue des adresses alors que le serveur de cette interface est {attendu} — il peut imposer une fausse passerelle ou de faux DNS"),
                        "T1557.003");
                }
            }
            // Réponses LLMNR (5355), mDNS (5353), NBNS (137) : qui répond pour quels noms
            5355 | 5353 | 137 if m[2] & 0x80 != 0 => {
                let (proto, nom) = match p.port_source {
                    5355 => ("LLMNR", nom_dns(m)),
                    5353 => ("mDNS", nom_dns(m)),
                    _ => ("NBNS", nom_nbns(m)),
                };
                let Some(nom) = nom else { return };
                let ip = p.source.to_string();
                let mut g = self.interne.lock().unwrap();
                if g.reponses.len() > 2000 && !g.reponses.contains_key(&(ip.clone(), proto)) {
                    g.reponses.retain(|_, f| f.iter().any(|(t, _)| t.elapsed() < Duration::from_secs(600)));
                    if g.reponses.len() > 2000 {
                        return;
                    }
                }
                let file = g.reponses.entry((ip.clone(), proto)).or_default();
                file.retain(|(t, _)| t.elapsed() < Duration::from_secs(600));
                if !file.iter().any(|(_, n)| *n == nom) && file.len() < 100 {
                    file.push((Instant::now(), nom.clone()));
                }
                let noms: Vec<String> = file.iter().map(|(_, n)| n.clone()).collect();
                let distincts = noms.len();
                let maintenant = commun::maintenant();
                let plein = g.etat.repondeurs.len() >= 200;
                match g.etat.repondeurs.iter_mut().find(|r| r.ip == ip && r.protocole == proto) {
                    Some(r) => {
                        r.noms = noms.iter().rev().take(10).cloned().collect();
                        r.derniere = maintenant;
                    }
                    None if !plein => g.etat.repondeurs.push(Repondeur { ip: ip.clone(), protocole: proto.into(), noms: noms.clone(), derniere: maintenant }),
                    None => {}
                }
                // mDNS : un appareil annonce souvent plusieurs noms de services, seuil plus haut
                let seuil = if proto == "mDNS" { 15 } else { 3 };
                if distincts >= seuil {
                    g.alerter(format!("repondeur|{ip}|{proto}"), "Alerte", 7, format!("{ip} ({proto})"),
                        format!("{ip} répond en {proto} pour {distincts} noms différents en 10 minutes ({}) : comportement d'empoisonneur de type Responder",
                            noms.iter().take(5).cloned().collect::<Vec<_>>().join(", ")),
                        "T1557.001");
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
pub fn nom_dns_test(m: &[u8]) -> Option<String> {
    nom_dns(m)
}

#[cfg(test)]
pub fn nom_nbns_test(m: &[u8]) -> Option<String> {
    nom_nbns(m)
}
