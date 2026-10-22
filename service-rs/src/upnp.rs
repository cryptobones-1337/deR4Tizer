//! Redirections de ports UPnP de la box (IGD) : un programme du PC peut demander à la box d'ouvrir un port
//! d'Internet vers lui, sans que le pare-feu de Windows le voie comme une exposition. Découverte SSDP, puis
//! lecture des redirections (GetGenericPortMappingEntry) en SOAP sur HTTP, uniquement vers une adresse du
//! réseau local. Réponses bornées en taille et en nombre.

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

#[derive(Serialize, Deserialize, Clone, Default, PartialEq)]
#[serde(rename_all = "PascalCase", default)]
pub struct Redirection {
    pub port_externe: u16,
    pub protocole: String,
    pub client: String,
    pub port_interne: u16,
    pub description: String,
    pub active: bool,
}

const TAILLE_MAX: usize = 256 * 1024;

/// Adresse d'un appareil du réseau local (jamais une requête vers Internet)
fn locale(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_private() || v.is_link_local(),
        _ => false,
    }
}

/// « http://192.168.1.254:5000/desc.xml » → (adresse, chemin)
fn decouper_url(url: &str) -> Option<(SocketAddr, String)> {
    let reste = url.trim().strip_prefix("http://")?;
    let (hote, chemin) = reste.split_once('/').map(|(h, c)| (h, format!("/{c}"))).unwrap_or((reste, "/".into()));
    let (ip, port) = hote.split_once(':').map(|(i, p)| (i, p.parse().ok())).unwrap_or((hote, Some(80)));
    let adresse = SocketAddr::new(ip.parse().ok()?, port?);
    locale(&adresse.ip()).then_some((adresse, chemin))
}

/// Corps d'une réponse HTTP/1.1 (gère « Transfer-Encoding: chunked ») et son code de statut
fn http(adresse: SocketAddr, requete: &str) -> Option<(u16, String)> {
    let mut flux = TcpStream::connect_timeout(&adresse, Duration::from_secs(3)).ok()?;
    let _ = flux.set_read_timeout(Some(Duration::from_secs(5)));
    flux.write_all(requete.as_bytes()).ok()?;
    let mut brut = Vec::new();
    let mut tampon = [0u8; 8192];
    while brut.len() < TAILLE_MAX {
        match flux.read(&mut tampon) {
            Ok(0) | Err(_) => break,
            Ok(n) => brut.extend_from_slice(&tampon[..n]),
        }
    }
    let texte = String::from_utf8_lossy(&brut).into_owned();
    let (entete, corps) = texte.split_once("\r\n\r\n")?;
    let statut: u16 = entete.split_whitespace().nth(1)?.parse().ok()?;
    let corps = if entete.to_ascii_lowercase().contains("transfer-encoding: chunked") { dechunker(corps) } else { corps.to_string() };
    Some((statut, corps))
}

fn dechunker(c: &str) -> String {
    let mut sortie = String::new();
    let mut reste = c;
    while let Some((taille, apres)) = reste.split_once("\r\n") {
        let n = usize::from_str_radix(taille.split(';').next().unwrap_or("").trim(), 16).unwrap_or(0);
        if n == 0 || n > apres.len() {
            break;
        }
        sortie.push_str(&apres[..n]);
        reste = apres[n..].trim_start_matches("\r\n");
    }
    sortie
}

fn balise<'a>(xml: &'a str, nom: &str) -> Option<&'a str> {
    let ouverture = format!("<{nom}>");
    let debut = xml.find(&ouverture)? + ouverture.len();
    let fin = xml[debut..].find(&format!("</{nom}>"))? + debut;
    Some(xml[debut..fin].trim())
}

/// Service de redirection de la box : (adresse, URL de contrôle, type de service)
fn service_igd(locale_ip: Ipv4Addr) -> Option<(SocketAddr, String, String)> {
    let s = UdpSocket::bind(SocketAddr::from((locale_ip, 0))).ok()?;
    let _ = s.set_read_timeout(Some(Duration::from_millis(500)));
    let recherche = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n";
    s.send_to(recherche.as_bytes(), "239.255.255.250:1900").ok()?;
    let debut = Instant::now();
    let mut tampon = [0u8; 2048];
    let mut emplacements = Vec::new();
    while debut.elapsed() < Duration::from_secs(3) && emplacements.len() < 8 {
        if let Ok((n, _)) = s.recv_from(&mut tampon) {
            let r = String::from_utf8_lossy(&tampon[..n]).into_owned();
            if let Some(l) = r.lines().find(|l| l.to_ascii_lowercase().starts_with("location:")) {
                emplacements.push(l[9..].trim().to_string());
            }
        }
    }
    for url in emplacements {
        let Some((adresse, chemin)) = decouper_url(&url) else { continue };
        let Some((200, description)) = http(adresse, &format!("GET {chemin} HTTP/1.1\r\nHost: {adresse}\r\nConnection: close\r\n\r\n")) else { continue };
        for bloc in description.split("<service>").skip(1) {
            let Some(type_) = balise(bloc, "serviceType") else { continue };
            if type_.contains("WANIPConnection") || type_.contains("WANPPPConnection") {
                let controle = balise(bloc, "controlURL")?.to_string();
                let controle = if controle.starts_with("http://") {
                    decouper_url(&controle).map(|(_, c)| c)?
                } else if controle.starts_with('/') { controle } else { format!("/{controle}") };
                return Some((adresse, controle, type_.to_string()));
            }
        }
    }
    None
}

/// Redirections de la box ; Err si aucune box UPnP ne répond (UPnP désactivé, ce qui est préférable)
pub fn redirections(locale_ip: Ipv4Addr) -> Result<Vec<Redirection>, String> {
    let (adresse, controle, type_) = service_igd(locale_ip).ok_or("aucune box UPnP ne répond (UPnP désactivé ou absent)")?;
    let mut l = Vec::new();
    for i in 0..64 {
        let corps = format!(
            "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
             s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:GetGenericPortMappingEntry xmlns:u=\"{type_}\">\
             <NewPortMappingIndex>{i}</NewPortMappingIndex></u:GetGenericPortMappingEntry></s:Body></s:Envelope>");
        let requete = format!(
            "POST {controle} HTTP/1.1\r\nHost: {adresse}\r\nContent-Type: text/xml; charset=\"utf-8\"\r\n\
             SOAPAction: \"{type_}#GetGenericPortMappingEntry\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{corps}", corps.len());
        let Some((statut, reponse)) = http(adresse, &requete) else { break };
        if statut != 200 {
            break; // fin de la liste (SpecifiedArrayIndexInvalid)
        }
        l.push(Redirection {
            port_externe: balise(&reponse, "NewExternalPort").and_then(|p| p.parse().ok()).unwrap_or(0),
            protocole: balise(&reponse, "NewProtocol").unwrap_or("").to_string(),
            client: balise(&reponse, "NewInternalClient").unwrap_or("").to_string(),
            port_interne: balise(&reponse, "NewInternalPort").and_then(|p| p.parse().ok()).unwrap_or(0),
            description: balise(&reponse, "NewPortMappingDescription").unwrap_or("").chars().take(80).collect(),
            active: balise(&reponse, "NewEnabled").map(|e| e == "1").unwrap_or(true),
        });
    }
    Ok(l)
}

#[cfg(test)]
pub fn decouper_url_test(url: &str) -> Option<(SocketAddr, String)> {
    decouper_url(url)
}

#[cfg(test)]
pub fn dechunker_test(c: &str) -> String {
    dechunker(c)
}
