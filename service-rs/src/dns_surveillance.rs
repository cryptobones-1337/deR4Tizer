//! Surveillance des serveurs DNS des cartes du poste (phase 7, PR 7.1, règle DNS-002). Un logiciel malveillant ou une box
//! compromise qui change le serveur DNS fait passer toutes les résolutions par l'attaquant ; le fichier hosts (SYS-001) ne
//! le montre pas. Relevé toutes les 60 s, hors du verrou du moniteur : serveurs DNS effectifs, passerelles et type de
//! chaque carte active (`GetAdaptersAddresses`), et serveur statique éventuel (`NameServer` du registre, IPv4 et IPv6).
//! Lecture seule : rien n'est remis en place (décision D7-10 du dossier, ouverte : proposition « jamais automatique »).
//! Lecture impossible : collecte `ConfigDns` indisponible, jamais « aucun changement ».

use crate::commun::{self, Alerte};

/// Une carte active, telle que relevée
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CarteDns {
    /// Identifiant stable de la carte (AdapterName, un GUID)
    pub id: String,
    /// Nom affiché (FriendlyName)
    pub nom: String,
    /// Type de l'interface (IfType : 6 Ethernet, 71 Wi-Fi, 131 tunnel…)
    pub type_carte: u32,
    pub passerelles: Vec<String>,
    pub dns: Vec<String>,
    /// Serveur DNS réglé à la main (NameServer non vide), par opposition à celui donné par le DHCP
    pub statique: bool,
}

/// Carte physique : Ethernet ou Wi-Fi. Les cartes virtuelles et VPN changent de DNS d'elles-mêmes : événement seulement
pub fn physique(type_carte: u32) -> bool {
    type_carte == 6 || type_carte == 71
}

/// Ce que donne la comparaison de deux relevés
pub enum Constat {
    /// DNS-002 : serveur statique changé sur une carte physique, réseau inchangé
    Alerte(Alerte),
    /// Changement attendu (réseau changé, DHCP, carte virtuelle) : événement du mini-SIEM, sans alerte
    Evenement(String),
}

fn liste(l: &[String]) -> String {
    if l.is_empty() { "aucun".into() } else { l.join(", ") }
}

/// Décision pure (testée, DNS-002) : relevé `apres` comparé au précédent, carte par carte (même identifiant). Une carte
/// nouvelle ou disparue ne donne rien (branchement, VPN qui se connecte) ; seules les cartes dont les serveurs DNS
/// changent sont examinées.
pub fn changements_dns(avant: &[CarteDns], apres: &[CarteDns]) -> Vec<Constat> {
    let mut l = Vec::new();
    for c in apres {
        let Some(a) = avant.iter().find(|a| a.id == c.id) else { continue };
        if a.dns == c.dns {
            continue;
        }
        let quoi = format!("serveurs DNS de la carte « {} » : {} → {}", c.nom, liste(&a.dns), liste(&c.dns));
        if !physique(c.type_carte) {
            l.push(Constat::Evenement(format!("{quoi} (carte virtuelle ou VPN)")));
        } else if a.passerelles != c.passerelles {
            l.push(Constat::Evenement(format!("{quoi} (changement de réseau : passerelle {} → {})", liste(&a.passerelles), liste(&c.passerelles))));
        } else if c.statique && !c.dns.is_empty() {
            l.push(Constat::Alerte(Alerte {
                regle: crate::regles::DNS_002.into(),
                id: commun::nouvel_id(), heure: commun::maintenant(), niveau: "Alerte".into(), score: 3,
                processus: "?".into(), destination: format!("carte « {} »", c.nom),
                raisons: format!("{quoi} : serveur DNS réglé à la main, réseau inchangé. Si ce changement n'est pas voulu (logiciel inconnu, prestataire non prévenu), toutes les résolutions de noms peuvent passer par un tiers : vérifier le réglage DNS de la carte."),
                ..Default::default()
            }));
        } else {
            l.push(Constat::Evenement(format!("{quoi} (donné par le DHCP, réseau inchangé)")));
        }
    }
    l
}

/// Serveur DNS statique réglé dans le registre pour cette carte (IPv4 ou IPv6)
fn statique(id: &str) -> bool {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let hklm = winreg::RegKey::predef(HKEY_LOCAL_MACHINE);
    ["Tcpip", "Tcpip6"].iter().any(|pile| {
        hklm.open_subkey(format!(r"SYSTEM\CurrentControlSet\Services\{pile}\Parameters\Interfaces\{id}"))
            .ok()
            .and_then(|k| k.get_value::<String, _>("NameServer").ok())
            .is_some_and(|v| !v.trim().is_empty())
    })
}

/// Adresse d'un SOCKET_ADDRESS (IPv4 ou IPv6), ou None
unsafe fn adresse(sa: *const windows::Win32::Networking::WinSock::SOCKADDR) -> Option<String> {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6};
    if sa.is_null() {
        return None;
    }
    if (*sa).sa_family == AF_INET {
        let s = &*(sa as *const SOCKADDR_IN);
        Some(Ipv4Addr::from(u32::from_be(s.sin_addr.S_un.S_addr)).to_string())
    } else if (*sa).sa_family == AF_INET6 {
        let s = &*(sa as *const SOCKADDR_IN6);
        Some(Ipv6Addr::from(s.sin6_addr.u.Byte).to_string())
    } else {
        None
    }
}

/// Relevé des cartes actives ; Err : lecture impossible (collecte indisponible)
pub fn releve() -> Result<Vec<CarteDns>, String> {
    use windows::Win32::NetworkManagement::IpHelper::{GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH};
    use windows::Win32::Networking::WinSock::AF_UNSPEC;
    let mut l = Vec::new();
    unsafe {
        let mut taille: u32 = 32 * 1024;
        let mut tampon = vec![0u8; taille as usize];
        let drapeaux = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_INCLUDE_GATEWAYS;
        let mut r = GetAdaptersAddresses(AF_UNSPEC.0 as u32, drapeaux, None, Some(tampon.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH), &mut taille);
        if r == 111 {
            tampon = vec![0u8; taille as usize];
            r = GetAdaptersAddresses(AF_UNSPEC.0 as u32, drapeaux, None, Some(tampon.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH), &mut taille);
        }
        if r != 0 {
            return Err(format!("GetAdaptersAddresses en échec ({r})"));
        }
        let mut a = tampon.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !a.is_null() {
            // Cartes actives seulement (IfOperStatusUp = 1)
            if (*a).OperStatus.0 == 1 {
                let id = (*a).AdapterName.to_string().unwrap_or_default();
                let nom: String = (*a).FriendlyName.to_string().unwrap_or_default().chars().filter(|c| !c.is_control()).take(80).collect();
                let mut dns = Vec::new();
                let mut d = (*a).FirstDnsServerAddress;
                while !d.is_null() && dns.len() < 16 {
                    if let Some(ip) = adresse((*d).Address.lpSockaddr) {
                        dns.push(ip);
                    }
                    d = (*d).Next;
                }
                let mut passerelles = Vec::new();
                let mut g = (*a).FirstGatewayAddress;
                while !g.is_null() && passerelles.len() < 16 {
                    if let Some(ip) = adresse((*g).Address.lpSockaddr) {
                        passerelles.push(ip);
                    }
                    g = (*g).Next;
                }
                let st = !id.is_empty() && statique(&id);
                l.push(CarteDns { id, nom, type_carte: (*a).IfType, passerelles, dns, statique: st });
            }
            a = (*a).Next;
            if l.len() > 64 {
                break;
            }
        }
    }
    Ok(l)
}
