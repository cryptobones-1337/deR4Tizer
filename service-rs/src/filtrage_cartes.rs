//! Activation du filtrage sur les cartes réseau (phase 7, PR 7.4, accord explicite du mainteneur du 2026-11-12) :
//! cartes Ethernet et Wi-Fi physiques actives réglées sur le résolveur local (`127.0.0.1` puis leurs serveurs d'origine
//! en secours ; `::1` puis les serveurs IPv6 d'origine), état d'origine enregistré avant toute modification, vérifié
//! après, restauré à l'identique (DHCP redevient DHCP).
//!
//! Préalables de l'audit de #161 (S161-02, threat-model) :
//! - jamais de carte réglée sans la liaison exclusive du port 53 tenue par le service (le résolveur démarre et répond
//!   avant le réglage) ;
//! - cartes rendues avant de relâcher le port : désactivation, arrêt du service, désinstallation, silence de l'amont ;
//! - contrôle au démarrage du service : réglage refait seulement si le résolveur a pu se lier, sinon cartes rendues.
//!
//! Refus (D7-5, recommandation appliquée) : poste avec un suffixe DNS principal (signe d'un poste joint à un domaine
//! Active Directory), stratégie DNS ou NRPT posée par stratégie de groupe, port 53 de la boucle locale déjà pris.

use crate::commun;
use serde::{Deserialize, Serialize};

pub const FICHIER: &str = "filtrage-origine.json";

/// État d'origine d'une carte, enregistré avant toute modification
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "PascalCase", default)]
pub struct OrigineCarte {
    /// AdapterName (GUID entre accolades)
    pub id: String,
    pub nom: String,
    /// Serveurs IPv4 réglés à la main (NameServer de Tcpip) ; vide : DHCP
    pub ns4: String,
    /// Serveurs IPv6 réglés à la main (NameServer de Tcpip6) ; vide : automatique
    pub ns6: String,
    /// Serveurs effectifs à l'activation (secours et amont du résolveur)
    pub dns4: Vec<String>,
    pub dns6: Vec<String>,
}

fn registre_ns(pile: &str, id: &str) -> String {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    winreg::RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(format!(r"SYSTEM\CurrentControlSet\Services\{pile}\Parameters\Interfaces\{id}"))
        .ok()
        .and_then(|k| k.get_value::<String, _>("NameServer").ok())
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Liste de serveurs d'un NameServer (virgules ou espaces) (pure)
pub fn serveurs(ns: &str) -> Vec<String> {
    ns.split([',', ' ']).map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect()
}

/// Origine des cartes physiques actives (pure à partir du relevé et des NameServer lus) ; IPv6 de lien local (avec une
/// zone) et boucle locale écartées des serveurs effectifs
pub fn origine_de(cartes: &[crate::dns_surveillance::CarteDns], ns: &dyn Fn(&str, &str) -> String) -> Vec<OrigineCarte> {
    use std::net::IpAddr;
    cartes.iter().filter(|c| crate::dns_surveillance::physique(c.type_carte) && !c.id.is_empty()).map(|c| {
        let ips: Vec<IpAddr> = c.dns.iter().filter_map(|d| d.parse::<IpAddr>().ok()).filter(|i| !i.is_loopback() && !i.is_unspecified()).collect();
        OrigineCarte {
            id: c.id.clone(), nom: c.nom.clone(), ns4: ns("Tcpip", &c.id), ns6: ns("Tcpip6", &c.id),
            dns4: ips.iter().filter(|i| i.is_ipv4()).map(IpAddr::to_string).take(3).collect(),
            dns6: ips.iter().filter(|i| i.is_ipv6()).map(IpAddr::to_string).take(3).collect(),
        }
    }).collect()
}

/// Valeurs réglées à l'activation (pure, testée) : résolveur local d'abord, serveurs d'origine en secours
pub fn valeurs_activees(o: &OrigineCarte) -> (String, String) {
    let quatre: Vec<String> = std::iter::once("127.0.0.1".to_string()).chain(o.dns4.iter().cloned()).collect();
    let six: Vec<String> = std::iter::once("::1".to_string()).chain(o.dns6.iter().cloned()).collect();
    (quatre.join(","), six.join(","))
}

/// Carte déjà réglée sur le résolveur local (une activation précédente non rendue) : on ne l'enregistre pas comme origine
pub fn deja_reglee(o: &OrigineCarte) -> bool {
    serveurs(&o.ns4).first().is_some_and(|s| s == "127.0.0.1") || serveurs(&o.ns6).first().is_some_and(|s| s == "::1")
}

/// Égalité de deux listes de serveurs, aux séparateurs près (pure)
pub fn meme_liste(a: &str, b: &str) -> bool {
    serveurs(a) == serveurs(b)
}

fn guid(id: &str) -> Result<windows::core::GUID, String> {
    let s = id.trim_matches(['{', '}']);
    windows::core::GUID::try_from(s).map_err(|_| format!("identifiant de carte invalide : {id}"))
}

/// Règle les serveurs DNS d'une carte (IPv4 puis IPv6) ; chaîne vide : retour au DHCP ou à l'automatique
fn regler(id: &str, ns4: &str, ns6: &str) -> Result<(), String> {
    use windows::core::PWSTR;
    use windows::Win32::NetworkManagement::IpHelper::{SetInterfaceDnsSettings, DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER};
    let g = guid(id)?;
    for (valeur, drapeaux) in [(ns4, DNS_SETTING_NAMESERVER as u64), (ns6, (DNS_SETTING_NAMESERVER | DNS_SETTING_IPV6) as u64)] {
        let mut large: Vec<u16> = valeur.encode_utf16().chain(std::iter::once(0)).collect();
        let r = DNS_INTERFACE_SETTINGS { Version: DNS_INTERFACE_SETTINGS_VERSION1, Flags: drapeaux, NameServer: PWSTR(large.as_mut_ptr()), ..Default::default() };
        let e = unsafe { SetInterfaceDnsSettings(g, &r) };
        if e.0 != 0 {
            return Err(format!("SetInterfaceDnsSettings en échec ({}) pour {}", e.0, if drapeaux & DNS_SETTING_IPV6 as u64 != 0 { "IPv6" } else { "IPv4" }));
        }
    }
    Ok(())
}

/// Règle puis vérifie (relecture du registre) ; erreur si l'écart persiste
fn regler_et_verifier(o: &OrigineCarte, ns4: &str, ns6: &str) -> Result<(), String> {
    regler(&o.id, ns4, ns6)?;
    let (lu4, lu6) = (registre_ns("Tcpip", &o.id), registre_ns("Tcpip6", &o.id));
    if meme_liste(&lu4, ns4) && meme_liste(&lu6, ns6) {
        Ok(())
    } else {
        Err(format!("carte « {} » : réglage non vérifié (lu « {lu4} » / « {lu6} », attendu « {ns4} » / « {ns6} »)", o.nom))
    }
}

pub fn appliquer(o: &OrigineCarte) -> Result<(), String> {
    let (ns4, ns6) = valeurs_activees(o);
    regler_et_verifier(o, &ns4, &ns6)
}

pub fn restaurer(o: &OrigineCarte) -> Result<(), String> {
    regler_et_verifier(o, &o.ns4, &o.ns6)
}

/// Rend toutes les cartes ; erreurs réunies (aucune n'arrête les suivantes)
pub fn restaurer_toutes(l: &[OrigineCarte]) -> Result<(), String> {
    let e: Vec<String> = l.iter().filter_map(|o| restaurer(o).err()).collect();
    if e.is_empty() { Ok(()) } else { Err(e.join(" ; ")) }
}

/// Règle toutes les cartes ; au premier échec, toutes sont rendues et l'erreur est rendue
pub fn appliquer_toutes(l: &[OrigineCarte]) -> Result<(), String> {
    for o in l {
        if let Err(e) = appliquer(o) {
            let r = restaurer_toutes(l).err().map(|x| format!(" ; remise en échec : {x}")).unwrap_or_default();
            return Err(format!("{e}{r}"));
        }
    }
    Ok(())
}

/// Relevé de l'origine des cartes physiques actives
pub fn releve_origine() -> Result<Vec<OrigineCarte>, String> {
    let cartes = crate::dns_surveillance::releve()?;
    Ok(origine_de(&cartes, &registre_ns))
}

/// Origine enregistrée (propriétaire contrôlé, comme tout fichier du dossier de données)
pub fn lire_origine() -> Option<Vec<OrigineCarte>> {
    let t = commun::lire_fichier_proprietaire(&commun::dossier().join(FICHIER))?;
    serde_json::from_str(t.trim_start_matches('\u{feff}')).ok()
}

pub fn effacer_origine() {
    let _ = std::fs::remove_file(commun::dossier().join(FICHIER));
}

/// Refus d'activation (D7-5) : raison, ou None (pure à partir des lectures, testée)
pub fn refus(suffixe_dns: &str, strategie_dns: bool) -> Option<String> {
    if !suffixe_dns.trim().is_empty() {
        return Some(format!("ce poste a un suffixe DNS principal ({}) : il semble joint à un domaine ; le filtrage n'est pas activé sur un poste d'entreprise (décision D7-5).", suffixe_dns.trim()))
    }
    if strategie_dns {
        return Some("une stratégie DNS ou NRPT est posée par stratégie de groupe : le filtrage n'est pas activé (décision D7-5).".into());
    }
    None
}

/// Suffixe DNS principal du poste (vide pour un poste hors domaine sans suffixe réglé)
pub fn suffixe_dns() -> String {
    use windows::core::PWSTR;
    use windows::Win32::System::SystemInformation::{ComputerNameDnsDomain, GetComputerNameExW};
    let mut n: u32 = 256;
    let mut t = vec![0u16; n as usize];
    match unsafe { GetComputerNameExW(ComputerNameDnsDomain, PWSTR(t.as_mut_ptr()), &mut n) } {
        Ok(()) => String::from_utf16_lossy(&t[..(n as usize).min(t.len())]),
        Err(_) => String::new(),
    }
}

/// Stratégie DNS ou NRPT posée par stratégie de groupe
pub fn strategie_dns() -> bool {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let k = winreg::RegKey::predef(HKEY_LOCAL_MACHINE);
    let nrpt = k.open_subkey(r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig").ok().is_some_and(|c| c.enum_keys().next().is_some());
    let serveurs = k.open_subkey(r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient").ok()
        .and_then(|c| c.get_value::<String, _>("NameServer").ok()).is_some_and(|v| !v.trim().is_empty());
    nrpt || serveurs
}
