//! Capture passive des paquets IPv4 par socket brute (SIO_RCVALL), sans pilote : Windows remet à la socket
//! une copie des paquets entrants et sortants de l'interface. Un fil par interface lit, décode les en-têtes
//! IP/TCP/UDP et distribue chaque paquet à ses analyseurs (trafic, NDR, DPI, IDS), qui gardent leur état
//! sans verrou. Le pare-feu de Windows filtre aussi ce que reçoit une socket brute : une règle
//! « deR4Tizer capture » autorise donc l'entrant pour le service.
//! Limite : un PC sur un réseau commuté ne voit que son propre trafic, le broadcast et le multicast.

use crate::commun;
use socket2::{Domain, Protocol, Socket, Type};
use std::cell::RefCell;
use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::os::windows::io::AsRawSocket;
use std::os::windows::process::CommandExt;
use std::time::{Duration, Instant};
use windows::Win32::Networking::WinSock::{WSAIoctl, RCVALL_ON, SIO_RCVALL, SOCKET};

pub const TCP: u8 = 6;
pub const UDP: u8 = 17;

pub struct Paquet<'a> {
    /// Vers ce PC (sinon : émis par ce PC)
    pub entrant: bool,
    pub proto: u8,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub port_source: u16,
    pub port_destination: u16,
    /// Longueur totale du paquet IP
    pub longueur: usize,
    /// Drapeaux TCP (SYN 0x02, ACK 0x10…)
    pub drapeaux: u8,
    pub charge: &'a [u8],
}

impl Paquet<'_> {
    /// Adresse et port de l'autre extrémité, et port local
    pub fn distant(&self) -> (Ipv4Addr, u16, u16) {
        if self.entrant { (self.source, self.port_source, self.port_destination) } else { (self.destination, self.port_destination, self.port_source) }
    }
}

#[derive(Default)]
struct Tables {
    tcp: HashMap<u16, u32>,
    udp: HashMap<u16, u32>,
    noms: HashMap<u32, String>,
    /// Connexions TCP établies : (port local, adresse distante, port distant)
    etablies: std::collections::HashSet<(u16, String, u16)>,
    lues: Option<Instant>,
}

/// Programme propriétaire d'un port local (tables TCP et UDP de Windows). Relues toutes les 2 s, et à la
/// demande (au plus toutes les 300 ms) quand un port est inconnu : nouvelle connexion.
#[derive(Default)]
pub struct Contexte {
    tables: RefCell<Tables>,
}

impl Contexte {
    fn rafraichir(&self) {
        let mut t = self.tables.borrow_mut();
        let tcp = crate::natif::lister_tcp();
        t.etablies = tcp.iter().filter(|c| c.etat == 5).map(|c| (c.port_local, c.ip.clone(), c.port)).collect();
        t.tcp = tcp.into_iter().map(|c| (c.port_local, c.pid)).collect();
        t.udp = crate::natif::lister_udp().into_iter().collect();
        t.noms = crate::natif::processus().into_iter().map(|(pid, i)| (pid, i.nom)).collect();
        t.lues = Some(Instant::now());
    }

    fn age(&self) -> Duration {
        self.tables.borrow().lues.map(|t| t.elapsed()).unwrap_or(Duration::MAX)
    }

    fn pid(&self, p: &Paquet) -> Option<u32> {
        let (_, _, port_local) = p.distant();
        let t = self.tables.borrow();
        match p.proto {
            TCP => t.tcp.get(&port_local).copied(),
            UDP => t.udp.get(&port_local).copied(),
            _ => None,
        }
    }

    /// Le paquet appartient à une connexion TCP établie (poignée de main complète) : l'adresse distante n'est
    /// donc pas usurpée, contrairement à un paquet isolé
    pub fn etablie(&self, p: &Paquet) -> bool {
        if p.proto != TCP {
            return false;
        }
        let (ip, port, port_local) = p.distant();
        let cle = (port_local, ip.to_string(), port);
        if self.tables.borrow().etablies.contains(&cle) {
            return true;
        }
        if self.age() > Duration::from_millis(300) {
            self.rafraichir();
        }
        self.tables.borrow().etablies.contains(&cle)
    }

    /// Nom du programme qui possède le port local du paquet, « ? » s'il est inconnu
    pub fn programme(&self, p: &Paquet) -> String {
        let mut pid = self.pid(p);
        if pid.is_none() && (p.proto == TCP || p.proto == UDP) && self.age() > Duration::from_millis(300) {
            self.rafraichir();
            pid = self.pid(p);
        }
        match pid {
            Some(4) => "System".into(),
            Some(pid) => self.tables.borrow().noms.get(&pid).cloned().unwrap_or_else(|| format!("PID {pid}")),
            None => "?".into(),
        }
    }
}

pub trait Analyseur: Send {
    fn paquet(&mut self, p: &Paquet, contexte: &Contexte);
    /// Appelé environ une fois par seconde (calculs, écriture de l'état)
    fn tic(&mut self) {}
}

/// Adresse IPv4 de l'interface qui porte la route par défaut (aucun paquet n'est envoyé)
pub fn adresse_locale() -> Option<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("1.1.1.1:53").ok()?;
    match s.local_addr().ok()? {
        SocketAddr::V4(a) if !a.ip().is_unspecified() => Some(*a.ip()),
        _ => None,
    }
}

/// Règle de pare-feu qui laisse arriver les paquets entrants jusqu'à la socket brute du service
fn autoriser_capture() {
    let Ok(exe) = std::env::current_exe() else { return };
    let script = format!(
        "if (-not (Get-NetFirewallRule -Name 'deR4Tizer-capture' -ErrorAction SilentlyContinue)) {{ \
         New-NetFirewallRule -Name 'deR4Tizer-capture' -DisplayName 'deR4Tizer capture' -Group '{}' -Direction Inbound \
         -Program '{}' -Action Allow -Protocol Any | Out-Null }}",
        crate::blocage::GROUPE, exe.to_string_lossy().replace('\'', "''"));
    crate::mesure::powershell("capture");
    let _ = std::process::Command::new(crate::natif::powershell_exe())
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .creation_flags(0x0800_0000)
        .output();
}

fn ouvrir(ip: Ipv4Addr) -> Result<Socket, String> {
    let s = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(0))).map_err(|e| format!("socket brute : {e}"))?;
    s.bind(&SocketAddr::from((ip, 0)).into()).map_err(|e| format!("liaison à {ip} : {e}"))?;
    let _ = s.set_read_timeout(Some(Duration::from_millis(500)));
    let _ = s.set_recv_buffer_size(8 * 1024 * 1024);
    let valeur: u32 = RCVALL_ON.0 as u32;
    let mut rendu = 0u32;
    let r = unsafe {
        WSAIoctl(SOCKET(s.as_raw_socket() as usize), SIO_RCVALL, Some(&valeur as *const u32 as *const _), 4, None, 0, &mut rendu, None, None)
    };
    if r != 0 {
        return Err(format!("SIO_RCVALL : {}", std::io::Error::last_os_error()));
    }
    Ok(s)
}

/// Décode un paquet IPv4 ; seul le premier fragment porte les ports et la charge utile
fn decoder(d: &[u8], locale: Ipv4Addr) -> Option<Paquet<'_>> {
    if d.len() < 20 || d[0] >> 4 != 4 {
        return None;
    }
    let ihl = (d[0] & 0x0F) as usize * 4;
    let total = (u16::from_be_bytes([d[2], d[3]]) as usize).min(d.len());
    if ihl < 20 || total < ihl {
        return None;
    }
    let decalage_fragment = u16::from_be_bytes([d[6], d[7]]) & 0x1FFF;
    let proto = d[9];
    let source = Ipv4Addr::new(d[12], d[13], d[14], d[15]);
    let destination = Ipv4Addr::new(d[16], d[17], d[18], d[19]);
    let mut p = Paquet {
        entrant: source != locale,
        proto,
        source,
        destination,
        port_source: 0,
        port_destination: 0,
        longueur: total,
        drapeaux: 0,
        charge: &[],
    };
    let l4 = &d[ihl..total];
    if decalage_fragment != 0 {
        return Some(p);
    }
    match proto {
        TCP if l4.len() >= 20 => {
            let entete = ((l4[12] >> 4) as usize * 4).max(20).min(l4.len());
            p.port_source = u16::from_be_bytes([l4[0], l4[1]]);
            p.port_destination = u16::from_be_bytes([l4[2], l4[3]]);
            p.drapeaux = l4[13];
            p.charge = &l4[entete..];
        }
        UDP if l4.len() >= 8 => {
            p.port_source = u16::from_be_bytes([l4[0], l4[1]]);
            p.port_destination = u16::from_be_bytes([l4[2], l4[3]]);
            p.charge = &l4[8..];
        }
        _ => {}
    }
    Some(p)
}

/// Lance un fil de capture sur l'interface que désigne `interface` (réévaluée toutes les 30 s) ;
/// sans interface, le fil attend. Renvoie immédiatement.
pub fn demarrer(
    nom: &str,
    mut analyseurs: Vec<Box<dyn Analyseur>>,
    interface: impl Fn() -> Option<Ipv4Addr> + Send + 'static,
    arret: impl Fn() -> bool + Send + 'static,
) {
    let nom = nom.to_string();
    std::thread::Builder::new().name(format!("capture {nom}")).spawn(move || {
        autoriser_capture();
        let mut tampon = vec![MaybeUninit::<u8>::uninit(); 65_536];
        let mut derniere_erreur = String::new();
        let mut dernier_tic = Instant::now();
        let contexte = Contexte::default();
        while !arret() {
            let Some(locale) = interface() else {
                std::thread::sleep(Duration::from_secs(30));
                continue;
            };
            let socket = match ouvrir(locale) {
                Ok(s) => s,
                Err(e) => {
                    if e != derniere_erreur {
                        commun::journal(&format!("capture des paquets ({nom}) impossible : {e}"));
                        derniere_erreur = e;
                    }
                    std::thread::sleep(Duration::from_secs(30));
                    continue;
                }
            };
            commun::journal(&format!("capture des paquets ({nom}) active sur {locale}"));
            derniere_erreur.clear();
            let mut verification = Instant::now();
            while !arret() {
                if let Ok(n) = socket.recv(&mut tampon) {
                    // Sûr : recv a initialisé les n premiers octets
                    let octets = unsafe { std::slice::from_raw_parts(tampon.as_ptr() as *const u8, n) };
                    if let Some(p) = decoder(octets, locale) {
                        for a in analyseurs.iter_mut() {
                            a.paquet(&p, &contexte);
                        }
                    }
                }
                if dernier_tic.elapsed() >= Duration::from_secs(1) {
                    dernier_tic = Instant::now();
                    if contexte.age() > Duration::from_secs(2) {
                        contexte.rafraichir();
                    }
                    for a in analyseurs.iter_mut() {
                        a.tic();
                    }
                }
                // Changement de réseau (Wi-Fi, VPN…) : on se relie à la nouvelle adresse
                if verification.elapsed() > Duration::from_secs(30) {
                    verification = Instant::now();
                    if interface() != Some(locale) {
                        break;
                    }
                }
            }
        }
    }).unwrap();
}

#[cfg(test)]
pub fn decoder_test(d: &[u8], locale: Ipv4Addr) -> Option<Paquet<'_>> {
    decoder(d, locale)
}
