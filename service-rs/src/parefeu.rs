//! Pare-feu et exposition à Internet :
//!   - changements de règles (journal « Windows Firewall With Advanced Security/Firewall », avec le programme auteur) ;
//!   - paquets entrants venus d'Internet, lus dans pfirewall.log : le PC est alors joignable depuis Internet ;
//!   - adresse publique portée directement par une carte réseau (pas de box ni de NAT devant).

use crate::commun::{self, Alerte};
use crate::evenements;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const JOURNAL: &str = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall";

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct EvenementRegle {
    pub heure: String,
    /// "ajoutée", "modifiée", "supprimée", "toutes supprimées"
    pub operation: String,
    pub regle: String,
    pub sens: String,
    pub action: String,
    pub ports: String,
    pub programme_cible: String,
    pub auteur: String,
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct EntreeExposee {
    pub derniere: String,
    pub premiere: String,
    pub source: String,
    pub port_local: u16,
    pub protocole: String,
    /// "ACCEPTÉ" ou "BLOQUÉ"
    pub action: String,
    pub nombre: u32,
    pub programme: String,
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Exposition {
    pub exposee: bool,
    pub raisons: Vec<String>,
    pub adresses_publiques: Vec<String>,
    pub journal_paquets: bool,
    pub entrees: Vec<EntreeExposee>,
    /// Ce sur quoi repose le verdict (journal des paquets, UPnP), pour ne pas affirmer plus qu'on ne sait
    pub base: String,
}

// ------------------------------------------------------------ adresses

/// Adresse joignable depuis Internet (ni privée, ni locale, ni réservée)
pub fn publique(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            !(v.is_private() || v.is_loopback() || v.is_link_local() || v.is_broadcast() || v.is_multicast() || v.is_unspecified()
                || o[0] == 0 || o[0] >= 240 || (o[0] == 100 && (64..128).contains(&o[1])))
        }
        IpAddr::V6(v) => {
            // Monodiffusion globale seulement (2000::/3)
            let s = v.segments();
            (s[0] & 0xE000) == 0x2000 && !v.is_loopback()
        }
    }
}

/// Adresses publiques portées directement par une carte réseau (GetAdaptersAddresses)
pub fn adresses_publiques() -> Vec<String> {
    use windows::Win32::NetworkManagement::IpHelper::{GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH};
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6};
    let mut l = Vec::new();
    unsafe {
        let mut taille: u32 = 32 * 1024;
        let mut tampon = vec![0u8; taille as usize];
        let drapeaux = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        let mut r = GetAdaptersAddresses(AF_UNSPEC.0 as u32, drapeaux, None, Some(tampon.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH), &mut taille);
        if r == 111 {
            tampon = vec![0u8; taille as usize];
            r = GetAdaptersAddresses(AF_UNSPEC.0 as u32, drapeaux, None, Some(tampon.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH), &mut taille);
        }
        if r != 0 {
            return l;
        }
        let mut a = tampon.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !a.is_null() {
            let nom = (*a).FriendlyName.to_string().unwrap_or_default();
            let mut u = (*a).FirstUnicastAddress;
            while !u.is_null() {
                let sa = (*u).Address.lpSockaddr;
                if !sa.is_null() {
                    let ip = if (*sa).sa_family == AF_INET {
                        let s = &*(sa as *const SOCKADDR_IN);
                        Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(s.sin_addr.S_un.S_addr))))
                    } else if (*sa).sa_family == AF_INET6 {
                        let s = &*(sa as *const SOCKADDR_IN6);
                        Some(IpAddr::V6(Ipv6Addr::from(s.sin6_addr.u.Byte)))
                    } else {
                        None
                    };
                    if let Some(ip) = ip.filter(publique) {
                        l.push(format!("{ip} ({nom})"));
                    }
                }
                u = (*u).Next;
            }
            a = (*a).Next;
        }
    }
    l
}

// ------------------------------------------------------------ règles du pare-feu

fn sens(d: &str) -> &'static str {
    match d {
        "1" => "entrant",
        "2" => "sortant",
        _ => "?",
    }
}

fn action(a: &str) -> &'static str {
    match a {
        "1" => "autoriser (contournement)",
        "2" => "bloquer",
        "3" => "autoriser",
        _ => "?",
    }
}

/// Traduit un événement du journal du pare-feu ; renvoie l'événement et éventuellement une alerte
pub fn traduire(xml: &str, signataire: &dyn Fn(&str) -> String) -> Option<(EvenementRegle, Option<Alerte>)> {
    let id: u32 = regex::Regex::new(r"<EventID[^>]*>(\d+)</EventID>").ok()?.captures(xml)?[1].parse().ok()?;
    let operation = match id {
        2004 | 2071 | 2097 => "ajoutée",
        2005 | 2072 | 2099 => "modifiée",
        2006 | 2033 | 2052 => "supprimée",
        2032 | 2059 => "toutes supprimées",
        _ => return None,
    };
    let d = evenements::donnees(xml);
    let v = |c: &str| d.get(c).cloned().unwrap_or_default();
    let e = EvenementRegle {
        heure: commun::maintenant(),
        operation: operation.into(),
        regle: if v("RuleName").is_empty() { v("RuleId") } else { v("RuleName") },
        sens: sens(&v("Direction")).into(),
        action: action(&v("Action")).into(),
        ports: [v("LocalPorts"), v("RemotePorts")].iter().filter(|p| !p.is_empty() && *p != "*").cloned().collect::<Vec<_>>().join(" / "),
        programme_cible: v("ApplicationPath"),
        auteur: v("ModifyingApplication"),
    };
    // Nos propres règles (blocages, isolements) ne déclenchent rien
    if e.regle.starts_with("deR4Tizer") {
        return Some((e, None));
    }
    let auteur_sig = if e.auteur.is_empty() || !Path::new(&e.auteur).exists() { "?".to_string() } else { signataire(&e.auteur) };
    let auteur_nom = Path::new(&e.auteur).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "?".into());
    let entrant_autorise = e.sens == "entrant" && e.action.starts_with("autoriser") && e.operation != "supprimée";
    let auteur_bas = e.auteur.to_lowercase();
    // Emplacements réservés aux administrateurs : un installeur temporaire disparu de là est un programme de mise à jour
    let dossier_protege = auteur_bas.contains(r"\program files") || auteur_bas.contains(r"\windows\systemtemp\");
    let outil_ligne_commande = ["netsh", "powershell", "pwsh", "cmd", "wmic"].contains(&auteur_nom.to_lowercase().as_str());
    let alerte = if operation == "toutes supprimées" && auteur_nom.eq_ignore_ascii_case("svchost") && crate::natif::binaire_windows(&e.auteur) {
        // Actualisation de la stratégie de groupe (gpupdate) : Windows recharge les règles de la GPO, ce qui
        // s'annonce comme une suppression de toutes les règles de ce magasin
        Some(("Info", 0, "règles du pare-feu rechargées par Windows (actualisation de la stratégie de groupe)".to_string()))
    } else if operation == "toutes supprimées" {
        Some(("Critique", 10, format!("TOUTES les règles du pare-feu ont été supprimées (par {})", if e.auteur.is_empty() { "?" } else { &e.auteur })))
    } else if auteur_sig.is_empty() {
        Some(("Critique", 8, format!("le pare-feu a été modifié par un programme NON SIGNÉ : règle « {} » {} ({} {})", e.regle, operation, e.sens, e.action)))
    } else if entrant_autorise && outil_ligne_commande {
        // Technique classique : « netsh advfirewall firewall add rule … action=allow »
        Some(("Alerte", 4, format!("port entrant ouvert en ligne de commande ({auteur_nom}) : règle « {} » {}{}", e.regle, operation,
            if e.ports.is_empty() { String::new() } else { format!(", ports {}", e.ports) })))
    } else if entrant_autorise && auteur_sig == "?" && dossier_protege {
        Some(("Info", 0, format!("règle de pare-feu entrante « {} » {} par un installeur de mise à jour ({})", e.regle, operation, auteur_nom)))
    } else if entrant_autorise && !auteur_sig.starts_with("Microsoft") && auteur_sig != "Windows (catalogue)" && auteur_sig != "?" {
        // Programme tiers signé (installeur, mise à jour) : information ; Windows lui-même : journal seulement
        Some(("Info", 0, format!("règle de pare-feu qui AUTORISE l'entrant : « {} » {}{} par {} (signé {})",
            e.regle, operation, if e.ports.is_empty() { String::new() } else { format!(", ports {}", e.ports) }, auteur_nom, auteur_sig)))
    } else if entrant_autorise && auteur_sig == "?" && !e.auteur.is_empty() {
        // Auteur disparu depuis (installeur temporaire) : on ne peut pas vérifier sa signature
        Some(("Alerte", 3, format!("règle de pare-feu qui AUTORISE l'entrant « {} » {} par un programme introuvable ({})", e.regle, operation, e.auteur)))
    } else {
        None
    };
    let alerte = alerte.map(|(niveau, score, raisons)| Alerte {
        id: commun::nouvel_id(),
        heure: commun::maintenant(),
        niveau: niveau.into(),
        score,
        processus: auteur_nom.clone(),
        chemin: e.auteur.clone(),
        destination: format!("règle de pare-feu : {}", e.regle),
        raisons,
        ..Default::default()
    });
    Some((e, alerte))
}

/// Suit le journal du pare-feu : chaque changement de règle est noté (parefeu.json), certains alertent
pub fn surveiller_regles(file: Arc<Mutex<Vec<Alerte>>>, signataire: impl Fn(&str) -> String + Send + 'static) -> bool {
    let mut historique: Vec<EvenementRegle> = commun::lire("parefeu.json").unwrap_or_default();
    evenements::abonner(JOURNAL, "*[System[(EventID=2004 or EventID=2005 or EventID=2006 or EventID=2032 or EventID=2033 or EventID=2052 or EventID=2059 or EventID=2071 or EventID=2072 or EventID=2097 or EventID=2099)]]",
        move |xml| {
            let Some((e, a)) = traduire(&xml, &signataire) else { return };
            crate::siem::regle_parefeu(&e.operation, &e.regle, &e.sens, &e.action, &e.auteur);
            historique.push(e);
            if historique.len() > 300 {
                historique.remove(0);
            }
            let _ = commun::ecrire("parefeu.json", &historique);
            if let Some(a) = a {
                // Actualisation de la GPO classée en information : on vérifie une minute plus tard que les règles
                // sont bien revenues (Windows en compte plusieurs centaines) ; sinon, alerte critique
                if a.raisons.starts_with("règles du pare-feu rechargées") {
                    let f = file.clone();
                    std::thread::spawn(move || {
                        std::thread::sleep(std::time::Duration::from_secs(60));
                        let n = crate::blocage::nombre_regles().unwrap_or(0);
                        if n < 50 {
                            f.lock().unwrap().push(Alerte {
                                id: commun::nouvel_id(),
                                heure: commun::maintenant(),
                                niveau: "Critique".into(),
                                score: 10,
                                processus: "svchost".into(),
                                destination: "règles du pare-feu".into(),
                                raisons: format!("après une suppression de toutes les règles du pare-feu, seules {n} règle(s) sont revenues : pare-feu vidé  [MITRE T1562.004]"),
                                mitre: "T1562.004".into(),
                                ..Default::default()
                            });
                        }
                    });
                }
                file.lock().unwrap().push(a);
            }
        })
}

// ------------------------------------------------------------ paquets entrants venus d'Internet (pfirewall.log)

/// Le pare-feu n'écrit pas son journal si le dossier n'existe pas (il ne le crée jamais lui-même) :
/// on le crée, on donne l'écriture au service du pare-feu (MpsSvc), puis on lui fait relire la stratégie.
fn preparer_dossier(fichier: &Path) {
    use std::os::windows::process::CommandExt;
    if fichier.exists() {
        return;
    }
    let Some(dossier) = fichier.parent() else { return };
    if !dossier.exists() && fs::create_dir_all(dossier).is_err() {
        return;
    }
    let _ = std::process::Command::new("icacls.exe")
        .arg(dossier)
        .args(["/grant", r"NT SERVICE\mpssvc:(OI)(CI)M"])
        .creation_flags(0x0800_0000)
        .output();
    // Il ne rouvre le fichier que sur un changement de stratégie : on reporte les mêmes réglages dans
    // le magasin local (changement de profil, pas de règle : aucune alerte de deR4Tizer)
    let fichier = fichier.to_path_buf();
    std::thread::spawn(move || {
        let script = "Set-NetFirewallProfile -All -PolicyStore localhost -LogBlocked True -LogAllowed True \
            -LogMaxSizeKilobytes 32767 -LogFileName '%systemroot%\\system32\\LogFiles\\Firewall\\pfirewall.log'";
        crate::mesure::powershell("parefeu");
        let _ = std::process::Command::new(crate::natif::powershell_exe())
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .creation_flags(0x0800_0000)
            .output();
        std::thread::sleep(Duration::from_secs(20));
        commun::journal(if fichier.exists() {
            "journal du pare-feu : actif (pfirewall.log)"
        } else {
            "journal du pare-feu : configuré, le fichier apparaîtra au redémarrage du pare-feu"
        });
    });
}

/// Ce qu'il faut savoir du poste pour distinguer une exposition réelle d'une réponse à une connexion sortante
pub struct ContexteExposition {
    /// Ports TCP locaux en écoute (état LISTEN) au moment de la lecture
    pub ecoute_tcp: std::collections::HashSet<u16>,
    /// Plage dynamique UDP du poste (ports des sockets clientes), bornes comprises
    pub udp_dynamique: (u16, u16),
    /// PID du service : ses lignes sont les copies reçues par sa socket de capture (règle « deR4Tizer capture »)
    pub pid_service: u32,
}

/// Décision pure : un paquet entrant venu d'Internet et ACCEPTÉ montre-t-il que le PC est joignable ? Non pour les
/// lignes du service (capture), ni pour les réponses aux connexions sortantes : en TCP, elles arrivent sur un port
/// éphémère où rien n'écoute (la plage dynamique TCP peut couvrir presque tous les ports : seul l'état d'écoute
/// fait foi) ; en UDP, sur un port de la plage dynamique ; en ICMP, ce sont des réponses d'écho (type 0)
pub fn exposition_reelle(protocole: &str, port_local: u16, pid: u32, icmp_type: &str, ctx: &ContexteExposition) -> bool {
    if pid != 0 && pid == ctx.pid_service {
        return false;
    }
    match protocole {
        "TCP" => ctx.ecoute_tcp.contains(&port_local),
        "UDP" => !(ctx.udp_dynamique.0..=ctx.udp_dynamique.1).contains(&port_local),
        "ICMP" => icmp_type == "8",
        _ => true,
    }
}

/// Durée pendant laquelle un envoi UDP du poste rend légitime la réponse en sens inverse
pub const DELAI_REPONSE_UDP: Duration = Duration::from_secs(120);

/// Flux UDP sortants récents : (port local, adresse distante, port distant) → heure de l'envoi
pub type FluxUdp = HashMap<(u16, IpAddr, u16), Instant>;

/// Décision pure, UDP : le paquet reçu (source:port_source vers port_local) répond-il à un envoi récent du poste
/// (port_local vers source:port_source) ? Décidé par l'état du flux, pas par une liste de ports : le client NTP de
/// Windows envoie depuis son port local 123 vers time.windows.com:123, et la réponse (123 vers 123) arrive hors de
/// la plage dynamique
pub fn reponse_udp(flux: &FluxUdp, port_local: u16, source: IpAddr, port_source: u16, maintenant: Instant) -> bool {
    flux.get(&(port_local, source, port_source)).is_some_and(|t| maintenant.saturating_duration_since(*t) <= DELAI_REPONSE_UDP)
}

/// Plage dynamique lue dans la sortie de « netsh int ipv4 show dynamicport … » (anglais ou français : les deux
/// nombres dans l'ordre, port de départ puis nombre de ports) ; None si illisible
pub fn plage_dynamique(sortie: &str) -> Option<(u16, u16)> {
    let nombres: Vec<u32> = sortie.lines().filter_map(|l| l.rsplit(':').next()?.trim().parse().ok()).collect();
    let (&debut, &nombre) = (nombres.first()?, nombres.get(1)?);
    let fin = debut.checked_add(nombre)?.checked_sub(1)?;
    (debut > 0 && nombre > 0 && fin <= 65535).then_some((debut as u16, fin as u16))
}

/// Plage dynamique UDP du poste (netsh), défaut de Windows si illisible
pub fn plage_dynamique_udp() -> (u16, u16) {
    use std::os::windows::process::CommandExt;
    std::process::Command::new("netsh.exe").args(["int", "ipv4", "show", "dynamicport", "udp"])
        .creation_flags(0x0800_0000).output().ok()
        .and_then(|s| plage_dynamique(&String::from_utf8_lossy(&s.stdout)))
        .unwrap_or((49152, 65535))
}

pub struct LecteurJournal {
    fichier: PathBuf,
    position: u64,
    champs: Vec<String>,
    entrees: HashMap<(String, u16, String), EntreeExposee>,
    alertees: HashMap<(String, u16, String), Instant>,
    flux_udp: FluxUdp,
}

impl LecteurJournal {
    pub fn nouveau() -> LecteurJournal {
        let fichier = PathBuf::from(crate::natif::dossier_systeme()).join(r"LogFiles\Firewall\pfirewall.log");
        preparer_dossier(&fichier);
        // On démarre à la fin du fichier : seuls les nouveaux paquets comptent
        let position = fs::metadata(&fichier).map(|m| m.len()).unwrap_or(0);
        let entrees = commun::lire::<Vec<EntreeExposee>>("exposition.json")
            .unwrap_or_default()
            .into_iter()
            .map(|e| ((e.source.clone(), e.port_local, e.action.clone()), e))
            .collect();
        LecteurJournal { fichier, position, champs: Vec::new(), entrees, alertees: HashMap::new(), flux_udp: HashMap::new() }
    }

    /// Lecteur sur un autre fichier (tests), positionné à la fin
    #[allow(dead_code)]
    pub fn sur_fichier(fichier: PathBuf) -> LecteurJournal {
        let position = fs::metadata(&fichier).map(|m| m.len()).unwrap_or(0);
        LecteurJournal { fichier, position, champs: Vec::new(), entrees: HashMap::new(), alertees: HashMap::new(), flux_udp: HashMap::new() }
    }

    pub fn actif(&self) -> bool {
        self.fichier.exists()
    }

    /// Lit les lignes ajoutées depuis le dernier passage ; renvoie les alertes
    pub fn lire(&mut self, nom_processus: &dyn Fn(u32) -> String, ctx: &ContexteExposition) -> Vec<Alerte> {
        let mut alertes = Vec::new();
        let Ok(mut f) = fs::File::open(&self.fichier) else { return alertes };
        let taille = f.metadata().map(|m| m.len()).unwrap_or(0);
        if taille < self.position {
            self.position = 0; // le journal a été recommencé (taille maximale atteinte)
        }
        if taille == self.position || f.seek(SeekFrom::Start(self.position)).is_err() {
            return alertes;
        }
        let mut nouveau = Vec::new();
        let _ = f.by_ref().take(8 * 1024 * 1024).read_to_end(&mut nouveau);
        // On ne traite que les lignes complètes
        let fin = nouveau.iter().rposition(|&c| c == b'\n').map(|p| p + 1).unwrap_or(0);
        self.position += fin as u64;
        let texte = String::from_utf8_lossy(&nouveau[..fin]).to_string();
        let mut modifie = false;
        for ligne in texte.lines() {
            if let Some(c) = ligne.strip_prefix("#Fields:") {
                self.champs = c.split_whitespace().map(String::from).collect();
                continue;
            }
            if ligne.starts_with('#') || ligne.trim().is_empty() {
                continue;
            }
            if self.champs.is_empty() {
                // En-tête standard de Windows si on a commencé après lui
                self.champs = "date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path pid"
                    .split(' ').map(String::from).collect();
            }
            let valeurs: Vec<&str> = ligne.split_whitespace().collect();
            let v = |nom: &str| self.champs.iter().position(|c| c == nom).and_then(|i| valeurs.get(i)).copied().unwrap_or("");
            // Envois UDP du poste : état des flux, pour reconnaître leurs réponses
            if v("path") == "SEND" {
                if v("protocol") == "UDP" {
                    if let (Ok(local), Ok(ip), Ok(distant)) = (v("src-port").parse::<u16>(), v("dst-ip").parse::<IpAddr>(), v("dst-port").parse::<u16>()) {
                        self.flux_udp.insert((local, ip, distant), Instant::now());
                    }
                }
                continue;
            }
            if v("path") != "RECEIVE" {
                continue;
            }
            let Ok(source) = v("src-ip").parse::<IpAddr>() else { continue };
            if !publique(&source) {
                continue;
            }
            let port: u16 = v("dst-port").parse().unwrap_or(0);
            let action = if v("action") == "ALLOW" { "ACCEPTÉ" } else { "BLOQUÉ" };
            let port_source: u16 = v("src-port").parse().unwrap_or(0);
            // Paquet accepté : seulement s'il montre une exposition réelle (pas la capture du service, pas une
            // réponse à une connexion sortante). Une réponse UDP acceptée vers un port dynamique est retenue comme
            // flux établi : le paquet bloqué qui la suivrait (état du flux perdu) n'est pas une exposition
            let pid: u32 = v("pid").parse().unwrap_or(0);
            if action == "ACCEPTÉ" && !exposition_reelle(v("protocol"), port, pid, v("icmptype"), ctx) {
                // Retenue seulement une vraie réponse : vers un port dynamique, et pas une ligne du service (sa socket de
                // capture reçoit des copies de tout paquet, que le pare-feu peut ensuite bloquer)
                let dynamique = (ctx.udp_dynamique.0..=ctx.udp_dynamique.1).contains(&port);
                if v("protocol") == "UDP" && dynamique && !(pid != 0 && pid == ctx.pid_service) {
                    self.flux_udp.insert((port, source, port_source), Instant::now());
                }
                continue;
            }
            // Accepté ou bloqué : un paquet UDP qui reprend en sens inverse un flux que le poste vient d'utiliser est
            // une réponse. Bloqué, il ne montre pas que la box laisse entrer des connexions (constaté : réponses d'un
            // flux QUIC sortant bloquées pendant une reconfiguration du réseau, réponses du serveur d'un VPN)
            if v("protocol") == "UDP" && reponse_udp(&self.flux_udp, port, source, port_source, Instant::now()) {
                continue;
            }
            let programme = v("pid").parse::<u32>().ok().filter(|p| *p > 0).map(nom_processus).unwrap_or_default();
            let cle = (source.to_string(), port, action.to_string());
            let maintenant = commun::maintenant();
            let e = self.entrees.entry(cle.clone()).or_insert_with(|| EntreeExposee {
                premiere: maintenant.clone(),
                source: source.to_string(),
                port_local: port,
                protocole: v("protocol").into(),
                action: action.into(),
                ..Default::default()
            });
            e.derniere = maintenant;
            e.nombre += 1;
            if !programme.is_empty() {
                e.programme = programme.clone();
            }
            modifie = true;
            // Une alerte par source, port et action toutes les 24 h
            if self.alertees.get(&cle).map(|t| t.elapsed() < Duration::from_secs(86400)).unwrap_or(false) {
                continue;
            }
            self.alertees.insert(cle, Instant::now());
            let accepte = action == "ACCEPTÉ";
            alertes.push(Alerte {
                id: commun::nouvel_id(),
                heure: commun::maintenant(),
                niveau: if accepte { "Critique" } else { "Alerte" }.into(),
                score: if accepte { 8 } else { 3 },
                processus: if programme.is_empty() { "?".into() } else { programme },
                destination: source.to_string(),
                ip: Some(source.to_string()),
                port,
                raisons: format!(
                    "PC EXPOSÉ À INTERNET : paquet entrant {} venu de {} vers le port local {} ({}){}",
                    if accepte { "ACCEPTÉ" } else { "bloqué par le pare-feu" },
                    source, port, v("protocol"),
                    if accepte { " — un programme de ce PC est joignable depuis Internet" } else { " — votre box ou votre réseau laisse passer des connexions entrantes jusqu'au PC" }
                ),
                ..Default::default()
            });
        }
        self.flux_udp.retain(|_, t| t.elapsed() <= DELAI_REPONSE_UDP);
        if modifie {
            // Les 200 entrées les plus récentes
            let mut liste: Vec<EntreeExposee> = self.entrees.values().cloned().collect();
            liste.sort_by(|a, b| b.derniere.cmp(&a.derniere));
            liste.truncate(200);
            self.entrees = liste.iter().map(|e| ((e.source.clone(), e.port_local, e.action.clone()), e.clone())).collect();
            let _ = commun::ecrire("exposition.json", &liste);
        }
        alertes
    }

    /// Bilan d'exposition pour l'interface
    pub fn bilan(&self, adresses: &[String], reseau: &crate::ndr::EtatReseau) -> Exposition {
        let mut entrees: Vec<EntreeExposee> = self.entrees.values().cloned().collect();
        entrees.sort_by(|a, b| b.derniere.cmp(&a.derniere));
        let hier = commun::heure(std::time::SystemTime::now() - Duration::from_secs(86400));
        let recentes: Vec<&EntreeExposee> = entrees.iter().filter(|e| e.derniere > hier).collect();
        let mut raisons = Vec::new();
        if !adresses.is_empty() {
            raisons.push(format!("adresse publique directement sur le PC : {}", adresses.join(", ")));
        }
        let acceptees = recentes.iter().filter(|e| e.action == "ACCEPTÉ").count();
        let bloquees = recentes.len() - acceptees;
        if acceptees > 0 {
            raisons.push(format!("{acceptees} connexion(s) entrante(s) venues d'Internet ACCEPTÉES en 24 h"));
        }
        if bloquees > 0 {
            raisons.push(format!("{bloquees} source(s) d'Internet ont atteint le PC en 24 h (bloquées par le pare-feu)"));
        }
        for r in reseau.redirections.iter().filter(|r| r.active && r.client == reseau.interface) {
            raisons.push(format!("la box redirige le port {} ({}) d'Internet vers ce PC, port {} (UPnP{})", r.port_externe, r.protocole, r.port_interne,
                if r.description.is_empty() { String::new() } else { format!(" : « {} »", r.description) }));
        }
        let base = format!("journal des paquets du pare-feu : {} ; redirections de la box (UPnP) : {}",
            if self.actif() { "actif" } else { "INACTIF (redémarrez le PC pour l'activer), entrées non vérifiées" },
            if reseau.upnp.is_empty() { "pas encore vérifiées".to_string() } else { reseau.upnp.clone() });
        Exposition {
            exposee: !raisons.is_empty(),
            raisons,
            adresses_publiques: adresses.to_vec(),
            journal_paquets: self.actif(),
            entrees: entrees.into_iter().take(50).collect(),
            base,
        }
    }
}
