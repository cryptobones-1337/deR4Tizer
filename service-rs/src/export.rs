//! Export des alertes vers un SIEM ou un outil tiers :
//!   - syslog (RFC 5424) en UDP ou TCP, détail en JSON ou au format CEF ;
//!   - mise en forme commune, réutilisée par l'API d'export (api.rs).
//! L'envoi passe par un fil dédié : une destination lente ne bloque jamais la surveillance.

use crate::commun::{self, Alerte, ConfigSyslog};
use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const PRODUIT: &str = "deR4Tizer";
/// Facilité syslog local4 (20)
const FACILITE: u8 = 20;

enum Message {
    Alerte(Alerte),
    Config(ConfigSyslog),
}

static FILE: OnceLock<Mutex<SyncSender<Message>>> = OnceLock::new();

/// Lance le fil d'envoi avec la configuration de départ
pub fn demarrer(config: &ConfigSyslog) {
    let (tx, rx) = sync_channel(2000);
    if FILE.set(Mutex::new(tx)).is_err() {
        return configurer(config);
    }
    let config = config.clone();
    std::thread::Builder::new().name("syslog".into()).spawn(move || boucle(config, rx)).unwrap();
}

pub fn configurer(config: &ConfigSyslog) {
    if let Some(f) = FILE.get() {
        let _ = f.lock().unwrap().try_send(Message::Config(config.clone()));
    }
}

/// Met l'alerte dans la file d'envoi (perdue si la file est pleine : la surveillance passe avant)
pub fn alerte(a: &Alerte) {
    if let Some(f) = FILE.get() {
        let _ = f.lock().unwrap().try_send(Message::Alerte(a.clone()));
    }
}

fn boucle(mut config: ConfigSyslog, rx: Receiver<Message>) {
    let mut tcp: Option<TcpStream> = None;
    let mut derniere_erreur = String::new();
    while let Ok(m) = rx.recv() {
        match m {
            Message::Config(c) => {
                tcp = None;
                config = c;
            }
            Message::Alerte(a) => {
                if !config.actif || rang(&a.niveau) < rang(&config.niveau_min) {
                    continue;
                }
                match envoyer(&config, &message(&config, &a), &mut tcp) {
                    Ok(()) => derniere_erreur.clear(),
                    Err(e) => {
                        if e != derniere_erreur {
                            commun::journal(&format!("syslog : envoi impossible vers {}:{} ({e})", config.hote, config.port));
                            derniere_erreur = e;
                        }
                    }
                }
            }
        }
    }
}

/// Envoie un message ; en TCP, la connexion est gardée et rouverte une fois en cas d'échec
fn envoyer(config: &ConfigSyslog, texte: &str, tcp: &mut Option<TcpStream>) -> Result<(), String> {
    let adresse = (config.hote.as_str(), config.port).to_socket_addrs().map_err(|e| e.to_string())?
        .next().ok_or("adresse introuvable")?;
    if config.protocole.eq_ignore_ascii_case("TCP") {
        // Trame terminée par un saut de ligne (RFC 6587, mode non transparent : rsyslog, syslog-ng, Graylog…)
        let ligne = format!("{texte}\n");
        for _ in 0..2 {
            if tcp.is_none() {
                let s = TcpStream::connect_timeout(&adresse, Duration::from_secs(3)).map_err(|e| e.to_string())?;
                let _ = s.set_write_timeout(Some(Duration::from_secs(3)));
                *tcp = Some(s);
            }
            if tcp.as_mut().unwrap().write_all(ligne.as_bytes()).is_ok() {
                return Ok(());
            }
            *tcp = None;
        }
        Err("connexion TCP perdue".into())
    } else {
        let s = UdpSocket::bind(if adresse.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }).map_err(|e| e.to_string())?;
        s.send_to(texte.as_bytes(), adresse).map(|_| ()).map_err(|e| e.to_string())
    }
}

/// Envoi immédiat d'un message de test (bouton « Tester » des réglages)
pub fn tester(config: &ConfigSyslog) -> Result<(), String> {
    if config.hote.trim().is_empty() {
        return Err("aucun serveur syslog indiqué".into());
    }
    let a = Alerte {
        id: commun::nouvel_id(),
        heure: commun::maintenant(),
        niveau: "Info".into(),
        processus: PRODUIT.into(),
        destination: "test".into(),
        raisons: "message de test envoyé depuis les réglages".into(),
        ..Default::default()
    };
    envoyer(config, &message(config, &a), &mut None)
}

// ------------------------------------------------------------ mise en forme

pub fn rang(niveau: &str) -> u8 {
    match niveau {
        "Critique" => 2,
        "Alerte" => 1,
        _ => 0,
    }
}

/// Gravité syslog : 2 critique, 4 avertissement, 6 information
fn gravite_syslog(niveau: &str) -> u8 {
    match niveau {
        "Critique" => 2,
        "Alerte" => 4,
        _ => 6,
    }
}

/// Gravité CEF (0 à 10)
fn gravite_cef(a: &Alerte) -> u8 {
    match a.niveau.as_str() {
        "Critique" => 9,
        "Alerte" => 6,
        _ => 2,
    }
}

pub fn hote_local() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "-".into())
}

/// Ligne syslog complète (en-tête RFC 5424 + corps JSON ou CEF)
pub fn message(config: &ConfigSyslog, a: &Alerte) -> String {
    let pri = FACILITE * 8 + gravite_syslog(&a.niveau);
    let corps = if config.format.eq_ignore_ascii_case("CEF") { cef(a) } else { json(a) };
    format!("<{pri}>1 {} {} {PRODUIT} {} alerte - {corps}", horodatage_utc(SystemTime::now()), hote_local(), std::process::id())
}

/// Alerte en JSON, avec l'hôte et le produit (une ligne)
pub fn json(a: &Alerte) -> String {
    let mut v = serde_json::to_value(a).unwrap_or_default();
    if let Some(o) = v.as_object_mut() {
        o.insert("Produit".into(), PRODUIT.into());
        o.insert("Hote".into(), hote_local().into());
    }
    v.to_string()
}

/// Alerte au format CEF : CEF:Version|Fournisseur|Produit|Version|Signature|Nom|Gravité|Extension
pub fn cef(a: &Alerte) -> String {
    // Tout caractère de contrôle (fin de ligne, NUL, ESC…) devient une espace (audit, AUD3-06)
    let sans_controle = |s: &str| s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect::<String>();
    let entete = |s: &str| sans_controle(s).replace('\\', "\\\\").replace('|', "\\|");
    let ext = |s: &str| sans_controle(s).replace('\\', "\\\\").replace('=', "\\=");
    let signature = if a.mitre.is_empty() { a.niveau.clone() } else { a.mitre.split_whitespace().next().unwrap_or("").to_string() };
    let nom: String = a.raisons.chars().take(120).collect();
    let mut e = vec![
        format!("rt={}", ext(&date_cef(&a.heure))),
        format!("dvchost={}", ext(&hote_local())),
        format!("sproc={}", ext(&a.processus)),
        format!("cs1Label=Score cs1={}", a.score),
        format!("msg={}", ext(&a.raisons)),
    ];
    if !a.chemin.is_empty() {
        e.push(format!("filePath={}", ext(&a.chemin)));
    }
    if let Some(pid) = a.pid {
        e.push(format!("spid={pid}"));
    }
    if let Some(ip) = a.ip.as_deref().filter(|i| !i.is_empty()) {
        e.push(format!("dst={}", ext(ip)));
    }
    if let Some(n) = a.nom_dns.as_deref().filter(|n| !n.is_empty()) {
        e.push(format!("dhost={}", ext(n)));
    }
    if a.port > 0 {
        e.push(format!("dpt={}", a.port));
    }
    if !a.mitre.is_empty() {
        e.push(format!("cs2Label=MITRE cs2={}", ext(&a.mitre)));
    }
    format!("CEF:0|{PRODUIT}|{PRODUIT}|{}|{}|{}|{}|{}", commun::VERSION, entete(&signature), entete(&nom), gravite_cef(a), e.join(" "))
}

/// Date CEF « MMM dd yyyy HH:mm:ss » à partir de l'heure locale « yyyy-MM-dd HH:mm:ss » des alertes
fn date_cef(heure: &str) -> String {
    const MOIS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let (Some(a), Some(m), Some(j), Some(h)) = (heure.get(0..4), heure.get(5..7), heure.get(8..10), heure.get(11..19)) else {
        return heure.to_string();
    };
    match m.parse::<usize>() {
        Ok(m) if (1..=12).contains(&m) => format!("{} {j} {a} {h}", MOIS[m - 1]),
        _ => heure.to_string(),
    }
}

/// Horodatage RFC 3339 en UTC (2026-10-22T07:05:37.123Z)
pub fn horodatage_utc(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs() as i64;
    let (jours, s) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Jours depuis 1970 vers date civile (algorithme de Howard Hinnant)
    let z = jours + 719_468;
    let ere = z.div_euclid(146_097);
    let jde = z - ere * 146_097;
    let ade = (jde - jde / 1460 + jde / 36_524 - jde / 146_096) / 365;
    let jda = jde - (365 * ade + ade / 4 - ade / 100);
    let mp = (5 * jda + 2) / 153;
    let jour = jda - (153 * mp + 2) / 5 + 1;
    let mois = if mp < 10 { mp + 3 } else { mp - 9 };
    let annee = ade + ere * 400 + if mois <= 2 { 1 } else { 0 };
    format!("{annee:04}-{mois:02}-{jour:02}T{:02}:{:02}:{:02}.{:03}Z", s / 3600, s % 3600 / 60, s % 60, d.subsec_millis())
}
