//! Origine des fichiers et actions de réponse :
//!   - origine : marque « Mark of the Web » posée par Windows sur les fichiers téléchargés (flux Zone.Identifier),
//!     âge du fichier ;
//!   - réponse : tuer, suspendre ou reprendre un processus, mettre un fichier en quarantaine (et le restaurer),
//!     isoler un programme du réseau, mode panique (tout le trafic sortant bloqué sauf Windows).

use crate::blocage;
use crate::commun;
use crate::natif::{self, large};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use windows::core::{BSTR, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, VARIANT_TRUE};
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, NetFwPolicy2, NetFwRule, NET_FW_ACTION_BLOCK, NET_FW_PROFILE2_DOMAIN,
    NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC, NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT,
};
use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE};

// ------------------------------------------------------------ origine des fichiers

#[derive(Clone, Default)]
pub struct Origine {
    /// 3 = Internet, 4 = sites non fiables
    pub zone: u32,
    pub source: String,
    pub age_jours: u64,
}

/// Lit la marque « téléchargé depuis Internet » (flux de données alternatif Zone.Identifier) et l'âge du fichier
pub fn origine(chemin: &str) -> Option<Origine> {
    if chemin.is_empty() {
        return None;
    }
    let age_jours = fs::metadata(chemin)
        .and_then(|m| m.created())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .map(|d| d.as_secs() / 86400)
        .unwrap_or(9999);
    let mut o = Origine { age_jours, ..Default::default() };
    if let Ok(t) = fs::read_to_string(format!("{chemin}:Zone.Identifier")) {
        for l in t.lines() {
            if let Some(z) = l.strip_prefix("ZoneId=") {
                o.zone = z.trim().parse().unwrap_or(0);
            } else if let Some(u) = l.strip_prefix("HostUrl=") {
                o.source = u.trim().to_string();
            } else if let Some(u) = l.strip_prefix("ReferrerUrl=") {
                if o.source.is_empty() {
                    o.source = u.trim().to_string();
                }
            }
        }
    }
    Some(o)
}

impl Origine {
    pub fn texte(&self) -> Option<String> {
        if self.zone < 3 {
            return None;
        }
        let source = if self.source.is_empty() { "Internet".to_string() } else { self.source.chars().take(120).collect() };
        Some(format!("téléchargé depuis {source}{}", if self.age_jours < 2 { " (il y a moins de 2 jours)" } else { "" }))
    }
}

// ------------------------------------------------------------ processus

/// Processus dont l'arrêt ou la suspension fige ou fait planter Windows (vérifiés : binaire de Windows)
const CRITIQUES: &[&str] = &[
    "csrss", "wininit", "winlogon", "lsass", "lsaiso", "services", "smss", "svchost", "dwm", "fontdrvhost", "registry",
    "memory compression", "secure system", "msmpeng", "mpdefendercoreservice",
];

/// Raison de refuser d'agir sur ce processus, s'il y en a une
pub fn protege(pid: u32) -> Option<String> {
    if pid <= 4 || pid == std::process::id() {
        return Some("processus du système ou de deR4Tizer".into());
    }
    let chemin = natif::chemin_processus(pid);
    let nom = Path::new(&chemin).file_stem().map(|s| s.to_string_lossy().to_lowercase()).unwrap_or_default();
    (CRITIQUES.contains(&nom.as_str()) && natif::binaire_windows(&chemin))
        .then(|| format!("{nom} est un processus critique de Windows (le système ou le réseau se figerait)"))
}

pub fn tuer(pid: u32) -> Result<(), String> {
    if let Some(r) = protege(pid) {
        return Err(format!("refusé : {r}"));
    }
    unsafe {
        let h = OpenProcess(PROCESS_TERMINATE, false, pid).map_err(|e| e.to_string())?;
        let r = TerminateProcess(h, 1).map_err(|e| e.to_string());
        let _ = CloseHandle(h);
        r
    }
}

/// Suspend ou reprend tous les fils d'un processus (fonctions NtSuspendProcess / NtResumeProcess de ntdll)
pub fn suspendre(pid: u32, suspendre: bool) -> Result<(), String> {
    if suspendre {
        if let Some(r) = protege(pid) {
            return Err(format!("refusé : {r}"));
        }
    }
    unsafe {
        let nom = large("ntdll.dll");
        let module = LoadLibraryW(PCWSTR(nom.as_ptr())).map_err(|e| e.to_string())?;
        let fonction = if suspendre { windows::core::s!("NtSuspendProcess") } else { windows::core::s!("NtResumeProcess") };
        let f = GetProcAddress(module, fonction).ok_or("fonction introuvable")?;
        let f: extern "system" fn(windows::Win32::Foundation::HANDLE) -> i32 = std::mem::transmute(f);
        let h = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid).map_err(|e| e.to_string())?;
        let statut = f(h);
        let _ = CloseHandle(h);
        if statut == 0 { Ok(()) } else { Err(format!("statut NT 0x{statut:08X}")) }
    }
}

// ------------------------------------------------------------ quarantaine

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct ElementQuarantaine {
    pub id: String,
    pub chemin_origine: String,
    pub date: String,
    pub raison: String,
    pub taille: u64,
}

fn dossier_quarantaine() -> PathBuf {
    commun::dossier().join("quarantaine")
}

/// Tue les processus qui exécutent ce fichier, puis le déplace dans la quarantaine (renommé, inexécutable)
pub fn mettre_en_quarantaine(chemin: &str, raison: &str) -> Result<String, String> {
    let p = Path::new(chemin);
    if !p.is_file() {
        return Err(format!("fichier introuvable : {chemin}"));
    }
    let bas = chemin.to_lowercase();
    if bas.starts_with(&natif::dossier_windows().to_lowercase()) {
        return Err("refusé : fichier du système Windows".into());
    }
    for (pid, _) in natif::processus() {
        if natif::chemin_processus(pid).eq_ignore_ascii_case(chemin) {
            let _ = tuer(pid);
        }
    }
    std::thread::sleep(std::time::Duration::from_millis(500));
    let dossier = dossier_quarantaine();
    fs::create_dir_all(&dossier).map_err(|e| e.to_string())?;
    let id = commun::nouvel_id();
    let taille = fs::metadata(p).map(|m| m.len()).unwrap_or(0);
    // Déplacement (même volume) ou copie puis suppression ; extension .quarantaine pour qu'il ne puisse pas être lancé
    let cible = dossier.join(format!("{id}.quarantaine"));
    if fs::rename(p, &cible).is_err() {
        fs::copy(p, &cible).map_err(|e| format!("copie impossible : {e}"))?;
        fs::remove_file(p).map_err(|e| format!("suppression de l'original impossible : {e}"))?;
    }
    let mut liste: Vec<ElementQuarantaine> = commun::lire("quarantaine.json").unwrap_or_default();
    liste.push(ElementQuarantaine { id: id.clone(), chemin_origine: chemin.into(), date: commun::maintenant(), raison: raison.into(), taille });
    commun::ecrire("quarantaine.json", &liste);
    Ok(format!("{} placé en quarantaine.", p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()))
}

pub fn restaurer(id: &str) -> Result<String, String> {
    let mut liste: Vec<ElementQuarantaine> = commun::lire("quarantaine.json").unwrap_or_default();
    let i = liste.iter().position(|e| e.id == id).ok_or("élément introuvable")?;
    let e = liste.remove(i);
    let source = dossier_quarantaine().join(format!("{id}.quarantaine"));
    if let Some(d) = Path::new(&e.chemin_origine).parent() {
        let _ = fs::create_dir_all(d);
    }
    if fs::rename(&source, &e.chemin_origine).is_err() {
        fs::copy(&source, &e.chemin_origine).map_err(|x| x.to_string())?;
        let _ = fs::remove_file(&source);
    }
    commun::ecrire("quarantaine.json", &liste);
    Ok(format!("{} restauré.", e.chemin_origine))
}

// ------------------------------------------------------------ pare-feu : programme isolé et mode panique

fn politique() -> windows::core::Result<INetFwPolicy2> {
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER)
    }
}

pub fn nom_regle_programme(chemin: &str, entrant: bool) -> String {
    format!("deR4Tizer - isole {} ({})", chemin, if entrant { "entrant" } else { "sortant" })
}

/// Bloque tout le trafic, entrant et sortant, d'un programme précis
pub fn isoler_programme(chemin: &str) -> Result<(), String> {
    unsafe {
        let p = politique().map_err(|e| e.to_string())?;
        for entrant in [false, true] {
            let r: INetFwRule = CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER).map_err(|e| e.to_string())?;
            r.SetName(&BSTR::from(nom_regle_programme(chemin, entrant))).map_err(|e| e.to_string())?;
            r.SetDescription(&BSTR::from("Programme isolé par deR4Tizer")).map_err(|e| e.to_string())?;
            r.SetGrouping(&BSTR::from(blocage::GROUPE)).map_err(|e| e.to_string())?;
            r.SetApplicationName(&BSTR::from(chemin)).map_err(|e| e.to_string())?;
            r.SetDirection(if entrant { NET_FW_RULE_DIR_IN } else { NET_FW_RULE_DIR_OUT }).map_err(|e| e.to_string())?;
            r.SetAction(NET_FW_ACTION_BLOCK).map_err(|e| e.to_string())?;
            r.SetProfiles(0x7FFF_FFFF).map_err(|e| e.to_string())?;
            r.SetEnabled(VARIANT_TRUE).map_err(|e| e.to_string())?;
            p.Rules().and_then(|rs| rs.Add(&r)).map_err(|e| e.to_string())?;
        }
    }
    // Coupe aussi les connexions déjà ouvertes par ce programme
    for c in natif::lister_tcp() {
        if c.etat == 5 && natif::chemin_processus(c.pid).eq_ignore_ascii_case(chemin) {
            natif::couper(&c);
        }
    }
    Ok(())
}

pub fn liberer_programme(chemin: &str) -> usize {
    let Ok(p) = politique() else { return 0 };
    let mut n = 0;
    unsafe {
        let Ok(regles) = p.Rules() else { return 0 };
        for entrant in [false, true] {
            let nom = BSTR::from(nom_regle_programme(chemin, entrant));
            while regles.Item(&nom).is_ok() && n < 20 && regles.Remove(&nom).is_ok() {
                n += 1;
            }
        }
    }
    n
}

const PROFILS: [windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_PROFILE_TYPE2; 3] =
    [NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC];

const PANIQUE_SORTANT: &str = "deR4Tizer PANIQUE (sortant)";
const PANIQUE_ENTRANT: &str = "deR4Tizer PANIQUE (entrant)";

/// Réseaux privés et réservés, jamais bloqués par le mode panique (le réseau local reste joignable)
const RESERVES: &[(u32, u32)] = &[
    (0x0000_0000, 0x00FF_FFFF), (0x0A00_0000, 0x0AFF_FFFF), (0x6440_0000, 0x647F_FFFF), (0x7F00_0000, 0x7FFF_FFFF),
    (0xA9FE_0000, 0xA9FE_FFFF), (0xAC10_0000, 0xAC1F_FFFF), (0xC0A8_0000, 0xC0A8_FFFF), (0xE000_0000, 0xFFFF_FFFF),
];

/// Plages IPv4 publiques privées des adresses à épargner, au format du pare-feu (« a.b.c.d-e.f.g.h »)
pub fn plages_internet(epargnees: &[std::net::Ipv4Addr]) -> Vec<String> {
    let mut trous: Vec<(u32, u32)> = RESERVES.to_vec();
    trous.extend(epargnees.iter().map(|ip| (u32::from(*ip), u32::from(*ip))));
    trous.sort();
    let mut plages = Vec::new();
    let mut debut: u64 = 0;
    for (d, f) in trous {
        if (d as u64) > debut {
            plages.push((debut as u32, d - 1));
        }
        debut = debut.max(f as u64 + 1);
    }
    if debut <= u32::MAX as u64 {
        plages.push((debut as u32, u32::MAX));
    }
    plages.iter().map(|(d, f)| format!("{}-{}", std::net::Ipv4Addr::from(*d), std::net::Ipv4Addr::from(*f))).collect()
}

/// Adresses à épargner : serveurs DNS de la machine et serveurs de notification (pour que l'alerte parte)
fn epargnees() -> Vec<std::net::Ipv4Addr> {
    use std::net::ToSocketAddrs;
    let mut l = Vec::new();
    let dns = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", "(Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses -join ','"])
        .output().map(|s| String::from_utf8_lossy(&s.stdout).trim().to_string()).unwrap_or_default();
    l.extend(dns.split(',').filter_map(|x| x.trim().parse::<std::net::Ipv4Addr>().ok()));
    let config: commun::Config = commun::lire("config.json").unwrap_or_default();
    let secrets = crate::notifications::lire_secrets();
    let mut hotes = Vec::new();
    for url in [&secrets.ntfy_url, &secrets.teams_url] {
        if let Some(h) = url.strip_prefix("https://").and_then(|r| r.split(['/', ':']).next()) {
            hotes.push(format!("{h}:443"));
        }
    }
    if config.notifications.smtp && !config.notifications.smtp_serveur.is_empty() {
        hotes.push(format!("{}:{}", config.notifications.smtp_serveur, config.notifications.smtp_port));
    }
    for h in hotes {
        if let Ok(a) = h.to_socket_addrs() {
            l.extend(a.filter_map(|x| match x.ip() { std::net::IpAddr::V4(v) => Some(v), _ => None }));
        }
    }
    l.sort();
    l.dedup();
    l
}

fn regle_blocage(p: &INetFwPolicy2, nom: &str, sortant: bool, adresses: &str) -> windows::core::Result<()> {
    unsafe {
        let r: INetFwRule = CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER)?;
        r.SetName(&BSTR::from(nom))?;
        r.SetDescription(&BSTR::from("Mode panique de deR4Tizer : Internet coupé, réseau local et alertes conservés"))?;
        r.SetGrouping(&BSTR::from(blocage::GROUPE))?;
        r.SetDirection(if sortant { NET_FW_RULE_DIR_OUT } else { NET_FW_RULE_DIR_IN })?;
        r.SetAction(NET_FW_ACTION_BLOCK)?;
        r.SetProtocol(256)?;
        r.SetRemoteAddresses(&BSTR::from(adresses))?;
        r.SetProfiles(0x7FFF_FFFF)?;
        r.SetEnabled(VARIANT_TRUE)?;
        p.Rules()?.Add(&r)
    }
}

/// Mode panique : deux règles de BLOCAGE (qui priment sur toutes les règles d'autorisation, y compris celles
/// qu'un programme malveillant aurait créées) vers tout Internet, IPv4 et IPv6 globales ; le réseau local, les
/// serveurs DNS et les serveurs de notification restent joignables. Rien d'autre n'est modifié : la sortie
/// du mode retire simplement les deux règles.
pub fn panique(activer: bool) -> Result<String, String> {
    let p = politique().map_err(|e| e.to_string())?;
    unsafe {
        if let Ok(regles) = p.Rules() {
            for nom in [PANIQUE_SORTANT, PANIQUE_ENTRANT] {
                let b = BSTR::from(nom);
                let mut n = 0;
                while regles.Item(&b).is_ok() && n < 10 && regles.Remove(&b).is_ok() {
                    n += 1;
                }
            }
        }
    }
    if !activer {
        let _ = fs::remove_file(commun::dossier().join("panique-active"));
        return Ok("Mode panique désactivé : Internet de nouveau accessible.".into());
    }
    let epargnees = epargnees();
    let mut adresses = plages_internet(&epargnees);
    adresses.push("2000::-3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".into());
    let liste = adresses.join(",");
    regle_blocage(&p, PANIQUE_SORTANT, true, &liste).map_err(|e| e.to_string())?;
    regle_blocage(&p, PANIQUE_ENTRANT, false, &liste).map_err(|e| e.to_string())?;
    unsafe {
        for profil in PROFILS {
            let _ = p.put_FirewallEnabled(profil, VARIANT_TRUE);
        }
    }
    // Coupe immédiatement les connexions vers Internet en cours (les règles ne s'appliquent qu'aux nouvelles)
    let n = natif::lister_tcp().iter()
        .filter(|c| c.etat == 5 && c.ip.parse().map(|a| crate::parefeu::publique(&a)).unwrap_or(false))
        .filter(|c| !c.ip.parse::<std::net::Ipv4Addr>().map(|a| epargnees.contains(&a)).unwrap_or(false))
        .filter(|c| natif::couper(c)).count();
    fs::write(commun::dossier().join("panique-active"), commun::maintenant()).map_err(|e| e.to_string())?;
    Ok(format!("MODE PANIQUE : Internet coupé pour tous les programmes ; réseau local, DNS et {} serveur(s) de notification conservés ; {n} connexion(s) coupée(s).",
        epargnees.len()))
}

pub fn panique_active() -> bool {
    commun::dossier().join("panique-active").exists()
}
