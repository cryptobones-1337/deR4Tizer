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
    INetFwPolicy2, INetFwRule, NetFwPolicy2, NetFwRule, NET_FW_ACTION_ALLOW, NET_FW_ACTION_BLOCK, NET_FW_PROFILE2_DOMAIN,
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

pub fn tuer(pid: u32) -> Result<(), String> {
    if pid <= 4 || pid == std::process::id() {
        return Err("processus protégé".into());
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
    if pid <= 4 || pid == std::process::id() {
        return Err("processus protégé".into());
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

/// Mode panique : action sortante par défaut « bloquer » sur tous les profils. Seuls les programmes
/// ayant une règle d'autorisation sortante explicite (essentiellement des composants de Windows) passent encore.
pub fn panique(activer: bool) -> Result<String, String> {
    unsafe {
        let p = politique().map_err(|e| e.to_string())?;
        for profil in PROFILS {
            p.put_DefaultOutboundAction(profil, if activer { NET_FW_ACTION_BLOCK } else { NET_FW_ACTION_ALLOW }).map_err(|e| e.to_string())?;
            if activer {
                p.put_FirewallEnabled(profil, VARIANT_TRUE).map_err(|e| e.to_string())?;
            }
        }
    }
    if activer {
        // Coupe immédiatement les connexions en cours (les règles ne s'appliquent qu'aux nouvelles)
        let n = natif::lister_tcp().iter().filter(|c| c.etat == 5).filter(|c| natif::couper(c)).count();
        fs::write(commun::dossier().join("panique-active"), commun::maintenant()).map_err(|e| e.to_string())?;
        Ok(format!("MODE PANIQUE : trafic sortant bloqué pour tous les programmes non autorisés ; {n} connexion(s) coupée(s)."))
    } else {
        let _ = fs::remove_file(commun::dossier().join("panique-active"));
        Ok("Mode panique désactivé : trafic sortant de nouveau autorisé.".into())
    }
}

pub fn panique_active() -> bool {
    commun::dossier().join("panique-active").exists()
}
