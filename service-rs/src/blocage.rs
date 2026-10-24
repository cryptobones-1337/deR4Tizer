//! Blocages : bloc géré dans le fichier hosts et règles du pare-feu Windows (API COM).

use crate::commun;
use crate::natif;
use regex::Regex;
use std::fs;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use windows::core::BSTR;
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, NetFwPolicy2, NetFwRule, NET_FW_ACTION_BLOCK, NET_FW_RULE_DIR_OUT,
};
use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED};
use windows::Win32::Foundation::VARIANT_TRUE;

pub const DEBUT_BLOC: &str = "# >>> deR4Tizer (bloc gere par le service, ne pas modifier a la main)";
pub const FIN_BLOC: &str = "# <<< deR4Tizer";
pub const GROUPE: &str = "deR4Tizer";

pub fn fichier_hosts() -> PathBuf {
    PathBuf::from(natif::dossier_systeme()).join(r"drivers\etc\hosts")
}

/// Lignes du fichier hosts hors de notre bloc, et domaines de notre bloc
pub fn lignes_hors_bloc() -> std::io::Result<(Vec<String>, Vec<String>)> {
    let texte = fs::read(fichier_hosts())?;
    let texte = String::from_utf8_lossy(&texte);
    let motif = Regex::new(r"^\s*\S+\s+(\S+)").unwrap();
    let (mut hors, mut bloc) = (Vec::new(), Vec::new());
    let mut dans = false;
    for l in texte.lines() {
        if l == DEBUT_BLOC {
            dans = true;
        } else if l == FIN_BLOC {
            dans = false;
        } else if !dans {
            hors.push(l.to_string());
        } else if let Some(c) = motif.captures(l) {
            bloc.push(c[1].to_string());
        }
    }
    Ok((hors, bloc))
}

pub fn empreinte_hosts() -> String {
    lignes_hors_bloc().map(|(h, _)| h.join("\n")).unwrap_or_default()
}

/// Noms écrits dans le bloc de deR4Tizer du fichier hosts : seulement des noms de domaine valides (phase 1), en
/// minuscules. Un nom avec une fin de ligne ajouterait une ligne arbitraire au fichier hosts (une banque redirigée
/// vers une adresse choisie) ; un nom accentué serait réduit par le filtre ASCII à un autre nom. Écartés et journalisés.
pub fn lignes_du_bloc(domaines: &[String]) -> Vec<String> {
    domaines.iter().filter_map(|d| {
        if crate::validation::nom_domaine_valide(d) {
            Some(d.trim_end_matches('.').to_lowercase())
        } else {
            commun::journal(&format!("fichier hosts : nom invalide écarté ({} caractères)", d.chars().count()));
            None
        }
    }).collect()
}

pub fn ecrire_bloc_hosts(domaines: &[String]) -> std::io::Result<()> {
    let (mut lignes, _) = lignes_hors_bloc()?;
    let sauvegardes = commun::dossier().join("sauvegardes");
    let _ = fs::create_dir_all(&sauvegardes);
    let horodatage = commun::maintenant().replace([':', ' '], "-");
    let _ = fs::copy(fichier_hosts(), sauvegardes.join(format!("hosts-{horodatage}.bak")));
    let mut liste = lignes_du_bloc(domaines);
    liste.sort();
    liste.dedup();
    if !liste.is_empty() {
        lignes.push(DEBUT_BLOC.into());
        lignes.extend(liste.iter().map(|d| format!("127.0.0.1\t{d}")));
        lignes.push(FIN_BLOC.into());
    }
    // ASCII pur, fins de ligne Windows
    let texte: String = lignes.iter().map(|l| format!("{}\r\n", l.trim_end_matches('\r'))).collect();
    fs::write(fichier_hosts(), texte.chars().filter(|c| c.is_ascii()).collect::<String>())?;
    natif::vider_cache_dns();
    Ok(())
}

// ------------------------------------------------------------ pare-feu

fn politique() -> windows::core::Result<INetFwPolicy2> {
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER)
    }
}

pub fn nom_regle(ip: &str) -> String {
    format!("deR4Tizer - bloque {ip}")
}

pub fn ajouter_regle(ip: &str, raison: &str) -> windows::core::Result<()> {
    unsafe {
        let p = politique()?;
        let r: INetFwRule = CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER)?;
        r.SetName(&BSTR::from(nom_regle(ip)))?;
        r.SetDescription(&BSTR::from(raison))?;
        r.SetGrouping(&BSTR::from(GROUPE))?;
        r.SetDirection(NET_FW_RULE_DIR_OUT)?;
        r.SetAction(NET_FW_ACTION_BLOCK)?;
        r.SetProtocol(256)?; // tous les protocoles
        r.SetRemoteAddresses(&BSTR::from(ip))?;
        r.SetProfiles(0x7FFF_FFFF)?;
        r.SetEnabled(VARIANT_TRUE)?;
        p.Rules()?.Add(&r)
    }
}

/// Nombre de règles du pare-feu actuellement en vigueur (None si illisible)
pub fn nombre_regles() -> Option<i32> {
    unsafe { politique().ok()?.Rules().ok()?.Count().ok() }
}

/// Supprime toutes les règles portant le nom de cette IP
pub fn supprimer_regle(ip: &str) -> usize {
    let Ok(p) = politique() else { return 0 };
    let nom = BSTR::from(nom_regle(ip));
    let mut n = 0;
    unsafe {
        let Ok(regles) = p.Rules() else { return 0 };
        while regles.Item(&nom).is_ok() && n < 50 {
            if regles.Remove(&nom).is_err() {
                break;
            }
            n += 1;
        }
    }
    n
}

/// Supprime toutes les règles du groupe deR4Tizer (désinstallation, ou règles orphelines)
pub fn supprimer_groupe() -> bool {
    crate::mesure::powershell("blocage");
    Command::new(crate::natif::powershell_exe())
        .args(["-NoProfile", "-Command", &format!("Get-NetFirewallRule -Group '{GROUPE}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule")])
        .creation_flags(0x0800_0000)
        .output()
        .map(|s| s.status.success())
        .unwrap_or(false)
}
