//! Lecture des journaux d'événements de Windows (Sécurité, Système, DNS, Sysmon…) : historique puis suivi.

use crate::natif::large;
use regex::Regex;
use std::collections::HashMap;
use std::process::Command;
use std::sync::OnceLock;
use windows::core::PCWSTR;
use windows::Win32::System::EventLog::{
    EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection, EvtRender, EvtRenderEventXml, EVT_HANDLE,
};

/// Journal activé ? (lu avec wevtutil, qui affiche « enabled: true/false »)
pub fn journal_actif(canal: &str) -> Option<bool> {
    let sortie = Command::new("wevtutil").args(["gl", canal]).output().ok()?;
    if !sortie.status.success() {
        return None;
    }
    let texte = String::from_utf8_lossy(&sortie.stdout).to_lowercase();
    Some(texte.contains("enabled: true"))
}

pub fn activer_journal(canal: &str, actif: bool) -> bool {
    Command::new("wevtutil")
        .args(["sl", canal, if actif { "/e:true" } else { "/e:false" }])
        .output()
        .map(|s| s.status.success())
        .unwrap_or(false)
}

fn rendre(evenement: EVT_HANDLE) -> Option<String> {
    unsafe {
        let mut utilise = 0u32;
        let mut proprietes = 0u32;
        let _ = EvtRender(None, evenement, EvtRenderEventXml.0 as u32, 0, None, &mut utilise, &mut proprietes);
        if utilise == 0 {
            return None;
        }
        let mut tampon = vec![0u16; utilise as usize / 2 + 1];
        EvtRender(None, evenement, EvtRenderEventXml.0 as u32, utilise, Some(tampon.as_mut_ptr() as *mut _), &mut utilise, &mut proprietes).ok()?;
        let fin = tampon.iter().position(|&c| c == 0).unwrap_or(tampon.len());
        Some(String::from_utf16_lossy(&tampon[..fin]))
    }
}

fn vider(resultats: EVT_HANDLE, traiter: &mut dyn FnMut(String)) {
    let mut evenements = [0isize; 32];
    loop {
        let mut n = 0u32;
        let ok = unsafe { EvtNext(resultats, &mut evenements, 1000, 0, &mut n) };
        if ok.is_err() || n == 0 {
            break;
        }
        for &e in &evenements[..n as usize] {
            let h = EVT_HANDLE(e);
            if let Some(xml) = rendre(h) {
                traiter(xml);
            }
            unsafe {
                let _ = EvtClose(h);
            }
        }
    }
}

/// Lit les événements passés qui correspondent à la requête XPath
pub fn historique(canal: &str, requete: &str, traiter: &mut dyn FnMut(String)) {
    let (c, r) = (large(canal), large(requete));
    unsafe {
        let Ok(resultats) = EvtQuery(None, PCWSTR(c.as_ptr()), PCWSTR(r.as_ptr()), EvtQueryChannelPath.0 as u32) else { return };
        vider(resultats, traiter);
        let _ = EvtClose(resultats);
    }
}

/// Numéro (EventRecordID) du dernier événement du journal ; None si le journal n'existe pas ou est illisible
fn dernier_numero(canal: &str) -> Option<u64> {
    static MOTIF: OnceLock<Regex> = OnceLock::new();
    let motif = MOTIF.get_or_init(|| Regex::new(r"<EventRecordID>(\d+)</EventRecordID>").unwrap());
    let (c, r) = (large(canal), large("*"));
    unsafe {
        let resultats = EvtQuery(None, PCWSTR(c.as_ptr()), PCWSTR(r.as_ptr()), EvtQueryChannelPath.0 as u32 | EvtQueryReverseDirection.0 as u32).ok()?;
        let mut evenements = [0isize; 1];
        let mut n = 0u32;
        let numero = if EvtNext(resultats, &mut evenements, 1000, 0, &mut n).is_ok() && n == 1 {
            let h = EVT_HANDLE(evenements[0]);
            let x = rendre(h);
            let _ = EvtClose(h);
            x.and_then(|x| motif.captures(&x).and_then(|m| m[1].parse().ok()))
        } else {
            Some(0)
        };
        let _ = EvtClose(resultats);
        numero
    }
}

/// Suit les nouveaux événements du journal qui correspondent à la requête « *[System[…]] » ; le traitement
/// tourne dans un fil dédié. Lecture incrémentale par numéro d'événement toutes les 2 s, plutôt qu'un
/// abonnement EvtSubscribe : sur un journal très actif (Sécurité avec l'audit des fichiers), un abonnement
/// qui prend du retard est déclaré périmé par Windows et ne livre plus rien.
pub fn abonner(canal: &str, requete: &str, mut traiter: impl FnMut(String) + Send + 'static) -> bool {
    let Some(conditions) = requete.trim().strip_prefix("*[System[").and_then(|r| r.strip_suffix("]]")).map(String::from) else { return false };
    let Some(mut dernier) = dernier_numero(canal) else { return false };
    let canal = canal.to_string();
    std::thread::Builder::new()
        .name(format!("journal {canal}"))
        .spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let Some(n) = dernier_numero(&canal) else { continue };
            if n < dernier {
                // Journal effacé : on repart du début
                dernier = 0;
            }
            if n == dernier {
                continue;
            }
            let q = format!("*[System[(EventRecordID > {dernier}) and (EventRecordID <= {n}) and ({conditions})]]");
            historique(&canal, &q, &mut traiter);
            dernier = n;
        })
        .is_ok()
}

/// Champs <Data Name='…'>…</Data> d'un événement rendu en XML
pub fn donnees(xml: &str) -> HashMap<String, String> {
    static MOTIF: OnceLock<Regex> = OnceLock::new();
    // Les noms peuvent contenir des espaces (journal de Defender : « Threat Name », « New Value »…)
    let motif = MOTIF.get_or_init(|| Regex::new(r"(?s)<Data Name='([^']+)'>(.*?)</Data>").unwrap());
    motif
        .captures_iter(xml)
        .map(|c| {
            let v = c[2].replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&");
            (c[1].to_string(), v)
        })
        .collect()
}
