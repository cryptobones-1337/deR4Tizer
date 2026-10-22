//! Lecture des journaux d'événements de Windows (journal DNS, Sysmon) : historique puis abonnement.

use crate::natif::large;
use regex::Regex;
use std::collections::HashMap;
use std::process::Command;
use std::sync::OnceLock;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
use windows::Win32::System::EventLog::{
    EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtRender, EvtRenderEventXml, EvtSubscribe,
    EvtSubscribeToFutureEvents, EVT_HANDLE,
};
use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

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

/// S'abonne aux nouveaux événements ; le traitement tourne dans un fil dédié
pub fn abonner(canal: &str, requete: &str, mut traiter: impl FnMut(String) + Send + 'static) -> bool {
    let (c, r) = (large(canal), large(requete));
    unsafe {
        let Ok(signal) = CreateEventW(None, false, false, None) else { return false };
        let abonnement = match EvtSubscribe(None, signal, PCWSTR(c.as_ptr()), PCWSTR(r.as_ptr()), None, None, None, EvtSubscribeToFutureEvents.0 as u32) {
            Ok(a) => a,
            Err(_) => {
                let _ = CloseHandle(signal);
                return false;
            }
        };
        let (signal, abonnement) = (signal.0 as isize, abonnement.0);
        std::thread::Builder::new()
            .name(format!("journal {canal}"))
            .spawn(move || loop {
                let s = windows::Win32::Foundation::HANDLE(signal as *mut _);
                if WaitForSingleObject(s, 2000) == WAIT_OBJECT_0 {
                    vider(EVT_HANDLE(abonnement), &mut traiter);
                }
            })
            .is_ok()
    }
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
