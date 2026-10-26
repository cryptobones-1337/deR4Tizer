//! Lecture des journaux d'événements de Windows (Sécurité, Système, DNS, Sysmon…) : historique puis suivi.

use crate::collectes::{self, Collecte};
use crate::commun;
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

/// ERROR_NO_MORE_ITEMS : fin normale des résultats ; tout autre échec d'EvtNext (délai dépassé…) est une lecture incomplète
fn fin_des_resultats(e: &windows::core::Error) -> bool {
    (e.code().0 as u32) & 0xFFFF == 259
}

/// Rend false si la lecture s'est arrêtée sur une erreur (événements restants non lus)
fn vider(resultats: EVT_HANDLE, traiter: &mut dyn FnMut(String)) -> bool {
    let mut evenements = [0isize; 32];
    loop {
        let mut n = 0u32;
        if let Err(e) = unsafe { EvtNext(resultats, &mut evenements, 1000, 0, &mut n) } {
            return fin_des_resultats(&e);
        }
        if n == 0 {
            return true;
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

/// Lit les événements passés qui correspondent à la requête XPath ; false si la requête est refusée ou la lecture
/// interrompue
pub fn historique(canal: &str, requete: &str, traiter: &mut dyn FnMut(String)) -> bool {
    let (c, r) = (large(canal), large(requete));
    unsafe {
        let Ok(resultats) = EvtQuery(None, PCWSTR(c.as_ptr()), PCWSTR(r.as_ptr()), EvtQueryChannelPath.0 as u32) else { return false };
        let ok = vider(resultats, traiter);
        let _ = EvtClose(resultats);
        ok
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
        let numero = match EvtNext(resultats, &mut evenements, 1000, 0, &mut n) {
            Ok(()) if n == 1 => {
                let h = EVT_HANDLE(evenements[0]);
                let x = rendre(h);
                let _ = EvtClose(h);
                x.and_then(|x| motif.captures(&x).and_then(|m| m[1].parse().ok()))
            }
            Ok(()) => Some(0),
            // Journal vide : 0 ; tout autre échec est une lecture impossible (pas « vide », qui ferait tout relire)
            Err(e) if fin_des_resultats(&e) => Some(0),
            Err(_) => None,
        };
        let _ = EvtClose(resultats);
        numero
    }
}

/// Suit les nouveaux événements du journal qui correspondent à la requête « *[System[…]] » ; le traitement
/// tourne dans un fil dédié. Lecture incrémentale par numéro d'événement toutes les 2 s, plutôt qu'un
/// abonnement EvtSubscribe : sur un journal très actif (Sécurité avec l'audit des fichiers), un abonnement
/// qui prend du retard est déclaré périmé par Windows et ne livre plus rien.
/// Chaque tour est noté pour la collecte `collecte` : réussi si le numéro du dernier événement est lu et, s'il y a du
/// nouveau, si les nouveaux événements le sont aussi ; sinon impossible, et les événements non lus sont relus au tour
/// suivant (`prochain_dernier`). Un journal illisible au départ (erreur passagère au démarrage du PC) est suivi quand
/// même : le fil cherche son dernier numéro à chaque tour, et le suivi part de là. Rend false seulement si la requête
/// est mal formée ou si le fil ne démarre pas.
pub fn abonner(canal: &str, requete: &str, collecte: Collecte, mut traiter: impl FnMut(String) + Send + 'static) -> bool {
    let Some(conditions) = requete.trim().strip_prefix("*[System[").and_then(|r| r.strip_suffix("]]")).map(String::from) else { return false };
    let mut depart = dernier_numero(canal);
    match depart {
        Some(_) => collectes::succes(collecte),
        None => collectes::echec(collecte, &format!("journal {canal} illisible")),
    }
    let canal = canal.to_string();
    let mut bloques = 0u32;
    std::thread::Builder::new()
        .name(format!("journal {canal}"))
        .spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let Some(n) = dernier_numero(&canal) else {
                collectes::echec(collecte, &format!("journal {canal} illisible"));
                continue;
            };
            let Some(mut dernier) = depart else {
                // Première lecture réussie après un départ illisible : le suivi part d'ici
                depart = Some(n);
                collectes::succes(collecte);
                continue;
            };
            if n < dernier {
                // Journal effacé : on repart du début
                dernier = 0;
            }
            if n == dernier {
                collectes::succes(collecte);
                depart = Some(dernier);
                continue;
            }
            let q = format!("*[System[(EventRecordID > {dernier}) and (EventRecordID <= {n}) and ({conditions})]]");
            let mut traite: Option<u64> = None;
            let ok = historique(&canal, &q, &mut |xml| {
                if let Some(id) = numero_evenement(&xml) {
                    traite = Some(traite.map_or(id, |t| t.max(id)));
                }
                traiter(xml);
            });
            if ok {
                collectes::succes(collecte);
            } else {
                collectes::echec(collecte, &format!("événements du journal {canal} illisibles"));
            }
            let (suivant, b, saute) = apres_blocage(dernier, prochain_dernier(dernier, n, ok, traite), n, ok, bloques);
            if saute {
                commun::journal(&format!("journal {canal} : lecture bloquée {LIMITE_BLOCAGE} tours de suite au même endroit ; événements {} à {n} sautés", dernier + 1));
            }
            bloques = b;
            dernier = suivant;
            depart = Some(dernier);
        })
        .is_ok()
}

/// Tours de suite sans aucun progrès avant de sauter l'intervalle illisible (2 s par tour : une minute)
pub const LIMITE_BLOCAGE: u32 = 30;

/// Décision pure (testée) : un événement qui fait toujours échouer la lecture (journal corrompu) ne bloque pas le suivi
/// sans fin. Rend (numéro de reprise, tours bloqués, intervalle sauté). Après `LIMITE_BLOCAGE` tours en échec sans
/// aucun progrès, on reprend après `n` : les événements de l'intervalle sont perdus, et c'est écrit au journal.
pub fn apres_blocage(dernier: u64, suivant: u64, n: u64, lecture_complete: bool, bloques: u32) -> (u64, u32, bool) {
    if lecture_complete || suivant > dernier {
        return (suivant, 0, false);
    }
    if bloques + 1 >= LIMITE_BLOCAGE { (n, 0, true) } else { (suivant, bloques + 1, false) }
}

/// Journal lisible maintenant (numéro de son dernier événement lu) ?
pub fn lisible(canal: &str) -> bool {
    dernier_numero(canal).is_some()
}

/// Numéro (EventRecordID) d'un événement rendu en XML
fn numero_evenement(xml: &str) -> Option<u64> {
    static MOTIF: OnceLock<Regex> = OnceLock::new();
    MOTIF.get_or_init(|| Regex::new(r"<EventRecordID>(\d+)</EventRecordID>").unwrap()).captures(xml).and_then(|m| m[1].parse().ok())
}

/// Décision pure (testée) : numéro à partir duquel relire au tour suivant. Lecture complète : `n`. Lecture interrompue :
/// après le dernier événement traité (aucun doublon), sinon tout l'intervalle est relu (aucune perte).
pub fn prochain_dernier(dernier: u64, n: u64, lecture_complete: bool, dernier_traite: Option<u64>) -> u64 {
    if lecture_complete { n } else { dernier_traite.map_or(dernier, |t| t.clamp(dernier, n)) }
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
