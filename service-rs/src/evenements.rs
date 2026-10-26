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

/// Issue d'une lecture d'événements
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lecture {
    /// Tous les événements demandés ont été lus
    Complete,
    /// Délai d'EvtNext dépassé (journal très chargé, inondé) : rien d'illisible, la lecture reprend au tour suivant
    Delai,
    /// Requête refusée ou événement illisible
    Erreur,
}

/// Lit les résultats jusqu'à la fin, un délai dépassé ou une erreur (événements restants non lus)
fn vider(resultats: EVT_HANDLE, traiter: &mut dyn FnMut(String)) -> Lecture {
    let mut evenements = [0isize; 32];
    loop {
        let mut n = 0u32;
        if let Err(e) = unsafe { EvtNext(resultats, &mut evenements, 1000, 0, &mut n) } {
            return if fin_des_resultats(&e) {
                Lecture::Complete
            } else if (e.code().0 as u32) & 0xFFFF == 1460 {
                // ERROR_TIMEOUT
                Lecture::Delai
            } else {
                Lecture::Erreur
            };
        }
        if n == 0 {
            return Lecture::Complete;
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
pub fn historique(canal: &str, requete: &str, traiter: &mut dyn FnMut(String)) -> Lecture {
    let (c, r) = (large(canal), large(requete));
    unsafe {
        let Ok(resultats) = EvtQuery(None, PCWSTR(c.as_ptr()), PCWSTR(r.as_ptr()), EvtQueryChannelPath.0 as u32) else { return Lecture::Erreur };
        let lecture = vider(resultats, traiter);
        let _ = EvtClose(resultats);
        lecture
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
    let mut blocage = Blocage::default();
    // Dernier saut (heure, nombre de numéros sautés) : la collecte reste « Partielle » une heure, pas « Active »
    let mut saut: Option<(std::time::Instant, u64)> = None;
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
                noter_lu(collecte, &saut);
                continue;
            };
            if n < dernier {
                // Journal effacé : on repart du début
                dernier = 0;
            }
            if n == dernier {
                noter_lu(collecte, &saut);
                depart = Some(dernier);
                continue;
            }
            let q = format!("*[System[(EventRecordID > {dernier}) and (EventRecordID <= {n}) and ({conditions})]]");
            let mut traite: Option<u64> = None;
            let lecture = historique(&canal, &q, &mut |xml| {
                if let Some(id) = numero_evenement(&xml) {
                    traite = Some(traite.map_or(id, |t| t.max(id)));
                }
                traiter(xml);
            });
            let ok = lecture == Lecture::Complete;
            let lu_jusqu_a = prochain_dernier(dernier, n, ok, traite);
            let (suivant, b, sautes) = apres_blocage(dernier, lu_jusqu_a, n, lecture, blocage);
            if sautes > 0 {
                commun::journal(&format!("journal {canal} : lecture bloquée {LIMITE_BLOCAGE} tours de suite au même endroit ; numéros {} à {suivant} sautés", lu_jusqu_a + 1));
                saut = Some((std::time::Instant::now(), saut.filter(|(t, _)| t.elapsed().as_secs() < 3600).map_or(0, |(_, s)| s) + sautes));
            }
            match lecture {
                Lecture::Complete => noter_lu(collecte, &saut),
                Lecture::Delai => collectes::partielle(collecte, &format!("lecture du journal {canal} trop lente (délai dépassé) : reprise au tour suivant")),
                Lecture::Erreur => collectes::echec(collecte, &format!("événements du journal {canal} illisibles")),
            }
            blocage = b;
            dernier = suivant;
            depart = Some(dernier);
        })
        .is_ok()
}

/// Lecture réussie : « Active », ou « Partielle » pendant une heure après un saut d'événements
fn noter_lu(collecte: Collecte, saut: &Option<(std::time::Instant, u64)>) {
    match saut {
        Some((t, n)) if t.elapsed().as_secs() < 3600 => {
            collectes::partielle(collecte, &format!("{n} numéro(s) d'événement sauté(s) dans l'heure (lecture bloquée)"))
        }
        _ => collectes::succes(collecte),
    }
}

/// Tours de suite en erreur sans aucun progrès avant de sauter (2 s par tour : une minute)
pub const LIMITE_BLOCAGE: u32 = 30;

/// Lecture bloquée en cours : tours en erreur sans progrès, et pas du prochain saut
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Blocage {
    pub tours: u32,
    pub pas: u64,
}

impl Default for Blocage {
    fn default() -> Self {
        Blocage { tours: 0, pas: 1 }
    }
}

/// Décision pure (testée) : un événement qui fait toujours échouer la lecture (journal corrompu) ne bloque pas le suivi
/// sans fin, sans pour autant jeter tout l'intervalle. Rend (numéro de reprise, blocage, numéros sautés).
/// - lecture complète, ou progrès : reprise normale, blocage remis à zéro ;
/// - délai dépassé (journal chargé, inondé) : ce n'est pas un blocage, rien n'est sauté, la lecture reprend où elle
///   s'est arrêtée (la collecte est « Partielle » tant que dure la lenteur) ;
/// - erreur sans progrès `LIMITE_BLOCAGE` tours de suite : on saute `pas` numéros juste après le dernier lu (1, puis
///   2, 4… si le blocage persiste, sans dépasser `n`) ; seul le voisinage du point de blocage est perdu.
pub fn apres_blocage(dernier: u64, suivant: u64, n: u64, lecture: Lecture, b: Blocage) -> (u64, Blocage, u64) {
    if lecture == Lecture::Complete || suivant > dernier {
        return (suivant, Blocage::default(), 0);
    }
    if lecture == Lecture::Delai {
        return (suivant, Blocage { tours: 0, ..b }, 0);
    }
    if b.tours + 1 < LIMITE_BLOCAGE {
        return (suivant, Blocage { tours: b.tours + 1, ..b }, 0);
    }
    let reprise = suivant.saturating_add(b.pas).min(n);
    // Encore bloqué au tour suivant : nouveau saut aussitôt, deux fois plus long
    (reprise, Blocage { tours: LIMITE_BLOCAGE - 1, pas: b.pas.saturating_mul(2) }, reprise - suivant)
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
