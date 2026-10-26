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
    EvtChannelConfigEnabled, EvtClose, EvtGetChannelConfigProperty, EvtNext, EvtOpenChannelConfig, EvtQuery, EvtQueryChannelPath,
    EvtQueryReverseDirection, EvtRender, EvtRenderEventXml, EVT_HANDLE, EVT_VARIANT,
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
    let ok = Command::new("wevtutil")
        .args(["sl", canal, if actif { "/e:true" } else { "/e:false" }])
        .output()
        .map(|s| s.status.success())
        .unwrap_or(false);
    // Journal coupé par le service lui-même (retour arrière de la baseline) : son suivi ne le réactive pas. Retenu
    // seulement si la coupure a réussi ; oublié dès qu'il est réactivé, par le service ou par un autre moyen
    if ok {
        if actif {
            oublier_coupe(canal);
        } else {
            let mut c = COUPES_PAR_LE_SERVICE.lock().unwrap_or_else(|e| e.into_inner());
            c.retain(|x| !x.eq_ignore_ascii_case(canal));
            c.push(canal.to_string());
        }
    }
    ok
}

fn oublier_coupe(canal: &str) {
    COUPES_PAR_LE_SERVICE.lock().unwrap_or_else(|e| e.into_inner()).retain(|x| !x.eq_ignore_ascii_case(canal));
}

static COUPES_PAR_LE_SERVICE: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Journal coupé par le service lui-même (retour arrière de la baseline vers un journal qui était coupé) ?
pub fn coupe_par_le_service(canal: &str) -> bool {
    COUPES_PAR_LE_SERVICE.lock().unwrap_or_else(|e| e.into_inner()).iter().any(|x| x.eq_ignore_ascii_case(canal))
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
    numero_extreme(canal, true)
}

/// Numéro du plus ancien événement encore présent (les plus anciens sont écrasés par la rotation du journal) ; 0 pour
/// un journal vide (`perte_rotation` n'y voit alors aucune perte)
fn plus_ancien_numero(canal: &str) -> Option<u64> {
    numero_extreme(canal, false)
}

fn numero_extreme(canal: &str, dernier: bool) -> Option<u64> {
    static MOTIF: OnceLock<Regex> = OnceLock::new();
    let motif = MOTIF.get_or_init(|| Regex::new(r"<EventRecordID>(\d+)</EventRecordID>").unwrap());
    let (c, r) = (large(canal), large("*"));
    unsafe {
        let sens = if dernier { EvtQueryReverseDirection.0 as u32 } else { 0 };
        let resultats = EvtQuery(None, PCWSTR(c.as_ptr()), PCWSTR(r.as_ptr()), EvtQueryChannelPath.0 as u32 | sens).ok()?;
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
    // Dernière perte (heure, nombre de numéros sautés ou écrasés) : la collecte reste « Partielle » une heure
    let mut perte: Option<(std::time::Instant, u64)> = None;
    // Désactivation du journal déjà écrite dans journal.txt (une ligne par épisode)
    let mut desactivation_signalee = false;
    std::thread::Builder::new()
        .name(format!("journal {canal}"))
        .spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let Some(n) = dernier_numero(&canal) else {
                collectes::echec(collecte, &format!("journal {canal} illisible"));
                continue;
            };
            // Journal désactivé : encore lisible, mais Windows n'y écrit plus rien. Le journal DNS est réactivé
            // (décision D4) ; les autres sont seulement signalés.
            let etat_canal = canal_actif(&canal);
            let desactive = etat_canal == Some(false);
            let mut reactive = false;
            // Coupé par le service lui-même (retour arrière de la baseline, demandé par l'administrateur) : respecté
            let coupe = desactive && coupe_par_le_service(&canal);
            if desactive {
                // Une tentative par épisode : une réactivation refusée ne relance pas wevtutil toutes les 2 s
                if a_reactiver(&canal) && !coupe && !desactivation_signalee {
                    reactive = activer_journal(&canal, true);
                }
                if !desactivation_signalee || reactive {
                    commun::journal(&format!("journal {canal} désactivé{}", match (coupe, a_reactiver(&canal), reactive) {
                        (true, _, _) => " par le retour arrière de la baseline : laissé coupé",
                        (_, true, true) => " par un autre programme : réactivé",
                        (_, true, false) => " par un autre programme : réactivation impossible",
                        _ => " par un autre programme",
                    }));
                }
                desactivation_signalee = !reactive;
            } else {
                desactivation_signalee = false;
                // Journal revu actif (réactivé par l'administrateur ou un autre moyen) : la coupure du service ne vaut
                // plus ; une coupure ultérieure par un tiers sera réactivée (D4)
                if etat_canal == Some(true) {
                    oublier_coupe(&canal);
                }
            }
            let noter = |issue: Option<Lecture>, b: &Blocage, perte: &Option<(std::time::Instant, u64)>| {
                if coupe {
                    collectes::desactivee(collecte, &format!("journal {canal} coupé par le retour arrière de la baseline"));
                    return;
                }
                if desactive && !reactive {
                    collectes::echec(collecte, &format!("journal {canal} désactivé : plus aucun événement n'y est écrit"));
                    return;
                }
                match issue {
                    None | Some(Lecture::Complete) => noter_lu(collecte, perte),
                    // Aucun progrès depuis une minute (délais, ou délais et erreurs mêlés) : plus rien n'est lu
                    Some(Lecture::Delai) if b.sans_progres >= LIMITE_BLOCAGE => {
                        collectes::echec(collecte, &format!("lecture du journal {canal} bloquée par des délais dépassés (journal inondé ?), rien n'est sauté"))
                    }
                    Some(Lecture::Delai) => collectes::partielle(collecte, &format!("lecture du journal {canal} trop lente (délai dépassé) : reprise au tour suivant")),
                    Some(Lecture::Erreur) => collectes::echec(collecte, &format!("événements du journal {canal} illisibles")),
                }
            };
            let Some(mut dernier) = depart else {
                // Première lecture réussie après un départ illisible : le suivi part d'ici
                depart = Some(n);
                noter(None, &blocage, &perte);
                continue;
            };
            if n < dernier {
                // Journal effacé : on repart du début
                dernier = 0;
            }
            if n == dernier {
                noter(None, &blocage, &perte);
                depart = Some(dernier);
                continue;
            }
            // Fenêtres enchaînées tant qu'elles se lisent jusqu'au bout et que le budget du tour (1,5 s) le permet : un
            // journal très actif est rattrapé sans figer le fil
            let debut = std::time::Instant::now();
            let lecture = loop {
                // Des événements non lus ont pu être écrasés par la rotation du journal (un petit journal, DNS-Client ou
                // Defender, tourne en quelques milliers d'événements) : vérifié avant chaque fenêtre ; on repart du plus
                // ancien encore présent, sans dépasser `n`, et la perte est signalée
                if let Some((reprise, perdus)) = plus_ancien_numero(&canal).and_then(|a| perte_rotation(dernier, a)) {
                    let reprise = reprise.min(n);
                    let perdus = perdus.min(n - dernier);
                    commun::journal(&format!("journal {canal} : {perdus} événement(s) écrasé(s) par la rotation du journal avant d'être lus"));
                    perte = Some((std::time::Instant::now(), cumul_perte(&perte) + perdus));
                    dernier = reprise;
                }
                let fin = fenetre(dernier, n);
                let q = format!("*[System[(EventRecordID > {dernier}) and (EventRecordID <= {fin}) and ({conditions})]]");
                let mut traite: Option<u64> = None;
                let lecture = historique(&canal, &q, &mut |xml| {
                    if let Some(id) = numero_evenement(&xml) {
                        traite = Some(traite.map_or(id, |t| t.max(id)));
                    }
                    traiter(xml);
                });
                let lu_jusqu_a = prochain_dernier(dernier, fin, lecture == Lecture::Complete, traite);
                let (suivant, b, sautes) = apres_blocage(dernier, lu_jusqu_a, fin, lecture, blocage);
                if sautes > 0 {
                    commun::journal(&format!("journal {canal} : lecture bloquée {LIMITE_BLOCAGE} tours de suite au même endroit ; numéros {} à {suivant} sautés", lu_jusqu_a + 1));
                    perte = Some((std::time::Instant::now(), cumul_perte(&perte) + sautes));
                }
                blocage = b;
                dernier = suivant;
                if !encore_une_fenetre(lecture, dernier, n, debut.elapsed()) {
                    break lecture;
                }
            };
            noter(Some(lecture), &blocage, &perte);
            depart = Some(dernier);
        })
        .is_ok()
}

/// Journal à réactiver s'il est désactivé (décision D4 : le journal DNS-Client, que le service active lui-même au
/// démarrage) ; les autres journaux désactivés sont seulement signalés
pub fn a_reactiver(canal: &str) -> bool {
    canal.eq_ignore_ascii_case("Microsoft-Windows-DNS-Client/Operational")
}

/// Journal activé ? (configuration du canal, API native : assez léger pour chaque tour de 2 s) ; None si illisible
pub fn canal_actif(canal: &str) -> Option<bool> {
    let c = large(canal);
    unsafe {
        let h = EvtOpenChannelConfig(None, PCWSTR(c.as_ptr()), 0).ok()?;
        let mut v = EVT_VARIANT::default();
        let mut utilise = 0u32;
        let r = EvtGetChannelConfigProperty(h, EvtChannelConfigEnabled, 0, std::mem::size_of::<EVT_VARIANT>() as u32, Some(&mut v), &mut utilise);
        let _ = EvtClose(h);
        r.ok()?;
        // EvtVarTypeBoolean
        (v.Type == 13).then(|| v.Anonymous.BooleanVal.as_bool())
    }
}

/// Numéros lus au plus par tour : une fenêtre lue jusqu'au bout avance jusqu'à sa borne, même sans événement retenu
/// (un journal inondé d'événements que la requête écarte ne fige plus la lecture)
pub const FENETRE: u64 = 5000;

/// Décision pure (testée) : lire une fenêtre de plus dans ce tour ? Seulement après une fenêtre lue jusqu'au bout, s'il
/// reste des numéros et si le tour a duré moins de 1,5 s (le fil revient régulièrement noter son état)
pub fn encore_une_fenetre(lecture: Lecture, dernier: u64, n: u64, ecoule: std::time::Duration) -> bool {
    lecture == Lecture::Complete && dernier < n && ecoule < std::time::Duration::from_millis(1500)
}

/// Décision pure (testée) : borne de la fenêtre lue à ce tour
pub fn fenetre(dernier: u64, n: u64) -> u64 {
    n.min(dernier.saturating_add(FENETRE))
}

/// Décision pure (testée) : le plus ancien numéro encore présent est au-delà du prochain à lire ? Rend (numéro de
/// reprise, numéros écrasés par la rotation avant d'être lus)
pub fn perte_rotation(dernier: u64, plus_ancien: u64) -> Option<(u64, u64)> {
    (plus_ancien > dernier.saturating_add(1)).then(|| (plus_ancien - 1, plus_ancien - 1 - dernier))
}

fn cumul_perte(perte: &Option<(std::time::Instant, u64)>) -> u64 {
    perte.filter(|(t, _)| t.elapsed().as_secs() < 3600).map_or(0, |(_, s)| s)
}

/// Lecture réussie : « Active », ou « Partielle » pendant une heure après une perte (saut ou rotation)
fn noter_lu(collecte: Collecte, perte: &Option<(std::time::Instant, u64)>) {
    match perte {
        Some((t, n)) if t.elapsed().as_secs() < 3600 => {
            collectes::partielle(collecte, &format!("{n} numéro(s) d'événement perdu(s) dans l'heure (lecture bloquée ou rotation du journal)"))
        }
        _ => collectes::succes(collecte),
    }
}

/// Tours de suite sans aucun progrès (délais dépassés et erreurs comptés ensemble) avant d'agir (2 s par tour : une
/// minute)
pub const LIMITE_BLOCAGE: u32 = 30;

/// Lecture bloquée en cours : tours sans progrès, pas du prochain saut
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Blocage {
    pub sans_progres: u32,
    pub pas: u64,
}

impl Default for Blocage {
    fn default() -> Self {
        Blocage { sans_progres: 0, pas: 1 }
    }
}

/// Décision pure (testée) : un journal dont la lecture ne progresse plus ne bloque pas le suivi sans fin, sans jeter
/// tout l'intervalle. Rend (numéro de reprise, blocage, numéros sautés).
/// - lecture complète, ou progrès : reprise normale, blocage remis à zéro ;
/// - sinon, un tour sans progrès de plus (délai dépassé ou erreur, comptés ensemble : une alternance des deux finit
///   aussi par agir) ; arrivé à `LIMITE_BLOCAGE` :
///   - sur une erreur (événement illisible, journal corrompu) : on saute `pas` numéros juste après le dernier lu (1,
///     puis 2, 4… si le blocage persiste, sans dépasser `n`) ;
///   - sur un délai dépassé (journal inondé) : rien n'est sauté, la collecte passe « Indisponible ».
pub fn apres_blocage(dernier: u64, suivant: u64, n: u64, lecture: Lecture, b: Blocage) -> (u64, Blocage, u64) {
    if lecture == Lecture::Complete || suivant > dernier {
        return (suivant, Blocage::default(), 0);
    }
    let sans_progres = b.sans_progres.saturating_add(1);
    if sans_progres < LIMITE_BLOCAGE || lecture == Lecture::Delai {
        return (suivant, Blocage { sans_progres, ..b }, 0);
    }
    let reprise = suivant.saturating_add(b.pas).min(n);
    // Encore bloqué au tour suivant : nouveau saut aussitôt, deux fois plus long
    (reprise, Blocage { sans_progres: LIMITE_BLOCAGE - 1, pas: b.pas.saturating_mul(2) }, reprise - suivant)
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
    // max puis min, et non clamp : aucune panique si `dernier` dépasse `n` (journal recommencé entre deux lectures)
    if lecture_complete { n } else { dernier_traite.map_or(dernier, |t| t.max(dernier).min(n.max(dernier))) }
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
