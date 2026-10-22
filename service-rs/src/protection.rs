//! Protection des données : le dossier de deR4Tizer (événements du SIEM, sessions DPI, trafic, appareils
//! du réseau, alertes avec lignes de commande…) n'est lisible que par SYSTEM, les administrateurs et les
//! comptes autorisés (lecteurs.json), plus par tous les utilisateurs du PC. Par défaut, le compte connecté
//! à la console au premier démarrage ; d'autres comptes s'ajoutent depuis l'interface (avec l'UAC).
//! Les droits sont reposés au démarrage puis toutes les heures.
//!
//! Au démarrage du service, AVANT toute lecture (securiser) : le dossier est créé avec ses droits dès la
//! création ; s'il existait déjà sans appartenir à SYSTEM ou aux administrateurs (créé d'avance par un compte
//! standard, qui pourrait sinon réécrire les droits), il est écarté. Dans le dossier, les liens (jonctions,
//! liens symboliques) sont supprimés et les fichiers d'un autre propriétaire mis de côté dans « ecartes »,
//! puis propriétaire et droits sont imposés à tout le contenu. Le paquet MSI crée aussi le dossier avec ces
//! droits (installeur\deR4Tizer.wxs).

use crate::commun;
use serde::{Deserialize, Serialize};
use std::os::windows::process::CommandExt;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// SYSTEM et administrateurs, propriétaire Administrateurs, sans héritage du dossier ProgramData
const SDDL_DOSSIER: &str = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

pub const SID_SYSTEME: &str = "S-1-5-18";
pub const SID_ADMINISTRATEURS: &str = "S-1-5-32-544";

/// Droits qui permettent d'écrire, de supprimer ou de changer les droits (fichiers et dossiers)
const DROITS_ECRITURE: u32 = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 // données, ajout, attributs étendus, suppression d'enfants, attributs
    | 0x1_0000 | 0x4_0000 | 0x8_0000 // DELETE, WRITE_DAC, WRITE_OWNER
    | 0x0200_0000 | 0x1000_0000 | 0x4000_0000; // MAXIMUM_ALLOWED, GENERIC_ALL, GENERIC_WRITE

/// Décision pure : un fichier du dossier de données n'est cru que s'il appartient à SYSTEM ou aux
/// administrateurs (tout autre compte pourrait en réécrire le contenu ou les droits)
pub fn proprietaire_acceptable(sid: &str) -> bool {
    sid == SID_SYSTEME || sid == SID_ADMINISTRATEURS
}

/// Décision pure sur des droits relus : propriétaire acceptable, héritage coupé, contrôle total pour les
/// seuls comptes de `complets`, lecture seule pour les `lecteurs`, rien pour les autres
pub fn droits_conformes(s: &crate::natif::Securite, complets: &[&str], lecteurs: &[&str]) -> Result<(), String> {
    droits_conformes_pour(s, &proprietaire_acceptable, complets, lecteurs)
}

/// `droits_conformes`, avec la règle d'acceptation du propriétaire fournie (tests hors service)
pub fn droits_conformes_pour(s: &crate::natif::Securite, proprietaire_ok: &dyn Fn(&str) -> bool, complets: &[&str], lecteurs: &[&str]) -> Result<(), String> {
    if !proprietaire_ok(&s.proprietaire) {
        return Err(format!("propriétaire {} (ni SYSTEM ni Administrateurs)", if s.proprietaire.is_empty() { "illisible" } else { &s.proprietaire }));
    }
    if !s.protege {
        return Err("droits hérités du dossier parent".into());
    }
    if s.ace_inconnue {
        return Err("entrée de droits d'un type inattendu".into());
    }
    for a in s.aces.iter().filter(|a| a.autorise) {
        let ok = complets.contains(&a.sid.as_str()) || (lecteurs.contains(&a.sid.as_str()) && a.masque & DROITS_ECRITURE == 0);
        if !ok {
            return Err(format!("droits accordés à {} (masque {:#x})", a.sid, a.masque));
        }
    }
    Ok(())
}

/// Relit les droits d'un chemin et les compare à l'attendu
pub fn verifier(chemin: &Path, complets: &[&str], lecteurs: &[&str]) -> Result<(), String> {
    let s = crate::natif::lire_securite(chemin).ok_or_else(|| format!("droits de {} illisibles", chemin.display()))?;
    droits_conformes(&s, complets, lecteurs).map_err(|e| format!("{} : {e}", chemin.display()))
}

#[derive(Serialize, Deserialize, Clone, Default, PartialEq)]
#[serde(rename_all = "PascalCase", default)]
pub struct Lecteur {
    pub sid: String,
    pub nom: String,
}

fn powershell(script: &str) -> String {
    Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .creation_flags(0x0800_0000)
        .output()
        .map(|s| String::from_utf8_lossy(&s.stdout).trim().to_string())
        .unwrap_or_default()
}

/// SID d'un compte utilisateur local ou de domaine : S-1-5-21-…
fn sid_valide(sid: &str) -> bool {
    sid.starts_with("S-1-5-21-") && sid.len() < 80 && sid[2..].chars().all(|c| c.is_ascii_digit() || c == '-')
}

/// Compte connecté à la console (session interactive) : (SID, nom)
fn utilisateur_console() -> Option<Lecteur> {
    let sortie = powershell("$u = (Get-CimInstance Win32_ComputerSystem).UserName; if ($u) { \
        (New-Object Security.Principal.NTAccount($u)).Translate([Security.Principal.SecurityIdentifier]).Value + '|' + $u }");
    let (sid, nom) = sortie.split_once('|')?;
    sid_valide(sid).then(|| Lecteur { sid: sid.into(), nom: nom.into() })
}

fn nom_de(sid: &str) -> String {
    powershell(&format!("try {{ (New-Object Security.Principal.SecurityIdentifier '{sid}').Translate([Security.Principal.NTAccount]).Value }} catch {{ }}"))
}

/// Comptes autorisés. Lu avec le seul contrôle du propriétaire (pas le verrou d'échec de la protection),
/// pour que la reprise après un échec retrouve les lecteurs
pub fn lecteurs() -> Vec<Lecteur> {
    commun::lire_fichier_proprietaire(&commun::dossier().join("lecteurs.json"))
        .and_then(|t| serde_json::from_str(t.trim_start_matches('\u{feff}')).ok())
        .unwrap_or_default()
}

fn sids_lecteurs(l: &[Lecteur]) -> Vec<&str> {
    l.iter().filter(|x| sid_valide(&x.sid)).map(|x| x.sid.as_str()).collect()
}

/// Pose les droits : SYSTEM et administrateurs en contrôle total, lecteurs en lecture, rien d'autre. La DACL
/// est remplacée en entier (une entrée posée par quelqu'un d'autre ne survit pas)
fn appliquer(lecteurs: &[Lecteur]) -> bool {
    let mut sddl = SDDL_DOSSIER.to_string();
    for l in lecteurs.iter().filter(|l| sid_valide(&l.sid)) {
        sddl.push_str(&format!("(A;OICI;0x1200a9;;;{})", l.sid)); // lecture et parcours
    }
    crate::natif::poser_droits(commun::dossier(), &sddl).is_ok()
}

/// icacls : avec /C (continuer sur erreur), le code de retour vaut 0 même quand un élément a échoué ;
/// ne jamais s'en servir comme preuve, relire les droits
pub fn icacls(args: &[&str]) -> bool {
    Command::new("icacls.exe").args(args).creation_flags(0x0800_0000).output().map(|s| s.status.success()).unwrap_or(false)
}

fn est_lien(m: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    m.file_attributes() & 0x400 != 0 // FILE_ATTRIBUTE_REPARSE_POINT
}

fn supprimer_lien(p: &Path) {
    // Un lien vers un dossier se supprime comme un dossier vide, sans toucher à sa cible
    let _ = fs::remove_dir(p).or_else(|_| fs::remove_file(p));
}

/// Sort d'un élément du dossier de données au démarrage
#[derive(Debug, PartialEq)]
pub enum Tri {
    Garder,
    SupprimerLien,
    Ecarter,
}

/// Décision pure : seul un élément dont le propriétaire est LU et acceptable est gardé. Un propriétaire
/// illisible (None) ne vaut pas confiance : un compte standard peut le rendre illisible pour SYSTEM (DACL
/// vide), alors que la prise de possession qui suit le rendrait ensuite « propre ».
pub fn trier_element(lien: bool, proprietaire_ok: Option<bool>) -> Tri {
    if lien {
        Tri::SupprimerLien
    } else if proprietaire_ok == Some(true) {
        Tri::Garder
    } else {
        Tri::Ecarter
    }
}

/// Crée le dossier « ecartes » s'il n'existe pas : avec ses droits dès la création en service, simplement
/// hors service (tests, console, où le propriétaire est l'utilisateur)
fn creer_ecartes(q: &Path) -> Result<(), String> {
    if fs::symlink_metadata(q).is_ok() {
        return Ok(());
    }
    let ok = if crate::natif::est_systeme() { crate::natif::creer_dossier_protege(q, SDDL_DOSSIER) } else { fs::create_dir(q).is_ok() };
    if ok { Ok(()) } else { Err(format!("création de {} impossible", q.display())) }
}

/// Déplace un élément sans jamais le supprimer ni en changer le propriétaire : déplacement simple, puis par
/// handle avec le privilège de restauration (droits verrouillés par leur propriétaire). Erreurs détaillées.
fn deplacer_sans_perte(p: &Path, dest: &Path) -> Result<(), String> {
    let mut erreurs = Vec::new();
    match fs::rename(p, dest) {
        Ok(()) => return Ok(()),
        Err(e) => erreurs.push(format!("déplacement : {e}")),
    }
    // Privilège actif sur ce fil et pour ce seul appel. JAMAIS de prise de possession : un élément resté sur
    // place aurait alors un propriétaire de confiance et serait chargé au démarrage suivant.
    match crate::natif::avec_privilege_restauration(|| crate::natif::renommer_par_handle(p, dest)) {
        Ok(Ok(())) => return Ok(()),
        Ok(Err(e)) => erreurs.push(format!("déplacement avec privilège : {e}")),
        Err(e) => erreurs.push(format!("privilège de restauration : {e}")),
    }
    Err(erreurs.join(" ; "))
}

/// Parcourt le contenu sans suivre les liens : liens supprimés, éléments au propriétaire non vérifié mis de
/// côté dans `quarantaine`. Jamais de suppression : un élément qui ne peut pas être déplacé reste intact
/// (propriétaire non vérifié, donc jamais lu) et le démarrage passe en échec fermé. Renvoie les chemins
/// écartés (relatifs), avec « IMPOSSIBLE À ÉCARTER » pour les échecs.
pub fn trier(dossier: &Path, racine: &Path, quarantaine: &Path, ecartes: &mut Vec<String>) {
    trier_avec(dossier, racine, quarantaine, ecartes, &crate::natif::proprietaire_de_confiance)
}

/// `trier`, avec la lecture du propriétaire fournie (tests : résultat indépendant du compte qui les lance)
pub fn trier_avec(dossier: &Path, racine: &Path, quarantaine: &Path, ecartes: &mut Vec<String>, de_confiance: &dyn Fn(&Path) -> Option<bool>) {
    let relatif = |p: &Path| p.strip_prefix(racine).unwrap_or(p).display().to_string();
    // Ce qu'on ne peut pas examiner n'est pas gardé en silence : échec fermé
    let lecture = match fs::read_dir(dossier) {
        Ok(l) => l,
        Err(e) => return ecartes.push(format!("{} (IMPOSSIBLE À ÉCARTER : contenu illisible : {e})", relatif(dossier))),
    };
    for e in lecture {
        let e = match e {
            Ok(e) => e,
            Err(err) => {
                ecartes.push(format!("{} (IMPOSSIBLE À ÉCARTER : élément illisible : {err})", relatif(dossier)));
                continue;
            }
        };
        let p = e.path();
        if p == quarantaine {
            continue;
        }
        let m = match fs::symlink_metadata(&p) {
            Ok(m) => m,
            Err(err) => {
                ecartes.push(format!("{} (IMPOSSIBLE À ÉCARTER : non inspectable : {err})", relatif(&p)));
                continue;
            }
        };
        match trier_element(est_lien(&m), de_confiance(&p)) {
            Tri::SupprimerLien => {
                supprimer_lien(&p);
                let ok = fs::symlink_metadata(&p).is_err();
                ecartes.push(format!("{} (lien supprimé){}", relatif(&p), if ok { "" } else { " (IMPOSSIBLE À ÉCARTER)" }));
            }
            Tri::Ecarter => {
                let dest = quarantaine.join(format!("{}-{}", commun::nouvel_id(), relatif(&p).replace(['\\', '/'], "_")));
                let r = creer_ecartes(quarantaine).and_then(|_| deplacer_sans_perte(&p, &dest));
                // Échec : l'élément reste tel quel, jamais supprimé ; démarrage en échec fermé
                ecartes.push(match r {
                    Ok(()) => relatif(&p),
                    Err(e) => format!("{} (IMPOSSIBLE À ÉCARTER : {e})", relatif(&p)),
                });
            }
            Tri::Garder if m.is_dir() => trier_avec(&p, racine, quarantaine, ecartes, de_confiance),
            Tri::Garder => {}
        }
    }
}

/// Dossier « ecartes » : lui-même soumis à la règle (un compte standard pourrait l'avoir créé d'avance, ou en
/// avoir fait un lien). S'il n'est pas sûr, il est mis de côté sous un autre nom, jamais supprimé ; s'il ne
/// peut pas l'être, échec fermé. Il est ensuite (re)créé avec ses droits au premier élément à écarter.
pub fn preparer_quarantaine(q: &Path) -> Result<(), String> {
    preparer_quarantaine_avec(q, &crate::natif::proprietaire_de_confiance)
}

pub fn preparer_quarantaine_avec(q: &Path, de_confiance: &dyn Fn(&Path) -> Option<bool>) -> Result<(), String> {
    let Ok(m) = fs::symlink_metadata(q) else { return Ok(()) };
    match trier_element(est_lien(&m), de_confiance(q)) {
        Tri::Garder => Ok(()),
        Tri::SupprimerLien => {
            supprimer_lien(q);
            if fs::symlink_metadata(q).is_ok() { Err("le dossier ecartes est un lien impossible à supprimer".into()) } else { Ok(()) }
        }
        Tri::Ecarter => {
            let suspect = q.with_file_name(format!("ecartes-suspect-{}", commun::nouvel_id()));
            deplacer_sans_perte(q, &suspect).map_err(|e| format!("dossier ecartes au propriétaire non vérifié, impossible à mettre de côté ({e})"))
        }
    }
}

/// Échec constaté au démarrage (dossier impossible à écarter…) : la vérification horaire ne peut pas le lever,
/// seul un redémarrage réussi du service le fait
static ECHEC_DEMARRAGE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Décision pure : un élément dont la DACL est protégée (héritage coupé) et dont le propriétaire est de
/// confiance a reçu ses propres droits à la création ; il ne doit pas être réinitialisé (ni son contenu)
pub fn a_garder_tel_quel(s: &crate::natif::Securite, proprietaire_ok: &dyn Fn(&str) -> bool) -> bool {
    s.protege && proprietaire_ok(&s.proprietaire)
}

/// Réinitialise aux droits hérités le contenu de `dossier`, élément par élément, sans suivre de lien, en
/// laissant intacts (avec leur contenu) les éléments à garder tels quels
pub fn reinitialiser_contenu(dossier: &Path, proprietaire_ok: &dyn Fn(&str) -> bool) {
    let Ok(lecture) = fs::read_dir(dossier) else { return };
    for e in lecture.flatten() {
        let p = e.path();
        let Ok(m) = fs::symlink_metadata(&p) else { continue };
        if est_lien(&m) || crate::natif::lire_securite(&p).is_some_and(|s| a_garder_tel_quel(&s, proprietaire_ok)) {
            continue;
        }
        icacls(&[&p.to_string_lossy(), "/reset", "/C", "/Q"]);
        if m.is_dir() {
            reinitialiser_contenu(&p, proprietaire_ok);
        }
    }
}

/// Démarrage du service, avant toute lecture du dossier de données
pub fn securiser() {
    if !crate::natif::est_systeme() {
        let _ = fs::create_dir_all(commun::dossier());
        return;
    }
    let racine = commun::dossier().clone();
    let mut messages = Vec::new();
    let mut echec = None;
    if let Ok(m) = fs::symlink_metadata(&racine) {
        match trier_element(est_lien(&m), crate::natif::proprietaire_de_confiance(&racine)) {
            Tri::Garder => {}
            Tri::SupprimerLien => {
                supprimer_lien(&racine);
                if fs::symlink_metadata(&racine).is_ok() {
                    echec = Some("le dossier de données est un lien impossible à supprimer".to_string());
                } else {
                    messages.push("le dossier de données était un lien : supprimé".to_string());
                }
            }
            Tri::Ecarter => {
                let ecarte = racine.with_file_name(format!("deR4Tizer.ecarte-{}", commun::maintenant().replace([':', ' '], "-")));
                if fs::rename(&racine, &ecarte).is_ok() {
                    messages.push(format!("le dossier de données n'appartenait pas (de façon vérifiable) à SYSTEM ou aux administrateurs : écarté vers {}", ecarte.display()));
                } else {
                    echec = Some("le dossier de données n'appartient pas (de façon vérifiable) à SYSTEM ou aux administrateurs et n'a pas pu être écarté".to_string());
                }
            }
        }
    }
    // Échec fermé : rien n'est imposé sur un dossier qu'on n'a pas pu écarter ni sur un lien (ce serait le
    // blanchir) ; le service tourne avec ses valeurs par défaut
    let resultat = match echec {
        Some(e) => Err(e),
        None => imposer(&racine, &mut messages),
    };
    // Tout échec du démarrage reste acquis jusqu'au prochain démarrage : la vérification horaire, qui ne revoit
    // que la racine, ne doit pas le lever (le contenu, lui, n'a pas été traité)
    if let Err(e) = &resultat {
        *ECHEC_DEMARRAGE.lock().unwrap() = Some(e.clone());
    }
    for m in messages {
        commun::journal(&format!("protection des données : {m}"));
    }
    let _ = publier(resultat);
}

/// Échec fermé : tant que la protection n'est pas vérifiée, aucun fichier de configuration ou de secret n'est
/// chargé (commun::lire_fichier), et l'échec est affiché dans l'interface (etat.json)
/// Décision pure : un échec du démarrage l'emporte sur le résultat d'une vérification ultérieure
pub fn combiner(echec_demarrage: Option<String>, resultat: Result<(), String>) -> Result<(), String> {
    match echec_demarrage {
        Some(e) => Err(e),
        None => resultat,
    }
}

fn publier(resultat: Result<(), String>) -> Option<String> {
    match combiner(ECHEC_DEMARRAGE.lock().unwrap().clone(), resultat) {
        Ok(()) => {
            commun::definir_echec_protection(None);
            None
        }
        Err(e) => {
            commun::journal(&format!("protection des données : ÉCHEC ({e}) : configuration et secrets ignorés, valeurs par défaut"));
            commun::definir_echec_protection(Some(e.clone()));
            Some(e)
        }
    }
}

/// Alerte critique locale à l'entrée en échec. Elle reste sur le poste : les secrets de remontée sont
/// ignorés en échec fermé (limite connue)
pub fn alerte_echec(raison: &str) -> commun::Alerte {
    commun::Alerte {
        id: commun::nouvel_id(),
        heure: commun::maintenant(),
        niveau: "Critique".into(),
        score: 10,
        processus: "deR4Tizer".into(),
        chemin: commun::dossier().display().to_string(),
        destination: "protection du dossier de données".into(),
        raisons: format!("PROTECTION DU DOSSIER DE DONNÉES EN ÉCHEC : {raison}. Configuration, apprentissage, blocages, \
            quarantaine et secrets sont ignorés (valeurs par défaut) ; la détection continue. Cette alerte n'est pas remontée \
            au prestataire. Que faire : regarder le journal (éléments écartés ou impossibles à écarter), fermer le programme \
            qui tient le fichier, puis redémarrer le service deR4Tizer."),
        ..Default::default()
    }
}

fn imposer(racine: &Path, messages: &mut Vec<String>) -> Result<(), String> {
    if !racine.exists() && !crate::natif::creer_dossier_protege(racine, SDDL_DOSSIER) {
        return Err(format!("impossible de créer {} avec ses droits", racine.display()));
    }
    // D'abord le dossier racine, propriétaire compris (plus personne d'autre ne peut y créer quoi que ce soit),
    // puis le contenu
    if !appliquer(&[]) {
        return Err("pose du propriétaire ou des droits du dossier refusée".into());
    }
    let quarantaine = racine.join("ecartes");
    preparer_quarantaine(&quarantaine)?;
    // Quarantaine : reprise des transactions interrompues, puis copies d'avant la 4.3 (propriétaire de
    // l'utilisateur) recopiées avec leurs droits avant le tri, qui sinon les écarterait (restauration impossible)
    messages.extend(crate::reponse::reprendre_et_migrer_quarantaine_service());
    let mut ecartes = Vec::new();
    trier(racine, racine, &quarantaine, &mut ecartes);
    if !ecartes.is_empty() {
        messages.push(format!("{} élément(s) d'un autre propriétaire ou lien(s) écarté(s) vers ecartes : {}", ecartes.len(),
            ecartes.iter().take(20).cloned().collect::<Vec<_>>().join(", ")));
    }
    if ecartes.iter().any(|e| e.contains("IMPOSSIBLE")) {
        return Err("un élément d'un autre propriétaire n'a pas pu être écarté".into());
    }
    // Tout ce qui reste appartient à SYSTEM ou aux administrateurs (vérifié par trier). Contenu : droits
    // hérités du dossier, sauf ce qui a reçu ses propres droits à la création (DACL protégée et propriétaire
    // de confiance : jeton, secrets, copies de quarantaine, dossiers de repli). Avec /C, icacls rend 0 même en
    // cas d'échec : son code n'est pas une preuve, seules les relectures de droits en sont une
    reinitialiser_contenu(racine, &proprietaire_acceptable);
    crate::notifications::preparer_dossier()?;
    crate::api::proteger_jeton()?;
    let l = lecteurs();
    if !appliquer(&l) {
        return Err("pose des droits des comptes autorisés refusée".into());
    }
    verifier(racine, &[SID_SYSTEME, SID_ADMINISTRATEURS], &sids_lecteurs(&l))
}

/// Ajoute un compte autorisé (commande de l'interface) ; renvoie son nom
pub fn autoriser(sid: &str) -> Result<String, String> {
    if !sid_valide(sid) {
        return Err("identifiant de compte invalide".into());
    }
    let mut l = lecteurs();
    let nom = nom_de(sid);
    if !l.iter().any(|x| x.sid == sid) {
        l.push(Lecteur { sid: sid.into(), nom: if nom.is_empty() { sid.into() } else { nom.clone() } });
        let _ = commun::ecrire("lecteurs.json", &l);
    }
    if !appliquer(&l) {
        return Err("pose des droits refusée par Windows".into());
    }
    commun::journal(&format!("protection des données : accès en lecture accordé à {}", if nom.is_empty() { sid } else { &nom }));
    Ok(if nom.is_empty() { sid.into() } else { nom })
}

pub fn demarrer(alertes: std::sync::Arc<std::sync::Mutex<Vec<commun::Alerte>>>) {
    std::thread::Builder::new().name("protection".into()).spawn(move || {
        let mut annonce = false;
        let mut en_echec = false;
        loop {
            let mut l = lecteurs();
            if l.is_empty() {
                if let Some(u) = utilisateur_console() {
                    l.push(u);
                    let _ = commun::ecrire("lecteurs.json", &l);
                }
            }
            let resultat = if appliquer(&l) {
                verifier(commun::dossier(), &[SID_SYSTEME, SID_ADMINISTRATEURS], &sids_lecteurs(&l))
            } else {
                Err("pose des droits du dossier refusée".into())
            };
            if !l.is_empty() && !annonce && resultat.is_ok() {
                commun::journal(&format!("protection des données : lecture réservée à SYSTEM, aux administrateurs et à {}",
                    l.iter().map(|x| x.nom.as_str()).collect::<Vec<_>>().join(", ")));
                annonce = true;
            }
            let echec = publier(resultat);
            // Entrée en échec (au démarrage ou plus tard) : une alerte critique, pas une par heure
            if let (Some(e), false) = (&echec, en_echec) {
                alertes.lock().unwrap().push(alerte_echec(e));
            }
            en_echec = echec.is_some();
            // Personne n'est encore connecté (démarrage du PC) : on réessaie bientôt
            std::thread::sleep(Duration::from_secs(if l.is_empty() { 60 } else { 3600 }));
        }
    }).unwrap();
}
