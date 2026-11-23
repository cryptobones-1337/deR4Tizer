//! Protection des données : le dossier de deR4Tizer (événements du SIEM, sessions DPI, trafic, appareils
//! du réseau, alertes avec lignes de commande…) n'est lisible que par SYSTEM, les administrateurs et les
//! comptes autorisés (lecteurs.json), plus par tous les utilisateurs du PC. Par défaut, le compte connecté
//! à la console au premier démarrage ; d'autres comptes s'ajoutent depuis l'interface (avec l'UAC).
//! Les droits sont reposés au démarrage puis toutes les heures.
//!
//! Au démarrage du service, AVANT toute lecture (securiser) : le dossier est créé avec ses droits dès la
//! création ; s'il existait déjà sans appartenir à SYSTEM ou aux administrateurs (créé d'avance par un compte
//! standard, qui pourrait sinon réécrire les droits), il est écarté sous un nom imprévisible. La racine est ensuite
//! ouverte sans suivre de lien, chemin final vérifié, et ses droits sont posés et relus sur ce handle (audit du
//! 2026-11-23, C-1) ; tant qu'elle ne l'est pas (lien impossible à supprimer, tenu ouvert par un autre compte), rien
//! n'est écrit dessous, l'échec est dit au journal d'événements de Windows et dans %SystemRoot%\Temp, et le service
//! réessaie chaque minute avant de démarrer la surveillance. Dans le dossier, les liens (jonctions, liens symboliques)
//! sont supprimés et les fichiers d'un autre propriétaire ou à plusieurs liens physiques mis de côté dans « ecartes »
//! (C-2) ; à la première prise en charge d'un dossier préexistant, tout son contenu l'est (marqueur
//! prise-en-charge.json). Puis propriétaire et droits sont imposés à tout le contenu. Le paquet MSI crée aussi le
//! dossier avec ces droits et refuse de s'installer quand il est un lien (installeur\deR4Tizer.wxs) ; la
//! désinstallation garde la racine, vide et protégée (vider_racine).

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

/// Personne d'autre que `complets` ne peut écrire, supprimer ni changer les droits, et le propriétaire est acceptable (pur,
/// testé) : tâche planifiée, que tout le monde peut lire
pub fn sans_ecriture_de_tiers(s: &crate::natif::Securite, complets: &[&str]) -> Result<(), String> {
    if !proprietaire_acceptable(&s.proprietaire) {
        return Err(format!("propriétaire {}", s.proprietaire));
    }
    if s.ace_inconnue {
        return Err("entrée de droits d'un type inattendu".into());
    }
    match s.aces.iter().find(|a| a.autorise && a.masque & DROITS_ECRITURE != 0 && !complets.contains(&a.sid.as_str())) {
        Some(a) => Err(format!("écriture accordée à {} (masque {:#x})", a.sid, a.masque)),
        None => Ok(()),
    }
}

/// NT SERVICE\TrustedInstaller : contrôle total hérité de Program Files sur une installation d'avant le droit posé par le MSI
pub const SID_TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

/// Décision pure (audit du 2026-11-23, A-4-1) : dossier de l'exécutable du service, ou l'un de ses programmes, que seuls
/// SYSTEM, les administrateurs et TrustedInstaller peuvent modifier, l'un d'eux en étant propriétaire. L'entrée CREATOR
/// OWNER (S-1-3-0) ne donne aucun droit sur l'objet lui-même. Un dossier d'installation redirigé (INSTALLFOLDER est une
/// propriété publique du MSI) dans un dossier qu'un compte standard peut écrire y ferait charger une DLL ou remplacer un
/// programme exécuté en SYSTEM
pub fn installation_conforme(s: &crate::natif::Securite) -> Result<(), String> {
    let complets = [SID_SYSTEME, SID_ADMINISTRATEURS, SID_TRUSTED_INSTALLER];
    if !complets.contains(&s.proprietaire.as_str()) {
        return Err(format!("propriétaire {}", if s.proprietaire.is_empty() { "illisible" } else { &s.proprietaire }));
    }
    if s.ace_inconnue {
        return Err("entrée de droits d'un type inattendu".into());
    }
    match s.aces.iter().find(|a| a.autorise && a.masque & DROITS_ECRITURE != 0 && !complets.contains(&a.sid.as_str()) && a.sid != "S-1-3-0") {
        Some(a) => Err(format!("écriture accordée à {} (masque {:#x})", a.sid, a.masque)),
        None => Ok(()),
    }
}

/// FILE_ADD_SUBDIRECTORY (AppendData d'un dossier) : création de dossiers, que Windows donne aux Utilisateurs authentifiés
/// sur la racine du volume ; ne permet ni de renommer ni de supprimer un dossier existant
const AJOUT_DE_DOSSIER: u32 = 0x4;

/// Décision pure (audit de #277, S277-01) : un dossier PARENT du dossier d'installation, jusqu'à la racine du volume.
/// Renommer ou supprimer le dossier d'installation demande « supprimer un enfant » (FILE_DELETE_CHILD) sur son parent,
/// ou DELETE sur lui-même : un compte qui l'obtient y pose un autre dossier avec un service piégé, exécuté en SYSTEM au
/// redémarrage. Seuls SYSTEM, les administrateurs et TrustedInstaller peuvent écrire, supprimer un enfant, changer les
/// droits ou le propriétaire, l'un d'eux en étant propriétaire (le propriétaire peut toujours réécrire les droits). Les
/// entrées qui ne valent que pour les enfants (INHERIT_ONLY_ACE) et CREATOR OWNER ne donnent rien sur le dossier lui-même ;
/// sur la racine, la création de dossiers est tolérée, jamais la suppression d'un enfant
pub fn parent_installation_conforme(s: &crate::natif::Securite, racine: bool) -> Result<(), String> {
    let complets = [SID_SYSTEME, SID_ADMINISTRATEURS, SID_TRUSTED_INSTALLER];
    if !complets.contains(&s.proprietaire.as_str()) {
        return Err(format!("propriétaire {}", if s.proprietaire.is_empty() { "illisible" } else { &s.proprietaire }));
    }
    if s.ace_inconnue {
        return Err("entrée de droits d'un type inattendu".into());
    }
    let interdits = if racine { DROITS_ECRITURE & !AJOUT_DE_DOSSIER } else { DROITS_ECRITURE };
    match s.aces.iter().find(|a| a.autorise && !a.heritage_seul && a.masque & interdits != 0 && !complets.contains(&a.sid.as_str()) && a.sid != "S-1-3-0") {
        Some(a) => Err(format!("écriture, suppression d'un enfant ou changement de droits accordé à {} (masque {:#x})", a.sid, a.masque)),
        None => Ok(()),
    }
}

/// Propriétaire et droits lus par le handle de l'élément ouvert sans suivre de lien (READ_CONTROL) ; un lien ou une
/// lecture refusée : Err (échec fermé)
fn securite_par_handle(p: &Path, dossier: bool) -> Result<crate::natif::Securite, String> {
    let f = crate::natif::ouvrir_sans_lien(p, 0x0002_0000, 0x7, dossier).map_err(|e| format!("{} non ouvert sans lien ({e:?})", p.display()))?;
    crate::natif::lire_securite_handle(&f).ok_or_else(|| format!("droits de {} illisibles", p.display()))
}

/// Relit propriétaire et droits du dossier de l'exécutable du service, de ses deux programmes et de chaque dossier
/// parent jusqu'à la racine du volume ; Err au premier écart ou droit illisible (échec fermé : la mise à jour
/// automatique est alors refusée)
pub fn verifier_installation() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("exécutable du service introuvable ({e})"))?;
    let dossier = exe.parent().ok_or("dossier de l'exécutable introuvable")?.to_path_buf();
    let interface = dossier.join("deR4Tizer.exe");
    let s = securite_par_handle(&dossier, true)?;
    installation_conforme(&s).map_err(|e| format!("{} : {e}", dossier.display()))?;
    for p in [exe.clone(), interface.clone()] {
        if p == interface && !interface.exists() {
            continue;
        }
        let s = securite_par_handle(&p, false)?;
        installation_conforme(&s).map_err(|e| format!("{} : {e}", p.display()))?;
    }
    let mut parent = dossier.parent();
    while let Some(p) = parent {
        let racine = p.parent().is_none();
        let s = securite_par_handle(p, true)?;
        parent_installation_conforme(&s, racine).map_err(|e| format!("{} (dossier parent) : {e}", p.display()))?;
        parent = p.parent();
    }
    Ok(())
}

/// INT-003 : dossier d'installation modifiable par un autre compte, alerte critique locale au démarrage (A-4-1)
pub fn alerte_installation(raison: &str) -> commun::Alerte {
    commun::Alerte {
        regle: crate::regles::INT_003.into(),
        id: commun::nouvel_id(),
        heure: commun::maintenant(),
        niveau: "Critique".into(),
        score: 10,
        processus: "deR4Tizer".into(),
        chemin: std::env::current_exe().ok().and_then(|e| e.parent().map(|d| d.display().to_string())).unwrap_or_default(),
        destination: "dossier d'installation".into(),
        raisons: format!("DOSSIER D'INSTALLATION DE DER4TIZER MODIFIABLE PAR UN AUTRE COMPTE : {raison}. Un programme ou une DLL posé là \
            serait exécuté en SYSTEM ; la mise à jour automatique est refusée. Que faire : réinstaller deR4Tizer dans son dossier par \
            défaut (Program Files), dont le paquet pose les droits."),
        ..Default::default()
    }
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
    crate::mesure::powershell("protection");
    Command::new(crate::natif::powershell_exe())
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

/// Droits d'un sous-dossier de données que l'interface lit (chronologies, PR 4.3) : ceux du dossier de données, et les
/// SID des lecteurs pour `droits_conformes`
pub fn sddl_lecture() -> (String, Vec<String>) {
    let l = lecteurs();
    let sids: Vec<String> = sids_lecteurs(&l).into_iter().map(String::from).collect();
    let mut sddl = SDDL_DOSSIER.to_string();
    for s in &sids {
        sddl.push_str(&format!("(A;OICI;0x1200a9;;;{s})"));
    }
    (sddl, sids)
}

/// Accès du handle de la racine : READ_CONTROL, WRITE_DAC, WRITE_OWNER, FILE_READ_ATTRIBUTES
const ACCES_RACINE: u32 = 0x0002_0000 | 0x0004_0000 | 0x0008_0000 | 0x80;

/// Ouvre la racine du dossier de données sans suivre de lien, chemin final vérifié (audit du 2026-11-23, C-1) : toute
/// lecture ou pose de ses droits passe par ce handle. Avant, poser_droits (par le chemin) agissait sur la jonction posée
/// à la racine, pas sur un dossier à nous
fn ouvrir_racine() -> Result<fs::File, String> {
    crate::natif::ouvrir_verifie(commun::dossier(), ACCES_RACINE, 0x7, true)
        .map_err(|e| format!("racine du dossier de données non ouverte sans lien ({e})"))
}

/// Décision pure (C-1) : racine ouverte par handle (sans lien, chemin final vérifié) dont les droits relus la gardent à
/// SYSTEM et aux administrateurs : propriétaire acceptable, héritage coupé, aucune écriture d'un autre compte. Sert aux
/// actions du MSI lancées en SYSTEM, qui ne posent pas de droits (verifier_racine)
pub fn racine_conforme(s: &crate::natif::Securite) -> Result<(), String> {
    if !s.protege {
        return Err("droits hérités du dossier parent".into());
    }
    sans_ecriture_de_tiers(s, &[SID_SYSTEME, SID_ADMINISTRATEURS])
}

/// Actions lancées en SYSTEM hors du service (MSI : nettoyage, baseline, relance, suppression des données) : la racine
/// n'est écrite (journal compris) qu'une fois ouverte sans lien et ses droits relus conformes (C-1) ; sinon leurs lignes
/// vont au journal d'événements de Windows
pub fn verifier_racine() -> Result<(), String> {
    let r = ouvrir_racine().and_then(|f| crate::natif::lire_securite_handle(&f).ok_or_else(|| "droits de la racine illisibles".to_string()))
        .and_then(|s| racine_conforme(&s));
    commun::definir_racine_verifiee(r.is_ok());
    r
}

/// SDDL de la racine : SYSTEM et administrateurs en contrôle total, lecteurs en lecture et parcours
fn sddl_racine(lecteurs: &[Lecteur]) -> String {
    let mut sddl = SDDL_DOSSIER.to_string();
    for l in lecteurs.iter().filter(|l| sid_valide(&l.sid)) {
        sddl.push_str(&format!("(A;OICI;0x1200a9;;;{})", l.sid)); // lecture et parcours
    }
    sddl
}

/// Pose les droits de la racine PAR SON HANDLE (ouverte sans suivre de lien, chemin final vérifié ; C-1), puis les relit
/// sur ce même handle : SYSTEM et administrateurs en contrôle total, lecteurs en lecture, rien d'autre. La DACL est
/// remplacée en entier (une entrée posée par quelqu'un d'autre ne survit pas)
fn appliquer(lecteurs: &[Lecteur]) -> Result<(), String> {
    let f = ouvrir_racine()?;
    crate::natif::poser_droits_handle(&f, &sddl_racine(lecteurs)).map_err(|e| format!("pose du propriétaire ou des droits du dossier refusée ({e})"))?;
    let s = crate::natif::lire_securite_handle(&f).ok_or_else(|| format!("droits de {} illisibles", commun::dossier().display()))?;
    droits_conformes(&s, &[SID_SYSTEME, SID_ADMINISTRATEURS], &sids_lecteurs(lecteurs)).map_err(|e| format!("{} : {e}", commun::dossier().display()))
}

/// icacls : avec /C (continuer sur erreur), le code de retour vaut 0 même quand un élément a échoué ;
/// ne jamais s'en servir comme preuve, relire les droits
pub fn icacls(args: &[&str]) -> bool {
    Command::new(crate::natif::systeme32("icacls.exe")).args(args).creation_flags(0x0800_0000).output().map(|s| s.status.success()).unwrap_or(false)
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
    trier_element_liens(lien, proprietaire_ok, Some(1))
}

/// `trier_element` avec le nombre de liens physiques du fichier (Some(1) pour un dossier) : un fichier à plusieurs liens
/// physiques, ou dont le nombre de liens ne se lit pas, est écarté quel que soit son propriétaire (audit du 2026-11-23,
/// C-2) : un lien dur posé vers un fichier de SYSTEM pris ailleurs porte le propriétaire de ce fichier, et les droits
/// imposés ensuite (icacls /reset) changeraient ceux du fichier d'origine
pub fn trier_element_liens(lien: bool, proprietaire_ok: Option<bool>, liens: Option<u32>) -> Tri {
    if lien {
        Tri::SupprimerLien
    } else if proprietaire_ok == Some(true) && liens == Some(1) {
        Tri::Garder
    } else {
        Tri::Ecarter
    }
}

/// Marqueur de prise en charge de la racine (C-2), écrit par le service : « Faite » une fois tout le contenu préexistant
/// mis de côté (ou pour la racine d'une version précédente)
pub const MARQUEUR: &str = "prise-en-charge.json";

#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
#[serde(rename_all = "PascalCase", default)]
pub struct PriseEnCharge {
    pub faite: bool,
    pub version: String,
    pub date: String,
}

/// Décision pure (C-2) : première prise en charge de la racine, dont tout le contenu est mis de côté quel qu'en soit le
/// propriétaire ? `marqueur` : None s'il est absent ou pas de confiance, sinon « faite ». Sans marqueur, un etat.json de
/// confiance (SYSTEM ou Administrateurs, un seul lien physique) désigne le dossier d'une version précédente, repris sans
/// tout mettre de côté (sinon une mise à niveau perdrait configuration, secrets et sauvegarde de la baseline) ; un compte
/// standard ne peut pas en poser un
pub fn premiere_prise_en_charge(marqueur: Option<bool>, etat_ancien: bool) -> bool {
    match marqueur {
        Some(faite) => !faite,
        None => !etat_ancien,
    }
}

/// Décision pure (C-2) : le dossier « ecartes » existant est-il jugé sur son propriétaire (gardé s'il est de confiance) ?
/// Oui hors première prise en charge, et en REPRISE d'une première prise en charge (marqueur « à faire ») : il a alors été
/// créé par le service après la pose des droits de la racine, et contient ce qu'un démarrage interrompu a déjà mis de
/// côté. Non à la première prise en charge sans marqueur : préexistant, il est mis de côté avec le reste. Avant (CI de
/// #288, run 45222958564) : à la reprise, les éléments déjà écartés étaient remis de côté une seconde fois, imbriqués
/// dans un « ecartes-suspect-… », hors de la vue de qui les cherche dans ecartes
pub fn ecartes_juge_au_proprietaire(premiere: bool, marqueur: Option<bool>) -> bool {
    !premiere || marqueur.is_some()
}

/// Nom du dossier de données écarté (pur, testé) : date et identifiant unique, pour qu'un compte standard ne puisse pas
/// poser ce nom d'avance (audit du 2026-11-23)
pub fn nom_ecarte(date: &str, id: &str) -> String {
    format!("deR4Tizer.ecarte-{}-{id}", date.replace([':', ' '], "-"))
}

/// Crée le dossier « ecartes » s'il n'existe pas : avec ses droits dès la création en service, simplement
/// hors service (tests, console, où le propriétaire est l'utilisateur)
fn creer_ecartes(q: &Path) -> Result<(), String> {
    if fs::symlink_metadata(q).is_ok() {
        return Ok(());
    }
    let ok = if crate::natif::est_systeme() { crate::natif::creer_dossier_protege(q, SDDL_DOSSIER) } else { commun::creer_dossier(q).is_ok() };
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

/// Parcourt le contenu sans suivre les liens : liens supprimés, éléments au propriétaire non vérifié (lu par
/// `de_confiance` : natif::proprietaire_de_confiance en service, toujours « non » à la première prise en charge, fourni
/// par les tests) ou à plusieurs liens physiques mis de côté dans `quarantaine`. Jamais de suppression : un élément qui
/// ne peut pas être déplacé reste intact (propriétaire non vérifié, donc jamais lu) et le démarrage passe en échec
/// fermé. Renvoie les chemins écartés (relatifs), avec « IMPOSSIBLE À ÉCARTER » pour les échecs.
pub fn trier_avec(dossier: &Path, racine: &Path, quarantaine: &Path, ecartes: &mut Vec<String>, de_confiance: &dyn Fn(&Path) -> Option<bool>) {
    let marqueur = racine.join(MARQUEUR);
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
        // Le marqueur de prise en charge est écrit par le service avant le tri (C-2)
        if p == quarantaine || p == marqueur {
            continue;
        }
        let m = match fs::symlink_metadata(&p) {
            Ok(m) => m,
            Err(err) => {
                ecartes.push(format!("{} (IMPOSSIBLE À ÉCARTER : non inspectable : {err})", relatif(&p)));
                continue;
            }
        };
        let liens = if m.is_dir() { Some(1) } else { crate::natif::nombre_de_liens_chemin(&p) };
        match trier_element_liens(est_lien(&m), de_confiance(&p), liens) {
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

/// Décision pure : un élément dont la DACL est protégée (héritage coupé), dont le propriétaire est de
/// confiance et sur lequel aucun autre compte n'a de droit d'écriture a reçu ses propres droits à la
/// création ; il ne doit pas être réinitialisé (ni son contenu). `de_confiance` : SYSTEM et Administrateurs
/// en service. Une entrée de type inconnu empêche de le garder.
pub fn a_garder_tel_quel(s: &crate::natif::Securite, de_confiance: &dyn Fn(&str) -> bool) -> bool {
    s.protege
        && de_confiance(&s.proprietaire)
        && !s.ace_inconnue
        && s.aces.iter().filter(|a| a.autorise).all(|a| de_confiance(&a.sid) || a.masque & DROITS_ECRITURE == 0)
}

/// Réinitialise aux droits hérités le contenu de `dossier`, élément par élément, sans suivre de lien, en
/// laissant intacts (avec leur contenu) les éléments à garder tels quels
pub fn reinitialiser_contenu(dossier: &Path, de_confiance: &dyn Fn(&str) -> bool) {
    let Ok(lecture) = fs::read_dir(dossier) else { return };
    for e in lecture.flatten() {
        let p = e.path();
        let Ok(m) = fs::symlink_metadata(&p) else { continue };
        if est_lien(&m) || crate::natif::lire_securite(&p).is_some_and(|s| a_garder_tel_quel(&s, de_confiance)) {
            continue;
        }
        icacls(&[&p.to_string_lossy(), "/reset", "/C", "/Q"]);
        if m.is_dir() {
            reinitialiser_contenu(&p, de_confiance);
        }
    }
}

/// Racine non sûre (C-1) : dit au journal d'événements de Windows et dans un compte rendu de %SystemRoot%\Temp (nom
/// unique, créé sans suivre de lien), une fois par raison (le service réessaie chaque minute)
fn signaler_racine_non_sure(raison: &str) {
    static DERNIERE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
    let mut d = DERNIERE.lock().unwrap_or_else(|e| e.into_inner());
    if d.as_deref() == Some(raison) {
        return;
    }
    *d = Some(raison.to_string());
    let texte = format!("deR4Tizer : protection des données : ÉCHEC ({raison}). Rien n'est écrit dans {} ni dessous tant que sa racine \
        n'a pas été vérifiée ; la surveillance ne démarre pas ; nouvel essai chaque minute. Que faire : fermer le programme qui tient \
        ce chemin (une jonction ou un lien posé par un autre compte), ou le supprimer en administrateur.", commun::dossier().display());
    crate::natif::journal_evenements(&texte, true);
    crate::natif::compte_rendu_systeme("deR4Tizer-protection", &texte);
}

/// Prise de la racine (C-1) : un lien est supprimé, une racine d'un autre propriétaire écartée sous un nom imprévisible,
/// une racine absente créée avec ses droits ; puis la racine est ouverte sans suivre de lien (chemin final vérifié), ses
/// propriétaire et droits posés et relus sur ce handle. Err : racine non sûre, rien ne doit être écrit dessous
fn prendre_racine(racine: &Path, messages: &mut Vec<String>) -> Result<(), String> {
    if let Ok(m) = fs::symlink_metadata(racine) {
        match trier_element(est_lien(&m), crate::natif::proprietaire_de_confiance(racine)) {
            Tri::Garder => {}
            Tri::SupprimerLien => {
                supprimer_lien(racine);
                if fs::symlink_metadata(racine).is_ok() {
                    return Err("le dossier de données est un lien impossible à supprimer".into());
                }
                messages.push("le dossier de données était un lien : supprimé".to_string());
            }
            Tri::Ecarter => {
                let ecarte = racine.with_file_name(nom_ecarte(&commun::maintenant(), &commun::nouvel_id()));
                if fs::rename(racine, &ecarte).is_err() {
                    return Err("le dossier de données n'appartient pas (de façon vérifiable) à SYSTEM ou aux administrateurs et n'a pas pu être écarté".into());
                }
                messages.push(format!("le dossier de données n'appartenait pas (de façon vérifiable) à SYSTEM ou aux administrateurs : écarté vers {}", ecarte.display()));
            }
        }
    }
    if fs::symlink_metadata(racine).is_err() && !crate::natif::creer_dossier_protege(racine, SDDL_DOSSIER) {
        return Err(format!("impossible de créer {} avec ses droits", racine.display()));
    }
    // Par le handle : propriétaire puis droits, plus personne d'autre ne peut y créer quoi que ce soit
    appliquer(&[])
}

/// Démarrage du service, avant toute lecture du dossier de données. Faux si la racine n'est pas sûre (C-1) : rien n'a été
/// écrit dessous, le service réessaie chaque minute avant de démarrer la surveillance (main.rs)
pub fn securiser() -> bool {
    if !crate::natif::est_systeme() {
        let _ = crate::commun::creer_dossiers(commun::dossier());
        return true;
    }
    // Chaque essai est un démarrage : un échec d'un essai précédent ne survit pas à un essai réussi
    *ECHEC_DEMARRAGE.lock().unwrap() = None;
    commun::definir_racine_verifiee(false);
    let racine = commun::dossier().clone();
    let mut messages = Vec::new();
    if let Err(e) = prendre_racine(&racine, &mut messages) {
        // Racine non sûre : ni journal, ni état, ni droits par le chemin ; l'échec est dit hors du dossier
        commun::definir_echec_protection(Some(e.clone()));
        signaler_racine_non_sure(&e);
        return false;
    }
    commun::definir_racine_verifiee(true);
    let resultat = imposer(&racine, &mut messages);
    // Tout échec du démarrage reste acquis jusqu'au prochain démarrage : la vérification horaire, qui ne revoit
    // que la racine, ne doit pas le lever (le contenu, lui, n'a pas été traité)
    if let Err(e) = &resultat {
        *ECHEC_DEMARRAGE.lock().unwrap() = Some(e.clone());
    }
    for m in messages {
        commun::journal(&format!("protection des données : {m}"));
    }
    let _ = publier(resultat);
    true
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
        regle: crate::regles::INT_001.into(),
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

/// Marqueur de prise en charge lu (C-2) : Some(faite) s'il est de confiance (lecture contrôlée : propriétaire, un seul lien
/// physique) et lisible, None sinon
fn lire_marqueur(racine: &Path) -> Option<bool> {
    commun::lire_fichier_proprietaire(&racine.join(MARQUEUR))
        .and_then(|t| serde_json::from_str::<PriseEnCharge>(t.trim_start_matches('\u{feff}')).ok())
        .map(|p| p.faite)
}

fn ecrire_marqueur(faite: bool) -> Result<(), String> {
    commun::ecrire(MARQUEUR, &PriseEnCharge { faite, version: commun::VERSION.into(), date: commun::maintenant() })
}

/// Contenu de la racine, une fois ses droits posés par handle (prendre_racine)
fn imposer(racine: &Path, messages: &mut Vec<String>) -> Result<(), String> {
    // Première prise en charge (C-2) : décidée et notée AVANT le tri (marqueur « à faire »), pour qu'un démarrage
    // interrompu la reprenne au lieu de prendre ce que la surveillance a écrit entre-temps pour la preuve d'une version
    // précédente
    let marqueur = lire_marqueur(racine);
    let premiere = premiere_prise_en_charge(marqueur, commun::lire_fichier_proprietaire(&racine.join("etat.json")).is_some());
    let mut marque = Ok(());
    if marqueur.is_none() {
        marque = ecrire_marqueur(!premiere);
    }
    let tous_a_ecarter = |_: &Path| Some(false);
    let de_confiance: &dyn Fn(&Path) -> Option<bool> = if premiere { &tous_a_ecarter } else { &crate::natif::proprietaire_de_confiance };
    let quarantaine = racine.join("ecartes");
    let proprietaire: &dyn Fn(&Path) -> Option<bool> = &crate::natif::proprietaire_de_confiance;
    preparer_quarantaine_avec(&quarantaine, if ecartes_juge_au_proprietaire(premiere, marqueur) { proprietaire } else { de_confiance })?;
    if premiere {
        messages.push("première prise en charge de ce dossier : tout son contenu, quel qu'en soit le propriétaire, est mis de côté dans ecartes".into());
    } else {
        // Quarantaine : reprise des transactions interrompues, puis copies d'avant la 4.3 (propriétaire de
        // l'utilisateur) recopiées avec leurs droits avant le tri, qui sinon les écarterait (restauration impossible)
        messages.extend(crate::reponse::reprendre_et_migrer_quarantaine_service());
    }
    let mut ecartes = Vec::new();
    trier_avec(racine, racine, &quarantaine, &mut ecartes, de_confiance);
    if !ecartes.is_empty() {
        messages.push(format!("{} élément(s) d'un autre propriétaire, à plusieurs liens physiques ou lien(s) écarté(s) vers ecartes : {}", ecartes.len(),
            ecartes.iter().take(20).cloned().collect::<Vec<_>>().join(", ")));
    }
    if ecartes.iter().any(|e| e.contains("IMPOSSIBLE")) {
        return Err("un élément d'un autre propriétaire n'a pas pu être écarté".into());
    }
    marque.map_err(|e| format!("marqueur de prise en charge non écrit ({e})"))?;
    if premiere {
        ecrire_marqueur(true).map_err(|e| format!("marqueur de prise en charge non écrit ({e})"))?;
    }
    // Tout ce qui reste appartient à SYSTEM ou aux administrateurs (vérifié par trier). Contenu : droits
    // hérités du dossier, sauf ce qui a reçu ses propres droits à la création (DACL protégée et propriétaire
    // de confiance : jeton, secrets, copies de quarantaine, dossiers de repli). Avec /C, icacls rend 0 même en
    // cas d'échec : son code n'est pas une preuve, seules les relectures de droits en sont une
    reinitialiser_contenu(racine, &proprietaire_acceptable);
    crate::notifications::preparer_dossier()?;
    crate::api::proteger_jeton()?;
    appliquer(&lecteurs())
}

/// Désinstallation sans GARDER_DONNEES (lot A, point 4 accordé le 2026-11-23) : le contenu du dossier de données est
/// supprimé, mais la racine est GARDÉE, vide, à SYSTEM et aux administrateurs (propriétaire Administrateurs, héritage
/// coupé, sans les comptes lecteurs) : un compte standard ne peut ni la supprimer ni y poser une jonction entre la
/// désinstallation et une réinstallation (essai en VM du 2026-11-23 : après une désinstallation qui l'effaçait, une
/// jonction posée à sa place recevait les écritures du service réinstallé). Une racine qui est un lien est supprimée
/// (le lien seul, jamais sa cible) puis recréée vide et protégée ; une racine d'un autre propriétaire n'est pas
/// touchée (le service la mettra de côté). Rien n'est suivi : chaque élément est supprimé sans traverser de lien.
/// Plusieurs essais (un fichier peut rester ouvert quelques instants après l'arrêt du service). Exception (audit du
/// 2026-11-23, A-4-3) : une quarantaine non vide est gardée, réservée à SYSTEM et aux administrateurs
/// (garder_la_quarantaine). Ok : compte rendu (texte_desinstallation) et vrai s'il doit être écrit hors de la sortie
/// (quarantaine gardée, ou supprimée faute de droits vérifiés)
pub fn vider_racine() -> Result<(String, bool), String> {
    let racine = commun::dossier();
    if let Ok(m) = fs::symlink_metadata(racine) {
        if est_lien(&m) {
            supprimer_lien(racine);
            if fs::symlink_metadata(racine).is_ok() {
                return Err(format!("{} est un lien impossible à supprimer : rien n'est supprimé sous lui", racine.display()));
            }
        }
    }
    if fs::symlink_metadata(racine).is_err() && !crate::natif::creer_dossier_protege(racine, SDDL_DOSSIER) {
        return Err(format!("{} : racine vide et protégée impossible à créer", racine.display()));
    }
    let f = ouvrir_racine()?;
    let s = crate::natif::lire_securite_handle(&f).ok_or_else(|| format!("droits de {} illisibles", racine.display()))?;
    if !proprietaire_acceptable(&s.proprietaire) {
        return Err(format!("{} appartient à {} : contenu laissé (le service le mettra de côté)", racine.display(), s.proprietaire));
    }
    // Droits de la racine gardée, par le handle : SYSTEM et administrateurs seulement
    crate::natif::poser_droits_handle(&f, SDDL_DOSSIER).map_err(|e| format!("droits de la racine gardée refusés ({e})"))?;
    drop(f);
    // Quarantaine (audit du 2026-11-23, A-4-3) : gardée si elle contient au moins une copie et que tout ce qui est gardé
    // est vérifié réservé à SYSTEM et aux administrateurs ; sinon supprimée avec le reste (échec fermé)
    let garde = garder_la_quarantaine(racine);
    let gardee = matches!(garde, Ok(n) if n > 0);
    let mut restes = Vec::new();
    for essai in 0..10 {
        restes = vider_contenu(racine, &|nom| garde_a_la_racine(nom, gardee));
        if restes.is_empty() {
            break;
        }
        if essai < 9 {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    if !restes.is_empty() {
        return Err(format!("suppression du contenu de {} incomplète : {}", racine.display(), restes.into_iter().take(10).collect::<Vec<_>>().join(" ; ")));
    }
    Ok((texte_desinstallation(&racine.display().to_string(), &garde), garde != Ok(0)))
}

/// Décision pure (audit du 2026-11-23, A-4-3) : élément gardé à la désinstallation réservé à SYSTEM et aux
/// administrateurs ? Propriétaire acceptable, aucune entrée de type inconnu, aucune autorisation (même en lecture) pour
/// un autre compte ; une DACL absente (accès total pour tout le monde) ne passe pas
pub fn reserve_systeme_admins(s: &crate::natif::Securite) -> bool {
    proprietaire_acceptable(&s.proprietaire) && !s.ace_inconnue && s.aces.iter().filter(|a| a.autorise).all(|a| proprietaire_acceptable(&a.sid))
}

/// Décision pure (A-4-3) : un élément de quarantaine\ est-il une copie à garder ? Fichier ordinaire, pas un lien, un seul
/// lien physique (lu). Le reste (lien, dossier, fichier à plusieurs liens) n'a pas été écrit par le service : supprimé
/// sans rien traverser
pub fn copie_a_garder(lien: bool, fichier: bool, liens: Option<u32>) -> bool {
    !lien && fichier && liens == Some(1)
}

/// Décision pure (A-4-3) : nom de la racine épargné par la suppression ? Seulement quand la quarantaine est gardée : le
/// dossier quarantaine, son index, et le marqueur de prise en charge (sans lui, une réinstallation verrait une première
/// prise en charge et mettrait la quarantaine de côté dans ecartes, hors de la page Quarantaine)
pub fn garde_a_la_racine(nom: &str, quarantaine_gardee: bool) -> bool {
    quarantaine_gardee && ["quarantaine", "quarantaine.json", MARQUEUR].iter().any(|n| nom.eq_ignore_ascii_case(n))
}

/// Compte rendu de la suppression des données (pur, testé) : `garde` vaut le nombre de copies gardées, ou la raison pour
/// laquelle la quarantaine n'a pas pu l'être
pub fn texte_desinstallation(racine: &str, garde: &Result<usize, String>) -> String {
    match garde {
        Ok(0) => format!("Données supprimées ; racine {racine} gardée, vide, réservée à SYSTEM et aux administrateurs"),
        Ok(n) => format!("Données supprimées, SAUF la quarantaine : {n} copie(s) gardée(s) dans {racine}\\quarantaine avec leur index \
            {racine}\\quarantaine.json, réservées à SYSTEM et aux administrateurs (contenu encodé, jamais exécutable tel quel). Restaurer : \
            réinstaller deR4Tizer (page Quarantaine). Supprimer : dans une invite de commandes d'administrateur, rmdir /s /q \"{racine}\\quarantaine\" \
            puis del \"{racine}\\quarantaine.json\" \"{racine}\\{MARQUEUR}\". Racine {racine} gardée, réservée à SYSTEM et aux administrateurs"),
        Err(e) => format!("Données supprimées, quarantaine COMPRISE : ses droits n'ont pas pu être vérifiés réservés à SYSTEM et aux \
            administrateurs ({e}) ; racine {racine} gardée, vide, réservée à SYSTEM et aux administrateurs"),
    }
}

/// Droits réservés à SYSTEM et aux administrateurs sur un élément gardé, par son handle (ouvert sans suivre de lien,
/// chemin final vérifié) : relus, posés (`sddl`) s'ils ne le sont pas, puis relus. Err : non vérifiables
fn reserver(p: &Path, dossier: bool, sddl: &str) -> Result<(), String> {
    let f = crate::natif::ouvrir_verifie(p, ACCES_RACINE, 0x7, dossier).map_err(|e| format!("{} non ouvert sans lien ({e})", p.display()))?;
    if crate::natif::lire_securite_handle(&f).is_some_and(|s| reserve_systeme_admins(&s)) {
        return Ok(());
    }
    crate::natif::poser_droits_handle(&f, sddl).map_err(|e| format!("{} : droits refusés ({e})", p.display()))?;
    match crate::natif::lire_securite_handle(&f) {
        Some(s) if reserve_systeme_admins(&s) => Ok(()),
        _ => Err(format!("{} : droits relus non réservés à SYSTEM et aux administrateurs", p.display())),
    }
}

/// Fichier gardé à la racine (index, marqueur) : absent, ou fichier ordinaire à un seul lien physique, réservé
fn reserver_fichier_racine(p: &Path) -> Result<(), String> {
    let Ok(m) = fs::symlink_metadata(p) else { return Ok(()) };
    let liens = crate::natif::nombre_de_liens_chemin(p);
    if !copie_a_garder(est_lien(&m), m.is_file(), liens) {
        return Err(format!("{} n'est pas un fichier ordinaire à un seul lien physique", p.display()));
    }
    reserver(p, false, crate::reponse::SDDL_QUARANTAINE)
}

/// Désinstallation (A-4-3) : prépare la quarantaine à garder et rend le nombre de copies gardées (0 : rien à garder).
/// Sans rien suivre : liens, dossiers et fichiers à plusieurs liens physiques de quarantaine\ supprimés ; chaque copie,
/// le dossier, l'index et le marqueur vérifiés réservés à SYSTEM et aux administrateurs (posés par handle au besoin).
/// Err : quelque chose n'a pas pu l'être, la quarantaine part avec le reste
fn garder_la_quarantaine(racine: &Path) -> Result<usize, String> {
    let q = racine.join("quarantaine");
    let Ok(m) = fs::symlink_metadata(&q) else { return Ok(0) };
    if est_lien(&m) || !m.is_dir() {
        return Ok(0);
    }
    reserver(&q, true, SDDL_DOSSIER)?;
    let lecture = fs::read_dir(&q).map_err(|e| format!("contenu de {} illisible ({e})", q.display()))?;
    let mut copies = 0;
    for e in lecture {
        let p = e.map_err(|e| format!("élément de {} illisible ({e})", q.display()))?.path();
        let m = fs::symlink_metadata(&p).map_err(|e| format!("{} non inspectable ({e})", p.display()))?;
        let liens = if m.is_file() && !est_lien(&m) { crate::natif::nombre_de_liens_chemin(&p) } else { None };
        if copie_a_garder(est_lien(&m), m.is_file(), liens) {
            reserver(&p, false, crate::reponse::SDDL_QUARANTAINE)?;
            copies += 1;
        } else {
            let r = if est_lien(&m) { fs::remove_dir(&p).or_else(|_| fs::remove_file(&p)) } else if m.is_dir() { fs::remove_dir_all(&p) } else { fs::remove_file(&p) };
            r.map_err(|e| format!("{} : suppression impossible ({e})", p.display()))?;
        }
    }
    if copies == 0 {
        return Ok(0);
    }
    reserver_fichier_racine(&racine.join("quarantaine.json"))?;
    reserver_fichier_racine(&racine.join(MARQUEUR))?;
    Ok(copies)
}

/// Supprime chaque élément de `dossier` sans traverser de lien (un lien est supprimé seul ; remove_dir_all ne suit pas
/// les jonctions), sauf ceux dont le nom est épargné (`epargne`, quarantaine gardée : A-4-3) ; renvoie les éléments
/// restés, avec l'erreur
pub fn vider_contenu(dossier: &Path, epargne: &dyn Fn(&str) -> bool) -> Vec<String> {
    let lecture = match fs::read_dir(dossier) {
        Ok(l) => l,
        Err(e) => return vec![format!("contenu illisible ({e})")],
    };
    let mut restes = Vec::new();
    for e in lecture {
        let p = match e {
            Ok(e) => e.path(),
            Err(err) => {
                restes.push(format!("élément illisible ({err})"));
                continue;
            }
        };
        if p.file_name().is_some_and(|n| epargne(&n.to_string_lossy())) {
            continue;
        }
        let r = match fs::symlink_metadata(&p) {
            Ok(m) if est_lien(&m) => fs::remove_dir(&p).or_else(|_| fs::remove_file(&p)),
            Ok(m) if m.is_dir() => fs::remove_dir_all(&p),
            Ok(_) => fs::remove_file(&p),
            Err(e) => Err(e),
        };
        if let Err(err) = r {
            if err.kind() != std::io::ErrorKind::NotFound {
                restes.push(format!("{} ({err})", p.display()));
            }
        }
    }
    restes
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
    appliquer(&l).map_err(|e| format!("pose des droits refusée par Windows ({e})"))?;
    commun::journal(&format!("protection des données : accès en lecture accordé à {}", if nom.is_empty() { sid } else { &nom }));
    Ok(if nom.is_empty() { sid.into() } else { nom })
}

pub fn demarrer(alertes: std::sync::Arc<std::sync::Mutex<Vec<commun::Alerte>>>) {
    std::thread::Builder::new().name("protection".into()).spawn(move || {
        // Dossier d'installation (A-4-1) : relu une fois au démarrage, alerte critique locale s'il est modifiable par un autre compte
        if let Err(e) = verifier_installation() {
            commun::journal(&format!("dossier d'installation non conforme : {e} ; mise à jour automatique refusée"));
            alertes.lock().unwrap().push(alerte_installation(&e));
        }
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
            // Par le handle de la racine (C-1) ; une racine qui ne s'ouvre plus sans lien arrête toute écriture dessous
            let resultat = appliquer(&l);
            commun::definir_racine_verifiee(resultat.is_ok());
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
