//! Protection contre les voleurs de données (« infostealers ») : mots de passe et cookies des
//! navigateurs, jetons Discord, session Telegram, portefeuilles crypto.
//! Le service pose un audit de lecture (SACL) sur ces fichiers ; Windows écrit alors un événement 4663
//! à chaque ouverture. On alerte quand le programme qui les ouvre n'est pas leur propriétaire légitime.
//! Nécessite l'audit « Système de fichiers » (profil de baseline « journalisation »).

use crate::commun::{self, Alerte};
use crate::evenements;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Cible surveillée : dossier relatif au profil, héritage aux sous-dossiers, propriétaires légitimes
pub struct Cible {
    pub nom: &'static str,
    pub relatif: &'static str,
    pub recursif: bool,
    pub proprietaires: &'static [&'static str],
}

pub const CIBLES: &[Cible] = &[
    Cible { nom: "mots de passe et état de Chrome", relatif: r"AppData\Local\Google\Chrome\User Data", recursif: false, proprietaires: &["chrome"] },
    Cible { nom: "mots de passe de Chrome", relatif: r"AppData\Local\Google\Chrome\User Data\Default", recursif: false, proprietaires: &["chrome"] },
    Cible { nom: "cookies de Chrome", relatif: r"AppData\Local\Google\Chrome\User Data\Default\Network", recursif: false, proprietaires: &["chrome"] },
    Cible { nom: "mots de passe et état de Brave", relatif: r"AppData\Local\BraveSoftware\Brave-Browser\User Data", recursif: false, proprietaires: &["brave"] },
    Cible { nom: "mots de passe de Brave", relatif: r"AppData\Local\BraveSoftware\Brave-Browser\User Data\Default", recursif: false, proprietaires: &["brave"] },
    Cible { nom: "cookies de Brave", relatif: r"AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Network", recursif: false, proprietaires: &["brave"] },
    Cible { nom: "mots de passe et état d'Edge", relatif: r"AppData\Local\Microsoft\Edge\User Data", recursif: false, proprietaires: &["msedge", "msedgewebview2"] },
    Cible { nom: "mots de passe d'Edge", relatif: r"AppData\Local\Microsoft\Edge\User Data\Default", recursif: false, proprietaires: &["msedge", "msedgewebview2"] },
    Cible { nom: "cookies d'Edge", relatif: r"AppData\Local\Microsoft\Edge\User Data\Default\Network", recursif: false, proprietaires: &["msedge", "msedgewebview2"] },
    Cible { nom: "profils Firefox (mots de passe, cookies)", relatif: r"AppData\Roaming\Mozilla\Firefox\Profiles", recursif: true, proprietaires: &["firefox", "plugin-container", "crashreporter"] },
    Cible { nom: "jeton de session Discord", relatif: r"AppData\Roaming\discord\Local Storage\leveldb", recursif: false, proprietaires: &["discord", "update"] },
    Cible { nom: "session Telegram", relatif: r"AppData\Roaming\Telegram Desktop\tdata", recursif: false, proprietaires: &["telegram", "updater"] },
    Cible { nom: "portefeuille Ledger", relatif: r"AppData\Roaming\Ledger Live", recursif: false, proprietaires: &["ledger live", "ledger wallet"] },
    Cible { nom: "portefeuille Exodus", relatif: r"AppData\Roaming\Exodus\exodus.wallet", recursif: true, proprietaires: &["exodus"] },
    Cible { nom: "portefeuille Electrum", relatif: r"AppData\Roaming\Electrum\wallets", recursif: false, proprietaires: &["electrum"] },
    Cible { nom: "extension MetaMask (Chrome)", relatif: r"AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn", recursif: false, proprietaires: &["chrome"] },
    Cible { nom: "extension MetaMask (Brave)", relatif: r"AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn", recursif: false, proprietaires: &["brave"] },
];

/// Éditeur attendu de chaque propriétaire légitime : nom EXACT du signataire Authenticode (comparaison sans
/// casse ni ponctuation). Un « chrome.exe » posé dans %TEMP% n'est pas signé « Google LLC » ; un certificat
/// « Brave Heart SARL » ne passe pas pour Brave. Noms relevés sur les logiciels installés.
const GOOGLE: &[&str] = &["Google LLC"];
const MICROSOFT: &[&str] = &["Microsoft Corporation", "Microsoft Windows", "Microsoft Windows Publisher"];
const EDITEURS: &[(&str, &[&str])] = &[
    ("chrome", GOOGLE), ("brave", &["Brave Software, Inc."]), ("msedge", MICROSOFT), ("msedgewebview2", MICROSOFT),
    ("firefox", &["Mozilla Corporation"]), ("plugin-container", &["Mozilla Corporation"]), ("crashreporter", &["Mozilla Corporation"]),
    ("discord", &["Discord Inc."]), ("update", &["Discord Inc."]), ("telegram", &["Telegram FZ-LLC"]), ("updater", &["Telegram FZ-LLC"]),
    ("ledger live", &["Ledger SAS"]), ("ledger wallet", &["Ledger SAS"]), ("exodus", &["Exodus Movement, Inc."]),
];

/// Programmes de Windows et de Microsoft qui ouvrent légitimement tous les fichiers (antivirus, indexation,
/// synchronisation) : binaire Windows vérifié (dossier Windows et signature) ou signé par Microsoft
const TOUJOURS_AUTORISES: &[&str] = &[
    "msmpeng", "mpdefendercoreservice", "mssense", "searchprotocolhost", "searchindexer", "onedrive", "filecoauth",
    "backgroundtaskhost", "svchost",
];

/// Logiciels qui lisent, copient ou synchronisent tous les fichiers et peuvent toucher un leurre sans être un
/// rançongiciel : (début du nom de l'exécutable, signataires exacts acceptés). Le couple est vérifié.
const LEURRES_AUTORISES: &[(&str, &[&str])] = &[
    // antivirus, indexation et sauvegarde de Windows
    ("msmpeng", MICROSOFT), ("mpdefendercoreservice", MICROSOFT), ("mssense", MICROSOFT), ("searchindexer", MICROSOFT),
    ("searchprotocolhost", MICROSOFT), ("searchfilterhost", MICROSOFT), ("wbengine", MICROSOFT), ("sdclt", MICROSOFT),
    ("vssvc", MICROSOFT), ("filehistory", MICROSOFT), ("onedrive", MICROSOFT), ("filecoauth", MICROSOFT),
    // synchronisation
    ("dropbox", &["Dropbox, Inc"]), ("googledrivefs", GOOGLE), ("nextcloud", &["Nextcloud GmbH"]), ("owncloud", &["ownCloud GmbH"]),
    ("synologydrive", &["Synology Inc."]), ("icloud", &["Apple Inc."]), ("megasync", &["Mega Limited"]), ("boxsync", &["Box, Inc."]),
    ("box", &["Box, Inc."]),
    // sauvegarde
    ("veeam", &["Veeam Software Group GmbH"]), ("acronis", &["Acronis International GmbH"]), ("trueimage", &["Acronis International GmbH"]),
    ("anti_ransomware_service", &["Acronis International GmbH"]), ("mmscmd", &["Acronis International GmbH"]),
    ("reflect", &["Paramount Software UK Ltd"]), ("macrium", &["Paramount Software UK Ltd"]), ("bztransmit", &["Backblaze, Inc."]),
    ("bzfilelist", &["Backblaze, Inc."]), ("idrive", &["IDrive Inc."]), ("carbonite", &["Carbonite, Inc.", "Open Text Corporation"]),
    ("urbackup", &["Infscape UG (haftungsbeschränkt)"]), ("arq", &["Haystack Software LLC"]), ("crashplan", &["Code42 Software, Inc."]),
    ("code42", &["Code42 Software, Inc."]),
];

/// Nom de signataire normalisé : sans casse, sans ponctuation, espaces simples
fn normaliser(nom: &str) -> String {
    nom.to_lowercase().chars().filter(|c| c.is_alphanumeric() || c.is_whitespace()).collect::<String>()
        .split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Le signataire est exactement l'un des éditeurs attendus
pub fn editeur_correspond(signataire: &str, attendus: &[&str]) -> bool {
    let s = normaliser(signataire);
    !s.is_empty() && attendus.iter().any(|a| normaliser(a) == s)
}

/// Signataire d'un exécutable, mis en cache par chemin et date de modification
fn signataire(chemin: &str) -> Option<String> {
    use std::sync::OnceLock;
    static CACHE: OnceLock<Mutex<HashMap<String, Option<String>>>> = OnceLock::new();
    let date = std::fs::metadata(chemin).and_then(|m| m.modified()).map(commun::filetime).unwrap_or(0);
    let cle = format!("{chemin}|{date}");
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(s) = cache.lock().unwrap().get(&cle) {
        return s.clone();
    }
    // Hors délai : pas de cache (relecture de #104, D2)
    let Ok(s) = crate::natif::signataire_a_echeance(chemin) else { return None };
    let mut c = cache.lock().unwrap();
    if c.len() > 2000 {
        c.clear();
    }
    c.insert(cle, s.clone());
    s
}

fn signe_par(chemin: &str, editeurs: &[&str]) -> bool {
    if std::ptr::eq(editeurs, MICROSOFT) && crate::natif::binaire_windows(chemin) {
        return true;
    }
    signataire(chemin).map(|s| editeur_correspond(&s, editeurs)).unwrap_or(false)
}

/// Programme autorisé à lire ces données : bon nom ET bon éditeur (ou binaire Windows vérifié)
fn legitime(exe: &str, chemin: &str, proprietaires: &[&str]) -> bool {
    if chemin.is_empty() {
        return false;
    }
    if std::env::current_exe().map(|p| p.to_string_lossy().eq_ignore_ascii_case(chemin)).unwrap_or(false) {
        return true;
    }
    if proprietaires.contains(&exe) {
        return EDITEURS.iter().any(|(n, e)| *n == exe && signe_par(chemin, e));
    }
    TOUJOURS_AUTORISES.contains(&exe) && signe_par(chemin, MICROSOFT)
}

/// Logiciel connu (couple nom et éditeur vérifié) qui peut toucher un leurre sans être un rançongiciel
pub fn leurre_autorise(chemin: &str) -> bool {
    let exe = Path::new(chemin).file_stem().map(|s| s.to_string_lossy().to_lowercase()).unwrap_or_default();
    LEURRES_AUTORISES.iter().any(|(n, e)| exe.starts_with(n) && signe_par(chemin, e))
}

/// Dossiers réellement présents sur ce PC : (chemin complet, cible)
pub fn dossiers_presents() -> Vec<(String, &'static Cible)> {
    let systeme = crate::natif::dossier_windows();
    let utilisateurs = format!(r"{}\Users", &systeme[..2]);
    let mut l = Vec::new();
    let Ok(profils) = std::fs::read_dir(&utilisateurs) else { return l };
    for p in profils.map_while(Result::ok) {
        for c in CIBLES {
            let d = p.path().join(c.relatif);
            // Ouvert sans suivre de lien, chemin final vérifié (is_dir suivrait une jonction posée par l'utilisateur)
            if crate::natif::ouvrir_verifie(&d, 0x80, 0x7, true).is_ok() {
                l.push((d.to_string_lossy().to_string(), c));
            }
        }
    }
    l
}

/// Audit de lecture : sur le dossier, entrée héritée par ses fichiers (InheritOnly : le parcourir n'est pas lire une
/// donnée, et produirait des milliers d'événements) ; NoPropagateInherit si la cible n'est pas récursive (ses
/// fichiers seulement, pas les sous-dossiers)
fn sddl_audit_dossier(recursif: bool) -> &'static str {
    if recursif { "S:(AU;OICIIOSA;0x1;;;WD)" } else { "S:(AU;OINPIOSA;0x1;;;WD)" }
}

/// Audit de lecture sur un fichier déjà présent (les nouveaux héritent de l'entrée du dossier)
const SDDL_AUDIT_FICHIER: &str = "S:(AU;SA;0x1;;;WD)";

/// Éléments parcourus au plus par dossier (profil de navigateur) et par passage
const MAXIMUM_PAR_DOSSIER: usize = 20_000;

/// Pose (ou repose) l'audit de lecture sur les dossiers. En SYSTEM dans les profils des utilisateurs : tout par
/// handle (natif::poser_audit_arborescence), jamais par chemin ni par PowerShell : une jonction posée par
/// l'utilisateur à la place d'un dossier de son profil ne fait rien écrire ailleurs, et seule la SACL est écrite
/// (Set-Acl réécrivait le descripteur complet, DACL comprise).
/// Pose l'audit sur chaque dossier présent ; rend (dossiers audités, dossiers en échec)
pub fn poser_audit() -> (usize, usize) {
    let (mut n, mut echecs) = (0, 0);
    for (d, c) in dossiers_presents() {
        match crate::natif::poser_audit_arborescence(Path::new(&d), sddl_audit_dossier(c.recursif), SDDL_AUDIT_FICHIER, c.recursif, MAXIMUM_PAR_DOSSIER) {
            Ok(b) => {
                n += 1;
                if b.ecartes > 0 || b.tronque {
                    commun::journal(&format!("audit des données sensibles : {d} : {} élément(s) écarté(s) (liens ou chemins détournés, jamais suivis){}",
                        b.ecartes, if b.tronque { " ; parcours arrêté au nombre maximal d'éléments" } else { "" }));
                }
            }
            Err(e) => {
                echecs += 1;
                commun::journal(&format!("audit des données sensibles : erreur : {d} : {e}"));
            }
        }
    }
    (n, echecs)
}

/// Analyse un événement 4663 : renvoie une alerte si un programme inattendu lit des données sensibles
pub fn analyser(xml: &str, dossiers: &[(String, &'static Cible)]) -> Option<Alerte> {
    let d = evenements::donnees(xml);
    let objet = d.get("ObjectName")?.to_lowercase();
    let processus = d.get("ProcessName").cloned().unwrap_or_default();
    let exe = Path::new(&processus).file_stem().map(|s| s.to_string_lossy().to_lowercase()).unwrap_or_default();
    // Le dossier surveillé le plus précis qui contient le fichier (Default plutôt que User Data)
    let (_, cible) = dossiers
        .iter()
        .filter(|(dossier, _)| objet.starts_with(&format!("{}\\", dossier.to_lowercase())))
        .max_by_key(|(dossier, _)| dossier.len())?;
    if legitime(&exe, &processus, cible.proprietaires) {
        return None;
    }
    // Seule la lecture d'un fichier compte : parcourir un dossier du profil (inventaire des extensions,
    // pose de l'audit par deR4Tizer, détection des navigateurs installés…) ne lit aucune donnée
    if Path::new(d.get("ObjectName")?).is_dir() {
        return None;
    }
    let suspect = processus.to_lowercase().contains(r"\temp\") || processus.to_lowercase().contains(r"\downloads\")
        || processus.to_lowercase().contains(r"\users\public\");
    Some(Alerte {
        regle: crate::regles::VOL_001.into(),
        id: commun::nouvel_id(),
        heure: commun::maintenant(),
        niveau: if suspect { "Critique" } else { "Alerte" }.into(),
        score: if suspect { 10 } else { 7 },
        processus: Path::new(&processus).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default(),
        chemin: processus.clone(),
        destination: cible.nom.into(),
        raisons: format!(
            "accès aux {} par un autre programme que {} : comportement typique d'un VOLEUR DE DONNÉES (fichier {})  [MITRE T1555 / T1539]",
            cible.nom,
            cible.proprietaires.join(" ou "),
            d.get("ObjectName").cloned().unwrap_or_default()
        ),
        pid: d.get("ProcessId").and_then(|p| u32::from_str_radix(p.trim_start_matches("0x"), 16).ok()),
        ..Default::default()
    })
}

/// Démarre la surveillance : audit posé au démarrage puis toutes les heures, abonnement aux 4663
pub fn surveiller(file: Arc<Mutex<Vec<Alerte>>>) {
    let dossiers = Arc::new(Mutex::new(dossiers_presents()));
    {
        let dossiers = dossiers.clone();
        let _ = std::thread::Builder::new().name("audit données sensibles".into()).spawn(move || loop {
            let (n, echecs) = poser_audit();
            commun::journal(&format!("audit de lecture posé sur {n} dossier(s) de données sensibles{}", if echecs > 0 { format!(", {echecs} en échec") } else { String::new() }));
            let utilisateurs = format!(r"{}\Users", crate::natif::dossier_windows().get(..2).unwrap_or("C:"));
            if std::fs::read_dir(&utilisateurs).is_err() {
                // Aucun dossier trouvé parce que les profils sont illisibles : pas « rien à auditer »
                crate::collectes::echec(crate::collectes::Collecte::AuditDonnees, "dossier des profils illisible");
            } else {
                crate::collectes::noter_comptes(crate::collectes::Collecte::AuditDonnees, n, echecs, "dossiers de données sensibles");
            }
            *dossiers.lock().unwrap() = dossiers_presents();
            std::thread::sleep(Duration::from_secs(3600));
        });
    }
    let mut vues: HashMap<String, Instant> = HashMap::new();
    evenements::abonner("Security", "*[System[EventID=4663]]", crate::collectes::Collecte::JournalSecurite, move |xml| {
        // Fichier leurre modifié ou supprimé : rançongiciel probable, on suspend aussitôt le programme
        if let Some((pid, programme, objet)) = crate::hygiene::pid_touchant_leurre(&xml) {
            let connu = leurre_autorise(&programme);
            // Sauvegarde, synchronisation, antivirus, indexation : noté sans rien suspendre. Sinon, rundll32,
            // regsvr32, mshta, powershell… sont des binaires Windows par lesquels passent beaucoup de rançongiciels :
            // ils sont suspendus. Seuls les processus critiques (csrss, lsass, svchost…) sont protégés, par
            // reponse::protege()
            let tentee = !connu && {
                let config: commun::Config = commun::lire("config.json").unwrap_or_default();
                suspendre_leurre(config.reponse_auto_rancongiciel, false, crate::reponse::protege(pid).is_some())
            };
            let (suspendu, retenue) = if tentee { suspension_leurre(pid, &programme, &file) } else { (false, None) };
            // Suspension automatique dans le SIEM, pour la chronologie (relecture de #94, D1)
            if tentee {
                let message = match &retenue {
                    Some(r) => format!("retenue : {r}"),
                    None if suspendu => "programme suspendu".to_string(),
                    None => "suspension en échec".to_string(),
                };
                crate::siem::reponse("suspendre", &pid.to_string(), suspendu, &message, &format!("automatique : leurre touché par {programme}"));
            }
            let mut alerte = alerte_leurre_touche(pid, &programme, &objet, connu, suspendu);
            if let Some(r) = retenue {
                alerte.raisons.push_str(&format!(" — suspension automatique retenue ({r}), programme toujours actif : vérifiez-le et arrêtez-le sans attendre si besoin"));
            }
            file.lock().unwrap().push(alerte);
            return;
        }
        let Some(a) = analyser(&xml, &dossiers.lock().unwrap()) else { return };
        // Une alerte par programme et par cible toutes les 24 h
        if premiere_en_24h(&mut vues, format!("{}|{}", a.chemin, a.destination), Instant::now()) {
            file.lock().unwrap().push(a);
        }
    });
}

/// La politique et la garde pour un programme qui touche un leurre : (suspendu, raison de la retenue). Hors du cycle : la
/// suspension n'attend pas le moniteur
fn suspension_leurre(pid: u32, programme: &str, file: &Mutex<Vec<Alerte>>) -> (bool, Option<String>) {
    use crate::politique::{self, Action, Contexte, Decision, Declencheur, Genre, Passage, SourceAuto};
    let contexte = Contexte { echec_protection: commun::echec_protection().is_some(), rancongiciel: true, ..Default::default() };
    match politique::decider(Action::Suspendre, Declencheur::Automatique(SourceAuto::Leurre), &contexte) {
        Decision::Autorisee(a) => match politique::passer(Genre::Suspension, programme, &mut || crate::natif::empreinte_a_echeance(programme).ok().flatten()) {
            Passage::Passe => {
                let suspendu = crate::execution::suspendre(&a, pid, true).is_ok();
                if suspendu {
                    politique::noter(Genre::Suspension, programme);
                }
                (suspendu, None)
            }
            Passage::Retenue { raison, alerte } => {
                if let Some(t) = alerte {
                    file.lock().unwrap().push(politique::alerte_garde(&t));
                }
                (false, Some(raison))
            }
        },
        Decision::Refusee(r) | Decision::AlerteSeulement(r) => (false, Some(r)),
    }
}

/// Décision pure (testée, LEU-002) : alerte d'un leurre touché. Logiciel connu et signé (sauvegarde, synchronisation,
/// antivirus) : Info, non suspendu ; sinon Critique, rançongiciel probable, avec la suspension si elle a eu lieu
pub(crate) fn alerte_leurre_touche(pid: u32, programme: &str, objet: &str, connu: bool, suspendu: bool) -> Alerte {
    let processus = Path::new(programme).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    if connu {
        return Alerte {
            regle: crate::regles::LEU_002.into(),
            id: commun::nouvel_id(),
            heure: commun::maintenant(),
            niveau: "Info".into(),
            processus,
            chemin: programme.into(),
            destination: "leurre anti-rançongiciel".into(),
            raisons: format!("{programme} (logiciel connu et signé : sauvegarde, synchronisation ou antivirus) a touché le fichier leurre {objet} — non suspendu"),
            pid: Some(pid),
            ..Default::default()
        };
    }
    Alerte {
        regle: crate::regles::LEU_002.into(),
        id: commun::nouvel_id(),
        heure: commun::maintenant(),
        niveau: "Critique".into(),
        score: 15,
        processus,
        chemin: programme.into(),
        destination: "leurre anti-rançongiciel".into(),
        raisons: format!("{programme} a modifié ou supprimé le fichier leurre {objet} : RANÇONGICIEL PROBABLE{}",
            if suspendu { " — programme SUSPENDU automatiquement (vérifiez puis tuez-le ou reprenez-le)" } else { "" }),
        pid: Some(pid),
        ..Default::default()
    }
}

/// Décision pure (testée, VOL-001) : une alerte par programme et par cible toutes les 24 h ; note l'heure si elle part
pub(crate) fn premiere_en_24h(vues: &mut HashMap<String, Instant>, cle: String, maintenant: Instant) -> bool {
    if vues.get(&cle).is_some_and(|t| maintenant.saturating_duration_since(*t) < Duration::from_secs(86400)) {
        return false;
    }
    vues.insert(cle, maintenant);
    true
}

/// Décision sur un programme qui a touché un leurre : suspendre seulement en réponse automatique, si ce n'est ni
/// un logiciel connu (sauvegarde, synchronisation, antivirus) ni un processus critique de Windows
pub fn suspendre_leurre(reponse_auto: bool, logiciel_connu: bool, critique: bool) -> bool {
    reponse_auto && !logiciel_connu && !critique
}
