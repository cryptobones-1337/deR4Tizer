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
/// rançongiciel : (nom exact de l'exécutable, sans extension, signataires exacts acceptés). Le couple est vérifié. Décision du
/// mainteneur, 2026-11-02 : nom exact, pas de début de nom. Noms relevés de mémoire, non vérifiés sur de vraies installations :
/// un exécutable oublié est suspendu s'il touche un leurre, jusqu'à une reprise par un administrateur.
/// Depuis le 2026-11-21 (S110-14), « connu » exige aussi SYSTEM ou un administrateur élevé : les clients de
/// synchronisation qui tournent sous le compte de l'utilisateur (OneDrive, FileCoAuth, Dropbox, Google Drive, Nextcloud,
/// ownCloud, Synology Drive, iCloud, MEGA, Box) ne pouvaient plus jamais l'être et sont retirés de la liste (revue
/// externe du 2026-11-21, défaut 3) : ils sont suspendus s'ils touchent un leurre, comme le dit le README. Restent les
/// services (SYSTEM) et les outils de sauvegarde qui demandent l'élévation
const LEURRES_AUTORISES: &[(&str, &[&str])] = &[
    // antivirus, indexation et sauvegarde de Windows
    ("msmpeng", MICROSOFT), ("mpdefendercoreservice", MICROSOFT), ("mssense", MICROSOFT), ("searchindexer", MICROSOFT),
    ("searchprotocolhost", MICROSOFT), ("searchfilterhost", MICROSOFT), ("wbengine", MICROSOFT), ("sdclt", MICROSOFT),
    ("vssvc", MICROSOFT), ("filehistory", MICROSOFT),
    // sauvegarde
    ("veeamagent", &["Veeam Software Group GmbH"]), ("veeam.endpoint.service", &["Veeam Software Group GmbH"]),
    ("trueimage", &["Acronis International GmbH"]), ("trueimagehomeservice", &["Acronis International GmbH"]),
    ("anti_ransomware_service", &["Acronis International GmbH"]), ("mmscmd", &["Acronis International GmbH"]), ("mms", &["Acronis International GmbH"]),
    ("reflect", &["Paramount Software UK Ltd"]), ("reflectbin", &["Paramount Software UK Ltd"]), ("reflectservice", &["Paramount Software UK Ltd"]),
    ("bztransmit", &["Backblaze, Inc."]), ("bztransmit64", &["Backblaze, Inc."]), ("bzfilelist", &["Backblaze, Inc."]), ("idriveservice", &["IDrive Inc."]),
    ("carboniteservice", &["Carbonite, Inc.", "Open Text Corporation"]),
    ("urbackupclientbackend", &["Infscape UG (haftungsbeschränkt)"]), ("arqagent", &["Haystack Software LLC"]), ("arq", &["Haystack Software LLC"]),
    ("crashplanservice", &["Code42 Software, Inc."]), ("code42service", &["Code42 Software, Inc."]),
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

/// Signataire d'un exécutable, mis en cache sous une clé qu'un compte standard ne forge pas (natif::cle_signature) :
/// un programme remplacé au même chemin, date remise à l'identique, ne garde pas l'éditeur de l'ancien et ne lit pas les
/// données d'un navigateur sans alerte VOL-001 (audit du 2026-11-23, B-2-01). Hors délai : pas de cache (relecture de
/// #104, D2)
fn signataire(chemin: &str) -> Option<String> {
    use std::sync::OnceLock;
    static CACHE: OnceLock<Mutex<HashMap<String, Option<String>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    crate::natif::en_cache_de_signature(cache, chemin, || crate::natif::signataire_a_echeance(chemin).ok()).flatten()
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

/// Dossiers où un compte standard n'écrit pas par défaut (décision du mainteneur, audit de #113, S113-10). Supposé, pas vérifié :
/// un installateur tiers peut ouvrir un dossier de Program Files en écriture (audit de #114, S114-01, préalable de distribution)
pub(crate) struct DossiersFermes {
    /// Le programme peut être dans un sous-dossier : Program Files, plateforme de Defender
    pub arbres: Vec<String>,
    /// Le programme doit être directement dedans : System32 et SysWOW64 ont des sous-dossiers ouverts (Tasks, spool\drivers\color)
    pub directs: Vec<String>,
}

fn dossiers_fermes() -> DossiersFermes {
    let v = |n: &str| std::env::var(n).unwrap_or_default();
    let systeme = crate::natif::dossier_windows();
    DossiersFermes {
        arbres: vec![v("ProgramFiles"), v("ProgramFiles(x86)"), v("ProgramW6432"), format!(r"{}\Microsoft\Windows Defender\Platform", v("ProgramData"))],
        directs: vec![format!(r"{systeme}\System32"), format!(r"{systeme}\SysWOW64")],
    }
}

/// Décision pure. Un programme du profil, de Temp ou d'un autre dossier ouvert n'est jamais « connu » : un attaquant peut y
/// déposer un binaire signé, avec une DLL à côté. Les applications du Store (WindowsApps) en sont aussi écartées
pub(crate) fn dossier_ferme(chemin: &str, d: &DossiersFermes) -> bool {
    let c = chemin.to_lowercase();
    if c.contains("..") || c.contains(r"\windowsapps\") {
        return false;
    }
    let sous = |dossier: &String| !dossier.is_empty() && c.starts_with(&format!("{}\\", dossier.trim_end_matches('\\').to_lowercase()));
    // Longueur du dossier en minuscules, et lecture bornée : aucune panique, quel que soit le nom du dossier de Windows
    d.arbres.iter().any(sous) || d.directs.iter().any(|dossier| sous(dossier) && c.get(dossier.trim_end_matches('\\').to_lowercase().len() + 1..).is_some_and(|fin| !fin.contains('\\')))
}

/// Décision pure : dossier fermé d'abord, sans lecture de signature sinon ; puis le couple nom et éditeur
pub(crate) fn leurre_connu(chemin: &str, dossiers: &DossiersFermes, signe: &dyn Fn(&[&str]) -> bool) -> bool {
    if !dossier_ferme(chemin, dossiers) {
        return false;
    }
    let exe = Path::new(chemin).file_stem().map(|s| s.to_string_lossy().to_lowercase()).unwrap_or_default();
    LEURRES_AUTORISES.iter().any(|(n, e)| exe == *n && signe(e))
}

/// Décision pure : « connu » seulement si, en plus, le programme et ses dossiers sont fermés en écriture et qu'il tourne
/// sous SYSTEM ou un administrateur (décision du mainteneur du 2026-11-21, S110-14, S114-01 et S114-02). Les droits ne
/// sont lus que pour un candidat déjà retenu par le chemin, le nom et l'éditeur
pub(crate) fn leurre_connu_garanti(chemin: &str, dossiers: &DossiersFermes, signe: &dyn Fn(&[&str]) -> bool, ferme: &dyn Fn(&str) -> bool, privilegie: &dyn Fn() -> bool) -> bool {
    // Le jeton n'est lu que pour un candidat déjà retenu (audit de #228, S228-03)
    leurre_connu(chemin, dossiers, signe) && ferme(chemin) && privilegie()
}

/// Logiciel connu (dossier fermé, couple nom et éditeur vérifié, droits et compte contrôlés) qui peut toucher un leurre
/// sans être un rançongiciel
pub fn leurre_autorise(pid: u32, chemin: &str) -> bool {
    let d = dossiers_fermes();
    let racines: Vec<String> = d.arbres.iter().chain(d.directs.iter()).cloned().collect();
    leurre_connu_garanti(chemin, &d, &|e| signe_par(chemin, e), &|c| crate::politique::ferme_en_ecriture(c, &racines), &|| crate::natif::compte_privilegie(pid) == Some(true))
}

/// Dossiers réellement présents sur ce PC : (chemin complet, cible)
pub fn dossiers_presents() -> Vec<(String, &'static Cible)> {
    let utilisateurs = format!(r"{}\Users", crate::natif::lecteur_systeme());
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

/// Formes héritées (« ID ») que Windows recopie de l'entrée d'un dossier audité : sur ses fichiers (cibles récursives
/// ou non), et sur ses sous-dossiers (cibles récursives)
const SDDL_COPIE_FICHIER: &str = "S:(AU;IDSA;0x1;;;WD)";
const SDDL_COPIE_DOSSIER: &str = "S:(AU;OICIIDSA;0x1;;;WD)";
/// Copie sans « ID » sur un sous-dossier créé après la pose (dossier audité sans « AI » : SetKernelObjectSecurity)
const SDDL_COPIE_DOSSIER_SANS_ID: &str = "S:(AU;OICISA;0x1;;;WD)";

/// Éléments parcourus au plus par dossier (profil de navigateur) et par passage
const MAXIMUM_PAR_DOSSIER: usize = 20_000;

/// Entrées d'audit de deR4Tizer pour une cible : la pose et le retrait les partagent (celles qu'on retire sont
/// exactement celles qu'on pose)
pub fn entrees_audit(recursif: bool) -> crate::natif::EntreesAudit<'static> {
    crate::natif::EntreesAudit { dossier: sddl_audit_dossier(recursif), fichier: SDDL_AUDIT_FICHIER, copie_dossier: SDDL_COPIE_DOSSIER, copie_fichier: SDDL_COPIE_FICHIER,
        copie_dossier_sans_id: SDDL_COPIE_DOSSIER_SANS_ID }
}

/// Désinstallation (audit du 2026-11-23, A-6-4) : retire l'audit de lecture posé dans les profils (sinon, avec
/// GARDER_BASELINE=1, l'audit « Système de fichiers » reste actif et Windows continue d'écrire des 4663 sur ces
/// fichiers). Par handle, comme la pose (natif::retirer_audit_arborescence) : seules les entrées identiques aux nôtres
/// partent. Rend un compte rendu d'une ligne
pub fn retirer_audit() -> String {
    let (mut n, mut retraits, mut echecs, mut ecartes) = (0, 0, 0, 0);
    for (d, c) in dossiers_presents() {
        match crate::natif::retirer_audit_arborescence(Path::new(&d), &entrees_audit(c.recursif), c.recursif, MAXIMUM_PAR_DOSSIER) {
            Ok(b) => {
                n += 1;
                retraits += b.poses;
                ecartes += b.ecartes + usize::from(b.tronque);
            }
            Err(_) => echecs += 1,
        }
    }
    texte_retrait_audit(n, retraits, echecs, ecartes)
}

/// Compte rendu du retrait de l'audit (pur, testé) : un échec ou un élément écarté se dit, avec ce qu'il reste à faire
pub fn texte_retrait_audit(dossiers: usize, retraits: usize, echecs: usize, ecartes: usize) -> String {
    let mut t = format!("Audit de lecture des données sensibles : retiré de {retraits} élément(s) dans {dossiers} dossier(s) de profil.");
    if echecs > 0 || ecartes > 0 {
        t.push_str(&format!(" {echecs} dossier(s) en échec, {ecartes} élément(s) écarté(s) (liens, illisibles ou au-delà du maximum) : \
            leur audit de lecture pour Tout le monde peut rester (Propriétés, Sécurité, Avancé, Audit)."));
    }
    t
}

/// Pose (ou repose) l'audit de lecture sur les dossiers. En SYSTEM dans les profils des utilisateurs : tout par
/// handle (natif::poser_audit_arborescence), jamais par chemin ni par PowerShell : une jonction posée par
/// l'utilisateur à la place d'un dossier de son profil ne fait rien écrire ailleurs, et seule la SACL est écrite
/// (Set-Acl réécrivait le descripteur complet, DACL comprise).
/// Pose l'audit sur chaque dossier présent ; rend (dossiers audités, dossiers en échec)
pub fn poser_audit() -> (usize, usize) {
    let (mut n, mut echecs) = (0, 0);
    for (d, c) in dossiers_presents() {
        let e = entrees_audit(c.recursif);
        match crate::natif::poser_audit_arborescence(Path::new(&d), e.dossier, e.fichier, c.recursif, MAXIMUM_PAR_DOSSIER) {
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
        // Arrière-plan (A-8-1) : pose de l'audit sur les dossiers, toutes les heures
        let _ = std::thread::Builder::new().name("audit données sensibles".into()).spawn(move || loop {
            crate::natif::fil_priorite(crate::natif::Priorite::Arriere);
            let (n, echecs) = poser_audit();
            commun::journal(&format!("audit de lecture posé sur {n} dossier(s) de données sensibles{}", if echecs > 0 { format!(", {echecs} en échec") } else { String::new() }));
            let utilisateurs = format!(r"{}\Users", crate::natif::lecteur_systeme());
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
    let mut suspendus: HashMap<u32, (u64, Instant)> = HashMap::new();
    // Fil des 4663 au-dessus de la normale (A-8-1) : la suspension d'un programme qui touche un leurre passe avant les
    // fils lourds du service. Gain à mesurer en VM (délai entre le 4663 et la suspension sous charge)
    evenements::abonner_avec_priorite("Security", "*[System[EventID=4663]]", crate::collectes::Collecte::JournalSecurite, Some(crate::natif::Priorite::Haute), move |xml| {
        // Fichier leurre modifié ou supprimé : rançongiciel probable, on suspend aussitôt le programme
        if let Some((pid, programme, objet)) = crate::hygiene::pid_touchant_leurre(&xml) {
            let connu = leurre_autorise(pid, &programme);
            // Sauvegarde, synchronisation, antivirus, indexation : noté sans rien suspendre. Sinon, rundll32,
            // regsvr32, mshta, powershell… sont des binaires Windows par lesquels passent beaucoup de rançongiciels :
            // ils sont suspendus. Seuls les processus critiques (csrss, lsass, svchost…) sont protégés, par
            // reponse::protege()
            let tentee = !connu && {
                let config: commun::Config = commun::lire("config.json").unwrap_or_default();
                suspendre_leurre(config.reponse_auto_rancongiciel, false, crate::reponse::protege(pid).is_some())
            };
            // Plusieurs événements d'une même écriture : un programme déjà suspendu ne consomme ni garde ni trace (audit de #110, S110-02)
            let creation = crate::natif::creation_processus(pid).unwrap_or(0);
            let maintenant = Instant::now();
            let deja = tentee && deja_suspendu(&mut suspendus, pid, creation, maintenant);
            let attendu = crate::reponse::Attendu::Leurre { avant: crate::hygiene::heure_evenement(&xml), chemin: programme.clone() };
            let (suspendu, retenue) = if deja { (true, None) } else if tentee { suspension_leurre(pid, &programme, &attendu, &file) } else { (false, None) };
            // Suspension automatique dans le SIEM, pour la chronologie (relecture de #94, D1)
            if tentee && !deja {
                let message = match &retenue {
                    Some(r) if r.starts_with("échec") => r.clone(),
                    Some(r) => format!("retenue : {r}"),
                    None if suspendu => "programme suspendu".to_string(),
                    None => "suspension en échec".to_string(),
                };
                crate::siem::reponse("suspendre", &pid.to_string(), suspendu, &message, &format!("automatique : leurre touché par {programme}"));
            }
            let mut alerte = alerte_leurre_touche(pid, &programme, &objet, connu, suspendu);
            if let Some(r) = retenue {
                dire_retenue(&mut alerte, &r);
            }
            file.lock().unwrap().push(alerte);
            // Après l'alerte : une écriture bloquée de l'historique ne la retient pas (audit de #110, S110-04)
            if suspendu && !deja {
                suspendus.insert(pid, (creation, maintenant));
                crate::politique::noter_suspension(&programme, crate::natif::empreinte_a_echeance(&programme).ok().flatten(), pid, creation);
            }
            return;
        }
        let Some(a) = analyser(&xml, &dossiers.lock().unwrap()) else { return };
        // Une alerte par programme et par cible toutes les 24 h
        if premiere_en_24h(&mut vues, format!("{}|{}", a.chemin, a.destination), Instant::now()) {
            file.lock().unwrap().push(a);
        }
    });
}

/// Ce processus vient-il d'être suspendu pour ce leurre ? (pur, testé) Même PID et même heure de création, dans la minute :
/// les événements en file d'une même écriture. Au-delà, il repasse par la garde, après une reprise par exemple
pub(crate) fn deja_suspendu(suspendus: &mut HashMap<u32, (u64, Instant)>, pid: u32, creation: u64, maintenant: Instant) -> bool {
    suspendus.retain(|_, (_, t)| maintenant.saturating_duration_since(*t) < Duration::from_secs(60));
    suspendus.get(&pid).is_some_and(|(c, _)| *c == creation)
}

/// Le texte commence par la suspension non faite : la clé de déduplication d'une alerte lit son début, et l'alerte précédente
/// de ce programme disait « suspendu » (pur, testé)
pub(crate) fn dire_retenue(alerte: &mut Alerte, raison: &str) {
    alerte.raisons = format!("Suspension automatique non faite ({raison}), programme peut-être actif, à vérifier et à arrêter sans attendre si besoin : {}", alerte.raisons);
}

/// Signature illisible ou hors délai : non signé, donc toujours suspendu
fn genre_leurre(pid: u32, programme: &str) -> crate::politique::Genre {
    let dossiers: Vec<String> = ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"].iter().filter_map(|v| std::env::var(v).ok()).collect();
    if !crate::politique::installe_dans(programme, &dossiers) {
        return crate::politique::Genre::SuspensionSansSeuil;
    }
    let signe = matches!(crate::natif::signataire_a_echeance(programme), Ok(Some(_)));
    // Droits et compte lus seulement pour un candidat au seuil (signé, dans Program Files)
    let candidat = signe && crate::politique::genre_suspension(programme, signe, &dossiers) == crate::politique::Genre::Suspension;
    let ferme = candidat && crate::politique::ferme_en_ecriture(programme, &dossiers);
    let privilegie = ferme && crate::natif::compte_privilegie(pid) == Some(true);
    crate::politique::genre_suspension_garanti(programme, signe, &dossiers, ferme, privilegie)
}

/// La politique et la garde pour un programme qui touche un leurre : (suspendu, raison de la retenue). Hors du cycle : la
/// suspension n'attend pas le moniteur
fn suspension_leurre(pid: u32, programme: &str, attendu: &crate::reponse::Attendu, file: &Mutex<Vec<Alerte>>) -> (bool, Option<String>) {
    use crate::politique::{self, Action, Contexte, Decision, Declencheur, Passage, SourceAuto};
    let contexte = Contexte { echec_protection: commun::echec_protection().is_some(), rancongiciel: true, ..Default::default() };
    match politique::decider(Action::Suspendre, Declencheur::Automatique(SourceAuto::Leurre), &contexte) {
        Decision::Autorisee(a) => match politique::passer(genre_leurre(pid, programme), programme, &mut || crate::natif::empreinte_a_echeance(programme).ok().flatten()) {
            Passage::Passe => match crate::execution::suspendre(&a, pid, attendu, true) {
                Ok(()) => (true, None),
                Err(e) => {
                    // L'alerte le dit : rien ne doit laisser croire que le programme est confiné (audit de #113, S113-01)
                    commun::journal(&format!("suspension de {programme} (PID {pid}) : {e}"));
                    (false, Some(format!("échec : {e}")))
                }
            },
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
