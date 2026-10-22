//! Protection contre les voleurs de données (« infostealers ») : mots de passe et cookies des
//! navigateurs, jetons Discord, session Telegram, portefeuilles crypto.
//! Le service pose un audit de lecture (SACL) sur ces fichiers ; Windows écrit alors un événement 4663
//! à chaque ouverture. On alerte quand le programme qui les ouvre n'est pas leur propriétaire légitime.
//! Nécessite l'audit « Système de fichiers » (profil de baseline « journalisation »).

use crate::commun::{self, Alerte};
use crate::evenements;
use std::collections::HashMap;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::Command;
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

/// Éditeur attendu (dans le nom du signataire Authenticode) de chaque propriétaire légitime : un
/// « chrome.exe » posé dans %TEMP% n'est pas signé par Google et reste suspect
const EDITEURS: &[(&str, &str)] = &[
    ("chrome", "Google"), ("brave", "Brave"), ("msedge", "Microsoft"), ("msedgewebview2", "Microsoft"),
    ("firefox", "Mozilla"), ("plugin-container", "Mozilla"), ("crashreporter", "Mozilla"),
    ("discord", "Discord"), ("update", "Discord"), ("telegram", "Telegram"), ("updater", "Telegram"),
    ("ledger live", "Ledger"), ("ledger wallet", "Ledger"), ("exodus", "Exodus"),
];

/// Programmes de Windows et de Microsoft qui ouvrent légitimement tous les fichiers (antivirus, indexation,
/// synchronisation) : binaire Windows vérifié (dossier Windows et signature) ou signé par Microsoft
const TOUJOURS_AUTORISES: &[&str] = &[
    "msmpeng", "mpdefendercoreservice", "mssense", "searchprotocolhost", "searchindexer", "onedrive", "filecoauth",
    "backgroundtaskhost", "svchost",
];

/// Logiciels qui lisent, copient ou synchronisent tous les fichiers et peuvent toucher un leurre sans être un
/// rançongiciel : (début du nom de l'exécutable, éditeur attendu dans la signature). Le couple est vérifié.
const LEURRES_AUTORISES: &[(&str, &str)] = &[
    // antivirus, indexation et sauvegarde de Windows
    ("msmpeng", "Microsoft"), ("mpdefendercoreservice", "Microsoft"), ("mssense", "Microsoft"), ("searchindexer", "Microsoft"),
    ("searchprotocolhost", "Microsoft"), ("searchfilterhost", "Microsoft"), ("wbengine", "Microsoft"), ("sdclt", "Microsoft"),
    ("vssvc", "Microsoft"), ("filehistory", "Microsoft"), ("onedrive", "Microsoft"), ("filecoauth", "Microsoft"),
    // synchronisation
    ("dropbox", "Dropbox"), ("googledrivefs", "Google"), ("nextcloud", "Nextcloud"), ("owncloud", "ownCloud"),
    ("synologydrive", "Synology"), ("icloud", "Apple"), ("megasync", "Mega Limited"), ("boxsync", "Box, Inc"), ("box", "Box, Inc"),
    // sauvegarde
    ("veeam", "Veeam"), ("acronis", "Acronis"), ("trueimage", "Acronis"), ("anti_ransomware_service", "Acronis"), ("mmscmd", "Acronis"),
    ("reflect", "Paramount Software"), ("macrium", "Paramount Software"), ("bztransmit", "Backblaze"), ("bzfilelist", "Backblaze"),
    ("cobian", "Cobian"), ("idrive", "IDrive"), ("carbonite", "Carbonite"), ("aomei", "AOMEI"), ("backupper", "AOMEI"),
    ("urbackup", "Infscape"), ("arq", "Haystack"), ("crashplan", "Code42"), ("code42", "Code42"),
];

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
    let s = crate::natif::signataire_valide(chemin);
    let mut c = cache.lock().unwrap();
    if c.len() > 2000 {
        c.clear();
    }
    c.insert(cle, s.clone());
    s
}

fn signe_par(chemin: &str, editeur: &str) -> bool {
    if editeur == "Microsoft" && crate::natif::binaire_windows(chemin) {
        return true;
    }
    signataire(chemin).map(|s| s.contains(editeur)).unwrap_or(false)
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
    TOUJOURS_AUTORISES.contains(&exe) && signe_par(chemin, "Microsoft")
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
            if d.is_dir() {
                l.push((d.to_string_lossy().to_string(), c));
            }
        }
    }
    l
}

/// Pose (ou repose) l'audit de lecture sur les dossiers ; les nouveaux fichiers en héritent.
/// Fait en PowerShell (Get-Acl -Audit / Set-Acl), qui active lui-même le privilège SeSecurityPrivilege.
pub fn poser_audit() -> Result<usize, String> {
    let dossiers = dossiers_presents();
    if dossiers.is_empty() {
        return Ok(0);
    }
    let mut script = String::from("$ErrorActionPreference='Continue'\n$n=0\n");
    for (d, c) in &dossiers {
        // InheritOnly : la règle ne vise pas le dossier lui-même (le parcourir n'est pas lire une donnée, et
        // produirait des milliers d'événements) ; NoPropagateInherit : seulement ses fichiers, pas les sous-dossiers
        let (heritage, propagation) = if c.recursif { ("ContainerInherit,ObjectInherit", "InheritOnly") } else { ("ObjectInherit", "InheritOnly,NoPropagateInherit") };
        // Reposée seulement si elle diffère : chaque Set-Acl se propage à tous les fichiers (événements 4907 en rafale)
        script.push_str(&format!(
            "try {{ $a = Get-Acl -LiteralPath '{d}' -Audit; \
             $r = New-Object Security.AccessControl.FileSystemAuditRule((New-Object Security.Principal.SecurityIdentifier 'S-1-1-0'),'ReadData','{heritage}','{propagation}','Success'); \
             $x = @($a.GetAuditRules($true, $false, [Security.Principal.SecurityIdentifier]) | Where-Object {{ $_.IdentityReference.Value -eq 'S-1-1-0' }}); \
             if (-not ($x.Count -eq 1 -and $x[0].FileSystemRights -eq $r.FileSystemRights -and $x[0].InheritanceFlags -eq $r.InheritanceFlags -and $x[0].PropagationFlags -eq $r.PropagationFlags)) {{ \
               $a.PurgeAuditRules((New-Object Security.Principal.SecurityIdentifier 'S-1-1-0')); $a.AddAuditRule($r); Set-Acl -LiteralPath '{d}' -AclObject $a }}; \
             Get-ChildItem -LiteralPath '{d}' -File -Force {recursion} -ErrorAction SilentlyContinue | ForEach-Object {{ \
               $fa = Get-Acl -LiteralPath $_.FullName -Audit; \
               if (-not @($fa.GetAuditRules($false, $true, [Security.Principal.SecurityIdentifier]) | Where-Object {{ $_.IdentityReference.Value -eq 'S-1-1-0' }}).Count) {{ \
                 $fa.SetAuditRuleProtection($false, $true); Set-Acl -LiteralPath $_.FullName -AclObject $fa }} }}; \
             $n++ }} catch {{ Write-Output (\"erreur : {d} : \" + $_.Exception.Message) }}\n",
            d = d.replace('\'', "''"),
            // Fichiers déjà présents sans la règle héritée (la modification du dossier ne leur parvient pas
            // toujours) : réécrire leur descripteur sans protection force Windows à recalculer l'héritage
            recursion = if c.recursif { "-Recurse" } else { "" },
        ));
    }
    script.push_str("Write-Output \"poses=$n\"\n");
    let sortie = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .creation_flags(0x0800_0000)
        .output()
        .map_err(|e| e.to_string())?;
    let texte = String::from_utf8_lossy(&sortie.stdout);
    for l in texte.lines().filter(|l| l.starts_with("erreur")) {
        commun::journal(&format!("audit des données sensibles : {l}"));
    }
    texte.lines().find_map(|l| l.strip_prefix("poses=")).and_then(|n| n.trim().parse().ok()).ok_or_else(|| texte.trim().to_string())
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
            match poser_audit() {
                Ok(n) => commun::journal(&format!("audit de lecture posé sur {n} dossier(s) de données sensibles")),
                Err(e) => commun::journal(&format!("audit des données sensibles impossible : {e}")),
            }
            *dossiers.lock().unwrap() = dossiers_presents();
            std::thread::sleep(Duration::from_secs(3600));
        });
    }
    let mut vues: HashMap<String, Instant> = HashMap::new();
    evenements::abonner("Security", "*[System[EventID=4663]]", move |xml| {
        // Fichier leurre modifié ou supprimé : rançongiciel probable, on suspend aussitôt le programme
        if let Some((pid, programme, objet)) = crate::hygiene::pid_touchant_leurre(&xml) {
            let connu = leurre_autorise(&programme);
            if connu {
                // Sauvegarde, synchronisation, antivirus, indexation : on le note sans rien suspendre
                file.lock().unwrap().push(Alerte {
                    id: commun::nouvel_id(),
                    heure: commun::maintenant(),
                    niveau: "Info".into(),
                    processus: Path::new(&programme).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default(),
                    chemin: programme.clone(),
                    destination: "leurre anti-rançongiciel".into(),
                    raisons: format!("{programme} (logiciel connu et signé : sauvegarde, synchronisation ou antivirus) a touché le fichier leurre {objet} — non suspendu"),
                    pid: Some(pid),
                    ..Default::default()
                });
                return;
            }
            let config: commun::Config = commun::lire("config.json").unwrap_or_default();
            // Un binaire de Windows (svchost partagé, explorer…) n'est jamais suspendu automatiquement : la session ou le
            // réseau se figeraient ; l'alerte reste critique
            let suspendu = config.reponse_auto_rancongiciel && !crate::natif::binaire_windows(&programme) && crate::reponse::suspendre(pid, true).is_ok();
            file.lock().unwrap().push(Alerte {
                id: commun::nouvel_id(),
                heure: commun::maintenant(),
                niveau: "Critique".into(),
                score: 15,
                processus: Path::new(&programme).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default(),
                chemin: programme.clone(),
                destination: "leurre anti-rançongiciel".into(),
                raisons: format!("{programme} a modifié ou supprimé le fichier leurre {objet} : RANÇONGICIEL PROBABLE{}",
                    if suspendu { " — programme SUSPENDU automatiquement (vérifiez puis tuez-le ou reprenez-le)" } else { "" }),
                pid: Some(pid),
                ..Default::default()
            });
            return;
        }
        let Some(a) = analyser(&xml, &dossiers.lock().unwrap()) else { return };
        // Une alerte par programme et par cible toutes les 24 h
        let cle = format!("{}|{}", a.chemin, a.destination);
        if vues.get(&cle).map(|t| t.elapsed() < Duration::from_secs(86400)).unwrap_or(false) {
            return;
        }
        vues.insert(cle, Instant::now());
        file.lock().unwrap().push(a);
    });
}
