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

/// Programmes qui ouvrent légitimement tous les fichiers (antivirus, sauvegarde de Windows, deR4Tizer…)
const TOUJOURS_AUTORISES: &[&str] = &[
    "msmpeng", "mpdefendercoreservice", "mssense", "searchprotocolhost", "searchindexer", "system", "der4tizersvc",
    "onedrive", "filecoauth", "backgroundtaskhost", "svchost",
];

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
        let heritage = if c.recursif { "ContainerInherit,ObjectInherit" } else { "ObjectInherit" };
        script.push_str(&format!(
            "try {{ $a = Get-Acl -LiteralPath '{d}' -Audit; \
             $r = New-Object Security.AccessControl.FileSystemAuditRule((New-Object Security.Principal.SecurityIdentifier 'S-1-1-0'),'ReadData','{heritage}','None','Success'); \
             $a.AddAuditRule($r); Set-Acl -LiteralPath '{d}' -AclObject $a; $n++ }} catch {{ Write-Output (\"erreur : {d} : \" + $_.Exception.Message) }}\n",
            d = d.replace('\'', "''"),
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
    if cible.proprietaires.contains(&exe.as_str()) || TOUJOURS_AUTORISES.contains(&exe.as_str()) {
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
            let config: commun::Config = commun::lire("config.json").unwrap_or_default();
            let suspendu = config.reponse_auto_rancongiciel && crate::reponse::suspendre(pid, true).is_ok();
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
