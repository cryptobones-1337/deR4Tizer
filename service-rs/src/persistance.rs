//! Surveillance des endroits où un programme peut s'inscrire pour démarrer avec Windows
//! (inspiré d'Autoruns) : clés Run, Winlogon, IFEO, AppInit, services, tâches planifiées,
//! dossiers Démarrage, abonnements WMI. Toute entrée nouvelle ou modifiée déclenche une alerte.

use crate::commun::{self, Alerte, EntreeDemarrage};
use crate::natif::{self, large};
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;
use windows::core::{Interface, PCWSTR};
use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, IPersistFile, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, STGM_READ};
use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};
use winreg::enums::*;
use winreg::RegKey;

const INTERPRETEURS: &[&str] = &[
    "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin", "msbuild", "installutil",
];

pub struct Persistance {
    reference: HashMap<String, EntreeDemarrage>,
    apprentissage: bool,
    pub entrees: Vec<EntreeDemarrage>,
}

fn dossier_suspect() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?i)\\(Temp|Downloads|Téléchargements)\\|\\Users\\Public\\|\\AppData\\Roaming\\[^\\]+\.exe$").unwrap())
}

impl Persistance {
    pub fn nouvelle() -> Persistance {
        let sauvegarde: Option<Vec<EntreeDemarrage>> = commun::lire("demarrage.json");
        // Premier démarrage du service Rust : on réapprend en silence (le relevé peut différer de détail de celui du C#)
        let marqueur = commun::dossier().join("demarrage-reference-rust");
        let apprentissage = sauvegarde.is_none() || !marqueur.exists();
        let _ = fs::write(&marqueur, commun::maintenant());
        let reference = sauvegarde.unwrap_or_default().into_iter().map(|e| (e.cle.clone(), e)).collect();
        Persistance { reference, apprentissage, entrees: Vec::new() }
    }

    pub fn verifier(&mut self, signataire: &mut dyn FnMut(&str) -> String) -> Vec<Alerte> {
        let mut releve: Vec<EntreeDemarrage> = Vec::new();
        let mut vues = std::collections::HashSet::new();
        for e in releve_complet() {
            if vues.insert(e.cle.clone()) {
                releve.push(e);
            }
        }
        for e in releve.iter_mut() {
            e.cible = cible(&e.commande);
            // Cible absolue seulement : un nom relatif non résolu serait cherché dans le dossier courant du service
            e.signataire = if !Path::new(&e.cible).is_absolute() || !Path::new(&e.cible).exists() { "?".into() } else { signataire(&e.cible) };
            e.remarque = evaluer(e);
        }
        let (alertes, modifie) = comparer(&self.reference, &mut releve, self.apprentissage);
        self.reference = releve.iter().map(|e| (e.cle.clone(), e.clone())).collect();
        if modifie {
            let _ = commun::ecrire("demarrage.json", &releve);
        }
        self.entrees = releve;
        self.apprentissage = false;
        alertes
    }
}

/// Décision pure (testée, PER-001 et PER-002) : compare un relevé, déjà évalué (cible, signataire, remarque), à la
/// référence. Entrée inconnue : NOUVELLE (PER-001) ; commande changée : MODIFIÉE (PER-002) ; commande inchangée mais
/// entrée DEVENUE SUSPECTE, sans remarque avant, avec une remarque maintenant (PER-002, PR 3.6 : une classe COM surchargée
/// après coup dans le profil d'un utilisateur, un fichier remplacé par un fichier non signé…) ; autre changement du
/// signataire ou de la remarque : noté (référence réécrite), sans alerte. Apprentissage : rien n'alerte. Rend (alertes,
/// référence à réécrire).
pub(crate) fn comparer(reference: &HashMap<String, EntreeDemarrage>, releve: &mut [EntreeDemarrage], apprentissage: bool) -> (Vec<Alerte>, bool) {
    let mut alertes = Vec::new();
    let mut modifie = releve.len() != reference.len();
    for e in releve.iter_mut() {
        match reference.get(&e.cle) {
            Some(ancienne) => {
                e.depuis = ancienne.depuis.clone();
                if ancienne.signataire != e.signataire || ancienne.remarque != e.remarque {
                    modifie = true;
                }
                if ancienne.commande != e.commande {
                    modifie = true;
                    if !apprentissage {
                        alertes.push(alerter(e, &format!("démarrage automatique MODIFIÉ (avant : {})", ancienne.commande)));
                    }
                } else if ancienne.remarque.is_empty() && !e.remarque.is_empty() && !apprentissage {
                    // Audit de #83, S83-06 : sinon une surcharge posée en deux temps ne serait jamais remontée
                    alertes.push(alerter(e, "démarrage automatique MODIFIÉ, DEVENU SUSPECT (même commande)"));
                }
            }
            None => {
                e.depuis = commun::maintenant();
                modifie = true;
                if !apprentissage {
                    alertes.push(alerter(e, "NOUVEAU démarrage automatique"));
                }
            }
        }
    }
    (alertes, modifie)
}

pub(crate) fn alerter(e: &EntreeDemarrage, quoi: &str) -> Alerte {
    let suspect = !e.remarque.is_empty();
    Alerte {
        regle: if quoi.starts_with("NOUVEAU") { crate::regles::PER_001 } else { crate::regles::PER_002 }.into(),
        id: commun::nouvel_id(),
        heure: commun::maintenant(),
        niveau: if suspect { "Alerte" } else { "Info" }.into(),
        score: if suspect { 3 } else { 0 },
        processus: Path::new(&e.cible).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(),
        chemin: e.cible.clone(),
        destination: format!("{} : {}", e.categorie, e.nom),
        raisons: format!("{quoi} : {}{}", e.commande, if suspect { format!(" [{}]", e.remarque) } else { String::new() }),
        ..Default::default()
    }
}

pub(crate) fn evaluer(e: &EntreeDemarrage) -> String {
    let mut r = Vec::new();
    let exe = Path::new(&e.cible).file_stem().map(|s| s.to_string_lossy().to_lowercase()).unwrap_or_default();
    let tache_windows = e.categorie == "Tâche planifiée" && e.nom.to_lowercase().starts_with(r"\microsoft\windows\");
    let nettoyage = e.categorie.starts_with("RunOnce") && nettoyage_onedrive(&e.commande);
    if INTERPRETEURS.contains(&exe.as_str()) && !tache_windows && !nettoyage {
        r.push(format!("lancé via {exe}"));
    }
    if e.signataire.is_empty() {
        r.push("NON SIGNÉ".to_string());
    }
    if let Some(s) = crate::processus::suspicion(&e.commande) {
        r.push(s.to_string());
    }
    if dossier_suspect().is_match(&e.cible) {
        r.push("dossier suspect".into());
    }
    if matches!(e.categorie.as_str(), "IFEO" | "AppInit" | "WMI") {
        r.push("technique de persistance rare".into());
    }
    // Tâche COM hors Windows dont le serveur n'est pas enregistré pour la machine, ou dont le fichier manque :
    // cas du détournement COM par le profil d'un utilisateur (HKCU, non lu ici), signalé plutôt que tu
    // Préfixe « COM » seul (pas le format exact) : un ClassId mal formé ne doit pas faire taire la remarque
    if !tache_windows && e.categorie == "Tâche planifiée" && e.commande.starts_with("COM ") && !Path::new(&e.cible).is_file() {
        r.push("serveur COM non enregistré pour la machine".into());
    }
    r.join(", ")
}

/// Décision pure (testée) : nettoyage que l'installation de OneDrive pose pour l'utilisateur (« RunOnce », effacer son
/// propre installeur). Commande exacte seulement : un seul « del » de OneDriveSetup.exe dans le dossier OneDrive du
/// profil, rien avant ni après ; tout ajout (« & », « | », autre fichier) la remet au rang des interpréteurs suspects
pub(crate) fn nettoyage_onedrive(commande: &str) -> bool {
    static MOTIF: OnceLock<Regex> = OnceLock::new();
    MOTIF.get_or_init(|| {
        // Ni « % » (variable remplacée par cmd avant l'analyse de la ligne : injection), ni « ^ », « ! », caractère de
        // contrôle (audit de #83, S83-01)
        Regex::new(r#"(?i)^[a-z]:\\windows\\system32\\cmd\.exe /q /c del /q "[a-z]:\\users\\[^\\"&|<>%^!()\x00-\x1f]+\\appdata\\local\\microsoft\\onedrive\\(update|standaloneupdater)\\onedrivesetup\.exe"$"#).unwrap()
    }).is_match(commande.trim())
}

fn developper(s: &str) -> String {
    // Variables d'environnement %X%
    let motif = Regex::new(r"%([^%]+)%").unwrap();
    motif.replace_all(s, |c: &regex::Captures| std::env::var(&c[1]).unwrap_or_else(|_| c[0].to_string())).to_string()
}

/// Extrait le fichier lancé par une ligne de commande
pub fn cible(commande: &str) -> String {
    static MOTIF: OnceLock<Regex> = OnceLock::new();
    let motif = MOTIF.get_or_init(|| Regex::new(r"(?i)^(.+?\.(exe|dll|sys|bat|cmd|ps1|vbs|js|com|scr|cpl|ocx))(\s|,|$)").unwrap());
    if commande.trim().is_empty() {
        return String::new();
    }
    // Tâche à gestionnaire COM (« COM {CLSID} ») : la cible est le serveur enregistré pour ce CLSID. Une valeur
    // du registre elle-même de la forme « COM {…} » est refusée : sinon récursion sans fin (pile, service arrêté)
    if let Some(clsid) = clsid_com(commande) {
        return serveur_com(clsid).filter(|s| clsid_com(s).is_none()).map(|s| cible(&s)).unwrap_or_default();
    }
    let windows = natif::dossier_windows();
    let mut c = developper(commande.trim());
    if let Some(r) = c.strip_prefix(r"\??\") {
        c = r.to_string();
    }
    // Comparaison sur les octets ASCII : sur la version en minuscules, un caractère Unicode (signe Kelvin…)
    // pourrait devenir ASCII et décaler le découpage au milieu d'un caractère (panique, service arrêté)
    if c.get(..12).is_some_and(|p| p.eq_ignore_ascii_case(r"\systemroot\")) {
        c = format!("{windows}{}", &c[11..]);
    }
    let bas = c.to_lowercase();
    if bas.starts_with(r"system32\") || bas.starts_with(r"syswow64\") {
        c = format!(r"{windows}\{c}");
    }
    let mut chemin = if let Some(r) = c.strip_prefix('"') {
        r.split('"').next().unwrap_or("").to_string()
    } else if let Some(m) = motif.captures(&c) {
        m[1].to_string()
    } else {
        c.split(' ').next().unwrap_or("").to_string()
    };
    if !chemin.is_empty() && !Path::new(&chemin).is_absolute() {
        // Comme Windows : dossier système puis dossiers du PATH
        let path = std::env::var("PATH").unwrap_or_default();
        let dossiers = std::iter::once(natif::dossier_systeme()).chain(path.split(';').filter(|d| !d.is_empty()).map(developper));
        for d in dossiers {
            let mut candidat = Path::new(&d).join(&chemin).to_string_lossy().to_string();
            if !candidat.to_lowercase().ends_with(".exe") && Path::new(&format!("{candidat}.exe")).is_file() {
                candidat.push_str(".exe");
            }
            // Un fichier seulement : un dossier du même nom (System32\COM…) n'est pas lancé
            if Path::new(&candidat).is_file() {
                chemin = candidat;
                break;
            }
        }
    }
    chemin
}

/// CLSID d'une action « COM {CLSID} » (forme écrite par `taches`)
fn clsid_com(commande: &str) -> Option<&str> {
    static MOTIF: OnceLock<Regex> = OnceLock::new();
    let motif = MOTIF.get_or_init(|| Regex::new(r"^COM (\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\})$").unwrap());
    motif.captures(commande.trim()).and_then(|c| c.get(1)).map(|m| m.as_str())
}

/// Commande relevée pour une action COM : ClassId entre accolades, avec ou sans dans la tâche (Windows accepte
/// et garde les deux formes)
pub(crate) fn commande_com(class_id: &str) -> String {
    let id = class_id.trim();
    let id = id.strip_prefix('{').and_then(|x| x.strip_suffix('}')).unwrap_or(id).trim();
    format!("COM {{{id}}}")
}

/// Serveur enregistré pour un CLSID (machine) : InprocServer32, sinon LocalServer32 ; à défaut, classe COM d'un paquet
/// installé pour la machine (AppX, `PackagedCom`, PR 3.6)
fn serveur_com(clsid: &str) -> Option<String> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    ["InprocServer32", "LocalServer32"].iter().find_map(|s| {
        let k = hklm.open_subkey(format!(r"SOFTWARE\Classes\CLSID\{clsid}\{s}")).ok()?;
        texte_registre(&k, "").filter(|v| !v.trim().is_empty())
    }).or_else(|| serveur_com_empaquete(&hklm, clsid))
}

/// Classe COM empaquetée (tâches « SoftLanding » de Windows, par exemple) : enregistrée pour la machine sous
/// `Classes\PackagedCom` (écrite par le système : le service de déploiement des paquets), son serveur est un fichier du dossier du paquet
/// (`DllPath`, sinon l'`Executable` de son serveur) ; la version la plus récente du paquet est retenue
fn serveur_com_empaquete(hklm: &RegKey, clsid: &str) -> Option<String> {
    // Classe surchargée dans le profil d'un utilisateur chargé (HKCU) : détournement COM possible, aucune résolution
    // (la remarque « serveur COM non enregistré pour la machine » reste ; audit de #83, S83-02)
    let hku = RegKey::predef(HKEY_USERS);
    let surchargee = hku.enum_keys().map_while(Result::ok).filter(|s| s.starts_with("S-1-5-21-")).any(|s| {
        let chemin = if s.ends_with("_Classes") { format!(r"{s}\CLSID\{clsid}") } else { format!(r"{s}\Software\Classes\CLSID\{clsid}") };
        hku.open_subkey(chemin).is_ok()
    });
    if surchargee {
        return None;
    }
    let index = hklm.open_subkey(format!(r"SOFTWARE\Classes\PackagedCom\ClassIndex\{clsid}")).ok()?;
    // Paquets de Windows seulement (éditeur Microsoft) : un paquet installé par un utilisateur, signé par son propre
    // certificat, ne fait pas taire la remarque (audit de #83, S83-03)
    let paquet = index.enum_keys().map_while(Result::ok).filter(|p| paquet_de_windows(p)).max_by(|a, b| version_paquet(a).cmp(&version_paquet(b)))?;
    let classe = hklm.open_subkey(format!(r"SOFTWARE\Classes\PackagedCom\Package\{paquet}\Class\{clsid}")).ok()?;
    let relatif = texte_registre(&classe, "DllPath").filter(|v| !v.trim().is_empty()).or_else(|| {
        let id: u32 = classe.get_value("ServerId").ok()?;
        let serveur = hklm.open_subkey(format!(r"SOFTWARE\Classes\PackagedCom\Package\{paquet}\Server\{id}")).ok()?;
        texte_registre(&serveur, "Executable")
    })?;
    let depot = hklm.open_subkey(format!(r"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\{paquet}")).ok()?;
    let racine = texte_registre(&depot, "Path")?;
    if !racine_systeme_de_paquets(&racine, &natif::dossier_windows(), &std::env::var("ProgramFiles").unwrap_or_default()) {
        return None;
    }
    chemin_dans_paquet(&racine, &relatif).map(|c| format!("\"{c}\""))
}

/// Décision pure (testée) : paquet publié par Microsoft (identifiants d'éditeur de Windows et du Store de Microsoft)
pub(crate) fn paquet_de_windows(nom_complet: &str) -> bool {
    let bas = nom_complet.to_ascii_lowercase();
    bas.ends_with("__cw5n1h2txyewy") || bas.ends_with("__8wekyb3d8bbwe")
}

/// Décision pure (testée) : dossier d'un paquet installé par le système (`Windows\SystemApps` ou
/// `Program Files\WindowsApps`, protégés), pas un dossier de développement ou du profil
pub(crate) fn racine_systeme_de_paquets(racine: &str, windows: &str, program_files: &str) -> bool {
    let r = racine.trim().to_ascii_lowercase().replace('/', "\\");
    let sous = |base: &str, dossier: &str| {
        let b = format!(r"{}\{dossier}\", base.trim().trim_end_matches('\\').to_ascii_lowercase());
        !base.trim().is_empty() && r.starts_with(&b) && r.len() > b.len()
    };
    // Aucun segment « .. » (ni fait seulement de points et d'espaces) : la racine ne remonte pas hors de ces dossiers
    if r.split('\\').any(|p| !p.is_empty() && p.chars().all(|c| c == '.' || c == ' ')) {
        return false;
    }
    sous(windows, "systemapps") || sous(program_files, "windowsapps")
}

/// Décision pure (testée) : version d'un nom complet de paquet (« Nom_1000.26100.372.0_x64__éditeur »), comparée
/// nombre par nombre (« 100 » après « 99 »)
pub(crate) fn version_paquet(nom: &str) -> Vec<u64> {
    nom.split('_').nth(1).unwrap_or("").split('.').map(|n| n.parse().unwrap_or(0)).collect()
}

/// Décision pure (testée) : chemin d'un fichier du paquet. Le chemin relatif lu dans le registre ne doit pas sortir du
/// dossier du paquet : ni absolu, ni lecteur, ni « .. », ni flux NTFS
pub(crate) fn chemin_dans_paquet(racine: &str, relatif: &str) -> Option<String> {
    let r = relatif.trim().trim_start_matches(['\\', '/']);
    // Un segment fait seulement de points et d'espaces (« .. », « ... », « . . ») est refusé : Win32 retire les points et
    // espaces de fin (audit de #83, S83-04)
    if racine.trim().is_empty() || r.is_empty() || r.contains(':') || r.split(['\\', '/']).any(|p| !p.is_empty() && p.chars().all(|c| c == '.' || c == ' ')) || relatif.trim().starts_with("\\\\") {
        return None;
    }
    Some(format!(r"{}\{}", racine.trim().trim_end_matches(['\\', '/']), r.replace('/', "\\")))
}

// ------------------------------------------------------------ relevé

fn releve_complet() -> Vec<EntreeDemarrage> {
    let mut l = Vec::new();
    registre(&mut l);
    services(&mut l);
    taches(&mut l);
    dossiers_demarrage(&mut l);
    if let Err(e) = wmi_consommateurs(&mut l) {
        commun::journal(&format!("relevé de persistance (WMI) : {e}"));
    }
    l
}

fn ajouter(l: &mut Vec<EntreeDemarrage>, categorie: &str, nom: &str, commande: &str) {
    if commande.trim().is_empty() {
        return;
    }
    l.push(EntreeDemarrage {
        cle: format!("{categorie}|{nom}"),
        categorie: categorie.into(),
        nom: nom.into(),
        commande: commande.trim().into(),
        ..Default::default()
    });
}

fn valeurs(l: &mut Vec<EntreeDemarrage>, racine: &RegKey, chemin: &str, drapeaux: u32, categorie: &str) {
    let Ok(k) = racine.open_subkey_with_flags(chemin, KEY_READ | drapeaux) else { return };
    for (nom, _) in k.enum_values().map_while(Result::ok) {
        if let Some(t) = texte_registre(&k, &nom) {
            ajouter(l, categorie, if nom.is_empty() { "(par défaut)" } else { &nom }, &t);
        }
    }
}

/// Valeur texte du registre ; REG_EXPAND_SZ est développé, comme le faisait le service C# (RegistryKey.GetValue)
fn texte_registre(k: &RegKey, nom: &str) -> Option<String> {
    let v = k.get_raw_value(nom).ok()?;
    let u: Vec<u16> = v.bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let fin = u.iter().position(|&c| c == 0).unwrap_or(u.len());
    let s = String::from_utf16_lossy(&u[..fin]);
    match v.vtype {
        REG_SZ => Some(s),
        REG_EXPAND_SZ => Some(developper(&s)),
        REG_DWORD => k.get_value::<u32, _>(nom).ok().map(|n| n.to_string()),
        _ => None,
    }
}

pub fn nom_utilisateur(sid: &str) -> String {
    // Nom d'utilisateur à partir du profil enregistré (évite une traduction de SID)
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(format!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}"))
        .ok()
        .and_then(|k| texte_registre(&k, "ProfileImagePath"))
        .and_then(|p| Path::new(&p).file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_else(|| sid.to_string())
}

pub fn sids_utilisateurs() -> Vec<String> {
    RegKey::predef(HKEY_USERS)
        .enum_keys()
        .map_while(Result::ok)
        .filter(|s| s.starts_with("S-1-5-21-") && !s.ends_with("_Classes"))
        .collect()
}

fn registre(l: &mut Vec<EntreeDemarrage>) {
    const RUN: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    const RUN_ONCE: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";
    const NT: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    valeurs(l, &hklm, RUN, KEY_WOW64_64KEY, "Run (machine)");
    valeurs(l, &hklm, RUN_ONCE, KEY_WOW64_64KEY, "RunOnce (machine)");
    valeurs(l, &hklm, RUN, KEY_WOW64_32KEY, "Run (machine, 32 bits)");
    valeurs(l, &hklm, RUN_ONCE, KEY_WOW64_32KEY, "RunOnce (machine, 32 bits)");
    if let Ok(w) = hklm.open_subkey(format!(r"{NT}\Winlogon")) {
        for v in ["Shell", "Userinit"] {
            if let Some(t) = texte_registre(&w, v) {
                ajouter(l, "Winlogon", v, &t);
            }
        }
    }
    if let Ok(ifeo) = hklm.open_subkey(format!(r"{NT}\Image File Execution Options")) {
        for exe in ifeo.enum_keys().map_while(Result::ok) {
            if let Some(d) = ifeo.open_subkey(&exe).ok().and_then(|k| texte_registre(&k, "Debugger")) {
                ajouter(l, "IFEO", &exe, &d);
            }
        }
    }
    if let Ok(w) = hklm.open_subkey(format!(r"{NT}\Windows")) {
        if w.get_value::<u32, _>("LoadAppInit_DLLs").unwrap_or(0) == 1 {
            if let Some(d) = texte_registre(&w, "AppInit_DLLs") {
                ajouter(l, "AppInit", "AppInit_DLLs", &d);
            }
        }
    }
    let hku = RegKey::predef(HKEY_USERS);
    for sid in sids_utilisateurs() {
        let u = nom_utilisateur(&sid);
        valeurs(l, &hku, &format!(r"{sid}\{RUN}"), 0, &format!("Run ({u})"));
        valeurs(l, &hku, &format!(r"{sid}\{RUN_ONCE}"), 0, &format!("RunOnce ({u})"));
        if let Some(s) = hku.open_subkey(format!(r"{sid}\{NT}\Winlogon")).ok().and_then(|k| texte_registre(&k, "Shell")) {
            ajouter(l, &format!("Winlogon ({u})"), "Shell", &s);
        }
    }
}

fn services(l: &mut Vec<EntreeDemarrage>) {
    let Ok(services) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(r"SYSTEM\CurrentControlSet\Services") else { return };
    for nom in services.enum_keys().map_while(Result::ok) {
        let Ok(k) = services.open_subkey(&nom) else { continue };
        let demarrage = k.get_value::<u32, _>("Start").unwrap_or(4);
        let Some(mut image) = texte_registre(&k, "ImagePath") else { continue };
        if demarrage > 2 || image.is_empty() {
            continue; // démarrage automatique seulement
        }
        let pilote = k.get_value::<u32, _>("Type").map(|t| t & 0x3 != 0).unwrap_or(false);
        // Les services hébergés par svchost chargent une DLL : c'est elle qui compte
        if image.to_lowercase().contains("svchost.exe") {
            if let Some(dll) = k.open_subkey("Parameters").ok().and_then(|p| texte_registre(&p, "ServiceDll")) {
                image = dll;
            }
        }
        ajouter(l, if pilote { "Pilote" } else { "Service" }, &nom, &image);
    }
}

fn taches(l: &mut Vec<EntreeDemarrage>) {
    let racine = format!(r"{}\Tasks", natif::dossier_systeme());
    let action = Regex::new(r"(?s)<Command>(.*?)</Command>(?:\s*<Arguments>(.*?)</Arguments>)?").unwrap();
    let com = Regex::new(r"(?s)<ComHandler>\s*<ClassId>(.*?)</ClassId>").unwrap();
    let desactivee = Regex::new(r"(?s)<Settings>.*?<Enabled>false</Enabled>").unwrap();
    let mut pile = vec![std::path::PathBuf::from(&racine)];
    while let Some(d) = pile.pop() {
        let Ok(entrees) = fs::read_dir(&d) else { continue };
        for e in entrees.map_while(Result::ok) {
            let p = e.path();
            if p.is_dir() {
                pile.push(p);
                continue;
            }
            let Ok(octets) = fs::read(&p) else { continue };
            let xml = decoder_texte(&octets);
            let mut nom = p.to_string_lossy()[racine.len()..].to_string();
            if desactivee.is_match(&xml) {
                nom.push_str(" (désactivée)");
            }
            if let Some(m) = action.captures(&xml) {
                let cmd = format!("{} {}", &m[1], m.get(2).map(|a| a.as_str()).unwrap_or(""));
                ajouter(l, "Tâche planifiée", &nom, &decoder_entites(cmd.trim()));
            } else if let Some(c) = com.captures(&xml) {
                ajouter(l, "Tâche planifiée", &nom, &commande_com(&c[1]));
            }
        }
    }
}

/// Les fichiers de tâches sont en UTF-16 (avec BOM) ; certains en UTF-8
fn decoder_texte(o: &[u8]) -> String {
    if o.len() >= 2 && o[0] == 0xFF && o[1] == 0xFE {
        let u: Vec<u16> = o[2..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&u)
    } else {
        String::from_utf8_lossy(o).trim_start_matches('\u{feff}').to_string()
    }
}

fn decoder_entites(s: &str) -> String {
    s.replace("&quot;", "\"").replace("&lt;", "<").replace("&gt;", ">").replace("&apos;", "'").replace("&amp;", "&")
}

fn cible_raccourci(fichier: &str) -> Option<String> {
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        let lien: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER).ok()?;
        let p: IPersistFile = lien.cast().ok()?;
        let f = large(fichier);
        p.Load(PCWSTR(f.as_ptr()), STGM_READ).ok()?;
        let mut cible = [0u16; 1024];
        lien.GetPath(&mut cible, std::ptr::null_mut(), 0).ok()?;
        let mut args = [0u16; 1024];
        let _ = lien.GetArguments(&mut args);
        let t = |b: &[u16]| String::from_utf16_lossy(&b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]);
        Some(format!("\"{}\" {}", t(&cible), t(&args)))
    }
}

fn dossiers_demarrage(l: &mut Vec<EntreeDemarrage>) {
    const RELATIF: &str = r"Microsoft\Windows\Start Menu\Programs\Startup";
    let mut dossiers = vec![format!(r"{}\{RELATIF}", std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into()))];
    let utilisateurs = format!(r"{}\Users", &natif::dossier_windows()[..2]);
    if let Ok(u) = fs::read_dir(&utilisateurs) {
        for e in u.map_while(Result::ok) {
            dossiers.push(format!(r"{}\AppData\Roaming\{RELATIF}", e.path().to_string_lossy()));
        }
    }
    for d in dossiers {
        let Ok(fichiers) = fs::read_dir(&d) else { continue };
        for f in fichiers.map_while(Result::ok) {
            let chemin = f.path().to_string_lossy().to_string();
            if chemin.to_lowercase().ends_with("desktop.ini") || f.path().is_dir() {
                continue;
            }
            let commande = if chemin.to_lowercase().ends_with(".lnk") { cible_raccourci(&chemin).unwrap_or_else(|| chemin.clone()) } else { chemin.clone() };
            ajouter(l, "Dossier Démarrage", &chemin, &commande);
        }
    }
}

fn wmi_consommateurs(l: &mut Vec<EntreeDemarrage>) -> Result<(), wmi::WMIError> {
    use wmi::{COMLibrary, Variant, WMIConnection};
    let com = unsafe { COMLibrary::assume_initialized() };
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
    }
    let con = WMIConnection::with_namespace_path(r"root\subscription", com)?;
    let resultats: Vec<HashMap<String, Variant>> = con.raw_query("SELECT * FROM __EventConsumer")?;
    for o in resultats {
        let texte = |cle: &str| match o.get(cle) {
            Some(Variant::String(s)) if !s.is_empty() => Some(s.clone()),
            _ => None,
        };
        let nom = texte("Name").unwrap_or_default();
        if nom == "SCM Event Log Consumer" {
            continue; // présent par défaut sur Windows
        }
        let classe = texte("__CLASS").unwrap_or_else(|| "__EventConsumer".into());
        let commande = ["CommandLineTemplate", "ExecutablePath", "ScriptText", "ScriptFileName"]
            .iter()
            .find_map(|c| texte(c))
            .unwrap_or_else(|| format!("(consommateur {classe})"));
        ajouter(l, "WMI", &format!("{classe} : {nom}"), &commande);
    }
    Ok(())
}
