//! Hygiène et pièges :
//!   - leurres anti-rançongiciel : fichiers cachés placés en tête de Documents, Images et Bureau ;
//!     un rançongiciel les chiffre en premier. Audit d'écriture (4663) pour savoir qui les touche ;
//!   - pilotes vulnérables ou malveillants connus (liste LOLDrivers, technique BYOVD) ;
//!   - extensions de navigateur : inventaire, permissions dangereuses, nouvelles extensions.

use crate::commun::{self, Alerte};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn alerte(niveau: &str, score: i32, processus: &str, chemin: &str, destination: &str, raisons: String) -> Alerte {
    Alerte {
        id: commun::nouvel_id(),
        heure: commun::maintenant(),
        niveau: niveau.into(),
        score,
        processus: processus.into(),
        chemin: chemin.into(),
        destination: destination.into(),
        raisons,
        ..Default::default()
    }
}

/// Profils des modèles de Windows : jamais de leurres ni d'inventaire dedans
const PROFILS_MODELES: &[&str] = &["default", "default user", "public", "all users", "defaultapppool"];

fn profils_modeles() -> Vec<PathBuf> {
    let racine = format!(r"{}\Users", &crate::natif::dossier_windows()[..2]);
    PROFILS_MODELES.iter().map(|n| Path::new(&racine).join(n)).collect()
}

fn profils() -> Vec<PathBuf> {
    let racine = format!(r"{}\Users", &crate::natif::dossier_windows()[..2]);
    fs::read_dir(racine)
        .map(|d| {
            d.map_while(Result::ok)
                .filter(|e| !PROFILS_MODELES.contains(&e.file_name().to_string_lossy().to_lowercase().as_str()))
                .map(|e| e.path())
                .filter(|p| p.join("NTUSER.DAT").exists())
                .collect()
        })
        .unwrap_or_default()
}

/// Retire les leurres posés par erreur dans les profils modèles (versions précédentes)
fn retirer_leurres_modeles() {
    for profil in profils_modeles() {
        for (dossier, nom) in ANCIENS_LEURRES.iter().map(|(d, n)| (d.to_string(), n.to_string())).chain(noms_leurres()) {
            let f = profil.join(dossier).join(nom);
            if f.exists() {
                let _ = Command::new("attrib.exe").args(["-h", "-s"]).arg(&f).creation_flags(0x0800_0000).output();
                let _ = fs::remove_file(&f);
            }
        }
    }
}

// ------------------------------------------------------------ leurres

/// Anciens noms fixes (publiés dans le code) : retirés et remplacés
const ANCIENS_LEURRES: &[(&str, &str)] = &[
    (r"Documents", "!000-deR4Tizer-leurre.docx"),
    (r"Pictures", "!000-deR4Tizer-leurre.jpg"),
    (r"Desktop", "!000-deR4Tizer-leurre.xlsx"),
];

/// Noms des leurres, tirés au hasard à l'installation (leurres-noms.json) : un rançongiciel qui lit ce code
/// ne peut pas les reconnaître. Ils commencent par « 0 » pour être parmi les premiers fichiers parcourus.
pub fn noms_leurres() -> Vec<(String, String)> {
    if let Some(l) = commun::lire::<Vec<(String, String)>>(FICHIER_NOMS).filter(|l| !l.is_empty()) {
        return l;
    }
    crate::notifications::preparer_dossier();
    let mut graine = commun::filetime(std::time::SystemTime::now()) ^ ((std::process::id() as u64) << 32);
    let mut hasard = |n: u64| {
        graine ^= graine << 13;
        graine ^= graine >> 7;
        graine ^= graine << 17;
        graine % n
    };
    let docs = ["0 Factures {}.docx", "0 Contrat {}.docx", "0 Devis {}.docx", "0 Archives {}.docx"];
    let images = ["0 IMG_{}.jpg", "0 Scan_{}.jpg", "0 Photo {}.jpg"];
    let bureau = ["0 Comptabilité {}.xlsx", "0 Budget {}.xlsx", "0 Clients {}.xlsx"];
    let mut l = Vec::new();
    for (dossier, modeles) in [("Documents", &docs[..]), ("Pictures", &images[..]), ("Desktop", &bureau[..])] {
        let modele = modeles[hasard(modeles.len() as u64) as usize];
        l.push((dossier.to_string(), modele.replace("{}", &(1000 + hasard(9000)).to_string())));
    }
    commun::ecrire(FICHIER_NOMS, &l);
    l
}

/// Noms et chemins des leurres : dans secrets\ (SYSTEM et administrateurs seulement). Dans le dossier de
/// données, le compte connecté pourrait les lire, et un rançongiciel lancé sous ce compte les éviterait.
pub const FICHIER_NOMS: &str = r"secrets\leurres-noms.json";
pub const FICHIER_LEURRES: &str = r"secrets\leurres.json";

/// Anciennes listes lisibles (versions précédentes) : leurres retirés et renommés, listes effacées
pub fn migrer_leurres() {
    let anciens: Vec<(String, String)> = commun::lire("leurres-noms.json").unwrap_or_default();
    if anciens.is_empty() && !commun::dossier().join("leurres.json").exists() {
        return;
    }
    for profil in profils() {
        for (dossier, nom) in &anciens {
            let f = profil.join(dossier).join(nom);
            if f.exists() {
                let _ = Command::new("attrib.exe").args(["-h", "-s"]).arg(&f).creation_flags(0x0800_0000).output();
                let _ = fs::remove_file(&f);
            }
        }
    }
    let _ = fs::remove_file(commun::dossier().join("leurres-noms.json"));
    let _ = fs::remove_file(commun::dossier().join("leurres.json"));
    commun::journal("leurres : anciens noms (lisibles par le compte connecté) remplacés par de nouveaux, rangés dans secrets\\");
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(default)]
pub struct Leurre {
    pub chemin: String,
    pub empreinte: String,
}

pub fn empreinte_fichier(chemin: &Path) -> Option<String> {
    let mut f = fs::OpenOptions::new().read(true).share_mode(7).open(chemin).ok()?;
    let mut h = Sha256::new();
    let mut tampon = [0u8; 65536];
    loop {
        let n = f.read(&mut tampon).ok()?;
        if n == 0 {
            break;
        }
        h.update(&tampon[..n]);
    }
    Some(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Crée les leurres manquants (cachés), leur pose un audit d'écriture, et renvoie la liste
pub fn poser_leurres() -> Vec<Leurre> {
    migrer_leurres();
    retirer_leurres_modeles();
    // Anciens leurres à nom fixe : retirés des profils
    for profil in profils() {
        for (dossier, nom) in ANCIENS_LEURRES {
            let f = profil.join(dossier).join(nom);
            if f.exists() {
                let _ = Command::new("attrib.exe").args(["-h", "-s"]).arg(&f).creation_flags(0x0800_0000).output();
                let _ = fs::remove_file(&f);
            }
        }
    }
    let noms = noms_leurres();
    let mut liste = Vec::new();
    let mut a_auditer = Vec::new();
    for profil in profils() {
        for (dossier, nom) in &noms {
            let d = profil.join(dossier);
            if !d.is_dir() {
                continue;
            }
            let f = d.join(nom);
            if !f.exists() {
                // Contenu sans importance mais stable ; taille réaliste
                let contenu: Vec<u8> = (0..24_576u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
                if fs::write(&f, contenu).is_err() {
                    continue;
                }
                let _ = Command::new("attrib.exe").args(["+h", "+s"]).arg(&f).creation_flags(0x0800_0000).output();
            }
            if let Some(e) = empreinte_fichier(&f) {
                a_auditer.push(f.to_string_lossy().to_string());
                liste.push(Leurre { chemin: f.to_string_lossy().to_string(), empreinte: e });
            }
        }
    }
    // Audit d'écriture et de suppression : l'événement 4663 dira quel programme les a touchés
    if !a_auditer.is_empty() {
        let mut script = String::from("$ErrorActionPreference='SilentlyContinue'\n");
        for f in &a_auditer {
            script.push_str(&format!(
                "$a = Get-Acl -LiteralPath '{0}' -Audit; $a.AddAuditRule((New-Object Security.AccessControl.FileSystemAuditRule((New-Object Security.Principal.SecurityIdentifier 'S-1-1-0'),'WriteData,AppendData,Delete','None','None','Success'))); Set-Acl -LiteralPath '{0}' -AclObject $a\n",
                f.replace('\'', "''")
            ));
        }
        let _ = Command::new("powershell.exe").args(["-NoProfile", "-NonInteractive", "-Command", &script]).creation_flags(0x0800_0000).output();
    }
    commun::ecrire(FICHIER_LEURRES, &liste);
    liste
}

/// Vérifie les leurres : modifié ou disparu = rançongiciel probable
pub fn verifier_leurres(liste: &mut Vec<Leurre>) -> Vec<Alerte> {
    let mut a = Vec::new();
    for l in liste.iter_mut() {
        let p = Path::new(&l.chemin);
        let etat = if !p.exists() { Some("SUPPRIMÉ ou RENOMMÉ") } else if empreinte_fichier(p).as_deref() != Some(l.empreinte.as_str()) { Some("MODIFIÉ") } else { None };
        if let Some(e) = etat {
            a.push(alerte("Critique", 15, "?", "", "leurre anti-rançongiciel",
                format!("fichier leurre {e} : {} — un RANÇONGICIEL est probablement en train de chiffrer vos fichiers. Utilisez le bouton PANIQUE et éteignez le PC si nécessaire.", l.chemin)));
            l.empreinte = String::from("alerte");
        }
    }
    liste.retain(|l| l.empreinte != "alerte");
    a
}

/// Événement 4663 sur un leurre : renvoie le PID du programme qui l'a touché
pub fn pid_touchant_leurre(xml: &str) -> Option<(u32, String, String)> {
    let d = crate::evenements::donnees(xml);
    let objet = d.get("ObjectName")?;
    let nom = Path::new(objet.as_str()).file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
    if !noms_leurres().iter().any(|(_, n)| n.to_lowercase() == nom) {
        return None;
    }
    let pid = u32::from_str_radix(d.get("ProcessId")?.trim_start_matches("0x"), 16).ok()?;
    Some((pid, d.get("ProcessName").cloned().unwrap_or_default(), objet.clone()))
}

// ------------------------------------------------------------ pilotes vulnérables (LOLDrivers)

/// Télécharge la liste LOLDrivers (une fois par jour) et renvoie l'ensemble des empreintes SHA-256
pub fn liste_loldrivers() -> HashSet<String> {
    let f = commun::dossier().join(r"menaces\loldrivers.json");
    let recent = fs::metadata(&f).and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).map(|d| d.as_secs() < 86400).unwrap_or(false);
    if !recent {
        let _ = fs::create_dir_all(commun::dossier().join("menaces"));
        let _ = Command::new("curl.exe")
            .args(["-sSL", "--fail", "--max-time", "300", "-o"])
            .arg(f.with_extension("tmp"))
            .arg("https://www.loldrivers.io/api/drivers.json")
            .creation_flags(0x0800_0000)
            .output()
            .ok()
            .filter(|s| s.status.success())
            .and_then(|_| fs::rename(f.with_extension("tmp"), &f).ok());
    }
    let Ok(t) = fs::read_to_string(&f) else { return HashSet::new() };
    Regex::new(r#""SHA256":\s*"([0-9a-fA-F]{64})""#).unwrap().captures_iter(&t).map(|c| c[1].to_lowercase()).collect()
}

/// Chemin d'un ImagePath de service ou de pilote (« \\SystemRoot\\… », « \\??\\C:\\… », « System32\\… »)
pub fn chemin_image(image: &str) -> PathBuf {
    let windows = crate::natif::dossier_windows();
    let i = image.trim().trim_matches('"');
    let i = i.strip_prefix(r"\??\").unwrap_or(i);
    // get() et non [..] : l'ImagePath vient d'un service installé par n'importe quel programme administrateur ;
    // un découpage au milieu d'un caractère UTF-8 ferait paniquer le service
    if i.get(..11).is_some_and(|p| p.eq_ignore_ascii_case(r"\SystemRoot")) {
        return PathBuf::from(format!("{windows}{}", &i[11..]));
    }
    if i.len() > 9 && i.get(..9).is_some_and(|p| p.eq_ignore_ascii_case(r"System32\")) {
        return PathBuf::from(&windows).join(i);
    }
    PathBuf::from(i)
}

/// Pilote connu de LOLDrivers. La liste est gardée en mémoire et rechargée une fois par jour par un fil à part :
/// l'appelant (le fil de corrélation du SIEM) n'attend jamais un téléchargement.
pub fn pilote_vulnerable(chemin: &Path) -> Option<String> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::{Duration, Instant};
    static CACHE: OnceLock<Arc<Mutex<(Option<Instant>, Arc<HashSet<String>>)>>> = OnceLock::new();
    static EN_COURS: AtomicBool = AtomicBool::new(false);
    let cache = CACHE.get_or_init(|| Arc::new(Mutex::new((None, Arc::new(HashSet::new()))))).clone();
    let (perime, liste) = {
        let c = cache.lock().unwrap();
        (c.0.map(|t| t.elapsed() > Duration::from_secs(86_400)).unwrap_or(true), c.1.clone())
    };
    if perime && !EN_COURS.swap(true, Ordering::SeqCst) {
        let c = cache.clone();
        std::thread::spawn(move || {
            let nouvelle = Arc::new(liste_loldrivers());
            *c.lock().unwrap() = (Some(Instant::now()), nouvelle);
            EN_COURS.store(false, Ordering::SeqCst);
        });
    }
    let h = empreinte_fichier(chemin)?;
    liste.contains(&h).then_some(h)
}

/// Pilotes déclarés dans le registre (services de type 1 ou 2), y compris en démarrage manuel et hors du
/// dossier drivers (un .sys posé dans %TEMP% puis lancé par « sc start »)
fn pilotes_declares() -> Vec<PathBuf> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let mut l = Vec::new();
    let Ok(services) = winreg::RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(r"SYSTEM\CurrentControlSet\Services") else { return l };
    for nom in services.enum_keys().map_while(Result::ok) {
        let Ok(k) = services.open_subkey(&nom) else { continue };
        let type_: u32 = k.get_value("Type").unwrap_or(0);
        if type_ != 1 && type_ != 2 {
            continue;
        }
        if let Ok(image) = k.get_value::<String, _>("ImagePath") {
            let p = chemin_image(&image);
            if p.is_file() {
                l.push(p);
            }
        }
    }
    l
}

/// Compare les pilotes présents (dossier drivers et pilotes déclarés) à la liste
pub fn verifier_pilotes(connus: &HashSet<String>, deja: &mut HashSet<String>) -> Vec<Alerte> {
    let mut a = Vec::new();
    if connus.is_empty() {
        return a;
    }
    let dossier = PathBuf::from(crate::natif::dossier_systeme()).join("drivers");
    let mut chemins: Vec<PathBuf> = fs::read_dir(&dossier).map(|d| d.map_while(Result::ok).map(|e| e.path()).collect()).unwrap_or_default();
    for p in pilotes_declares() {
        if !chemins.iter().any(|c| c.as_os_str().eq_ignore_ascii_case(p.as_os_str())) {
            chemins.push(p);
        }
    }
    for p in chemins {
        if p.extension().map(|x| !x.eq_ignore_ascii_case("sys")).unwrap_or(true) {
            continue;
        }
        let Some(h) = empreinte_fichier(&p) else { continue };
        if connus.contains(&h) && deja.insert(h.clone()) {
            a.push(alerte("Critique", 10, &p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(),
                &p.to_string_lossy(), "pilote vulnérable",
                format!("PILOTE VULNÉRABLE OU MALVEILLANT CONNU (LOLDrivers, SHA-256 {}…) : technique « BYOVD » utilisée pour désactiver les antivirus  [MITRE T1068]", &h[..16])));
        }
    }
    a
}

// ------------------------------------------------------------ extensions de navigateur

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct Extension {
    pub navigateur: String,
    pub id: String,
    pub nom: String,
    pub version: String,
    pub permissions: String,
    pub dangereuse: bool,
    pub depuis: String,
}

const PERMISSIONS_DANGEREUSES: &[&str] = &[
    "<all_urls>", "*://*/*", "http://*/*", "https://*/*", "cookies", "webRequest", "webRequestBlocking", "declarativeNetRequest",
    "clipboardRead", "nativeMessaging", "debugger", "proxy", "management", "history", "downloads", "scripting",
];

fn texte_json(v: &serde_json::Value) -> Vec<String> {
    v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
}

/// Nom lisible d'une extension Chromium (« __MSG_nom__ » renvoie vers _locales)
fn nom_chromium(dossier: &Path, manifeste: &serde_json::Value) -> String {
    let nom = manifeste["name"].as_str().unwrap_or("").to_string();
    let Some(cle) = nom.strip_prefix("__MSG_").and_then(|n| n.strip_suffix("__")) else { return nom };
    for langue in ["fr", "en", "en_US"] {
        if let Ok(t) = fs::read_to_string(dossier.join("_locales").join(langue).join("messages.json")) {
            if let Ok(m) = serde_json::from_str::<serde_json::Value>(t.trim_start_matches('\u{feff}')) {
                if let Some(obj) = m.as_object() {
                    if let Some((_, v)) = obj.iter().find(|(k, _)| k.eq_ignore_ascii_case(cle)) {
                        return v["message"].as_str().unwrap_or(&nom).to_string();
                    }
                }
            }
        }
    }
    nom
}

pub fn inventaire_extensions() -> Vec<Extension> {
    let mut l = Vec::new();
    let navigateurs = [
        ("Chrome", r"AppData\Local\Google\Chrome\User Data"),
        ("Brave", r"AppData\Local\BraveSoftware\Brave-Browser\User Data"),
        ("Edge", r"AppData\Local\Microsoft\Edge\User Data"),
    ];
    for profil in profils() {
        for (nav, rel) in navigateurs {
            let donnees = profil.join(rel);
            let Ok(sous) = fs::read_dir(&donnees) else { continue };
            for p in sous.map_while(Result::ok).map(|e| e.path()).filter(|p| p.join("Extensions").is_dir()) {
                let Ok(exts) = fs::read_dir(p.join("Extensions")) else { continue };
                for ext in exts.map_while(Result::ok) {
                    let id = ext.file_name().to_string_lossy().to_string();
                    // Dernière version installée
                    let Some(version) = fs::read_dir(ext.path()).ok().and_then(|v| v.map_while(Result::ok).map(|e| e.path()).filter(|p| p.join("manifest.json").exists()).max()) else { continue };
                    let Ok(t) = fs::read_to_string(version.join("manifest.json")) else { continue };
                    let Ok(m) = serde_json::from_str::<serde_json::Value>(t.trim_start_matches('\u{feff}')) else { continue };
                    let mut perms = texte_json(&m["permissions"]);
                    perms.extend(texte_json(&m["host_permissions"]));
                    if let Some(cs) = m["content_scripts"].as_array() {
                        perms.extend(cs.iter().flat_map(|c| texte_json(&c["matches"])));
                    }
                    perms.sort();
                    perms.dedup();
                    let dangereuse = perms.iter().any(|x| PERMISSIONS_DANGEREUSES.contains(&x.as_str()));
                    l.push(Extension {
                        navigateur: format!("{nav} ({})", p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()),
                        id: id.clone(),
                        nom: nom_chromium(&version, &m),
                        version: m["version"].as_str().unwrap_or("").into(),
                        permissions: perms.join(", "),
                        dangereuse,
                        depuis: String::new(),
                    });
                }
            }
        }
        // Firefox : extensions.json de chaque profil
        if let Ok(pf) = fs::read_dir(profil.join(r"AppData\Roaming\Mozilla\Firefox\Profiles")) {
            for p in pf.map_while(Result::ok) {
                let Ok(t) = fs::read_to_string(p.path().join("extensions.json")) else { continue };
                let Ok(m) = serde_json::from_str::<serde_json::Value>(&t) else { continue };
                for a in m["addons"].as_array().cloned().unwrap_or_default() {
                    if a["location"].as_str() != Some("app-profile") {
                        continue; // extensions intégrées à Firefox
                    }
                    let mut perms = texte_json(&a["userPermissions"]["permissions"]);
                    perms.extend(texte_json(&a["userPermissions"]["origins"]));
                    let dangereuse = perms.iter().any(|x| PERMISSIONS_DANGEREUSES.contains(&x.as_str()));
                    l.push(Extension {
                        navigateur: "Firefox".into(),
                        id: a["id"].as_str().unwrap_or("").into(),
                        nom: a["defaultLocale"]["name"].as_str().unwrap_or("").into(),
                        version: a["version"].as_str().unwrap_or("").into(),
                        permissions: perms.join(", "),
                        dangereuse,
                        depuis: String::new(),
                    });
                }
            }
        }
    }
    l
}

/// Compare à l'inventaire précédent : alerte sur chaque nouvelle extension (sauf au premier relevé)
pub fn verifier_extensions() -> (Vec<Extension>, Vec<Alerte>) {
    let connues: Option<HashMap<String, String>> = commun::lire("extensions-connues.json");
    let apprentissage = connues.is_none();
    let mut connues = connues.unwrap_or_default();
    let mut liste = inventaire_extensions();
    let mut alertes = Vec::new();
    for e in liste.iter_mut() {
        let cle = format!("{}|{}", e.navigateur, e.id);
        match connues.get(&cle) {
            Some(d) => e.depuis = d.clone(),
            None => {
                e.depuis = commun::maintenant();
                connues.insert(cle, e.depuis.clone());
                if !apprentissage {
                    alertes.push(alerte(if e.dangereuse { "Alerte" } else { "Info" }, if e.dangereuse { 4 } else { 0 }, &e.nom, "",
                        &format!("extension {}", e.navigateur),
                        format!("NOUVELLE extension de navigateur « {} » {}{}", e.nom, e.version,
                            if e.dangereuse { format!(" avec des permissions sensibles ({}) : vérifiez que vous l'avez installée vous-même  [MITRE T1176]", e.permissions) } else { String::new() })));
                }
            }
        }
    }
    commun::ecrire("extensions-connues.json", &connues);
    liste.sort_by(|a, b| b.dangereuse.cmp(&a.dangereuse).then(a.nom.to_lowercase().cmp(&b.nom.to_lowercase())));
    commun::ecrire("extensions.json", &liste);
    (liste, alertes)
}
