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
    /// Dernier relevé des tâches tronqué ou hors délai : collecte « partielle » (relecture de #103, D2)
    pub incomplet: bool,
    /// Nouvelles tâches en attente d'être relevées : tour de leur première vue (S106-13)
    attente_taches: HashMap<String, u64>,
    tours_taches: u64,
    /// Relevé des tâches hors délai depuis cet instant : au-delà de 30 min, collecte indisponible (S103-06)
    bloque_depuis: Option<std::time::Instant>,
    /// Entrées devenues suspectes au relevé précédent, à confirmer au suivant (anti-rebond de « DEVENU SUSPECT »)
    en_attente: std::collections::HashSet<String>,
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
        Persistance { reference, apprentissage, entrees: Vec::new(), incomplet: false, attente_taches: HashMap::new(), tours_taches: 0, bloque_depuis: None, en_attente: Default::default() }
    }

    pub fn bloque_depuis_longtemps(&self) -> bool {
        releve_bloque(self.bloque_depuis.map(|t| t.elapsed()))
    }

    pub fn verifier(&mut self, signataire: &mut dyn FnMut(&str) -> String) -> Vec<Alerte> {
        let mut releve = dedupliquer_releve(releve_complet());
        if !self.apprentissage {
            self.tours_taches += 1;
            plafonner_nouvelles_taches(&self.reference, &mut releve, MAX_NOUVELLES_TACHES, &mut self.attente_taches, self.tours_taches);
        }
        let hors_delai = releve.iter().any(|e| e.anomalie && e.nom == anomalie_incomplet(QUOI_DELAI).0);
        self.bloque_depuis = if hors_delai { self.bloque_depuis.or(Some(std::time::Instant::now())) } else { None };
        self.incomplet = garder_taches_non_vues(&self.reference, &mut releve);
        for e in releve.iter_mut() {
            e.cible = cible(&e.commande);
            // Cible absolue seulement : un nom relatif non résolu serait cherché dans le dossier courant du service
            e.signataire = if !Path::new(&e.cible).is_absolute() || !Path::new(&e.cible).exists() { "?".into() } else { signataire(&e.cible) };
            e.remarque = evaluer(e);
        }
        let (alertes, modifie) = comparer(&self.reference, &mut releve, self.apprentissage, &mut self.en_attente);
        self.reference = releve.iter().map(|e| (e.cle.clone(), e.clone())).collect();
        if modifie {
            let _ = commun::ecrire("demarrage.json", &releve);
        }
        self.entrees = releve;
        // Même si ce premier relevé est incomplet : prolonger l'apprentissage ferait taire PER-001 et PER-002 pour tout le relevé tant
        // qu'il le reste, ce qu'un compte standard obtiendrait avec 65 fichiers vides (audit de #103, S103-10). Le prix : une seule
        // vague de « NOUVEAU » pour les tâches non lues
        self.apprentissage = false;
        alertes
    }
}

/// Décision pure (testée, PER-001 et PER-002) : compare un relevé, déjà évalué (cible, signataire, remarque), à la
/// référence. Entrée inconnue : NOUVELLE (PER-001) ; commande changée : MODIFIÉE (PER-002) ; commande inchangée mais
/// entrée DEVENUE SUSPECTE, sans remarque avant, avec une remarque maintenant (PER-002, PR 3.6 : une classe COM surchargée
/// après coup dans le profil d'un utilisateur, un fichier remplacé par un fichier non signé…), si la remarque est encore
/// là au relevé suivant (`en_attente` : une vérification de signature impossible un instant, au démarrage du PC par
/// exemple, ne lève rien) ; autre changement du signataire ou de la remarque : noté (référence réécrite), sans alerte.
/// Apprentissage : rien n'alerte. Rend (alertes, référence à réécrire).
pub(crate) fn comparer(reference: &HashMap<String, EntreeDemarrage>, releve: &mut [EntreeDemarrage], apprentissage: bool,
                       en_attente: &mut std::collections::HashSet<String>) -> (Vec<Alerte>, bool) {
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
                } else if ancienne.remarque.is_empty() && !e.remarque.is_empty() {
                    // Audit de #83, S83-06 : sinon une surcharge posée en deux temps ne serait jamais remontée ; confirmée
                    // au relevé suivant (relecture de #83, R3-D1 : vérification de signature passagèrement impossible)
                    if !apprentissage {
                        en_attente.insert(e.cle.clone());
                    }
                } else if en_attente.remove(&e.cle) && !e.remarque.is_empty() && !apprentissage {
                    alertes.push(alerter(e, "démarrage automatique MODIFIÉ, DEVENU SUSPECT (même commande)"));
                }
            }
            None => {
                e.depuis = commun::maintenant();
                modifie = true;
                // Une anomalie du dossier des tâches n'est pas apprise : présente au premier relevé, elle reste à dire (S103-02)
                if !apprentissage || e.anomalie {
                    alertes.push(alerter(e, "NOUVEAU démarrage automatique"));
                }
            }
        }
    }
    // Entrées disparues ou dont la commande a changé : plus rien à confirmer
    en_attente.retain(|c| releve.iter().any(|e| &e.cle == c && reference.get(c).is_some_and(|a| a.commande == e.commande)));
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
    if e.anomalie {
        r.push(REMARQUE_ANOMALIE_TACHES.into());
    }
    if e.categorie == "Tâche planifiée" && e.commande == ACTION_NON_RECONNUE {
        r.push("action non reconnue".into());
    }
    if e.categorie == "Tâche planifiée" && e.commande.contains(MARQUE_TRONQUEE) {
        r.push("commande tronquée".into());
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
    taches_a_echeance(&mut l);
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

/// Décision pure (testée) : un relevé hors délai depuis plus de 30 min n'est plus « partiel », et SAN-001 finira par le dire
pub(crate) fn releve_bloque(depuis: Option<std::time::Duration>) -> bool {
    depuis.is_some_and(|d| d.as_secs() > 1800)
}

/// Bornes de l'examen du dossier des tâches : les comptes authentifiés peuvent y créer des éléments, examinés toutes les minutes en
/// SYSTEM (audit de #102, S102-01). Rien n'y est ouvert : énumération et métadonnées seulement, qui ne bloquent pas
pub(crate) struct BornesTaches {
    pub profondeur: usize,
    pub par_dossier: usize,
    pub enumeres: usize,
    pub dossiers: usize,
    pub anomalies: usize,
}

const BORNES_TACHES: BornesTaches = BornesTaches { profondeur: 8, par_dossier: 5000, enumeres: 2_000_000, dossiers: 10_000, anomalies: 16 };

/// Tâches lues auprès du Planificateur par relevé (mesuré en VM le 2026-10-31 : 252 fichiers) ; au-delà, relevé incomplet
const MAX_TACHES: usize = 20_000;
const MAX_NIVEAUX_TACHES: usize = 16;
const MAX_DOSSIERS_TACHES: usize = 5000;
/// Longueur gardée d'une commande : le Planificateur accepte de très longs arguments, et chaque entrée est gardée et écrite (audit de #106, S106-06)
const MAX_COMMANDE_TACHE: usize = 4096;
/// Revérifications de fichiers inconnus par relevé : chacune interroge le Planificateur (audit de #106, S106-04)
const MAX_REVERIFICATIONS: usize = 32;
/// Nouvelles tâches par relevé : un compte standard peut en créer sans limite, et chaque alerte en chasse une vraie (audit de #106, S106-05)
const MAX_NOUVELLES_TACHES: usize = 16;

/// Échéance du relevé des tâches : un Planificateur qui ne répond pas ne doit pas faire taire toute la persistance (S103-04)
const ECHEANCE_TACHES: std::time::Duration = std::time::Duration::from_secs(30);

/// Début de la commande d'une entrée qui signale une anomalie du dossier, pas une tâche
pub(crate) const ANOMALIE_TACHES: &str = "Dossier des tâches : ";
/// Remarque d'une telle entrée, signal fort de l'apprentissage ; en minuscules, comparée à des raisons mises en minuscules
pub(crate) const REMARQUE_ANOMALIE_TACHES: &str = "élément anormal du dossier des tâches";

/// Le fichier existe-t-il, sous son nom exact ? Un chemin ordinaire perd les points et espaces finaux : un nom hostile paraîtrait absent (relecture de #106, S1)
pub(crate) fn existe_tel_quel(p: &Path) -> bool {
    let mut exact = std::ffi::OsString::from(r"\\?\");
    exact.push(p.as_os_str());
    fs::symlink_metadata(std::path::PathBuf::from(exact)).is_ok()
}

/// Ce que dit le Planificateur d'un fichier du dossier
#[derive(Debug, PartialEq, Clone, Copy)]
pub(crate) enum Fichier {
    Enregistre,
    SansTache,
    NonLisible,
    Inconnu,
}

/// Décision pure (testée) d'après l'erreur de `GetTask` : seule une panne de transport vers le Planificateur laisse sans conclusion ; sinon un nom ou une
/// tâche préparés par un compte standard épuiseraient les revérifications sans jamais être nommés (relecture de #106, R7, S3 ; audit S106-22)
pub(crate) fn verdict_reverification(code: u32) -> Fichier {
    match code {
        // Fichier ou chemin introuvable ; nom ou paramètre invalide
        0x8007_0002 | 0x8007_0003 | 0x8007_007B | 0x8007_0057 => Fichier::SansTache,
        // Transport : RPC (0x800706xx), COM (0x8001xxxx)
        c if c & 0xFFFF_FF00 == 0x8007_0600 || c & 0xFFFF_0000 == 0x8001_0000 => Fichier::Inconnu,
        // Accès refusé, image de tâche corrompue (SCHED_E_*), le reste
        _ => Fichier::NonLisible,
    }
}

/// Examine le dossier des tâches, pour ses seules anomalies : les tâches viennent du Planificateur, un fichier posé là n'en est pas une
/// (audit de #103, S103-02, S103-03). Aucun point d'analyse n'est suivi (jonction, lien), et le service n'y ouvre rien. `enregistree` dit si un nom
/// relatif correspond à une tâche ; elle n'est plus appelée une fois les anomalies au plafond. Rend les
/// anomalies (nom, motif), de libellés stables : un nombre dans le motif relèverait PER-002 à chaque relevé
pub(crate) fn examiner_dossier_taches(racine: &Path, b: &BornesTaches, enregistree: &mut dyn FnMut(&str, &Path) -> Fichier) -> Vec<(String, String)> {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    let longueur = racine.to_string_lossy().len();
    let mut anomalies: Vec<(String, String)> = Vec::new();
    let mut bornes = std::collections::BTreeSet::new();
    let (mut enumeres, mut dossiers) = (0usize, 0usize);
    let mut pile = vec![(racine.to_path_buf(), 0usize)];
    'parcours: while let Some((d, niveau)) = pile.pop() {
        let Ok(entrees) = fs::read_dir(&d) else { continue };
        for (rang, e) in entrees.map_while(Result::ok).enumerate() {
            enumeres += 1;
            if enumeres > b.enumeres {
                bornes.insert("éléments");
                break 'parcours;
            }
            let p = e.path();
            let nom = p.to_string_lossy()[longueur..].to_string();
            // Métadonnées de l'entrée elle-même : le lien n'est pas suivi
            let Ok(m) = e.metadata() else { continue };
            let lien = m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0;
            if m.is_dir() && !lien {
                if niveau + 1 >= b.profondeur {
                    bornes.insert("profondeur");
                } else if dossiers >= b.dossiers {
                    bornes.insert("dossiers");
                } else {
                    dossiers += 1;
                    pile.push((p, niveau + 1));
                }
                continue;
            }
            // Au-delà de la borne d'un dossier, ses fichiers ne sont plus examinés ; ses sous-dossiers, si
            if rang >= b.par_dossier {
                bornes.insert("éléments");
                continue;
            }
            if anomalies.len() >= b.anomalies {
                bornes.insert("anomalies");
                continue;
            }
            if lien {
                anomalies.push((nom, "lien non suivi".into()));
                continue;
            }
            match enregistree(&nom, &p) {
                Fichier::Enregistre => {}
                Fichier::SansTache => anomalies.push((nom, "fichier sans tâche enregistrée".into())),
                // Enregistrée mais illisible pour SYSTEM : nommée, c'est l'anomalie la plus nette (audit de #106, S106-08, S106-15)
                Fichier::NonLisible => anomalies.push((nom, "tâche enregistrée non lisible".into())),
                // Pas de conclusion, pas d'alerte : un Planificateur qui redémarre ne doit pas en lever (relecture de #106, D7)
                Fichier::Inconnu => {
                    bornes.insert("revérifications");
                }
            }
        }
    }
    // Ces bornes ne disent rien des tâches, lues ailleurs : pas un relevé incomplet
    anomalies.extend(bornes.into_iter().map(|k| (format!(r"\(dossier des tâches : {k})"), "examen du dossier arrêté, bornes atteintes".to_string())));
    anomalies
}

/// Garde la première entrée de chaque clé. Deux tâches peuvent donner la même clé (noms à surrogates seuls, que la conversion en texte confond) : commandes
/// différentes, une anomalie le dit, la seconde ne disparaît pas sans signal (pure, testée ; relecture de #106, S2)
pub(crate) fn dedupliquer_releve(releve: Vec<EntreeDemarrage>) -> Vec<EntreeDemarrage> {
    let mut vues: HashMap<String, String> = HashMap::new();
    let mut gardees = Vec::new();
    let mut doublons = Vec::new();
    for e in releve {
        match vues.get(&e.cle) {
            None => {
                vues.insert(e.cle.clone(), e.commande.clone());
                gardees.push(e);
            }
            Some(c) if e.categorie == "Tâche planifiée" && *c != e.commande => doublons.push(e.nom),
            Some(_) => {}
        }
    }
    for nom in doublons {
        if !vues.contains_key(&format!("Tâche planifiée|{nom} : doublon")) {
            vues.insert(format!("Tâche planifiée|{nom} : doublon"), String::new());
            ajouter_anomalie(&mut gardees, &format!("{nom} : doublon"), "deux tâches de même nom affiché, commandes différentes");
        }
    }
    gardees
}

/// Nouvelles tâches au-delà du plafond : retirées de ce relevé, donc de la référence, et levées aux relevés suivants ; une entrée le dit (pure, testée).
/// Par ancienneté, celles de `\\Microsoft` d'abord : l'ordre de lecture ne décide plus, et en créer de nouvelles ne retarde pas sans fin une tâche déjà vue
/// (audit de #106, S106-13). Une tâche supprimée pendant son attente n'est jamais levée ; `attente` ne garde que les tâches encore présentes
pub(crate) fn plafonner_nouvelles_taches(reference: &HashMap<String, EntreeDemarrage>, releve: &mut Vec<EntreeDemarrage>, max: usize, attente: &mut HashMap<String, u64>, tour: u64) {
    // Relevé incomplet : une tâche absente n'est pas supprimée, elle garde son rang (relecture de #106, S4)
    let complet = !releve.iter().any(|e| e.anomalie && e.nom.starts_with(PREFIXE_INCOMPLET));
    let est_nouvelle = |e: &EntreeDemarrage| e.categorie == "Tâche planifiée" && !e.anomalie && !reference.contains_key(&e.cle);
    let mut nouvelles: Vec<(bool, u64, String)> = releve.iter().filter(|e| est_nouvelle(e)).map(|e| {
        let vue = *attente.entry(e.cle.clone()).or_insert(tour);
        (!e.nom.to_lowercase().starts_with(r"\microsoft\"), vue, e.cle.clone())
    }).collect();
    let presentes: std::collections::HashSet<String> = nouvelles.iter().map(|n| n.2.clone()).collect();
    if complet {
        attente.retain(|c, _| presentes.contains(c));
    }
    if nouvelles.len() <= max {
        for n in &nouvelles {
            attente.remove(&n.2);
        }
        return;
    }
    nouvelles.sort();
    let gardees: std::collections::HashSet<String> = nouvelles.iter().take(max).map(|n| n.2.clone()).collect();
    for c in &gardees {
        attente.remove(c);
    }
    releve.retain(|e| !est_nouvelle(e) || gardees.contains(&e.cle));
    ajouter_anomalie(releve, r"\(relevé des tâches : nouvelles tâches plafonnées)", "nouvelles tâches au-delà du plafond par relevé, relevées aux suivants");
}

fn anomalie_incomplet(quoi: &str) -> (String, String) {
    (format!(r"{PREFIXE_INCOMPLET}{quoi})"), "relevé incomplet".to_string())
}

const PREFIXE_INCOMPLET: &str = r"\(relevé incomplet : ";
const QUOI_DELAI: &str = "délai";

/// Relevé incomplet : les tâches connues non vues restent dans la référence, sinon elles reviendraient en « NOUVEAU » au relevé
/// complet suivant, ce qu'un compte standard pourrait provoquer à volonté (relecture de #103, D1). Rend s'il est incomplet
pub(crate) fn garder_taches_non_vues(reference: &HashMap<String, EntreeDemarrage>, releve: &mut Vec<EntreeDemarrage>) -> bool {
    if !releve.iter().any(|e| e.anomalie && e.nom.starts_with(PREFIXE_INCOMPLET)) {
        return false;
    }
    let vues: std::collections::HashSet<String> = releve.iter().map(|e| e.cle.clone()).collect();
    releve.extend(reference.values().filter(|e| e.categorie == "Tâche planifiée" && !e.anomalie && !vues.contains(&e.cle)).cloned());
    true
}

/// Le relevé des tâches à échéance : le Planificateur peut ne pas répondre. Un seul à la fois : tant qu'un relevé reste bloqué, aucun autre fil
/// n'est lancé. Hors délai, ce qui a été lu reste, tour après tour tant que ce relevé est bloqué (S103-06)
fn taches_a_echeance(l: &mut Vec<EntreeDemarrage>) {
    static EN_COURS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    type Partiel = std::sync::Arc<std::sync::Mutex<Vec<EntreeDemarrage>>>;
    static DERNIER: std::sync::Mutex<Option<Partiel>> = std::sync::Mutex::new(None);
    let partiel = Partiel::default();
    let sortie = partiel.clone();
    let bloque = EN_COURS.load(std::sync::atomic::Ordering::SeqCst);
    if !bloque {
        *DERNIER.lock().unwrap() = Some(partiel);
    }
    let fini = commun::avec_echeance_unique(&EN_COURS, ECHEANCE_TACHES, move || taches(&sortie)).is_some();
    if let Some(p) = DERNIER.lock().unwrap().as_ref() {
        l.extend(p.lock().unwrap().iter().cloned());
    }
    if !fini {
        let (nom, motif) = anomalie_incomplet(QUOI_DELAI);
        ajouter_anomalie(l, &nom, &motif);
    }
}

/// Action d'une tâche, lue par l'API du Planificateur et non par motif dans son XML : un commentaire, un préfixe ou un second `Exec` y feraient
/// relever une autre commande que celle qui s'exécute (audit de #106, S106-01)
pub(crate) enum ActionTache {
    Exec(String, String),
    Com(String),
    Autre,
}

/// Commande d'une tâche sans action exécutable reconnue, jugée suspecte
const ACTION_NON_RECONNUE: &str = "(action non reconnue)";

/// Dans une commande tronquée : l'empreinte de la commande entière la suit, pour qu'un changement au-delà de la borne se voie (relecture de #106, R2)
const MARQUE_TRONQUEE: &str = " [tronquée, sha256 ";

fn commande_bornee(s: &str) -> String {
    use sha2::{Digest, Sha256};
    if s.chars().count() <= MAX_COMMANDE_TACHE {
        return s.to_string();
    }
    let debut: String = s.chars().take(MAX_COMMANDE_TACHE).collect();
    let empreinte: String = Sha256::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
    format!("{debut}{MARQUE_TRONQUEE}{empreinte}]")
}

/// Entrée d'une anomalie, reconnue à son indicateur, jamais à son texte
fn ajouter_anomalie(l: &mut Vec<EntreeDemarrage>, nom: &str, motif: &str) {
    ajouter(l, "Tâche planifiée", nom, &format!("{ANOMALIE_TACHES}{motif}"));
    if let Some(e) = l.last_mut() {
        e.anomalie = true;
    }
}

/// Entrées d'une tâche, une par action (pure, testée) : une action après la première ne doit pas passer sous la cible de la première. Les suffixes
/// portent « : », impossible dans un nom de tâche : aucune tâche ne peut prendre la clé d'une autre (relecture de #106, R1)
pub(crate) fn entrees_de_tache(l: &mut Vec<EntreeDemarrage>, chemin: &str, active: bool, actions: &[ActionTache]) {
    let base = if active { chemin.to_string() } else { format!("{chemin} : désactivée") };
    if actions.is_empty() {
        ajouter(l, "Tâche planifiée", &base, ACTION_NON_RECONNUE);
    }
    for (i, a) in actions.iter().enumerate() {
        let nom = if i == 0 { base.clone() } else { format!("{base} : action {}", i + 1) };
        match a {
            ActionTache::Exec(p, args) => ajouter(l, "Tâche planifiée", &nom, &commande_bornee(format!("{p} {args}").trim())),
            ActionTache::Com(id) => ajouter(l, "Tâche planifiée", &nom, &commande_com(id)),
            // Vient de la tâche, donc dans la file des nouvelles tâches, pas une anomalie du service (audit de #106, S106-21)
            ActionTache::Autre => ajouter(l, "Tâche planifiée", &nom, ACTION_NON_RECONNUE),
        }
    }
}

/// Le COM de ce fil, le temps d'un relevé : chaque tour crée un fil neuf (relecture de #106)
pub(crate) struct ComFil;

impl ComFil {
    pub(crate) fn nouveau() -> ComFil {
        unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        }
        ComFil
    }
}

impl Drop for ComFil {
    fn drop(&mut self) {
        unsafe { windows::Win32::System::Com::CoUninitialize() }
    }
}

pub(crate) struct LectureTaches {
    pub vus: std::collections::HashSet<String>,
    /// Raisons d'un relevé incomplet ; vide : toutes les tâches ont été lues
    pub incomplet: std::collections::BTreeSet<&'static str>,
    pub premiere_erreur: Option<String>,
    pub racine: Option<windows::Win32::System::TaskScheduler::ITaskFolder>,
}

/// Actions d'une tâche, par l'API du Planificateur
unsafe fn actions_de(tache: &windows::Win32::System::TaskScheduler::IRegisteredTask) -> windows::core::Result<Vec<ActionTache>> {
    use windows::core::{Interface, BSTR};
    use windows::Win32::System::TaskScheduler::{IComHandlerAction, IExecAction, TASK_ACTION_COM_HANDLER, TASK_ACTION_EXEC, TASK_ACTION_TYPE};
    let liste = tache.Definition()?.Actions()?;
    let mut n = 0i32;
    liste.Count(&mut n)?;
    let mut actions = Vec::new();
    for i in 1..=n {
        let a = liste.get_Item(i)?;
        let mut type_ = TASK_ACTION_TYPE::default();
        a.Type(&mut type_)?;
        actions.push(if type_ == TASK_ACTION_EXEC {
            let e: IExecAction = a.cast()?;
            let (mut p, mut args) = (BSTR::new(), BSTR::new());
            e.Path(&mut p)?;
            e.Arguments(&mut args)?;
            ActionTache::Exec(p.to_string(), args.to_string())
        } else if type_ == TASK_ACTION_COM_HANDLER {
            let c: IComHandlerAction = a.cast()?;
            let mut id = BSTR::new();
            c.ClassId(&mut id)?;
            ActionTache::Com(id.to_string())
        } else {
            ActionTache::Autre
        });
    }
    Ok(actions)
}

/// Les tâches d'un dossier. Une erreur est notée, le relevé continue : un dossier ou une tâche à problème ne doit pas cacher les suivants (S106-03).
/// Rend faux si la borne est atteinte
unsafe fn lire_dossier_taches(dossier: &windows::Win32::System::TaskScheduler::ITaskFolder, l: &mut LectureTaches, traiter: &mut dyn FnMut(&str, bool, &[ActionTache])) -> bool {
    use windows::core::VARIANT;
    use windows::Win32::System::TaskScheduler::TASK_ENUM_HIDDEN;
    let erreur = |l: &mut LectureTaches, quoi: &'static str, e: windows::core::Error| {
        l.incomplet.insert(quoi);
        l.premiere_erreur.get_or_insert_with(|| format!("{quoi} : {e}"));
    };
    let liste = match dossier.GetTasks(TASK_ENUM_HIDDEN.0) {
        Ok(x) => x,
        Err(e) => { erreur(l, "lecture partielle", e); return true; }
    };
    let n = match liste.Count() {
        Ok(x) => x,
        Err(e) => { erreur(l, "lecture partielle", e); return true; }
    };
    for i in 1..=n {
        let tache = match liste.get_Item(&VARIANT::from(i)) {
            Ok(x) => x,
            Err(e) => { erreur(l, "lecture partielle", e); continue; }
        };
        let chemin = match tache.Path() {
            Ok(x) => x.to_string(),
            Err(e) => { erreur(l, "lecture partielle", e); continue; }
        };
        l.vus.insert(chemin.to_lowercase());
        if l.vus.len() > MAX_TACHES {
            l.incomplet.insert("nombre de tâches");
            return false;
        }
        // Définition illisible : la tâche est connue, sa commande non : relevé incomplet, pas d'entrée qui sortirait de la référence (S106-02)
        match actions_de(&tache) {
            Ok(a) => traiter(&chemin, tache.Enabled().map(|b| b.as_bool()).unwrap_or(true), &a),
            Err(e) => erreur(l, "définition illisible", e),
        }
    }
    true
}

/// Toutes les tâches enregistrées, cachées comprises, lues auprès du Planificateur. La racine en dernier : un compte standard y écrit, pas dans
/// `\Microsoft` (droits lus), et ses tâches ne doivent pas faire passer la borne avant celles de Windows (S106-10). Le COM du fil est à la charge de l'appelant
pub(crate) fn lire_taches_planificateur(traiter: &mut dyn FnMut(&str, bool, &[ActionTache])) -> LectureTaches {
    use windows::core::{BSTR, VARIANT};
    use windows::Win32::System::TaskScheduler::{ITaskService, TaskScheduler};
    let mut l = LectureTaches { vus: Default::default(), incomplet: Default::default(), premiere_erreur: None, racine: None };
    unsafe {
        let connecte = (|| -> windows::core::Result<_> {
            let service: ITaskService = CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)?;
            let vide = VARIANT::default();
            service.Connect(&vide, &vide, &vide, &vide)?;
            service.GetFolder(&BSTR::from(r"\"))
        })();
        let racine = match connecte {
            Ok(r) => r,
            Err(e) => {
                l.incomplet.insert("planificateur");
                l.premiere_erreur = Some(format!("planificateur : {e}"));
                return l;
            }
        };
        let mut pile = vec![(racine.clone(), 0usize)];
        let mut dossiers = 0usize;
        let mut encore = true;
        while let Some((d, niveau)) = pile.pop() {
            if niveau > 0 && !lire_dossier_taches(&d, &mut l, traiter) {
                encore = false;
                break;
            }
            let sous = match d.GetFolders(0) {
                Ok(s) => s,
                Err(e) => {
                    l.incomplet.insert("lecture partielle");
                    l.premiere_erreur.get_or_insert_with(|| format!("dossiers : {e}"));
                    continue;
                }
            };
            let nombre = sous.Count().unwrap_or_else(|e| {
                l.incomplet.insert("lecture partielle");
                l.premiere_erreur.get_or_insert_with(|| format!("dossiers : {e}"));
                0
            });
            for i in 1..=nombre {
                // Une borne ne se tait pas : une vraie tâche plus loin ne serait lue nulle part (relecture de #106, D2)
                if niveau + 1 >= MAX_NIVEAUX_TACHES {
                    l.incomplet.insert("profondeur");
                    break;
                }
                dossiers += 1;
                if dossiers > MAX_DOSSIERS_TACHES {
                    l.incomplet.insert("dossiers");
                    break;
                }
                match sous.get_Item(&VARIANT::from(i)) {
                    Ok(x) => pile.push((x, niveau + 1)),
                    Err(e) => {
                        l.incomplet.insert("lecture partielle");
                        l.premiere_erreur.get_or_insert_with(|| format!("dossier : {e}"));
                    }
                }
            }
        }
        if encore {
            lire_dossier_taches(&racine, &mut l, traiter);
        }
        l.racine = Some(racine);
    }
    l
}

fn taches(sortie: &std::sync::Mutex<Vec<EntreeDemarrage>>) {
    use windows::core::BSTR;
    let _com = ComFil::nouveau();
    let lecture = lire_taches_planificateur(&mut |chemin, active, actions| entrees_de_tache(&mut sortie.lock().unwrap(), chemin, active, actions));
    let mut anomalies: Vec<(String, String)> = lecture.incomplet.iter().map(|q| anomalie_incomplet(q)).collect();
    // Une ligne quand la raison change, pas une par minute
    static DERNIERE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
    let mut derniere = DERNIERE.lock().unwrap_or_else(|e| e.into_inner());
    if *derniere != lecture.premiere_erreur {
        if let Some(e) = &lecture.premiere_erreur {
            commun::journal(&format!("relevé des tâches : {e}"));
        }
        derniere.clone_from(&lecture.premiere_erreur);
    }
    drop(derniere);
    if let Some(racine) = &lecture.racine {
        let dossier = format!(r"{}\Tasks", natif::dossier_systeme());
        let mut reverifications = 0usize;
        let mut enregistree = |nom: &str, chemin: &Path| {
            if lecture.vus.contains(&nom.to_lowercase()) {
                return Fichier::Enregistre;
            }
            // Pas dans l'énumération : créée depuis ? Revérifiée, au plus quelques fois, sur la même connexion
            if reverifications >= MAX_REVERIFICATIONS {
                return Fichier::Inconnu;
            }
            reverifications += 1;
            match unsafe { racine.GetTask(&BSTR::from(nom)) } {
                Ok(_) => Fichier::Enregistre,
                // Supprimée depuis : plus de fichier, rien à dire
                Err(e) => match verdict_reverification(e.code().0 as u32) {
                    Fichier::SansTache if !existe_tel_quel(chemin) => Fichier::Enregistre,
                    v => v,
                },
            }
        };
        anomalies.extend(examiner_dossier_taches(Path::new(&dossier), &BORNES_TACHES, &mut enregistree));
    }
    let mut l = sortie.lock().unwrap();
    for (nom, motif) in anomalies {
        ajouter_anomalie(&mut l, &nom, &motif);
    }
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
