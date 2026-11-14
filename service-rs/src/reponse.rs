//! Origine des fichiers et actions de réponse :
//!   - origine : marque « Mark of the Web » posée par Windows sur les fichiers téléchargés (flux Zone.Identifier),
//!     âge du fichier ;
//!   - réponse : tuer, suspendre ou reprendre un processus, mettre un fichier en quarantaine (et le restaurer),
//!     isoler un programme du réseau, mode panique (tout le trafic sortant bloqué sauf Windows).

use crate::blocage;
use crate::commun;
use crate::natif::{self, large};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use windows::core::{BSTR, PCWSTR};
use windows::Win32::Foundation::{VARIANT_FALSE, VARIANT_TRUE};
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, NetFwPolicy2, NetFwRule, NET_FW_ACTION_BLOCK, NET_FW_PROFILE2_DOMAIN,
    NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC, NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT,
};
use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::System::Threading::{TerminateProcess, PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE};

// ------------------------------------------------------------ origine des fichiers

#[derive(Clone, Default)]
pub struct Origine {
    /// 3 = Internet, 4 = sites non fiables
    pub zone: u32,
    pub source: String,
    pub age_jours: u64,
}

/// Lit la marque « téléchargé depuis Internet » (flux de données alternatif Zone.Identifier) et l'âge du fichier
pub fn origine(chemin: &str) -> Option<Origine> {
    if chemin.is_empty() {
        return None;
    }
    let age_jours = fs::metadata(chemin)
        .and_then(|m| m.created())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .map(|d| d.as_secs() / 86400)
        .unwrap_or(9999);
    let mut o = Origine { age_jours, ..Default::default() };
    if let Ok(t) = fs::read_to_string(format!("{chemin}:Zone.Identifier")) {
        for l in t.lines() {
            if let Some(z) = l.strip_prefix("ZoneId=") {
                o.zone = z.trim().parse().unwrap_or(0);
            } else if let Some(u) = l.strip_prefix("HostUrl=") {
                o.source = u.trim().to_string();
            } else if let Some(u) = l.strip_prefix("ReferrerUrl=") {
                if o.source.is_empty() {
                    o.source = u.trim().to_string();
                }
            }
        }
    }
    Some(o)
}

impl Origine {
    pub fn texte(&self) -> Option<String> {
        if self.zone < 3 {
            return None;
        }
        let source = if self.source.is_empty() { "Internet".to_string() } else { self.source.chars().take(120).collect() };
        Some(format!("téléchargé depuis {source}{}", if self.age_jours < 2 { " (il y a moins de 2 jours)" } else { "" }))
    }
}

// ------------------------------------------------------------ processus

/// Processus dont l'arrêt ou la suspension fige ou fait planter Windows, par chemin EXACT relatif au dossier Windows.
/// Avant, le nom suffisait avec un chemin qui COMMENÇAIT par le dossier Windows et une signature Microsoft : une copie
/// de powershell.exe nommée explorer.exe dans C:\Windows\Tasks (où tout compte peut écrire) échappait à la suspension
/// automatique d'un rançongiciel et aux actions manuelles (audit, AUD5-01). Defender (MsMpEng) est un processus
/// protégé que le service ne peut pas ouvrir : il n'a pas besoin d'y figurer.
const CRITIQUES: &[&str] = &[
    r"system32\csrss.exe", r"system32\wininit.exe", r"system32\winlogon.exe", r"system32\lsass.exe", r"system32\lsaiso.exe",
    r"system32\services.exe", r"system32\smss.exe", r"system32\svchost.exe", r"system32\dwm.exe", r"system32\fontdrvhost.exe",
    r"explorer.exe",
];

/// Chemin d'un processus critique : exactement l'un des CRITIQUES sous le dossier Windows (casse ignorée)
pub fn chemin_critique(chemin: &str, dossier_windows: &str) -> bool {
    let c = chemin.to_lowercase();
    let w = dossier_windows.trim_end_matches('\\').to_lowercase();
    c.strip_prefix(&w).and_then(|r| r.strip_prefix('\\')).is_some_and(|r| CRITIQUES.contains(&r))
}

/// Raison de refuser d'agir sur ce processus, s'il y en a une
/// Décision pure (testée) : sur un chemin critique, une lecture hors délai protège : un compte standard ne doit pas pouvoir ouvrir cette
/// garde en bloquant des lectures (audit de #104, S104-01)
pub(crate) fn garde_critique(lecture: Result<bool, natif::HorsDelai>) -> bool {
    lecture.unwrap_or(true)
}

pub fn protege(pid: u32) -> Option<String> {
    if pid <= 4 || pid == std::process::id() {
        return Some("processus du système ou de deR4Tizer".into());
    }
    protege_chemin(&natif::chemin_processus(pid))
}

/// Chemin complet canonique (QueryFullProcessImageName), comparé exactement ; signature Microsoft en plus
fn protege_chemin(chemin: &str) -> Option<String> {
    let nom = Path::new(chemin).file_stem().map(|s| s.to_string_lossy().to_lowercase()).unwrap_or_default();
    (chemin_critique(chemin, &natif::dossier_windows()) && garde_critique(natif::binaire_windows_lu(chemin)))
        .then(|| format!("{nom} est un processus critique de Windows (le système ou le réseau se figerait)"))
}

/// Identité attendue d'un processus, fixée à la décision. Le PID et l'heure de création désignent un seul processus. Le
/// chemin n'est pas comparé (décision du mainteneur, audit de #113, S113-01, S113-02) : un programme qui se renomme, ou
/// dont le chemin est très long, ne doit échapper ni à la suspension ni à l'arrêt
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Attendu {
    /// Telle que l'administrateur l'a vue, ou relevée à la décision
    Exacte { creation: u64 },
    /// Événement 4663 : processus créé avant l'événement. Heure de l'événement illisible : le chemin, seul indice restant
    Leurre { avant: Option<u64>, chemin: String },
}

/// Décision pure : le processus ouvert est-il celui de la décision ? Heure de création illisible : non
pub(crate) fn meme_processus(attendu: &Attendu, creation: Option<u64>, chemin: &str) -> bool {
    let Some(creation) = creation else { return false };
    match attendu {
        Attendu::Exacte { creation: c } => creation == *c,
        Attendu::Leurre { avant: Some(t), .. } => creation <= *t,
        Attendu::Leurre { avant: None, chemin: a } => !chemin.is_empty() && chemin.to_lowercase() == a.to_lowercase(),
    }
}

/// Le message n'est jamais une action : échec fermé si l'identité a changé
pub const IDENTITE_CHANGEE: &str = "processus terminé ou remplacé depuis la décision : aucune action";

/// Ouvre le processus une seule fois, lit et compare son identité, refait le contrôle « critique » sur le chemin lu par le
/// handle, puis agit sur ce même handle
fn agir(pid: u32, attendu: &Attendu, droits: windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS, controle_critique: bool, action: impl FnOnce(&natif::ProcessusOuvert) -> Result<(), String>) -> Result<(), String> {
    if pid <= 4 || pid == std::process::id() {
        return Err("refusé : processus du système ou de deR4Tizer".into());
    }
    let p = natif::ProcessusOuvert::ouvrir(pid, droits)?;
    let chemin = p.chemin();
    if !meme_processus(attendu, p.creation(), &chemin) {
        return Err(IDENTITE_CHANGEE.into());
    }
    if controle_critique {
        if let Some(r) = protege_chemin(&chemin) {
            return Err(format!("refusé : {r}"));
        }
    }
    action(&p)
}

pub fn tuer(pid: u32, attendu: &Attendu) -> Result<(), String> {
    agir(pid, attendu, PROCESS_TERMINATE, true, |p| unsafe { TerminateProcess(p.handle(), 1).map_err(|e| e.to_string()) })
}

/// Suspend ou reprend tous les fils d'un processus (fonctions NtSuspendProcess / NtResumeProcess de ntdll)
pub fn suspendre(pid: u32, attendu: &Attendu, suspendre: bool) -> Result<(), String> {
    agir(pid, attendu, PROCESS_SUSPEND_RESUME, suspendre, |p| unsafe {
        let nom = large("ntdll.dll");
        let module = LoadLibraryW(PCWSTR(nom.as_ptr())).map_err(|e| e.to_string())?;
        let fonction = if suspendre { windows::core::s!("NtSuspendProcess") } else { windows::core::s!("NtResumeProcess") };
        let f = GetProcAddress(module, fonction).ok_or("fonction introuvable")?;
        let f: extern "system" fn(windows::Win32::Foundation::HANDLE) -> i32 = std::mem::transmute(f);
        let statut = f(p.handle());
        if statut == 0 { Ok(()) } else { Err(format!("statut NT 0x{statut:08X}")) }
    })
}

// ------------------------------------------------------------ quarantaine

#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq)]
#[serde(rename_all = "PascalCase", default)]
pub struct ElementQuarantaine {
    pub id: String,
    pub chemin_origine: String,
    pub date: String,
    pub raison: String,
    pub taille: u64,
    /// Nom du fichier dans quarantaine\ (vide : « <id>.quarantaine », éléments d'avant la 4.3)
    pub fichier: String,
    /// Empreinte SHA-256 du contenu d'origine (la copie décodée, pas la copie encodée sur le disque), vérifiée à la
    /// restauration et comparée à l'original par la reprise au démarrage (vide : élément pas encore migré)
    pub sha256: String,
    /// « en_cours », « terminee » ou « restauree » (vide : éléments d'avant la 4.3, terminés)
    pub etat: String,
    /// Marque Internet de l'original (flux Zone.Identifier), réécrite à la restauration
    pub zone_identifier: String,
    /// Emplacement où le fichier a été restauré (origine ou dossier de repli du service), renseigné avec l'état
    /// « restauree » ; vide sinon
    pub chemin_restaure: String,
}

/// État d'un élément de quarantaine (transaction)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EtatQuarantaine {
    /// Copie faite et enregistrée, original pas encore supprimé
    EnCours,
    Terminee,
    /// Fichier restauré et vérifié, copie pas encore retirée
    Restauree,
}

/// Nom de fichier simple dans quarantaine\ (audit du 2026-11-14, B3) : lettres et chiffres ASCII, « - », « _ » et
/// « . », 1 à 200 caractères, ni « .. », ni point initial. Refuse tout séparateur, lecteur ou chemin absolu, donc
/// tout ce qu'un quarantaine.json réécrit ferait joindre hors du dossier
pub fn nom_copie_simple(n: &str) -> bool {
    !n.is_empty() && n.len() <= 200 && !n.starts_with('.') && !n.contains("..")
        && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

impl ElementQuarantaine {
    /// Nom de la copie, ou None si l'entrée (identifiant ou nom enregistré) n'est pas un nom simple : aucune action
    /// sur une telle entrée (audit du 2026-11-14, B3). L'identifiant est exigé simple même quand le nom est
    /// enregistré : la migration en bâtit le nom de la nouvelle copie (audit de #173, S173-01)
    pub fn nom_fichier(&self) -> Option<String> {
        if !nom_copie_simple(&self.id) {
            return None;
        }
        let n = if self.fichier.is_empty() { format!("{}.quarantaine", self.id) } else { self.fichier.clone() };
        nom_copie_simple(&n).then_some(n)
    }

    pub fn etat(&self) -> EtatQuarantaine {
        match self.etat.as_str() {
            "en_cours" => EtatQuarantaine::EnCours,
            "restauree" => EtatQuarantaine::Restauree,
            _ => EtatQuarantaine::Terminee,
        }
    }

    fn marquer(&mut self, etat: EtatQuarantaine) {
        self.etat = match etat {
            EtatQuarantaine::EnCours => "en_cours",
            EtatQuarantaine::Terminee => "terminee",
            EtatQuarantaine::Restauree => "restauree",
        }.into();
    }
}

/// Copie en quarantaine : fichier créé par le service avec ses droits (propriétaire SYSTEM, SYSTEM et
/// administrateurs seulement), jamais lisible par les comptes autorisés. Un déplacement garderait le
/// propriétaire d'origine (l'utilisateur) : la copie serait écartée au démarrage suivant.
pub const SDDL_QUARANTAINE: &str = "O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)";

/// Contenu des copies encodé, jamais en clair sur le disque (un exécutable ou un script malveillant n'a rien à
/// y faire, et un antivirus pourrait supprimer la copie) : en-tête « D4TQ », version, nonce de 16 octets, puis
/// le contenu combiné (XOR) à un flux dérivé de SHA-256(clé ‖ nonce ‖ numéro de bloc). Ce n'est pas un
/// chiffrement : la clé est fixe et publique, seul compte que les octets d'origine n'apparaissent plus.
const MAGIE: &[u8; 4] = b"D4TQ";
const VERSION_ENCODAGE: u8 = 1;
const TAILLE_ENTETE: usize = 4 + 1 + 16;
const CLE_QUARANTAINE: &[u8] = b"deR4Tizer : contenu mis en quarantaine, encodage v1";

/// Nonce d'une copie, dérivé de son nom de fichier (unique)
pub fn nonce_de(fichier: &str) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(fichier.as_bytes());
    let mut n = [0u8; 16];
    n.copy_from_slice(&h[..16]);
    n
}

/// Encode ou décode (même opération) `octets`, situés à `position` dans le contenu d'origine
pub fn encoder_flux(nonce: &[u8; 16], position: u64, octets: &mut [u8]) {
    use sha2::{Digest, Sha256};
    let mut bloc_courant = u64::MAX;
    let mut flux = [0u8; 32];
    for (i, o) in octets.iter_mut().enumerate() {
        let p = position + i as u64;
        if p / 32 != bloc_courant {
            bloc_courant = p / 32;
            let mut h = Sha256::new();
            h.update(CLE_QUARANTAINE);
            h.update(nonce);
            h.update(bloc_courant.to_le_bytes());
            flux.copy_from_slice(&h.finalize());
        }
        *o ^= flux[(p % 32) as usize];
    }
}

pub fn entete_encodage(nonce: &[u8; 16]) -> Vec<u8> {
    let mut e = MAGIE.to_vec();
    e.push(VERSION_ENCODAGE);
    e.extend_from_slice(nonce);
    e
}

/// Nonce si le fichier commence par un en-tête d'encodage reconnu
fn lire_entete(f: &mut fs::File) -> Option<[u8; 16]> {
    use std::io::Read;
    let mut e = [0u8; TAILLE_ENTETE];
    f.read_exact(&mut e).ok()?;
    if &e[..4] != MAGIE || e[4] != VERSION_ENCODAGE {
        return None;
    }
    let mut n = [0u8; 16];
    n.copy_from_slice(&e[5..]);
    Some(n)
}

pub fn est_encodee(chemin: &Path) -> bool {
    fs::File::open(chemin).ok().and_then(|mut f| lire_entete(&mut f)).is_some()
}

/// Décode une copie encodée vers `sortie` ; renvoie l'empreinte SHA-256 du contenu décodé
fn decoder(copie: &Path, sortie: &mut dyn std::io::Write) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut f = fs::File::open(copie).map_err(|e| format!("copie illisible : {e}"))?;
    let nonce = lire_entete(&mut f).ok_or("copie sans en-tête d'encodage")?;
    let mut h = Sha256::new();
    let mut tampon = vec![0u8; 1 << 16];
    let mut position = 0u64;
    loop {
        let n = f.read(&mut tampon).map_err(|e| format!("lecture de la copie : {e}"))?;
        if n == 0 {
            break;
        }
        encoder_flux(&nonce, position, &mut tampon[..n]);
        position += n as u64;
        h.update(&tampon[..n]);
        sortie.write_all(&tampon[..n]).map_err(|e| format!("écriture : {e}"))?;
    }
    Ok(h.finalize().iter().map(|o| format!("{o:02x}")).collect())
}

/// Empreinte du contenu d'origine d'une copie : décodée si encodée, telle quelle sinon (copies d'avant)
fn empreinte_copie(copie: &Path) -> Option<String> {
    if est_encodee(copie) { decoder(copie, &mut std::io::sink()).ok() } else { crate::hygiene::empreinte_fichier(copie) }
}

/// Recrée le contenu d'origine d'une copie dans `cible`, fichier déjà créé et vérifié (handle)
fn restituer_dans(copie: &Path, cible: &mut fs::File) -> Result<(), String> {
    if est_encodee(copie) {
        return decoder(copie, cible).map(|_| ());
    }
    let mut f = fs::File::open(copie).map_err(|e| format!("copie illisible : {e}"))?;
    std::io::copy(&mut f, cible).map(|_| ()).map_err(|e| format!("écriture : {e}"))
}

/// Empreinte SHA-256 d'un flux (fichier ouvert par handle)
fn empreinte_lecteur(r: &mut dyn std::io::Read) -> Option<String> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    let mut tampon = vec![0u8; 1 << 16];
    loop {
        let n = r.read(&mut tampon).ok()?;
        if n == 0 {
            break;
        }
        h.update(&tampon[..n]);
    }
    Some(h.finalize().iter().map(|o| format!("{o:02x}")).collect())
}

/// Écriture du manifeste (quarantaine.json en service ; injectée dans les tests pour simuler un échec)
pub type EcrireManifeste<'a> = &'a dyn Fn(&[ElementQuarantaine]) -> Result<(), String>;

fn dossier_quarantaine() -> PathBuf {
    commun::dossier().join("quarantaine")
}

/// Marque Internet (flux Zone.Identifier) d'un fichier, 4 Ko au plus ; vide s'il n'en a pas
pub fn lire_marque_internet(chemin: &Path) -> String {
    use std::io::Read;
    let mut t = String::new();
    if let Ok(f) = fs::File::open(format!("{}:Zone.Identifier", chemin.display())) {
        let _ = f.take(4096).read_to_string(&mut t);
    }
    t
}

/// Marque Internet du fichier ouvert, lue par rapport à son handle (sans repasser par le chemin)
fn lire_marque_handle(f: &fs::File) -> String {
    use std::io::Read;
    let mut t = String::new();
    if let Ok(Some(flux)) = natif::ouvrir_flux(f, ":Zone.Identifier", false) {
        let _ = flux.take(4096).read_to_string(&mut t);
    }
    t
}

/// Réécrit la marque Internet sur le fichier ouvert, par rapport à son handle
fn ecrire_marque_handle(f: &fs::File, marque: &str) -> Result<(), String> {
    use std::io::Write;
    if marque.is_empty() {
        return Ok(());
    }
    let mut flux = natif::ouvrir_flux(f, ":Zone.Identifier", true)?.ok_or("marque Internet : flux non créé")?;
    flux.write_all(marque.as_bytes()).map_err(|e| format!("marque Internet : {e}"))
}

/// Copie protégée et ENCODÉE de `source` dans `dossier`, relue et décodée pour vérification. Renvoie
/// l'empreinte du contenu d'origine
fn copier_verifie(dossier: &Path, source: &mut dyn std::io::Read, fichier: &str, sddl: &str) -> Result<String, String> {
    fs::create_dir_all(dossier).map_err(|e| e.to_string())?;
    let copie = dossier.join(fichier);
    let nonce = nonce_de(fichier);
    let sha = natif::copier_protege_depuis(source, &copie, sddl, &entete_encodage(&nonce), &mut |b, p| encoder_flux(&nonce, p, b))?;
    if empreinte_copie(&copie).is_none_or(|h| !h.eq_ignore_ascii_case(&sha)) {
        let _ = fs::remove_file(&copie);
        return Err("copie en quarantaine illisible ou différente de l'original".into());
    }
    Ok(sha)
}

/// Mise en quarantaine transactionnelle : l'original est ouvert UNE fois par handle, sans suivre de lien,
/// chemin final vérifié, partagé en lecture seule (personne ne peut le modifier ni le remplacer pendant
/// l'opération) ; contenu, marque Internet et suppression passent par ce handle, aucune opération par chemin
/// après le contrôle. Copie protégée vérifiée, entrée « en_cours » ENREGISTRÉE, puis seulement suppression de
/// l'original, puis « terminee ». Échec d'enregistrement : copie retirée, original
/// intact. Original impossible à supprimer : entrée et copie retirées, original intact. Échec du dernier
/// enregistrement : l'original est déjà supprimé, la copie est en place ; la reprise au démarrage termine.
pub fn quarantaine_transaction(dossier: &Path, liste: &mut Vec<ElementQuarantaine>, source: &Path, id: &str, raison: &str,
                               sddl: &str, ecrire: EcrireManifeste) -> Result<(), String> {
    let fichier = format!("{id}.quarantaine");
    // GENERIC_READ | DELETE | SYNCHRONIZE, partage en lecture seule
    let mut original = natif::ouvrir_verifie(source, 0x8000_0000 | 0x0001_0000 | 0x0010_0000, 0x1, false)
        .map_err(|e| format!("{} : {e} ; quarantaine refusée", source.display()))?;
    let zone_identifier = lire_marque_handle(&original);
    let taille = original.metadata().map(|m| m.len()).unwrap_or(0);
    let sha256 = copier_verifie(dossier, &mut original, &fichier, sddl)?;
    let copie = dossier.join(&fichier);
    let mut e = ElementQuarantaine { id: id.into(), chemin_origine: source.display().to_string(), date: commun::maintenant(),
        raison: raison.into(), taille, fichier, sha256, zone_identifier, ..Default::default() };
    e.marquer(EtatQuarantaine::EnCours);
    liste.push(e);
    if let Err(x) = ecrire(liste) {
        liste.pop();
        let _ = fs::remove_file(&copie);
        return Err(format!("quarantaine non enregistrée ({x}) : original intact"));
    }
    // Suppression par le handle vérifié (effective à sa fermeture)
    if let Err(x) = natif::supprimer_par_handle(&original) {
        liste.pop();
        if ecrire(liste).is_ok() {
            let _ = fs::remove_file(&copie);
        }
        return Err(format!("suppression de l'original impossible : {x}"));
    }
    drop(original);
    if let Some(e) = liste.last_mut() {
        e.marquer(EtatQuarantaine::Terminee);
    }
    // Échec ici : original supprimé, copie et entrée « en_cours » en place, la reprise passera à « terminee »
    let _ = ecrire(liste);
    Ok(())
}

/// Lit le manifeste. Absent : liste vide. Présent mais illisible (protection en échec, propriétaire non
/// vérifié, contenu invalide) : erreur, pour ne jamais le réécrire avec une liste incomplète.
fn charger_liste() -> Result<Vec<ElementQuarantaine>, String> {
    let f = commun::dossier().join("quarantaine.json");
    if fs::symlink_metadata(&f).is_err() {
        return Ok(Vec::new());
    }
    commun::lire::<Vec<ElementQuarantaine>>("quarantaine.json")
        .ok_or_else(|| "manifeste de quarantaine illisible ou protection du dossier non vérifiée".to_string())
}

fn ecrire_manifeste_service(liste: &[ElementQuarantaine]) -> Result<(), String> {
    commun::ecrire("quarantaine.json", liste)
}

/// Tue les processus qui exécutent ce fichier, puis le met en quarantaine (copie protégée, inexécutable)
pub fn mettre_en_quarantaine(chemin: &str, raison: &str) -> Result<String, String> {
    let p = Path::new(chemin);
    if !p.is_file() {
        return Err(format!("fichier introuvable : {chemin}"));
    }
    let bas = chemin.to_lowercase();
    if bas.starts_with(&natif::dossier_windows().to_lowercase()) {
        return Err("refusé : fichier du système Windows".into());
    }
    let mut liste = charger_liste()?;
    for (pid, _) in natif::processus() {
        let lu = natif::chemin_processus(pid);
        if lu.eq_ignore_ascii_case(chemin) {
            if let Some(creation) = natif::creation_processus(pid) {
                let _ = tuer(pid, &Attendu::Exacte { creation });
            }
        }
    }
    std::thread::sleep(std::time::Duration::from_millis(500));
    quarantaine_transaction(&dossier_quarantaine(), &mut liste, p, &commun::nouvel_id(), raison, SDDL_QUARANTAINE, &ecrire_manifeste_service)?;
    Ok(format!("{} placé en quarantaine.", p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()))
}

/// Crée le fichier de destination d'une restauration (et ses dossiers) ; renvoie son handle vérifié
pub type CreerCible<'a> = &'a dyn Fn(&Path) -> Result<fs::File, String>;

/// Restauration transactionnelle vers `cible` (emplacement d'origine ou dossier de repli) : empreinte de la
/// copie vérifiée (refus si absente ou différente), refus si l'emplacement est occupé, fichier créé par
/// `creer` (en service : sous l'identité de l'utilisateur propriétaire, chemin final vérifié ; échec = erreur
/// avant toute copie), contenu restitué, empreinte relue et marque Internet réécrite PAR LE HANDLE, état
/// « restauree » ENREGISTRÉ, puis seulement retrait de la copie et de l'entrée. Tout échec après la création :
/// fichier restauré supprimé par son handle, copie et entrée intactes.
pub fn restaurer_transaction(dossier: &Path, liste: &mut Vec<ElementQuarantaine>, id: &str, cible: &Path, creer: CreerCible,
                             ecrire: EcrireManifeste) -> Result<String, String> {
    use std::io::{Seek, SeekFrom};
    let i = liste.iter().position(|e| e.id == id).ok_or("élément introuvable")?;
    let e = liste[i].clone();
    let source = dossier.join(e.nom_fichier().ok_or("nom de la copie en quarantaine refusé : restauration refusée")?);
    if e.sha256.len() != 64 {
        return Err("empreinte de la copie inconnue : restauration refusée".into());
    }
    match empreinte_copie(&source) {
        Some(h) if h.eq_ignore_ascii_case(&e.sha256) => {}
        Some(_) => return Err("la copie en quarantaine a été modifiée : restauration refusée".into()),
        None => return Err("copie en quarantaine introuvable ou illisible".into()),
    }
    if fs::symlink_metadata(cible).is_ok() {
        return Err(format!("{} existe déjà : restauration refusée", cible.display()));
    }
    let mut fichier = creer(cible)?;
    let annuler = |f: &fs::File, raison: String| {
        let _ = natif::supprimer_par_handle(f);
        Err(raison)
    };
    if let Err(x) = restituer_dans(&source, &mut fichier) {
        return annuler(&fichier, x);
    }
    let relu = fichier.seek(SeekFrom::Start(0)).ok().and_then(|_| empreinte_lecteur(&mut fichier));
    if relu.is_none_or(|h| !h.eq_ignore_ascii_case(&e.sha256)) {
        return annuler(&fichier, "restauration incomplète : fichier restauré retiré, copie conservée".into());
    }
    if let Err(x) = ecrire_marque_handle(&fichier, &e.zone_identifier) {
        return annuler(&fichier, x);
    }
    liste[i].marquer(EtatQuarantaine::Restauree);
    liste[i].chemin_restaure = cible.display().to_string();
    if let Err(x) = ecrire(liste) {
        liste[i] = e.clone();
        return annuler(&fichier, format!("restauration non enregistrée ({x}) : fichier restauré retiré, copie conservée"));
    }
    drop(fichier);
    // Échecs suivants sans gravité : la reprise au démarrage retire la copie et l'entrée
    let _ = fs::remove_file(&source);
    liste.remove(i);
    let _ = ecrire(liste);
    Ok(cible.display().to_string())
}

/// Où restaurer : à l'emplacement d'origine sous l'identité de son propriétaire, ou dans le dossier de repli
#[derive(Debug, PartialEq)]
pub enum CibleRestauration {
    Origine,
    Repli(&'static str),
}

/// Décision pure. Jamais d'écriture en SYSTEM à l'emplacement d'origine : il faut un propriétaire qui soit un
/// compte d'utilisateur (S-1-5-21-…) avec une session ouverte, dont on emprunte l'identité
pub fn cible_restauration(proprietaire: Option<&str>, session_ouverte: bool) -> CibleRestauration {
    match proprietaire {
        None => CibleRestauration::Repli("propriétaire de l'emplacement illisible"),
        Some(sid) if !sid.starts_with("S-1-5-21-") => CibleRestauration::Repli("emplacement appartenant au système ou aux administrateurs"),
        Some(_) if !session_ouverte => CibleRestauration::Repli("aucune session ouverte du propriétaire de l'emplacement"),
        Some(_) => CibleRestauration::Origine,
    }
}

/// Crée un fichier et ses dossiers sans suivre de lien : refus si un élément existant du chemin est un lien,
/// création, puis chemin final vérifié (fichier supprimé par son handle s'il a été détourné)
pub fn creer_sans_lien(cible: &Path) -> Result<fs::File, String> {
    if natif::chemin_contient_lien(cible) {
        return Err(format!("{} : un élément du chemin est un lien ; restauration refusée", cible.display()));
    }
    if let Some(d) = cible.parent() {
        fs::create_dir_all(d).map_err(|x| format!("dossier d'origine impossible à créer : {x}"))?;
    }
    natif::creer_verifie(cible).map_err(|x| format!("{} : {x} ; restauration refusée", cible.display()))
}

/// Propriétaire du plus proche dossier existant de `cible`, lu par handle sans suivre de lien (chemin final
/// vérifié) ; None si illisible ou détourné
fn proprietaire_emplacement(cible: &Path) -> Option<String> {
    let mut d = cible.parent();
    while let Some(x) = d {
        // READ_CONTROL | SYNCHRONIZE, tout partage
        match natif::ouvrir_verifie(x, 0x0002_0000 | 0x0010_0000, 0x7, true) {
            Ok(f) => return natif::proprietaire_par_handle(&f),
            Err(natif::ErreurOuverture::Absent) => d = x.parent(),
            Err(_) => return None,
        }
    }
    None
}

const REPLI: &str = "REPLI";

/// Emplacement d'origine d'un élément de quarantaine (registre des actions, PR 6.4b)
pub fn origine_quarantaine(id: &str) -> Option<String> {
    charger_liste().ok()?.into_iter().find(|e| e.id == id).map(|e| e.chemin_origine)
}

pub fn restaurer(id: &str) -> Result<String, String> {
    let mut liste = charger_liste()?;
    let e = liste.iter().find(|e| e.id == id).cloned().ok_or("élément introuvable")?;
    let cible = PathBuf::from(&e.chemin_origine);
    let proprietaire = proprietaire_emplacement(&cible);
    if let CibleRestauration::Repli(raison) = cible_restauration(proprietaire.as_deref(), true) {
        return Err(format!("{REPLI} : {raison}. Restauration possible dans le dossier de deR4Tizer (bouton « Restaurer dans le dossier de deR4Tizer »)."));
    }
    let sid = proprietaire.unwrap_or_default();
    // Création sous l'identité du propriétaire : Windows applique SES droits (une jonction vers un dossier
    // système échoue) ; le reste (restitution, vérification, marque) passe par le handle obtenu
    let creer = |c: &Path| match natif::avec_jeton_de(&sid, || creer_sans_lien(c)) {
        Ok(r) => r,
        Err(x) => Err(format!("{REPLI} : {x}. Restauration possible dans le dossier de deR4Tizer (bouton « Restaurer dans le dossier de deR4Tizer »).")),
    };
    let chemin = restaurer_transaction(&dossier_quarantaine(), &mut liste, id, &cible, &creer, &ecrire_manifeste_service)?;
    Ok(format!("{chemin} restauré."))
}

/// Prépare le dossier de repli `base\<id>` : refus si la protection du dossier de données est en échec ;
/// `base` créé (erreur vérifiée) puis ouvert par handle sans suivre de lien, chemin final vérifié ;
/// `<id>` créé avec ses droits s'il n'existe pas, puis ouvert de même ; ses droits sont relus par le handle
/// et comparés à l'attendu (`conforme`) ; non conformes : réimposés par le handle puis relus ; échec = refus
pub fn preparer_dossier_repli(base: &Path, id: &str, sddl: &str, echec_protection: bool,
                              conforme: &dyn Fn(&natif::Securite) -> Result<(), String>) -> Result<PathBuf, String> {
    if echec_protection {
        return Err("protection du dossier de données en échec : restauration de repli refusée".into());
    }
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err("identifiant d'élément invalide".into());
    }
    if fs::symlink_metadata(base).is_err() {
        fs::create_dir(base).map_err(|e| format!("{} impossible à créer : {e}", base.display()))?;
    }
    // READ_CONTROL | SYNCHRONIZE, tout partage
    natif::ouvrir_verifie(base, 0x0002_0000 | 0x0010_0000, 0x7, true).map_err(|e| format!("{} : {e} ; repli refusé", base.display()))?;
    let dossier = base.join(id);
    if fs::symlink_metadata(&dossier).is_err() && !natif::creer_dossier_protege(&dossier, sddl) {
        return Err(format!("{} impossible à créer avec ses droits", dossier.display()));
    }
    // READ_CONTROL | WRITE_DAC | WRITE_OWNER | SYNCHRONIZE
    let h = natif::ouvrir_verifie(&dossier, 0x0002_0000 | 0x0004_0000 | 0x0008_0000 | 0x0010_0000, 0x7, true)
        .map_err(|e| format!("{} : {e} ; repli refusé", dossier.display()))?;
    let verifier = |h: &fs::File| natif::lire_securite_handle(h).ok_or_else(|| "droits illisibles".to_string()).and_then(|s| conforme(&s));
    if verifier(&h).is_err() {
        natif::poser_droits_handle(&h, sddl).map_err(|e| format!("{} : droits refusés ({e}) ; repli refusé", dossier.display()))?;
        verifier(&h).map_err(|e| format!("{} : {e} ; repli refusé", dossier.display()))?;
    }
    Ok(dossier)
}

/// Restauration de repli : dans un dossier créé par le service (ProgramData\deR4Tizer\restaurations\<id>),
/// lisible par SYSTEM, les administrateurs et le propriétaire de l'emplacement d'origine s'il est un utilisateur
pub fn restaurer_repli(id: &str) -> Result<String, String> {
    use crate::protection::{droits_conformes, SID_ADMINISTRATEURS, SID_SYSTEME};
    let mut liste = charger_liste()?;
    let e = liste.iter().find(|e| e.id == id).cloned().ok_or("élément introuvable")?;
    let nom = Path::new(&e.chemin_origine).file_name().map(|n| n.to_string_lossy().to_string()).filter(|n| !n.is_empty())
        .unwrap_or_else(|| format!("{id}.restaure"));
    let lecteur = proprietaire_emplacement(Path::new(&e.chemin_origine)).filter(|s| s.starts_with("S-1-5-21-") && s.chars().all(|c| c.is_ascii_digit() || c == '-' || c == 'S'));
    let sddl = format!("O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA){}", lecteur.as_ref().map(|s| format!("(A;OICI;0x1200a9;;;{s})")).unwrap_or_default());
    let lecteurs: Vec<&str> = lecteur.iter().map(String::as_str).collect();
    let conforme = |s: &natif::Securite| droits_conformes(s, &[SID_SYSTEME, SID_ADMINISTRATEURS], &lecteurs);
    let dossier = preparer_dossier_repli(&commun::dossier().join("restaurations"), &e.id, &sddl, commun::echec_protection().is_some(), &conforme)?;
    let cible = dossier.join(nom);
    let creer = |c: &Path| natif::creer_verifie(c).map_err(|x| format!("{} : {x}", c.display()));
    let chemin = restaurer_transaction(&dossier_quarantaine(), &mut liste, id, &cible, &creer, &ecrire_manifeste_service)?;
    Ok(format!("Fichier restauré dans le dossier de deR4Tizer : {chemin}"))
}

/// Action de reprise au démarrage d'une entrée, selon son état et la présence de l'original et de la copie.
/// Ne supprime jamais un original.
#[derive(Debug, PartialEq)]
pub enum Reprise {
    Rien,
    /// Quarantaine non aboutie (original intact) : copie et entrée retirées
    RetirerCopieEtEntree,
    /// Original supprimé, copie en place : la quarantaine est terminée
    MarquerTerminee,
    RetirerEntree,
    /// Fichier restauré disparu, copie en place : de nouveau en quarantaine
    RemettreTerminee,
    /// Anomalie journalisée, entrée conservée
    Signaler(&'static str),
}

/// Fichier présent à l'emplacement d'origine, comparé à l'empreinte enregistrée
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Original {
    Absent,
    Identique,
    /// Un autre fichier occupe le chemin : ce n'est pas l'original
    Different,
}

pub fn decision_reprise(etat: EtatQuarantaine, original: Original, copie: bool) -> Reprise {
    use EtatQuarantaine::*;
    use Original::*;
    match (etat, original, copie) {
        // Quarantaine non aboutie : l'original est intact, la copie n'a plus lieu d'être
        (EnCours, Identique, true) => Reprise::RetirerCopieEtEntree,
        // Original supprimé, ou remplacé par un autre fichier : la copie est le seul exemplaire, on la garde
        (EnCours, Absent | Different, true) => Reprise::MarquerTerminee,
        (EnCours, Identique | Different, false) => Reprise::RetirerEntree,
        (EnCours, Absent, false) => Reprise::Signaler("quarantaine interrompue : ni original ni copie"),
        (Terminee, _, true) => Reprise::Rien,
        (Terminee, _, false) => Reprise::Signaler("copie en quarantaine manquante"),
        // Restauration enregistrée et fichier restauré intact : la copie n'a plus lieu d'être
        (Restauree, Identique, true) => Reprise::RetirerCopieEtEntree,
        // Fichier restauré disparu ou différent : la copie redevient le seul exemplaire
        (Restauree, Absent | Different, true) => Reprise::RemettreTerminee,
        (Restauree, Identique | Different, false) => Reprise::RetirerEntree,
        (Restauree, Absent, false) => Reprise::Signaler("restauration interrompue : ni fichier restauré ni copie"),
    }
}

/// Original lu par handle, sans suivre de lien, chemin final vérifié : un lien ou un chemin détourné compte
/// comme « différent » (la copie est gardée) ; rien n'est lu hors du chemin
pub fn etat_original(chemin: &Path, sha256: &str) -> Original {
    // GENERIC_READ | SYNCHRONIZE, tout partage
    match natif::ouvrir_verifie(chemin, 0x8000_0000 | 0x0010_0000, 0x7, false) {
        Err(natif::ErreurOuverture::Absent) => Original::Absent,
        Err(_) => Original::Different,
        Ok(mut f) => {
            if empreinte_lecteur(&mut f).is_some_and(|h| h.eq_ignore_ascii_case(sha256)) { Original::Identique } else { Original::Different }
        }
    }
}

/// Applique la reprise à chaque entrée, puis signale les copies orphelines (sans entrée), conservées.
/// Renvoie les messages pour le journal ; `liste` est mise à jour (à enregistrer par l'appelant).
pub fn reprendre_quarantaine(dossier: &Path, liste: &mut Vec<ElementQuarantaine>) -> Vec<String> {
    let mut messages = Vec::new();
    let mut garder = Vec::new();
    for mut e in liste.drain(..) {
        let Some(nom) = e.nom_fichier() else {
            // Entrée au nom refusé : conservée telle quelle, sans rien supprimer ni déplacer (B3)
            messages.push(format!("quarantaine : entrée {} au nom de copie refusé, conservée sans action", e.id.chars().take(40).collect::<String>()));
            garder.push(e);
            continue;
        };
        let copie = dossier.join(nom);
        // Fichier restauré : à l'emplacement où il l'a été (origine ou dossier de repli)
        let chemin = if e.etat() == EtatQuarantaine::Restauree && !e.chemin_restaure.is_empty() { &e.chemin_restaure } else { &e.chemin_origine };
        let original = etat_original(Path::new(chemin), &e.sha256);
        let decision = decision_reprise(e.etat(), original, fs::symlink_metadata(&copie).is_ok());
        let garde = match decision {
            Reprise::Rien => true,
            Reprise::RetirerCopieEtEntree => {
                let _ = fs::remove_file(&copie);
                false
            }
            Reprise::MarquerTerminee | Reprise::RemettreTerminee => {
                e.marquer(EtatQuarantaine::Terminee);
                true
            }
            Reprise::RetirerEntree => false,
            Reprise::Signaler(m) => {
                messages.push(format!("quarantaine : {} : {m}", e.chemin_origine));
                true
            }
        };
        if !matches!(decision, Reprise::Rien | Reprise::Signaler(_)) {
            messages.push(format!("quarantaine : reprise de {} ({decision:?})", e.chemin_origine));
        }
        if garde {
            garder.push(e);
        }
    }
    *liste = garder;
    let connus: std::collections::HashSet<String> = liste.iter().filter_map(|e| e.nom_fichier()).map(|n| n.to_lowercase()).collect();
    for f in fs::read_dir(dossier).into_iter().flatten().flatten() {
        let n = f.file_name().to_string_lossy().to_string();
        if !connus.contains(&n.to_lowercase()) {
            messages.push(format!("quarantaine : copie orpheline conservée : {n}"));
        }
    }
    messages
}

/// Migration au démarrage (avant le tri du dossier de données) : une copie qui n'appartient pas à SYSTEM ou aux
/// administrateurs (déplacée avant la 4.3, elle garde le propriétaire de l'utilisateur) serait écartée par le
/// tri. Elle est recopiée de façon protégée (marque Internet relevée sur l'ancienne), la nouvelle copie est
/// ENREGISTRÉE, puis seulement l'ancienne est supprimée (sinon laissée au tri, jamais perdue). Une copie de
/// confiance sans empreinte reçoit la sienne. Renvoie les messages pour le journal.
pub fn migrer_quarantaine(dossier: &Path, liste: &mut Vec<ElementQuarantaine>, sddl: &str,
                          de_confiance: impl Fn(&Path) -> Option<bool>, ecrire: EcrireManifeste) -> Vec<String> {
    let mut messages = Vec::new();
    let mut empreintes_ajoutees = false;
    for i in 0..liste.len() {
        let Some(nom) = liste[i].nom_fichier() else { continue };
        let ancien = dossier.join(nom);
        if fs::symlink_metadata(&ancien).is_err() {
            continue;
        }
        let encodee = est_encodee(&ancien);
        if encodee && de_confiance(&ancien) == Some(true) {
            if liste[i].sha256.is_empty() {
                if let Some(h) = empreinte_copie(&ancien) {
                    liste[i].sha256 = h;
                    empreintes_ajoutees = true;
                }
            }
            continue;
        }
        let avant = liste[i].clone();
        let fichier = format!("{}-{}.quarantaine", avant.id, commun::nouvel_id());
        // Copie en clair : réencodée ; copie déjà encodée mais d'un autre propriétaire : recopiée telle quelle
        // (l'en-tête et le nonce restent ceux de l'ancien nom), empreinte décodée vérifiée
        let recopie = if encodee {
            natif::copier_protege(&ancien, &dossier.join(&fichier), sddl).and_then(|_| {
                let h = empreinte_copie(&dossier.join(&fichier)).ok_or("copie illisible")?;
                if !avant.sha256.is_empty() && !h.eq_ignore_ascii_case(&avant.sha256) {
                    let _ = fs::remove_file(dossier.join(&fichier));
                    return Err("empreinte différente de celle enregistrée".to_string());
                }
                Ok(h)
            })
        } else {
            fs::File::open(&ancien).map_err(|x| format!("ancienne copie illisible : {x}")).and_then(|mut f| copier_verifie(dossier, &mut f, &fichier, sddl))
        };
        let sha = match recopie {
            Ok(s) => s,
            Err(x) => {
                messages.push(format!("quarantaine : {} NON migrée ({x}) ; ancienne copie laissée au tri", avant.chemin_origine));
                continue;
            }
        };
        let e = &mut liste[i];
        e.fichier = fichier.clone();
        e.sha256 = sha;
        if e.zone_identifier.is_empty() {
            e.zone_identifier = lire_marque_internet(&ancien);
        }
        if let Err(x) = ecrire(liste) {
            liste[i] = avant.clone();
            let _ = fs::remove_file(dossier.join(&fichier));
            messages.push(format!("quarantaine : {} NON migrée (manifeste : {x}) ; ancienne copie laissée au tri", avant.chemin_origine));
            continue;
        }
        let supprime = fs::remove_file(&ancien).is_ok();
        messages.push(format!("quarantaine : {} recopiée avec ses droits{}", avant.chemin_origine,
            if supprime { "" } else { " (ancienne copie laissée au tri du démarrage)" }));
    }
    if empreintes_ajoutees {
        if let Err(x) = ecrire(liste) {
            messages.push(format!("quarantaine : empreintes non enregistrées ({x})"));
        }
    }
    messages
}

/// Reprise puis migration, appliquées au dossier de données du service (appelé par protection::imposer)
pub fn reprendre_et_migrer_quarantaine_service() -> Vec<String> {
    let f = commun::dossier().join("quarantaine.json");
    if fs::symlink_metadata(&f).is_err() {
        return Vec::new();
    }
    let Some(mut liste) = commun::lire_fichier_proprietaire(&f)
        .and_then(|t| serde_json::from_str::<Vec<ElementQuarantaine>>(t.trim_start_matches('\u{feff}')).ok()) else {
        return vec!["quarantaine : manifeste illisible ou au propriétaire non vérifié : reprise et migration non faites".into()];
    };
    let avant = liste.clone();
    let mut messages = reprendre_quarantaine(&dossier_quarantaine(), &mut liste);
    if liste != avant {
        if let Err(x) = ecrire_manifeste_service(&liste) {
            messages.push(format!("quarantaine : reprise non enregistrée ({x})"));
            return messages;
        }
    }
    messages.extend(migrer_quarantaine(&dossier_quarantaine(), &mut liste, SDDL_QUARANTAINE, natif::proprietaire_de_confiance, &ecrire_manifeste_service));
    messages
}

// ------------------------------------------------------------ pare-feu : programme isolé et mode panique

fn politique() -> windows::core::Result<INetFwPolicy2> {
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER)
    }
}

pub fn nom_regle_programme(chemin: &str, entrant: bool) -> String {
    format!("deR4Tizer - isole {} ({})", chemin, if entrant { "entrant" } else { "sortant" })
}

/// Chemin final rendu par Windows, sans préfixe `\\?\`, s'il est sur un lecteur local à lettre (pur, testé)
pub fn chemin_dos(chemin_final: &str) -> Option<String> {
    let s = chemin_final.strip_prefix(r"\\?\").unwrap_or(chemin_final);
    let b = s.as_bytes();
    (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\').then(|| s.to_string())
}

/// Décision pure : le refus du dossier Windows porte sur le chemin FINAL (noms courts, jonctions, points de montage
/// résolus) ; un chemin réseau ou un volume sans lettre est refusé. Rend le chemin à isoler (dossier de la phase 6)
pub fn isolation_permise(chemin_final: &str, windows: &str) -> Result<String, String> {
    let c = chemin_dos(chemin_final).ok_or("Refusé : le programme n'est pas sur un lecteur local (réseau ou volume sans lettre).")?;
    let (l, w) = (c.to_lowercase(), windows.trim_end_matches('\\').to_lowercase());
    if w.is_empty() || l == w || l.starts_with(&format!("{w}\\")) {
        return Err("Refusé : programme du système Windows (chemin final).".into());
    }
    // Un vrai binaire critique est sous Windows, déjà refusé : ailleurs, son nom ne sert qu'à faire couper le vrai par
    // une jonction posée après coup (audit de #118). La quarantaine convient mieux
    let nom = l.rsplit('\\').next().unwrap_or("");
    if CRITIQUES.iter().any(|x| x.rsplit('\\').next() == Some(nom)) {
        return Err(format!("Refusé : « {nom} » est le nom d'un programme critique de Windows, hors du dossier Windows ; la quarantaine convient mieux."));
    }
    Ok(c)
}

/// Ouvre le programme par handle, sans suivre de lien sur son dernier élément, et rend son chemin final s'il peut être
/// isolé : c'est ce chemin qui est comparé au dossier Windows et qui porte les règles (PR 6.6)
pub fn chemin_final_a_isoler(chemin: &str) -> Result<String, String> {
    if chemin.trim().is_empty() {
        return Err("Refusé : chemin vide.".into());
    }
    // Avant toute ouverture : le service (SYSTEM) ne contacte ni partage réseau ni tube nommé pour un chemin qui sera
    // refusé de toute façon (relecture de #118, R1)
    if chemin_dos(chemin).is_none() {
        return Err("Refusé : le programme n'est pas sur un lecteur local (réseau ou volume sans lettre).".into());
    }
    // Un dossier du chemin qui est un lien n'est pas traversé par SYSTEM : l'administrateur donne le chemin réel
    // (relecture de #119, R1). Une seule descente par handles : pas de course entre la vérification et l'ouverture
    // (audit de #119, S119-01). FILE_READ_ATTRIBUTES : un programme en cours reste ouvrable
    let f = natif::ouvrir_sans_traverser_lien(Path::new(chemin), 0x80).map_err(|e| match e {
        natif::ErreurOuverture::Absent => "Refusé : programme introuvable.".to_string(),
        natif::ErreurOuverture::Lien => "Refusé : le chemin est un lien (jonction ou lien symbolique).".to_string(),
        natif::ErreurOuverture::Detourne(p) => format!("Refusé : un dossier du chemin est un lien ({p}) ; donnez le chemin réel du programme."),
        natif::ErreurOuverture::Autre(r) if r.starts_with("dossier absent") => "Refusé : programme introuvable.".to_string(),
        natif::ErreurOuverture::Autre(r) => format!("Refusé : programme illisible ({r})."),
    })?;
    let reel = natif::chemin_final(&f).map_err(|e| format!("Refusé : chemin final illisible ({e})."))?;
    let c = isolation_permise(&reel, &natif::dossier_windows())?;
    // Nom d'un programme livré avec Windows (dllhost.exe, RuntimeBroker.exe…) : une jonction posée après coup ferait
    // couper le vrai (audit de #119, S119-03)
    let nom = c.rsplit('\\').next().unwrap_or("");
    if nom_programme_windows(nom, &natif::dossier_windows(), |p| p.is_file()) {
        return Err(format!("Refusé : « {nom} » est le nom d'un programme livré avec Windows ; hors du dossier Windows, la quarantaine convient mieux."));
    }
    Ok(c)
}

/// Décision pure : un programme de ce nom existe-t-il dans le dossier Windows, System32 ou SysWOW64 ?
pub fn nom_programme_windows(nom: &str, windows: &str, existe: impl Fn(&Path) -> bool) -> bool {
    let w = windows.trim_end_matches('\\');
    !nom.is_empty() && !w.is_empty() && !nom.contains(['\\', '/', ':'])
        && ["", "System32", "SysWOW64"].iter().any(|d| existe(&Path::new(w).join(d).join(nom)))
}

/// Une isolation tient-elle toujours ? La règle de pare-feu porte un chemin : un dossier remplacé après coup par une
/// jonction la ferait viser un autre programme, peut-être de Windows (audit de #118, S118-01)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EtatIsolation {
    Valable,
    /// Programme absent : la règle ne vise rien ; elle reste (copie ailleurs : limite écrite)
    Absent,
    /// Illisible à ce relevé : elle reste, relue au suivant
    Illisible,
    /// Le chemin mène ailleurs : chemin final constaté
    Detournee(String),
}

/// Décision pure. `cible_longue` : chemin isolé, noms courts développés ; `lu` : chemin final lu par handle, `Ok(None)`
/// si le programme est absent, `Err` s'il est illisible
pub fn decision_isolation(cible_longue: &str, lu: &Result<Option<String>, String>, windows: &str) -> EtatIsolation {
    match lu {
        Ok(None) => EtatIsolation::Absent,
        Err(_) => EtatIsolation::Illisible,
        Ok(Some(f)) => match isolation_permise(f, windows) {
            Err(_) => EtatIsolation::Detournee(f.clone()),
            Ok(c) if natif::meme_chemin(&c, cible_longue) => EtatIsolation::Valable,
            Ok(c) => EtatIsolation::Detournee(c),
        },
    }
}

/// Décision pure : une étiquette de point d'analyse redirige-t-elle le chemin ? Bit 29, « substitut de nom »
/// (IsReparseTagNameSurrogate) : jonctions, points de montage, liens symboliques, et toute autre étiquette qui redirige ;
/// pas les fichiers OneDrive à la demande ni la déduplication (relecture de #119, R2 ; audit, liste fermée remplacée)
pub fn etiquette_lien(etiquette: u32) -> bool {
    etiquette & 0x2000_0000 != 0
}

pub fn verifier_isolation(cible: &str) -> EtatIsolation {
    if chemin_dos(cible).is_none() {
        return EtatIsolation::Detournee(cible.to_string());
    }
    // Une seule descente par handles (audit de #119, S119-01). Un dossier du chemin devenu lien : détourné, sans le
    // traverser (il peut mener à un partage réseau) ; dossier absent ou illisible : la règle reste, relue au relevé
    // suivant (relecture de #119, R3)
    let lu = match natif::ouvrir_sans_traverser_lien(Path::new(cible), 0x80) {
        Ok(f) => natif::chemin_final(&f).map(Some),
        Err(natif::ErreurOuverture::Detourne(p)) => return EtatIsolation::Detournee(format!("{p} (lien)")),
        Err(natif::ErreurOuverture::Absent) => Ok(None),
        // Dernier élément remplacé par un lien : détourné, sans le suivre
        Err(natif::ErreurOuverture::Lien) => Ok(Some("(lien)".to_string())),
        Err(e) => Err(format!("{e:?}")),
    };
    // `cible` est déjà un chemin final (`chemin_final_a_isoler`) : aucune autre lecture du chemin entier, qui suivrait
    // un dossier remplacé par un lien après la descente (relecture de #126, D1)
    decision_isolation(cible, &lu, &natif::dossier_windows())
}

/// Bloque tout le trafic, entrant et sortant, d'un programme précis (`chemin` : chemin final, `chemin_final_a_isoler`)
pub fn isoler_programme(chemin: &str) -> Result<(), String> {
    unsafe {
        let p = politique().map_err(|e| e.to_string())?;
        for entrant in [false, true] {
            let r: INetFwRule = CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER).map_err(|e| e.to_string())?;
            r.SetName(&BSTR::from(nom_regle_programme(chemin, entrant))).map_err(|e| e.to_string())?;
            r.SetDescription(&BSTR::from("Programme isolé par deR4Tizer")).map_err(|e| e.to_string())?;
            r.SetGrouping(&BSTR::from(blocage::GROUPE)).map_err(|e| e.to_string())?;
            r.SetApplicationName(&BSTR::from(chemin)).map_err(|e| e.to_string())?;
            r.SetDirection(if entrant { NET_FW_RULE_DIR_IN } else { NET_FW_RULE_DIR_OUT }).map_err(|e| e.to_string())?;
            r.SetAction(NET_FW_ACTION_BLOCK).map_err(|e| e.to_string())?;
            r.SetProfiles(0x7FFF_FFFF).map_err(|e| e.to_string())?;
            r.SetEnabled(VARIANT_TRUE).map_err(|e| e.to_string())?;
            p.Rules().and_then(|rs| rs.Add(&r)).map_err(|e| e.to_string())?;
        }
    }
    // Coupe aussi les connexions déjà ouvertes par ce programme
    for c in natif::lister_tcp() {
        if c.etat == 5 && natif::chemin_processus(c.pid).eq_ignore_ascii_case(chemin) {
            natif::couper(&c);
        }
    }
    Ok(())
}

pub fn liberer_programme(chemin: &str) -> usize {
    let Ok(p) = politique() else { return 0 };
    let mut n = 0;
    unsafe {
        let Ok(regles) = p.Rules() else { return 0 };
        for entrant in [false, true] {
            let nom = BSTR::from(nom_regle_programme(chemin, entrant));
            while regles.Item(&nom).is_ok() && n < 20 && regles.Remove(&nom).is_ok() {
                n += 1;
            }
        }
    }
    n
}

const PROFILS: [windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_PROFILE_TYPE2; 3] =
    [NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC];

const PANIQUE_SORTANT: &str = "deR4Tizer PANIQUE (sortant)";
const PANIQUE_ENTRANT: &str = "deR4Tizer PANIQUE (entrant)";

/// Réseaux privés et réservés, jamais bloqués par le mode panique (le réseau local reste joignable)
const RESERVES: &[(u32, u32)] = &[
    (0x0000_0000, 0x00FF_FFFF), (0x0A00_0000, 0x0AFF_FFFF), (0x6440_0000, 0x647F_FFFF), (0x7F00_0000, 0x7FFF_FFFF),
    (0xA9FE_0000, 0xA9FE_FFFF), (0xAC10_0000, 0xAC1F_FFFF), (0xC0A8_0000, 0xC0A8_FFFF), (0xE000_0000, 0xFFFF_FFFF),
];

/// Plages IPv4 publiques privées des adresses à épargner, au format du pare-feu (« a.b.c.d-e.f.g.h »)
pub fn plages_internet(epargnees: &[std::net::Ipv4Addr]) -> Vec<String> {
    let mut trous: Vec<(u32, u32)> = RESERVES.to_vec();
    trous.extend(epargnees.iter().map(|ip| (u32::from(*ip), u32::from(*ip))));
    trous.sort();
    let mut plages = Vec::new();
    let mut debut: u64 = 0;
    for (d, f) in trous {
        if (d as u64) > debut {
            plages.push((debut as u32, d - 1));
        }
        debut = debut.max(f as u64 + 1);
    }
    if debut <= u32::MAX as u64 {
        plages.push((debut as u32, u32::MAX));
    }
    plages.iter().map(|(d, f)| format!("{}-{}", std::net::Ipv4Addr::from(*d), std::net::Ipv4Addr::from(*f))).collect()
}

/// Adresses à épargner : serveurs DNS de la machine et serveurs de notification (pour que l'alerte parte). Lance un
/// PowerShell et des résolutions DNS : appelée hors du verrou du moniteur (`moniteur::preparer`, PR 6.5)
pub fn epargnees() -> Vec<std::net::Ipv4Addr> {
    use std::net::ToSocketAddrs;
    let mut l = Vec::new();
    crate::mesure::powershell("reponse");
    let dns = std::process::Command::new(crate::natif::powershell_exe())
        .args(["-NoProfile", "-NonInteractive", "-Command", "(Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses -join ','"])
        .output().map(|s| String::from_utf8_lossy(&s.stdout).trim().to_string()).unwrap_or_default();
    l.extend(dns.split(',').filter_map(|x| x.trim().parse::<std::net::Ipv4Addr>().ok()));
    let config: commun::Config = commun::lire("config.json").unwrap_or_default();
    let secrets = crate::notifications::lire_secrets();
    let mut hotes = Vec::new();
    for url in [&secrets.ntfy_url, &secrets.teams_url] {
        if let Some(h) = url.strip_prefix("https://").and_then(|r| r.split(['/', ':']).next()) {
            hotes.push(format!("{h}:443"));
        }
    }
    if config.notifications.smtp && !config.notifications.smtp_serveur.is_empty() {
        hotes.push(format!("{}:{}", config.notifications.smtp_serveur, config.notifications.smtp_port));
    }
    for h in hotes {
        if let Ok(a) = h.to_socket_addrs() {
            l.extend(a.filter_map(|x| match x.ip() { std::net::IpAddr::V4(v) => Some(v), _ => None }));
        }
    }
    l.sort();
    l.dedup();
    l
}

fn regle_blocage(p: &INetFwPolicy2, nom: &str, sortant: bool, adresses: &str) -> windows::core::Result<()> {
    unsafe {
        let r: INetFwRule = CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER)?;
        r.SetName(&BSTR::from(nom))?;
        r.SetDescription(&BSTR::from("Mode panique de deR4Tizer : Internet coupé, réseau local et alertes conservés"))?;
        r.SetGrouping(&BSTR::from(blocage::GROUPE))?;
        r.SetDirection(if sortant { NET_FW_RULE_DIR_OUT } else { NET_FW_RULE_DIR_IN })?;
        r.SetAction(NET_FW_ACTION_BLOCK)?;
        r.SetProtocol(256)?;
        r.SetRemoteAddresses(&BSTR::from(adresses))?;
        r.SetProfiles(0x7FFF_FFFF)?;
        r.SetEnabled(VARIANT_TRUE)?;
        p.Rules()?.Add(&r)
    }
}

const PANIQUE_REGLES: [&str; 2] = [PANIQUE_SORTANT, PANIQUE_ENTRANT];

/// Le pare-feu tel que le voit le mode panique : celui de Windows, ou un pare-feu simulé dans les tests (PR 6.5)
pub trait PareFeuPanique {
    fn ajouter(&self, nom: &str, sortant: bool, adresses: &str) -> Result<(), String>;
    /// Retire toutes les règles de ce nom
    fn retirer(&self, nom: &str);
    /// Une règle de ce nom existe, activée, en blocage
    fn presente(&self, nom: &str) -> bool;
}

struct PareFeuWindows(INetFwPolicy2);

impl PareFeuPanique for PareFeuWindows {
    fn ajouter(&self, nom: &str, sortant: bool, adresses: &str) -> Result<(), String> {
        regle_blocage(&self.0, nom, sortant, adresses).map_err(|e| e.to_string())
    }
    fn retirer(&self, nom: &str) {
        unsafe {
            if let Ok(regles) = self.0.Rules() {
                let b = BSTR::from(nom);
                let mut n = 0;
                while regles.Item(&b).is_ok() && n < 10 && regles.Remove(&b).is_ok() {
                    n += 1;
                }
            }
        }
    }
    fn presente(&self, nom: &str) -> bool {
        unsafe {
            self.0.Rules().and_then(|rs| rs.Item(&BSTR::from(nom)))
                .map(|r| r.Enabled().map(|e| e == VARIANT_TRUE).unwrap_or(false) && r.Action().map(|a| a == NET_FW_ACTION_BLOCK).unwrap_or(false))
                .unwrap_or(false)
        }
    }
}

/// État effectif du mode panique, compté sur les règles et pas sur le drapeau seul (dossier de la phase 6, § 4.6)
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum EtatPanique {
    #[default]
    Inactive,
    Active,
    /// Drapeau sans ses deux règles, ou règle sans drapeau : seule « Rétablir Internet » est sûre
    Incertaine,
}

impl EtatPanique {
    pub fn texte(self) -> &'static str {
        match self {
            EtatPanique::Inactive => "inactive",
            EtatPanique::Active => "active",
            EtatPanique::Incertaine => "incertaine",
        }
    }
}

pub fn etat_panique_de(pf: &dyn PareFeuPanique, drapeau: bool) -> EtatPanique {
    match (drapeau, PANIQUE_REGLES.iter().filter(|n| pf.presente(n)).count()) {
        (true, 2) => EtatPanique::Active,
        (false, 0) => EtatPanique::Inactive,
        _ => EtatPanique::Incertaine,
    }
}

/// Activation transactionnelle : les deux règles posées et vérifiées, puis seulement le drapeau. Un échec à n'importe
/// quelle étape retire ce qui a été posé : jamais d'état moitié posé (pur, testé sur un pare-feu simulé)
pub fn activer_panique(pf: &dyn PareFeuPanique, adresses: &str, ecrire_drapeau: &dyn Fn() -> Result<(), String>) -> Result<(), String> {
    for n in PANIQUE_REGLES {
        pf.retirer(n);
    }
    let pose = pf.ajouter(PANIQUE_SORTANT, true, adresses)
        .and_then(|_| pf.ajouter(PANIQUE_ENTRANT, false, adresses))
        .and_then(|_| match PANIQUE_REGLES.iter().find(|n| !pf.presente(n)) {
            Some(n) => Err(format!("règle « {n} » absente ou inactive après l'ajout")),
            None => Ok(()),
        })
        .and_then(|_| ecrire_drapeau());
    if let Err(e) = pose {
        for n in PANIQUE_REGLES {
            pf.retirer(n);
        }
        if PANIQUE_REGLES.iter().any(|n| pf.presente(n)) {
            return Err(format!("{e} ; retrait incomplet, état incertain"));
        }
        return Err(e);
    }
    Ok(())
}

/// Désactivation : retrait, vérification qu'aucune règle ne reste, puis seulement effacement du drapeau. Une règle
/// restée garde le drapeau : l'état publié est « incertain », pas « inactif » (pur, testé)
pub fn desactiver_panique(pf: &dyn PareFeuPanique, effacer_drapeau: &dyn Fn() -> Result<(), String>) -> Result<(), String> {
    for n in PANIQUE_REGLES {
        pf.retirer(n);
    }
    let restes: Vec<&str> = PANIQUE_REGLES.iter().copied().filter(|n| pf.presente(n)).collect();
    if !restes.is_empty() {
        return Err(format!("règle(s) toujours présente(s) après le retrait : {} ; état incertain", restes.join(", ")));
    }
    effacer_drapeau()
}

fn drapeau_panique() -> PathBuf {
    commun::dossier().join("panique-active")
}

/// Une commande du mode panique pose ou retire ses règles : l'état est un instant « incertain », sans que ce soit un
/// incident (audit de #117)
static COMMANDE_PANIQUE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Augmentée au début et à la fin de chaque commande du mode panique
static GENERATION_PANIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn commande_panique_en_cours() -> bool {
    COMMANDE_PANIQUE.load(std::sync::atomic::Ordering::SeqCst)
}

/// Dernier état effectif lu, publié dans `etat.json` sans requête au pare-feu sous le verrou du moniteur
static ETAT_PANIQUE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Relit l'état effectif (règles et drapeau) : fil « sante » toutes les 30 s, et après chaque commande
/// `None` : le pare-feu n'a pas répondu à temps ; l'état publié reste le précédent, et rien ne doit en être conclu
/// (audit de #122, S122-03)
pub fn rafraichir_etat_panique() -> Option<EtatPanique> {
    // Une commande commencée ou finie pendant la lecture a publié son propre état : celui-ci, plus ancien, ne
    // l'écrase pas (relecture de #118, R2). Lecture sur un fil à part, avec une échéance : un pare-feu figé ne fige pas
    // le fil « sante » (audit de #117, S117-02) ; l'état publié reste alors le précédent
    let generation = GENERATION_PANIQUE.load(std::sync::atomic::Ordering::SeqCst);
    let lu = avec_echeance(&LECTURE_PANIQUE, std::time::Duration::from_secs(DELAI_LECTURE_PANIQUE), move || {
        let e = lire_etat_panique();
        if lecture_publiable(generation, GENERATION_PANIQUE.load(std::sync::atomic::Ordering::SeqCst), commande_panique_en_cours()) {
            ETAT_PANIQUE.store(e as u8, std::sync::atomic::Ordering::Relaxed);
        }
        e
    });
    // Une ligne au début et à la fin d'une panne, pas une par relevé (audit de #122, S122-02)
    if let Some(ligne) = transition_pare_feu(PARE_FEU_MUET.swap(lu.is_none(), std::sync::atomic::Ordering::SeqCst), lu.is_none()) {
        commun::journal(ligne);
    }
    lu
}

static PARE_FEU_MUET: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Ligne de journal à écrire quand le pare-feu devient muet ou répond de nouveau ; rien sinon (pur, testé)
pub fn transition_pare_feu(muet_avant: bool, muet: bool) -> Option<&'static str> {
    match (muet_avant, muet) {
        (false, true) => Some("mode panique : le pare-feu ne répond pas, état publié inchangé jusqu'à sa réponse"),
        (true, false) => Some("mode panique : le pare-feu répond de nouveau"),
        _ => None,
    }
}

/// Échéance d'une lecture de l'état du pare-feu
const DELAI_LECTURE_PANIQUE: u64 = 10;
static LECTURE_PANIQUE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Exécute `f` sur un fil à part et attend `delai` au plus. Une lecture précédente encore figée : `None` tout de suite,
/// sans nouveau fil (un pare-feu muet n'accumule pas de fils). `occupe` est relâché par le fil à la fin de `f` (testé)
pub fn avec_echeance<T: Send + 'static>(occupe: &'static std::sync::atomic::AtomicBool, delai: std::time::Duration, f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    use std::sync::atomic::Ordering::SeqCst;
    if occupe.swap(true, SeqCst) {
        return None;
    }
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let r = f();
        occupe.store(false, SeqCst);
        let _ = tx.send(r);
    });
    rx.recv_timeout(delai).ok()
}

pub fn generation_panique() -> u64 {
    GENERATION_PANIQUE.load(std::sync::atomic::Ordering::SeqCst)
}

/// Décision pure : une lecture faite hors commande, sans commande commencée ni finie pendant elle, peut être publiée
pub fn lecture_publiable(generation_avant: u64, generation_apres: u64, commande_en_cours: bool) -> bool {
    !commande_en_cours && generation_avant == generation_apres
}

/// Décision pure : état à publier avant la première lecture des règles. Drapeau présent : rien ne dit que les règles
/// sont là, « incertaine » (l'interface offre « Rétablir Internet ») ; absent : « inactive »
pub fn etat_provisoire(drapeau: bool) -> EtatPanique {
    if drapeau { EtatPanique::Incertaine } else { EtatPanique::Inactive }
}

/// Au démarrage du service : aucune requête au pare-feu
pub fn etat_provisoire_panique() {
    ETAT_PANIQUE.store(etat_provisoire(drapeau_panique().exists()) as u8, std::sync::atomic::Ordering::Relaxed);
}

fn lire_etat_panique() -> EtatPanique {
    let drapeau = drapeau_panique().exists();
    match politique() {
        Ok(p) => etat_panique_de(&PareFeuWindows(p), drapeau),
        // Règles illisibles : avec le drapeau, rien ne dit qu'elles sont là
        Err(_) if drapeau => EtatPanique::Incertaine,
        Err(_) => EtatPanique::Inactive,
    }
}

pub fn etat_panique() -> EtatPanique {
    match ETAT_PANIQUE.load(std::sync::atomic::Ordering::Relaxed) {
        1 => EtatPanique::Active,
        2 => EtatPanique::Incertaine,
        _ => EtatPanique::Inactive,
    }
}

/// Mode panique : deux règles de BLOCAGE (qui priment sur toutes les règles d'autorisation, y compris celles
/// qu'un programme malveillant aurait créées) vers tout Internet, IPv4 et IPv6 globales ; le réseau local, les
/// serveurs DNS et les serveurs de notification (`epargnees`, lues hors du verrou) restent joignables. Rien d'autre
/// n'est modifié : la sortie du mode retire simplement les deux règles. Transactionnel depuis la PR 6.5
pub fn panique(activer: bool, epargnees: &[std::net::Ipv4Addr]) -> Result<String, String> {
    struct EnCours;
    impl Drop for EnCours {
        fn drop(&mut self) {
            GENERATION_PANIQUE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            COMMANDE_PANIQUE.store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }
    GENERATION_PANIQUE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    COMMANDE_PANIQUE.store(true, std::sync::atomic::Ordering::SeqCst);
    let _en_cours = EnCours;
    let p = politique().map_err(|e| e.to_string())?;
    let pf = PareFeuWindows(p);
    let resultat = if !activer {
        desactiver_panique(&pf, &|| match fs::remove_file(drapeau_panique()) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(format!("drapeau du mode panique non effacé : {e}")),
            _ => Ok(()),
        })
        .map(|_| "Mode panique désactivé : Internet de nouveau accessible.".to_string())
    } else if etat_panique_de(&pf, drapeau_panique().exists()) == EtatPanique::Active {
        Ok("Mode panique déjà actif.".to_string())
    } else {
        let mut adresses = plages_internet(epargnees);
        adresses.push("2000::-3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".into());
        // Profils désactivés avant : réactivés pour que les règles s'appliquent, rendus tels quels si l'activation échoue
        // (audit de #117, S117-01)
        // Un profil illisible est réactivé aussi, sans être rendu : la coupure s'applique partout (audit de #117)
        let lus: Vec<_> = PROFILS.into_iter().map(|p| (p, unsafe { pf.0.get_FirewallEnabled(p) }.ok().map(|v| v == VARIANT_TRUE))).collect();
        let desactives: Vec<_> = lus.iter().filter(|(_, actif)| *actif == Some(false)).map(|(p, _)| *p).collect();
        unsafe {
            for (profil, actif) in &lus {
                if *actif != Some(true) {
                    let _ = pf.0.put_FirewallEnabled(*profil, VARIANT_TRUE);
                }
            }
        }
        activer_panique(&pf, &adresses.join(","), &|| fs::write(drapeau_panique(), commun::maintenant()).map_err(|e| format!("drapeau du mode panique non écrit : {e}")))
            .map_err(|e| {
                unsafe {
                    for profil in &desactives {
                        let _ = pf.0.put_FirewallEnabled(*profil, VARIANT_FALSE);
                    }
                }
                e
            })
            .map(|_| {
                // Coupe immédiatement les connexions vers Internet en cours (les règles ne s'appliquent qu'aux nouvelles)
                let n = natif::lister_tcp().iter()
                    .filter(|c| c.etat == 5 && c.ip.parse().map(|a| crate::parefeu::publique(&a)).unwrap_or(false))
                    .filter(|c| !c.ip.parse::<std::net::Ipv4Addr>().map(|a| epargnees.contains(&a)).unwrap_or(false))
                    .filter(|c| natif::couper(c)).count();
                format!("MODE PANIQUE : Internet coupé pour tous les programmes ; réseau local, DNS et {} serveur(s) de notification conservés ; {n} connexion(s) coupée(s).",
                    epargnees.len())
            })
    };
    // État final de la commande, publié par elle seule
    ETAT_PANIQUE.store(lire_etat_panique() as u8, std::sync::atomic::Ordering::Relaxed);
    resultat
}
