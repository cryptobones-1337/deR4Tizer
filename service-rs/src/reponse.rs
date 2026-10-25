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
use windows::Win32::Foundation::{CloseHandle, VARIANT_TRUE};
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, NetFwPolicy2, NetFwRule, NET_FW_ACTION_BLOCK, NET_FW_PROFILE2_DOMAIN,
    NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC, NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT,
};
use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE};

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
pub fn protege(pid: u32) -> Option<String> {
    if pid <= 4 || pid == std::process::id() {
        return Some("processus du système ou de deR4Tizer".into());
    }
    // Chemin complet canonique (QueryFullProcessImageName), comparé exactement ; signature Microsoft en plus
    let chemin = natif::chemin_processus(pid);
    let nom = Path::new(&chemin).file_stem().map(|s| s.to_string_lossy().to_lowercase()).unwrap_or_default();
    (chemin_critique(&chemin, &natif::dossier_windows()) && natif::binaire_windows(&chemin))
        .then(|| format!("{nom} est un processus critique de Windows (le système ou le réseau se figerait)"))
}

pub fn tuer(pid: u32) -> Result<(), String> {
    if let Some(r) = protege(pid) {
        return Err(format!("refusé : {r}"));
    }
    unsafe {
        let h = OpenProcess(PROCESS_TERMINATE, false, pid).map_err(|e| e.to_string())?;
        let r = TerminateProcess(h, 1).map_err(|e| e.to_string());
        let _ = CloseHandle(h);
        r
    }
}

/// Suspend ou reprend tous les fils d'un processus (fonctions NtSuspendProcess / NtResumeProcess de ntdll)
pub fn suspendre(pid: u32, suspendre: bool) -> Result<(), String> {
    if suspendre {
        if let Some(r) = protege(pid) {
            return Err(format!("refusé : {r}"));
        }
    }
    unsafe {
        let nom = large("ntdll.dll");
        let module = LoadLibraryW(PCWSTR(nom.as_ptr())).map_err(|e| e.to_string())?;
        let fonction = if suspendre { windows::core::s!("NtSuspendProcess") } else { windows::core::s!("NtResumeProcess") };
        let f = GetProcAddress(module, fonction).ok_or("fonction introuvable")?;
        let f: extern "system" fn(windows::Win32::Foundation::HANDLE) -> i32 = std::mem::transmute(f);
        let h = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid).map_err(|e| e.to_string())?;
        let statut = f(h);
        let _ = CloseHandle(h);
        if statut == 0 { Ok(()) } else { Err(format!("statut NT 0x{statut:08X}")) }
    }
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

impl ElementQuarantaine {
    pub fn nom_fichier(&self) -> String {
        if self.fichier.is_empty() { format!("{}.quarantaine", self.id) } else { self.fichier.clone() }
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
        if natif::chemin_processus(pid).eq_ignore_ascii_case(chemin) {
            let _ = tuer(pid);
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
    let source = dossier.join(e.nom_fichier());
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
        let copie = dossier.join(e.nom_fichier());
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
    let connus: std::collections::HashSet<String> = liste.iter().map(|e| e.nom_fichier().to_lowercase()).collect();
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
        let ancien = dossier.join(liste[i].nom_fichier());
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

/// Bloque tout le trafic, entrant et sortant, d'un programme précis
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

/// Adresses à épargner : serveurs DNS de la machine et serveurs de notification (pour que l'alerte parte)
fn epargnees() -> Vec<std::net::Ipv4Addr> {
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

/// Mode panique : deux règles de BLOCAGE (qui priment sur toutes les règles d'autorisation, y compris celles
/// qu'un programme malveillant aurait créées) vers tout Internet, IPv4 et IPv6 globales ; le réseau local, les
/// serveurs DNS et les serveurs de notification restent joignables. Rien d'autre n'est modifié : la sortie
/// du mode retire simplement les deux règles.
pub fn panique(activer: bool) -> Result<String, String> {
    let p = politique().map_err(|e| e.to_string())?;
    unsafe {
        if let Ok(regles) = p.Rules() {
            for nom in [PANIQUE_SORTANT, PANIQUE_ENTRANT] {
                let b = BSTR::from(nom);
                let mut n = 0;
                while regles.Item(&b).is_ok() && n < 10 && regles.Remove(&b).is_ok() {
                    n += 1;
                }
            }
        }
    }
    if !activer {
        let _ = fs::remove_file(commun::dossier().join("panique-active"));
        return Ok("Mode panique désactivé : Internet de nouveau accessible.".into());
    }
    let epargnees = epargnees();
    let mut adresses = plages_internet(&epargnees);
    adresses.push("2000::-3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".into());
    let liste = adresses.join(",");
    regle_blocage(&p, PANIQUE_SORTANT, true, &liste).map_err(|e| e.to_string())?;
    regle_blocage(&p, PANIQUE_ENTRANT, false, &liste).map_err(|e| e.to_string())?;
    unsafe {
        for profil in PROFILS {
            let _ = p.put_FirewallEnabled(profil, VARIANT_TRUE);
        }
    }
    // Coupe immédiatement les connexions vers Internet en cours (les règles ne s'appliquent qu'aux nouvelles)
    let n = natif::lister_tcp().iter()
        .filter(|c| c.etat == 5 && c.ip.parse().map(|a| crate::parefeu::publique(&a)).unwrap_or(false))
        .filter(|c| !c.ip.parse::<std::net::Ipv4Addr>().map(|a| epargnees.contains(&a)).unwrap_or(false))
        .filter(|c| natif::couper(c)).count();
    fs::write(commun::dossier().join("panique-active"), commun::maintenant()).map_err(|e| e.to_string())?;
    Ok(format!("MODE PANIQUE : Internet coupé pour tous les programmes ; réseau local, DNS et {} serveur(s) de notification conservés ; {n} connexion(s) coupée(s).",
        epargnees.len()))
}

pub fn panique_active() -> bool {
    commun::dossier().join("panique-active").exists()
}
