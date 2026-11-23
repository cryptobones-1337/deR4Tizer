//! Stratégie de groupe locale (GPO locale) : lecture et écriture de Registry.pol (format PReg),
//! de la stratégie d'audit avancée (audit.csv) et de gpt.ini, puis application avec gpupdate.
//! Les réglages apparaissent ainsi comme de vraies stratégies, comme le ferait gpedit.msc ou LGPO.exe.
//!
//! Échec fermé (audit du 2026-11-23, A-2-2) : ces fichiers portent aussi les stratégies machine d'autres outils
//! (Defender, Windows Update, restrictions). Seul « fichier introuvable » vaut « vide » ; un fichier présent mais
//! illisible, tronqué ou d'un format non compris arrête l'opération avant toute écriture. Chaque fichier est écrit
//! d'un bloc (fichier voisin puis remplacement), sans changer ses droits.

use std::fs;
use std::io::Write;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const REG_SZ: u32 = 1;
pub const REG_DWORD: u32 = 4;

/// Extensions côté client : Registre (+ outil d'administration) et Audit avancé
const CSE_REGISTRE: &str = "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]";
const CSE_AUDIT: &str = "[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]";

/// En-tête d'un fichier de stratégie d'audit avancée ([MS-GPAC] 2.2 : fichier UTF-8, fins de ligne CRLF)
const ENTETE_AUDIT: &str = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value";

pub fn racine() -> PathBuf {
    PathBuf::from(crate::natif::dossier_systeme()).join("GroupPolicy")
}

fn fichier_pol() -> PathBuf {
    racine().join(r"Machine\Registry.pol")
}

pub fn fichier_audit() -> PathBuf {
    racine().join(r"Machine\Microsoft\Windows NT\Audit\audit.csv")
}

fn fichier_gpt() -> PathBuf {
    racine().join("gpt.ini")
}

/// Programme de System32 par son chemin complet : un nom nu est d'abord cherché dans le dossier de l'exécutable du
/// service, puis dans le PATH (audit du 2026-11-23, A-2-1)
pub fn outil_systeme(nom: &str) -> String {
    format!(r"{}\{nom}", crate::natif::dossier_systeme())
}

#[derive(Clone, Debug, PartialEq)]
pub struct EntreePol {
    pub cle: String,
    pub nom: String,
    pub type_: u32,
    pub donnees: Vec<u8>,
}

impl EntreePol {
    pub fn dword(cle: &str, nom: &str, v: u32) -> Self {
        EntreePol { cle: cle.into(), nom: nom.into(), type_: REG_DWORD, donnees: v.to_le_bytes().to_vec() }
    }
    pub fn texte(cle: &str, nom: &str, v: &str) -> Self {
        let donnees = v.encode_utf16().chain(std::iter::once(0)).flat_map(|c| c.to_le_bytes()).collect();
        EntreePol { cle: cle.into(), nom: nom.into(), type_: REG_SZ, donnees }
    }
    fn meme_valeur(&self, autre: &EntreePol) -> bool {
        self.cle.eq_ignore_ascii_case(&autre.cle) && self.nom.eq_ignore_ascii_case(&autre.nom)
    }
}

// ------------------------------------------------------------ lecture et écriture des fichiers

/// Contenu d'un fichier de la GPO : None s'il est introuvable ; toute autre erreur (fichier tenu par un autre
/// programme, droits, chemin qui n'est pas un fichier) est une erreur, jamais « vide » (A-2-2)
pub fn lire_ou_absent(chemin: &Path) -> Result<Option<Vec<u8>>, String> {
    match fs::read(chemin) {
        Ok(o) => Ok(Some(o)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{} illisible ({e})", nom_court(chemin))),
    }
}

fn nom_court(chemin: &Path) -> String {
    chemin.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| chemin.display().to_string())
}

/// Façon de remplacer un fichier existant
#[derive(Debug, PartialEq)]
pub enum ModeEcriture {
    /// Fichier voisin puis remplacement d'un bloc : seulement si ses droits sont ceux de l'original
    Remplacer,
    /// Réécriture du fichier lui-même, qui garde ses droits
    EnPlace,
}

/// Décision pure : le fichier voisin (droits hérités du dossier) ne remplace l'original que si propriétaire,
/// héritage et entrées de la DACL sont identiques ; droits illisibles, entrée non reconnue ou différence : le
/// fichier est réécrit en place, pour ne jamais changer les droits d'un fichier de stratégie (A-2-2)
pub fn mode_ecriture(original: Option<&crate::natif::Securite>, voisin: Option<&crate::natif::Securite>) -> ModeEcriture {
    match (original, voisin) {
        (Some(o), Some(v)) if !o.ace_inconnue && !v.ace_inconnue && o.proprietaire == v.proprietaire && o.protege == v.protege && o.aces == v.aces => {
            ModeEcriture::Remplacer
        }
        _ => ModeEcriture::EnPlace,
    }
}

/// Écrit un fichier de la GPO d'un bloc : fichier voisin dans le même dossier, relu, puis remplacement
/// (MoveFileExW, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) si les droits restent les mêmes ; sinon
/// réécriture en place relue. Le chemin doit être un fichier ordinaire (jamais un lien) ou absent.
pub fn ecrire_d_un_bloc(chemin: &Path, contenu: &[u8]) -> Result<(), String> {
    let nom = nom_court(chemin);
    let dossier = chemin.parent().ok_or_else(|| format!("{nom} : dossier introuvable"))?;
    fs::create_dir_all(dossier).map_err(|e| format!("{nom} : dossier non créé ({e})"))?;
    let existe = match fs::symlink_metadata(chemin) {
        Ok(m) if m.file_type().is_file() => true,
        Ok(_) => return Err(format!("{nom} n'est pas un fichier ordinaire : rien n'est écrit")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(format!("{nom} illisible ({e}) : rien n'est écrit")),
    };
    // Fichiers voisins laissés par un arrêt brutal (même motif exact, autre PID) : retirés avant l'écriture (S270-02)
    if let Ok(l) = fs::read_dir(dossier) {
        for x in l.flatten() {
            let n = x.file_name().to_string_lossy().into_owned();
            if est_voisin_orphelin(&n, &nom) && fs::symlink_metadata(x.path()).map(|m| m.file_type().is_file()).unwrap_or(false) {
                let _ = fs::remove_file(x.path());
            }
        }
    }
    let voisin = dossier.join(format!("{nom}.d4t-{}.tmp", std::process::id()));
    let _ = fs::remove_file(&voisin);
    let ecrit = (|| -> std::io::Result<()> {
        let mut f = fs::OpenOptions::new().write(true).create_new(true).open(&voisin)?;
        f.write_all(contenu)?;
        f.sync_all()
    })();
    if let Err(e) = ecrit.map_err(|e| e.to_string()).and_then(|_| relire_identique(&voisin, contenu)) {
        let _ = fs::remove_file(&voisin);
        return Err(format!("{nom} : fichier voisin non écrit ({e}) : rien n'est modifié"));
    }
    let mode = if existe {
        mode_ecriture(crate::natif::lire_securite(chemin).as_ref(), crate::natif::lire_securite(&voisin).as_ref())
    } else {
        ModeEcriture::Remplacer
    };
    match mode {
        ModeEcriture::Remplacer => remplacer(&voisin, chemin).map_err(|e| {
            let _ = fs::remove_file(&voisin);
            format!("{nom} : remplacement impossible ({e}) : rien n'est modifié")
        }),
        ModeEcriture::EnPlace => {
            let _ = fs::remove_file(&voisin);
            let r = (|| -> std::io::Result<()> {
                // Sans création : le fichier existe, et ses droits restent les siens
                let mut f = fs::OpenOptions::new().write(true).truncate(true).open(chemin)?;
                f.write_all(contenu)?;
                f.sync_all()
            })();
            r.map_err(|e| e.to_string()).and_then(|_| relire_identique(chemin, contenu)).map_err(|e| format!("{nom} : réécriture en place en échec ({e})"))
        }
    }
}

/// Décision pure : nom d'un fichier voisin de deR4Tizer pour ce fichier, motif exact « <nom>.d4t-<chiffres>.tmp »
pub fn est_voisin_orphelin(fichier: &str, nom: &str) -> bool {
    fichier
        .strip_prefix(nom)
        .and_then(|r| r.strip_prefix(".d4t-"))
        .and_then(|r| r.strip_suffix(".tmp"))
        .map(|pid| !pid.is_empty() && pid.len() <= 10 && pid.bytes().all(|b| b.is_ascii_digit()))
        .unwrap_or(false)
}

fn relire_identique(chemin: &Path, contenu: &[u8]) -> Result<(), String> {
    match fs::read(chemin) {
        Ok(o) if o == contenu => Ok(()),
        Ok(_) => Err("relu différent de celui écrit".into()),
        Err(e) => Err(format!("illisible après écriture ({e})")),
    }
}

fn remplacer(source: &Path, cible: &Path) -> Result<(), String> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH};
    let (s, c) = (crate::natif::large(&source.to_string_lossy()), crate::natif::large(&cible.to_string_lossy()));
    unsafe { MoveFileExW(PCWSTR(s.as_ptr()), PCWSTR(c.as_ptr()), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH).map_err(|e| e.to_string()) }
}

// ------------------------------------------------------------ Registry.pol (PReg)

/// Lit Registry.pol : "PReg", version 1, puis des entrées [clé;nom;type;taille;données] en UTF-16
pub fn lire_pol() -> Result<Vec<EntreePol>, String> {
    lire_pol_de(&fichier_pol())
}

pub fn lire_pol_de(f: &Path) -> Result<Vec<EntreePol>, String> {
    match lire_ou_absent(f)? {
        None => Ok(Vec::new()),
        Some(o) => decoder_pol(&o).map_err(|e| format!("Registry.pol non compris ({e})")),
    }
}

/// Décodage strict de Registry.pol : un fichier vide ne porte rien ; sinon l'en-tête doit être « PReg » version 1
/// et le fichier entier doit être consommé, chaque séparateur vérifié. Toute entrée tronquée ou mal formée est une
/// erreur : jamais une liste partielle, qui ferait effacer les stratégies suivantes à la réécriture (A-2-2)
pub fn decoder_pol(o: &[u8]) -> Result<Vec<EntreePol>, String> {
    if o.is_empty() {
        return Ok(Vec::new());
    }
    if o.get(0..4) != Some(b"PReg".as_slice()) {
        return Err("en-tête inconnu".into());
    }
    let u32_a = |p: usize| -> Option<u32> { o.get(p..p.checked_add(4)?).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])) };
    let u16_a = |p: usize| -> Option<u16> { o.get(p..p.checked_add(2)?).map(|b| u16::from_le_bytes([b[0], b[1]])) };
    if u32_a(4) != Some(1) {
        return Err("version différente de 1".into());
    }
    let attendre = |p: &mut usize, c: char, quoi: &str| -> Result<(), String> {
        if u16_a(*p) == Some(c as u16) {
            *p += 2;
            Ok(())
        } else {
            Err(format!("« {c} » attendu ({quoi}) à l'octet {}", *p))
        }
    };
    let chaine = |p: &mut usize, quoi: &str| -> Result<String, String> {
        let mut c = Vec::new();
        loop {
            let x = u16_a(*p).ok_or_else(|| format!("{quoi} sans fin à l'octet {}", *p))?;
            *p += 2;
            if x == 0 {
                break;
            }
            c.push(x);
        }
        String::from_utf16(&c).map_err(|_| format!("{quoi} en UTF-16 invalide"))
    };
    let mut entrees = Vec::new();
    let mut p = 8;
    while p < o.len() {
        attendre(&mut p, '[', "début d'entrée")?;
        let cle = chaine(&mut p, "clé")?;
        attendre(&mut p, ';', "après la clé")?;
        let nom = chaine(&mut p, "nom")?;
        attendre(&mut p, ';', "après le nom")?;
        let type_ = u32_a(p).ok_or("type tronqué")?;
        p += 4;
        attendre(&mut p, ';', "après le type")?;
        let taille = u32_a(p).ok_or("taille tronquée")? as usize;
        p += 4;
        attendre(&mut p, ';', "après la taille")?;
        let fin = p.checked_add(taille).filter(|f| *f <= o.len()).ok_or("données tronquées")?;
        let donnees = o.get(p..fin).ok_or("données tronquées")?.to_vec();
        p = fin;
        attendre(&mut p, ']', "fin d'entrée")?;
        entrees.push(EntreePol { cle, nom, type_, donnees });
    }
    Ok(entrees)
}

/// Lecture tolérante réservée au diagnostic `--relire-pol` (affichage seul) : jamais pour une écriture
pub fn analyser_pol(o: &[u8]) -> Vec<EntreePol> {
    decoder_pol(o).unwrap_or_default()
}

pub fn serialiser_pol(entrees: &[EntreePol]) -> Vec<u8> {
    let mut o = b"PReg".to_vec();
    o.extend(1u32.to_le_bytes());
    let car = |o: &mut Vec<u8>, c: char| o.extend((c as u16).to_le_bytes());
    let texte = |o: &mut Vec<u8>, s: &str| {
        for c in s.encode_utf16().chain(std::iter::once(0)) {
            o.extend(c.to_le_bytes());
        }
    };
    for e in entrees {
        car(&mut o, '[');
        texte(&mut o, &e.cle);
        car(&mut o, ';');
        texte(&mut o, &e.nom);
        car(&mut o, ';');
        o.extend(e.type_.to_le_bytes());
        car(&mut o, ';');
        o.extend((e.donnees.len() as u32).to_le_bytes());
        car(&mut o, ';');
        o.extend(&e.donnees);
        car(&mut o, ']');
    }
    o
}

/// Décision pure : ajoute ou remplace des entrées, retire celles demandées, conserve toutes les autres. Une entrée
/// à retirer n'est retirée que si elle vaut encore la valeur posée (même type, mêmes données) ; changée depuis par
/// un tiers, elle est gardée et rendue dans la seconde liste (audit du 2026-11-23, A-2-3)
pub fn fusionner_pol(entrees: Vec<EntreePol>, ajouts: &[EntreePol], retraits: &[EntreePol]) -> (Vec<EntreePol>, Vec<EntreePol>) {
    let mut gardees = Vec::new();
    let mut resultat: Vec<EntreePol> = entrees
        .into_iter()
        .filter(|e| {
            if ajouts.iter().any(|a| a.meme_valeur(e)) {
                return false;
            }
            match retraits.iter().find(|r| r.meme_valeur(e)) {
                Some(r) if r.type_ == e.type_ && r.donnees == e.donnees => false,
                Some(_) => {
                    gardees.push(e.clone());
                    true
                }
                None => true,
            }
        })
        .collect();
    resultat.extend(ajouts.iter().cloned());
    (resultat, gardees)
}

/// Modifie Registry.pol ; rend les entrées gardées parce qu'un tiers les a changées depuis (A-2-3)
pub fn modifier_pol(ajouts: &[EntreePol], retraits: &[EntreePol]) -> Result<Vec<EntreePol>, String> {
    modifier_pol_de(&fichier_pol(), ajouts, retraits)
}

/// Lecture vérifiée d'abord : un fichier présent mais illisible ou non compris arrête tout, rien n'est écrit (A-2-2)
pub fn modifier_pol_de(f: &Path, ajouts: &[EntreePol], retraits: &[EntreePol]) -> Result<Vec<EntreePol>, String> {
    let entrees = lire_pol_de(f)?;
    let (entrees, gardees) = fusionner_pol(entrees, ajouts, retraits);
    ecrire_d_un_bloc(f, &serialiser_pol(&entrees))?;
    Ok(gardees)
}

// ------------------------------------------------------------ audit.csv

/// Stratégie d'audit avancée : lignes de sous-catégorie (GUID en majuscules, nom, valeur 0..3), et toutes les autres
/// lignes (options d'audit, audit global des objets…) gardées telles quelles
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AuditCsv {
    pub lignes: Vec<(String, String, u32)>,
    pub autres: Vec<String>,
}

pub fn lire_audit() -> Result<AuditCsv, String> {
    lire_audit_de(&fichier_audit())
}

pub fn lire_audit_de(f: &Path) -> Result<AuditCsv, String> {
    match lire_ou_absent(f)? {
        None => Ok(AuditCsv::default()),
        Some(o) => decoder_audit(&o).map_err(|e| format!("audit.csv non compris ({e})")),
    }
}

fn est_guid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 38
        && b[0] == b'{'
        && b[37] == b'}'
        && b[1..37].iter().enumerate().all(|(i, c)| if matches!(i, 8 | 13 | 18 | 23) { *c == b'-' } else { c.is_ascii_hexdigit() })
}

/// Décodage strict de audit.csv. Encodage : UTF-8 selon [MS-GPAC] 2.2 (« All advanced audit policy files […] are
/// UTF-8 encoded ») ; une marque d'ordre UTF-8 est admise, tout autre encodage (UTF-16, ANSI) est une erreur,
/// jamais « vide ». En-tête exigé sur un fichier non vide ; une ligne de sous-catégorie à valeur hors 0..3 est une
/// erreur ; les autres lignes sont gardées telles quelles (A-2-2)
pub fn decoder_audit(o: &[u8]) -> Result<AuditCsv, String> {
    if o.is_empty() {
        return Ok(AuditCsv::default());
    }
    if o.starts_with(&[0xFF, 0xFE]) || o.starts_with(&[0xFE, 0xFF]) {
        return Err("encodé en UTF-16, format non prévu ([MS-GPAC] : UTF-8)".into());
    }
    let o = o.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(o);
    let t = std::str::from_utf8(o).map_err(|_| "pas en UTF-8".to_string())?;
    let mut lignes = t.lines();
    match lignes.next() {
        Some(l) if l.trim().eq_ignore_ascii_case(ENTETE_AUDIT) => {}
        _ => return Err("en-tête inconnu".into()),
    }
    let mut a = AuditCsv::default();
    for l in lignes {
        if l.trim().is_empty() {
            continue;
        }
        let c: Vec<&str> = l.split(',').collect();
        if c.len() == 7 && c[1].trim().eq_ignore_ascii_case("System") && est_guid(c[3].trim()) {
            let v: u32 = c[6].trim().parse().ok().filter(|v| *v <= 3).ok_or_else(|| format!("valeur d'audit invalide pour {}", c[3].trim()))?;
            let guid = c[3].trim().to_uppercase();
            // Sous-catégorie en double : laquelle fait foi n'est pas sûr, refus (prérelecture de #270)
            if a.lignes.iter().any(|x| x.0 == guid) {
                return Err(format!("sous-catégorie {guid} en double"));
            }
            a.lignes.push((guid, c[2].to_string(), v));
        } else if c.iter().any(|x| est_guid(x.trim())) {
            // Ligne de sous-catégorie d'une autre forme (colonnes en plus ou en moins, autre cible) : gardée telle
            // quelle, elle pourrait se retrouver en double avec celle que deR4Tizer écrit ; refus (prérelecture de #270)
            return Err("ligne de sous-catégorie d'une forme non prévue".into());
        } else {
            a.autres.push(l.to_string());
        }
    }
    Ok(a)
}

pub fn serialiser_audit(a: &AuditCsv) -> String {
    let mut t = format!("{ENTETE_AUDIT}\r\n");
    for (guid, nom, v) in &a.lignes {
        let inclusion = match v {
            1 => "Success",
            2 => "Failure",
            3 => "Success and Failure",
            _ => "No Auditing",
        };
        t.push_str(&format!(",System,{nom},{guid},{inclusion},,{v}\r\n"));
    }
    // Options d'audit puis audit global des objets viennent après les sous-catégories ([MS-GPAC] 2.2)
    for l in &a.autres {
        t.push_str(l);
        t.push_str("\r\n");
    }
    t
}

pub fn ecrire_audit(a: &AuditCsv) -> Result<(), String> {
    ecrire_d_un_bloc(&fichier_audit(), serialiser_audit(a).as_bytes())
}

// ------------------------------------------------------------ gpt.ini et application

/// gpt.ini tel qu'il est : absent = vide ; illisible ou pas en UTF-8 (ASCII attendu) = erreur (A-2-2)
pub fn lire_gpt() -> Result<String, String> {
    lire_gpt_de(&fichier_gpt())
}

pub fn lire_gpt_de(f: &Path) -> Result<String, String> {
    match lire_ou_absent(f)? {
        None => Ok(String::new()),
        Some(o) => {
            let o = o.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(&o[..]).to_vec();
            String::from_utf8(o).map_err(|_| "gpt.ini non compris (encodage non prévu)".to_string())
        }
    }
}

/// Décision pure : déclare les extensions utilisées et incrémente la version machine ; une version illisible est
/// une erreur (repartir de 0 pourrait faire ignorer la GPO par gpupdate)
pub fn maj_gpt(existant: &str, audit: bool) -> Result<String, String> {
    let mut version: u32 = 0;
    let mut extensions_machine = String::new();
    let mut autres = Vec::new();
    for l in existant.lines() {
        let l = l.trim();
        if let Some(v) = l.strip_prefix("Version=") {
            version = v.trim().parse().map_err(|_| "gpt.ini non compris (version illisible)".to_string())?;
        } else if let Some(v) = l.strip_prefix("gPCMachineExtensionNames=") {
            extensions_machine = v.to_string();
        } else if !l.is_empty() && !l.eq_ignore_ascii_case("[General]") {
            autres.push(l.to_string());
        }
    }
    // La liste est une suite de [CSE][outils] ; on ajoute les nôtres puis on trie, comme le fait gpedit
    let mut paires: Vec<String> = extensions_machine.split("][").map(|s| format!("[{}]", s.trim_matches(|c| c == '[' || c == ']'))).filter(|s| s.len() > 2).collect();
    for cse in std::iter::once(CSE_REGISTRE).chain(audit.then_some(CSE_AUDIT)) {
        if !paires.iter().any(|p| p.eq_ignore_ascii_case(cse)) {
            paires.push(cse.to_string());
        }
    }
    paires.sort_by_key(|p| p.to_uppercase());
    // Version : 16 bits de poids fort pour l'utilisateur, 16 bits de poids faible pour la machine
    let machine = (version & 0xFFFF) + 1;
    let version = (version & 0xFFFF_0000) | (machine & 0xFFFF);
    let mut t = String::from("[General]\r\n");
    t.push_str(&format!("gPCMachineExtensionNames={}\r\n", paires.join("")));
    for a in autres {
        t.push_str(&format!("{a}\r\n"));
    }
    t.push_str(&format!("Version={version}\r\n"));
    Ok(t)
}

/// Déclare les extensions utilisées et incrémente la version machine, pour que gpupdate relise la GPO
pub fn marquer_gpt(audit: bool) -> Result<(), String> {
    marquer_gpt_de(&fichier_gpt(), audit)
}

pub fn marquer_gpt_de(f: &Path, audit: bool) -> Result<(), String> {
    let t = maj_gpt(&lire_gpt_de(f)?, audit)?;
    ecrire_d_un_bloc(f, t.as_bytes())
}

pub fn gpupdate() -> Result<(), String> {
    let s = Command::new(outil_systeme("gpupdate.exe"))
        .args(["/target:computer", "/force"])
        .creation_flags(0x0800_0000)
        .output()
        .map_err(|e| e.to_string())?;
    if s.status.success() { Ok(()) } else { Err(String::from_utf8_lossy(&s.stdout).trim().to_string()) }
}

/// Réglage d'audit effectif d'une sous-catégorie (auditpol, droits administrateur requis) : 0..3
pub fn audit_effectif(guid: &str) -> Option<u32> {
    let s = Command::new(outil_systeme("auditpol.exe")).args(["/get", &format!("/subcategory:{guid}"), "/r"]).creation_flags(0x0800_0000).output().ok()?;
    if !s.status.success() {
        return None;
    }
    let t = String::from_utf8_lossy(&s.stdout);
    let ligne = t.lines().nth(1)?;
    let inclusion = ligne.split(',').nth(4)?.to_lowercase();
    // Libellés anglais ou français selon la langue de Windows (Success / Succès, Failure / Échec)
    Some(match (inclusion.contains("succ"), inclusion.contains("fail") || inclusion.contains("chec")) {
        (true, true) => 3,
        (true, false) => 1,
        (false, true) => 2,
        _ => 0,
    })
}
