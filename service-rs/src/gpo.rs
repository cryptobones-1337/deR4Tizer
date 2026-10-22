//! Stratégie de groupe locale (GPO locale) : lecture et écriture de Registry.pol (format PReg),
//! de la stratégie d'audit avancée (audit.csv) et de gpt.ini, puis application avec gpupdate.
//! Les réglages apparaissent ainsi comme de vraies stratégies, comme le ferait gpedit.msc ou LGPO.exe.

use std::fs;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

pub const REG_SZ: u32 = 1;
pub const REG_DWORD: u32 = 4;

/// Extensions côté client : Registre (+ outil d'administration) et Audit avancé
const CSE_REGISTRE: &str = "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]";
const CSE_AUDIT: &str = "[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]";

pub fn racine() -> PathBuf {
    PathBuf::from(crate::natif::dossier_systeme()).join("GroupPolicy")
}

fn fichier_pol() -> PathBuf {
    racine().join(r"Machine\Registry.pol")
}

pub fn fichier_audit() -> PathBuf {
    racine().join(r"Machine\Microsoft\Windows NT\Audit\audit.csv")
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

// ------------------------------------------------------------ Registry.pol (PReg)

/// Lit Registry.pol : "PReg", version 1, puis des entrées [clé;nom;type;taille;données] en UTF-16
pub fn lire_pol() -> Vec<EntreePol> {
    let Ok(o) = fs::read(fichier_pol()) else { return Vec::new() };
    analyser_pol(&o)
}

pub fn analyser_pol(o: &[u8]) -> Vec<EntreePol> {
    let mut entrees = Vec::new();
    if o.len() < 8 || &o[0..4] != b"PReg" {
        return entrees;
    }
    let u16_a = |p: usize| u16::from_le_bytes([o[p], o[p + 1]]);
    let u32_a = |p: usize| u32::from_le_bytes([o[p], o[p + 1], o[p + 2], o[p + 3]]);
    let chaine = |p: &mut usize| -> String {
        let mut c = Vec::new();
        while *p + 1 < o.len() {
            let x = u16_a(*p);
            *p += 2;
            if x == 0 {
                break;
            }
            c.push(x);
        }
        String::from_utf16_lossy(&c)
    };
    let mut p = 8;
    while p + 2 <= o.len() && u16_a(p) == '[' as u16 {
        p += 2;
        let cle = chaine(&mut p);
        p += 2; // ;
        let nom = chaine(&mut p);
        p += 2;
        if p + 4 > o.len() {
            break;
        }
        let type_ = u32_a(p);
        p += 6; // type ;
        if p + 4 > o.len() {
            break;
        }
        let taille = u32_a(p) as usize;
        p += 6; // taille ;
        if p + taille > o.len() {
            break;
        }
        let donnees = o[p..p + taille].to_vec();
        p += taille + 2; // données ]
        entrees.push(EntreePol { cle, nom, type_, donnees });
    }
    entrees
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

/// Ajoute ou remplace des entrées, retire celles demandées, en conservant toutes les autres stratégies
pub fn modifier_pol(ajouts: &[EntreePol], retraits: &[EntreePol]) -> std::io::Result<()> {
    let mut entrees = lire_pol();
    entrees.retain(|e| !ajouts.iter().chain(retraits).any(|a| a.meme_valeur(e)));
    entrees.extend(ajouts.iter().cloned());
    if let Some(d) = fichier_pol().parent() {
        fs::create_dir_all(d)?;
    }
    fs::write(fichier_pol(), serialiser_pol(&entrees))
}

// ------------------------------------------------------------ audit.csv

/// Lignes de la stratégie d'audit avancée : GUID de sous-catégorie -> (nom, valeur 0..3)
pub fn lire_audit() -> Vec<(String, String, u32)> {
    let Ok(t) = fs::read_to_string(fichier_audit()) else { return Vec::new() };
    t.trim_start_matches('\u{feff}')
        .lines()
        .skip(1)
        .filter_map(|l| {
            let c: Vec<&str> = l.split(',').collect();
            (c.len() >= 7).then(|| (c[3].to_uppercase(), c[2].to_string(), c[6].trim().parse().unwrap_or(0)))
        })
        .collect()
}

pub fn ecrire_audit(lignes: &[(String, String, u32)]) -> std::io::Result<()> {
    let mut t = String::from("Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value\r\n");
    for (guid, nom, v) in lignes {
        let inclusion = match v {
            1 => "Success",
            2 => "Failure",
            3 => "Success and Failure",
            _ => "No Auditing",
        };
        t.push_str(&format!(",System,{nom},{guid},{inclusion},,{v}\r\n"));
    }
    if let Some(d) = fichier_audit().parent() {
        fs::create_dir_all(d)?;
    }
    fs::write(fichier_audit(), t)
}

// ------------------------------------------------------------ gpt.ini et application

/// Déclare les extensions utilisées et incrémente la version machine, pour que gpupdate relise la GPO
pub fn marquer_gpt(audit: bool) -> std::io::Result<()> {
    let f = racine().join("gpt.ini");
    let existant = fs::read_to_string(&f).unwrap_or_default();
    let mut version: u32 = 0;
    let mut extensions_machine = String::new();
    let mut autres = Vec::new();
    for l in existant.lines() {
        let l = l.trim();
        if let Some(v) = l.strip_prefix("Version=") {
            version = v.parse().unwrap_or(0);
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
    fs::write(f, t)
}

pub fn gpupdate() -> Result<(), String> {
    let s = Command::new("gpupdate.exe")
        .args(["/target:computer", "/force"])
        .creation_flags(0x0800_0000)
        .output()
        .map_err(|e| e.to_string())?;
    if s.status.success() { Ok(()) } else { Err(String::from_utf8_lossy(&s.stdout).trim().to_string()) }
}

/// Réglage d'audit effectif d'une sous-catégorie (auditpol, droits administrateur requis) : 0..3
pub fn audit_effectif(guid: &str) -> Option<u32> {
    let s = Command::new("auditpol.exe").args(["/get", &format!("/subcategory:{guid}"), "/r"]).creation_flags(0x0800_0000).output().ok()?;
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
