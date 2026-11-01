//! Appels Windows de bas niveau : table TCP, chemins et liste des processus, signatures Authenticode.

use std::collections::HashMap;
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, SetTcpEntry, MIB_TCPROW_LH, MIB_TCPROW_LH_0, MIB_TCP_STATE, TCP_TABLE_OWNER_PID_ALL,
    UDP_TABLE_OWNER_PID,
};
use windows::Win32::Security::Cryptography::{CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE};
use windows::Win32::Security::WinTrust::{
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2,
    WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOKE_NONE,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

pub fn large(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn texte(tampon: &[u16]) -> String {
    let fin = tampon.iter().position(|&c| c == 0).unwrap_or(tampon.len());
    String::from_utf16_lossy(&tampon[..fin])
}

// ------------------------------------------------------------ table TCP

#[derive(Clone)]
pub struct Connexion {
    pub pid: u32,
    /// 2 = écoute, 3 = SYN envoyé, 5 = établie
    pub etat: u32,
    pub ip: String,
    pub port: u16,
    pub ip_locale: String,
    pub port_local: u16,
    /// Valeurs brutes de la ligne IPv4, pour pouvoir couper la connexion
    brut: Option<[u32; 4]>,
}

#[cfg(test)]
impl Connexion {
    /// Connexion synthétique pour les tests des règles
    pub(crate) fn pour_test(pid: u32, etat: u32, ip_locale: &str, port_local: u16, ip: &str, port: u16) -> Connexion {
        Connexion { pid, etat, ip: ip.into(), port, ip_locale: ip_locale.into(), port_local, brut: None }
    }
}

fn port_reseau(v: u32) -> u16 {
    (((v & 0xFF) << 8) | ((v >> 8) & 0xFF)) as u16
}

fn ip_texte(ip: IpAddr) -> String {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => v6.to_string(),
        },
        v4 => v4.to_string(),
    }
}

pub fn lister_tcp() -> Vec<Connexion> {
    lister_tcp_lu().0
}

/// Connexions TCP, et l'échec de lecture d'une des deux tables s'il y en a un : une table illisible n'est pas
/// « aucune connexion » (état des collectes)
pub fn lister_tcp_lu() -> (Vec<Connexion>, Result<(), String>) {
    let mut liste = Vec::new();
    let r4 = lire_table(2, &mut liste);
    let r6 = lire_table(23, &mut liste);
    (liste, r4.and(r6))
}

fn lire_table(famille: u32, liste: &mut Vec<Connexion>) -> Result<(), String> {
    let mut taille: u32 = 0;
    unsafe {
        GetExtendedTcpTable(None, &mut taille, false, famille, TCP_TABLE_OWNER_PID_ALL, 0);
    }
    for _ in 0..3 {
        taille += 8192;
        let mut tampon = vec![0u8; taille as usize];
        let r = unsafe {
            GetExtendedTcpTable(Some(tampon.as_mut_ptr() as *mut c_void), &mut taille, false, famille, TCP_TABLE_OWNER_PID_ALL, 0)
        };
        if r == 122 {
            continue; // la table a grossi entre les deux appels
        }
        if r != 0 {
            return Err(format!("table TCP {} illisible (erreur {r})", if famille == 2 { "IPv4" } else { "IPv6" }));
        }
        let lire32 = |pos: usize| u32::from_le_bytes(tampon[pos..pos + 4].try_into().unwrap());
        let n = lire32(0) as usize;
        let mut p = 4;
        for _ in 0..n {
            if famille == 2 {
                if p + 24 > tampon.len() {
                    break;
                }
                let (etat, local, port_local, distant, port_distant, pid) =
                    (lire32(p), lire32(p + 4), lire32(p + 8), lire32(p + 12), lire32(p + 16), lire32(p + 20));
                liste.push(Connexion {
                    pid,
                    etat,
                    ip: Ipv4Addr::from(u32::from_be(distant)).to_string(),
                    port: port_reseau(port_distant),
                    ip_locale: Ipv4Addr::from(u32::from_be(local)).to_string(),
                    port_local: port_reseau(port_local),
                    brut: Some([local, port_local, distant, port_distant]),
                });
                p += 24;
            } else {
                if p + 56 > tampon.len() {
                    break;
                }
                let local: [u8; 16] = tampon[p..p + 16].try_into().unwrap();
                let distant: [u8; 16] = tampon[p + 24..p + 40].try_into().unwrap();
                liste.push(Connexion {
                    pid: lire32(p + 52),
                    etat: lire32(p + 48),
                    ip: ip_texte(IpAddr::V6(Ipv6Addr::from(distant))),
                    port: port_reseau(lire32(p + 44)),
                    ip_locale: ip_texte(IpAddr::V6(Ipv6Addr::from(local))),
                    port_local: port_reseau(lire32(p + 20)),
                    brut: None,
                });
                p += 56;
            }
        }
        return Ok(());
    }
    Err(format!("table TCP {} illisible (elle grossit plus vite qu'elle ne se lit)", if famille == 2 { "IPv4" } else { "IPv6" }))
}

/// Ports UDP IPv4 ouverts : (port local, pid)
pub fn lister_udp() -> Vec<(u16, u32)> {
    let mut liste = Vec::new();
    let mut taille: u32 = 0;
    unsafe {
        GetExtendedUdpTable(None, &mut taille, false, 2, UDP_TABLE_OWNER_PID, 0);
    }
    for _ in 0..3 {
        taille += 8192;
        let mut tampon = vec![0u8; taille as usize];
        let r = unsafe { GetExtendedUdpTable(Some(tampon.as_mut_ptr() as *mut c_void), &mut taille, false, 2, UDP_TABLE_OWNER_PID, 0) };
        if r == 122 {
            continue;
        }
        if r != 0 {
            return liste;
        }
        let lire32 = |pos: usize| u32::from_le_bytes(tampon[pos..pos + 4].try_into().unwrap());
        let n = lire32(0) as usize;
        // MIB_UDPROW_OWNER_PID : adresse locale, port local, pid (12 octets)
        for i in 0..n {
            let p = 4 + i * 12;
            if p + 12 > tampon.len() {
                break;
            }
            liste.push((port_reseau(lire32(p + 4)), lire32(p + 8)));
        }
        break;
    }
    liste
}

/// Coupe une connexion IPv4 établie (DELETE_TCB) ; nécessite les droits administrateur
pub fn couper(c: &Connexion) -> bool {
    let Some([local, port_local, distant, port_distant]) = c.brut else { return false };
    let ligne = MIB_TCPROW_LH {
        Anonymous: MIB_TCPROW_LH_0 { State: MIB_TCP_STATE(12) },
        dwLocalAddr: local,
        dwLocalPort: port_local,
        dwRemoteAddr: distant,
        dwRemotePort: port_distant,
    };
    unsafe { SetTcpEntry(&ligne) == 0 }
}

// ------------------------------------------------------------ processus

pub fn chemin_processus(pid: u32) -> String {
    if pid <= 4 {
        return String::new();
    }
    unsafe {
        let Ok(h) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else { return String::new() };
        let mut tampon = [0u16; 1024];
        let mut taille = tampon.len() as u32;
        let r = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, PWSTR(tampon.as_mut_ptr()), &mut taille);
        let _ = CloseHandle(h);
        if r.is_ok() { String::from_utf16_lossy(&tampon[..taille as usize]) } else { String::new() }
    }
}

pub struct InfoListe {
    pub nom: String,
    pub parent: u32,
}

/// Liste de tous les processus : pid -> nom (sans .exe) et pid du parent
pub fn processus() -> HashMap<u32, InfoListe> {
    processus_lu().unwrap_or_default()
}

/// Liste des processus ; un instantané impossible est une erreur, pas « aucun processus » (état des collectes)
pub fn processus_lu() -> Result<HashMap<u32, InfoListe>, String> {
    let mut carte = HashMap::new();
    unsafe {
        let Ok(h) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else { return Err("instantané des processus impossible".into()) };
        let mut e = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
        let premier = Process32FirstW(h, &mut e).is_ok();
        if premier {
            loop {
                let nom = texte(&e.szExeFile);
                let nom = nom.strip_suffix(".exe").or_else(|| nom.strip_suffix(".EXE")).unwrap_or(&nom).to_string();
                carte.insert(e.th32ProcessID, InfoListe { nom, parent: e.th32ParentProcessID });
                if Process32NextW(h, &mut e).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(h);
        if !premier {
            return Err("liste des processus illisible".into());
        }
    }
    Ok(carte)
}

/// Décision pure : processus enfants directs de `parent` dont le nom (sans .exe) est l'un de `noms`, casse ignorée
pub fn enfants_nommes(liste: &HashMap<u32, InfoListe>, parent: u32, noms: &[&str]) -> Vec<u32> {
    let mut v: Vec<u32> = liste.iter()
        .filter(|(pid, i)| **pid != parent && i.parent == parent && noms.iter().any(|n| n.eq_ignore_ascii_case(&i.nom)))
        .map(|(pid, _)| *pid)
        .collect();
    v.sort_unstable();
    v
}

/// Termine les processus enfants du processus courant portant l'un de ces noms (sans .exe) ; renvoie leur nombre.
/// Arrêt du service : un curl.exe lancé par lui (téléchargement de GeoIP, des listes de menaces…) lui survivait et
/// gardait ouvert un fichier du dossier de données, que la désinstallation ne pouvait plus supprimer (constaté en
/// Windows Sandbox). Le script d'installation des mises à jour (powershell.exe) n'est pas visé : il doit survivre.
pub fn terminer_enfants(noms: &[&str]) -> usize {
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
    let mut n = 0;
    for pid in enfants_nommes(&processus(), std::process::id(), noms) {
        unsafe {
            if let Ok(h) = OpenProcess(PROCESS_TERMINATE, false, pid) {
                if TerminateProcess(h, 1).is_ok() {
                    n += 1;
                }
                let _ = CloseHandle(h);
            }
        }
    }
    n
}

// ------------------------------------------------------------ signatures

/// Lecture hors délai, ou déjà en cours, ou trop de lectures bloquées
#[derive(Debug, PartialEq)]
pub struct HorsDelai;

enum EtatLecture {
    EnCours,
    Fini(Option<String>),
}

struct Lectures {
    etats: std::collections::HashMap<String, EtatLecture>,
    en_cours: usize,
    fenetre: std::time::Instant,
    attendu: std::time::Duration,
}

/// Lectures de fichiers à échéance, sous le verrou du moniteur. Un compte qui peut ouvrir un fichier en lecture peut y poser un verrou
/// opportuniste, y compris sur un exécutable en cours d'exécution ou sur `hosts`, et l'ouverture attend alors sans délai maximal connu
/// (audits de #103 et #104, S103-07, S104-02). Une seule lecture à la fois par clé ; son résultat, même tardif, est gardé pour
/// l'appel suivant ; au plus `max` lectures en cours, bloquées comprises ; et un budget d'attente par minute, qui borne le retard
/// quel que soit le nombre de fichiers
pub struct Lecteur {
    etat: std::sync::Mutex<Lectures>,
    fini: std::sync::Condvar,
    max: usize,
    echeance: std::time::Duration,
    budget: std::time::Duration,
    fenetre: std::time::Duration,
}

const MAX_RESULTATS_GARDES: usize = 512;

impl Lecteur {
    pub fn nouveau(max: usize, echeance: std::time::Duration, budget: std::time::Duration, fenetre: std::time::Duration) -> std::sync::Arc<Lecteur> {
        std::sync::Arc::new(Lecteur {
            etat: std::sync::Mutex::new(Lectures { etats: Default::default(), en_cours: 0, fenetre: std::time::Instant::now(), attendu: Default::default() }),
            fini: std::sync::Condvar::new(),
            max,
            echeance,
            budget,
            fenetre,
        })
    }

    pub fn lire(self: &std::sync::Arc<Self>, cle: &str, f: impl FnOnce() -> Option<String> + Send + 'static) -> Result<Option<String>, HorsDelai> {
        use std::time::{Duration, Instant};
        let mut e = self.etat.lock().unwrap();
        match e.etats.get(cle) {
            Some(EtatLecture::EnCours) => return Err(HorsDelai),
            Some(EtatLecture::Fini(_)) => {
                let Some(EtatLecture::Fini(v)) = e.etats.remove(cle) else { return Err(HorsDelai) };
                return Ok(v);
            }
            None => {}
        }
        if e.en_cours >= self.max {
            return Err(HorsDelai);
        }
        e.en_cours += 1;
        e.etats.insert(cle.to_string(), EtatLecture::EnCours);
        let (moi, c) = (self.clone(), cle.to_string());
        std::thread::spawn(move || {
            let v = f();
            let mut e = moi.etat.lock().unwrap();
            e.en_cours -= 1;
            if e.etats.len() > MAX_RESULTATS_GARDES {
                e.etats.retain(|_, x| matches!(x, EtatLecture::EnCours));
            }
            e.etats.insert(c, EtatLecture::Fini(v));
            moi.fini.notify_all();
        });
        if e.fenetre.elapsed() >= self.fenetre {
            e.fenetre = Instant::now();
            e.attendu = Duration::ZERO;
        }
        let permis = self.echeance.min(self.budget.saturating_sub(e.attendu));
        let debut = Instant::now();
        let (mut e, _) = self.fini.wait_timeout_while(e, permis, |x| matches!(x.etats.get(cle), Some(EtatLecture::EnCours))).unwrap();
        e.attendu += debut.elapsed();
        match e.etats.get(cle) {
            Some(EtatLecture::Fini(_)) => {
                let Some(EtatLecture::Fini(v)) = e.etats.remove(cle) else { return Err(HorsDelai) };
                Ok(v)
            }
            _ => Err(HorsDelai),
        }
    }
}

/// Lecture d'un fichier à échéance. La clé porte la date du fichier (`metadata` ne bloque pas) : un résultat tardif ne vaut pas pour un
/// fichier changé depuis
pub fn lecture_fichier(quoi: &str, chemin: &str, f: impl FnOnce() -> Option<String> + Send + 'static) -> Result<Option<String>, HorsDelai> {
    static LECTEUR: std::sync::OnceLock<std::sync::Arc<Lecteur>> = std::sync::OnceLock::new();
    let date = std::fs::metadata(chemin).and_then(|m| m.modified()).map(crate::commun::filetime).unwrap_or(0);
    LECTEUR.get_or_init(|| Lecteur::nouveau(8, std::time::Duration::from_secs(8), std::time::Duration::from_secs(16), std::time::Duration::from_secs(60))).lire(&format!("{quoi}|{chemin}|{date}"), f)
}

/// Signature à échéance, en distinguant le délai dépassé de l'absence de signature
pub fn signataire_a_echeance(chemin: &str) -> Result<Option<String>, HorsDelai> {
    let c = chemin.to_string();
    lecture_fichier("signature", chemin, move || signataire_direct(&c))
}

pub fn catalogue_a_echeance(chemin: &str) -> Result<bool, HorsDelai> {
    let c = chemin.to_string();
    lecture_fichier("catalogue", chemin, move || catalogue_direct(&c).then(String::new)).map(|o| o.is_some())
}

/// Empreinte à échéance. None aussi si le fichier est illisible
pub fn empreinte_a_echeance(chemin: &str) -> Result<Option<String>, HorsDelai> {
    let c = std::path::PathBuf::from(chemin);
    lecture_fichier("empreinte", chemin, move || crate::hygiene::empreinte_fichier(&c))
}

/// Signataire valide, ou None : aussi bien sans signature que hors délai, ce qui ne donne jamais confiance
pub fn signataire_valide(chemin: &str) -> Option<String> {
    signataire_a_echeance(chemin).ok().flatten()
}

/// Vérifie la signature Authenticode intégrée au fichier ; renvoie le nom du signataire si elle est valide
fn signataire_direct(chemin: &str) -> Option<String> {
    let chemin_large = large(chemin);
    let mut fichier = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(chemin_large.as_ptr()),
        hFile: HANDLE::default(),
        pgKnownSubject: std::ptr::null_mut(),
    };
    let mut donnees = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut fichier },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        ..Default::default()
    };
    let mut action: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    unsafe {
        let r = WinVerifyTrust(HWND::default(), &mut action, &mut donnees as *mut _ as *mut c_void);
        let mut nom = None;
        if r == 0 {
            nom = Some(String::new());
            let fournisseur = WTHelperProvDataFromStateData(donnees.hWVTStateData);
            if !fournisseur.is_null() {
                let signataire = WTHelperGetProvSignerFromChain(fournisseur, 0, false, 0);
                if !signataire.is_null() && !(*signataire).pasCertChain.is_null() {
                    let cert = (*(*signataire).pasCertChain).pCert;
                    if !cert.is_null() {
                        let mut tampon = [0u16; 256];
                        let n = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, Some(&mut tampon));
                        if n > 1 {
                            nom = Some(String::from_utf16_lossy(&tampon[..n as usize - 1]));
                        }
                    }
                }
            }
        }
        donnees.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(HWND::default(), &mut action, &mut donnees as *mut _ as *mut c_void);
        nom
    }
}

/// Décision pure, sur les erreurs de la chaîne du signataire (CERT_TRUST_STATUS.dwErrorStatus) après un
/// WinVerifyTrust réussi : la révocation doit avoir été vérifiée. La politique Authenticode par défaut tolère une
/// révocation hors ligne ou inconnue (CRL injoignable) ; ici, c'est un refus, comme un certificat révoqué.
pub fn revocation_verifiee(erreurs_chaine: u32) -> bool {
    const CERT_TRUST_IS_REVOKED: u32 = 0x0000_0004;
    const CERT_TRUST_REVOCATION_STATUS_UNKNOWN: u32 = 0x0000_0040;
    const CERT_TRUST_IS_OFFLINE_REVOCATION: u32 = 0x0100_0000;
    erreurs_chaine & (CERT_TRUST_IS_REVOKED | CERT_TRUST_REVOCATION_STATUS_UNKNOWN | CERT_TRUST_IS_OFFLINE_REVOCATION) == 0
}

/// Empreinte SHA-256 de la clé publique du certificat qui a signé le fichier, après vérification complète de la
/// signature AVEC contrôle de révocation de toute la chaîne (un certificat volé puis révoqué est refusé, et une
/// révocation impossible à vérifier aussi : revocation_verifiee).
/// Sert à la mise à jour automatique : on compare une clé, pas un nom (que n'importe qui peut obtenir).
pub fn cle_signataire_verifiee(chemin: &str) -> Option<String> {
    use sha2::{Digest, Sha256};
    use windows::Win32::Security::WinTrust::{WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, WTD_REVOKE_WHOLECHAIN};
    let chemin_large = large(chemin);
    let mut fichier = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(chemin_large.as_ptr()),
        hFile: HANDLE::default(),
        pgKnownSubject: std::ptr::null_mut(),
    };
    let mut donnees = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut fichier },
        dwStateAction: WTD_STATEACTION_VERIFY,
        // Racine exclue : une racine n'a pas d'adresse de CRL (elle se retire du magasin, elle ne se révoque
        // pas) ; vérifiée, elle serait « révocation inconnue » et revocation_verifiee refuserait tout
        dwProvFlags: WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
        ..Default::default()
    };
    let mut action: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    unsafe {
        let r = WinVerifyTrust(HWND::default(), &mut action, &mut donnees as *mut _ as *mut c_void);
        let mut cle = None;
        if r == 0 {
            let fournisseur = WTHelperProvDataFromStateData(donnees.hWVTStateData);
            if !fournisseur.is_null() {
                let signataire = WTHelperGetProvSignerFromChain(fournisseur, 0, false, 0);
                // WinVerifyTrust réussit aussi quand la révocation n'a pas pu être vérifiée (CRL injoignable) :
                // l'état de la chaîne du signataire fait foi (échec fermé)
                let chaine = if signataire.is_null() { std::ptr::null_mut() } else { (*signataire).pChainContext };
                if !chaine.is_null() && revocation_verifiee((*chaine).TrustStatus.dwErrorStatus) && !(*signataire).pasCertChain.is_null() {
                    let cert = (*(*signataire).pasCertChain).pCert;
                    if !cert.is_null() && !(*cert).pCertInfo.is_null() {
                        let pk = &(*(*cert).pCertInfo).SubjectPublicKeyInfo.PublicKey;
                        if !pk.pbData.is_null() && pk.cbData > 0 {
                            let octets = std::slice::from_raw_parts(pk.pbData, pk.cbData as usize);
                            cle = Some(Sha256::digest(octets).iter().map(|o| format!("{o:02x}")).collect());
                        }
                    }
                }
            }
        }
        donnees.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(HWND::default(), &mut action, &mut donnees as *mut _ as *mut c_void);
        cle
    }
}

// ------------------------------------------------------------ divers

/// Vide le cache DNS de Windows (fonction non documentée de dnsapi.dll, comme ipconfig /flushdns)
pub fn vider_cache_dns() {
    unsafe {
        let nom = large("dnsapi.dll");
        if let Ok(module) = LoadLibraryW(PCWSTR(nom.as_ptr())) {
            if let Some(f) = GetProcAddress(module, windows::core::s!("DnsFlushResolverCache")) {
                let f: extern "system" fn() -> i32 = std::mem::transmute(f);
                f();
            }
        }
    }
}

pub fn dossier_windows() -> String {
    std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into())
}

pub fn dossier_systeme() -> String {
    format!(r"{}\System32", dossier_windows())
}

/// Chemin absolu de Windows PowerShell : powershell.exe n'est pas directement dans System32, un nom nu était donc
/// cherché dans le PATH par le service (SYSTEM) ; un dossier du PATH machine modifiable par un compte standard aurait
/// suffi à faire exécuter un faux PowerShell en SYSTEM (audit AUD2-02)
pub fn powershell_exe() -> String {
    format!(r"{}\WindowsPowerShell\v1.0\powershell.exe", dossier_systeme())
}

/// Chemin absolu de curl.exe (System32), pour la même raison qu'AUD2-02 (audit de #98, S98-05)
pub fn curl_exe() -> String {
    format!(r"{}\curl.exe", dossier_systeme())
}

// ------------------------------------------------------------ catalogues de sécurité et processus

/// Fichier signé par un catalogue de sécurité installé (signature de Windows et des pilotes, rangée dans
/// System32\CatRoot et non dans le fichier lui-même) : vrai contrôle de l'empreinte, pas du dossier
fn catalogue_direct(chemin: &str) -> bool {
    use windows::Win32::Security::Cryptography::Catalog::{
        CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2, CryptCATAdminEnumCatalogFromHash,
        CryptCATAdminReleaseCatalogContext, CryptCATAdminReleaseContext,
    };
    use windows::Win32::Storage::FileSystem::{CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING};
    let large_chemin = large(chemin);
    unsafe {
        let Ok(fichier) = CreateFileW(PCWSTR(large_chemin.as_ptr()), FILE_GENERIC_READ.0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None, OPEN_EXISTING, FILE_FLAGS_AND_ATTRIBUTES(0), None) else { return false };
        let mut trouve = false;
        // Catalogues récents en SHA-256, anciens en SHA-1
        for algorithme in [windows::core::w!("SHA256"), PCWSTR::null()] {
            let mut admin = 0isize;
            if CryptCATAdminAcquireContext2(&mut admin, None, algorithme, None, 0).is_err() {
                continue;
            }
            let mut taille = 0u32;
            let _ = CryptCATAdminCalcHashFromFileHandle2(admin, fichier, &mut taille, None, 0);
            if taille > 0 && taille <= 64 {
                let mut empreinte = vec![0u8; taille as usize];
                if CryptCATAdminCalcHashFromFileHandle2(admin, fichier, &mut taille, Some(empreinte.as_mut_ptr()), 0).is_ok() {
                    let info = CryptCATAdminEnumCatalogFromHash(admin, &empreinte, 0, None);
                    if info != 0 {
                        trouve = true;
                        let _ = CryptCATAdminReleaseCatalogContext(admin, info, 0);
                    }
                }
            }
            let _ = CryptCATAdminReleaseContext(admin, 0);
            if trouve {
                break;
            }
        }
        let _ = CloseHandle(fichier);
        trouve
    }
}

/// Heure de création d'un processus (FILETIME), pour écarter les PID réutilisés
pub fn creation_processus(pid: u32) -> Option<u64> {
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::System::Threading::GetProcessTimes;
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let (mut c, mut e, mut k, mut u) = (FILETIME::default(), FILETIME::default(), FILETIME::default(), FILETIME::default());
        let r = GetProcessTimes(h, &mut c, &mut e, &mut k, &mut u);
        let _ = CloseHandle(h);
        r.ok()?;
        Some(((c.dwHighDateTime as u64) << 32) | c.dwLowDateTime as u64)
    }
}

/// Binaire de Windows : situé dans le dossier Windows et signé par Microsoft (dans le fichier ou par catalogue)
pub fn binaire_windows(chemin: &str) -> bool {
    binaire_windows_lu(chemin).unwrap_or(false)
}

/// Comme `binaire_windows`, hors délai rendu tel quel : à la garde de savoir dans quel sens échouer
pub fn binaire_windows_lu(chemin: &str) -> Result<bool, HorsDelai> {
    let windows = dossier_windows().to_lowercase();
    if !chemin.to_lowercase().starts_with(&windows) {
        return Ok(false);
    }
    decision_binaire_windows(signataire_a_echeance(chemin), &|| catalogue_a_echeance(chemin))
}

/// Décision pure (testée) : une signature Microsoft valide suffit ; sinon le catalogue dit
pub(crate) fn decision_binaire_windows(signature: Result<Option<String>, HorsDelai>, catalogue: &dyn Fn() -> Result<bool, HorsDelai>) -> Result<bool, HorsDelai> {
    if signature?.is_some_and(|s| s.starts_with("Microsoft")) {
        return Ok(true);
    }
    catalogue()
}


// ------------------------------------------------------------ propriétaires et droits des fichiers

/// Le processus tourne-t-il en SYSTEM (service) ? Les contrôles de propriétaire ne s'appliquent qu'alors :
/// en mode console ou dans les tests, les fichiers appartiennent légitimement à l'utilisateur.
pub fn est_systeme() -> bool {
    use std::sync::OnceLock;
    use windows::Win32::Security::{GetTokenInformation, IsWellKnownSid, TokenUser, WinLocalSystemSid, TOKEN_QUERY, TOKEN_USER};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    static SYSTEME: OnceLock<bool> = OnceLock::new();
    *SYSTEME.get_or_init(|| unsafe {
        let mut jeton = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut jeton).is_err() {
            return false;
        }
        let mut tampon = vec![0u64; 64];
        let mut taille = 0u32;
        let ok = GetTokenInformation(jeton, TokenUser, Some(tampon.as_mut_ptr() as *mut c_void), (tampon.len() * 8) as u32, &mut taille).is_ok();
        let _ = CloseHandle(jeton);
        ok && IsWellKnownSid((*(tampon.as_ptr() as *const TOKEN_USER)).User.Sid, WinLocalSystemSid).as_bool()
    })
}

/// Identité du client d'un tube (phase 1, autorisation par commande) : SYSTEM, administrateur (groupe
/// Administrateurs actif dans son jeton), ou autre. Lue sur le jeton du PROCESSUS client
/// (GetNamedPipeClientProcessId), sans emprunter son identité : rien ne change sur le fil du service. Tout échec
/// (processus disparu, jeton illisible) : « autre », donc refus (échec fermé).
pub fn client_tube(tube: HANDLE) -> crate::validation::Client {
    identite_client_tube(tube).0
}

/// `client_tube`, avec le SID du compte du processus client (vide si illisible) : auteur des transitions d'incident
/// (phase 4, PR 4.2). Le SID ne sert qu'à l'historique, jamais à une autorisation
pub fn identite_client_tube(tube: HANDLE) -> (crate::validation::Client, String) {
    use crate::validation::Client;
    use windows::Win32::Foundation::BOOL;
    use windows::Win32::Security::{
        CheckTokenMembership, CreateWellKnownSid, DuplicateToken, GetTokenInformation, IsWellKnownSid, SecurityIdentification, TokenUser,
        WinBuiltinAdministratorsSid, WinLocalSystemSid, PSID, TOKEN_DUPLICATE, TOKEN_QUERY, TOKEN_USER,
    };
    use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
    use windows::Win32::System::Threading::{OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION};
    unsafe {
        let mut pid = 0u32;
        if GetNamedPipeClientProcessId(tube, &mut pid).is_err() || pid == 0 {
            return (Client::Autre, String::new());
        }
        let Ok(processus) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else { return (Client::Autre, String::new()) };
        let mut jeton = HANDLE::default();
        let ouvert = OpenProcessToken(processus, TOKEN_QUERY | TOKEN_DUPLICATE, &mut jeton).is_ok();
        let _ = CloseHandle(processus);
        if !ouvert {
            return (Client::Autre, String::new());
        }
        let mut tampon = vec![0u64; 64];
        let mut taille = 0u32;
        let lu = GetTokenInformation(jeton, TokenUser, Some(tampon.as_mut_ptr() as *mut c_void), (tampon.len() * 8) as u32, &mut taille).is_ok();
        let sid = if lu { sid_texte((*(tampon.as_ptr() as *const TOKEN_USER)).User.Sid) } else { String::new() };
        let systeme = lu && IsWellKnownSid((*(tampon.as_ptr() as *const TOKEN_USER)).User.Sid, WinLocalSystemSid).as_bool();
        let mut client = if systeme { Client::Systeme } else { Client::Autre };
        if !systeme {
            // CheckTokenMembership exige un jeton d'emprunt : copie au niveau « identification » (aucun accès possible)
            let mut copie = HANDLE::default();
            if DuplicateToken(jeton, SecurityIdentification, &mut copie).is_ok() {
                let mut sid = vec![0u64; 16];
                let mut t = (sid.len() * 8) as u32;
                let psid = PSID(sid.as_mut_ptr() as *mut c_void);
                let mut membre = BOOL(0);
                if CreateWellKnownSid(WinBuiltinAdministratorsSid, None, psid, &mut t).is_ok()
                    && CheckTokenMembership(copie, psid, &mut membre).is_ok()
                    && membre.as_bool()
                {
                    client = Client::Administrateur;
                }
                let _ = CloseHandle(copie);
            }
        }
        let _ = CloseHandle(jeton);
        (client, sid)
    }
}

/// Entrée d'une liste de droits (DACL) : autorisation ou refus, masque d'accès, SID du compte
#[derive(Debug, Clone, PartialEq)]
pub struct Ace {
    pub autorise: bool,
    pub masque: u32,
    pub sid: String,
}

/// Propriétaire et droits d'un fichier ou d'un dossier, tels que Windows les rapporte
#[derive(Debug, Clone, Default)]
pub struct Securite {
    pub proprietaire: String,
    /// Héritage coupé (SE_DACL_PROTECTED)
    pub protege: bool,
    pub aces: Vec<Ace>,
    /// Entrée d'un type non reconnu (objet, rappel…) : à traiter comme non conforme
    pub ace_inconnue: bool,
}

fn sid_texte(sid: windows::Win32::Security::PSID) -> String {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    unsafe {
        let mut p = PWSTR::null();
        if ConvertSidToStringSidW(sid, &mut p).is_err() || p.is_null() {
            return String::new();
        }
        let t = p.to_string().unwrap_or_default();
        let _ = LocalFree(HLOCAL(p.0 as *mut c_void));
        t
    }
}

/// Lit le propriétaire et la DACL ; None si illisible
pub fn lire_securite(chemin: &std::path::Path) -> Option<Securite> {
    use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows::Win32::Security::{ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};
    let nom = large(&chemin.to_string_lossy());
    unsafe {
        let mut proprietaire = PSID::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        let r = GetNamedSecurityInfoW(PCWSTR(nom.as_ptr()), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut proprietaire), None, Some(&mut dacl), None, &mut sd);
        if r.0 != 0 {
            return None;
        }
        analyser_descripteur(proprietaire, dacl, sd)
    }
}

/// `lire_securite` par le handle d'un élément déjà ouvert (et vérifié), sans repasser par son chemin ; le
/// handle doit avoir READ_CONTROL
pub fn lire_securite_handle(f: &std::fs::File) -> Option<Securite> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows::Win32::Security::{ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};
    unsafe {
        let mut proprietaire = PSID::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        let r = GetSecurityInfo(HANDLE(f.as_raw_handle()), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut proprietaire), None, Some(&mut dacl), None, Some(&mut sd));
        if r.0 != 0 {
            return None;
        }
        analyser_descripteur(proprietaire, dacl, sd)
    }
}

/// Propriétaire et entrées d'un descripteur de sécurité rendu par Windows (libéré ici)
unsafe fn analyser_descripteur(proprietaire: windows::Win32::Security::PSID, dacl: *mut windows::Win32::Security::ACL,
                               sd: windows::Win32::Security::PSECURITY_DESCRIPTOR) -> Option<Securite> {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::{GetAce, GetSecurityDescriptorControl, ACCESS_ALLOWED_ACE, ACE_HEADER, PSID};
    if sd.0.is_null() {
        return None;
    }
    let mut s = Securite { proprietaire: if proprietaire.is_invalid() { String::new() } else { sid_texte(proprietaire) }, ..Default::default() };
    let (mut controle, mut revision) = (0u16, 0u32);
    if GetSecurityDescriptorControl(sd, &mut controle, &mut revision).is_ok() {
        s.protege = controle & 0x1000 != 0; // SE_DACL_PROTECTED
    }
    if dacl.is_null() {
        // DACL absente : accès total pour tout le monde
        s.aces.push(Ace { autorise: true, masque: 0x1000_0000, sid: "S-1-1-0".into() });
    } else {
        for i in 0..(*dacl).AceCount as u32 {
            let mut p: *mut c_void = std::ptr::null_mut();
            if GetAce(dacl, i, &mut p).is_err() || p.is_null() {
                s.ace_inconnue = true;
                continue;
            }
            let entete = &*(p as *const ACE_HEADER);
            match entete.AceType {
                // ACCESS_ALLOWED_ACE et ACCESS_DENIED_ACE ont la même disposition
                0 | 1 => {
                    let ace = &*(p as *const ACCESS_ALLOWED_ACE);
                    let sid = PSID(&ace.SidStart as *const u32 as *mut c_void);
                    s.aces.push(Ace { autorise: entete.AceType == 0, masque: ace.Mask, sid: sid_texte(sid) });
                }
                _ => s.ace_inconnue = true,
            }
        }
    }
    let _ = LocalFree(HLOCAL(sd.0));
    Some(s)
}

/// `poser_droits` par le handle d'un élément déjà ouvert et vérifié (WRITE_OWNER si le SDDL a un
/// propriétaire, WRITE_DAC) : propriétaire puis DACL entière, héritage coupé
pub fn poser_droits_handle(f: &std::fs::File, sddl: &str) -> Result<(), String> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::{BOOL, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT};
    use windows::Win32::Security::{
        GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    };
    let h = HANDLE(f.as_raw_handle());
    let s = large(sddl);
    unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(s.as_ptr()), SDDL_REVISION_1, &mut sd, None).map_err(|e| e.to_string())?;
        let (mut present, mut defaut) = (BOOL::default(), BOOL::default());
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut proprietaire = PSID::default();
        let mut r = GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaut).map_err(|e| e.to_string());
        if r.is_ok() && (!present.as_bool() || dacl.is_null()) {
            r = Err("SDDL sans DACL".into());
        }
        if r.is_ok() {
            r = GetSecurityDescriptorOwner(sd, &mut proprietaire, &mut defaut).map_err(|e| e.to_string());
        }
        if r.is_ok() && !proprietaire.is_invalid() {
            let e = SetSecurityInfo(h, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, proprietaire, PSID::default(), None, None);
            if e.0 != 0 {
                r = Err(format!("propriétaire : {}", windows::core::Error::from(e)));
            }
        }
        if r.is_ok() {
            let e = SetSecurityInfo(h, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, PSID::default(),
                PSID::default(), Some(dacl), None);
            if e.0 != 0 {
                r = Err(format!("droits : {}", windows::core::Error::from(e)));
            }
        }
        let _ = LocalFree(HLOCAL(sd.0));
        r
    }
}

/// Propriétaire du fichier ou du dossier : SYSTEM ou Administrateurs ? None si illisible
pub fn proprietaire_de_confiance(chemin: &std::path::Path) -> Option<bool> {
    lire_securite(chemin).map(|s| crate::protection::proprietaire_acceptable(&s.proprietaire))
}

/// Écrit un fichier avec son descripteur de sécurité dès la création (fichier temporaire créé avec le SDDL,
/// puis remplacement atomique : les droits explicites et protégés suivent le fichier). Aucune fenêtre où le
/// contenu serait lisible avec les droits hérités.
pub fn ecrire_fichier_protege(chemin: &std::path::Path, contenu: &[u8], sddl: &str) -> Result<(), String> {
    use windows::Win32::Foundation::{HLOCAL, LocalFree, GENERIC_WRITE};
    use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, MoveFileExW, WriteFile, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let tmp = chemin.with_extension(format!("tmp-{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let (n_tmp, n_final, s) = (large(&tmp.to_string_lossy()), large(&chemin.to_string_lossy()), large(sddl));
    unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(s.as_ptr()), SDDL_REVISION_1, &mut sd, None).map_err(|e| e.to_string())?;
        let attributs = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd.0, bInheritHandle: false.into() };
        let f = CreateFileW(PCWSTR(n_tmp.as_ptr()), GENERIC_WRITE.0, FILE_SHARE_NONE, Some(&attributs), CREATE_NEW, FILE_ATTRIBUTE_NORMAL, HANDLE::default());
        let _ = LocalFree(HLOCAL(sd.0));
        let f = f.map_err(|e| e.to_string())?;
        let mut ecrits = 0u32;
        let r = WriteFile(f, Some(contenu), Some(&mut ecrits), None);
        let _ = CloseHandle(f);
        if let Err(e) = r.map_err(|e| e.to_string()).and_then(|_| if ecrits as usize == contenu.len() { Ok(()) } else { Err("écriture incomplète".into()) }) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        MoveFileExW(PCWSTR(n_tmp.as_ptr()), PCWSTR(n_final.as_ptr()), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            e.to_string()
        })
    }
}

/// Crée un dossier avec son descripteur de sécurité dès la création (SDDL), sans fenêtre où il hériterait
/// des droits de son parent
pub fn creer_dossier_protege(chemin: &std::path::Path, sddl: &str) -> bool {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows::Win32::Storage::FileSystem::CreateDirectoryW;
    let (nom, s) = (large(&chemin.to_string_lossy()), large(sddl));
    unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(s.as_ptr()), SDDL_REVISION_1, &mut sd, None).is_err() {
            return false;
        }
        let attributs = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd.0, bInheritHandle: false.into() };
        let ok = CreateDirectoryW(PCWSTR(nom.as_ptr()), Some(&attributs)).is_ok();
        let _ = LocalFree(HLOCAL(sd.0));
        ok
    }
}

/// Exécute `f` avec le privilège de restauration actif, sur ce fil seulement et pendant `f` seulement : le fil
/// emprunte une copie du jeton du processus, y active le privilège, puis revient au jeton du processus (où le
/// privilège reste inactif). Le reste du service n'en profite jamais.
pub fn avec_privilege_restauration<T>(f: impl FnOnce() -> T) -> Result<T, String> {
    use windows::Win32::Foundation::{GetLastError, LUID, ERROR_NOT_ALL_ASSIGNED};
    use windows::Win32::Security::{
        AdjustTokenPrivileges, ImpersonateSelf, LookupPrivilegeValueW, RevertToSelf, SecurityImpersonation, LUID_AND_ATTRIBUTES,
        SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};
    unsafe {
        ImpersonateSelf(SecurityImpersonation).map_err(|e| format!("emprunt du jeton : {e}"))?;
        let resultat = (|| {
            let mut jeton = HANDLE::default();
            OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, false, &mut jeton).map_err(|e| format!("jeton du fil : {e}"))?;
            let nom = large("SeRestorePrivilege");
            let mut luid = LUID::default();
            let mut r = LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(nom.as_ptr()), &mut luid).map_err(|e| e.to_string());
            if r.is_ok() {
                let tp = TOKEN_PRIVILEGES { PrivilegeCount: 1, Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }] };
                // AdjustTokenPrivileges réussit même si le privilège n'est pas accordé : ERROR_NOT_ALL_ASSIGNED
                r = AdjustTokenPrivileges(jeton, false, Some(&tp), 0, None, None).map_err(|e| e.to_string());
                if r.is_ok() && GetLastError() == ERROR_NOT_ALL_ASSIGNED {
                    r = Err("privilège de restauration absent du jeton".into());
                }
            }
            let _ = CloseHandle(jeton);
            r
        })();
        let valeur = resultat.map(|_| f());
        retour_ou_arret(RevertToSelf().map_err(|e| e.to_string()), "privilège de restauration", arreter);
        valeur
    }
}

/// Après un emprunt d'identité ou un privilège activé sur le fil : si le retour à l'identité du service
/// (RevertToSelf) échoue, le fil garderait une autre identité ou le privilège ; `arret` est appelé (en service :
/// journal puis arrêt du processus, que le gestionnaire de services relance avec un jeton propre)
pub fn retour_ou_arret(retour: Result<(), String>, contexte: &str, arret: impl FnOnce(String)) {
    if let Err(e) = retour {
        arret(format!("ARRÊT : retour à l'identité du service impossible ({contexte}) : {e}"));
    }
}

fn arreter(message: String) {
    crate::commun::journal(&message);
    std::process::abort();
}

/// Déplace un fichier ou un dossier par son handle, ouvert avec DELETE et la sémantique de sauvegarde (le
/// privilège de restauration, s'il est actif, accorde DELETE sans toucher au propriétaire ni aux droits). Les
/// liens ne sont pas suivis. Échoue si l'élément est tenu ouvert sans partage de suppression.
pub fn renommer_par_handle(source: &std::path::Path, destination: &std::path::Path) -> Result<(), String> {
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FileRenameInfo, SetFileInformationByHandle, DELETE, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_RENAME_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, SYNCHRONIZE,
    };
    let src = large(&source.to_string_lossy());
    let dst: Vec<u16> = destination.to_string_lossy().encode_utf16().collect();
    unsafe {
        let h = CreateFileW(PCWSTR(src.as_ptr()), (DELETE | SYNCHRONIZE).0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, None,
            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, HANDLE::default())
            .map_err(|e| format!("ouverture : {e}"))?;
        // FILE_RENAME_INFO est de taille variable : nom de destination à la suite de la structure
        let decalage = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
        let taille = decalage + (dst.len() + 1) * 2;
        let mut tampon = vec![0u64; taille.div_ceil(8)];
        let info = tampon.as_mut_ptr() as *mut FILE_RENAME_INFO;
        (*info).FileNameLength = (dst.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(dst.as_ptr(), (tampon.as_mut_ptr() as *mut u8).add(decalage) as *mut u16, dst.len());
        let r = SetFileInformationByHandle(h, FileRenameInfo, tampon.as_ptr() as *const c_void, taille as u32).map_err(|e| format!("renommage : {e}"));
        let _ = CloseHandle(h);
        r
    }
}

/// Remplace le propriétaire puis toute la DACL (héritage coupé) par ceux du SDDL ; les enfants héritent des
/// nouvelles entrées. Contrairement à icacls /grant, aucune entrée existante n'est conservée. En deux temps :
/// changer de propriétaire demande WRITE_OWNER (privilège de prise de possession), réécrire la DACL demande
/// WRITE_DAC, que donne le fait d'être devenu propriétaire.
pub fn poser_droits(chemin: &std::path::Path, sddl: &str) -> Result<(), String> {
    use windows::Win32::Foundation::{BOOL, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    };
    let (nom, s) = (large(&chemin.to_string_lossy()), large(sddl));
    unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(s.as_ptr()), SDDL_REVISION_1, &mut sd, None).map_err(|e| e.to_string())?;
        let (mut present, mut defaut) = (BOOL::default(), BOOL::default());
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut proprietaire = PSID::default();
        let mut r = GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaut).map_err(|e| e.to_string());
        if r.is_ok() && (!present.as_bool() || dacl.is_null()) {
            r = Err("SDDL sans DACL".into());
        }
        if r.is_ok() {
            r = GetSecurityDescriptorOwner(sd, &mut proprietaire, &mut defaut).map_err(|e| e.to_string());
        }
        if r.is_ok() && !proprietaire.is_invalid() {
            let e = SetNamedSecurityInfoW(PCWSTR(nom.as_ptr()), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
                proprietaire, PSID::default(), None, None);
            if e.0 != 0 {
                r = Err(format!("propriétaire : {}", windows::core::Error::from(e)));
            }
        }
        if r.is_ok() {
            let e = SetNamedSecurityInfoW(PCWSTR(nom.as_ptr()), SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, PSID::default(), PSID::default(), Some(dacl), None);
            if e.0 != 0 {
                r = Err(format!("droits : {}", windows::core::Error::from(e)));
            }
        }
        let _ = LocalFree(HLOCAL(sd.0));
        r
    }
}

/// Copie un fichier vers un nouveau fichier créé directement avec son descripteur de sécurité (SDDL), par
/// blocs (taille quelconque), et renvoie l'empreinte SHA-256 du contenu copié. La destination ne doit pas
/// exister ; en cas d'échec, elle est supprimée.
pub fn copier_protege(source: &std::path::Path, destination: &std::path::Path, sddl: &str) -> Result<String, String> {
    copier_protege_avec(source, destination, sddl, &[], &mut |_, _| {})
}

/// `copier_protege`, avec un en-tête écrit avant le contenu et une transformation appliquée à chaque bloc
/// (paramètres : octets du bloc, position du bloc dans le fichier d'origine). L'empreinte renvoyée est
/// celle du contenu d'ORIGINE, avant transformation.
pub fn copier_protege_avec(source: &std::path::Path, destination: &std::path::Path, sddl: &str, entete: &[u8],
                           transformer: &mut dyn FnMut(&mut [u8], u64)) -> Result<String, String> {
    let mut entree = std::fs::File::open(source).map_err(|e| format!("lecture de l'original : {e}"))?;
    copier_protege_depuis(&mut entree, destination, sddl, entete, transformer)
}

/// `copier_protege_avec`, depuis un flux déjà ouvert (handle vérifié de l'original, par exemple)
pub fn copier_protege_depuis(entree: &mut dyn std::io::Read, destination: &std::path::Path, sddl: &str, entete: &[u8],
                             transformer: &mut dyn FnMut(&mut [u8], u64)) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    use std::io::Write;
    use std::os::windows::io::FromRawHandle;
    use windows::Win32::Foundation::{HLOCAL, LocalFree, GENERIC_WRITE};
    use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows::Win32::Storage::FileSystem::{CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE};
    let (nom, s) = (large(&destination.to_string_lossy()), large(sddl));
    let sortie = unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(s.as_ptr()), SDDL_REVISION_1, &mut sd, None).map_err(|e| e.to_string())?;
        let attributs = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd.0, bInheritHandle: false.into() };
        let h = CreateFileW(PCWSTR(nom.as_ptr()), GENERIC_WRITE.0, FILE_SHARE_NONE, Some(&attributs), CREATE_NEW, FILE_ATTRIBUTE_NORMAL, HANDLE::default());
        let _ = LocalFree(HLOCAL(sd.0));
        std::fs::File::from_raw_handle(h.map_err(|e| format!("création de la copie : {e}"))?.0 as _)
    };
    let mut sortie = sortie;
    let mut empreinte = Sha256::new();
    let mut tampon = vec![0u8; 1 << 16];
    let r = (|| -> std::io::Result<()> {
        sortie.write_all(entete)?;
        let mut position = 0u64;
        loop {
            let n = entree.read(&mut tampon)?;
            if n == 0 {
                break;
            }
            empreinte.update(&tampon[..n]);
            transformer(&mut tampon[..n], position);
            position += n as u64;
            sortie.write_all(&tampon[..n])?;
        }
        sortie.sync_all()
    })();
    drop(sortie);
    if let Err(e) = r {
        let _ = std::fs::remove_file(destination);
        return Err(format!("copie : {e}"));
    }
    Ok(empreinte.finalize().iter().map(|o| format!("{o:02x}")).collect())
}

/// Remplace `destination` par `source` (même volume), écriture immédiate sur le disque
pub fn remplacer_fichier(source: &std::path::Path, destination: &std::path::Path) -> Result<(), String> {
    use windows::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH};
    let (s, d) = (large(&source.to_string_lossy()), large(&destination.to_string_lossy()));
    unsafe { MoveFileExW(PCWSTR(s.as_ptr()), PCWSTR(d.as_ptr()), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH).map_err(|e| e.to_string()) }
}

// ------------------------------------------------------------ chemins choisis par l'utilisateur, opérés en SYSTEM
//
// Un contrôle suivi d'une opération par chemin laisse une fenêtre où une jonction ou un lien redirige
// l'opération (vers un dossier système, par exemple). Ici : une ouverture par handle sans suivre de lien sur
// le dernier élément, le chemin final réel vérifié, puis toutes les opérations par ce handle.

/// Échec d'ouverture sans suivre de lien
#[derive(Debug, Clone, PartialEq)]
pub enum ErreurOuverture {
    Absent,
    /// Le dernier élément est un lien (jonction, lien symbolique)
    Lien,
    /// Le chemin final réel n'est pas le chemin demandé (lien ou jonction plus haut dans le chemin)
    Detourne(String),
    Autre(String),
}

impl std::fmt::Display for ErreurOuverture {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ErreurOuverture::Absent => write!(f, "introuvable"),
            ErreurOuverture::Lien => write!(f, "le chemin est un lien"),
            ErreurOuverture::Detourne(r) => write!(f, "le chemin mène ailleurs ({r})"),
            ErreurOuverture::Autre(e) => write!(f, "{e}"),
        }
    }
}

/// Décision pure : deux chemins désignent-ils le même emplacement ? (préfixes \\?\ et \\?\UNC\ retirés,
/// séparateurs, casse, barre finale)
pub fn meme_chemin(a: &str, b: &str) -> bool {
    fn n(s: &str) -> String {
        let s = s.replace('/', "\\");
        let s = match s.strip_prefix(r"\\?\UNC\") {
            Some(r) => format!(r"\\{r}"),
            None => s.strip_prefix(r"\\?\").unwrap_or(&s).to_string(),
        };
        s.trim_end_matches('\\').to_lowercase()
    }
    !a.trim().is_empty() && !b.trim().is_empty() && n(a) == n(b)
}

/// Chemin final réel d'un handle (liens et jonctions résolus)
pub fn chemin_final(f: &std::fs::File) -> Result<String, String> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Storage::FileSystem::{GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED};
    let h = HANDLE(f.as_raw_handle());
    let mut tampon = vec![0u16; 1024];
    for _ in 0..2 {
        let n = unsafe { GetFinalPathNameByHandleW(h, &mut tampon, FILE_NAME_NORMALIZED) } as usize;
        if n == 0 {
            return Err(windows::core::Error::from_win32().to_string());
        }
        if n < tampon.len() {
            return Ok(String::from_utf16_lossy(&tampon[..n]));
        }
        tampon = vec![0u16; n + 1];
    }
    Err("chemin final trop long".into())
}

/// Ouvre un fichier (ou un dossier) sans suivre de lien sur son dernier élément ; refuse s'il en est un
pub fn ouvrir_sans_lien(chemin: &std::path::Path, acces: u32, partage: u32, dossier: bool) -> Result<std::fs::File, ErreurOuverture> {
    use std::os::windows::io::FromRawHandle;
    use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FileAttributeTagInfo, GetFileInformationByHandleEx, FILE_ATTRIBUTE_TAG_INFO, FILE_FLAGS_AND_ATTRIBUTES,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_MODE, OPEN_EXISTING,
    };
    let nom = large(&chemin.to_string_lossy());
    let options = FILE_FLAG_OPEN_REPARSE_POINT | if dossier { FILE_FLAG_BACKUP_SEMANTICS } else { FILE_FLAGS_AND_ATTRIBUTES(0) };
    let h = unsafe { CreateFileW(PCWSTR(nom.as_ptr()), acces, FILE_SHARE_MODE(partage), None, OPEN_EXISTING, options, HANDLE::default()) }
        .map_err(|e| {
            if e.code() == ERROR_FILE_NOT_FOUND.to_hresult() || e.code() == ERROR_PATH_NOT_FOUND.to_hresult() {
                ErreurOuverture::Absent
            } else {
                ErreurOuverture::Autre(e.to_string())
            }
        })?;
    let f = unsafe { std::fs::File::from_raw_handle(h.0 as _) };
    let mut info = FILE_ATTRIBUTE_TAG_INFO::default();
    unsafe {
        GetFileInformationByHandleEx(h, FileAttributeTagInfo, &mut info as *mut _ as *mut c_void, std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32)
    }.map_err(|e| ErreurOuverture::Autre(e.to_string()))?;
    if info.FileAttributes & 0x400 != 0 {
        return Err(ErreurOuverture::Lien);
    }
    Ok(f)
}

/// Forme longue d'un chemin (noms courts 8.3 comme « RUNNER~1 » développés), pour le comparer au chemin final
/// que rend Windows. Ne suit pas les jonctions : elle traduit des noms, elle ne résout pas de lien. Pour un
/// élément qui n'existe pas encore, son dossier parent est développé.
pub fn forme_longue(p: &std::path::Path) -> std::path::PathBuf {
    use windows::Win32::Storage::FileSystem::GetLongPathNameW;
    let n = large(&p.to_string_lossy());
    let mut tampon = vec![0u16; 1024];
    let l = unsafe { GetLongPathNameW(PCWSTR(n.as_ptr()), Some(&mut tampon)) } as usize;
    if l > 0 && l < tampon.len() {
        return std::path::PathBuf::from(String::from_utf16_lossy(&tampon[..l]));
    }
    match (p.parent(), p.file_name()) {
        (Some(parent), Some(nom)) if parent != p => forme_longue(parent).join(nom),
        _ => p.to_path_buf(),
    }
}

/// Chemin attendu, absolu et en forme longue
fn chemin_attendu(chemin: &std::path::Path) -> Result<std::path::PathBuf, ErreurOuverture> {
    std::path::absolute(chemin).map(|a| forme_longue(&a)).map_err(|e| ErreurOuverture::Autre(e.to_string()))
}

/// Ouvre sans suivre de lien et vérifie que le chemin final réel est le chemin demandé
pub fn ouvrir_verifie(chemin: &std::path::Path, acces: u32, partage: u32, dossier: bool) -> Result<std::fs::File, ErreurOuverture> {
    let attendu = chemin_attendu(chemin)?;
    let f = ouvrir_sans_lien(&attendu, acces, partage, dossier)?;
    let reel = chemin_final(&f).map_err(ErreurOuverture::Autre)?;
    if !meme_chemin(&reel, &attendu.to_string_lossy()) {
        return Err(ErreurOuverture::Detourne(reel));
    }
    Ok(f)
}

/// Crée un fichier qui n'existe pas encore, sans suivre de lien, et vérifie son chemin final réel ; s'il ne
/// correspond pas, le fichier créé est supprimé par son handle et la création refusée. Le handle permet
/// lecture, écriture et suppression.
pub fn creer_verifie(chemin: &std::path::Path) -> Result<std::fs::File, ErreurOuverture> {
    use std::os::windows::io::FromRawHandle;
    use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows::Win32::Storage::FileSystem::{CreateFileW, CREATE_NEW, DELETE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_NONE};
    let attendu = chemin_attendu(chemin)?;
    let nom = large(&attendu.to_string_lossy());
    let h = unsafe {
        CreateFileW(PCWSTR(nom.as_ptr()), GENERIC_READ.0 | GENERIC_WRITE.0 | DELETE.0, FILE_SHARE_NONE, None, CREATE_NEW,
            FILE_FLAG_OPEN_REPARSE_POINT, HANDLE::default())
    }.map_err(|e| ErreurOuverture::Autre(e.to_string()))?;
    let f = unsafe { std::fs::File::from_raw_handle(h.0 as _) };
    match chemin_final(&f) {
        Ok(reel) if meme_chemin(&reel, &attendu.to_string_lossy()) => Ok(f),
        Ok(reel) => {
            let _ = supprimer_par_handle(&f);
            Err(ErreurOuverture::Detourne(reel))
        }
        Err(e) => {
            let _ = supprimer_par_handle(&f);
            Err(ErreurOuverture::Autre(e))
        }
    }
}

/// Supprime le fichier ouvert (à la fermeture de son dernier handle) ; le handle doit avoir l'accès DELETE
pub fn supprimer_par_handle(f: &std::fs::File) -> Result<(), String> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Storage::FileSystem::{FileDispositionInfo, SetFileInformationByHandle, FILE_DISPOSITION_INFO};
    let info = FILE_DISPOSITION_INFO { DeleteFile: true.into() };
    unsafe {
        SetFileInformationByHandle(HANDLE(f.as_raw_handle()), FileDispositionInfo, &info as *const _ as *const c_void,
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32)
    }.map_err(|e| e.to_string())
}

/// Ajoute des attributs (caché, système…) au fichier ouvert, par son handle (accès FILE_WRITE_ATTRIBUTES requis)
pub fn ajouter_attributs(f: &std::fs::File, attributs: u32) -> Result<(), String> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Storage::FileSystem::{FileBasicInfo, GetFileInformationByHandleEx, SetFileInformationByHandle, FILE_BASIC_INFO};
    let h = HANDLE(f.as_raw_handle());
    let mut info = FILE_BASIC_INFO::default();
    let taille = std::mem::size_of::<FILE_BASIC_INFO>() as u32;
    unsafe {
        GetFileInformationByHandleEx(h, FileBasicInfo, &mut info as *mut _ as *mut c_void, taille).map_err(|e| e.to_string())?;
        info.FileAttributes |= attributs;
        SetFileInformationByHandle(h, FileBasicInfo, &info as *const _ as *const c_void, taille).map_err(|e| e.to_string())
    }
}

/// Exécute `f` avec le privilège `nom` actif sur CE fil seulement (jeton d'emprunt de soi-même), puis revient à
/// l'identité du service ; si ce retour échoue, le service s'arrête (le fil garderait le privilège)
fn avec_privilege<T>(nom: &str, f: impl FnOnce() -> T) -> Result<T, String> {
    use windows::Win32::Foundation::{GetLastError, LUID, ERROR_NOT_ALL_ASSIGNED};
    use windows::Win32::Security::{
        AdjustTokenPrivileges, ImpersonateSelf, LookupPrivilegeValueW, RevertToSelf, SecurityImpersonation, LUID_AND_ATTRIBUTES,
        SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};
    unsafe {
        ImpersonateSelf(SecurityImpersonation).map_err(|e| format!("emprunt du jeton : {e}"))?;
        let resultat = (|| {
            let mut jeton = HANDLE::default();
            OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, false, &mut jeton).map_err(|e| format!("jeton du fil : {e}"))?;
            let n = large(nom);
            let mut luid = LUID::default();
            let mut r = LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(n.as_ptr()), &mut luid).map_err(|e| e.to_string());
            if r.is_ok() {
                let tp = TOKEN_PRIVILEGES { PrivilegeCount: 1, Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }] };
                r = AdjustTokenPrivileges(jeton, false, Some(&tp), 0, None, None).map_err(|e| e.to_string());
                if r.is_ok() && GetLastError() == ERROR_NOT_ALL_ASSIGNED {
                    r = Err(format!("privilège {nom} absent du jeton"));
                }
            }
            let _ = CloseHandle(jeton);
            r
        })();
        let valeur = resultat.map(|_| f());
        retour_ou_arret(RevertToSelf().map_err(|e| e.to_string()), &format!("privilège {nom}"), arreter);
        valeur
    }
}

/// Pose l'audit (SACL) d'un fichier par son handle, ouvert sans suivre de lien et chemin final vérifié, avec
/// SeSecurityPrivilege actif sur ce fil pour ce seul appel ; `sddl` décrit une seule entrée d'audit (« S:(AU;…) »).
/// SACL complétée par SetKernelObjectSecurity (poser_sacl, comme l'audit des données sensibles) : SetSecurityInfo
/// relit aussi le descripteur de l'objet et échouait (« Access is denied ») avec un handle ouvert pour la seule SACL
/// (constaté sur un poste réel : leurres jamais audités ; les scénarios d'intégration n'ont pas de session).
pub fn poser_audit_verifie(chemin: &std::path::Path, sddl: &str) -> Result<(), String> {
    // ACCESS_SYSTEM_SECURITY | SYNCHRONIZE, tout partage
    const ACCES: u32 = 0x0100_0000 | 0x0010_0000;
    let voulue = entree_normalisee(sddl)?;
    avec_privilege("SeSecurityPrivilege", || {
        let f = ouvrir_verifie(chemin, ACCES, 0x7, false).map_err(|e| format!("{} : {e}", chemin.display()))?;
        poser_sacl(&f, &voulue, false, &mut BilanAudit::default()).map_err(|e| format!("audit : {e}"))
    })?
}

/// Bilan d'une pose d'audit sur une arborescence
#[derive(Debug, Default, Clone, PartialEq)]
pub struct BilanAudit {
    /// Éléments dont la SACL a été complétée
    pub poses: usize,
    /// Éléments qui avaient déjà l'audit voulu
    pub deja: usize,
    /// Liens, chemins détournés ou éléments illisibles : écartés, jamais suivis
    pub ecartes: usize,
    /// Parcours arrêté au nombre maximal d'éléments
    pub tronque: bool,
}

/// Descripteur construit depuis un SDDL, libéré à la fin
struct DescripteurSddl(windows::Win32::Security::PSECURITY_DESCRIPTOR);

impl DescripteurSddl {
    fn depuis(sddl: &str) -> Result<DescripteurSddl, String> {
        use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
        use windows::Win32::Security::PSECURITY_DESCRIPTOR;
        let s = large(sddl);
        let mut sd = PSECURITY_DESCRIPTOR::default();
        unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(s.as_ptr()), SDDL_REVISION_1, &mut sd, None) }.map_err(|e| format!("{sddl} : {e}"))?;
        Ok(DescripteurSddl(sd))
    }
}

impl Drop for DescripteurSddl {
    fn drop(&mut self) {
        use windows::Win32::Foundation::{HLOCAL, LocalFree};
        unsafe {
            let _ = LocalFree(HLOCAL(self.0 .0));
        }
    }
}

/// SACL d'un descripteur, en SDDL (« S:… ») ; descripteur sans SACL (cas de la plupart des fichiers) : chaîne vide,
/// pas une erreur. None : descripteur illisible.
fn texte_sacl(sd: windows::Win32::Security::PSECURITY_DESCRIPTOR) -> Option<String> {
    use windows::Win32::Foundation::{BOOL, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{ConvertSecurityDescriptorToStringSecurityDescriptorW, SDDL_REVISION_1};
    use windows::Win32::Security::{GetSecurityDescriptorSacl, ACL, SACL_SECURITY_INFORMATION};
    unsafe {
        let (mut presente, mut defaut) = (BOOL::default(), BOOL::default());
        let mut acl: *mut ACL = std::ptr::null_mut();
        GetSecurityDescriptorSacl(sd, &mut presente, &mut acl, &mut defaut).ok()?;
        if !presente.as_bool() || acl.is_null() {
            return Some(String::new());
        }
        let mut p = windows::core::PWSTR::null();
        ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, SACL_SECURITY_INFORMATION, &mut p, None).ok()?;
        if p.is_null() {
            return Some(String::new());
        }
        let t = p.to_string().ok();
        let _ = LocalFree(HLOCAL(p.0 as _));
        t
    }
}

/// SACL, en SDDL, d'un descripteur donné en SDDL (tests : même chemin que la lecture d'un objet)
pub fn texte_sacl_de_sddl(sddl: &str) -> Option<String> {
    texte_sacl(DescripteurSddl::depuis(sddl).ok()?.0)
}

/// Entrée d'audit voulue, en SDDL normalisé par Windows (« AU;OINPIOSA;CC;;;WD »), tirée d'un SDDL « S:(…) » d'une
/// seule entrée
fn entree_normalisee(sddl: &str) -> Result<String, String> {
    let d = DescripteurSddl::depuis(sddl)?;
    let t = texte_sacl(d.0).ok_or_else(|| format!("{sddl} : SACL illisible"))?;
    let e = entrees_sacl(&t).1;
    match e.as_slice() {
        [une] => Ok(une.clone()),
        _ => Err(format!("{sddl} : une seule entrée d'audit attendue")),
    }
}

/// SACL actuelle de l'objet ouvert (handle avec ACCESS_SYSTEM_SECURITY), en SDDL ; None : illisible
fn sacl_du_handle(f: &std::fs::File) -> Option<String> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Security::{GetKernelObjectSecurity, PSECURITY_DESCRIPTOR, SACL_SECURITY_INFORMATION};
    let h = HANDLE(f.as_raw_handle());
    let mut taille = 0u32;
    unsafe {
        let _ = GetKernelObjectSecurity(h, SACL_SECURITY_INFORMATION.0, PSECURITY_DESCRIPTOR::default(), 0, &mut taille);
        if taille == 0 {
            return None;
        }
        let mut tampon = vec![0u8; taille as usize];
        GetKernelObjectSecurity(h, SACL_SECURITY_INFORMATION.0, PSECURITY_DESCRIPTOR(tampon.as_mut_ptr() as *mut c_void), taille, &mut taille).ok()?;
        texte_sacl(PSECURITY_DESCRIPTOR(tampon.as_mut_ptr() as *mut c_void))
    }
}

/// SACL en SDDL découpée : (drapeaux de contrôle « AI », « P »…, entrées sans parenthèses)
fn entrees_sacl(t: &str) -> (String, Vec<String>) {
    let t = t.strip_prefix("S:").unwrap_or(t);
    let debut = t.find('(').unwrap_or(t.len());
    let entrees = t[debut..].split(')').map(|e| e.trim_start_matches('(')).filter(|e| !e.is_empty()).map(String::from).collect();
    (t[..debut].to_string(), entrees)
}

/// Décision pure : SACL complétée, ou None si l'audit voulu est déjà en place. Seules les entrées de deR4Tizer sont
/// retirées : audit explicite (non hérité) de Tout le monde (WD), sur les succès (SA), avec les droits de l'entrée
/// voulue ; toute autre entrée (règle d'audit de l'organisation, entrée héritée) est gardée telle quelle. Pour un
/// fichier (`heritee_suffit`), l'entrée voulue héritée du dossier (« ID ») suffit.
pub fn sacl_completee(actuelle: &str, voulue: &str, heritee_suffit: bool) -> Option<String> {
    let champs = |e: &str| e.split(';').map(String::from).collect::<Vec<_>>();
    let v = champs(voulue);
    let notre = |e: &str| {
        let c = champs(e);
        c.len() == 6 && c[0] == "AU" && c[5] == "WD" && c[2] == v[2] && c[1].contains("SA") && !c[1].contains("ID")
    };
    let (controle, entrees) = entrees_sacl(actuelle);
    let exacte = entrees.iter().any(|e| e == voulue);
    let heritee = heritee_suffit && entrees.iter().any(|e| { let mut c = champs(e); c.len() == 6 && { c[1] = c[1].replace("ID", ""); c == v } });
    let perimees = entrees.iter().any(|e| notre(e) && e != voulue);
    if (exacte || heritee) && !perimees {
        return None;
    }
    let mut nouvelle: Vec<&str> = entrees.iter().filter(|e| !notre(e)).map(String::as_str).collect();
    nouvelle.push(voulue);
    Some(format!("S:{controle}{}", nouvelle.iter().map(|e| format!("({e})")).collect::<String>()))
}

/// Complète la SACL de l'objet ouvert si besoin. SetKernelObjectSecurity : cet objet seul, SACL seule (ni DACL, ni
/// propriétaire, ni propagation par chemin aux enfants, contrairement à Set-Acl et SetSecurityInfo). SACL actuelle
/// illisible : rien n'est écrit (elle pourrait contenir des entrées à garder).
fn poser_sacl(f: &std::fs::File, voulue: &str, dossier: bool, bilan: &mut BilanAudit) -> Result<(), String> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Security::{SetKernelObjectSecurity, SACL_SECURITY_INFORMATION};
    let actuelle = sacl_du_handle(f).ok_or("SACL actuelle illisible")?;
    let Some(nouvelle) = sacl_completee(&actuelle, voulue, !dossier) else {
        bilan.deja += 1;
        return Ok(());
    };
    let sd = DescripteurSddl::depuis(&nouvelle)?;
    unsafe { SetKernelObjectSecurity(HANDLE(f.as_raw_handle()), SACL_SECURITY_INFORMATION, sd.0) }.map_err(|e| e.to_string())?;
    bilan.poses += 1;
    Ok(())
}

/// Pose l'audit (SACL) sur une arborescence de l'utilisateur, en SYSTEM, tout par handle : SeSecurityPrivilege
/// actif sur ce fil pendant le seul parcours ; chaque élément ouvert sans suivre de lien sur le dernier élément et
/// son chemin final vérifié (un lien, ou un chemin détourné plus haut, est écarté et jamais suivi : une jonction
/// posée par l'utilisateur ne fait rien écrire ailleurs) ; SACL complétée seulement si besoin (sinon des rafales
/// d'événements 4907), entrées tierces gardées. `sddl_dossier` sur la racine (et chaque sous-dossier si `recursif`),
/// `sddl_fichier` sur les fichiers déjà présents (les nouveaux héritent de l'entrée du dossier) : une seule entrée
/// chacun. Err : racine introuvable, détournée ou impossible à auditer.
pub fn poser_audit_arborescence(racine: &std::path::Path, sddl_dossier: &str, sddl_fichier: &str, recursif: bool, maximum: usize) -> Result<BilanAudit, String> {
    // ACCESS_SYSTEM_SECURITY | SYNCHRONIZE, tout partage
    const ACCES: u32 = 0x0100_0000 | 0x0010_0000;
    let (voulue_dossier, voulue_fichier) = (entree_normalisee(sddl_dossier)?, entree_normalisee(sddl_fichier)?);
    avec_privilege("SeSecurityPrivilege", || {
        let mut bilan = BilanAudit::default();
        let ouverte = ouvrir_verifie(racine, ACCES, 0x7, true).map_err(|e| format!("{} : {e}", racine.display()))?;
        poser_sacl(&ouverte, &voulue_dossier, true, &mut bilan).map_err(|e| format!("{} : {e}", racine.display()))?;
        drop(ouverte);
        let mut a_parcourir = vec![racine.to_path_buf()];
        let mut vus = 0usize;
        while let Some(dossier) = a_parcourir.pop() {
            // Liste lue par chemin ; chaque entrée est ensuite ouverte et vérifiée : une redirection du dossier entre
            // la liste et l'ouverture donne un autre chemin final, donc un refus
            let Ok(entrees) = std::fs::read_dir(&dossier) else { bilan.ecartes += 1; continue };
            for e in entrees.flatten() {
                vus += 1;
                if vus > maximum {
                    bilan.tronque = true;
                    return Ok(bilan);
                }
                // Type tiré de la liste, sans suivre de lien : une jonction ou un lien n'est ni dossier ni fichier
                let Ok(t) = e.file_type() else { bilan.ecartes += 1; continue };
                if t.is_symlink() {
                    bilan.ecartes += 1;
                    continue;
                }
                if t.is_dir() && !recursif {
                    continue;
                }
                let chemin = e.path();
                match ouvrir_verifie(&chemin, ACCES, 0x7, t.is_dir()) {
                    Ok(f) => {
                        let voulue = if t.is_dir() { &voulue_dossier } else { &voulue_fichier };
                        if poser_sacl(&f, voulue, t.is_dir(), &mut bilan).is_err() {
                            bilan.ecartes += 1;
                        } else if t.is_dir() {
                            a_parcourir.push(chemin);
                        }
                    }
                    Err(_) => bilan.ecartes += 1,
                }
            }
        }
        Ok(bilan)
    })?
}

/// Ouvre un flux de données alternatif (« :Zone.Identifier ») du fichier ouvert, par rapport à son handle et
/// sans repasser par le chemin. Lecture : None si le flux n'existe pas. Écriture : flux créé ou remplacé.
pub fn ouvrir_flux(f: &std::fs::File, flux: &str, ecriture: bool) -> Result<Option<std::fs::File>, String> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows::Wdk::Storage::FileSystem::{NtCreateFile, NTCREATEFILE_CREATE_DISPOSITION, NTCREATEFILE_CREATE_OPTIONS};
    use windows::Win32::Foundation::UNICODE_STRING;
    use windows::Win32::Storage::FileSystem::{FILE_ACCESS_RIGHTS, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE};
    use windows::Win32::System::IO::IO_STATUS_BLOCK;
    let mut nom: Vec<u16> = flux.encode_utf16().collect();
    let chaine = UNICODE_STRING { Length: (nom.len() * 2) as u16, MaximumLength: (nom.len() * 2) as u16, Buffer: PWSTR(nom.as_mut_ptr()) };
    let attributs = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: HANDLE(f.as_raw_handle()),
        ObjectName: &chaine,
        Attributes: 0x40, // OBJ_CASE_INSENSITIVE
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    // GENERIC_READ ou GENERIC_WRITE, plus SYNCHRONIZE ; FILE_OPEN (1) ou FILE_OVERWRITE_IF (5) ;
    // FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
    let acces = FILE_ACCESS_RIGHTS(if ecriture { 0x4000_0000 } else { 0x8000_0000 } | 0x0010_0000);
    let disposition = NTCREATEFILE_CREATE_DISPOSITION(if ecriture { 5 } else { 1 });
    let mut h = HANDLE::default();
    let mut io = IO_STATUS_BLOCK::default();
    let statut = unsafe {
        // Partage total : le handle du fichier lui-même peut détenir DELETE (mise en quarantaine), qu'un flux
        // ouvert sans FILE_SHARE_DELETE contredirait (violation de partage)
        NtCreateFile(&mut h, acces, &attributs, &mut io, None, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, disposition,
            NTCREATEFILE_CREATE_OPTIONS(0x40 | 0x20), None, 0)
    };
    if statut.0 == 0xC000_0034u32 as i32 && !ecriture {
        return Ok(None); // STATUS_OBJECT_NAME_NOT_FOUND
    }
    if statut.0 < 0 {
        return Err(format!("flux {flux} : NTSTATUS {:#x}", statut.0 as u32));
    }
    Ok(Some(unsafe { std::fs::File::from_raw_handle(h.0 as _) }))
}

/// Propriétaire (SID) du fichier ou dossier ouvert
pub fn proprietaire_par_handle(f: &std::fs::File) -> Option<String> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows::Win32::Security::{OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};
    let mut proprietaire = PSID::default();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        let r = GetSecurityInfo(HANDLE(f.as_raw_handle()), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, Some(&mut proprietaire), None,
            None, None, Some(&mut sd));
        if r.0 != 0 || proprietaire.is_invalid() {
            return None;
        }
        let s = sid_texte(proprietaire);
        let _ = LocalFree(HLOCAL(sd.0));
        Some(s).filter(|s| !s.is_empty())
    }
}

/// Sessions actives avec un utilisateur (phase 4, PR 4.5a) : état `WTSActive` et jeton de session lisible ; une
/// énumération impossible est une erreur, jamais « aucune session »
pub fn sessions_actives() -> Result<Vec<u32>, String> {
    use windows::Win32::System::RemoteDesktop::{WTSActive, WTSEnumerateSessionsW, WTSFreeMemory, WTSQueryUserToken, WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW};
    unsafe {
        let mut sessions: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
        let mut n = 0u32;
        WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut sessions, &mut n).map_err(|e| format!("sessions : {e}"))?;
        // Audit de #100, S100-02 : from_raw_parts exige un pointeur non nul, même pour zéro élément
        let liste = if sessions.is_null() || n == 0 { Vec::new() } else { std::slice::from_raw_parts(sessions, n as usize).to_vec() };
        if !sessions.is_null() {
            WTSFreeMemory(sessions as *mut c_void);
        }
        let mut actives = Vec::new();
        for s in liste.iter().filter(|s| s.State == WTSActive) {
            let mut jeton = HANDLE::default();
            if WTSQueryUserToken(s.SessionId, &mut jeton).is_ok() {
                let _ = CloseHandle(jeton);
                actives.push(s.SessionId);
            }
        }
        Ok(actives)
    }
}

/// Sessions où tourne un processus dont le chemin complet est **exactement** `chemin` (sans tenir compte de la casse) :
/// une copie de l'interface posée ailleurs ne compte pas (phase 4, PR 4.5a). Instantané impossible : erreur
pub fn sessions_du_programme(chemin: &str) -> Result<Vec<u32>, String> {
    use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    let nom = std::path::Path::new(chemin).file_stem().map(|s| s.to_string_lossy().to_lowercase()).unwrap_or_default();
    let mut sessions = Vec::new();
    for (pid, info) in processus_lu()? {
        if info.nom.to_lowercase() != nom || !chemin_processus(pid).eq_ignore_ascii_case(chemin) {
            continue;
        }
        let mut session = 0u32;
        if unsafe { ProcessIdToSessionId(pid, &mut session) }.is_ok() && !sessions.contains(&session) {
            sessions.push(session);
        }
    }
    Ok(sessions)
}

/// Exécute `f` sous l'identité d'un utilisateur dont une session est ouverte (jeton de sa session), sur ce
/// fil seulement : Windows applique alors SES droits, pas ceux de SYSTEM. Erreur si aucune session de ce
/// compte n'est ouverte. Si le retour au jeton du service échoue, le service s'arrête plutôt que de
/// continuer sous une autre identité.
pub fn avec_jeton_de<T>(sid: &str, f: impl FnOnce() -> T) -> Result<T, String> {
    use windows::Win32::Security::{GetTokenInformation, ImpersonateLoggedOnUser, RevertToSelf, TokenUser, TOKEN_USER};
    use windows::Win32::System::RemoteDesktop::{WTSEnumerateSessionsW, WTSFreeMemory, WTSQueryUserToken, WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW};
    unsafe {
        let mut sessions: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
        let mut n = 0u32;
        WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut sessions, &mut n).map_err(|e| format!("sessions : {e}"))?;
        // Audit de #100, S100-02 : from_raw_parts exige un pointeur non nul, même pour zéro élément
        let liste = if sessions.is_null() || n == 0 { Vec::new() } else { std::slice::from_raw_parts(sessions, n as usize).to_vec() };
        if !sessions.is_null() {
            WTSFreeMemory(sessions as *mut c_void);
        }
        for s in liste {
            let mut jeton = HANDLE::default();
            if WTSQueryUserToken(s.SessionId, &mut jeton).is_err() {
                continue;
            }
            let mut tampon = vec![0u64; 64];
            let mut taille = 0u32;
            let ok = GetTokenInformation(jeton, TokenUser, Some(tampon.as_mut_ptr() as *mut c_void), (tampon.len() * 8) as u32, &mut taille).is_ok();
            if !ok || sid_texte((*(tampon.as_ptr() as *const TOKEN_USER)).User.Sid) != sid {
                let _ = CloseHandle(jeton);
                continue;
            }
            let r = ImpersonateLoggedOnUser(jeton).map_err(|e| format!("emprunt de l'identité : {e}"));
            let _ = CloseHandle(jeton);
            r?;
            let valeur = f();
            retour_ou_arret(RevertToSelf().map_err(|e| e.to_string()), "restauration sous l'identité de l'utilisateur", arreter);
            return Ok(valeur);
        }
        Err("aucune session ouverte de ce compte".into())
    }
}

/// Un élément EXISTANT du chemin (fichier ou dossier parent) est-il un lien (jonction, lien symbolique) ?
/// Contrôle préalable seulement : la preuve reste le chemin final vérifié après ouverture
pub fn chemin_contient_lien(chemin: &std::path::Path) -> bool {
    use std::os::windows::fs::MetadataExt;
    chemin.ancestors().any(|p| std::fs::symlink_metadata(p).is_ok_and(|m| m.file_attributes() & 0x400 != 0))
}

/// Propriétés d'un paquet MSI lues dans sa table Property (lecture seule, rien n'est exécuté) :
/// (ProductVersion, UpgradeCode). À n'appeler qu'APRÈS la vérification de la signature du fichier.
pub fn proprietes_msi(chemin: &std::path::Path) -> Result<(String, String), String> {
    use windows::Win32::System::ApplicationInstallationAndServicing::{
        MsiCloseHandle, MsiDatabaseOpenViewW, MsiOpenDatabaseW, MsiRecordGetStringW, MsiViewExecute, MsiViewFetch, MSIDBOPEN_READONLY,
        MSIHANDLE,
    };
    let nom = large(&chemin.to_string_lossy());
    unsafe {
        let mut base = MSIHANDLE::default();
        let r = MsiOpenDatabaseW(PCWSTR(nom.as_ptr()), MSIDBOPEN_READONLY, &mut base);
        if r != 0 {
            return Err(format!("paquet MSI illisible (erreur {r})"));
        }
        let lire = |propriete: &str| -> Result<String, String> {
            let requete = large(&format!("SELECT `Value` FROM `Property` WHERE `Property`='{propriete}'"));
            let mut vue = MSIHANDLE::default();
            if MsiDatabaseOpenViewW(base, PCWSTR(requete.as_ptr()), &mut vue) != 0 {
                return Err(format!("{propriete} : requête refusée"));
            }
            let mut resultat = Err(format!("{propriete} absente du paquet"));
            if MsiViewExecute(vue, MSIHANDLE::default()) == 0 {
                let mut enr = MSIHANDLE::default();
                if MsiViewFetch(vue, &mut enr) == 0 {
                    let mut tampon = vec![0u16; 256];
                    let mut n = tampon.len() as u32;
                    if MsiRecordGetStringW(enr, 1, PWSTR(tampon.as_mut_ptr()), Some(&mut n)) == 0 {
                        resultat = Ok(String::from_utf16_lossy(&tampon[..n as usize]));
                    }
                    MsiCloseHandle(enr);
                }
            }
            MsiCloseHandle(vue);
            resultat
        };
        let r = lire("ProductVersion").and_then(|v| lire("UpgradeCode").map(|u| (v, u)));
        MsiCloseHandle(base);
        r
    }
}
