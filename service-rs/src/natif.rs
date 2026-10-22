//! Appels Windows de bas niveau : table TCP, chemins et liste des processus, signatures Authenticode.

use std::collections::HashMap;
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, SetTcpEntry, MIB_TCPROW_LH, MIB_TCPROW_LH_0, MIB_TCP_STATE, TCP_TABLE_OWNER_PID_ALL,
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
    let mut liste = Vec::new();
    lire_table(2, &mut liste);
    lire_table(23, &mut liste);
    liste
}

fn lire_table(famille: u32, liste: &mut Vec<Connexion>) {
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
            return;
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
        return;
    }
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
    let mut carte = HashMap::new();
    unsafe {
        let Ok(h) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else { return carte };
        let mut e = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
        if Process32FirstW(h, &mut e).is_ok() {
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
    }
    carte
}

// ------------------------------------------------------------ signatures

/// Vérifie la signature Authenticode intégrée au fichier ; renvoie le nom du signataire si elle est valide
pub fn signataire_valide(chemin: &str) -> Option<String> {
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
