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

/// Empreinte SHA-256 de la clé publique du certificat qui a signé le fichier, après vérification complète de la
/// signature AVEC contrôle de révocation de toute la chaîne (un certificat volé puis révoqué est refusé).
/// Sert à la mise à jour automatique : on compare une clé, pas un nom (que n'importe qui peut obtenir).
pub fn cle_signataire_verifiee(chemin: &str) -> Option<String> {
    use sha2::{Digest, Sha256};
    use windows::Win32::Security::WinTrust::{WTD_REVOCATION_CHECK_CHAIN, WTD_REVOKE_WHOLECHAIN};
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
        dwProvFlags: WTD_REVOCATION_CHECK_CHAIN,
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
                if !signataire.is_null() && !(*signataire).pasCertChain.is_null() {
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

// ------------------------------------------------------------ catalogues de sécurité et processus

/// Fichier signé par un catalogue de sécurité installé (signature de Windows et des pilotes, rangée dans
/// System32\CatRoot et non dans le fichier lui-même) : vrai contrôle de l'empreinte, pas du dossier
pub fn signe_par_catalogue(chemin: &str) -> bool {
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
    let windows = dossier_windows().to_lowercase();
    chemin.to_lowercase().starts_with(&windows)
        && (signataire_valide(chemin).map(|s| s.starts_with("Microsoft")).unwrap_or(false) || signe_par_catalogue(chemin))
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
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows::Win32::Security::{
        GetAce, GetSecurityDescriptorControl, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID,
    };
    let nom = large(&chemin.to_string_lossy());
    unsafe {
        let mut proprietaire = PSID::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        let r = GetNamedSecurityInfoW(PCWSTR(nom.as_ptr()), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut proprietaire), None, Some(&mut dacl), None, &mut sd);
        if r.0 != 0 || sd.0.is_null() {
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
        let _ = RevertToSelf();
        valeur
    }
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
    use sha2::{Digest, Sha256};
    use std::io::{Read, Write};
    use std::os::windows::io::FromRawHandle;
    use windows::Win32::Foundation::{HLOCAL, LocalFree, GENERIC_WRITE};
    use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows::Win32::Storage::FileSystem::{CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE};
    let mut entree = std::fs::File::open(source).map_err(|e| format!("lecture de l'original : {e}"))?;
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
        loop {
            let n = entree.read(&mut tampon)?;
            if n == 0 {
                break;
            }
            empreinte.update(&tampon[..n]);
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
