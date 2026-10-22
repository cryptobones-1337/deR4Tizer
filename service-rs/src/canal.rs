//! Canal de commandes : tube nommé \\.\pipe\deR4Tizer, réservé aux administrateurs et à SYSTEM.
//! L'interface envoie une ligne JSON (Commande) et reçoit une ligne JSON (Reponse).

use crate::commun::{self, Commande, Reponse};
use crate::moniteur::{Moniteur, Partage};
use crate::natif::large;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HLOCAL, LocalFree, INVALID_HANDLE_VALUE};
use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{FlushFileBuffers, ReadFile, WriteFile, PIPE_ACCESS_DUPLEX};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
};

/// SYSTEM et administrateurs ; en mode console (tests uniquement), tout utilisateur connecté
fn descripteur(console: bool) -> String {
    let mut sddl = "D:(A;;GA;;;SY)(A;;GRGW;;;BA)".to_string();
    if console {
        sddl.push_str("(A;;GRGW;;;AU)");
    }
    sddl
}

pub fn servir(moniteur: Arc<Mutex<Moniteur>>, partage: Arc<Partage>, console: bool) {
    std::thread::Builder::new().name("commandes".into()).spawn(move || {
        let mut derniere_erreur = String::new();
        while !partage.arret.load(Ordering::Relaxed) {
            if let Err(e) = une_connexion(&moniteur, &partage, console) {
                // Une erreur répétée (tube déjà pris par une autre instance…) n'est notée qu'une fois
                if e != derniere_erreur {
                    commun::journal(&format!("erreur du canal de commandes : {e}"));
                    derniere_erreur = e;
                }
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
        }
    }).unwrap();
}

fn une_connexion(moniteur: &Arc<Mutex<Moniteur>>, partage: &Arc<Partage>, console: bool) -> Result<(), String> {
    unsafe {
        let sddl = large(&descripteur(console));
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(sddl.as_ptr()), SDDL_REVISION_1, &mut sd, None)
            .map_err(|e| e.to_string())?;
        let attributs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: false.into(),
        };
        let nom = large(commun::NOM_PIPE);
        let tube = CreateNamedPipeW(PCWSTR(nom.as_ptr()), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1, 4096, 4096, 0, Some(&attributs));
        let _ = LocalFree(HLOCAL(sd.0));
        if tube == INVALID_HANDLE_VALUE || tube.is_invalid() {
            return Err(windows::core::Error::from_win32().to_string());
        }
        // ERROR_PIPE_CONNECTED : le client s'est connecté entre la création et l'attente, c'est normal
        if let Err(e) = ConnectNamedPipe(tube, None) {
            if e.code().0 as u32 != 0x8007_0217 {
                let _ = CloseHandle(tube);
                return Err(e.to_string());
            }
        }

        // Lecture d'une ligne
        let mut demande = Vec::new();
        let mut tampon = [0u8; 4096];
        loop {
            let mut lus = 0u32;
            if ReadFile(tube, Some(&mut tampon), Some(&mut lus), None).is_err() || lus == 0 {
                break;
            }
            demande.extend_from_slice(&tampon[..lus as usize]);
            if demande.contains(&b'\n') || demande.len() > 65536 {
                break;
            }
        }
        let texte = String::from_utf8_lossy(&demande);
        let ligne = texte.trim_start_matches('\u{feff}').lines().next().unwrap_or("");
        let reponse = match serde_json::from_str::<Commande>(ligne) {
            Ok(c) => moniteur.lock().unwrap().executer(c, partage),
            Err(e) => Reponse::erreur(format!("commande illisible : {e}")),
        };
        let mut sortie = serde_json::to_vec(&reponse).unwrap_or_default();
        sortie.extend_from_slice(b"\r\n");
        let mut ecrits = 0u32;
        let _ = WriteFile(tube, Some(&sortie), Some(&mut ecrits), None);
        let _ = FlushFileBuffers(tube);
        let _ = DisconnectNamedPipe(tube);
        let _ = CloseHandle(tube);
        Ok(())
    }
}
