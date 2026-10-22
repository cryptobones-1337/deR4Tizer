//! Canal de commandes : tube nommé \\.\pipe\deR4Tizer, réservé aux administrateurs et à SYSTEM.
//! L'interface envoie une ligne JSON (Commande) et reçoit une ligne JSON (Reponse).
//! Protection contre l'usurpation du tube : la première instance est créée avec FILE_FLAG_FIRST_PIPE_INSTANCE
//! (échec si quelqu'un l'a déjà créé), et une instance reste toujours ouverte (la suivante est créée avant de
//! traiter la connexion en cours) ; créer une instance supplémentaire exige un droit que seul SYSTEM possède.
//! L'interface vérifie de son côté que le serveur du tube est bien le processus du service.

use crate::commun::{self, Commande, Reponse};
use crate::moniteur::{Moniteur, Partage};
use crate::natif::large;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree, INVALID_HANDLE_VALUE};
use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{FlushFileBuffers, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

/// SYSTEM et administrateurs ; en mode console (tests uniquement), tout utilisateur connecté
fn descripteur(console: bool) -> String {
    let mut sddl = "D:(A;;GA;;;SY)(A;;GRGW;;;BA)".to_string();
    if console {
        sddl.push_str("(A;;GRGW;;;AU)");
    }
    sddl
}

fn creer(console: bool, premiere: bool) -> Result<HANDLE, String> {
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
        let mode = if premiere { PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE } else { PIPE_ACCESS_DUPLEX };
        let tube = CreateNamedPipeW(PCWSTR(nom.as_ptr()), mode, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, Some(&attributs));
        let _ = LocalFree(HLOCAL(sd.0));
        if tube == INVALID_HANDLE_VALUE || tube.is_invalid() {
            let e = windows::core::Error::from_win32();
            return Err(if premiere { format!("{e} (un autre programme occupe peut-être le canal \\\\.\\pipe\\deR4Tizer)") } else { e.to_string() });
        }
        Ok(tube)
    }
}

pub fn servir(moniteur: Arc<Mutex<Moniteur>>, partage: Arc<Partage>, console: bool) {
    std::thread::Builder::new().name("commandes".into()).spawn(move || {
        let mut derniere_erreur = String::new();
        while !partage.arret.load(Ordering::Relaxed) {
            // Première instance : refusée si le nom est déjà pris
            let mut courant = match creer(console, true) {
                Ok(t) => t,
                Err(e) => {
                    if e != derniere_erreur {
                        commun::journal(&format!("erreur du canal de commandes : {e}"));
                        derniere_erreur = e;
                    }
                    std::thread::sleep(std::time::Duration::from_secs(5));
                    continue;
                }
            };
            derniere_erreur.clear();
            while !partage.arret.load(Ordering::Relaxed) {
                unsafe {
                    // ERROR_PIPE_CONNECTED : le client s'est connecté entre la création et l'attente, c'est normal
                    if let Err(e) = ConnectNamedPipe(courant, None) {
                        if e.code().0 as u32 != 0x8007_0217 {
                            let _ = CloseHandle(courant);
                            break;
                        }
                    }
                }
                // L'instance suivante existe avant que celle-ci ne se ferme : le nom n'est jamais libre
                let suivant = match creer(console, false) {
                    Ok(t) => t,
                    Err(e) => {
                        commun::journal(&format!("erreur du canal de commandes : {e}"));
                        traiter(courant, &moniteur, &partage);
                        unsafe { let _ = CloseHandle(courant); }
                        break;
                    }
                };
                traiter(courant, &moniteur, &partage);
                unsafe { let _ = CloseHandle(courant); }
                courant = suivant;
            }
        }
    }).unwrap();
}

fn traiter(tube: HANDLE, moniteur: &Arc<Mutex<Moniteur>>, partage: &Arc<Partage>) {
    unsafe {
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
    }
}
