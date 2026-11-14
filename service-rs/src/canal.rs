//! Canal de commandes : tube nommé \\.\pipe\deR4Tizer, réservé aux administrateurs et à SYSTEM.
//! L'interface envoie une ligne JSON (Commande) et reçoit une ligne JSON (Reponse).
//! Protection contre l'usurpation du tube : la première instance est créée avec FILE_FLAG_FIRST_PIPE_INSTANCE
//! (échec si quelqu'un l'a déjà créé), et une instance reste toujours ouverte (la suivante est créée avant de
//! traiter la connexion en cours) ; créer une instance supplémentaire exige un droit que seul SYSTEM possède.
//! L'interface vérifie de son côté que le serveur du tube est bien le processus du service.
//! Un client qui se connecte puis se tait ne bloque pas le canal : la lecture d'une commande est bornée dans le
//! temps (DELAI_LECTURE). Si le nom est déjà pris au démarrage (squat), alerte critique locale avec le PID et le
//! chemin du processus qui tient le tube, lus en client anonyme.
//! Phase 1 : avant toute exécution, débit borné (DEBIT_MAX par DEBIT_FENETRE), client identifié sur le jeton de sa
//! connexion (SYSTEM, administrateur, autre), autorisation par commande et validation de chaque champ (validation.rs).
//! Durcissement (relecture indépendante du canal) : clients distants refusés par le tube lui-même
//! (PIPE_REJECT_REMOTE_CLIENTS) ; identité lue sur le jeton de la connexion, après la lecture de la commande, et non
//! plus sur le PID du processus client ; réponse écrite en DELAI_ECRITURE au plus, un client qui ne la lit jamais ne
//! bloque plus le canal (IPC-04).

use crate::commun::{self, Commande, Reponse};
use crate::validation::{self, Client, Debit};
use crate::moniteur::{Moniteur, Partage};
use crate::natif::large;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree, INVALID_HANDLE_VALUE};
use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{FlushFileBuffers, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

/// Délai maximal de lecture d'une commande : l'interface et le script de mise à jour écrivent la leur dès la
/// connexion
const DELAI_LECTURE: Duration = Duration::from_secs(10);

/// Délai maximal d'écriture de la réponse, jusqu'à sa lecture par le client : l'interface et le script de mise à jour
/// la lisent dès qu'elle arrive
const DELAI_ECRITURE: Duration = Duration::from_secs(5);

/// Phase 1 : débit maximal du canal (toutes commandes confondues) ; l'interface n'envoie qu'une commande par action
/// de l'utilisateur, le script de mise à jour une vérification par seconde au plus
const DEBIT_MAX: usize = 30;
const DEBIT_FENETRE: Duration = Duration::from_secs(10);

/// SYSTEM et administrateurs ; en mode console (tests uniquement), tout utilisateur connecté
fn descripteur(console: bool) -> String {
    let mut sddl = "D:(A;;GA;;;SY)(A;;GRGW;;;BA)".to_string();
    if console {
        sddl.push_str("(A;;GRGW;;;AU)");
    }
    sddl
}

/// Décision pure : l'échec de création de la PREMIÈRE instance signale un squat seulement si le nom est déjà pris :
/// ERROR_ACCESS_DENIED (5, FILE_FLAG_FIRST_PIPE_INSTANCE), ou ERROR_PIPE_BUSY (231) quand le processus qui le tient
/// limite le nombre d'instances (constaté, test lot5_canal_squat_pid_et_alerte_critique) ; les autres erreurs vont
/// au journal seulement
pub fn squat(code_win32: u32) -> bool {
    code_win32 == 5 || code_win32 == 231
}

/// Création d'une instance ; en cas d'échec : message et code Win32
fn creer(console: bool, premiere: bool) -> Result<HANDLE, (String, u32)> {
    unsafe {
        let sddl = large(&descripteur(console));
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(sddl.as_ptr()), SDDL_REVISION_1, &mut sd, None)
            .map_err(|e| (e.to_string(), 0))?;
        let attributs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: false.into(),
        };
        let nom = large(commun::NOM_PIPE);
        let mode = if premiere { PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE } else { PIPE_ACCESS_DUPLEX };
        // Clients distants refusés par le tube lui-même (relecture indépendante du canal) ; la DACL ne laissait déjà
        // passer que SYSTEM et les administrateurs
        let tube = CreateNamedPipeW(PCWSTR(nom.as_ptr()), mode, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, Some(&attributs));
        let _ = LocalFree(HLOCAL(sd.0));
        if tube == INVALID_HANDLE_VALUE || tube.is_invalid() {
            let e = windows::core::Error::from_win32();
            let code = (e.code().0 as u32) & 0xFFFF;
            return Err((if premiere { format!("{e} (un autre programme occupe peut-être le canal \\\\.\\pipe\\deR4Tizer)") } else { e.to_string() }, code));
        }
        Ok(tube)
    }
}

pub fn servir(moniteur: Arc<Mutex<Moniteur>>, partage: Arc<Partage>, console: bool) {
    std::thread::Builder::new().name("commandes".into()).spawn(move || {
        let mut derniere_erreur = String::new();
        let mut debit = Debit::new(DEBIT_MAX, DEBIT_FENETRE);
        while !partage.arret.load(Ordering::Relaxed) {
            // Première instance : refusée si le nom est déjà pris
            let mut courant = match creer(console, true) {
                Ok(t) => t,
                Err((e, code)) => {
                    if e != derniere_erreur {
                        commun::journal(&format!("erreur du canal de commandes : {e}"));
                        // Refus d'accès sur la première instance : le nom est pris par un autre processus (squat).
                        // Alerte avec le PID et le chemin s'ils sont lisibles (un tube qui refuse SYSTEM ne les
                        // donne pas)
                        if squat(code) {
                            let pid = pid_serveur_anonyme(commun::NOM_PIPE);
                            let chemin = pid.map(crate::natif::chemin_processus).unwrap_or_default();
                            partage.alertes_externes.lock().unwrap().push(alerte_squat(pid, &chemin));
                        }
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
                    Err((e, _)) => {
                        commun::journal(&format!("erreur du canal de commandes : {e}"));
                        traiter(courant, &moniteur, &partage, &mut debit);
                        unsafe { let _ = CloseHandle(courant); }
                        break;
                    }
                };
                traiter(courant, &moniteur, &partage, &mut debit);
                unsafe { let _ = CloseHandle(courant); }
                courant = suivant;
            }
        }
    }).unwrap();
}

/// Exécute `f` en `delai` au plus pour ses E/S synchrones sur ce fil : à l'échéance, un fil de garde annule l'E/S
/// bloquante en cours (CancelSynchronousIo), et recommence toutes les 100 ms tant que `f` n'a pas rendu la main (une
/// annulation tombée entre deux E/S ne serait pas retenue). Sans garde possible : None, `f` n'est pas exécutée.
pub fn avec_echeance<T>(delai: Duration, f: impl FnOnce() -> T) -> Option<T> {
    use std::sync::mpsc::{channel, RecvTimeoutError};
    use windows::Win32::System::Threading::{GetCurrentThreadId, OpenThread, THREAD_TERMINATE};
    use windows::Win32::System::IO::CancelSynchronousIo;
    let fil = unsafe { OpenThread(THREAD_TERMINATE, false, GetCurrentThreadId()) }.ok()?;
    let brut = fil.0 as usize;
    let (fin, attente) = channel::<()>();
    let garde = std::thread::spawn(move || unsafe {
        let f = HANDLE(brut as _);
        if attente.recv_timeout(delai) == Err(RecvTimeoutError::Timeout) {
            while attente.recv_timeout(Duration::from_millis(100)) == Err(RecvTimeoutError::Timeout) {
                let _ = CancelSynchronousIo(f);
            }
        }
        let _ = CloseHandle(f);
    });
    let r = f();
    let _ = fin.send(());
    let _ = garde.join();
    Some(r)
}

/// Lit une commande (jusqu'à la fin de ligne, 64 Ko au plus) en DELAI au plus (`avec_echeance`). Sans garde
/// possible, rien n'est lu.
pub fn lire_commande(tube: HANDLE, delai: Duration) -> Vec<u8> {
    let debut = Instant::now();
    let lu = avec_echeance(delai, || {
        let mut demande = Vec::new();
        let mut tampon = [0u8; 4096];
        loop {
            let mut lus = 0u32;
            if unsafe { ReadFile(tube, Some(&mut tampon), Some(&mut lus), None) }.is_err() || lus == 0 {
                break;
            }
            demande.extend_from_slice(&tampon[..lus as usize]);
            if demande.contains(&b'\n') || demande.len() > 65536 || debut.elapsed() >= delai {
                break;
            }
        }
        demande
    });
    let Some(mut demande) = lu else {
        commun::journal("canal de commandes : garde de lecture impossible, commande ignorée");
        return Vec::new();
    };
    // Échéance atteinte sans fin de ligne : commande incomplète, ignorée
    if !demande.contains(&b'\n') && debut.elapsed() >= delai {
        demande.clear();
    }
    demande
}

/// Écrit la réponse puis attend que le client l'ait lue (FlushFileBuffers : sans cette attente, DisconnectNamedPipe
/// jetterait une réponse non lue), le tout en `delai` au plus (`avec_echeance`) : un client qui ne lit jamais la
/// réponse ne bloque plus le canal (relecture indépendante du canal, IPC-04). Vrai si la réponse a été lue ; sans
/// garde possible, rien n'est écrit.
pub fn ecrire_reponse(tube: HANDLE, sortie: &[u8], delai: Duration) -> bool {
    avec_echeance(delai, || unsafe {
        let mut ecrits = 0u32;
        WriteFile(tube, Some(sortie), Some(&mut ecrits), None).is_ok() && ecrits as usize == sortie.len() && FlushFileBuffers(tube).is_ok()
    })
    .unwrap_or(false)
}

/// PID du processus qui tient un tube nommé, lu en client ANONYME (SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS) :
/// le service ne se présente jamais avec l'identité de SYSTEM à un serveur qui pourrait l'emprunter ; rien n'est
/// écrit dans le tube
pub fn pid_serveur_anonyme(chemin: &str) -> Option<u32> {
    use windows::Win32::Foundation::GENERIC_READ;
    use windows::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_NONE, OPEN_EXISTING, SECURITY_ANONYMOUS, SECURITY_SQOS_PRESENT};
    use windows::Win32::System::Pipes::GetNamedPipeServerProcessId;
    let nom = large(chemin);
    unsafe {
        let h = CreateFileW(PCWSTR(nom.as_ptr()), GENERIC_READ.0, FILE_SHARE_NONE, None, OPEN_EXISTING,
            SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS, None).ok()?;
        let mut pid = 0u32;
        let ok = GetNamedPipeServerProcessId(h, &mut pid).is_ok();
        let _ = CloseHandle(h);
        (ok && pid != 0).then_some(pid)
    }
}

/// Alerte critique locale : le canal de commandes est tenu par un autre processus
pub fn alerte_squat(pid: Option<u32>, chemin: &str) -> commun::Alerte {
    let qui = match (pid, chemin.is_empty()) {
        (Some(p), false) => format!("le processus {p} ({chemin})"),
        (Some(p), true) => format!("le processus {p} (chemin illisible)"),
        (None, _) => "un processus inconnu".to_string(),
    };
    commun::Alerte {
        regle: crate::regles::INT_002.into(),
        id: commun::nouvel_id(),
        heure: commun::maintenant(),
        niveau: "Critique".into(),
        score: 10,
        processus: if chemin.is_empty() { "inconnu".into() } else { chemin.to_string() },
        chemin: chemin.to_string(),
        destination: "canal de commandes de deR4Tizer".into(),
        raisons: format!("CANAL DE COMMANDES OCCUPÉ : {qui} tient le tube {} à la place du service. L'interface ne peut \
            plus commander le service, et ce programme peut se faire passer pour lui. Que faire : arrêter ce programme, \
            l'analyser, puis redémarrer le service deR4Tizer.", commun::NOM_PIPE),
        pid,
        ..Default::default()
    }
}

/// Phase 1 : décision pure, avant toute exécution : débit, lecture, autorisation de ce client pour cette action,
/// validation de chaque champ. Ok : commande normalisée à exécuter ; Err : réponse de refus (rien d'exécuté).
pub fn admettre(demande: &[u8], client: Client, debit_ok: bool) -> Result<Commande, Reponse> {
    if !debit_ok {
        return Err(Reponse::erreur("Trop de commandes en peu de temps : réessayez dans quelques secondes."));
    }
    let mut c = validation::decoder_commande(demande).map_err(Reponse::erreur)?;
    validation::normaliser(&mut c);
    let action = c.action.clone().unwrap_or_default();
    if !validation::autorisee(&action, client) {
        commun::journal(&format!("commande refusée : {} non autorisée pour ce client ({client:?})",
            action.chars().filter(|x| !x.is_control()).take(64).collect::<String>()));
        return Err(Reponse::erreur("Commande refusée : non autorisée pour ce client."));
    }
    validation::valider(&c).map_err(|e| {
        commun::journal(&format!("commande refusée : {action} : {e}"));
        Reponse::erreur(format!("Commande refusée : {e}."))
    })?;
    Ok(c)
}

fn traiter(tube: HANDLE, moniteur: &Arc<Mutex<Moniteur>>, partage: &Arc<Partage>, debit: &mut Debit) {
    unsafe {
        // Commande lue d'abord, puis identité lue sur le jeton de la connexion (ImpersonateNamedPipeClient après une
        // lecture, comme le demande sa documentation) : liée à la connexion qui a porté la commande, et non plus à un
        // PID qu'un autre processus pourrait reprendre
        let demande = lire_commande(tube, DELAI_LECTURE);
        let (client, sid) = crate::natif::identite_client_tube(tube);
        let reponse = match admettre(&demande, client, debit.accepter(Instant::now())) {
            Ok(mut c) => {
                // Auteur des transitions d'incident : SID lu sur le jeton du client, jamais pris dans la commande
                c.auteur = sid;
                // PowerShell et résolutions DNS du mode panique hors du verrou (PR 6.5)
                let prealable = crate::moniteur::preparer(&c);
                moniteur.lock().unwrap().executer(c, partage, prealable)
            }
            Err(r) => r,
        };
        let mut sortie = serde_json::to_vec(&reponse).unwrap_or_default();
        sortie.extend_from_slice(b"\r\n");
        if !ecrire_reponse(tube, &sortie, DELAI_ECRITURE) {
            commun::journal("canal de commandes : réponse non lue par le client (parti ou muet), connexion fermée");
        }
        let _ = DisconnectNamedPipe(tube);
    }
}
