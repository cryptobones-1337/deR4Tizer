//! Relance de l'interface par une tâche planifiée (phase 4, PR 4.5b ; décision D4-1, option C, accord du mainteneur le
//! 2026-10-27). Le service en fonctionnement ne lance rien : la tâche est posée par le MSI (action différée, SYSTEM), et
//! Windows la lance sous l'identité de chaque utilisateur connecté, sans élévation. L'interface sort aussitôt si elle tourne
//! déjà dans la session (mutex). Un compte standard ne peut pas modifier une tâche posée par SYSTEM.

use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

pub const NOM_TACHE: &str = "deR4Tizer Relance interface";
/// Groupe local « Utilisateurs » (SID, indépendant de la langue de Windows)
const GROUPE_UTILISATEURS: &str = "S-1-5-32-545";
/// Droits de la tâche, posés explicitement : SYSTEM et administrateurs ; lecture et exécution seules pour les autres.
/// Audit de #101, S101-01 : le nom est public, un compte standard a pu créer la tâche avant nous
const DROITS_TACHE: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;AU)";
/// `schtasks` peut poser une question : pas d'entrée, et 60 s au plus. L'action du MSI est synchrone, le service attend
/// (audit de #101, S101-08)
const DUREE_MAX_SCHTASKS: Duration = Duration::from_secs(60);

fn echappe_xml(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;")
}

/// Définition de la tâche (pure, testée) : à l'ouverture de session et toutes les 5 min, chez chaque membre d'Utilisateurs,
/// sans élévation, sans limite de durée (l'interface reste ouverte), plusieurs instances permises (une par session : celle
/// de trop sort aussitôt)
pub fn definition_tache(interface: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>deR4Tizer</Author>
    <Description>Relance l'interface de deR4Tizer si elle ne tourne plus dans la session.</Description>
    <URI>\{nom}</URI>
    <SecurityDescriptor>{droits}</SecurityDescriptor>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
    <TimeTrigger>
      <Repetition><Interval>PT5M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>
      <StartBoundary>2026-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Utilisateurs"><GroupId>{groupe}</GroupId><RunLevel>LeastPrivilege</RunLevel></Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>false</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Utilisateurs">
    <Exec><Command>{interface}</Command><Arguments>--cache --relance</Arguments></Exec>
  </Actions>
</Task>
"#,
        nom = echappe_xml(NOM_TACHE),
        groupe = GROUPE_UTILISATEURS,
        droits = DROITS_TACHE,
        interface = echappe_xml(interface),
    )
}

fn lancer_schtasks(arguments: &[&str]) -> Result<Output, String> {
    let exe = format!(r"{}\schtasks.exe", crate::natif::dossier_systeme());
    let mut enfant = Command::new(exe).args(arguments).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .creation_flags(0x0800_0000).spawn().map_err(|e| e.to_string())?;
    let fin = Instant::now() + DUREE_MAX_SCHTASKS;
    while enfant.try_wait().map_err(|e| e.to_string())?.is_none() {
        if Instant::now() >= fin {
            let _ = enfant.kill();
            let _ = enfant.wait();
            return Err(format!("schtasks sans réponse après {} s", DUREE_MAX_SCHTASKS.as_secs()));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    enfant.wait_with_output().map_err(|e| e.to_string())
}

fn schtasks(arguments: &[&str]) -> Result<(), String> {
    let sortie = lancer_schtasks(arguments)?;
    if sortie.status.success() { Ok(()) } else { Err(String::from_utf8_lossy(&sortie.stderr).trim().chars().take(300).collect()) }
}

/// Tâche relue conforme à ce qui a été posé (pur, testé) : commande, arguments, groupe et niveau. `relue` est la sortie de
/// `schtasks /Query /XML`, dans laquelle le chemin est échappé de la même façon
pub fn definition_conforme(relue: &str, interface: &str) -> bool {
    let r = relue.to_lowercase();
    r.contains(&format!("<command>{}</command>", echappe_xml(interface).to_lowercase()))
        && r.contains("<arguments>--cache --relance</arguments>")
        && r.contains(&format!("<groupid>{}</groupid>", GROUPE_UTILISATEURS.to_lowercase()))
        && r.contains("<runlevel>leastprivilege</runlevel>")
        && !r.contains("<userid>")
}

/// Pose la tâche : action du MSI, en SYSTEM. Toute tâche de ce nom est d'abord supprimée (S101-01 : `/F` pourrait garder les
/// droits d'une tâche créée par un compte standard), puis la création se fait sans `/F` : si quelqu'un l'a recréée
/// entre-temps, elle échoue, et SAN-010 finira par le signaler. Relecture ensuite : commande et droits ; écart, tâche retirée.
/// Le fichier de définition passe par le dossier d'installation (administrateurs seulement), puis il est effacé
pub fn poser() -> Result<(), String> {
    retirer()?;
    let service = std::env::current_exe().map_err(|e| e.to_string())?;
    let dossier = service.parent().ok_or("dossier du service introuvable")?;
    let interface = dossier.join("deR4Tizer.exe");
    let fichier = dossier.join("relance-tache.xml");
    let octets: Vec<u8> = "\u{feff}".encode_utf16().chain(definition_tache(&interface.to_string_lossy()).encode_utf16()).flat_map(u16::to_le_bytes).collect();
    std::fs::write(&fichier, octets).map_err(|e| format!("{} : {e}", fichier.display()))?;
    let resultat = schtasks(&["/Create", "/TN", NOM_TACHE, "/XML", &fichier.to_string_lossy()]);
    let _ = std::fs::remove_file(Path::new(&fichier));
    resultat?;
    if let Err(e) = verifier(&interface.to_string_lossy()) {
        let _ = retirer();
        return Err(format!("tâche retirée : {e}"));
    }
    Ok(())
}

/// Décision pure (testée) d'après la lecture de la valeur Run : absente, le choix de `LANCEMENT_SESSION=0` ; toute autre
/// erreur n'est pas un refus de lancement (relecture de #101, D7 : échec fermé)
pub fn decision_lancement(lecture: std::io::Result<String>) -> Result<bool, String> {
    match lecture {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("lancement à l'ouverture de session illisible : {e}")),
    }
}

/// Lancement de l'interface posé à l'installation : valeur Run de la machine (la tâche n'existe qu'avec elle). Sans elle, une
/// session sans interface n'a rien d'anormal
pub fn lancement_pose() -> Result<bool, String> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY};
    decision_lancement(winreg::RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", KEY_READ | KEY_WOW64_64KEY)
        .and_then(|k| k.get_value::<String, _>("deR4Tizer")))
}

/// Au démarrage du service, après la protection du dossier : un échec de pose n'a pas d'autre trace (S101-11)
pub fn signaler_etat() {
    if lancement_pose() != Ok(true) {
        return;
    }
    let interface = crate::sante::chemin_interface().unwrap_or_default();
    match verifier(&interface) {
        Ok(()) => {}
        Err(e) => crate::commun::journal(&format!("tâche de relance de l'interface absente ou non conforme : {e} ; l'interface ne sera pas relancée")),
    }
}

fn verifier(interface: &str) -> Result<(), String> {
    let sortie = lancer_schtasks(&["/Query", "/TN", NOM_TACHE, "/XML"])?;
    if !definition_conforme(&String::from_utf8_lossy(&sortie.stdout), interface) {
        return Err("définition relue différente".into());
    }
    let fichier = Path::new(&crate::natif::dossier_systeme()).join("Tasks").join(NOM_TACHE);
    let s = crate::natif::lire_securite(&fichier).ok_or("droits de la tâche illisibles")?;
    crate::protection::sans_ecriture_de_tiers(&s, &[crate::protection::SID_SYSTEME, crate::protection::SID_ADMINISTRATEURS])
}

fn existe() -> bool {
    lancer_schtasks(&["/Query", "/TN", NOM_TACHE]).map(|s| s.status.success()).unwrap_or(false)
}

/// Retire la tâche (désinstallation, ou LANCEMENT_SESSION=0) ; erreur si elle existe encore ensuite
pub fn retirer() -> Result<(), String> {
    if !existe() {
        return Ok(());
    }
    let resultat = schtasks(&["/Delete", "/F", "/TN", NOM_TACHE]);
    if existe() { Err(resultat.err().unwrap_or_else(|| "tâche toujours présente".into())) } else { Ok(()) }
}

/// Option de la ligne de commande : le résultat sur la sortie seulement. Action du MSI, avant la protection du dossier de
/// données : rien n'y est écrit (relecture et audit de #101, S101-02), et le MSI ignore le code de retour
pub fn compte_rendu(quoi: &str, resultat: Result<(), String>) {
    match resultat {
        Ok(()) => println!("tâche de relance de l'interface : {quoi}"),
        Err(e) => println!("tâche de relance de l'interface : {quoi} impossible : {e}"),
    }
}
