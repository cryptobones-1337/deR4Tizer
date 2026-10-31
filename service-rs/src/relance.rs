//! Relance de l'interface par une tâche planifiée (phase 4, PR 4.5b ; décision D4-1, option C, accord du mainteneur le
//! 2026-10-27). Le service en fonctionnement ne lance rien : la tâche est posée par le MSI (action différée, SYSTEM), et
//! Windows la lance sous l'identité de chaque utilisateur connecté, sans élévation. L'interface sort aussitôt si elle tourne
//! déjà dans la session (mutex). Un compte standard ne peut pas modifier une tâche posée par SYSTEM.

use crate::commun;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::Command;

pub const NOM_TACHE: &str = "deR4Tizer Relance interface";
/// Groupe local « Utilisateurs » (SID, indépendant de la langue de Windows)
const GROUPE_UTILISATEURS: &str = "S-1-5-32-545";

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
    <AllowStartOnDemand>true</AllowStartOnDemand>
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
        interface = echappe_xml(interface),
    )
}

fn schtasks(arguments: &[&str]) -> Result<(), String> {
    let exe = format!(r"{}\schtasks.exe", crate::natif::dossier_systeme());
    let sortie = Command::new(exe).args(arguments).creation_flags(0x0800_0000).output().map_err(|e| e.to_string())?;
    if sortie.status.success() { Ok(()) } else { Err(String::from_utf8_lossy(&sortie.stderr).trim().chars().take(300).collect()) }
}

/// Pose (ou remplace) la tâche : action du MSI, en SYSTEM. Le fichier de définition passe par le dossier d'installation
/// (administrateurs seulement), puis il est effacé
pub fn poser() -> Result<(), String> {
    let service = std::env::current_exe().map_err(|e| e.to_string())?;
    let dossier = service.parent().ok_or("dossier du service introuvable")?;
    let interface = dossier.join("deR4Tizer.exe");
    let fichier = dossier.join("relance-tache.xml");
    let octets: Vec<u8> = "\u{feff}".encode_utf16().chain(definition_tache(&interface.to_string_lossy()).encode_utf16()).flat_map(u16::to_le_bytes).collect();
    std::fs::write(&fichier, octets).map_err(|e| format!("{} : {e}", fichier.display()))?;
    let resultat = schtasks(&["/Create", "/F", "/TN", NOM_TACHE, "/XML", &fichier.to_string_lossy()]);
    let _ = std::fs::remove_file(Path::new(&fichier));
    resultat
}

/// Retire la tâche (désinstallation, ou LANCEMENT_SESSION=0) ; absente : rien à faire
pub fn retirer() -> Result<(), String> {
    let exe = format!(r"{}\schtasks.exe", crate::natif::dossier_systeme());
    let existe = Command::new(exe).args(["/Query", "/TN", NOM_TACHE]).creation_flags(0x0800_0000).output().map(|s| s.status.success()).unwrap_or(false);
    if !existe {
        return Ok(());
    }
    schtasks(&["/Delete", "/F", "/TN", NOM_TACHE])
}

/// Option de la ligne de commande : écrit le résultat au journal et sur la sortie (le MSI ignore le code de retour)
pub fn compte_rendu(quoi: &str, resultat: Result<(), String>) {
    let message = match resultat {
        Ok(()) => format!("tâche de relance de l'interface : {quoi}"),
        Err(e) => format!("tâche de relance de l'interface : {quoi} impossible : {e}"),
    };
    println!("{message}");
    commun::journal(&message);
}
