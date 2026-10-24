//! Surveillance de Microsoft Defender : un malware commence souvent par le désactiver ou par s'y
//! ajouter une exclusion. On suit le journal de Defender (détections, blocages ASR, accès contrôlé
//! aux dossiers, protection réseau, changements de configuration) et son état (WMI).

use crate::commun::{self, Alerte};
use crate::evenements;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use wmi::{COMLibrary, Variant, WMIConnection};

const JOURNAL: &str = "Microsoft-Windows-Windows Defender/Operational";

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct EtatDefender {
    pub disponible: bool,
    pub antivirus: bool,
    pub temps_reel: bool,
    pub protection_falsification: bool,
    pub mode: String,
    pub signatures: String,
    pub derniere_analyse: String,
}

/// Noms des règles ASR, pour des alertes lisibles
fn nom_asr(id: &str) -> &'static str {
    match id.to_uppercase().as_str() {
        "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" => "exécutable reçu par courriel",
        "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" => "Office qui lance un programme",
        "3B576869-A4EC-4529-8536-B80A7769E899" => "Office qui crée un exécutable",
        "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" => "Office qui injecte du code",
        "D3E037E1-3EB8-44C8-A917-57927947596D" => "script qui lance un téléchargement",
        "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" => "script obscurci",
        "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" => "appel Win32 depuis une macro",
        "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" => "vol d'identifiants dans LSASS",
        "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" => "persistance WMI",
        "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" => "programme non signé sur clé USB",
        "C1DB55AB-C21A-4637-BB3F-A12568109D35" => "comportement de rançongiciel",
        "56A863A9-875E-4185-98A7-B882C64B5CE5" => "pilote vulnérable",
        "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C" => "Adobe Reader qui lance un programme",
        "01443614-CD74-433A-B99E-2ECDC07BFC25" => "exécutable rare ou récent",
        "D1E49AAC-8F56-4280-B9BA-993A6D77406C" => "processus créé par PsExec ou WMI",
        _ => "règle ASR",
    }
}

fn alerte(niveau: &str, score: i32, processus: &str, chemin: &str, destination: &str, raisons: String) -> Alerte {
    Alerte {
        id: commun::nouvel_id(),
        heure: commun::maintenant(),
        niveau: niveau.into(),
        score,
        processus: processus.into(),
        chemin: chemin.into(),
        destination: destination.into(),
        raisons,
        ..Default::default()
    }
}

fn fichier(chemin: &str) -> String {
    chemin.rsplit(['\\', '/']).next().unwrap_or(chemin).trim_end_matches(".exe").to_string()
}

/// Traduit un événement du journal de Defender en alerte (ou rien si l'événement n'est pas intéressant)
pub fn traduire(xml: &str) -> Option<Alerte> {
    let id: u32 = regex::Regex::new(r"<EventID[^>]*>(\d+)</EventID>").ok()?.captures(xml)?[1].parse().ok()?;
    let d = evenements::donnees(xml);
    let v = |c: &str| d.get(c).cloned().unwrap_or_default();
    let chemin = v("Path").trim_start_matches("file:_").to_string();
    let processus = v("Process Name");
    Some(match id {
        1116 => alerte("Critique", 10, &fichier(&processus), &processus, &v("Threat Name"),
            format!("Defender a DÉTECTÉ {} ({}) dans {}", v("Threat Name"), v("Category Name"), chemin)),
        1117 => alerte("Info", 0, &fichier(&processus), &processus, &v("Threat Name"),
            format!("Defender a traité {} : {}", v("Threat Name"), v("Action Name"))),
        5001 => alerte("Critique", 10, "Defender", "", "protection en temps réel", "la protection en temps réel de Defender a été DÉSACTIVÉE".into()),
        5010 | 5012 => alerte("Critique", 10, "Defender", "", "analyse", "l'analyse antivirus de Defender a été DÉSACTIVÉE".into()),
        5007 => {
            let nouvelle = v("New Value");
            let bas = nouvelle.to_lowercase();
            if bas.contains("\\exclusions\\") {
                alerte("Critique", 10, "Defender", "", "exclusion",
                    format!("EXCLUSION ajoutée à Defender (technique classique des malwares) : {nouvelle}"))
            } else if bas.contains("disablerealtimemonitoring = 0x1") || bas.contains("disableantispyware = 0x1") || bas.contains("tamperprotection = 0x4") {
                alerte("Critique", 10, "Defender", "", "configuration", format!("protection de Defender AFFAIBLIE : {nouvelle}"))
            } else {
                return None;
            }
        }
        1121 => alerte("Alerte", 5, &fichier(&processus), &processus, &fichier(&chemin),
            format!("Defender ASR a BLOQUÉ : {} ({})", nom_asr(&v("ID")), chemin)),
        1122 => alerte("Info", 0, &fichier(&processus), &processus, &fichier(&chemin),
            format!("Defender ASR (audit) aurait bloqué : {} ({})", nom_asr(&v("ID")), chemin)),
        1123 => alerte("Alerte", 5, &fichier(&processus), &processus, &fichier(&chemin),
            format!("accès contrôlé aux dossiers a BLOQUÉ une modification de {chemin}")),
        1124 => alerte("Info", 0, &fichier(&processus), &processus, &fichier(&chemin),
            format!("accès contrôlé aux dossiers (audit) : modification de {chemin}")),
        1125 | 1126 => alerte(if id == 1125 { "Alerte" } else { "Info" }, if id == 1125 { 5 } else { 0 }, &fichier(&processus), &processus,
            &v("Path"), format!("protection réseau de Defender {} : {}", if id == 1125 { "a BLOQUÉ" } else { "(audit)" }, v("Path"))),
        _ => return None,
    })
}

/// S'abonne au journal de Defender ; chaque alerte est déposée dans la file
pub fn surveiller(file: Arc<Mutex<Vec<Alerte>>>) -> bool {
    evenements::abonner(JOURNAL, "*[System[(EventID=1116 or EventID=1117 or EventID=5001 or EventID=5007 or EventID=5010 or EventID=5012 or (EventID>=1121 and EventID<=1126))]]",
        move |xml| {
            if let Some(a) = traduire(&xml) {
                file.lock().unwrap().push(a);
            }
        })
}

fn date_wmi(v: Option<&Variant>) -> String {
    // Format CIM : aaaammjjhhmmss.ffffff+zzz
    match v {
        Some(Variant::String(s)) => match (s.get(0..4), s.get(4..6), s.get(6..8), s.get(8..10), s.get(10..12)) {
            (Some(a), Some(m), Some(j), Some(h), Some(mi)) => format!("{a}-{m}-{j} {h}:{mi}"),
            _ => String::new(),
        },
        _ => String::new(),
    }
}

/// État de Defender (WMI, espace root\Microsoft\Windows\Defender)
pub fn etat() -> EtatDefender {
    let lire = || -> Option<EtatDefender> {
        let com = COMLibrary::without_security().ok()?;
        let con = WMIConnection::with_namespace_path(r"root\Microsoft\Windows\Defender", com).ok()?;
        let r: Vec<HashMap<String, Variant>> = con.raw_query("SELECT * FROM MSFT_MpComputerStatus").ok()?;
        let o = r.first()?;
        let b = |c: &str| matches!(o.get(c), Some(Variant::Bool(true)));
        Some(EtatDefender {
            disponible: true,
            antivirus: b("AntivirusEnabled"),
            temps_reel: b("RealTimeProtectionEnabled"),
            protection_falsification: b("IsTamperProtected"),
            mode: match o.get("AMRunningMode") {
                Some(Variant::String(s)) => s.clone(),
                _ => String::new(),
            },
            signatures: date_wmi(o.get("AntivirusSignatureLastUpdated")),
            derniere_analyse: date_wmi(o.get("QuickScanEndTime")),
        })
    };
    lire().unwrap_or_default()
}

/// Décision pure : faut-il relire l'état avant de le publier ? Oui tant qu'aucun état n'a encore été publié
/// (`deja_publie` faux) et que Defender ne répond pas ou se dit « Not running » : au démarrage du PC, il répond ainsi
/// quelques minutes, et l'interface affichait « DEFENDER DÉSACTIVÉ » jusqu'au relevé suivant (10 min). Une fois un
/// état publié, plus d'attente : une vraie désactivation est vue à chaque relevé.
pub fn relire_avant_publication(etat: &EtatDefender, deja_publie: bool) -> bool {
    !deja_publie && (!etat.disponible || etat.mode.eq_ignore_ascii_case("Not running"))
}

/// Alertes sur un changement d'état entre deux relevés
pub fn ecarts(avant: &EtatDefender, apres: &EtatDefender) -> Vec<Alerte> {
    let mut a = Vec::new();
    if !avant.disponible || !apres.disponible {
        return a;
    }
    if avant.temps_reel && !apres.temps_reel {
        a.push(alerte("Critique", 10, "Defender", "", "protection en temps réel", "la protection en temps réel de Defender est COUPÉE".into()));
    }
    if avant.protection_falsification && !apres.protection_falsification {
        a.push(alerte("Critique", 10, "Defender", "", "protection contre les falsifications", "la protection contre les falsifications de Defender est DÉSACTIVÉE".into()));
    }
    if avant.antivirus && !apres.antivirus {
        a.push(alerte("Critique", 10, "Defender", "", "antivirus", "l'antivirus Defender est DÉSACTIVÉ".into()));
    }
    a
}
