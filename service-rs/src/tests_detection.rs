//! Tests des règles de détection, un positif et un négatif par règle (phase 3, PR 3.5 à 3.12 ; noms
//! `<id>_positif` et `<id>_negatif`, docs/detection/regles.md). Un positif prouve que la règle se déclenche sur
//! l'entrée qui la décrit ; un négatif, qu'une entrée voisine et légitime ne la déclenche pas.

// ------------------------------------------------------------ DEF : Microsoft Defender (PR 3.5)
// Journal Microsoft-Windows-Windows Defender/Operational (defender::traduire) et écarts entre deux relevés de l'état
// WMI (defender::ecarts). Aucune de ces règles n'est exercée en VM : Defender y reste intouché (lot 3d).

fn evenement_defender(id: u32, donnees: &[(&str, &str)]) -> String {
    let d: String = donnees.iter().map(|(n, v)| format!("<Data Name='{n}'>{v}</Data>")).collect();
    format!("<Event><System><EventID>{id}</EventID></System><EventData>{d}</EventData></Event>")
}

fn regle_defender(id: u32, donnees: &[(&str, &str)]) -> Option<(String, String)> {
    crate::defender::traduire(&evenement_defender(id, donnees)).map(|a| (a.regle, a.niveau))
}

fn regle_et_niveau(r: &str, n: &str) -> Option<(String, String)> {
    Some((r.to_string(), n.to_string()))
}

#[test]
fn def_001_positif() {
    assert_eq!(regle_defender(1116, &[("Threat Name", "Trojan:Win32/Test"), ("Path", "file:_C:\\x\\a.exe")]), regle_et_niveau("DEF-001", "Critique"));
}

#[test]
fn def_001_negatif() {
    // Une mise à jour des signatures (2000) n'est pas une détection
    assert_eq!(regle_defender(2000, &[("Threat Name", "Trojan:Win32/Test")]), None);
}

#[test]
fn def_002_positif() {
    assert_eq!(regle_defender(1117, &[("Threat Name", "Trojan:Win32/Test"), ("Action Name", "Quarantaine")]), regle_et_niveau("DEF-002", "Info"));
}

#[test]
fn def_002_negatif() {
    // 1118 (échec d'une action) n'est pas suivie : jamais « menace traitée »
    assert_eq!(regle_defender(1118, &[("Threat Name", "Trojan:Win32/Test")]), None);
}

#[test]
fn def_003_positif() {
    assert_eq!(regle_defender(5001, &[]), regle_et_niveau("DEF-003", "Critique"));
}

#[test]
fn def_003_negatif() {
    // 5000 : protection en temps réel ACTIVÉE
    assert_eq!(regle_defender(5000, &[]), None);
}

#[test]
fn def_004_positif() {
    assert_eq!(regle_defender(5010, &[]), regle_et_niveau("DEF-004", "Critique"));
    assert_eq!(regle_defender(5012, &[]), regle_et_niveau("DEF-004", "Critique"));
}

#[test]
fn def_004_negatif() {
    // 5009, 5011 : analyses réactivées
    assert_eq!(regle_defender(5009, &[]), None);
    assert_eq!(regle_defender(5011, &[]), None);
}

#[test]
fn def_005_positif() {
    let v = r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\outil = 0x0";
    assert_eq!(regle_defender(5007, &[("New Value", v)]), regle_et_niveau("DEF-005", "Critique"));
}

#[test]
fn def_005_negatif() {
    // Exclusion RETIRÉE : nouvelle valeur vide, l'ancienne porte le chemin
    let ancienne = r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\outil = 0x0";
    assert_eq!(regle_defender(5007, &[("Old Value", ancienne), ("New Value", "")]), None);
    // Autre réglage modifié (mise à jour des signatures)
    assert_eq!(regle_defender(5007, &[("New Value", r"HKLM\SOFTWARE\Microsoft\Windows Defender\Signature Updates\SignatureUpdateInterval = 0x4")]), None);
}

#[test]
fn def_006_positif() {
    for v in [r"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring = 0x1",
              r"HKLM\SOFTWARE\Microsoft\Windows Defender\DisableAntiSpyware = 0x1",
              r"HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection = 0x4"] {
        assert_eq!(regle_defender(5007, &[("New Value", v)]), regle_et_niveau("DEF-006", "Critique"), "{v}");
    }
}

#[test]
fn def_006_negatif() {
    // Protection RÉTABLIE (valeurs inverses)
    for v in [r"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring = 0x0",
              r"HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection = 0x5"] {
        assert_eq!(regle_defender(5007, &[("New Value", v)]), None, "{v}");
    }
}

#[test]
fn def_007_positif() {
    assert_eq!(regle_defender(1121, &[("ID", "D4F940AB-401B-4EFC-AADC-AD5F3C50688A"), ("Path", r"C:\x\a.exe")]), regle_et_niveau("DEF-007", "Alerte"));
    assert_eq!(regle_defender(1122, &[("ID", "D4F940AB-401B-4EFC-AADC-AD5F3C50688A"), ("Path", r"C:\x\a.exe")]), regle_et_niveau("DEF-007", "Info"));
}

#[test]
fn def_007_negatif() {
    // 1120 : hors de la plage suivie ; l'audit (1122) n'est jamais une alerte, seul le blocage (1121) l'est
    assert_eq!(regle_defender(1120, &[("ID", "D4F940AB-401B-4EFC-AADC-AD5F3C50688A")]), None);
    assert_ne!(regle_defender(1122, &[("ID", "D4F940AB-401B-4EFC-AADC-AD5F3C50688A")]).map(|(_, n)| n), Some("Alerte".into()));
}

#[test]
fn def_008_positif() {
    assert_eq!(regle_defender(1123, &[("Path", r"C:\Users\u\Documents\a.docx")]), regle_et_niveau("DEF-008", "Alerte"));
    assert_eq!(regle_defender(1124, &[("Path", r"C:\Users\u\Documents\a.docx")]), regle_et_niveau("DEF-008", "Info"));
}

#[test]
fn def_008_negatif() {
    // L'audit (1124) n'est jamais une alerte : seul le blocage (1123) l'est
    assert_ne!(regle_defender(1124, &[("Path", r"C:\Users\u\Documents\a.docx")]).map(|(_, n)| n), Some("Alerte".into()));
}

#[test]
fn def_009_positif() {
    assert_eq!(regle_defender(1125, &[("Path", "exemple.invalid")]), regle_et_niveau("DEF-009", "Alerte"));
    assert_eq!(regle_defender(1126, &[("Path", "exemple.invalid")]), regle_et_niveau("DEF-009", "Info"));
}

#[test]
fn def_009_negatif() {
    // 1127 : hors de la plage suivie
    assert_eq!(regle_defender(1127, &[("Path", "exemple.invalid")]), None);
}

fn etat_defender(temps_reel: bool, falsification: bool, antivirus: bool) -> crate::defender::EtatDefender {
    crate::defender::EtatDefender { disponible: true, temps_reel, protection_falsification: falsification, antivirus, ..Default::default() }
}

fn regles_ecarts(avant: &crate::defender::EtatDefender, apres: &crate::defender::EtatDefender) -> Vec<String> {
    crate::defender::ecarts(avant, apres).into_iter().map(|a| a.regle).collect()
}

#[test]
fn def_010_positif() {
    assert_eq!(regles_ecarts(&etat_defender(true, true, true), &etat_defender(false, true, true)), ["DEF-010"]);
}

#[test]
fn def_010_negatif() {
    // Protection rétablie, ou déjà coupée au relevé précédent (une seule alerte, au moment de la coupure)
    assert!(regles_ecarts(&etat_defender(false, true, true), &etat_defender(true, true, true)).is_empty());
    assert!(regles_ecarts(&etat_defender(false, true, true), &etat_defender(false, true, true)).is_empty());
}

#[test]
fn def_011_positif() {
    assert_eq!(regles_ecarts(&etat_defender(true, true, true), &etat_defender(true, false, true)), ["DEF-011"]);
}

#[test]
fn def_011_negatif() {
    assert!(regles_ecarts(&etat_defender(true, false, true), &etat_defender(true, true, true)).is_empty());
}

#[test]
fn def_012_positif() {
    assert_eq!(regles_ecarts(&etat_defender(true, true, true), &etat_defender(true, true, false)), ["DEF-012"]);
}

#[test]
fn def_012_negatif() {
    // État illisible à l'un des deux relevés (WMI) : aucune conclusion, aucune alerte (la collecte EtatDefender le dit)
    let mut illisible = etat_defender(false, false, false);
    illisible.disponible = false;
    assert!(regles_ecarts(&etat_defender(true, true, true), &illisible).is_empty());
    assert!(regles_ecarts(&illisible, &etat_defender(true, true, true)).is_empty());
}

/// Dossier phase 3, § 7.1 : `defender::traduire` lit le journal de Defender (données écrites par Defender, mais aussi les
/// chemins et noms de menace qu'il recopie) : aucune panique sur un XML altéré
#[test]
fn def_traduire_sans_panique() {
    for id in [1116u32, 1117, 5007, 1121, 1123, 1125] {
        let valide = evenement_defender(id, &[("Threat Name", "Trojan:Win32/Test"), ("Path", "file:_C:\\x\\a.exe"), ("Process Name", "C:\\x\\p.exe"),
            ("New Value", r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\x = 0x0"), ("ID", "D4F940AB-401B-4EFC-AADC-AD5F3C50688A")]);
        crate::tests::torturer_texte(&valide, &mut |x| {
            let _ = crate::defender::traduire(x);
        });
    }
}
