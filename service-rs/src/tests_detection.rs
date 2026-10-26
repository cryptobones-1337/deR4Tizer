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

// ------------------------------------------------------------ PER : démarrages automatiques (PR 3.6)
// Relevé des démarrages automatiques comparé à la référence (persistance::comparer, décision pure) ; le relevé lui-même
// (registre, services, tâches) n'est pas exécuté ici. En VM : l'alerte de la clé Run de test (lot 3a).

fn entree_demarrage(cle: &str, commande: &str, signataire: &str, remarque: &str) -> crate::commun::EntreeDemarrage {
    crate::commun::EntreeDemarrage {
        cle: cle.into(), categorie: "Run (HKLM)".into(), nom: "Outil".into(), commande: commande.into(), cible: r"C:\Program Files\Outil\outil.exe".into(),
        signataire: signataire.into(), remarque: remarque.into(), ..Default::default()
    }
}

fn reference_demarrage(entrees: &[crate::commun::EntreeDemarrage]) -> std::collections::HashMap<String, crate::commun::EntreeDemarrage> {
    entrees.iter().map(|e| (e.cle.clone(), e.clone())).collect()
}

fn regles_comparer(reference: &[crate::commun::EntreeDemarrage], releve: &[crate::commun::EntreeDemarrage], apprentissage: bool) -> (Vec<(String, String)>, bool) {
    let mut r = releve.to_vec();
    let (a, modifie) = crate::persistance::comparer(&reference_demarrage(reference), &mut r, apprentissage);
    (a.into_iter().map(|a| (a.regle, a.niveau)).collect(), modifie)
}

#[test]
fn per_001_positif() {
    let connue = entree_demarrage("k1", r#""C:\Program Files\Outil\outil.exe""#, "Éditeur", "");
    let nouvelle = entree_demarrage("k2", r#"powershell -w hidden -enc AAAA"#, "", "lancé via powershell");
    let (a, modifie) = regles_comparer(&[connue.clone()], &[connue, nouvelle], false);
    assert_eq!(a, [("PER-001".to_string(), "Alerte".to_string())], "entrée inconnue et suspecte : PER-001 au niveau Alerte");
    assert!(modifie);
    // Inconnue mais sans remarque : PER-001 au niveau Info
    let banale = entree_demarrage("k3", r#""C:\Program Files\Autre\autre.exe""#, "Éditeur", "");
    assert_eq!(regles_comparer(&[], &[banale], false).0, [("PER-001".to_string(), "Info".to_string())]);
}

#[test]
fn per_001_negatif() {
    let connue = entree_demarrage("k1", r#""C:\Program Files\Outil\outil.exe""#, "Éditeur", "");
    // Relevé identique : rien
    assert_eq!(regles_comparer(&[connue.clone()], &[connue.clone()], false), (vec![], false));
    // Entrée nouvelle pendant l'apprentissage (premier relevé) : apprise, pas d'alerte
    let nouvelle = entree_demarrage("k2", "x.exe", "", "NON SIGNÉ");
    let (a, modifie) = regles_comparer(&[connue.clone()], &[connue, nouvelle], true);
    assert!(a.is_empty() && modifie, "apprentissage : référence réécrite, aucune alerte");
}

#[test]
fn per_002_positif() {
    let avant = entree_demarrage("k1", r#""C:\Program Files\Outil\outil.exe""#, "Éditeur", "");
    let apres = entree_demarrage("k1", r#""C:\Users\Public\outil.exe""#, "", "dossier suspect");
    let (a, modifie) = regles_comparer(&[avant], &[apres], false);
    assert_eq!(a, [("PER-002".to_string(), "Alerte".to_string())]);
    assert!(modifie);
}

#[test]
fn per_002_negatif() {
    // Même commande, signataire ou remarque changés (mise à jour signée par un autre certificat) : noté, sans alerte
    let avant = entree_demarrage("k1", r#""C:\Program Files\Outil\outil.exe""#, "Éditeur", "");
    let apres = entree_demarrage("k1", r#""C:\Program Files\Outil\outil.exe""#, "Éditeur 2", "");
    let (a, modifie) = regles_comparer(&[avant.clone()], &[apres], false);
    assert!(a.is_empty() && modifie, "signataire changé : référence réécrite, aucune alerte");
    // Commande changée pendant l'apprentissage : pas d'alerte
    let modifiee = entree_demarrage("k1", "autre.exe", "Éditeur", "");
    assert!(regles_comparer(&[avant], &[modifiee], true).0.is_empty());
}

/// Bruit mesuré (PR 3.6) : tâches « SoftLanding » de Windows dont la classe COM est empaquetée (AppX). Leur serveur est
/// un fichier du dossier du paquet ; le chemin lu dans le registre ne doit jamais en sortir
#[test]
fn per_001_com_empaquete_chemin_borne() {
    use crate::persistance::{chemin_dans_paquet, version_paquet};
    let racine = r"C:\WINDOWS\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy";
    assert_eq!(chemin_dans_paquet(racine, r"SoftLandingTask\SoftLandingTask.exe").as_deref(), Some(r"C:\WINDOWS\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SoftLandingTask\SoftLandingTask.exe"));
    assert_eq!(chemin_dans_paquet(&format!(r"{racine}\"), "a/b.dll").as_deref(), Some(r"C:\WINDOWS\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\a\b.dll"));
    for mauvais in [r"..\..\Users\Public\x.exe", r"a\..\..\x.exe", r"C:\Users\Public\x.exe", r"\\serveur\partage\x.exe", "a.exe:flux", "", "  ",
                    r"...\x.exe", r". .\x.exe", r"a\ .. \x.exe"] {
        assert_eq!(chemin_dans_paquet(racine, mauvais), None, "{mauvais}");
    }
    assert_eq!(chemin_dans_paquet("", "a.exe"), None);
    // Paquets de Windows seulement (audit de #83, S83-03) ; racine sous SystemApps ou WindowsApps, sans remontée
    use crate::persistance::{paquet_de_windows, racine_systeme_de_paquets};
    assert!(paquet_de_windows("MicrosoftWindows.Client.CBS_1000.26100.372.0_x64__cw5n1h2txyewy"));
    assert!(paquet_de_windows("Microsoft.WindowsStore_22410.1401.3.0_x64__8wekyb3d8bbwe"));
    assert!(!paquet_de_windows("Editeur.Outil_1.0.0.0_x64__abcdefghijklm"));
    assert!(!paquet_de_windows("Editeur.Outil_1.0.0.0_x64__cw5n1h2txyewyx"));
    let (w, pf) = (r"C:\WINDOWS", r"C:\Program Files");
    assert!(racine_systeme_de_paquets(r"C:\WINDOWS\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy", w, pf));
    assert!(racine_systeme_de_paquets(r"C:\Program Files\WindowsApps\Microsoft.X_1.0_x64__8wekyb3d8bbwe", w, pf));
    for mauvaise in [r"C:\Users\u\AppData\Local\Packages\X", r"C:\WINDOWS\SystemApps", r"C:\WINDOWS\SystemApps\..\Temp", r"D:\dev\paquet", r"C:\WINDOWS\SystemAppsX\Y", ""] {
        assert!(!racine_systeme_de_paquets(mauvaise, w, pf), "{mauvaise}");
    }
    assert!(!racine_systeme_de_paquets(r"C:\WINDOWS\SystemApps\X", "", ""), "dossiers système inconnus : refus");
    // Classe surchargée dans un profil (HKCU) : jamais résolue (contrôle du source : le registre n'est pas lu ici)
    let p = include_str!("persistance.rs").replace("\r\n", "\n");
    let d = p.find("fn serveur_com_empaquete(").unwrap();
    let f = &p[d..d + p[d..].find("\n}\n").unwrap()];
    assert!(f.find("if surchargee {\n        return None;").unwrap() < f.find(r"PackagedCom\ClassIndex").unwrap(), "classe surchargée dans un profil résolue quand même");
    assert!(f.contains(".filter(|p| paquet_de_windows(p))") && f.contains("if !racine_systeme_de_paquets("), "paquet ou racine non vérifiés");
    // La version la plus récente, comparée nombre par nombre
    assert!(version_paquet("P_1000.26100.372.0_x64__e") > version_paquet("P_1000.26100.360.0_x64__e"));
    assert!(version_paquet("P_1.100.0.0_x64__e") > version_paquet("P_1.99.0.0_x64__e"));
}

/// Bruit mesuré (PR 3.6) : le nettoyage que OneDrive pose dans « RunOnce » (effacer son installeur) n'est plus pris pour
/// un interpréteur suspect ; la moindre variation de la commande l'y remet
#[test]
fn per_001_nettoyage_onedrive() {
    use crate::persistance::nettoyage_onedrive;
    assert!(nettoyage_onedrive(r#"C:\WINDOWS\system32\cmd.exe /q /c del /q "C:\Users\u\AppData\Local\Microsoft\OneDrive\Update\OneDriveSetup.exe""#));
    assert!(nettoyage_onedrive(r#"C:\WINDOWS\system32\cmd.exe /q /c del /q "C:\Users\Jean Dupont\AppData\Local\Microsoft\OneDrive\StandaloneUpdater\OneDriveSetup.exe""#));
    for c in [
        r#"C:\WINDOWS\system32\cmd.exe /q /c del /q "C:\Users\u\AppData\Local\Microsoft\OneDrive\Update\OneDriveSetup.exe" & calc.exe"#,
        r#"C:\WINDOWS\system32\cmd.exe /q /c del /q "C:\Users\u\AppData\Local\Microsoft\OneDrive\Update\Autre.exe""#,
        r#"C:\WINDOWS\system32\cmd.exe /q /c del /q "C:\Users\u&calc\AppData\Local\Microsoft\OneDrive\Update\OneDriveSetup.exe""#,
        r#"C:\WINDOWS\system32\cmd.exe /c powershell -enc AAAA"#,
        r#"C:\Users\u\cmd.exe /q /c del /q "C:\Users\u\AppData\Local\Microsoft\OneDrive\Update\OneDriveSetup.exe""#,
        // Audit de #83, S83-01 : variable remplacée par cmd avant l'analyse (injection), et autres caractères spéciaux
        r#"C:\WINDOWS\system32\cmd.exe /q /c del /q "C:\Users\%Z%\AppData\Local\Microsoft\OneDrive\Update\OneDriveSetup.exe""#,
        r#"C:\WINDOWS\system32\cmd.exe /q /c del /q "C:\Users\u^&calc\AppData\Local\Microsoft\OneDrive\Update\OneDriveSetup.exe""#,
        r#"C:\WINDOWS\system32\cmd.exe /q /c del /q "C:\Users\!Z!\AppData\Local\Microsoft\OneDrive\Update\OneDriveSetup.exe""#,
        r#"C:\WINDOWS\system32\cmd.exe /q /c del /q "C:\Users\u)(x\AppData\Local\Microsoft\OneDrive\Update\OneDriveSetup.exe""#,
    ] {
        assert!(!nettoyage_onedrive(c), "{c}");
    }
    // Branché dans l'évaluation : la commande exacte n'est plus « lancé via cmd », une variante l'est toujours
    let e = |commande: &str| crate::commun::EntreeDemarrage {
        categorie: "RunOnce (u)".into(), nom: "Delete Cached Update Binary".into(), commande: commande.into(),
        cible: r"C:\WINDOWS\system32\cmd.exe".into(), signataire: "Microsoft Windows".into(), ..Default::default()
    };
    assert!(!crate::persistance::evaluer(&e(r#"C:\WINDOWS\system32\cmd.exe /q /c del /q "C:\Users\u\AppData\Local\Microsoft\OneDrive\Update\OneDriveSetup.exe""#)).contains("lancé via cmd"));
    assert!(crate::persistance::evaluer(&e(r#"C:\WINDOWS\system32\cmd.exe /q /c del /q "C:\Users\u\AppData\Local\Microsoft\OneDrive\Update\OneDriveSetup.exe" & calc"#)).contains("lancé via cmd"));
    // Exemption réservée à « RunOnce » : la même commande dans « Run » ou une tâche reste suspecte (S83-01)
    let mut run = e(r#"C:\WINDOWS\system32\cmd.exe /q /c del /q "C:\Users\u\AppData\Local\Microsoft\OneDrive\Update\OneDriveSetup.exe""#);
    run.categorie = "Run (u)".into();
    assert!(crate::persistance::evaluer(&run).contains("lancé via cmd"));
}
