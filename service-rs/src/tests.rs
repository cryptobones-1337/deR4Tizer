//! Tests des fonctions pures qui lisent des données venues du réseau ou de fichiers externes.
//! Le service est compilé avec panic = "abort" : un index hors limites tuerait le service SYSTEM. D'où, en
//! plus des cas valides, un « mini-fuzz » : toutes les troncatures d'un message valide et des milliers
//! d'entrées pseudo-aléatoires, qui ne doivent jamais provoquer de panique.
//!   cargo test --release

use std::net::Ipv4Addr;

/// Générateur pseudo-aléatoire déterministe (xorshift), pour des tests reproductibles
struct Hasard(u64);

impl Hasard {
    fn suivant(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn octets(&mut self, max: usize) -> Vec<u8> {
        let n = (self.suivant() % max as u64) as usize;
        (0..n).map(|_| self.suivant() as u8).collect()
    }
}

/// Toutes les troncatures, puis des variantes corrompues octet par octet
fn torturer(valide: &[u8], f: &mut dyn FnMut(&[u8])) {
    for n in 0..=valide.len() {
        f(&valide[..n]);
    }
    let mut h = Hasard(0x9E37_79B9_7F4A_7C15);
    for _ in 0..3000 {
        let mut v = valide.to_vec();
        for _ in 0..4 {
            if !v.is_empty() {
                let i = (h.suivant() % v.len() as u64) as usize;
                v[i] = h.suivant() as u8;
            }
        }
        f(&v);
        f(&h.octets(600));
    }
}

// ------------------------------------------------------------ paquets IP

fn paquet_udp(charge: &[u8]) -> Vec<u8> {
    let total = 20 + 8 + charge.len();
    let mut p = vec![0x45, 0, (total >> 8) as u8, total as u8, 0, 0, 0x40, 0, 64, 17, 0, 0, 10, 2, 0, 2, 198, 51, 100, 1];
    p.extend_from_slice(&[0xC3, 0x50, 0, 9, 0, (8 + charge.len()) as u8, 0, 0]);
    p.extend_from_slice(charge);
    p
}

#[test]
fn decoder_paquet_udp() {
    let d = paquet_udp(b"bonjour");
    let p = crate::capture::decoder_test(&d, Ipv4Addr::new(10, 2, 0, 2)).expect("paquet valide");
    assert!(!p.entrant);
    assert_eq!(p.proto, 17);
    assert_eq!(p.port_destination, 9);
    assert_eq!(p.destination, Ipv4Addr::new(198, 51, 100, 1));
    assert_eq!(p.charge, b"bonjour");
}

#[test]
fn decoder_sans_panique() {
    let valide = paquet_udp(b"0123456789abcdef");
    torturer(&valide, &mut |d| {
        let _ = crate::capture::decoder_test(d, Ipv4Addr::new(10, 2, 0, 2));
    });
}

// ------------------------------------------------------------ TLS ClientHello

/// ClientHello minimal : TLS 1.2, deux suites (dont une GREASE), SNI, groupes, formats de points
fn client_hello(nom: &str) -> Vec<u8> {
    let mut ext = Vec::new();
    // SNI (0)
    let mut sni = vec![0, 0];
    let liste_len = 3 + nom.len();
    sni.extend_from_slice(&((liste_len + 2) as u16).to_be_bytes());
    sni.extend_from_slice(&(liste_len as u16).to_be_bytes());
    sni.push(0);
    sni.extend_from_slice(&(nom.len() as u16).to_be_bytes());
    sni.extend_from_slice(nom.as_bytes());
    ext.extend(sni);
    // GREASE (0x0a0a), ignoré par JA3
    ext.extend_from_slice(&[0x0a, 0x0a, 0, 0]);
    // supported_groups (10) : 29, 23
    ext.extend_from_slice(&[0, 10, 0, 6, 0, 4, 0, 29, 0, 23]);
    // ec_point_formats (11) : 0
    ext.extend_from_slice(&[0, 11, 0, 2, 1, 0]);
    let mut corps = vec![0x03, 0x03];
    corps.extend_from_slice(&[0u8; 32]);
    corps.push(0);
    corps.extend_from_slice(&[0, 4, 0x13, 0x01, 0x2a, 0x2a]);
    corps.extend_from_slice(&[1, 0]);
    corps.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    corps.extend(ext);
    let mut hs = vec![1, 0, (corps.len() >> 8) as u8, corps.len() as u8];
    hs.extend(corps);
    let mut rec = vec![0x16, 0x03, 0x01, (hs.len() >> 8) as u8, hs.len() as u8];
    rec.extend(hs);
    rec
}

#[test]
fn client_hello_sni_et_ja3() {
    use md5::{Digest, Md5};
    let (sni, ja3) = crate::dpi::client_hello_test(&client_hello("www.example.com")).expect("ClientHello valide");
    assert_eq!(sni.as_deref(), Some("www.example.com"));
    // GREASE exclu des suites et des extensions
    let attendu: String = Md5::digest(b"771,4865,0-10-11,29-23,0").iter().map(|o| format!("{o:02x}")).collect();
    assert_eq!(ja3, attendu);
}

#[test]
fn client_hello_sans_panique() {
    torturer(&client_hello("exemple.lu"), &mut |d| {
        let _ = crate::dpi::client_hello_test(d);
    });
}

// ------------------------------------------------------------ DNS, LLMNR, NBNS

fn question_dns(nom: &str) -> Vec<u8> {
    let mut q = vec![0x12, 0x34, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for partie in nom.split('.') {
        q.push(partie.len() as u8);
        q.extend_from_slice(partie.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    q
}

#[test]
fn noms_dns() {
    assert_eq!(crate::dpi::nom_question_test(&question_dns("Mairie.Example.LU")).as_deref(), Some("mairie.example.lu"));
    torturer(&question_dns("a.b.c.example.lu"), &mut |d| {
        let _ = crate::dpi::nom_question_test(d);
        let _ = crate::ndr::nom_dns_test(d);
        let _ = crate::ndr::nom_nbns_test(d);
    });
}

// ------------------------------------------------------------ règles IDS

#[test]
fn regles_integrees_lisibles() {
    let (regles, ignorees) = crate::ids::lire_texte_test(crate::ids::REGLES_INTEGREES);
    assert_eq!(ignorees, 0, "toutes les règles intégrées doivent être prises en charge");
    assert!(regles >= 15);
}

#[test]
fn regle_contenu_hexa_et_correspondance() {
    let r = r#"alert udp any any -> any any (msg:"test"; content:"ab|43 44|"; nocase; content:!"zz"; sid:1;)"#;
    assert!(crate::ids::correspond_test(r, b"xx AbCD yy").expect("règle lisible"));
    assert!(!crate::ids::correspond_test(r, b"xx AbCD zz").expect("règle lisible"), "contenu nié présent");
    let r = r#"alert tcp any any -> any any (msg:"d"; content:"GET"; depth:3; content:"admin"; distance:0; within:20; sid:2;)"#;
    assert!(crate::ids::correspond_test(r, b"GET /admin HTTP/1.1").unwrap());
    assert!(!crate::ids::correspond_test(r, b"POST /admin").unwrap(), "depth : GET doit être au début");
}

#[test]
fn regles_non_prises_en_charge_ignorees() {
    let (n, ignorees) = crate::ids::lire_texte_test("alert tcp any any -> any any (msg:\"x\"; pcre:\"/a+/\"; sid:3;)\nalert foo\n# commentaire\n");
    assert_eq!((n, ignorees), (0, 2));
}

#[test]
fn regles_sans_panique() {
    let base = br#"alert tcp $EXTERNAL_NET any -> $HOME_NET [80,8080:8090] (msg:"x"; content:"|41 42|"; offset:2; depth:5; dsize:>3; flags:S; sid:7;)"#;
    torturer(base, &mut |d| {
        let _ = crate::ids::lire_texte_test(&String::from_utf8_lossy(d));
    });
}

// ------------------------------------------------------------ adresses

#[test]
fn reseaux_reserves() {
    let ip = |s: &str| u32::from(s.parse::<Ipv4Addr>().unwrap());
    assert!(crate::menaces::recouvre_reserve_test(ip("172.0.0.0"), ip("172.255.255.255")), "172.0.0.0/8 contient 172.16.0.0/12");
    assert!(crate::menaces::recouvre_reserve_test(ip("100.0.0.0"), ip("100.255.255.255")), "CGNAT");
    assert!(!crate::menaces::recouvre_reserve_test(ip("8.8.8.0"), ip("8.8.8.255")));
}

#[test]
fn plages_du_mode_panique() {
    let epargnee: Ipv4Addr = "1.1.1.1".parse().unwrap();
    let plages = crate::reponse::plages_internet(&[epargnee]);
    let dans = |ip: Ipv4Addr| plages.iter().any(|p| {
        let (a, b) = p.split_once('-').unwrap();
        let (a, b): (Ipv4Addr, Ipv4Addr) = (a.parse().unwrap(), b.parse().unwrap());
        u32::from(ip) >= u32::from(a) && u32::from(ip) <= u32::from(b)
    });
    assert!(dans("8.8.8.8".parse().unwrap()));
    assert!(!dans(epargnee), "serveur épargné");
    for local in ["192.168.1.254", "10.0.0.1", "172.16.5.5", "100.64.0.1", "224.0.0.252"] {
        assert!(!dans(local.parse().unwrap()), "{local} ne doit pas être bloqué");
    }
}

#[test]
fn api_adresses_autorisees() {
    let l = vec!["192.168.1.10".to_string(), "10.0.0.0/8".to_string()];
    assert!(crate::api::autorisee_test("192.168.1.10".parse().unwrap(), &l));
    assert!(crate::api::autorisee_test("10.20.30.40".parse().unwrap(), &l));
    assert!(!crate::api::autorisee_test("192.168.1.11".parse().unwrap(), &l));
    assert!(crate::api::autorisee_test("127.0.0.1".parse().unwrap(), &[]));
    assert_eq!(crate::api::decoder_test("a%20b+c%3A%"), "a b c:%");
}

// ------------------------------------------------------------ mise en forme

#[test]
fn horodatage_et_base64() {
    let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_792_998_000);
    assert_eq!(crate::export::horodatage_utc(t), "2026-10-26T07:00:00.000Z");
    assert_eq!(crate::notifications::base64_test(b"Ma"), "TWE=");
    assert_eq!(crate::notifications::base64_test("é".as_bytes()), "w6k=");
}

#[test]
fn chemins_des_pilotes() {
    let w = crate::natif::dossier_windows();
    assert_eq!(crate::hygiene::chemin_image(r"\SystemRoot\System32\drivers\x.sys").to_string_lossy().to_lowercase(), format!(r"{w}\System32\drivers\x.sys").to_lowercase());
    assert_eq!(crate::hygiene::chemin_image(r"\??\C:\Temp\y.sys").to_string_lossy(), r"C:\Temp\y.sys");
    assert_eq!(crate::hygiene::chemin_image(r"System32\drivers\z.sys").to_string_lossy().to_lowercase(), format!(r"{w}\System32\drivers\z.sys").to_lowercase());
}

// ------------------------------------------------------------ décisions (un test par correctif des revues)

fn alerte(niveau: &str, destination: &str, raisons: &str, score: i32) -> crate::commun::Alerte {
    crate::commun::Alerte {
        niveau: niveau.into(), destination: destination.into(), raisons: raisons.into(), score,
        processus: "réseau local".into(), mitre: "T1557.003".into(), heure: "2026-10-22 10:00:00".into(), ..Default::default()
    }
}

#[test]
fn b1_leurre_touche_par_rundll32_suspendu() {
    // rundll32 : binaire Windows, mais ni logiciel connu ni processus critique → suspendu
    assert!(crate::vol_donnees::suspendre_leurre(true, false, false));
    // processus critique (svchost partagé…) : jamais
    assert!(!crate::vol_donnees::suspendre_leurre(true, false, true));
    // sauvegarde connue et signée : jamais
    assert!(!crate::vol_donnees::suspendre_leurre(true, true, false));
    // réponse automatique désactivée : jamais
    assert!(!crate::vol_donnees::suspendre_leurre(false, false, false));
}

#[test]
fn b2_noms_des_leurres_dans_le_dossier_des_secrets() {
    assert!(crate::hygiene::FICHIER_NOMS.starts_with("secrets\\"));
    assert!(crate::hygiene::FICHIER_LEURRES.starts_with("secrets\\"));
}

#[test]
fn b3_vraie_alerte_visible_parmi_300_usurpations() {
    let mut lot: Vec<_> = (1..=300).map(|i| alerte("Critique", &format!("serveur DHCP 192.168.1.{i}"),
        "SERVEUR DHCP PIRATE probable", 12)).collect();
    let mut vraie = alerte("Critique", "passerelle 192.168.1.254", "USURPATION ARP probable", 12);
    vraie.mitre = "T1557.002".into();
    lot.insert(150, vraie);
    let t = crate::notifications::texte(&lot);
    assert!(t.contains("USURPATION ARP"), "l'alerte unique doit apparaître");
    assert!(t.contains("300 × serveur DHCP"), "les 300 usurpations doivent tenir sur une ligne : {t}");
    assert!(t.find("USURPATION ARP").unwrap() < t.find("300 ×").unwrap(), "l'alerte unique d'abord");
}

#[test]
fn notifications_critiques_jamais_retenues() {
    let lot = vec![alerte("Critique", "a", "x", 10), alerte("Alerte", "b", "y", 5)];
    // plafond atteint : la critique part, l'autre est retenue
    let (envoi, retenues, compte) = crate::notifications::repartir(lot.clone(), 10, 10);
    assert_eq!((envoi.len(), retenues, compte), (1, 1, false));
    assert_eq!(envoi[0].niveau, "Critique");
    // sous le plafond : tout part et l'envoi compte
    let (envoi, retenues, compte) = crate::notifications::repartir(lot, 0, 10);
    assert_eq!((envoi.len(), retenues, compte), (2, 0, true));
}

#[test]
fn editeurs_compares_exactement() {
    use crate::vol_donnees::editeur_correspond;
    assert!(editeur_correspond("Brave Software, Inc.", &["Brave Software, Inc."]));
    assert!(editeur_correspond("BRAVE SOFTWARE INC", &["Brave Software, Inc."]), "casse et ponctuation ignorées");
    assert!(!editeur_correspond("Brave Heart SARL", &["Brave Software, Inc."]));
    assert!(!editeur_correspond("Box, Inc. Fake Ltd", &["Box, Inc."]));
    assert!(!editeur_correspond("", &["Google LLC"]));
}

#[test]
fn blocages_leves_a_expiration_ou_hors_liste() {
    use crate::commun::Blocage;
    let b = |cible: &str, raison: &str, expire: &str| Blocage { type_: "parefeu".into(), cible: cible.into(), raison: raison.into(), date: String::new(), expire: expire.into() };
    let l = vec![
        b("1.1.1.1", "blocage automatique : Spamhaus", "2026-10-29 10:00:00"),
        b("2.2.2.2", "blocage automatique : Spamhaus", "2026-10-21 10:00:00"),
        b("3.3.3.3", "blocage manuel", ""),
    ];
    let listee = |ip: &str| ip != "1.1.1.1";
    let r = crate::moniteur::blocages_a_lever(&l, "2026-10-22 10:00:00", true, listee);
    let cibles: Vec<&str> = r.iter().map(|x| x.1.as_str()).collect();
    assert_eq!(cibles, vec!["1.1.1.1", "2.2.2.2"], "hors liste et expiré levés, manuel conservé");
    // listes pas encore chargées : seule l'expiration compte (sinon tout serait débloqué au démarrage)
    let r = crate::moniteur::blocages_a_lever(&l, "2026-10-22 10:00:00", false, |_| false);
    assert_eq!(r.len(), 1);
}

#[test]
fn baseline_reglage_asr_partage_conserve() {
    use crate::baseline::{reglages_partages, REGLES};
    let asr: Vec<&crate::baseline::Regle> = REGLES.iter().filter(|r| r.id.starts_with("asr.")).collect();
    assert!(asr.len() >= 2);
    // on annule la première règle ASR : ExploitGuard_ASR_Rules doit rester, puisque la deuxième l'utilise
    let retires = vec![(r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR".to_string(), "ExploitGuard_ASR_Rules".to_string())];
    let garder = reglages_partages(&retires, &asr[1..]);
    assert_eq!(garder.len(), 1);
    assert_eq!(garder[0].1, "ExploitGuard_ASR_Rules");
    // plus aucune règle ASR appliquée : rien à conserver
    assert!(reglages_partages(&retires, &[]).is_empty());
}

#[test]
fn chemins_de_profil_masques() {
    assert_eq!(crate::commun::masquer_chemin(r"C:\Users\marie\AppData\Local\Zoom\bin\Zoom.exe"), r"%USERPROFILE%\AppData\Local\Zoom\bin\Zoom.exe");
    assert_eq!(crate::commun::masquer_chemin(r"C:\Program Files\App\a.exe"), r"C:\Program Files\App\a.exe");
}

// ------------------------------------------------------------ revue v6 : N1 à N3 et non-bloquants

/// Variante du mini-fuzz pour les fonctions qui prennent du texte : octets aléatoires (dont non ASCII)
/// convertis par from_utf8_lossy, comme le texte reçu du réseau
fn torturer_texte(valide: &str, f: &mut dyn FnMut(&str)) {
    torturer(valide.as_bytes(), &mut |d| f(&String::from_utf8_lossy(d)));
    for t in ["é", "Révolution", "\u{212A}", "\u{FFFD}\u{FFFD}", "日本語", "\u{1F600}"] {
        f(t);
        f(&format!("{t}{valide}{t}"));
    }
}

#[test]
fn n1_upnp_sans_panique_sur_utf8_coupe() {
    // Cas reproduit par la revue : bloc de 2 octets invalides en UTF-8
    let r = crate::upnp::reponse_test(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n\xff\xff\r\n0\r\n\r\n");
    assert_eq!(r.map(|(s, _)| s), Some(200));
    // « é » (2 octets) coupé entre deux blocs : le texte final est reconstitué
    let corps = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nR\xc3\r\n9\r\n\xa9volution\r\n0\r\n\r\n";
    assert_eq!(crate::upnp::reponse_test(corps).unwrap().1, "Révolution");
    assert_eq!(crate::upnp::dechunker_test(b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"), b"Wikipedia");
    torturer(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n", &mut |d| {
        let _ = crate::upnp::reponse_test(d);
        let _ = crate::upnp::dechunker_test(d);
    });
    assert!(crate::upnp::decouper_url_test("http://192.168.1.254:5000/desc.xml").is_some());
    assert!(crate::upnp::decouper_url_test("http://203.0.113.9/desc.xml").is_none(), "jamais de requête vers Internet");
}

#[test]
fn fonctions_texte_sans_panique() {
    torturer_texte("a%20b+c%3A%C3%A9", &mut |t| { let _ = crate::api::decoder_test(t); });
    torturer_texte(r#"alert tcp any any -> any any (msg:"é"; content:"|41|é"; sid:9;)"#, &mut |t| { let _ = crate::ids::lire_texte_test(t); });
    torturer_texte(r"C:\Users\marie\AppData\x.exe", &mut |t| { let _ = crate::commun::masquer_chemin(t); });
    torturer_texte("Brave Software, Inc.", &mut |t| { let _ = crate::moniteur::ip_directe_normale(t); });
    torturer_texte("4.10.2", &mut |t| { let _ = crate::maj::version_valide(t); let _ = crate::maj::plus_recente(t, "4.1"); });
    torturer_texte(r"\SystemRoot\System32\drivers\x.sys", &mut |t| { let _ = crate::hygiene::chemin_image(t); });
    torturer_texte(r#""C:\Program Files\Google\Chrome\Application\chrome.exe" --remote-debugging-port=9222"#, &mut |t| { let _ = crate::processus::suspicion(t); });
}

#[test]
fn n2_mise_a_jour_cle_epinglee() {
    use crate::maj::{cles_epinglees, installation_autorisee, plus_recente, version_valide};
    let cle = "a".repeat(64);
    let autre = "b".repeat(64);
    let une = cles_epinglees(Some(&cle));
    assert!(installation_autorisee(Some(&cle), &une).is_ok());
    assert!(installation_autorisee(Some(&autre), &une).is_err(), "autre clé (même nom de certificat possible) : refusé");
    assert!(installation_autorisee(None, &une).is_err(), "non signé, invalide ou révoqué : refusé");
    assert!(installation_autorisee(Some(&cle), &cles_epinglees(None)).is_err(), "aucune clé épinglée : jamais d'installation");
    assert!(installation_autorisee(Some(&cle), &cles_epinglees(Some("court"))).is_err());
    // Revue v7 : clé actuelle et clé suivante (renouvellement du certificat) ; variable vide = aucune clé
    let deux = cles_epinglees(Some(&format!(" {cle}, {} ;zz", autre.to_uppercase())));
    assert_eq!(deux.len(), 2);
    assert!(installation_autorisee(Some(&autre), &deux).is_ok(), "clé suivante acceptée");
    assert!(cles_epinglees(Some("")).is_empty() && cles_epinglees(Some(&"g".repeat(64))).is_empty() && cles_epinglees(Some(&"a".repeat(63))).is_empty());
    assert!(version_valide("4.2") && version_valide("10.0.1"));
    for v in ["", "4..2", "4.2-beta", "..\\..\\x", "4.2 ", "4/2"] {
        assert!(!version_valide(v), "« {v} » ne doit pas servir de nom de dossier");
    }
    assert!(plus_recente("4.10", "4.9") && !plus_recente("4.0", "4.0") && !plus_recente("3.9", "4.0"));
}

#[test]
fn n3_apprentissage_par_chemin_editeur_et_destination() {
    use crate::apprentissage::{decider, signal_fort, signature_avec};
    use std::collections::BTreeSet;
    let mut vrai = alerte("Alerte", "203.0.113.5", "IP DIRECTE (aucune requête DNS)", 3);
    vrai.processus = "keepass".into();
    vrai.chemin = r"C:\Program Files\KeePass\KeePass.exe".into();
    vrai.mitre = String::new();
    let mut faux = vrai.clone();
    faux.chemin = r"C:\Users\x\AppData\Local\Temp\KeePass.exe".into();
    assert_ne!(signature_avec(&vrai, "Dominik Reichl"), signature_avec(&faux, "non signé"), "même nom, autre chemin et éditeur : autre comportement");
    let mut autre_ip = vrai.clone();
    autre_ip.destination = "198.51.100.77".into();
    assert_ne!(signature_avec(&vrai, "e"), signature_avec(&autre_ip, "e"), "une autre IP n'est pas apprise d'office");
    let mut domaine = vrai.clone();
    domaine.nom_dns = Some("keepass.info".into());
    let mut domaine_autre_ip = domaine.clone();
    domaine_autre_ip.destination = "198.51.100.77".into();
    assert_eq!(signature_avec(&domaine, "e"), signature_avec(&domaine_autre_ip, "e"), "même domaine : même comportement");
    for r in ["suppression des sauvegardes (typique d'un rançongiciel) : vssadmin delete shadows",
              "document winword qui lance powershell (macro ou exploit probable)",
              "PowerShell obscurci ou qui télécharge du code : iex", "détournement d'outil Windows (LOLBin) : certutil -urlcache"] {
        assert!(signal_fort(&alerte("Alerte", "lancé par x", r, 5)), "{r}");
    }
    let mut ids = alerte("Alerte", "IDS : Bureau à distance (RDP) sollicité depuis Internet", "règle 9000041", 6);
    ids.mitre = String::new();
    assert!(signal_fort(&ids));
    let vide = BTreeSet::new();
    assert_eq!(decider("Critique", "x", true, &vide, &[]), None);
    assert!(decider("Alerte", "x", true, &vide, &[]).is_some_and(|d| d.2));
}

#[test]
fn regroupement_second_niveau() {
    let mut lot: Vec<_> = (1..=300).map(|i| {
        let mut a = alerte("Alerte", &format!("{}-liste.example", ["alpha", "beta", "gamma", "delta"][i % 4].repeat(1 + i % 7)), "domaine listé demandé", 6);
        a.processus = "svchost".into();
        a.mitre = "T1071.004".into();
        a
    }).collect();
    let mut vraie = alerte("Critique", "passerelle 192.168.1.254", "USURPATION ARP probable", 12);
    vraie.mitre = "T1557.002".into();
    lot.push(vraie);
    let groupes = crate::notifications::regrouper(&lot);
    assert!(groupes.len() <= 3, "les domaines différents d'une même nature sont fusionnés : {} groupes", groupes.len());
    assert!(crate::notifications::texte(&lot).contains("USURPATION ARP"));
}

#[test]
fn ip_directe_editeurs_exacts() {
    use crate::moniteur::ip_directe_normale;
    assert!(ip_directe_normale("Proton AG"));
    assert!(ip_directe_normale("Google LLC"));
    assert!(ip_directe_normale("Valve Corp."));
    assert!(!ip_directe_normale("Google Fake Updates Ltd"), "sous-chaîne : refusé");
    assert!(!ip_directe_normale("TeamViewer Germany GmbH"), "prise en main à distance : jamais exemptée");
    assert!(!ip_directe_normale("AnyDesk Software GmbH"));
    assert!(!ip_directe_normale(""));
}

#[test]
fn debogage_a_distance_ancre_sur_l_executable() {
    use crate::processus::suspicion;
    assert!(suspicion(r#""C:\Program Files\Google\Chrome\Application\chrome.exe" --remote-debugging-port=9222 --headless"#).is_some());
    assert!(suspicion("chrome.exe --remote-debugging-pipe").is_some());
    assert!(suspicion(r#""C:\Program Files (x86)\Microsoft\EdgeWebView\Application\msedgewebview2.exe" --remote-debugging-port=0"#).is_none());
    assert!(suspicion(r#""C:\Program Files\Google\Chrome\Application\chrome.exe" --profile-directory=Default"#).is_none());
}

// ------------------------------------------------------------ revue v7

#[test]
fn m1_proprietaire_du_dossier_de_donnees() {
    use crate::natif::proprietaire_de_confiance;
    use std::path::Path;
    let programdata = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
    assert_eq!(proprietaire_de_confiance(Path::new(&programdata)), Some(true), "ProgramData appartient à SYSTEM");
    let systeme = crate::natif::dossier_systeme();
    assert_eq!(proprietaire_de_confiance(&Path::new(&systeme).join("kernel32.dll")), Some(false), "TrustedInstaller n'est ni SYSTEM ni Administrateurs");
    assert_eq!(proprietaire_de_confiance(Path::new(r"C:\n-existe-pas\x.json")), None);
    // Hors service (tests, console), pas de contrôle : les fichiers appartiennent à l'utilisateur
    assert!(!crate::natif::est_systeme());
}

#[test]
fn script_de_mise_a_jour_valide() {
    use std::path::{Path, PathBuf};
    let inst = Path::new(r"C:\ProgramData\deR4Tizer\maj\installation");
    let prog = Path::new(r"C:\Program Files\deR4Tizer");
    let h = "ab".repeat(32);
    for fichiers in [vec![(inst.join(r"4.4\deR4Tizer.msi"), h.clone())],
                     vec![(inst.join(r"4.4\deR4TizerSvc.exe"), h.clone()), (inst.join(r"4.4\deR4Tizer.exe"), h.clone())]] {
        let s = crate::maj::script_installation("4.4", inst, prog, &fichiers);
        assert!(s.contains(&format!("Hash -eq '{h}'")), "empreinte revérifiée juste avant l'exécution");
        assert!(s.contains("\"Action\":\"verification\"") && s.contains(r"deR4Tizer 4\.4"), "contrôle par le canal, pas seulement l'existence du tube");
        assert!(s.contains(r"installation\4.3\deR4Tizer.msi") || s.contains(&format!(r"installation\{}\deR4Tizer.msi", crate::commun::VERSION)));
        // Syntaxe PowerShell valide
        let f = std::env::temp_dir().join(format!("der4tizer-script-{}.ps1", std::process::id()));
        std::fs::write(&f, &s).unwrap();
        let sortie = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command",
                &format!("$e = $null; [void][Management.Automation.Language.Parser]::ParseFile('{}', [ref]$null, [ref]$e); $e.Count", f.display())])
            .output().unwrap();
        let _ = std::fs::remove_file(&f);
        assert_eq!(String::from_utf8_lossy(&sortie.stdout).trim(), "0", "{s}");
        let _: Vec<PathBuf> = fichiers.into_iter().map(|x| x.0).collect();
    }
}

// ------------------------------------------------------------ lot 1 : propriété et droits du dossier de données

fn securite(proprietaire: &str, protege: bool, aces: &[(bool, u32, &str)]) -> crate::natif::Securite {
    crate::natif::Securite {
        proprietaire: proprietaire.into(),
        protege,
        aces: aces.iter().map(|&(autorise, masque, sid)| crate::natif::Ace { autorise, masque, sid: sid.into() }).collect(),
        ace_inconnue: false,
    }
}

#[test]
fn lot1_proprietaire_acceptable() {
    use crate::protection::proprietaire_acceptable;
    assert!(proprietaire_acceptable("S-1-5-18"), "SYSTEM");
    assert!(proprietaire_acceptable("S-1-5-32-544"), "Administrateurs");
    for refuse in ["S-1-5-21-1004336348-1177238915-682003330-1001", "S-1-5-32-545", "S-1-5-11", "S-1-1-0",
                   "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", // TrustedInstaller
                   "", "S-1-5-32-5440", "S-1-5-180", " S-1-5-18", "s-1-5-18"] {
        assert!(!proprietaire_acceptable(refuse), "{refuse:?}");
    }
}

#[test]
fn lot1_droits_conformes() {
    use crate::protection::{droits_conformes, SID_ADMINISTRATEURS as BA, SID_SYSTEME as SY};
    let lecteur = "S-1-5-21-1-2-3-1001";
    let complets = [SY, BA];
    let ok = securite(BA, true, &[(true, 0x1f01ff, SY), (true, 0x1f01ff, BA), (true, 0x1200a9, lecteur)]);
    assert!(droits_conformes(&ok, &complets, &[lecteur]).is_ok());
    // Propriétaire : un compte standard qui a créé le dossier d'avance
    assert!(droits_conformes(&securite(lecteur, true, &[(true, 0x1f01ff, SY)]), &complets, &[]).is_err());
    assert!(droits_conformes(&securite("", true, &[]), &complets, &[]).is_err(), "propriétaire illisible");
    // Héritage de ProgramData encore actif
    assert!(droits_conformes(&securite(BA, false, &[(true, 0x1f01ff, SY)]), &complets, &[]).is_err());
    // Utilisateurs, Utilisateurs authentifiés, Tout le monde, Créateur propriétaire : aucun droit, même en lecture
    for autre in ["S-1-5-32-545", "S-1-5-11", "S-1-1-0", "S-1-3-0"] {
        assert!(droits_conformes(&securite(BA, true, &[(true, 0x1200a9, autre)]), &complets, &[lecteur]).is_err(), "{autre}");
    }
    // Lecteur : lecture seulement ; chaque droit d'écriture isolé est refusé
    for ecriture in [0x2u32, 0x4, 0x10, 0x40, 0x100, 0x1_0000, 0x4_0000, 0x8_0000, 0x0200_0000, 0x1000_0000, 0x4000_0000] {
        let s = securite(BA, true, &[(true, 0x1200a9 | ecriture, lecteur)]);
        assert!(droits_conformes(&s, &complets, &[lecteur]).is_err(), "droit {ecriture:#x}");
    }
    // Dossier de travail de la mise à jour : SYSTEM seul, les administrateurs exclus
    assert!(droits_conformes(&securite(SY, true, &[(true, 0x1f01ff, SY)]), &[SY], &[]).is_ok());
    assert!(droits_conformes(&securite(SY, true, &[(true, 0x1f01ff, SY), (true, 0x1f01ff, BA)]), &[SY], &[]).is_err());
    // Un refus explicite ne gêne pas ; une entrée d'un type inconnu, si
    assert!(droits_conformes(&securite(BA, true, &[(false, 0x1f01ff, "S-1-5-32-545"), (true, 0x1f01ff, SY)]), &complets, &[]).is_ok());
    let mut inconnue = securite(BA, true, &[(true, 0x1f01ff, SY)]);
    inconnue.ace_inconnue = true;
    assert!(droits_conformes(&inconnue, &complets, &[]).is_err());
}

#[test]
fn lot1_lecture_echec_ferme() {
    use crate::commun::lecture_autorisee;
    // Hors service : pas de contrôle (tests, mode console)
    assert!(lecture_autorisee(false, true, true, true, Some(false)).is_ok());
    // En service
    assert!(lecture_autorisee(true, true, false, true, Some(true)).is_ok());
    assert!(lecture_autorisee(true, true, false, false, None).is_ok(), "fichier absent : la lecture échoue d'elle-même");
    assert!(lecture_autorisee(true, true, false, true, None).is_err(), "fichier présent au propriétaire illisible (DACL vide)");
    assert!(lecture_autorisee(true, true, false, true, Some(false)).is_err(), "propriétaire : compte standard");
    assert!(lecture_autorisee(true, true, true, true, Some(true)).is_err(), "protection non vérifiée : rien n'est chargé");
    // lecteurs.json (sans le verrou) : seul le propriétaire compte
    assert!(lecture_autorisee(true, false, true, true, Some(true)).is_ok());
    assert!(lecture_autorisee(true, false, true, true, Some(false)).is_err());
    assert!(lecture_autorisee(true, false, true, true, None).is_err());
}

#[test]
fn lot1_tri_au_demarrage_proprietaire_non_verifie_ecarte() {
    use crate::protection::{trier_element, Tri};
    assert_eq!(trier_element(false, Some(true)), Tri::Garder);
    assert_eq!(trier_element(false, Some(false)), Tri::Ecarter, "compte standard");
    // Revue de la PR 1 : un compte standard pose une DACL vide sur son fichier, SYSTEM ne lit plus le
    // propriétaire ; garder le fichier le ferait blanchir par la prise de possession qui suit
    assert_eq!(trier_element(false, None), Tri::Ecarter, "propriétaire illisible");
    for p in [Some(true), Some(false), None] {
        assert_eq!(trier_element(true, p), Tri::SupprimerLien, "un lien est supprimé quel que soit son propriétaire");
    }
}

#[test]
fn lot1_echec_du_demarrage_non_leve_par_la_verification_horaire() {
    use crate::protection::combiner;
    // Constaté sur le poste : un dossier piégé impossible à écarter mettait la protection en échec, puis la
    // première vérification horaire (racine seule, conforme) levait l'échec dans la même seconde
    let e = Some("un élément d'un autre propriétaire n'a pas pu être écarté".to_string());
    assert!(combiner(e.clone(), Ok(())).is_err());
    assert!(combiner(e, Err("autre".into())).is_err());
    assert!(combiner(None, Ok(())).is_ok());
    assert!(combiner(None, Err("droits de la racine".into())).is_err());
}

#[test]
fn lot1_dacl_vide_proprietaire_illisible() {
    // Ce que voit le service sur un fichier à DACL vide dont il n'est pas propriétaire : lecture des droits
    // impossible. Hors élévation, le propriétaire (le compte du test) garde READ_CONTROL : on vérifie au moins
    // que la DACL vide est bien posée et que la décision ne s'appuie pas sur un None.
    use crate::natif::{lire_securite, poser_droits};
    let d = std::env::temp_dir().join(format!("der4tizer-dacl-vide-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let f = d.join("config.json");
    std::fs::write(&f, b"{}").unwrap();
    let proprietaire = lire_securite(&f).unwrap().proprietaire;
    poser_droits(&f, &format!("O:{proprietaire}D:P")).unwrap();
    if let Some(s) = lire_securite(&f) {
        assert!(s.protege && s.aces.is_empty(), "DACL vide : {:?}", s.aces);
    }
    assert!(std::fs::read(&f).is_err(), "plus personne ne lit le contenu");
    // Remise des droits pour nettoyer : le propriétaire garde le droit de réécrire la DACL (pas de changer
    // le propriétaire, d'où icacls et non poser_droits)
    assert!(crate::protection::icacls(&[&f.to_string_lossy(), "/grant", &format!("*{proprietaire}:F")]));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn lot1_fichier_cree_avec_ses_droits_et_dacl_remplacee() {
    use crate::natif::{ecrire_fichier_protege, lire_securite, poser_droits};
    let d = std::env::temp_dir().join(format!("der4tizer-lot1-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    // Le test tourne sans élévation : le compte du test garde ses droits (le service, lui, est SYSTEM)
    let utilisateur = lire_securite(&d).unwrap().proprietaire;
    assert!(utilisateur.starts_with("S-1-5-"), "{utilisateur}");
    let sddl = format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{utilisateur})");
    // Fichier créé directement avec une DACL protégée, rien d'hérité du dossier
    let f = d.join("jeton.txt");
    ecrire_fichier_protege(&f, b"abc", &sddl).unwrap();
    let s = lire_securite(&f).expect("droits lisibles");
    assert!(s.protege);
    // Comptes distincts : en CI, le test tourne en administrateur élevé et le compte du test est alors
    // Administrateurs lui-même (Windows fusionne les deux entrées)
    let sids: std::collections::BTreeSet<_> = s.aces.iter().filter(|a| a.autorise).map(|a| a.sid.clone()).collect();
    let attendu: std::collections::BTreeSet<_> = ["S-1-5-18".to_string(), "S-1-5-32-544".into(), utilisateur.clone()].into();
    assert_eq!(sids, attendu);
    // Remplacement d'un fichier existant : toujours protégé, contenu remplacé
    ecrire_fichier_protege(&f, b"defg", &sddl).unwrap();
    assert!(lire_securite(&f).unwrap().protege);
    assert_eq!(std::fs::read(&f).unwrap(), b"defg");
    // poser_droits remplace TOUTE la DACL : une entrée « Utilisateurs : modification » ne survit pas
    assert!(crate::protection::icacls(&[&d.to_string_lossy(), "/grant", "*S-1-5-32-545:(OI)(CI)M"]));
    assert!(lire_securite(&d).unwrap().aces.iter().any(|a| a.sid == "S-1-5-32-545"));
    poser_droits(&d, &format!("O:{utilisateur}D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{utilisateur})")).unwrap();
    let s = lire_securite(&d).unwrap();
    assert!(s.protege && !s.ace_inconnue);
    assert!(!s.aces.iter().any(|a| a.sid == "S-1-5-32-545"), "entrée étrangère retirée : {:?}", s.aces);
    assert!(poser_droits(&d, "D:P(A;;FA;;;SY").is_err(), "SDDL invalide : erreur, rien de posé");
    let _ = std::fs::remove_dir_all(&d);
}

// ------------------------------------------------------------ lot 1, seconde relecture de la PR 1

#[test]
fn lot1_mise_de_cote_ratee_jamais_de_confiance() {
    // Relecture : un fichier piégé tenu ouvert sans partage de suppression pendant le démarrage ne doit pas
    // changer de propriétaire, sinon il serait gardé (et chargé) au démarrage suivant
    use crate::natif::{lire_securite, renommer_par_handle};
    use crate::protection::{trier_element, Tri};
    use std::os::windows::fs::OpenOptionsExt;
    let d = std::env::temp_dir().join(format!("der4tizer-tenu-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("ecartes")).unwrap();
    let f = d.join("lecteurs.json");
    std::fs::write(&f, b"[]").unwrap();
    let avant = lire_securite(&f).unwrap();
    {
        // Ouvert en lecture, partage en lecture seule : ni écriture ni suppression partagées
        let _tenu = std::fs::OpenOptions::new().read(true).share_mode(0x1).open(&f).unwrap();
        assert!(renommer_par_handle(&f, &d.join("ecartes").join("x-lecteurs.json")).is_err(), "fichier tenu : déplacement impossible");
        let apres = lire_securite(&f).unwrap();
        assert_eq!(apres.proprietaire, avant.proprietaire, "aucune prise de possession");
        assert_eq!(apres.aces, avant.aces, "droits inchangés");
    }
    // Propriétaire inchangé, donc toujours non vérifié pour le service : écarté au démarrage suivant
    for p in [Some(false), None] {
        assert_eq!(trier_element(false, p), Tri::Ecarter);
    }
    // Une fois relâché, le déplacement par handle réussit, sans changer propriétaire ni droits
    let dest = d.join("ecartes").join("x-lecteurs.json");
    renommer_par_handle(&f, &dest).unwrap();
    assert!(!f.exists() && dest.exists());
    assert_eq!(lire_securite(&dest).unwrap().proprietaire, avant.proprietaire);
    // Un dossier se déplace aussi
    std::fs::create_dir_all(d.join("piege")).unwrap();
    renommer_par_handle(&d.join("piege"), &d.join("ecartes").join("x-piege")).unwrap();
    assert!(d.join("ecartes").join("x-piege").is_dir());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn lot1_privilege_de_restauration_limite_a_l_appel() {
    use crate::natif::avec_privilege_restauration;
    // Hors élévation, le privilège n'est pas dans le jeton : refus, et f n'est pas exécutée. En CI (élevé),
    // il est accordé le temps de l'appel. Dans les deux cas, le fil revient à son jeton.
    let mut appele = false;
    match avec_privilege_restauration(|| appele = true) {
        Ok(()) => assert!(appele),
        Err(e) => {
            assert!(!appele, "f ne doit pas s'exécuter sans le privilège");
            assert!(e.contains("privilège") || e.contains("jeton"), "{e}");
        }
    }
    // Rappel immédiat : pas d'emprunt de jeton resté actif (un second ImpersonateSelf réussit pareil)
    let r2 = avec_privilege_restauration(|| 1);
    assert_eq!(r2.is_ok(), appele);
}

#[test]
fn lot1_lisible_en_echec_liste_d_autorisation() {
    use crate::commun::lisible_en_echec;
    for oui in ["geoip\\afrinic.txt", "GeoIP/ripencc.txt", "alertes.json", "incidents.json", "dns.json", "journal.txt"] {
        assert!(lisible_en_echec(oui), "{oui}");
    }
    for non in ["config.json", "lecteurs.json", "apprentissage.json", "blocages.json", "quarantaine.json",
                "secrets\\notifications.json", "secrets\\leurres-noms.json", "api-jeton.txt", "baseline-sauvegarde.json",
                "executables.json", "extensions-connues.json", "ecoutes-connues.json", "peripheriques-connus.json",
                "geoip\\sous\\x.txt", "geoip\\", "geoip\\x.json", "..\\config.json", "", "alertes.json\\x"] {
        assert!(!lisible_en_echec(non), "{non}");
    }
}

#[test]
fn lot1_alerte_critique_locale_en_echec() {
    let a = crate::protection::alerte_echec("un élément d'un autre propriétaire n'a pas pu être écarté");
    assert_eq!(a.niveau, "Critique");
    assert!(a.raisons.contains("n'a pas pu être écarté") && a.raisons.contains("pas remontée"));
    assert!(!a.raisons.contains("  "), "texte sans espaces doublés : {}", a.raisons);
}
