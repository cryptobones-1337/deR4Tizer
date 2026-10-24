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
    let mut p = vec![0x45, 0, (total >> 8) as u8, total as u8, 0, 0, 0x40, 0, 64, 17, 0, 0, 10, 0, 0, 2, 198, 51, 100, 1];
    p.extend_from_slice(&[0xC3, 0x50, 0, 9, 0, (8 + charge.len()) as u8, 0, 0]);
    p.extend_from_slice(charge);
    p
}

#[test]
fn decoder_paquet_udp() {
    let d = paquet_udp(b"bonjour");
    let p = crate::capture::decoder_test(&d, Ipv4Addr::new(10, 0, 0, 2)).expect("paquet valide");
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
        let _ = crate::capture::decoder_test(d, Ipv4Addr::new(10, 0, 0, 2));
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

/// IDS, règle Shellshock (sid 9000011, rév. 2), correction de bruit hors phase 3 : constaté, une alerte CRITIQUE sur
/// un téléchargement chiffré de plusieurs gigaoctets (réponses d'un port 443) ; « () { » puis « }; » n'importe où
/// après finissent par apparaître au hasard dans des octets chiffrés. La règle vise une requête vers un serveur HTTP
/// en clair du poste, avec la forme de l'attaque (« } » dans les 10 octets qui suivent « () { »). Règle entière
/// appliquée : en-tête (adresses, ports) et contenu.
#[test]
fn ids_shellshock_sans_faux_positif_sur_des_octets_quelconques() {
    use crate::capture::Paquet;
    use crate::ids::correspond_paquet_test;
    let regle = crate::ids::REGLES_INTEGREES.lines().find(|l| l.contains("sid:9000011")).expect("règle Shellshock");
    let paquet = |source: [u8; 4], port_source: u16, port_destination: u16, charge: &'static [u8]| Paquet {
        entrant: true, proto: 6, source: source.into(), destination: [192, 168, 0, 10].into(), port_source,
        port_destination, longueur: 40 + charge.len(), drapeaux: 0x18, charge,
    };
    let attaque: &[u8] = b"GET /cgi-bin/x HTTP/1.1\r\nUser-Agent: () { :; }; /bin/cat /etc/passwd\r\n\r\n";
    // Positif : requête Shellshock vers le port 80 du poste, depuis Internet
    assert_eq!(correspond_paquet_test(regle, &paquet([203, 0, 113, 5], 50000, 80, attaque)), Some(true), "attaque vers le port 80");
    assert_eq!(correspond_paquet_test(regle, &paquet([203, 0, 113, 5], 50000, 8080, b"Referer: () { _; } >_[$($())] { echo x; }\r\n")),
        Some(true), "variante vers le port 8080");
    // Négatifs : octets chiffrés ou quelconques (« () { » puis « }; » loin après), réponse d'un port 443, port TLS
    let mut quelconque = vec![0x17u8, 0x03, 0x03, 0x40, 0x00];
    quelconque.extend_from_slice(b"() {");
    quelconque.extend(std::iter::repeat(0xA5u8).take(500));
    quelconque.extend_from_slice(b"};");
    let quelconque: &'static [u8] = Box::leak(quelconque.into_boxed_slice());
    assert_eq!(correspond_paquet_test(regle, &paquet([203, 0, 113, 5], 50000, 80, quelconque)), Some(false), "« }} » loin de « () {{ »");
    assert_eq!(correspond_paquet_test(regle, &paquet([203, 0, 113, 5], 443, 50001, attaque)), Some(false), "réponse d'un serveur (port 443)");
    assert_eq!(correspond_paquet_test(regle, &paquet([203, 0, 113, 5], 50000, 443, attaque)), Some(false), "port TLS du poste");
    assert_eq!(correspond_paquet_test(regle, &paquet([192, 168, 0, 20], 50000, 80, attaque)), Some(false), "source du réseau local");
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

/// Lot 5 : jeton de l'API en échec fermé (BCryptGenRandom en échec ou octets nuls : aucun jeton, donc pas d'API),
/// et /api/v1/sante, servie sans jeton, ne dit plus le nom de la machine
#[test]
fn lot5_api_jeton_echec_ferme_et_sante_anonyme() {
    use crate::api::{corps_sante, jeton_depuis_alea};
    assert_eq!(jeton_depuis_alea(false, &[7u8; 32]), None, "générateur en échec : pas de jeton");
    assert_eq!(jeton_depuis_alea(true, &[0u8; 32]), None, "octets nuls : pas de jeton");
    assert_eq!(jeton_depuis_alea(true, &[0u8; 8]), None, "trop court : pas de jeton");
    let j = jeton_depuis_alea(true, &[0xab; 32]).unwrap();
    assert_eq!(j, "ab".repeat(32));
    let s = corps_sante();
    assert!(s.contains(r#""Ok":true"#) && s.contains(crate::commun::VERSION), "{s}");
    assert!(!s.contains("Hote"), "nom de la machine renvoyé sans jeton : {s}");
    let hote = crate::export::hote_local();
    assert!(hote.is_empty() || !s.contains(&hote), "nom de la machine renvoyé sans jeton : {s}");
    // Revue : un jeton DÉJÀ présent n'est repris que s'il a la forme d'un jeton créé par le service
    use crate::api::jeton_valide;
    assert!(jeton_valide(&"ab".repeat(32)));
    assert!(jeton_valide(&"0123456789ABCDEF".repeat(4)), "majuscules hexadécimales acceptées");
    assert!(!jeton_valide(&"0".repeat(64)), "jeton nul refusé");
    assert!(!jeton_valide(&"a".repeat(32)), "32 caractères : trop court");
    assert!(!jeton_valide(&"a".repeat(65)), "trop long");
    assert!(!jeton_valide(&"g".repeat(64)), "non hexadécimal");
    assert!(!jeton_valide(""), "vide");
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

#[test]
fn reglages_de_l_interface_avec_blocs_nuls() {
    // Ce qu'envoie l'interface tant que config.json n'existe pas (première installation) : blocs non créés,
    // sérialisés à null. Refusé, le passage en anglais échouait en « réglages illisibles »
    let json = r#"{"Langue":"en","Syslog":{"Actif":false,"Hote":"","Port":514,"Protocole":"UDP","Format":"JSON","NiveauMin":"Alerte"},"Api":{"Actif":false,"Port":8642,"Reseau":false,"Adresses":null},"Ips":false,"ListesRestreintes":false,"Notifications":null,"Maj":null,"BlocageAutoMenaces":true,"ReponseAutoRancongiciel":true}"#;
    let c: crate::commun::Config = serde_json::from_str(json).expect("réglages de l'interface lisibles");
    assert_eq!(c.langue, "en");
    assert_eq!(c.api.adresses, "");
    let defaut = crate::commun::Config::default();
    assert_eq!(c.maj.url, defaut.maj.url, "bloc nul : valeurs par défaut");
    assert_eq!(c.notifications.niveau_min, defaut.notifications.niveau_min);
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

#[test]
fn tache_com_cible_le_serveur_du_clsid() {
    // Tâche planifiée à gestionnaire COM (Wininet\CacheTask, présente sur tout Windows) : la cible est la DLL du
    // CLSID, pas le dossier System32\COM trouvé en cherchant « COM » (signataire vide, donc « NON SIGNÉ » à tort)
    let w = crate::natif::dossier_windows();
    let c = crate::persistance::cible("COM {0358B920-0AC7-461F-98F4-58E32CD89148}");
    assert_eq!(c.to_lowercase(), format!(r"{w}\system32\wininet.dll").to_lowercase());
    // CLSID inconnu : aucune cible (signataire « ? »), jamais un dossier
    assert_eq!(crate::persistance::cible("COM {00000000-0000-0000-0000-0000000000D4}"), "");
    // Un nom relatif ne se résout jamais en dossier (ici System32\COM)
    assert_ne!(crate::persistance::cible("COM").to_lowercase(), format!(r"{w}\system32\com").to_lowercase());
}

#[test]
fn tache_com_hors_windows_sans_serveur_signalee() {
    // Détournement COM : tâche hors \Microsoft\Windows\ dont le CLSID n'est pas enregistré pour la machine (HKCU,
    // non lu) ou dont le serveur manque. Ne doit jamais sortir sans remarque
    let tache = |nom: &str, cible: &str| crate::commun::EntreeDemarrage {
        categorie: "Tâche planifiée".into(), nom: nom.into(), commande: "COM {00000000-0000-0000-0000-0000000000D4}".into(),
        cible: cible.into(), signataire: "?".into(), ..Default::default()
    };
    let absent = format!(r"{}\d4t-absent-{}.dll", crate::natif::dossier_systeme(), std::process::id());
    for (nom, c) in [(r"\Mise a jour", ""), (r"\Microsoft\Office\Tache", ""), (r"\Mise a jour", absent.as_str())] {
        assert!(crate::persistance::evaluer(&tache(nom, c)).contains("serveur COM non enregistré"), "{nom} / {c}");
    }
    // Tâche livrée avec Windows au CLSID non enregistré : pas de bruit
    assert_eq!(crate::persistance::evaluer(&tache(r"\Microsoft\Windows\Wininet\X", "")), "");
    // ClassId sans accolades (accepté et gardé tel quel par Windows) : la remarque ne se contourne pas
    let mut sans = tache(r"\Mise a jour", "");
    sans.commande = "COM 00000000-0000-0000-0000-0000000000D4".into();
    assert!(crate::persistance::evaluer(&sans).contains("serveur COM non enregistré"));
    // et le relevé le ramène à la forme reconnue, résolue comme les autres
    let wininet = "0358B920-0AC7-461F-98F4-58E32CD89148";
    for id in [wininet.to_string(), format!("{{{wininet}}}"), format!("  {{{wininet}}} ")] {
        assert_eq!(crate::persistance::commande_com(&id), format!("COM {{{wininet}}}"), "{id}");
    }
    let w = crate::natif::dossier_windows();
    assert_eq!(crate::persistance::cible(&crate::persistance::commande_com(wininet)).to_lowercase(), format!(r"{w}\system32\wininet.dll").to_lowercase());
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

/// Lot 3c : un certificat dont la CRL ne répond pas était accepté (WinVerifyTrust tolère la révocation hors
/// ligne). Révocation révoquée, inconnue ou hors ligne : refus ; les autres états de la chaîne n'y changent rien.
#[test]
fn n2_revocation_verifiee_ou_refus() {
    use crate::natif::revocation_verifiee;
    assert!(revocation_verifiee(0), "chaîne sans erreur");
    assert!(!revocation_verifiee(0x0000_0004), "révoqué");
    assert!(!revocation_verifiee(0x0000_0040), "révocation inconnue");
    assert!(!revocation_verifiee(0x0100_0000), "révocation hors ligne (CRL injoignable)");
    assert!(!revocation_verifiee(0x0100_0040), "inconnue et hors ligne, comme Windows les signale ensemble");
    assert!(!revocation_verifiee(0x0100_0000 | 0x0000_0001), "hors ligne avec une autre erreur");
    assert!(revocation_verifiee(0x0000_0001), "autre erreur seule : du ressort de WinVerifyTrust, pas de cette décision");
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

/// Phase 1 : mesure du cycle de surveillance (condition préalable au découpage de Moniteur). Répartition par
/// classes de durée, cumul et fenêtre alimentés ensemble, PowerShell comptés par contexte.
#[test]
fn phase1_mesure_du_cycle() {
    use crate::mesure::{duree, instantane, powershell, Stat, SEUILS_MS};
    use std::time::Duration;
    let mut s = Stat::default();
    for ms in [0u64, 1, 3, 7, 40, 90, 400, 900, 4000, 9000] {
        s.ajouter(Duration::from_millis(ms));
    }
    assert_eq!(s.nombre, 10);
    assert_eq!(s.repartition, [2, 1, 1, 1, 1, 1, 1, 1, 1], "classes ≤ {SEUILS_MS:?} ms puis au-delà");
    assert_eq!(s.max_ms, 9000.0);
    assert_eq!(s.dernier_ms, 9000.0);
    assert!((s.total_ms - 14441.0).abs() < 0.5);
    let etape = format!("essai.{}", std::process::id());
    duree(&etape, Duration::from_millis(12));
    duree(&etape, Duration::from_millis(30));
    powershell("essai-mesure");
    let (cumul, fenetre) = instantane();
    for m in [&cumul, &fenetre] {
        let st = m.etapes.get(&etape).expect("étape mesurée");
        assert_eq!((st.nombre, st.repartition[3]), (2, 2), "deux mesures entre 10 et 50 ms");
        assert!(m.powershell.get("essai-mesure").copied().unwrap_or(0) >= 1);
    }
}

/// Defender au démarrage du PC : constaté, l'interface affichait « DEFENDER DÉSACTIVÉ » pendant les 10 minutes qui
/// suivent un redémarrage (premier relevé « Not running », Defender pas encore prêt). L'état est relu tant qu'aucun
/// état n'a été publié et que Defender ne répond pas ou se dit « Not running » ; ensuite, plus d'attente.
#[test]
fn defender_relu_au_demarrage_avant_publication() {
    use crate::defender::{relire_avant_publication, EtatDefender};
    let pas_pret = EtatDefender { disponible: true, mode: "Not running".into(), ..Default::default() };
    let normal = EtatDefender { disponible: true, antivirus: true, temps_reel: true, mode: "Normal".into(), ..Default::default() };
    let muet = EtatDefender::default();
    assert!(relire_avant_publication(&pas_pret, false), "« Not running » avant tout état publié : relire");
    assert!(relire_avant_publication(&muet, false), "WMI muet avant tout état publié : relire");
    assert!(!relire_avant_publication(&normal, false), "état normal : publié aussitôt");
    assert!(!relire_avant_publication(&pas_pret, true), "après un état publié : une désactivation est vue aussitôt");
    let desactive = EtatDefender { disponible: true, mode: "Normal".into(), temps_reel: false, ..Default::default() };
    assert!(!relire_avant_publication(&desactive, false), "protection en temps réel coupée (mode Normal) : publiée aussitôt");
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

/// Lot 5 : après un emprunt d'identité ou un privilège activé sur le fil, un retour à l'identité du service
/// impossible (RevertToSelf en échec) arrête le service, dans les deux fonctions qui empruntent
#[test]
fn lot5_retour_a_soi_impossible_arret() {
    use crate::natif::retour_ou_arret;
    let mut arrete = false;
    retour_ou_arret(Err("refusé".to_string()), "essai", |_| arrete = true);
    assert!(arrete, "échec du retour : arrêt");
    let mut arrete = false;
    retour_ou_arret(Ok(()), "essai", |_| arrete = true);
    assert!(!arrete, "retour réussi : pas d'arrêt");
    let natif = include_str!("natif.rs");
    assert!(!natif.contains("let _ = RevertToSelf()"), "un échec de RevertToSelf est ignoré quelque part");
}

/// Lot 5 : en échec de la protection du dossier, aucune réponse automatique alimentée par les fichiers du dossier
/// (listes de menaces, règles IDS) : ni blocage automatique, ni IPS ; hors échec, rien ne change
#[test]
fn lot5_reponses_automatiques_jamais_en_echec_ferme() {
    use crate::ids::blocage_ips;
    use crate::moniteur::blocage_automatique;
    assert!(blocage_automatique(true, true, false, false));
    assert!(!blocage_automatique(true, true, false, true), "échec fermé : pas de blocage automatique");
    assert!(!blocage_automatique(false, true, false, false), "confiance non haute");
    assert!(!blocage_automatique(true, false, false, false), "réglage désactivé");
    assert!(!blocage_automatique(true, true, true, false), "déjà bloquée");
    assert!(blocage_ips(true, true, "drop", 3, true, false));
    assert!(blocage_ips(true, true, "alert", 1, true, false), "priorité 1");
    assert!(!blocage_ips(true, true, "drop", 3, true, true), "échec fermé : pas de blocage IPS");
    assert!(!blocage_ips(false, true, "drop", 3, true, false), "IPS désactivé");
    assert!(!blocage_ips(true, false, "drop", 3, true, false), "adresse non publique");
    assert!(!blocage_ips(true, true, "alert", 2, true, false), "ni drop, ni reject, ni priorité 1");
    assert!(!blocage_ips(true, true, "drop", 3, false, false), "connexion non établie (source usurpable)");
}

/// Lot 5 : les fichiers du dossier de données que le service télécharge lui-même (listes de menaces, règles IDS,
/// LOLDrivers, JA3) et les événements du SIEM sont lus par commun (propriétaire contrôlé), jamais directement
#[test]
fn lot5_lectures_du_dossier_par_commun() {
    for (module, source) in [("menaces.rs", include_str!("menaces.rs")), ("ids.rs", include_str!("ids.rs")),
                             ("dpi.rs", include_str!("dpi.rs")), ("siem.rs", include_str!("siem.rs"))] {
        for interdit in ["fs::read_to_string(", "fs::File::open(", "fs::read("] {
            assert!(!source.contains(interdit), "{module} lit directement ({interdit})");
        }
    }
    let hygiene = include_str!("hygiene.rs");
    let loldrivers = &hygiene[hygiene.find("loldrivers.json").expect("loldrivers.json")..];
    // Fin de la fonction (« \n} » : valable avec des fins de ligne LF comme CRLF)
    let fonction = &loldrivers[..loldrivers.find("\n}").unwrap_or(loldrivers.len())];
    assert!(!fonction.contains("fs::read_to_string("), "hygiene.rs lit loldrivers.json directement");
}

#[test]
fn lot1_lisible_en_echec_liste_d_autorisation() {
    use crate::commun::lisible_en_echec;
    for oui in ["geoip\\afrinic.txt", "GeoIP/ripencc.txt", "alertes.json", "incidents.json", "journal.txt"] {
        assert!(lisible_en_echec(oui), "{oui}");
    }
    for non in ["config.json", "lecteurs.json", "apprentissage.json", "blocages.json", "quarantaine.json",
                "secrets\\notifications.json", "secrets\\leurres-noms.json", "api-jeton.txt", "baseline-sauvegarde.json",
                "executables.json", "extensions-connues.json", "ecoutes-connues.json", "peripheriques-connus.json",
                "geoip\\sous\\x.txt", "geoip\\", "geoip\\x.json", "..\\config.json", "", "alertes.json\\x",
                // Lot 5 : le cache DNS n'est plus lu en échec fermé
                "dns.json"] {
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

// ------------------------------------------------------------ lot 1 bis : quarantaine et mise à l'écart sans perte

fn dossier_test(nom: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("der4tizer-{nom}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// SID du compte du test (propriétaire de ce qu'il crée) et SDDL de quarantaine pour le test : même forme que
/// celle du service, avec le compte du test à la place de SYSTEM (hors élévation, on ne peut pas donner un
/// fichier à SYSTEM)
fn sddl_test(d: &std::path::Path) -> (String, String) {
    let moi = crate::natif::lire_securite(d).unwrap().proprietaire;
    (moi.clone(), format!("O:{moi}D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{moi})"))
}

/// Écriture du manifeste pour les tests : vers un fichier, en échouant à l'appel numéro `echec` (0 : jamais)
struct Manifeste {
    fichier: std::path::PathBuf,
    appels: std::cell::Cell<u32>,
    echec: u32,
}

impl Manifeste {
    fn new(d: &std::path::Path, echec: u32) -> Self {
        Manifeste { fichier: d.join("quarantaine.json"), appels: std::cell::Cell::new(0), echec }
    }
    fn ecrire(&self, l: &[crate::reponse::ElementQuarantaine]) -> Result<(), String> {
        self.appels.set(self.appels.get() + 1);
        if self.appels.get() == self.echec {
            return Err("disque plein (simulé)".into());
        }
        crate::commun::ecrire_dans(&self.fichier, l)
    }
    fn lu(&self) -> Vec<crate::reponse::ElementQuarantaine> {
        serde_json::from_slice(&std::fs::read(&self.fichier).unwrap_or_default()).unwrap_or_default()
    }
}

#[test]
fn lot1bis_quarantaine_redemarrage_restauration() {
    use crate::protection::{trier_element, Tri};
    use crate::reponse::{quarantaine_transaction, EtatQuarantaine, SDDL_QUARANTAINE};
    let d = dossier_test("quarantaine");
    let (moi, sddl) = sddl_test(&d);
    let dq = d.join("quarantaine");
    let origine = d.join("Téléchargements").join("faux-positif.exe");
    std::fs::create_dir_all(origine.parent().unwrap()).unwrap();
    let contenu: Vec<u8> = (0..200_000u32).map(|i| (i * 7 % 251) as u8).collect();
    std::fs::write(&origine, &contenu).unwrap();
    let m = Manifeste::new(&d, 0);
    let mut liste = Vec::new();
    quarantaine_transaction(&dq, &mut liste, &origine, "id1", "test", &sddl, &|l| m.ecrire(l)).unwrap();
    assert!(!origine.exists(), "original retiré");
    assert_eq!(liste[0].etat(), EtatQuarantaine::Terminee);
    assert_eq!(m.lu(), liste, "manifeste enregistré");
    let copie = dq.join(liste[0].nom_fichier());
    // Copie créée par le service avec ses droits : propriétaire celui du SDDL (en service, SYSTEM)
    let s = crate::natif::lire_securite(&copie).unwrap();
    assert_eq!(s.proprietaire, moi);
    assert!(s.protege);
    assert!(SDDL_QUARANTAINE.starts_with("O:SY"), "en service, propriétaire SYSTEM");
    // Redémarrage : une copie à SYSTEM est gardée par le tri
    assert_eq!(trier_element(false, Some(true)), Tri::Garder);
    // Copie modifiée : refus
    let mut altere = contenu.clone();
    altere[10] ^= 1;
    std::fs::write(&copie, &altere).unwrap();
    assert!(restaurer_test(&dq, &mut liste, "id1", &|l| m.ecrire(l)).unwrap_err().contains("modifiée"));
    std::fs::write(&copie, &contenu).unwrap();
    // Emplacement d'origine occupé : refus, rien d'écrasé
    std::fs::write(&origine, b"autre").unwrap();
    assert!(restaurer_test(&dq, &mut liste, "id1", &|l| m.ecrire(l)).is_err());
    assert_eq!(std::fs::read(&origine).unwrap(), b"autre");
    std::fs::remove_file(&origine).unwrap();
    // Restauration : même contenu, copie et entrée retirées
    restaurer_test(&dq, &mut liste, "id1", &|l| m.ecrire(l)).unwrap();
    assert_eq!(std::fs::read(&origine).unwrap(), contenu);
    assert!(!copie.exists() && liste.is_empty() && m.lu().is_empty());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn lot1bis_marque_internet_conservee() {
    use crate::reponse::{lire_marque_internet, migrer_quarantaine, quarantaine_transaction, ElementQuarantaine};
    let d = dossier_test("marque");
    let (_, sddl) = sddl_test(&d);
    let dq = d.join("quarantaine");
    let marque = "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://exemple.invalid/setup.exe\r\n";
    let m = Manifeste::new(&d, 0);
    // Quarantaine puis restauration
    let f = d.join("setup.exe");
    std::fs::write(&f, b"MZ...").unwrap();
    std::fs::write(format!("{}:Zone.Identifier", f.display()), marque).unwrap();
    let mut liste = Vec::new();
    quarantaine_transaction(&dq, &mut liste, &f, "z1", "test", &sddl, &|l| m.ecrire(l)).unwrap();
    assert!(liste[0].zone_identifier.contains("ZoneId=3"));
    restaurer_test(&dq, &mut liste, "z1", &|l| m.ecrire(l)).unwrap();
    assert!(lire_marque_internet(&f).contains("ZoneId=3"), "marque réécrite sur le fichier restauré");
    // Migration d'une ancienne copie (déplacée avec son flux), puis restauration
    std::fs::write(dq.join("ancien.quarantaine"), b"MZ ancien").unwrap();
    std::fs::write(format!("{}:Zone.Identifier", dq.join("ancien.quarantaine").display()), marque).unwrap();
    let g = d.join("ancien.exe");
    let mut liste = vec![ElementQuarantaine { id: "ancien".into(), chemin_origine: g.display().to_string(), ..Default::default() }];
    migrer_quarantaine(&dq, &mut liste, &sddl, |_| Some(false), &|l| m.ecrire(l));
    assert!(liste[0].zone_identifier.contains("ZoneId=3"));
    restaurer_test(&dq, &mut liste, "ancien", &|l| m.ecrire(l)).unwrap();
    assert!(lire_marque_internet(&g).contains("ZoneId=3"));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn lot1bis_ancien_fichier_quarantaine_migre_sans_perte() {
    use crate::reponse::{migrer_quarantaine, ElementQuarantaine};
    let d = dossier_test("migration");
    let (_, sddl) = sddl_test(&d);
    let dq = d.join("quarantaine");
    std::fs::create_dir_all(&dq).unwrap();
    // Avant la 4.3 : déplacé tel quel (propriétaire de l'utilisateur), sans empreinte, nom « <id>.quarantaine »
    std::fs::write(dq.join("ancien.quarantaine"), b"contenu d'origine").unwrap();
    std::fs::write(dq.join("confiance.quarantaine"), b"deja sur").unwrap();
    let origine = d.join("restaure.exe");
    let mut liste = vec![
        ElementQuarantaine { id: "ancien".into(), chemin_origine: origine.display().to_string(), ..Default::default() },
        ElementQuarantaine { id: "confiance".into(), chemin_origine: d.join("x").display().to_string(), ..Default::default() },
        ElementQuarantaine { id: "disparu".into(), chemin_origine: d.join("y").display().to_string(), ..Default::default() },
    ];
    let m = Manifeste::new(&d, 0);
    let messages = migrer_quarantaine(&dq, &mut liste, &sddl, |p| Some(p.ends_with("confiance.quarantaine")), &|l| m.ecrire(l));
    assert_eq!(messages.len(), 2, "{messages:?}");
    assert!(liste[0].fichier.starts_with("ancien-") && liste[0].sha256.len() == 64);
    assert!(!dq.join("ancien.quarantaine").exists());
    // Copies en clair réencodées, propriétaire de confiance ou non : plus rien du contenu en clair
    for e in &liste[..2] {
        let c = dq.join(&e.fichier);
        assert!(crate::reponse::est_encodee(&c), "{}", e.fichier);
        assert!(!contient(&std::fs::read(&c).unwrap(), b"contenu") && !contient(&std::fs::read(&c).unwrap(), b"deja sur"));
    }
    assert!(liste[1].fichier.starts_with("confiance-") && liste[1].sha256.len() == 64);
    assert!(liste[2].sha256.is_empty());
    assert_eq!(m.lu(), liste, "nouvelle copie enregistrée");
    restaurer_test(&dq, &mut liste, "ancien", &|l| m.ecrire(l)).unwrap();
    assert_eq!(std::fs::read(&origine).unwrap(), b"contenu d'origine");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn lot1bis_decision_de_reprise() {
    use crate::reponse::{decision_reprise, EtatQuarantaine::*, Original::*, Reprise};
    // (état, original, copie présente) : toutes les combinaisons
    assert_eq!(decision_reprise(EnCours, Identique, true), Reprise::RetirerCopieEtEntree);
    assert_eq!(decision_reprise(EnCours, Different, true), Reprise::MarquerTerminee, "un autre fichier au même chemin : copie gardée");
    assert_eq!(decision_reprise(EnCours, Absent, true), Reprise::MarquerTerminee);
    assert_eq!(decision_reprise(EnCours, Identique, false), Reprise::RetirerEntree);
    assert_eq!(decision_reprise(EnCours, Different, false), Reprise::RetirerEntree);
    assert!(matches!(decision_reprise(EnCours, Absent, false), Reprise::Signaler(_)));
    for o in [Identique, Different, Absent] {
        assert_eq!(decision_reprise(Terminee, o, true), Reprise::Rien);
        assert!(matches!(decision_reprise(Terminee, o, false), Reprise::Signaler(_)));
    }
    assert_eq!(decision_reprise(Restauree, Identique, true), Reprise::RetirerCopieEtEntree);
    assert_eq!(decision_reprise(Restauree, Different, true), Reprise::RemettreTerminee);
    assert_eq!(decision_reprise(Restauree, Absent, true), Reprise::RemettreTerminee);
    assert_eq!(decision_reprise(Restauree, Identique, false), Reprise::RetirerEntree);
    assert_eq!(decision_reprise(Restauree, Different, false), Reprise::RetirerEntree);
    assert!(matches!(decision_reprise(Restauree, Absent, false), Reprise::Signaler(_)));
}

#[test]
fn lot1bis_echec_du_manifeste_etat_reel_des_fichiers() {
    use crate::reponse::{quarantaine_transaction, reprendre_quarantaine, EtatQuarantaine, ElementQuarantaine};
    use std::os::windows::fs::OpenOptionsExt;
    let d = dossier_test("transaction");
    let (_, sddl) = sddl_test(&d);
    let dq = d.join("quarantaine");
    let copies = || std::fs::read_dir(&dq).map(|l| l.count()).unwrap_or(0);

    // 1. Échec du premier enregistrement (« en_cours ») : copie retirée, original intact, rien d'enregistré
    let f = d.join("a.exe");
    std::fs::write(&f, b"AAA").unwrap();
    let m = Manifeste::new(&d, 1);
    let mut liste = Vec::new();
    assert!(quarantaine_transaction(&dq, &mut liste, &f, "a", "t", &sddl, &|l| m.ecrire(l)).is_err());
    assert_eq!(std::fs::read(&f).unwrap(), b"AAA");
    assert!(liste.is_empty() && copies() == 0 && m.lu().is_empty());

    // 2. Original impossible à supprimer (tenu ouvert) : copie et entrée retirées, original intact
    let m = Manifeste::new(&d, 0);
    {
        let _tenu = std::fs::OpenOptions::new().read(true).share_mode(0x1).open(&f).unwrap();
        assert!(quarantaine_transaction(&dq, &mut liste, &f, "a", "t", &sddl, &|l| m.ecrire(l)).is_err());
    }
    assert_eq!(std::fs::read(&f).unwrap(), b"AAA");
    assert!(liste.is_empty() && copies() == 0 && m.lu().is_empty());

    // 3. Échec du dernier enregistrement (« terminee ») : original supprimé, copie en place, entrée
    //    enregistrée « en_cours » ; la reprise au démarrage la termine
    let m = Manifeste::new(&d, 2);
    quarantaine_transaction(&dq, &mut liste, &f, "a", "t", &sddl, &|l| m.ecrire(l)).unwrap();
    assert!(!f.exists() && copies() == 1);
    let mut lu = m.lu();
    assert_eq!(lu[0].etat(), EtatQuarantaine::EnCours);
    reprendre_quarantaine(&dq, &mut lu);
    assert_eq!(lu[0].etat(), EtatQuarantaine::Terminee);
    let mut liste = lu;

    // 3 bis. « en_cours », original remplacé par un autre fichier au même chemin : la copie est gardée
    let mut autre_fichier = liste.clone();
    autre_fichier[0].etat = "en_cours".into();
    std::fs::write(&f, b"un autre fichier").unwrap();
    reprendre_quarantaine(&dq, &mut autre_fichier);
    assert_eq!(autre_fichier[0].etat(), EtatQuarantaine::Terminee);
    assert!(copies() == 1, "copie gardée");
    std::fs::remove_file(&f).unwrap();

    // 4. Restauration, échec de l'enregistrement « restauree » : fichier restauré retiré, copie et entrée intactes
    let m = Manifeste::new(&d, 1);
    assert!(restaurer_test(&dq, &mut liste, "a", &|l| m.ecrire(l)).is_err());
    assert!(!f.exists() && copies() == 1 && liste[0].etat() == EtatQuarantaine::Terminee);

    // 5. Dossier d'origine impossible à créer (un fichier à sa place) : erreur avant toute copie
    let bloque = d.join("bloque");
    std::fs::write(&bloque, b"").unwrap();
    let mut autre = liste.clone();
    autre[0].chemin_origine = bloque.join("sous").join("a.exe").display().to_string();
    let m = Manifeste::new(&d, 0);
    assert!(restaurer_test(&dq, &mut autre, "a", &|l| m.ecrire(l)).unwrap_err().contains("dossier d'origine"));
    assert!(copies() == 1 && m.appels.get() == 0, "rien de copié ni d'enregistré");

    // 6. Restauration interrompue après l'enregistrement « restauree » : la reprise retire la copie et l'entrée
    let m = Manifeste::new(&d, 2);
    restaurer_test(&dq, &mut liste, "a", &|l| m.ecrire(l)).unwrap();
    assert_eq!(std::fs::read(&f).unwrap(), b"AAA");
    let mut lu = m.lu();
    assert_eq!(lu[0].etat(), EtatQuarantaine::Restauree);
    std::fs::write(dq.join(lu[0].nom_fichier()), b"AAA").unwrap(); // copie encore présente (retrait raté)
    reprendre_quarantaine(&dq, &mut lu);
    assert!(lu.is_empty() && copies() == 0);

    // 7. Copie orpheline (sans entrée) : signalée et conservée
    std::fs::write(dq.join("orpheline.quarantaine"), b"x").unwrap();
    let mut vide: Vec<ElementQuarantaine> = Vec::new();
    let messages = reprendre_quarantaine(&dq, &mut vide);
    assert!(messages.iter().any(|m| m.contains("orpheline")) && dq.join("orpheline.quarantaine").exists());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn lot1bis_migration_echec_du_manifeste_ancienne_copie_gardee() {
    use crate::reponse::{migrer_quarantaine, ElementQuarantaine};
    let d = dossier_test("migration-echec");
    let (_, sddl) = sddl_test(&d);
    let dq = d.join("quarantaine");
    std::fs::create_dir_all(&dq).unwrap();
    std::fs::write(dq.join("ancien.quarantaine"), b"precieux").unwrap();
    let mut liste = vec![ElementQuarantaine { id: "ancien".into(), chemin_origine: d.join("x").display().to_string(), ..Default::default() }];
    let avant = liste.clone();
    let m = Manifeste::new(&d, 1);
    let messages = migrer_quarantaine(&dq, &mut liste, &sddl, |_| Some(false), &|l| m.ecrire(l));
    assert!(messages[0].contains("NON migrée"), "{messages:?}");
    assert_eq!(liste, avant, "entrée inchangée");
    assert_eq!(std::fs::read(dq.join("ancien.quarantaine")).unwrap(), b"precieux", "ancienne copie gardée");
    assert_eq!(std::fs::read_dir(&dq).unwrap().count(), 1, "nouvelle copie retirée");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn lot1bis_deplacement_impossible_intact_et_echec_ferme() {
    use std::os::windows::fs::OpenOptionsExt;
    let d = dossier_test("intact");
    let f = d.join("config.json");
    std::fs::write(&f, b"{\"piege\":1}").unwrap();
    let mut ecartes = Vec::new();
    {
        // Tenu ouvert sans partage de suppression ; propriétaire déclaré non vérifié (à écarter)
        let _tenu = std::fs::OpenOptions::new().read(true).share_mode(0x1).open(&f).unwrap();
        crate::protection::trier_avec(&d, &d, &d.join("ecartes"), &mut ecartes, &|_| Some(false));
    }
    assert!(ecartes.iter().any(|e| e.starts_with("config.json") && e.contains("IMPOSSIBLE")), "{ecartes:?}");
    assert_eq!(std::fs::read(&f).unwrap(), b"{\"piege\":1}", "jamais supprimé");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn lot1bis_creation_de_ecartes_impossible_intact_et_echec_ferme() {
    let d = dossier_test("sans-ecartes");
    let f = d.join("apprentissage.json");
    std::fs::write(&f, b"[]").unwrap();
    let mut ecartes = Vec::new();
    // Dossier de mise à l'écart impossible à créer (parent absent)
    crate::protection::trier_avec(&d, &d, &d.join("absent").join("ecartes"), &mut ecartes, &|_| Some(false));
    assert!(ecartes.iter().any(|e| e.starts_with("apprentissage.json") && e.contains("IMPOSSIBLE")), "{ecartes:?}");
    assert_eq!(std::fs::read(&f).unwrap(), b"[]", "jamais supprimé");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn lot1bis_ecartes_suspect_mis_de_cote_sans_suppression() {
    let d = dossier_test("ecartes-suspect");
    let q = d.join("ecartes");
    std::fs::create_dir_all(&q).unwrap();
    std::fs::write(q.join("piece.json"), b"garde").unwrap();
    // Propriétaire déclaré non vérifié : ecartes est mis de côté
    crate::protection::preparer_quarantaine_avec(&q, &|_| Some(false)).unwrap();
    assert!(!q.exists());
    let suspect = std::fs::read_dir(&d).unwrap().flatten().find(|e| e.file_name().to_string_lossy().starts_with("ecartes-suspect-")).unwrap().path();
    assert_eq!(std::fs::read(suspect.join("piece.json")).unwrap(), b"garde", "contenu conservé");
    let _ = std::fs::remove_dir_all(&d);
}

fn contient(foin: &[u8], aiguille: &[u8]) -> bool {
    foin.windows(aiguille.len()).any(|w| w == aiguille)
}

/// Chaîne de test EICAR (68 octets), reconstituée en mémoire à partir d'octets décalés de +1 : elle ne figure
/// ni dans ce source ni dans le binaire de test (Defender supprimerait l'un ou l'autre), et n'est jamais
/// écrite sur le disque
fn eicar() -> Vec<u8> {
    const DECALES: &[u8] = &[89, 54, 80, 34, 81, 38, 65, 66, 81, 92, 53, 93, 81, 91, 89, 54, 53, 41, 81, 95, 42, 56, 68, 68, 42, 56,
        126, 37, 70, 74, 68, 66, 83, 46, 84, 85, 66, 79, 69, 66, 83, 69, 46, 66, 79, 85, 74, 87, 74, 83, 86, 84, 46, 85, 70, 84, 85,
        46, 71, 74, 77, 70, 34, 37, 73, 44, 73, 43];
    DECALES.iter().map(|o| o - 1).collect()
}

#[test]
fn lot1bis_copie_encodee_jamais_en_clair() {
    use crate::reponse::{encoder_flux, entete_encodage, est_encodee, nonce_de, quarantaine_transaction};
    // En mémoire : la chaîne EICAR encodée ne contient plus la chaîne, ni aucun de ses motifs de 8 octets
    let e = eicar();
    assert_eq!(e.len(), 68);
    let nonce = nonce_de("test.quarantaine");
    let mut encode = e.clone();
    encoder_flux(&nonce, 0, &mut encode);
    for w in e.windows(8) {
        assert!(!contient(&encode, w), "motif {:?}", String::from_utf8_lossy(w));
    }
    let mut decode = encode.clone();
    encoder_flux(&nonce, 0, &mut decode);
    assert_eq!(decode, e, "réversible");
    // Encodage par morceaux (positions) identique à l'encodage d'un seul tenant
    let mut morceaux = e.clone();
    let (a, b) = morceaux.split_at_mut(13);
    encoder_flux(&nonce, 0, a);
    encoder_flux(&nonce, 13, b);
    assert_eq!(morceaux, encode);
    assert_eq!(entete_encodage(&nonce).len(), 21);

    // Sur le disque : contenu très répétitif (le pire cas pour un XOR à clé courte), mis en quarantaine
    let d = dossier_test("encodage");
    let (_, sddl) = sddl_test(&d);
    let dq = d.join("quarantaine");
    let f = d.join("journal.txt");
    let contenu: Vec<u8> = b"ligne de test deR4Tizer, identique a chaque fois : 0123456789\r\n".repeat(3000);
    std::fs::write(&f, &contenu).unwrap();
    let m = Manifeste::new(&d, 0);
    let mut liste = Vec::new();
    quarantaine_transaction(&dq, &mut liste, &f, "enc", "test", &sddl, &|l| m.ecrire(l)).unwrap();
    let chemin_copie = dq.join(liste[0].nom_fichier());
    let copie = std::fs::read(&chemin_copie).unwrap();
    assert!(est_encodee(&chemin_copie) && copie.starts_with(b"D4TQ"));
    for motif in [&b"ligne de test"[..], b"deR4Tizer", b"0123456789"] {
        assert!(!contient(&copie, motif), "motif en clair : {}", String::from_utf8_lossy(motif));
    }
    // Aucune fenêtre de 16 octets du contenu d'origine ne se retrouve dans la copie
    let fenetres: std::collections::HashSet<&[u8]> = contenu.windows(16).collect();
    assert!(!copie.windows(16).any(|w| fenetres.contains(w)));
    // Restauration identique à l'octet
    restaurer_test(&dq, &mut liste, "enc", &|l| m.ecrire(l)).unwrap();
    assert_eq!(std::fs::read(&f).unwrap(), contenu);
    let _ = std::fs::remove_dir_all(&d);
}

// ------------------------------------------------------------ lot 1 ter : opérations SYSTEM sur des chemins de l'utilisateur

/// Restauration de test à l'emplacement d'origine de l'entrée, avec la création sans lien (en service, la
/// même création se fait sous l'identité du propriétaire)
fn restaurer_test(dq: &std::path::Path, liste: &mut Vec<crate::reponse::ElementQuarantaine>, id: &str,
                  ecrire: crate::reponse::EcrireManifeste) -> Result<String, String> {
    let cible = std::path::PathBuf::from(&liste.iter().find(|e| e.id == id).ok_or("élément introuvable")?.chemin_origine);
    crate::reponse::restaurer_transaction(dq, liste, id, &cible, &crate::reponse::creer_sans_lien, ecrire)
}

/// Jonction (pas besoin d'élévation) `lien` → `cible`
fn jonction(lien: &std::path::Path, cible: &std::path::Path) {
    let s = std::process::Command::new("cmd").args(["/c", "mklink", "/J"]).arg(lien).arg(cible).output().unwrap();
    assert!(s.status.success(), "mklink /J : {}", String::from_utf8_lossy(&s.stderr));
}

/// Revue de sécurité : les leurres sont posés, lus et retirés dans les dossiers de l'utilisateur, qu'il contrôle.
/// Tout passe par un handle ouvert sans suivre de lien, chemin final vérifié : un dossier du profil remplacé par
/// une jonction vers un autre dossier (canari) est refusé, et rien n'y est créé, lu ni supprimé
#[test]
fn leurres_par_handle_jamais_a_travers_un_lien() {
    use crate::hygiene::{creer_leurre, empreinte_verifiee, retirer_leurre};
    let d = dossier_test("leurres-liens");
    let canari = d.join("canari");
    std::fs::create_dir_all(&canari).unwrap();
    std::fs::write(canari.join("0 Factures 1234.docx"), b"fichier du canari").unwrap();
    let avant = contenu_dossier(&canari);
    // Profil piégé : Documents est une jonction vers le canari
    let piege = d.join("piege");
    std::fs::create_dir_all(&piege).unwrap();
    jonction(&piege.join("Documents"), &canari);
    let par_le_lien = piege.join("Documents").join("0 Factures 1234.docx");
    assert!(!retirer_leurre(&par_le_lien), "retrait à travers une jonction : refusé");
    assert!(creer_leurre(&piege.join("Documents").join("0 Nouveau 5678.docx")).is_err(), "création à travers une jonction : refusée");
    assert!(empreinte_verifiee(&par_le_lien).is_none(), "lecture à travers une jonction : refusée");
    assert_eq!(contenu_dossier(&canari), avant, "canari modifié");
    assert_eq!(std::fs::read(canari.join("0 Factures 1234.docx")).unwrap(), b"fichier du canari");
    // Témoin : vrai dossier, tout fonctionne
    let vrai = d.join("vrai").join("Documents");
    std::fs::create_dir_all(&vrai).unwrap();
    let f = vrai.join("0 Contrat 4321.docx");
    creer_leurre(&f).unwrap();
    use std::os::windows::fs::MetadataExt;
    let attributs = std::fs::metadata(&f).unwrap().file_attributes();
    assert_eq!(attributs & 0x6, 0x6, "leurre caché et système");
    assert_eq!(empreinte_verifiee(&f), crate::hygiene::empreinte_fichier(&f), "empreinte lue par le handle vérifié");
    assert!(creer_leurre(&f).is_err(), "un leurre existant n'est jamais écrasé");
    assert!(retirer_leurre(&f) && !f.exists(), "retrait du vrai leurre");
    let _ = std::fs::remove_dir(piege.join("Documents"));
    let _ = std::fs::remove_dir_all(&d);
}

/// Revue de sécurité : plus aucune opération par chemin sur les leurres (suppression, écriture, attributs, audit
/// posé par PowerShell), ni dans hygiene.rs ni au nettoyage de la désinstallation ; profils lus dans ProfileList
#[test]
fn leurres_aucune_operation_par_chemin() {
    let hygiene = include_str!("hygiene.rs");
    let debut = hygiene.find("// ------------------------------------------------------------ leurres").unwrap_or(0);
    let fin = hygiene.find("// ------------------------------------------------------------ pilotes").unwrap_or(hygiene.len());
    let leurres = &hygiene[debut..fin];
    for interdit in ["fs::write(", "attrib.exe", "Set-Acl", "Get-Acl", ".exists()"] {
        assert!(!leurres.contains(interdit), "hygiene.rs (leurres) : opération par chemin {interdit}");
    }
    // Suppression par chemin admise seulement dans le dossier de données (protégé), jamais dans un profil
    for (i, _) in leurres.match_indices("fs::remove_file(") {
        assert!(leurres[i..].starts_with("fs::remove_file(commun::dossier()"), "hygiene.rs (leurres) : suppression par chemin hors du dossier de données");
    }
    let modeles = &hygiene[hygiene.find("fn retirer_leurres_modeles").unwrap()..debut];
    assert!(!modeles.contains("fs::remove_file(") && !modeles.contains("attrib.exe"), "profils modèles : retrait par chemin");
    let moniteur = include_str!("moniteur.rs");
    assert!(!moniteur.contains("fs::remove_file(&l.chemin)"), "nettoyage : retrait par chemin");
    assert_eq!(crate::hygiene::chemin_image_profil(r"%SystemDrive%\Users\marie", "C:"), std::path::PathBuf::from(r"C:\Users\marie"));
    assert_eq!(crate::hygiene::chemin_image_profil(r"D:\Profils\paul", "C:"), std::path::PathBuf::from(r"D:\Profils\paul"));
}

fn contenu_dossier(d: &std::path::Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(d).map(|l| l.flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect()).unwrap_or_default();
    v.sort();
    v
}

#[test]
fn lot1ter_meme_chemin_et_chemin_final() {
    use crate::natif::{chemin_final, forme_longue, meme_chemin, ouvrir_verifie, ErreurOuverture};
    assert!(meme_chemin(r"\\?\C:\Users\Marie\x.txt", r"c:\users\marie\X.TXT"));
    assert!(meme_chemin(r"\\?\UNC\serveur\partage\x", r"\\serveur\partage\x\"));
    assert!(meme_chemin("C:/a/b", r"C:\a\b"));
    assert!(!meme_chemin(r"C:\a\b", r"C:\a\bc"));
    assert!(!meme_chemin("", ""));
    assert!(!meme_chemin(r"\\?\C:\Windows\System32\x", r"C:\Users\x"));
    let d = dossier_test("chemin-final");
    let f = d.join("a.txt");
    std::fs::write(&f, b"a").unwrap();
    let h = ouvrir_verifie(&f, 0x8000_0000 | 0x0010_0000, 0x7, false).unwrap();
    // Le dossier temporaire peut lui-même être désigné en noms courts (CI) : comparaison avec la forme longue
    assert!(meme_chemin(&chemin_final(&h).unwrap(), &forme_longue(&f).to_string_lossy()));
    assert_eq!(ouvrir_verifie(&d.join("absent.txt"), 0x8000_0000, 0x7, false).unwrap_err(), ErreurOuverture::Absent);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn lot1ter_jonction_avant_restauration() {
    use crate::reponse::{creer_sans_lien, quarantaine_transaction};
    let d = dossier_test("jonction-restauration");
    let (_, sddl) = sddl_test(&d);
    let dq = d.join("quarantaine");
    let origine = d.join("Documents");
    let systeme = d.join("systeme"); // tient lieu de dossier système
    std::fs::create_dir_all(&origine).unwrap();
    std::fs::create_dir_all(&systeme).unwrap();
    let f = origine.join("pilote.dll");
    std::fs::write(&f, b"contenu").unwrap();
    let m = Manifeste::new(&d, 0);
    let mut liste = Vec::new();
    quarantaine_transaction(&dq, &mut liste, &f, "j1", "test", &sddl, &|l| m.ecrire(l)).unwrap();
    // Avant la restauration, Documents est remplacé par une jonction vers le dossier « système »
    std::fs::remove_dir(&origine).unwrap();
    jonction(&origine, &systeme);
    let r = restaurer_test(&dq, &mut liste, "j1", &|l| m.ecrire(l));
    assert!(r.unwrap_err().contains("lien"), "restauration refusée");
    assert!(contenu_dossier(&systeme).is_empty(), "rien d'écrit hors du dossier d'origine");
    assert_eq!(liste.len(), 1, "copie et entrée intactes");
    // Même sans le contrôle préalable (jonction posée juste après lui) : création détournée détectée par le
    // chemin final, fichier créé supprimé par son handle
    assert!(crate::natif::creer_verifie(&f).is_err());
    assert!(contenu_dossier(&systeme).is_empty(), "fichier détourné retiré");
    assert!(creer_sans_lien(&f).is_err());
    std::fs::remove_dir(&origine).unwrap(); // retire la jonction, pas sa cible
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn lot1ter_jonction_pendant_la_quarantaine() {
    use crate::reponse::quarantaine_transaction;
    let d = dossier_test("jonction-quarantaine");
    let (_, sddl) = sddl_test(&d);
    let dq = d.join("quarantaine");
    let telechargements = d.join("Telechargements");
    let systeme = d.join("systeme");
    std::fs::create_dir_all(&systeme).unwrap();
    std::fs::write(systeme.join("setup.exe"), b"fichier systeme").unwrap();
    // Entre le contrôle (chemin demandé dans Téléchargements) et l'opération, le dossier devient une jonction
    jonction(&telechargements, &systeme);
    let m = Manifeste::new(&d, 0);
    let mut liste = Vec::new();
    let r = quarantaine_transaction(&dq, &mut liste, &telechargements.join("setup.exe"), "q1", "test", &sddl, &|l| m.ecrire(l));
    assert!(r.unwrap_err().contains("ailleurs"), "chemin final différent : refus");
    assert_eq!(std::fs::read(systeme.join("setup.exe")).unwrap(), b"fichier systeme", "rien de supprimé");
    assert!(contenu_dossier(&dq).is_empty() && liste.is_empty(), "rien de lu ni de copié");
    // Le dernier élément lui-même est une jonction : refus aussi
    let r = quarantaine_transaction(&dq, &mut liste, &telechargements, "q2", "test", &sddl, &|l| m.ecrire(l));
    assert!(r.is_err());
    std::fs::remove_dir(&telechargements).unwrap();
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn lot1ter_lien_dans_le_chemin_au_demarrage() {
    use crate::reponse::{etat_original, Original};
    let d = dossier_test("jonction-reprise");
    let systeme = d.join("systeme");
    std::fs::create_dir_all(&systeme).unwrap();
    std::fs::write(systeme.join("x.txt"), b"meme contenu").unwrap();
    let sha = crate::hygiene::empreinte_fichier(&systeme.join("x.txt")).unwrap();
    assert_eq!(etat_original(&systeme.join("x.txt"), &sha), Original::Identique);
    // Même contenu, mais atteint par une jonction : « différent », la copie sera gardée
    let lien = d.join("lien");
    jonction(&lien, &systeme);
    assert_eq!(etat_original(&lien.join("x.txt"), &sha), Original::Different);
    assert_eq!(etat_original(&lien, &sha), Original::Different, "le chemin est lui-même un lien");
    assert_eq!(etat_original(&d.join("absent.txt"), &sha), Original::Absent);
    std::fs::remove_dir(&lien).unwrap();
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn lot1ter_restauration_sans_session_jamais_en_system() {
    use crate::reponse::{cible_restauration, CibleRestauration};
    let utilisateur = "S-1-5-21-1-2-3-1001";
    assert_eq!(cible_restauration(Some(utilisateur), true), CibleRestauration::Origine);
    assert!(matches!(cible_restauration(Some(utilisateur), false), CibleRestauration::Repli(_)), "pas de session : repli");
    for systeme in ["S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"] {
        assert!(matches!(cible_restauration(Some(systeme), true), CibleRestauration::Repli(_)), "{systeme}");
    }
    assert!(matches!(cible_restauration(None, true), CibleRestauration::Repli(_)));
    // Emprunt du jeton d'un compte sans session : erreur, et l'opération n'est pas exécutée
    let mut execute = false;
    assert!(crate::natif::avec_jeton_de(utilisateur, || execute = true).is_err());
    assert!(!execute);
}


/// Forme courte (8.3) d'un chemin existant, si le volume en crée
fn forme_courte(p: &std::path::Path) -> Option<std::path::PathBuf> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::GetShortPathNameW;
    let n: Vec<u16> = p.to_string_lossy().encode_utf16().chain(Some(0)).collect();
    let mut t = vec![0u16; 1024];
    let l = unsafe { GetShortPathNameW(PCWSTR(n.as_ptr()), Some(&mut t)) } as usize;
    (l > 0 && l < t.len()).then(|| std::path::PathBuf::from(String::from_utf16_lossy(&t[..l])))
}

#[test]
fn lot1ter_chemin_en_noms_courts_accepte() {
    // CI : le dossier temporaire est atteint par un nom court (C:\Users\RUNNER~1\…) alors que Windows rend le
    // chemin final en noms longs ; un chemin légitime ne doit pas être pris pour un détournement
    use crate::natif::{creer_verifie, forme_longue, meme_chemin, ouvrir_verifie};
    use crate::reponse::{etat_original, Original};
    let d = dossier_test("noms-courts");
    let long = d.join("un dossier au nom vraiment long");
    std::fs::create_dir_all(&long).unwrap();
    let f = long.join("fichier au nom tres long.txt");
    std::fs::write(&f, b"contenu").unwrap();
    let sha = crate::hygiene::empreinte_fichier(&f).unwrap();
    // Le dossier temporaire peut lui-même être désigné en noms courts (CI) : références en forme longue
    let f_long = forme_longue(&f);
    assert!(!f_long.to_string_lossy().contains('~'), "{}", f_long.display());
    match forme_courte(&f).filter(|c| !meme_chemin(&c.to_string_lossy(), &f_long.to_string_lossy())) {
        Some(court) => {
            assert!(meme_chemin(&forme_longue(&court).to_string_lossy(), &f_long.to_string_lossy()), "{}", court.display());
            assert!(ouvrir_verifie(&court, 0x8000_0000 | 0x0010_0000, 0x7, false).is_ok(), "{}", court.display());
            assert_eq!(etat_original(&court, &sha), Original::Identique);
            // Fichier à créer dans un dossier désigné par son nom court
            let dossier_court = forme_courte(&long).unwrap();
            let nouveau = dossier_court.join("nouveau.txt");
            assert!(creer_verifie(&nouveau).is_ok(), "{}", nouveau.display());
            assert!(long.join("nouveau.txt").exists());
        }
        None => eprintln!("noms courts 8.3 désactivés sur ce volume : cas de la CI non reproductible ici"),
    }
    let _ = std::fs::remove_dir_all(&d);
}

// ------------------------------------------------------------ lot 1 ter, revue de la PR 5

#[test]
fn lot1ter_reinitialisation_garde_les_droits_poses_a_la_creation() {
    use crate::natif::{copier_protege, creer_dossier_protege, lire_securite};
    use crate::protection::{icacls, proprietaire_acceptable, reinitialiser_contenu};
    let d = dossier_test("reinitialisation");
    let (moi, _) = sddl_test(&d);
    // Racine : droit de lecture hérité pour Utilisateurs (tient lieu des comptes autorisés)
    assert!(icacls(&[&d.to_string_lossy(), "/grant", "*S-1-5-32-545:(OI)(CI)RX"]));
    let q = d.join("quarantaine");
    std::fs::create_dir_all(&q).unwrap();
    let source = d.join("source.bin");
    std::fs::write(&source, b"contenu").unwrap();
    let copie = q.join("x.quarantaine");
    copier_protege(&source, &copie, &format!("O:{moi}D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{moi})")).unwrap();
    std::fs::create_dir_all(d.join("restaurations")).unwrap();
    let repli = d.join("restaurations").join("id1");
    assert!(creer_dossier_protege(&repli, &format!("O:{moi}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{moi})(A;OICI;0x1200a9;;;S-1-5-32-546)")));
    let ordinaire = d.join("ordinaire.json");
    std::fs::write(&ordinaire, b"{}").unwrap();
    assert!(icacls(&[&ordinaire.to_string_lossy(), "/grant", "*S-1-5-11:F"]));
    // DACL protégée et propriétaire de confiance, mais Utilisateurs authentifiés peut y écrire : pas gardé
    let ecrivable = d.join("protege-mais-ecrivable.json");
    copier_protege(&source, &ecrivable, &format!("O:{moi}D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{moi})(A;;0x1301bf;;;S-1-5-11)")).unwrap();
    // En service, la règle est « propriétaire SYSTEM ou Administrateurs » ; ici le compte du test en tient lieu
    reinitialiser_contenu(&d, &|o: &str| o == moi || proprietaire_acceptable(o));
    let s = lire_securite(&copie).unwrap();
    assert!(s.protege, "copie de quarantaine : héritage toujours coupé");
    assert!(!s.aces.iter().any(|a| a.sid == "S-1-5-32-545"), "aucun droit hérité ajouté : {:?}", s.aces);
    let s = lire_securite(&repli).unwrap();
    assert!(s.protege && s.aces.iter().any(|a| a.sid == "S-1-5-32-546"), "dossier de repli : lecteur conservé {:?}", s.aces);
    let s = lire_securite(&ordinaire).unwrap();
    assert!(!s.aces.iter().any(|a| a.sid == "S-1-5-11"), "élément ordinaire : entrée explicite retirée {:?}", s.aces);
    assert!(s.aces.iter().any(|a| a.sid == "S-1-5-32-545"), "élément ordinaire : droits hérités du dossier");
    let s = lire_securite(&ecrivable).unwrap();
    assert!(!s.aces.iter().any(|a| a.sid == "S-1-5-11"), "écriture d'un autre compte : réinitialisé {:?}", s.aces);
    assert!(!s.protege && s.aces.iter().any(|a| a.sid == "S-1-5-32-545"));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn lot1ter_dossier_de_repli_verifie() {
    use crate::natif::lire_securite;
    use crate::protection::{droits_conformes_pour, SID_ADMINISTRATEURS as BA, SID_SYSTEME as SY};
    use crate::reponse::preparer_dossier_repli;
    let d = dossier_test("repli");
    let (moi, _) = sddl_test(&d);
    let lecteur = "S-1-5-32-546";
    let sddl = format!("O:{moi}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{moi})(A;OICI;0x1200a9;;;{lecteur})");
    let conforme = |s: &crate::natif::Securite| droits_conformes_pour(s, &|o: &str| o == moi, &[SY, BA, moi.as_str()], &[lecteur]);
    let base = d.join("restaurations");
    // Création normale
    let r = preparer_dossier_repli(&base, "a1", &sddl, false, &conforme).unwrap();
    assert!(conforme(&lire_securite(&r).unwrap()).is_ok());
    // Sous-dossier préexistant aux droits incorrects (hérités, sans le lecteur) : droits réimposés puis relus
    std::fs::create_dir_all(base.join("a2")).unwrap();
    assert!(conforme(&lire_securite(&base.join("a2")).unwrap()).is_err());
    let r = preparer_dossier_repli(&base, "a2", &sddl, false, &conforme).unwrap();
    let s = lire_securite(&r).unwrap();
    assert!(s.protege && s.aces.iter().any(|a| a.sid == lecteur), "{:?}", s.aces);
    // Sous-dossier remplacé par une jonction (vers un dossier « système ») : refus
    let systeme = d.join("systeme");
    std::fs::create_dir_all(&systeme).unwrap();
    jonction(&base.join("a3"), &systeme);
    assert!(preparer_dossier_repli(&base, "a3", &sddl, false, &conforme).unwrap_err().contains("lien"));
    std::fs::remove_dir(base.join("a3")).unwrap();
    // Dossier restaurations lui-même remplacé par une jonction : refus
    let base2 = d.join("restaurations2");
    jonction(&base2, &systeme);
    assert!(preparer_dossier_repli(&base2, "a4", &sddl, false, &conforme).is_err());
    assert!(contenu_dossier(&systeme).is_empty(), "rien de créé dans la cible de la jonction");
    std::fs::remove_dir(&base2).unwrap();
    // Protection du dossier de données en échec : refus
    assert!(preparer_dossier_repli(&base, "a5", &sddl, true, &conforme).unwrap_err().contains("échec"));
    assert!(!base.join("a5").exists());
    // Dossier restaurations impossible à créer (parent absent) : erreur, pas ignorée
    assert!(preparer_dossier_repli(&d.join("absent").join("restaurations"), "a6", &sddl, false, &conforme).is_err());
    // Identifiant qui sortirait du dossier : refus
    assert!(preparer_dossier_repli(&base, r"..\x", &sddl, false, &conforme).is_err());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn lot1ter_garder_tel_quel_sans_ecriture_etrangere() {
    use crate::protection::{a_garder_tel_quel, proprietaire_acceptable, SID_ADMINISTRATEURS as BA, SID_SYSTEME as SY};
    let ok = |s: &crate::natif::Securite| a_garder_tel_quel(s, &proprietaire_acceptable);
    let lecteur = "S-1-5-21-1-2-3-1001";
    // Copie de quarantaine, secrets, jeton : SYSTEM et Administrateurs seulement
    assert!(ok(&securite(SY, true, &[(true, 0x1f01ff, SY), (true, 0x1f01ff, BA)])));
    // Dossier de repli : lecteur en lecture seule
    assert!(ok(&securite(SY, true, &[(true, 0x1f01ff, SY), (true, 0x1f01ff, BA), (true, 0x1200a9, lecteur)])));
    // Un autre compte avec un droit d'écriture, quel qu'il soit : réinitialisé
    for ecriture in [0x2u32, 0x4, 0x10, 0x40, 0x100, 0x1_0000, 0x4_0000, 0x8_0000, 0x0200_0000, 0x1000_0000, 0x4000_0000] {
        assert!(!ok(&securite(SY, true, &[(true, 0x1f01ff, SY), (true, 0x1200a9 | ecriture, lecteur)])), "droit {ecriture:#x}");
    }
    assert!(!ok(&securite(SY, true, &[(true, 0x1f01ff, "S-1-1-0")])), "Tout le monde en contrôle total");
    // Un refus explicite ne compte pas comme un droit
    assert!(ok(&securite(SY, true, &[(false, 0x1f01ff, "S-1-1-0"), (true, 0x1f01ff, SY)])));
    // Héritage actif, propriétaire étranger, entrée inconnue : réinitialisé
    assert!(!ok(&securite(SY, false, &[(true, 0x1f01ff, SY)])));
    assert!(!ok(&securite(lecteur, true, &[(true, 0x1f01ff, SY)])));
    let mut inconnue = securite(SY, true, &[(true, 0x1f01ff, SY)]);
    inconnue.ace_inconnue = true;
    assert!(!ok(&inconnue));
}

// ------------------------------------------------------------ lot 2 : mise à jour, version lue dans le paquet signé

fn manifeste_json(version: &str, fichiers: &[(&str, &str, &str)]) -> Vec<u8> {
    let f: Vec<String> = fichiers.iter().map(|(n, u, h)| format!(r#"{{"Nom":"{n}","Url":"{u}","Sha256":"{h}"}}"#)).collect();
    format!(r#"{{"Version":"{version}","Fichiers":[{}]}}"#, f.join(",")).into_bytes()
}

#[test]
fn lot2_manifeste_strict() {
    use crate::maj::lire_manifeste;
    let h = "ab".repeat(32);
    let url = "https://github.com/cryptobones-1337/deR4Tizer/releases/download/v4.4/deR4Tizer.msi";
    let m = lire_manifeste(&manifeste_json("4.4", &[("deR4Tizer.msi", url, &h)])).unwrap();
    assert_eq!(m.version, "4.4");
    let mut bom = "\u{feff}".as_bytes().to_vec();
    bom.extend(manifeste_json("4.4", &[("deR4Tizer.msi", url, &h)]));
    assert!(lire_manifeste(&bom).is_ok(), "BOM UTF-8 accepté");
    let refus = |octets: Vec<u8>, attendu: &str| {
        let e = lire_manifeste(&octets).unwrap_err();
        assert!(e.contains(attendu), "{e}");
    };
    // Fichier manquant, en double, inattendu
    refus(manifeste_json("4.4", &[]), "absent");
    refus(manifeste_json("4.4", &[("deR4Tizer.msi", url, &h), ("deR4Tizer.msi", url, &h)]), "double");
    refus(manifeste_json("4.4", &[("deR4Tizer.msi", url, &h), ("deR4TizerSvc.exe", url, &h)]), "inattendu");
    refus(manifeste_json("4.4", &[("autre.msi", url, &h)]), "inattendu");
    // Champs inconnus ou manquants, version, empreinte, adresse
    refus(br#"{"Version":"4.4","Fichiers":[],"Clef":"x"}"#.to_vec(), "invalide");
    refus(format!(r#"{{"Version":"4.4","Fichiers":[{{"Nom":"deR4Tizer.msi","Url":"{url}","Sha256":"{h}","Taille":1}}]}}"#).into_bytes(), "invalide");
    refus(format!(r#"{{"Version":"4.4","Fichiers":[{{"Nom":"deR4Tizer.msi","Url":"{url}"}}]}}"#).into_bytes(), "invalide");
    refus(manifeste_json("99.0-beta", &[("deR4Tizer.msi", url, &h)]), "version");
    refus(manifeste_json("4..4", &[("deR4Tizer.msi", url, &h)]), "version");
    refus(manifeste_json("4.4", &[("deR4Tizer.msi", url, "abc")]), "empreinte");
    refus(manifeste_json("4.4", &[("deR4Tizer.msi", "http://exemple.invalid/x.msi", &h)]), "adresse");
    refus(manifeste_json("4.4", &[("deR4Tizer.msi", "https://exemple.invalid/a b.msi", &h)]), "adresse");
    // Taille bornée
    let mut gros = manifeste_json("4.4", &[("deR4Tizer.msi", url, &h)]);
    gros.extend(std::iter::repeat_n(b' ', 70_000));
    refus(gros, "trop gros");
    refus(vec![0xff, 0xfe, 0x00], "UTF-8");
    // Mini-fuzz : jamais de panique
    torturer(&manifeste_json("4.4", &[("deR4Tizer.msi", url, &h)]), &mut |d| {
        let _ = lire_manifeste(d);
    });
}

#[test]
fn lot2_decision_installation() {
    use crate::maj::{cles_epinglees, decision_installation, lire_manifeste, meme_version, Artefact, UPGRADE_CODE};
    let h = "ab".repeat(32);
    let cle = "c1".repeat(32);
    let cles = cles_epinglees(Some(&cle));
    let url = "https://github.com/cryptobones-1337/deR4Tizer/releases/download/v4.4/deR4Tizer.msi";
    let m = lire_manifeste(&manifeste_json("4.4", &[("deR4Tizer.msi", url, &h)])).unwrap();
    let bon = Artefact { sha256: h.clone(), cle: Some(cle.clone()), proprietes: Some(("4.4.0".into(), UPGRADE_CODE.into())) };
    assert!(decision_installation(&m, &bon, "4.3", &cles).is_ok());
    assert!(meme_version("4.4", "4.4.0") && !meme_version("4.4", "4.4.1") && !meme_version("4.4", "x"));
    let refus = |a: &Artefact, installee: &str, cles: &[String], attendu: &str| {
        let e = decision_installation(&m, a, installee, cles).unwrap_err();
        assert!(e.contains(attendu), "{e}");
    };
    // Version de l'artefact ≠ manifeste (manifeste « 4.4 » pour un ancien paquet signé)
    refus(&Artefact { proprietes: Some(("4.1.0".into(), UPGRADE_CODE.into())), ..bon.clone() }, "4.3", &cles, "différente");
    // Version égale ou plus ancienne que la version installée
    refus(&bon, "4.4", &cles, "pas plus récente");
    refus(&bon, "4.10", &cles, "pas plus récente");
    // Empreinte fausse
    refus(&Artefact { sha256: "cd".repeat(32), ..bon.clone() }, "4.3", &cles, "empreinte");
    // Signature absente (ou invalide, ou révoquée)
    refus(&Artefact { cle: None, ..bon.clone() }, "4.3", &cles, "signature");
    // Clé inattendue
    refus(&Artefact { cle: Some("ee".repeat(32)), ..bon.clone() }, "4.3", &cles, "autre clé");
    // Liste de clés vide ou mal formée
    refus(&bon, "4.3", &cles_epinglees(None), "épinglée");
    refus(&bon, "4.3", &cles_epinglees(Some("c1c1 ; trop-court ;")), "épinglée");
    // Paquet signé d'un autre produit, propriétés illisibles
    refus(&Artefact { proprietes: Some(("4.4.0".into(), "{00000000-0000-0000-0000-000000000000}".into())), ..bon.clone() }, "4.3", &cles, "autre produit");
    refus(&Artefact { proprietes: None, ..bon.clone() }, "4.3", &cles, "illisibles");
}

#[test]
fn lot2_adresse_du_paquet_de_retour() {
    use crate::maj::url_paquet_version;
    assert_eq!(url_paquet_version("https://github.com/cryptobones-1337/deR4Tizer/releases/latest/download/manifeste.json", "4.3").as_deref(),
        Some("https://github.com/cryptobones-1337/deR4Tizer/releases/download/v4.3/deR4Tizer.msi"));
    assert!(url_paquet_version("http://github.com/x/releases/latest/download/manifeste.json", "4.3").is_none());
    assert!(url_paquet_version("https://exemple.invalid/manifeste.json", "4.3").is_none());
    assert!(url_paquet_version("https://github.com/x/releases/latest/download/autre.json", "4.3").is_none());
    assert!(url_paquet_version("https://github.com/x/releases/latest/download/manifeste.json", "4.3/../x").is_none());
}

#[test]
fn lot2_proprietes_lues_dans_le_paquet() {
    use crate::natif::proprietes_msi;
    use windows::core::PCWSTR;
    use windows::Win32::System::ApplicationInstallationAndServicing::{
        MsiCloseHandle, MsiDatabaseCommit, MsiDatabaseOpenViewW, MsiOpenDatabaseW, MsiViewExecute, MSIDBOPEN_CREATE, MSIHANDLE,
    };
    let d = dossier_test("msi");
    let f = d.join("test.msi");
    let large = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
    unsafe {
        let mut base = MSIHANDLE::default();
        assert_eq!(MsiOpenDatabaseW(PCWSTR(large(&f.to_string_lossy()).as_ptr()), MSIDBOPEN_CREATE, &mut base), 0);
        for requete in ["CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` LONGCHAR NOT NULL PRIMARY KEY `Property`)",
                        "INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductVersion', '4.4.0')",
                        "INSERT INTO `Property` (`Property`, `Value`) VALUES ('UpgradeCode', '{6F1E2B47-9C3A-4D58-8E21-4B7D0C9A3F15}')"] {
            let mut vue = MSIHANDLE::default();
            assert_eq!(MsiDatabaseOpenViewW(base, PCWSTR(large(requete).as_ptr()), &mut vue), 0, "{requete}");
            assert_eq!(MsiViewExecute(vue, MSIHANDLE::default()), 0, "{requete}");
            MsiCloseHandle(vue);
        }
        assert_eq!(MsiDatabaseCommit(base), 0);
        MsiCloseHandle(base);
    }
    assert_eq!(proprietes_msi(&f).unwrap(), ("4.4.0".to_string(), crate::maj::UPGRADE_CODE.to_string()));
    let pas_msi = d.join("pas-un-msi.msi");
    std::fs::write(&pas_msi, b"MZ").unwrap();
    assert!(proprietes_msi(&pas_msi).is_err());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn lot2_retour_arriere_simule() {
    use crate::maj::{script_installation, ParametresScript, Simulation};
    let d = dossier_test("retour-arriere");
    let paquet = d.join("4.4").join("deR4Tizer.msi");
    let retour = d.join("4.3").join("deR4Tizer.msi");
    std::fs::create_dir_all(paquet.parent().unwrap()).unwrap();
    std::fs::create_dir_all(retour.parent().unwrap()).unwrap();
    std::fs::write(&paquet, b"paquet 4.4").unwrap();
    std::fs::write(&retour, b"paquet 4.3").unwrap();
    let sha_paquet = crate::hygiene::empreinte_fichier(&paquet).unwrap();
    let sha_retour = crate::hygiene::empreinte_fichier(&retour).unwrap();
    let journal = d.join("actions.txt");
    let echec = d.join("echec.txt");
    let jouer_pid = |reponse: &str, sha_paquet: &str, pid_serveur: u32| -> (Vec<String>, Option<String>) {
        let _ = std::fs::remove_file(&journal);
        let _ = std::fs::remove_file(&echec);
        let s = script_installation(&ParametresScript {
            version: "4.4", paquet: &paquet, sha_paquet, retour: &retour, sha_retour: &sha_retour, journaux: &d,
            simulation: Some(Simulation { journal: &journal, reponse, pid_serveur, pid_service: 4242 }),
        });
        let sortie = std::process::Command::new("powershell.exe").args(["-NoProfile", "-NonInteractive", "-Command", &s]).env_remove("PSModulePath").output().unwrap();
        assert!(sortie.status.success(), "{}", String::from_utf8_lossy(&sortie.stderr));
        let actions: Vec<String> = std::fs::read_to_string(&journal).unwrap_or_default().lines().map(|l| l.trim().to_string()).collect();
        let e = std::fs::read_to_string(&echec).ok();
        // Diagnostic, affiché seulement si le test échoue
        eprintln!("réponse {reponse:?} : actions {actions:?}, journal présent {}, échec {e:?}, sortie {:?}, erreurs {:?}",
            journal.exists(), String::from_utf8_lossy(&sortie.stdout), String::from_utf8_lossy(&sortie.stderr));
        (actions, e)
    };
    let jouer = |reponse: &str, sha_paquet: &str| jouer_pid(reponse, sha_paquet, 4242);
    let installer = |p: &std::path::Path| format!("installer {}", p.display());
    // Le service répond, en JSON, avec la nouvelle version : pas de retour arrière
    let (a, e) = jouer(r#"{"Ok":true,"Message":"deR4Tizer 4.4"}"#, &sha_paquet);
    assert_eq!(a, vec![installer(&paquet), "canal".into()]);
    assert!(e.is_none());
    // Le service ne répond pas en JSON valide (ou pas du tout) : retour arrière par le paquet précédent
    for reponse in ["", "\"Ok\":true deR4Tizer 4.4", r#"{"Ok":false,"Message":"deR4Tizer 4.4"}"#, r#"{"Ok":true,"Message":"deR4Tizer 4.3"}"#] {
        let (a, e) = jouer(reponse, &sha_paquet);
        assert_eq!(a, vec![installer(&paquet), "canal".into(), "canal".into(), installer(&retour)], "réponse {reponse:?}");
        assert!(e.as_deref().is_some_and(|t| t.contains("réinstallé") && t.contains("4.4")), "{e:?}");
    }
    // Réponse valide, mais le tube est tenu par un autre processus que le service (squat pendant l'arrêt de
    // l'ancien service) : échec de santé, retour arrière
    let (a, e) = jouer_pid(r#"{"Ok":true,"Message":"deR4Tizer 4.4"}"#, &sha_paquet, 5151);
    assert_eq!(a, vec![installer(&paquet), "canal".into(), "canal".into(), installer(&retour)]);
    assert!(e.as_deref().is_some_and(|t| t.contains("réinstallé")), "{e:?}");
    // Paquet modifié après vérification : rien n'est installé
    let (a, e) = jouer(r#"{"Ok":true,"Message":"deR4Tizer 4.4"}"#, &"00".repeat(32));
    assert!(a.is_empty(), "{a:?}");
    assert!(e.as_deref().is_some_and(|t| t.contains("abandonnée")));
    let _ = std::fs::remove_dir_all(&d);
}

/// Lot 5 : un client du canal qui se connecte puis se tait ne bloque plus le canal : la lecture d'une commande est
/// bornée dans le temps ; une commande normale est toujours lue
#[test]
fn lot5_canal_lecture_bornee_client_silencieux() {
    use std::io::Write;
    use std::time::{Duration, Instant};
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows::Win32::System::Pipes::{ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT};
    for (essai, envoi) in [("silence", None), ("commande", Some("{\"Action\":\"verification\"}\n"))] {
        let nom = format!(r"\\.\pipe\d4t-essai-lot5-{essai}-{}", std::process::id());
        let large: Vec<u16> = nom.encode_utf16().chain(Some(0)).collect();
        let tube = unsafe { CreateNamedPipeW(PCWSTR(large.as_ptr()), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 512, 512, 0, None) };
        assert!(!tube.is_invalid());
        let nom_client = nom.clone();
        let client = std::thread::spawn(move || {
            let mut c = std::fs::OpenOptions::new().read(true).write(true).open(&nom_client).unwrap();
            if let Some(t) = envoi {
                c.write_all(t.as_bytes()).unwrap();
            }
            // Le client garde la connexion ouverte sans rien envoyer de plus
            std::thread::sleep(Duration::from_secs(6));
        });
        let _ = unsafe { ConnectNamedPipe(tube, None) };
        let debut = Instant::now();
        let lu = crate::canal::lire_commande(HANDLE(tube.0), Duration::from_millis(800));
        let duree = debut.elapsed();
        assert!(duree < Duration::from_secs(3), "{essai} : lecture non bornée ({duree:?})");
        match envoi {
            None => assert!(lu.is_empty(), "silence : rien ne doit être lu"),
            Some(t) => assert_eq!(String::from_utf8_lossy(&lu), t, "commande : lue en entier"),
        }
        unsafe { let _ = CloseHandle(tube); }
        client.join().unwrap();
    }
}

/// Lot 5 : canal occupé par un autre processus au démarrage (squat) : le PID de celui qui tient le tube est lu en
/// client anonyme (jamais avec l'identité de SYSTEM), et l'alerte est critique, avec le PID et le chemin
#[test]
fn lot5_canal_squat_pid_et_alerte_critique() {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows::Win32::System::Pipes::{CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT};
    let nom = format!(r"\\.\pipe\d4t-essai-lot5-squat-{}", std::process::id());
    let large: Vec<u16> = nom.encode_utf16().chain(Some(0)).collect();
    let tube = unsafe { CreateNamedPipeW(PCWSTR(large.as_ptr()), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 512, 512, 0, None) };
    assert!(!tube.is_invalid());
    assert_eq!(crate::canal::pid_serveur_anonyme(&nom), Some(std::process::id()));
    unsafe { let _ = CloseHandle(tube); }
    assert_eq!(crate::canal::pid_serveur_anonyme(&nom), None, "tube fermé : aucun PID");
    let a = crate::canal::alerte_squat(Some(4242), r"C:\Users\x\AppData\squat.exe");
    assert_eq!(a.niveau, "Critique");
    assert_eq!(a.pid, Some(4242));
    assert!(a.raisons.contains("4242") && a.raisons.contains(r"C:\Users\x\AppData\squat.exe"), "{}", a.raisons);
    let inconnu = crate::canal::alerte_squat(None, "");
    assert_eq!(inconnu.niveau, "Critique");
    // Revue : alerte de squat seulement quand le nom est déjà pris à la création de la première instance
    use crate::canal::squat;
    assert!(squat(5), "ERROR_ACCESS_DENIED : nom déjà pris");
    assert!(squat(231), "ERROR_PIPE_BUSY : nom pris par un tube à instances limitées");
    assert!(!squat(8), "ERROR_NOT_ENOUGH_MEMORY : autre erreur");
    assert!(!squat(0));
    // Code réellement rendu par Windows quand un autre processus tient déjà le nom, qu'il limite ou non le nombre
    // d'instances : la décision s'appuie sur ce constat
    use windows::Win32::Storage::FileSystem::FILE_FLAG_FIRST_PIPE_INSTANCE;
    for max in [1u32, 255] {
        let nom = format!(r"\\.\pipe\d4t-essai-lot5-pris-{max}-{}", std::process::id());
        let large: Vec<u16> = nom.encode_utf16().chain(Some(0)).collect();
        let tenu = unsafe { CreateNamedPipeW(PCWSTR(large.as_ptr()), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, max, 512, 512, 0, None) };
        assert!(!tenu.is_invalid());
        let second = unsafe { CreateNamedPipeW(PCWSTR(large.as_ptr()), PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 255, 512, 512, 0, None) };
        let code = (windows::core::Error::from_win32().code().0 as u32) & 0xFFFF;
        assert!(second.is_invalid(), "nom déjà pris : création refusée");
        assert!(squat(code), "instances maximales {max} : code {code}, pas reconnu comme squat");
        unsafe { let _ = CloseHandle(tenu); }
    }
}

/// Serveur de tube de test : accepte un client, lit une ligne, répond `reponse` ; renvoie la ligne reçue
fn serveur_tube(nom: &str, reponse: &'static str) -> std::thread::JoinHandle<String> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Storage::FileSystem::{FlushFileBuffers, ReadFile, WriteFile, PIPE_ACCESS_DUPLEX};
    use windows::Win32::System::Pipes::{ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT};
    let chemin: Vec<u16> = format!(r"\\.\pipe\{nom}").encode_utf16().chain(Some(0)).collect();
    let tube = unsafe { CreateNamedPipeW(PCWSTR(chemin.as_ptr()), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 512, 512, 0, None) };
    assert!(!tube.is_invalid());
    let brut = tube.0 as usize;
    std::thread::spawn(move || unsafe {
        let h = HANDLE(brut as _);
        let _ = ConnectNamedPipe(h, None);
        let mut recu = Vec::new();
        let mut octet = [0u8; 1];
        let mut n = 0u32;
        while ReadFile(h, Some(&mut octet), Some(&mut n), None).is_ok() && n == 1 {
            if octet[0] == b'\n' {
                break;
            }
            recu.push(octet[0]);
        }
        if !recu.is_empty() {
            let _ = WriteFile(h, Some(format!("{reponse}\r\n").as_bytes()), None, None);
            let _ = FlushFileBuffers(h);
        }
        let _ = CloseHandle(h);
        String::from_utf8_lossy(&recu).trim_end_matches('\r').to_string()
    })
}

fn powershell_sortie(script: &str) -> String {
    let s = std::process::Command::new("powershell.exe").args(["-NoProfile", "-NonInteractive", "-Command", script]).env_remove("PSModulePath").output().unwrap();
    assert!(s.status.success(), "{}", String::from_utf8_lossy(&s.stderr));
    String::from_utf8_lossy(&s.stdout).trim().to_string()
}

#[test]
fn lot2_canal_code_de_production_sur_un_vrai_tube() {
    // Le code PowerShell EXACT du script de production (ps_canal), passé comme lui en ligne de commande à
    // powershell.exe : requête reçue par le serveur, filtre CIM, PID du serveur du tube
    use crate::maj::{ps_canal, script_installation, ParametresScript};
    let pid = std::process::id();
    let nom = format!("der4tizer-test-{pid}");
    // Pid-Service tel quel, sur un service qui existe partout (WMI) : filtre CIM correctement échappé
    let p = powershell_sortie(&format!("{}; Write-Output (Pid-Service)", ps_canal(&nom, "Winmgmt")));
    assert!(p.parse::<u32>().is_ok_and(|v| v > 0), "PID de Winmgmt : {p:?}");
    // Tube tenu par le processus attendu (ici le test, à la place du service) : requête exacte et réponse
    let serveur = serveur_tube(&nom, r#"{"Ok":true,"Message":"deR4Tizer 4.4"}"#);
    let sortie = powershell_sortie(&format!("{}; function Pid-Service {{ [uint32]{pid} }}; Write-Output ('REPONSE=' + (Lire-Reponse))", ps_canal(&nom, "Winmgmt")));
    let recu = serveur.join().unwrap();
    assert_eq!(recu, r#"{"Action":"verification"}"#, "requête envoyée au service");
    let c: crate::commun::Commande = serde_json::from_str(&recu).expect("JSON valide pour le service");
    assert_eq!(c.action.as_deref(), Some("verification"));
    assert_eq!(sortie, r#"REPONSE={"Ok":true,"Message":"deR4Tizer 4.4"}"#);
    // Tube tenu par un autre processus que le service : aucune requête envoyée, réponse nulle
    let serveur = serveur_tube(&nom, r#"{"Ok":true,"Message":"deR4Tizer 4.4"}"#);
    let sortie = powershell_sortie(&format!("{}; function Pid-Service {{ [uint32]1 }}; Write-Output ('NUL=' + ($null -eq (Lire-Reponse)))", ps_canal(&nom, "Winmgmt")));
    assert_eq!(serveur.join().unwrap(), "", "rien n'est envoyé à un tube squatté");
    assert_eq!(sortie, "NUL=True");
    // Le script de production embarque ce code tel quel, et sa syntaxe est valide
    let d = dossier_test("script-production");
    let (paquet, retour) = (d.join("n.msi"), d.join("a.msi"));
    let s = script_installation(&ParametresScript { version: "4.4", paquet: &paquet, sha_paquet: &"ab".repeat(32), retour: &retour,
        sha_retour: &"cd".repeat(32), journaux: &d, simulation: None });
    assert!(s.contains(&ps_canal("deR4Tizer", "deR4Tizer")));
    let f = d.join("script.ps1");
    std::fs::write(&f, &s).unwrap();
    let erreurs = powershell_sortie(&format!("$e = $null; [void][Management.Automation.Language.Parser]::ParseFile('{}', [ref]$null, [ref]$e); $e.Count", f.display()));
    assert_eq!(erreurs, "0");
    let _ = std::fs::remove_dir_all(&d);
}

/// Faux positifs « PC EXPOSÉ À INTERNET » (constatés le 2026-10-24) : le journal du pare-feu attribue au service les
/// paquets que reçoit sa socket de capture, et note les réponses aux connexions sortantes vers des ports éphémères.
/// Exposition réelle seulement : TCP vers un port en écoute, UDP hors de la plage dynamique, demande d'écho ICMP ;
/// jamais une ligne du service lui-même
#[test]
fn exposition_reelle_sans_faux_positifs() {
    use crate::parefeu::{exposition_reelle, plage_dynamique, ContexteExposition, LecteurJournal};
    let ctx = ContexteExposition { ecoute_tcp: [40001u16, 40002].into_iter().collect(), udp_dynamique: (49152, 65535), pid_service: 4000 };
    assert!(!exposition_reelle("TCP", 50001, 4000, "-", &ctx), "ligne de la socket de capture du service");
    assert!(!exposition_reelle("TCP", 1550, 9999, "-", &ctx), "réponse vers un port éphémère, rien n'y écoute");
    assert!(exposition_reelle("TCP", 40001, 9999, "-", &ctx), "connexion entrante vers un port en écoute");
    assert!(!exposition_reelle("UDP", 50003, 9999, "-", &ctx), "réponse UDP vers un port dynamique");
    assert!(exposition_reelle("UDP", 3000, 9999, "-", &ctx), "UDP vers un port fixe");
    assert!(!exposition_reelle("ICMP", 0, 9999, "0", &ctx), "réponse d'écho");
    assert!(exposition_reelle("ICMP", 0, 9999, "8", &ctx), "demande d'écho venue d'Internet");
    // Sortie de netsh, en anglais comme en français
    assert_eq!(plage_dynamique("Protocol udp Dynamic Port Range\n---\nStart Port      : 49152\nNumber of Ports : 16384\n"), Some((49152, 65535)));
    assert_eq!(plage_dynamique("Plage de ports dynamiques du protocole tcp\n---\nPort de démarrage : 1024\nNombre de ports   : 64511\n"), Some((1024, 65534)));
    assert_eq!(plage_dynamique("rien"), None);
    // Lignes synthétiques au format du journal (adresses de documentation, RFC 5737) : seule la connexion vers un
    // port en écoute donne une alerte
    let d = dossier_test("exposition");
    let f = d.join("pfirewall.log");
    std::fs::write(&f, "#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path pid\n").unwrap();
    let mut lecteur = LecteurJournal::sur_fichier(f.clone());
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new().append(true).open(&f).unwrap();
    for l in [
        "2026-01-01 10:00:01 ALLOW TCP 198.51.100.7 192.168.0.10 443 50001 0 - 0 0 0 - - - RECEIVE 4000",
        "2026-01-01 10:00:02 ALLOW TCP 198.51.100.20 192.168.0.10 443 50002 0 - 0 0 0 - - - RECEIVE 5000",
        "2026-01-01 10:00:03 ALLOW ICMP 192.0.2.53 192.168.0.10 - - 0 - - - - 0 0 - RECEIVE 4",
        "2026-01-01 10:00:04 ALLOW TCP 203.0.113.9 192.168.0.10 51515 40001 0 - 0 0 0 - - - RECEIVE 6000",
    ] {
        writeln!(o, "{l}").unwrap();
    }
    drop(o);
    let alertes = lecteur.lire(&|_| String::new(), &ctx);
    assert_eq!(alertes.len(), 1, "{:?}", alertes.iter().map(|a| a.raisons.clone()).collect::<Vec<_>>());
    assert!(alertes[0].raisons.contains("203.0.113.9") && alertes[0].port == 40001);
    let _ = std::fs::remove_dir_all(&d);
}

/// Client NTP de Windows : envoi du port local 123 vers time.windows.com:123, réponse de 123 vers 123, hors de la
/// plage dynamique. Reconnue par l'état du flux (envoi récent en sens inverse), pas par une liste de ports : le même
/// port 123 joint par une autre source, ou par la même source depuis un autre port, reste une exposition
#[test]
fn exposition_udp_reponse_reconnue_par_le_flux() {
    use crate::parefeu::{reponse_udp, ContexteExposition, FluxUdp, LecteurJournal, DELAI_REPONSE_UDP};
    use std::time::{Duration, Instant};
    let serveur: std::net::IpAddr = "192.0.2.123".parse().unwrap();
    let mut flux = FluxUdp::new();
    let maintenant = Instant::now();
    flux.insert((123, serveur, 123), maintenant);
    assert!(reponse_udp(&flux, 123, serveur, 123, maintenant), "réponse du serveur NTP");
    assert!(!reponse_udp(&flux, 123, "203.0.113.9".parse().unwrap(), 123, maintenant), "autre source vers le port 123");
    assert!(!reponse_udp(&flux, 123, serveur, 40000, maintenant), "même source, autre port distant");
    assert!(!reponse_udp(&flux, 123, serveur, 123, maintenant + DELAI_REPONSE_UDP + Duration::from_secs(1)), "envoi trop ancien");
    // Lignes du journal : envoi puis réponse, sans alerte ; la même source sans envoi préalable, avec alerte
    let ctx = ContexteExposition { ecoute_tcp: Default::default(), udp_dynamique: (49152, 65535), pid_service: 4000 };
    let d = dossier_test("exposition-ntp");
    let f = d.join("pfirewall.log");
    std::fs::write(&f, "#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path pid
").unwrap();
    let mut lecteur = LecteurJournal::sur_fichier(f.clone());
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new().append(true).open(&f).unwrap();
    for l in [
        "2026-01-01 12:00:00 ALLOW UDP 192.168.0.10 192.0.2.123 123 123 0 - - - - - - - SEND 1500",
        "2026-01-01 12:00:00 ALLOW UDP 192.0.2.123 192.168.0.10 123 123 0 - - - - - - - RECEIVE 1500",
        "2026-01-01 12:00:05 ALLOW UDP 203.0.113.9 192.168.0.10 123 123 0 - - - - - - - RECEIVE 1500",
    ] {
        writeln!(o, "{l}").unwrap();
    }
    drop(o);
    let alertes = lecteur.lire(&|_| String::new(), &ctx);
    assert_eq!(alertes.len(), 1, "{:?}", alertes.iter().map(|a| a.raisons.clone()).collect::<Vec<_>>());
    assert!(alertes[0].raisons.contains("203.0.113.9") && alertes[0].port == 123);
    let _ = std::fs::remove_dir_all(&d);
}

/// Audit des données sensibles, posé par handle (natif::poser_audit_arborescence) : SACL complétée, jamais
/// remplacée. Seules les entrées de deR4Tizer (audit explicite de Tout le monde, succès, mêmes droits) sont
/// retirées ; une règle de l'organisation ou une entrée héritée est gardée. Rien à écrire si l'audit est déjà en
/// place (sinon des rafales d'événements 4907 à chaque passage). La pose réelle (privilège SeSecurityPrivilege,
/// jonction vers un canari, entrée tierce gardée) est vérifiée par le scénario 3b.
#[test]
fn audit_donnees_sacl_completee() {
    use crate::natif::sacl_completee;
    let dossier = "AU;OINPIOSA;CC;;;WD";
    let fichier = "AU;SA;CC;;;WD";
    // Aucune SACL : l'entrée est ajoutée
    assert_eq!(sacl_completee("", dossier, false).as_deref(), Some("S:(AU;OINPIOSA;CC;;;WD)"));
    assert_eq!(sacl_completee("S:", fichier, true).as_deref(), Some("S:(AU;SA;CC;;;WD)"));
    // Déjà en place : rien à écrire
    assert_eq!(sacl_completee("S:(AU;OINPIOSA;CC;;;WD)", dossier, false), None);
    assert_eq!(sacl_completee("S:AI(AU;IDSA;CC;;;WD)", fichier, true), None, "fichier : entrée héritée du dossier");
    assert!(sacl_completee("S:AI(AU;IDOINPIOSA;CC;;;WD)", dossier, false).is_some(), "dossier : l'entrée héritée ne suffit pas");
    // Entrée tierce (règle de l'organisation) gardée, la nôtre ajoutée
    assert_eq!(sacl_completee("S:(AU;SAFA;FA;;;BA)", dossier, false).as_deref(), Some("S:(AU;SAFA;FA;;;BA)(AU;OINPIOSA;CC;;;WD)"));
    assert_eq!(sacl_completee("S:(AU;SAFA;FA;;;BA)(AU;OINPIOSA;CC;;;WD)", dossier, false), None, "tierce et nôtre : rien à écrire");
    // Autre audit de Tout le monde, mais pas le nôtre (échecs, autres droits) : gardé
    assert_eq!(sacl_completee("S:(AU;FA;CC;;;WD)(AU;SA;FA;;;WD)", fichier, true).as_deref(), Some("S:(AU;FA;CC;;;WD)(AU;SA;FA;;;WD)(AU;SA;CC;;;WD)"));
    // Notre ancienne entrée (autres drapeaux d'héritage) remplacée, drapeaux de contrôle et entrées héritées gardés
    assert_eq!(sacl_completee("S:AI(AU;OICIIOSA;CC;;;WD)(AU;IDSAFA;FA;;;BA)", dossier, false).as_deref(),
        Some("S:AI(AU;IDSAFA;FA;;;BA)(AU;OINPIOSA;CC;;;WD)"));
    // Doublon de la nôtre : un seul exemplaire gardé
    assert_eq!(sacl_completee("S:(AU;OINPIOSA;CC;;;WD)(AU;OICIIOSA;CC;;;WD)", dossier, false).as_deref(), Some("S:(AU;OINPIOSA;CC;;;WD)"));
    // Idempotent : le résultat complété ne demande plus rien
    let r = sacl_completee("S:(AU;SAFA;FA;;;BA)", fichier, true).unwrap();
    assert_eq!(sacl_completee(&r, fichier, true), None);
    // Lecture : un descripteur sans SACL (la plupart des fichiers) donne une SACL vide, pas « illisible » ; sans quoi
    // l'audit n'était jamais posé sur ces fichiers (constaté par le scénario 3b en Windows Sandbox)
    use crate::natif::texte_sacl_de_sddl;
    assert_eq!(texte_sacl_de_sddl("O:BAG:BAD:(A;;FA;;;BA)").as_deref(), Some(""));
    let vide = texte_sacl_de_sddl("O:BAG:BAD:(A;;FA;;;BA)").unwrap();
    assert_eq!(sacl_completee(&vide, fichier, true).as_deref(), Some("S:(AU;SA;CC;;;WD)"));
    assert_eq!(texte_sacl_de_sddl("O:BAS:(AU;SAFA;FA;;;BA)").as_deref(), Some("S:(AU;SAFA;FA;;;BA)"));
    // SACL présente mais nulle : vide aussi (sa forme texte « S:NO_ACCESS_CONTROL » donnerait un SDDL invalide)
    assert_eq!(texte_sacl_de_sddl("O:BAS:NO_ACCESS_CONTROL").as_deref(), Some(""));
}

/// Le script d'installation lancé par la commande de production s'exécute vraiment. Avec DETACHED_PROCESS, Windows
/// PowerShell 5.1 sortait avec le code 0 sans rien exécuter : aucune mise à jour n'était installée et aucun retour
/// arrière n'avait lieu (scénario 3c en Windows Sandbox). Témoin : la même commande détachée n'écrit rien.
#[test]
fn script_installation_lance_s_execute() {
    use crate::maj::commande_script;
    use std::os::windows::process::CommandExt;
    let d = dossier_test("script-lance");
    let (marque, temoin) = (d.join("marque.txt"), d.join("temoin.txt"));
    let ecrire = |f: &std::path::Path| format!("Set-Content -LiteralPath '{}' -Value ok", f.display());
    let code = commande_script(&ecrire(&marque)).spawn().unwrap().wait().unwrap();
    assert!(code.success() && marque.exists(), "le script lancé par commande_script ne s'est pas exécuté");
    let code = commande_script(&ecrire(&temoin)).creation_flags(0x0800_0000 | 0x0000_0008).spawn().unwrap().wait().unwrap();
    assert!(code.success() && !temoin.exists(), "témoin : PowerShell détaché a exécuté la commande (comportement à revoir)");
    let _ = std::fs::remove_dir_all(&d);
}

/// Arrêt du service : ses enfants curl.exe sont terminés (sinon ils gardaient ouvert un fichier du dossier de données
/// et la désinstallation le laissait). Décision : enfants directs seulement, par nom sans casse. Réel : un enfant lancé
/// par ce processus de test est bien terminé, un processus d'un autre parent ne l'est pas.
#[test]
fn arret_termine_les_enfants_nommes() {
    use crate::natif::{enfants_nommes, terminer_enfants, InfoListe};
    let mut l = std::collections::HashMap::new();
    l.insert(10, InfoListe { nom: "deR4TizerSvc".into(), parent: 1 });
    l.insert(11, InfoListe { nom: "curl".into(), parent: 10 });
    l.insert(12, InfoListe { nom: "CURL".into(), parent: 10 });
    l.insert(13, InfoListe { nom: "powershell".into(), parent: 10 });
    l.insert(14, InfoListe { nom: "curl".into(), parent: 99 });
    assert_eq!(enfants_nommes(&l, 10, &["curl"]), vec![11, 12], "curl, sans casse ; ni powershell ni le curl d'un autre parent");
    assert!(enfants_nommes(&l, 10, &["deR4TizerSvc"]).is_empty(), "jamais le parent lui-même");
    // Réel : ping.exe lancé par ce processus (30 s), terminé tout de suite
    let mut enfant = std::process::Command::new("ping.exe").args(["-n", "30", "127.0.0.1"])
        .stdout(std::process::Stdio::null()).spawn().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
    let debut = std::time::Instant::now();
    assert!(terminer_enfants(&["ping"]) >= 1, "enfant ping.exe non terminé");
    let code = enfant.wait().unwrap();
    assert!(!code.success() && debut.elapsed() < std::time::Duration::from_secs(5), "ping.exe a continué ({code:?})");
}

/// Exposition : un paquet UDP BLOQUÉ qui répond à un flux du poste n'est pas une exposition (réponses d'un flux QUIC
/// sortant bloquées pendant une reconfiguration du réseau ; paquet du serveur d'un VPN au milieu de paquets
/// acceptés). Flux appris d'un envoi du poste ou d'une réponse acceptée vers un port dynamique. Un paquet bloqué
/// d'une source avec laquelle le poste n'a rien échangé, ou d'un autre port de cette source, reste une alerte.
/// Lignes synthétiques (adresses de documentation, RFC 5737).
#[test]
fn exposition_paquet_bloque_reponse_a_un_flux() {
    use crate::parefeu::{ContexteExposition, LecteurJournal};
    let ctx = ContexteExposition { ecoute_tcp: Default::default(), udp_dynamique: (49152, 65535), pid_service: 4000 };
    let d = dossier_test("exposition-bloques");
    let f = d.join("pfirewall.log");
    std::fs::write(&f, "#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path pid\n").unwrap();
    let mut lecteur = LecteurJournal::sur_fichier(f.clone());
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new().append(true).open(&f).unwrap();
    for l in [
        // Flux QUIC sortant, puis réponses bloquées
        "2026-01-01 10:00:00 ALLOW UDP 192.168.0.10 198.51.100.30 50010 443 0 - - - - - - - SEND 5000",
        "2026-01-01 10:00:02 DROP UDP 198.51.100.30 192.168.0.10 443 50010 56 - - - - - - - RECEIVE 5000",
        "2026-01-01 10:00:03 DROP UDP 198.51.100.30 192.168.0.10 443 50010 1039 - - - - - - - RECEIVE 5000",
        // Serveur d'un VPN : réponse acceptée vers un port dynamique, puis un paquet bloqué du même flux
        "2026-01-01 10:00:04 ALLOW UDP 203.0.113.40 192.168.0.10 51820 50020 0 - - - - - - - RECEIVE 5100",
        "2026-01-01 10:00:05 DROP UDP 203.0.113.40 192.168.0.10 51820 50020 176 - - - - - - - RECEIVE 5100",
        // Témoins, chacun sur son propre port local (clé d'alerte distincte de celle des réponses) : source inconnue ;
        // même source, autre port distant ; ligne acceptée de la socket de capture du service (PID 4000), qui ne doit
        // pas masquer le paquet bloqué qui la suit
        "2026-01-01 10:00:06 DROP UDP 192.0.2.99 192.168.0.10 5000 50030 60 - - - - - - - RECEIVE 0",
        "2026-01-01 10:00:07 DROP UDP 198.51.100.30 192.168.0.10 9999 50011 60 - - - - - - - RECEIVE 0",
        "2026-01-01 10:00:08 ALLOW UDP 192.0.2.77 192.168.0.10 6000 50040 0 - - - - - - - RECEIVE 4000",
        "2026-01-01 10:00:09 DROP UDP 192.0.2.77 192.168.0.10 6000 50040 60 - - - - - - - RECEIVE 0",
    ] {
        writeln!(o, "{l}").unwrap();
    }
    drop(o);
    let alertes = lecteur.lire(&|_| String::new(), &ctx);
    let raisons: Vec<String> = alertes.iter().map(|a| a.raisons.clone()).collect();
    assert_eq!(alertes.len(), 3, "{raisons:?}");
    assert!(alertes.iter().any(|a| a.raisons.contains("192.0.2.99") && a.port == 50030), "{raisons:?}");
    assert!(alertes.iter().any(|a| a.raisons.contains("198.51.100.30") && a.port == 50011), "{raisons:?}");
    assert!(alertes.iter().any(|a| a.raisons.contains("192.0.2.77") && a.port == 50040), "{raisons:?}");
    assert!(!alertes.iter().any(|a| a.port == 50010), "réponses du flux QUIC sortant : {raisons:?}");
    assert!(!raisons.iter().any(|r| r.contains("203.0.113.40")), "{raisons:?}");
    let _ = std::fs::remove_dir_all(&d);
}
