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

/// Préfixe IPv6 hors bornes dans une liste de menaces téléchargée : « /129 » faisait lire ip[16] dans dans_reseau6
/// (panique, service arrêté par panic = "abort", et de nouveau à chaque redémarrage tant que la liste est en cache).
/// Une entrée invalide est écartée ; les préfixes de /16 à /128 restent pris en compte.
#[test]
fn liste_de_menaces_prefixe_ipv6_hors_bornes() {
    use crate::menaces::ajouter_et_chercher_test as essai;
    let cible = "2001:4860:4860::8888";
    for l in [129, 130, 255, 999, 4294967295u32] {
        let (n, trouve) = essai(&[&format!("2001:4860::/{l}")], cible);
        assert_eq!((n, trouve), (0, None), "/{l} : entrée refusée, aucune panique");
        // Le cas qui plantait : adresse cherchée identique au préfixe (les 16 octets comparés, puis ip[16])
        assert_eq!(essai(&[&format!("{cible}/{l}")], cible), (0, None), "{cible}/{l}");
    }
    for l in [0, 8, 15] {
        assert_eq!(essai(&[&format!("2001::/{l}")], cible).0, 0, "/{l} : trop large, refusé");
    }
    assert_eq!(essai(&["2001:4860::/16"], cible), (1, Some("essai".into())));
    assert_eq!(essai(&["2001:4860:4860::/48"], cible), (1, Some("essai".into())));
    assert_eq!(essai(&["2001:4860:4860::8888/127"], cible), (1, Some("essai".into())));
    assert_eq!(essai(&["2001:4860:4860::8888/128"], cible), (1, Some("essai".into())));
    assert_eq!(essai(&["2001:4860:4860::8889/128"], cible), (1, None));
    // Une ligne invalide parmi d'autres n'empêche pas les suivantes
    assert_eq!(essai(&["2001:db8::/200", "2001:4860::/32"], cible), (1, Some("essai".into())));
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

/// Audit SEC-009 (AUD3-01) et SEC-007 (AUD3-04) : seule la partie avant « / » était vérifiée, la suite allait telle
/// quelle dans un script PowerShell exécuté en SYSTEM ; un réseau IPv6 ouvrait le pare-feu sans être jamais reconnu
#[test]
fn audit_api_adresses_autorisees_strictes() {
    use crate::api::{adresse_autorisee_valide as valide, adresses_invalides, liste_powershell};
    for a in ["10.0.0.1", "192.168.1.0/24", "10.0.0.0/8", "203.0.113.7/32"] {
        assert!(valide(a), "{a}");
    }
    for a in ["10.0.0.1/$(New-Item C:\\x)", "10.0.0.1/x|Out-Null", "10.0.0.1/8;calc", "10.0.0.1/24`n", "fd00::/64", "2001:db8::1",
              "10.0.0.1/7", "10.0.0.1/33", "10.0.0.1/0", "10.0.0.1/", "10.0.0.1/+24", "10.0.0.1/024", "exemple.test"] {
        assert!(!valide(a), "{a} : refusé");
    }
    assert_eq!(adresses_invalides("10.0.0.1, 10.0.0.1/x|Out-Null ; fd00::/64"), vec!["10.0.0.1/x|Out-Null", "fd00::/64"]);
    assert!(adresses_invalides("10.0.0.1;192.168.1.0/24").is_empty());
    // Script : chaînes entre apostrophes, jamais de texte libre ; liste vide : rien n'est ouvert
    assert_eq!(liste_powershell(&["10.0.0.1".into(), "192.168.1.0/24".into()]), "@('10.0.0.1','192.168.1.0/24')");
    assert_eq!(liste_powershell(&["10.0.0.1/$(x)".into()]), "'127.0.0.1'");
    assert_eq!(liste_powershell(&[]), "'127.0.0.1'");
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

/// Audit AUD2-02 : powershell.exe n'est pas dans System32 même, un nom nu était cherché dans le PATH par SYSTEM.
/// Chemin absolu, et aucun module du service ne lance plus « powershell.exe » par son seul nom.
#[test]
fn audit_powershell_par_chemin_absolu() {
    let p = crate::natif::powershell_exe();
    assert!(std::path::Path::new(&p).is_absolute() && p.to_lowercase().ends_with(r"\system32\windowspowershell\v1.0\powershell.exe"), "{p}");
    assert!(std::path::Path::new(&p).is_file(), "{p} introuvable");
    let nus = [concat!("Command::new(", "\"powershell.exe\")"), concat!("Command::new(", "\"powershell\")")];
    for (nom, source) in [("api", include_str!("api.rs")), ("baseline", include_str!("baseline.rs")), ("blocage", include_str!("blocage.rs")),
                          ("capture", include_str!("capture.rs")), ("maj", include_str!("maj.rs")), ("parefeu", include_str!("parefeu.rs")),
                          ("protection", include_str!("protection.rs")), ("reponse", include_str!("reponse.rs")), ("moniteur", include_str!("moniteur.rs")),
                          ("hygiene", include_str!("hygiene.rs")), ("natif", include_str!("natif.rs")), ("gpo", include_str!("gpo.rs"))] {
        assert!(!nus.iter().any(|nu| source.contains(nu)), "{nom}.rs lance encore powershell.exe par son seul nom");
    }
    // msiexec du script de mise à jour (SYSTEM) : par son chemin absolu, jamais cherché dans le PATH
    assert!(!include_str!("maj.rs").contains(concat!("Start-Process ", "msiexec")), "msiexec cherché dans le PATH");
    // curl : -q en premier argument partout (aucun .curlrc lu ; -q n'agit qu'en premier)
    let appel = concat!("Command::new(", "\"curl.exe\")");
    for (nom, source) in [("menaces", include_str!("menaces.rs")), ("maj", include_str!("maj.rs")), ("notifications", include_str!("notifications.rs")),
                          ("dpi", include_str!("dpi.rs")), ("geoip", include_str!("geoip.rs")), ("hygiene", include_str!("hygiene.rs"))] {
        for (i, _) in source.match_indices(appel) {
            let suite: String = source[i + appel.len()..].chars().filter(|c| !c.is_whitespace()).take(20).collect();
            assert!(suite.starts_with(".args([\"-q\"") || suite.starts_with(".arg(\"-q\")"), "{nom}.rs : curl sans -q en premier ({suite})");
        }
    }
}

/// Audit AUD4-05 : un nom DNS, NBNS ou UPnP, une ligne de commande contenant une fin de ligne ajoutaient de fausses
/// lignes horodatées au journal du service
#[test]
fn audit_journal_une_seule_ligne_par_message() {
    let l = crate::commun::ligne_de_journal("nom a\r\n2026-10-25 10:00:00  faux\u{2028}suite\u{0}\tfin");
    assert!(!l.chars().any(|c| c.is_control() || c == '\u{2028}' || c == '\u{2029}'), "{l:?}");
    assert!(l.contains("2026-10-25 10:00:00  faux") && l.starts_with("nom a"));
    assert_eq!(crate::commun::ligne_de_journal("é ordinaire"), "é ordinaire");
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

/// Audit AUD5-01 : la protection des processus critiques se contentait du nom et d'un chemin qui COMMENÇAIT par le
/// dossier Windows : une copie de powershell.exe nommée explorer.exe dans C:\Windows\Tasks (où tout compte peut écrire)
/// échappait à la suspension d'un rançongiciel. Chemin exact maintenant.
#[test]
fn audit_processus_critiques_par_chemin_exact() {
    use crate::reponse::chemin_critique as critique;
    let w = r"C:\Windows";
    for c in [r"C:\Windows\System32\svchost.exe", r"C:\WINDOWS\system32\LSASS.EXE", r"C:\Windows\explorer.exe", r"C:\Windows\System32\csrss.exe"] {
        assert!(critique(c, w), "{c}");
    }
    for c in [r"C:\Windows\Tasks\explorer.exe", r"C:\Windows\Temp\svchost.exe", r"C:\Windows\System32\spool\drivers\color\svchost.exe",
              r"C:\WindowsX\explorer.exe", r"C:\Windows\System32\..\Tasks\svchost.exe", r"D:\Windows\explorer.exe", r"C:\Users\x\explorer.exe",
              r"C:\Windows\System32\notepad.exe", r"C:\Windows\SysWOW64\explorer.exe"] {
        assert!(!critique(c, w), "{c} : pas un processus critique");
    }
    assert!(critique(r"C:\Windows\explorer.exe", r"C:\Windows\"), "dossier Windows avec barre finale");
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

/// Audit AUD6-02 et AUD3-07 : un serveur SMTP changé sans nouveau mot de passe recevait l'ancien (le dialogue de
/// confirmation ne montrait pas le serveur) ; une fin de ligne dans l'expéditeur ou les destinataires ajoutait des
/// en-têtes au message
#[test]
fn audit_notifications_secret_jamais_envoye_a_un_autre_serveur() {
    use crate::commun::ConfigNotifications;
    use crate::notifications::{preparer, Secrets};
    let actuelle = ConfigNotifications { smtp_serveur: "smtp.exemple.test".into(), smtp_utilisateur: "alertes".into(), ..Default::default() };
    let actuels = Secrets { ntfy_url: "https://ntfy.exemple.test/a".into(), ..Default::default() };
    let essai = |nouvelle: &ConfigNotifications, s: Secrets| { let mut s = s; preparer(&actuelle, nouvelle, &actuels, &mut s).map(|_| s) };
    // Même serveur, même compte, sans nouveau mot de passe : l'ancien est gardé
    assert_eq!(essai(&actuelle, Secrets::default()).unwrap().smtp_mot_de_passe, "");
    // Serveur, port ou compte changé sans nouveau mot de passe : l'ancien est effacé
    for n in [
        ConfigNotifications { smtp_serveur: "smtp.attaquant.test".into(), ..actuelle.clone() },
        ConfigNotifications { smtp_port: 2525, ..actuelle.clone() },
        ConfigNotifications { smtp_utilisateur: "autre".into(), ..actuelle.clone() },
    ] {
        assert_eq!(essai(&n, Secrets::default()).unwrap().smtp_mot_de_passe, "-", "{}:{} {}", n.smtp_serveur, n.smtp_port, n.smtp_utilisateur);
    }
    // Sécurité SMTP changée (TLS vers « aucune ») sans nouveau mot de passe : effacé (il partirait en clair)
    assert_eq!(essai(&ConfigNotifications { smtp_securite: "aucune".into(), ..actuelle.clone() }, Secrets::default()).unwrap().smtp_mot_de_passe, "-");
    // Nouveau mot de passe fourni avec le nouveau serveur : gardé
    let n = ConfigNotifications { smtp_serveur: "smtp2.exemple.test".into(), ..actuelle.clone() };
    assert_eq!(essai(&n, Secrets { smtp_mot_de_passe: "nouveau".into(), ..Default::default() }).unwrap().smtp_mot_de_passe, "nouveau");
    // Adresse ntfy changée sans nouveau jeton : jeton effacé ; même adresse : gardé
    assert_eq!(essai(&actuelle, Secrets { ntfy_url: "https://ntfy.attaquant.test/b".into(), ..Default::default() }).unwrap().ntfy_jeton, "-");
    assert_eq!(essai(&actuelle, Secrets { ntfy_url: "https://ntfy.exemple.test/a".into(), ..Default::default() }).unwrap().ntfy_jeton, "");
    // Adresses ntfy et Teams : homoglyphes, espaces et caractères invisibles refusés ; adresse ordinaire acceptée
    for u in ["https://ntfy.\u{0455}h/sujet", "https://ntfy.sh/a b", "https://ntfy.sh/a\u{200B}", "https://ntfy.sh/a\r\nX: y"] {
        assert!(essai(&actuelle, Secrets { ntfy_url: u.into(), ..Default::default() }).is_err(), "{u:?}");
        assert!(essai(&actuelle, Secrets { teams_url: u.into(), ..Default::default() }).is_err(), "{u:?}");
    }
    assert!(essai(&actuelle, Secrets { ntfy_url: "https://ntfy.sh/mon-sujet".into(), ..Default::default() }).is_ok());
    // Forme de l'adresse : compte, barre oblique inverse, autre schéma refusés ; port accepté ; « - » efface
    for u in [r"https://ntfy.sh\@evil.test/sujet", "https://ntfy.sh@evil.test/sujet", "http://ntfy.sh/sujet", "https://:443/x", "https://ntfy.sh:44a/x", "ftp://x/y"] {
        assert!(essai(&actuelle, Secrets { ntfy_url: u.into(), ..Default::default() }).is_err(), "{u:?}");
        assert!(essai(&actuelle, Secrets { teams_url: u.into(), ..Default::default() }).is_err(), "{u:?}");
    }
    for u in ["https://ntfy.exemple.test:8443/a", "https://prod-01.westeurope.logic.azure.com/workflows/x?api-version=1", "-"] {
        assert!(essai(&actuelle, Secrets { teams_url: u.into(), ..Default::default() }).is_ok(), "{u:?}");
    }
    // Caractères de contrôle : refus (en-têtes ajoutés)
    for n in [
        ConfigNotifications { expediteur: "a@exemple.test\r\nBcc: x@attaquant.test".into(), ..actuelle.clone() },
        ConfigNotifications { destinataires: "b@exemple.test\nBcc: x@attaquant.test".into(), ..actuelle.clone() },
        ConfigNotifications { smtp_serveur: "smtp.exemple.test\0".into(), ..actuelle.clone() },
        ConfigNotifications { expediteur: "a@exemple.test\u{202E}tset.tnaquatta".into(), ..actuelle.clone() },
        ConfigNotifications { destinataires: "b@exemple\u{200B}.test".into(), ..actuelle.clone() },
    ] {
        assert!(essai(&n, Secrets::default()).is_err());
    }
}

/// Audit AUD3-06 : CEF n'échappait que les fins de ligne ; NUL, ESC et tabulations passaient vers le SIEM
#[test]
fn audit_cef_sans_caractere_de_controle() {
    let mut a = alerte("Alerte", "dest\u{1b}[31m\u{0}x", "raison\twith\u{7}bell", 5);
    a.processus = "p\u{0}r\u{1b}oc".into();
    let ligne = crate::export::cef(&a);
    assert!(!ligne.chars().any(char::is_control), "{ligne:?}");
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

/// Audit AUD4-04 : un appareil du réseau local qui répond à la découverte UPnP octet par octet bloquait le fil NDR
/// (délai par lecture seulement). Échéance globale de la réponse.
#[test]
fn audit_upnp_reponse_goutte_a_goutte_bornee() {
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};
    let ecoute = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let adresse = ecoute.local_addr().unwrap();
    let serveur = std::thread::spawn(move || {
        if let Ok((mut c, _)) = ecoute.accept() {
            let mut t = [0u8; 512];
            let _ = c.read(&mut t);
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\n");
            for _ in 0..40 {
                if c.write_all(b"x").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    });
    let debut = Instant::now();
    let r = crate::upnp::http_avec_echeance(adresse, "GET / HTTP/1.1\r\nHost: x\r\n\r\n", Duration::from_secs(2));
    assert!(debut.elapsed() < Duration::from_secs(4), "réponse goutte à goutte : {:?}", debut.elapsed());
    assert!(r.is_none(), "réponse incomplète à l'échéance : abandonnée");
    let _ = serveur.join();
    // Réponse qui finit juste avant l'échéance puis se tait : la dernière lecture ne dépasse pas l'échéance
    let ecoute = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let adresse = ecoute.local_addr().unwrap();
    let serveur = std::thread::spawn(move || {
        if let Ok((mut c, _)) = ecoute.accept() {
            let mut t = [0u8; 512];
            let _ = c.read(&mut t);
            std::thread::sleep(Duration::from_millis(1500));
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\n");
            std::thread::sleep(Duration::from_secs(6));
        }
    });
    let debut = Instant::now();
    let _ = crate::upnp::http_avec_echeance(adresse, "GET / HTTP/1.1\r\nHost: x\r\n\r\n", Duration::from_secs(2));
    assert!(debut.elapsed() < Duration::from_millis(2800), "échéance dépassée par la dernière lecture : {:?}", debut.elapsed());
    let _ = serveur.join();
    // Échéance nulle (passage UPnP épuisé) : rien n'est tenté
    let debut = Instant::now();
    assert!(crate::upnp::http_avec_echeance(adresse, "GET / HTTP/1.1\r\n\r\n", Duration::ZERO).is_none());
    assert!(debut.elapsed() < Duration::from_millis(100));
    assert!(crate::upnp::ECHEANCE_PASSAGE <= Duration::from_secs(30));
    // Échéance du passage UPnP entier (relecture de #55, D2) : une requête du passage n'attend jamais au-delà de la fin
    // du passage, même si l'échéance d'une réponse (10 s) est plus loin ; fin dépassée : rien n'est tenté
    let ecoute = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let adresse = ecoute.local_addr().unwrap();
    let serveur = std::thread::spawn(move || {
        if let Ok((c, _)) = ecoute.accept() {
            std::thread::sleep(Duration::from_secs(4));
            drop(c);
        }
    });
    let debut = Instant::now();
    assert!(crate::upnp::http_test(adresse, "GET / HTTP/1.1\r\n\r\n", Instant::now() + Duration::from_millis(500)).is_none());
    assert!(debut.elapsed() < Duration::from_millis(1500), "fin du passage ignorée : {:?}", debut.elapsed());
    let _ = serveur.join();
    let debut = Instant::now();
    assert!(crate::upnp::http_test(adresse, "GET / HTTP/1.1\r\n\r\n", Instant::now()).is_none());
    assert!(debut.elapsed() < Duration::from_millis(100));
}

/// Audit AUD4-02, AUD4-03 : tables de déduplication alimentées par des adresses du réseau, jamais purgées
#[test]
fn audit_tables_de_deduplication_bornees() {
    use std::collections::HashMap;
    use std::time::{Duration, Instant};
    let mut m: HashMap<u32, Instant> = HashMap::new();
    let maintenant = Instant::now();
    for i in 0..100u32 {
        m.insert(i, maintenant.checked_sub(Duration::from_secs(u64::from(i) * 60)).unwrap_or(maintenant));
    }
    crate::commun::purger_anciens(&mut m, Duration::from_secs(30 * 60 + 30), 1000);
    assert_eq!(m.len(), 31, "entrées de plus de 30 min retirées");
    crate::commun::purger_anciens(&mut m, Duration::from_secs(86400), 10);
    assert_eq!(m.len(), 10, "au-delà du maximum, les plus anciennes retirées");
    assert!(m.contains_key(&0) && !m.contains_key(&30), "les plus récentes gardées");
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
    // Chemin avec retour à la ligne ou espace (en-têtes ajoutés à la requête) : refusé
    assert!(crate::upnp::decouper_url_test("http://192.168.1.1/d.xml\r\nX-Injecte: 1").is_none());
    assert!(crate::upnp::decouper_url_test("http://192.168.1.1/a b").is_none());
    assert!(!crate::upnp::chemin_sur_test("/ctl\r\nHost: x") && crate::upnp::chemin_sur_test("/upnp/control/WANIPConn1"));
}

/// Audit de sécurité S58-02 : champs texte des réglages en listes fermées (langue, protocole, format, niveau) et hôte
/// syslog sans caractère de contrôle ni de mise en forme (la confirmation pouvait être repoussée hors de l'écran ou
/// inversée) ; les valeurs que l'interface envoie passent
#[test]
fn audit_reglages_champs_texte_fermes() {
    use crate::commun::{reglages_invalides, Config, ConfigSyslog};
    let ok = Config { langue: "en".into(), syslog: ConfigSyslog { actif: true, hote: "siem.exemple.test".into(), ..Default::default() }, ..Default::default() };
    assert_eq!(reglages_invalides(&ok), None);
    for (p, f, n) in [("UDP", "JSON", "Info"), ("TCP", "CEF", "Alerte"), ("UDP", "CEF", "Critique")] {
        let c = Config { syslog: ConfigSyslog { actif: true, hote: "10.0.0.5".into(), protocole: p.into(), format: f.into(), niveau_min: n.into(), ..Default::default() }, ..ok.clone() };
        assert_eq!(reglages_invalides(&c), None, "{p} {f} {n}");
    }
    let mauvais = [
        Config { langue: "fr · syslog : désactivé\n\n".into(), ..ok.clone() },
        Config { langue: "EN".into(), ..ok.clone() },
        Config { syslog: ConfigSyslog { protocole: "udp".into(), ..ok.syslog.clone() }, ..ok.clone() },
        Config { syslog: ConfigSyslog { format: "XML".into(), ..ok.syslog.clone() }, ..ok.clone() },
        Config { syslog: ConfigSyslog { niveau_min: "Tout".into(), ..ok.syslog.clone() }, ..ok.clone() },
        Config { syslog: ConfigSyslog { hote: "siem\u{202E}tset".into(), ..ok.syslog.clone() }, ..ok.clone() },
        Config { syslog: ConfigSyslog { hote: "siem.test\r\n".into(), ..ok.syslog.clone() }, ..ok.clone() },
        Config { syslog: ConfigSyslog { actif: false, hote: "a b".into(), ..ok.syslog.clone() }, ..ok.clone() },
    ];
    for c in mauvais {
        assert!(reglages_invalides(&c).is_some(), "{:?} {:?}", c.langue, c.syslog.hote);
    }
}

/// Relecture de #58 (D2) : chemins complets des commandes (ce que le service appelle), sur ce que l'interface envoie
/// réellement (aucun refus) et sur les contournements (refus)
/// Audit de sécurité S58-05, S58-06, S58-07 : champs remplis d'espaces (la confirmation en administrateur montrait
/// l'adresse légitime suivie de blanc, et repoussait hors de l'écran une adresse ajoutée) et « : » dans l'hôte syslog
#[test]
fn audit_champs_sans_remplissage() {
    use crate::commun::{lire_reglages, lire_syslog_test, ConfigNotifications};
    use crate::notifications::{preparer, Secrets};
    let actuelle = ConfigNotifications { smtp_serveur: "smtp.exemple.test".into(), smtp_utilisateur: "alertes".into(), ..Default::default() };
    let essai = |n: &ConfigNotifications| { let mut s = Secrets::default(); preparer(&actuelle, n, &Secrets::default(), &mut s) };
    // Ce que l'utilisateur tape d'ordinaire : accepté
    assert!(essai(&ConfigNotifications { destinataires: "a@exemple.test, b@exemple.test;c@exemple.test".into(), ..actuelle.clone() }).is_ok());
    // Remplissage : suites d'espaces, espaces non ASCII, longueur démesurée
    let cache = format!("admin@legit.example{},x@attacker.example", " ".repeat(30_000));
    for d in [cache.as_str(), "a@exemple.test\u{00A0}\u{00A0},x@attacker.example", "a@exemple.test\u{3000},x@attacker.example", "a@exemple.test    ,x@attacker.example"] {
        assert!(essai(&ConfigNotifications { destinataires: d.into(), ..actuelle.clone() }).is_err(), "{:?}", &d[..d.len().min(40)]);
    }
    assert!(essai(&ConfigNotifications { destinataires: format!("{}@exemple.test", "a".repeat(1100)), ..actuelle.clone() }).is_err());
    assert!(essai(&ConfigNotifications { expediteur: format!("a@exemple.test{}", "\u{2007}".repeat(5)), ..actuelle.clone() }).is_err());
    // Adresses autorisées de l'API : chiffres, « . », « / », « , » et espaces simples seulement
    let reglages = |adresses: &str| lire_reglages(&format!(r#"{{"Langue":"fr","Api":{{"Actif":true,"Port":8642,"Reseau":true,"Adresses":"{adresses}"}}}}"#));
    assert!(reglages("192.168.1.10, 10.0.0.0/8").is_ok());
    assert!(reglages(&format!("192.168.1.10{},203.0.113.0/24", " ".repeat(30_000))).is_err());
    assert!(reglages("192.168.1.10\u{3000},203.0.113.0/24").is_err());
    assert!(reglages(&"1.2.3.4,".repeat(200)).is_err(), "longueur bornée");
    // Hôte syslog : « : » seulement dans une adresse IPv6 valide
    assert!(lire_syslog_test(r#"{"Hote":"fd00::5","Port":514,"Protocole":"UDP"}"#).is_ok());
    assert!(lire_syslog_test(r#"{"Hote":"10.0.0.5:25","Port":514,"Protocole":"UDP"}"#).is_err());
}

#[test]
fn audit_reglages_commandes_completes() {
    use crate::commun::{lire_reglages, lire_syslog_test, Config};
    use crate::notifications::controler_demande;
    // Ce que l'interface envoie : Config complète (mêmes noms de champs), demande de notifications
    let interface = serde_json::to_string(&Config { langue: "en".into(), ..Config::default() }).unwrap();
    assert_eq!(lire_reglages(&interface).unwrap().langue, "en");
    assert!(lire_syslog_test(r#"{"Actif":true,"Hote":"siem.exemple.test","Port":514,"Protocole":"TCP","Format":"CEF","NiveauMin":"Alerte"}"#).is_ok());
    assert!(controler_demande(r#"{"Config":{"Ntfy":true},"NtfyUrl":"https://ntfy.sh/a","NtfyJeton":"","TeamsUrl":"","SmtpMotDePasse":""}"#).is_ok());
    assert!(controler_demande(r#"{"Config":null}"#).is_ok());
    // Contournements : clé ambiguë, texte illisible comme valeur, valeur hors liste
    let syslog_cache = r#"{"Langue":"fr","Syslog":{"Actif":true,"Hote":"203.0.113.9","Port":514,"Protocole":"TCP","Format":"JSON","NiveauMin":"Info"},"syslog":{"Actif":false},"Zz":"\uD800"}"#;
    assert!(lire_reglages(syslog_cache).is_err());
    assert!(lire_reglages(r#"{"Langue":"fr","langue":"en"}"#).is_err());
    assert!(lire_reglages(r#"{"Langue":"fr","Syslog":{"Actif":true,"Hote":"s.test","NiveauMin":"critique"}}"#).is_err(), "« critique » traité comme Info");
    assert!(lire_syslog_test(r#"{"Hote":"10.0.0.5","Port":25,"Protocole":"tcp"}"#).is_err());
    assert!(lire_syslog_test(r#"{"Hote":"10.0.0.5","hote":"10.0.0.6"}"#).is_err());
    assert!(controler_demande(r#"{"Config":{"Ntfy":true},"config":{"Ntfy":false}}"#).is_err());
    assert!(controler_demande(r#"{"NtfyUrl":"https://ntfy.sh/a","ntfyurl":"https://ntfy.sh/b"}"#).is_err());
    assert!(controler_demande(r#"{"NtfyUrl":"https://ntfy.sh/a","X":"\uD800"}"#).is_err());
}

/// Audit AUD6-03 : une clé qui ne diffère d'une clé connue que par la casse est refusée (l'interface en afficherait
/// la valeur, le service appliquerait l'autre) ; une clé inconnue sans homonyme reste ignorée ; une commande ordinaire
/// passe
#[test]
fn audit_reglages_cle_ambigue_refusee() {
    use crate::commun::{cle_ambigue, Config};
    let modele = serde_json::to_value(Config::default()).unwrap();
    assert_eq!(cle_ambigue(r#"{"Langue":"fr","langue":"en"}"#, &modele).as_deref(), Some("langue"));
    assert_eq!(cle_ambigue(r#"{"Api":{"Actif":true,"port":80,"Port":8642}}"#, &modele).as_deref(), Some("Api.port"));
    assert_eq!(cle_ambigue(r#"{"SYSLOG":{"Actif":true}}"#, &modele).as_deref(), Some("SYSLOG"));
    assert_eq!(cle_ambigue(r#"{"Langue":"fr","Api":{"Actif":false,"Port":8642},"Inconnue":1}"#, &modele), None);
    assert_eq!(cle_ambigue(&serde_json::to_string(&Config::default()).unwrap(), &modele), None);
    // Texte que serde_json ne lit pas comme valeur, mais qu'il lit comme Config (audit de sécurité S58-01 : surrogat
    // isolé ou nombre hors plage dans un champ ignoré) : refusé, jamais laissé passer
    assert!(cle_ambigue("pas du json", &modele).is_some());
    let contournement = r#"{"Langue":"fr","Syslog":{"Actif":true,"Hote":"203.0.113.9","Port":514,"Protocole":"TCP","Format":"JSON","NiveauMin":"Info"},"syslog":{"Actif":false},"Zz":"\uD800"}"#;
    assert!(serde_json::from_str::<Config>(contournement).is_ok(), "témoin : serde lit bien ce texte comme Config");
    assert!(cle_ambigue(contournement, &modele).is_some(), "surrogat isolé : refusé");
    assert!(cle_ambigue(r#"{"Langue":"fr","langue":"en","Zz":1e400}"#, &modele).is_some(), "nombre hors plage : refusé");
    crate::tests::torturer_texte(r#"{"Langue":"fr","Api":{"Port":8642}}"#, &mut |t| { let _ = cle_ambigue(t, &modele); });
}

#[test]
fn fonctions_texte_sans_panique() {
    torturer_texte("a%20b+c%3A%C3%A9", &mut |t| { let _ = crate::api::decoder_test(t); });
    torturer_texte(r#"alert tcp any any -> any any (msg:"é"; content:"|41|é"; sid:9;)"#, &mut |t| { let _ = crate::ids::lire_texte_test(t); });
    torturer_texte(r"C:\Users\marie\AppData\x.exe", &mut |t| { let _ = crate::commun::masquer_chemin(t); });
    torturer_texte("Brave Software, Inc.", &mut |t| { let _ = crate::moniteur::ip_directe_normale(t); });
    torturer_texte("192.168.1.0/24", &mut |t| { let _ = crate::api::adresse_autorisee_valide(t); let _ = crate::api::adresses_invalides(t); });
    torturer_texte(r"C:\Windows\System32\svchost.exe", &mut |t| { let _ = crate::reponse::chemin_critique(t, r"C:\Windows"); let _ = crate::reponse::chemin_critique(r"C:\Windows\explorer.exe", t); });
    torturer_texte("# u\r\n# >>> deR4Tizer (bloc gere par le service, ne pas modifier a la main)\r\n127.0.0.1\ta.test\r\n# <<< deR4Tizer\r\n", &mut |t| {
        let d = ["b.test".to_string()];
        if let Ok(un) = crate::blocage::nouveau_contenu(t.as_bytes(), &d) {
            // Idempotence sur toute entrée : réécrire avec les mêmes domaines ne change rien
            assert_eq!(crate::blocage::nouveau_contenu(&un, &d).unwrap(), un, "{t:?}");
        }
    });
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
    // Table bornée : au-delà de MAX_ETAPES noms distincts, le reste est compté sous « autre »
    for i in 0..(crate::mesure::MAX_ETAPES + 10) {
        duree(&format!("commande.inconnue{i}"), Duration::from_millis(1));
    }
    let (cumul, _) = instantane();
    assert!(cumul.etapes.len() <= crate::mesure::MAX_ETAPES + 1, "{} étapes", cumul.etapes.len());
    assert!(cumul.etapes.contains_key("autre"));
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

// ------------------------------------------------------------ phase 1 : autorisation, validation, débit du canal

fn commande_json(j: &str) -> crate::commun::Commande {
    serde_json::from_str(j).unwrap_or_else(|e| panic!("{j} : {e}"))
}

#[test]
fn phase1_autorisation_par_commande() {
    use crate::validation::{autorisee, Client, ACTIONS};
    for a in ACTIONS {
        assert!(autorisee(a, Client::Systeme) && autorisee(a, Client::Administrateur), "{a} : SYSTEM et administrateurs");
        assert_eq!(autorisee(a, Client::Autre), *a == "verification", "{a} : un client « autre » ne peut que demander la version");
    }
    for inconnue in ["", "Tuer", "tuer ", "panique\n", "toutDebloquer2", "executer"] {
        for c in [Client::Systeme, Client::Administrateur, Client::Autre] {
            assert!(!autorisee(inconnue, c), "action inconnue {inconnue:?} refusée pour {c:?}");
        }
    }
    // Admission : un client « autre » est refusé avant toute validation, sans exécution
    let r = crate::canal::admettre(br#"{"Action":"toutDebloquer"}"#, Client::Autre, true).err().expect("refus");
    assert!(!r.ok && r.message.contains("non autorisée"), "{}", r.message);
    assert!(crate::canal::admettre(br#"{"Action":"verification"}"#, Client::Autre, true).is_ok());
}

#[test]
fn phase1_commandes_de_l_interface_acceptees() {
    // Formes exactes envoyées par l'interface (src/*.cs) : aucune régression
    let sid = "S-1-5-21-1111111111-2222222222-3333333333-1001";
    for j in [
        r#"{"Action":"apprentissage","Valeur":"oublier"}"#.to_string(),
        r#"{"Action":"apprentissage","Valeur":"recommencer"}"#.to_string(),
        r#"{"Action":"apprentissage","Valeur":"terminer"}"#.to_string(),
        format!(r#"{{"Action":"autoriserLecteur","Valeur":"{sid}"}}"#),
        r#"{"Action":"baseline","Valeur":"appliquer","Cible":"recommandé"}"#.to_string(),
        r#"{"Action":"baseline","Valeur":"annuler","Cible":"recommandé,renforcé"}"#.to_string(),
        r#"{"Action":"baseline","Valeur":"evaluer","Cible":""}"#.to_string(),
        r#"{"Action":"bloquer","Ip":"203.0.113.7","NomDns":"exemple.test","Raison":"flux de chrome"}"#.to_string(),
        r#"{"Action":"bloquer","Ip":"2001:db8::7","NomDns":null,"Raison":"flux de x"}"#.to_string(),
        r#"{"Action":"config","Cible":"Ips","Valeur":"true"}"#.to_string(),
        r#"{"Action":"config","Cible":"ReponseAutoRancongiciel","Valeur":"false"}"#.to_string(),
        r#"{"Action":"debloquer","Type":"hosts","Cible":"exemple.test"}"#.to_string(),
        r#"{"Action":"debloquer","Type":"parefeu","Cible":"203.0.113.7"}"#.to_string(),
        r#"{"Action":"debloquer","Type":"programme","Cible":"C:\\Outils\\x.exe"}"#.to_string(),
        r#"{"Action":"exception","Cible":"01db2f1c3a4b5c6d-00001a2b-0003"}"#.to_string(),
        r#"{"Action":"jetonApi"}"#.to_string(), r#"{"Action":"nouveauJeton"}"#.to_string(),
        r#"{"Action":"majConfig","Valeur":"{\"Auto\":false,\"Url\":\"https://exemple.test/m.json\"}"}"#.to_string(),
        r#"{"Action":"majMenaces"}"#.to_string(), r#"{"Action":"majVerifier"}"#.to_string(),
        r#"{"Action":"panique","Valeur":"on"}"#.to_string(), r#"{"Action":"panique","Valeur":"off"}"#.to_string(),
        r#"{"Action":"reglages","Valeur":"{\"Langue\":\"en\",\"Notifications\":null}"}"#.to_string(),
        r#"{"Action":"restaurer","Cible":"01db2f1c3a4b5c6d-00001a2b-0004"}"#.to_string(),
        r#"{"Action":"restaurerRepli","Cible":"01db2f1c3a4b5c6d-00001a2b-0004"}"#.to_string(),
        r#"{"Action":"testerSyslog","Valeur":"{\"Actif\":true}"}"#.to_string(),
        r#"{"Action":"toutDebloquer"}"#.to_string(),
        r#"{"Action":"notifications","Valeur":"{\"Config\":null}"}"#.to_string(),
        r#"{"Action":"testerNotifications","Valeur":"{}"}"#.to_string(),
        r#"{"Action":"tuer","Cible":"4242","Raison":"action manuelle sur x"}"#.to_string(),
        r#"{"Action":"tuerChaine","Cible":"4242","Raison":"action manuelle sur x"}"#.to_string(),
        r#"{"Action":"suspendre","Cible":"4242"}"#.to_string(), r#"{"Action":"reprendre","Cible":"4242"}"#.to_string(),
        r#"{"Action":"quarantaine","Cible":"C:\\Users\\x\\Downloads\\outil.exe","Raison":"action manuelle sur outil"}"#.to_string(),
        r#"{"Action":"isolerProgramme","Cible":"D:\\Jeux\\jeu.exe","Raison":"action manuelle sur jeu"}"#.to_string(),
        r#"{"Action":"verification"}"#.to_string(),
    ] {
        assert_eq!(crate::validation::valider(&commande_json(&j)), Ok(()), "{j}");
    }
}

#[test]
fn phase1_champs_invalides_refuses() {
    use crate::validation::valider;
    let long = "a".repeat(5000);
    for (j, pourquoi) in [
        (r#"{}"#.to_string(), "action manquante"),
        (r#"{"Action":"inconnue"}"#.to_string(), "action inconnue"),
        (r#"{"Action":"bloquer","NomDns":"exemple.test\r\n203.0.113.9 banque.test"}"#.to_string(), "fin de ligne dans le nom : injection du fichier hosts"),
        (r#"{"Action":"bloquer","NomDns":"évil.test"}"#.to_string(), "nom accentué hors punycode"),
        (r#"{"Action":"bloquer","NomDns":"a..b"}"#.to_string(), "étiquette vide"),
        (r#"{"Action":"bloquer","NomDns":"-a.test"}"#.to_string(), "étiquette commençant par un tiret"),
        (r#"{"Action":"bloquer"}"#.to_string(), "ni nom ni adresse"),
        (r#"{"Action":"bloquer","Ip":"1.2.3"}"#.to_string(), "adresse tronquée"),
        (r#"{"Action":"bloquerIp","Ip":"203.0.113.7 ; netsh"}"#.to_string(), "adresse suivie d'une commande"),
        (r#"{"Action":"debloquer","Type":"autre","Cible":"x"}"#.to_string(), "type inconnu"),
        (r#"{"Action":"debloquer","Type":"parefeu","Cible":"exemple.test"}"#.to_string(), "pare-feu : adresse attendue"),
        (r#"{"Action":"debloquer","Type":"programme","Cible":"x.exe"}"#.to_string(), "chemin relatif"),
        (r#"{"Action":"config","Cible":"Defender","Valeur":"false"}"#.to_string(), "réglage inconnu"),
        (r#"{"Action":"config","Cible":"Ips","Valeur":"oui"}"#.to_string(), "valeur non booléenne"),
        (r#"{"Action":"reglages","Valeur":"pas du json"}"#.to_string(), "objet JSON attendu"),
        (r#"{"Action":"tuer","Cible":"4"}"#.to_string(), "PID de System"),
        (r#"{"Action":"tuer","Cible":"0"}"#.to_string(), "PID nul"),
        (r#"{"Action":"tuer","Cible":"-1"}"#.to_string(), "PID négatif"),
        (r#"{"Action":"quarantaine","Cible":"\\\\serveur\\partage\\x.exe"}"#.to_string(), "chemin réseau"),
        (r#"{"Action":"quarantaine","Cible":"\\\\?\\C:\\x.exe"}"#.to_string(), "chemin d'appareil"),
        (r#"{"Action":"quarantaine","Cible":"C:\\x\u0000.exe"}"#.to_string(), "caractère NUL"),
        (r#"{"Action":"isolerProgramme","Cible":"C:\\x\\..\\Windows\\System32\\svchost.exe"}"#.to_string(), "élément .. (contournement du refus du dossier Windows)"),
        (r#"{"Action":"quarantaine","Cible":"C:\\x\\..\\y.exe"}"#.to_string(), "élément .."),
        (r#"{"Action":"isolerProgramme","Cible":"C:\\.\\Windows\\System32\\cmd.exe"}"#.to_string(), "élément « . »"),
        (r#"{"Action":"isolerProgramme","Cible":"C:\\\\Windows\\System32\\cmd.exe"}"#.to_string(), "élément vide"),
        (r#"{"Action":"isolerProgramme","Cible":"C:\\Windows.\\System32\\cmd.exe"}"#.to_string(), "élément terminé par un point"),
        (r#"{"Action":"isolerProgramme","Cible":"C:\\Windows \\System32\\cmd.exe"}"#.to_string(), "élément terminé par une espace"),
        (r#"{"Action":"quarantaine","Cible":"C:\\x\\a.exe:flux"}"#.to_string(), "flux de données"),
        (r#"{"Action":"quarantaine","Cible":"C:\\x\\"}"#.to_string(), "dossier, pas un fichier"),
        (r#"{"Action":"isolerProgramme","Cible":"programme.exe"}"#.to_string(), "chemin relatif"),
        (r#"{"Action":"restaurer","Cible":"../../x"}"#.to_string(), "identifiant avec séparateurs"),
        (r#"{"Action":"panique","Valeur":"peut-être"}"#.to_string(), "valeur de panique"),
        (r#"{"Action":"baseline","Valeur":"supprimer","Cible":"recommandé"}"#.to_string(), "opération de baseline inconnue"),
        (r#"{"Action":"baseline","Valeur":"appliquer","Cible":"recommandé;x"}"#.to_string(), "sélection de baseline invalide"),
        (r#"{"Action":"apprentissage","Valeur":"tout"}"#.to_string(), "apprentissage inconnu"),
        (r#"{"Action":"autoriserLecteur","Valeur":"Administrateurs"}"#.to_string(), "SID attendu"),
        (format!(r#"{{"Action":"quarantaine","Cible":"C:\\{long}"}}"#), "cible trop longue"),
        (format!(r#"{{"Action":"reglages","Valeur":"{{{}}}"}}"#, "a".repeat(40000)), "valeur trop longue"),
        (r#"{"Action":"reglages","Valeur":"{\u0007}"}"#.to_string(), "caractère de contrôle dans la valeur"),
    ] {
        assert!(valider(&commande_json(&j)).is_err(), "{pourquoi} : devait être refusé ({})", j.chars().take(120).collect::<String>());
    }
    // Raison : normalisée, jamais une cause de refus (un programme nommé avec une fin de ligne reste blocable)
    let mut c = commande_json(r#"{"Action":"tuer","Cible":"4242","Raison":"action manuelle sur x\r\nfaux"}"#);
    crate::validation::normaliser(&mut c);
    assert_eq!(c.raison.as_deref(), Some("action manuelle sur x  faux"));
    assert_eq!(valider(&c), Ok(()));
    let mut l = commande_json(&format!(r#"{{"Action":"verification","Raison":"{}"}}"#, "r".repeat(2000)));
    crate::validation::normaliser(&mut l);
    assert_eq!(l.raison.unwrap().chars().count(), crate::validation::MAX_RAISON);
}

#[test]
fn phase1_fichier_hosts_sans_injection() {
    let noms = vec!["Exemple.Test.".to_string(), "a.test\r\n203.0.113.9 banque.test".to_string(), "évil.test".to_string(), "b.test".to_string()];
    assert_eq!(crate::blocage::lignes_du_bloc(&noms), vec!["exemple.test", "b.test"], "noms invalides écartés, valides en minuscules");
}

/// Audit SEC-005, SEC-006, AUD5-05, AUD5-06 : le fichier hosts était entièrement décodé et filtré en ASCII (lignes
/// de l'utilisateur altérées), un début de bloc sans fin faisait perdre la suite, et l'écriture n'était pas atomique.
/// Les lignes hors du bloc sont maintenant recopiées octet pour octet.
#[test]
fn audit_fichier_hosts_lignes_de_l_utilisateur_intactes() {
    use crate::blocage::{nouveau_contenu, DEBUT_BLOC, FIN_BLOC};
    let d = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let utilisateur = "# serveur du café, étage 2\r\n192.168.1.20\tnas.local\r\n".as_bytes();
    // Sans bloc ni domaine : contenu identique, octet pour octet (y compris sans fin de ligne finale)
    assert_eq!(nouveau_contenu(utilisateur, &[]).unwrap(), utilisateur);
    assert_eq!(nouveau_contenu(b"10.0.0.1 a", &[]).unwrap(), b"10.0.0.1 a");
    // Bloc ajouté : lignes de l'utilisateur intactes devant
    let n = nouveau_contenu(utilisateur, &d(&["Exemple.Test"])).unwrap();
    assert!(n.starts_with(utilisateur));
    assert_eq!(&n[utilisateur.len()..], format!("{DEBUT_BLOC}\r\n127.0.0.1\texemple.test\r\n{FIN_BLOC}\r\n").as_bytes());
    // Bloc existant remplacé, lignes avant et après gardées telles quelles
    let avec = [utilisateur, format!("{DEBUT_BLOC}\r\n127.0.0.1\tancien.test\r\n{FIN_BLOC}\r\n").as_bytes(), "# après, déjà là\r\n".as_bytes()].concat();
    let n = nouveau_contenu(&avec, &d(&["b.test"])).unwrap();
    let t = String::from_utf8(n).unwrap();
    assert!(t.starts_with("# serveur du café, étage 2\r\n192.168.1.20\tnas.local\r\n# après, déjà là\r\n"), "{t:?}");
    assert!(t.contains("127.0.0.1\tb.test") && !t.contains("ancien.test"));
    // Bloc retiré quand il n'y a plus de domaine
    assert_eq!(nouveau_contenu(&avec, &[]).unwrap(), [utilisateur, "# après, déjà là\r\n".as_bytes()].concat());
    // Faux début de bloc sans fin : ligne de l'utilisateur, rien n'est perdu après
    let faux = [utilisateur, format!("{DEBUT_BLOC}\r\n10.6.6.6 banque.test\r\n").as_bytes()].concat();
    let n = nouveau_contenu(&faux, &d(&["c.test"])).unwrap();
    assert!(n.starts_with(&faux), "le faux début de bloc et la ligne suivante sont gardés");
    // Écritures successives (relecture de #54) : faux début AVANT le vrai bloc ; la seconde écriture ne doit rien
    // perdre de l'utilisateur, et une écriture répétée avec les mêmes domaines ne change rien (idempotence)
    let faux_avant = format!("# u\r\n{DEBUT_BLOC}\r\n10.0.0.9 nas.test\r\n# ligne de l'utilisateur\r\n").into_bytes();
    let un = nouveau_contenu(&faux_avant, &d(&["c.test"])).unwrap();
    assert!(un.starts_with(&faux_avant));
    let deux = nouveau_contenu(&un, &d(&["d.test"])).unwrap();
    let t = String::from_utf8(deux.clone()).unwrap();
    assert!(t.starts_with(std::str::from_utf8(&faux_avant).unwrap()), "seconde écriture : lignes de l'utilisateur perdues : {t:?}");
    assert!(t.contains("127.0.0.1\td.test") && !t.contains("c.test"), "{t:?}");
    assert_eq!(nouveau_contenu(&deux, &d(&["d.test"])).unwrap(), deux, "même domaines : contenu inchangé");
    assert_eq!(nouveau_contenu(&deux, &[]).unwrap(), faux_avant, "bloc retiré : exactement les lignes de l'utilisateur");
    // Deux blocs complets (fichier laissé ainsi par une version ancienne, ou édité à la main) : tous retirés, idempotent
    let deux = format!("# u\r\n{DEBUT_BLOC}\r\n127.0.0.1\ta.test\r\n{FIN_BLOC}\r\n# v\r\n{DEBUT_BLOC}\r\n127.0.0.1\tb.test\r\n{FIN_BLOC}\r\n# w\r\n").into_bytes();
    assert_eq!(nouveau_contenu(&deux, &[]).unwrap(), b"# u\r\n# v\r\n# w\r\n", "retrait complet : aucun bloc ne reste");
    let un = nouveau_contenu(&deux, &d(&["c.test"])).unwrap();
    let t = String::from_utf8(un.clone()).unwrap();
    assert_eq!(t.matches(DEBUT_BLOC).count(), 1, "{t:?}");
    assert!(!t.contains("a.test") && !t.contains("b.test") && t.contains("c.test"), "{t:?}");
    assert_eq!(nouveau_contenu(&un, &d(&["c.test"])).unwrap(), un, "idempotent après fusion des blocs");
    let (hors, bloc) = crate::blocage::decouper_hosts(&deux);
    assert_eq!(hors, ["# u", "# v", "# w"]);
    assert_eq!(bloc, ["a.test", "b.test"]);
    // Fin sans début avant le bloc : ligne de l'utilisateur, gardée
    let fin_seule = format!("{FIN_BLOC}\r\n# u\r\n").into_bytes();
    let n = nouveau_contenu(&fin_seule, &d(&["e.test"])).unwrap();
    assert!(n.starts_with(&fin_seule) && nouveau_contenu(&n, &[]).unwrap() == fin_seule);
    // Bloc en fin de fichier sans fin de ligne finale : jamais « \r\r\n », ni ligne laissée sans sa fin de ligne
    let sans_fin = format!("# u\r\n{DEBUT_BLOC}\r\n127.0.0.1\tf.test\r\n{FIN_BLOC}").into_bytes();
    let n = nouveau_contenu(&sans_fin, &d(&["g.test"])).unwrap();
    assert!(!n.windows(3).any(|w| w == b"\r\r\n") && n.starts_with(b"# u\r\n"), "{:?}", String::from_utf8_lossy(&n));
    assert_eq!(nouveau_contenu(&sans_fin, &[]).unwrap(), b"# u\r\n");
    // UTF-16 : refusé plutôt que cassé
    assert!(nouveau_contenu(&[0xFF, 0xFE, b'#', 0], &d(&["a.test"])).is_err());
}

#[test]
fn phase1_messages_malformes_tronques() {
    use crate::validation::Client;
    // Lecture : vide, BOM, seconde ligne ignorée, non UTF-8
    assert!(crate::validation::decoder_commande(b"").is_err());
    assert!(crate::validation::decoder_commande(b"   \r\n").is_err());
    assert_eq!(crate::validation::decoder_commande("\u{feff}{\"Action\":\"verification\"}\r\n{\"Action\":\"toutDebloquer\"}".as_bytes()).unwrap().action.as_deref(), Some("verification"));
    assert!(crate::validation::decoder_commande(&[0xff, 0xfe, 0x00, 0x7b]).is_err());
    // Toutes les troncatures et des milliers de variantes corrompues : jamais de panique ; une commande admise est
    // toujours une commande valide
    for valide in [
        br#"{"Action":"bloquer","Ip":"203.0.113.7","NomDns":"exemple.test","Raison":"flux de x"}"#.as_slice(),
        br#"{"Action":"quarantaine","Cible":"C:\\Users\\x\\a.exe","Raison":"r"}"#.as_slice(),
        br#"{"Action":"reglages","Valeur":"{\"Langue\":\"en\"}"}"#.as_slice(),
    ] {
        torturer(valide, &mut |o| {
            if let Ok(c) = crate::canal::admettre(o, Client::Administrateur, true) {
                assert_eq!(crate::validation::valider(&c), Ok(()));
            }
        });
    }
    // Débit dépassé : refus avant lecture, même pour une commande valide
    let r = crate::canal::admettre(br#"{"Action":"verification"}"#, Client::Administrateur, false).err().expect("refus");
    assert!(r.message.contains("Trop de commandes"), "{}", r.message);
}

#[test]
fn phase1_debit_du_canal() {
    use std::time::{Duration, Instant};
    let mut d = crate::validation::Debit::new(3, Duration::from_secs(10));
    let t = Instant::now();
    assert!(d.accepter(t) && d.accepter(t + Duration::from_secs(1)) && d.accepter(t + Duration::from_secs(2)));
    assert!(!d.accepter(t + Duration::from_secs(3)), "quatrième commande dans la fenêtre : refusée");
    assert!(!d.accepter(t + Duration::from_secs(9)), "un refus ne compte pas, mais la fenêtre est encore pleine");
    assert!(d.accepter(t + Duration::from_secs(10)), "la première est sortie de la fenêtre");
    assert!(!d.accepter(t + Duration::from_secs(10)));
}

#[test]
fn phase1_client_du_tube_identifie_sur_son_jeton() {
    use std::io::Write;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows::Win32::System::Pipes::{ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT};
    let nom = format!(r"\\.\pipe\d4t-essai-phase1-client-{}", std::process::id());
    let large: Vec<u16> = nom.encode_utf16().chain(Some(0)).collect();
    let tube = unsafe { CreateNamedPipeW(PCWSTR(large.as_ptr()), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 512, 512, 0, None) };
    assert!(!tube.is_invalid());
    let n = nom.clone();
    let client = std::thread::spawn(move || {
        let mut c = std::fs::OpenOptions::new().read(true).write(true).open(&n).unwrap();
        c.write_all(b"x").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(500));
    });
    let _ = unsafe { ConnectNamedPipe(tube, None) };
    // Le client est ce processus de test : comparé à un calcul indépendant (IsUserAnAdmin : administrateur élevé).
    // Tests lancés élevés : le cas « administrateur » est exercé ; sinon « autre » (et le passage VM, en
    // administrateur, exerce le cas élevé avec le service réel)
    let vu = crate::natif::client_tube(HANDLE(tube.0));
    let attendu = if crate::natif::est_systeme() {
        crate::validation::Client::Systeme
    } else if unsafe { windows::Win32::UI::Shell::IsUserAnAdmin() }.as_bool() {
        crate::validation::Client::Administrateur
    } else {
        crate::validation::Client::Autre
    };
    assert_eq!(vu, attendu, "client du tube mal identifié");
    client.join().unwrap();
    unsafe { let _ = CloseHandle(tube); }
    // Handle invalide : « autre » (échec fermé)
    assert_eq!(crate::natif::client_tube(windows::Win32::Foundation::INVALID_HANDLE_VALUE), crate::validation::Client::Autre);
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
