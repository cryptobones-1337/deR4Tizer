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
fn debogage_a_distance_du_navigateur() {
    assert!(crate::processus::suspicion(r#""C:\Program Files\Google\Chrome\Application\chrome.exe" --remote-debugging-port=9222 --headless"#).is_some());
    assert!(crate::processus::suspicion(r#""C:\Program Files\Google\Chrome\Application\chrome.exe" --profile-directory=Default"#).is_none());
}

// ------------------------------------------------------------ bruit, VPN, vie privée, UPnP, mise à jour

#[test]
fn apprentissage_et_exceptions() {
    use crate::apprentissage::{decider, signature, Exception};
    use std::collections::BTreeSet;
    let mut a = alerte("Alerte", "lancé par rmm-agent", "PowerShell obscurci : -enc AAAA", 5);
    a.processus = "powershell".into();
    a.mitre = "T1059.001".into();
    let sig = signature(&a);
    let vide = BTreeSet::new();
    // pendant l'apprentissage : information, comportement mémorisé
    assert_eq!(decider("Alerte", &sig, true, &vide, &[]), Some(("Info", " [mode apprentissage : comportement mémorisé]", true)));
    // une alerte critique n'est jamais adoucie, même apprise ou en exception
    let appris: BTreeSet<String> = [sig.clone()].into_iter().collect();
    assert_eq!(decider("Critique", &sig, true, &appris, &[]), None);
    // après l'apprentissage : comportement appris en information, inconnu en alerte
    assert_eq!(decider("Alerte", &sig, false, &appris, &[]).map(|d| d.0), Some("Info"));
    assert_eq!(decider("Alerte", "autre|chose|t####", false, &appris, &[]), None);
    // exception explicite
    let ex = vec![Exception { signature: sig.clone(), ..Default::default() }];
    assert_eq!(decider("Alerte", &sig, false, &vide, &ex).map(|d| d.0), Some("Info"));
    // une autre IP ne fait pas un autre comportement
    let mut b = a.clone();
    let mut c = a.clone();
    b.destination = "203.0.113.5".into();
    c.destination = "198.51.100.77".into();
    assert_eq!(signature(&b), signature(&c));
}

#[test]
fn mise_a_jour_versions_et_signatures() {
    use crate::maj::{plus_recente, signature_acceptable};
    assert!(plus_recente("4.10", "4.9"));
    assert!(plus_recente("v5.0", "4.9.9"));
    assert!(!plus_recente("4.0", "4.0"));
    assert!(!plus_recente("3.9", "4.0"));
    assert!(signature_acceptable(Some("Mairie X"), Some("Mairie X"), false).is_ok());
    assert!(signature_acceptable(Some("Pirate"), Some("Mairie X"), true).is_err(), "autre éditeur : refusé même en mode permissif");
    assert!(signature_acceptable(None, Some("Mairie X"), true).is_err(), "retour au non signé : refusé");
    assert!(signature_acceptable(None, None, false).is_err(), "non signé : pas d'installation automatique");
    assert!(signature_acceptable(None, None, true).is_ok());
    assert!(signature_acceptable(Some("Mairie X"), None, false).is_ok(), "première version signée");
}

#[test]
fn chemins_de_profil_masques() {
    assert_eq!(crate::commun::masquer_chemin(r"C:\Users\marie\AppData\Local\Zoom\bin\Zoom.exe"), r"%USERPROFILE%\AppData\Local\Zoom\bin\Zoom.exe");
    assert_eq!(crate::commun::masquer_chemin(r"C:\Program Files\App\a.exe"), r"C:\Program Files\App\a.exe");
}

#[test]
fn ip_directe_pour_les_editeurs_connus() {
    use crate::moniteur::ip_directe_normale;
    assert!(ip_directe_normale("Proton AG"));
    assert!(ip_directe_normale("Google LLC"));
    assert!(ip_directe_normale("Valve Corp."));
    assert!(!ip_directe_normale(""), "programme non signé : toujours pénalisé");
    assert!(!ip_directe_normale("Evil Software Ltd"));
}

#[test]
fn upnp_adresses_locales_seulement() {
    assert!(crate::upnp::decouper_url_test("http://192.168.1.254:5000/desc.xml").is_some());
    assert!(crate::upnp::decouper_url_test("http://203.0.113.9/desc.xml").is_none(), "jamais de requête vers Internet");
    assert!(crate::upnp::decouper_url_test("https://192.168.1.254/x").is_none());
    assert_eq!(crate::upnp::dechunker_test("4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"), "Wikipedia");
    let _ = crate::upnp::dechunker_test("ffffffff\r\nabc");
}
