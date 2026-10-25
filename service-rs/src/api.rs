//! API HTTP d'export, en lecture seule, pour un SIEM ou un outil tiers.
//! Protégée par un jeton (en-tête « Authorization: Bearer <jeton> »), stocké dans api-jeton.txt,
//! lisible par SYSTEM et les administrateurs seulement. Écoute sur 127.0.0.1, ou sur le réseau local
//! si demandé (une règle de pare-feu « deR4Tizer API » ouvre alors le port, profils Domaine et Privé).
//!
//!   GET /api/v1/sante                                    sans jeton : vérification de disponibilité
//!   GET /api/v1/alertes?depuis=&niveau=&limite=&format=  format : json (défaut), ndjson ou cef
//!   GET /api/v1/evenements?q=&source=&type=&niveau=&depuis=&jusqua=&limite=&format=json|ndjson   (mini-SIEM)
//!   GET /api/v1/incidents                                incidents de corrélation
//!   GET /api/v1/connexions | etat | exposition | baseline | regles-parefeu | blocages
//!   GET /api/v1/journal?lignes=200                       texte brut

use crate::commun::{self, Alerte, ConfigApi};
use crate::export;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use windows::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_ALG_HANDLE, BCRYPT_USE_SYSTEM_PREFERRED_RNG};

pub const FICHIER_JETON: &str = "api-jeton.txt";
const NOM_REGLE: &str = "deR4Tizer-API";
const MAX_CONNEXIONS: usize = 16;

static GENERATION: AtomicU64 = AtomicU64::new(0);
static CONNEXIONS: AtomicUsize = AtomicUsize::new(0);

// ------------------------------------------------------------ jeton

fn nouveau_jeton() -> Option<String> {
    let mut octets = [0u8; 32];
    let ok = unsafe { BCryptGenRandom(BCRYPT_ALG_HANDLE::default(), &mut octets, BCRYPT_USE_SYSTEM_PREFERRED_RNG).is_ok() };
    jeton_depuis_alea(ok, &octets)
}

/// Décision pure : jeton tiré des octets aléatoires, seulement si le générateur a réussi et a rendu 32 octets
/// non tous nuls (un tampon resté à zéro donnerait un jeton connu de tous). None : pas de jeton, pas d'API
/// (échec fermé)
pub fn jeton_depuis_alea(generateur_ok: bool, octets: &[u8]) -> Option<String> {
    (generateur_ok && octets.len() >= 32 && octets.iter().any(|&o| o != 0)).then(|| octets.iter().map(|o| format!("{o:02x}")).collect())
}

/// Décision pure : un jeton déjà présent n'est repris que s'il a la forme de ceux que crée le service (64 caractères
/// hexadécimaux, pas tous nuls) ; sinon il est régénéré
pub fn jeton_valide(j: &str) -> bool {
    j.len() == 64 && j.bytes().all(|o| o.is_ascii_hexdigit()) && j.bytes().any(|o| o != b'0')
}

/// Réponse de /api/v1/sante, servie sans jeton : disponibilité et version, rien qui identifie le poste
pub fn corps_sante() -> String {
    format!(r#"{{"Ok":true,"Produit":"deR4Tizer","Version":"{}"}}"#, commun::VERSION)
}

/// Jeton : SYSTEM et administrateurs seulement, droits posés à la création du fichier (le dossier est
/// lisible par les comptes autorisés)
const SDDL_JETON: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";

/// Jeton actuel, créé au premier besoin. None si le jeton ne peut pas être créé avec ses droits : l'API ne
/// démarre pas sans jeton protégé (échec fermé)
pub fn jeton() -> Option<String> {
    let f = commun::dossier().join(FICHIER_JETON);
    match commun::lire_fichier(&f) {
        Some(j) if jeton_valide(j.trim()) && droits_jeton(&f).is_ok() => Some(j.trim().to_string()),
        _ => regenerer_jeton().map_err(|e| commun::journal(&format!("API d'export : jeton non créé ({e})"))).ok(),
    }
}

/// Droits du jeton relus (en service seulement : en mode console, le propriétaire est l'utilisateur)
fn droits_jeton(f: &std::path::Path) -> Result<(), String> {
    use crate::protection::{SID_ADMINISTRATEURS, SID_SYSTEME};
    if !crate::natif::est_systeme() {
        return Ok(());
    }
    crate::protection::verifier(f, &[SID_SYSTEME, SID_ADMINISTRATEURS], &[])
}

pub fn regenerer_jeton() -> Result<String, String> {
    let f = commun::dossier().join(FICHIER_JETON);
    let j = nouveau_jeton().ok_or("générateur aléatoire de Windows en échec")?;
    crate::natif::ecrire_fichier_protege(&f, j.as_bytes(), SDDL_JETON)?;
    droits_jeton(&f)?;
    Ok(j)
}

/// Au démarrage : un jeton dont les droits ne sont plus ceux posés à la création a pu être lu ; il est remplacé
pub fn proteger_jeton() -> Result<(), String> {
    let f = commun::dossier().join(FICHIER_JETON);
    if !f.exists() || droits_jeton(&f).is_ok() {
        return Ok(());
    }
    commun::journal("API d'export : droits du jeton modifiés, nouveau jeton créé");
    regenerer_jeton().map(|_| ())
}

/// Comparaison en temps constant
fn egaux(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ------------------------------------------------------------ serveur

/// (Re)démarre l'API selon la configuration ; l'ancienne écoute s'arrête d'elle-même
pub fn demarrer(config: &ConfigApi) {
    let generation = GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
    regle_parefeu(config);
    if !config.actif {
        return;
    }
    let Some(jeton) = jeton() else {
        commun::journal("API d'export : non démarrée, jeton impossible à créer avec ses droits");
        return;
    };
    let autorisees = adresses_autorisees(config);
    if config.reseau && autorisees.is_empty() {
        commun::journal("API d'export : accès réseau refusé sans adresse de SIEM autorisée ; écoute locale seulement");
    }
    let reseau = config.reseau && !autorisees.is_empty();
    let adresse = format!("{}:{}", if reseau { "0.0.0.0" } else { "127.0.0.1" }, config.port);
    std::thread::Builder::new().name("api".into()).spawn(move || {
        // L'ancienne écoute peut tenir le port quelques instants
        let mut ecoute = None;
        for _ in 0..10 {
            match TcpListener::bind(&adresse) {
                Ok(l) => {
                    ecoute = Some(l);
                    break;
                }
                Err(_) => std::thread::sleep(Duration::from_millis(500)),
            }
        }
        let Some(ecoute) = ecoute else {
            commun::journal(&format!("API d'export : impossible d'écouter sur {adresse}"));
            return;
        };
        let _ = ecoute.set_nonblocking(true);
        commun::journal(&format!("API d'export : écoute sur {adresse}"));
        while GENERATION.load(Ordering::SeqCst) == generation {
            match ecoute.accept() {
                Ok((flux, pair)) => {
                    // Défense en profondeur, en plus de la règle de pare-feu : seulement les adresses du SIEM
                    if CONNEXIONS.load(Ordering::SeqCst) >= MAX_CONNEXIONS || !autorisee(pair.ip(), &autorisees) {
                        continue;
                    }
                    CONNEXIONS.fetch_add(1, Ordering::SeqCst);
                    let j = jeton.clone();
                    std::thread::spawn(move || {
                        let _ = traiter(flux, &j);
                        CONNEXIONS.fetch_sub(1, Ordering::SeqCst);
                    });
                }
                Err(_) => std::thread::sleep(Duration::from_millis(250)),
            }
        }
    }).unwrap();
}

/// Ouvre le port sur le réseau local (profils Domaine et Privé, jamais Public), ou retire la règle
fn regle_parefeu(config: &ConfigApi) {
    let script = if config.actif && config.reseau {
        format!("Remove-NetFirewallRule -Name '{NOM_REGLE}' -ErrorAction SilentlyContinue; \
            New-NetFirewallRule -Name '{NOM_REGLE}' -DisplayName 'deR4Tizer API' -Group '{}' -Direction Inbound \
            -Protocol TCP -LocalPort {} -RemoteAddress {} -Action Allow -Profile Domain,Private | Out-Null; \
            Remove-NetFirewallRule -Name '{NOM_REGLE}-public' -ErrorAction SilentlyContinue; \
            New-NetFirewallRule -Name '{NOM_REGLE}-public' -DisplayName 'deR4Tizer API (réseau public bloqué)' -Group '{}' \
            -Direction Inbound -Protocol TCP -LocalPort {} -Action Block -Profile Public | Out-Null",
            crate::blocage::GROUPE, config.port, liste_powershell(&adresses_autorisees(config)), crate::blocage::GROUPE, config.port)
    } else {
        format!("Remove-NetFirewallRule -Name '{NOM_REGLE}' -ErrorAction SilentlyContinue; Remove-NetFirewallRule -Name '{NOM_REGLE}-public' -ErrorAction SilentlyContinue")
    };
    crate::mesure::powershell("api");
    let _ = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .creation_flags(0x0800_0000)
        .output();
}

/// Une adresse autorisée : IPv4 exacte, ou réseau IPv4 de /8 à /32 (l'API n'écoute qu'en IPv4). Tout le reste est
/// refusé : avant, seule la partie avant « / » était vérifiée et la suite allait telle quelle dans un script
/// PowerShell exécuté en SYSTEM (audit, SEC-009) ; un réseau IPv6 ouvrait le pare-feu sans jamais être reconnu (SEC-007).
pub fn adresse_autorisee_valide(a: &str) -> bool {
    match a.split_once('/') {
        None => a.parse::<std::net::Ipv4Addr>().is_ok(),
        Some((ip, l)) => ip.parse::<std::net::Ipv4Addr>().is_ok() && l.len() <= 2 && l.bytes().all(|b| b.is_ascii_digit())
            && l.parse::<u32>().is_ok_and(|n| (8..=32).contains(&n)),
    }
}

/// Entrées invalides de la liste saisie (vide : liste valide)
pub fn adresses_invalides(texte: &str) -> Vec<String> {
    texte.split([',', ';', ' ', '\t', '\r', '\n']).map(str::trim).filter(|a| !a.is_empty() && !adresse_autorisee_valide(a)).map(String::from).collect()
}

/// Adresses ou réseaux (CIDR) autorisés à interroger l'API depuis le réseau (seulement des entrées valides)
fn adresses_autorisees(config: &ConfigApi) -> Vec<String> {
    config.adresses.split([',', ';', ' ', '\t', '\r', '\n']).map(str::trim)
        .filter(|a| !a.is_empty() && adresse_autorisee_valide(a))
        .map(String::from).collect()
}

/// Liste PowerShell de chaînes entre apostrophes (chiffres, points et « / » seulement après validation) ; vide : rien
/// n'est autorisé (« 127.0.0.1 »)
pub fn liste_powershell(adresses: &[String]) -> String {
    let l: Vec<String> = adresses.iter().filter(|a| adresse_autorisee_valide(a)).map(|a| format!("'{a}'")).collect();
    if l.is_empty() { "'127.0.0.1'".into() } else { format!("@({})", l.join(",")) }
}

fn autorisee(ip: std::net::IpAddr, autorisees: &[String]) -> bool {
    if ip.is_loopback() {
        return true;
    }
    autorisees.iter().any(|a| match a.split_once('/') {
        None => a.parse::<std::net::IpAddr>().map(|x| x == ip).unwrap_or(false),
        Some((r, l)) => match (r.parse::<std::net::Ipv4Addr>(), l.parse::<u32>(), ip) {
            (Ok(r), Ok(l), std::net::IpAddr::V4(v)) if l <= 32 => {
                let m = if l == 0 { 0 } else { u32::MAX << (32 - l) };
                u32::from(r) & m == u32::from(v) & m
            }
            _ => false,
        },
    })
}

fn traiter(mut flux: TcpStream, jeton: &str) -> std::io::Result<()> {
    flux.set_nonblocking(false)?;
    flux.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut demande = Vec::new();
    let mut tampon = [0u8; 2048];
    // Échéance totale de lecture de la requête (audit, AUD3-05) : avant, un client qui envoyait un octet toutes les
    // 4 s tenait la connexion des heures ; 16 connexions lentes rendaient l'API indisponible. Chaque lecture attend au
    // plus le temps qui reste (5 s au plus) : 10 s en tout, jamais 10 s plus une dernière lecture
    let debut = std::time::Instant::now();
    while !demande.windows(4).any(|w| w == b"\r\n\r\n") {
        let reste = Duration::from_secs(10).saturating_sub(debut.elapsed());
        if reste.is_zero() {
            return Ok(());
        }
        flux.set_read_timeout(Some(reste.min(Duration::from_secs(5))))?;
        let n = flux.read(&mut tampon)?;
        if n == 0 || demande.len() > 16 * 1024 {
            break;
        }
        demande.extend_from_slice(&tampon[..n]);
    }
    let texte = String::from_utf8_lossy(&demande);
    let mut lignes = texte.split("\r\n");
    let premiere = lignes.next().unwrap_or("");
    let mut morceaux = premiere.split_whitespace();
    let (methode, cible) = (morceaux.next().unwrap_or(""), morceaux.next().unwrap_or(""));
    let autorisation = lignes
        .filter_map(|l| l.split_once(':'))
        .find(|(n, _)| n.trim().eq_ignore_ascii_case("authorization"))
        .map(|(_, v)| v.trim().to_string())
        .unwrap_or_default();
    let (chemin, requete) = cible.split_once('?').unwrap_or((cible, ""));
    let parametre = |nom: &str| -> Option<String> {
        requete.split('&').filter_map(|p| p.split_once('=')).find(|(n, _)| *n == nom).map(|(_, v)| decoder(v))
    };

    if methode != "GET" {
        return repondre(&mut flux, 405, "application/json", r#"{"Erreur":"méthode non autorisée (lecture seule)"}"#);
    }
    if chemin == "/api/v1/sante" {
        return repondre(&mut flux, 200, "application/json", &corps_sante());
    }
    let fourni = autorisation.strip_prefix("Bearer ").unwrap_or("");
    if !egaux(fourni, jeton) {
        // Ralentit les essais de jeton
        std::thread::sleep(Duration::from_secs(1));
        return repondre(&mut flux, 401, "application/json", r#"{"Erreur":"jeton absent ou invalide"}"#);
    }

    let brut = |nom: &str| commun::lire_fichier(&commun::dossier().join(nom)).unwrap_or_else(|| "null".into());
    let champ_etat = |champ: &str| {
        serde_json::from_str::<serde_json::Value>(&brut("etat.json")).ok()
            .and_then(|v| v.get(champ).cloned()).unwrap_or_default().to_string()
    };
    match chemin {
        "/api/v1/alertes" => {
            let mut alertes: Vec<Alerte> = commun::lire("alertes.json").unwrap_or_default();
            if let Some(d) = parametre("depuis") {
                let d = d.replace('T', " ");
                alertes.retain(|a| a.heure.as_str() > d.as_str());
            }
            if let Some(n) = parametre("niveau") {
                alertes.retain(|a| export::rang(&a.niveau) >= export::rang(&n));
            }
            let limite = parametre("limite").and_then(|l| l.parse().ok()).unwrap_or(500usize).min(1000);
            let debut = alertes.len().saturating_sub(limite);
            let alertes = &alertes[debut..];
            match parametre("format").as_deref() {
                Some("ndjson") => repondre(&mut flux, 200, "application/x-ndjson",
                    &alertes.iter().map(export::json).collect::<Vec<_>>().join("\n")),
                Some("cef") => repondre(&mut flux, 200, "text/plain",
                    &alertes.iter().map(export::cef).collect::<Vec<_>>().join("\n")),
                _ => repondre(&mut flux, 200, "application/json", &serde_json::to_string(alertes).unwrap_or_default()),
            }
        }
        "/api/v1/evenements" => {
            let p = |n: &str| parametre(n).unwrap_or_default().replace('T', " ");
            let filtre = crate::siem::Filtre {
                texte: parametre("q").unwrap_or_default(),
                source: p("source"),
                type_: parametre("type").unwrap_or_default(),
                niveau_min: p("niveau"),
                depuis: p("depuis"),
                jusqua: p("jusqua"),
                limite: parametre("limite").and_then(|l| l.parse().ok()).unwrap_or(500usize).min(5000),
            };
            let evenements = crate::siem::rechercher(&filtre);
            if parametre("format").as_deref() == Some("ndjson") {
                repondre(&mut flux, 200, "application/x-ndjson",
                    &evenements.iter().filter_map(|e| serde_json::to_string(e).ok()).collect::<Vec<_>>().join("\n"))
            } else {
                repondre(&mut flux, 200, "application/json", &serde_json::to_string(&evenements).unwrap_or_default())
            }
        }
        "/api/v1/incidents" => repondre(&mut flux, 200, "application/json", &brut("incidents.json")),
        "/api/v1/connexions" => repondre(&mut flux, 200, "application/json", &champ_etat("Flux")),
        "/api/v1/exposition" => repondre(&mut flux, 200, "application/json", &champ_etat("Exposition")),
        "/api/v1/etat" => repondre(&mut flux, 200, "application/json", &brut("etat.json")),
        "/api/v1/baseline" => repondre(&mut flux, 200, "application/json", &brut("baseline.json")),
        "/api/v1/regles-parefeu" => repondre(&mut flux, 200, "application/json", &brut("parefeu.json")),
        "/api/v1/blocages" => repondre(&mut flux, 200, "application/json", &brut("blocages.json")),
        "/api/v1/journal" => {
            let n = parametre("lignes").and_then(|l| l.parse().ok()).unwrap_or(200usize).min(5000);
            let tout = commun::lire_fichier(&commun::dossier().join("journal.txt")).unwrap_or_default();
            let lignes: Vec<&str> = tout.lines().collect();
            repondre(&mut flux, 200, "text/plain", &lignes[lignes.len().saturating_sub(n)..].join("\n"))
        }
        _ => repondre(&mut flux, 404, "application/json", r#"{"Erreur":"route inconnue"}"#),
    }
}

fn repondre(flux: &mut TcpStream, code: u16, type_: &str, corps: &str) -> std::io::Result<()> {
    let statut = match code {
        200 => "OK",
        401 => "Unauthorized",
        404 => "Not Found",
        _ => "Method Not Allowed",
    };
    let entete = format!("HTTP/1.1 {code} {statut}\r\nContent-Type: {type_}; charset=utf-8\r\nContent-Length: {}\r\n\
        Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n", corps.len());
    flux.write_all(entete.as_bytes())?;
    flux.write_all(corps.as_bytes())?;
    flux.flush()
}

/// Décodage des paramètres d'URL (%xx et +)
fn decoder(v: &str) -> String {
    let o = v.as_bytes();
    let mut sortie = Vec::with_capacity(o.len());
    let mut i = 0;
    while i < o.len() {
        match o[i] {
            b'+' => sortie.push(b' '),
            b'%' if i + 2 < o.len() => {
                match u8::from_str_radix(std::str::from_utf8(&o[i + 1..i + 3]).unwrap_or(""), 16) {
                    Ok(b) => {
                        sortie.push(b);
                        i += 2;
                    }
                    Err(_) => sortie.push(b'%'),
                }
            }
            b => sortie.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&sortie).into_owned()
}

#[cfg(test)]
pub fn autorisee_test(ip: std::net::IpAddr, l: &[String]) -> bool {
    autorisee(ip, l)
}

#[cfg(test)]
pub fn decoder_test(v: &str) -> String {
    decoder(v)
}
