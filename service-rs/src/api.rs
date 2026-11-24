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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use windows::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_ALG_HANDLE, BCRYPT_USE_SYSTEM_PREFERRED_RNG};

pub const FICHIER_JETON: &str = "api-jeton.txt";
const NOM_REGLE: &str = "deR4Tizer-API";
pub const MAX_CONNEXIONS: usize = 16;
/// Places des connexions venues du poste quand l'API écoute aussi sur le réseau (audit du 2026-11-23, A-1-3) : avant, 16
/// connexions muettes ouvertes depuis le poste, par n'importe quel compte, prenaient toutes les places et le SIEM distant
/// n'avait plus rien, sans alerte. Est comptée « du poste » une connexion de la boucle locale ou dont l'adresse distante est
/// l'adresse locale de la connexion (le poste vers sa propre adresse réseau, S295-02). Limite : une connexion du poste
/// vers une autre de ses adresses (poste à plusieurs cartes, adresse source choisie) n'est pas reconnue
pub const MAX_LOCALES: usize = 4;
/// Au plus un signal (SIEM et journal) par fenêtre quand des connexions sont refusées faute de place (A-1-3)
pub const FENETRE_SIGNAL_REFUS: Duration = Duration::from_secs(600);

static GENERATION: AtomicU64 = AtomicU64::new(0);
static PLACES: Mutex<Places> = Mutex::new(Places { total: 0, locales: 0 });
static SIGNAL: Mutex<SignalRefus> = Mutex::new(SignalRefus { dernier: None, quota_local: 0, plein: 0 });

/// Places occupées par les connexions en cours de traitement
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Places {
    pub total: usize,
    /// Connexions venues de la boucle locale (127.0.0.0/8, ::1)
    pub locales: usize,
}

/// Sort d'une connexion acceptée par le système
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    Acceptee,
    /// Adresse hors de la liste du SIEM (défense en profondeur, en plus du pare-feu) : fermée sans signal, comme avant
    AdresseRefusee,
    /// Boucle locale déjà à MAX_LOCALES places, API ouverte sur le réseau (A-1-3)
    QuotaLocal,
    /// Toutes les places prises
    Plein,
}

/// Décision pure (S295-02) : connexion venue du poste ? Boucle locale, ou adresse distante égale à l'adresse locale de la
/// connexion (le poste qui se connecte à sa propre adresse réseau, dans un réseau de SIEM autorisé). Adresse locale
/// illisible : comptée du poste (le quota le plus strict)
pub fn connexion_du_poste(distante: std::net::IpAddr, locale: Option<std::net::IpAddr>) -> bool {
    distante.is_loopback() || locale.is_none_or(|l| l == distante)
}

/// Décision pure (A-1-3). Sur le réseau, les connexions du poste (`connexion_du_poste`) n'ont que MAX_LOCALES places : un
/// programme du poste qui se connecte par la boucle locale ou par l'adresse de la connexion ne peut plus prendre celles
/// du SIEM (limite : par une autre adresse du poste, voir MAX_LOCALES). En écoute locale seule, tous les clients, SIEM
/// compris, viennent de la boucle locale : aucun quota ne peut les départager (limite déclarée), seul le signal reste
pub fn admettre(places: Places, locale: bool, autorisee: bool, reseau: bool) -> Admission {
    if !autorisee {
        Admission::AdresseRefusee
    } else if places.total >= MAX_CONNEXIONS {
        Admission::Plein
    } else if reseau && locale && places.locales >= MAX_LOCALES {
        Admission::QuotaLocal
    } else {
        Admission::Acceptee
    }
}

/// Refus faute de place comptés entre deux signaux
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SignalRefus {
    pub dernier: Option<Instant>,
    pub quota_local: u64,
    pub plein: u64,
}

impl SignalRefus {
    /// Décision pure : compte le refus ; Some((quota_local, plein)) quand un signal est dû (premier refus, puis premier
    /// refus après FENETRE_SIGNAL_REFUS), avec les refus comptés depuis le signal précédent, remis à zéro. Une ligne par
    /// fenêtre, jamais une par connexion
    pub fn noter(&mut self, refus: Admission, maintenant: Instant) -> Option<(u64, u64)> {
        match refus {
            Admission::QuotaLocal => self.quota_local += 1,
            Admission::Plein => self.plein += 1,
            Admission::Acceptee | Admission::AdresseRefusee => return None,
        }
        if self.dernier.is_some_and(|d| maintenant.saturating_duration_since(d) < FENETRE_SIGNAL_REFUS) {
            return None;
        }
        self.dernier = Some(maintenant);
        let compte = (self.quota_local, self.plein);
        (self.quota_local, self.plein) = (0, 0);
        Some(compte)
    }
}

/// Texte du signal de refus (pur)
pub fn message_refus(quota_local: u64, plein: u64) -> String {
    format!("API d'export : connexions refusées faute de place depuis le dernier signal : {quota_local} venue(s) du poste \
        (boucle locale ou adresse de la connexion) au-delà de leurs {MAX_LOCALES} places, {plein} avec les {MAX_CONNEXIONS} places prises. Un programme du poste \
        tient peut-être les places de l'API (A-1-3) ; le SIEM peut ne plus recevoir de réponse")
}

fn verrou<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Place rendue à la fin du traitement de la connexion, quoi qu'il arrive
struct Place {
    places: &'static Mutex<Places>,
    locale: bool,
}

impl Drop for Place {
    fn drop(&mut self) {
        let mut p = verrou(self.places);
        p.total = p.total.saturating_sub(1);
        if self.locale {
            p.locales = p.locales.saturating_sub(1);
        }
    }
}

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

/// Écoute de l'API (T-18), telle que le fil qui l'ouvre la connaît déjà : pas encore sue, ouverte, ou impossible (jeton
/// non créé, port non obtenu)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EtatEcoute {
    EnCours,
    Ouverte,
    Echec,
}

/// Génération de l'API et état de son écoute : seule la génération en cours écrit
static ECOUTE: Mutex<(u64, EtatEcoute)> = Mutex::new((0, EtatEcoute::EnCours));

fn noter_ecoute(generation: u64, e: EtatEcoute) {
    let mut g = verrou(&ECOUTE);
    if ecoute_notable(generation, g.0, GENERATION.load(Ordering::SeqCst)) {
        *g = (generation, e);
    }
}

/// Décision pure : un fil d'écoute ne note son état que pour la génération en cours, jamais par-dessus une plus récente.
/// Un fil arrêté par une génération suivante (arrêt normal) ne note donc rien ; un fil sorti alors que sa génération
/// est encore la courante note « Echec » (audit de #308, S308-02)
pub fn ecoute_notable(generation: u64, notee: u64, courante: u64) -> bool {
    generation >= notee && generation == courante
}

/// Décision pure (T-18) : état effectif de l'API d'export publié dans etat.json. « Desactive » ; « Joignable » (port
/// ouvert par le service : l'accès depuis le SIEM, pare-feu et réseau compris, n'est pas vérifié) ; « EnEchec » (jeton
/// non créé ou port non obtenu) ; « NonVerifiable » (ouverture en cours)
pub fn etat_api(actif: bool, ecoute: EtatEcoute) -> &'static str {
    if !actif {
        return "Desactive";
    }
    match ecoute {
        EtatEcoute::Ouverte => "Joignable",
        EtatEcoute::Echec => "EnEchec",
        EtatEcoute::EnCours => "NonVerifiable",
    }
}

/// État publié de l'API (`actif` : réglage en vigueur du moniteur). Écoute d'une génération dépassée : pas encore sue
pub fn etat_publie(actif: bool) -> commun::EtatSortie {
    let (g, e) = *verrou(&ECOUTE);
    let e = if g == GENERATION.load(Ordering::SeqCst) { e } else { EtatEcoute::EnCours };
    commun::EtatSortie { actif, etat: etat_api(actif, e).into() }
}

/// (Re)démarre l'API selon la configuration ; l'ancienne écoute s'arrête d'elle-même
pub fn demarrer(config: &ConfigApi) {
    let generation = GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
    noter_ecoute(generation, EtatEcoute::EnCours);
    regle_parefeu(config);
    if !config.actif {
        return;
    }
    let Some(jeton) = jeton() else {
        commun::journal("API d'export : non démarrée, jeton impossible à créer avec ses droits");
        noter_ecoute(generation, EtatEcoute::Echec);
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
            noter_ecoute(generation, EtatEcoute::Echec);
            return;
        };
        let _ = ecoute.set_nonblocking(true);
        commun::journal(&format!("API d'export : écoute sur {adresse}"));
        noter_ecoute(generation, EtatEcoute::Ouverte);
        ecouter(&ecoute, &jeton, &autorisees, reseau, &PLACES, &SIGNAL, &|| GENERATION.load(Ordering::SeqCst) == generation);
        // Écoute terminée : si cette génération est encore la courante, le port n'est plus tenu (« Joignable » ne doit pas
        // rester ; audit de #308, S308-02) ; arrêt normal par une génération suivante : ignoré par noter_ecoute
        noter_ecoute(generation, EtatEcoute::Echec);
    }).unwrap();
}

/// Boucle d'acceptation, tant que `continuer` (fonction à part pour le test de saturation, A-1-3). Places décidées par
/// `admettre` ; une connexion refusée est fermée aussitôt, et un refus faute de place est signalé au plus une fois par
/// fenêtre (`SignalRefus`)
pub fn ecouter(ecoute: &TcpListener, jeton: &str, autorisees: &[String], reseau: bool, places: &'static Mutex<Places>,
    signal: &Mutex<SignalRefus>, continuer: &dyn Fn() -> bool) {
    while continuer() {
        match ecoute.accept() {
            Ok((flux, pair)) => {
                let locale = connexion_du_poste(pair.ip(), flux.local_addr().ok().map(|a| a.ip()));
                // Défense en profondeur, en plus de la règle de pare-feu : seulement les adresses du SIEM
                let admission = {
                    let mut p = verrou(places);
                    let a = admettre(*p, locale, autorisee(pair.ip(), autorisees), reseau);
                    if a == Admission::Acceptee {
                        p.total += 1;
                        if locale {
                            p.locales += 1;
                        }
                    }
                    a
                };
                if admission != Admission::Acceptee {
                    drop(flux);
                    signaler(signal, admission);
                    continue;
                }
                let place = Place { places, locale };
                let j = jeton.to_string();
                // Fil impossible à créer : la fermeture est rendue, la place avec elle (pas de panique)
                let _ = std::thread::Builder::new().name("api-connexion".into()).spawn(move || {
                    let _place = place;
                    let _ = traiter(flux, &j);
                });
            }
            Err(_) => std::thread::sleep(Duration::from_millis(250)),
        }
    }
}

/// Signal d'un refus faute de place : journal et SIEM (source « api », type « connexions-refusees »), une fois par fenêtre
fn signaler(signal: &Mutex<SignalRefus>, refus: Admission) {
    let du = verrou(signal).noter(refus, Instant::now());
    if let Some((quota_local, plein)) = du {
        let m = message_refus(quota_local, plein);
        commun::journal(&m);
        crate::siem::enregistrer(crate::siem::Evenement {
            heure: commun::maintenant(), source: "api".into(), type_: "connexions-refusees".into(), niveau: "Alerte".into(),
            message: m, ..Default::default()
        });
    }
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
    // Suivi : l'arrêt du service attend ce PowerShell, qui ne recrée donc pas ses règles après la désinstallation (PR 6.12)
    crate::blocage::powershell_regles("api", &script);
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
            // Lecture tolérante sans effet (phase 3.1) : un élément illisible ne vide plus la réponse
            let mut alertes: Vec<Alerte> = commun::lire_alertes_sans_effet();
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
                echeance: None,
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
