//! Résolveur local (phase 7, PR 7.3) : écoute UDP et TCP sur `127.0.0.1:53` et `[::1]:53` **seulement**, répond
//! lui-même pour un nom bloqué par le filtrage (`filtrage.rs`) et relaie le reste vers l'amont. **Non branché sur les
//! cartes** pendant un essai (commande `filtrageEssai`, 10 minutes au plus). En mode permanent (PR 7.4, activation du
//! filtrage, `filtrage_cartes.rs`), les cartes matérielles sont réglées sur lui ; quand l'amont se tait, les cartes sont
//! rendues à leurs serveurs d'origine **sans relâcher le port** (préalable de l'audit de #161, S161-02), puis rebranchées
//! dès qu'une sonde de l'amont répond.
//!
//! - Requête (parseur borné, torturé) : UDP 512 octets, TCP 4096 au plus ; une seule question ; nom de 253 caractères
//!   et 127 étiquettes au plus, sans pointeur de compression ; sinon FORMERR, rien n'est relayé.
//! - Bloqué : A `0.0.0.0`, AAAA `::`, autres types (HTTPS, SVCB…) réponse vide (NODATA) ; TTL 60 s. Nom spécial
//!   `use-application-dns.net` : NXDOMAIN quand le filtrage est actif (D7-6 : Firefox ne passe pas de lui-même au DNS
//!   chiffré).
//! - Relayé : nouvel identifiant et nouveau port source aléatoires (`BCryptGenRandom`, port tiré dans la plage
//!   dynamique 49152-65535 : relecture de #161, constat 1 ; MS08-037 ; générateur en échec : rien n'est relayé, C-10) ;
//!   réponse acceptée
//!   seulement si l'adresse de l'amont, l'identifiant et la question correspondent, puis rendue avec l'identifiant
//!   d'origine. Pas de cache (le client DNS de Windows en a un). Réponse tronquée en UDP : rendue telle quelle, le client
//!   réessaie en TCP auprès du résolveur, qui relaie alors en TCP. 2 s par amont, puis le suivant ; en TCP, 4 s en
//!   tout pour l'échange avec un amont (C-6).
//! - Amont : serveurs DNS des cartes matérielles au lancement de l'essai (`amonts` : ni boucle locale, ni `fec0::/10`,
//!   ni lien local ; IPv4 d'abord).
//! - Dégradation ouverte : aucun amont ne répond pendant 30 s, et la sonde du service (un nom de la liste de protection)
//!   non plus → l'essai s'arrête (le DNS du poste n'est jamais coupé : les cartes ne sont pas réglées sur le
//!   résolveur). Les seules requêtes des clients ne suffisent pas (C-7).
//! - Bornes : 16 requêtes en cours, dont 4 connexions TCP au plus ; au-delà, la requête est ignorée (le client
//!   réessaie). Une connexion TCP a 4 s en tout pour envoyer sa requête (audit de #161, S161-01). Ni PowerShell ni
//!   verrou du moniteur sur le chemin d'une requête.
//! - Écoutes liées avec `SO_EXCLUSIVEADDRUSE` : aucun autre programme ne peut se lier au même port à côté, et la
//!   liaison échoue si un autre logiciel tient déjà le port 53 (audit de #161, S161-02, préalable à 7.4).

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const MAX_UDP: usize = 512;
pub const MAX_TCP: usize = 4096;
pub const TTL: u32 = 60;
pub const CANARI: &str = "use-application-dns.net";
pub const MAX_EN_COURS: usize = 16;
/// Connexions TCP en cours, au plus (sur les 16) : l'UDP reste servi
pub const MAX_TCP_EN_COURS: usize = 4;
/// Échéance totale d'une connexion TCP pour envoyer sa requête, depuis l'acceptation
const ECHEANCE_TCP: Duration = Duration::from_secs(4);
/// Échéance totale d'un échange TCP avec un amont (connexion, envoi, réponse complète) : C-6
pub const ECHEANCE_TCP_AMONT: Duration = Duration::from_secs(4);
pub const DUREE_ESSAI: Duration = Duration::from_secs(600);
/// Délai par amont
const DELAI_AMONT: Duration = Duration::from_secs(2);
/// Sans aucune réponse d'amont pendant ce délai (alors que des requêtes sont relayées) : arrêt
pub const SILENCE_AMONT_S: u64 = 30;

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASSE_IN: u16 = 1;

/// Question d'une requête
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    /// Nom en texte (étiquettes jointes par des points, octets non ASCII remplacés : le filtrage le jugera invalide)
    pub nom: String,
    pub type_: u16,
    pub classe: u16,
    /// Octets de la question telle que reçue (nom encodé, type, classe)
    pub brute: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Requete {
    pub id: u16,
    pub drapeaux: u16,
    pub question: Question,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Lecture {
    Requete(Requete),
    /// En-tête lisible mais requête refusée : FORMERR avec cet identifiant
    Formerr(u16),
    /// Trop court, ou réponse (bit QR) : ignoré sans réponse
    Ignoree,
}

fn u16_de(p: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*p.get(i)?, *p.get(i + 1)?]))
}

/// Lecture d'une requête (pure, testée, torturée)
pub fn lire_requete(p: &[u8], max: usize) -> Lecture {
    if p.len() < 12 {
        return Lecture::Ignoree;
    }
    let id = u16::from_be_bytes([p[0], p[1]]);
    let drapeaux = u16::from_be_bytes([p[2], p[3]]);
    if drapeaux & 0x8000 != 0 {
        return Lecture::Ignoree;
    }
    let opcode = (drapeaux >> 11) & 0xF;
    let (qd, an, ns) = (u16::from_be_bytes([p[4], p[5]]), u16::from_be_bytes([p[6], p[7]]), u16::from_be_bytes([p[8], p[9]]));
    if p.len() > max || opcode != 0 || qd != 1 || an != 0 || ns != 0 {
        return Lecture::Formerr(id);
    }
    let mut i = 12;
    let mut etiquettes: Vec<String> = Vec::new();
    let mut longueur_texte = 0usize;
    loop {
        let Some(&n) = p.get(i) else { return Lecture::Formerr(id) };
        i += 1;
        if n == 0 {
            break;
        }
        // Pointeur de compression (0xC0) ou type d'étiquette réservé (0x40, 0x80) : refusé dans une question
        if n & 0xC0 != 0 {
            return Lecture::Formerr(id);
        }
        let n = n as usize;
        let Some(e) = p.get(i..i + n) else { return Lecture::Formerr(id) };
        if e.contains(&b'.') {
            return Lecture::Formerr(id);
        }
        i += n;
        longueur_texte += n + usize::from(!etiquettes.is_empty());
        etiquettes.push(e.iter().map(|&b| if b.is_ascii_graphic() { b as char } else { '\u{FFFD}' }).collect());
        if etiquettes.len() > 127 || longueur_texte > 253 {
            return Lecture::Formerr(id);
        }
    }
    let (Some(type_), Some(classe)) = (u16_de(p, i), u16_de(p, i + 2)) else { return Lecture::Formerr(id) };
    let brute = p[12..i + 4].to_vec();
    Lecture::Requete(Requete { id, drapeaux, question: Question { nom: etiquettes.join("."), type_, classe, brute } })
}

fn entete(id: u16, drapeaux_requete: u16, rcode: u16, qd: u16, an: u16) -> Vec<u8> {
    // QR, opcode 0, RD repris de la requête, RA
    let drapeaux = 0x8000 | (drapeaux_requete & 0x0100) | 0x0080 | (rcode & 0xF);
    let mut v = Vec::with_capacity(64);
    for x in [id, drapeaux, qd, an, 0, 0] {
        v.extend_from_slice(&x.to_be_bytes());
    }
    v
}

/// Réponse à un nom bloqué (pure, testée) : A `0.0.0.0`, AAAA `::`, autre type NODATA ; TTL 60 s
pub fn reponse_bloquee(r: &Requete) -> Vec<u8> {
    let q = &r.question;
    let donnees: Option<&[u8]> = match (q.type_, q.classe) {
        (TYPE_A, CLASSE_IN) => Some(&[0u8; 4]),
        (TYPE_AAAA, CLASSE_IN) => Some(&[0u8; 16]),
        _ => None,
    };
    let mut v = entete(r.id, r.drapeaux, 0, 1, u16::from(donnees.is_some()));
    v.extend_from_slice(&q.brute);
    if let Some(d) = donnees {
        v.extend_from_slice(&0xC00Cu16.to_be_bytes());
        v.extend_from_slice(&q.type_.to_be_bytes());
        v.extend_from_slice(&q.classe.to_be_bytes());
        v.extend_from_slice(&TTL.to_be_bytes());
        v.extend_from_slice(&(d.len() as u16).to_be_bytes());
        v.extend_from_slice(d);
    }
    v
}

/// NXDOMAIN (nom spécial de Firefox), question reprise (pure)
pub fn reponse_nxdomain(r: &Requete) -> Vec<u8> {
    let mut v = entete(r.id, r.drapeaux, 3, 1, 0);
    v.extend_from_slice(&r.question.brute);
    v
}

/// FORMERR, sans question (pure)
pub fn reponse_formerr(id: u16) -> Vec<u8> {
    entete(id, 0, 1, 0, 0)
}

/// Réponse d'amont acceptée seulement si elle porte l'identifiant envoyé, le bit de réponse, une seule question, et
/// la même question (le nom sans tenir compte de la casse : un amont peut la changer) (pure, testée)
pub fn reponse_assortie(rep: &[u8], id_envoye: u16, question_brute: &[u8]) -> bool {
    if rep.len() < 12 + question_brute.len() || u16::from_be_bytes([rep[0], rep[1]]) != id_envoye || rep[2] & 0x80 == 0 {
        return false;
    }
    if u16::from_be_bytes([rep[4], rep[5]]) != 1 {
        return false;
    }
    // Nom sans tenir compte de la casse ; type et classe (4 derniers octets) à l'identique
    let n = question_brute.len().saturating_sub(4);
    let recu = &rep[12..12 + question_brute.len()];
    recu[..n].eq_ignore_ascii_case(&question_brute[..n]) && recu[n..] == question_brute[n..]
}

/// Le même paquet avec un autre identifiant (pure)
pub fn avec_id(p: &[u8], id: u16) -> Vec<u8> {
    let mut v = p.to_vec();
    if v.len() >= 2 {
        v[..2].copy_from_slice(&id.to_be_bytes());
    }
    v
}

/// Ce que le résolveur fait d'une requête lue (pure, testée)
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Repondre(Vec<u8>),
    Relayer,
}

pub fn traiter(r: &Requete, filtrage_actif: bool, bloque: &dyn Fn(&str) -> bool) -> Action {
    let nom = r.question.nom.to_ascii_lowercase();
    if filtrage_actif && (nom == CANARI || nom.ends_with(&format!(".{CANARI}"))) {
        return Action::Repondre(reponse_nxdomain(r));
    }
    if filtrage_actif && bloque(&nom) {
        return Action::Repondre(reponse_bloquee(r));
    }
    Action::Relayer
}

/// Silence de l'amont (pur, testé) : vrai quand aucun amont n'a répondu depuis `SILENCE_AMONT_S` alors que des
/// requêtes ont été relayées pendant tout ce temps
#[derive(Default)]
pub struct Sante {
    premier_echec: Option<u64>,
}

impl Sante {
    pub fn noter(&mut self, ok: bool, maintenant_s: u64) -> bool {
        if ok {
            self.premier_echec = None;
            return false;
        }
        let debut = *self.premier_echec.get_or_insert(maintenant_s);
        maintenant_s.saturating_sub(debut) >= SILENCE_AMONT_S
    }

    /// Seuil atteint par `noter` : le silence n'est déclaré que si la sonde propre du service (un nom de la liste de
    /// protection, `sonder`) ne reçoit pas de réponse non plus (constat C-7 de l'audit du 2026-11-23 : les seules
    /// requêtes des clients, qu'un programme du poste choisit, par exemple des noms dont le serveur ne répond jamais,
    /// faisaient rendre les cartes et suspendre le filtrage pour tout le poste). Sonde répondue : fenêtre remise à zéro
    pub fn confirmer(&mut self, sonde_repond: bool) -> bool {
        if sonde_repond {
            self.premier_echec = None;
        }
        !sonde_repond
    }
}

/// Amonts de l'essai : serveurs DNS des cartes réglables (`dns_surveillance::filtrable`), utilisables
/// (`filtrage_cartes::amont_utilisable` : ni boucle locale, ni `fec0::/10`, ni lien local), sans doublon, IPv4 d'abord
/// comme en mode permanent, 4 au plus (pur, testé ; T-9, T-10)
pub fn amonts(cartes: &[crate::dns_surveillance::CarteDns]) -> Vec<IpAddr> {
    let mut l: Vec<IpAddr> = Vec::new();
    let tous = cartes.iter().filter(|c| crate::dns_surveillance::filtrable(c)).flat_map(|c| c.dns.iter()).filter_map(|d| d.parse::<IpAddr>().ok())
        .filter(crate::filtrage_cartes::amont_utilisable).collect::<Vec<_>>();
    for ip in tous.iter().filter(|i| i.is_ipv4()).chain(tous.iter().filter(|i| i.is_ipv6())) {
        if !l.contains(ip) && l.len() < 4 {
            l.push(*ip);
        }
    }
    l
}

/// 16 bits aléatoires, seulement si le générateur a réussi (pur, testé ; constat C-10 de l'audit du 2026-11-23, comme
/// `api::jeton_depuis_alea`) : None, et rien n'est relayé (échec fermé), plutôt qu'un identifiant et un port toujours nuls
pub fn alea_u16(generateur_ok: bool, octets: [u8; 2]) -> Option<u16> {
    generateur_ok.then(|| u16::from_ne_bytes(octets))
}

fn identifiant_aleatoire() -> Option<u16> {
    use windows::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_ALG_HANDLE, BCRYPT_USE_SYSTEM_PREFERRED_RNG};
    let mut o = [0u8; 2];
    let ok = unsafe { BCryptGenRandom(BCRYPT_ALG_HANDLE::default(), &mut o, BCRYPT_USE_SYSTEM_PREFERRED_RNG).is_ok() };
    alea_u16(ok, o)
}

/// Port de la plage dynamique (49152-65535) tiré de 16 bits aléatoires (pur, testé)
pub fn port_dynamique(alea: u16) -> u16 {
    49152 + alea % 16384
}

/// Socket UDP vers l'amont, lié à un port source tiré au hasard ; 8 essais si le port est pris, puis repli sur le port
/// choisi par Windows (`lier_amont`, S281-01)
fn socket_amont(amont: IpAddr) -> Option<UdpSocket> {
    let ip: IpAddr = if amont.is_ipv4() { std::net::Ipv4Addr::UNSPECIFIED.into() } else { std::net::Ipv6Addr::UNSPECIFIED.into() };
    lier_amont(identifiant_aleatoire, |port| UdpSocket::bind(SocketAddr::new(ip, port)).ok())
}

/// Port source du relais (pur, testé) : 8 tirages dans la plage dynamique, puis en dernier recours le port 0, choisi par
/// Windows (audit de #281, S281-01 : un compte standard qui occupe des ports de la plage faisait échouer les 8 essais) ;
/// l'identifiant de la requête reste aléatoire
pub fn lier_amont<T>(mut alea: impl FnMut() -> Option<u16>, mut lier: impl FnMut(u16) -> Option<T>) -> Option<T> {
    (0..8).find_map(|_| lier(port_dynamique(alea()?))).or_else(|| lier(0))
}

/// Bilan d'un relais (S281-01) : un échec local (socket impossible à lier, générateur en échec) n'est ni une réponse ni
/// un silence de l'amont
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bilan {
    Reponse,
    Muet,
    EchecLocal,
}

/// Bilan des essais auprès des amonts (pur, testé) : une réponse l'emporte ; sinon un amont muet ; sinon (rien que des
/// échecs locaux) échec local
pub fn bilan(essais: &[Bilan]) -> Bilan {
    if essais.contains(&Bilan::Reponse) {
        Bilan::Reponse
    } else if essais.contains(&Bilan::Muet) {
        Bilan::Muet
    } else {
        Bilan::EchecLocal
    }
}

/// Relais UDP vers un amont : réponse assortie, ou `Muet` (délai, réponse étrangère ignorée), ou `EchecLocal`
fn relayer_udp(paquet: &[u8], q: &Question, amont: IpAddr) -> Result<Vec<u8>, Bilan> {
    let (Some(s), Some(id)) = (socket_amont(amont), identifiant_aleatoire()) else { return Err(Bilan::EchecLocal) };
    let cible = SocketAddr::new(amont, 53);
    s.send_to(&avec_id(paquet, id), cible).map_err(|_| Bilan::Muet)?;
    let fin = Instant::now() + DELAI_AMONT;
    let mut tampon = [0u8; MAX_TCP];
    while let Some(reste) = fin.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()) {
        s.set_read_timeout(Some(reste)).map_err(|_| Bilan::Muet)?;
        let (n, de) = s.recv_from(&mut tampon).map_err(|_| Bilan::Muet)?;
        if de == cible && reponse_assortie(&tampon[..n], id, &q.brute) {
            return Ok(tampon[..n].to_vec());
        }
    }
    Err(Bilan::Muet)
}

/// Relais vers les amonts dans l'ordre, jusqu'à la première réponse ; bilan des essais
fn relayer_tous(paquet: &[u8], q: &Question, amonts: &[IpAddr], tcp: bool) -> (Option<Vec<u8>>, Bilan) {
    let mut essais = Vec::new();
    for &a in amonts {
        match if tcp { relayer_tcp(paquet, q, a).ok_or(Bilan::Muet) } else { relayer_udp(paquet, q, a) } {
            Ok(v) => return (Some(v), Bilan::Reponse),
            Err(b) => essais.push(b),
        }
    }
    (None, bilan(&essais))
}

/// Relais TCP vers un amont (requête reçue en TCP)
fn relayer_tcp(paquet: &[u8], q: &Question, amont: IpAddr) -> Option<Vec<u8>> {
    relayer_tcp_vers(paquet, q, SocketAddr::new(amont, 53), ECHEANCE_TCP_AMONT)
}

/// Échange TCP avec un amont, en tout `duree` au plus depuis la connexion (constat C-6 de l'audit du 2026-11-23 : un
/// délai par lecture laissait un amont qui envoie un octet toutes les 1,9 s tenir une des 4 places TCP pendant des
/// heures). Même échéance totale que côté client (`lire_avant`)
pub(crate) fn relayer_tcp_vers(paquet: &[u8], q: &Question, cible: SocketAddr, duree: Duration) -> Option<Vec<u8>> {
    let echeance = Instant::now() + duree;
    let reste = || echeance.checked_duration_since(Instant::now()).filter(|d| !d.is_zero());
    let mut s = TcpStream::connect_timeout(&cible, reste()?.min(DELAI_AMONT)).ok()?;
    s.set_write_timeout(Some(reste()?)).ok()?;
    let id = identifiant_aleatoire()?;
    let p = avec_id(paquet, id);
    s.write_all(&(p.len() as u16).to_be_bytes()).ok()?;
    s.write_all(&p).ok()?;
    let mut l = [0u8; 2];
    if !lire_avant(&mut s, &mut l, echeance) {
        return None;
    }
    let mut rep = vec![0u8; u16::from_be_bytes(l) as usize];
    if !lire_avant(&mut s, &mut rep, echeance) {
        return None;
    }
    reponse_assortie(&rep, id, &q.brute).then_some(rep)
}

/// Décision du filtrage, fournie par le moniteur (lit `Partage.filtrage`, verrou à part)
pub type Juge = Arc<dyn Fn(&str) -> bool + Send + Sync>;

struct Essai {
    arret: AtomicBool,
    en_cours: AtomicUsize,
    tcp_en_cours: AtomicUsize,
    /// Fils encore vivants (écoutes et requêtes) : un nouvel essai attend qu'ils aient tous rendu leurs sockets
    fils: AtomicUsize,
    /// Une catégorie au moins est active (nom spécial de Firefox, réponses locales) ; changé sans relancer (PR 7.5a)
    filtrage_actif: AtomicBool,
    juge: Juge,
    /// Amonts, changés à chaud (résolveur tiers choisi, repli au portail captif : PR 7.6)
    amonts: std::sync::RwLock<Vec<IpAddr>>,
    sante: Mutex<Sante>,
    debut: Instant,
    bloquees: AtomicUsize,
    relayees: AtomicUsize,
    /// Mode permanent (filtrage activé) : le silence de l'amont n'arrête pas le résolveur, il appelle `sur_silence`
    permanent: bool,
    /// Silence de l'amont constaté (mode permanent) : cartes rendues à leurs serveurs d'origine, en attente de la sonde
    silence: AtomicBool,
    sur_silence: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Sonde de confirmation du silence en cours (C-7) : une seule à la fois
    sonde_en_cours: AtomicBool,
    /// Relais impossibles depuis le poste (S281-01)
    echecs_locaux: AtomicUsize,
}

static ESSAI: Mutex<Option<Arc<Essai>>> = Mutex::new(None);

impl Essai {
    fn repondre(&self, paquet: &[u8], max: usize, tcp: bool) -> Option<Vec<u8>> {
        match lire_requete(paquet, max) {
            Lecture::Ignoree => None,
            Lecture::Formerr(id) => Some(reponse_formerr(id)),
            Lecture::Requete(r) => match traiter(&r, self.filtrage_actif.load(Ordering::Relaxed), &*self.juge) {
                Action::Repondre(v) => {
                    self.bloquees.fetch_add(1, Ordering::Relaxed);
                    Some(v)
                }
                Action::Relayer => {
                    let amonts = self.amonts.read().unwrap().clone();
                    let (rep, b) = relayer_tous(paquet, &r.question, &amonts, tcp);
                    let maintenant = self.debut.elapsed().as_secs();
                    // Échec local (S281-01) : compté et journalisé, jamais noté comme un amont muet
                    let seuil = if b == Bilan::EchecLocal {
                        self.noter_echec_local();
                        false
                    } else {
                        self.sante.lock().unwrap().noter(b == Bilan::Reponse, maintenant)
                    };
                    // Confirmation par la sonde du service (C-7), une seule à la fois, hors du verrou de la santé ; sonde
                    // en échec local : pas de silence
                    let silence = seuil && !self.sonde_en_cours.swap(true, Ordering::AcqRel) && {
                        let s = sonder_bilan(&amonts);
                        self.sonde_en_cours.store(false, Ordering::Release);
                        if s == Bilan::EchecLocal {
                            self.noter_echec_local();
                            false
                        } else {
                            self.sante.lock().unwrap().confirmer(s == Bilan::Reponse)
                        }
                    };
                    if silence {
                        if !self.permanent {
                            crate::commun::journal("résolveur local : aucun amont ne répond depuis 30 s, sonde du service comprise ; essai arrêté (dégradation ouverte)");
                            self.arret.store(true, Ordering::Relaxed);
                        } else if !self.silence.swap(true, Ordering::AcqRel) {
                            crate::commun::journal("résolveur local : aucun amont ne répond depuis 30 s, sonde du service comprise ; cartes rendues à leurs serveurs d'origine, port gardé (dégradation ouverte)");
                            if let Some(f) = &self.sur_silence {
                                f();
                            }
                        }
                    }
                    self.relayees.fetch_add(1, Ordering::Relaxed);
                    rep.map(|v| avec_id(&v, r.id))
                }
            },
        }
    }

    /// Échec local du relais (S281-01) : compté, journalisé au premier puis tous les 1000
    fn noter_echec_local(&self) {
        let n = self.echecs_locaux.fetch_add(1, Ordering::Relaxed) + 1;
        if n == 1 || n % 1000 == 0 {
            crate::commun::journal(&format!("résolveur local : relais impossible depuis le poste ({n} fois : socket ou générateur aléatoire) ; compté à part, jamais comme un silence de l'amont"));
        }
    }

    /// Une requête de plus, si la borne le permet
    fn prendre(&self) -> bool {
        if self.en_cours.fetch_add(1, Ordering::AcqRel) >= MAX_EN_COURS {
            self.en_cours.fetch_sub(1, Ordering::AcqRel);
            return false;
        }
        true
    }

    fn prendre_tcp(&self) -> bool {
        if self.tcp_en_cours.fetch_add(1, Ordering::AcqRel) >= MAX_TCP_EN_COURS {
            self.tcp_en_cours.fetch_sub(1, Ordering::AcqRel);
            return false;
        }
        if !self.prendre() {
            self.tcp_en_cours.fetch_sub(1, Ordering::AcqRel);
            return false;
        }
        true
    }
}

/// Lance un fil de l'essai ; un fil impossible à créer est abandonné sans arrêter le service (audit de #161,
/// S161-03 : `std::thread::spawn` panique, et le service est compilé avec `panic = "abort"`)
fn lancer(e: &Arc<Essai>, nom: &str, f: impl FnOnce() + Send + 'static) -> bool {
    e.fils.fetch_add(1, Ordering::AcqRel);
    let e2 = e.clone();
    let r = std::thread::Builder::new().name(nom.into()).spawn(move || {
        f();
        e2.fils.fetch_sub(1, Ordering::AcqRel);
    });
    if r.is_err() {
        e.fils.fetch_sub(1, Ordering::AcqRel);
    }
    r.is_ok()
}

/// Liaison exclusive (`SO_EXCLUSIVEADDRUSE`) d'un socket UDP ou d'une écoute TCP : erreur si un autre programme tient
/// déjà l'adresse ou le port de toutes les adresses
pub(crate) fn lier_exclusif(adresse: SocketAddr, tcp: bool) -> std::io::Result<std::os::windows::io::RawSocket> {
    use windows::Win32::Networking::WinSock::{
        bind, closesocket, listen, setsockopt, WSASocketW, AF_INET, AF_INET6, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0, IPPROTO_TCP,
        IPPROTO_UDP, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_IN6_0, SOCK_DGRAM, SOCK_STREAM, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
        WSA_FLAG_NO_HANDLE_INHERIT, WSA_FLAG_OVERLAPPED,
    };
    // Winsock initialisé par la bibliothèque standard (WSAStartup à la première utilisation)
    let _ = UdpSocket::bind("127.0.0.1:0");
    let (famille, type_, proto) = (
        if adresse.is_ipv4() { AF_INET.0 as i32 } else { AF_INET6.0 as i32 },
        if tcp { SOCK_STREAM } else { SOCK_DGRAM },
        if tcp { IPPROTO_TCP.0 } else { IPPROTO_UDP.0 },
    );
    unsafe {
        // Code d'erreur Winsock du dernier appel, pas le HRESULT (relecture de #161, R57)
        // Socket non héritable, dès sa création (comme ceux de la bibliothèque standard) : `socket()` le crée héritable,
        // et tout programme lancé par le service pendant que le résolveur tourne (curl, PowerShell…) en gardait une copie,
        // donc le port 53 lié après « filtrage off » (échec du scénario 7.4, run 45365657788). Drapeau posé à la création,
        // pas après : un autre fil peut lancer un programme entre les deux
        let s = WSASocketW(famille, type_.0, proto, None, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT)
            .map_err(|_| std::io::Error::last_os_error())?;
        let erreur = |s| {
            let e = std::io::Error::last_os_error();
            let _ = closesocket(s);
            Err(e)
        };
        if setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, Some(&1i32.to_ne_bytes())) != 0 {
            return erreur(s);
        }
        let lie = match adresse {
            SocketAddr::V4(a) => {
                let sa = SOCKADDR_IN { sin_family: AF_INET, sin_port: a.port().to_be(),
                    sin_addr: IN_ADDR { S_un: IN_ADDR_0 { S_addr: u32::from_ne_bytes(a.ip().octets()) } }, sin_zero: [0; 8] };
                bind(s, &sa as *const SOCKADDR_IN as *const SOCKADDR, std::mem::size_of::<SOCKADDR_IN>() as i32)
            }
            SocketAddr::V6(a) => {
                let sa = SOCKADDR_IN6 { sin6_family: AF_INET6, sin6_port: a.port().to_be(), sin6_flowinfo: 0,
                    sin6_addr: IN6_ADDR { u: IN6_ADDR_0 { Byte: a.ip().octets() } }, Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 } };
                bind(s, &sa as *const SOCKADDR_IN6 as *const SOCKADDR, std::mem::size_of::<SOCKADDR_IN6>() as i32)
            }
        };
        if lie != 0 || (tcp && listen(s, 64) != 0) {
            return erreur(s);
        }
        Ok(s.0 as std::os::windows::io::RawSocket)
    }
}

fn boucle_udp(e: Arc<Essai>, s: UdpSocket) {
    let s = Arc::new(s);
    let mut tampon = [0u8; MAX_UDP + 1];
    while !e.arret.load(Ordering::Relaxed) {
        let Ok((n, de)) = s.recv_from(&mut tampon) else { continue };
        // Double contrôle : seule la boucle locale est servie
        if !de.ip().is_loopback() || !e.prendre() {
            continue;
        }
        let (e2, s2, p) = (e.clone(), s.clone(), tampon[..n].to_vec());
        if !lancer(&e, "résolveur local requête", move || {
            if let Some(v) = e2.repondre(&p, MAX_UDP, false) {
                let _ = s2.send_to(&v, de);
            }
            e2.en_cours.fetch_sub(1, Ordering::AcqRel);
        }) {
            e.en_cours.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// Lecture complète avant l'échéance (pas seulement un délai par lecture : une connexion qui goutte un octet à la fois
/// ne tient pas sa place plus longtemps)
fn lire_avant(c: &mut TcpStream, tampon: &mut [u8], echeance: Instant) -> bool {
    let mut lu = 0;
    while lu < tampon.len() {
        let Some(reste) = echeance.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()) else { return false };
        if c.set_read_timeout(Some(reste)).is_err() {
            return false;
        }
        match c.read(&mut tampon[lu..]) {
            Ok(0) | Err(_) => return false,
            Ok(n) => lu += n,
        }
    }
    true
}

fn servir_tcp(e: &Essai, mut c: TcpStream, echeance: Instant) {
    let _ = c.set_write_timeout(Some(DELAI_AMONT));
    let mut l = [0u8; 2];
    if !lire_avant(&mut c, &mut l, echeance) {
        return;
    }
    let n = u16::from_be_bytes(l) as usize;
    if n > MAX_TCP {
        return;
    }
    let mut p = vec![0u8; n];
    if !lire_avant(&mut c, &mut p, echeance) {
        return;
    }
    if let Some(v) = e.repondre(&p, MAX_TCP, true) {
        let _ = c.write_all(&(v.len() as u16).to_be_bytes());
        let _ = c.write_all(&v);
    }
}

fn boucle_tcp(e: Arc<Essai>, l: TcpListener) {
    while !e.arret.load(Ordering::Relaxed) {
        match l.accept() {
            Ok((c, de)) => {
                let echeance = Instant::now() + ECHEANCE_TCP;
                if !de.ip().is_loopback() || !e.prendre_tcp() {
                    continue;
                }
                let _ = c.set_nonblocking(false);
                let e2 = e.clone();
                let liberer = |x: &Essai| {
                    x.en_cours.fetch_sub(1, Ordering::AcqRel);
                    x.tcp_en_cours.fetch_sub(1, Ordering::AcqRel);
                };
                if !lancer(&e, "résolveur local connexion", move || {
                    servir_tcp(&e2, c, echeance);
                    liberer(&e2);
                }) {
                    liberer(&e);
                }
            }
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

/// Lance un essai du résolveur sur la boucle locale (10 minutes au plus). Refusé si un essai tourne déjà, si aucun
/// amont n'est connu, ou si le port 53 de la boucle locale est déjà pris (le service n'arrête jamais l'autre logiciel)
pub fn demarrer_essai(filtrage_actif: bool, juge: Juge, amonts: Vec<IpAddr>) -> Result<String, String> {
    demarrer(filtrage_actif, juge, amonts.clone(), None)?;
    let amonts: Vec<String> = amonts.iter().map(IpAddr::to_string).collect();
    Ok(format!("Essai du résolveur local lancé pour 10 minutes sur 127.0.0.1 et ::1 (amont : {} ; filtrage {}). Aucune carte réseau n'est réglée sur lui.",
        amonts.join(", "), if filtrage_actif { "actif" } else { "sans catégorie active : tout est relayé" }))
}

/// Lance le résolveur en mode permanent (filtrage activé, PR 7.4) : pas de durée, le silence de l'amont appelle
/// `sur_silence` (cartes rendues) au lieu d'arrêter. Mêmes refus que l'essai
pub fn demarrer_permanent(filtrage_actif: bool, juge: Juge, amonts: Vec<IpAddr>, sur_silence: Arc<dyn Fn() + Send + Sync>) -> Result<(), String> {
    demarrer(filtrage_actif, juge, amonts, Some(sur_silence))
}

/// Le résolveur tourne-t-il en mode permanent ?
pub fn permanent_actif() -> bool {
    ESSAI.lock().unwrap().as_ref().is_some_and(|e| e.permanent && !e.arret.load(Ordering::Relaxed))
}

/// Silence de l'amont en cours (mode permanent), et remise à zéro quand la sonde a répondu et les cartes sont rebranchées
pub fn en_silence() -> bool {
    ESSAI.lock().unwrap().as_ref().is_some_and(|e| e.silence.load(Ordering::Acquire))
}

/// Amonts changés pendant que le résolveur tourne (résolveur tiers choisi ou repli, PR 7.6) ; santé remise à zéro
pub fn regler_amonts(amonts: Vec<IpAddr>) {
    if let Some(e) = ESSAI.lock().unwrap().as_ref() {
        if !amonts.is_empty() {
            *e.amonts.write().unwrap() = amonts;
            *e.sante.lock().unwrap() = Sante::default();
        }
    }
}

/// Catégories changées pendant que le résolveur tourne (commande filtrageCategories)
pub fn regler_filtrage_actif(actif: bool) {
    if let Some(e) = ESSAI.lock().unwrap().as_ref() {
        e.filtrage_actif.store(actif, Ordering::Relaxed);
    }
}

/// Silence posé d'office (démarrage sans amont joignable : cartes rendues, port gardé, la sonde rebranchera)
pub fn marquer_silence() {
    if let Some(e) = ESSAI.lock().unwrap().as_ref() {
        e.silence.store(true, Ordering::Release);
    }
}

pub fn fin_silence() {
    if let Some(e) = ESSAI.lock().unwrap().as_ref() {
        e.silence.store(false, Ordering::Release);
        *e.sante.lock().unwrap() = Sante::default();
    }
}

/// Amonts du résolveur en cours (sonde)
pub fn amonts_en_cours() -> Vec<IpAddr> {
    ESSAI.lock().unwrap().as_ref().map(|e| e.amonts.read().unwrap().clone()).unwrap_or_default()
}

/// Requête DNS d'un nom (une question, classe IN, RD) (pure, testée)
pub fn requete(id: u16, nom: &str, type_: u16) -> Vec<u8> {
    let mut v = id.to_be_bytes().to_vec();
    v.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for e in nom.split('.').filter(|e| !e.is_empty()).take(127) {
        let e = &e.as_bytes()[..e.len().min(63)];
        v.push(e.len() as u8);
        v.extend_from_slice(e);
    }
    v.push(0);
    v.extend_from_slice(&type_.to_be_bytes());
    v.extend_from_slice(&CLASSE_IN.to_be_bytes());
    v
}

/// Sonde : un des amonts répond-il à une requête d'un nom de la liste de protection ?
pub fn sonder(amonts: &[IpAddr]) -> bool {
    sonder_bilan(amonts) == Bilan::Reponse
}

/// Sonde avec son bilan : générateur ou socket en échec : `EchecLocal` (S281-01)
fn sonder_bilan(amonts: &[IpAddr]) -> Bilan {
    let Some(id) = identifiant_aleatoire() else { return Bilan::EchecLocal };
    let p = requete(id, "www.msftconnecttest.com", TYPE_A);
    let Lecture::Requete(r) = lire_requete(&p, MAX_UDP) else { return Bilan::Muet };
    relayer_tous(&p, &r.question, amonts, false).1
}

/// Le résolveur local répond-il sur 127.0.0.1 ? (contrôle avant de régler les cartes)
pub fn repond_localement() -> bool {
    let Some(id) = identifiant_aleatoire() else { return false };
    let p = requete(id, "www.msftconnecttest.com", TYPE_A);
    let Lecture::Requete(r) = lire_requete(&p, MAX_UDP) else { return false };
    let Ok(s) = UdpSocket::bind("127.0.0.1:0") else { return false };
    let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
    if s.send_to(&p, "127.0.0.1:53").is_err() {
        return false;
    }
    let mut t = [0u8; MAX_TCP];
    matches!(s.recv_from(&mut t), Ok((n, _)) if reponse_assortie(&t[..n], r.id, &r.question.brute))
}

fn demarrer(filtrage_actif: bool, juge: Juge, amonts: Vec<IpAddr>, sur_silence: Option<Arc<dyn Fn() + Send + Sync>>) -> Result<(), String> {
    let permanent = sur_silence.is_some();
    let mut g = ESSAI.lock().unwrap();
    if g.as_ref().is_some_and(|e| !e.arret.load(Ordering::Relaxed)) {
        return Err("Un essai du résolveur local est déjà en cours.".into());
    }
    // Essai précédent arrêté mais dont des fils tiennent encore un socket (une requête relayée : 8 s au plus) : message
    // juste, plutôt que « port déjà pris » (audit de #161, S161-03)
    if g.as_ref().is_some_and(|e| e.fils.load(Ordering::Acquire) > 0) {
        return Err("L'essai précédent se termine : réessayez dans quelques secondes.".into());
    }
    if amonts.is_empty() {
        return Err("Aucun serveur DNS d'amont sur les cartes physiques : essai impossible.".into());
    }
    use std::os::windows::io::FromRawSocket;
    let pris = |e: std::io::Error| format!("Port 53 de la boucle locale déjà pris ({e}) : essai refusé ; deR4Tizer n'arrête pas l'autre logiciel.");
    let (v4, v6): (SocketAddr, SocketAddr) = ("127.0.0.1:53".parse().unwrap(), "[::1]:53".parse().unwrap());
    // Chaque socket est rendu à la bibliothèque standard dès sa liaison : fermé si une liaison suivante échoue
    let u4 = unsafe { UdpSocket::from_raw_socket(lier_exclusif(v4, false).map_err(pris)?) };
    let u6 = unsafe { UdpSocket::from_raw_socket(lier_exclusif(v6, false).map_err(pris)?) };
    let t4 = unsafe { TcpListener::from_raw_socket(lier_exclusif(v4, true).map_err(pris)?) };
    let t6 = unsafe { TcpListener::from_raw_socket(lier_exclusif(v6, true).map_err(pris)?) };
    for u in [&u4, &u6] {
        u.set_read_timeout(Some(Duration::from_millis(500))).map_err(|e| e.to_string())?;
    }
    for t in [&t4, &t6] {
        t.set_nonblocking(true).map_err(|e| e.to_string())?;
    }
    let e = Arc::new(Essai {
        arret: AtomicBool::new(false), en_cours: AtomicUsize::new(0), tcp_en_cours: AtomicUsize::new(0), fils: AtomicUsize::new(0),
        filtrage_actif: AtomicBool::new(filtrage_actif), juge, amonts: std::sync::RwLock::new(amonts.clone()),
        sante: Mutex::new(Sante::default()), debut: Instant::now(), bloquees: AtomicUsize::new(0), relayees: AtomicUsize::new(0),
        permanent, silence: AtomicBool::new(false), sur_silence, sonde_en_cours: AtomicBool::new(false),
        echecs_locaux: AtomicUsize::new(0),
    });
    let mut lances = true;
    for u in [u4, u6] {
        let e2 = e.clone();
        lances &= lancer(&e, "résolveur local udp", move || boucle_udp(e2, u));
    }
    for t in [t4, t6] {
        let e2 = e.clone();
        lances &= lancer(&e, "résolveur local tcp", move || boucle_tcp(e2, t));
    }
    if !lances {
        e.arret.store(true, Ordering::Relaxed);
        *g = Some(e);
        return Err("Fils du résolveur local impossibles à créer : essai abandonné.".into());
    }
    // Fin de l'essai au plus tard après DUREE_ESSAI (essai seulement). Fil impossible à créer : écoutes arrêtées et essai
    // enregistré, pour que « off » le trouve (relecture de #161, R56)
    let e2 = e.clone();
    let fin = std::thread::Builder::new().name("résolveur local fin".into()).spawn(move || {
        while !e2.arret.load(Ordering::Relaxed) && (e2.permanent || e2.debut.elapsed() < DUREE_ESSAI) {
            std::thread::sleep(Duration::from_secs(1));
        }
        e2.arret.store(true, Ordering::Relaxed);
        crate::commun::journal(&format!("résolveur local : {} ({} requête(s) bloquée(s), {} relayée(s), {} relais impossible(s) depuis le poste)",
            if e2.permanent { "arrêté" } else { "essai terminé" }, e2.bloquees.load(Ordering::Relaxed), e2.relayees.load(Ordering::Relaxed),
            e2.echecs_locaux.load(Ordering::Relaxed)));
    });
    if fin.is_err() {
        e.arret.store(true, Ordering::Relaxed);
        *g = Some(e);
        return Err("Fil de fin du résolveur local impossible à créer : abandonné.".into());
    }
    *g = Some(e);
    Ok(())
}

/// Arrête l'essai en cours (les écoutes se ferment dans la seconde). Le mode permanent ne s'arrête que par
/// `arreter_permanent`, après la remise des cartes
pub fn arreter_essai() -> String {
    match ESSAI.lock().unwrap().as_ref() {
        Some(e) if e.permanent && !e.arret.load(Ordering::Relaxed) => "Le filtrage est activé : le résolveur local tourne en permanence ; désactivez le filtrage pour l'arrêter.".into(),
        Some(e) if !e.arret.load(Ordering::Relaxed) => {
            e.arret.store(true, Ordering::Relaxed);
            "Essai du résolveur local arrêté.".into()
        }
        _ => "Aucun essai du résolveur local en cours.".into(),
    }
}

/// Arrête le résolveur permanent, puis attend (5 s au plus) que ses fils aient rendu leurs sockets. À n'appeler
/// qu'après la remise des cartes (préalable de l'audit de #161)
pub fn arreter_permanent() {
    let e = ESSAI.lock().unwrap().clone();
    if let Some(e) = e.filter(|e| e.permanent) {
        e.arret.store(true, Ordering::Relaxed);
        // Plus de silence après l'arrêt : aucune sonde ne doit rebrancher des cartes sur un résolveur arrêté (audit de
        // #167, S167-01, en défense)
        e.silence.store(false, Ordering::Release);
        let fin = Instant::now() + Duration::from_secs(5);
        while e.fils.load(Ordering::Acquire) > 0 && Instant::now() < fin {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}
