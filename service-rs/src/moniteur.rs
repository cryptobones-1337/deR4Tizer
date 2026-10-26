//! Cœur du service : relève les connexions toutes les 3 s, évalue chaque flux, lève les alertes,
//! fait tourner les modules (vie privée, persistance, origine des processus) et applique les commandes.

use crate::baseline;
use crate::blocage;
use crate::chaines::{Arbre, Chaine};
use crate::collectes::{self, Collecte};
use crate::reponse;
use crate::{hygiene, mitre, parefeu};
use crate::defender::{self, EtatDefender};
use crate::commun::{self, Alerte, Blocage, Commande, Config, Etat, FluxInfo, Reponse};
use crate::evenements;
use crate::mesure;
use crate::menaces::Menaces;
use crate::natif::{self, Connexion};
use crate::persistance::Persistance;
use crate::processus::{self, Processus};
use crate::surveillances::Surveillances;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant, SystemTime};

const JOURNAL_DNS: &str = "Microsoft-Windows-DNS-Client/Operational";
const NAVIGATEURS_DOH: &[&str] = &["chrome", "brave", "firefox", "msedge", "opera", "vivaldi"];
const PORTS_COURANTS: &[u16] = &[80, 443, 53, 853, 123, 993, 995, 465, 587, 22, 1119, 5222, 8080, 8443];

pub fn est_locale(ip: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?i)^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0|::1$|::$|fe80:|f[cd][0-9a-f]{2}:)").unwrap())
        .is_match(ip)
}

fn dossier_suspect(chemin: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?i)\\(Temp|Downloads|Téléchargements)\\|\\Users\\Public\\").unwrap()).is_match(chemin)
}

fn dossier_microsoft(chemin: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?i)^[A-Z]:\\Program Files( \(x86\))?\\(Windows [^\\]+|Common Files\\microsoft shared)\\").unwrap()).is_match(chemin)
}

/// État partagé entre le fil de surveillance, le fil DNS et le canal de commandes
pub struct Partage {
    pub dns: Mutex<HashMap<String, String>>,
    /// Alertes produites hors du fil de surveillance (DNS, Defender, baseline…)
    pub alertes_externes: Arc<Mutex<Vec<Alerte>>>,
    /// Adresses à bloquer demandées par l'IPS : (IP, raison)
    pub blocages_ips: Arc<Mutex<Vec<(String, String)>>>,
    pub menaces: RwLock<Menaces>,
    pub defender: Mutex<EtatDefender>,
    pub baseline_occupee: AtomicBool,
    pub arret: AtomicBool,
    /// Alertes du relevé des démarrages automatiques (fil « persistance »), traitées comme avant, sans clé de
    /// déduplication
    pub alertes_persistance: Mutex<Vec<Alerte>>,
    /// Nombre d'entrées de démarrage relevées (affichage console)
    pub entrees_persistance: AtomicUsize,
    /// Relevé des démarrages en cours : l'arrêt l'attend avant de vider la file (sinon une alerte déjà retirée de la
    /// référence demarrage.json serait perdue pour toujours : relecture de #61)
    pub persistance_en_cours: AtomicBool,
}

/// Alertes de persistance encore en file, après la fin du relevé en cours (attendue au plus `attente`) : appelé à
/// l'arrêt du service, qui les enregistre avant de s'arrêter
pub fn vider_persistance(en_cours: &AtomicBool, file: &Mutex<Vec<Alerte>>, attente: Duration) -> Vec<Alerte> {
    let fin = Instant::now() + attente;
    while en_cours.load(Ordering::SeqCst) && Instant::now() < fin {
        std::thread::sleep(Duration::from_millis(50));
    }
    std::mem::take(&mut *file.lock().unwrap())
}

/// Toutes les files d'alertes à l'arrêt : celle de la persistance (relevé en cours attendu, `vider_persistance`), puis
/// les autres (alertes externes des fils, détections de processus), prises après cette attente pour reprendre aussi ce
/// qu'elles ont reçu pendant. Rend (alertes sans clé de déduplication, alertes avec clé), comme le cycle les traite
pub fn vider_a_l_arret(en_cours: &AtomicBool, persistance: &Mutex<Vec<Alerte>>, autres: &[&Mutex<Vec<Alerte>>], attente: Duration) -> (Vec<Alerte>, Vec<Alerte>) {
    let sans_cle = vider_persistance(en_cours, persistance, attente);
    let avec_cle = autres.iter().flat_map(|f| std::mem::take(&mut *f.lock().unwrap())).collect();
    (sans_cle, avec_cle)
}

pub struct Moniteur {
    partage: Arc<Partage>,
    console: bool,
    demarrage: String,
    config: Config,
    signatures: HashMap<String, String>,
    premieres_vues: HashMap<String, String>,
    preexistants: HashSet<String>,
    dernieres_alertes: HashMap<String, Instant>,
    executables_vus: HashSet<String>,
    apprentissage: bool,
    alertes: Vec<Alerte>,
    blocages: Vec<Blocage>,
    dernieres_connexions: Vec<Connexion>,
    empreinte_hosts: String,
    expiration: Instant,
    derniere_signature_etat: String,
    dernier_etat_ecrit: Instant,
    derniere_sauvegarde_dns: Instant,
    premier_passage: bool,
    numero_passage: u64,
    surveillances: Surveillances,
    processus: Processus,
    notre_dossier: String,
    arbre: Arbre,
    chaines: Vec<Chaine>,
    origines: HashMap<String, Option<reponse::Origine>>,
    leurres: Vec<hygiene::Leurre>,
    /// Dernière pose des leurres (None en console : jamais posés) ; reprise régulière pour les utilisateurs qui
    /// ouvrent une session après le démarrage du service (création sous leur identité seulement)
    pose_leurres: Option<Instant>,
    /// Pour repérer les « balises » : ports locaux déjà vus et instants des nouvelles connexions, par flux
    balises: HashMap<(u32, String, u16), (HashSet<u16>, Vec<Instant>)>,
    journal_parefeu: parefeu::LecteurJournal,
    /// Plage dynamique UDP du poste, lue au démarrage (exposition à Internet)
    udp_dynamique: (u16, u16),
    adresses_publiques: Vec<String>,
    exposition: parefeu::Exposition,
}

impl Moniteur {
    pub fn demarrer(console: bool) -> (Arc<Mutex<Moniteur>>, Arc<Partage>) {
        let _ = fs::create_dir_all(commun::dossier().join("sauvegardes"));
        let partage = Arc::new(Partage {
            dns: Mutex::new(commun::lire_carte("dns.json").unwrap_or_default()),
            alertes_externes: Arc::new(Mutex::new(Vec::new())),
            blocages_ips: Arc::new(Mutex::new(Vec::new())),
            menaces: RwLock::new(Menaces::charger(&HashMap::new())),
            defender: Mutex::new(EtatDefender::default()),
            baseline_occupee: AtomicBool::new(false),
            arret: AtomicBool::new(false),
            alertes_persistance: Mutex::new(Vec::new()),
            entrees_persistance: AtomicUsize::new(0),
            persistance_en_cours: AtomicBool::new(false),
        });
        crate::siem::demarrer(partage.alertes_externes.clone(), !console);
        if !console {
            crate::protection::demarrer(partage.alertes_externes.clone());
            std::thread::spawn(baseline::forcer_tailles);
            crate::maj::demarrer();
        }
        defender::surveiller(partage.alertes_externes.clone());
        {
            // Changements de règles du pare-feu, avec le signataire du programme auteur
            let cache = Mutex::new(HashMap::new());
            let notre = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_string_lossy().to_lowercase())).unwrap_or_default();
            parefeu::surveiller_regles(partage.alertes_externes.clone(), move |c| signataire_cache(&mut cache.lock().unwrap(), &notre, c));
        }
        if !console {
            // Pose d'audit (SACL) : réservée au service, qui tourne en SYSTEM
            crate::vol_donnees::surveiller(partage.alertes_externes.clone());
        } else {
            collectes::desactivee(Collecte::AuditDonnees, "mode console : audit des données non posé");
        }
        let exes: Option<Vec<String>> = commun::lire("executables.json");
        let processus = Processus::nouveau();
        let notre_dossier = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_string_lossy().to_lowercase()))
            .unwrap_or_default();

        let journal_dns_actif = demarrer_dns(&partage);
        {
            let p = partage.clone();
            processus.demarrer(move |nom, resultats| traiter_dns(&p, nom, resultats));
        }

        let m = Moniteur {
            partage: partage.clone(),
            console,
            demarrage: commun::maintenant(),
            config: commun::lire("config.json").unwrap_or_default(),
            signatures: HashMap::new(),
            premieres_vues: HashMap::new(),
            preexistants: HashSet::new(),
            dernieres_alertes: HashMap::new(),
            apprentissage: exes.is_none(),
            executables_vus: exes.unwrap_or_default().into_iter().map(|e| e.to_lowercase()).collect(),
            alertes: commun::lire_alertes(),
            blocages: commun::lire("blocages.json").unwrap_or_default(),
            dernieres_connexions: Vec::new(),
            empreinte_hosts: blocage::empreinte_hosts(),
            expiration: Instant::now(),
            derniere_signature_etat: String::new(),
            dernier_etat_ecrit: Instant::now() - Duration::from_secs(60),
            derniere_sauvegarde_dns: Instant::now(),
            premier_passage: true,
            numero_passage: 0,
            arbre: Arbre::default(),
            chaines: Vec::new(),
            origines: HashMap::new(),
            // Les leurres ne sont posés que par le service (pas lors d'un test en console)
            leurres: if console {
                collectes::desactivee(Collecte::Leurres, "mode console : leurres non posés");
                Vec::new()
            } else {
                hygiene::poser_leurres()
            },
            pose_leurres: if console { None } else { Some(Instant::now()) },
            balises: HashMap::new(),
            journal_parefeu: parefeu::LecteurJournal::nouveau(),
            udp_dynamique: parefeu::plage_dynamique_udp(),
            adresses_publiques: parefeu::adresses_publiques(),
            exposition: parefeu::Exposition::default(),
            surveillances: Surveillances::nouvelles(),
            processus,
            notre_dossier,
        };
        {
            let infos = &partage.menaces.read().unwrap().infos;
            commun::journal(&format!(
                "démarrage v{} (Rust ; journal DNS {}, processus : {}, {} IP et {} domaines malveillants connus)",
                commun::VERSION,
                if journal_dns_actif { "actif" } else { "inactif" },
                m.processus.source.lock().unwrap(),
                infos.total_ip,
                infos.total_domaines
            ));
        }
        crate::export::demarrer(&m.config.syslog);
        crate::notifications::demarrer(&m.config.notifications);
        if !console {
            // Capture des paquets : trafic, NDR local, DPI, IDS/IPS
            // Trafic, DPI et IDS sur l'interface de la route par défaut (le tunnel, avec un VPN) ;
            // NDR sur la carte du réseau local
            let analyseurs: Vec<Box<dyn crate::capture::Analyseur>> = vec![
                Box::new(crate::trafic::Trafic::nouveau(partage.clone())),
                Box::new(crate::dpi::Dpi::nouveau(partage.clone())),
                Box::new(crate::ids::Ids::nouveau(partage.alertes_externes.clone(), partage.blocages_ips.clone())),
            ];
            let p = partage.clone();
            crate::capture::demarrer("trafic", Collecte::CaptureTrafic, analyseurs, crate::capture::adresse_locale, move || p.arret.load(std::sync::atomic::Ordering::Relaxed));
            let ndr = crate::ndr::demarrer(partage.alertes_externes.clone());
            let p = partage.clone();
            crate::capture::demarrer("réseau local", Collecte::CaptureReseauLocal, vec![Box::new(ndr)], crate::ndr::adresse_lan, move || p.arret.load(std::sync::atomic::Ordering::Relaxed));
        } else {
            for c in [Collecte::CaptureTrafic, Collecte::CaptureReseauLocal] {
                collectes::desactivee(c, "mode console : capture des paquets non lancée");
            }
        }
        if !console {
            crate::api::demarrer(&m.config.api);
        }
        let mut m = m;
        let telemetrie: Vec<String> = m.blocages.iter().filter(|b| b.type_ == "hosts" && b.raison == "télémétrie").map(|b| b.cible.clone()).collect();
        if !telemetrie.is_empty() {
            m.blocages.retain(|b| !(b.type_ == "hosts" && b.raison == "télémétrie"));
            let domaines: Vec<String> = m.blocages.iter().filter(|b| b.type_ == "hosts").map(|b| b.cible.clone()).collect();
            if blocage::ecrire_bloc_hosts(&domaines).is_ok() {
                m.empreinte_hosts = blocage::empreinte_hosts();
                let _ = commun::ecrire("blocages.json", &m.blocages);
                commun::journal(&format!("blocage de la télémétrie retiré du fichier hosts ({} domaine(s))", telemetrie.len()));
            }
        }
        let m = Arc::new(Mutex::new(m));

        // Surveillance toutes les 3 s
        {
            let (m, p) = (m.clone(), partage.clone());
            std::thread::Builder::new().name("surveillance".into()).spawn(move || {
                let mut cycles = 0u64;
                while !p.arret.load(Ordering::Relaxed) {
                    let t = Instant::now();
                    let mut g = m.lock().unwrap();
                    let t = mesure::noter("verrou.attente.surveillance", t);
                    g.passage();
                    drop(g);
                    mesure::noter("verrou.tenu.surveillance (cycle complet)", t);
                    cycles += 1;
                    if cycles.is_multiple_of(200) {
                        mesure::ecrire();
                    }
                    std::thread::sleep(Duration::from_secs(3));
                }
            }).unwrap();
        }
        // Démarrages automatiques toutes les minutes, dans leur propre fil (phase 1, mesure du cycle) : ce relevé, avec la
        // vérification de signature de chaque cible, tenait le verrou du Moniteur jusqu'à 6,3 s une fois par minute
        // (surveillance aveugle et commandes de l'interface en attente pendant ce temps). Le verrou n'est plus pris que par
        // le cycle, qui reprend les alertes produites ici
        {
            let p = partage.clone();
            std::thread::Builder::new().name("persistance".into()).spawn(move || {
                let mut persistance = Persistance::nouvelle();
                let mut cache = HashMap::new();
                let notre = std::env::current_exe().ok().and_then(|x| x.parent().map(|d| d.to_string_lossy().to_lowercase())).unwrap_or_default();
                loop {
                    // « En cours » posé AVANT de regarder l'arrêt : l'arrêt, qui pose l'arrêt puis attend la fin du relevé,
                    // ne peut pas manquer un relevé commencé (ordre séquentiel des deux drapeaux)
                    p.persistance_en_cours.store(true, Ordering::SeqCst);
                    if p.arret.load(Ordering::SeqCst) {
                        p.persistance_en_cours.store(false, Ordering::SeqCst);
                        return;
                    }
                    let t = Instant::now();
                    let alertes = persistance.verifier(&mut |c| signataire_cache_releve(&mut cache, &notre, c));
                    p.entrees_persistance.store(persistance.entrees.len(), Ordering::Relaxed);
                    // Un relevé sans aucune entrée (aucun Windows n'en a zéro : services, pilotes) est une lecture impossible
                    if persistance.entrees.is_empty() {
                        collectes::echec(Collecte::Persistance, "relevé des démarrages automatiques vide");
                    } else {
                        collectes::succes(Collecte::Persistance);
                    }
                    p.alertes_persistance.lock().unwrap().extend(alertes);
                    p.persistance_en_cours.store(false, Ordering::SeqCst);
                    mesure::noter("controles.persistance (fil dédié, toutes les minutes)", t);
                    for _ in 0..60 {
                        if p.arret.load(Ordering::Relaxed) {
                            return;
                        }
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
            }).unwrap();
        }
        // Contrôles toutes les 10 minutes : état de Defender et conformité de la baseline
        {
            let p = partage.clone();
            std::thread::Builder::new().name("contrôles".into()).spawn(move || {
                let _com = wmi::COMLibrary::without_security();
                let mut baseline_avant: Option<baseline::EtatBaseline> = None;
                let mut premier = true;
                // Première publication de l'état de Defender faite (même si WMI n'a jamais répondu) : plus d'attente
                let mut defender_publie = false;
                let mut tour_pilotes = 0u32;
                let mut pilotes_signales = HashSet::new();
                while !p.arret.load(Ordering::Relaxed) {
                    // Étape « Defender » : lecture WMI comprise (et ses relectures au démarrage du PC)
                    let t = Instant::now();
                    let mut etat = defender::etat();
                    // Démarrage du PC : Defender répond « Not running » quelques minutes ; relu toutes les 30 s
                    // (10 min au plus) avant le premier état publié, pour ne pas l'afficher désactivé à tort
                    // (une seule fois : si WMI ne répond jamais, l'attente ne revient pas à chaque relevé ; arrêt du service
                    // vu chaque seconde pendant l'attente)
                    let mut essais = 0;
                    while defender::relire_avant_publication(&etat, defender_publie) && essais < 20 && !p.arret.load(Ordering::Relaxed) {
                        for _ in 0..30 {
                            if p.arret.load(Ordering::Relaxed) {
                                break;
                            }
                            std::thread::sleep(Duration::from_secs(1));
                        }
                        etat = defender::etat();
                        essais += 1;
                    }
                    defender_publie = true;
                    let ecarts = defender::ecarts(&p.defender.lock().unwrap(), &etat);
                    p.alertes_externes.lock().unwrap().extend(ecarts);
                    if etat.disponible {
                        collectes::succes(Collecte::EtatDefender);
                    } else {
                        collectes::echec(Collecte::EtatDefender, "état de Defender illisible (WMI)");
                    }
                    *p.defender.lock().unwrap() = etat;

                    // Extensions de navigateur toutes les 10 min ; pilotes vulnérables une fois par jour
                    let t = mesure::noter("controles.defender", t);
                    let (_, alertes_ext) = hygiene::verifier_extensions();
                    p.alertes_externes.lock().unwrap().extend(alertes_ext);
                    let t = mesure::noter("controles.extensions", t);
                    if tour_pilotes == 0 {
                        let liste = hygiene::liste_loldrivers();
                        let a = hygiene::verifier_pilotes(&liste, &mut pilotes_signales);
                        p.alertes_externes.lock().unwrap().extend(a);
                        mesure::noter("controles.pilotes", t);
                    }
                    let t = Instant::now();
                    tour_pilotes = (tour_pilotes + 1) % 144;

                    if !p.baseline_occupee.load(Ordering::Relaxed) {
                        let b = baseline::evaluer();
                        let inconnues = b.regles.iter().filter(|r| r.etat == "inconnu").count();
                        collectes::noter_comptes(Collecte::Baseline, b.regles.len() - inconnues, inconnues, "réglages de la baseline");
                        // Le service applique lui-même le profil « journalisation » (demandé par l'utilisateur),
                        // une fois au démarrage, s'il n'est pas conforme
                        if premier && !console && baseline::gestion().is_none() && b.regles.iter().any(|r| r.profil == "journalisation" && r.etat == "non conforme") {
                            let r = baseline::appliquer(&baseline::selection("journalisation"));
                            commun::journal(&format!("baseline « journalisation » : {}", r.unwrap_or_else(|e| format!("échec : {e}"))));
                            premier = false;
                            continue; // réévalue tout de suite pour publier l'état après application
                        }
                        if let Some(avant) = &baseline_avant {
                            p.alertes_externes.lock().unwrap().extend(baseline::derives(avant, &b));
                        }
                        let _ = commun::ecrire("baseline.json", &b);
                        baseline_avant = Some(b);
                        mesure::noter("controles.baseline", t);
                    }
                    premier = false;
                    for _ in 0..600 {
                        if p.arret.load(Ordering::Relaxed) {
                            return;
                        }
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
            }).unwrap();
        }
        // Listes de menaces : vérifie toutes les heures, télécharge ce qui a plus de 12 h
        {
            let p = partage.clone();
            std::thread::Builder::new().name("listes de menaces".into()).spawn(move || {
                while !p.arret.load(Ordering::Relaxed) {
                    mettre_a_jour_menaces(&p, false);
                    for _ in 0..3600 {
                        if p.arret.load(Ordering::Relaxed) {
                            return;
                        }
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
            }).unwrap();
        }
        (m, partage)
    }

    pub fn arreter(&mut self) {
        self.partage.arret.store(true, Ordering::SeqCst);
        // Alertes pas encore reprises par le cycle, enregistrées avant l'arrêt : persistance, relevé en cours compris
        // (relecture de #61), puis files des autres fils et détections de processus (phase 1). Relevé attendu 8 s au plus,
        // sous les 10 s annoncées à Windows (wait_hint) ; au-delà, ou si Windows tue le service à l'extinction, l'alerte
        // d'un relevé en cours peut encore être perdue, comme celle qu'un autre fil produit après la reprise
        let (sans_cle, avec_cle) = vider_a_l_arret(&self.partage.persistance_en_cours, &self.partage.alertes_persistance,
            &[&self.partage.alertes_externes, &self.processus.detections], Duration::from_secs(8));
        let mut modifiees = false;
        for a in sans_cle {
            modifiees |= self.ajouter_alerte_brute(a, None);
        }
        for a in avec_cle {
            let cle = cle_alerte(&a);
            modifiees |= self.ajouter_alerte_brute(a, Some(cle));
        }
        if modifiees {
            self.ecrire_alertes();
        }
        let _ = commun::ecrire("dns.json", &*self.partage.dns.lock().unwrap());
        commun::journal("arrêt");
    }

    /// alertes.json, borné aux 1000 dernières (cycle et arrêt)
    fn ecrire_alertes(&mut self) {
        if self.alertes.len() > 1000 {
            let surplus = self.alertes.len() - 1000;
            self.alertes.drain(..surplus);
        }
        // Mise de côté d'un historique illisible encore en attente : rien n'est réécrit (relecture de #72, S72-02)
        if !commun::ecriture_alertes_permise() {
            return;
        }
        let _ = commun::ecrire("alertes.json", &self.alertes);
    }

    // ------------------------------------------------------------ signatures

    fn signataire(&mut self, chemin: &str) -> String {
        signataire_cache(&mut self.signatures, &self.notre_dossier, chemin)
    }

    // ------------------------------------------------------------ surveillance

    fn passage(&mut self) {
        self.numero_passage += 1;
        let t = Instant::now();
        let (toutes, lecture) = natif::lister_tcp_lu();
        match lecture {
            Ok(()) => collectes::succes(Collecte::Connexions),
            Err(e) => collectes::echec(Collecte::Connexions, &e),
        }
        let liste = match natif::processus_lu() {
            Ok(l) => {
                collectes::succes(Collecte::Processus);
                l
            }
            Err(e) => {
                collectes::echec(Collecte::Processus, &e);
                HashMap::new()
            }
        };
        self.arbre.maj(&liste);
        let t = mesure::noter("cycle.connexions_et_processus", t);
        let connexions: Vec<Connexion> = toutes.iter().filter(|c| (c.etat == 5 || c.etat == 3) && !est_locale(&c.ip)).cloned().collect();
        let mut groupes: HashMap<(u32, String, u16), Vec<&Connexion>> = HashMap::new();
        for c in &connexions {
            groupes.entry((c.pid, c.ip.clone(), c.port)).or_default().push(c);
        }
        let mut chemins: HashMap<u32, String> = HashMap::new();
        let mut flux: Vec<FluxInfo> = Vec::new();
        let mut cles_vues = HashSet::new();
        let (mut alertes_modifiees, mut exes_modifies) = (false, false);

        // Indice « IP directe » : seulement si le journal DNS a été lu récemment (sinon toute connexion sans nom le
        // prendrait) ; un échec passager (lecture lente) ne le retire pas
        let dns_lu = collectes::lue_recemment(Collecte::JournalDns);
        for ((pid, ip, port), groupe) in &groupes {
            let chemin = chemins.entry(*pid).or_insert_with(|| natif::chemin_processus(*pid)).clone();
            let nom_processus = if !chemin.is_empty() {
                Path::new(&chemin).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default()
            } else if *pid == 4 {
                "System".into()
            } else {
                liste.get(pid).map(|p| p.nom.clone()).unwrap_or_else(|| format!("PID {pid}"))
            };
            let signataire = self.signataire(&chemin);
            let nom = self.partage.dns.lock().unwrap().get(ip).cloned();
            let cle = format!("{}|{ip}|{port}", if chemin.is_empty() { &nom_processus } else { &chemin });
            cles_vues.insert(cle.clone());
            let nouveau = !self.premieres_vues.contains_key(&cle);
            if nouveau {
                self.premieres_vues.insert(cle.clone(), commun::maintenant());
                if !self.premier_passage {
                    crate::siem::connexion(&nom_processus, *pid, ip, *port, nom.as_deref());
                }
                if self.premier_passage {
                    self.preexistants.insert(cle.clone());
                }
            }
            let origine = if *pid > 4 { self.processus.infos(*pid) } else { None };

            let menace = {
                let m = self.partage.menaces.read().unwrap();
                m.chercher_ip(ip).or_else(|| nom.as_deref().and_then(|n| m.chercher_domaine(n)))
            };
            // Origine du fichier : téléchargé depuis Internet, récent, non signé
            let origine_fichier = self.origines.entry(chemin.clone()).or_insert_with(|| reponse::origine(&chemin)).clone();
            let texte_origine = origine_fichier.as_ref().and_then(|o| o.texte());
            let bloque = self.est_bloque(ip, nom.as_deref());
            let (score, raisons) = score_flux(&IndicesFlux {
                menace: menace.as_ref().map(|m| m.source.as_str()),
                // Chemin vide : signataire « ? », jamais vide
                non_signe: signataire.is_empty(),
                dossier_temporaire: dossier_suspect(&chemin),
                origine: origine_fichier.as_ref().zip(texte_origine.as_deref()).map(|(o, t)| (t, o.age_jours)),
                suspicion_ligne: origine.as_ref().and_then(|o| o.ligne_commande.as_deref()).and_then(processus::suspicion),
                nom_dns_connu: nom.is_some(),
                navigateur_doh: NAVIGATEURS_DOH.contains(&nom_processus.to_lowercase().as_str()),
                application_ip_directe: ip_directe_normale(&signataire),
                dns_lu,
                preexistant: self.preexistants.contains(&cle),
                balise: self.balise(*pid, ip, *port, groupe),
                port: *port,
                telemetrie: nom.as_deref().map(est_telemetrie).unwrap_or(false),
                bloque,
            });

            let f = FluxInfo {
                cle: cle.clone(),
                score,
                processus: nom_processus.clone(),
                pid: *pid,
                chemin: chemin.clone(),
                signataire: if signataire.is_empty() { "-".into() } else { signataire },
                ip: ip.clone(),
                nom_dns: nom.clone(),
                port: *port,
                raisons: raisons.join(", "),
                premiere_vue: self.premieres_vues[&cle].clone(),
                connexions: groupe.len(),
                parent: origine.as_ref().and_then(|o| o.parent.clone()).or_else(|| liste.get(pid).and_then(|p| liste.get(&p.parent)).map(|p| p.nom.clone())),
                ligne_commande: origine.as_ref().and_then(|o| o.ligne_commande.clone()),
                origine: texte_origine,
            };

            let regle = regle_flux(menace.is_some(), nouveau, self.premier_passage, score);
            if let (Some(crate::regles::RES_001), Some(m)) = (regle, &menace) {
                // Une menace connue alerte même si la connexion existait au démarrage du service
                let mut action = String::new();
                if blocage_automatique(m.haute, self.config.blocage_auto_menaces, bloque, commun::echec_protection().is_some()) {
                    self.bloquer_ip_auto(ip, &format!("blocage automatique : {} ({nom_processus})", m.source));
                    action = " ; IP BLOQUÉE automatiquement et connexion coupée".into();
                }
                alertes_modifiees |= self.ajouter_alerte(crate::regles::RES_001, "Critique", &f, format!("{}{action}", f.raisons));
            } else if regle == Some(crate::regles::RES_002) {
                alertes_modifiees |= self.ajouter_alerte(crate::regles::RES_002, "Alerte", &f, f.raisons.clone());
            }

            let exe = if chemin.is_empty() { nom_processus.to_lowercase() } else { chemin.to_lowercase() };
            if self.executables_vus.insert(exe) {
                exes_modifies = true;
                if premiere_connexion_signalee(self.apprentissage, self.premier_passage) {
                    let texte = format!("première connexion à Internet de ce programme{}",
                        f.parent.as_ref().map(|p| format!(" (lancé par {p})")).unwrap_or_default());
                    alertes_modifiees |= self.ajouter_alerte(crate::regles::RES_003, "Info", &f, texte);
                }
            }
            // Arbre des processus : les signaux réseau de poids (≥ 2) comptent dans la chaîne
            self.arbre.completer(f.pid, &f.chemin, f.ligne_commande.as_deref());
            if f.score >= 2 {
                self.arbre.signaler(f.pid, f.score, &format!("réseau : {}", f.raisons));
            }
            flux.push(f);
        }

        let t = mesure::noter("cycle.flux", t);
        // Oublie les flux fermés pour que leur réapparition soit considérée comme nouvelle
        self.premieres_vues.retain(|k, _| cles_vues.contains(k));
        self.dernieres_connexions = connexions.clone();

        // Exposition à Internet : paquets entrants venus d'Internet (pfirewall.log), adresses publiques
        let noms: HashMap<u32, String> = liste.iter().map(|(p, i)| (*p, i.nom.clone())).collect();
        let contexte = parefeu::ContexteExposition {
            ecoute_tcp: toutes.iter().filter(|c| c.etat == 2).map(|c| c.port_local).collect(),
            udp_dynamique: self.udp_dynamique,
            pid_service: std::process::id(),
        };
        for a in self.journal_parefeu.lire(&|pid| noms.get(&pid).cloned().unwrap_or_default(), &contexte) {
            alertes_modifiees |= self.ajouter_alerte_brute(a, None);
        }
        if self.numero_passage % 100 == 0 {
            let apres = parefeu::adresses_publiques();
            let alerte = alerte_adresses_publiques(&self.adresses_publiques, &apres);
            self.adresses_publiques = apres;
            if let Some(a) = alerte {
                alertes_modifiees |= self.ajouter_alerte_brute(a, Some("adresse-publique".into()));
            }
        }
        let reseau: crate::ndr::EtatReseau = commun::lire("reseau.json").unwrap_or_default();
        self.exposition = self.journal_parefeu.bilan(&self.adresses_publiques, &reseau);

        let t = mesure::noter("cycle.exposition", t);
        // Leurres anti-rançongiciel : pose reprise toutes les 15 min (nouvelles sessions), leurres déjà suivis gardés
        if self.pose_leurres.is_some_and(|t| t.elapsed() >= Duration::from_secs(900)) {
            self.pose_leurres = Some(Instant::now());
            for l in hygiene::poser_leurres() {
                if !self.leurres.iter().any(|x| x.chemin == l.chemin) {
                    self.leurres.push(l);
                }
            }
        }
        // Vérification par empreinte, en plus de l'audit d'écriture
        for a in hygiene::verifier_leurres(&mut self.leurres) {
            alertes_modifiees |= self.ajouter_alerte_brute(a, None);
        }
        if self.pose_leurres.is_some() {
            // Aucun leurre suivi (pose refusée partout, ou leurres déjà signalés et pas encore reposés) : LEU-001 muette
            if self.leurres.is_empty() {
                collectes::echec(Collecte::Leurres, "aucun leurre posé");
            } else {
                collectes::succes(Collecte::Leurres);
            }
        }
        self.balises.retain(|_, (_, t)| t.last().map(|x| x.elapsed() < Duration::from_secs(3600)).unwrap_or(false));

        if let Some(a) = relever_hosts(&mut self.empreinte_hosts, blocage::empreinte_hosts()) {
            alertes_modifiees |= self.ajouter_alerte_brute(a, None);
        }

        let t = mesure::noter("cycle.leurres_et_hosts", t);
        // Modules : vie privée et accès distant à chaque passage ; persistance dans son propre fil (alertes reprises ici)
        let mut cache = std::mem::take(&mut self.signatures);
        let notre = self.notre_dossier.clone();
        let mut signer = |c: &str| signataire_cache(&mut cache, &notre, c);
        let alertes_surv = self.surveillances.verifier(&toutes, &liste, &mut signer);
        let t = mesure::noter("cycle.surveillances", t);
        let alertes_pers: Vec<Alerte> = std::mem::take(&mut *self.partage.alertes_persistance.lock().unwrap());
        self.signatures = cache;
        for a in alertes_surv {
            let cle = cle_alerte(&a);
            alertes_modifiees |= self.ajouter_alerte_brute(a, Some(cle));
        }
        for a in alertes_pers {
            alertes_modifiees |= self.ajouter_alerte_brute(a, None);
        }
        let detections: Vec<Alerte> = std::mem::take(&mut *self.processus.detections.lock().unwrap());
        let dns: Vec<Alerte> = std::mem::take(&mut *self.partage.alertes_externes.lock().unwrap());
        let a_bloquer: Vec<(String, String)> = std::mem::take(&mut *self.partage.blocages_ips.lock().unwrap());
        // Échec de la protection du dossier : aucune réponse automatique alimentée par ses fichiers (règles IDS)
        let a_bloquer = if commun::echec_protection().is_some() { Vec::new() } else { a_bloquer };
        for (ip, raison) in a_bloquer {
            let r = self.bloquer_ip_auto(&ip, &raison);
            commun::journal(&format!("IPS : {}", r.message));
        }
        if self.expiration.elapsed() > Duration::from_secs(60) {
            self.expiration = Instant::now();
            self.expirer_blocages();
        }
        for a in detections.into_iter().chain(dns) {
            if let Some(pid) = a.pid {
                let raison: String = a.raisons.chars().take(90).collect();
                self.arbre.signaler(pid, a.score, &raison);
            }
            let cle = cle_alerte(&a);
            alertes_modifiees |= self.ajouter_alerte_brute(a, Some(cle));
        }
        let t = mesure::noter("cycle.reponses_et_detections", t);
        // Chaînes de processus : score cumulé, alerte au-delà du seuil
        self.chaines = self.arbre.chaines();
        for a in self.arbre.alertes(&self.chaines) {
            alertes_modifiees |= self.ajouter_alerte_brute(a, None);
        }
        if self.numero_passage % 200 == 0 {
            self.processus.nettoyer();
        }

        let t = mesure::noter("cycle.chaines", t);
        if alertes_modifiees {
            self.ecrire_alertes();
        }
        if exes_modifies {
            let _ = commun::ecrire("executables.json", &self.executables_vus.iter().collect::<Vec<_>>());
        }
        if self.apprentissage && !self.premier_passage {
            self.apprentissage = false;
        }

        flux.sort_by(|a, b| b.score.cmp(&a.score).then(a.processus.to_lowercase().cmp(&b.processus.to_lowercase())));
        let s = &self.surveillances;
        let signature_etat = format!(
            "{}|{}|{}|{}|{}",
            flux.iter().map(|f| format!("{}{}", f.cle, f.raisons)).collect::<Vec<_>>().join(";"),
            s.usages.iter().map(|u| format!("{}{}{}", u.chemin, u.en_cours, u.dernier_debut)).collect::<Vec<_>>().join(";"),
            s.outils.iter().map(|o| o.pid.to_string()).collect::<Vec<_>>().join(";"),
            s.rdp,
            s.ecoutes.iter().map(|e| format!("{}:{}", e.pid, e.port)).collect::<Vec<_>>().join(";")
        );
        if signature_etat != self.derniere_signature_etat || self.dernier_etat_ecrit.elapsed() >= Duration::from_secs(30) {
            let ip_connues = self.partage.dns.lock().unwrap().len();
            let n = flux.len();
            let (etats_collectes, regles_sans_collecte, regles_degradees, causes_sans_collecte) = collectes::publier();
            let _ = commun::ecrire("etat.json", &Etat {
                mis_a_jour: commun::maintenant(),
                demarrage: self.demarrage.clone(),
                version: commun::VERSION.into(),
                // Même critère que l'indice « IP directe » : dernière lecture réussie il y a moins de trois intervalles
                journal_dns_actif: collectes::lue_recemment(Collecte::JournalDns),
                ip_connues,
                source_processus: self.processus.source.lock().unwrap().clone(),
                bureau_a_distance: s.rdp,
                flux,
                peripheriques: s.usages.clone(),
                outils_distants: s.outils.clone(),
                ecoutes: s.ecoutes.clone(),
                defender: self.partage.defender.lock().unwrap().clone(),
                chaines: self.chaines.iter().take(30).cloned().collect(),
                panique: reponse::panique_active(),
                exposition: self.exposition.clone(),
                protection_donnees: commun::echec_protection().unwrap_or_default(),
                collectes: etats_collectes,
                regles_sans_collecte,
                regles_degradees,
                causes_sans_collecte,
            });
            self.derniere_signature_etat = signature_etat;
            self.dernier_etat_ecrit = Instant::now();
            if self.console {
                println!("{}  {} flux, {} alertes, {} IP connues par le DNS, {} entrées de démarrage, {} ports en écoute",
                    commun::maintenant(), n, self.alertes.len(), ip_connues, self.partage.entrees_persistance.load(Ordering::Relaxed), s.ecoutes.len());
            }
        }
        if self.derniere_sauvegarde_dns.elapsed() >= Duration::from_secs(300) {
            let _ = commun::ecrire("dns.json", &*self.partage.dns.lock().unwrap());
            self.derniere_sauvegarde_dns = Instant::now();
        }
        mesure::noter("cycle.ecritures", t);
        self.premier_passage = false;
    }

    fn est_bloque(&self, ip: &str, nom: Option<&str>) -> bool {
        self.blocages.iter().any(|b| (b.type_ == "parefeu" && b.cible == ip)
            || (b.type_ == "hosts" && nom.map(|n| b.cible.eq_ignore_ascii_case(n)).unwrap_or(false)))
    }

    fn ajouter_alerte(&mut self, regle: &str, niveau: &str, f: &FluxInfo, raisons: String) -> bool {
        let cle = format!("{niveau}|{}|{}|{}", f.chemin, f.processus, f.ip);
        self.ajouter_alerte_brute(Alerte {
            regle: regle.into(),
            id: commun::nouvel_id(),
            heure: commun::maintenant(),
            niveau: niveau.into(),
            score: f.score,
            processus: f.processus.clone(),
            chemin: f.chemin.clone(),
            destination: f.nom_dns.clone().unwrap_or_else(|| f.ip.clone()),
            ip: Some(f.ip.clone()),
            nom_dns: f.nom_dns.clone(),
            port: f.port,
            raisons,
            pid: Some(f.pid),
            ..Default::default()
        }, Some(cle))
    }

    /// Ajoute une alerte ; avec une clé, la même alerte n'est levée qu'une fois par 24 h
    /// Note les nouvelles connexions d'un flux (nouveau port local) ; renvoie l'intervalle moyen en secondes
    /// si elles reviennent à un rythme régulier (au moins 6 dans l'heure, écart-type < 25 % de la moyenne)
    fn balise(&mut self, pid: u32, ip: &str, port: u16, groupe: &[&Connexion]) -> Option<u64> {
        let (ports, instants) = self.balises.entry((pid, ip.to_string(), port)).or_default();
        let premier = ports.is_empty();
        for c in groupe {
            if ports.insert(c.port_local) && !premier {
                instants.push(Instant::now());
            }
        }
        if ports.len() > 500 {
            ports.clear();
        }
        instants.retain(|t| t.elapsed() < Duration::from_secs(3600));
        if instants.len() < 6 {
            return None;
        }
        let ecarts: Vec<f64> = instants.windows(2).map(|w| (w[1] - w[0]).as_secs_f64()).collect();
        let moyenne = ecarts.iter().sum::<f64>() / ecarts.len() as f64;
        let variance = ecarts.iter().map(|e| (e - moyenne).powi(2)).sum::<f64>() / ecarts.len() as f64;
        (moyenne >= 10.0 && moyenne <= 1800.0 && variance.sqrt() < 0.25 * moyenne).then_some(moyenne.round() as u64)
    }

    fn ajouter_alerte_brute(&mut self, mut a: Alerte, cle: Option<String>) -> bool {
        commun::marquer_modele(&mut a);
        // Décisions sur le texte entier (MITRE, signal fort, apprentissage), puis bornage avant tout usage (S72-06)
        mitre::enrichir(&mut a);
        // Empreinte du comportement, sur le texte entier, pour les exceptions posées plus tard depuis cette alerte
        // (S72-10) ; seulement là où une exception peut s'appliquer (ni Critique ni Info)
        let empreinte = if a.niveau != "Critique" && a.niveau != "Info" { commun::empreinte_signature(&crate::apprentissage::signature(&a)) } else { String::new() };
        crate::apprentissage::filtrer(&mut a);
        a.signature = empreinte;
        // Collecte d'origine (phase 3.3c), hors de la signature : les exceptions et l'apprentissage n'en dépendent pas
        if a.collecte.is_empty() {
            a.collecte = collectes::collecte_de_l_alerte(&a.regle).to_string();
        }
        commun::borner_alerte(&mut a);
        if let Some(cle) = cle {
            if let Some(t) = self.dernieres_alertes.get(&cle) {
                if t.elapsed() < Duration::from_secs(24 * 3600) {
                    return false;
                }
            }
            // Table bornée : des clés venues du réseau (adresses usurpées) la faisaient grossir sans fin (audit AUD4-03)
            if self.dernieres_alertes.len() >= 20_000 {
                commun::purger_anciens(&mut self.dernieres_alertes, Duration::from_secs(24 * 3600), 10_000);
            }
            self.dernieres_alertes.insert(cle, Instant::now());
        }
        commun::journal(&format!("{} : {} -> {}{} ({})", a.niveau, a.processus, a.destination,
            if a.port > 0 { format!(":{}", a.port) } else { String::new() }, a.raisons));
        crate::export::alerte(&a);
        crate::notifications::alerte(&a);
        crate::siem::depuis_alerte(&a);
        self.alertes.push(a);
        true
    }

    // ------------------------------------------------------------ commandes de l'interface

    pub fn executer(&mut self, c: Commande, partage: &Arc<Partage>) -> Reponse {
        let debut = Instant::now();
        let action = c.action.clone().unwrap_or_default();
        let r = self.executer_action(c, partage, &action);
        mesure::duree(&format!("commande.{}", action.chars().filter(|x| x.is_ascii_alphanumeric()).take(32).collect::<String>()), debut.elapsed());
        r
    }

    fn executer_action(&mut self, c: Commande, partage: &Arc<Partage>, action: &str) -> Reponse {
        let action = action.to_string();
        commun::journal(&format!("commande : {action} {}", c.nom_dns.as_deref().or(c.ip.as_deref()).or(c.cible.as_deref()).unwrap_or("")));
        let raison = c.raison.clone().unwrap_or_default();
        match action.as_str() {
            // Contrôle de bon fonctionnement après une mise à jour (maj.rs) : le service répond et dit sa version
            "verification" => Reponse::ok(format!("deR4Tizer {}", commun::VERSION)),
            "bloquer" => match c.nom_dns.as_deref().filter(|n| !n.is_empty()) {
                Some(n) => self.bloquer_domaines(&[n.to_string()], &raison, c.ip.as_deref()),
                None => self.bloquer_ip(c.ip.as_deref().unwrap_or(""), &raison),
            },
            "bloquerIp" => self.bloquer_ip(c.ip.as_deref().unwrap_or(""), &raison),
            "debloquer" => self.debloquer(c.type_.as_deref().unwrap_or(""), c.cible.as_deref().unwrap_or("")),
            "toutDebloquer" => self.tout_debloquer(),
            "config" => {
                let actif = c.valeur.as_deref() == Some("true");
                let quoi = match c.cible.as_deref() {
                    Some("BlocageAutoMenaces") => {
                        self.config.blocage_auto_menaces = actif;
                        "Blocage automatique des menaces"
                    }
                    Some("ListesRestreintes") => {
                        self.config.listes_restreintes = actif;
                        let _ = commun::ecrire("config.json", &self.config);
                        let p = partage.clone();
                        std::thread::spawn(move || mettre_a_jour_menaces(&p, true));
                        "Listes non commerciales ou non vérifiées"
                    }
                    Some("Ips") => {
                        self.config.ips = actif;
                        "Prévention d'intrusion (IPS)"
                    }
                    Some("ReponseAutoRancongiciel") => {
                        self.config.reponse_auto_rancongiciel = actif;
                        "Suspension automatique des rançongiciels"
                    }
                    _ => return Reponse::erreur("réglage inconnu"),
                };
                let _ = commun::ecrire("config.json", &self.config);
                Reponse::ok(format!("{quoi} {}.", if actif { "activé(e)" } else { "désactivé(e)" }))
            }
            // ---------------- réglages (langue, syslog, API d'export) : Valeur = Config en JSON
            "reglages" => {
                let n = match commun::lire_reglages(c.valeur.as_deref().unwrap_or("")) {
                    Ok(n) => n,
                    Err(e) => return Reponse::erreur(e),
                };
                if n.syslog.actif && n.syslog.hote.trim().is_empty() {
                    return Reponse::erreur("Indiquez le serveur syslog.");
                }
                if n.api.actif && n.api.port < 1024 {
                    return Reponse::erreur("Choisissez un port d'API entre 1024 et 65535.");
                }
                if n.api.actif && n.api.reseau && n.api.adresses.trim().is_empty() {
                    return Reponse::erreur("Indiquez l'adresse du SIEM autorisé à interroger l'API depuis le réseau.");
                }
                let invalides = crate::api::adresses_invalides(&n.api.adresses);
                if !invalides.is_empty() {
                    return Reponse::erreur(format!("Adresses autorisées invalides (adresse IPv4, ou réseau IPv4 de /8 à /32) : {}",
                        invalides.iter().map(|a| a.chars().filter(|x| !x.is_control()).take(40).collect::<String>()).collect::<Vec<_>>().join(", ")));
                }
                self.config.langue = n.langue.clone();
                if n.syslog != self.config.syslog {
                    self.config.syslog = n.syslog;
                    crate::export::configurer(&self.config.syslog);
                }
                if n.api != self.config.api {
                    self.config.api = n.api;
                    crate::api::demarrer(&self.config.api);
                }
                let _ = commun::ecrire("config.json", &self.config);
                Reponse::ok("Réglages enregistrés.")
            }
            "testerSyslog" => {
                // Mêmes contrôles que les réglages (S58-01, S58-02) ; la confirmation affiche la destination
                let cfg = match c.valeur.as_deref() {
                    Some(v) => match commun::lire_syslog_test(v) { Ok(s) => s, Err(e) => return Reponse::erreur(e) },
                    None => self.config.syslog.clone(),
                };
                match crate::export::tester(&cfg) {
                    Ok(()) => Reponse::ok(format!("Message de test envoyé à {}:{} ({}).", cfg.hote, cfg.port, cfg.protocole)),
                    Err(e) => Reponse::erreur(format!("Échec de l'envoi : {e}")),
                }
            }
            // ---------------- remontée des alertes : Valeur = { Config, NtfyUrl, NtfyJeton, TeamsUrl, SmtpMotDePasse }
            "notifications" | "testerNotifications" => {
                #[derive(serde::Deserialize, Default)]
                #[serde(rename_all = "PascalCase", default)]
                struct Demande {
                    // absente ou nulle : réglages par défaut (tout désactivé)
                    config: Option<commun::ConfigNotifications>,
                    #[serde(flatten)]
                    secrets: crate::notifications::Secrets,
                }
                if let Err(e) = crate::notifications::controler_demande(c.valeur.as_deref().unwrap_or("")) {
                    return Reponse::erreur(e);
                }
                let Some(mut d) = c.valeur.as_deref().and_then(|v| serde_json::from_str::<Demande>(v).ok()) else {
                    return Reponse::erreur("réglages des notifications illisibles");
                };
                let nouvelle = d.config.clone().unwrap_or_default();
                if let Err(e) = crate::notifications::preparer(&self.config.notifications, &nouvelle,
                    &crate::notifications::lire_secrets(), &mut d.secrets) {
                    return Reponse::erreur(format!("Réglages des notifications refusés : {e}"));
                }
                if let Err(e) = crate::notifications::enregistrer_secrets(&d.secrets) {
                    return Reponse::erreur(format!("Secrets non enregistrés : {e}"));
                }
                self.config.notifications = d.config.unwrap_or_default();
                let _ = commun::ecrire("config.json", &self.config);
                crate::notifications::configurer(&self.config.notifications);
                if action == "testerNotifications" {
                    match crate::notifications::tester(&self.config.notifications) {
                        Ok(m) => Reponse::ok(m),
                        Err(e) => Reponse::erreur(format!("Échec : {e}")),
                    }
                } else {
                    Reponse::ok("Réglages des notifications enregistrés.")
                }
            }
            // ---------------- bruit : « ne plus alerter pour ce comportement » (Cible : identifiant de l'alerte)
            "exception" => match self.alertes.iter().find(|a| Some(a.id.as_str()) == c.cible.as_deref()).cloned() {
                Some(a) => match crate::apprentissage::ajouter_exception(&a) {
                    Ok(d) => Reponse::ok(format!("Ce comportement ne déclenchera plus qu'une information : {d}")),
                    Err(e) => Reponse::erreur(e),
                },
                None => Reponse::erreur("Alerte introuvable."),
            },
            "apprentissage" => match crate::apprentissage::commande(c.valeur.as_deref().unwrap_or("")) {
                Ok(m) => Reponse::ok(m),
                Err(e) => Reponse::erreur(e),
            },
            "majVerifier" => {
                crate::maj::verifier_maintenant(self.config.maj.clone());
                Reponse::ok("Recherche de mise à jour lancée : le résultat s'affichera dans les Réglages.")
            }
            "majConfig" => {
                let m = match commun::lire_config_maj(c.valeur.as_deref().unwrap_or("")) {
                    Ok(m) => m,
                    Err(e) => return Reponse::erreur(e),
                };
                self.config.maj = m;
                let _ = commun::ecrire("config.json", &self.config);
                Reponse::ok("Réglages de mise à jour enregistrés.")
            }
            "autoriserLecteur" => match crate::protection::autoriser(c.valeur.as_deref().unwrap_or("")) {
                Ok(nom) => Reponse::ok(format!("Le compte {nom} peut maintenant lire les données de deR4Tizer.")),
                Err(e) => Reponse::erreur(e),
            },
            "jetonApi" | "nouveauJeton" => {
                let j = if action == "nouveauJeton" {
                    let j = crate::api::regenerer_jeton();
                    crate::api::demarrer(&self.config.api);
                    j
                } else {
                    crate::api::jeton().ok_or_else(|| "jeton impossible à créer avec ses droits".to_string())
                };
                let j = match j {
                    Ok(j) => j,
                    Err(e) => return Reponse::erreur(format!("Jeton de l'API indisponible : {e}")),
                };
                Reponse::ok(format!("Jeton de l'API (Ctrl+C pour copier ce message) :

{j}

En-tête : Authorization: Bearer {j}"))
            }
            "majMenaces" => {
                let p = partage.clone();
                std::thread::spawn(move || {
                    mettre_a_jour_menaces(&p, true);
                    commun::journal("listes de menaces mises à jour à la demande");
                });
                Reponse::ok("Mise à jour des listes de menaces lancée (1 à 2 minutes).")
            }
            // ---------------- actions de réponse (Cible : PID, chemin ou identifiant)
            "tuer" | "suspendre" | "reprendre" => {
                let Some(pid) = c.cible.as_deref().and_then(|p| p.parse::<u32>().ok()) else { return Reponse::erreur("PID invalide.") };
                let r = match action.as_str() {
                    "tuer" => reponse::tuer(pid),
                    "suspendre" => reponse::suspendre(pid, true),
                    _ => reponse::suspendre(pid, false),
                };
                match r {
                    Ok(()) => Reponse::ok(format!("Processus {pid} : {} fait.", action)),
                    Err(e) => Reponse::erreur(format!("Processus {pid} : {e}")),
                }
            }
            "tuerChaine" => {
                // Tue un processus et tous ses descendants (une chaîne d'attaque entière)
                let Some(pid) = c.cible.as_deref().and_then(|p| p.parse::<u32>().ok()) else { return Reponse::erreur("PID invalide.") };
                let liste = natif::processus();
                let mut a_tuer = vec![pid];
                let mut i = 0;
                while i < a_tuer.len() {
                    let parent = a_tuer[i];
                    // Windows ne remet pas à zéro le PID parent des orphelins : un « enfant » créé avant son parent
                    // appartient à un ancien processus qui portait le même PID, il n'est pas de la chaîne
                    let naissance_parent = natif::creation_processus(parent).unwrap_or(0);
                    a_tuer.extend(liste.iter()
                        .filter(|(p, x)| x.parent == parent && !a_tuer.contains(p))
                        .filter(|(p, _)| natif::creation_processus(**p).map(|n| n >= naissance_parent).unwrap_or(false))
                        .map(|(p, _)| *p).collect::<Vec<_>>());
                    i += 1;
                }
                let n = a_tuer.iter().rev().filter(|p| reponse::tuer(**p).is_ok()).count();
                Reponse::ok(format!("{n} processus arrêté(s)."))
            }
            "quarantaine" => match reponse::mettre_en_quarantaine(c.cible.as_deref().unwrap_or(""), &raison) {
                Ok(m) => Reponse::ok(m),
                Err(e) => Reponse::erreur(e),
            },
            "restaurer" => match reponse::restaurer(c.cible.as_deref().unwrap_or("")) {
                Ok(m) => Reponse::ok(m),
                Err(e) => Reponse::erreur(e),
            },
            // Repli quand la restauration à l'emplacement d'origine est refusée (pas de session du propriétaire,
            // emplacement système) : dossier créé par le service
            "restaurerRepli" => match reponse::restaurer_repli(c.cible.as_deref().unwrap_or("")) {
                Ok(m) => Reponse::ok(m),
                Err(e) => Reponse::erreur(e),
            },
            "isolerProgramme" => {
                let chemin = c.cible.clone().unwrap_or_default();
                if chemin.is_empty() || chemin.to_lowercase().starts_with(&natif::dossier_windows().to_lowercase()) {
                    return Reponse::erreur("Refusé : chemin vide ou programme du système Windows.");
                }
                match reponse::isoler_programme(&chemin) {
                    Ok(()) => {
                        self.blocages.push(Blocage { type_: "programme".into(), cible: chemin.clone(), raison, date: commun::maintenant(), expire: String::new() });
                        let _ = commun::ecrire("blocages.json", &self.blocages);
                        Reponse::ok(format!("{chemin} est coupé du réseau (entrant et sortant)."))
                    }
                    Err(e) => Reponse::erreur(format!("Pare-feu : {e}")),
                }
            }
            "panique" => match reponse::panique(c.valeur.as_deref() != Some("off")) {
                Ok(m) => {
                    commun::journal(&m);
                    Reponse::ok(m)
                }
                Err(e) => Reponse::erreur(format!("Pare-feu : {e}")),
            },
            "baseline" => {
                // Valeur : appliquer / annuler / evaluer ; Cible : profil(s) ou identifiants de règles séparés par des virgules
                if partage.baseline_occupee.swap(true, Ordering::Relaxed) {
                    return Reponse::erreur("Une opération sur la baseline est déjà en cours.");
                }
                let (operation, cible) = (c.valeur.unwrap_or_default(), c.cible.unwrap_or_default());
                let p = partage.clone();
                std::thread::spawn(move || {
                    let regles = baseline::selection(&cible);
                    let resultat = match operation.as_str() {
                        "appliquer" => baseline::appliquer(&regles),
                        "annuler" => baseline::annuler(&regles),
                        _ => Ok("Conformité réévaluée.".into()),
                    };
                    let message = resultat.unwrap_or_else(|e| format!("Échec : {e}"));
                    commun::journal(&format!("baseline {operation} {cible} : {message}"));
                    let mut b = baseline::evaluer();
                    b.message = message;
                    let _ = commun::ecrire("baseline.json", &b);
                    p.baseline_occupee.store(false, Ordering::Relaxed);
                });
                Reponse::ok("Opération lancée : la GPO locale est mise à jour (environ 30 secondes). Le résultat s'affichera dans l'onglet Baseline.")
            }
            autre => Reponse::erreur(format!("commande inconnue : {autre}")),
        }
    }

    fn bloquer_domaines(&mut self, domaines: &[String], raison: &str, ip_a_couper: Option<&str>) -> Reponse {
        let nouveaux: Vec<String> = domaines.iter()
            .filter(|d| !d.is_empty() && !self.blocages.iter().any(|b| b.type_ == "hosts" && b.cible.eq_ignore_ascii_case(d)))
            .cloned()
            .collect();
        if nouveaux.is_empty() {
            return Reponse::ok("Déjà bloqué.");
        }
        let tous: Vec<String> = self.blocages.iter().filter(|b| b.type_ == "hosts").map(|b| b.cible.clone()).chain(nouveaux.iter().cloned()).collect();
        if let Err(e) = blocage::ecrire_bloc_hosts(&tous) {
            return Reponse::erreur(format!("Écriture du fichier hosts refusée : {e}"));
        }
        self.empreinte_hosts = blocage::empreinte_hosts(); // notre propre écriture ne doit pas déclencher d'alerte
        for d in &nouveaux {
            self.blocages.push(Blocage { type_: "hosts".into(), cible: d.clone(), raison: raison.into(), date: commun::maintenant(), expire: String::new() });
        }
        let _ = commun::ecrire("blocages.json", &self.blocages);
        let coupees = ip_a_couper.map(|ip| self.couper(ip)).unwrap_or(0);
        Reponse::ok(format!("{} domaine(s) redirigé(s) vers 127.0.0.1{}", nouveaux.len(), message_coupure(coupees)))
    }

    fn bloquer_ip(&mut self, ip: &str, raison: &str) -> Reponse {
        if ip.parse::<IpAddr>().is_err() {
            return Reponse::erreur("Adresse IP invalide.");
        }
        if est_locale(ip) || ip.parse::<IpAddr>().map(|a| !crate::parefeu::publique(&a)).unwrap_or(true) {
            return Reponse::erreur(format!("Refusé : {ip} n'est pas une adresse publique (réseau local, CGNAT, multicast…)."));
        }
        if !self.blocages.iter().any(|b| b.type_ == "parefeu" && b.cible == ip) {
            if let Err(e) = blocage::ajouter_regle(ip, raison) {
                return Reponse::erreur(format!("Pare-feu : {e}"));
            }
            self.blocages.push(Blocage { type_: "parefeu".into(), cible: ip.into(), raison: raison.into(), date: commun::maintenant(), expire: String::new() });
            let _ = commun::ecrire("blocages.json", &self.blocages);
        }
        let coupees = self.couper(ip);
        Reponse::ok(format!("Connexions sortantes vers {ip} bloquées par le pare-feu{}", message_coupure(coupees)))
    }

    /// Blocage automatique (liste de menaces, IPS) : levé au bout de 7 jours, ou plus tôt si l'adresse sort des
    /// listes (adresse réattribuée, CDN…)
    fn bloquer_ip_auto(&mut self, ip: &str, raison: &str) -> Reponse {
        let r = self.bloquer_ip(ip, raison);
        if r.ok {
            let fin = commun::heure(std::time::SystemTime::now() + Duration::from_secs(7 * 86_400));
            if let Some(b) = self.blocages.iter_mut().find(|b| b.type_ == "parefeu" && b.cible == ip && b.expire.is_empty() && b.raison == raison) {
                b.expire = fin;
                let _ = commun::ecrire("blocages.json", &self.blocages);
            }
        }
        r
    }

    fn expirer_blocages(&mut self) {
        let maintenant = commun::maintenant();
        let a_retirer = {
            let menaces = self.partage.menaces.read().unwrap();
            let chargees = menaces.infos.total_ip + menaces.infos.total_reseaux > 0;
            blocages_a_lever(&self.blocages, &maintenant, chargees, |ip| menaces.chercher_ip(ip).is_some())
        };
        for (t, c, pourquoi) in a_retirer {
            self.debloquer(&t, &c);
            commun::journal(&format!("blocage automatique levé : {c} ({pourquoi})"));
        }
    }

    fn couper(&self, ip: &str) -> usize {
        self.dernieres_connexions.iter().filter(|c| c.ip == ip).filter(|c| natif::couper(c)).count()
    }

    fn debloquer(&mut self, type_: &str, cible: &str) -> Reponse {
        if type_ == "parefeu" {
            blocage::supprimer_regle(cible);
        }
        if type_ == "programme" {
            reponse::liberer_programme(cible);
        }
        self.blocages.retain(|b| !(b.type_ == type_ && b.cible == cible));
        if type_ == "hosts" {
            let domaines: Vec<String> = self.blocages.iter().filter(|b| b.type_ == "hosts").map(|b| b.cible.clone()).collect();
            if let Err(e) = blocage::ecrire_bloc_hosts(&domaines) {
                return Reponse::erreur(format!("Écriture du fichier hosts refusée : {e}"));
            }
            self.empreinte_hosts = blocage::empreinte_hosts();
        }
        let _ = commun::ecrire("blocages.json", &self.blocages);
        Reponse::ok(format!("{cible} débloqué."))
    }

    fn tout_debloquer(&mut self) -> Reponse {
        let ips: Vec<String> = self.blocages.iter().filter(|b| b.type_ == "parefeu").map(|b| b.cible.clone()).collect();
        let mut regles: usize = ips.iter().map(|ip| blocage::supprimer_regle(ip)).sum();
        for b in self.blocages.iter().filter(|b| b.type_ == "programme") {
            regles += reponse::liberer_programme(&b.cible);
        }
        blocage::supprimer_groupe(); // règles orphelines éventuelles
        if let Err(e) = blocage::ecrire_bloc_hosts(&[]) {
            return Reponse::erreur(format!("Écriture du fichier hosts refusée : {e}"));
        }
        self.empreinte_hosts = blocage::empreinte_hosts();
        self.blocages.clear();
        let _ = commun::ecrire("blocages.json", &self.blocages);
        Reponse::ok(format!("Tous les blocages retirés ({regles} règle(s) de pare-feu)."))
    }
}

/// Signataire d'un exécutable, mis en cache par chemin et date de modification ; un échec est gardé tant que le fichier
/// ne change pas (cycle de surveillance, sous le verrou : pas de nouvelle vérification à chaque tour)
pub(crate) fn signataire_cache(cache: &mut HashMap<String, String>, notre: &str, chemin: &str) -> String {
    signataire_cache_a(cache, notre, chemin, maintenant_s(), u64::MAX)
}

/// Comme `signataire_cache`, mais un échec n'est gardé que 30 s (relevé des démarrages automatiques, relecture de #83,
/// R4-D1 : une vérification passagèrement impossible, au démarrage du PC par exemple, est refaite au relevé suivant au
/// lieu d'être confirmée par le cache ; limité à ce fil, la mesure du cycle ayant montré le coût d'une nouvelle
/// vérification toutes les 30 s sous le verrou)
pub(crate) fn signataire_cache_releve(cache: &mut HashMap<String, String>, notre: &str, chemin: &str) -> String {
    signataire_cache_a(cache, notre, chemin, maintenant_s(), 30)
}

fn maintenant_s() -> u64 {
    SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// `signataire_cache` à une heure donnée (secondes), un échec gardé `duree_echec` secondes, pour les tests
pub(crate) fn signataire_cache_a(cache: &mut HashMap<String, String>, notre: &str, chemin: &str, maintenant: u64, duree_echec: u64) -> String {
    if chemin.is_empty() {
        return "?".into();
    }
    // Nos propres exécutables (non signés tant qu'il n'y a pas de certificat de signature de code) : reconnus
    // par leur empreinte SHA-256, pas par leur dossier, pour qu'un autre fichier posé à côté ne soit pas approuvé
    let _ = notre;
    let nom = Path::new(chemin).file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
    if nom == "der4tizersvc.exe" || nom == "der4tizer.exe" {
        static NOS: OnceLock<HashSet<String>> = OnceLock::new();
        let nos = NOS.get_or_init(|| {
            let exe = std::env::current_exe().unwrap_or_default();
            [exe.clone(), exe.with_file_name("deR4Tizer.exe")].iter().filter_map(|p| crate::hygiene::empreinte_fichier(p)).collect()
        });
        if crate::hygiene::empreinte_fichier(Path::new(chemin)).is_some_and(|h| nos.contains(&h)) {
            return "deR4Tizer (empreinte vérifiée)".into();
        }
    }
    let date = fs::metadata(chemin).and_then(|m| m.modified()).map(commun::filetime).unwrap_or(0);
    let cle = format!("{chemin}|{date}");
    if let Some(s) = cache.get(&cle) {
        return s.clone();
    }
    // Un échec (signataire vide) n'est gardé que `duree_echec` secondes et tant que le fichier ne change pas. Une seule
    // clé d'échec par chemin, réécrite à chaque échec (relecture de #83, R5-D1 : pas d'accumulation dans le service)
    let cle_echec = format!("{chemin}|échec");
    if cache.get(&cle_echec).is_some_and(|v| echec_recent(v, date, maintenant, duree_echec)) {
        return String::new();
    }
    let windows = natif::dossier_windows().to_lowercase();
    let s = match natif::signataire_valide(chemin) {
        Some(nom) if nom.is_empty() => "signé".to_string(),
        Some(nom) => nom,
        // Fichiers système signés par catalogue, pas dans le fichier lui-même : empreinte vérifiée dans les
        // catalogues installés (C:\Windows\Tasks ou spool\drivers\color sont inscriptibles par tous)
        None if (chemin.to_lowercase().starts_with(&windows) || dossier_microsoft(chemin)) && natif::signe_par_catalogue(chemin) => "Windows (catalogue)".into(),
        None => String::new(),
    };
    if s.is_empty() {
        cache.insert(cle_echec, format!("{date}|{maintenant}"));
    } else {
        cache.remove(&cle_echec);
        cache.insert(cle, s.clone());
    }
    s
}

/// Décision pure (testée) : l'échec noté (« date du fichier|heure de la vérification ») vaut-il encore pour ce fichier ?
/// Même date de modification, et vérifié il y a moins de `duree` secondes ; une horloge qui a reculé depuis la
/// vérification la fait refaire (relecture de #83, R6-D1)
pub(crate) fn echec_recent(valeur: &str, date: u64, maintenant: u64, duree: u64) -> bool {
    let Some((d, t)) = valeur.split_once('|') else { return false };
    d.parse() == Ok(date) && t.parse::<u64>().is_ok_and(|t| maintenant >= t && maintenant - t < duree)
}

fn cle_alerte(a: &Alerte) -> String {
    format!("{}|{}|{}|{}", a.niveau, a.chemin, a.destination, a.raisons.chars().take(40).collect::<String>())
}

fn message_coupure(n: usize) -> String {
    if n > 0 { format!(" ; {n} connexion(s) en cours coupée(s).") } else { ".".into() }
}

fn est_telemetrie(nom: &str) -> bool {
    commun::telemetrie().iter().flat_map(|(_, d)| d.iter()).any(|d| nom.eq_ignore_ascii_case(d) || nom.to_lowercase().ends_with(&format!(".{d}")))
}

fn mettre_a_jour_menaces(p: &Arc<Partage>, forcer: bool) {
    let statuts = Menaces::telecharger(forcer);
    let nouvelles = Menaces::charger(&statuts);
    let i = &nouvelles.infos;
    let actives = |t: &str| i.sources.iter().filter(|s| s.type_ == t && !s.statut.starts_with("désactivée")).count();
    collectes::noter_listes(actives("IP"), i.total_ip + i.total_reseaux, actives("Domaines"), i.total_domaines);
    *p.menaces.write().unwrap() = nouvelles;
}

// ------------------------------------------------------------ DNS

/// Active le journal DNS de Windows (s'il ne l'était pas), lit les 24 dernières heures puis s'abonne
fn demarrer_dns(partage: &Arc<Partage>) -> bool {
    let mut actif = evenements::journal_actif(JOURNAL_DNS).unwrap_or(false);
    if !actif && evenements::activer_journal(JOURNAL_DNS, true) {
        let _ = fs::write(commun::dossier().join("journal-dns-active-par-deR4Tizer"), commun::maintenant());
        actif = true;
    }
    if !actif {
        commun::journal("impossible d'activer le journal DNS");
        collectes::echec(Collecte::JournalDns, "journal DNS-Client inactif et impossible à activer");
        return false;
    }
    let p = partage.clone();
    evenements::historique(JOURNAL_DNS, "*[System[EventID=3008 and TimeCreated[timediff(@SystemTime) <= 86400000]]]", &mut |xml| {
        let d = evenements::donnees(&xml);
        if let (Some(n), Some(r)) = (d.get("QueryName"), d.get("QueryResults")) {
            noter_dns(&p, n, r);
        }
    });
    let p = partage.clone();
    evenements::abonner(JOURNAL_DNS, "*[System[EventID=3008]]", Collecte::JournalDns, move |xml| {
        let d = evenements::donnees(&xml);
        if let Some(n) = d.get("QueryName") {
            traiter_dns(&p, n, d.get("QueryResults").map(|s| s.as_str()).unwrap_or(""));
        }
    })
}

/// Requête DNS vue en direct (journal DNS de Windows ou Sysmon) : vérifie le nom puis note les IP
fn traiter_dns(p: &Arc<Partage>, nom: &str, resultats: &str) {
    if nom.is_empty() {
        return;
    }
    let nom = nom.trim_end_matches('.');
    let alerte = alerte_dns(&p.menaces.read().unwrap(), nom);
    if let Some(a) = alerte {
        p.alertes_externes.lock().unwrap().push(a);
    }
    noter_dns(p, nom, resultats);
}

/// Décision pure (testée, DNS-001) : requête DNS vers un domaine des listes de menaces
pub(crate) fn alerte_dns(menaces: &crate::menaces::Menaces, nom: &str) -> Option<Alerte> {
    let m = menaces.chercher_domaine(nom)?;
    Some(Alerte {
        regle: crate::regles::DNS_001.into(),
        id: commun::nouvel_id(),
        heure: commun::maintenant(),
        niveau: "Critique".into(),
        score: 10,
        processus: "?".into(),
        destination: nom.into(),
        nom_dns: Some(nom.into()),
        raisons: format!("requête DNS vers un domaine MALVEILLANT connu ({})", m.source),
        ..Default::default()
    })
}

/// Indices d'une connexion, lus dans le cycle de surveillance (`score_flux`)
pub(crate) struct IndicesFlux<'a> {
    /// Source de la liste de menaces qui contient l'adresse ou le nom
    pub menace: Option<&'a str>,
    pub non_signe: bool,
    pub dossier_temporaire: bool,
    /// Texte « téléchargé depuis Internet… » et âge du fichier en jours
    pub origine: Option<(&'a str, u64)>,
    /// Motif suspect de la ligne de commande du processus
    pub suspicion_ligne: Option<&'a str>,
    pub nom_dns_connu: bool,
    pub navigateur_doh: bool,
    /// Éditeur connu pour joindre des adresses sans requête DNS (VPN, messagerie, jeu…)
    pub application_ip_directe: bool,
    /// Journal DNS lu récemment : l'absence de nom a un sens
    pub dns_lu: bool,
    /// Connexion déjà ouverte au démarrage du service
    pub preexistant: bool,
    /// Intervalle de la balise régulière, en secondes
    pub balise: Option<u64>,
    pub port: u16,
    pub telemetrie: bool,
    pub bloque: bool,
}

/// Décision pure (testée, RES-001 et RES-002) : score et raisons d'une connexion, dans l'ordre affiché
pub(crate) fn score_flux(i: &IndicesFlux) -> (i32, Vec<String>) {
    let mut raisons: Vec<String> = Vec::new();
    let mut score = 0;
    if let Some(source) = i.menace {
        raisons.push(format!("MENACE CONNUE ({source})"));
        score += 10;
    }
    if i.non_signe {
        raisons.push("NON SIGNÉ".into());
        score += 3;
    }
    if i.dossier_temporaire {
        raisons.push("lancé depuis un dossier temporaire".into());
        score += 3;
    }
    if let Some((texte, age_jours)) = i.origine {
        if i.non_signe {
            raisons.push(texte.into());
            score += if age_jours < 2 { 3 } else { 2 };
        }
    }
    if let Some(s) = i.suspicion_ligne {
        raisons.push(s.into());
        score += 3;
    }
    if !i.nom_dns_connu {
        if i.navigateur_doh {
            raisons.push("IP sans DNS (navigateur, DoH probable)".into());
        } else if i.application_ip_directe {
            raisons.push("IP sans DNS (application connue : VPN, messagerie, notifications, jeu…)".into());
        } else if i.dns_lu && !i.preexistant {
            raisons.push("IP DIRECTE (aucune requête DNS)".into());
            score += 2;
        } else {
            raisons.push("nom DNS inconnu".into());
        }
    }
    if let Some(intervalle) = i.balise {
        let fort = i.non_signe || !i.nom_dns_connu;
        raisons.push(format!("balise régulière (nouvelle connexion toutes les ~{intervalle} s)"));
        score += if fort { 3 } else { 1 };
    }
    if !PORTS_COURANTS.contains(&i.port) {
        raisons.push(format!("port inhabituel {}", i.port));
        score += 1;
    }
    if i.telemetrie {
        raisons.push("télémétrie connue".into());
        score += 1;
    }
    if i.bloque {
        raisons.push("BLOQUÉ".into());
    }
    (score, raisons)
}

/// Décision pure (testée) : règle d'une connexion. Menace connue : RES-001, même pour une connexion déjà ouverte au
/// démarrage ; sinon nouvelle connexion au score suffisant, hors premier passage : RES-002
pub(crate) fn regle_flux(menace: bool, nouveau: bool, premier_passage: bool, score: i32) -> Option<&'static str> {
    if menace {
        Some(crate::regles::RES_001)
    } else if nouveau && !premier_passage && score >= commun::SEUIL_ALERTE {
        Some(crate::regles::RES_002)
    } else {
        None
    }
}

/// Décision pure (testée, RES-003) : première connexion d'un programme signalée, sauf en apprentissage et au premier
/// passage (connexions déjà ouvertes au démarrage du service)
pub(crate) fn premiere_connexion_signalee(apprentissage: bool, premier_passage: bool) -> bool {
    !apprentissage && !premier_passage
}

/// Décision pure (testée, RES-004) : réseau public apparu sur une carte réseau depuis le relevé précédent. PR 3.8 :
/// comparé réseau par réseau ; avant, seul un nombre d'adresses en hausse alertait, et une adresse publique qui en
/// remplaçait une autre passait inaperçue. Une adresse IPv4 est son propre réseau ; une adresse IPv6 compte par son
/// préfixe /64 : les adresses temporaires que Windows renouvelle chaque jour dans le même préfixe ne sont pas une
/// exposition nouvelle (relecture de #87, D1)
pub(crate) fn alerte_adresses_publiques(avant: &[String], apres: &[String]) -> Option<Alerte> {
    let connus: Vec<String> = avant.iter().map(|a| reseau_public(a)).collect();
    if !apres.iter().any(|a| !connus.contains(&reseau_public(a))) {
        return None;
    }
    Some(Alerte {
        regle: crate::regles::RES_004.into(),
        id: commun::nouvel_id(), heure: commun::maintenant(), niveau: "Alerte".into(), score: 4, processus: "Windows".into(),
        destination: "carte réseau".into(),
        raisons: format!("PC EXPOSÉ À INTERNET : adresse publique directement sur le PC ({})", apres.join(", ")),
        ..Default::default()
    })
}

/// Décision pure (testée, SYS-001) : relevé de l'empreinte du fichier hosts, comparé à la dernière connue, qui est
/// mise à jour. Nos propres écritures (blocages par nom) mettent l'empreinte connue à jour aussitôt, et ne passent donc
/// pas ici. PR 3.10 : un relevé illisible (empreinte vide) ne déclenche rien et garde l'empreinte connue, pour qu'un
/// changement fait pendant la panne soit signalé dès le retour du fichier ; avant, l'alerte partait à tort à la panne
/// et au retour. Fichier illisible au démarrage : le premier relevé lisible devient la référence, sans alerte
pub(crate) fn relever_hosts(connue: &mut String, actuelle: String) -> Option<Alerte> {
    if actuelle.is_empty() {
        return None;
    }
    let a = alerte_hosts(connue, &actuelle);
    *connue = actuelle;
    a
}

/// Empreinte du fichier hosts changée depuis la dernière connue (référence inconnue : rien)
pub(crate) fn alerte_hosts(connue: &str, actuelle: &str) -> Option<Alerte> {
    if actuelle == connue || connue.is_empty() {
        return None;
    }
    Some(Alerte {
        regle: crate::regles::SYS_001.into(),
        id: commun::nouvel_id(), heure: commun::maintenant(), niveau: "Alerte".into(), score: 3,
        processus: "?".into(), destination: "fichier hosts".into(),
        raisons: "le fichier hosts a été modifié par un autre programme".into(), ..Default::default()
    })
}

/// Réseau d'une adresse publique relevée par `parefeu::adresses_publiques` (« adresse (carte) ») : l'adresse IPv4
/// elle-même, le préfixe /64 d'une adresse IPv6, sans le nom de la carte (relecture de #87, R2-D1 : l'adresse est lue
/// avant le premier espace) ; un texte illisible est gardé tel quel
fn reseau_public(releve: &str) -> String {
    let adresse = releve.split(' ').next().unwrap_or(releve);
    match adresse.parse::<IpAddr>() {
        Ok(IpAddr::V6(v6)) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
        _ => adresse.to_string(),
    }
}

fn noter_dns(p: &Arc<Partage>, nom: &str, resultats: &str) {
    let mut dns = p.dns.lock().unwrap();
    if dns.len() > 50_000 {
        dns.clear();
    }
    for jeton in resultats.split(';') {
        let j = jeton.trim();
        let j = j.strip_prefix("type:").map(|r| r.trim_start().trim_start_matches(|c: char| c.is_ascii_digit()).trim_start()).unwrap_or(j);
        let j = j.strip_prefix("::ffff:").unwrap_or(j);
        if let Ok(ip) = j.parse::<IpAddr>() {
            dns.insert(ip.to_string(), nom.trim_end_matches('.').to_string());
        }
    }
}

/// Désinstallation : retire tous les blocages et désactive le journal DNS s'il l'avait activé
pub fn nettoyer() {
    // Dossier de travail de la mise à jour (Program Files) : inconnu du paquet MSI, retiré ici
    match fs::remove_dir_all(crate::maj::dossier_travail()) {
        Ok(()) => println!("Dossier de mise à jour supprimé."),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => println!("Dossier de mise à jour : {e}"),
    }
    let blocages: Vec<Blocage> = commun::lire("blocages.json").unwrap_or_default();
    let n: usize = blocages.iter().filter(|b| b.type_ == "parefeu").map(|b| blocage::supprimer_regle(&b.cible)).sum();
    blocage::supprimer_groupe();
    println!("Règles de pare-feu supprimées : {n} (et règles orphelines du groupe deR4Tizer).");
    match blocage::lignes_hors_bloc() {
        Ok((_, bloc)) if !bloc.is_empty() => match blocage::ecrire_bloc_hosts(&[]) {
            Ok(()) => println!("Bloc deR4Tizer retiré du fichier hosts."),
            Err(e) => println!("Fichier hosts : {e}"),
        },
        Ok(_) => println!("Aucun bloc deR4Tizer dans le fichier hosts."),
        Err(e) => println!("Fichier hosts : {e}"),
    }
    // Leurres anti-rançongiciel et mode panique
    let mut leurres: Vec<hygiene::Leurre> = commun::lire(hygiene::FICHIER_LEURRES).unwrap_or_default();
    leurres.extend(commun::lire::<Vec<hygiene::Leurre>>("leurres.json").unwrap_or_default());
    // Par handle, sans suivre de lien, sous l'identité du propriétaire du profil quand il a une session
    let n = hygiene::retirer_leurres(&leurres.iter().map(|l| l.chemin.clone()).collect::<Vec<_>>());
    println!("Fichiers leurres supprimés : {n}.");
    if reponse::panique_active() {
        let _ = reponse::panique(false);
        println!("Mode panique désactivé.");
    }
    let marqueur = commun::dossier().join("journal-dns-active-par-deR4Tizer");
    if marqueur.exists() && evenements::activer_journal(JOURNAL_DNS, false) {
        let _ = fs::remove_file(marqueur);
        println!("Journal DNS de Windows désactivé (il l'était avant deR4Tizer).");
    }
}

/// Décision pure du blocage automatique d'une adresse des listes de menaces : liste de confiance haute, réglage
/// actif, adresse pas encore bloquée, et jamais en échec de la protection du dossier de données (les listes y sont
/// rangées : aucune réponse automatique alimentée par des fichiers dont la protection n'est pas vérifiée)
pub fn blocage_automatique(haute: bool, actif: bool, deja_bloquee: bool, echec_protection: bool) -> bool {
    haute && actif && !deja_bloquee && !echec_protection
}

/// Blocages automatiques à lever : durée écoulée, ou adresse sortie des listes (si les listes sont chargées)
pub fn blocages_a_lever(blocages: &[Blocage], maintenant: &str, listes_chargees: bool, listee: impl Fn(&str) -> bool) -> Vec<(String, String, &'static str)> {
    blocages.iter().filter_map(|b| {
        if !b.expire.is_empty() && b.expire.as_str() < maintenant {
            Some((b.type_.clone(), b.cible.clone(), "durée écoulée"))
        } else if listes_chargees && b.raison.starts_with("blocage automatique") && !listee(&b.cible) {
            Some((b.type_.clone(), b.cible.clone(), "adresse retirée des listes de menaces"))
        } else {
            None
        }
    }).collect()
}

/// Éditeurs dont les applications contactent normalement des adresses IP sans requête DNS (VPN, messageries,
/// canaux de notification, jeux) : le critère « IP directe » ne les pénalise pas. Nom EXACT du signataire
/// (sans casse ni ponctuation) ; pas d'outils de prise en main à distance (TeamViewer, AnyDesk : arnaques au
/// faux support technique)
pub fn ip_directe_normale(signataire: &str) -> bool {
    const EDITEURS: &[&str] = &[
        "Proton AG", "Proton Technologies AG", "WireGuard LLC", "OpenVPN Inc.", "Tefincom S.A.", "Nord Security", "Tailscale Inc.",
        "Mullvad VPN AB", "Express Technologies Ltd.", "Private Internet Access, Inc.", "Cloudflare, Inc.",
        "Microsoft Corporation", "Microsoft Windows", "Google LLC", "Apple Inc.", "Mozilla Corporation", "Brave Software, Inc.",
        "Valve Corp.", "Blizzard Entertainment, Inc.", "Riot Games, Inc.", "Epic Games Inc.", "Electronic Arts, Inc.",
        "Discord Inc.", "Zoom Video Communications, Inc.", "Spotify AB", "WhatsApp LLC", "Meta Platforms, Inc.",
        "Telegram FZ-LLC", "Signal Messenger, LLC",
    ];
    crate::vol_donnees::editeur_correspond(signataire, EDITEURS)
}
