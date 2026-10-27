//! deR4TizerSvc.exe : service Windows (compte SYSTEM) qui surveille les connexions sortantes,
//! la persistance, la caméra et le micro, lève des alertes et applique les blocages demandés par l'interface.
//!   deR4TizerSvc.exe              lancé par le gestionnaire de services
//!   deR4TizerSvc.exe --console    même surveillance dans une console (débogage)
//!   deR4TizerSvc.exe --nettoyer   retire tous les blocages (utilisé par la désinstallation)
//!   --dossier <chemin>            dossier de données (par défaut C:\ProgramData\deR4Tizer)

mod baseline;
mod blocage;
mod canal;
mod capture;
mod dpi;
mod geoip;
mod ids;
mod maj;
mod ndr;
mod notifications;
mod trafic;
mod upnp;
mod chaines;
mod collectes;
mod api;
mod apprentissage;
mod commun;
mod defender;
mod evenements;
mod export;
mod gpo;
mod hygiene;
mod incidents;
mod mitre;
mod menaces;
mod mesure;
mod moniteur;
mod regles;
mod natif;
mod parefeu;
mod persistance;
mod processus;
mod protection;
mod reponse;
mod siem;
mod surveillances;
mod validation;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_detection;
mod vol_donnees;

use std::ffi::OsString;
use std::sync::mpsc;
use std::time::Duration;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

define_windows_service!(entree_service, service_principal);

fn initialiser_com() {
    // Sécurité COM du processus (une seule fois), nécessaire aux requêtes WMI
    let _ = wmi::COMLibrary::new();
}

fn priorite_basse() {
    use windows::Win32::System::Threading::{GetCurrentProcess, SetPriorityClass, BELOW_NORMAL_PRIORITY_CLASS};
    unsafe {
        let _ = SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS);
    }
}

fn service_principal(_arguments: Vec<OsString>) {
    let (arret_tx, arret_rx) = mpsc::channel();
    let gestionnaire = move |controle| match controle {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = arret_tx.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(etat) = service_control_handler::register(commun::NOM_SERVICE, gestionnaire) else { return };
    let statut = |s: ServiceState, accepte: ServiceControlAccept| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: s,
        controls_accepted: accepte,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    };
    let _ = etat.set_service_status(statut(ServiceState::StartPending, ServiceControlAccept::empty()));

    // Avant toute lecture : propriétaire et droits du dossier de données
    protection::securiser();
    initialiser_com();
    priorite_basse();
    let (moniteur, partage) = moniteur::Moniteur::demarrer(false);
    canal::servir(moniteur.clone(), partage, false);
    let _ = etat.set_service_status(statut(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN));

    let _ = arret_rx.recv();
    let _ = etat.set_service_status(statut(ServiceState::StopPending, ServiceControlAccept::empty()));
    moniteur.lock().unwrap().arreter();
    // Téléchargements en cours (curl.exe) : terminés avec le service, sinon ils gardent ouverts des fichiers du
    // dossier de données (désinstallation incomplète)
    let n = natif::terminer_enfants(&["curl"]);
    if n > 0 {
        commun::journal(&format!("arrêt : {n} téléchargement(s) en cours interrompu(s)"));
    }
    let _ = etat.set_service_status(statut(ServiceState::Stopped, ServiceControlAccept::empty()));
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--dossier") {
        if let Some(d) = args.get(i + 1) {
            commun::definir_dossier(d.into());
        }
    }
    // Le dossier de données n'est pas créé ici : le service le crée avec ses droits (protection::securiser)

    // Outils de diagnostic (sans rien modifier)
    if let Some(i) = args.iter().position(|a| a == "--chercher") {
        // --chercher <texte> [source] : recherche dans les événements du mini-SIEM
        let filtre = siem::Filtre {
            texte: args.get(i + 1).cloned().unwrap_or_default(),
            source: args.get(i + 2).cloned().unwrap_or_default(),
            type_: String::new(),
            niveau_min: String::new(),
            depuis: String::new(),
            jusqua: String::new(),
            limite: 5,
            echeance: None,
        };
        for e in siem::rechercher(&filtre) {
            println!("{} [{}] {} {}", e.heure, e.source, e.type_, e.message.chars().take(100).collect::<String>());
        }
        return;
    }
    if args.iter().any(|a| a == "--baseline") {
        initialiser_com();
        let b = baseline::evaluer();
        for r in &b.regles {
            println!("{:<13} {:<14} {:<28} actuel={} attendu={}", r.profil, r.etat, r.id, r.actuel, r.attendu);
        }
        println!("scores : {:?}", b.scores);
        return;
    }
    if let Some(i) = args.iter().position(|a| a == "--relire-pol") {
        // Vérifie que la lecture puis la réécriture d'un Registry.pol redonne exactement le même fichier
        let f = args.get(i + 1).cloned().unwrap_or_default();
        let o = std::fs::read(&f).unwrap_or_default();
        let entrees = gpo::analyser_pol(&o);
        for e in &entrees {
            println!("{} :: {} (type {}, {} octets)", e.cle, e.nom, e.type_, e.donnees.len());
        }
        println!("identique après réécriture : {}", gpo::serialiser_pol(&entrees) == o);
        return;
    }
    if args.iter().any(|a| a == "--donnees-sensibles") {
        let dossiers = vol_donnees::dossiers_presents();
        for (d, c) in &dossiers {
            println!("{:<42} {}", c.nom, d);
        }
        // Événement 4663 fictif : Chrome lit ses mots de passe (normal), puis un inconnu dans Temp (alerte)
        if let Some((d, _)) = dossiers.iter().find(|(_, c)| c.nom == "mots de passe de Chrome") {
            for p in [r"C:\Program Files\Google\Chrome\Application\chrome.exe", r"C:\Users\Public\AppData\Local\Temp\x7.exe"] {
                let xml = format!("<Event><System><EventID>4663</EventID></System><EventData><Data Name='ObjectName'>{d}\\Login Data</Data><Data Name='ProcessName'>{p}</Data></EventData></Event>");
                match vol_donnees::analyser(&xml, &dossiers) {
                    Some(a) => println!("{p} -> {} : {}", a.niveau, a.raisons),
                    None => println!("{p} -> rien (propriétaire légitime)"),
                }
            }
        }
        return;
    }
    if args.iter().any(|a| a == "--test-chaine") {
        // explorer → WINWORD → powershell → x7 (dans Temp) : trois signaux sur trois maillons
        let mut liste = std::collections::HashMap::new();
        for (pid, nom, parent) in [(100, "explorer", 4), (200, "WINWORD", 100), (300, "powershell", 200), (400, "x7", 300), (500, "notepad", 100)] {
            liste.insert(pid, natif::InfoListe { nom: nom.into(), parent });
        }
        let mut arbre = chaines::Arbre::default();
        arbre.maj(&liste);
        arbre.completer(300, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", Some("powershell -w hidden -enc SQBFAFgA..."));
        arbre.signaler(300, 5, "document WINWORD qui lance powershell");
        arbre.signaler(400, 5, "réseau : NON SIGNÉ, IP DIRECTE");
        arbre.signaler(400, 7, "accès aux mots de passe de Chrome");
        arbre.signaler(500, 1, "port inhabituel");
        let c = arbre.chaines();
        for ch in &c {
            println!("chaîne « {} » score {} : {}", ch.racine, ch.score, ch.resume);
            for n in &ch.noeuds {
                println!("  {}{} ({}) score {} {}", "  ".repeat(n.profondeur as usize), n.nom, n.pid, n.score, n.raisons);
            }
        }
        for a in arbre.alertes(&c) {
            println!("ALERTE {} : {}", a.niveau, a.raisons);
        }
        println!("seconde évaluation, sans nouveau signal : {} alerte(s)", arbre.alertes(&c).len());
        return;
    }
    if args.iter().any(|a| a == "--test-reponse") {
        // Faux fichier « téléchargé » : marque Zone.Identifier comme le ferait un navigateur
        let f = commun::dossier().join("faux-telechargement.exe");
        let _ = std::fs::write(&f, b"MZ test");
        let _ = std::fs::write(format!("{}:Zone.Identifier", f.display()), "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://exemple.invalid/setup.exe\r\n");
        let o = reponse::origine(&f.to_string_lossy()).unwrap_or_default();
        println!("origine : zone {} ; {:?}", o.zone, o.texte());
        // Processus de test : suspendre, reprendre, tuer
        let mut enfant = std::process::Command::new("ping").args(["-n", "60", "127.0.0.1"]).stdout(std::process::Stdio::null()).spawn().unwrap();
        let pid = enfant.id();
        println!("suspendre {pid} : {:?}", reponse::suspendre(pid, true));
        println!("reprendre {pid} : {:?}", reponse::suspendre(pid, false));
        println!("tuer {pid} : {:?}", reponse::tuer(pid));
        println!("terminé : {:?}", enfant.try_wait().map(|s| s.is_some()));
        // Quarantaine puis restauration
        let q = reponse::mettre_en_quarantaine(&f.to_string_lossy(), "test");
        println!("quarantaine : {q:?} ; original présent : {}", f.exists());
        let liste: Vec<reponse::ElementQuarantaine> = commun::lire("quarantaine.json").unwrap_or_default();
        if let Some(e) = liste.last() {
            println!("restaurer : {:?} ; original présent : {}", reponse::restaurer(&e.id), f.exists());
        }
        let _ = std::fs::remove_file(&f);
        return;
    }
    if args.iter().any(|a| a == "--hygiene") {
        for e in hygiene::inventaire_extensions() {
            println!("{:<22} {:<40} {:<10} {}{}", e.navigateur, e.nom.chars().take(40).collect::<String>(), e.version,
                if e.dangereuse { "SENSIBLE : " } else { "" }, e.permissions.chars().take(80).collect::<String>());
        }
        let liste = hygiene::liste_loldrivers();
        let debut = std::time::Instant::now();
        let a = hygiene::verifier_pilotes(&liste, &mut Default::default());
        println!("LOLDrivers : {} empreintes ; pilotes vérifiés en {:.1} s ; {} alerte(s)", liste.len(), debut.elapsed().as_secs_f32(), a.len());
        for x in a {
            println!("  {} : {}", x.processus, x.raisons);
        }
        let mut test = commun::Alerte { raisons: "accès aux mots de passe de Chrome : comportement typique d'un VOLEUR DE DONNÉES".into(), ..Default::default() };
        mitre::enrichir(&mut test);
        println!("MITRE : {} / {}", test.mitre, test.conseil);
        return;
    }
    if args.iter().any(|a| a == "--test-parefeu") {
        println!("adresses publiques sur le PC : {:?}", parefeu::adresses_publiques());
        // Derniers changements de règles réels
        let mut n = 0;
        evenements::historique("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", "*[System[(EventID=2097 or EventID=2099 or EventID=2052)]]", &mut |xml| {
            if n >= 400 {
                return;
            }
            n += 1;
            if let Some((e, a)) = parefeu::traduire(&xml, &|c| natif::signataire_valide(c).unwrap_or_default()) {
                if let Some(a) = a {
                    println!("[{}] {} — règle « {} » {} {} {} par {}", a.niveau, a.raisons.chars().take(110).collect::<String>(), e.regle, e.operation, e.sens, e.action, e.auteur);
                }
            }
        });
        println!("{n} événements de règles lus");
        // Faux journal pfirewall.log : une IP publique acceptée, une bloquée, une locale (ignorée)
        let f = commun::dossier().join("pfirewall-test.log");
        let _ = std::fs::write(&f, "#Version: 1.5\r\n#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path pid\r\n");
        let mut lecteur = parefeu::LecteurJournal::sur_fichier(f.clone());
        let _ = std::fs::OpenOptions::new().append(true).open(&f).and_then(|mut x| {
            use std::io::Write;
            x.write_all(b"2026-01-01 07:00:01 ALLOW TCP 203.0.113.7 192.168.0.10 51515 3389 0 - - - - - - - RECEIVE 1234\r\n\
2026-01-01 07:00:02 DROP TCP 198.51.100.9 192.168.0.10 40000 445 0 - - - - - - - RECEIVE 0\r\n\
2026-01-01 07:00:03 ALLOW UDP 192.168.0.1 192.168.0.10 53 5353 0 - - - - - - - RECEIVE 0\r\n\
2026-01-01 07:00:04 ALLOW TCP 192.168.0.10 192.0.2.8 50000 443 0 - - - - - - - SEND 999\r\n")
        });
        // Diagnostic : le port 3389 de l'exemple est réputé en écoute
        let contexte = parefeu::ContexteExposition { ecoute_tcp: [3389u16].into_iter().collect(), udp_dynamique: parefeu::plage_dynamique_udp(), pid_service: std::process::id() };
        for a in lecteur.lire(&|pid| format!("prog{pid}"), &contexte) {
            println!("[{}] {} : {}", a.niveau, a.processus, a.raisons);
        }
        let b = lecteur.bilan(&[], &Default::default());
        println!("exposé : {} — {:?}", b.exposee, b.raisons);
        let _ = std::fs::remove_file(&f);
        return;
    }
    if args.iter().any(|a| a == "--defender") {
        initialiser_com();
        let e = defender::etat();
        println!("{}", serde_json::to_string_pretty(&e).unwrap_or_default());
        return;
    }

    if args.iter().any(|a| a == "--annuler-baseline") {
        // Désinstallation : remet les valeurs d'origine de toutes les règles appliquées par deR4Tizer
        initialiser_com();
        let toutes: Vec<&baseline::Regle> = baseline::REGLES.iter().collect();
        match baseline::annuler(&toutes) {
            Ok(m) => println!("Baseline : {m}"),
            Err(e) => println!("Baseline : {e}"),
        }
        return;
    }
    if args.iter().any(|a| a == "--nettoyer") {
        initialiser_com();
        moniteur::nettoyer();
        return;
    }
    if args.iter().any(|a| a == "--supprimer-donnees") {
        // Désinstallation complète (MSI sans GARDER_DONNEES=1) : alertes, journal, quarantaine, secrets. Plusieurs
        // essais (un fichier peut rester ouvert quelques instants après l'arrêt du service) ; en cas d'échec, compte
        // rendu dans %SystemRoot%\Temp : l'action du MSI ignore le code de retour, l'échec ne doit pas passer inaperçu
        let d = commun::dossier();
        let mut erreur = None;
        for essai in 0..10 {
            match std::fs::remove_dir_all(&d) {
                Ok(()) => { erreur = None; break }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => { erreur = None; break }
                Err(e) => erreur = Some(e),
            }
            if essai < 9 {
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        match erreur {
            None => println!("Données supprimées : {}", d.display()),
            Some(e) => {
                let texte = format!("deR4Tizer : suppression de {} incomplète ({e})", d.display());
                println!("{texte}");
                let _ = std::fs::write(std::path::PathBuf::from(natif::dossier_systeme()).parent().unwrap_or(std::path::Path::new(r"C:\Windows"))
                    .join(r"Temp\deR4Tizer-desinstallation.txt"), &texte);
            }
        }
        return;
    }
    if args.iter().any(|a| a == "--console") {
        let _ = std::fs::create_dir_all(commun::dossier());
        initialiser_com();
        priorite_basse();
        println!("deR4Tizer {} (Rust) en mode console, données : {}. Entrée pour arrêter.", commun::VERSION, commun::dossier().display());
        let (moniteur, partage) = moniteur::Moniteur::demarrer(true);
        canal::servir(moniteur.clone(), partage, true);
        let mut ligne = String::new();
        let _ = std::io::stdin().read_line(&mut ligne);
        moniteur.lock().unwrap().arreter();
        return;
    }
    if service_dispatcher::start(commun::NOM_SERVICE, entree_service).is_err() {
        eprintln!("Ce programme est le service deR4Tizer : lancez-le avec --console pour un test, ou installez-le avec installer.ps1.");
    }
}
