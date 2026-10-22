//! deR4TizerSvc.exe : service Windows (compte SYSTEM) qui surveille les connexions sortantes,
//! la persistance, la caméra et le micro, lève des alertes et applique les blocages demandés par l'interface.
//!   deR4TizerSvc.exe              lancé par le gestionnaire de services
//!   deR4TizerSvc.exe --console    même surveillance dans une console (débogage)
//!   deR4TizerSvc.exe --nettoyer   retire tous les blocages (utilisé par la désinstallation)
//!   --dossier <chemin>            dossier de données (par défaut C:\ProgramData\deR4Tizer)

mod baseline;
mod blocage;
mod canal;
mod chaines;
mod api;
mod commun;
mod defender;
mod evenements;
mod export;
mod gpo;
mod hygiene;
mod mitre;
mod menaces;
mod moniteur;
mod natif;
mod parefeu;
mod persistance;
mod processus;
mod reponse;
mod surveillances;
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

    initialiser_com();
    priorite_basse();
    let (moniteur, partage) = moniteur::Moniteur::demarrer(false);
    canal::servir(moniteur.clone(), partage, false);
    let _ = etat.set_service_status(statut(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN));

    let _ = arret_rx.recv();
    let _ = etat.set_service_status(statut(ServiceState::StopPending, ServiceControlAccept::empty()));
    moniteur.lock().unwrap().arreter();
    let _ = etat.set_service_status(statut(ServiceState::Stopped, ServiceControlAccept::empty()));
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--dossier") {
        if let Some(d) = args.get(i + 1) {
            commun::definir_dossier(d.into());
        }
    }
    let _ = std::fs::create_dir_all(commun::dossier());

    // Outils de diagnostic (sans rien modifier)
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
            x.write_all(b"2026-10-22 07:00:01 ALLOW TCP 203.0.113.7 192.168.1.50 51515 3389 0 - - - - - - - RECEIVE 1234\r\n\
2026-10-22 07:00:02 DROP TCP 198.51.100.9 192.168.1.50 40000 445 0 - - - - - - - RECEIVE 0\r\n\
2026-10-22 07:00:03 ALLOW UDP 192.168.1.254 192.168.1.50 53 5353 0 - - - - - - - RECEIVE 0\r\n\
2026-10-22 07:00:04 ALLOW TCP 192.168.1.50 8.8.8.8 50000 443 0 - - - - - - - SEND 999\r\n")
        });
        for a in lecteur.lire(&|pid| format!("prog{pid}")) {
            println!("[{}] {} : {}", a.niveau, a.processus, a.raisons);
        }
        let b = lecteur.bilan(&[]);
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
    if args.iter().any(|a| a == "--console") {
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
