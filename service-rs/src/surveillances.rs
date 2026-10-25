//! Vie privée et accès à distance : caméra et micro (journal d'accès de Windows), outils de prise
//! en main à distance, Bureau à distance, ports ouverts sur le réseau et connexions entrantes.

use crate::commun::{self, Alerte, Ecoute, OutilDistant, UsagePeripherique};
use crate::moniteur::est_locale;
use crate::natif::{self, Connexion, InfoListe};
use crate::persistance::sids_utilisateurs;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use winreg::enums::*;
use winreg::RegKey;

const CONSENTEMENT: &str = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore";

/// Nom de processus (sans .exe, en minuscules) -> outil
const OUTILS: &[(&str, &str)] = &[
    ("anydesk", "AnyDesk"), ("teamviewer", "TeamViewer"), ("teamviewer_service", "TeamViewer"), ("tv_w32", "TeamViewer"),
    ("rustdesk", "RustDesk"), ("screenconnect.clientservice", "ScreenConnect"), ("screenconnect.windowsclient", "ScreenConnect"),
    ("connectwisecontrol.client", "ConnectWise Control"), ("srservice", "Splashtop"), ("strwinclt", "Splashtop"),
    ("logmein", "LogMeIn"), ("lmiguardiansvc", "LogMeIn"), ("ultraviewer_service", "UltraViewer"), ("ultraviewer_desktop", "UltraViewer"),
    ("ateraagent", "Atera"), ("ninjarmmagent", "NinjaOne"), ("tvnserver", "TightVNC"), ("winvnc", "VNC"), ("vncserver", "VNC"),
    ("uvnc_service", "UltraVNC"), ("rserver3", "Radmin"), ("dwagent", "DWService"), ("dwagsvc", "DWService"),
    ("supremo", "Supremo"), ("supremoservice", "Supremo"), ("ngrok", "ngrok (tunnel)"), ("remoting_host", "Chrome Remote Desktop"),
    ("client32", "NetSupport"), ("meshagent", "MeshCentral"), ("tacticalrmm", "Tactical RMM"), ("quickassist", "Assistance rapide Windows"),
    ("remotepcservice", "RemotePC"), ("zaservice", "Zoho Assist"), ("parsecd", "Parsec"), ("action1_agent", "Action1"),
    ("simplehelp", "SimpleHelp"), ("level", "Level RMM"), ("gotoassist", "GoTo Assist"), ("bomgar-scc", "BeyondTrust"),
];

pub struct Surveillances {
    peripheriques_connus: HashSet<String>,
    apprentissage_peripheriques: bool,
    en_cours_avant: HashSet<String>,
    outils_vus: HashMap<u32, String>,
    ecoutes_connues: HashMap<String, String>,
    apprentissage_ecoutes: bool,
    rdp_avant: Option<bool>,
    pub usages: Vec<UsagePeripherique>,
    pub outils: Vec<OutilDistant>,
    pub ecoutes: Vec<Ecoute>,
    pub rdp: bool,
}

fn alerte(regle: &str, niveau: &str, score: i32, processus: &str, chemin: &str, destination: &str, raisons: String) -> Alerte {
    Alerte {
        regle: regle.into(),
        id: commun::nouvel_id(),
        heure: commun::maintenant(),
        niveau: niveau.into(),
        score,
        processus: processus.into(),
        chemin: chemin.into(),
        destination: destination.into(),
        raisons,
        ..Default::default()
    }
}

fn nom_fichier(chemin: &str) -> String {
    Path::new(chemin).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default()
}

impl Surveillances {
    pub fn nouvelles() -> Surveillances {
        let p: Option<Vec<String>> = commun::lire("peripheriques-connus.json");
        let e = commun::lire_carte("ecoutes-connues.json");
        Surveillances {
            apprentissage_peripheriques: p.is_none(),
            peripheriques_connus: p.unwrap_or_default().into_iter().map(|s| s.to_lowercase()).collect(),
            en_cours_avant: HashSet::new(),
            outils_vus: HashMap::new(),
            apprentissage_ecoutes: e.is_none(),
            ecoutes_connues: e.unwrap_or_default(),
            rdp_avant: None,
            usages: Vec::new(),
            outils: Vec::new(),
            ecoutes: Vec::new(),
            rdp: false,
        }
    }

    pub fn verifier(&mut self, tcp: &[Connexion], liste: &HashMap<u32, InfoListe>, signataire: &mut dyn FnMut(&str) -> String) -> Vec<Alerte> {
        let mut alertes = Vec::new();
        self.camera(&mut alertes);
        self.outils_distants(liste, signataire, &mut alertes);
        self.bureau_a_distance(&mut alertes);
        self.ports_ouverts(tcp, signataire, &mut alertes);
        alertes
    }

    // ------------------------------------------------------------ caméra et micro

    fn camera(&mut self, alertes: &mut Vec<Alerte>) {
        let mut usages = Vec::new();
        lire_consentement(&RegKey::predef(HKEY_LOCAL_MACHINE), CONSENTEMENT, &mut usages);
        let hku = RegKey::predef(HKEY_USERS);
        for sid in sids_utilisateurs() {
            lire_consentement(&hku, &format!(r"{sid}\{CONSENTEMENT}"), &mut usages);
        }
        let mut modifies = false;
        let mut en_cours = HashSet::new();
        for u in &usages {
            let cle = format!("{}|{}", u.peripherique, u.chemin).to_lowercase();
            if u.en_cours {
                en_cours.insert(cle.clone());
                if !self.en_cours_avant.contains(&cle) && !self.peripheriques_connus.contains(&cle) && !self.apprentissage_peripheriques {
                    let quoi = if u.peripherique == "Caméra" { "la caméra" } else { "le micro" };
                    alertes.push(alerte(crate::regles::VIE_001, "Alerte", 3, &u.programme, &u.chemin, &u.peripherique,
                        format!("{} utilise {quoi} pour la première fois", u.programme)));
                }
            }
            if self.peripheriques_connus.insert(cle) {
                modifies = true;
            }
        }
        self.en_cours_avant = en_cours;
        if modifies {
            let _ = commun::ecrire("peripheriques-connus.json", &self.peripheriques_connus.iter().collect::<Vec<_>>());
        }
        self.apprentissage_peripheriques = false;
        usages.sort_by(|a, b| b.en_cours.cmp(&a.en_cours).then(b.dernier_debut.cmp(&a.dernier_debut)));
        // Affichage : 30 derniers jours et chemins de profil masqués (poste partagé, données personnelles)
        let limite = commun::heure(std::time::SystemTime::now() - std::time::Duration::from_secs(30 * 86_400));
        self.usages = usages.into_iter()
            .filter(|u| u.en_cours || u.dernier_debut >= limite)
            .map(|mut u| {
                u.chemin = commun::masquer_chemin(&u.chemin);
                u
            })
            .collect();
    }

    // ------------------------------------------------------------ prise en main à distance

    fn outils_distants(&mut self, liste: &HashMap<u32, InfoListe>, signataire: &mut dyn FnMut(&str) -> String, alertes: &mut Vec<Alerte>) {
        let mut actuels = Vec::new();
        let mut pids = HashSet::new();
        for (&pid, p) in liste {
            let nom = p.nom.to_lowercase();
            let Some(&(_, outil)) = OUTILS.iter().find(|(n, _)| *n == nom) else { continue };
            pids.insert(pid);
            let chemin = natif::chemin_processus(pid);
            let depuis = self.outils_vus.entry(pid).or_insert_with(|| {
                alertes.push(alerte(crate::regles::VIE_002, "Alerte", 3, &p.nom, &chemin, outil,
                    format!("outil de prise en main à distance en cours d'exécution ({outil})")));
                commun::maintenant()
            }).clone();
            actuels.push(OutilDistant {
                nom: outil.into(),
                pid,
                signataire: if chemin.is_empty() { "?".into() } else { signataire(&chemin) },
                chemin,
                depuis,
            });
        }
        self.outils_vus.retain(|pid, _| pids.contains(pid));
        self.outils = actuels;
    }

    fn bureau_a_distance(&mut self, alertes: &mut Vec<Alerte>) {
        self.rdp = RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey(r"SYSTEM\CurrentControlSet\Control\Terminal Server")
            .and_then(|k| k.get_value::<u32, _>("fDenyTSConnections"))
            .map(|v| v == 0)
            .unwrap_or(false);
        if self.rdp && self.rdp_avant == Some(false) {
            alertes.push(alerte(crate::regles::VIE_003, "Alerte", 3, "Windows", "", "Bureau à distance", "le Bureau à distance vient d'être ACTIVÉ".into()));
        }
        self.rdp_avant = Some(self.rdp);
    }

    // ------------------------------------------------------------ ports ouverts et connexions entrantes

    fn ports_ouverts(&mut self, tcp: &[Connexion], signataire: &mut dyn FnMut(&str) -> String, alertes: &mut Vec<Alerte>) {
        let mut ecoutes: Vec<Ecoute> = Vec::new();
        let mut modifiees = false;
        let mut ports_ecoute = HashSet::new();
        for c in tcp.iter().filter(|c| c.etat == 2 && !c.ip_locale.starts_with("127.") && c.ip_locale != "::1") {
            ports_ecoute.insert((c.pid, c.port_local));
            let chemin = natif::chemin_processus(c.pid);
            let sig = if chemin.is_empty() { "?".to_string() } else { signataire(&chemin) };
            let systeme = sig == "Windows (catalogue)" || sig.starts_with("Microsoft");
            if systeme && c.port_local >= 49152 {
                continue; // ports RPC dynamiques de Windows, changent à chaque démarrage
            }
            let cle = format!("{}|{}", if chemin.is_empty() { format!("PID {}", c.pid) } else { chemin.clone() }, c.port_local);
            let depuis = match self.ecoutes_connues.get(&cle) {
                Some(d) => d.clone(),
                None => {
                    let d = commun::maintenant();
                    self.ecoutes_connues.insert(cle, d.clone());
                    modifiees = true;
                    if !self.apprentissage_ecoutes {
                        let non_signe = sig.is_empty();
                        alertes.push(alerte(crate::regles::RES_006, if non_signe { "Alerte" } else { "Info" }, if non_signe { 3 } else { 0 }, &nom_fichier(&chemin), &chemin,
                            &format!("port {}", c.port_local),
                            format!("nouveau port ouvert en écoute sur le réseau ({}:{}){}", c.ip_locale, c.port_local,
                                if non_signe { ", programme NON SIGNÉ" } else { "" })));
                    }
                    d
                }
            };
            if ecoutes.iter().any(|e| e.pid == c.pid && e.port == c.port_local) {
                continue;
            }
            let programme = if !chemin.is_empty() { nom_fichier(&chemin) } else if c.pid == 4 { "System (partage de fichiers)".into() } else { format!("PID {}", c.pid) };
            ecoutes.push(Ecoute {
                programme,
                chemin,
                pid: c.pid,
                adresse: c.ip_locale.clone(),
                port: c.port_local,
                signataire: if sig.is_empty() { "-".into() } else { sig },
                depuis,
            });
        }
        if modifiees {
            let _ = commun::ecrire("ecoutes-connues.json", &self.ecoutes_connues);
        }
        self.apprentissage_ecoutes = false;
        ecoutes.sort_by_key(|e| e.port);
        self.ecoutes = ecoutes;

        // Connexion établie sur un port en écoute, depuis une adresse d'Internet : quelqu'un se connecte à ce PC
        for c in tcp.iter().filter(|c| c.etat == 5 && ports_ecoute.contains(&(c.pid, c.port_local)) && !est_locale(&c.ip)) {
            let Ok(ip) = c.ip.parse::<std::net::IpAddr>() else { continue };
            if !crate::parefeu::publique(&ip) {
                continue;
            }
            let chemin = natif::chemin_processus(c.pid);
            let non_signe = !chemin.is_empty() && signataire(&chemin).is_empty();
            let mut a = alerte(crate::regles::RES_007, if non_signe { "Critique" } else { "Alerte" }, if non_signe { 8 } else { 5 }, &nom_fichier(&chemin), &chemin, &c.ip,
                format!("CONNEXION ENTRANTE depuis Internet ({} vers le port local {}) : PC EXPOSÉ À INTERNET{}", c.ip, c.port_local,
                    if non_signe { ", programme NON SIGNÉ" } else { "" }));
            a.pid = Some(c.pid);
            a.ip = Some(c.ip.clone());
            a.port = c.port_local;
            alertes.push(a);
        }
    }
}

fn lire_consentement(racine: &RegKey, chemin: &str, usages: &mut Vec<UsagePeripherique>) {
    for (cle, peripherique) in [("webcam", "Caméra"), ("microphone", "Micro")] {
        let Ok(k) = racine.open_subkey(format!(r"{chemin}\{cle}")) else { continue };
        for app in k.enum_keys().map_while(Result::ok) {
            if app == "NonPackaged" {
                let Ok(np) = k.open_subkey(&app) else { continue };
                for exe in np.enum_keys().map_while(Result::ok) {
                    if let Ok(e) = np.open_subkey(&exe) {
                        ajouter(usages, peripherique, &exe.replace('#', "\\"), &e);
                    }
                }
            } else if let Ok(e) = k.open_subkey(&app) {
                ajouter(usages, peripherique, &app, &e);
            }
        }
    }
}

fn ajouter(usages: &mut Vec<UsagePeripherique>, peripherique: &str, chemin: &str, k: &RegKey) {
    let debut = k.get_value::<u64, _>("LastUsedTimeStart").unwrap_or(0);
    let fin = k.get_value::<u64, _>("LastUsedTimeStop").unwrap_or(0);
    if debut == 0 {
        return;
    }
    usages.push(UsagePeripherique {
        peripherique: peripherique.into(),
        chemin: chemin.into(),
        programme: if chemin.contains('\\') { nom_fichier(chemin) } else { chemin.split('_').next().unwrap_or(chemin).to_string() },
        dernier_debut: commun::heure_filetime(debut),
        derniere_fin: if fin > 0 { commun::heure_filetime(fin) } else { String::new() },
        en_cours: fin == 0,
    });
}
