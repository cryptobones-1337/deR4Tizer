//! Phase 1 : autorisation par commande et validation de chaque champ reçu sur le canal de commandes, avant toute
//! exécution. Fonctions pures (testées dans tests.rs) ; le canal identifie le client (canal::client) et refuse une
//! commande non autorisée ou mal formée sans rien exécuter.
//!
//! Le tube n'accepte que SYSTEM et les administrateurs (canal::descripteur) ; cette vérification est une seconde
//! barrière, par commande : un client « autre » (mode console des tests, ou descripteur affaibli) ne peut que
//! demander la version.

use crate::commun::Commande;
use std::net::IpAddr;

/// Identité du client du tube, lue sur son jeton (canal::client)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Client {
    Systeme,
    Administrateur,
    Autre,
}

/// Toutes les actions connues du service (moniteur::executer)
pub const ACTIONS: &[&str] = &[
    "verification", "bloquer", "bloquerIp", "debloquer", "toutDebloquer", "config", "reglages", "testerSyslog",
    "notifications", "testerNotifications", "exception", "apprentissage", "majVerifier", "majConfig", "autoriserLecteur",
    "jetonApi", "nouveauJeton", "majMenaces", "tuer", "suspendre", "reprendre", "tuerChaine", "quarantaine", "restaurer",
    "restaurerRepli", "isolerProgramme", "panique", "baseline", "incident",
];

/// Réglages modifiables par « config »
pub const REGLAGES: &[&str] = &["BlocageAutoMenaces", "ListesRestreintes", "Ips", "ReponseAutoRancongiciel"];

/// Longueurs maximales (caractères) : au-delà, la commande est refusée sans être exécutée
pub const MAX_ACTION: usize = 64;
pub const MAX_IP: usize = 64;
pub const MAX_DOMAINE: usize = 253;
pub const MAX_TYPE: usize = 32;
pub const MAX_CIBLE: usize = 4096;
pub const MAX_RAISON: usize = 512;
pub const MAX_VALEUR: usize = 32768;
pub const MAX_CATEGORIES: usize = 64;

/// Autorisation par commande : action connue, et client SYSTEM ou administrateur ; un client « autre » ne peut que
/// demander la version (« verification »)
pub fn autorisee(action: &str, client: Client) -> bool {
    if !ACTIONS.contains(&action) {
        return false;
    }
    match client {
        Client::Systeme | Client::Administrateur => true,
        Client::Autre => action == "verification",
    }
}

/// Aucun caractère de contrôle (fin de ligne, tabulation, NUL…) : un champ ne doit jamais pouvoir ajouter une ligne
/// au fichier hosts, à un journal ou à une règle
fn sans_controle(s: &str) -> bool {
    !s.chars().any(char::is_control)
}

/// Nom de domaine au sens du fichier hosts : ASCII, étiquettes de 1 à 63 caractères (lettres, chiffres, « - », « _ »),
/// séparées par des points, 253 caractères au plus, point final toléré. Un nom accentué doit arriver en punycode
/// (« xn--… ») : sinon le filtre ASCII du fichier hosts bloquerait un autre nom que celui demandé.
pub fn nom_domaine_valide(d: &str) -> bool {
    let d = d.strip_suffix('.').unwrap_or(d);
    !d.is_empty()
        && d.len() <= MAX_DOMAINE
        && d.split('.').all(|e| {
            !e.is_empty() && e.len() <= 63 && e.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                && !e.starts_with('-') && !e.ends_with('-')
        })
}

/// Chemin absolu local (« X:\… »), sans caractère de contrôle ; jamais un chemin réseau (« \\serveur\… ») ni un
/// chemin d'appareil (« \\?\… », « \\.\… »). Aucun élément que Windows réécrit avant d'ouvrir le fichier : vide,
/// « . », « .. », terminé par un point ou une espace ; aucun « : » après le lecteur (flux de données). Sinon un
/// garde-fou par préfixe, comme le refus du dossier Windows pour isolerProgramme, serait contourné par
/// « C:\x\..\Windows\… », « C:\.\Windows\… », « C:\\Windows\… » ou « C:\Windows.\… ». Les noms courts
/// (« WINDOW~1 ») ne sont pas réécrits ici : la comparaison sur la forme complète du chemin relève de la phase 6.
pub fn chemin_local_absolu(p: &str) -> bool {
    let b = p.as_bytes();
    p.len() <= MAX_CIBLE && b.len() >= 4 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\' && sans_controle(p)
        && !p[2..].contains(':')
        && p[3..].split(['\\', '/']).all(|e| !e.is_empty() && !e.ends_with(['.', ' ']))
}

/// Identifiant d'alerte ou d'élément de quarantaine (commun::nouvel_id, GUID de l'ancien service C#)
pub fn identifiant_valide(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// PID d'un processus ordinaire : jamais 0 (processus inactif) ni 4 (System)
pub fn pid_valide(p: &str) -> bool {
    p.len() <= 10 && p.parse::<u32>().map(|n| n > 4).unwrap_or(false)
}

fn ip_valide(ip: &str) -> bool {
    ip.len() <= MAX_IP && ip.parse::<IpAddr>().is_ok()
}

/// Cible de « baseline » : profils ou identifiants de règles séparés par des virgules (lettres, chiffres, « + »,
/// « _ », « - », « . », espace)
fn selection_baseline(c: &str) -> bool {
    c.chars().count() <= 1024 && c.chars().all(|x| x.is_alphanumeric() || " +_-.,".contains(x))
}

fn requis<'a>(v: &'a Option<String>, quoi: &str) -> Result<&'a str, String> {
    v.as_deref().filter(|s| !s.is_empty()).ok_or_else(|| format!("champ {quoi} manquant"))
}

/// Validation de chaque champ reçu, avant exécution. Erreur : message lisible, rien n'est exécuté.
pub fn valider(c: &Commande) -> Result<(), String> {
    let action = requis(&c.action, "Action")?;
    // Longueurs et caractères, pour tous les champs, quelle que soit l'action
    let bornes: [(&Option<String>, usize, &str); 6] = [
        (&c.action, MAX_ACTION, "Action"), (&c.ip, MAX_IP, "Ip"), (&c.nom_dns, MAX_DOMAINE, "NomDns"),
        (&c.type_, MAX_TYPE, "Type"), (&c.cible, MAX_CIBLE, "Cible"), (&c.raison, MAX_RAISON, "Raison"),
    ];
    for (v, max, quoi) in bornes {
        if let Some(s) = v {
            if s.chars().count() > max {
                return Err(format!("champ {quoi} trop long ({} caractères au plus)", max));
            }
            if !sans_controle(s) {
                return Err(format!("champ {quoi} : caractère de contrôle refusé"));
            }
        }
    }
    if let Some(v) = &c.valeur {
        // Valeur : texte court ou JSON ; tabulations et fins de ligne admises, aucun autre caractère de contrôle
        if v.chars().count() > MAX_VALEUR {
            return Err(format!("champ Valeur trop long ({MAX_VALEUR} caractères au plus)"));
        }
        if v.chars().any(|x| x.is_control() && !matches!(x, '\t' | '\r' | '\n')) {
            return Err("champ Valeur : caractère de contrôle refusé".into());
        }
    }
    if let Some(l) = &c.categories {
        if l.len() > MAX_CATEGORIES || l.iter().any(|x| x.chars().count() > 64 || !sans_controle(x)) {
            return Err("champ Categories invalide".into());
        }
    }
    let json = |quoi: &str, optionnel: bool| -> Result<(), String> {
        match c.valeur.as_deref().map(str::trim) {
            None | Some("") if optionnel => Ok(()),
            Some(v) if v.starts_with('{') && v.ends_with('}') => Ok(()),
            _ => Err(format!("champ Valeur : objet JSON attendu ({quoi})")),
        }
    };
    match action {
        "verification" | "toutDebloquer" | "majVerifier" | "jetonApi" | "nouveauJeton" | "majMenaces" => Ok(()),
        "bloquer" => {
            let nom = c.nom_dns.as_deref().filter(|n| !n.is_empty());
            let ip = c.ip.as_deref().filter(|n| !n.is_empty());
            if nom.is_none() && ip.is_none() {
                return Err("champ NomDns ou Ip manquant".into());
            }
            if nom.is_some_and(|n| !nom_domaine_valide(n)) {
                return Err("nom de domaine invalide".into());
            }
            if ip.is_some_and(|i| !ip_valide(i)) {
                return Err("adresse IP invalide".into());
            }
            Ok(())
        }
        "bloquerIp" => ip_valide(requis(&c.ip, "Ip")?).then_some(()).ok_or_else(|| "adresse IP invalide".into()),
        "debloquer" => {
            let cible = requis(&c.cible, "Cible")?;
            let bon = match requis(&c.type_, "Type")? {
                "hosts" => nom_domaine_valide(cible),
                "parefeu" => ip_valide(cible),
                "programme" => chemin_local_absolu(cible),
                _ => return Err("type de blocage inconnu".into()),
            };
            bon.then_some(()).ok_or_else(|| "cible du déblocage invalide".into())
        }
        "config" => {
            if !REGLAGES.contains(&requis(&c.cible, "Cible")?) {
                return Err("réglage inconnu".into());
            }
            matches!(c.valeur.as_deref(), Some("true" | "false")).then_some(()).ok_or_else(|| "valeur attendue : true ou false".into())
        }
        "reglages" => json("réglages", false),
        "testerSyslog" => json("syslog", true),
        "notifications" | "testerNotifications" => json("notifications", false),
        "majConfig" => json("mise à jour", false),
        "exception" | "restaurer" | "restaurerRepli" => {
            identifiant_valide(requis(&c.cible, "Cible")?).then_some(()).ok_or_else(|| "identifiant invalide".into())
        }
        "apprentissage" => matches!(c.valeur.as_deref(), Some("terminer" | "recommencer" | "oublier"))
            .then_some(()).ok_or_else(|| "commande d'apprentissage inconnue".into()),
        "autoriserLecteur" => {
            let s = requis(&c.valeur, "Valeur")?;
            (s.starts_with("S-1-") && s.len() < 80 && s[2..].bytes().all(|b| b.is_ascii_digit() || b == b'-'))
                .then_some(()).ok_or_else(|| "identifiant de compte invalide".into())
        }
        "tuer" | "suspendre" | "reprendre" | "tuerChaine" => {
            pid_valide(requis(&c.cible, "Cible")?).then_some(()).ok_or_else(|| "PID invalide".into())
        }
        "quarantaine" | "isolerProgramme" => {
            chemin_local_absolu(requis(&c.cible, "Cible")?).then_some(()).ok_or_else(|| "chemin local absolu attendu".into())
        }
        "panique" => matches!(c.valeur.as_deref(), None | Some("" | "on" | "off"))
            .then_some(()).ok_or_else(|| "valeur attendue : on ou off".into()),
        // Transition d'un incident suivi (phase 4, PR 4.2) : Cible = identifiant, Valeur = état visé, Type = motif de
        // clôture, Raison = note (300 caractères au plus ; caractères de contrôle déjà ôtés par `normaliser`)
        "incident" => {
            identifiant_valide(requis(&c.cible, "Cible")?).then_some(()).ok_or("identifiant invalide")?;
            crate::incidents::etat_de(requis(&c.valeur, "Valeur")?).ok_or("état attendu : Ouvert, PrisEnCharge ou Clos")?;
            matches!(c.type_.as_deref(), None | Some("" | "Resolu" | "FauxPositif" | "Accepte")).then_some(())
                .ok_or("motif attendu : Resolu, FauxPositif ou Accepte")?;
            (c.raison.as_deref().unwrap_or("").chars().count() <= crate::incidents::MAX_NOTE).then_some(())
                .ok_or_else(|| format!("note de {} caractères au plus", crate::incidents::MAX_NOTE))
        }
        "baseline" => {
            if !matches!(c.valeur.as_deref(), Some("appliquer" | "annuler" | "evaluer")) {
                return Err("opération de baseline inconnue".into());
            }
            selection_baseline(c.cible.as_deref().unwrap_or("")).then_some(()).ok_or_else(|| "sélection de baseline invalide".into())
        }
        autre => Err(format!("commande inconnue : {autre}")),
    }
}

/// Champs normalisés avant validation : la raison, faite de noms de processus ou de domaines vus sur le poste,
/// n'est jamais une cause de refus (un programme nommé avec une fin de ligne ne doit pas empêcher qu'on le bloque) :
/// caractères de contrôle remplacés par une espace, longueur ramenée à MAX_RAISON
pub fn normaliser(c: &mut Commande) {
    if let Some(r) = c.raison.as_mut() {
        *r = r.chars().map(|x| if x.is_control() { ' ' } else { x }).take(MAX_RAISON).collect();
    }
}

/// Commande lue sur le canal : première ligne, sans BOM, en JSON ; jamais de panique sur une entrée tronquée ou
/// quelconque (texte non UTF-8 remplacé)
pub fn decoder_commande(octets: &[u8]) -> Result<Commande, String> {
    let texte = String::from_utf8_lossy(octets);
    let ligne = texte.trim_start_matches('\u{feff}').lines().next().unwrap_or("");
    if ligne.trim().is_empty() {
        return Err("commande vide".into());
    }
    serde_json::from_str::<Commande>(ligne).map_err(|e| format!("commande illisible : {e}"))
}

/// Limite de débit du canal : au plus `max` commandes par `fenetre` glissante ; au-delà, refus sans exécution
pub struct Debit {
    max: usize,
    fenetre: std::time::Duration,
    instants: std::collections::VecDeque<std::time::Instant>,
}

impl Debit {
    pub fn new(max: usize, fenetre: std::time::Duration) -> Self {
        Debit { max, fenetre, instants: std::collections::VecDeque::new() }
    }

    pub fn accepter(&mut self, maintenant: std::time::Instant) -> bool {
        while self.instants.front().is_some_and(|t| maintenant.saturating_duration_since(*t) >= self.fenetre) {
            self.instants.pop_front();
        }
        if self.instants.len() >= self.max {
            return false;
        }
        self.instants.push_back(maintenant);
        true
    }
}
