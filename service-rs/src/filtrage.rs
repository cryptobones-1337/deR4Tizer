//! Moteur de filtrage par nom de domaine (phase 7, PR 7.2) : sources compilées, téléchargement, formats acceptés,
//! recherche par domaine et parents, liste de protection, autorisations de l'utilisateur. **Aucun effet réseau** : rien
//! ne consulte encore ces listes pour répondre à une requête (le résolveur local arrive en 7.3, son activation en 7.4).
//!
//! - Sources compilées dans le binaire (règle 6 : aucune source ajoutée par un fichier du dossier de données).
//!   Décisions D7-2 et D7-3 du dossier, tranchées sur sa recommandation (journal des décisions) : aucune liste de
//!   sécurité (licences non commerciales ou inconnues) ; EasyPrivacy et EasyList pour « publicités et pistage », règles
//!   de domaine seules.
//! - Rien n'est téléchargé tant qu'aucune catégorie n'est active (`Config.filtrage.categories`, vide par défaut).
//! - Formats : hosts (`0.0.0.0 domaine`), domaine seul, et le sous-ensemble adblock `||domaine^` / `@@||domaine^`.
//!   Toute autre règle (chemin, options `$…`, expressions régulières, règles cosmétiques) est écartée et comptée.
//! - Empreintes FNV-1a 64 bits triées, comme `menaces.rs`. Collision : faux blocage possible mais improbable, levé par
//!   une autorisation de l'utilisateur.
//! - Ordre de décision (`Filtrage::decider`, pur) : nom invalide → relayé ; liste de protection → jamais bloqué ;
//!   autorisation de l'utilisateur → jamais bloqué ; exception `@@` d'une liste → lève les blocages de sa catégorie
//!   seulement ; liste de sécurité → bloqué ; liste de publicité → bloqué ; sinon relayé.

use crate::commun;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Catégorie d'une liste ; chaque catégorie s'active à part (le risque de casser un site n'est pas le même)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Categorie {
    Securite,
    Publicite,
}

impl Categorie {
    pub fn nom(self) -> &'static str {
        match self {
            Categorie::Securite => "securite",
            Categorie::Publicite => "publicite",
        }
    }
    pub fn libelle(self) -> &'static str {
        match self {
            Categorie::Securite => "sécurité",
            Categorie::Publicite => "publicité et pistage",
        }
    }
    pub fn de_nom(n: &str) -> Option<Categorie> {
        [Categorie::Securite, Categorie::Publicite].into_iter().find(|c| c.nom() == n)
    }
}

pub struct Source {
    pub nom: &'static str,
    pub categorie: Categorie,
    pub url: &'static str,
    /// Conditions, d'après la page du projet (lecture technique, pas un avis juridique) ; affichées avec l'attribution
    /// par l'interface (PR 7.5)
    #[allow(dead_code)]
    pub licence: &'static str,
}

/// Sources compilées. Le poste télécharge chaque liste chez sa source : deR4Tizer ne redistribue rien
pub const SOURCES: &[Source] = &[
    Source { nom: "EasyPrivacy", categorie: Categorie::Publicite, url: "https://easylist.to/easylist/easyprivacy.txt",
        licence: "GPLv3 ou CC BY-SA 3.0, au choix ; « The EasyList authors »" },
    Source { nom: "EasyList", categorie: Categorie::Publicite, url: "https://easylist.to/easylist/easylist.txt",
        licence: "GPLv3 ou CC BY-SA 3.0, au choix ; « The EasyList authors »" },
];

/// Total des entrées chargées, toutes listes confondues (8 Mo en mémoire)
pub const MAX_ENTREES: usize = 1_000_000;
/// Autorisations de l'utilisateur, au plus
pub const MAX_AUTORISES: usize = 1000;
/// Recherches par requête, au plus (le nom lui-même et ses parents les plus courts)
pub const MAX_RECHERCHES: usize = 10;
/// Taille d'une liste téléchargée, au plus
const MAX_OCTETS: u64 = 32 * 1024 * 1024;

/// Liste de protection compilée : jamais bloquée, quelle que soit la liste, et ses sous-domaines non plus. Établie
/// d'après la documentation de Microsoft (points de terminaison de Windows Update, de Defender, du test de
/// connectivité, de l'heure et de l'activation) et des autorités de signature courantes ; à compléter par les journaux
/// d'une VM quand le résolveur local existera (PR 7.3), et à relire
pub const PROTECTION: &[&str] = &[
    // Windows Update et Delivery Optimization
    "windowsupdate.com", "update.microsoft.com", "windowsupdate.microsoft.com", "delivery.mp.microsoft.com",
    "dl.delivery.mp.microsoft.com", "download.windowsupdate.com", "download.microsoft.com", "do.dsp.mp.microsoft.com",
    // Activation et licences
    "activation.sls.microsoft.com", "validation.sls.microsoft.com", "licensing.mp.microsoft.com",
    // Defender et SmartScreen
    "wdcp.microsoft.com", "wdcpalt.microsoft.com", "wd.microsoft.com", "definitionupdates.microsoft.com",
    "smartscreen.microsoft.com", "smartscreen-prod.microsoft.com", "urs.microsoft.com", "unitedstates.smartscreen-prod.microsoft.com",
    "europe.smartscreen-prod.microsoft.com",
    // Test de connectivité de Windows (portails captifs) et heure
    "msftconnecttest.com", "msftncsi.com", "time.windows.com",
    // Révocation et OCSP des autorités de signature (vérification des mises à jour)
    "crl.microsoft.com", "mscrl.microsoft.com", "ocsp.msocsp.com", "oneocsp.microsoft.com", "ctldl.windowsupdate.com",
    "ocsp.digicert.com", "crl3.digicert.com", "crl4.digicert.com", "cacerts.digicert.com", "ocsp.sectigo.com",
    "crl.sectigo.com", "ocsp.comodoca.com", "crl.comodoca.com", "ocsp.globalsign.com", "crl.globalsign.com",
    "crl.certum.pl", "ocsp.certum.pl", "subca.ocsp-certum.com", "repository.certum.pl", "r3.o.lencr.org", "x1.c.lencr.org",
    // Serveur de mise à jour de deR4Tizer (versions publiées sur GitHub)
    "github.com", "api.github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com",
];

/// FNV-1a 64 bits sur les caractères UTF-16, comme `menaces::empreinte` (le même nom donne la même empreinte)
fn empreinte(s: &str) -> u64 {
    let mut h: u64 = 14695981039346656037;
    for c in s.encode_utf16() {
        h ^= c as u64;
        h = h.wrapping_mul(1099511628211);
    }
    h
}

/// Première étiquette des suffixes publics de deux étiquettes (`co.uk`, `gouv.fr`, `com.br`…). Une règle qui viserait
/// un tel suffixe bloquerait, par la recherche des parents, tout un pays ou tous les sites publics : jamais un domaine
/// (audit de #160, S160-01, l'équivalent pour les noms de la couverture aberrante des listes d'adresses)
const SUFFIXES_PUBLICS: &[&str] = &[
    "co", "com", "net", "org", "gov", "gouv", "ac", "edu", "mil", "asso", "ltd", "plc", "sch", "nhs", "gob",
];

/// Suffixe public de deux étiquettes (pur, testé)
pub fn suffixe_public(nom: &str) -> bool {
    match nom.split_once('.') {
        Some((premiere, reste)) => !reste.contains('.') && SUFFIXES_PUBLICS.contains(&premiere),
        None => true,
    }
}

/// Nom normalisé : minuscules ASCII, sans point final, au moins deux étiquettes, valide au sens du fichier hosts, et
/// jamais une adresse IP, un nom de `.arpa` ni un suffixe public de deux étiquettes. Un nom internationalisé est attendu
/// déjà en `xn--`
pub fn normaliser(nom: &str) -> Option<String> {
    let n = nom.trim();
    let n = n.strip_suffix('.').unwrap_or(n);
    if !n.is_ascii() {
        return None;
    }
    let n = n.to_ascii_lowercase();
    if !n.contains('.') || n.parse::<std::net::IpAddr>().is_ok() || n.ends_with(".arpa") || suffixe_public(&n)
        || !crate::validation::nom_domaine_valide(&n) {
        return None;
    }
    Some(n)
}

/// Le nom et ses parents, jamais le domaine de premier niveau seul : `a.b.ex.fr` → `a.b.ex.fr`, `b.ex.fr`, `ex.fr`.
/// Au plus `MAX_RECHERCHES` : le nom lui-même, puis les parents **les plus courts** ; un nom allongé d'étiquettes ne
/// peut donc pas échapper au blocage de son domaine
pub fn noms_a_chercher(nom: &str) -> Vec<&str> {
    let mut suffixes: Vec<&str> = Vec::new();
    let mut reste = nom;
    while let Some((_, apres)) = reste.split_once('.') {
        if apres.contains('.') {
            suffixes.push(apres);
        }
        reste = apres;
    }
    // suffixes : du plus long au plus court ; on garde les plus courts
    let garder = suffixes.len().min(MAX_RECHERCHES - 1);
    let mut l = vec![nom];
    l.extend_from_slice(&suffixes[suffixes.len() - garder..]);
    l
}

/// Ce que donne une ligne de liste
#[derive(Debug, PartialEq, Eq)]
pub enum Ligne {
    /// Commentaire, en-tête ou ligne vide : ni compté ni écarté
    Ignoree,
    Bloque(String),
    /// `@@||domaine^` : exception de la liste
    Exception(String),
    /// Règle hors du sous-ensemble accepté (chemin, options, expression régulière, cosmétique, nom invalide)
    Ecartee,
}

/// Lecture d'une ligne (pure, testée, torturée)
pub fn analyser_ligne(ligne: &str) -> Ligne {
    let l = ligne.trim();
    // Règle cosmétique (« ##.pub », « #@#… », « #?#… ») : écartée, avant les commentaires du format hosts
    if l.starts_with("##") || l.starts_with("#@#") || l.starts_with("#?#") || l.starts_with("#$#") {
        return Ligne::Ecartee;
    }
    if l.is_empty() || l.starts_with(['!', '#', '[']) {
        return Ligne::Ignoree;
    }
    let domaine = |d: &str| normaliser(d);
    if let Some(r) = l.strip_prefix("@@||") {
        return match r.strip_suffix('^').and_then(domaine) {
            Some(d) => Ligne::Exception(d),
            None => Ligne::Ecartee,
        };
    }
    if let Some(r) = l.strip_prefix("||") {
        return match r.strip_suffix('^').and_then(domaine) {
            Some(d) => Ligne::Bloque(d),
            None => Ligne::Ecartee,
        };
    }
    // Toute autre syntaxe adblock (chemin, options, cosmétique, expression régulière) est écartée
    if l.contains(['/', '$', '*', '^', '|', '@', '?', '=', '&']) || l.contains("##") || l.contains("#@#") {
        return Ligne::Ecartee;
    }
    // hosts : « adresse nom [# commentaire] » ; domaine seul : « nom »
    let sans_commentaire = l.split('#').next().unwrap_or("");
    let jetons: Vec<&str> = sans_commentaire.split_whitespace().collect();
    let nom = match jetons.as_slice() {
        [n] => *n,
        [ip, n] if ip.parse::<std::net::IpAddr>().is_ok() => *n,
        _ => return Ligne::Ecartee,
    };
    match domaine(nom) {
        Some(d) => Ligne::Bloque(d),
        // « 0.0.0.0 localhost », « 0.0.0.0 0.0.0.0 » : écartés
        None => Ligne::Ecartee,
    }
}

/// Bilan de lecture d'une liste
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Compte {
    pub entrees: usize,
    pub exceptions: usize,
    pub ecartees: usize,
    /// Domaines de la liste de protection présents dans la liste : ignorés (la liste n'est pas refusée pour autant)
    pub proteges_ignores: usize,
}

/// Liste lue, prête à être chargée
pub struct ListeLue {
    pub bloques: Vec<u64>,
    pub exceptions: Vec<u64>,
    pub compte: Compte,
}

/// Lecture d'un texte de liste (pure, testée) ; `protection` : empreintes triées des noms jamais bloqués
pub fn lire_liste(texte: &str, protection: &[u64]) -> ListeLue {
    let mut bloques = Vec::new();
    let mut exceptions = Vec::new();
    let mut compte = Compte::default();
    for l in texte.lines() {
        match analyser_ligne(l) {
            Ligne::Ignoree => {}
            Ligne::Ecartee => compte.ecartees += 1,
            Ligne::Bloque(d) => {
                if noms_a_chercher(&d).iter().any(|n| protection.binary_search(&empreinte(n)).is_ok()) {
                    compte.proteges_ignores += 1;
                } else {
                    bloques.push(empreinte(&d));
                }
            }
            Ligne::Exception(d) => exceptions.push(empreinte(&d)),
        }
    }
    bloques.sort_unstable();
    bloques.dedup();
    exceptions.sort_unstable();
    exceptions.dedup();
    compte.entrees = bloques.len();
    compte.exceptions = exceptions.len();
    ListeLue { bloques, exceptions, compte }
}

/// Garde-fou du remplacement (pur, testé) : une nouvelle copie vide, qui s'effondre (moins de la moitié de la
/// précédente) ou qui explose (plus du double) est refusée, et la copie précédente est gardée
pub fn remplacement_admis(ancienne: usize, nouvelle: usize) -> bool {
    nouvelle > 0 && (ancienne == 0 || (nouvelle.saturating_mul(2) >= ancienne && nouvelle <= ancienne.saturating_mul(2)))
}

/// Verdict pour un nom demandé
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Transmis au résolveur d'amont (nom invalide, ou rien ne le bloque)
    Relaye,
    /// Liste de protection
    Protege,
    /// Autorisé par l'utilisateur, ou par une exception `@@` de la liste qui l'aurait bloqué
    Autorise,
    Bloque { categorie: Categorie, liste: String },
}

struct ListeChargee {
    nom: String,
    categorie: Categorie,
    bloques: Vec<u64>,
    exceptions: Vec<u64>,
}

/// Listes chargées, protection et autorisations
#[derive(Default)]
pub struct Filtrage {
    listes: Vec<ListeChargee>,
    protection: Vec<u64>,
    autorises: Vec<u64>,
    /// Bilan par liste, pour le journal et (plus tard) l'interface
    pub bilan: Vec<(String, Categorie, Compte)>,
}

/// Empreintes triées d'une liste de noms (invalides écartés)
fn empreintes<'a>(noms: impl Iterator<Item = &'a str>) -> Vec<u64> {
    let mut v: Vec<u64> = noms.filter_map(normaliser).map(|n| empreinte(&n)).collect();
    v.sort_unstable();
    v.dedup();
    v
}

impl Filtrage {
    /// Filtrage sans liste : protection compilée, plus les hôtes à épargner donnés (remontée configurée, mise à jour)
    pub fn nouveau(hotes_proteges: &[String]) -> Filtrage {
        Filtrage { protection: empreintes(PROTECTION.iter().copied().chain(hotes_proteges.iter().map(String::as_str))), ..Default::default() }
    }

    pub fn protection(&self) -> &[u64] {
        &self.protection
    }

    /// Ajoute une liste lue ; refusée si le total dépassait `MAX_ENTREES` (rien n'est tronqué)
    pub fn ajouter(&mut self, nom: &str, categorie: Categorie, l: ListeLue) -> bool {
        if self.total() + l.bloques.len() + l.exceptions.len() > MAX_ENTREES {
            return false;
        }
        self.bilan.push((nom.to_string(), categorie, l.compte.clone()));
        self.listes.push(ListeChargee { nom: nom.to_string(), categorie, bloques: l.bloques, exceptions: l.exceptions });
        true
    }

    /// Entrées chargées, toutes listes confondues
    pub fn total(&self) -> usize {
        self.listes.iter().map(|l| l.bloques.len() + l.exceptions.len()).sum()
    }

    pub fn autoriser(&mut self, noms: &[String]) {
        self.autorises = empreintes(noms.iter().map(String::as_str));
    }

    /// Décision (pure, testée) : voir l'en-tête du module
    pub fn decider(&self, nom: &str, actives: &[Categorie]) -> Verdict {
        let Some(n) = normaliser(nom) else { return Verdict::Relaye };
        let h: Vec<u64> = noms_a_chercher(&n).iter().map(|x| empreinte(x)).collect();
        let dans = |t: &[u64]| h.iter().any(|x| t.binary_search(x).is_ok());
        if dans(&self.protection) {
            return Verdict::Protege;
        }
        if dans(&self.autorises) {
            return Verdict::Autorise;
        }
        let mut excepte = false;
        for categorie in [Categorie::Securite, Categorie::Publicite] {
            if !actives.contains(&categorie) {
                continue;
            }
            let listes = || self.listes.iter().filter(move |l| l.categorie == categorie);
            if listes().any(|l| dans(&l.exceptions)) {
                excepte = true;
                continue;
            }
            if let Some(l) = listes().find(|l| dans(&l.bloques)) {
                return Verdict::Bloque { categorie, liste: l.nom.clone() };
            }
        }
        if excepte { Verdict::Autorise } else { Verdict::Relaye }
    }
}

/// Catégories actives d'après la configuration (noms inconnus ignorés)
pub fn categories_actives(config: &commun::Config) -> Vec<Categorie> {
    let s: BTreeSet<Categorie> = config.filtrage.categories.iter().filter_map(|c| Categorie::de_nom(c)).collect();
    s.into_iter().collect()
}

/// Hôte d'une adresse https://hôte[:port]/… (pur)
pub fn hote_d_url(url: &str) -> Option<String> {
    let r = url.trim().strip_prefix("https://")?;
    let h = r.split(['/', ':', '?', '#']).next()?;
    normaliser(h)
}

/// Hôtes à épargner lus dans la configuration : remontée configurée (ntfy, Teams, SMTP) et serveur de mise à jour,
/// comme le mode panique (`reponse::epargnees`)
pub fn hotes_proteges(config: &commun::Config) -> Vec<String> {
    let secrets = crate::notifications::lire_secrets();
    let mut l: Vec<String> = [secrets.ntfy_url.as_str(), secrets.teams_url.as_str(), config.maj.url.as_str()]
        .into_iter().filter_map(hote_d_url).collect();
    if config.notifications.smtp {
        l.extend(normaliser(&config.notifications.smtp_serveur));
    }
    l
}

fn dossier() -> PathBuf {
    commun::dossier().join("filtrage")
}

fn fichier(s: &Source) -> PathBuf {
    dossier().join(format!("{}.txt", s.nom))
}

fn entrees_du_fichier(f: &Path, protection: &[u64]) -> usize {
    commun::lire_fichier_proprietaire(f).map(|t| lire_liste(&t, protection).compte.entrees).unwrap_or(0)
}

/// Télécharge, pour les catégories actives seulement, les listes de plus de 12 h ; la copie précédente est gardée si
/// la nouvelle est refusée (`remplacement_admis`). Rien n'est téléchargé sans catégorie active. Retour : statut par
/// liste en échec ou refusée
pub fn telecharger(actives: &[Categorie], protection: &[u64]) -> Vec<(String, String)> {
    let mut statuts = Vec::new();
    if actives.is_empty() {
        return statuts;
    }
    let _ = fs::create_dir_all(dossier());
    for s in SOURCES.iter().filter(|s| actives.contains(&s.categorie)) {
        let f = fichier(s);
        let recent = fs::metadata(&f).and_then(|m| m.modified())
            .map(|t| SystemTime::now().duration_since(t).unwrap_or_default() < Duration::from_secs(12 * 3600))
            .unwrap_or(false);
        if recent {
            continue;
        }
        let tmp = f.with_extension("tmp");
        match crate::menaces::curl_https(s.url, &tmp, MAX_OCTETS) {
            Ok(()) => {
                let nouvelle = entrees_du_fichier(&tmp, protection);
                let ancienne = if f.exists() { entrees_du_fichier(&f, protection) } else { 0 };
                if remplacement_admis(ancienne, nouvelle) {
                    let _ = fs::rename(&tmp, &f);
                } else {
                    let m = format!("liste refusée : {nouvelle} domaine(s) contre {ancienne} dans la copie précédente, gardée");
                    commun::journal(&format!("filtrage : {} : {m}", s.nom));
                    statuts.push((s.nom.to_string(), m));
                    let _ = fs::remove_file(&tmp);
                }
            }
            Err(e) => {
                commun::journal(&format!("filtrage : {} : échec du téléchargement : {e}", s.nom));
                statuts.push((s.nom.to_string(), format!("échec du téléchargement : {e}")));
                let _ = fs::remove_file(&tmp);
            }
        }
    }
    statuts
}

/// Charge les listes des catégories actives (propriétaire contrôlé). En échec de la protection du dossier de données :
/// aucune liste chargée (comme l'IPS, rien ne s'appuie sur des fichiers dont la protection n'est pas vérifiée)
pub fn charger(config: &commun::Config, echec_protection: bool) -> Filtrage {
    let mut f = Filtrage::nouveau(&hotes_proteges(config));
    f.autoriser(&config.filtrage.autorises);
    if echec_protection {
        return f;
    }
    let actives = categories_actives(config);
    for s in SOURCES.iter().filter(|s| actives.contains(&s.categorie)) {
        let Some(texte) = commun::lire_fichier_proprietaire(&fichier(s)) else { continue };
        let l = lire_liste(&texte, f.protection());
        if !f.ajouter(s.nom, s.categorie, l) {
            commun::journal(&format!("filtrage : {} non chargée : plus de {MAX_ENTREES} entrées au total", s.nom));
        }
    }
    f
}

/// Ligne de journal du bilan (pure, testée)
pub fn resume(actives: &[Categorie], f: &Filtrage) -> String {
    if actives.is_empty() {
        return "filtrage : aucune catégorie active, aucune liste téléchargée ni chargée".into();
    }
    let noms: Vec<&str> = actives.iter().map(|c| c.libelle()).collect();
    let listes: Vec<String> = f.bilan.iter().map(|(n, _, c)| format!("{n} : {} domaine(s), {} exception(s), {} règle(s) écartée(s), {} domaine(s) protégé(s) ignoré(s)",
        c.entrees, c.exceptions, c.ecartees, c.proteges_ignores)).collect();
    let securite = if actives.contains(&Categorie::Securite) && !SOURCES.iter().any(|s| s.categorie == Categorie::Securite) {
        " ; aucune liste de sécurité retenue (décision D7-2)"
    } else {
        ""
    };
    format!("filtrage : catégories actives : {} ; {} ; aucun effet réseau tant que le résolveur local n'est pas activé{securite}",
        noms.join(", "), if listes.is_empty() { "aucune liste chargée".into() } else { listes.join(" ; ") })
}
