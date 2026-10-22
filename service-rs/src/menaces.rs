//! Listes de menaces open source : téléchargées toutes les 12 h dans C:\ProgramData\deR4Tizer\menaces,
//! chargées en mémoire sous forme compacte (IP en entiers, réseaux en plages fusionnées, domaines en empreintes 64 bits).

use crate::commun::{self, InfosMenaces, SourceMenace};
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv6Addr};
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime};

#[derive(Clone)]
pub struct Correspondance {
    pub source: String,
    pub haute: bool,
}

struct Source {
    nom: &'static str,
    type_: &'static str,
    confiance: &'static str,
    /// "ip" (une IP ou un réseau par ligne), "spamhaus" (JSON par ligne), "domaine"
    format: &'static str,
    url: &'static str,
    /// Conditions d'utilisation : seules les listes « libres » sont utilisées par défaut ; les autres
    /// (non commerciales ou non vérifiées) demandent le réglage ListesRestreintes
    licence: &'static str,
    libre: bool,
}

const SOURCES: &[Source] = &[
    Source { nom: "Spamhaus DROP (IPv4)", type_: "IP", confiance: "haute", format: "spamhaus", url: "https://www.spamhaus.org/drop/drop_v4.json", licence: "libre, citation de Spamhaus, un téléchargement par jour", libre: true },
    Source { nom: "Spamhaus DROP (IPv6)", type_: "IP", confiance: "haute", format: "spamhaus", url: "https://www.spamhaus.org/drop/drop_v6.json", licence: "libre, citation de Spamhaus, un téléchargement par jour", libre: true },
    Source { nom: "FireHOL niveau 1", type_: "IP", confiance: "haute", format: "ip", url: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", licence: "à vérifier : agrège DShield, dont les données sont non commerciales", libre: false },
    Source { nom: "Feodo Tracker (C2 botnets)", type_: "IP", confiance: "haute", format: "ip", url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", licence: "libre, usage équitable (conditions d'abuse.ch)", libre: true },
    Source { nom: "ThreatView C2 Cobalt Strike", type_: "IP", confiance: "haute", format: "ip", url: "https://threatview.io/Downloads/High-Confidence-CobaltStrike-C2%20-Feeds.txt", licence: "à vérifier", libre: false },
    Source { nom: "ThreatView IP", type_: "IP", confiance: "réputation", format: "ip", url: "https://threatview.io/Downloads/IP-High-Confidence-Feed.txt", licence: "à vérifier", libre: false },
    Source { nom: "Emerging Threats (compromises)", type_: "IP", confiance: "réputation", format: "ip", url: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", licence: "à vérifier", libre: false },
    Source { nom: "CINS Army", type_: "IP", confiance: "réputation", format: "ip", url: "https://cinsscore.com/list/ci-badguys.txt", licence: "à vérifier (usage non commercial probable)", libre: false },
    Source { nom: "IPsum (niveau 3)", type_: "IP", confiance: "réputation", format: "ip", url: "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt", licence: "à vérifier", libre: false },
    Source { nom: "ThreatView domaines", type_: "Domaines", confiance: "réputation", format: "domaine", url: "https://threatview.io/Downloads/DOMAIN-High-Confidence-Feed.txt", licence: "à vérifier", libre: false },
    Source { nom: "Phishing Army", type_: "Domaines", confiance: "réputation", format: "domaine", url: "https://phishing.army/download/phishing_army_blocklist.txt", licence: "non commerciale (CC BY-NC 4.0)", libre: false },
];

#[derive(Clone)]
struct Plage {
    debut: u32,
    fin: u32,
    source: String,
}

struct Reseau6 {
    prefixe: [u8; 16],
    longueur: u32,
    source: String,
    haute: bool,
}

#[derive(Default)]
pub struct Menaces {
    ip4: HashMap<u32, Correspondance>,
    ip6: HashMap<Ipv6Addr, Correspondance>,
    plages_hautes: Vec<Plage>,
    plages_reputation: Vec<Plage>,
    reseaux6: Vec<Reseau6>,
    domaines: Vec<(String, Vec<u64>)>,
    pub infos: InfosMenaces,
}

fn dossier() -> PathBuf {
    commun::dossier().join("menaces")
}

fn fichier(s: &Source) -> PathBuf {
    let nom: String = s.nom.chars().map(|c| if c.is_alphanumeric() { c } else { '_' }).collect();
    let nom = Regex::new("_+").unwrap().replace_all(&nom, "_").to_string();
    dossier().join(format!("{nom}.txt"))
}

/// FNV-1a 64 bits (sur les caractères UTF-16, comme l'ancien service C#)
fn empreinte(s: &str) -> u64 {
    let mut h: u64 = 14695981039346656037;
    for c in s.encode_utf16() {
        h ^= c as u64;
        h = h.wrapping_mul(1099511628211);
    }
    h
}

fn reservee(v: u32) -> bool {
    let (a, b) = (v >> 24, (v >> 16) & 0xFF);
    a == 0 || a == 10 || a == 127 || a >= 224
        || (a == 100 && (64..128).contains(&b)) // CGNAT, Tailscale
        || (a == 169 && b == 254)
        || (a == 172 && (16..32).contains(&b))
        || (a == 192 && b == 168)
}

/// Réseaux privés et réservés (RFC 1918, CGNAT, lien local, bouclage, multicast, réservés)
const RESERVES: &[(u32, u32)] = &[
    (0x0000_0000, 0x00FF_FFFF), (0x0A00_0000, 0x0AFF_FFFF), (0x6440_0000, 0x647F_FFFF), (0x7F00_0000, 0x7FFF_FFFF),
    (0xA9FE_0000, 0xA9FE_FFFF), (0xAC10_0000, 0xAC1F_FFFF), (0xC000_0000, 0xC000_00FF), (0xC0A8_0000, 0xC0A8_FFFF),
    (0xC612_0000, 0xC613_FFFF), (0xE000_0000, 0xFFFF_FFFF),
];

fn recouvre_reserve(debut: u32, fin: u32) -> bool {
    RESERVES.iter().any(|(d, f)| debut <= *f && fin >= *d)
}

impl Menaces {
    // ------------------------------------------------------------ recherche

    pub fn chercher_ip(&self, texte: &str) -> Option<Correspondance> {
        let ip: IpAddr = texte.parse().ok()?;
        // Une liste ne doit jamais faire signaler (ni bloquer) une imprimante, un NAS ou la box
        if !crate::parefeu::publique(&ip) {
            return None;
        }
        match ip {
            IpAddr::V4(v4) => {
                let v = u32::from(v4);
                let exacte = self.ip4.get(&v);
                if let Some(c) = exacte {
                    if c.haute {
                        return Some(c.clone());
                    }
                }
                if let Some(s) = dans_plages(&self.plages_hautes, v) {
                    return Some(Correspondance { source: s, haute: true });
                }
                if let Some(c) = exacte {
                    return Some(c.clone());
                }
                dans_plages(&self.plages_reputation, v).map(|s| Correspondance { source: s, haute: false })
            }
            IpAddr::V6(v6) => {
                if let Some(c) = self.ip6.get(&v6) {
                    return Some(c.clone());
                }
                let o = v6.octets();
                self.reseaux6.iter().find(|r| dans_reseau6(&o, r)).map(|r| Correspondance { source: r.source.clone(), haute: r.haute })
            }
        }
    }

    pub fn chercher_domaine(&self, nom: &str) -> Option<Correspondance> {
        if nom.is_empty() {
            return None;
        }
        let h = empreinte(&nom.trim().trim_end_matches('.').to_lowercase());
        self.domaines.iter().find(|(_, t)| t.binary_search(&h).is_ok()).map(|(s, _)| Correspondance { source: s.clone(), haute: false })
    }

    // ------------------------------------------------------------ téléchargement et chargement

    /// Télécharge (avec curl.exe, fourni par Windows) les listes de plus de 12 h (24 h pour Spamhaus, qui le
    /// demande), en HTTPS uniquement et 100 Mo au plus ; une liste vide ou qui s'effondre est rejetée et la copie
    /// précédente est gardée
    pub fn telecharger(forcer: bool) -> HashMap<String, String> {
        let _ = fs::create_dir_all(dossier());
        let mut statuts = HashMap::new();
        let restreintes = commun::lire::<commun::Config>("config.json").map(|c| c.listes_restreintes).unwrap_or(false);
        for s in SOURCES {
            if !s.libre && !restreintes {
                continue;
            }
            let f = fichier(s);
            let delai = if s.format == "spamhaus" { 24 * 3600 } else { 12 * 3600 };
            let recent = fs::metadata(&f)
                .and_then(|m| m.modified())
                .map(|t| SystemTime::now().duration_since(t).unwrap_or_default() < Duration::from_secs(delai))
                .unwrap_or(false);
            if !forcer && recent {
                continue;
            }
            let tmp = f.with_extension("tmp");
            let resultat = Command::new("curl.exe")
                .args(["-sSL", "--fail", "--proto", "=https", "--proto-redir", "=https", "--max-filesize", "104857600",
                    "--max-time", "180", "-A", &format!("deR4Tizer/{}", commun::VERSION), "-o"])
                .arg(&tmp)
                .arg(s.url)
                .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
                .output();
            match resultat {
                Ok(sortie) if sortie.status.success() => {
                    let nouvelle = compter(s, &tmp);
                    let ancienne = if f.exists() { compter(s, &f) } else { 0 };
                    if nouvelle == 0 || (ancienne >= 50 && nouvelle < ancienne / 5) {
                        let message = format!("liste rejetée : {nouvelle} entrée(s) valide(s) contre {ancienne} dans la copie précédente, gardée");
                        commun::journal(&format!("liste {} : {message}", s.nom));
                        statuts.insert(s.nom.to_string(), message);
                        let _ = fs::remove_file(&tmp);
                    } else {
                        let _ = fs::rename(&tmp, &f);
                    }
                }
                Ok(sortie) => {
                    let message = String::from_utf8_lossy(&sortie.stderr).trim().to_string();
                    commun::journal(&format!("liste {} : {}", s.nom, message));
                    statuts.insert(s.nom.to_string(), format!("échec du téléchargement : {message}"));
                    let _ = fs::remove_file(&tmp);
                }
                Err(e) => {
                    statuts.insert(s.nom.to_string(), format!("échec du téléchargement : {e}"));
                }
            }
        }
        statuts
    }

    pub fn charger(statuts: &HashMap<String, String>) -> Menaces {
        let mut m = Menaces::default();
        let mut plages_h = Vec::new();
        let mut plages_r = Vec::new();
        let mut infos = InfosMenaces { mis_a_jour: commun::maintenant(), ..Default::default() };
        let motif_spamhaus = Regex::new(r#""cidr"\s*:\s*"([^"]+)""#).unwrap();

        let restreintes = commun::lire::<commun::Config>("config.json").map(|c| c.listes_restreintes).unwrap_or(false);
        for s in SOURCES {
            let f = fichier(s);
            let statut = statuts.get(s.nom).cloned();
            let mut info = SourceMenace { nom: s.nom.into(), type_: s.type_.into(), confiance: s.confiance.into(), licence: s.licence.into(), ..Default::default() };
            if !s.libre && !restreintes {
                info.statut = format!("désactivée (licence : {})", s.licence);
                infos.sources.push(info);
                continue;
            }
            let Ok(fh) = fs::File::open(&f) else {
                info.statut = statut.unwrap_or_else(|| "pas encore téléchargée".into());
                infos.sources.push(info);
                continue;
            };
            info.mis_a_jour = fs::metadata(&f).and_then(|x| x.modified()).ok().map(|t| commun::heure(t).chars().take(16).collect());
            let haute = s.confiance == "haute";
            let mut rejetee = false;
            let lignes = BufReader::new(fh).lines().map_while(Result::ok);
            let n = if s.format == "domaine" {
                let mut h: Vec<u64> = lignes.filter_map(|l| domaine_de_ligne(&l)).map(|d| empreinte(&d)).collect();
                h.sort_unstable();
                h.dedup();
                let n = h.len();
                m.domaines.push((s.nom.to_string(), h));
                n
            } else {
                let mut n = 0;
                let (debut_h, debut_r) = (plages_h.len(), plages_r.len());
                for l in lignes {
                    let jeton = if s.format == "spamhaus" {
                        motif_spamhaus.captures(&l).map(|c| c[1].to_string())
                    } else {
                        premier_jeton(&l)
                    };
                    let Some(j) = jeton else { continue };
                    let plages = if haute { &mut plages_h } else { &mut plages_r };
                    if m.ajouter(&j, s.nom, haute, plages) {
                        n += 1;
                    }
                }
                let couverture: u64 = plages_h[debut_h..].iter().chain(plages_r[debut_r..].iter()).map(|p| (p.fin - p.debut) as u64 + 1).sum();
                if couverture > 1 << 27 {
                    // Plus de 134 millions d'adresses : liste corrompue ou détournée, jamais appliquée
                    plages_h.truncate(debut_h);
                    plages_r.truncate(debut_r);
                    m.ip4.retain(|_, c| c.source != s.nom);
                    commun::journal(&format!("liste {} rejetée : elle couvrirait {couverture} adresses", s.nom));
                    rejetee = true;
                    0
                } else {
                    n
                }
            };
            info.entrees = n;
            if rejetee {
                info.statut = "rejetée : couverture aberrante (liste corrompue ?)".into();
                infos.sources.push(info);
                continue;
            }
            info.statut = match statut {
                Some(st) => format!("{st} (copie locale utilisée)"),
                None => "ok".into(),
            };
            infos.sources.push(info);
        }

        infos.total_reseaux = plages_h.len() + plages_r.len() + m.reseaux6.len();
        m.plages_hautes = fusionner(plages_h);
        m.plages_reputation = fusionner(plages_r);
        infos.total_ip = m.ip4.len() + m.ip6.len();
        infos.total_domaines = m.domaines.iter().map(|(_, t)| t.len()).sum();
        commun::ecrire("menaces.json", &infos);
        m.infos = infos;
        m
    }

    fn ajouter(&mut self, jeton: &str, source: &str, haute: bool, plages: &mut Vec<Plage>) -> bool {
        let (adresse, longueur) = match jeton.split_once('/') {
            Some((a, l)) => match l.parse::<u32>() {
                Ok(l) => (a, Some(l)),
                Err(_) => return false,
            },
            None => (jeton, None),
        };
        let Ok(ip) = adresse.parse::<IpAddr>() else { return false };
        match ip {
            IpAddr::V4(v4) => {
                let v = u32::from(v4);
                if reservee(v) {
                    return false; // FireHOL inclut les réseaux privés et réservés (« bogons »)
                }
                match longueur {
                    None | Some(32) => {
                        let entree = self.ip4.entry(v).or_insert(Correspondance { source: source.into(), haute });
                        if haute && !entree.haute {
                            *entree = Correspondance { source: source.into(), haute: true };
                        }
                        true
                    }
                    Some(l) if (8..32).contains(&l) => {
                        let masque = u32::MAX << (32 - l);
                        if recouvre_reserve(v & masque, (v & masque) | !masque) {
                            return false; // par exemple 172.0.0.0/8, qui contient 172.16.0.0/12
                        }
                        plages.push(Plage { debut: v & masque, fin: (v & masque) | !masque, source: source.into() });
                        true
                    }
                    _ => false,
                }
            }
            IpAddr::V6(v6) => match longueur {
                None | Some(128) => {
                    self.ip6.entry(v6).or_insert(Correspondance { source: source.into(), haute });
                    true
                }
                Some(l) if l >= 16 => {
                    self.reseaux6.push(Reseau6 { prefixe: v6.octets(), longueur: l, source: source.into(), haute });
                    true
                }
                _ => false,
            },
        }
    }
}

fn dans_plages(plages: &[Plage], v: u32) -> Option<String> {
    // Dernière plage qui commence avant v
    let i = plages.partition_point(|p| p.debut <= v);
    if i == 0 {
        return None;
    }
    let p = &plages[i - 1];
    (p.fin >= v).then(|| p.source.clone())
}

fn dans_reseau6(ip: &[u8; 16], r: &Reseau6) -> bool {
    let (complets, reste) = ((r.longueur / 8) as usize, r.longueur % 8);
    if ip[..complets] != r.prefixe[..complets] {
        return false;
    }
    if reste == 0 {
        return true;
    }
    let masque = (0xFFu32 << (8 - reste)) as u8;
    ip[complets] & masque == r.prefixe[complets] & masque
}

/// Nombre d'entrées valides d'un fichier de liste (contrôle avant de remplacer la copie précédente)
fn compter(s: &Source, chemin: &std::path::Path) -> usize {
    let Ok(t) = fs::read_to_string(chemin) else { return 0 };
    match s.format {
        "domaine" => t.lines().filter_map(domaine_de_ligne).count(),
        "spamhaus" => t.matches("\"cidr\"").count(),
        _ => t.lines().filter_map(premier_jeton).filter(|j| j.split('/').next().unwrap_or("").parse::<IpAddr>().is_ok()).count(),
    }
}

fn premier_jeton(ligne: &str) -> Option<String> {
    let l = ligne.trim();
    if l.is_empty() || l.starts_with(['#', ';', '!', '<']) {
        return None;
    }
    l.split([' ', '\t', ',', ';']).find(|s| !s.is_empty()).map(String::from)
}

fn domaine_de_ligne(ligne: &str) -> Option<String> {
    let l = ligne.trim();
    if l.is_empty() || l.starts_with(['#', '!']) {
        return None;
    }
    // Format hosts « 0.0.0.0 domaine » ou domaine seul
    let d = l.split_whitespace().last()?.trim_end_matches('.').to_lowercase();
    if !d.contains('.') || d.parse::<IpAddr>().is_ok() || d.ends_with(".arpa") {
        return None;
    }
    Some(d)
}

fn fusionner(mut plages: Vec<Plage>) -> Vec<Plage> {
    plages.sort_by_key(|p| p.debut);
    let mut resultat: Vec<Plage> = Vec::new();
    for p in plages {
        if let Some(derniere) = resultat.last_mut() {
            if p.debut as u64 <= derniere.fin as u64 + 1 {
                derniere.fin = derniere.fin.max(p.fin);
                if !derniere.source.contains(&p.source) && derniere.source.len() < 80 {
                    derniere.source = format!("{}, {}", derniere.source, p.source);
                }
                continue;
            }
        }
        resultat.push(p);
    }
    resultat
}
