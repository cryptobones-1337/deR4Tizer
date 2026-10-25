//! Pays des adresses IPv4, d'après les fichiers « delegated » publiés par les cinq registres Internet
//! régionaux (ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC) : données publiques, sans licence ni service en ligne.
//! C'est le pays du titulaire du bloc d'adresses, pas toujours celui du serveur (CDN, hébergeurs mondiaux).

use crate::commun;
use std::fs;
use std::net::Ipv4Addr;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime};

const SOURCES: &[(&str, &str)] = &[
    ("arin", "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest"),
    ("ripencc", "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest"),
    ("apnic", "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest"),
    ("lacnic", "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest"),
    ("afrinic", "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest"),
];

fn dossier() -> PathBuf {
    commun::dossier().join("geoip")
}

/// Plages triées : (début, fin incluse, code pays ISO 3166 alpha-2)
#[derive(Default)]
pub struct GeoIp {
    plages: Vec<(u32, u32, [u8; 2])>,
}

impl GeoIp {
    /// Télécharge les fichiers de plus de 7 jours (curl.exe, fourni par Windows)
    pub fn telecharger() {
        let _ = fs::create_dir_all(dossier());
        for (nom, url) in SOURCES {
            let f = dossier().join(format!("{nom}.txt"));
            let recent = fs::metadata(&f).and_then(|m| m.modified())
                .map(|t| SystemTime::now().duration_since(t).unwrap_or_default() < Duration::from_secs(7 * 86_400)).unwrap_or(false);
            if recent {
                continue;
            }
            let tmp = f.with_extension("tmp");
            let ok = Command::new("curl.exe")
                .args(["-q", "-sSL", "--fail", "--proto", "=https", "--proto-redir", "=https", "--max-filesize", "104857600",
                    "--max-time", "300", "-A", &format!("deR4Tizer/{}", commun::VERSION), "-o"])
                .arg(&tmp)
                .arg(url)
                .creation_flags(0x0800_0000)
                .output()
                .map(|s| s.status.success())
                .unwrap_or(false);
            if ok {
                let _ = fs::rename(&tmp, &f);
            } else {
                let _ = fs::remove_file(&tmp);
                commun::journal(&format!("géolocalisation : téléchargement de {nom} impossible"));
            }
        }
    }

    pub fn charger() -> GeoIp {
        let mut plages = Vec::new();
        for (nom, _) in SOURCES {
            let Some(texte) = crate::commun::lire_fichier(&dossier().join(format!("{nom}.txt"))) else { continue };
            // registre|pays|ipv4|début|nombre|date|statut[|…]
            for ligne in texte.lines() {
                let c: Vec<&str> = ligne.split('|').collect();
                if c.len() < 7 || c[2] != "ipv4" || c[1].len() != 2 || !(c[6] == "allocated" || c[6] == "assigned") {
                    continue;
                }
                let (Ok(debut), Ok(nombre)) = (c[3].parse::<Ipv4Addr>(), c[4].parse::<u64>()) else { continue };
                let d = u32::from(debut);
                let fin = (d as u64 + nombre.saturating_sub(1)).min(u32::MAX as u64) as u32;
                let b = c[1].as_bytes();
                plages.push((d, fin, [b[0].to_ascii_uppercase(), b[1].to_ascii_uppercase()]));
            }
        }
        plages.sort_unstable();
        GeoIp { plages }
    }

    pub fn taille(&self) -> usize {
        self.plages.len()
    }

    /// Code pays (« FR ») de l'adresse, ou None (adresse privée, inconnue)
    pub fn pays(&self, ip: Ipv4Addr) -> Option<String> {
        let v = u32::from(ip);
        let i = self.plages.partition_point(|p| p.0 <= v);
        let (debut, fin, code) = self.plages.get(i.checked_sub(1)?)?;
        (v >= *debut && v <= *fin).then(|| String::from_utf8_lossy(code).into_owned())
    }
}
