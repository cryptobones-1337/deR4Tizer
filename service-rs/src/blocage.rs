//! Blocages : bloc géré dans le fichier hosts et règles du pare-feu Windows (API COM).

use crate::commun;
use crate::natif;
use regex::Regex;
use std::fs;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use windows::core::BSTR;
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, NetFwPolicy2, NetFwRule, NET_FW_ACTION_BLOCK, NET_FW_RULE_DIR_OUT,
};
use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED};
use windows::Win32::Foundation::VARIANT_TRUE;

pub const DEBUT_BLOC: &str = "# >>> deR4Tizer (bloc gere par le service, ne pas modifier a la main)";
pub const FIN_BLOC: &str = "# <<< deR4Tizer";
pub const GROUPE: &str = "deR4Tizer";

pub fn fichier_hosts() -> PathBuf {
    PathBuf::from(natif::dossier_systeme()).join(r"drivers\etc\hosts")
}

/// Lignes du fichier hosts hors de nos blocs, et domaines de nos blocs : mêmes bornes que nouveau_contenu (un début ou
/// une fin isolés sont des lignes de l'utilisateur ; tous les blocs complets sont à nous)
pub fn lignes_hors_bloc() -> std::io::Result<(Vec<String>, Vec<String>)> {
    let octets = fs::read(fichier_hosts())?;
    Ok(decouper_hosts(&octets))
}

/// (lignes hors de nos blocs, domaines de nos blocs), pur et testé
pub fn decouper_hosts(octets: &[u8]) -> (Vec<String>, Vec<String>) {
    let motif = Regex::new(r"^\s*\S+\s+(\S+)").unwrap();
    let mut garder: Vec<&[u8]> = if octets.is_empty() { Vec::new() } else { octets.split(|&b| b == b'\n').collect() };
    if garder.last().is_some_and(|d| d.is_empty()) {
        garder.pop();
    }
    let mut bloc = Vec::new();
    while let Some((d, f)) = bornes_du_bloc(&garder) {
        for l in &garder[d + 1..f] {
            if let Some(c) = motif.captures(&String::from_utf8_lossy(l)) {
                bloc.push(c[1].to_string());
            }
        }
        garder.drain(d..=f);
    }
    let hors = garder.iter().map(|l| String::from_utf8_lossy(l.strip_suffix(b"\r").unwrap_or(l)).into_owned()).collect();
    (hors, bloc)
}

/// Empreinte du fichier hosts ENTIER : avant, seules les lignes hors du bloc de deR4Tizer comptaient, et une ligne
/// ajoutée dans le bloc (ou un faux début de bloc) passait sans alerte (audit AUD5-06)
pub fn empreinte_hosts() -> String {
    crate::hygiene::empreinte_fichier(&fichier_hosts()).unwrap_or_default()
}

/// Bornes du bloc de deR4Tizer : (ligne de début, ligne de fin) : la première fin précédée d'un début, et le DERNIER
/// début avant elle. Un début sans fin, ou une fin sans début, est une ligne de l'utilisateur, gardée telle quelle :
/// avant, le premier début était pris, et une seconde écriture effaçait toutes les lignes de l'utilisateur entre un
/// faux début (fichier laissé tronqué par l'ancien code) et la fin du vrai bloc (relecture de #54)
fn bornes_du_bloc(lignes: &[&[u8]]) -> Option<(usize, usize)> {
    let net = |l: &[u8]| -> Vec<u8> { l.strip_suffix(b"\r").unwrap_or(l).to_vec() };
    let mut debut = None;
    for (i, l) in lignes.iter().enumerate() {
        let l = net(l);
        if l == DEBUT_BLOC.as_bytes() {
            debut = Some(i);
        } else if l == FIN_BLOC.as_bytes() {
            if let Some(d) = debut {
                return Some((d, i));
            }
        }
    }
    None
}

/// Nouveau contenu du fichier hosts (pur, testé) : les lignes de l'utilisateur hors du bloc sont recopiées OCTET POUR
/// OCTET (avant, le fichier entier passait par un décodage approximatif et un filtre ASCII : commentaires accentués
/// perdus, fichier UTF-16 cassé, audit SEC-006) ; seul le bloc de deR4Tizer est réécrit, en ASCII, fins de ligne
/// Windows. Fichier en UTF-16 (BOM) : refusé plutôt que réécrit.
pub fn nouveau_contenu(original: &[u8], domaines: &[String]) -> Result<Vec<u8>, String> {
    if original.starts_with(&[0xFF, 0xFE]) || original.starts_with(&[0xFE, 0xFF]) {
        return Err("fichier hosts en UTF-16 : non modifié".into());
    }
    let lignes: Vec<&[u8]> = if original.is_empty() { Vec::new() } else { original.split(|&b| b == b'\n').collect() };
    // split laisse un dernier élément vide quand le fichier finit par une fin de ligne
    let (lignes, fin_de_ligne) = match lignes.split_last() {
        Some((d, reste)) if d.is_empty() => (reste.to_vec(), true),
        _ => (lignes.clone(), lignes.is_empty()),
    };
    let mut garder: Vec<&[u8]> = lignes.clone();
    let mut fin_de_ligne = fin_de_ligne;
    // TOUS les blocs complets (relecture de #54 : avec deux blocs, seul le premier était retiré ; un domaine débloqué
    // restait bloqué, même après la désinstallation)
    while let Some((d, f)) = bornes_du_bloc(&garder) {
        // Bloc en fin de fichier sans fin de ligne finale : la ligne qui le précédait gardait la sienne
        if f + 1 == garder.len() {
            fin_de_ligne = true;
        }
        garder.drain(d..=f);
    }
    // Lignes gardées rejointes telles quelles (avec leur \r éventuel), fin de ligne finale seulement si l'original
    // en avait une : sans bloc, le contenu est exactement l'original
    let mut sortie = garder.join(&b'\n');
    if fin_de_ligne && !garder.is_empty() {
        sortie.push(b'\n');
    }
    let mut liste = lignes_du_bloc(domaines);
    liste.sort();
    liste.dedup();
    if !liste.is_empty() {
        if !sortie.is_empty() && !sortie.ends_with(b"\n") {
            sortie.extend_from_slice(if sortie.ends_with(b"\r") { b"\n" } else { b"\r\n" });
        }
        for l in std::iter::once(DEBUT_BLOC.to_string()).chain(liste.iter().map(|d| format!("127.0.0.1\t{d}"))).chain(std::iter::once(FIN_BLOC.to_string())) {
            sortie.extend_from_slice(l.as_bytes());
            sortie.extend_from_slice(b"\r\n");
        }
    }
    Ok(sortie)
}

/// Noms écrits dans le bloc de deR4Tizer du fichier hosts : seulement des noms de domaine valides (phase 1), en
/// minuscules. Un nom avec une fin de ligne ajouterait une ligne arbitraire au fichier hosts (une banque redirigée
/// vers une adresse choisie) ; un nom accentué serait réduit par le filtre ASCII à un autre nom. Écartés et journalisés.
pub fn lignes_du_bloc(domaines: &[String]) -> Vec<String> {
    domaines.iter().filter_map(|d| {
        if crate::validation::nom_domaine_valide(d) {
            Some(d.trim_end_matches('.').to_lowercase())
        } else {
            commun::journal(&format!("fichier hosts : nom invalide écarté ({} caractères)", d.chars().count()));
            None
        }
    }).collect()
}

/// Sauvegardes du fichier hosts gardées (les plus récentes)
const SAUVEGARDES_HOSTS: usize = 20;

/// Réécrit le bloc de deR4Tizer (audit SEC-005) : sauvegarde obligatoire avant toute écriture (échec : rien n'est
/// écrit), puis fichier temporaire dans le même dossier et remplacement (jamais de fichier hosts tronqué) ; seules les
/// SAUVEGARDES_HOSTS dernières sauvegardes sont gardées, plus la toute première (fichier d'origine, jamais effacée).
pub fn ecrire_bloc_hosts(domaines: &[String]) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind, Write};
    let hosts = fichier_hosts();
    let original = match fs::read(&hosts) {
        Ok(o) => o,
        Err(e) if e.kind() == ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e),
    };
    let contenu = nouveau_contenu(&original, domaines).map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
    if contenu == original {
        return Ok(());
    }
    let sauvegardes = commun::dossier().join("sauvegardes");
    fs::create_dir_all(&sauvegardes)?;
    if !original.is_empty() {
        // Fichier d'origine : gardé à part, hors rotation (sinon effacé après 20 écritures)
        let origine = sauvegardes.join("origine-hosts.bak");
        if !origine.exists() {
            fs::write(&origine, &original)?;
        }
        // Nom unique : deux écritures dans la même seconde ne s'écrasent pas
        let horodatage = commun::maintenant().replace([':', ' '], "-");
        // Suffixe toujours présent (-00, -01…) : l'ordre alphabétique reste l'ordre chronologique dans une même seconde
        let mut nom = sauvegardes.join(format!("hosts-{horodatage}-00.bak"));
        let mut n = 1;
        while nom.exists() {
            nom = sauvegardes.join(format!("hosts-{horodatage}-{n:02}.bak"));
            n += 1;
        }
        fs::write(&nom, &original)?;
        let mut anciennes: Vec<_> = fs::read_dir(&sauvegardes)?.filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("hosts-")).map(|e| e.path()).collect();
        anciennes.sort();
        let surplus = anciennes.len().saturating_sub(SAUVEGARDES_HOSTS);
        for a in anciennes.into_iter().take(surplus) {
            let _ = fs::remove_file(a);
        }
    }
    let tmp = hosts.with_file_name("hosts.deR4Tizer.tmp");
    let ecrit = (|| -> std::io::Result<()> {
        let mut h = fs::File::create(&tmp)?;
        h.write_all(&contenu)?;
        h.sync_all()
    })();
    if let Err(e) = ecrit {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = natif::remplacer_fichier(&tmp, &hosts) {
        let _ = fs::remove_file(&tmp);
        return Err(Error::other(e));
    }
    natif::vider_cache_dns();
    Ok(())
}

// ------------------------------------------------------------ pare-feu

fn politique() -> windows::core::Result<INetFwPolicy2> {
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER)
    }
}

pub fn nom_regle(ip: &str) -> String {
    format!("deR4Tizer - bloque {ip}")
}

pub fn ajouter_regle(ip: &str, raison: &str) -> windows::core::Result<()> {
    unsafe {
        let p = politique()?;
        let r: INetFwRule = CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER)?;
        r.SetName(&BSTR::from(nom_regle(ip)))?;
        r.SetDescription(&BSTR::from(raison))?;
        r.SetGrouping(&BSTR::from(GROUPE))?;
        r.SetDirection(NET_FW_RULE_DIR_OUT)?;
        r.SetAction(NET_FW_ACTION_BLOCK)?;
        r.SetProtocol(256)?; // tous les protocoles
        r.SetRemoteAddresses(&BSTR::from(ip))?;
        r.SetProfiles(0x7FFF_FFFF)?;
        r.SetEnabled(VARIANT_TRUE)?;
        p.Rules()?.Add(&r)
    }
}

/// Nombre de règles du pare-feu actuellement en vigueur (None si illisible)
pub fn nombre_regles() -> Option<i32> {
    unsafe { politique().ok()?.Rules().ok()?.Count().ok() }
}

/// Supprime toutes les règles portant le nom de cette IP
pub fn supprimer_regle(ip: &str) -> usize {
    let Ok(p) = politique() else { return 0 };
    let nom = BSTR::from(nom_regle(ip));
    let mut n = 0;
    unsafe {
        let Ok(regles) = p.Rules() else { return 0 };
        while regles.Item(&nom).is_ok() && n < 50 {
            if regles.Remove(&nom).is_err() {
                break;
            }
            n += 1;
        }
    }
    n
}

/// Supprime toutes les règles du groupe deR4Tizer (désinstallation, ou règles orphelines)
pub fn supprimer_groupe() -> bool {
    crate::mesure::powershell("blocage");
    Command::new(crate::natif::powershell_exe())
        .args(["-NoProfile", "-Command", &format!("Get-NetFirewallRule -Group '{GROUPE}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule")])
        .creation_flags(0x0800_0000)
        .output()
        .map(|s| s.status.success())
        .unwrap_or(false)
}
