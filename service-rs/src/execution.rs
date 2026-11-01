//! Seul module qui exécute les actions de réponse (phase 6, PR 6.2). Chaque fonction exige une `Autorisation`, que seul
//! `politique::decider` fabrique. Un test de structure vérifie qu'aucun autre module n'appelle ces actions.

use crate::politique::Autorisation;
use crate::{blocage, reponse};

pub fn tuer(_: &Autorisation, pid: u32) -> Result<(), String> {
    reponse::tuer(pid)
}

pub fn suspendre(_: &Autorisation, pid: u32, suspendre: bool) -> Result<(), String> {
    reponse::suspendre(pid, suspendre)
}

pub fn isoler_programme(_: &Autorisation, chemin: &str) -> Result<(), String> {
    reponse::isoler_programme(chemin)
}

pub fn panique(_: &Autorisation, activer: bool) -> Result<String, String> {
    reponse::panique(activer)
}

pub fn ajouter_regle(_: &Autorisation, ip: &str, raison: &str) -> windows::core::Result<()> {
    blocage::ajouter_regle(ip, raison)
}
