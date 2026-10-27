//! Registre des règles de détection (phase 3, PR 3.2) : un identifiant stable pour chaque détection existante, tel que
//! `docs/detection/regles.md` le décrit (un test vérifie que les deux concordent). Données compilées dans le binaire :
//! aucun fichier de règles, donc aucune surface de confiance nouvelle. Un identifiant n'est jamais réutilisé ; une règle
//! retirée reste au registre, marquée « retirée ». Chaque producteur d'alertes pose la constante de sa règle (un
//! identifiant inexistant ne compile pas).

// Titre et constantes COR-* : lus par le registre (siem.rs cherche « COR-R<n> » par regle()) et par la PR 3.4 (interface)
#[allow(dead_code)]
pub struct Regle {
    pub id: &'static str,
    pub titre: &'static str,
}

macro_rules! registre {
    ($($nom:ident = $id:literal : $titre:literal;)*) => {
        $(#[allow(dead_code)] pub const $nom: &str = $id;)*
        pub const REGLES: &[Regle] = &[$(Regle { id: $id, titre: $titre },)*];
    };
}

registre! {
    RES_001 = "RES-001" : "connexion vers une adresse ou un domaine des listes de menaces";
    RES_002 = "RES-002" : "nouvelle connexion au score suspect";
    RES_003 = "RES-003" : "première connexion à Internet d'un programme";
    RES_004 = "RES-004" : "adresse publique directement sur le PC";
    RES_005 = "RES-005" : "paquet entrant venu d'Internet";
    RES_006 = "RES-006" : "nouveau port ouvert en écoute sur le réseau";
    RES_007 = "RES-007" : "connexion entrante depuis Internet";
    DNS_001 = "DNS-001" : "requête DNS vers un domaine malveillant connu";
    PRC_001 = "PRC-001" : "document bureautique qui lance un interpréteur";
    PRC_002 = "PRC-002" : "PowerShell obscurci ou qui télécharge du code";
    PRC_003 = "PRC-003" : "détournement d'outil Windows (LOLBin)";
    PRC_004 = "PRC-004" : "navigateur lancé en débogage à distance";
    PRC_005 = "PRC-005" : "suppression des sauvegardes";
    CHA_001 = "CHA-001" : "chaîne de processus au score cumulé";
    PER_001 = "PER-001" : "démarrage automatique nouveau";
    PER_002 = "PER-002" : "démarrage automatique modifié";
    DEF_001 = "DEF-001" : "Defender : menace détectée (1116)";
    DEF_002 = "DEF-002" : "Defender : menace traitée (1117)";
    DEF_003 = "DEF-003" : "Defender : protection en temps réel désactivée (5001)";
    DEF_004 = "DEF-004" : "Defender : analyse antivirus désactivée (5010, 5012)";
    DEF_005 = "DEF-005" : "Defender : exclusion ajoutée (5007)";
    DEF_006 = "DEF-006" : "Defender : protection affaiblie (5007)";
    DEF_007 = "DEF-007" : "Defender : règle ASR (1121, 1122)";
    DEF_008 = "DEF-008" : "Defender : accès contrôlé aux dossiers (1123, 1124)";
    DEF_009 = "DEF-009" : "Defender : protection réseau (1125, 1126)";
    DEF_010 = "DEF-010" : "Defender : protection en temps réel coupée (état WMI)";
    DEF_011 = "DEF-011" : "Defender : protection contre les falsifications désactivée (état WMI)";
    DEF_012 = "DEF-012" : "Defender : antivirus désactivé (état WMI)";
    LEU_001 = "LEU-001" : "leurre modifié, supprimé, renommé ou remplacé par un lien";
    LEU_002 = "LEU-002" : "leurre touché (audit des accès)";
    VOL_001 = "VOL-001" : "accès aux secrets d'un logiciel par un autre programme";
    SYS_001 = "SYS-001" : "fichier hosts modifié par un autre programme";
    SYS_002 = "SYS-002" : "règle de pare-feu ajoutée ou modifiée";
    SYS_003 = "SYS-003" : "toutes les règles du pare-feu supprimées";
    PIL_001 = "PIL-001" : "pilote vulnérable connu présent";
    EXT_001 = "EXT-001" : "nouvelle extension de navigateur";
    VIE_001 = "VIE-001" : "programme qui utilise la caméra ou le micro pour la première fois";
    VIE_002 = "VIE-002" : "outil de prise en main à distance en cours d'exécution";
    VIE_003 = "VIE-003" : "Bureau à distance activé";
    BAS_001 = "BAS-001" : "réglage de sécurité de la baseline défait";
    COR_R1 = "COR-R1" : "tentatives de mot de passe en série";
    COR_R2 = "COR-R2" : "session ouverte après une série d'échecs";
    COR_R3 = "COR-R3" : "nouveau compte administrateur";
    COR_R3B = "COR-R3b" : "ajout d'un compte existant au groupe Administrateurs";
    COR_R4 = "COR-R4" : "journal d'événements effacé";
    COR_R5 = "COR-R5" : "service installé depuis un emplacement suspect";
    COR_R6 = "COR-R6" : "attaque en plusieurs étapes";
    COR_R7 = "COR-R7" : "protection affaiblie";
    COR_R9 = "COR-R9" : "session ouverte depuis une adresse publique";
    COR_R10 = "COR-R10" : "pilote vulnérable installé (BYOVD)";
    INT_001 = "INT-001" : "échec de la protection du dossier de données";
    INT_002 = "INT-002" : "tube de commandes déjà pris par un autre processus";
    SAN_001 = "SAN-001" : "collecte critique indisponible plus de 30 min";
    SAN_002 = "SAN-002" : "collecte rétablie";
    SAN_003 = "SAN-003" : "Defender (journal et état) illisible plus de 30 min";
    SAN_004 = "SAN-004" : "remontée des alertes en échec depuis plus d'une heure (constat local)";
    SAN_012 = "SAN-012" : "alertes non suivies (plus de 500 incidents non clos)";
    EXP_IDS_001 = "EXP-IDS-001" : "IDS expérimental : règle au format Suricata (identifiant de la règle IDS dans les raisons)";
    EXP_DPI_001 = "EXP-DPI-001" : "DPI expérimental";
    EXP_NDR_001 = "EXP-NDR-001" : "NDR expérimental";
}

/// Règle du registre portant cet identifiant
pub fn regle(id: &str) -> Option<&'static Regle> {
    REGLES.iter().find(|r| r.id == id)
}

/// Forme d'un identifiant : DOM-NNN, COR-R<n>[b], EXP-<module>-NNN
pub fn identifiant_valide(id: &str) -> bool {
    let chiffres = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_digit());
    if let Some(r) = id.strip_prefix("COR-R") {
        let r = r.strip_suffix('b').unwrap_or(r);
        return !r.is_empty() && r.len() <= 2 && r.bytes().all(|b| b.is_ascii_digit());
    }
    if let Some(r) = id.strip_prefix("EXP-") {
        return matches!(r.split_once('-'), Some((m, n)) if ["IDS", "DPI", "NDR"].contains(&m) && chiffres(n, 3));
    }
    matches!(id.split_once('-'), Some((d, n)) if d.len() == 3 && d.bytes().all(|b| b.is_ascii_uppercase()) && chiffres(n, 3))
}
