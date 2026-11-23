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
    /// Technique ATT&CK de la règle (couverture ATT&CK, lot 2) : la seule table, d'après docs/validation/carte-attack.md
    pub techniques: Techniques,
}

/// Technique ATT&CK d'une règle (version 20.1). Plus aucune recherche de mots dans le texte de l'alerte : la technique
/// vient de l'identifiant de règle. Une règle qui couvre plusieurs comportements laisse le code qui produit l'alerte la
/// poser ; une règle sans technique le dit
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Techniques {
    /// Toujours les mêmes techniques
    Fixes(&'static [&'static str]),
    /// Posées par le code qui produit l'alerte, selon le comportement vu (champ `mitre` de l'alerte, identifiants
    /// séparés par « / ») : CHA-001 (techniques des signaux de la chaîne), COR-R7 (événement), VIE-001 (caméra ou
    /// micro), VIE-002 (outil d'accès à distance, ou tunnel pour ngrok), EXP-NDR-001, EXP-DPI-001, EXP-IDS-001 (aucune posée à ce jour : l'identifiant de la règle IDS est dans
    /// les raisons)
    ParLAlerte,
    /// Aucune technique : constat de santé, réponse, intégrité, détection générique de Defender, ou comportement sans
    /// technique précise
    Aucune,
}

use Techniques::{Aucune, Fixes, ParLAlerte};

macro_rules! registre {
    ($($nom:ident = $id:literal : $titre:literal => $tech:expr;)*) => {
        $(#[allow(dead_code)] pub const $nom: &str = $id;)*
        pub const REGLES: &[Regle] = &[$(Regle { id: $id, titre: $titre, techniques: $tech },)*];
    };
}

registre! {
    RES_001 = "RES-001" : "connexion vers une adresse ou un domaine des listes de menaces" => Fixes(&["T1071.001"]);
    RES_002 = "RES-002" : "nouvelle connexion au score suspect" => Fixes(&["T1071.001"]);
    RES_003 = "RES-003" : "première connexion à Internet d'un programme" => Fixes(&["T1071.001"]);
    RES_004 = "RES-004" : "adresse publique directement sur le PC" => Fixes(&["T1133"]);
    RES_005 = "RES-005" : "paquet entrant venu d'Internet" => Fixes(&["T1133"]);
    RES_006 = "RES-006" : "nouveau port ouvert en écoute sur le réseau" => Aucune;
    RES_007 = "RES-007" : "connexion entrante depuis Internet" => Fixes(&["T1133"]);
    DNS_001 = "DNS-001" : "requête DNS vers un domaine malveillant connu" => Fixes(&["T1071.004"]);
    DNS_002 = "DNS-002" : "serveur DNS changé sur une carte du poste" => Fixes(&["T1557"]);
    DNS_003 = "DNS-003" : "port DNS de la boucle locale tenu par un autre programme, carte encore réglée sur le résolveur" => Fixes(&["T1557"]);
    PRC_001 = "PRC-001" : "document bureautique qui lance un interpréteur" => Fixes(&["T1566.001", "T1204.002"]);
    PRC_002 = "PRC-002" : "PowerShell obscurci ou qui télécharge du code" => ParLAlerte;
    PRC_003 = "PRC-003" : "détournement d'outil Windows (LOLBin)" => ParLAlerte;
    PRC_004 = "PRC-004" : "navigateur lancé en débogage à distance" => Fixes(&["T1539"]);
    PRC_005 = "PRC-005" : "suppression des sauvegardes" => Fixes(&["T1490"]);
    CHA_001 = "CHA-001" : "chaîne de processus au score cumulé" => ParLAlerte;
    PER_001 = "PER-001" : "démarrage automatique nouveau" => ParLAlerte;
    PER_002 = "PER-002" : "démarrage automatique modifié" => ParLAlerte;
    DEF_001 = "DEF-001" : "Defender : menace détectée (1116)" => Aucune;
    DEF_002 = "DEF-002" : "Defender : menace traitée (1117)" => Aucune;
    DEF_003 = "DEF-003" : "Defender : protection en temps réel désactivée (5001)" => Fixes(&["T1685"]);
    DEF_004 = "DEF-004" : "Defender : analyse antivirus désactivée (5010, 5012)" => Fixes(&["T1685"]);
    DEF_005 = "DEF-005" : "Defender : exclusion ajoutée (5007)" => Fixes(&["T1685"]);
    DEF_006 = "DEF-006" : "Defender : protection affaiblie (5007)" => Fixes(&["T1685"]);
    DEF_007 = "DEF-007" : "Defender : règle ASR (1121, 1122)" => Aucune;
    DEF_008 = "DEF-008" : "Defender : accès contrôlé aux dossiers (1123, 1124)" => Aucune;
    DEF_009 = "DEF-009" : "Defender : protection réseau (1125, 1126)" => Aucune;
    DEF_010 = "DEF-010" : "Defender : protection en temps réel coupée (état WMI)" => Fixes(&["T1685"]);
    DEF_011 = "DEF-011" : "Defender : protection contre les falsifications désactivée (état WMI)" => Fixes(&["T1685"]);
    DEF_012 = "DEF-012" : "Defender : antivirus désactivé (état WMI)" => Fixes(&["T1685"]);
    LEU_001 = "LEU-001" : "leurre modifié, supprimé, renommé ou remplacé par un lien" => Fixes(&["T1486"]);
    LEU_002 = "LEU-002" : "leurre touché (audit des accès)" => Fixes(&["T1486"]);
    VOL_001 = "VOL-001" : "accès aux secrets d'un logiciel par un autre programme" => Fixes(&["T1555.003", "T1539"]);
    SYS_001 = "SYS-001" : "fichier hosts modifié par un autre programme" => Fixes(&["T1565"]);
    SYS_002 = "SYS-002" : "règle de pare-feu ajoutée ou modifiée" => Fixes(&["T1686.003"]);
    SYS_003 = "SYS-003" : "toutes les règles du pare-feu supprimées" => Fixes(&["T1686.003"]);
    PIL_001 = "PIL-001" : "pilote vulnérable connu présent" => Fixes(&["T1068"]);
    EXT_001 = "EXT-001" : "nouvelle extension de navigateur" => Fixes(&["T1176.001"]);
    VIE_001 = "VIE-001" : "programme qui utilise la caméra ou le micro pour la première fois" => ParLAlerte;
    VIE_002 = "VIE-002" : "outil de prise en main à distance en cours d'exécution" => ParLAlerte;
    VIE_003 = "VIE-003" : "Bureau à distance activé" => Fixes(&["T1021.001"]);
    BAS_001 = "BAS-001" : "réglage de sécurité de la baseline défait" => Fixes(&["T1685", "T1112"]);
    COR_R1 = "COR-R1" : "tentatives de mot de passe en série" => Fixes(&["T1110"]);
    COR_R2 = "COR-R2" : "session ouverte après une série d'échecs" => Fixes(&["T1110", "T1078.003"]);
    COR_R3 = "COR-R3" : "nouveau compte administrateur" => Fixes(&["T1136.001"]);
    COR_R3B = "COR-R3b" : "ajout d'un compte existant au groupe Administrateurs" => Fixes(&["T1098"]);
    COR_R4 = "COR-R4" : "journal d'événements effacé" => Fixes(&["T1685.005"]);
    COR_R5 = "COR-R5" : "service installé depuis un emplacement suspect" => Fixes(&["T1543.003", "T1569.002"]);
    COR_R6 = "COR-R6" : "attaque en plusieurs étapes" => Aucune;
    COR_R7 = "COR-R7" : "protection affaiblie" => ParLAlerte;
    COR_R9 = "COR-R9" : "session ouverte depuis une adresse publique" => Fixes(&["T1133"]);
    COR_R10 = "COR-R10" : "pilote vulnérable installé (BYOVD)" => Fixes(&["T1068"]);
    INT_001 = "INT-001" : "échec de la protection du dossier de données" => Aucune;
    INT_002 = "INT-002" : "tube de commandes déjà pris par un autre processus" => Aucune;
    INT_003 = "INT-003" : "dossier d'installation modifiable par un autre compte" => Aucune;
    SAN_001 = "SAN-001" : "collecte critique indisponible plus de 30 min" => Aucune;
    SAN_002 = "SAN-002" : "collecte rétablie" => Aucune;
    SAN_003 = "SAN-003" : "Defender (journal et état) illisible plus de 30 min" => Aucune;
    SAN_004 = "SAN-004" : "remontée des alertes en échec depuis plus d'une heure (constat local)" => Aucune;
    SAN_010 = "SAN-010" : "interface absente d'une session active plus de 15 min" => Aucune;
    SAN_011 = "SAN-011" : "interface arrêtée à répétition (3 fois en une heure)" => Aucune;
    SAN_012 = "SAN-012" : "alertes non suivies (plus de 500 incidents non clos)" => Aucune;
    REP_001 = "REP-001" : "action de réponse toujours en cours : relance, jamais une levée" => Aucune;
    REP_002 = "REP-002" : "boucle d'actions arrêtée : actions automatiques retenues par la garde" => Aucune;
    REP_003 = "REP-003" : "mode panique non posé ou non retiré : état effectif publié, jamais moitié posé" => Aucune;
    REP_004 = "REP-004" : "isolation détournée (le chemin isolé mène à un autre programme) ou non vérifiable ; règles gardées" => Aucune;
    EXP_IDS_001 = "EXP-IDS-001" : "IDS expérimental : règle au format Suricata (identifiant de la règle IDS dans les raisons)" => ParLAlerte;
    EXP_DPI_001 = "EXP-DPI-001" : "DPI expérimental" => ParLAlerte;
    EXP_NDR_001 = "EXP-NDR-001" : "NDR expérimental" => ParLAlerte;
}

/// Règle du registre portant cet identifiant
pub fn regle(id: &str) -> Option<&'static Regle> {
    REGLES.iter().find(|r| r.id == id)
}

/// Techniques d'une règle ; identifiant inconnu (alerte d'un modèle plus récent) : None
pub fn techniques(id: &str) -> Option<Techniques> {
    regle(id).map(|r| r.techniques)
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
