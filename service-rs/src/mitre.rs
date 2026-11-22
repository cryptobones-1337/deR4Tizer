//! Technique MITRE ATT&CK et conseil « Que faire ? » en français de chaque alerte, pour qu'un non-spécialiste sache
//! comment réagir. La technique vient de l'identifiant de règle (`regles.rs`, couverture ATT&CK, lot 2), jamais du texte ;
//! le conseil, lui, est encore choisi par mots-clés dans les raisons.

use crate::commun::Alerte;
use crate::regles::{self, Techniques};

/// Nom affiché de chaque technique posée par le service (ATT&CK v20.1) : « T1059.001 PowerShell ». L'interface traduit
/// chaque nom (Langue.cs, un test le vérifie) ; un identifiant absent de la table est affiché seul
pub const NOMS: &[(&str, &str)] = &[
    ("T1021", "Services distants"),
    ("T1021.001", "Bureau à distance"),
    ("T1027", "Code obscurci"),
    ("T1041", "Exfiltration par le canal de contrôle"),
    ("T1047", "WMI détourné"),
    ("T1048.003", "Exfiltration par un protocole non chiffré"),
    ("T1053.005", "Tâche planifiée"),
    ("T1059.001", "PowerShell"),
    ("T1069.001", "Découverte des groupes locaux"),
    ("T1068", "Élévation de privilèges par une faille (pilote vulnérable)"),
    ("T1071.001", "Communication par protocole web"),
    ("T1071.004", "Communication via DNS"),
    ("T1078.003", "Compte local valide"),
    ("T1098", "Manipulation de compte"),
    ("T1105", "Téléchargement d'outils"),
    ("T1110", "Force brute"),
    ("T1112", "Registre modifié"),
    ("T1123", "Capture audio"),
    ("T1125", "Capture vidéo"),
    ("T1133", "Services distants exposés"),
    ("T1136.001", "Compte local créé"),
    ("T1176.001", "Extension de navigateur"),
    ("T1187", "Authentification forcée"),
    ("T1197", "Tâches BITS"),
    ("T1200", "Matériel ajouté"),
    ("T1204.002", "Fichier piégé lancé par l'utilisateur"),
    ("T1218", "Binaire système détourné"),
    ("T1219", "Outil d'accès à distance"),
    ("T1486", "Chiffrement de données (rançongiciel)"),
    ("T1490", "Suppression des sauvegardes"),
    ("T1539", "Vol de cookies de session"),
    ("T1543.003", "Service Windows"),
    ("T1546.003", "Abonnement WMI"),
    ("T1547.001", "Clés Run et dossier Démarrage"),
    ("T1552", "Identifiants non protégés"),
    ("T1555.003", "Identifiants des navigateurs"),
    ("T1557", "Interception (adversaire au milieu)"),
    ("T1557.001", "Empoisonnement de la résolution de noms"),
    ("T1557.002", "Usurpation ARP"),
    ("T1557.003", "Serveur DHCP pirate"),
    ("T1565", "Manipulation de données"),
    ("T1566.001", "Pièce jointe piégée"),
    ("T1566.002", "Lien d'hameçonnage"),
    ("T1569.002", "Exécution par un service"),
    ("T1685", "Protections désactivées ou modifiées"),
    ("T1685.001", "Journalisation désactivée ou modifiée"),
    ("T1685.005", "Journaux d'événements effacés"),
    ("T1686.003", "Pare-feu de Windows modifié"),
];

/// Libellé d'une technique : identifiant suivi de son nom, ou l'identifiant seul s'il n'a pas de nom
pub fn libelle(id: &str) -> String {
    match NOMS.iter().find(|(i, _)| *i == id) {
        Some((i, n)) => format!("{i} {n}"),
        None => id.to_string(),
    }
}

/// Identifiants ATT&CK présents dans un texte (« T1557.002 », « T1059.001 / T1027 ») : jetons de la forme
/// T + 4 chiffres, avec une sous-technique éventuelle, dans l'ordre et sans doublon
pub fn identifiants_du_texte(texte: &str) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    for j in texte.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.')) {
        let j = j.trim_end_matches('.');
        let b = j.as_bytes();
        let base = b.len() >= 5 && b[0] == b'T' && b[1..5].iter().all(u8::is_ascii_digit);
        let sous = b.len() == 5 || (b.len() == 9 && b[5] == b'.' && b[6..9].iter().all(u8::is_ascii_digit));
        if base && sous && !v.iter().any(|x| x == j) {
            v.push(j.to_string());
        }
    }
    v
}

/// Décision pure (testée) : identifiants des techniques d'une alerte, d'après sa règle. Liste fixe de la table ; règle
/// à plusieurs comportements : ceux que le code a posés dans l'alerte ; aucune technique : vide. Règle inconnue
/// (modèle plus récent) : ceux de l'alerte, tels quels
pub fn identifiants(a: &Alerte) -> Vec<String> {
    identifiants_de_regle(&a.regle, &a.mitre)
}

/// Même décision, d'après l'identifiant de règle et les techniques posées par le code
pub fn identifiants_de_regle(regle: &str, mitre: &str) -> Vec<String> {
    match regles::techniques(regle) {
        Some(Techniques::Fixes(t)) => t.iter().map(|s| s.to_string()).collect(),
        Some(Techniques::ParLAlerte) | None => identifiants_du_texte(mitre),
        Some(Techniques::Aucune) => Vec::new(),
    }
}

/// (mots-clés tous présents dans les raisons, conseil) — le premier qui correspond l'emporte. Ne pose plus aucune technique
const CONSEILS: &[(&[&str], &str)] = &[
    (&["leurre"],
     "Cliquez sur PANIQUE pour couper Internet, puis éteignez le PC si des fichiers changent d'extension. Ne payez pas : contactez un professionnel et restaurez vos sauvegardes."),
    (&["chaîne d'attaque"],
     "Tuez la chaîne (bouton « Agir » de l'alerte : tuer le processus et ses enfants), mettez le dernier programme en quarantaine, puis lancez une analyse hors ligne de Microsoft Defender."),
    (&["voleur de données"],
     "Mettez le programme en quarantaine, puis depuis un AUTRE appareil : changez vos mots de passe importants et déconnectez toutes les sessions (Google, Discord, Telegram, banque)."),
    (&["menace connue"],
     "Le programme parle à un serveur connu pour piloter des malwares. Isolez-le du réseau, mettez-le en quarantaine et lancez une analyse hors ligne de Defender."),
    (&["domaine malveillant"],
     "Un programme a cherché un domaine malveillant ou d'hameçonnage. Si vous venez de cliquer sur un lien, ne saisissez aucun mot de passe ; sinon identifiez le programme dans Connexions."),
    (&["defender", "exclusion"],
     "Ouvrez Sécurité Windows > Protection contre les virus > Exclusions et supprimez l'exclusion si vous ne l'avez pas ajoutée vous-même."),
    (&["defender", "désactiv"],
     "Réactivez la protection dans Sécurité Windows. Si elle se recoupe toute seule, un malware est probablement actif : analyse hors ligne de Defender."),
    (&["defender", "coupée"], "Réactivez la protection en temps réel dans Sécurité Windows."),
    (&["defender a détecté"], "Vérifiez dans Sécurité Windows > Historique de protection que la menace a bien été supprimée ou mise en quarantaine."),
    (&["pilote vulnérable"],
     "Un pilote connu pour permettre de désactiver les antivirus est présent. Identifiez le logiciel qui l'a installé et désinstallez-le ; activez la règle ASR « pilotes vulnérables » (page Baseline)."),
    (&["prise en main à distance"],
     "Si vous n'avez pas lancé cet outil vous-même (ou si quelqu'un au téléphone vous l'a demandé), cliquez sur PANIQUE : c'est le scénario des arnaques au faux support technique."),
    (&["exposé à internet"],
     "Le PC est joignable depuis Internet. Dans l'interface de votre box, désactivez la DMZ, l'UPnP et les redirections de ports que vous ne connaissez pas ; isolez le programme qui écoute s'il vous est inconnu."),
    (&["pare-feu", "toutes"],
     "Toutes les règles ont disparu : réinitialisez le pare-feu (Sécurité Windows > Pare-feu > Restaurer les paramètres par défaut) et lancez une analyse hors ligne de Defender."),
    (&["pare-feu"],
     "Si vous ne reconnaissez pas le programme auteur ni la règle, supprimez la règle (wf.msc) et mettez le programme en quarantaine."),
    (&["connexion entrante"],
     "Quelqu'un se connecte à ce PC depuis Internet. Si vous n'attendez rien de tel, isolez le programme concerné."),
    (&["powershell obscurci"], "Code PowerShell caché ou téléchargé : tuez le processus et regardez son parent dans Connexions ou dans la chaîne."),
    (&["lolbin"], "Un outil de Windows est détourné pour lancer du code. Tuez le processus et identifiez ce qui l'a lancé."),
    (&["document", "lance"],
     "Un document a lancé un programme : refermez-le sans activer les macros, tuez la chaîne et supprimez la pièce jointe."),
    (&["sauvegardes"], "Typique d'un rançongiciel juste avant le chiffrement : cliquez sur PANIQUE et éteignez le PC."),
    (&["balise"],
     "Le programme contacte la même adresse à intervalle régulier, comme un RAT qui attend ses ordres. Vérifiez qu'il s'agit d'un logiciel que vous connaissez."),
    (&["démarrage automatique"],
     "Si vous ne reconnaissez pas cette entrée, ouvrez l'emplacement du fichier, mettez-le en quarantaine et désactivez l'entrée (Autoruns ou Gestionnaire des tâches)."),
    (&["extension"],
     "Si vous n'avez pas installé cette extension, supprimez-la depuis la page des extensions du navigateur."),
    (&["caméra"], "Si vous ne reconnaissez pas ce programme, fermez-le et mettez-le en quarantaine."),
    // « utilise le micro » (VIE-001) et non « micro » seul, qui se trouve aussi dans « microsoft » : toute destination de
    // Microsoft recevait la technique T1123 et son conseil (vu sur les captures de l'interface, 2026-11-12)
    (&["utilise le micro"], "Si vous ne reconnaissez pas ce programme, fermez-le et mettez-le en quarantaine."),
    (&["fichier hosts"], "Ouvrez le fichier hosts (C:\\Windows\\System32\\drivers\\etc\\hosts) et retirez les lignes que vous n'avez pas ajoutées."),
    (&["baseline"], "Un réglage de sécurité a été défait. Réappliquez-le depuis la page Baseline et cherchez quel programme l'a modifié."),
    (&["ip directe"], "Les malwares contactent souvent une IP en dur. Vérifiez le programme ; isolez-le s'il est inconnu."),
    (&["non signé"], "Programme sans signature d'éditeur : vérifiez son origine (page Connexions, raisons de la ligne)."),
];

pub fn enrichir(a: &mut Alerte) {
    a.mitre = identifiants(a).iter().map(|i| libelle(i)).collect::<Vec<_>>().join(" / ");
    let texte = format!("{} {}", a.raisons, a.destination).to_lowercase();
    if let Some((_, conseil)) = CONSEILS.iter().find(|(mots, _)| mots.iter().all(|m| texte.contains(m))) {
        a.conseil = conseil.to_string();
    }
}
