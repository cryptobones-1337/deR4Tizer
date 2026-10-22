//! Rattache chaque alerte à une technique MITRE ATT&CK et à un conseil « Que faire ? » en français,
//! pour qu'un non-spécialiste sache comment réagir.

use crate::commun::Alerte;

/// (mots-clés tous présents dans les raisons, technique, conseil) — la première règle qui correspond l'emporte
const REGLES: &[(&[&str], &str, &str)] = &[
    (&["leurre"], "T1486 Chiffrement de données (rançongiciel)",
     "Cliquez sur PANIQUE pour couper Internet, puis éteignez le PC si des fichiers changent d'extension. Ne payez pas : contactez un professionnel et restaurez vos sauvegardes."),
    (&["chaîne d'attaque"], "T1204 Exécution par l'utilisateur",
     "Tuez la chaîne (clic droit), mettez le dernier programme en quarantaine, puis lancez une analyse hors ligne de Microsoft Defender."),
    (&["voleur de données"], "T1555 Identifiants des navigateurs / T1539 Vol de cookies de session",
     "Mettez le programme en quarantaine, puis depuis un AUTRE appareil : changez vos mots de passe importants et déconnectez toutes les sessions (Google, Discord, Telegram, banque)."),
    (&["menace connue"], "T1071 Communication avec un serveur de contrôle",
     "Le programme parle à un serveur connu pour piloter des malwares. Isolez-le du réseau, mettez-le en quarantaine et lancez une analyse hors ligne de Defender."),
    (&["domaine malveillant"], "T1071.004 Communication via DNS / T1566 Hameçonnage",
     "Un programme a cherché un domaine malveillant ou d'hameçonnage. Si vous venez de cliquer sur un lien, ne saisissez aucun mot de passe ; sinon identifiez le programme dans Connexions."),
    (&["defender", "exclusion"], "T1562.001 Affaiblissement des défenses",
     "Ouvrez Sécurité Windows > Protection contre les virus > Exclusions et supprimez l'exclusion si vous ne l'avez pas ajoutée vous-même."),
    (&["defender", "désactiv"], "T1562.001 Affaiblissement des défenses",
     "Réactivez la protection dans Sécurité Windows. Si elle se recoupe toute seule, un malware est probablement actif : analyse hors ligne de Defender."),
    (&["defender", "coupée"], "T1562.001 Affaiblissement des défenses", "Réactivez la protection en temps réel dans Sécurité Windows."),
    (&["defender a détecté"], "Détection antivirus", "Vérifiez dans Sécurité Windows > Historique de protection que la menace a bien été supprimée ou mise en quarantaine."),
    (&["pilote vulnérable"], "T1068 Élévation de privilèges / BYOVD",
     "Un pilote connu pour permettre de désactiver les antivirus est présent. Identifiez le logiciel qui l'a installé et désinstallez-le ; activez la règle ASR « pilotes vulnérables » (onglet Baseline)."),
    (&["prise en main à distance"], "T1219 Logiciel d'accès à distance",
     "Si vous n'avez pas lancé cet outil vous-même (ou si quelqu'un au téléphone vous l'a demandé), cliquez sur PANIQUE : c'est le scénario des arnaques au faux support technique."),
    (&["exposé à internet"], "T1133 Services distants exposés",
     "Le PC est joignable depuis Internet. Dans l'interface de votre box, désactivez la DMZ, l'UPnP et les redirections de ports que vous ne connaissez pas ; isolez le programme qui écoute s'il vous est inconnu."),
    (&["pare-feu", "toutes"], "T1562.004 Désactivation du pare-feu",
     "Toutes les règles ont disparu : réinitialisez le pare-feu (Sécurité Windows > Pare-feu > Restaurer les paramètres par défaut) et lancez une analyse hors ligne de Defender."),
    (&["pare-feu"], "T1562.004 Modification du pare-feu",
     "Si vous ne reconnaissez pas le programme auteur ni la règle, supprimez la règle (wf.msc) et mettez le programme en quarantaine."),
    (&["connexion entrante"], "T1133 Services distants exposés",
     "Quelqu'un se connecte à ce PC depuis Internet. Si vous n'attendez rien de tel, isolez le programme concerné."),
    (&["powershell obscurci"], "T1059.001 PowerShell", "Code PowerShell caché ou téléchargé : tuez le processus et regardez son parent dans Connexions ou dans la chaîne."),
    (&["lolbin"], "T1218 Exécution par un binaire système détourné", "Un outil de Windows est détourné pour lancer du code. Tuez le processus et identifiez ce qui l'a lancé."),
    (&["document", "lance"], "T1566.001 Pièce jointe piégée / T1204.002",
     "Un document a lancé un programme : refermez-le sans activer les macros, tuez la chaîne et supprimez la pièce jointe."),
    (&["sauvegardes"], "T1490 Suppression des sauvegardes", "Typique d'un rançongiciel juste avant le chiffrement : cliquez sur PANIQUE et éteignez le PC."),
    (&["balise"], "T1071 Communication périodique (beaconing)",
     "Le programme contacte la même adresse à intervalle régulier, comme un RAT qui attend ses ordres. Vérifiez qu'il s'agit d'un logiciel que vous connaissez."),
    (&["démarrage automatique"], "T1547 Démarrage automatique / T1053 Tâche planifiée",
     "Si vous ne reconnaissez pas cette entrée, ouvrez l'emplacement du fichier, mettez-le en quarantaine et désactivez l'entrée (Autoruns ou Gestionnaire des tâches)."),
    (&["extension"], "T1176 Extension de navigateur",
     "Si vous n'avez pas installé cette extension, supprimez-la depuis la page des extensions du navigateur."),
    (&["caméra"], "T1125 Capture vidéo", "Si vous ne reconnaissez pas ce programme, fermez-le et mettez-le en quarantaine."),
    (&["micro"], "T1123 Capture audio", "Si vous ne reconnaissez pas ce programme, fermez-le et mettez-le en quarantaine."),
    (&["fichier hosts"], "T1565 Manipulation de données", "Ouvrez le fichier hosts (C:\\Windows\\System32\\drivers\\etc\\hosts) et retirez les lignes que vous n'avez pas ajoutées."),
    (&["baseline"], "T1562 Affaiblissement des défenses", "Un réglage de sécurité a été défait. Réappliquez-le depuis l'onglet Baseline et cherchez quel programme l'a modifié."),
    (&["ip directe"], "T1071 Communication sans résolution DNS", "Les malwares contactent souvent une IP en dur. Vérifiez le programme ; isolez-le s'il est inconnu."),
    (&["non signé"], "T1036 Programme inconnu", "Programme sans signature d'éditeur : vérifiez son origine (onglet Connexions, colonne Raisons)."),
];

pub fn enrichir(a: &mut Alerte) {
    let texte = format!("{} {}", a.raisons, a.destination).to_lowercase();
    if let Some((_, technique, conseil)) = REGLES.iter().find(|(mots, _, _)| mots.iter().all(|m| texte.contains(m))) {
        a.mitre = technique.to_string();
        a.conseil = conseil.to_string();
    }
}
