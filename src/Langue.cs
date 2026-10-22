// Langue de l'interface : le texte français sert de clé, la traduction anglaise est cherchée ici.
// Un texte absent du dictionnaire reste en français (ajoutez-le ici pour le traduire).
using System.Collections.Generic;

namespace DeR4Tizer
{
    static class L
    {
        public static bool En;

        public static string T(string fr)
        {
            string en;
            return En && fr != null && Anglais.TryGetValue(fr, out en) ? en : fr;
        }

        static readonly Dictionary<string, string> Anglais = new Dictionary<string, string>
        {
            // Navigation et pages
            { "Connexions", "Connections" }, { "Alertes", "Alerts" }, { "Chaînes", "Chains" }, { "Vie privée", "Privacy" },
            { "Pare-feu", "Firewall" }, { "Démarrage auto", "Autostart" }, { "Baseline", "Baseline" }, { "Extensions", "Extensions" },
            { "Blocages", "Blocks" }, { "Quarantaine", "Quarantine" }, { "Menaces", "Threats" }, { "Réglages", "Settings" },
            { "Chaînes de processus", "Process chains" }, { "Vie privée et accès", "Privacy and access" },
            { "Pare-feu et exposition à Internet", "Firewall and Internet exposure" }, { "Démarrage automatique", "Autostart" },
            { "Baseline de sécurité", "Security baseline" }, { "Extensions de navigateur", "Browser extensions" },
            { "Menaces et réponses automatiques", "Threats and automatic responses" },
            { "Flux sortants en direct. Survolez une ligne pour le chemin, la ligne de commande et l'origine du fichier ; clic droit pour bloquer ou réagir.",
              "Live outbound flows. Hover a row for the path, command line and file origin; right-click to block or respond." },
            { "Critique : menace avérée. Alerte : comportement suspect. Info : première fois qu'un programme fait quelque chose.",
              "Critical: confirmed threat. Alert: suspicious behaviour. Info: first time a program does something." },
            { "Qui a lancé quoi. Le score s'additionne sur toute la chaîne : une suite d'actions banales une à une devient visible. Alerte au-delà de 12.",
              "Who launched what. The score adds up along the chain: a series of individually harmless actions becomes visible. Alert above 12." },
            { "Caméra, micro, prise en main à distance et ports ouverts sur le réseau.", "Camera, microphone, remote control and ports open to the network." },
            { "Paquets entrants venus d'Internet (journal du pare-feu) et changements de règles avec le programme qui les a faits.",
              "Inbound packets from the Internet (firewall log) and rule changes with the program that made them." },
            { "Tout ce qui se lance avec Windows. Une entrée nouvelle ou modifiée déclenche une alerte.",
              "Everything that starts with Windows. A new or modified entry raises an alert." },
            { "Inspirée des baselines Intune et Microsoft, appliquée par la stratégie de groupe locale. La journalisation est appliquée automatiquement ; le reste à votre demande.",
              "Inspired by the Intune and Microsoft baselines, applied through local Group Policy. Logging is applied automatically; the rest on request." },
            { "Une extension avec des permissions sensibles peut lire vos pages, vos cookies ou vos saisies. Une nouvelle extension déclenche une alerte.",
              "An extension with sensitive permissions can read your pages, cookies or keystrokes. A new extension raises an alert." },
            { "Domaines redirigés vers 127.0.0.1 (fichier hosts), IP bloquées et programmes isolés au pare-feu.",
              "Domains redirected to 127.0.0.1 (hosts file), IPs blocked and programs isolated at the firewall." },
            { "Fichiers retirés de leur emplacement et rendus inexécutables. Ils peuvent être restaurés.",
              "Files removed from their location and made non-executable. They can be restored." },
            { "Listes open source téléchargées toutes les 12 h par le service, et réactions automatiques.",
              "Open-source lists downloaded every 12 h by the service, and automatic responses." },
            { "Langue, envoi des alertes à un SIEM (syslog), API d'export et export des journaux.",
              "Language, alert forwarding to a SIEM (syslog), export API and log export." },

            // Colonnes
            { "Score", "Score" }, { "Programme", "Program" }, { "Lancé par", "Parent" }, { "PID", "PID" }, { "Destination", "Destination" },
            { "Port", "Port" }, { "Signataire", "Signer" }, { "Vu depuis", "Seen since" }, { "Vue depuis", "Seen since" }, { "Raisons", "Reasons" },
            { "Heure", "Time" }, { "Niveau", "Level" }, { "Chemin", "Path" }, { "Processus", "Process" }, { "Ligne de commande", "Command line" },
            { "Élément", "Item" }, { "Détail", "Detail" }, { "Depuis / dernière fois", "Since / last time" }, { "Quand", "When" },
            { "Catégorie", "Category" }, { "Nom", "Name" }, { "Commande", "Command" }, { "Remarque", "Note" }, { "Règle", "Rule" },
            { "État", "State" }, { "Actuel", "Current" }, { "Attendu", "Expected" }, { "Compatibilité", "Compatibility" },
            { "Navigateur", "Browser" }, { "Extension", "Extension" }, { "Version", "Version" }, { "Permissions", "Permissions" },
            { "Type", "Type" }, { "Cible", "Target" }, { "Raison", "Reason" }, { "Date", "Date" }, { "Fichier d'origine", "Original file" },
            { "Taille", "Size" }, { "Source", "Source" }, { "Confiance", "Confidence" }, { "Entrées", "Entries" }, { "Mise à jour", "Updated" },
            { "Statut", "Status" },

            // Boutons, cases, menus
            { "Démarrer le service", "Start the service" }, { "◉ PANIQUE : couper Internet", "◉ PANIC: cut the Internet" },
            { "Journal du service", "Service log" }, { "Dossier des données", "Data folder" },
            { "Appliquer le profil recommandé", "Apply recommended profile" }, { "Appliquer le profil renforcé…", "Apply hardened profile…" },
            { "Appliquer la sélection", "Apply selection" }, { "Annuler la sélection", "Revert selection" }, { "Tout annuler", "Revert all" },
            { "Réévaluer", "Re-evaluate" }, { "Débloquer la sélection", "Unblock selection" }, { "Tout débloquer", "Unblock all" },
            { "Bloquer la télémétrie…", "Block telemetry…" }, { "Bloquer", "Block" }, { "Restaurer la sélection", "Restore selection" },
            { "Mettre à jour maintenant", "Update now" },
            { "Masquer les entrées signées Microsoft / Windows", "Hide entries signed by Microsoft / Windows" },
            { "Bloquer automatiquement au pare-feu les IP des listes de confiance haute", "Automatically block high-confidence list IPs at the firewall" },
            { "Suspendre automatiquement un programme qui touche aux fichiers leurres (rançongiciel)", "Automatically suspend a program that touches canary files (ransomware)" },
            { "Bloquer (nom dans le fichier hosts, sinon IP au pare-feu)", "Block (name in hosts file, otherwise IP at the firewall)" },
            { "Bloquer l'IP au pare-feu", "Block the IP at the firewall" }, { "Bloquer cette destination", "Block this destination" },
            { "Isoler ce programme du réseau", "Isolate this program from the network" }, { "Suspendre le processus", "Suspend the process" },
            { "Reprendre le processus", "Resume the process" }, { "Tuer le processus", "Kill the process" },
            { "Tuer le processus et ses enfants", "Kill the process and its children" },
            { "Tuer ce processus et toute sa descendance", "Kill this process and all its descendants" },
            { "Mettre le programme en quarantaine", "Quarantine the program" }, { "Mettre la cible en quarantaine", "Quarantine the target" },
            { "Ouvrir l'emplacement du programme", "Open program location" }, { "Ouvrir l'emplacement du fichier", "Open file location" },
            { "Copier", "Copy" }, { "Ouvrir", "Open" }, { "Quitter", "Quit" },
            { "Sélectionnez une alerte pour voir la technique d'attaque et quoi faire.", "Select an alert to see the attack technique and what to do." },
            { "L'interface reste dans la zone de notification. Le service, lui, tourne en permanence.",
              "The interface stays in the notification area. The service keeps running at all times." },

            // Événements (mini-SIEM)
            { "Événements", "Events" }, { "Rechercher", "Search" }, { "Toutes les sources", "All sources" }, { "Tous niveaux", "All levels" },
            { "1 heure", "1 hour" }, { "24 heures", "24 hours" }, { "7 jours", "7 days" }, { "30 jours", "30 days" }, { "Recherche…", "Searching…" },
            { "Incident", "Incident" }, { "Résumé", "Summary" }, { "Utilisateur", "User" }, { "Chercher cette valeur", "Search this value" },
            { "Sélectionnez un incident ou un événement pour voir le détail.", "Select an incident or an event to see the details." },
            { "Mini-SIEM local : sessions, comptes, processus, services, connexions, pare-feu et alertes, conservés 30 jours. Les règles de corrélation lèvent des incidents.",
              "Local mini-SIEM: logons, accounts, processes, services, connections, firewall and alerts, kept for 30 days. Correlation rules raise incidents." },

            // Trafic, réseau local, détection
            { "Trafic", "Traffic" }, { "Réseau local", "Local network" }, { "Détection", "Detection" },
            { "Analyse passive des paquets de ce PC depuis minuit. Pays d'enregistrement des adresses (registres Internet régionaux) ; les arcs montrent les échanges des 10 dernières secondes.",
              "Passive analysis of this PC's packets since midnight. Country where addresses are registered (regional Internet registries); arcs show exchanges in the last 10 seconds." },
            { "Pas encore de données de trafic (le service capture les paquets au démarrage).", "No traffic data yet (the service captures packets at startup)." },
            { "Reçu", "Received" }, { "Envoyé", "Sent" }, { "Destinations", "Destinations" }, { "Pays", "Country" }, { "Volume", "Volume" }, { "Programmes", "Programs" },
            { "Surveillance passive de la carte reliée à la box (même avec un VPN) : usurpation ARP, serveur DHCP pirate, empoisonnement LLMNR/NBNS (Responder). Un leurre interroge toutes les 10 minutes un nom qui n'existe pas : personne ne doit répondre.",
              "Passive monitoring of the adapter connected to the router (even with a VPN): ARP spoofing, rogue DHCP server, LLMNR/NBNS poisoning (Responder). A decoy queries a non-existent name every 10 minutes: nobody should answer." },
            { "Pas encore de données (le service analyse le réseau au démarrage).", "No data yet (the service analyses the network at startup)." },
            { "Adresse IP", "IP address" }, { "Première vue", "First seen" }, { "Dernière vue", "Last seen" },
            { "Appareils du réseau local", "Local network devices" }, { "Passerelle (box)", "Gateway (router)" }, { "Appareil", "Device" },
            { "Serveurs DHCP vus", "DHCP servers seen" }, { "Serveur DHCP", "DHCP server" }, { "Serveur DHCP PIRATE", "ROGUE DHCP server" },
            { "serveur de cette interface", "server of this interface" }, { "n'est pas le serveur de cette interface", "is not this interface's server" },
            { "Répondeurs LLMNR / NBNS / mDNS", "LLMNR / NBNS / mDNS responders" },
            { "IDS/IPS : règles au format Suricata (intégrées + fichiers .rules du dossier des règles, par exemple Emerging Threats Open). DPI : nom des sites TLS (SNI), empreintes des clients TLS (JA3, liste SSLBL d'abuse.ch), requêtes HTTP en clair et DNS.",
              "IDS/IPS: Suricata-format rules (built-in + .rules files in the rules folder, e.g. Emerging Threats Open). DPI: TLS site names (SNI), TLS client fingerprints (JA3, abuse.ch SSLBL list), cleartext HTTP and DNS requests." },
            { "Détections IDS", "IDS detections" }, { "Sessions TLS (SNI, JA3)", "TLS sessions (SNI, JA3)" }, { "Requêtes HTTP en clair", "Cleartext HTTP requests" },
            { "Requêtes DNS", "DNS requests" }, { "Empreintes JA3", "JA3 fingerprints" }, { "Dossier des règles", "Rules folder" },
            { "IPS : bloquer au pare-feu l'adresse distante des règles « drop » ou de priorité 1", "IPS: block at the firewall the remote address of \"drop\" or priority-1 rules" },
            { "Message", "Message" }, { "Bloqué", "Blocked" }, { "oui", "yes" }, { "Site (SNI)", "Site (SNI)" }, { "Hôte et chemin", "Host and path" },
            { "Nom demandé", "Requested name" }, { "Serveur DNS", "DNS server" }, { "Empreinte JA3", "JA3 fingerprint" }, { "Sessions", "Sessions" },

            // Accès aux données
            { "ACCÈS AUX DONNÉES", "DATA ACCESS" }, { "Autoriser un autre compte…", "Authorise another account…" }, { "Autoriser", "Authorise" },
            { "Les événements, sessions, alertes et appareils du réseau ne sont lisibles que par SYSTEM, les administrateurs et ces comptes :",
              "Events, sessions, alerts and network devices can only be read by SYSTEM, administrators and these accounts:" },
            { "Nom du compte (par exemple : PC-ACCUEIL\\marie)", "Account name (for example: FRONT-DESK\\marie)" }, { "Compte introuvable.", "Account not found." },

            // Réglages
            { "LANGUE", "LANGUAGE" }, { "Langue de l'interface", "Interface language" },
            { "La langue s'applique au prochain lancement de l'interface.", "The language applies the next time the interface starts." },
            { "ENVOI DES ALERTES (SYSLOG)", "ALERT FORWARDING (SYSLOG)" },
            { "Envoyer les alertes à un serveur syslog / SIEM", "Send alerts to a syslog server / SIEM" },
            { "Serveur", "Server" }, { "Protocole", "Protocol" }, { "Format", "Format" }, { "Niveau minimal", "Minimum level" },
            { "JSON : en-tête RFC 5424 et détail en JSON. CEF : reconnu par la plupart des SIEM (Splunk, QRadar, Sentinel, Wazuh, Graylog…).",
              "JSON: RFC 5424 header with JSON detail. CEF: understood by most SIEMs (Splunk, QRadar, Sentinel, Wazuh, Graylog…)." },
            { "API D'EXPORT (HTTP, LECTURE SEULE)", "EXPORT API (HTTP, READ-ONLY)" },
            { "Activer l'API d'export", "Enable the export API" },
            { "Accessible depuis le réseau local (sinon cet ordinateur seulement)", "Reachable from the local network (otherwise this computer only)" },
            { "Afficher le jeton", "Show token" }, { "Nouveau jeton", "New token" },
            { "Chaque requête doit porter l'en-tête « Authorization: Bearer <jeton> ». Routes : /api/v1/alertes, /connexions, /exposition, /baseline, /regles-parefeu, /blocages, /journal.",
              "Every request must carry the header \"Authorization: Bearer <token>\". Routes: /api/v1/alertes, /connexions, /exposition, /baseline, /regles-parefeu, /blocages, /journal." },
            { "EXPORT DES JOURNAUX", "LOG EXPORT" }, { "Exporter les alertes…", "Export alerts…" }, { "Exporter le journal du service…", "Export service log…" },
            { "Enregistrer", "Save" }, { "Tester l'envoi", "Send test" },
            { "Remplacer le jeton ? Les outils qui utilisent l'ancien devront être mis à jour.", "Replace the token? Tools using the old one will have to be updated." },
            { "Réglages enregistrés.", "Settings saved." },
            { "Indiquez le serveur syslog.", "Enter the syslog server." },
        };
    }
}
