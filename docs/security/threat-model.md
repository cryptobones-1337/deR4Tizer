# Modèle de menaces de deR4Tizer

État au 2026-10-24 (`main`, commit `1cf04fe`, version 4.3). Les mesures citées renvoient au code et, quand elles sont prouvées en
conditions réelles, aux scénarios de CI (`docs/roadmap/capability-matrix.md`).

## Frontières de privilège

| Frontière | Côté privilégié | Côté exposé | Mesures | Preuve |
|---|---|---|---|---|
| Service | `deR4TizerSvc.exe`, compte SYSTEM | Tout le reste du poste | Aucun pilote noyau ; `panic = "abort"` (un index hors limites arrête le service au lieu de le corrompre) et mini-fuzz des parseurs. Diagnostic d'exposition (U5c-1) : lecture seule de la politique du pare-feu (INetFwPolicy2 : profils actifs, état, action entrante par défaut), sans écriture ; textes publiés bornés (200 caractères, sans caractère de contrôle). | `cargo test` (mini-fuzz, `structure_diagnostic_lecture_seule`) |
| Interface | Service | `deR4Tizer.exe`, sans droits d'administrateur | L'interface lit l'état (fichiers JSON du dossier de données, lecture seule) ; toute action passe par le canal, donc par un administrateur (UAC). Depuis la bascule (B1), la coquille WPF est l'interface par défaut ; l'assistant élevé (`--commande-fichier`) sort avant le mutex et ne charge jamais WPF (mode décidé par une fonction pure, pilote dans une méthode jamais intégrée). Seconde instance (B2) : un événement de la session (`Local\deR4Tizer.Interface.Montrer`) demande à l'interface déjà ouverte de se montrer ; il ne porte aucune donnée, et un programme de la session qui le signale ne peut que faire apparaître la fenêtre (au plus quelques fois par seconde) ; s'il le précrée, quels qu'en soient les droits ou le mode, la première instance ne l'écoute pas et la seconde redevient muette ; le droit de passer au premier plan n'est accordé qu'au PID de la première instance (même nom, même session, même exécutable), jamais à tout processus (audit de #158). Premiers réglages (U7a, U7b, U7c) : trois commandes seulement, celles des pages Réglages et Menaces (apprentissage, deux réponses automatiques de niveau 3, message de test des notifications avec les réglages relus au clic et sans secret ; le service applique ces réglages avant d'envoyer le test, d'où la relecture au clic et la confirmation en administrateur, aussi depuis la page Réglages : audit de #154, S154-01), par le canal donc confirmées ; une interface déjà élevée les fait confirmer par Canal, comme toute commande « config » ou « apprentissage » depuis l'audit de #152 (S152-02 : avant, les pages Réglages, Menaces et Détection d'une interface élevée les envoyaient en un clic), et comme la levée d'un blocage, les réglages syslog et API, les notifications, la mise à jour l'autorisation d'un compte lecteur (audit de #153, S153-01) et l'exception durable « Ne plus alerter pour ce comportement » (S153-02) ; seul fichier écrit par l'interface, un repère par utilisateur dans `%LOCALAPPDATA%\deR4Tizer` qui veut dire « déjà proposés » : un programme du compte qui l'efface ou le crée ne fait que reproposer ou taire l'assistant, jamais changer un réglage. Une interface lancée en administrateur n'écrit jamais ce repère, dans un dossier que les programmes non élevés du compte contrôlent (jonction, lien : audit de #151, S151-01) ; `derniere-alerte-lue.txt` (même dossier) n'est plus écrit non plus par une interface élevée : la dernière alerte lue y reste en mémoire. | 3a (compte standard refusé) |
| Canal de commandes `\\.\pipe\deR4Tizer` | Service | Processus locaux | Réservé à SYSTEM et aux administrateurs ; première instance créée avec `FILE_FLAG_FIRST_PIPE_INSTANCE`, une instance toujours ouverte ; l'interface et le script de mise à jour vérifient que le serveur du tube est le processus du service. Phase 1 : débit borné, client identifié sur le jeton de son processus, autorisation par commande et validation de chaque champ avant toute exécution ; noms écrits dans le fichier hosts validés (plus d'injection de ligne). | 3a ; `lot2_canal_code_de_production_sur_un_vrai_tube` |
| API d'export (HTTP) | Service | Réseau local (si activé) ou 127.0.0.1 | Désactivée par défaut ; lecture seule ; jeton (`api-jeton.txt`, SYSTEM et administrateurs) ; sur le réseau, adresses autorisées obligatoires (IPv4 exacte ou /8 à /32, validées avant d'aller dans la règle de pare-feu) et règle de pare-feu (profils Domaine et Privé, Public bloqué) ; requête lue en 10 s au plus. **En clair** (HTTP) : sur le réseau, jeton et données passent en clair (risque résiduel, comme syslog). | 3a (port témoin) ; `api_adresses_autorisees` |
| Installation interactive (U8a) | Installeur (SYSTEM pour les actions différées) | Session de l'utilisateur qui installe | Aucune action de l'interface du MSI ne lance de programme : la dernière page affiche un texte (affectations de propriété, type 51), sans case « Lancer » ; l'interface est démarrée par la tâche de relance, sans élévation. Lancée depuis l'installeur, elle aurait pu tourner élevée et garder le mutex de la session. | `tests/test-msi.ps1` (sources et paquet) ; 3a (interface venue de la tâche, jeton non élevé) |
| Mise à jour automatique | Service (installe un MSI en SYSTEM) | Serveur de publication (GitHub), réseau | Manifeste strict ; empreinte SHA-256 ; signature Authenticode avec révocation ; clé publique du signataire comparée aux clés épinglées dans le binaire ; version lue dans le paquet signé ; dossier de travail réservé à SYSTEM ; retour arrière par le MSI de la version installée, lui aussi vérifié. Installation automatique désactivée par défaut. | `lot2_*` ; 3c en Windows Sandbox seulement (jamais en CI) |
| Dossier de données `C:\ProgramData\deR4Tizer` | Service | Comptes locaux | Créé avec ses droits (MSI et service) ; propriétaire et droits imposés et vérifiés au démarrage ; éléments d'un autre propriétaire mis de côté, jamais lus ; échec fermé (configuration et secrets ignorés). | 3a |
| Opérations de fichiers SYSTEM sur des chemins de l'utilisateur (quarantaine, restauration) | Service | Utilisateur propriétaire du chemin | Ouverture par handle sans suivre de lien, chemin final vérifié ; restauration sous l'identité de l'utilisateur, jamais en SYSTEM à l'emplacement d'origine ; repli dans le dossier du service. | 3b |
| Capture réseau | Service (socket brute) | Tout paquet reçu par le poste | Parseurs bornés et testés (mini-fuzz) ; règle « deR4Tizer capture » nécessaire (tout l'entrant vers le service) ; le service n'écoute aucun port, sauf l'API facultative. | `cargo test` (mini-fuzz) |
| Remontée des alertes | Service | ntfy, Teams, serveur SMTP | Secrets réservés aux administrateurs, gardés en mémoire du service entre deux envois (fichier retiré : ntfy et Teams coupés au tour suivant, un serveur SMTP sans compte reste joignable ; modifié à la main : pas adopté avant le prochain réglage ou redémarrage) ; envois par `curl.exe` de Windows (HTTPS, SMTP avec TLS). | `notifications_*` |
| Export syslog | Service | Réseau | **En clair** (UDP ou TCP, sans TLS). | — |

### Résolveur DNS local (phase 7, PR 7.3 : essai seulement, non branché sur les cartes)

Dans le code (`dns_local.rs`), mécanisme M2 du dossier (D7-1 : recommandation appliquée, révisable par le mainteneur
avant 7.4). En 7.3, il n'écoute que pendant un **essai de 10 minutes** lancé par un administrateur (commande
`filtrageEssai`) ; aucune carte n'est réglée sur lui. C'est la première écoute réseau du service en dehors de l'API
facultative, et le premier analyseur de requêtes et de réponses DNS non fiables en SYSTEM (avec `panic = "abort"`).
État des exigences écrites avant le code (audit de #157, S157-01 ; dossier de la phase 7, section 6) :
- écoute sur `127.0.0.1` et `::1` seulement, jamais sur une carte réseau, et double contrôle de l'adresse du client :
  **tenu** (preuve : `Get-NetUDPEndpoint` et `Get-NetTCPConnection` dans le cas 3a) ;
- liaison exclusive (`SO_EXCLUSIVEADDRUSE`) des quatre écoutes : **tenu** (audit de #161, S161-02 ; preuve : un second
  socket ne peut pas se lier au port 53 de la boucle locale pendant l'essai, cas 3a) ;
- requêtes et réponses bornées (une question, tailles bornées, réponses aux noms bloqués construites, jamais recopiées
  au-delà de la question), sans panique possible : **tenu** (`dns_requete_bornee`, `dns_torturer`) ;
- débit borné : 16 requêtes en cours dont 4 connexions TCP, 4 s en tout pour qu'une connexion TCP envoie sa requête
  (S161-01). **Écart** : pas de file de 256 ; au-delà de la borne, la requête est ignorée et le client réessaie. Aucune
  résolution pour un autre hôte ;
- réponses de l'amont acceptées seulement si l'amont, l'identifiant et la question correspondent, identifiant et port
  source aléatoires (port tiré dans la plage dynamique) : **tenu** (`dns_reponse_amont_mal_assortie_ignoree`,
  `dns_port_source_dynamique`) ;
- **préalables à l'activation (7.4)**, du même audit, **tenus** par `filtrage_cartes.rs` et le moniteur (test
  `activation_ordre_des_operations`, cas 3a « Filtrage activé (7.4) ») :
  - jamais de carte réglée sans la liaison exclusive : le résolveur démarre et répond au contrôle avant le réglage ;
  - cartes rendues avant de relâcher le port : désactivation (une carte non rendue garde le résolveur et son port),
    arrêt du service, désinstallation (`--nettoyer`) ; silence de l'amont : cartes rendues, port gardé, rebranchées par
    une sonde toutes les 5 minutes ;
  - contrôle au démarrage : le port est pris avant toute remise ou tout réglage ; cartes réglées seulement si le
    résolveur répond ; sinon rendues en tenant le port, et rebranchées par la sonde ; port relâché seulement quand
    aucune carte ne pointe plus sur la boucle locale (audit de #164, S164-01).

  **Risque restant** : si le service est tué (plantage, arrêt forcé), le port est relâché alors que les cartes pointent
  encore sur `127.0.0.1`, jusqu'au redémarrage par le gestionnaire de services (5 s) et le contrôle du démarrage. Dans cet
  intervalle, un programme local qui prendrait le port 53 répondrait aux résolutions du poste. Même risque si, à un
  arrêt normal, la remise des cartes échoue deux fois : un repli retire alors au moins `127.0.0.1` et `::1` (serveurs
  d'origine en statique), mais s'il échoue aussi, le port est relâché avec la carte sur la boucle locale (S164-02).
  Écrit, non fermé ; depuis la PR 7.5a, ce cas au démarrage lève l'alerte critique DNS-003 avec le PID du programme
  qui tient le port ;
- **données de navigation** (PR 7.5a) : seuls les 50 derniers noms **bloqués** sont gardés, 24 h, dans
  `filtrage-etat.json` (dossier protégé) ; aucun nom relayé n'est noté ; rien de cela n'entre dans `etat.json` ni dans
  l'API ;
- ce qu'un compte standard local peut en faire : viser l'analyseur par des paquets forgés, saturer le résolveur (déni
  de service local qu'il peut déjà provoquer autrement), contourner le filtrage (possible : ce n'est pas une barrière ;
  changer le DNS des cartes demande d'être administrateur, et DNS-002 le signale).

## Attaquants considérés

### Compte standard local
Veut lire les données de surveillance (lignes de commande, sessions, trafic), modifier la configuration ou les
listes pour aveugler le service, détourner une opération SYSTEM (lien, jonction, fichier précréé), ou se faire
passer pour le service sur le canal.

- Phase 4 (PR 4.2) : il ne peut ni clore ni modifier un incident (commande `incident` réservée aux administrateurs,
  auteur lu sur le jeton du client). Il peut provoquer des alertes sur de nombreuses entités pour saturer le suivi
  (500 incidents non clos) : seuls les clos sont retirés, le surplus est compté (SAN-012, PR 4.4) et reste dans
  `alertes.json`.
- Mesures : dossier de données protégé et vérifié, échec fermé ; canal réservé aux administrateurs ; opérations de
  fichiers par handle ; restauration sous l'identité de l'utilisateur ; PowerShell lancé par son chemin absolu (un
  nom nu était cherché dans le PATH machine) ; journal du service sans caractère de contrôle (fausses lignes).
- Prouvé en CI (3a, 3b) : écriture, création et commandes refusées partout ; dossier précréé, fichiers à DACL
  vide, fichier tenu ouvert, configuration piégée pendant une mise à niveau : écartés, jamais chargés ; jonctions :
  refusées, canaris intacts.
- Risques résiduels : un fichier mis de côté dans `ecartes` reste modifiable par son auteur (jamais lu) ; le
  scénario avec un compte standard connecté à la console n'est pas exécuté (VM) ; la course
  contrôle-création de la restauration n'est pas reproduite.
- Angles morts publiés (phase 3, état des collectes) : `etat.json` est lisible par les comptes lecteurs, dont le compte
  connecté à la console par défaut. Un programme qui tourne sous ce compte y lit quelles collectes manquent
  (`Collectes`, `ReglesSansCollecte`, `ReglesDegradees` : Sysmon absent, journal illisible, règles PRC dégradées sous
  WMI) et peut choisir une technique que le service ne voit pas. Le champ « Source » des processus le montrait déjà en
  partie. Choix assumé : l'utilisateur doit voir ce qui n'est pas surveillé ; les raisons publiées ne portent aucun
  nom de compte. Réserver ces champs aux administrateurs reste possible (décision du mainteneur).

### Appareil du réseau local
Veut exploiter les parseurs (paquets capturés, réponses UPnP), interroger l'API, écouter l'export, ou empoisonner
la résolution de noms.

- Mesures : parseurs bornés et testés ; API désactivée par défaut, jeton, adresses autorisées ; détection NDR
  (ARP, DHCP, LLMNR/NBNS/mDNS), expérimentale.
- Risques résiduels : l'export syslog part en clair ; la règle « deR4Tizer capture » autorise tout l'entrant vers
  le service (nécessaire à la capture). Jeton de l'API en échec fermé et `/api/v1/sante` sans nom de machine
  (PR #14), testés en labo seulement.

### Compte GitHub compromis
Veut publier une version malveillante que les postes installeraient.

- Mesures : clé de signature épinglée dans les binaires déjà installés (une nouvelle clé n'est acceptée que par
  les binaires compilés avec elle) ; certificat dans l'environnement « publication » (secrets ; approbation obligatoire à confirmer),
  compilation séparée de la signature ; ensemble de règles « tags-version » actif sur les tags (vu le 2026-10-22,
  contenu à confirmer) ; `main` protégée (PR obligatoire, pas de poussée forcée ; vérifications de CI obligatoires
  retirées temporairement pendant la désactivation de GitHub Actions, remplacées par la preuve locale de
  `CLAUDE.md`) ; version lue
  dans le paquet signé, plus récente que l'installée.
- Risques résiduels : un attaquant qui contrôle le compte du mainteneur peut aussi approuver l'environnement de
  publication et faire signer un paquet par le vrai certificat ; seule la protection du compte (double facteur,
  sessions) le couvre. Une liste de révocation injoignable fait refuser la signature (PR #12 ; prouvé par le 3c en
  Windows Sandbox seulement). Aucune version signée n'est publiée : la mise à jour automatique, inopérante dans les
  versions 4.2 et 4.3 publiées (corrigée par la PR #26, non encore publiée), n'installe rien aujourd'hui.
- Choix du certificat : l'épinglage repose sur la clé publique. SignPath et Azure Trusted Signing ne sont pas utilisables en l'état.
  SignPath Foundation émet le certificat à son propre nom, peut-être commun à plusieurs projets : épingler sa clé
  ferait accepter un MSI signé pour un autre projet, avec l'`UpgradeCode` de deR4Tizer et une version plus élevée.
  Parades, à décider par cryptobones-1337 (changement du modèle de confiance) : une seconde signature propre au projet
  (Ed25519, clé hors ligne) de l'empreinte du MSI, seule épinglée pour les mises à jour ; ou, au minimum, le nom
  de produit « deR4Tizer » exigé dans le paquet signé (repose alors sur le contrôle de SignPath). Un certificat de
  quelques jours dont la clé changerait à chaque renouvellement (Azure Trusted Signing, à vérifier) rendrait
  l'épinglage inutilisable et demanderait aussi un nouveau modèle de confiance. Le comportement de la révocation avec un certificat expiré et une signature
  horodatée est à tester avec le vrai certificat avant toute publication.

### Liste de menaces corrompue
Une source compromise ou erronée publie des adresses légitimes (DNS public, service de mise à jour, serveur du
prestataire).

- Mesures : téléchargement en HTTPS, chargement borné ; une liste qui couvrirait plus de 2^27 adresses IPv4 ou
  2^48 réseaux IPv6 /64 ou plus (un /16) est rejetée en entier (borne IPv6 : PR 6.15) ; Feodo Tracker n'admet
  que des adresses seules, pas de réseau (PR 6.15) ; blocage automatique limité à Spamhaus DROP et Feodo
  Tracker, et à 30 par heure (un compte standard peut l'atteindre exprès : arrêt d'une heure, alertes conservées) ; un
  déblocage manuel prime pendant 7 jours ; blocages levés quand l'adresse sort de la liste ou à expiration.
- Risques résiduels : un blocage automatique d'une adresse légitime coupe un service jusqu'à la mise à jour
  suivante de la liste.

Réutilisation des PID : tuer, suspendre et reprendre exigent le PID et l'heure de création, comparés sur le handle qui sert à agir.

Compte standard contre la suspension sur leurre : un programme nommé comme un logiciel connu, signé par son éditeur, échappe à la suspension s'il se trouve dans un dossier de Program Files ouvert par un installateur tiers, ou s'il est un processus creux lancé depuis un binaire autorisé. L'alerte reste, au niveau Info. À fermer avant toute distribution.

## Hors du modèle

- Un programme sous le compte de l'utilisateur peut fermer ou suspendre l'interface : la tâche planifiée la relance (5 min au plus), SAN-010 et SAN-011 signalent une absence ou des arrêts répétés, une interface suspendue n'est pas vue ; la surveillance et la remontée continuent. La tâche, posée par SYSTEM après suppression de toute tâche du même nom, avec ses droits et relue ensuite, n'est pas modifiable par un compte standard. Un administrateur qui retire la valeur Run coupe SAN-010 et SAN-011 (il peut aussi arrêter le service).
- Un attaquant déjà administrateur ou SYSTEM : il peut arrêter le service, modifier ses fichiers et ses droits. Depuis la phase 4 (PR 4.4b), quand la remontée est configurée, le battement quotidien cesse : le prestataire peut voir
  qu'un poste ne répond plus, sans savoir pourquoi (service arrêté, poste éteint, réseau coupé).
  deR4Tizer complète Microsoft Defender, il ne le remplace pas.
- La conservation des traces face à cet attaquant, ou après une intrusion découverte tard. Le SIEM (`siem\`, 30 jours
  et 1 Go au plus : les jours les plus anciens partent d'abord, parfois bien avant 30 jours) et le journal du service
  (`journal.txt`, 2 Mo, puis un fichier précédent) restent sur la machine surveillée : un administrateur peut les
  effacer, et une intrusion plus ancienne que ces limites n'y est plus. Seule une copie déjà partie ailleurs y échappe,
  et aucune n'est complète : l'export syslog, s'il est configuré, n'envoie que les alertes, en clair (sans TLS), sans
  garantie de réception ; la remontée (ntfy, Teams, SMTP), chiffrée en transit, n'envoie que des alertes regroupées et
  plafonnées ; l'API d'export, si un outil tiers vient la lire, donne aussi les événements du SIEM, en clair (HTTP) sur
  le réseau local. Aucun export chiffré et complet des traces n'existe.
- L'injection de code dans un processus légitime (le vol de données est détecté par l'identité du programme qui
  lit les fichiers).
