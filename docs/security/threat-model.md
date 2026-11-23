# Modèle de menaces de deR4Tizer

État au 2026-11-23 (`main`, commit `6ad1858` ; version 4.3 signée et publiée). Les mesures citées renvoient au code et, quand elles sont prouvées en
conditions réelles, aux scénarios de CI (`docs/roadmap/capability-matrix.md`). Les constats ouverts de l'audit par passes du
2026-11-23 (fait par Claude : ce n'est pas une relecture indépendante) sont signalés par leur numéro (A-x-y), avec la mention
« non corrigé ».

Utilisateur visé : le particulier ou la petite structure est souvent membre du groupe Administrateurs, avec l'UAC en simple
consentement. Pour lui, la barrière entre un programme malveillant et une commande privilégiée est la fenêtre de
confirmation de deR4Tizer : tout programme de son compte peut écrire un fichier de commande et lancer l'assistant élevé,
signé au nom de l'éditeur. La confirmation dit vrai et son bouton par défaut est « Annuler » ; pour une commande qui
affaiblit la protection, elle dit en tête que la demande ne vient peut-être pas de l'utilisateur et n'arme « Continuer »
qu'après 2 s (A-1-2, corrigé ; testé par `tests\test-confirmations.ps1`, à essayer en VM). L'assistant n'accepte que son
propre fichier de commande, jugé sur le texte du chemin avant tout accès disque : aucun chemin réseau n'est ouvert avec
l'identité de l'administrateur (A-1-1, corrigé ; même test).

## Frontières de privilège

| Frontière | Côté privilégié | Côté exposé | Mesures | Preuve |
|---|---|---|---|---|
| Service | `deR4TizerSvc.exe`, compte SYSTEM | Tout le reste du poste | Aucun pilote noyau ; `panic = "abort"` (un index hors limites arrête le service au lieu de le corrompre) et mini-fuzz des parseurs. Après un arrêt, Windows relance le service sans limite (5 s, actions de récupération posées par le MSI) : une panique répétée ferait des trous de quelques secondes dans la surveillance ; l'audit du 2026-11-23 n'a trouvé aucune panique atteignable par une donnée d'attaquant (lecture dirigée, sans fuzzing). Le service tourne en priorité normale ; ses fils lourds et périodiques passent en arrière-plan, le fil des 4663 des leurres et le canal de commandes au-dessus de la normale (A-8-1, corrigé, test `a8_1_priorites_des_fils` ; effet sur le délai de suspension sous charge non mesuré, à mesurer en VM). Diagnostic d'exposition (U5c-1) : lecture seule de la politique du pare-feu (INetFwPolicy2 : profils actifs, état, action entrante par défaut), sans écriture ; textes publiés bornés (200 caractères, sans caractère de contrôle). | `cargo test` (mini-fuzz, `structure_diagnostic_lecture_seule`) |
| Interface | Service | `deR4Tizer.exe`, sans droits d'administrateur | L'interface lit l'état (fichiers JSON du dossier de données, lecture seule) ; toute action passe par le canal, donc par un administrateur (UAC). Depuis la bascule (B1), la coquille WPF est l'interface par défaut ; l'assistant élevé (`--commande-fichier`) sort avant le mutex et ne charge jamais WPF (mode décidé par une fonction pure, pilote dans une méthode jamais intégrée). Seconde instance (B2) : un événement de la session (`Local\deR4Tizer.Interface.Montrer`) demande à l'interface déjà ouverte de se montrer ; il ne porte aucune donnée, et un programme de la session qui le signale ne peut que faire apparaître la fenêtre (au plus quelques fois par seconde) ; s'il le précrée, quels qu'en soient les droits ou le mode, la première instance ne l'écoute pas et la seconde redevient muette ; le droit de passer au premier plan n'est accordé qu'au PID de la première instance (même nom, même session, même exécutable), jamais à tout processus (audit de #158). Premiers réglages (U7a, U7b, U7c) : trois commandes seulement, celles des pages Réglages et Menaces (apprentissage, deux réponses automatiques de niveau 3, message de test des notifications avec les réglages relus au clic et sans secret ; le service applique ces réglages avant d'envoyer le test, d'où la relecture au clic et la confirmation en administrateur, aussi depuis la page Réglages : audit de #154, S154-01), par le canal donc confirmées ; une interface déjà élevée les fait confirmer par Canal, comme toute commande « config » ou « apprentissage » depuis l'audit de #152 (S152-02 : avant, les pages Réglages, Menaces et Détection d'une interface élevée les envoyaient en un clic), et comme la levée d'un blocage, les réglages syslog et API, les notifications, la mise à jour, l'autorisation d'un compte lecteur (audit de #153, S153-01) et l'exception durable « Ne plus alerter pour ce comportement » (S153-02) ; seul fichier écrit par l'interface, un repère par utilisateur dans `%LOCALAPPDATA%\deR4Tizer` qui veut dire « déjà proposés » : un programme du compte qui l'efface ou le crée ne fait que reproposer ou taire l'assistant, jamais changer un réglage. Une interface lancée en administrateur n'écrit jamais ce repère, dans un dossier que les programmes non élevés du compte contrôlent (jonction, lien : audit de #151, S151-01) ; `derniere-alerte-lue.txt` (même dossier) n'est plus écrit non plus par une interface élevée : la dernière alerte lue y reste en mémoire. | 3a (compte standard refusé) |
| Canal de commandes `\\.\pipe\deR4Tizer` | Service | Processus locaux | Réservé à SYSTEM et aux administrateurs ; première instance créée avec `FILE_FLAG_FIRST_PIPE_INSTANCE`, une instance toujours ouverte ; l'interface et le script de mise à jour vérifient que le serveur du tube est le processus du service. Phase 1 : débit borné, autorisation par commande et validation de chaque champ avant toute exécution ; noms écrits dans le fichier hosts validés (plus d'injection de ligne). Durcissement (relecture du canal) : clients distants refusés par le tube (`PIPE_REJECT_REMOTE_CLIENTS`) ; client identifié sur le jeton de la connexion, après la lecture de la commande (`ImpersonateNamedPipeClient`, retour immédiat à l'identité du service, arrêt si ce retour échoue), et non plus sur le PID de son processus, qu'un autre processus pouvait reprendre ; clients du service au niveau Identification (le service lit leur jeton, jamais n'agit avec) ; client au niveau Anonymous : « autre » ; réponse écrite en 5 s au plus, un client qui ne la lit jamais ne bloque plus le canal (IPC-04) ; lecture de la réponse bornée côté interface (120 s). Connexion distante (IPC-03) : pas encore essayée depuis une autre machine. Disponibilité (A-8-2, non corrigé) : le nom du tube est fixe ; un compte standard qui le prend pendant un redémarrage du service (mise à jour, mise à niveau, plantage) coupe toutes les commandes et fait échouer le contrôle de santé de la mise à jour, donc revenir à la version précédente, tant qu'il le tient (alerte critique avec son PID). Les administrateurs peuvent créer une instance du tube (droit d'écriture générique, A-1-4) : c'est la vérification du serveur par l'interface et par le script de mise à jour qui protège. | 3a (anonyme refusé, IPC-04, 8 clients simultanés) ; `lot2_canal_code_de_production_sur_un_vrai_tube`, `phase1_client_du_tube_identifie_sur_son_jeton`, `canal_reponse_bornee_client_qui_ne_lit_pas` |
| API d'export (HTTP) | Service | Réseau local (si activé) ou 127.0.0.1 | Désactivée par défaut ; lecture seule ; jeton (`api-jeton.txt`, SYSTEM et administrateurs) ; sur le réseau, adresses autorisées obligatoires (IPv4 exacte ou /8 à /32, validées avant d'aller dans la règle de pare-feu) et règle de pare-feu (profils Domaine et Privé, Public bloqué) ; requête lue en 10 s au plus. **En clair** (HTTP) : sur le réseau, jeton et données passent en clair (risque résiduel, comme syslog). | 3a (port témoin) ; `api_adresses_autorisees` |
| Installation interactive (U8a) | Installeur (SYSTEM pour les actions différées) | Session de l'utilisateur qui installe | Aucune action de l'interface du MSI ne lance de programme : la dernière page affiche un texte (affectations de propriété, type 51), sans case « Lancer » ; l'interface est démarrée par la tâche de relance, sans élévation. Lancée depuis l'installeur, elle aurait pu tourner élevée et garder le mutex de la session. | `tests/test-msi.ps1` (sources et paquet) ; 3a (interface venue de la tâche, jeton non élevé) |
| Mise à jour automatique | Service (installe un MSI en SYSTEM) | Serveur de publication (GitHub), réseau | Manifeste strict ; empreinte SHA-256 ; signature Authenticode avec révocation ; clé publique du signataire comparée aux clés épinglées dans le binaire ; version lue dans le paquet signé ; dossier de travail réservé à SYSTEM ; retour arrière par le MSI de la version installée, lui aussi vérifié. Installation automatique désactivée par défaut. | `lot2_*` ; 3c en Windows Sandbox seulement (jamais en CI) |
| Dossier de données `C:\ProgramData\deR4Tizer` | Service | Comptes locaux | Créé avec ses droits (MSI et service) ; propriétaire et droits imposés et vérifiés au démarrage ; éléments d'un autre propriétaire mis de côté, jamais lus ; échec fermé (configuration et secrets ignorés). En échec de la protection, une alerte critique reste locale : les secrets de remontée sont ignorés, le prestataire n'est pas prévenu. | 3a |
| Opérations de fichiers SYSTEM sur des chemins de l'utilisateur (quarantaine, restauration) | Service | Utilisateur propriétaire du chemin | Ouverture par handle sans suivre de lien, chemin final vérifié ; restauration sous l'identité de l'utilisateur, jamais en SYSTEM à l'emplacement d'origine ; repli dans le dossier du service. Audit du 2026-11-14 : nom de la copie lu dans `quarantaine.json` limité à un nom simple (B3 : sinon une entrée réécrite faisait supprimer un fichier quelconque en SYSTEM à la reprise) ; adresse du manifeste de mise à jour revalidée à chaque vérification et passée à curl par `--url` (B2) ; en échec de la protection du dossier, les commandes qui réécrivent `config.json` sont refusées (B8). | 3b ; `audit_b3_reprise_entree_forgee_ne_supprime_rien`, `audit_b3_nom_de_copie_simple`, `audit_b2_b8_cablage` |
| Capture réseau | Service (socket brute) | Tout paquet reçu par le poste | Parseurs bornés et testés (mini-fuzz) ; règle « deR4Tizer capture » nécessaire (tout l'entrant vers le service) ; le service n'écoute aucun port, sauf l'API facultative. | `cargo test` (mini-fuzz) |
| Remontée des alertes | Service | ntfy, Teams, serveur SMTP | Secrets réservés aux administrateurs, gardés en mémoire du service entre deux envois (fichier retiré : ntfy et Teams coupés au tour suivant, un serveur SMTP sans compte reste joignable ; modifié à la main : pas adopté avant le prochain réglage ou redémarrage) ; envois par `curl.exe` de Windows (HTTPS, SMTP avec TLS). | `notifications_*` |
| Export syslog | Service | Réseau | **En clair** (UDP ou TCP, sans TLS). | — |

### Résolveur DNS local (phase 7 : PR 7.3, branché sur les cartes par 7.4)

Dans le code (`dns_local.rs`), mécanisme M2 du dossier (D7-1 : recommandation appliquée ;
mise en service sur les cartes avec l'accord explicite du mainteneur pour la 7.4 (2026-11-12)). En 7.3, il n'écoutait que pendant un **essai de 10 minutes** lancé par un administrateur (commande
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
- **résolveur tiers** (PR 7.6) : Quad9 choisi, toutes les requêtes DNS non bloquées du poste lui sont envoyées (en
  clair : pas de DNS chiffré, 7.7 non faite), noms locaux et requêtes inverses d'adresses privées compris ; jamais par
  défaut, dit dans la confirmation et sur la page. La confirmation conseille de garder le résolveur du réseau sur un
  réseau d'entreprise, et dit qu'au portail captif le relais par le DNS du réseau vient après jusqu'à 30 s puis
  jusqu'à 5 minutes sans filtrage (relecture de #167, R6) ;
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
- Lignes de commande publiées (couverture ATT&CK, lot 1) : depuis la lecture des 4688, les chaînes de processus de
  `etat.json` peuvent montrer les 300 premiers caractères de la ligne de commande de processus d'autres comptes, SYSTEM
  compris, aux comptes lecteurs (ce que la trace WMI permettait déjà pour un processus encore vivant). Un secret passé
  en argument (mot de passe en ligne de commande) peut y apparaître ; le nombre de nœuds d'une chaîne n'est pas borné
  (audit de #244). Le SIEM garde en plus 400 caractères de la ligne de commande de chaque création de processus (4688),
  tous comptes, 30 jours, lisibles par les comptes lecteurs, et l'export syslog ou l'API les transmet : un mot de passe
  d'administrateur tapé en argument peut y être lu par un compte standard (A-6-1, non corrigé ; masquage prévu). Le
  premier compte vu à la console devient lecteur, sans être affiché ni revu ensuite (A-6-2, non corrigé).
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
  les binaires compilés avec elle) ; compilation par la CI (artefact « a-signer »), aucune signature en CI : la clé
  Certum est dans SimplySign et la signature se fait sur le poste du mainteneur (`signer-version.ps1` vérifie l'empreinte
  de l'artefact publiée par GitHub, la clé compilée et la version) ; versions immuables activées sur le dépôt le
  2026-11-23 (à partir de la version suivante ; la v4.3 reste modifiable : un compte compromis pourrait y remplacer le
  MSI et les notes, ce qu'une première installation à la main ne verrait qu'au nom de l'éditeur, A-3-1) ; ensemble de
  règles « tags-version » actif sur les tags (vu le 2026-10-22, contenu non vérifié) ; `main` protégée (PR obligatoire, pas de poussée forcée ; vérifications de CI obligatoires
  retirées pendant la désactivation de GitHub Actions, du 2026-10-22 au 2026-11-17, et pas encore rétablies : la CI
  tourne, mais une fusion n'exige pas qu'elle soit verte) ; version lue
  dans le paquet signé, plus récente que l'installée.
- Retour arrière : le MSI accepte une version plus ancienne (`AllowDowngrades`, nécessaire au retour arrière) ; le refus
  d'une version plus ancienne est assuré par le service, pour la mise à jour automatique seulement : un administrateur
  peut toujours installer une version plus ancienne à la main (`capability-matrix.md`, installation).
- Risques résiduels : un attaquant qui contrôle le compte du mainteneur peut faire compiler un code de son choix par la
  CI ; il ne le fait signer que si le mainteneur signe cet artefact. Poste de signature : frontière de confiance à part
  entière. Les exécutables attendent dans un dossier temporaire du compte du mainteneur entre le contrôle d'empreinte et
  la signature, et un programme de ce compte pendant la session SimplySign peut faire signer ce qu'il veut : seule
  l'hygiène de ce poste le couvre. Aucune reconstruction indépendante : chaîne Rust « stable » non figée et `cargo` sans
  `--locked` (A-3-3, non corrigé), MSI construit sur le poste du mainteneur. Une liste de révocation injoignable fait refuser la signature (PR #12 ; prouvé par le 3c en
  Windows Sandbox, puis en CI au run 44480286774 (PR #205, `cd36ee4`, 2026-11-19)). Première version signée publiée : v4.3 (2026-11-23). La mise à jour automatique,
  inopérante dans les versions de test 4.2 et 4.3 installées à la main (corrigée par la PR #26, incluse dans la v4.3),
  ne part que de la v4.3 signée, vers une version suivante.
- Choix du certificat : l'épinglage repose sur la clé publique. Certificat retenu par le mainteneur le 2026-11-11 :
  Certum Open Source, au nom du mainteneur ; sa clé publique est épinglée (`CLE_SIGNATURE`). L'épinglage accepterait
  aussi un paquet signé par cette même clé pour un autre projet du même titulaire (l'`UpgradeCode` et la version
  restent contrôlés). Le certificat est valable jusqu'au
  2027-11-17. La v4.3 n'épingle qu'une clé : la suivante doit être épinglée dans une version publiée avant cette date,
  sinon les postes ne pourront plus se mettre à jour seuls. SignPath Foundation (certificat au nom de la fondation,
  peut-être commun à plusieurs projets) et Azure Trusted Signing (clé qui changerait à chaque renouvellement) ont été
  écartés : ils rendaient l'épinglage inutile ou impossible. Le comportement de la révocation avec un certificat expiré
  et une signature horodatée devait être essayé avec le vrai certificat avant toute publication : non fait, v4.3 publiée
  avant (écart décidé par le mainteneur, 2026-11-23). Risque : après le 2027-11-17, si la révocation de l'ancien
  certificat ne répond plus, le paquet de retour arrière, signé par lui, serait refusé, et plus aucune mise à jour ne
  s'installerait (A-3-H1, à vérifier en VM).

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

Compte standard contre la suspension sur leurre : un programme nommé comme un logiciel connu, signé par son éditeur, n'échappe plus à la suspension depuis un dossier de Program Files ouvert par un installateur tiers (droits du programme et de ses dossiers exigés, et compte SYSTEM ou administrateur, depuis le 2026-11-21 : S110-14, S114-01, S228-01). Reste ouvert à la publication de la v4.3 : un processus creux lancé depuis un binaire autorisé, sous SYSTEM ou un administrateur, garde ce statut (S114-02) ; l'alerte reste, au niveau Info.

Compte standard contre les leurres eux-mêmes : ils sont posés dans `Documents`, `Pictures` et `Desktop` à leur emplacement réel, lu dans la ruche de l'utilisateur (sauvegarde OneDrive des dossiers, redirection ; A-7-2, corrigé). La valeur lue est écrite par l'utilisateur : elle n'est admise que sous son profil ou, ailleurs, dans un dossier d'un lecteur local fixe (vu par SYSTEM) dont il est propriétaire, jamais sur un partage réseau ni avec « .. » ou une variable inconnue ; un leurre à plusieurs noms (lien dur vers un autre fichier) n'est ni audité ni suivi (S268-01) ; et la création reste par handle, sans suivre de lien, sous son identité. Reste : utilisateur sans session (ruche non chargée) ou dossier redirigé vers un partage : leurre dans le dossier par défaut, refus journalisé. Sous la charge d'un chiffrement, la suspension dépend de la priorité du fil des 4663, désormais au-dessus de la normale (A-8-1, corrigé, effet non mesuré).

Opérations privilégiées, audit du 2026-11-23 : la GPO locale est lue en échec fermé avant toute écriture (fichier illisible, tronqué ou non compris : refus, rien n'est écrit) et écrite d'un bloc sans changer ses droits ; l'annulation laisse une valeur durcie depuis par un tiers (A-2-2 et A-2-3, corrigés ; testé en labo, à vérifier en VM). Corrigés ensuite (lot 4b ; testés en labo, à essayer en VM) : le service n'ouvre plus aucun chemin réseau, amovible ou sans lettre pour lire la signature, le catalogue, l'empreinte ou la marque d'un programme (décision `natif::lisible_en_systeme`, appliquée avant tout accès dans `natif::lecture_fichier` ; un tel programme est lu « non signé ») : le compte de la machine n'est plus envoyé à un autre hôte (A-5-2, `audit_a_5_2_aucun_chemin_reseau_lu_en_systeme`) ; limite : un dossier local qui est un lien symbolique vers un partage n'est pas détecté par cette décision sur le texte. Le paquet pose les droits du dossier des programmes (SYSTEM et administrateurs contrôle total, Utilisateurs lecture et exécution, héritage coupé) ; le service les relit au démarrage, alerte critique INT-003 et mise à jour refusée s'ils permettent à un autre compte d'écrire (A-4-1, `audit_a_4_1_dossier_installation_protege`, `tests\test-msi.ps1`). Outils de Windows lancés par leur chemin complet dans le service et l'interface (A-2-1, A-5-3). Les caches de signature (connexions, apprentissage, VOL-001) ont pour clé l'identité du fichier lue par handle avec son numéro USN, ou l'empreinte SHA-256 du contenu sans USN, au lieu du chemin et de la date de modification qu'un compte standard remet à l'identique (B-2-01, second audit, `audit_b_2_01_programme_remplace_meme_date_reverifie`).

## Hors du modèle

- Un programme sous le compte de l'utilisateur peut fermer ou suspendre l'interface : la tâche planifiée la relance (5 min au plus), SAN-010 et SAN-011 signalent une absence ou des arrêts répétés, une interface suspendue n'est pas vue ; la surveillance et la remontée continuent. La tâche, posée par SYSTEM après suppression de toute tâche du même nom, avec ses droits et relue ensuite, n'est pas modifiable par un compte standard. Un administrateur qui retire la valeur Run coupe SAN-010 et SAN-011 (il peut aussi arrêter le service).
- Un attaquant déjà administrateur ou SYSTEM : il peut arrêter le service, modifier ses fichiers et ses droits. Depuis la phase 4 (PR 4.4b), quand la remontée est configurée, le battement quotidien cesse : le prestataire peut voir
  qu'un poste ne répond plus, sans savoir pourquoi (service arrêté, poste éteint, réseau coupé).
  deR4Tizer complète Microsoft Defender, il ne le remplace pas.
- La conservation des traces face à cet attaquant, ou après une intrusion découverte tard. Un compte standard peut
  aussi chasser l'historique, ce qui relève du modèle et n'est pas corrigé : en créant des processus en boucle, il fait
  dépasser 1 Go au SIEM (les jours les plus anciens partent, fichier du jour compris) et déborder sa file (événements
  perdus, sans constat de santé) ; du bruit provoqué remplit le journal du service (A-6-3, A-8-3). Le SIEM (`siem\`, 30 jours
  et 1 Go au plus : les jours les plus anciens partent d'abord, parfois bien avant 30 jours) et le journal du service
  (`journal.txt`, 2 Mo, puis un fichier précédent) restent sur la machine surveillée : un administrateur peut les
  effacer, et une intrusion plus ancienne que ces limites n'y est plus. Seule une copie déjà partie ailleurs y échappe,
  et aucune n'est complète : l'export syslog, s'il est configuré, n'envoie que les alertes, en clair (sans TLS), sans
  garantie de réception ; la remontée (ntfy, Teams, SMTP), chiffrée en transit, n'envoie que des alertes regroupées et
  plafonnées ; l'API d'export, si un outil tiers vient la lire, donne aussi les événements du SIEM, en clair (HTTP) sur
  le réseau local. Aucun export chiffré et complet des traces n'existe.
- L'injection de code dans un processus légitime (le vol de données est détecté par l'identité du programme qui
  lit les fichiers).
