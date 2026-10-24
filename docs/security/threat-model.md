# Modèle de menaces de deR4Tizer

État au 2026-10-24 (`main`, commit `4702837`, version 4.3). Les mesures citées renvoient au code et, quand elles sont prouvées en
conditions réelles, aux scénarios de CI (`docs/roadmap/capability-matrix.md`).

## Frontières de privilège

| Frontière | Côté privilégié | Côté exposé | Mesures | Preuve |
|---|---|---|---|---|
| Service | `deR4TizerSvc.exe`, compte SYSTEM | Tout le reste du poste | Aucun pilote noyau ; `panic = "abort"` (un index hors limites arrête le service au lieu de le corrompre) et mini-fuzz des parseurs. | `cargo test` (mini-fuzz) |
| Interface | Service | `deR4Tizer.exe`, sans droits d'administrateur | L'interface lit l'état (fichiers JSON du dossier de données, lecture seule) ; toute action passe par le canal, donc par un administrateur (UAC). | 3a (compte standard refusé) |
| Canal de commandes `\\.\pipe\deR4Tizer` | Service | Processus locaux | Réservé à SYSTEM et aux administrateurs ; première instance créée avec `FILE_FLAG_FIRST_PIPE_INSTANCE`, une instance toujours ouverte ; l'interface et le script de mise à jour vérifient que le serveur du tube est le processus du service. | 3a ; `lot2_canal_code_de_production_sur_un_vrai_tube` |
| API d'export (HTTP) | Service | Réseau local (si activé) ou 127.0.0.1 | Désactivée par défaut ; lecture seule ; jeton (`api-jeton.txt`, SYSTEM et administrateurs) ; sur le réseau, adresses autorisées obligatoires et règle de pare-feu (profils Domaine et Privé, Public bloqué). | 3a (port témoin) ; `api_adresses_autorisees` |
| Mise à jour automatique | Service (installe un MSI en SYSTEM) | Serveur de publication (GitHub), réseau | Manifeste strict ; empreinte SHA-256 ; signature Authenticode avec révocation ; clé publique du signataire comparée aux clés épinglées dans le binaire ; version lue dans le paquet signé ; dossier de travail réservé à SYSTEM ; retour arrière par le MSI de la version installée, lui aussi vérifié. Installation automatique désactivée par défaut. | `lot2_*` ; 3c en Windows Sandbox seulement (jamais en CI) |
| Dossier de données `C:\ProgramData\deR4Tizer` | Service | Comptes locaux | Créé avec ses droits (MSI et service) ; propriétaire et droits imposés et vérifiés au démarrage ; éléments d'un autre propriétaire mis de côté, jamais lus ; échec fermé (configuration et secrets ignorés). | 3a |
| Opérations de fichiers SYSTEM sur des chemins de l'utilisateur (quarantaine, restauration) | Service | Utilisateur propriétaire du chemin | Ouverture par handle sans suivre de lien, chemin final vérifié ; restauration sous l'identité de l'utilisateur, jamais en SYSTEM à l'emplacement d'origine ; repli dans le dossier du service. | 3b |
| Capture réseau | Service (socket brute) | Tout paquet reçu par le poste | Parseurs bornés et testés (mini-fuzz) ; règle « deR4Tizer capture » nécessaire (tout l'entrant vers le service) ; le service n'écoute aucun port, sauf l'API facultative. | `cargo test` (mini-fuzz) |
| Remontée des alertes | Service | ntfy, Teams, serveur SMTP | Secrets réservés aux administrateurs ; envois par `curl.exe` de Windows (HTTPS, SMTP avec TLS). | `notifications_*` |
| Export syslog | Service | Réseau | **En clair** (UDP ou TCP, sans TLS). | — |

## Attaquants considérés

### Compte standard local
Veut lire les données de surveillance (lignes de commande, sessions, trafic), modifier la configuration ou les
listes pour aveugler le service, détourner une opération SYSTEM (lien, jonction, fichier précréé), ou se faire
passer pour le service sur le canal.

- Mesures : dossier de données protégé et vérifié, échec fermé ; canal réservé aux administrateurs ; opérations de
  fichiers par handle ; restauration sous l'identité de l'utilisateur.
- Prouvé en CI (3a, 3b) : écriture, création et commandes refusées partout ; dossier précréé, fichiers à DACL
  vide, fichier tenu ouvert, configuration piégée pendant une mise à niveau : écartés, jamais chargés ; jonctions :
  refusées, canaris intacts.
- Risques résiduels : un fichier mis de côté dans `ecartes` reste modifiable par son auteur (jamais lu) ; le
  scénario avec un compte standard connecté à la console n'est pas exécuté (VM) ; la course
  contrôle-création de la restauration n'est pas reproduite.

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
  Parades, à décider par Benoît (changement du modèle de confiance) : une seconde signature propre au projet
  (Ed25519, clé hors ligne) de l'empreinte du MSI, seule épinglée pour les mises à jour ; ou, au minimum, le nom
  de produit « deR4Tizer » exigé dans le paquet signé (repose alors sur le contrôle de SignPath). Un certificat de
  quelques jours dont la clé changerait à chaque renouvellement (Azure Trusted Signing, à vérifier) rendrait
  l'épinglage inutilisable et demanderait aussi un nouveau modèle de confiance. Le comportement de la révocation avec un certificat expiré et une signature
  horodatée est à tester avec le vrai certificat avant toute publication.

### Liste de menaces corrompue
Une source compromise ou erronée publie des adresses légitimes (DNS public, service de mise à jour, serveur du
prestataire).

- Mesures : téléchargement en HTTPS, chargement borné ; blocage automatique limité aux listes de confiance
  « haute » ; blocages levés quand l'adresse sort de la liste ou à expiration.
- Risques résiduels : un blocage automatique d'une adresse légitime coupe un service jusqu'à la mise à jour
  suivante de la liste ; avec le réglage « listes restreintes », le blocage automatique s'étend à FireHOL
  niveau 1 et à ThreatView, au-delà de la politique de réponse (`docs/reponse/politique.md`).

## Hors du modèle

- Un attaquant déjà administrateur ou SYSTEM : il peut arrêter le service, modifier ses fichiers et ses droits.
  deR4Tizer complète Microsoft Defender, il ne le remplace pas.
- L'injection de code dans un processus légitime (le vol de données est détecté par l'identité du programme qui
  lit les fichiers).
