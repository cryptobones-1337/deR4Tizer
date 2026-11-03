# Politique de réponse de deR4Tizer

Une action de réponse coupe ou modifie quelque chose sur le poste du client : elle doit être juste, réversible
et prévisible. Cette politique fixe ce que deR4Tizer a le droit de faire seul. Son application complète dans le
code relève de la phase 6 ; l'écart avec le code actuel est listé plus bas.

## Niveaux

| Niveau | Nom | Ce qui se passe | Exemples |
|---|---|---|---|
| 0 | Observation | Événement enregistré (mini-SIEM, journal), aucune alerte. | Nouvelle connexion d'un programme connu, comportement appris. |
| 1 | Alerte | Alerte locale et, selon la gravité, remontée au prestataire. Aucune action sur le poste. | Persistance nouvelle, connexion suspecte, extension dangereuse. |
| 2 | Action sous contrôle humain | Action proposée et confirmée par un administrateur (UAC), **ou** action automatique désactivée par défaut, activée sciemment. | Tuer, suspendre, mettre en quarantaine, isoler un programme, mode panique, blocage manuel ; IPS (désactivé par défaut). |
| 3 | Action automatique | Action prise seule par le service, sans confirmation. | Seulement les deux actions ci-dessous. |

## Seules actions de niveau 3 autorisées

1. **Blocage des adresses IP de Spamhaus DROP et de Feodo Tracker** au pare-feu (listes de confiance haute,
   libres d'usage), identifiées dans le binaire, quel que soit le réglage « listes restreintes » : toute autre liste
   donne une alerte seule. Le blocage est levé quand l'adresse sort de ces listes, si les trois sont chargées, ou à expiration (7 jours).
2. **Suspension du programme qui touche un leurre anti-rançongiciel.** Les processus critiques de Windows
   (`reponse::protege`) ne sont jamais suspendus ; les logiciels connus et signés, au nom exact, installés hors du profil de l'utilisateur (droits du dossier non vérifiés), de sauvegarde, de
   synchronisation ou d'antivirus déclenchent une alerte sans suspension. Le programme reste suspendu jusqu'à
   une décision humaine.

Tout le reste, IPS compris, est au niveau 2 au plus.

## Règles communes

- Une alerte critique n'est jamais adoucie (apprentissage, exceptions) ni retenue par le plafond de remontée.
- Chaque action automatique est journalisée et produit une alerte qui dit quoi faire.
- Chaque action de réponse a une durée maximale et une procédure de récupération testée. À l'échéance, jamais de
  reprise automatique d'un processus suspendu ni de levée automatique d'une isolation : l'alerte est relancée
  vers le prestataire, la récupération est une action humaine (phase 6).

## Point de décision et garde contre les boucles

Le blocage d'une adresse, la suspension, la reprise, l'arrêt d'un processus, l'isolation et le mode panique passent par
`politique.rs` : aucun n'est exécuté sans une autorisation qu'il délivre (`execution.rs`). Le blocage par domaine, la
quarantaine, la restauration et le déblocage sont manuels et n'y passent pas. Une action automatique n'est permise que
dans les cas écrits ici.

**Identité revalidée.** Tuer, suspendre et reprendre portent sur un processus identifié par son PID et son heure de création.
L'instance administrateur les lit et les montre, avec le chemin et la signature vérifiée, et le service les compare juste
avant d'agir, sur le même handle ; sinon, aucune action. Une commande sans identité est refusée. Pour un leurre : processus créé
avant l'événement. Le chemin n'est pas comparé (décision du mainteneur, 2026-11-01) : un programme qui se renomme, ou dont le
chemin est très long, doit rester suspendable et arrêtable.

La garde ne concerne que les actions automatiques, n'a aucun réglage et ne retient jamais l'alerte : seule l'action
est retenue. Un administrateur peut toujours agir à la main.

| Garde | Seuil | Effet |
|---|---|---|
| Même blocage automatique sur la même adresse | 3 fois par 24 h | ensuite, alerte seule et alerte « Critique » de boucle arrêtée (REP-002) |
| Suspension d'un programme signé installé dans Program Files, hors interpréteurs | 3 fois par 24 h | ensuite, alerte seule et alerte « Critique » de boucle arrêtée (REP-002) |
| Blocages IP par les listes, toutes cibles | 30 par heure | au-delà, arrêtés 1 h, alerte « Critique » une fois |
| Adresses distinctes par l'IPS (compteur à part des listes) | 50 par heure | au-delà, alerte seule |
| Décision humaine contraire (déblocage, reprise) | 7 jours | aucune action automatique sur cette cible, alerte seule |

- **Suspension sans plafond global, et sans seuil hors de Program Files** (décisions du mainteneur, 2026-11-01) : un
  rançongiciel ne doit pouvoir s'exempter ni avec des programmes jetables, ni en se lançant quatre fois, ni par trois touches
  via `powershell.exe`. Seul un programme signé installé dans Program Files, hors interpréteurs, a un seuil. En contrepartie,
  un programme légitime hors de ce cas est suspendu à chaque touche, et un programme relancé en boucle s'accumule, suspendu,
  jusqu'à ce qu'un administrateur le reprenne ou l'arrête. Le seuil de Program Files reste utilisable par un programme signé
  déjà installé qui toucherait les leurres trois fois : l'alerte reste.
- **Limite du plafond des listes** : un compte standard peut l'atteindre en se connectant à 31 adresses listées. Les
  blocages par les listes s'arrêtent alors une heure, renouvelable ; les alertes « Critique » restent. Le plafond protège
  d'une liste corrompue.
- **Limite de l'IPS** : `ids.rs`, gelé, écrit « bloquée » dans son alerte dès la détection, même si l'action est ensuite
  retenue ; le SIEM et le journal disent la retenue.
- **Décision humaine sur un programme** : liée à l'empreinte de l'exécutable. Un fichier remplacé au même chemin n'en
  hérite pas, et une empreinte illisible ne donne aucune exception. Une reprise n'en est une que si le programme a été
  suspendu automatiquement dans les 7 derniers jours.
- **Historique** : `reponses.json`, borné (2 000 traces, 500 décisions humaines), gardé après un redémarrage. Contenu mal
  formé : aucune action automatique, alerte REP-002 ; retirer le fichier du dossier de données, puis redémarrer le service,
  rétablit la réponse automatique. Lecture refusée (fichier tenu ouvert, protection du dossier en échec) : la garde repart
  en mémoire, sans son historique, et la réponse reste.

## Prévu en phase 6 (pas encore dans le code)

Décisions : `docs/roadmap/phase6.md`. Ces valeurs entrent en vigueur avec la PR qui les apporte.

**Mode panique transactionnel (PR 6.5).** Les deux règles sont posées et vérifiées (présentes, activées, en blocage),
puis seulement le drapeau est écrit ; un échec à n'importe quelle étape retire tout et lève l'alerte REP-003 « mode
panique NON activé ». La désactivation retire, vérifie qu'aucune règle ne reste, puis efface le drapeau ; une règle
restée garde le drapeau. L'état publié est l'état effectif, compté sur les règles : « active », « inactive » ou
« incertaine ». Un profil du pare-feu désactivé avant est réactivé pour l'activation, et rendu désactivé si elle
échoue. Limite : les serveurs DNS de la machine et les adresses des serveurs de notification restent joignables, tous
ports, pour tous les programmes (un tunnel DNS reste possible).

**Isolation sur le chemin final (PR 6.6).** Le programme est ouvert en descendant son chemin élément par élément, chaque
dossier ouvert par rapport au handle de son parent, sans suivre de point d'analyse (PR 6.13) ; son chemin final (noms courts, jonctions et points de montage résolus) est comparé au dossier Windows, et
c'est lui qui porte les règles de pare-feu. Un chemin réseau, un tube ou un volume sans lettre est refusé sur le texte,
avant toute ouverture ; un fichier qui porte le nom d'un programme critique de Windows (svchost.exe, lsass.exe…) ou
d'un programme livré avec Windows (présent dans le dossier Windows, System32 ou SysWOW64 : dllhost.exe,
RuntimeBroker.exe…, PR 6.13) hors du dossier Windows aussi (la quarantaine convient mieux ; limite : un maliciel nommé svchost.exe dans un dossier de
l'utilisateur ne peut donc pas être isolé, seulement mis en quarantaine), ainsi qu'un chemin dont un dossier est un
lien (l'administrateur donne le chemin réel). Toutes les 5 minutes, chaque isolation est revérifiée par la même descente, dossier par dossier
sans suivre de lien (seules comptent les étiquettes qui redirigent le chemin, bit « substitut de nom » : jonctions, liens
symboliques…, pas les fichiers OneDrive à la demande ; un chemin illisible 3 relevés de suite est dit par REP-004). Le
chemin n'est jamais repassé à Windows en entier : un dossier remplacé par un lien pendant la lecture n'est pas traversé
(PR 6.13 ; avant, il pouvait l'être entre la lecture des dossiers et l'ouverture du fichier) : si son chemin mène ailleurs (dossier remplacé par une jonction ou un lien), l'alerte REP-004 le dit, une fois ; les règles sont gardées, jamais levées
automatiquement, et peuvent alors couper le réseau du programme visé : la décision reste humaine. Limite : un programme isolé copié
ailleurs n'est plus coupé du réseau (la règle vise un chemin, pas un fichier).

**Interface (PR 6.7b).** La page « Réponses en cours » montre chaque action active : quoi, sur quoi, déclencheur,
depuis quand, échéance de relance, état (« relance en attente » en jaune, mode panique en rouge, toujours écrit en
toutes lettres), procédure de récupération, service arrêté compris. Son bouton (« Reprendre », « Libérer »,
« Débloquer », « Rétablir Internet », « Restaurer ») envoie la commande par le canal : pour un compte non administrateur,
par l'assistant élevé et sa confirmation ; pour un administrateur, après la confirmation de la page (et celle de
l'assistant pour « Reprendre »). « Reprendre » refuse un PID réutilisé (heure de création comparée). La confirmation du mode panique dit
sa portée (tout Internet, IPv4 et IPv6 ; connexions IPv6 ouvertes non coupées ; réseau local, DNS et serveurs de
notification joignables), la relance à 4 h et le retour arrière ; l'en-tête montre l'état effectif publié par le
service. La confirmation d'une isolation montre le chemin réel qui sera isolé, aussi à un administrateur, quand il est sur un
disque local fixe et lisible en 2 s.

**Échéances.** Une échéance est un rendez-vous de relance, pas une levée. Depuis la PR 6.4, le registre des actions
(`reponses.json`) suit les suspensions, l'isolation et le mode panique, et depuis la PR 6.4b la quarantaine et les
blocages manuels ; une relance est l'alerte REP-001, une seule par sorte d'action et par heure au plus (24 h pour la
quarantaine et le blocage manuel ; les relances retenues partent, comptées, avec la suivante). Un processus
suspendu qui n'existe plus passe à « terminé », sans alerte. Au-delà de 500 actions en cours, seules les plus anciennes
suspensions automatiques, quarantaines et blocages manuels sortent du suivi ; un mode panique, une isolation ou une
suspension manuelle restent toujours suivis. L'état réel des fils d'un processus suspendu n'est pas relu : la relance dit
qu'il peut avoir été repris hors de deR4Tizer.

| Action | Échéance | À l'échéance | État |
|---|---|---|---|
| Blocage IP de niveau 3 (Spamhaus DROP, Feodo Tracker) | 7 jours | levé ; plus tôt si l'adresse sort de la liste | fait |
| Blocage IP par l'IPS | 24 h | levé | fait (PR 6.4) |
| Suspension automatique (leurre) | 2 h | reste suspendu ; relance « Critique », puis toutes les 24 h | fait (PR 6.4) |
| Suspension manuelle | 24 h | reste suspendu ; relance « Alerte », puis toutes les 24 h | fait (PR 6.4) |
| Isolation d'un programme | 7 jours | reste isolé ; relance « Alerte », puis tous les 7 jours | fait (PR 6.4) |
| Mode panique | 4 h | reste actif ; relance « Critique », puis toutes les 24 h | fait (PR 6.4) |
| Quarantaine | 30 jours | reste en quarantaine, jamais supprimée ; relance « Info », puis tous les 30 jours ; close par une restauration | fait (PR 6.4b) |
| Blocage manuel (hosts, IP) | 90 jours | reste bloqué ; rappel « Info », puis tous les 90 jours ; clos par un déblocage | fait (PR 6.4b) |
| Tuer, tuer une chaîne | sans objet | irréversible, journalisé | — |

Un blocage automatique dont l'échéance n'a pas été écrite en reçoit une au contrôle suivant : 24 h s'il vient de l'IPS,
7 jours sinon.

**Récupération.** Chaque procédure sera écrite et vérifiée en VM par la PR qui porte l'action ; celle qui n'est que lue sera déclarée « non exécutée ».

| Action | Avec le service | Service arrêté ou en panne | Après la désinstallation |
|---|---|---|---|
| Suspension | « Reprendre » (identité revalidée) ou « Tuer » | Moniteur de ressources de Windows (`resmon`, « Reprendre le processus »), ou arrêt du processus dans le Gestionnaire des tâches | le processus reste suspendu jusqu'à son arrêt ou au redémarrage : redémarrer le poste |
| Isolation | « Libérer » (sur le chemin final ; contrôle VM écrit par la PR 6.6, pas encore exécuté) | Pare-feu Windows avancé : supprimer les règles « deR4Tizer - isole … » (groupe `deR4Tizer`) | `--nettoyer` retire le groupe, à vérifier pour les règles d'isolation |
| Mode panique | « Rétablir Internet » ; aussi sûr en état « incertain » (signal VM, PR 6.5) | supprimer les règles « deR4Tizer PANIQUE » dans le pare-feu, puis le fichier `panique-active` du dossier de données | `--nettoyer`, d'après les règles et pas seulement le drapeau |
| Blocage IP | « Débloquer » | règles « deR4Tizer » du pare-feu | `--nettoyer` |
| Quarantaine | « Restaurer » ou repli | aucune (copie encodée dans le dossier de données) | avec `GARDER_DONNEES=1` : réinstaller puis restaurer ; sans : perdue, à vérifier |

## Écarts du code actuel (4.3) avec cette politique

| Écart | Où | À traiter |
|---|---|---|
| L'IPS, une fois activé, bloque au pare-feu sans confirmation (niveau 2 « désactivé par défaut », conforme), mais sans durée maximale propre ni procédure de récupération documentée. | `ids.rs`, `moniteur.rs` | Phase 6. |
| Aucune durée maximale ni relance vers le prestataire pour un processus suspendu ou un programme isolé. | `vol_donnees.rs`, `reponse.rs` | Phase 6. |
