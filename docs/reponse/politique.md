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
   (`reponse::protege`) ne sont jamais suspendus ; les logiciels connus et signés de sauvegarde, de
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

**Identité revalidée.** Tuer, suspendre et reprendre portent sur un processus identifié par son PID, son heure de création et
son chemin. L'instance administrateur les lit, les montre, et le service les compare juste avant d'agir, sur le même handle ;
sinon, aucune action. Une commande sans identité est refusée. Pour un leurre : même programme, créé avant l'événement.

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

**Échéances.** Une échéance est un rendez-vous de relance, pas une levée.

| Action | Échéance | À l'échéance |
|---|---|---|
| Blocage IP de niveau 3 (Spamhaus DROP, Feodo Tracker) | 7 jours | levé ; plus tôt si l'adresse sort de la liste |
| Blocage IP par l'IPS | 24 h | levé |
| Suspension automatique (leurre) | 2 h | reste suspendu ; relance « Critique », puis toutes les 24 h |
| Suspension manuelle | 24 h | reste suspendu ; relance « Alerte », puis toutes les 24 h |
| Isolation d'un programme | 7 jours | reste isolé ; relance « Alerte », puis tous les 7 jours |
| Mode panique | 4 h | reste actif ; relance « Critique », puis toutes les 24 h |
| Quarantaine | 30 jours | reste en quarantaine, jamais supprimée ; relance « Info » |
| Blocage manuel (hosts, IP) | aucune | rappel « Info » tous les 90 jours |
| Tuer, tuer une chaîne | sans objet | irréversible, journalisé |

**Récupération.** Chaque procédure sera écrite et vérifiée en VM par la PR qui porte l'action ; celle qui n'est que lue sera déclarée « non exécutée ».

| Action | Avec le service | Service arrêté ou en panne | Après la désinstallation |
|---|---|---|---|
| Suspension | « Reprendre » (identité revalidée) ou « Tuer » | Moniteur de ressources de Windows (`resmon`, « Reprendre le processus »), ou arrêt du processus dans le Gestionnaire des tâches | le processus reste suspendu jusqu'à son arrêt ou au redémarrage : redémarrer le poste |
| Isolation | « Libérer » | Pare-feu Windows avancé : supprimer les règles « deR4Tizer - isole … » (groupe `deR4Tizer`) | `--nettoyer` retire le groupe, à vérifier pour les règles d'isolation |
| Mode panique | « Désactiver le mode panique » | supprimer les règles « deR4Tizer PANIQUE » dans le pare-feu | `--nettoyer` |
| Blocage IP | « Débloquer » | règles « deR4Tizer » du pare-feu | `--nettoyer` |
| Quarantaine | « Restaurer » ou repli | aucune (copie encodée dans le dossier de données) | avec `GARDER_DONNEES=1` : réinstaller puis restaurer ; sans : perdue, à vérifier |

## Écarts du code actuel (4.3) avec cette politique

| Écart | Où | À traiter |
|---|---|---|
| L'IPS, une fois activé, bloque au pare-feu sans confirmation (niveau 2 « désactivé par défaut », conforme), mais sans durée maximale propre ni procédure de récupération documentée. | `ids.rs`, `moniteur.rs` | Phase 6. |
| Aucune durée maximale ni relance vers le prestataire pour un processus suspendu ou un programme isolé. | `vol_donnees.rs`, `reponse.rs` | Phase 6. |
