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
   libres d'usage). Le blocage est levé quand l'adresse sort de la liste ou à expiration (7 jours).
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

**Garde contre les boucles.** Elle ne concerne que les actions automatiques, n'a aucun réglage et ne retient jamais
l'alerte : seule l'action est retenue.

| Garde | Seuil | Effet |
|---|---|---|
| Même action automatique sur la même cible | 3 fois par 24 h | ensuite, alerte seule et alerte « Critique » de boucle arrêtée |
| Blocages IP automatiques, toutes cibles | 30 par heure | au-delà, suspendus 1 h, alerte « Critique » une fois |
| Suspensions automatiques, toutes cibles | 3 par heure | au-delà, suspendues 1 h, alerte « Critique » une fois |
| Adresses distinctes par l'IPS | 50 par heure | au-delà, alerte seule |
| Décision humaine contraire (déblocage, reprise) | 7 jours | aucune action automatique sur cette cible, alerte seule |

## Écarts du code actuel (4.3) avec cette politique

| Écart | Où | À traiter |
|---|---|---|
| Avec le réglage « listes restreintes » (désactivé par défaut), le blocage automatique s'étend aux autres listes de confiance haute : FireHOL niveau 1 et ThreatView Cobalt Strike. | `menaces.rs` (`SOURCES`, champ `confiance`), `moniteur.rs` (`blocage_auto_menaces`) | Phase 6 : limiter le blocage automatique à Spamhaus DROP et Feodo Tracker. |
| L'IPS, une fois activé, bloque au pare-feu sans confirmation (niveau 2 « désactivé par défaut », conforme), mais sans durée maximale propre ni procédure de récupération documentée. | `ids.rs`, `moniteur.rs` | Phase 6. |
| Aucune durée maximale ni relance vers le prestataire pour un processus suspendu ou un programme isolé. | `vol_donnees.rs`, `reponse.rs` | Phase 6. |
| Revalidation de l'identité du processus juste avant l'action et protection contre les boucles d'actions : non systématiques. | `reponse.rs`, `moniteur.rs` | Phase 6. |
