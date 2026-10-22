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

## Écarts du code actuel (4.3) avec cette politique

| Écart | Où | À traiter |
|---|---|---|
| Avec le réglage « listes restreintes » (désactivé par défaut), le blocage automatique s'étend aux autres listes de confiance haute : FireHOL niveau 1 et ThreatView Cobalt Strike. | `menaces.rs` (`SOURCES`, champ `confiance`), `moniteur.rs` (`blocage_auto_menaces`) | Phase 6 : limiter le blocage automatique à Spamhaus DROP et Feodo Tracker. |
| L'IPS, une fois activé, bloque au pare-feu sans confirmation (niveau 2 « désactivé par défaut », conforme), mais sans durée maximale propre ni procédure de récupération documentée. | `ids.rs`, `moniteur.rs` | Phase 6. |
| Aucune durée maximale ni relance vers le prestataire pour un processus suspendu ou un programme isolé. | `vol_donnees.rs`, `reponse.rs` | Phase 6. |
| Revalidation de l'identité du processus juste avant l'action et protection contre les boucles d'actions : non systématiques. | `reponse.rs`, `moniteur.rs` | Phase 6. |
