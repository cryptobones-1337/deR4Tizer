# Phase 6 : politique de réponse appliquée dans le code

Ouverte le 2026-11-01, à la fin de la phase 4, sur l'accord explicite du mainteneur (réponse « Oui, selon le dossier »,
`CLAUDE.md`, section 5, point 4). Ce document fixe le périmètre, le découpage et les décisions de la phase. Ce qu'il
prévoit n'existe pas encore dans le code, sauf ce qui est dit « comme aujourd'hui » : chaque élément passe à « testé en labo » dans la matrice
(`docs/roadmap/capability-matrix.md`) seulement avec la PR qui l'apporte.

## Besoin

Une action de réponse coupe ou modifie quelque chose sur un poste sans informaticien sur place. Quatre manques :

1. **Le niveau 3 déborde** : avec le réglage « listes restreintes », le blocage automatique s'étend à FireHOL niveau 1 et
   à ThreatView, ce que la politique ne permet pas.
2. **L'identité n'est pas revalidée** : entre la décision et l'action, un PID réutilisé peut désigner un autre programme.
3. **Rien ne borne la répétition** : une adresse débloquée à la main est rebloquée dès qu'une connexion vers elle reparaît, et un programme
   repris peut être suspendu de nouveau sans limite.
4. **Rien n'a d'échéance** : un processus suspendu, un programme isolé ou le mode panique le restent sans que personne
   ne soit relancé.

## Ce que la phase ne fait pas

- aucune nouvelle action, aucun nouveau déclencheur automatique, aucun élargissement du niveau 3 ;
- aucun arrêt automatique d'un processus, aucune mise en quarantaine automatique ;
- aucune modification de la logique de l'IDS, du DPI ou du NDR, qui restent gelés : la politique s'applique en aval, dans
  le moniteur ;
- rien de Microsoft Defender, ni rien des phases 7 à 9.

## Découpage

Chaque PR part de `main` à jour, sans empilement, avec sa relecture, son audit et son passage complet en VM avant la
fusion. Celles qui touchent le même fichier passent l'une après l'autre.

| PR | Contenu |
|---|---|
| 6.0 | Ce document, la section « Prévu en phase 6 » de la politique, les lignes « prévu » de la matrice |
| 6.1 | Niveau 3 restreint par l'identité de la source : Spamhaus DROP et Feodo Tracker seulement, quel que soit le réglage |
| 6.2 | Point de décision unique (`politique.rs`) et garde contre les boucles ; tous les déclencheurs automatiques y passent |
| 6.3 | Identité revalidée par handle, action sur ce même handle ; nouveaux champs de commande ; confirmation complète |
| 6.4 | Registre `reponses.json`, échéances, relances (`REP-001`) |
| 6.5 | Mode panique transactionnel, état effectif, PowerShell hors du verrou |
| 6.6 | Isolation sur le chemin final, lu par handle |
| 6.7 | Interface : page « Réponses en cours », portée et retour arrière du mode panique |

Chaque PR apporte la procédure de récupération de ses actions, écrite et vérifiée en VM ; celle qui n'est que lue est
déclarée « non exécutée ». Les procédures prévues sont dans `docs/reponse/politique.md`.

Les fiches `REP-*` entrent dans `docs/detection/regles.md` avec leur entrée au registre (`regles.rs`), leur code et leurs
tests, dans la PR qui les apporte : le test du registre exige que les fiches et le registre concordent.

## Décisions

Accord explicite du mainteneur le 2026-11-01 sur les recommandations du dossier de conception, pour les PR 6.1 à 6.7
tant qu'elles y restent. La question posée rappelait : listes restreintes en alerte seule, identité revalidée avant
chaque action, décision humaine prioritaire 7 jours, jamais de reprise automatique. Elle rappelait aussi un plafond de 3
suspensions par heure, retiré ensuite par le mainteneur (voir plus bas).

| # | Décision | Retenu |
|---|---|---|
| D6-1 | Politique et IPS, sans dégeler l'IDS | En aval, dans le moniteur, sur la file des blocages ; `ids.rs` intact. |
| D6-2 | Identité d'un processus | PID et heure de création, revalidés et appliqués sur un même handle. Le chemin est montré, pas comparé (décision du mainteneur, 2026-11-01, après l'audit de la PR 6.3 : un programme qui se renomme y échappait). L'empreinte SHA-256 de l'exécutable n'est exigée que pour la liste « décision humaine ». |
| D6-3 | Échéances | Voir la politique : ce sont des rendez-vous de relance, jamais une levée pour la suspension, l'isolation et le mode panique. |
| D6-4 | Durée d'un blocage par l'IPS | 24 h, au lieu des 7 jours hérités. |
| D6-5 | Seuils de la garde | 3 actions par cible et par 24 h (pour une suspension : programme signé dans Program Files seulement, décision du mainteneur, 2026-11-01) ; 30 blocages par les listes par heure ; 50 adresses par heure pour l'IPS, à part ; décision humaine prioritaire 7 jours. Aucun réglage dans l'interface. Le plafond de 3 suspensions par heure du dossier est retiré (décision du mainteneur, 2026-11-01). |
| D6-6 | Relance sans remontée configurée | Locale seulement, et la page Santé le dit. Sans canal, personne n'est prévenu : limite écrite. |
| D6-7 | Échec de `--nettoyer` à la désinstallation | La désinstallation n'est jamais bloquée ; un compte rendu est écrit et vérifié. |
| D6-8 | Nouvelle dépendance | Aucune. |
| D6-9 | Arrêt automatique d'un processus | Hors du niveau 3, comme aujourd'hui. |
| D6-10 | Suspension sur leurre, protection du dossier en échec | Gardée, comme aujourd'hui : elle ne dépend d'aucun fichier du dossier de données. Seules les actions alimentées par ces fichiers sont refusées. |

## Plafond des suspensions retiré

Le dossier prévoyait au plus 3 suspensions automatiques par heure. L'audit de la PR 6.2 a montré qu'un compte standard
pouvait l'user avec 3 programmes jetables, puis lancer un rançongiciel qui ne serait pas suspendu. Le mainteneur a décidé
de le retirer le 2026-11-01. L'audit a ensuite montré que le seuil de 3 par programme en 24 h permettait la même attaque,
par un programme lancé quatre fois ou par trois touches via `powershell.exe`. Le mainteneur l'a limité le même jour aux
programmes signés installés dans Program Files, hors interpréteurs. Tout le reste est toujours suspendu, et seule une
reprise par un administrateur arrête une boucle.

## Preuve

GitHub Actions est toujours désactivé. Pour la phase 6, la preuve locale en VM tient lieu de CI GitHub, d'après la même
réponse du mainteneur, qui portait aussi sur ce régime de preuve, en attendant qu'il l'inscrive dans `CLAUDE.md`. Rien ne
change pour la distribution : CI GitHub verte, lot 3d réussi, binaires signés et relecture indépendante restent exigés.

Les échéances longues (2 h, 24 h, 7 jours) ne seront vérifiées qu'en labo : aucun réglage de test dans le binaire livré.
La reprise par le Moniteur de ressources de Windows est décrite, pas testée, et le cas d'un processus suspendu sans
registre n'est pas reproduit. Les scénarios le déclareront « non exécuté ».

## À inscrire dans `CLAUDE.md` par le mainteneur

L'agent ne peut pas modifier `CLAUDE.md`. Texte proposé, sous la section 5, point 4 :

- Ouverture : le 2026-11-01, à la fin de la phase 4, accord explicite du mainteneur pour coder la phase selon le dossier
  de conception (réponse « Oui, selon le dossier »). Décisions de la phase : `docs/roadmap/phase6.md`.
- Comme pour les phases 3 et 4, la preuve locale en VM (section 4, « Exception temporaire ») tient lieu de CI GitHub pour
  les PR de la phase 6. Rien ne change pour la distribution.
