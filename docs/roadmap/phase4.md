# Phase 4 : incidents, chronologie, santé des collecteurs et de l'interface

Ouverte le 2026-10-27, à la fusion de la dernière PR de la phase 3 (PR 3.12), d'après la réponse du mainteneur du
2026-10-26 (`CLAUDE.md`, section 5, point 3). Ce document fixe le périmètre, le découpage et les décisions de la phase.
Rien de ce qu'il décrit n'existe encore dans le code : chaque élément passe à « testé en labo » dans la matrice
(`docs/roadmap/capability-matrix.md`) seulement avec la PR qui l'apporte.

## Besoin

Le poste d'une TPE ou d'une petite commune n'a ni SOC ni administrateur sur place, et le prestataire ne voit que ce que
deR4Tizer lui envoie. Quatre manques :

1. **Pas de suivi** : une alerte reste un message isolé, qu'on ne peut ni prendre en charge ni clore.
2. **Pas de chronologie par incident** : reconstituer ce qui s'est passé autour d'une alerte est une recherche manuelle
   dans le SIEM, et les actions de réponse n'y figurent pas.
3. **Une panne reste silencieuse dans le temps** : l'état des collectes est visible depuis la phase 3, mais il n'est ni
   historisé ni remonté ; une remontée qui échoue n'est pas retentée.
4. **L'interface peut disparaître sans bruit** : l'utilisateur, ou un programme de son compte, peut la fermer, et le
   service ne le voit pas. Les notifications locales n'apparaissent plus sans elle ; la détection et la remontée par le
   service continuent.

## Ce que la phase ne fait pas

- aucune nouvelle détection, au-delà des constats de santé (`SAN-*`) ;
- aucune action de réponse nouvelle ni modifiée (phase 6) : les actions existantes sont seulement **enregistrées** ;
- aucune fermeture automatique d'un incident ;
- aucun envoi au prestataire du contenu d'une chronologie (lignes de commande, comptes) : le résumé seulement ;
- rien des phases 6 à 9, ni dégel de l'IDS, du DPI ou du NDR.

## Découpage

Chaque PR part de `main` à jour, sans empilement, avec sa relecture et son passage complet en VM avant la fusion.

| PR | Contenu |
|---|---|
| 4.0 | Ce document, le modèle prévu (`docs/detection/modele-evenement.md`), les lignes « prévu » de la matrice |
| 4.1 | `HeureUtc` et `Seq` sur les alertes et les événements ; pertes de la file du SIEM comptées ; actions de réponse dans le SIEM (`Source` « reponse ») |
| 4.2 | Incidents : modèle, rattachement des alertes, `suivi-incidents.json`, commande `incident` (administrateurs) |
| 4.3 | Chronologie par incident (calcul hors du verrou du moniteur, trous de collecte, bornes) |
| 4.4 | Santé des collectes, en deux PR : **4.4a** historique et constats SAN-001, SAN-002, SAN-003, SAN-012 ; **4.4b** file de remontée retentée, SAN-004, battement quotidien (touche `notifications.rs`, chemin privilégié, audité à part) |
| 4.5 | Santé de l'interface, en deux PR : **4.5a** repérage par le service, collecte `Sessions`, SAN-010 et SAN-011 (et la suite S99-04 de la remontée) ; **4.5b** relance par une tâche planifiée posée par le MSI (D4-1, option C, accord du mainteneur le 2026-10-27), `--relance` sans invite, texte de « Quitter » |
| 4.6 | Interface : pages Incidents et Santé |

Les fiches `SAN-*` entrent dans `docs/detection/regles.md` avec leur entrée au registre (`regles.rs`), leur code et
leurs tests, dans la PR qui les apporte (4.2, 4.4, 4.5) : le test du registre exige que les fiches et le registre
concordent.

## Décisions

Le mainteneur a demandé, le 2026-10-26, d'enchaîner sur la phase 4 sans attendre sa validation de la phase 3 (réponse
« Enchaîner sur la phase 4 »). Dans le cadre de cette réponse, les décisions ouvertes ont été **tranchées par l'agent**,
selon les recommandations du dossier de conception ; le mainteneur peut revenir sur chacune.

| # | Décision | Retenu |
|---|---|---|
| D4-1 | Interface disparue : relancer ou alerter | Repérage et alerte par le service (SAN-010 après 15 min d'absence, niveau « Critique », décision du mainteneur le 2026-10-31 ; SAN-011 après 3 arrêts en une heure, niveau « Alerte », remonté seulement si la remontée est configurée à ce niveau) : retenus. La **relance** par une tâche planifiée posée par le MSI, sous l'identité de l'utilisateur, est un comportement privilégié (`CLAUDE.md`, section 4, « Avant chaque lot », point 3) : elle attendait **l'accord explicite du mainteneur**, donné le 2026-10-27 (« the service may relaunch the interface through a scheduled task (decision D4-1) > validated »), puis un essai en VM : descripteur de la tâche non modifiable par un compte standard, fait avec la PR 4.5b ; **sessions Bureau à distance et changement rapide d'utilisateur reportés à la campagne de fin de phase 7, depuis la VM Kali, par décision du mainteneur le 2026-10-31, aucune version n'étant publiée avant** ; retour arrière vers une version sans relance, comportement relevé en VM, limite acceptée par le mainteneur le 2026-10-31, la 4.5b entrant dans la première version distribuée. Sans cet accord, ou si l'essai échoue : alerte seule, sans relance. Une relance directe par le service (création de processus dans la session) n'est pas envisagée. |
| D4-2 | Fichier du suivi | Nouveau `suivi-incidents.json`, écrit par le moniteur seul ; `incidents.json` (corrélations du SIEM) inchangé. |
| D4-3 | Fermeture automatique d'un incident | Jamais. Un incident sans activité depuis 7 jours est seulement affiché « inactif ». |
| D4-4 | `HeureUtc` et `Seq` dans `Alerte` et `Evenement` | Oui, en ajouts au modèle 1 : sans eux, la chronologie se trompe d'ordre pendant l'heure répétée du passage à l'heure d'hiver. |
| D4-5 | Collectes « critiques » pour SAN-001 | `JournalDefender`, `EtatDefender`, `JournalSecurite`, `Connexions`, `Processus`, `ListesMenaces`. |
| D4-6 | Battement quotidien au prestataire | Oui, quand la remontée est configurée : compteurs seulement, une fois par jour. |
| D4-7 | Suivi et chronologie dans l'API d'export | Non pendant la phase 4 (à reprendre avec la phase 8, mode avancé). |
| D4-8 | File de remontée sur disque | Non : en mémoire, bornée (100 éléments, 24 h) ; la perte au redémarrage est une limite écrite. |
| D4-9 | Nouvelle dépendance | Aucune. |
| D4-10 | « Faux positif » à la clôture | Aucune exception posée d'office ; elle est proposée à part, avec sa propre confirmation. |

## Preuve

GitHub Actions est toujours désactivé. `CLAUDE.md` ne prévoit la preuve locale en VM à la place de la CI GitHub que pour
la phase 3. Pour la phase 4, elle est **appliquée d'après la réponse du mainteneur du 2026-10-26**, en attendant qu'il
l'inscrive dans `CLAUDE.md`. Rien ne change pour la distribution : CI GitHub verte, lot 3d réussi, binaires signés et
relecture indépendante restent exigés.

## À inscrire dans `CLAUDE.md` par le mainteneur

L'agent ne peut pas modifier `CLAUDE.md`. Texte proposé, sous la section 5, point 3 :

- Ouverture : le 2026-10-26, le mainteneur a demandé d'enchaîner sur la phase 4 à la fin de la phase 3, sans attendre sa
  validation de celle-ci (réponse « Enchaîner sur la phase 4 »). Décisions de la phase : `docs/roadmap/phase4.md`.
- Comme pour la phase 3, la preuve locale en VM (section 4, « Exception temporaire ») tient lieu de CI GitHub pour les
  PR de la phase 4. Rien ne change pour la distribution.
- D4-1 : la relance de l'interface par une tâche planifiée : accord explicite du mainteneur le 2026-10-27, essai en VM avec la PR 4.5b.
