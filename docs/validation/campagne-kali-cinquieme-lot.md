# Campagne Kali — cinquième lot (lot 3d Defender formel ; sessions standard : spécificité)

> **Note du 2026-11-19** (audit documentaire ; les résultats ci-dessous ne sont pas réécrits) : (1) Le « lot 3d » mesuré ici (scan de Defender sans détection, sur le produit des instantanés, sans artefact de la CI, sans quarantaine ni restauration) n'est pas le lot 3d de `CLAUDE.md` et de la matrice (`tests/vm/lot3d.ps1`, 12 contrôles) : c'est un essai de non-détection. (2) N-02 en configuration C est une hypothèse, non évaluée. (3) Aucun nombre d'essais n'est donné : mesures non consolidées.

Date : 2026-11-16. Liste des scénarios : v1.4 (`campagne-kali-phase1.md`). Résultats bruts hors dépôt.
Aucune donnée personnelle, aucun nom de poste, aucun mot de passe. Adresses du labo : plages de documentation
(RFC 5737) ; noms de test en `.test` (RFC 2606). Ce lot couvre deux critères durs restants de l'étape 1 :
le **scénario Defender formel (lot 3d)** et les **sessions standard** (tests négatifs de spécificité).

**Réserve (latences)** : comme aux passages précédents, l'horloge de la VM est décalée dans les résultats bruts ; les
verdicts reposent sur la présence (ou l'absence) du comportement attendu, pas sur l'heure. Préconditions auto-validées
(ci-dessous).

## Lot 3d — Defender formel (le produit installé n'est pas considéré malveillant)

Mesure sur le produit **courant** (deR4Tizer 4.3, MSI `6AC1B4F15290`) tel qu'installé dans les instantanés de campagne,
avec **Microsoft Defender pleinement actif**. L'artefact de CI n'a pas été nécessaire : le build courant est déjà présent
dans le labo. Defender n'est **jamais** modifié.

| Scénario | Configuration | Verdict | Résumé |
|---|---|---|---|
| lot 3d (Defender formel) | C (baseline durcie) | **VP** | Protection temps réel **et** surveillance comportementale **et** antivirus actifs ; **aucune exclusion** ne couvre deR4Tizer ; scan personnalisé du dossier d'installation + `C:\ProgramData\deR4Tizer` puis analyse rapide **terminés** ; **zéro détection** (`Get-MpThreatDetection`/`Get-MpThreat`) ; binaire **intact** (non mis en quarantaine) ; service **Running**. |
| lot 3d (Defender formel) | A (sans baseline) | **VP** | Identique, Defender actif sans durcissement. |

**Précondition auto-validée** : l'essai n'est retenu que si (1) Defender est **pleinement actif** (temps réel +
comportement + antivirus) et (2) **aucune exclusion** ne couvre un chemin ou un processus deR4Tizer ; sinon l'essai est
déclaré invalide (D), jamais un faux « aucune détection ».

**Point notable (honnête)** : le binaire installé `deR4TizerSvc.exe` est **non signé** (la signature de code — Certum /
SignPath — est l'étape 5 du lancement, pas encore faite). *Note du 2026-11-19 : « étape 5 du lancement » renvoie au plan de lancement du mainteneur, hors dépôt (signature de la version, puis lot 3d rejoué sur la version signée) ; le certificat retenu est Certum Open Source (2026-11-11), SignPath est écarté (`CLAUDE.md`, section 6).* Le résultat est d'autant plus significatif : Defender, y compris
en baseline durcie (ASR activé, cloud élevé, PUA), **ne flague pas** un service SYSTEM non signé.

**Portée** : c'est un **signal en VM de test**, pas une preuve sur un poste réel. Les conditions de distribution restent
inchangées (voir README) : CI GitHub verte, lot 3d réussi sur **la version distribuée et signée**, relecture indépendante.

## Sessions standard — spécificité (tests négatifs)

Une activité légitime ne doit produire **aucune** alerte de niveau Alerte/Critique.

| Test | Configuration | Verdict | Résumé |
|---|---|---|---|
| N-01 (session locale + administration PowerShell signée + interface) | A | **RÉUSSI** | **Zéro** alerte Alerte/Critique ; ouverture de session **collectée** (4624 dans le mini-SIEM : la collecte fonctionne) ; aucune collecte en panne. |
| N-01 | C (baseline durcie) | **RÉUSSI** | Identique ; le pilotage et la collecte fonctionnent sous la baseline ; aucune alerte due à la baseline. |
| N-02 (tâche planifiée créée par un administrateur vers un programme signé de Program Files) | A | **RÉUSSI** | PER-001 au plus au niveau **Info** ; **aucune** alerte Alerte/Critique ; création de tâche observée par la collecte (précondition prouvée). |

**Précondition auto-validée** : N-01 n'est « RÉUSSI » que si une **ouverture de session est réellement collectée**
(preuve que la collecte tourne) ; N-02, que si la **tâche est réellement créée** et qu'un événement de création (ou une
entrée PER-001) est observé. Sans cette preuve, l'essai est D — jamais un faux « aucune alerte » dû à une collecte morte.

**Témoin négatif déjà couvert — N-05** : le retour de la carte au DNS du réseau (DHCP) après le filtrage **ne déclenche
pas** DNS-002 ; ce comportement a été exercé à la remise en état du troisième lot (S-06), la carte étant rendue par
`ResetServerAddresses` sans alerte.

## Grille de couverture — mise à jour (cumul des cinq lots)

| Domaine / technique | Règle attendue | Config A | Config C |
|---|---|---|---|
| Vol d'identifiants de navigateur (T1555 / T1539) | VOL-001 | **VP (Critique)** | **VP (Critique)** |
| Requête vers domaine malveillant connu (T1071 / renseignement) | DNS-001 | **VP (Critique)** | **VP (Critique)** |
| Connexion vers IP de menace connue (T1071) | RES-001 + blocage auto | **VP (Critique + blocage 7 j)** | **VP (Critique + blocage 7 j)** |
| Changement de serveur DNS sur une carte (T1557) | DNS-002 | **VP (Alerte)** | **VP (Alerte)** |
| Filtrage DNS : nom listé bloqué (adresse nulle) | filtrage par résolveur local | **VP** | **VP** |
| Defender pleinement actif ne flague pas le produit | lot 3d (non-détection) | **VP** | **VP** |
| Session légitime : aucune alerte forte | N-01 (spécificité) | **RÉUSSI** | **RÉUSSI** |
| Tâche planifiée bénigne : Info au plus | N-02 (spécificité) | **RÉUSSI** | — (hypothèse « identique ») |

## Méthode (rappel)

Instantanés « campagne A » (sans baseline) et « campagne C » (baseline à 100 %). Remise à l'instantané avant et après
chaque essai, VM remise en veille à la fin. Defender jamais modifié à la main. Lot 3d et sessions standard sont
entièrement locaux (la VM Kali n'intervient pas pour N-01/N-02 ; aucune adresse réelle contactée).
