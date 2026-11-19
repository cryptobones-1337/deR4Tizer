# Campagne Kali — sixième lot (scénarios v1.4 restants : sessions, réseau, exécution, simulations)

Date : 2026-11-16. Liste des scénarios : v1.4 (`campagne-kali-phase1.md`). Résultats bruts hors dépôt.

> **Note du 2026-11-19** (audit documentaire ; les résultats ci-dessous ne sont pas réécrits) : (1) « Ce lot termine les scénarios v1.4 non encore exécutés » est inexact : restent sans résultat N-03, N-04, S-18, S-05 (a) et (b), S-10 (b), S-11 (b) et (c), l'option longue de S-16, « Débloquer » de S-07 et le volet réussite de S-03 (liste dans `README.md` de ce dossier). (2) Grille du §5 : N-02 « RÉUSSI » en configuration C et SAN-010 en C sont des hypothèses (« tenue pour identique ») : non évalués ; les lignes PowerShell encodé (PRC-002, VP avec Sysmon) et accès limité à LSASS (B2) sont des mesures de la configuration B, pas de A ni de C. (3) « IDS/DPI/NDR gelés » vaut à la date du lot ; dégelés depuis (IDS et NDR le 2026-11-16, DPI le 2026-11-18, `CLAUDE.md`, paragraphe « Dégel de l'IDS, du NDR et du DPI »). (4) Aucun nombre d'essais n'est donné : mesures non consolidées.
Aucune donnée personnelle, aucun nom de poste, aucun mot de passe. Adresses du labo : plages de documentation
(RFC 5737) ; noms de test en `.test` (RFC 2606). Ce lot termine les scénarios v1.4 non encore exécutés.

**Réserve (latences)** : comme aux passages précédents, l'horloge de la VM est décalée dans les résultats bruts ; les
verdicts reposent sur la présence (ou l'absence) du comportement attendu, pas sur l'heure. Préconditions auto-validées
repliées dans chaque mesure (verdict D si une précondition n'est pas tenue, jamais un faux négatif).

**Mécanisme d'identifiant de test** (sous-lots sessions) : pour les scénarios à session authentifiée réussie, un compte
de test **dédié** est créé après restauration avec un **mot de passe généré** (jamais un mot de passe réel), transmis à
la VM attaquante par le canal SSH chiffré, **jamais journalisé ni écrit en preuve**, et effacé par la remise à
l'instantané. Le mot de passe de la VM attaquante n'est jamais saisi (accès par clé seulement).

## 1. Sessions et corrélations

| Scénario | Config A | Config C | Règle mesurée |
|---|---|---|---|
| S-17 — session administrative à distance sur partage admin (T1021.002) | **VP** | **VP** | COR-R9 Alerte « Session ouverte depuis Internet » ; 4672 présent (jeton admin) ; 5140 produit mais non lu (B2) |
| S-04 — connexion distante au canal de commandes (IPC-03) | **VP** | **VP** | COR-R9 Alerte ; tube `deR4Tizer` distant **rejeté** (`STATUS_ACCESS_DENIED`, `PIPE_REJECT_REMOTE_CLIENTS`), aucune commande exécutée |
| S-02 — force brute RDP **suivie d'une réussite** (T1110.001/T1078.003/T1133) | **VP** | **P-baseline** | COR-R1 Alerte + **COR-R2 Critique** (≥ 5 échecs) + COR-R9 Alerte (réussite) |

**Première mesure de COR-R2 (Critique) et du volet « réussite » de COR-R9** de toute la campagne (reportés au premier
passage). En configuration C, le Bureau à distance est refusé par la baseline durcie (3389 non à l'écoute) : prévention
confirmée, COR-R2/R9 non exerçables.

**Constat produit (honnête) — COR-R9 sur RDP = Alerte, pas Critique.** Pour une ouverture Bureau à distance réussie,
Windows émet la 4624 **type 3 (réseau NLA) avant** la type 10 (RemoteInteractive), de même IP et même utilisateur. La
clé de déduplication `R9|ip|user` est prise par la type 3, dont le message ne contient pas « bureau à distance » : COR-R9
sort donc en **Alerte** « Session ouverte depuis Internet », et non en **Critique** « Bureau à distance ouvert depuis
Internet ». C'est un **constat de mesure** (analogue au constat R3 du premier passage), candidat à un correctif
comportemental (inclure le type d'ouverture dans la clé, ou rapprocher la type 10 avant d'épuiser la clé) — à proposer
en phase 6, pas dans ce lot de validation.

## 2. Réseau (C2, exfiltration) et balayage

| Scénario | Config A | Config C | Règle mesurée |
|---|---|---|---|
| S-11 — C2 HTTP simulé + transfert d'un fichier bénin (T1071.001/T1105) | **VP** | **VP** | RES-002 Alerte (flux sortant du programme non signé) + RES-003 (première connexion) |
| S-12 — exfiltration d'un fichier canari (T1041) | **VP** | **VP** | RES-002 Alerte (flux sortant d'exfil) + RES-003 ; volume/contenu = **E** (DPI gelé) |
| S-08 — balayage de ports (T1046) | **GAP** | **GAP** | *aucune règle de balayage* |

S-11 et S-12 : un programme de test **non signé**, lancé depuis un dossier temporaire, ouvre une connexion sortante
**maintenue** (ESTABLISHED) vers le serveur HTTP du labo ; deR4Tizer lit la table TCP native (`GetExtendedTcpTable`,
indépendante de la capture de paquets gelée) et score le flux (non signé, dossier temporaire, IP directe, port
inhabituel) au-dessus du seuil → **RES-002 Alerte**. deR4Tizer détecte la **connexion** d'exfiltration ; le **volume et
le contenu** exfiltrés ne sont pas mesurés (IDS/DPI/NDR gelés) : limite connue (classe E), pas un faux négatif.

**S-08 (balayage) = gap d'architecture assumé.** Il n'existe **aucune règle de détection de balayage** (`parefeu.rs`) ;
les seules alertes fortes sont RES-004 (auto-exposition IPv4 publique de la VM) et RES-005 (paquets refusés du balayage),
**toutes dans la plage du labo** → artefacts d'exposition (décision D-1), exclus des VP/FP. À classer **C/E** (couverture
manquante connue), **jamais un faux négatif**, jamais 0.

## 3. Exécution et simulations

| Scénario | Verdict | Détail |
|---|---|---|
| S-10 — PowerShell encodé (T1059.001/T1027), charge bénigne | **VP (Sysmon)** | PRC-002 Alerte sur la commande `-EncodedCommand` |
| S-15 — accès limité à LSASS (T1003.001, SIMULATION) | **B2** | Sysmon 10 (ProcessAccess) présent ; **aucune règle deR4Tizer** ne consomme l'accès processus |
| S-16 — leurre anti-rançongiciel touché (T1486, SIMULATION) | **VP (A) / P-Defender (C)** | LEU-002 Critique + suspension automatique du processus (A) ; accès contrôlé aux dossiers refuse l'écriture (C) |

**S-10 — PRC-002 fiable avec Sysmon ; non déterministe sans Sysmon (constat honnête).** La source de la ligne de
commande de PRC-002 est **Sysmon si installé, sinon WMI** (`processus.rs`) — deR4Tizer ne lit **pas** le journal 4688.
En configuration B (Sysmon), la capture est à la création du processus : PRC-002 se lève de façon **fiable** (VP). Sans
Sysmon (WMI, par PID après coup), un `powershell` encodé **court** peut se terminer avant l'interrogation WMI, qui perd
alors la ligne de commande : la détection est **non déterministe** (mesuré : deux essais, l'un avec PRC-002, l'autre
sans). **Ce n'est pas un faux négatif** mais une limite de collecte connue. Amélioration produit possible (lire aussi le
4688 avec ligne de commande) — à proposer, pas dans ce lot.

**S-15 — gap assumé.** Handle LSASS ouvert en « informations limitées » (`PROCESS_QUERY_LIMITED_INFORMATION`) puis fermé
aussitôt, aucune lecture mémoire. La télémétrie (Sysmon 10) existe, mais aucune règle deR4Tizer n'en fait une détection :
**B2** (ni faux négatif, ni détection), à classer comme couverture manquante connue.

**S-16 — détection + réponse automatique, prévenu sous baseline.** Un programme non signé ajoute **un seul octet** à un
leurre (SIMULATION réversible). En configuration A : **LEU-002 Critique** + **suspension automatique** du processus
(NtSuspendProcess, threads suspendus vérifiés). En configuration C : l'accès contrôlé aux dossiers de la baseline
renforcée **refuse l'écriture** (leurre intact, événement Defender 1123) → **P-Defender** (prévention). Les deux comptent,
non fusionnés.

## 4. Session standard (présence de l'interface)

| Volet | Verdict | Détail |
|---|---|---|
| S-05 — spécificité (interface présente dans une session active) | **RÉUSSI** | Interface présente dans la session console active ; **aucun SAN-010/011** pendant la présence (pas de faux positif) |
| S-05 — témoin négatif (interface absente > 15 min) | **RÉUSSI** | Tâche de relance désactivée + interface arrêtée → **SAN-010 Critique** levé après 15 min d'absence pour la session concernée |

Le mécanisme cœur de la décision D4-1 est couvert dans la **session console interactive existante** : le service suit
l'interface **par session** et ne lève aucune alerte tant qu'elle est présente (spécificité), mais lève **SAN-010
Critique** quand elle reste absente plus de 15 min (témoin). La mesure confirme que **le service ne relance rien
lui-même** (`sante.rs`) : l'interface n'est revenue qu'à la remise à l'instantané (tâche de relance rétablie). SAN-010
est une règle de santé **indépendante de la baseline** ; la configuration C est tenue pour identique (hypothèse).

**Limites de reproductibilité (honnêtes)** : les deux volets de D4-1 qui exigent une **seconde session interactive** —
(a) ouverture d'une session **Bureau à distance** et (b) **bascule rapide d'utilisateur** — ne sont pas reproduits dans
ce harnais non interactif (PowerShell Direct ne crée pas de session interactive). Le mécanisme de suivi de l'interface
par session qu'ils exercent est couvert par la session console ci-dessus ; leur exécution en session Bureau à distance
ou seconde console reste une vérification manuelle en VM.

## 5. Grille de couverture — mise à jour (cumul des six lots)

| Domaine / technique | Règle | Config A | Config C |
|---|---|---|---|
| Vol d'identifiants de navigateur (T1555/T1539) | VOL-001 | **VP (Critique)** | **VP (Critique)** |
| Domaine / IP de liste de menaces (T1071) | DNS-001 / RES-001 + blocage 7 j | **VP (Critique)** | **VP (Critique)** |
| Changement de serveur DNS (T1557) ; filtrage DNS | DNS-002 ; filtrage | **VP** | **VP** |
| Defender pleinement actif ne flague pas le produit | lot 3d | **VP** | **VP** |
| Force brute RDP/SMB + corrélations | COR-R1/R2/R9 | **VP** | VP (SMB) / P-baseline (RDP) |
| Session admin distante ; canal de commandes distant | COR-R9 ; refus du tube | **VP** | **VP** |
| C2 HTTP / exfiltration (connexion) | RES-002 | **VP** | **VP** |
| PowerShell encodé | PRC-002 | **VP (Sysmon)** | VP (Sysmon) ; non déterministe sans Sysmon |
| Leurre anti-rançongiciel | LEU-002 + suspension | **VP** | P-Defender |
| Balayage de ports | *aucune* | **GAP (C/E)** | **GAP (C/E)** |
| Accès limité à LSASS | *aucune* | **B2** | **B2** |
| Session légitime ; tâche planifiée bénigne | N-01 ; N-02 | **RÉUSSI** | **RÉUSSI** |

## 6. Méthode (rappel)

Instantanés « campagne A » (sans baseline), « campagne B » (+ Sysmon + Atomic Red Team), « campagne C » (baseline à
100 %). Remise à l'instantané avant et après chaque essai, VM remise en veille à la fin. Defender jamais modifié à la
main. VM unique ⇒ scénarios strictement en série. Décisions D-1 (artefacts d'exposition de labo exclus des VP/FP) et
D-2 (collecte d'une règle = Active au départ, sinon essai invalide) appliquées. Les programmes de test sont bénins,
réversibles, non signés, lancés depuis un dossier temporaire ; aucune charge hostile, aucune infrastructure réelle
contactée.

**Constats produits à transmettre au mainteneur** : (1) COR-R9 par RDP = Alerte et non Critique (ordre type 3 → type 10) ;
(2) PRC-002 non déterministe sans Sysmon (source WMI par PID). Deux candidats d'amélioration comportementale, hors du
périmètre de ce lot de validation.

**Limites de reproductibilité en laboratoire** : le volume/contenu d'exfiltration (S-11/S-12) n'est pas mesuré
(IDS/DPI/NDR gelés) ; les volets Bureau à distance (a) et bascule rapide d'utilisateur (b) de S-05 ne sont pas
reproduits dans un harnais non interactif (voir §4).
