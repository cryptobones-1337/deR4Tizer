# Campagne Kali — premier passage

Date : 2026-11-15. Liste des scénarios : v1.3 (`campagne-kali-phase1.md`). Résultats bruts hors dépôt.
Aucune donnée personnelle, aucun nom de poste, aucun mot de passe. Adresses du labo : plages de documentation (RFC 5737),
non routables.

**Réserve (latences)** : aucune latence n'est rapportée à ce stade. L'horloge de la VM est ~9 h derrière celle de l'hôte
dans les résultats bruts ; les latences seront mesurées en phase 4, après normalisation en UTC à partir de l'écart
d'horloges relevé (précondition 4.3). Les verdicts VP reposent sur la présence règle/niveau/entité, pas sur l'heure.

## Chaîne de mesure validée

Trois contrôles établissent que la chaîne (comportement → événement Windows → collecte → corrélation → alerte → incident)
fonctionne, dans les deux configurations, avant toute mesure offensive consolidée.

| Scénario | Configuration | Verdict | Résumé |
|---|---|---|---|
| N-01 (témoin de chaîne, négatif) | A (sans baseline) | RÉUSSI | Activité légitime : 0 alerte Alerte/Critique, ouverture de session vue, aucune collecte dégradée. |
| N-01 (témoin de chaîne, négatif) | C (baseline 100 %) | RÉUSSI | Identique sous baseline durcie : pilotage et collecte des preuves opérationnels (UAC bureau sécurisé, règles ASR). |
| S-19 (contrôle de la configuration C) | C | RÉUSSI | Baseline conforme (journalisation 100, renforcé 100, recommandé 96 = écart D-BAS-01 attendu). Defender : 27 réglages comparés à la référence, **aucun affaibli, aucune exclusion**. Bureau à distance refusé (port 3389 fermé). Protection LSA effective. Pare-feu actif sur les trois profils. 0 alerte en 25 min. Le score recommandé à 96 fait passer D-BAS-01 d'hypothèse de lecture à **constat mesuré** (appuie le correctif prévu en phase 6). |

## Détection de force brute (COR-R1)

| Scénario | Configuration | Verdict | Résumé |
|---|---|---|---|
| S-01 (force brute RDP, échecs seuls) | A | VP | Série d'échecs d'authentification RDP (mots de passe faux, aucun accès obtenu) → 6× événement 4625 tous de la source → COR-R1 **Alerte** sur l'entité `source:<Kali>` (« 5 échecs d'ouverture de session en 5 minutes ») dans le délai → 1 incident ouvert. Annexes admises : RES-004 (Alerte) et RES-005 (Critique), classées « artefact d'exposition de labo » (adresse du labo, exclue du décompte VP et FP). **Consolidation : 10 essais sur 10 = VP** (0 FN, 0 FP, 0 invalide ; 6× 4625 et 1 COR-R1 par essai) — détection déterministe. |

En configuration C, S-01 est **prévenu** (Bureau à distance refusé par la baseline) : la détection COR-R1 se mesure en A
(S-01) ; en C, COR-R1 se mesurera par un vecteur d'ouverture de session non RDP (S-03).

## Persistance (PER-001)

| Scénario | Configuration | Verdict | Résumé |
|---|---|---|---|
| S-09 (persistance : clé Run + tâche planifiée) | C | VP | Deux entrées de démarrage neuves lancées par un interpréteur → **2 alertes PER-001 (Alerte)**, une par mécanisme ; événement 4698 (création de tâche) produit. Détecté sous la baseline durcie ; aucune règle ASR ne gêne. |
| S-09 (persistance : clé Run + tâche planifiée) | A | VP | Identique (2 PER-001 Alerte, 4698 produit). Persistance détectée dans les deux configurations. |

## Corrélations système (service, compte, journaux, audit)

| Scénario | Configuration | Verdict | Résumé |
|---|---|---|---|
| S-13 (service + compte admin + journal effacé + audit modifié) | C | C (3/4 + 1 constat) | **R4** (journal effacé) et **R5** (service depuis un dossier suspect) en **Critique** ; **R7** (protection affaiblie par modification de l'audit) en **Alerte** ; **BAS-001** (dérive de baseline) confirmée. La 4ᵉ corrélation attendue, **R3**, ne se déclenche pas : voir le constat ci-dessous. |

### Constat produit — corrélation R3 « nouveau compte administrateur »

La corrélation **R3** (« un compte créé il y a moins de 30 min a été ajouté aux Administrateurs », Critique, T1136.001)
**ne se déclenche jamais par le vecteur standard** ; on obtient à la place **R3b** (« Ajout au groupe Administrateurs »,
Alerte, T1098), de niveau moindre et sans le lien « compte neuf → promu admin ».

Cause (lecture du code `siem.rs` + reproduction) : l'événement Windows d'ajout à un groupe local (4732) journalise le
membre par **identifiant de sécurité (SID)**, le nom de compte valant « - » ; le moteur rapproche alors le membre par
**SID**, alors que la table des comptes récemment créés est indexée par **nom** (issu de l'événement 4720). Nom contre
SID : le rapprochement échoue toujours, quel que soit le mode d'ajout (par nom ou par SID). **Confirmé par événements
bruts** : le 4720 porte `TargetUserName` et `TargetSid=…-1004` ; le 4732 porte `MemberName=« - »` (vide) et
`MemberSid=…-1004` — le même SID que le compte créé. La donnée de rapprochement existe donc (SID identique), mais le
produit relie par nom, indisponible dans le 4732. Correctif prouvé (hors de la campagne, à décider par le mainteneur) :
conserver le **SID** du compte créé (présent dans le 4720) et rapprocher le **MemberSid** du 4732.

## Grille de couverture (premier passage)

| Domaine / technique | Règle attendue | Config A | Config C |
|---|---|---|---|
| Activité légitime (témoin) | — | RÉUSSI (0 FP) | RÉUSSI (0 FP) |
| Contrôle du durcissement | — (S-19) | s/o | RÉUSSI (Defender 0 affaibli ; D-BAS-01 confirmé) |
| Force brute RDP (T1110.001) | COR-R1 | **VP 10/10** | prévenu (RDP refusé) ; COR-R1 mesuré en C par S-03 |
| Force brute SMB (T1110.001, T1021.002) | COR-R1 | **VP** (IP source présente dans le 4625) | **prévention** (baseline bloque SMB par défaut) **+ détection VP** si SMB autorisé ; COR-R2/R9 reportés (volet réussite) |
| Persistance (T1547.001, T1053.005) | PER-001 ×2 | **VP** | **VP** |
| Service depuis dossier suspect (T1543.003) | COR-R5 | non exécuté | **VP (Critique)** |
| Effacement de journal (T1070.001) | COR-R4 | non exécuté | **VP (Critique)** |
| Protection affaiblie / audit (T1562.002) | COR-R7 + BAS-001 | non exécuté | **VP (Alerte + BAS-001)** |
| Compte créé puis promu admin (T1136.001) | COR-R3 | non exécuté | **constat : R3 inatteignable, dégrade en R3b** |

Aucune case n'est notée « 0 » : non évalué ≠ échec.

### Scénarios restants et leurs préalables (pour la suite)

- **S-13 en A** : exécuté — identique à C (R4, R5, R7, BAS-001 ; R3 → R3b). Constat R3 indépendant de la configuration.
- **S-06 (DNS, filtrage phase 7)** : reporté. Le code source du filtrage (collectes `FiltrageDns`/`ConfigDns`, règle
  DNS-002) n'est pas dans le checkout lu (présent seulement dans le binaire 4.3 installé). À préciser : version de source
  correspondant au 4.3, commande d'activation du filtrage, format de la liste `.test`.
- **S-14 (vol d'identifiants, VOL-001)** : préalable à poser — le service pose lui-même la SACL d'audit sur les dossiers
  d'identifiants de navigateur ; ces dossiers doivent exister dans la VM (profil de navigateur) et la collecte
  `AuditDonnees` être « Active » (un cycle de lecture 4663 réussi) avant l'essai.
- **S-07 (listes de menaces, DNS-001/RES-001)** : préalable — collectes `ListesMenaces` et `ListesDomaines` « Active » ;
  listes synthétiques `.test` posées.
- **S-04 (canal de commandes)**, **S-02/S-05** (RDP réussite), **S-08/S-10/S-15** : repoussés (cf. analyse de l'agent).

Préalable de labo commun constaté : les instantanés de campagne n'ouvrent pas le partage de fichiers (SMB-In) ; il a
fallu l'activer pour S-03. À intégrer aux instantanés pour S-03/S-04.

## Points ouverts (à trancher par l'agent purple team, pour la liste v1.4)

1. RES-004 / RES-005 (« PC exposé à Internet ») sur l'adresse du labo (décision D-1) : classés « artefact d'exposition
   de labo » (plage de documentation, non routable) et **exclus du décompte VP comme du décompte FP dans tous les
   scénarios**, y compris les tests négatifs. Aucun correctif produit : sur un poste réel avec une vraie adresse
   publique, ces alertes seraient de vrais positifs d'exposition ; les filtrer dégraderait une détection légitime.
2. Critère de collecte de N-01 (décision D-2) : une collecte à cycle long peut paraître « Indisponible » juste après une
   restauration d'instantané (dernier succès daté de la prise de l'instantané). Convention retenue : une collecte non
   exercée par le scénario est écartée du verdict seulement si la cause prouvée est « pas de lecture depuis la
   restauration » ; en revanche, toute collecte dont dépend une règle du scénario doit être « Active » au départ (sinon
   essai invalide). Conséquence : S-14 (AuditDonnees) et S-07 (ListesMenaces, ListesDomaines) ne sont mesurables
   qu'après activation de ces collectes. Question produit consignée comme vérification de phase 5 : sur un poste réel
   sortant d'une veille longue (> 3 h), une collecte événementielle ou à rafraîchissement périodique passe-t-elle
   « Indisponible » à tort ?

## Méthode (rappel)

Instantanés de campagne « campagne A » (sans baseline) et « campagne C » (baseline à 100 % appliquée par le service),
préparés hors campagne, apprentissage terminé. Remise à l'instantané avant chaque essai des scénarios à corrélation.
Defender jamais modifié à la main (règle 2). S-19 exécuté au début de chaque lot en C.
