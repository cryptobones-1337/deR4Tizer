# Campagne de validation Kali : audit initial et liste fermée de scénarios (phase 1)

| Champ | Valeur |
|---|---|
| Version de la liste | **1.2** |
| Date de la version 1.2 | 2026-11-14 |
| Versions précédentes | 1.1 du 2026-11-14 ; 1.0 du 2026-11-14 |
| Code audité | `main` au commit `cde9468` ; règle d'approbation relue dans `CLAUDE.md` à `8faf4f9` (section 5, campagne Kali) ; instantanés de campagne relus dans le `CLAUDE.md` de la PR #172 (section 5, campagne Kali) |
| Statut | **APPROUVÉE PAR L'AGENT DE VALIDATION** |

> **Rappel sur l'approbation (v1.2).** L'approbation par l'agent de validation **n'est ni humaine ni indépendante** (même modèle que celui qui exécute les scénarios ; leurs angles morts peuvent coïncider) et **ne lève aucune règle** de `CLAUDE.md` ni du mandat. La **version 1.2 est transmise au mainteneur, pour information, avant toute exécution.** Les deux volets autrefois laissés au mainteneur (volet T1562.002 de S-13 ; DNS-003, désormais S-18) restent approuvés depuis la v1.1, à la suite de sa décision du 2026-11-14 citée en 5.2.

## Approbation

Approuvée le 2026-11-14, version 1.0, par l'agent de validation, en application de `CLAUDE.md` (section 5, phase 7,
campagne Kali : « Liste fermée de scénarios écrite et approuvée par l'agent de validation avant toute exécution »).

- **2026-11-14, version 1.1** : approuvée par l'agent de validation (volets T1562.002 de S-13 et DNS-003 approuvés sur la
  décision du mainteneur citée en 5.2).
- **2026-11-14, version 1.2** : approuvée par l'agent de validation, après le « Pas go » de la relecture de la PR #172
  (instantanés de campagne « campagne A » et « campagne B », approbation datée, sens de « non mesurée »). **Cette
  approbation n'est ni humaine ni indépendante** ; elle ne lève aucune règle, et la v1.2 est transmise au mainteneur, pour
  information, avant toute exécution.

- **Cette approbation n'est ni humaine ni indépendante** : l'agent est le même modèle que celui qui exécute les
  scénarios ; leurs angles morts peuvent coïncider. Elle n'est jamais présentée comme une validation.
- Elle ne lève aucune règle : aucun scénario qui toucherait Defender, sortirait du labo, volerait un identifiant réel,
  porterait une charge destructive ou exigerait une saisie de mot de passe n'est approuvé. Les cas douteux sont laissés au
  mainteneur (section 5.2).
- Cette version est transmise au mainteneur, pour information, **avant toute exécution**. Il peut retirer un scénario ou
  reprendre l'approbation à tout moment. Tout ajout ou changement de scénario fait l'objet d'une nouvelle version
  approuvée de la même façon avant d'être exécuté.
- L'exécution ne commence qu'une fois les prérequis de la section 4 vérifiés, par N-01 puis S-01 seul ; le scénario
  suivant n'est lancé que si l'état de référence est vérifié (VM conforme à l'instantané de campagne de sa configuration,
  section 3.0) et les preuves du précédent complètes.

**Retenus (v1.1)** : N-01 à N-05 ; S-01 à S-12 ; S-13 **y compris son volet T1562.002** (approuvé en v1.1) ; S-14 à
S-18 ; S-16 avec son option longue (2 h). **Ajouté en v1.1** : S-18 (DNS-003).

**Écartés (v1.1)** : T1567 (D, aucun service web réel autorisé) ; T1055 (non exécuté) ; T1562.001 contre Defender, les
journaux de Windows ou deR4Tizer (interdit) ; fiches Atomic qui téléchargent, désactivent une protection, lisent la
mémoire de LSASS ou effacent un journal réel.

**Tranchés par le mainteneur le 2026-11-14, approuvés en v1.1 (plus aucun scénario en attente)** : volet T1562.002 de
S-13 ; DNS-003 (devenu S-18). Décision citée mot pour mot en section 5.2.

**Changements de la v1.1 par rapport à la v1.0** : les deux volets ci-dessus passent de « non approuvé / laissé au
mainteneur » à approuvé ; S-18 créé pour DNS-003, avec nettoyage à rétablissement vérifié (service relancé et vérifié)
et remise à l'instantané ; cross-références des sections 2, 3 et 5 mises à jour ; en-tête passé en version 1.1.

**Changements de la v1.2 par rapport à la v1.1** (relecture de la PR #172, « Pas go ») : D1, les configurations A et B
partent des instantanés de campagne « campagne A » et « campagne B » (deR4Tizer installé, apprentissage terminé, comptes
de test, réglages du labo), et non plus de « propre », qui n'a rien de cela ; toutes les remises par essai et par lot
visent l'instantané de la configuration ; la VM ne revient à « propre » qu'après la campagne (sections 3.0, 4, 5.1.2,
5.1.3 et renvois) ; D2, approbation datée de la v1.2 ; section 1.3, « non mesurée » précisé en « non mesurée en VM ».
Aucun scénario ajouté, retiré ni changé dans son action ou son attendu.
Document écrit pour être publiable tel quel (`docs/validation/`) : niveau comportement, identifiants ATT&CK, attendus,
nettoyage et preuves ; aucune commande offensive détaillée ; aucune donnée personnelle, aucun chemin de profil, aucun
identifiant de compte ni mot de passe. Adresses en plages de documentation (RFC 5737), noms de test en `.test` (RFC 2606).

Tout ce qui est marqué **HYPOTHÈSE** est déduit de la lecture du code et des documents, non mesuré. Rien ici n'est un
résultat.

---

## 1. État des capacités de détection (d'après le code et `docs/`)

### 1.1 Architecture utile à la campagne

- Service Rust en SYSTEM, cycle de surveillance toutes les 3 s environ (`moniteur.rs`), fils séparés pour les journaux,
  la persistance (1 min), la santé (30 s), le DNS (60 s), le filtrage.
- Canal `\\.\pipe\deR4Tizer` : clients distants refusés par le tube (PR #168) ; connexion distante (IPC-03) **jamais
  essayée** (matrice des capacités).
- Alertes avec `Regle`, `Modele`, `HeureUtc`, `Seq`, `Collecte` ; une alerte Alerte ou Critique ouvre ou rejoint un
  incident (entité, 24 h) ; une alerte Info n'ouvre rien.
- **Apprentissage** (`apprentissage.rs`) : 7 jours après la première installation, toute alerte « Alerte » sans signal
  fort devient « Info » et son comportement est mémorisé (il reste « Info » ensuite). Jamais adoucis : Critique, SAN-*,
  REP-*, DNS-002, IDS, et les motifs téléchargement de code, LOLBin, débogage à distance, suppression des sauvegardes,
  macro, anomalie du dossier des tâches. Conséquence directe pour la mesure (décision 5.1.1 : apprentissage terminé).
- Profil de baseline « journalisation » appliqué automatiquement au premier démarrage sur un poste non géré : audit des
  ouvertures de session, création de processus (4688) avec ligne de commande, système de fichiers (4663), autres objets
  (4698), comptes et groupes, politique d'audit, extensions de sécurité, règles du pare-feu, `pfirewall.log` (trois
  profils), blocs de script PowerShell (4104), modules (4103), journaux DNS-Client et Planificateur. À vérifier dans
  l'instantané (section 4).

### 1.2 Sources d'événements réellement consommées

| Source | Consommée par | Remarque |
|---|---|---|
| Sécurité : 4624, 4625, 4648, 4672, 4688, 4697, 4719, 4720-4726, 4728, 4732, 4740, 4756, 4798, 1102 | `siem.rs` (COR-*) | 4688 enregistré dans le SIEM mais aucune règle PRC ne s'en sert ; 4698, 5140, 5145 non souscrits |
| Sécurité 4663 | VOL-001, LEU-002 | exige l'audit des objets et la SACL posée |
| Système : 7045, 104, 7036 | `siem.rs` | 7036 seulement pour deR4Tizer, Defender, pare-feu, journal d'événements, Centre de sécurité |
| Sysmon 1 et 22 seulement | `processus.rs` | **choisi au démarrage du service s'il est présent**, sinon WMI ; les autres événements Sysmon ne sont pas lus |
| WMI des processus | `processus.rs` | processus brefs perdus, lignes de commande souvent absentes |
| DNS-Client (ou Sysmon 22) | DNS-001, indice « IP directe » | |
| Defender (journal, état) | DEF-001 à 012 | DEF-003 à 006 et 010 à 012 supposent Defender affaibli : jamais exercées |
| Journal du pare-feu (règles) | SYS-002, SYS-003 | |
| `pfirewall.log` | RES-005 | une alerte par (source, port, action) et par 24 h |
| Table TCP, ports en écoute | RES-001 à 003, 006, 007 | relevé périodique : une connexion brève peut être manquée (HYPOTHÈSE) |
| Démarrages automatiques | PER-001, PER-002 | toutes les minutes |
| Leurres, hosts | LEU-001, SYS-001 | empreintes |
| Cartes réseau | DNS-002, DNS-003 | 60 s |
| PowerShell 4104 | **aucune règle** | produit par Windows, jamais lu |

### 1.3 Règles (`regles.rs`, `docs/detection/regles.md`)

État de mesure : **non mesurée en VM** pour toutes les fiches, sauf PER-001 (clé Run) et DNS-002, vues au scénario 3a.
« Non mesurée en VM » ne veut pas dire « sans test » : certaines lignes de la matrice des capacités sont « testé en labo »
sur la foi de tests unitaires ; aucune n'a encore été mesurée par une campagne d'attaque en VM.

- RES-001 (menace connue, Critique, blocage automatique si Spamhaus DROP ou Feodo Tracker), RES-002 (score ≥ 3 : non signé
  +3, dossier temporaire +3, origine Internet +2/3, ligne suspecte +3, IP directe +2, balise +1/3, port hors liste +1),
  RES-003 (Info), RES-004, RES-005, RES-006, RES-007.
- DNS-001 (listes de domaines désactivées par défaut, licences restreintes), DNS-002, DNS-003.
- PRC-001 à 005, CHA-001 (seuil 12) ; PER-001, PER-002 ; DEF-001 à 012 ; LEU-001, LEU-002 ; VOL-001 ; SYS-001 à 003 ;
  PIL-001 ; EXT-001 ; VIE-001 à 003 ; BAS-001 (relevé 10 min).
- COR-R1 (5 échecs en 5 min, même source), COR-R2 (réussite après au moins 5 échecs de la même source en 30 min,
  Critique), COR-R3/R3b, COR-R4 (1102/104), COR-R5, COR-R6, COR-R7, COR-R9 (Critique si Bureau à distance, Alerte sinon),
  COR-R10. Pas de R8.
- SAN-001 à 004, SAN-010 à 012 ; REP-001 à 004 ; INT-001, INT-002 ; EXP-IDS/DPI/NDR (gelés).

### 1.4 Réponses automatiques et durées (`docs/reponse/politique.md`)

| Action | Niveau | Échéance | À l'échéance |
|---|---|---|---|
| Blocage IP Spamhaus DROP / Feodo Tracker | 3, actif par défaut | 7 jours | levé |
| Suspension du programme qui touche un leurre | 3, actif par défaut | 2 h | reste suspendu ; REP-001 Critique puis toutes les 24 h |
| Blocage IPS | 2, IPS désactivé par défaut | 24 h | levé |
| Suspension manuelle, isolation, panique | 2 | 24 h, 7 j, 4 h | jamais levé, relance |
| Quarantaine, blocage manuel | 2 | 30 j, 90 j | rappel Info |
| Filtrage DNS | 2, mode désactivé par défaut | aucune | — |

Gardes : 3 blocages de la même adresse par 24 h, 30 blocages par listes par heure, suspension sans plafond hors
Program Files, décision humaine respectée 7 jours ; REP-002 quand une action est retenue.

### 1.5 Filtrage DNS (phase 7)

Résolveur local sur la boucle, cartes physiques réglées sur lui à l'activation (administrateur), serveurs d'origine en
secours, échec ouvert. Catégorie « sécurité » **sans liste compilée** ; « publicité et pistage » : listes téléchargées
sur Internet. Un blocage n'est pas une alerte : il apparaît dans `filtrage-etat.json`. Limite écrite : tant que l'amont
ne répond pas, les cartes restent sur leurs serveurs d'origine, sans filtrage ; un labo sans Internet exige donc un amont
DNS de labo (décision 5.1.4).

### 1.6 Limites connues qui pèsent sur la campagne

- IDS, DPI, NDR gelés : contenu HTTP, empreintes TLS, détection réseau de balayage : classe E.
- Aucune détection de balayage hors IDS ; effet attendu : RES-005 par port touché (HYPOTHÈSE d'inondation).
- Aucune télémétrie d'accès à un processus ni d'injection consommée : T1003.001 et T1055 sans règle.
- 4104 jamais lu : un obscurcissement absent de la ligne de commande n'a aucune règle.
- « Active » garantit la lecture d'une source, pas la production des événements par Windows.
- Corrélations dédupliquées une heure en mémoire et fenêtre d'échecs de 30 min : deux essais depuis la même source dans
  l'heure ne donnent pas deux incidents (conception des essais, 3.0).
- Les plages de documentation RFC 5737 comptent comme Internet pour le service : c'est ce qui rend COR-R9 possible ;
  effets de bord attendus : VM vue « exposée », RES-005, RES-007, indice « IP directe » vers Kali.

---

## 2. Cartographie ATT&CK → alerte attendue

Classe a priori : **HYPOTHÈSE** pour toutes les lignes. A détection attendue ; B événement produit sans règle ; C alerte
attendue mais incorrecte ou trop générique ; D non exécutable dans le labo ; E non testable avec l'architecture
actuelle. Sous-classes descriptives proposées : B1 reçu par deR4Tizer sans règle, B2 produit par Windows ou Sysmon mais
non lu par deR4Tizer.

| Technique | Comportement simulé | Capteur requis | Événement attendu | Règle | Alerte attendue | Classe a priori (HYPOTHÈSE) |
|---|---|---|---|---|---|---|
| T1110.001 (RDP) | série d'échecs de mot de passe vers un compte de test | audit Logon | 4625 type 3 avec adresse source | COR-R1 | COR-R1 Alerte | A |
| T1110.001 puis T1078.003 | échecs puis réussite depuis la même source | audit Logon | 4625 ×≥5 puis 4624 | COR-R2 | COR-R2 Critique | A |
| T1133 / T1021.001 | session Bureau à distance depuis 203.0.113.0/24 | audit Logon | 4624 type 3 puis type 10 | COR-R9 | COR-R9 Critique | **C** : la clé de déduplication de R9 (adresse + compte) serait prise par la 4624 de type 3 qui précède la type 10 ; R9 sortirait « Session ouverte depuis Internet », Alerte |
| T1021.001 | même session | table TCP | connexion établie sur 3389 | RES-007 | RES-007 Alerte | A |
| T1110.001 (SMB) | échecs puis réussite sur le partage de fichiers | audit Logon | 4625/4624 type 3 | COR-R1, R2, R9 | R1 Alerte, R2 Critique, R9 Alerte | A ; si l'adresse source manque dans l'événement, clé « compte » et R9 muette |
| T1021.002 | accès authentifié à un partage administratif, lecture seule | audit Logon | 4624 type 3, 4672, 5140 | COR-R9 | COR-R9 Alerte | A pour la session ; B2 pour l'accès au partage |
| T1046 | balayage de ports TCP borné | `pfirewall.log` | paquets bloqués depuis une adresse « publique » | RES-005 | aucune règle « balayage » | C (une RES-005 par port) ou E |
| T1071.001 | requêtes HTTP régulières vers un serveur du labo | table TCP, DNS-Client | connexions répétées sans requête DNS | RES-002 | RES-002 Alerte (balise, IP directe, port) | A si les connexions sont vues par le relevé ; sinon FN de collecte |
| T1105 | téléchargement d'un fichier texte bénin par PowerShell | Sysmon 1 ou WMI, table TCP | processus, connexion | PRC-002, RES-002 | PRC-002 Alerte | A avec Sysmon ; instable sans |
| T1105 | même téléchargement par un outil Windows détourné | idem ; Defender | idem | PRC-003, DEF-001 | PRC-003 Alerte ; DEF-001 si Defender réagit | A |
| T1059.001 + T1027 | commande PowerShell encodée longue, contenu bénin | Sysmon 1 ou WMI | ligne de commande | PRC-002 | PRC-002 Alerte | A avec Sysmon |
| T1027 | script bénin obscurci lancé par fichier | 4104 | 4104 | aucune | aucune | B2 |
| T1547.001 | valeur Run vers une commande bénigne | démarrages automatiques | entrée nouvelle | PER-001 | PER-001 Alerte (cible suspecte) | A |
| T1053.005 | tâche planifiée bénigne lancée par un interpréteur | relevé des tâches | tâche nouvelle ; 4698 non lu | PER-001 | PER-001 Alerte | A |
| T1543.003 | service local dont l'image est dans un dossier inscriptible, commande bénigne | journal Système | 7045 | COR-R5, PER-001 | COR-R5 Critique | A |
| T1136.001 + T1098 | compte local créé puis ajouté aux Administrateurs | audit comptes et groupes | 4720, 4732 | COR-R3 | COR-R3 Critique | A |
| T1070.001 (SIMULATION) | effacement d'un journal dédié créé pour le test | journal Système | 104 | COR-R4 | COR-R4 Critique | A (HYPOTHÈSE : 104 émis pour ce journal) |
| T1562.002 (SIMULATION) | sous-catégorie d'audit hors besoins des règles désactivée puis rétablie | audit politique ; baseline | 4719 ; dérive | COR-R7, BAS-001 | COR-R7 Alerte ; BAS-001 Alerte si la sous-catégorie fait partie du profil | A |
| T1562.001 | Defender, journaux et deR4Tizer intouchables | — | — | DEF-003 à 006, 010 à 012 | — | D (interdit) |
| T1003.001 (SIMULATION) | ouverture de LSASS en accès « informations limitées », sans lecture de mémoire | Sysmon 10 si configuré | 10 | aucune | aucune | B2 |
| T1555.003 (SIMULATION) | ouverture en lecture du fichier d'identifiants d'un navigateur d'un compte de test vide, par un programme de test non signé lancé d'un dossier temporaire | 4663 + SACL | 4663 | VOL-001 | VOL-001 Critique | A |
| T1055 (SIMULATION) | aucune action ; seule la télémétrie disponible est inventoriée | — | — | aucune | aucune | non exécuté ; aucun capteur consommé |
| T1486 (SIMULATION) | un programme de test modifie un seul leurre de deR4Tizer | 4663 + empreinte | 4663 | LEU-002, LEU-001 | LEU-002 Critique + suspension automatique ; REP-001 à 2 h | A |
| T1041 | envoi HTTP d'un fichier canari généré vers Kali | table TCP | connexion sortante | RES-002 | RES-002 Alerte selon le score | A pour la connexion ; E pour le contenu et le volume |
| T1567 | envoi vers un service web public | — | — | — | — | D (aucun service réel autorisé) |
| — (menace connue) | connexion vers une adresse du labo inscrite dans une liste de test | table TCP, liste locale | connexion | RES-001 | RES-001 Critique ; blocage automatique 7 j | A |
| — (DNS) | résolution d'un nom `.test` d'une liste de domaines de test | DNS-Client / Sysmon 22 | requête | DNS-001 | DNS-001 Critique | A (listes restreintes à activer) |
| — (DNS) | serveur DNS statique réglé sur la carte | cartes, registre | changement | DNS-002 | DNS-002 Alerte | A |
| — (DNS, S-18) | port 53 de la boucle tenu par un autre programme au redémarrage, carte encore sur le résolveur | échec de liaison, registre des cartes, table UDP | échec de liaison exclusive + PID | DNS-003 | DNS-003 Critique (PID) | A (approuvé en v1.1) |
| — (filtrage) | résolution d'un nom `.test` de la liste de filtrage | résolveur local | blocage | — | aucune alerte ; nom dans les derniers blocages | A (fonction) |
| IPC-03 | ouverture du canal depuis Kali par le réseau | tube | refus | — | refus, aucune commande exécutée | A (refus attendu) |

---

## 3. Liste fermée proposée

### 3.0 Règles communes

- Adressage : VM cible 203.0.113.10, Kali 203.0.113.20 sur `d4t-labo` ; lien d'administration 198.51.100.0/24 entre le
  poste et Kali seulement ; carte « Default Switch » de la VM débranchée.
- Instantané de départ selon la configuration (décision 5.1.2) : « campagne A » (configuration A, sans Sysmon) ou
  « campagne B » (configuration B, avec Sysmon et Atomic Red Team). Les deux sont préparés hors campagne et contiennent
  deR4Tizer installé, l'apprentissage terminé, les comptes de test et les réglages du labo (Bureau à distance, partage de
  fichiers, profil réseau). Leurs noms ne commencent jamais par « propre ».
- Dans tout ce document, **« remise à l'instantané » désigne la remise à l'instantané de campagne de la configuration de
  l'essai** (« campagne A » ou « campagne B »), **jamais à « propre »** : « propre » est l'instantané des passages
  complets, sans deR4Tizer, sans comptes de test ni réglages du labo ; y revenir effacerait les préconditions de S-01 à
  S-04, S-13 et S-17. Remise avant et après chaque lot, et **avant chaque essai des scénarios à corrélation** (COR-*) :
  la déduplication d'une heure et la fenêtre d'échecs de 30 min sont en mémoire, un second essai sans remise ne serait
  pas indépendant.
- La VM n'est remise à « propre » qu'**après la campagne**, une fois les preuves collectées.
- Atomic Red Team n'existe que dans « campagne B » : une fiche Atomic (S-09 par exemple) ne sert qu'en configuration B ;
  en configuration A, le comportement est produit sans elle.
- Comptes locaux de test dédiés ; mots de passe de labo jamais écrits dans un rapport ni dans le dépôt.
- Horodatage : début (UTC) relevé sur la VM ; latence = `HeureUtc` de l'alerte moins `TimeCreated` de l'événement Windows
  déclencheur (et, en second, moins le début de l'action).
- Essai valide : comportement prouvé (événement Windows ou Sysmon, journal côté Kali), collectes « Active » au début et à
  la fin. Sinon D (invalide), jamais 0.
- VP : règle, niveau et entité attendus, dans le délai ; C : autre règle ou autre niveau ; FN : rien dans le délai ; FP :
  alerte Alerte ou Critique pendant un test négatif ou sans lien avec le scénario. Les alertes annexes prévues par
  scénario ne comptent pas comme FP.
- 10 essais valides par scénario avant toute mesure consolidée ; SIMULATION et émulation jamais dans le même score.
- Preuves communes : `alertes.json`, `suivi-incidents.json`, `incidents.json`, événements du SIEM du jour, `etat.json`
  (`Collectes`, `ReglesSansCollecte`), `reponses.json`, `blocages.json`, `journal.txt` ; extraits des journaux Windows et
  de Sysmon sur la fenêtre de l'essai ; versions de deR4Tizer, Windows, Sysmon et sa configuration, Atomic Red Team ;
  état de Defender au début et à la fin. Résultats bruts hors du dépôt.

### 3.1 Scénarios (du plus bénin au moins bénin)

**N-01 — Témoin de chaîne : activité légitime (négatif, valide la collecte et les preuves)**
- Technique : aucune (négatif).
- Nature : activité légitime.
- Préconditions : instantané de campagne de la configuration (« campagne A » ou « campagne B », 3.0) ; collectes actives ;
  apprentissage terminé (décision 5.1.1) ; horloges relevées.
- Action : ouverture de session locale du compte de test, une commande d'administration PowerShell signée lancée par
  fichier, consultation de l'interface.
- Attendu : aucune alerte Alerte/Critique ; 4624 présents dans le SIEM ; aucune collecte en panne.
- Délai : 10 min d'observation.
- Nettoyage : fermeture de session.
- Preuves : communes + état des collectes au début et à la fin.

**S-01 — Force brute RDP, échecs seuls (premier scénario : valide la chaîne de mesure, COR-R1)**
- Technique : T1110.001.
- Nature : émulation (échecs réels contre un compte de test, aucun accès obtenu).
- Préconditions : N-01 réussi ; Bureau à distance autorisé sur le profil de la carte du labo ; compte de test hors
  Administrateurs ; nombre d'échecs inférieur au seuil de verrouillage relevé.
- Action : depuis Kali, 6 tentatives erronées en moins de 2 min, puis arrêt.
- Attendu : 6 × 4625 (source 203.0.113.20) ; COR-R1 Alerte, entité `source:203.0.113.20` ; un incident ouvert. Annexes
  admises : RES-005, RES-007.
- Délai maximal : 120 s après le 5e échec.
- Nettoyage : remise à l'instantané avant l'essai suivant.
- Preuves : communes + 4625 exportés ; journal côté Kali (heure, nombre, résultat ; sans mot de passe).

**S-02 — Force brute RDP suivie d'une réussite**
- Technique : T1110.001, T1078.003, T1133.
- Nature : émulation.
- Préconditions : comme S-01.
- Action : 6 échecs puis une ouverture de session réussie du compte de test, fermée aussitôt.
- Attendu : COR-R1 Alerte ; COR-R2 Critique ; COR-R9 Critique selon la fiche (**HYPOTHÈSE C** : Alerte « Session ouverte
  depuis Internet ») ; R2 et R9 dans un même incident `compte:<compte de test>` ; RES-007.
- Délai : 120 s après la 4624.
- Nettoyage : déconnexion ; remise à l'instantané.
- Preuves : communes + 4624 (types 3 et 10), 4625.

**S-03 — Force brute SMB suivie d'une réussite**
- Technique : T1110.001, T1021.002.
- Nature : émulation.
- Préconditions : partage de fichiers autorisé sur le profil de la carte du labo ; compte de test.
- Action : 6 échecs d'authentification sur le partage de fichiers, puis une connexion réussie en lecture d'un partage de
  test.
- Attendu : COR-R1, COR-R2, COR-R9 Alerte ; si l'adresse source manque dans 4625, R1 par compte et R9 muette (à
  constater).
- Délai : 120 s.
- Nettoyage : remise à l'instantané.
- Preuves : communes + 4625/4624 avec le champ d'adresse source.

**S-04 — Connexion distante au canal de commandes (IPC-03)**
- Technique : aucune directe (frontière de privilège).
- Nature : émulation.
- Préconditions : compte de test standard.
- Action : depuis Kali, tentative d'ouverture du tube de deR4Tizer par le réseau, avec une demande de version.
- Attendu : refus ; aucune commande exécutée ; COR-R9 Alerte pour la session réseau.
- Délai : 60 s.
- Nettoyage : remise à l'instantané.
- Preuves : erreur côté Kali, `journal.txt`, SIEM.

**S-05 — Essais D4-1 : interface en session Bureau à distance et au changement rapide d'utilisateur**
- Technique : aucune (essai fonctionnel reporté, décision D4-1).
- Nature : essai fonctionnel.
- Préconditions : deux comptes de test ; tâche de relance présente.
- Action : (a) session Bureau à distance du compte A depuis Kali ; (b) changement rapide vers le compte B à la console.
- Attendu : interface présente dans chaque session active au plus tard 6 min après l'ouverture ; aucun SAN-010 sur 25 min ;
  témoin retenu : interface fermée volontairement plus de 15 min, SAN-010.
- Délai : 25 min par cas.
- Nettoyage : sessions fermées ; remise à l'instantané.
- Preuves : processus par session, SIEM (`Type` « interface »), alertes SAN.

**S-06 — Changement de serveur DNS et filtrage DNS**
- Technique : sans correspondance exacte (redirection de résolution) ; fonction de phase 7.
- Nature : émulation (DNS-002), essai fonctionnel (filtrage).
- Préconditions : amont DNS de labo sur Kali (décision 5.1.4) ; liste de filtrage synthétique en `.test` posée en administrateur ;
  filtrage activé par la commande prévue.
- Action : (a) serveur DNS statique réglé sur la carte de la VM, puis retour au réglage d'origine ; (b) résolution d'un nom
  bloqué et d'un nom autorisé.
- Attendu : (a) DNS-002 Alerte, aucune au retour (témoin écarté) ; (b) nom bloqué résolu en adresse nulle et présent dans
  les derniers blocages, nom autorisé relayé, aucune alerte ; désactivation : cartes rendues à l'identique.
- Délai : 180 s (a), 60 s (b).
- Nettoyage : filtrage désactivé, réglages d'origine vérifiés ; remise à l'instantané.
- Preuves : communes + `filtrage-etat.json`, `filtrage-origine.json`, réglages des cartes avant et après.

**S-07 — Domaine et adresse inscrits dans des listes de menaces de test**
- Technique : T1071 (infrastructure connue).
- Nature : émulation.
- Préconditions : listes synthétiques locales posées en administrateur : un nom `.test` dans une liste de domaines
  (listes restreintes activées pour le test, décision 5.1.5) ; une adresse secondaire de Kali dédiée (jamais 203.0.113.20) dans une
  liste de niveau 3.
- Action : résolution du nom listé ; connexion HTTP bénigne vers l'adresse listée.
- Attendu : DNS-001 Critique ; RES-001 Critique ; blocage automatique avec échéance de 7 jours ; recouvrement par
  « Débloquer » vérifié.
- Délai : 60 s.
- Nettoyage : déblocage ; listes de test retirées ; remise à l'instantané.
- Preuves : communes + règles « deR4Tizer » du pare-feu avant et après.

**S-08 — Balayage de ports**
- Technique : T1046.
- Nature : émulation.
- Préconditions : journal des paquets actif sur le profil de la carte du labo.
- Action : un balayage TCP borné (100 ports), une fois.
- Attendu : aucune règle dédiée ; RES-005 par port bloqué (HYPOTHÈSE, à compter) ; alertes EXP éventuelles relevées sans
  notation.
- Délai : 180 s.
- Nettoyage : remise à l'instantané.
- Preuves : communes + `pfirewall.log`, `exposition.json`, nombre de RES-005.

**S-09 — Persistance par clé Run et par tâche planifiée**
- Technique : T1547.001, T1053.005.
- Nature : émulation (commande bénigne qui écrit un fichier témoin).
- Préconditions : fiches Atomic correspondantes lues (prérequis, commande, nettoyage) si elles servent ; écartées si
  elles téléchargent ou ne se nettoient pas.
- Action : (a) valeur Run vers un interpréteur qui écrit un témoin ; (b) tâche planifiée équivalente.
- Attendu : PER-001 Alerte pour chacune ; 4698 produit (B2).
- Délai : 180 s.
- Nettoyage : valeur et tâche supprimées ; aucune alerte résiduelle.
- Preuves : communes + `demarrage.json`.

**S-10 — PowerShell encodé et obscurci (contenu bénin)**
- Technique : T1059.001, T1027.
- Nature : émulation.
- Préconditions : configurations A et B (décision 5.1.2).
- Action : (a) commande encodée longue qui écrit un témoin ; (b) script obscurci au même effet, lancé par fichier.
- Attendu : (a) PRC-002 Alerte ; (b) aucune alerte, 4104 présent (B2).
- Délai : 60 s.
- Nettoyage : témoin supprimé.
- Preuves : communes + Sysmon 1, 4688, 4104.

**S-11 — Commande et contrôle HTTP simulé, transfert d'un fichier bénin**
- Technique : T1071.001, T1105.
- Nature : émulation (serveur HTTP sur Kali servant un fichier texte).
- Préconditions : serveur du labo sur un port hors liste courante ; réponses tenues quelques secondes pour être vues par
  le relevé périodique.
- Action : (a) requêtes régulières toutes les 15 s pendant 3 min ; (b) téléchargement par PowerShell ; (c) même
  téléchargement par un outil Windows détourné.
- Attendu : (a) RES-002 avec indice « balise » ; (b) PRC-002 et/ou RES-002 ; (c) PRC-003 Alerte, DEF-001 si Defender
  réagit (résultat, jamais contourné) ; CHA-001 si deux signaux s'enchaînent ; contenu HTTP : E.
- Délai : 300 s (a), 60 s (b, c).
- Nettoyage : fichiers supprimés ; remise à l'instantané.
- Preuves : communes + journal du serveur, journal Defender.

**S-12 — Exfiltration d'un fichier canari**
- Technique : T1041.
- Nature : émulation (fichier généré, marqué CANARI, aucune donnée réelle).
- Préconditions : réception sur Kali.
- Action : envoi HTTP du canari par un programme de test.
- Attendu : RES-002 si le score est atteint ; rien sur le volume ni le contenu (E).
- Délai : 60 s.
- Nettoyage : canari supprimé des deux côtés.
- Preuves : communes + empreinte du canari, journal du serveur.

**S-13 — Service, compte administrateur, journal dédié effacé, audit modifié**
- Technique : T1543.003, T1136.001, T1098, T1070.001 (SIMULATION), T1562.002 (SIMULATION).
- Nature : SIMULATION pour T1070.001 et T1562.002 ; émulation pour les autres.
- Préconditions : journal dédié créé pour le test (décision 5.1.6). **Volet T1562.002 approuvé en v1.1** (décision du mainteneur du 2026-11-14 citée en 5.2) : il est désormais exécuté, avec le nettoyage à rétablissement vérifié ci-dessous. État initial de la sous-catégorie d'audit relevé avant l'essai.
- Action : service créé avec une image dans un dossier inscriptible (commande bénigne) ; compte de test créé puis ajouté
  aux Administrateurs ; journal dédié effacé ; sous-catégorie d'audit désactivée puis rétablie.
- Attendu : COR-R5 Critique ; COR-R3 Critique ; COR-R4 Critique ; COR-R7 Alerte ; BAS-001 Alerte si la sous-catégorie
  appartient au profil « journalisation ».
- Délai : 120 s ; 25 min pour BAS-001.
- Nettoyage : service, compte, journal dédié supprimés ; sous-catégorie d'audit remise dans son état initial (relevé avant l'essai) et le rétablissement vérifié (comparaison avant/après) ; remise à l'instantané après l'essai.
- Preuves : communes + 7045, 4720, 4732, 104, 4719 ; politique d'audit avant et après.

**S-14 — Lecture d'un fichier d'identifiants de navigateur (SIMULATION)**
- Technique : T1555.003 (SIMULATION).
- Nature : SIMULATION : compte de test sans aucun mot de passe enregistré ; ouverture en lecture puis fermeture, aucune
  copie, aucun déchiffrement.
- Préconditions : audit des objets actif, SACL posée par deR4Tizer.
- Action : un programme de test non signé, lancé d'un dossier temporaire, ouvre le fichier en lecture.
- Attendu : VOL-001 Critique.
- Délai : 60 s.
- Nettoyage : programme de test supprimé ; remise à l'instantané.
- Preuves : communes + 4663.

**S-15 — Accès limité à LSASS (SIMULATION)**
- Technique : T1003.001 (SIMULATION).
- Nature : SIMULATION : handle en accès « informations limitées » seulement, aucune lecture de mémoire, aucun outil de vol
  d'identifiants.
- Préconditions : configuration Sysmon notée.
- Action : ouverture puis fermeture immédiate du handle.
- Attendu : aucune alerte de deR4Tizer (aucune règle) ; Sysmon 10 si configuré (B2) ; réaction de Defender relevée.
- Délai : 60 s.
- Nettoyage : aucun.
- Preuves : communes + Sysmon 10.

**S-16 — Leurre anti-rançongiciel touché (SIMULATION, réponse automatique)**
- Technique : T1486 (SIMULATION).
- Nature : SIMULATION : un programme de test modifie un seul leurre ; aucun chiffrement, aucun autre fichier.
- Préconditions : leurres posés (collecte `Leurres` active) ; réponse automatique activée (défaut).
- Action : écriture d'un octet dans un leurre par un programme de test hors Program Files.
- Attendu : LEU-002 Critique, suspension automatique, inscription dans `reponses.json` ; LEU-001 au relevé suivant ;
  option longue : REP-001 Critique à 2 h, processus toujours suspendu ; « Reprendre » vérifié.
- Délai : 60 s ; 2 h 05 pour l'option.
- Nettoyage : reprise puis arrêt du programme de test ; remise à l'instantané.
- Preuves : communes + 4663, état du processus.

**S-17 — Session administrative à distance sur un partage administratif**
- Technique : T1021.002.
- Nature : émulation (liste d'un répertoire seulement ; aucun service distant, aucune exécution à distance).
- Préconditions : compte de test administrateur dédié.
- Action : depuis Kali, connexion authentifiée au partage administratif, liste d'un répertoire, déconnexion.
- Attendu : COR-R9 Alerte ; 4672 dans le SIEM ; 5140 produit mais non lu (B2).
- Délai : 120 s.
- Nettoyage : remise à l'instantané.
- Preuves : communes + 4624, 4672, 5140.

**S-18 — DNS-003 : port 53 de la boucle locale tenu par un autre programme au redémarrage du service (approuvé en v1.1)**
- Technique : sans correspondance ATT&CK exacte (interférence avec le résolveur local, détournement de la résolution) ; fonction de phase 7.
- Nature : émulation.
- Statut : **approuvé en v1.1** à la suite de la décision du mainteneur du 2026-11-14 citée en 5.2. Ce scénario exige un **arrêt du service deR4Tizer puis sa relance** ; il n'est exécutable que parce que le mainteneur l'a tranché (il sort du principe « deR4Tizer intact » du mandat courant). Sans cette décision écrite, il resterait non approuvé et non exécuté.
- Préconditions : configuration A suffit ; filtrage DNS activé (cartes réglées sur le résolveur local, `127.0.0.1`/`::1`) ; état des collectes, du filtrage et des cartes relevé ; un programme d'écoute bénin de labo prêt (il ouvre seulement le port 53 en écoute locale, sans servir de vraie résolution).
- Action : (a) le service est arrêté de telle sorte que les cartes restent réglées sur la boucle locale (cas de risque décrit au modèle de menace) ; (b) le programme bénin de labo prend le port 53 ; (c) le service est relancé et ne peut pas lier le port 53, une carte pointant encore sur `127.0.0.1`/`::1`.
- Attendu (**HYPOTHÈSE a priori, classe A attendue**) : DNS-003 Critique, avec le PID du programme qui tient le port 53 (règle non adoucie par l'apprentissage) ; aucune autre alerte Alerte/Critique sans lien. À mesurer, jamais présenté comme un résultat.
- Délai maximal : 180 s après la relance du service.
- Nettoyage : programme d'écoute arrêté, port 53 libéré ; **service deR4Tizer relancé et son bon fonctionnement vérifié** (le tube répond à une demande de version, collectes revenues « Active », filtrage et cartes rendus à leur état d'origine, comparaison avant/après) ; **remise à l'instantané après l'essai**.
- Preuves : communes + `filtrage-etat.json` et `filtrage-origine.json` avant et après, réglage des cartes avant et après, `journal.txt` (arrêt et relance du service, échec de liaison du port 53, PID relevé), état des collectes au début et à la fin.

### 3.2 Tests négatifs

| Id | Activité légitime | Attendu |
|---|---|---|
| N-01 | sessions locales, administration PowerShell par fichier signé | aucune Alerte/Critique |
| N-02 | tâche planifiée créée par un administrateur vers un programme signé de Program Files | PER-001 Info au plus |
| N-03 | téléchargement autorisé depuis Kali par le navigateur | aucune RES-002 ; RES-003 Info admise |
| N-04 | une erreur de mot de passe puis réussite en Bureau à distance | aucune COR-R1/R2 ; COR-R9 reste attendue (aucun négatif R9 possible : tout le labo est « public » pour le service) |
| N-05 | réglage DNS rendu au DHCP | aucune DNS-002 |

### 3.3 Écartés ou non exécutés

- T1567 : D (aucun service web réel autorisé ; un substitut du labo serait T1041).
- T1055 : non exécuté ; aucune injection, même bénigne, sans accord explicite ; aucun capteur consommé.
- T1562.001 contre Defender, les journaux Windows ou deR4Tizer : D (interdit).
- DNS-003 : exige l'arrêt puis la relance du service ; **approuvé en v1.1** (décision du mainteneur du 2026-11-14, 5.2), devenu le scénario S-18 (section 3.1).
- Volet T1562.002 de S-13 : **approuvé en v1.1** (décision du mainteneur du 2026-11-14, 5.2), exécuté dans S-13.
- Fiches Atomic qui téléchargent, désactivent une protection, lisent la mémoire de LSASS ou effacent un journal réel :
  écartées d'office.

---

## 4. Prérequis du labo à vérifier avant S-01

1. Réseau : VM cible et Kali seules sur `d4t-labo` ; « Default Switch » de la VM débranché ; lien d'administration sans
   route vers la VM ; aucune route vers Internet pendant la campagne.
2. Adresses : 203.0.113.10 (VM), 203.0.113.20 (Kali), adresse secondaire de Kali réservée à S-07 ; profil réseau de la
   carte de la VM relevé, Bureau à distance et partage de fichiers autorisés sur ce profil.
3. Horloges : écart VM, Kali et hôte relevé au début et à la fin de chaque lot.
4. Instantanés de campagne « campagne A » (sans Sysmon) et « campagne B » (Sysmon et Atomic, versions figées) présents,
   préparés hors campagne, chacun avec deR4Tizer installé, l'apprentissage terminé, les comptes de test et les réglages
   du labo ; aucun nom ne commence par « propre » ; instantané « propre » présent pour le retour après la campagne
   seulement ; Defender actif, sans exclusion, état relevé dans chaque instantané de campagne.
5. deR4Tizer : version et empreinte du MSI ; service en marche ; aucune collecte « Inconnue » ; profil « journalisation »
   conforme (audit Logon, 4688 avec ligne de commande, 4104, 4663, `pfirewall.log`) ; état de l'apprentissage ; source
   des processus (Sysmon ou WMI) relevée.
6. Collecte indépendante : 4688, 4104, Planificateur, Defender, Sysmon (configuration notée) lisibles et exportables.
7. Comptes de test créés, seuil de verrouillage relevé ; aucun mot de passe dans une preuve.
8. Kali : outils et versions notés ; serveur HTTP et amont DNS du labo prêts (S-06, S-07, S-11) ; journal horodaté.
9. Collecte des preuves sur la VM (PowerShell Direct) essayée à blanc sur N-01.

---

## 5. Décisions de conception et points laissés au mainteneur

### 5.1 Décisions prises par l'agent de validation (v1.0 ; 2 et 3 révisées en v1.2)

1. **Apprentissage terminé dans l'instantané de campagne.** Raison : on mesure le régime normal d'un poste après ses
   7 premiers jours ; en apprentissage, presque toute « Alerte » sortirait « Info » et la mesure ne dirait rien des règles.
   La fin de l'apprentissage est relevée (date, `apprentissage.json`) dans chaque rapport ; une mesure en apprentissage
   pourra venir plus tard, notée à part.
2. **Deux configurations, jamais fusionnées** (révisée en v1.2). Configuration A « sans Sysmon » : instantané
   « campagne A », collecte indépendante par les journaux natifs (4688 avec ligne de commande, 4104, Planificateur,
   Defender). Configuration B « avec Sysmon » : instantané « campagne B » (Sysmon et Atomic Red Team). Les deux sont
   préparés hors campagne avec deR4Tizer installé, l'apprentissage terminé, les comptes de test et les réglages du labo ;
   aucun ne part de « propre », qui ne sert qu'au retour après la campagne. Raison : deR4Tizer choisit Sysmon au démarrage s'il est
   présent ; A mesure le poste client par défaut, B la meilleure télémétrie disponible ; Sysmon n'est une collecte
   indépendante que pour les événements que deR4Tizer ne lit pas (tout sauf 1 et 22). Scénarios sans processus (COR-*,
   DNS, IPC-03, D4-1) : configuration A suffit ; scénarios PRC et persistance : les deux.
3. **Remise à l'instantané de campagne de la configuration avant chaque essai des scénarios à corrélation** (S-01 à
   S-04, S-13, S-17 ; révisée en v1.2). Raison : la déduplication d'une heure et la fenêtre d'échecs de 30 min sont en
   mémoire ; sans remise, les essais ne sont pas indépendants. La remise vise « campagne A » ou « campagne B », jamais
   « propre », qui effacerait deR4Tizer, les comptes de test et les réglages du labo. Les autres scénarios gardent la
   remise par lot vers le même instantané, avec l'état de référence vérifié entre deux essais. La VM revient à « propre »
   seulement après la campagne.
4. **Résolveur DNS de labo sur Kali**, sur `d4t-labo` seulement, qui ne répond que pour une zone `.test` et les noms du
   labo, sans aucun relais vers Internet. Raison : le filtrage ne s'engage que si un amont répond (limite écrite en
   phase 7) ; c'est la seule façon de l'exercer hors Internet. Outil côté Kali, hors de la VM de test : aucune dépendance
   nouvelle dans la VM.
5. **Listes restreintes activées pour S-07, avec des listes synthétiques locales** (noms `.test`, adresse secondaire de
   Kali), posées en administrateur, effacées par la remise à l'instantané. Raison : sans elles, DNS-001 et RES-001 ne
   peuvent pas se déclencher dans un labo sans Internet ; aucun contenu de tiers n'est utilisé, la question de licence
   ne se pose pas. L'adresse principale de Kali n'est jamais listée (sinon le blocage automatique couperait le labo).
6. **T1070.001 en SIMULATION sur un journal dédié créé pour le test** : retenu. Raison : aucun journal existant de Windows
   n'est touché, l'effacement ne porte que sur ce journal, supprimé ensuite. **T1562.002** (sous-catégorie d'audit
   désactivée puis rétablie) : modifie la journalisation de Windows ; d'abord laissé au mainteneur, puis **approuvé en
   v1.1** sur sa décision du 2026-11-14 (5.2), exécuté dans S-13 avec rétablissement vérifié de la sous-catégorie.
7. **Option longue de S-16 (REP-001 à 2 h)** : retenue, une observation par configuration, rapportée comme non
   consolidée (pas 10 essais de 2 h). Raison : c'est la seule façon de vérifier l'échéance et la relance de la phase 6 ;
   le programme suspendu est un programme de test, repris puis arrêté.
8. **T1555.003 (S-14) ajouté**, en SIMULATION : compte de test sans aucun mot de passe enregistré, ouverture en lecture
   puis fermeture, aucune copie, aucun déchiffrement. Raison : seul moyen d'exercer VOL-001 ; aucun identifiant réel
   n'existe ni n'est lu. S-15 (LSASS en accès « informations limitées », sans lecture de mémoire) reste dans la forme
   que prévoit la consigne.
9. **Classement** : T1567 en D (aucun service web réel autorisé ; un substitut du labo serait T1041) ; T1055 non exécuté
   (D, aucune injection, même bénigne) ; B1 et B2 restent des sous-divisions descriptives de la classe B, comptées en B
   dans tous les scores.
10. **Publication** : ce document, une fois transmis au mainteneur, est proposé sous `docs/validation/` par une PR de
    documentation seule, après la garde PII ; la fusion reste décidée par le mainteneur.

### 5.2 Points remontés au mainteneur, tranchés le 2026-11-14

Ces deux volets sortaient du mandat de l'agent (ils touchent la journalisation de Windows ou le service lui-même) et
avaient été laissés au mainteneur en v1.0. **Décision du mainteneur, 2026-11-14, citée mot pour mot : « J'autorise les
deux ».** Les deux volets passent donc de non approuvé à approuvé en v1.1. Cette décision est une décision du mainteneur,
pas une approbation de l'agent : l'approbation de l'agent reste ni humaine ni indépendante et ne lève aucune règle. La
v1.1 lui est transmise, pour information, avant toute exécution ; il peut retirer un scénario ou reprendre l'approbation
à tout moment.

1. **Volet T1562.002 de S-13** (désactivation temporaire d'une sous-catégorie d'audit, puis rétablissement) : touche la
   journalisation de Windows. **Approuvé en v1.1** sur la décision ci-dessus. S-13 l'exécute désormais ; nettoyage à
   rétablissement vérifié : la sous-catégorie est remise dans son état initial (relevé avant l'essai, comparaison
   avant/après) et l'essai est suivi d'une remise à l'instantané. Aucune autre sous-catégorie ni aucun autre réglage
   d'audit n'est touché.
2. **DNS-003** (devenu le scénario S-18, section 3.1) : exige d'arrêter le service deR4Tizer puis de faire tenir le
   port 53 par un autre programme, et de relancer le service. **Approuvé en v1.1** sur la décision ci-dessus ; c'est la
   seule dérogation au principe « deR4Tizer intact » du mandat, et elle tient à cette décision écrite. Nettoyage à
   rétablissement vérifié : programme d'écoute arrêté, port 53 libéré, **service relancé et son bon fonctionnement
   vérifié** (tube qui répond, collectes « Active », filtrage et cartes rendus à l'identique), puis remise à
   l'instantané après l'essai.