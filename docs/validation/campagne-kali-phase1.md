# Campagne de validation Kali : audit initial et liste fermée de scénarios (phase 1)

| Champ | Valeur |
|---|---|
| Version de la liste | **1.5** (S-20 à S-27 ajoutés le 2026-11-19, §6 ; version 1.4 pour le reste) |
| Date de la version 1.4 | 2026-11-15 |
| Versions précédentes | 1.3 du 2026-11-14 ; 1.2 du 2026-11-14 ; 1.1 et 1.0 du 2026-11-14 (publiées/transmises sous `docs/validation/campagne-kali-phase1.md`) |
| Code audité | (v1.3) `main` au commit `cde9468` ; règle d'approbation relue dans `CLAUDE.md` à `8faf4f9` ; baseline lue dans `service-rs/src/baseline.rs` et `gpo.rs` à `ede269f`. (v1.4) Correction de l'énoncé de S-07, réécriture de la fiche S-06 et correction d'une erreur de la rédaction initiale (« code DNS-002/filtrage absent »), établies à la **lecture du worktree complet de `main` à jour** (après les fusions de phase 7.3/7.4) ; le checkout de travail de la v1.3 était sur une branche périmée (`passages-en-vm`) antérieure à ces fusions, d'où l'erreur. Aucune mesure n'y est présentée. |
| Statut | **APPROUVÉE PAR L'AGENT DE VALIDATION** |

> **Note du 2026-11-19** : les mentions « IDS, DPI, NDR gelés » de cette liste (§2, §3, §5) et la classe E qui en découle valent à la date de la v1.4 ; l'IDS et le NDR sont dégelés depuis le 2026-11-16, le DPI depuis le 2026-11-18 (`CLAUDE.md`).

> **Rappel sur l'approbation (v1.4).** L'approbation par l'agent de validation **n'est ni humaine ni indépendante** (même modèle que celui qui exécute les scénarios ; leurs angles morts peuvent coïncider) et **ne lève aucune règle** de `CLAUDE.md` ni du mandat. La **version 1.4 a été transmise au mainteneur, pour information, le 2026-11-15, avant toute exécution.** Nouveautés principales : **correction de l'énoncé de S-07** (adresse de menace placée dans une source de **confiance haute**, et non « liste de niveau 3 » : une source de réputation ne déclenche pas le blocage automatique) ; **règles de décision D-1** (artefact d'exposition de labo RES-004/005) **et D-2** (collecte « Indisponible » après restauration) inscrites comme règles de notation (5.4) ; **S-06** (DNS-002 et filtrage DNS) **réécrit au niveau comportement et testable** (DNS-002 = Alerte ; filtrage = blocage sans alerte, noté dans les « derniers blocages »), après correction de l'erreur « code absent » de la rédaction initiale (checkout périmé ; le code est bien dans `main`, 5.5). Les volets T1562.002 de S-13 et DNS-003 (S-18) restent approuvés depuis la v1.1 (5.2). **Rien ici n'est un résultat.**

## Approbation

Approuvée le 2026-11-14, version 1.0, par l'agent de validation, en application de `CLAUDE.md` (section 5, phase 7,
campagne Kali : « Liste fermée de scénarios écrite et approuvée par l'agent de validation avant toute exécution »).

- **2026-11-14, version 1.1** : approuvée par l'agent de validation (volets T1562.002 de S-13 et DNS-003 approuvés sur la
  décision du mainteneur citée en 5.2).
- **2026-11-14, version 1.2** : approuvée par l'agent de validation (instantanés de campagne « campagne A » et
  « campagne B », approbation datée). **Ni humaine ni indépendante** ; ne lève aucune règle ; transmise au mainteneur avant
  toute exécution.
- **2026-11-14, version 1.3** : approuvée par l'agent de validation (configuration C principale, baseline à 100 % sur
  décision du mainteneur ; attendu en configuration C par scénario ; classe P « prévenu (baseline) » ; S-19 ; défaut
  D-BAS-01). **Ni humaine ni indépendante** ; ne lève aucune règle ; transmise au mainteneur le 2026-11-14 avant toute
  exécution.
- **2026-11-15, version 1.4** : approuvée par l'agent de validation (correction de l'énoncé de S-07 : source de
  **confiance haute**, non « niveau 3 » ; **règles de décision D-1 et D-2** inscrites ; **S-06 réécrit au niveau
  comportement et classé testable** — le code de DNS-002 et du filtrage est présent dans `main`, l'erreur « code absent »
  d'une rédaction initiale venait d'un checkout périmé). **Cette approbation n'est ni humaine
  ni indépendante** ; elle ne lève aucune règle, et la v1.4 a été transmise au mainteneur, pour information, le 2026-11-15,
  avant toute exécution.
- **2026-11-19, version 1.5** : S-20 à S-27 ajoutés sur décision du mainteneur (`CLAUDE.md`, campagne Kali), **après
  leur exécution** (2026-11-16 et 2026-11-17) ; aucune approbation préalable de l'agent de validation (§6).

- **Cette approbation n'est ni humaine ni indépendante** : l'agent est le même modèle que celui qui exécute les
  scénarios ; leurs angles morts peuvent coïncider. Elle n'est jamais présentée comme une validation.
- Elle ne lève aucune règle : aucun scénario qui toucherait Defender, sortirait du labo, volerait un identifiant réel,
  porterait une charge destructive ou exigerait une saisie de mot de passe n'est approuvé. Les cas douteux sont laissés au
  mainteneur (section 5.2).
- Cette version est transmise au mainteneur, pour information, **avant toute exécution**. Il peut retirer un scénario ou
  reprendre l'approbation à tout moment. Tout ajout ou changement fait l'objet d'une nouvelle version approuvée avant
  d'être exécuté.
- L'exécution ne commence qu'une fois les prérequis de la section 4 vérifiés, par N-01 puis S-01 seul ; le scénario
  suivant n'est lancé que si l'état de référence est vérifié et les preuves du précédent complètes.

**Retenus (v1.4)** : N-01 à N-05 ; S-01 à S-05 ; **S-06 (DNS-002 et filtrage DNS, testable)** ; S-07 à
S-12 ; S-13 **y compris son volet T1562.002** (approuvé en v1.1) ; S-14 à S-19 ; S-16 avec son option longue (2 h, en
configuration A). **Ajoutés** : S-18 (DNS-003) en v1.1 ; S-19 (contrôle de la configuration C) en v1.3. Configurations :
C principale, A comparaison, B collecte Sysmon (3.0, 5.1.2, 5.1.11).

**Écartés (v1.1)** : T1567 (D) ; T1055 (non exécuté) ; T1562.001 contre Defender, les journaux de Windows ou deR4Tizer
(interdit) ; fiches Atomic qui téléchargent, désactivent une protection, lisent la mémoire de LSASS ou effacent un journal réel.

**Tranchés par le mainteneur le 2026-11-14, approuvés en v1.1** : volet T1562.002 de S-13 ; DNS-003 (devenu S-18).
Décision citée mot pour mot en section 5.2.

**Correction (v1.4)** : **S-06** (DNS-002 et filtrage DNS) avait été faussement classé « code absent / en attente du
mainteneur » par une rédaction initiale, à cause d'un checkout périmé (branche `passages-en-vm`, antérieure aux fusions
de phase 7.3/7.4). Le code est bien présent dans `main` : S-06 est **testable** et sa fiche est réécrite au niveau
comportement (3.1, 5.5).

**Changements de la v1.1 à la v1.0** : les deux volets ci-dessus passent de « laissé au mainteneur » à approuvé ; S-18
créé pour DNS-003 ; cross-références mises à jour ; en-tête en version 1.1.

**Changements de la v1.2 à la v1.1** (relecture PR #172) : les configurations A et B partent des instantanés « campagne A »
et « campagne B » (et non de « propre ») ; toutes les remises visent l'instantané de la configuration ; la VM ne revient
à « propre » qu'après la campagne ; « non mesurée » précisé en « non mesurée en VM ». Aucun scénario ajouté, retiré ni
changé dans son action ou son attendu.

**Changements de la v1.3 à la v1.2** (décision du mainteneur du 2026-11-14 : « pour les tests kali, tu as bien pris en
compte d'avoir la baseline à 100% ? C'est l'un des interêts du produit », puis « ok parfait ») : configuration C ajoutée,
instantané « campagne C » (« campagne A » plus la baseline appliquée par le service, trois profils), devenue
configuration principale de mesure ; A reste la comparaison, B la collecte Sysmon ; section 1.7 ; classe P « prévenu
(baseline) », jamais confondue avec une détection ; un attendu en configuration C (HYPOTHÈSE) par scénario et par test
négatif ; S-19 ; section 5.3 (défaut D-BAS-01). Actions et nettoyages des scénarios existants inchangés.

**Changements de la v1.4 à la v1.3** (lecture du worktree complet de `main`, après les fusions de phase 7.3/7.4) :
- **S-07 corrigé.** La v1.3 plaçait l'adresse de menace dans une « liste de niveau 3 ». **Une source de réputation (par
  exemple un niveau 3) ne déclenche PAS le blocage automatique** ; le blocage automatique de 7 jours exige une source de
  **confiance haute**. L'énoncé de S-07 (3.1), la cartographie (2) et la décision 5.1.5 sont corrigés : l'adresse de
  menace est placée dans une **source de confiance haute** (par exemple une liste C2 de botnets ou un bloc DROP). S-07 est
  décrit **au niveau comportement** : domaine malveillant connu (DNS-001) + adresse de menace connue de confiance haute
  (RES-001) + blocage automatique à échéance de 7 jours. Aucun nom de fichier d'implémentation, aucune commande offensive
  détaillée, aucune adresse hors plage de documentation.
- **Règles de décision D-1 et D-2 inscrites** (5.4, renvoi en 3.0) : D-1, les alertes RES-004/RES-005 portant une adresse
  de la plage de documentation du labo sont des **artefacts d'exposition de labo**, exclus des VP comme des FP, conservés
  dans les preuves ; D-2, critère de collecte « Indisponible » après restauration (une collecte dont dépend une règle du
  scénario doit être « Active » au départ, prouvée par une lecture postérieure à la restauration, sinon essai invalide,
  classe D, jamais 0).
- **S-06 réécrit au niveau comportement, testable** (1.5, 2, 3.1, 3.3, 5.5) : une rédaction initiale avait classé S-06
  « code absent / classe E » ; c'était une **erreur due à un checkout périmé** (branche `passages-en-vm`, antérieure aux
  fusions de phase 7.3/7.4). Le code de **DNS-002** (`dns_surveillance.rs`) et du **filtrage DNS** (résolveur local,
  `dns_local.rs`, `filtrage.rs`, `filtrage_cartes.rs`) est bien dans `main` et listé par la matrice des capacités. S-06
  couvre désormais (a) DNS-002 = changement de serveur DNS statique sur une carte → Alerte, et (b) le filtrage par
  résolveur local = un nom `.test` de la liste est résolu en adresse nulle et apparaît dans les « derniers blocages »,
  sans alerte. Le témoin **N-05** redevient un **témoin négatif normal** (retour au DHCP sans alerte). Aucune action ni
  nettoyage d'un autre scénario n'est changé.

Document publiable tel quel (`docs/validation/`) : niveau comportement, identifiants ATT&CK, attendus, nettoyage et
preuves ; aucune commande offensive détaillée ; aucune donnée personnelle, aucun chemin de profil, aucun identifiant de
compte ni mot de passe. Adresses en plages de documentation (RFC 5737), noms de test en `.test` (RFC 2606).

Tout ce qui est marqué **HYPOTHÈSE** est déduit de la lecture du code et des documents, non mesuré. Rien ici n'est un
résultat.

---

## 1. État des capacités de détection (d'après le code et `docs/`)

### 1.1 Architecture utile à la campagne

- Service Rust en SYSTEM, cycle de surveillance toutes les 3 s environ, fils séparés pour les journaux, la persistance
  (1 min), la santé (30 s), le DNS (60 s), le filtrage.
- Canal `\.\pipe\deR4Tizer` : clients distants refusés par le tube (PR #168) ; connexion distante (IPC-03) **jamais
  essayée** (matrice des capacités).
- Alertes avec `Regle`, `Modele`, `HeureUtc`, `Seq`, `Collecte` ; une alerte Alerte ou Critique ouvre ou rejoint un
  incident (entité, 24 h) ; une alerte Info n'ouvre rien.
- **Apprentissage** : 7 jours après la première installation, toute alerte « Alerte » sans signal fort devient « Info » et
  son comportement est mémorisé. Jamais adoucis : Critique, SAN-*, REP-*, DNS-002, IDS, et les motifs téléchargement de
  code, LOLBin, débogage à distance, suppression des sauvegardes, macro, anomalie du dossier des tâches. Conséquence pour
  la mesure (décision 5.1.1 : apprentissage terminé).
- Profil de baseline « journalisation » appliqué automatiquement au premier démarrage sur un poste non géré : audit des
  ouvertures de session, création de processus (4688) avec ligne de commande, système de fichiers (4663), autres objets
  (4698), comptes et groupes, politique d'audit, extensions de sécurité, règles du pare-feu, `pfirewall.log`, blocs de
  script PowerShell (4104), modules (4103), journaux DNS-Client et Planificateur. À vérifier dans l'instantané (section 4).

### 1.2 Sources d'événements réellement consommées

| Source | Consommée par | Remarque |
|---|---|---|
| Sécurité : 4624, 4625, 4648, 4672, 4688, 4697, 4719, 4720-4726, 4728, 4732, 4740, 4756, 4798, 1102 | COR-* | 4688 enregistré mais aucune règle PRC ne s'en sert ; 4698, 5140, 5145 non souscrits |
| Sécurité 4663 | VOL-001, LEU-002 | exige l'audit des objets et la SACL posée |
| Système : 7045, 104, 7036 | SIEM | 7036 seulement pour deR4Tizer, Defender, pare-feu, journal d'événements, Centre de sécurité |
| Sysmon 1 et 22 seulement | processus | **choisi au démarrage si présent**, sinon WMI ; les autres événements Sysmon ne sont pas lus |
| WMI des processus | processus | processus brefs perdus, lignes de commande souvent absentes |
| DNS-Client (ou Sysmon 22) | DNS-001, indice « IP directe » | |
| Defender (journal, état) | DEF-001 à 012 | DEF-003 à 006 et 010 à 012 supposent Defender affaibli : jamais exercées |
| Journal du pare-feu (règles) | SYS-002, SYS-003 | |
| `pfirewall.log` | RES-005 | une alerte par (source, port, action) et par 24 h |
| Table TCP, ports en écoute | RES-001 à 003, 006, 007 | relevé périodique : une connexion brève peut être manquée (HYPOTHÈSE) |
| Démarrages automatiques | PER-001, PER-002 | toutes les minutes |
| Leurres, hosts | LEU-001, SYS-001 | empreintes |
| Cartes réseau | DNS-002, DNS-003 | 60 s — voir réserve ci-dessous |
| PowerShell 4104 | **aucune règle** | produit par Windows, jamais lu |

> **Note (v1.4) sur la ligne « Cartes réseau / DNS-002, DNS-003 ».** À la lecture du worktree complet de `main` (après
> les fusions de phase 7.3/7.4), la **surveillance du serveur DNS de carte (DNS-002, `dns_surveillance.rs`)** et le
> **filtrage DNS par résolveur local** (`dns_local.rs` sur `127.0.0.1:53` et `[::1]:53`, moteur `filtrage.rs`, activation
> sur les cartes `filtrage_cartes.rs`, état `filtrage-etat.json`) sont bien présents, en plus de la lecture du journal
> DNS-Client (3008) qui alimente **DNS-001** et du vidage du cache. Une rédaction initiale les disait « absents » : erreur
> due à un checkout périmé, corrigée ici (5.5). **DNS-002, le filtrage et DNS-003 (S-18) sont donc testables.** Prudence
> conservée, non bloquante : vérifier que le binaire installé correspond bien à cette source de `main` avant de mesurer.

### 1.3 Règles (`regles.rs`, `docs/detection/regles.md`)

État de mesure : **non mesurée en VM** pour toutes les fiches, sauf PER-001 (clé Run) et DNS-002, vues au scénario 3a.
La « DNS-002 vue au scénario 3a » provient simplement de `main` (règle `DNS_002` de `regles.rs`, détection dans
`dns_surveillance.rs`) ; la spéculation d'une rédaction initiale (binaire d'une branche non fusionnée) venait d'un
checkout périmé et est retirée (5.5).

- RES-001 (menace connue, Critique, blocage automatique **si la source est de confiance haute**, par exemple un bloc DROP
  ou une liste C2 de botnets), RES-002 (score ≥ 3), RES-003 (Info), RES-004, RES-005, RES-006, RES-007.
- DNS-001 (listes de domaines désactivées par défaut, licences restreintes), DNS-002, DNS-003.
- PRC-001 à 005, CHA-001 ; PER-001, PER-002 ; DEF-001 à 012 ; LEU-001, LEU-002 ; VOL-001 ; SYS-001 à 003 ; PIL-001 ;
  EXT-001 ; VIE-001 à 003 ; BAS-001.
- COR-R1 (5 échecs en 5 min, même source), COR-R2 (réussite après ≥ 5 échecs en 30 min, Critique), COR-R3/R3b, COR-R4
  (1102/104), COR-R5, COR-R6, COR-R7, COR-R9 (Critique si Bureau à distance, Alerte sinon), COR-R10. Pas de R8.
- SAN-001 à 004, SAN-010 à 012 ; REP-001 à 004 ; INT-001, INT-002 ; EXP-IDS/DPI/NDR (gelés).

### 1.4 Réponses automatiques et durées

| Action | Niveau | Échéance | À l'échéance |
|---|---|---|---|
| Blocage IP d'une source de confiance haute (bloc DROP / liste C2 de botnets) | 3, actif par défaut | 7 jours | levé |
| Suspension du programme qui touche un leurre | 3, actif par défaut | 2 h | reste suspendu ; REP-001 Critique puis toutes les 24 h |
| Blocage IPS | 2, IPS désactivé par défaut | 24 h | levé |
| Suspension manuelle, isolation, panique | 2 | 24 h, 7 j, 4 h | jamais levé, relance |
| Quarantaine, blocage manuel | 2 | 30 j, 90 j | rappel Info |
| Filtrage DNS | 2, mode désactivé par défaut | aucune | — (un blocage n'est pas une alerte : il apparaît dans les « derniers blocages », `filtrage-etat.json` ; S-06) |

Gardes : 3 blocages de la même adresse par 24 h, 30 blocages par listes par heure, décision humaine respectée 7 jours ;
REP-002 quand une action est retenue.

### 1.5 Filtrage DNS (phase 7) — **présent dans `main` (v1.4)**

Fonction documentée (phase 7) : résolveur local sur la boucle, cartes physiques réglées sur lui à l'activation, serveurs
d'origine en secours, échec ouvert ; un blocage n'est pas une alerte (il apparaît dans un fichier d'état). Limite
documentée : tant que l'amont ne répond pas, les cartes restent sur leurs serveurs d'origine, sans filtrage ; un labo
sans Internet exige donc un amont DNS de labo (décision 5.1.4).

**Constat de lecture (v1.4) : ce code est présent dans `main`** (`dns_local.rs`, `filtrage.rs`, `filtrage_cartes.rs`,
état `filtrage-etat.json`), et DNS-002 dans `dns_surveillance.rs` ; la matrice des capacités les liste (résolveur local,
moteur de filtrage, état/DNS-003, Quad9). Une rédaction initiale les disait « absents » : erreur due à un checkout périmé
(branche `passages-en-vm`), corrigée ici. **Conséquence** : le scénario S-06 est **testable** (3.1) et le témoin N-05 est
un **témoin négatif normal** (3.2). Seule prudence maintenue, non bloquante : confirmer que le binaire installé correspond
à cette source avant de mesurer (section 4).

### 1.6 Limites connues qui pèsent sur la campagne

- IDS, DPI, NDR gelés : contenu HTTP, empreintes TLS, détection réseau de balayage : classe E.
- Aucune détection de balayage hors IDS ; effet attendu : RES-005 par port touché (HYPOTHÈSE).
- Aucune télémétrie d'accès à un processus ni d'injection consommée : T1003.001 et T1055 sans règle.
- 4104 jamais lu : un obscurcissement absent de la ligne de commande n'a aucune règle.
- « Active » garantit la lecture d'une source, pas la production des événements par Windows.
- Corrélations dédupliquées une heure en mémoire et fenêtre d'échecs de 30 min : deux essais depuis la même source dans
  l'heure ne donnent pas deux incidents (conception des essais, 3.0).
- La plage de documentation RFC 5737 compte comme Internet pour le service : c'est ce qui rend COR-R9 possible ; effets de
  bord : VM vue « exposée », RES-004/RES-005, RES-007, indice « IP directe ». Ces RES-004/RES-005 sur une adresse du labo
  sont des **artefacts d'exposition de labo** (règle de décision D-1, 5.4).
- **DNS-002, filtrage DNS et DNS-003 présents dans `main`** (1.5) : S-06 et S-18 sont testables ; seule prudence, non
  bloquante, confirmer que le binaire installé correspond à la source avant de mesurer (section 4).

### 1.7 Baseline de deR4Tizer appliquée à 100 % (configuration C, ajouté en v1.3)

Lu dans `service-rs/src/baseline.rs` (`main` à `ede269f`). La baseline passe par la GPO locale ; les valeurs d'origine
sont sauvegardées pour l'annulation ; l'application est refusée sur un poste géré (domaine ou MDM). Trois profils :
journalisation (appliqué d'office), recommandé, renforcé. Effets attendus sur la campagne, tous **HYPOTHÈSE** :

| Règle de la baseline | Profil | Effet attendu sur la campagne |
|---|---|---|
| `reseau.bureau-distance` | recommandé | S-01, S-02, S-05 (a), N-04 : RDP impossible ; COR-R1/R2 et la variante Critique de R9 par RDP non exerçables en C, mesurées en A |
| `reseau.pare-feu` | recommandé | règles d'autorisation locales conservées ; davantage de paquets refusés journalisés (S-08) |
| `reseau.smb1`, `reseau.invite-smb` ; `reseau.signature-smb` | recommandé ; renforcé | S-03, S-04, S-17 : Kali doit parler SMB 2 ou 3 ; signature exigée côté client, VM en serveur non touchée |
| `asr.scripts-obscurcis`, `asr.scripts-telecharges` | recommandé | S-10 : contenu obscurci bloqué possible ; création du processus et ligne de commande restent visibles |
| `asr.lsass` ; `systeme.lsa` ; `systeme.wdigest` | recommandé ; renforcé ; recommandé | S-15 : accès « informations limitées » permis ; une lecture de mémoire serait refusée (jamais exercée) |
| `asr.psexec-wmi` | renforcé | aucun scénario n'exécute à distance ; effet de bord possible relevé |
| `asr.prevalence` (mode audit) | renforcé | programmes de test récents (S-14, S-16, S-18) : événements 1122, sans blocage |
| `asr.rancongiciel` | recommandé | s'appuie sur le cloud, injoignable : effet incertain sur S-16 |
| `defender.dossiers-blocage` | renforcé | S-16 : leurres dans Documents, Images, Bureau (protégés) : écriture du programme de test non signé refusée ; témoins de S-09 hors de ces dossiers |
| `defender.pua`, `defender.cloud`, `defender.reseau` | recommandé | sans Internet, cloud et réputation injoignables : effet attendu faible sur S-07 et S-11 ; toute réaction relevée |
| `systeme.wsh` | renforcé | toute variante .vbs ou .js bloquée ; S-09 et S-10 passent par PowerShell |
| `systeme.smartscreen` | recommandé | N-03 : avertissement à l'ouverture d'un fichier téléchargé, pas au téléchargement |
| `systeme.uac` | recommandé | sans effet attendu sur le pilotage par PowerShell Direct (vérifié par N-01 en C) |

En configuration C, une action peut être **prévenue** (réglage de Windows posé par la baseline, ou Defender durci par
elle) sans être **détectée** par deR4Tizer : les deux sont notés séparément (classe P, section 2). Défaut constaté à la
lecture : D-BAS-01 (5.3).

---

## 2. Cartographie ATT&CK → alerte attendue

Classe a priori : **HYPOTHÈSE** pour toutes les lignes. A détection attendue ; B événement produit sans règle ; C alerte
attendue mais incorrecte ou trop générique ; D non exécutable dans le labo ; **E non testable avec l'architecture
actuelle** (gelé, ou fonction absente de la source lue). Sous-classes descriptives : B1 reçu par deR4Tizer sans règle, B2
produit par Windows ou Sysmon mais non lu.

Classe ajoutée en v1.3 : **P, prévenu (baseline)**. Le comportement est empêché, preuve à l'appui, par un réglage de
Windows posé par la baseline (P-baseline) ou par un composant de Defender durci par elle (P-Defender). **P n'est jamais
une détection** : un essai entièrement prévenu sort du dénominateur de détection (ni VP, ni FN) et est compté à part ; si
deR4Tizer alerte aussi, l'essai est noté « P + A » et seule la part A entre dans le score. Une réaction de Defender en
configuration A ou B (sans baseline durcie) est notée « bloqué par Defender », jamais attribuée à la baseline.

| Technique | Comportement simulé | Capteur requis | Événement attendu | Règle | Alerte attendue | Classe a priori (HYPOTHÈSE) |
|---|---|---|---|---|---|---|
| T1110.001 (RDP) | série d'échecs de mot de passe vers un compte de test | audit Logon | 4625 type 3 avec adresse source | COR-R1 | COR-R1 Alerte | A |
| T1110.001 puis T1078.003 | échecs puis réussite depuis la même source | audit Logon | 4625 ×≥5 puis 4624 | COR-R2 | COR-R2 Critique | A |
| T1133 / T1021.001 | session Bureau à distance depuis la plage de documentation du labo | audit Logon | 4624 type 3 puis type 10 | COR-R9 | COR-R9 Critique | **C** : la clé de déduplication de R9 serait prise par la 4624 de type 3 qui précède la type 10 ; R9 sortirait « Session ouverte depuis Internet », Alerte |
| T1021.001 | même session | table TCP | connexion établie sur 3389 | RES-007 | RES-007 Alerte | A |
| T1110.001 (SMB) | échecs puis réussite sur le partage de fichiers | audit Logon | 4625/4624 type 3 | COR-R1, R2, R9 | R1 Alerte, R2 Critique, R9 Alerte | A ; si l'adresse source manque, clé « compte » et R9 muette |
| T1021.002 | accès authentifié à un partage administratif, lecture seule | audit Logon | 4624 type 3, 4672, 5140 | COR-R9 | COR-R9 Alerte | A pour la session ; B2 pour l'accès au partage |
| T1046 | balayage de ports TCP borné | `pfirewall.log` | paquets bloqués depuis une adresse « publique » | RES-005 | aucune règle « balayage » | C (une RES-005 par port) ou E |
| T1071.001 | requêtes HTTP régulières vers un serveur du labo | table TCP, DNS-Client | connexions répétées | RES-002 | RES-002 Alerte (balise, IP directe, port) | A si vues par le relevé ; sinon FN de collecte |
| T1105 | téléchargement d'un fichier texte bénin par PowerShell | Sysmon 1 ou WMI, table TCP | processus, connexion | PRC-002, RES-002 | PRC-002 Alerte | A avec Sysmon ; instable sans |
| T1105 | même téléchargement par un outil Windows détourné | idem ; Defender | idem | PRC-003, DEF-001 | PRC-003 Alerte ; DEF-001 si Defender réagit | A |
| T1059.001 + T1027 | commande PowerShell encodée longue, contenu bénin | Sysmon 1 ou WMI | ligne de commande | PRC-002 | PRC-002 Alerte | A avec Sysmon |
| T1027 | script bénin obscurci lancé par fichier | 4104 | 4104 | aucune | aucune | B2 |
| T1547.001 | valeur Run vers une commande bénigne | démarrages automatiques | entrée nouvelle | PER-001 | PER-001 Alerte | A |
| T1053.005 | tâche planifiée bénigne lancée par un interpréteur | relevé des tâches | tâche nouvelle ; 4698 non lu | PER-001 | PER-001 Alerte | A |
| T1543.003 | service local, image dans un dossier inscriptible, commande bénigne | journal Système | 7045 | COR-R5, PER-001 | COR-R5 Critique | A |
| T1136.001 + T1098 | compte local créé puis ajouté aux Administrateurs | audit comptes et groupes | 4720, 4732 | COR-R3 | COR-R3 Critique | A |
| T1070.001 (SIMULATION) | effacement d'un journal dédié créé pour le test | journal Système | 104 | COR-R4 | COR-R4 Critique | A (HYPOTHÈSE : 104 émis) |
| T1562.002 (SIMULATION) | sous-catégorie d'audit hors besoins des règles désactivée puis rétablie | audit politique ; baseline | 4719 ; dérive | COR-R7, BAS-001 | COR-R7 Alerte ; BAS-001 Alerte si la sous-catégorie fait partie du profil | A |
| T1562.001 | Defender, journaux et deR4Tizer intouchables | — | — | DEF-003 à 006, 010 à 012 | — | D (interdit) |
| T1003.001 (SIMULATION) | ouverture de LSASS en accès « informations limitées », sans lecture de mémoire | Sysmon 10 si configuré | 10 | aucune | aucune | B2 |
| T1555.003 (SIMULATION) | ouverture en lecture du fichier d'identifiants d'un navigateur d'un compte de test vide, par un programme de test non signé lancé d'un dossier temporaire | 4663 + SACL | 4663 | VOL-001 | VOL-001 Critique | A |
| T1055 (SIMULATION) | aucune action ; télémétrie disponible inventoriée | — | — | aucune | aucune | non exécuté ; aucun capteur consommé |
| T1486 (SIMULATION) | un programme de test modifie un seul leurre de deR4Tizer | 4663 + empreinte | 4663 | LEU-002, LEU-001 | LEU-002 Critique + suspension automatique ; REP-001 à 2 h | A |
| T1041 | envoi HTTP d'un fichier canari généré vers Kali | table TCP | connexion sortante | RES-002 | RES-002 Alerte selon le score | A pour la connexion ; E pour le contenu et le volume |
| T1567 | envoi vers un service web public | — | — | — | — | D (aucun service réel autorisé) |
| — (menace connue) | connexion vers une adresse du labo inscrite dans une **source de confiance haute** | table TCP, liste locale | connexion | RES-001 | RES-001 Critique ; blocage automatique 7 j | A |
| — (DNS) | résolution d'un nom `.test` d'une liste de domaines **de confiance haute** | DNS-Client / Sysmon 22 | requête | DNS-001 | DNS-001 Critique | A (listes restreintes à activer) |
| — (DNS, S-06) | serveur DNS statique réglé sur la carte | cartes, registre | changement | DNS-002 | DNS-002 Alerte | A |
| — (DNS, S-18) | port 53 de la boucle tenu par un autre programme au redémarrage | échec de liaison, registre des cartes, table UDP | échec de liaison exclusive + PID | DNS-003 | DNS-003 Critique (PID) | A (approuvé en v1.1 ; filtrage présent dans `main`) |
| — (filtrage, S-06) | résolution d'un nom `.test` de la liste de filtrage | résolveur local | blocage | — | aucune alerte ; nom dans les derniers blocages | A (essai fonctionnel : blocage attendu, sans alerte) |
| IPC-03 | ouverture du canal depuis Kali par le réseau | tube | refus | — | refus, aucune commande exécutée | A (refus attendu) |

---

## 3. Liste fermée proposée

### 3.0 Règles communes

- Adressage : VM cible et Kali sur `d4t-labo`, dans la plage de documentation RFC 5737 ; lien d'administration sur une
  plage de documentation distincte entre le poste et Kali seulement ; carte « Default Switch » de la VM débranchée.
- Instantané de départ selon la configuration (décisions 5.1.2 et 5.1.11) :
  - « campagne C » (configuration C, **principale de mesure** depuis la v1.3) : « campagne A » plus la baseline de
    deR4Tizer appliquée par le service lui-même (`baseline appliquer`, trois profils, une seule commande), puis
    redémarrage ; sans Sysmon ;
  - « campagne A » (configuration A, comparaison) : installation sans baseline au-delà du profil journalisation appliqué
    d'office ; sans Sysmon ;
  - « campagne B » (configuration B, collecte Sysmon) : avec Sysmon et Atomic Red Team.
  Les trois sont préparés hors campagne avec deR4Tizer installé, l'apprentissage terminé, les comptes de test et les
  réglages du labo ; en C, la baseline l'emporte quand elle les contredit (Bureau à distance refusé). Leurs noms ne
  commencent jamais par « propre ».
- **« Remise à l'instantané » désigne la remise à l'instantané de campagne de la configuration de l'essai**, **jamais à
  « propre »** (qui effacerait deR4Tizer, les comptes de test et les réglages du labo). Remise avant et après chaque lot,
  et **avant chaque essai des scénarios à corrélation** (COR-*).
- La VM n'est remise à « propre » qu'**après la campagne**, une fois les preuves collectées.
- Atomic Red Team n'existe que dans « campagne B » ; en A ou C, le comportement est produit sans elle.
- Chaque scénario porte un attendu en configuration C, marqué HYPOTHÈSE. Scénarios que C rend inexécutables ou prévenus
  (S-01, S-02, S-05 (a), N-04 : Bureau à distance refusé ; S-16 : leurres dans des dossiers protégés) : la détection se
  mesure en A, l'essai en C reste une mesure de prévention (classe P). S-19 est exécuté au début de chaque lot en C ; s'il
  échoue, le lot est invalide (D).
- Scores séparés par configuration (A, B, C), jamais fusionnés ; classe P comptée à part, jamais comme détection.
- Comptes locaux de test dédiés ; mots de passe de labo jamais écrits dans un rapport ni dans le dépôt.
- Horodatage : début (UTC) relevé sur la VM ; latence = `HeureUtc` de l'alerte moins `TimeCreated` de l'événement
  déclencheur (et, en second, moins le début de l'action).
- Essai valide : comportement prouvé (événement Windows ou Sysmon, journal côté Kali), collectes « Active » au début et à
  la fin. Sinon D (invalide), jamais 0. **Critère précisé par la règle de décision D-2 (5.4) :** toute collecte dont dépend
  une règle du scénario doit être « Active » au départ, prouvée par une lecture réussie **postérieure à la restauration**
  de l'instantané ; sinon l'essai est invalide (D).
- VP : règle, niveau et entité attendus, dans le délai ; C : autre règle ou autre niveau ; FN : rien dans le délai ; FP :
  alerte Alerte ou Critique pendant un test négatif ou sans lien avec le scénario. **Règle de décision D-1 (5.4) :** une
  alerte **RES-004/RES-005** portant une adresse de la **plage de documentation du labo** est un **artefact d'exposition
  de labo**, exclu du décompte des VP comme des FP (y compris dans les tests négatifs), mais conservé dans les preuves ;
  une RES-004/005 portant une adresse hors plage de labo est investiguée, jamais exclue d'office.
- 10 essais valides par scénario avant toute mesure consolidée ; SIMULATION et émulation jamais dans le même score.
- Preuves communes : `alertes.json`, `suivi-incidents.json`, `incidents.json`, événements du SIEM du jour, `etat.json`,
  `reponses.json`, `blocages.json`, `journal.txt` ; extraits des journaux Windows et de Sysmon sur la fenêtre de l'essai ;
  versions de deR4Tizer, Windows, Sysmon, Atomic Red Team ; état de Defender au début et à la fin. Résultats bruts hors
  du dépôt.

### 3.1 Scénarios (du plus bénin au moins bénin)

**N-01 — Témoin de chaîne : activité légitime (négatif, valide la collecte et les preuves)**
- Technique : aucune (négatif).
- Préconditions : instantané de campagne de la configuration ; collectes actives ; apprentissage terminé ; horloges
  relevées.
- Action : ouverture de session locale du compte de test, une commande d'administration PowerShell signée lancée par
  fichier, consultation de l'interface.
- Attendu : aucune alerte Alerte/Critique ; 4624 présents dans le SIEM ; aucune collecte en panne.
- Délai : 10 min d'observation.
- Nettoyage : fermeture de session.
- Preuves : communes + état des collectes au début et à la fin.
- Attendu en configuration C (HYPOTHÈSE) : identique ; vérifie que le pilotage par PowerShell Direct et la collecte des
  preuves fonctionnent sous la baseline ; aucune alerte due à la baseline.

**S-01 — Force brute RDP, échecs seuls (premier scénario : valide la chaîne de mesure, COR-R1)**
- Technique : T1110.001. Nature : émulation (échecs réels contre un compte de test, aucun accès obtenu).
- Préconditions : N-01 réussi ; Bureau à distance autorisé sur le profil de la carte du labo ; compte de test hors
  Administrateurs ; nombre d'échecs inférieur au seuil de verrouillage relevé.
- Action : depuis Kali, une série d'échecs d'authentification au-delà du seuil de corrélation, en moins de 2 min, puis
  arrêt.
- Attendu : plusieurs 4625 (source = Kali) ; COR-R1 Alerte, entité `source:<adresse Kali>` ; un incident ouvert. Annexes
  admises : RES-005, RES-007 (RES-004/005 sur l'adresse du labo = artefact de labo, D-1).
- Délai maximal : 120 s après l'atteinte du seuil.
- Nettoyage : remise à l'instantané avant l'essai suivant.
- Preuves : communes + 4625 exportés ; journal côté Kali (heure, nombre, résultat ; sans mot de passe).
- Attendu en configuration C (HYPOTHÈSE) : **prévenu (P-baseline)** : Bureau à distance refusé, connexion refusée côté
  Kali, aucune 4625 par RDP, COR-R1 non exercée. Ce n'est pas un FN : COR-R1 se mesure en C par S-03 et en A par S-01.

**S-02 — Force brute RDP suivie d'une réussite**
- Technique : T1110.001, T1078.003, T1133. Nature : émulation.
- Préconditions : comme S-01.
- Action : une série d'échecs au-delà du seuil puis une ouverture de session réussie du compte de test, fermée aussitôt.
- Attendu : COR-R1 Alerte ; COR-R2 Critique ; COR-R9 Critique selon la fiche (**HYPOTHÈSE C** : Alerte « Session ouverte
  depuis Internet ») ; R2 et R9 dans un même incident `compte:<compte de test>` ; RES-007.
- Délai : 120 s après la 4624. Nettoyage : déconnexion ; remise à l'instantané.
- Preuves : communes + 4624 (types 3 et 10), 4625.
- Attendu en configuration C (HYPOTHÈSE) : **prévenu (P-baseline)** comme S-01 ; COR-R2 et la variante Critique de COR-R9
  (Bureau à distance) non exerçables en C, mesurées en A.

**S-03 — Force brute SMB suivie d'une réussite**
- Technique : T1110.001, T1021.002. Nature : émulation.
- Préconditions : partage de fichiers autorisé sur le profil de la carte du labo ; compte de test.
- Action : une série d'échecs d'authentification sur le partage au-delà du seuil, puis une connexion réussie en lecture
  d'un partage de test.
- Attendu : COR-R1, COR-R2, COR-R9 Alerte ; si l'adresse source manque dans 4625, R1 par compte et R9 muette (à
  constater). Délai : 120 s. Nettoyage : remise à l'instantané.
- Preuves : communes + 4625/4624 avec le champ d'adresse source.
- Attendu en configuration C (HYPOTHÈSE) : identique à A si l'autorisation « partage de fichiers » survit au blocage des
  entrées par défaut ; Kali en SMB 2 ou 3. Accès refusé par le pare-feu : P-baseline, relevé.

**S-04 — Connexion distante au canal de commandes (IPC-03)**
- Technique : aucune directe (frontière de privilège). Nature : émulation.
- Préconditions : compte de test standard.
- Action : depuis Kali, tentative d'ouverture du tube de deR4Tizer par le réseau, avec une demande de version.
- Attendu : refus ; aucune commande exécutée ; COR-R9 Alerte pour la session réseau. Délai : 60 s. Nettoyage : remise à
  l'instantané. Preuves : erreur côté Kali, `journal.txt`, SIEM.
- Attendu en configuration C (HYPOTHÈSE) : identique (refus du tube, COR-R9 Alerte) ; si la session SMB est refusée en
  amont : P-baseline, et le refus du tube n'est pas exercé (D pour IPC-03).

**S-05 — Essais D4-1 : interface en session Bureau à distance et au changement rapide d'utilisateur**
- Technique : aucune (essai fonctionnel, décision D4-1). Nature : essai fonctionnel.
- Préconditions : deux comptes de test ; tâche de relance présente.
- Action : (a) session Bureau à distance du compte A depuis Kali ; (b) changement rapide vers le compte B à la console.
- Attendu : interface présente dans chaque session active au plus tard 6 min après l'ouverture ; aucun SAN-010 sur
  25 min ; témoin retenu : interface fermée volontairement plus de 15 min, SAN-010. Délai : 25 min par cas.
- Nettoyage : sessions fermées ; remise à l'instantané. Preuves : processus par session, SIEM, alertes SAN.
- Attendu en configuration C (HYPOTHÈSE) : (a) **non exécutable** (Bureau à distance refusé) : D en C, mesuré en A ;
  (b) identique à A.

**S-06 — Changement de serveur DNS (DNS-002) et filtrage DNS par résolveur local**
- Technique : sans correspondance ATT&CK exacte (redirection de résolution) ; fonction de phase 7. Nature : émulation
  (DNS-002, changement de serveur DNS), essai fonctionnel (filtrage par résolveur local).
- **Statut v1.4 : testable.** Le code est présent dans `main` (DNS-002 : `dns_surveillance.rs` ; filtrage : résolveur
  local `dns_local.rs`, moteur `filtrage.rs`, activation sur les cartes `filtrage_cartes.rs`, état `filtrage-etat.json`).
  Une rédaction initiale classait S-06 « code absent / classe E » : c'était une erreur due à un checkout périmé, corrigée
  (5.5). L'activation des cartes sur le résolveur local en SYSTEM a l'accord du mainteneur (phase 7.4) : ce n'est pas une
  question ouverte.
- Préconditions : configuration A suffit ; amont DNS de labo sur Kali (le résolveur local relaie vers lui ; sans amont qui
  répond, les cartes restent sur leurs serveurs d'origine, limite de 5.1.4) ; résolveur local actif ; filtrage activé par
  la commande `filtrage` de l'administrateur (cartes physiques réglées sur le résolveur local, serveurs d'origine en
  secours) ; liste de filtrage synthétique locale avec un nom `.test` (noms `.test` uniquement, aucune liste de tiers) ;
  état des collectes, du filtrage et des cartes relevé ; critère D-2 (5.4) : les collectes `ConfigDns` (DNS-002) et
  `FiltrageDns` doivent être « Active » au départ, prouvées par une lecture postérieure à la restauration.
- Action : (a) **DNS-002** : un serveur DNS statique est réglé sur une carte physique active de la VM (réseau inchangé),
  puis le relevé des cartes (toutes les 60 s) le compare ; (b) **filtrage** : résolution par le client DNS de Windows d'un
  nom `.test` présent dans la liste de filtrage synthétique.
- Attendu : (a) **DNS-002 Alerte** (serveur DNS réglé à la main sur une carte physique ; règle non adoucie par
  l'apprentissage) ; (b) **aucune alerte** : le nom `.test` listé est résolu en **adresse nulle** et apparaît dans les
  « derniers blocages » (`filtrage-etat.json`), l'état du filtrage le comptant ; un nom `.test` **hors** liste est relayé
  vers l'amont de labo (témoin). 1 incident pour DNS-002 au plus.
- Délai maximal : 120 s pour DNS-002 (après le relevé des cartes) ; 60 s pour le filtrage.
- Nettoyage : serveur DNS statique retiré, carte rendue au DHCP (témoin négatif N-05 : aucune alerte au retour au DHCP,
  changement donné par le réseau) ; filtrage désactivé par la commande `filtrage` (cartes rendues à leurs serveurs
  d'origine, port 53 relâché, résolveur local arrêté) ; liste de filtrage synthétique retirée ; **vérifier que les cartes
  et le filtrage sont rendus à l'identique** ; remise à l'instantané après l'essai.
- Preuves : communes + réglage DNS des cartes avant/après (relevé et registre `NameServer`), `alertes.json` (DNS-002),
  `filtrage-etat.json` (derniers blocages, catégories, état actif), événement DNS brut (nom résolu), état des collectes
  `ConfigDns` et `FiltrageDns` au début et à la fin.
- Attendu en configuration C (HYPOTHÈSE) : identique (DNS-002 Alerte ; blocage sans alerte) ; aucune règle de la baseline
  ne porte sur le réglage DNS des cartes ni sur le filtrage ; si le poste est vu « joint à un domaine », l'activation du
  filtrage est refusée (décision D7-5 du code) : le relever, et mesurer alors le filtrage en configuration A.

**S-07 — Domaine et adresse inscrits dans des listes de menaces de test (confiance haute) — DNS-001 / RES-001**
- Technique : T1071 (infrastructure connue). Nature : émulation.
- Préconditions : listes synthétiques locales posées par un administrateur (propriétaire SYSTEM ou Administrateurs),
  effacées par la remise à l'instantané :
  - un **nom de domaine `.test`** (nom malveillant connu de test) dans une **liste de domaines de confiance haute**
    (listes restreintes activées pour le test, décision 5.1.5) ;
  - une **adresse secondaire de Kali dédiée** (dans la plage de documentation du labo, **jamais l'adresse principale de
    Kali**, sinon le blocage automatique couperait le labo) placée dans une **source de confiance haute** (par exemple une
    liste C2 de botnets ou un bloc DROP). **Correction v1.4 :** une source de **réputation** (par exemple de niveau 3) **ne
    déclenche PAS** le blocage automatique ; seule une source de **confiance haute** le fait. La v1.3 parlait à tort d'une
    « liste de niveau 3 ».
  - critère D-2 (5.4) : les collectes « listes de menaces » et « listes de domaines » doivent être **Active** au départ
    (listes synthétiques effectivement chargées), prouvées **après** la restauration ; sinon l'essai est **invalide (D)**.
- Action : (a) résolution du nom de domaine listé par le client DNS de Windows (requête vers l'amont de labo sur Kali, le
  commutateur privé ; aucun vrai domaine contacté) ; (b) connexion réseau bénigne, maintenue quelques secondes, vers
  l'adresse de menace listée (serveur du labo sur Kali), pour qu'elle soit vue par le relevé périodique de la table TCP.
- Attendu : **DNS-001 Critique** (résolution d'un domaine malveillant connu) ; **RES-001 Critique** (connexion vers une
  adresse de menace de confiance haute) + **blocage automatique à échéance de 7 jours** avec coupure de la connexion ;
  recouvrement par « Débloquer » vérifié (après « Débloquer », une nouvelle connexion re-déclenche tant que la liste est
  présente — à noter). 1+ incident.
- Délai : 60 s (résolution et connexion).
- Nettoyage : « Débloquer » l'adresse dans l'interface ; listes de test retirées ; listes restreintes remises à leur
  valeur d'origine ; remise à l'instantané.
- Preuves : communes + `menaces.json` (sources et compteurs avant/après), événement DNS brut (nom résolu), `alertes.json`
  (DNS-001, RES-001), `blocages.json` (échéance +7 j), règles « deR4Tizer » du pare-feu avant et après.
- Attendu en configuration C (HYPOTHÈSE) : identique (DNS-001, RES-001, blocage de 7 jours) ; sans réputation cloud
  joignable, la protection réseau ne devrait pas bloquer l'adresse du labo ; si elle le fait : P-Defender relevé à part,
  DNS-001 restant attendue (la résolution précède la connexion).

**S-08 — Balayage de ports**
- Technique : T1046. Nature : émulation. Préconditions : journal des paquets actif sur le profil de la carte du labo.
- Action : un balayage TCP borné, une fois.
- Attendu : aucune règle dédiée ; RES-005 par port bloqué (HYPOTHÈSE, à compter ; RES-004/005 sur l'adresse du labo =
  artefact de labo, D-1) ; alertes EXP éventuelles relevées sans notation. Délai : 180 s. Nettoyage : remise à l'instantané.
- Preuves : communes + `pfirewall.log`, `exposition.json`, nombre de RES-005.
- Attendu en configuration C (HYPOTHÈSE) : comme A, avec davantage de paquets refusés journalisés si la carte est sur le
  profil public et le port 3389 fermé ; nombre de RES-005 comparé à A.

**S-09 — Persistance par clé Run et par tâche planifiée**
- Technique : T1547.001, T1053.005. Nature : émulation (commande bénigne qui écrit un fichier témoin).
- Préconditions : fiches Atomic correspondantes lues si elles servent ; écartées si elles téléchargent ou ne se nettoient
  pas.
- Action : (a) valeur Run vers un interpréteur qui écrit un témoin ; (b) tâche planifiée équivalente.
- Attendu : PER-001 Alerte pour chacune ; 4698 produit (B2). Délai : 180 s. Nettoyage : valeur et tâche supprimées ;
  aucune alerte résiduelle. Preuves : communes + `demarrage.json`.
- Attendu en configuration C (HYPOTHÈSE) : PER-001 Alerte pour (a) et (b) ; témoin écrit hors des dossiers protégés (sinon
  P-Defender par l'accès contrôlé aux dossiers, relevé) ; variante par Windows Script Host bloquée (P-baseline), non
  utilisée.

**S-10 — PowerShell encodé et obscurci (contenu bénin)**
- Technique : T1059.001, T1027. Nature : émulation. Préconditions : configurations A et B.
- Action : (a) commande encodée longue qui écrit un témoin ; (b) script obscurci au même effet, lancé par fichier.
- Attendu : (a) PRC-002 Alerte ; (b) aucune alerte, 4104 présent (B2). Délai : 60 s. Nettoyage : témoin supprimé.
- Preuves : communes + Sysmon 1, 4688, 4104.
- Attendu en configuration C (HYPOTHÈSE) : (a) PRC-002 Alerte, avec un blocage possible du contenu par
  `asr.scripts-obscurcis` (1121) : « P + A » ; (b) blocage probable du script obscurci (P-Defender), aucune alerte de
  deR4Tizer, 4104 relevé s'il est produit.

**S-11 — Commande et contrôle HTTP simulé, transfert d'un fichier bénin**
- Technique : T1071.001, T1105. Nature : émulation (serveur HTTP sur Kali servant un fichier texte).
- Préconditions : serveur du labo sur un port hors liste courante ; réponses tenues quelques secondes.
- Action : (a) requêtes régulières pendant quelques minutes ; (b) téléchargement par PowerShell ; (c) même téléchargement
  par un outil Windows détourné.
- Attendu : (a) RES-002 avec indice « balise » ; (b) PRC-002 et/ou RES-002 ; (c) PRC-003 Alerte, DEF-001 si Defender
  réagit (résultat, jamais contourné) ; CHA-001 si deux signaux s'enchaînent ; contenu HTTP : E. Délai : 300 s (a), 60 s
  (b, c). Nettoyage : fichiers supprimés ; remise à l'instantané. Preuves : communes + journal du serveur, journal Defender.
- Attendu en configuration C (HYPOTHÈSE) : identique (RES-002, PRC-002, PRC-003) ; cloud et protection réseau
  injoignables, effet attendu faible ; toute détection ou tout blocage de Defender noté à part (P-Defender ou DEF-001).

**S-12 — Exfiltration d'un fichier canari**
- Technique : T1041. Nature : émulation (fichier généré, marqué CANARI, aucune donnée réelle). Préconditions : réception
  sur Kali. Action : envoi HTTP du canari par un programme de test.
- Attendu : RES-002 si le score est atteint ; rien sur le volume ni le contenu (E). Délai : 60 s. Nettoyage : canari
  supprimé des deux côtés. Preuves : communes + empreinte du canari, journal du serveur.
- Attendu en configuration C (HYPOTHÈSE) : identique (RES-002 selon le score) ; aucune règle de la baseline ne porte sur
  l'envoi HTTP.

**S-13 — Service, compte administrateur, journal dédié effacé, audit modifié**
- Technique : T1543.003, T1136.001, T1098, T1070.001 (SIMULATION), T1562.002 (SIMULATION). Nature : SIMULATION pour
  T1070.001 et T1562.002 ; émulation pour les autres.
- Préconditions : journal dédié créé pour le test. **Volet T1562.002 approuvé en v1.1** (décision du mainteneur du
  2026-11-14, 5.2) : exécuté avec nettoyage à rétablissement vérifié. État initial de la sous-catégorie d'audit relevé
  avant l'essai.
- Action : service créé avec une image dans un dossier inscriptible (commande bénigne) ; compte de test créé puis ajouté
  aux Administrateurs ; journal dédié effacé ; sous-catégorie d'audit désactivée puis rétablie.
- Attendu : COR-R5 Critique ; COR-R3 Critique ; COR-R4 Critique ; COR-R7 Alerte ; BAS-001 Alerte si la sous-catégorie
  appartient au profil « journalisation ». Délai : 120 s ; 25 min pour BAS-001.
- Nettoyage : service, compte, journal dédié supprimés ; sous-catégorie d'audit remise dans son état initial et le
  rétablissement vérifié (comparaison avant/après) ; remise à l'instantané après l'essai.
- Preuves : communes + 7045, 4720, 4732, 104, 4719 ; politique d'audit avant et après.
- Attendu en configuration C (HYPOTHÈSE) : identique (COR-R5, COR-R3, COR-R4, COR-R7) ; aucune règle ASR ne bloque la
  création du service ni du compte ; BAS-001 attendue si la sous-catégorie modifiée appartient au profil journalisation ;
  la GPO locale peut rétablir d'elle-même la sous-catégorie à son actualisation : heure du rétablissement relevée.

**S-14 — Lecture d'un fichier d'identifiants de navigateur (SIMULATION)**
- Technique : T1555.003 (SIMULATION). Nature : SIMULATION : compte de test sans aucun mot de passe enregistré ; ouverture
  en lecture puis fermeture, aucune copie, aucun déchiffrement.
- Préconditions : audit des objets actif, SACL posée par deR4Tizer ; collecte « audit des données » **Active** au départ,
  prouvée par une lecture auditée postérieure à la restauration (D-2, 5.4) — amorçage par une lecture légitime du
  navigateur, qui ne lève aucune alerte.
- Action : un programme de test non signé, lancé d'un dossier temporaire, ouvre le fichier en lecture puis ferme aussitôt.
- Attendu : VOL-001 Critique. Délai : 60 s. Nettoyage : programme de test supprimé ; remise à l'instantané. Preuves :
  communes + 4663.
- Attendu en configuration C (HYPOTHÈSE) : identique (VOL-001 Critique) : l'accès contrôlé aux dossiers ne bloque que
  l'écriture et ne protège pas ce fichier ; audit ASR de prévalence (1122) possible pour le programme de test, sans blocage.

**S-15 — Accès limité à LSASS (SIMULATION)**
- Technique : T1003.001 (SIMULATION). Nature : SIMULATION : handle en accès « informations limitées » seulement, aucune
  lecture de mémoire, aucun outil de vol d'identifiants. Préconditions : configuration Sysmon notée.
- Action : ouverture puis fermeture immédiate du handle.
- Attendu : aucune alerte de deR4Tizer (aucune règle) ; Sysmon 10 si configuré (B2) ; réaction de Defender relevée.
  Délai : 60 s. Nettoyage : aucun. Preuves : communes + Sysmon 10.
- Attendu en configuration C (HYPOTHÈSE) : identique (aucune alerte de deR4Tizer, B2) : la protection LSA et `asr.lsass`
  laissent passer l'accès « informations limitées » ; toute réaction (1121, ouverture refusée) est relevée comme P, sans
  changer la classe de détection.

**S-16 — Leurre anti-rançongiciel touché (SIMULATION, réponse automatique)**
- Technique : T1486 (SIMULATION). Nature : SIMULATION : un programme de test modifie un seul leurre ; aucun chiffrement,
  aucun autre fichier. Préconditions : leurres posés (collecte `Leurres` active) ; réponse automatique activée (défaut).
- Action : écriture d'un octet dans un leurre par un programme de test hors Program Files.
- Attendu : LEU-002 Critique, suspension automatique, inscription dans `reponses.json` ; LEU-001 au relevé suivant ;
  option longue : REP-001 Critique à 2 h, processus toujours suspendu ; « Reprendre » vérifié. Délai : 60 s ; 2 h 05 pour
  l'option. Nettoyage : reprise puis arrêt du programme de test ; remise à l'instantané. Preuves : communes + 4663, état
  du processus.
- Attendu en configuration C (HYPOTHÈSE) : **prévenu (P-Defender)** : leurres dans Documents, Images et Bureau, protégés
  par l'accès contrôlé aux dossiers en blocage ; écriture du programme de test non signé refusée (1123), leurre intact ;
  LEU-002 et la suspension probablement non déclenchées (aucune modification réussie). Détection et réponse automatique
  mesurées en A ; option longue en A seulement. LEU-002 malgré tout en C : « P + A », relevé.

**S-17 — Session administrative à distance sur un partage administratif**
- Technique : T1021.002. Nature : émulation (liste d'un répertoire seulement ; aucun service distant, aucune exécution à
  distance). Préconditions : compte de test administrateur dédié.
- Action : depuis Kali, connexion authentifiée au partage administratif, liste d'un répertoire, déconnexion.
- Attendu : COR-R9 Alerte ; 4672 dans le SIEM ; 5140 produit mais non lu (B2). Délai : 120 s. Nettoyage : remise à
  l'instantané. Preuves : communes + 4624, 4672, 5140.
- Attendu en configuration C (HYPOTHÈSE) : identique (COR-R9 Alerte, 4672) ; `asr.psexec-wmi` sans objet ; Kali en SMB 2 ou 3.

**S-18 — DNS-003 : port 53 de la boucle locale tenu par un autre programme au redémarrage du service (approuvé en v1.1)**
- Technique : sans correspondance ATT&CK exacte (interférence avec le résolveur local) ; fonction de phase 7. Nature :
  émulation.
- Statut : **approuvé en v1.1** (décision du mainteneur du 2026-11-14, 5.2). Exige un **arrêt du service deR4Tizer puis sa
  relance** ; exécutable seulement parce que le mainteneur l'a tranché (dérogation au principe « deR4Tizer intact »).
- **Note v1.4 :** S-18 s'appuie sur la **fonction de filtrage DNS** (cartes réglées sur le résolveur local), **présente
  dans `main`** (`dns_local.rs`, `filtrage.rs`, `filtrage_cartes.rs`, 1.5) : S-18 est testable. Seule prudence, non
  bloquante, confirmer que le binaire installé correspond à cette source avant de mesurer.
- Préconditions : configuration A suffit ; filtrage DNS activé (cartes réglées sur le résolveur local) ; état des
  collectes, du filtrage et des cartes relevé ; un programme d'écoute bénin de labo prêt (il ouvre seulement le port 53 en
  écoute locale, sans servir de vraie résolution).
- Action : (a) le service est arrêté de telle sorte que les cartes restent réglées sur la boucle locale (cas de risque du
  modèle de menace) ; (b) le programme bénin de labo prend le port 53 ; (c) le service est relancé et ne peut pas lier le
  port 53, une carte pointant encore sur le résolveur local.
- Attendu (**HYPOTHÈSE a priori, classe A attendue**) : DNS-003 Critique, avec le PID du programme qui tient le port 53
  (règle non adoucie par l'apprentissage) ; aucune autre alerte Alerte/Critique sans lien. À mesurer, jamais présenté
  comme un résultat. Délai maximal : 180 s après la relance.
- Nettoyage : programme d'écoute arrêté, port 53 libéré ; **service deR4Tizer relancé et son bon fonctionnement vérifié**
  (tube qui répond, collectes « Active », filtrage et cartes rendus à l'identique) ; **remise à l'instantané après l'essai**.
- Preuves : communes + fichiers d'état du filtrage avant et après, réglage des cartes avant et après, `journal.txt`
  (arrêt et relance, échec de liaison du port 53, PID relevé), état des collectes au début et à la fin.
- Attendu en configuration C (HYPOTHÈSE) : identique (DNS-003 Critique avec le PID) ; programme d'écoute récent : audit
  ASR de prévalence (1122) possible, sans blocage ; nettoyage inchangé (service relancé et vérifié, remise à « campagne C »).

**S-19 — Contrôle de la configuration C : conformité de la baseline et état de Defender (ajouté en v1.3)**
- Technique : aucune (contrôle de configuration ; préalable de chaque lot en configuration C). Nature : contrôle, lecture
  seule.
- Préconditions : « campagne C » préparé hors campagne depuis « campagne A » : relevé de référence de Defender
  (Get-MpPreference, Get-MpComputerStatus) et de `baseline.json` pris dans « campagne A » juste avant l'application ;
  baseline appliquée par le service en une seule commande `baseline appliquer` (journalisation, recommandé, renforcé ; deux
  commandes successives risqueraient une BAS-001 à tort, 5.3) ; redémarrage avant la prise de l'instantané.
- Action : à la préparation, puis au début de chaque lot en C : relevé de `baseline.json` et de l'état de Defender ;
  comparaison réglage par réglage avec le relevé de référence.
- Attendu (HYPOTHÈSE) :
  - Defender : **aucun réglage plus faible qu'avant** (protection temps réel, surveillance du comportement, analyse des
    scripts et des téléchargements, protection contre les falsifications, cloud, PUA, protection réseau, accès contrôlé aux
    dossiers) ; règles ASR jamais rétrogradées ; aucune exclusion avant comme après. Valeurs plus fortes attendues. « Plus
    faible » défini réglage par réglage dans une table écrite avant le premier relevé.
  - Baseline : profils journalisation et renforcé à 100 % ; profil recommandé **sous 100 %**, du seul fait de
    `defender.dossiers-audit` vue non conforme (défaut D-BAS-01, 5.3) ; tout autre écart rend le lot invalide (D).
  - Effets au-delà du registre : Bureau à distance refusé (port 3389 fermé) ; protection LSA effective après redémarrage ;
    pare-feu actif sur les trois profils ; `EnableControlledFolderAccess` effectif relevé.
  - deR4Tizer : aucune alerte Alerte/Critique due à l'application elle-même ; aucune BAS-001 tant que rien n'est modifié.
- Délai : relevé immédiat ; 25 min d'observation après l'application. Nettoyage : aucun (lecture seule).
- Garde-fou : un réglage de Defender plus faible qu'avant arrête la configuration C et remonte au mainteneur
  (`CLAUDE.md`, règle 2) ; aucun réglage de Defender n'est corrigé à la main pour poursuivre.
- Preuves : `baseline.json`, `baseline-sauvegarde.json`, Get-MpPreference et Get-MpComputerStatus avant et après, table
  de comparaison, état de Bureau à distance, de la protection LSA, du pare-feu et de l'accès contrôlé aux dossiers.

### 3.2 Tests négatifs

| Id | Activité légitime | Attendu | Attendu en configuration C (HYPOTHÈSE) |
|---|---|---|---|
| N-01 | sessions locales, administration PowerShell par fichier signé | aucune Alerte/Critique | identique ; aucune alerte due à la baseline |
| N-02 | tâche planifiée créée par un administrateur vers un programme signé de Program Files | PER-001 Info au plus | identique |
| N-03 | téléchargement autorisé depuis Kali par le navigateur | aucune RES-002 ; RES-003 Info admise | identique ; avertissement SmartScreen à l'ouverture du fichier, sans alerte de deR4Tizer |
| N-04 | une erreur de mot de passe puis réussite en Bureau à distance | aucune COR-R1/R2 ; COR-R9 reste attendue (tout le labo est « public » pour le service) | non exécutable (Bureau à distance refusé) : D en C, mesuré en A |
| N-05 | réglage DNS rendu au DHCP (après S-06) | témoin négatif : DNS-002 ne se déclenche pas au retour au DHCP (changement donné par le réseau : événement du mini-SIEM, sans alerte) | identique |

### 3.3 Écartés, non exécutés ou en attente

- T1567 : D (aucun service web réel autorisé ; un substitut du labo serait T1041).
- T1055 : non exécuté ; aucune injection, même bénigne, sans accord explicite ; aucun capteur consommé.
- T1562.001 contre Defender, les journaux Windows ou deR4Tizer : D (interdit).
- DNS-003 : exige l'arrêt puis la relance du service ; **approuvé en v1.1** (5.2), devenu S-18 ; filtrage présent dans
  `main` (5.5) : S-18 testable.
- Volet T1562.002 de S-13 : **approuvé en v1.1** (5.2), exécuté dans S-13.
- **S-06 (DNS-002 + filtrage DNS) : testable (v1.4).** Code présent dans `main` ; fiche réécrite au niveau comportement
  (3.1). L'erreur « code absent » d'une rédaction initiale venait d'un checkout périmé (5.5). N-05 est un témoin négatif
  normal.
- En configuration C seulement (v1.3) : S-01, S-02, S-05 (a) et N-04 non exécutables comme détection (Bureau à distance
  refusé), S-16 attendu prévenu ; mesurés en A. L'essai en C reste une mesure de prévention.
- Fiches Atomic qui téléchargent, désactivent une protection, lisent la mémoire de LSASS ou effacent un journal réel :
  écartées d'office.

---

## 4. Prérequis du labo à vérifier avant S-01

1. Réseau : VM cible et Kali seules sur `d4t-labo` ; « Default Switch » de la VM débranché ; lien d'administration sans
   route vers la VM ; aucune route vers Internet pendant la campagne.
2. Adresses : VM cible et Kali en plage de documentation RFC 5737 ; adresse secondaire de Kali réservée à S-07 (plage de
   documentation) ; profil réseau de la carte de la VM relevé, Bureau à distance et partage de fichiers autorisés sur ce
   profil.
3. Horloges : écart VM, Kali et hôte relevé au début et à la fin de chaque lot.
4. Instantanés de campagne « campagne A », « campagne B » et « campagne C » présents, préparés hors campagne, chacun avec
   deR4Tizer installé, l'apprentissage terminé, les comptes de test et les réglages du labo ; aucun nom ne commence par
   « propre » ; instantané « propre » présent pour le retour après la campagne seulement ; Defender actif, sans exclusion,
   état relevé dans chaque instantané.
5. deR4Tizer : version et empreinte du MSI ; service en marche ; aucune collecte « Inconnue » ; profil « journalisation »
   conforme ; état de l'apprentissage ; source des processus (Sysmon ou WMI) relevée. **Version de source alignée sur le
   binaire installé relevée** (pour S-06/S-18) : confirmer que le binaire installé correspond bien à la source de `main`
   (après les fusions de phase 7.3/7.4) qui expose DNS-002 et le filtrage, avant de mesurer ces règles.
6. Collecte indépendante : 4688, 4104, Planificateur, Defender, Sysmon (configuration notée) lisibles et exportables.
7. Comptes de test créés, seuil de verrouillage relevé ; aucun mot de passe dans une preuve.
8. Kali : outils et versions notés ; serveur HTTP et amont DNS du labo prêts (S-07, S-11, S-06) ;
   journal horodaté.
9. Collecte des preuves sur la VM (PowerShell Direct) essayée à blanc sur N-01, en configuration A et en configuration C.
10. « campagne C » : préparé depuis « campagne A » ; relevé de référence de Defender et de `baseline.json` pris avant
    l'application ; baseline appliquée par le service en une seule commande ; redémarrage ; S-19 réussi ; instantané pris
    ensuite.

---

## 5. Décisions de conception et points laissés au mainteneur

### 5.1 Décisions prises par l'agent de validation (v1.0 ; 2 et 3 révisées en v1.2 ; 2 révisée et 11 ajoutée en v1.3 ; 5 corrigée en v1.4)

1. **Apprentissage terminé dans l'instantané de campagne.** On mesure le régime normal d'un poste après ses 7 premiers
   jours. La fin de l'apprentissage est relevée dans chaque rapport ; une mesure en apprentissage pourra venir plus tard,
   notée à part.
2. **Trois configurations, jamais fusionnées** (révisée en v1.2 ; en v1.3, C ajoutée et devenue principale, 5.1.11).
   Configuration A « sans Sysmon » : collecte indépendante par les journaux natifs. Configuration B « avec Sysmon » :
   Sysmon et Atomic Red Team. Les deux préparées hors campagne, apprentissage terminé, comptes de test et réglages du
   labo ; aucune ne part de « propre ». Scénarios sans processus (COR-*, DNS, IPC-03, D4-1) : A suffit ; scénarios PRC et
   persistance : les deux.
3. **Remise à l'instantané de campagne avant chaque essai des scénarios à corrélation** (S-01 à S-04, S-13, S-17 ;
   révisée en v1.2). La déduplication d'une heure et la fenêtre d'échecs de 30 min sont en mémoire ; sans remise, les
   essais ne sont pas indépendants. La remise vise l'instantané de la configuration, jamais « propre ». La VM revient à
   « propre » seulement après la campagne.
4. **Résolveur DNS de labo sur Kali**, sur `d4t-labo` seulement, pour une zone `.test` et les noms du labo, sans relais
   vers Internet. Raison : exercer DNS-001 (S-07) hors Internet ; le filtrage de phase 7 (S-06) l'exige aussi (amont du résolveur
   local). Outil côté Kali, hors de la VM de test.
5. **Listes restreintes activées pour S-07, avec des listes synthétiques locales** (noms `.test`, adresse secondaire de
   Kali), posées par un administrateur, effacées par la remise à l'instantané. **Correction v1.4 :** l'adresse de menace
   est placée dans une **source de confiance haute** (par exemple une liste C2 de botnets ou un bloc DROP), **et non dans
   une source de réputation (par exemple un niveau 3)** : seule une source de confiance haute déclenche le blocage
   automatique de 7 jours (la v1.3 parlait à tort d'une « liste de niveau 3 »). Sans ces listes, DNS-001 et RES-001 ne
   peuvent pas se déclencher dans un labo sans Internet ; aucun contenu de tiers n'est utilisé. L'adresse principale de
   Kali n'est jamais listée (sinon le blocage automatique couperait le labo).
6. **T1070.001 en SIMULATION sur un journal dédié créé pour le test** : retenu (aucun journal existant de Windows n'est
   touché). **T1562.002** : modifie la journalisation de Windows ; d'abord laissé au mainteneur, puis **approuvé en v1.1**
   (5.2), exécuté dans S-13 avec rétablissement vérifié.
7. **Option longue de S-16 (REP-001 à 2 h)** : retenue, une observation par configuration, rapportée comme non consolidée.
8. **T1555.003 (S-14) ajouté**, en SIMULATION : compte de test sans aucun mot de passe enregistré, ouverture en lecture
   puis fermeture, aucune copie, aucun déchiffrement. S-15 (LSASS en accès « informations limitées ») reste dans la forme
   prévue par la consigne.
9. **Classement** : T1567 en D ; T1055 non exécuté (D) ; B1 et B2 restent des sous-divisions de B ; **classe E** réservée
   au gelé (IDS/DPI/NDR). S-06 n'est plus en E : le code de DNS-002 et du filtrage est présent dans `main` (5.5).
10. **Publication** : ce document, une fois transmis au mainteneur, est proposé sous `docs/validation/` par une PR de
    documentation seule, après la garde PII ; la fusion reste décidée par le mainteneur.
11. **Configuration C, principale de mesure (v1.3), sur décision du mainteneur du 2026-11-14** : les tests Kali se font
    avec la baseline de deR4Tizer appliquée à 100 % (décision citée telle quelle : « pour les tests kali, tu as bien pris
    en compte d'avoir la baseline à 100% ? C'est l'un des interêts du produit », puis « ok parfait »). La baseline est
    appliquée par le service lui-même ; elle ne fait que durcir Defender, ce que S-19 vérifie : la règle 2 de `CLAUDE.md`
    reste entière. Effet réversible, confiné à la VM de test. A reste la comparaison, B la collecte Sysmon.

### 5.2 Points remontés au mainteneur, tranchés le 2026-11-14

Ces deux volets sortaient du mandat de l'agent (journalisation de Windows ou service lui-même) et avaient été laissés au
mainteneur en v1.0. **Décision du mainteneur, 2026-11-14, citée mot pour mot : « J'autorise les deux ».** Les deux volets
passent de non approuvé à approuvé en v1.1. C'est une décision du mainteneur, pas une approbation de l'agent (qui reste
ni humaine ni indépendante et ne lève aucune règle). La v1.1 lui est transmise, pour information, avant toute exécution ;
il peut retirer un scénario ou reprendre l'approbation à tout moment.

1. **Volet T1562.002 de S-13** (désactivation temporaire d'une sous-catégorie d'audit, puis rétablissement) : touche la
   journalisation de Windows. **Approuvé en v1.1.** S-13 l'exécute ; nettoyage à rétablissement vérifié (sous-catégorie
   remise dans son état initial, comparaison avant/après) puis remise à l'instantané. Aucune autre sous-catégorie ni aucun
   autre réglage d'audit n'est touché.
2. **DNS-003** (devenu S-18) : exige d'arrêter le service deR4Tizer, de faire tenir le port 53 par un autre programme, et
   de relancer le service. **Approuvé en v1.1** ; seule dérogation au principe « deR4Tizer intact », tenant à cette
   décision écrite. Nettoyage à rétablissement vérifié (programme d'écoute arrêté, port 53 libéré, service relancé et
   vérifié) puis remise à l'instantané. Filtrage présent dans `main` (5.5) : S-18 est testable.

### 5.3 Défauts du produit constatés à la lecture (ajouté en v1.3)

**D-BAS-01 : deux règles de la baseline écrivent la même valeur de registre.** Constat de lecture de `baseline.rs` et
`gpo.rs` à `ede269f`, non mesuré en VM.
- `defender.dossiers-audit` (profil recommandé) et `defender.dossiers-blocage` (profil renforcé) posent toutes deux
  `EnableControlledFolderAccess` : 2 (audit) pour l'une, 1 (blocage) pour l'autre. Appliquées ensemble, le blocage, écrit
  en dernier, l'emporte (HYPOTHÈSE de lecture, vérifiée par S-19).
- `evaluer` compare règle par règle : `defender.dossiers-audit` est alors vue « non conforme » et le profil recommandé ne
  peut pas atteindre 100 %. **Une conformité de 100 % sur tous les profils est donc impossible.**
- Effets : une règle affichée « non conforme » alors que le réglage effectif est plus fort ; et, si les profils recommandé
  puis renforcé sont appliqués par deux commandes successives, une BAS-001 « réglage modifié hors de deR4Tizer » serait
  levée à tort (HYPOTHÈSE de lecture, non mesurée).
- Correctif proposé, minimal, soumis au circuit habituel : déclarer les deux règles exclusives, la plus forte remplaçant
  la plus faible. Tests de non-régression décrits. Effet sur la détection : aucun ; supprime un faux « non conforme » et un
  faux positif possible de BAS-001.
- Effet sur la campagne : S-19 attend le profil recommandé sous 100 % ; ce constat n'est pas un échec de S-19.

**Point à vérifier P-BAS-02** : `systeme.lsa` (protection LSA) est vue conforme dès que la valeur de registre est posée,
alors qu'elle n'agit qu'après un redémarrage. Défaut non établi : S-19 vérifie la protection effective après redémarrage.

### 5.4 Règles de décision D-1 et D-2 (ajoutées en v1.4, tranchées par l'agent de validation)

Deux règles de notation qui confirment et formalisent des propositions du premier passage. Elles ne lèvent aucune règle
du mandat ; elles encadrent le décompte et la validité des essais. Transmises au mainteneur, pour information.

**D-1 — RES-004 / RES-005 (« PC exposé à Internet ») sur une adresse du labo : artefact d'exposition de labo.**
- Cause établie à la lecture : la plage de documentation du labo est considérée **« publique »** par le service (ni
  privée, ni locale, ni réservée). Le trafic entrant depuis Kali (force brute, balayage) est lu comme une **exposition
  réelle** et lève RES-004/RES-005. Sur un poste réel avec une vraie adresse publique, ces alertes seraient de **vrais
  positifs d'exposition** ; les filtrer dégraderait une détection légitime.
- **Règle (dans tous les scénarios, y compris les tests négatifs) :** une alerte **RES-004/RES-005** dont l'adresse
  homologue **appartient à la plage de documentation du labo** est étiquetée **« artefact d'exposition de labo »** et
  **exclue du décompte des VP comme des FP**. Avant d'exclure, **vérifier l'adresse homologue** : toute RES-004/005 portant
  une adresse **hors** plage de labo est **investiguée** (jamais exclue d'office). Ces alertes sont **conservées dans les
  preuves brutes**.
- **Aucun correctif produit** : le comportement est correct sur un poste réel.

**D-2 — Critère de collecte « Indisponible » après restauration d'instantané.**
- Constat : une collecte à cycle long peut paraître « Indisponible » juste après une restauration (dernier succès daté de
  la prise de l'instantané), sans panne réelle de la télémétrie.
- **Règle :** une collecte **non exercée** par le scénario est **écartée du verdict** seulement si la cause prouvée est
  « aucune lecture depuis la restauration ». Toute collecte **dont dépend une règle du scénario** doit être **« Active » au
  départ**, prouvée par une **lecture réussie postérieure à la restauration** ; sinon l'essai est **invalide (classe D)**,
  **jamais compté 0**.
- **Application :** S-14, collecte « audit des données » Active (au moins une lecture auditée depuis la restauration, par
  un amorçage légitime) avant l'essai ; S-07, collectes « listes de menaces » et « listes de domaines » Active (listes
  synthétiques effectivement chargées) avant l'essai.
- **Reporté en phase 5 (question produit, non bloquante) :** sur un poste réel sortant d'une veille longue, une collecte
  événementielle ou périodique passe-t-elle « Indisponible » à tort ? À instrumenter en phase 5, sans impact sur la
  notation des campagnes.

### 5.5 Correction v1.4 — S-06 (DNS-002 et filtrage DNS) : erreur « code absent » d'une rédaction initiale

Une rédaction initiale de la v1.4 affirmait que le code de **DNS-002** et du **filtrage DNS** (résolveur local) était
« absent de la source », classait **S-06 en classe E / en attente du mainteneur** et remontait quatre questions au
mainteneur. **Cette prémisse était fausse.** Elle venait d'un **checkout de travail périmé** (branche `passages-en-vm`),
antérieur aux fusions de phase 7.3/7.4.

À la lecture du **worktree complet de `main` à jour**, le code est bien présent :
- **DNS-002** : `dns_surveillance.rs` (relevé des serveurs DNS des cartes toutes les 60 s ; un serveur statique changé
  sur une carte physique lève la règle `DNS_002`, niveau Alerte), règle déclarée dans `regles.rs`.
- **Filtrage DNS** : résolveur local sur `127.0.0.1:53` et `[::1]:53` (`dns_local.rs`), moteur de filtrage et état
  (`filtrage.rs`, `EtatFiltrage`, `filtrage-etat.json`, « derniers blocages »), activation sur les cartes
  (`filtrage_cartes.rs`, commande `filtrage` de l'administrateur, phase 7.4, réglage des cartes en SYSTEM accordé par le
  mainteneur), **DNS-003** via l'alerte « port DNS tenu » (`alerte_port_dns_tenu`, Critique, au démarrage du service).
- La **matrice des capacités** (`capability-matrix.md`) liste DNS-002, le moteur de filtrage, le résolveur local,
  l'état/DNS-003 et Quad9.

**Conséquences :** S-06 est **testable**, sa fiche est réécrite au niveau comportement (3.1) ; DNS-003 (S-18) est
testable (5.2) ; N-05 est un témoin négatif normal (3.2). **Il n'y a pas de question bloquante au mainteneur sur ce
point.** Seule prudence maintenue, non bloquante : avant de mesurer, confirmer que le **binaire installé** dans
l'instantané de test correspond bien à cette source de `main` (empreinte du MSI et version relevées, section 4, point 5).

## 6. Version 1.5 (2026-11-19) : scénarios de détection réseau S-20 à S-27, approuvés après exécution

Ajoutés à la liste approuvée le 2026-11-19 sur décision du mainteneur (« Scénario S20 à S27, il faut les ajouter à la
liste approuvée », `CLAUDE.md`, campagne Kali). **Approbation après coup** : ces scénarios ont été conçus dans le dossier
de conception « détection réseau » (hors dépôt) et exécutés du 2026-11-16 au 2026-11-17, avant leur inscription ici.
Niveaux et techniques d'après le code (`ndr.rs`, `ids.rs`). Nature : émulation bénigne et réversible depuis la VM Kali,
sur le segment de laboratoire (topologie accordée le 2026-11-19).

| Id | Comportement | Technique | Règle et niveau attendus | Rapport |
|---|---|---|---|---|
| S-20 | usurpation ARP de la passerelle (deux adresses sur une même adresse MAC) | T1557.002 | EXP-NDR-001 Critique | `campagne-kali-detection-reseau-lot2.md` |
| S-21 | serveur DHCP pirate (un second serveur sur le segment) | T1557.003 | EXP-NDR-001 Critique | lot 2 et lot 5 « détection réseau » (à remesurer après la PR #190) |
| S-22 | répondeur LLMNR qui répond au leurre actif | T1557.001 | EXP-NDR-001 Critique | `campagne-kali-detection-reseau-lot1.md` |
| S-23 | répondeur passif LLMNR (au moins 3 noms) | T1557.001 | EXP-NDR-001 Alerte | `campagne-kali-detection-reseau-lot2.md` |
| S-24 | trafic portant le motif de la règle IDS de test intégrée (sid 9000000) | aucune posée par le code | EXP-IDS-001, niveau de la règle | `campagne-kali-detection-reseau-lot1.md` |
| S-25 | répondeur NBNS réel qui répond au leurre actif (jambe NBNS du leurre) | T1557.001 | EXP-NDR-001 Critique | `campagne-kali-detection-reseau-lot2.md` |
| S-26 | répondeur passif mDNS (au moins 15 noms) | T1557.001 | EXP-NDR-001 Alerte | `campagne-kali-detection-reseau-lot3.md` |
| S-27 | redirection UPnP d'un port vers ce PC annoncée par la box émulée | T1133 | EXP-NDR-001 Alerte | `campagne-kali-detection-reseau-lot4.md` |

Pour chacun : préconditions et nettoyage décrits dans son rapport ; remise à l'instantané avant et après chaque essai ;
résultat attendu = l'alerte ci-dessus dans le délai du cycle du NDR ; mesures non consolidées tant qu'il n'y a pas 10
essais valides. Non couverts : responder passif NBNS (non exercé), IDS directionnel et de contenu, mode IPS.
