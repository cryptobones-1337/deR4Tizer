# Base de tests de deR4Tizer

Commandes réellement exécutées et résultats constatés. À mettre à jour à chaque lot.

## Tests unitaires du service

```
cd service-rs
cargo test --release
```

- 2026-10-24, arbre `7ad06963` (`main` `1cf04fe`), local, chaîne `stable-x86_64-pc-windows-msvc` :
  **86 réussis, 0 échoué**.
- 2026-11-19, job `windows` de la CI (run 44476563634, PR #205, commit `774e3cb`, service identique à `main`), chaîne
  MSVC : **469 réussis, 0 échoué** (tests de `tests.rs` et de `tests_detection.rs`).
- Contenu (`service-rs/src/tests.rs`) : fonctions pures qui lisent des données du réseau ou de fichiers externes
  (paquets, TLS, DNS, règles IDS, manifestes, UPnP), décisions de sécurité (droits, tri au démarrage,
  quarantaine, reprise, restauration, mise à jour, clé épinglée), avec un mini-fuzz (toutes les troncatures d'un
  message valide et des milliers d'entrées pseudo-aléatoires, jamais de panique : le service est compilé avec
  `panic = "abort"`).
- Le job `windows` de la CI exécute la même commande (chaîne MSVC) à chaque PR et sur `main`, et vérifie que le
  service ne dépend pas du runtime Visual C++ (`dumpbin /dependents`). GitHub Actions a été désactivé du
  2026-10-22 au 2026-11-17 ; depuis, ce job tourne à chaque PR (469 réussis le 2026-11-19, run 44480286774 (PR #205, `cd36ee4`, 2026-11-19)).

## Compilation

| Commande | Résultat constaté |
|---|---|
| `./compiler.ps1 -InterfaceSeulement` | 2026-10-22, local : code 0, `bin\deR4Tizer.exe` (404 992 octets). |
| `powershell -File tests\test-msi.ps1 [-Msi bin\deR4Tizer.msi [-Reference <MSI de main>]]` | 2026-11-11, local (U8a) : sources et paquet, tables d'exécution identiques au MSI de main ; les sources de main y échouent (5 cas). |
| `cargo build --release` (MSVC) puis `./construire-msi.ps1` | Job `windows` de chaque exécution de la CI : `deR4Tizer.msi`, `deR4TizerSvc.exe`, `deR4Tizer.exe` en artefacts. Depuis la PR #284 : `cargo test --release --locked` et `cargo build --release --locked`, chaîne figée par `service-rs/rust-toolchain.toml` (rustc 1.100.0) ; job `windows` réussi au run 45175958903 (`e2d2991`). |
| Copie locale de `service-rs`, `Cargo.toml` modifié (version 4.3.0 vers 4.3.1) sans `Cargo.lock` : `cargo build --release --locked` | 2026-11-23, local (chaîne MSVC 1.99.1, copie hors du dépôt, rien poussé) : échec, code 101 (« cannot update the lock file … because --locked was passed »), `Cargo.lock` inchangé. Sans `--locked`, `cargo metadata` réécrit `Cargo.lock` en silence (code 0, seule différence : 4.3.0 vers 4.3.1). Preuve du correctif d'A-3-3. |

## Analyse statique en CI : dépendances du service (lot 1, PR #284)

Job `dependances` de `.github/workflows/ci.yml`, outils installés par `cargo install --locked` à version figée
(cargo-audit 0.22.2, cargo-deny 0.20.2), chaîne rustc 1.100.0. Configuration de cargo deny : `service-rs/deny.toml`.

| Commande (dans `service-rs`) | Résultat constaté |
|---|---|
| `cargo audit --file Cargo.lock` | Run 45175958903 (`e2d2991`, 2026-11-23) : 1562 avis RustSec chargés, 78 paquets du `Cargo.lock` lus, aucune vulnérabilité ni avertissement, code 0. |
| `cargo deny --locked --config deny.toml check --show-stats advisories licenses sources` | Même run : `advisories ok: 0 errors, 0 warnings, 0 notes` ; `licenses FAILED: 1 errors, 2 warnings, 63 notes` ; `sources ok: 0 errors, 0 warnings, 0 notes`. Seule erreur : `der4tizer-svc = 4.3.0 is unlicensed` (le service lui-même, sans champ `license` dans `Cargo.toml`). |
| Même commande, après les décisions du mainteneur du 2026-11-23 (`license = "EUPL-1.2"` dans `Cargo.toml`, liste des licences validée, EUPL-1.2 ajoutée) | Run 45184585387 (`28eab0a`) : `advisories ok: 0 errors, 0 warnings, 0 notes` ; `licenses ok: 0 errors, 0 warnings, 64 notes` ; `sources ok: 0 errors, 0 warnings, 0 notes` ; job `dependances` réussi. cargo audit : 1562 avis, 78 paquets, aucune alerte. Job `windows` au même run : 565 tests réussis, 0 échoué (`--locked`). |

Ces contrôles ne voient que les avis publiés (RustSec), les licences déclarées et la provenance des paquets : aucun
défaut de logique, aucun code du service. Ce n'est pas une relecture indépendante.

## Intégration (CI, runner Windows jetable, service réel installé par le MSI)

Chaque script écrit un tableau (RÉUSSI, ÉCHOUÉ, NON EXÉCUTÉ avec la raison) dans le résumé du job ; un seul
ÉCHOUÉ fait échouer le job ; un NON EXÉCUTÉ n'est jamais compté comme réussi.

| Lot | Job | Script | Dernière exécution validée | Résultat |
|---|---|---|---|---|
| 3a | `integration-installation` | `tests/integration/installation.ps1` | run 39822711631 (`3194bb6`) | 42 scénarios, 0 échoué, 0 non exécuté |
| 3b | `integration-quarantaine` | `tests/integration/quarantaine.ps1` | run 39822711631 (`3194bb6`) | 21 scénarios, 0 échoué, 1 non exécuté |
| 3c | `integration-maj` | `tests/integration/maj.ps1` | run 44480286774 (PR #205, `cd36ee4`, 2026-11-19) | 20 scénarios, 0 échoué, 1 non exécuté |

Non exécuté en 3b : refus par `creer_sans_lien` d'une jonction posée entre le contrôle du propriétaire et la
création (course non reproductible de façon déterministe).

Au même run 44480286774 (PR #205, `cd36ee4`, 2026-11-19) : 3a 91 scénarios, 0 échoué, 4 non exécutés ; 3b 35, 0 échoué, 1 non exécuté.

## Intégration en Windows Sandbox (preuve locale pendant la désactivation de GitHub Actions, du 2026-10-22 au 2026-11-17)

Mêmes scripts, lancés par `tests/bac-a-sable/preparer.ps1` puis `lancer.ps1 -Scenario installation|quarantaine|maj`
(et `preparer.ps1 -Maj` pour 3c), dans une Windows Sandbox jetable. Signal, pas preuve : ni poste réel ni Defender
actif (désactivé dans la Sandbox) ; jamais compté comme « validé sur Windows (VM) ».

Le dossier de compilation du service est commun à toutes les copies du dépôt (worktrees). Cargo juge un fichier à jour
par sa date : sans précaution, une copie dont les sources sont plus anciennes que la dernière compilation d'une autre
copie livrait le binaire de l'autre copie. C'est arrivé le 2026-10-26, sur un passage de mesure seule : le binaire de
`main` a été testé sous la tête d'une PR, avec le nombre de tests unitaires de `main`. `cible-cargo.ps1`, chargé par
`compiler-rs.ps1` et `preparer.ps1`, donne à chaque copie son propre dossier de compilation
(`%USERPROFILE%\.der4tizer-build-msvc\<empreinte du chemin>`), ce qui couvre aussi deux compilations simultanées ; les
dossiers des copies retirées sont effacés. Les rapports gardent le nombre de tests
unitaires lancés, à comparer à celui de la tête testée.

2026-10-24, arbre `370e4d272d88515c1e6901882933bc8340995602`, identique à `main` après la fusion des PR #10 à #27
(l'historique a été réécrit le 2026-10-24 pour en retirer des données personnelles : l'arbre testé `370e4d27`
est identique, aux adresses IP des données de test près, à celui de `main` `7ff8309` ; anciens identifiants de
commit cités pour mémoire), Windows 11 Pro 10.0.26300.9711, MSI des scénarios 3a et 3b SHA-256
`D36263F9BC19170C25193A5642974E8FB33D969CF466CDAE96AF5AB4C30F38D5` :

| Lot | Réussis | Échoués | Non exécutés |
|---|---|---|---|
| 3a | 41 | 0 | 2 : aucun compte à la console (lecture accordée au compte de la console ; droits de la 4.1.0, qui ne les pose qu'avec un compte à la console) |
| 3b | 23 | 0 | 3 : aucune session interactive (leurres de la session, restauration avec session) ; course de `creer_sans_lien` |
| 3c | 19 | 0 | 1 : service muet après l'installation (simulation seulement) |

Tableaux complets en commentaire des PR #10 à #27.

2026-10-24, arbre `4bdcc38dd6e99aa52376d1d44b78ebad7c61db15`, celui de `main` `c60d9b3` après la fusion des PR #34,
#31, #32, #33, #35 (commit testé `bfaa412`, `git diff bfaa412 main` vide), Windows 11 Pro 10.0.26300.9711, MSI des
scénarios 3a et 3b SHA-256 `6F63CE69B91596A13BCECE69891BDDF5404EB3BE01CF2551CC1385857558E9D9`, 80 tests unitaires :

| Lot | Réussis | Échoués | Non exécutés |
|---|---|---|---|
| 3a | 41 | 0 | 2 (mêmes raisons) |
| 3b | 24 | 0 | 3 (mêmes raisons) |
| 3c | 19 | 0 | 1 (même raison) |

Nouveaux par rapport au passage précédent : leurre déjà présent dans un profil sans session audité (3b) ;
désinstallation sans `GARDER_DONNEES` qui retire bien les données (3a, 3b). Tableaux en commentaire des PR #31 à #35.

2026-10-24, arbre `67978e1f8a2d8fc42b55c2c8624761ff50826949`, celui de `main` `b72874f` après la fusion des PR #36,
#37, #40, #41, #42 (commit testé `51f8796`, `git diff 51f8796 main` vide), Windows 11 Pro 10.0.26300.9711, 83 tests
unitaires. MSI SHA-256 : 3a `D8EE3E666BBDD0A11B8FB1844CF07598231BE521B5EE5DFD97F67F55B0B74F92` ; 3b
`7322DF3A3E6F79E1F70EB23A49B2F14B2BD990FDA449053876C55DD7E41C8FB2` (même arbre, recompilé : relancé après un échec de
démarrage de Windows Sandbox) ; 3c, reconstruit après les paquets de test,
`C72D73FD548489979886893411BBC167C93692B775438A47151FAB532299F555`.

| Lot | Réussis | Échoués | Non exécutés |
|---|---|---|---|
| 3a | 41 | 0 | 2 (mêmes raisons) |
| 3b | 24 | 0 | 3 (mêmes raisons) |
| 3c | 19 | 0 | 1 (même raison) |

Tableaux en commentaire des PR #36, #37, #40, #41, #42.

2026-10-24, arbre `7ad0696305ea17de643b2c015aff497d7dadd10b`, celui de `main` `1cf04fe` après la fusion des PR #43,
#44, #45, #46 (commit testé `b86e8d2`, `git diff b86e8d2 main` vide), Windows 11 Pro 10.0.26300.9711, 86 tests
unitaires. MSI SHA-256 : 3a et 3b `E6EA86BA979D5DBB84E93F70BF837F9CDB22BA6C84A6B7130995E0977A4862C8` ; 3c, reconstruit
après les paquets de test, `F7D7CFA1122C417D9C9250B8C0F3EFBC27B076090F75155049E6DE06340F5704`.

| Lot | Réussis | Échoués | Non exécutés |
|---|---|---|---|
| 3a | 41 | 0 | 2 (mêmes raisons) |
| 3b | 24 | 0 | 3 (mêmes raisons) |
| 3c | 19 | 0 | 1 (même raison) |

Tableaux en commentaire des PR #43, #44, #45, #46.

## Analyse statique en CI : CodeQL (lot 3)

Code scanning de GitHub en « default setup », activé par le mainteneur le 2026-11-23 (réglage du dépôt, marche à
suivre à la section 6 de `CLAUDE.md`) : CodeQL 2.27.5, suite de requêtes « default », runner `ubuntu-latest`
(image ubuntu-26.04), build mode `none`, à chaque poussée et PR vers `main` et chaque semaine. Aucun fichier de
workflow dans le dépôt : l'exécution est le workflow dynamique « CodeQL » de GitHub.

| Langage | Analyse sur `main` (`edc2639`, run 45181833445, 2026-11-23) | Règles | Alertes | Extraction |
|---|---|---|---|---|
| Rust | 2229920801 | 27 | 5 | 49 fichiers sur 49, dont 4 extraits avec erreurs : `commun.rs` (« expected an item » aux lignes 1 et 2, fichier qui commence par un BOM), `main.rs` (macro `define_windows_service` non développée), `natif.rs` et `reponse.rs` (macros `windows::core::s` et `w` non développées) |
| C# | 2229883658 | 52 | 0 | 11 fichiers sur 11 ; aucun projet ni solution trouvé, références prises dans les assemblages .NET de CodeQL (203), « WPF usage detected: False » ; diagnostic « Low C# analysis quality » : 65 % des appels avec cible connue (seuil 85 %), 77 % des expressions de type connu (seuil 85 %) |
| Python | 2229881103 | 43 | 1 | 1 fichier sur 1 (`tests/integration/serveur-maj.py`) |
| Actions | 2229879240 | 17 | 0 | workflows de `.github/workflows` |

Tri des 6 alertes ouvertes sur `main` (détail, raison et scénario dans la PR du lot 3) : aucun défaut réel ;
6 faux positifs, à faire écarter par le mainteneur avec leur raison.

| N° | Règle (gravité) | Emplacement | Classement |
|---|---|---|---|
| 5 | `rust/hard-coded-cryptographic-value` (critique) | `service-rs/src/reponse.rs:280` | Faux positif : tampon `[0u8; 16]` entièrement recopié depuis SHA-256 du nom de la copie ; l'encodage de quarantaine n'est pas un chiffrement (clé publique, documenté) |
| 6 | `rust/hard-coded-cryptographic-value` (critique) | `service-rs/src/reponse.rs:319` | Faux positif : même tampon, rempli par les 16 octets lus dans l'en-tête de la copie |
| 2 | `rust/access-invalid-pointer` (haute) | `service-rs/src/ndr.rs:250` | Faux positif : pointeur rempli par `GetIpNetTable2`, retour d'erreur et pointeur nul écartés juste avant |
| 3, 4 | `rust/access-invalid-pointer` (haute) | `service-rs/src/natif.rs:918`, `:922` | Faux positifs : pointeur rendu par `GetAce`, erreur et pointeur nul écartés juste avant, DACL rendue par Windows |
| 1 | `py/insecure-protocol` (haute) | `tests/integration/serveur-maj.py:40` | Faux positif, code de test : serveur local du lot 3c sur 127.0.0.1, runner jetable ; `PROTOCOL_TLS_SERVER` refuse déjà TLS 1.0 et 1.1 depuis Python 3.10 |

Alerte n° 7 (`rust/cleartext-logging`, haute) : seulement sur les PR #269 et #278 (`service-rs/src/tests.rs`),
pas sur `main` ; faux positif (message d'un `assert!` de test qui affiche le texte déjà passé par
`masquer_secrets`). Aucune alerte écartée à ce jour.

CodeQL ne voit ni les défauts de logique, ni les décisions de confiance propres au produit ; l'analyse C# sans
compilation reste partielle (seuils de qualité non atteints). Ce n'est pas une relecture indépendante.

## Non couvert

- Exécution avec Microsoft Defender actif (lot 3d) sur un poste réel : le lot ne tourne que dans la VM de test, et reste exigé sur la version distribuée.
- Scénarios demandant une session interactive (aucune en Windows Sandbox ; celle du runner hébergé est un
  administrateur) : leurres posés dans le profil de la session, restauration avec la session d'un utilisateur
  standard, lecture des données par le compte de la console.
- Interface : tests automatisés de ses décisions et de son rendu hors écran (`tests/rendu-pilote.ps1`,
  `tests/test-confirmations.ps1`, `tests/test-reponses-interface.ps1`, `tests/test-incidents-interface.ps1`), et captures
  réelles en VM (`tests/vm/captures.ps1`) ; rendu à 125 % et 150 % non vérifié sur un écran réel ; les fenêtres de
  confirmation ne sont exercées par aucun scénario.
