# Base de tests de deR4Tizer

Commandes réellement exécutées et résultats constatés. À mettre à jour à chaque lot.

## Tests unitaires du service

```
cd service-rs
cargo test --release
```

- 2026-10-24, arbre `7ad06963` (`main` `1cf04fe`), local, chaîne `stable-x86_64-pc-windows-msvc` :
  **86 réussis, 0 échoué**.
- Contenu (`service-rs/src/tests.rs`) : fonctions pures qui lisent des données du réseau ou de fichiers externes
  (paquets, TLS, DNS, règles IDS, manifestes, UPnP), décisions de sécurité (droits, tri au démarrage,
  quarantaine, reprise, restauration, mise à jour, clé épinglée), avec un mini-fuzz (toutes les troncatures d'un
  message valide et des milliers d'entrées pseudo-aléatoires, jamais de panique : le service est compilé avec
  `panic = "abort"`).
- Le job `windows` de la CI exécute la même commande (chaîne MSVC) à chaque PR et sur `main`, et vérifie que le
  service ne dépend pas du runtime Visual C++ (`dumpbin /dependents`). GitHub Actions est désactivé sur le dépôt
  depuis le 2026-10-22 : ce job n'a pas tourné sur l'arbre actuel.

## Compilation

| Commande | Résultat constaté |
|---|---|
| `./compiler.ps1 -InterfaceSeulement` | 2026-10-22, local : code 0, `bin\deR4Tizer.exe` (404 992 octets). |
| `cargo build --release` (MSVC) puis `./construire-msi.ps1` | Job `windows` de chaque exécution de la CI : `deR4Tizer.msi`, `deR4TizerSvc.exe`, `deR4Tizer.exe` en artefacts. |

## Intégration (CI, runner Windows jetable, service réel installé par le MSI)

Chaque script écrit un tableau (RÉUSSI, ÉCHOUÉ, NON EXÉCUTÉ avec la raison) dans le résumé du job ; un seul
ÉCHOUÉ fait échouer le job ; un NON EXÉCUTÉ n'est jamais compté comme réussi.

| Lot | Job | Script | Dernière exécution validée | Résultat |
|---|---|---|---|---|
| 3a | `integration-installation` | `tests/integration/installation.ps1` | run 39822711631 (`3194bb6`) | 42 scénarios, 0 échoué, 0 non exécuté |
| 3b | `integration-quarantaine` | `tests/integration/quarantaine.ps1` | run 39822711631 (`3194bb6`) | 21 scénarios, 0 échoué, 1 non exécuté |
| 3c | `integration-maj` | `tests/integration/maj.ps1` | jamais exécuté en CI | — |

Non exécuté en 3b : refus par `creer_sans_lien` d'une jonction posée entre le contrôle du propriétaire et la
création (course non reproductible de façon déterministe).

## Intégration en Windows Sandbox (preuve locale pendant la désactivation de GitHub Actions)

Mêmes scripts, lancés par `tests/bac-a-sable/preparer.ps1` puis `lancer.ps1 -Scenario installation|quarantaine|maj`
(et `preparer.ps1 -Maj` pour 3c), dans une Windows Sandbox jetable. Signal, pas preuve : ni poste réel ni Defender
actif (désactivé dans la Sandbox) ; jamais compté comme « validé sur Windows (VM) ».

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

## Non couvert

- Exécution avec Microsoft Defender actif (lot 3d) : VM ou runner auto-hébergé nécessaire.
- Scénarios demandant une session interactive (aucune en Windows Sandbox ; celle du runner hébergé est un
  administrateur) : leurres posés dans le profil de la session, restauration avec la session d'un utilisateur
  standard, lecture des données par le compte de la console.
- Interface : aucun test automatisé ; rendu à 125 % et 150 % non vérifié sur un écran réel.
