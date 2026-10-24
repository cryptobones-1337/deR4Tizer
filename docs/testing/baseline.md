# Base de tests de deR4Tizer

Commandes réellement exécutées et résultats constatés. À mettre à jour à chaque lot.

## Tests unitaires du service

```
cd service-rs
cargo test --release
```

- 2026-10-24, arbre `370e4d27` (celui de `main` après la fusion des PR #10 à #27, avant la réécriture de l'historique), local, chaîne `stable-x86_64-pc-windows-msvc` :
  **79 réussis, 0 échoué**.
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

## Non couvert

- Exécution avec Microsoft Defender actif (lot 3d) : VM ou runner auto-hébergé nécessaire.
- Scénarios demandant une session interactive (aucune en Windows Sandbox ; celle du runner hébergé est un
  administrateur) : leurres posés dans le profil de la session, restauration avec la session d'un utilisateur
  standard, lecture des données par le compte de la console.
- Interface : aucun test automatisé ; rendu à 125 % et 150 % non vérifié sur un écran réel.
