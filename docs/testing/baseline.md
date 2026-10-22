# Base de tests de deR4Tizer

Commandes réellement exécutées et résultats constatés. À mettre à jour à chaque lot.

## Tests unitaires du service

```
cd service-rs
cargo test --release
```

- 2026-10-22, `main` (`1007795`), local, `rustc 1.99.1`, chaîne `stable-x86_64-pc-windows-gnu` :
  **66 réussis, 0 échoué**.
- Contenu (`service-rs/src/tests.rs`) : fonctions pures qui lisent des données du réseau ou de fichiers externes
  (paquets, TLS, DNS, règles IDS, manifestes, UPnP), décisions de sécurité (droits, tri au démarrage,
  quarantaine, reprise, restauration, mise à jour, clé épinglée), avec un mini-fuzz (toutes les troncatures d'un
  message valide et des milliers d'entrées pseudo-aléatoires, jamais de panique : le service est compilé avec
  `panic = "abort"`).
- Le job `windows` de la CI exécute la même commande (chaîne MSVC) à chaque PR et sur `main`.

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
| 3c | `integration-maj` | `tests/integration/maj.ps1` | PR #10, non fusionnée | à reporter |

Non exécuté en 3b : refus par `creer_sans_lien` d'une jonction posée entre le contrôle du propriétaire et la
création (course non reproductible de façon déterministe).

## Non couvert

- Exécution avec Microsoft Defender actif (lot 3d) : VM ou runner auto-hébergé nécessaire.
- Scénarios demandant la session d'un utilisateur standard (la session du runner hébergé est celle d'un
  administrateur) : restauration avec session, lecture des données par le compte de la console.
- Interface : aucun test automatisé ; rendu à 125 % et 150 % non vérifié sur un écran réel.
