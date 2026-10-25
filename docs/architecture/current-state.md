# Architecture actuelle de deR4Tizer

État au 2026-10-22 (`main`, version 4.3). Description du code tel qu'il est, pas d'une cible.

## Composants

| Composant | Langage | Compte | Rôle |
|---|---|---|---|
| `deR4TizerSvc.exe` (`service-rs/`) | Rust (chaîne MSVC pour les binaires livrés) | SYSTEM | Surveillance, détection, réponse, export, mise à jour, protection du dossier de données. |
| `deR4Tizer.exe` (`src/`) | C#, .NET Framework 4.8 | Utilisateur, sans droits d'administrateur | Affichage de l'état ; actions envoyées au service par le canal, avec l'UAC (`runas`). |
| `deR4Tizer.msi` (`installeur/deR4Tizer.wxs`, `construire-msi.ps1`) | WiX 3.14 | Administrateur | Installation du service (démarrage automatique, redémarrage sur échec), du dossier de données avec ses droits, mise à niveau (`MajorUpgrade`, `AllowDowngrades`), désinstallation (`--nettoyer`, `--supprimer-donnees` sauf `GARDER_DONNEES=1`). |

Aucun pilote noyau. API Windows utilisées : journaux d'événements, ETW, WMI, pare-feu (COM), IP Helper,
sockets brutes (`SIO_RCVALL`), `WinVerifyTrust`, Windows Installer, sécurité NTFS.

## Communication

- **Canal** `\\.\pipe\deR4Tizer` : une ligne JSON par commande (`commun::Commande`), une ligne JSON en réponse.
  SYSTEM et administrateurs seulement ; l'interface vérifie que le serveur du tube est le processus du service
  (`GetNamedPipeServerProcessId`).
- **Fichiers d'état** : le service écrit des fichiers JSON dans le dossier de données, l'interface les lit.
- **API HTTP d'export** (facultative) : lecture seule, jeton, 127.0.0.1 ou réseau local filtré.
- **Sorties** : syslog (UDP ou TCP, en clair), ntfy, Teams, SMTP (par `curl.exe`), téléchargement des listes de
  menaces, des données GeoIP et du manifeste de mise à jour (HTTPS).

## Fils du service

`surveillance` (cœur, `moniteur.rs`, relève toutes les 3 s), `commandes` (canal), `protection` (droits du dossier,
toutes les heures), `listes de menaces` (12 h), `mise à jour` (quotidienne, 10 min après le démarrage),
`notifications`, `syslog`, `api`, `siem`, `ndr`, `geoip`, `ja3`, `audit données sensibles`, `traces de processus`,
`contrôles`, `persistance` (démarrages automatiques, toutes les minutes, hors du verrou du moniteur ; ses alertes sont reprises par le cycle, ou à l'arrêt après la fin du relevé en cours, attendue 8 s au plus), plus un fil de capture par interface réseau (`capture.rs`). À l'arrêt du service, les alertes encore en file (persistance, alertes des autres fils, détections de processus) sont enregistrées dans `alertes.json` avant la sortie ; une alerte produite par un fil après cette reprise peut encore être perdue.

Mesure du cycle (phase 1, `mesure.rs`) : durée de chaque étape du cycle de 3 s, attente et tenue du verrou du
moniteur par la surveillance, durée de chaque commande (verrou tenu), étapes des contrôles de 10 minutes et nombre de
PowerShell lancés par contexte. Écrite dans `mesures.json` toutes les 200 cycles (environ 10 minutes) : cumul depuis le
démarrage et dernière fenêtre, avec la répartition par classes de durée. Condition préalable à tout découpage de
`Moniteur` (CLAUDE.md, phase 1) ; aucune décision du service n'en dépend.

## Dossier de données `C:\ProgramData\deR4Tizer`

Propriétaire Administrateurs, héritage coupé ; SYSTEM et Administrateurs en contrôle total ; comptes autorisés en
lecture. Contenu principal :

| Élément | Rôle |
|---|---|
| `config.json` | Réglages (API, mise à jour, blocage automatique, IPS…). |
| `lecteurs.json` | Comptes autorisés en lecture. |
| `etat.json`, `alertes.json`, `incidents.json`, `journal.txt` | État publié, alertes, incidents, journal du service. |
| `siem\` | Événements normalisés, un fichier NDJSON par jour (30 jours, 1 Go au plus). |
| `trafic.json`, `dpi.json`, `ids.json`, `reseau.json`, `exposition.json`, `dns.json` | Résultats de l'analyse réseau. |
| `menaces\`, `menaces.json`, `regles\`, `geoip\` | Listes de menaces, règles IDS, données GeoIP. |
| `blocages.json`, `panique-active` | Blocages en cours, mode panique. |
| `quarantaine\`, `quarantaine.json`, `restaurations\` | Copies encodées, manifeste, dossiers de repli. |
| `ecartes\` | Éléments d'un autre propriétaire mis de côté au démarrage (jamais lus). |
| `maj\`, `maj.json` | Manifeste téléchargé, journaux d'installation, `echec.txt`, état de la mise à jour. |
| `secrets\`, `api-jeton.txt`, `notifications.json` | Secrets de remontée et jeton de l'API (droits propres, administrateurs). |
| `baseline.json`, `baseline-sauvegarde.json`, `sauvegardes\` | Baseline appliquée et valeurs précédentes. |
| `leurres.json`, `leurres-noms.json`, `demarrage.json`, `executables.json`, `extensions*.json`, `parefeu.json` | État des surveillances. |

Dossier de travail de la mise à jour : `%ProgramFiles%\deR4Tizer\maj`, réservé à SYSTEM.

## Compilation et CI

- Tests : `cargo test --release` (chaîne GNU en local, MSVC en CI).
- Binaires livrés : chaîne MSVC (`compiler-rs.ps1` en local, job `windows` en CI) ; interface :
  `compiler.ps1 -InterfaceSeulement` ; paquet : `construire-msi.ps1`.
- `.github/workflows/ci.yml` : `windows` (tests, compilation, MSI, artefacts), `integration-installation` (3a),
  `integration-quarantaine` (3b), tous trois obligatoires sur `main` ; `integration-maj` (3c) dans la PR #10.
- `.github/workflows/publication.yml` : sur un tag `v*`, compilation sans secret, signature dans l'environnement
  « publication », manifeste, version GitHub.
