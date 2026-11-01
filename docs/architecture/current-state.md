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

Registre des règles (phase 3, `regles.rs`) : un identifiant stable par détection existante, compilé dans le binaire (aucun fichier de règles) ; chaque producteur d'alertes pose le sien dans `Alerte.Regle`, repris par le SIEM (`Evenement.Regle`, avec `Modele`). Liste et fiches : `docs/detection/regles.md`.

État des collectes (phase 3, `collectes.rs`) : chaque source de télémétrie note ses lectures réussies ou en échec dans un tableau fixe d'atomiques (un succès répété ne prend aucun verrou) ; une source active muette plus de trois intervalles devient indisponible, une source jamais notée reste « Inconnue ». `etat.json` publie `Collectes` (`Id`, `Etat`, `Depuis`, `DernierSucces`, `Raison` sans nom de compte, 200 caractères au plus), `ReglesSansCollecte`, `ReglesDegradees` (règle portée seulement par une source partielle, par exemple WMI sans Sysmon) et, depuis la PR 3.3d, `CausesSansCollecte` (pour chaque règle sans collecte, les sources dont l'une au moins manque). L'interface (PR 3.4, classe `Couverture` de `src/Commun.cs`) les lit sans rien écrire. Depuis la phase 4 (PR 4.4a, `sante.rs`), le fil « sante » écrit chaque changement d'état dans le SIEM (`Source` « sante ») et lève les constats SAN-001 (collecte critique indisponible plus de 30 min), SAN-002 (rétablie), SAN-003 (Defender aveugle) et SAN-012 (alertes non suivies), hors du verrou du moniteur. La remontée (PR 4.4b, `notifications.rs`) retente les alertes critiques et les constats non remis (file en mémoire, 100, 24 h), signale une panne de plus d'une heure (SAN-004, local) et envoie un battement quotidien de compteurs. Le fil « sante » repère aussi l'interface dans chaque session active (PR 4.5a, chemin installé exact) et signale son absence (SAN-010) ou ses arrêts répétés (SAN-011), sans rien relancer. La relance passe par une tâche planifiée posée par le MSI (`relance.rs`, PR 4.5b), lancée par Windows sous l'identité de chaque utilisateur connecté. Toutes les sources sont notées depuis la PR 3.3b.

Suivi des incidents (phase 4, `incidents.rs`) : décisions pures (entité, rattachement d'une alerte, transitions, plafond de 500 incidents) ; le moniteur tient le suivi sous son verrou et l'écrit dans `suivi-incidents.json` avec `alertes.json` ; la commande `incident` (administrateurs) change l'état, avec l'auteur lu sur le jeton du client du tube (`natif::identite_client_tube`, passé par `canal.rs`). Chronologie de chaque incident calculée par le fil « chronologies », hors du verrou du moniteur, et écrite dans `chronologies\<id>.json` (PR 4.3). Ordre total des alertes et des événements par `HeureUtc` et `Seq` (PR 4.1) ; actions de réponse écrites dans le SIEM (`Source` « reponse »). Format : `docs/detection/modele-evenement.md`.

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
| `reponses.json` | Historique de la garde contre les boucles : actions automatiques récentes, décisions humaines (`politique.rs`). |
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
