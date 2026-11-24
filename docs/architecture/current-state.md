# Current architecture of deR4Tizer

State as of 2026-10-22 (`main`, version 4.3), extended PR by PR up to 2026-11-19. A description of the code as it
is, not of a target.

## Components

| Component | Language | Account | Role |
|---|---|---|---|
| `deR4TizerSvc.exe` (`service-rs/`) | Rust (MSVC toolchain for the shipped binaries) | SYSTEM | Monitoring, detection, response, export, update, protection of the data folder. |
| `deR4Tizer.exe` (`src/`) | C#, .NET Framework 4.8 (WPF for the default interface, `src/Fluent.cs`; WinForms for the former interface, `--classique`, and for the hidden window that carries the notification area) | User, without administrator rights | Display of the state; actions sent to the service over the channel, with UAC (`runas`). |
| `deR4Tizer.msi` (`installeur/deR4Tizer.wxs`, `construire-msi.ps1`) | WiX 3.14 | Administrator | Installation of the service (automatic start, restart on failure), of the data folder with its rights, upgrade (`MajorUpgrade`, `AllowDowngrades`), uninstallation (`--nettoyer`, `--supprimer-donnees` unless `GARDER_DONNEES=1`: content deleted, root kept and protected, permanent component; a non-empty quarantine is kept, restricted to SYSTEM and administrators, audit of 2026-11-23, A-4-3; `--nettoyer` also removes the read audit set in the profiles, our own entries only, and the old reports in `%SystemRoot%\Temp` written by SYSTEM, A-6-4). Refuses to install, upgrade or repair when the data folder is a link (read-only JScript action `installeur/lire-dossier-donnees.js`, launch condition failing closed; audit of 2026-11-23, C-1). |

No kernel driver. Windows APIs used: event logs, ETW, WMI, firewall (COM), IP Helper,
raw sockets (`SIO_RCVALL`), `WinVerifyTrust`, Windows Installer, NTFS security.

## Communication

- **Channel** `\\.\pipe\deR4Tizer`: one JSON line per command (`commun::Commande`), one JSON line in reply.
  SYSTEM and administrators only; the interface checks that the pipe server is the service process
  (`GetNamedPipeServerProcessId`).
- **State files**: the service writes JSON files in the data folder, the interface reads them.
- **HTTP export API** (optional): read-only, token, 127.0.0.1 or filtered local network.
- **Outputs**: syslog (UDP or TCP, in clear text), ntfy, Teams, SMTP (through `curl.exe`), download of the threat
  lists, the GeoIP data and the update manifest (HTTPS).

## Service threads

`surveillance` (core, `moniteur.rs`, a reading every 3 s), `commandes` (channel), `protection` (folder rights,
every hour), `listes de menaces` (12 h; 24 h for the two Spamhaus DROP lists), `mise à jour` (daily, 10 min after start),
`notifications`, `syslog`, `api`, `siem`, `ndr`, `geoip`, `ja3`, `audit données sensibles`, `traces de processus`,
`contrôles`, `persistance` (automatic start entries, every minute, outside the monitor lock; its alerts are picked up by the cycle, or at stop after the end of the reading in progress, waited for 8 s at most), `dns` (reading of the adapters' DNS servers, DNS-002, every 60 s), `sante` (health of the interface and of the collections),
`chronologies` (timeline of each incident), `filtrage` (domain name filtering, with `filtrage rechargement`,
`filtrage sonde` and `résolveur local fin`), `garde-canal`, plus one capture thread per network interface (`capture.rs`). When the service stops, the alerts still queued (persistence, alerts from the other threads, process detections) are saved in `alertes.json` before exit; an alert produced by a thread after this pickup can still be lost.

Rule registry (phase 3, `regles.rs`): one stable identifier per existing detection, compiled into the binary (no rule file); each alert producer sets its own in `Alerte.Regle`, carried over by the SIEM (`Evenement.Regle`, with `Modele`). List and rule sheets: `docs/detection/regles.md`.

Collection state (phase 3, `collectes.rs`): each telemetry source records its successful or failed readings in a fixed array of atomics (a repeated success takes no lock); an active source silent for more than three intervals becomes unavailable, a source never recorded stays "Inconnue". `etat.json` publishes `Collectes` (`Id`, `Etat`, `Depuis`, `DernierSucces`, `Raison` without account name, 200 characters at most), `ReglesSansCollecte`, `ReglesDegradees` (a rule carried only by a partial source, for example WMI without Sysmon) and, since PR 3.3d, `CausesSansCollecte` (for each rule without collection, the sources of which at least one is missing). The interface (PR 3.4, class `Couverture` in `src/Commun.cs`) reads them without writing anything. Since phase 4 (PR 4.4a, `sante.rs`), the "sante" thread writes each state change to the SIEM (`Source` "sante") and raises the findings SAN-001 (critical collection unavailable for more than 30 min), SAN-002 (restored), SAN-003 (Defender blind), SAN-012 (alerts not followed up) and, since the audit of 2026-11-23, SAN-013 (mini-SIEM history incomplete), outside the monitor lock. Escalation (PR 4.4b, `notifications.rs`) retries the critical alerts and the undelivered findings (in-memory queue, 100, 24 h), reports an outage of more than one hour (SAN-004, local) and sends a daily heartbeat of counters. The "sante" thread also locates the interface in each active session (PR 4.5a, exact installed path) and reports its absence (SAN-010) or its repeated stops (SAN-011), without restarting anything. The restart goes through a scheduled task set by the MSI (`relance.rs`, PR 4.5b), launched by Windows under the identity of each signed-in user. All sources are recorded since PR 3.3b.

Incident tracking (phase 4, `incidents.rs`): pure decisions (entity, attachment of an alert, transitions, cap of 500 incidents); the monitor keeps the tracking under its lock and writes it to `suivi-incidents.json` together with `alertes.json`; the `incident` command (administrators) changes the state, with the author read from the token of the pipe client (`natif::identite_client_tube`, passed through `canal.rs`). Timeline of each incident computed by the "chronologies" thread, outside the monitor lock, and written to `chronologies\<id>.json` (PR 4.3). Total order of alerts and events by `HeureUtc` and `Seq` (PR 4.1); response actions written to the SIEM (`Source` "reponse"). Format: `docs/detection/modele-evenement.md`.

Cycle measurement (phase 1, `mesure.rs`): duration of each step of the 3 s cycle, wait for and hold of the
monitor lock by the monitoring, duration of each command (lock held), steps of the 10-minute checks and number of
PowerShell processes started per context, named counters (`chaines.alertes_plafonnees`: CHA-001 alerts held back by the
cap of three per chain and per hour, T-1; `chaines.alertes_hors_plafond`: alerts raised beyond it because
they brought a new technique or a strong signal). Written to `mesures.json` every 200 cycles (about 10 minutes): totals since
start and last window, with the breakdown by duration class. Precondition for any split of
`Moniteur` (CLAUDE.md, phase 1); no service decision depends on it.

## Data folder `C:\ProgramData\deR4Tizer`

Owner Administrators, inheritance cut; SYSTEM and Administrators with full control; authorized accounts with
read access. Main content:

| Item | Role |
|---|---|
| `config.json` | Settings (API, update, automatic blocking, IPS…). |
| `reponses.json` | Register of the actions in progress and of their deadlines, reminders included; history of the guard against loops: recent automatic actions, human decisions (`politique.rs`). |
| `suivi-incidents.json`, `chronologies\` | Incident life cycle (open, taken in charge, closed) and timeline of each one (phase 4). |
| `mesures.json` | Measurements of the monitoring cycle (`mesure.rs`). |
| `filtrage-etat.json`, `filtrage-origine.json` | Published state of domain name filtering; original DNS settings of the adapters, to give them back (phase 7). |
| `lecteurs.json` | Accounts authorized to read. |
| `etat.json`, `alertes.json`, `incidents.json`, `journal.txt` | Published state, alerts, incidents, service log (2 MB, then `journal.1.txt` to `journal.5.txt`, audit of 2026-11-23, A-8-3). |
| `siem\` | Normalized events, one NDJSON file per day (30 days, 1 GB at most, 1 GB / 30 per day; the current day's file is never deleted, audit of 2026-11-23, A-6-3). Secrets in command lines masked (A-6-1). |
| `trafic.json`, `dpi.json`, `ids.json`, `reseau.json`, `exposition.json`, `dns.json` | Results of the network analysis. |
| `menaces\`, `menaces.json`, `regles\`, `geoip\` | Threat lists, IDS rules, GeoIP data. |
| `blocages.json`, `panique-active` | Current blocks, panic mode. |
| `quarantaine\`, `quarantaine.json`, `restaurations\` | Encoded copies, manifest, fallback folders. |
| `ecartes\` | Items owned by another account set aside at start (never read). |
| `maj\`, `maj.json` | Downloaded manifest, installation logs, `echec.txt`, update state. |
| `secrets\`, `api-jeton.txt`, `notifications.json` | Escalation secrets and API token (own rights, administrators). |
| `baseline.json`, `baseline-sauvegarde.json`, `sauvegardes\` | Applied baseline and previous values. |
| `leurres.json`, `leurres-noms.json`, `demarrage.json`, `executables.json`, `extensions*.json`, `parefeu.json` | State of the monitors. |

Working folder of the update: `%ProgramFiles%\deR4Tizer\maj`, restricted to SYSTEM.

## Build and CI

- Tests: `cargo test --release` (MSVC toolchain, locally as in CI; never a local GNU build).
- Shipped binaries: MSVC toolchain (`compiler-rs.ps1` locally, `windows` job in CI); interface:
  `compiler.ps1 -InterfaceSeulement`; package: `construire-msi.ps1`.
- `.github/workflows/ci.yml`: `windows` (tests, build, MSI, artifacts), `integration-installation` (3a),
  `integration-quarantaine` (3b), and `integration-maj` (3c), which run on every PR; none of them is a required check on `main` today (protection not restored, a maintainer action).
- `.github/workflows/publication.yml`: on a `v*` tag, build without secrets, signing in the
  "publication" environment, manifest, GitHub release.
