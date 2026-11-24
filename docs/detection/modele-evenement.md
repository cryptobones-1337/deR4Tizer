# Event model (phase 3)

This document describes the format of the service's alerts (`Alerte`, `service-rs/src/commun.rs`) as phase 3
versions it. Since PR 3.1, the fields `Modele`, `Regle` and `Collecte` exist (and `Signature` since PR 3.1b), every new alert carries `Modele` 1, and `alertes.json`
is read element by element. Since PR 3.2, each alert carries the identifier of its rule in `Regle` (registry
`regles.rs`). Since PR 3.3c, `Collecte` carries a **presumption** of the collection the alert comes from
(`collectes::collecte_de`: the first source read from the first telemetry group of its rule, otherwise the first
listed), not the source actually read by the producer. Examples of mismatch: DNS-001 coming from Sysmon is recorded as
`JournalDns` if both are read; COR-R4 and COR-R5 coming from the System log are recorded as `JournalSecurite`; LEU-002,
drawn from 4663 events, is recorded as `Leurres`. It stays empty, and is not written, for a rule that follows no source
(INT-*, COR-R6…). It is not part of the signature of exceptions.

## Principle

- **Fields are only added**: no existing field changes name or type.
- **Version carried by each alert**, not by the file: `alertes.json` stays an array of alerts. An envelope
  (`{ "Version": 1, "Alertes": [...] }`) would break the interface, the API (`/api/v1/alertes`) and a rollback to a
  previous version, which would no longer read anything and would then rewrite an empty file.

## Added fields (version 1)

| Field | Type | Absent (alerts from before phase 3) | Meaning |
|---|---|---|---|
| `Modele` | integer | 0 | model version; 1 for the alerts created by the version that introduces it |
| `Regle` | text, omitted if empty | "" | identifier of the rule (`docs/detection/regles.md`), "" if the alert is attached to none |
| `Collecte` | text, omitted if empty | "" | collection the alert comes from (identifier from `etat.json`, `Collectes`), PR 3.3c |
| `Signature` | text, omitted if empty | "" | fingerprint (`sha256:…`) of the behavior, computed on the whole text before truncation; set on alerts of level "Alerte" before filtering (including those that learning lowers to "Info"); it is what an exception set from the alert targets |
| `Comportement` | text, omitted if empty | "" | stable code of the behavior, set by the code that produces the alert (auditor's review of 2026-11-22, point 2): tools seen for PRC-003 (`PRC-003:certutil`, `PRC-003:certutil,wmic`), patterns seen for PRC-002 (`PRC-002:obscurci`, `PRC-002:telecharge`, `PRC-002:obscurci,telecharge`), rules of the patterns seen and `document` for the other process rules, entry type for PER-* (`run`, `tache`, `service`, `wmi`…, followed by `:suspect` or `:devenu-suspect`), sorted indicators of a connection for RES-* (`balise+non-signe`…), category for NDR and DPI, `sid:<n>` for the IDS, `camera` or `micro` for VIE-001, the tool for VIE-002, `asr:<GUID>` (ASR rule) for DEF-007, and for CHA-001 the codes of the signals of the chain, sorted (`PRC-002+RES-002#balise+non-signe`…; long or non-ASCII: `sha:` and the start of their fingerprint). For RES-*, all indicators go into the code: an exception covers exactly that set, and an indicator that changes (port, telemetry) makes the alert reappear (cautious direction, at the cost of a little noise). It goes into the `Signature` fingerprint; never an ATT&CK technique or an advice. ASCII only, 120 characters at most |
| `HeureUtc` | text, omitted if empty | "" | UTC creation time (RFC 3339 to the second, "…Z"), phase 4, PR 4.1; capped at 32 characters |
| `Seq` | integer, omitted if 0 | 0 | creation sequence number, increasing since the service started (reset to zero at each start), phase 4, PR 4.1 |
| `Entite` | text, omitted if empty | "" | entity for incident tracking, when the producer knows it (phase 4, PR 4.3): `source:<adresse, ou « compte X » sans adresse>` for COR-R1; `compte:<compte sans domaine>` for COR-R2 and R9 (the account that opened the session; failing that, the source); `compte:<membre>` for COR-R3 and R3b; `COR-R<n>:<clé>` for the other correlations. Beyond 10 distinct entities of the same rule R1, R2 or R9 within one hour, the next ones are grouped under `COR-R<n>:regroupees`: an attack spread over hundreds of addresses does not open hundreds of incidents. Capped at 160 characters |

- `Modele` is set in a single place (`ajouter_alerte_brute`), and only if it is 0: an alert read back from an
  old file keeps 0, its history is not rewritten.
- An alert is **always** produced, even if looking up its rule fails (`Regle` empty).
- SIEM events (`siem::Evenement`, PR 3.2): only `Modele` and `Regle` are added to them (not `Collecte` or
  `Signature`). `Modele` is 1 on **all** events recorded since this version, whether they come from an
  alert or from a Windows log; `Regle` is taken from the original alert (empty for an event that does not come from one).
  Existing NDJSON lines are read back, with `Modele` 0.
- **Total order** (phase 4, PR 4.1, decision D4-4): `HeureUtc` and `Seq` are set on each new alert (in the same
  place as `Modele`) and on each SIEM event when it is recorded. The event drawn from an alert takes its
  `HeureUtc`. The local time (`Heure`) remains, unchanged; it is ambiguous during the repeated hour of the switch to
  winter time, ordering is done on (`HeureUtc`, `Seq`). An alert or a line from before phase 4 is read back with these fields
  empty, and is not re-timestamped.
- **Response actions in the SIEM** (phase 4, PR 4.1): each response command (`bloquer`, `bloquerIp`,
  `debloquer`, `toutDebloquer`, `tuer`, `suspendre`, `reprendre`, `tuerChaine`, `quarantaine`, `restaurer`,
  `restaurerRepli`, `isolerProgramme`, `panique`), the automatic block of an address (threat lists, IPS) and its
  lifting at expiry, and the automatic suspension of a program that touches a decoy (LEU-002, each attempt)
  produce an event with `Source` "reponse", `Type` the name of the action, `Destination` the target, level "Info" if
  the action succeeded, "Alerte" otherwise, and a message that states the result and the trigger ("commande
  d'administrateur" or "automatique : …"). Target, message and trigger are capped at 300 characters and cleaned
  (control and formatting characters replaced with "?", audit of #94, S94-01). The logic of the actions does not
  change. Only action that does not go through it: lifting panic mode during the cleanup at uninstallation.
- **Slots of the export API** (audit of 2026-11-23, A-1-3): a connection refused for lack of a slot (connections of the computer,
  loopback or address of the connection, beyond their 4 slots when the API listens on the network, or 16 slots taken) produces at most one event per 10 minutes:
  `Source` "api", `Type` "connexions-refusees", level "Alerte", message with the number of refusals of each kind
  since the previous event; the same line goes to the service log. An address outside the SIEM list is closed
  without an event (firewall).
- **SIEM queue losses** (phase 4, PR 4.1): an event that finds no room in the queue (20,000) is
  counted (`siem::pertes`), with a log line at the 1st, 10th, 100th… loss; before, it disappeared without a trace. The
  counter will be published with the reporting health (PR 4.4b).

## Compatibility

- **Reading old files**: absent fields take their default value (`Modele` 0, empty texts).
- **Tolerant reading** (PR 3.1, `commun::lire_alertes`, decision `decision_alertes`). Order of the checks:
  - reading refused (owner, folder protection): nothing is read or moved, even if the file is too large;
  - more than 16 MB: set aside (`alertes-trop-grand-<horodatage>.json`, in the data folder);
  - content that is not UTF-8, or that is not a JSON array: set aside (`alertes-illisible-…`);
  - otherwise, each element is read separately; an unreadable element is discarded and counted (one line in the log), the others
    are kept, and a copy of the original file is kept first (`alertes-partiel-…`).

  Before, a single malformed alert lost the whole history, then the file was rewritten empty. A setting
  aside that fails (file held open elsewhere) is retried at each write, and `alertes.json` is not rewritten
  as long as it has not succeeded: new alerts stay in memory. The set-aside name never overwrites an
  existing file.
- **Limits**: a transient read error (file held open elsewhere during the read) restarts empty, and the
  first addition rewrites the file; set-aside files are never purged; only the decision is tested in the
  lab, the setting aside itself (renaming, copy) is tested neither in the lab nor in a VM.
- **Capped fields** (security audit of #72, S72-01, S72-06, S72-07): in `ajouter_alerte_brute`, decisions are
  made on the **whole** text (MITRE technique, strong signal, learning), then the alert is capped (`borner_alerte`)
  before any use (log, export, notifications, SIEM, `alertes.json`). `Raisons` is kept to 1000 characters,
  `Chemin` and `Parent` to 520, `Processus`, `Destination`, `Conseil`, `Ip` and `NomDns` to 256, the fields set by the code
  shorter still (`Mitre` 128, `Regle` and `Collecte` 64, `Signature` 80, `Niveau`, `Heure`, `Id`), keeping the
  **start and the end** ("…" in the middle):
  the conclusion of an alert (remark, reason) is often at the end, after a long external piece of data. Control
  characters become "?". A capped alert fits in less than 16 KB even if **all** its fields are filled with
  4-byte characters (worst-case test), 1000 alerts in less than 16 MB: a standard
  account can no longer get the history set aside by creating a few giant autostart entries, nor make
  the reason for a persistence disappear by pushing it beyond the cap.
- **Learning**: a set-aside file counts as history (`historique_alertes_existe`): a setting aside does not
  make a computer already in service look like a first installation (review of #72, D7).
- **Exceptions and learned behaviors** (security audit of #72, S72-10; review, R7): an exception set from
  an alert targets the `Signature` fingerprint of the whole behavior, not the capped alert. Before, an exception set on an
  alert with a long path never applied, and a program placed at the literal capped path could inherit it. The
  new learned behaviors are stored by their fingerprint (fixed size: `apprentissage.json` stays bounded). The
  exceptions and behaviors already recorded in clear remain recognized. An alert from before this version has no
  fingerprint: an exception set from it takes the old signature, only if it is of level "Alerte"
  and no field of its signature was capped; otherwise the exception is refused (security audit of #73, S73-01). A
  malformed fingerprint is refused too (S73-02).
- **Additional limit**: if the folder protection fails, someone who pre-creates every possible set-aside name
  (100 per second of timestamp) can prevent the setting aside, and so hold back the writing of `alertes.json`:
  new alerts stay in memory (1000 at most) and are lost at shutdown. The failure is written only once to the
  log per series.
- **Interface**: it reads `alertes.json` with a JSON reader that ignores the fields it does not know (verified:
  an alert with `Modele`, `Regle` and `Collecte` is read).
- **Rollback** to a previous version: it ignores unknown fields, then rewrites the file without them.
  After a new upgrade, these alerts go back to `Modele` 0. Accepted. In `apprentissage.json`, the previous
  version ignores the exceptions and learned behaviors stored by fingerprint (PR 3.1b): the alerts concerned
  return to level "Alerte" (fail-closed); these entries still count toward the ceiling of 5000.
- **Learning signature**: its content does not change during phase 3 (it then depended on the `Mitre` text);
  since the auditor's review of 2026-11-22 (point 2, format 3 of `apprentissage.json`), it reads the rule and the
  `Comportement` code set by the producer (failing that, the start of the reasons), never the ATT&CK techniques or the
  advice: editing their tables or changing the ATT&CK version no longer makes any exception obsolete. The
  exceptions of a previous format (one-way fingerprints, not convertible) are kept apart and counted in
  `etat.json` (`ExceptionsPerimees`, `ApprisPerimes`); the Health page states their number ("Exceptions" line, "to
  set again") and a log line says so at migration. "Clear exceptions from a previous version" (settings)
  clears only them; "Delete exceptions" clears them too. Before migration, `apprentissage.json` is copied
  to `apprentissage-format<N>-<date>.json` (the previous state, exceptions of the old format included; never an overwritten
  copy). A malformed file is kept as `apprentissage-illisible-<date>.json`; a file that is present but
  unreadable (permissions, lock) is rewritten neither at startup nor afterwards, until the service restarts (the exceptions
  set in the meantime are held in memory; the answer to the exception says so, and the Health page adds a line
  "Exceptions", "in memory only", `ApprentissageNonCharge` in `etat.json`). The same applies when a malformed
  file could not be set aside. Known limit: a rollback to a version with
  format 2 clears the exceptions set in format 3 (code of the old version), and no copy keeps them; their
  alerts reappear (cautious direction), they must be set again. Only the
  stored form of the signature changes with PR 3.1b (fingerprint, see below).
  The deduplication key of alerts does not change.
- **Export**: the JSON export (syslog) and the API (`/api/v1/alertes`, JSON and NDJSON) serialize the whole alert: `Modele`
  appears there from PR 3.1, `Signature` from PR 3.1b (alerts of level "Alerte"), `Regle` and `Collecte` when they
  are filled (empty, they are not written). CEF does not
  change. The API reads `alertes.json` through the same tolerant reading, without moving anything (`lire_alertes_sans_effet`):
  an unreadable element no longer empties its answer.

## Collection health (phase 4, PR 4.4a)

Each change of state of a collection (`collectes::instantane`) is written to the SIEM by the "sante" thread (every
30 s, outside the monitor lock), on change only:

| Field | Value |
|---|---|
| `Source` | `sante` |
| `Type` | `collecte` |
| `Niveau` | `Alerte` if the collection becomes `Indisponible`, otherwise `Info` |
| `Destination` | identifier of the collection (`JournalSecurite`, `Connexions`…) |
| `Message` | "collecte <id> : <avant> → <après> (<raison>)", capped at 400 characters, cleaned |

- The switch from "Inconnue" to "Active" at startup is not written.
- Interface (PR 4.5a): `Type` "interface", `Destination` "session <n>", `Niveau` Alerte on disappearance (or on
  absence noted after the 5 min grace period), Info on return.
- More than 6 changes within the hour: collection "instable", one line per hour at most (the message says so).
- An interruption shorter than the thread's period (30 s) may go unseen.
- Findings SAN-001, SAN-002, SAN-003, SAN-012 and SAN-013: `docs/detection/regles.md`.

## Reporting health (phase 4, PR 4.4b)

`notifications.json` (read by the interface, no secret) gains:

| Field | Value |
|---|---|
| `EchecDepuis` | local time of the first undelivered batch of an ongoing outage; empty otherwise |
| `EnAttente` | alerts in the retry queue |
| `Abandonnees` | alerts dropped by the queue (full, or more than 24 h) since startup |
| `DernierBattement` | local date (YYYY-MM-DD) of the last heartbeat; read back at startup |

- **Delivered**: a batch is delivered if at least one channel tried succeeded; delivered on a single channel, it is not retried (it
  would arrive there twice). No channel tried (secrets absent): not delivered.
- **Retry queue**: critical alerts and SAN-* findings (except SAN-004) of an undelivered batch; without duplicates
  (same `Id`); 100 at most (when full, the first 50 stay and the second half rotates: alerts triggered in
  large numbers do not push out the first one); 24 h at most; attempts at +1, +5, +15, +60 min, then every
  hour, in one batch. **In memory** (D4-8): a restart empties it; the alerts stay in `alertes.json`.
- **SAN-004**: reporting failing for more than an hour; local finding, never reported or queued.
- **Heartbeat** (D4-6): when reporting is configured, one message per day from 09:00 local time, level
  "Info", outside the ceiling and the minimum level: incidents not closed, active and unavailable collections (identifiers
  of the unavailable critical collections), pending alerts. Counters only: no account name, program name
  or command line. If it monitors the absence of the heartbeat, the provider can infer that the service is
  stopped, the computer off or reporting cut.
- The loop keeps the pair (settings, secrets) and replaces it in one go, which rules out sending new secrets
  with old settings; a window of a few milliseconds remains, the secrets file being written just before
  the settings are dropped off. It takes the settings from a slot that is never lost, even with the message queue full, before
  each round of sending and before sending a batch. The secrets therefore stay in the service's memory between two sends;
  data folder protection failing: none is used.
- Secrets file removed: seen at the next round (about one minute, more during grouping or a send), secrets
  dropped and queue emptied (the destinations have changed). Unreadable: secrets dropped, queue kept but not sent; it
  is emptied on return only if the destinations read back differ. A failed read at startup empties it on return. Settings received during a read outage: refused, so as not to lose the secrets absent from the request; folder protection failing, fix it then restart the service, without deleting the secrets; malformed file, an administrator deletes it, then the secrets must be entered again. In both cases, ntfy and Teams no longer go out; an SMTP server
  without an account stays reachable. Edited by hand: not adopted before the
  next setting or restart, whereas the test and panic mode read the file.
- Reporting destinations changed (channels enabled, addresses, server, SMTP security and account, recipients): the
  queue is emptied (its alerts counted in `Abandonnees`), so that they do not go to the new ones;
  the level, the ceiling, a token, a password or the "Test" button with the same destinations do not empty it;
  reporting cut: the failure is also cleared. The batch being grouped (15 s of recent alerts) goes to the
  new destinations; a send already started finishes to the old ones, with the old secrets.
- Delivered on a single channel, a batch counts as delivered: a permanently broken channel does not raise SAN-004 as long as another
  works; its error stays in `DerniereErreur`. No usable channel: "aucun canal utilisable" is written there.

## Incident tracking (phase 4, PR 4.2)

`suivi-incidents.json` (data folder) is an array of incidents, written by the monitor alone, at the same time
as `alertes.json` and after each transition. `incidents.json` (SIEM correlations) does not change.

| Field | Meaning |
|---|---|
| `Modele` | 1 |
| `Id`, `Ouverture`, `OuvertureUtc` | identifier, opening time (local and UTC) |
| `DerniereActiviteUtc` | UTC time of the last attached alert |
| `Niveau` | the highest of the attached alerts (Alerte or Critique); never goes down |
| `Entite` | the `Entite` of the alert if the producer set it (SIEM correlations, PR 4.3; CHA-001 chains since T-3: `programme:<chemin du programme de tête>`, or `chaine:<nom>#<pid>@<heure de création>` if that path is missing or designates an interpreter or a generic launcher, never the text of the chain); otherwise `programme:<chemin complet, en minuscules>` if the path is known; otherwise `destination:<destination>`; otherwise `regle:<identifiant>`. Never a program name alone: two programs with the same name at different paths make two incidents |
| `Regles` | distinct identifiers of the attached alerts (16 at most) |
| `Etat`, `MotifCloture` | `Ouvert`, `PrisEnCharge` or `Clos`; reason `Resolu`, `FauxPositif` or `Accepte` for a closed incident |
| `Precedent` | closed incident of the same entity, if there is one (recurrence) |
| `Alertes`, `NombreAlertes` | summaries of the first 5 and the last 5 attached alerts (path 260, process 64, destination 128 and reasons 200 characters at most, without control or formatting characters), and their number |
| `Transitions` | 20 at most: local and UTC time, start and end state, reason, author (SID read from the token of the pipe client, never taken from the command; a transition without a known author is refused), note (300 characters at most, without control or formatting characters) |
| `NombreTransitions` | transitions since opening, including those that fell out of the 20 kept (second audit, B-5-01); absent from an older tracking file: 0, and the number of `Transitions` stands in for it |

- **Attachment**: an "Info" alert creates nothing; an "Alerte" or "Critique" alert joins the incident not
  closed of the same entity whose last activity is less than 24 h old; otherwise it opens an incident. A closed
  incident is never silently reopened: the recurrence opens a new incident, which names the previous one.
- **Transitions** (`incident` command, administrators only: `Cible` = identifier, `Valeur` = target state,
  `Type` = reason, `Raison` = note): Ouvert to PrisEnCharge or Clos; PrisEnCharge to Clos; Clos to Ouvert
  (explicit reopening, reason cleared, history kept). Any other transition is refused, without writing anything. Closing
  with "FauxPositif" sets no exception (D4-10). No automatic closing (D4-3).
- **Bounds**: 500 incidents at most. Beyond that, the oldest closed ones leave first; an incident not closed is
  never removed. If there are only incidents not closed, an alert from a new entity is not tracked: it is
  counted (health finding SAN-012, PR 4.4) and stays in `alertes.json`.
- **Reading** (`incidents::decision_suivi`): owner checked, element by element (an unreadable element is
  discarded and counted, the others are kept and capped to the same bounds as at creation).
  - Read in part: an original copy is set aside (`suivi-incidents-partiel-<horodatage>.json`) before allowing
    the rewrite; if the copy fails, the tracking file is not rewritten (review of #95, D1).
  - More than 64 MB: set aside (`suivi-incidents-trop-grand-<horodatage>.json`), tracking restarted empty (audit of #95,
    S95-01). The bounds guarantee that a full tracking file (500 incidents at worst) stays under this size.
  - Unreadable (permissions, not a JSON array): empty tracking, **never rewritten**, `incident` command refused **until a
    manual intervention** (moving the file). This is more cautious than for `alertes.json`, and it will be reported by
    health (PR 4.4b).
- **Rollback** to a version without tracking: the file is ignored, then picked up as is at the next
  upgrade.

## Incident timeline (phase 4, PR 4.3)

`chronologies\<id>.json` (data folder): for each tracked incident, a dated and ordered list, recomputed by
the service **outside the monitor lock** ("chronologies" thread, every minute) when the incident changes (new
attached alert, new transition), 50 incidents at most per round. The interface reads it without asking for anything; the
files of incidents that are no longer tracked are deleted.

- **Folder**: prepared like `restaurations`: nothing is written or deleted when the data folder protection
  fails; the folder is created with the permissions of the data folder (SYSTEM and administrators, readers with read access),
  opened without following links, its permissions checked. The name of a file is the identifier of the incident, checked
  (`[A-Za-z0-9-]`, 64 characters): an incident read back with another identifier is discarded; the cleanup only deletes
  regular files named this way.

- **Elements**: the summaries of the attached alerts, the transitions, and the SIEM events of the entity in the window
  [opening − 30 min, last activity + 30 min]: response actions, log events, connections, and any
  change of state of a collection (`Source` "sante", PR 4.4: a collection gap shows up in the timeline). The
  SIEM alerts are discarded, already present through the summaries. Order: UTC time, then sequence number.
- **Link with the entity** (`incidents::lien`): program (full path from the event or quoted; without a path, the file
  name alone, and the element then carries `ParNom`: another program with the same name may be its author), destination
  (destination, address or text), source of a correlation (address, or account with or without domain), account, rule.
- **Reading the SIEM**: for each incident, over its window only, the lines that quote its entity
  (`incidents::cle_recherche`) then the collection health; the connections of other programs therefore do not fill
  the read.
- **Bounds** (phase 4 design file): 3 days of files at most (longer window: the last 3 days); 20,000
  events per read; 5 s per timeline and 10 s per round (a timeline is only started with its full 5 s; the remaining incidents wait for the next round); 2000 elements (beyond that, the first 1000 and the last 1000,
  `Tronquee`); text of each element capped at 400 characters, cleaned. If a read bound is reached,
  `FenetreSiemIncomplete` says so. `SansHeureUtc` counts the events from before phase 4, which cannot be
  placed; `PertesSiem` says how many events the SIEM queue has lost since startup: steps may
  be missing.
- **After a restart**: a timeline already written for the same state of the incident (`Repere`: last activity,
  total number of transitions, number of alerts) is kept as is, not recomputed. The marker follows the total
  number of transitions (`NombreTransitions`), not the kept list: before the fix of the second audit (B-5-01),
  beyond 20 transitions it no longer changed and the timeline was no longer recomputed; tested in the lab
  (`chronologie_recalculee_au_dela_de_20_transitions`). A tracking file written earlier keeps the same marker: nothing is
  recomputed because of it at startup. When the incident changes, it is recomputed on what
  the SIEM still has (30 days of files): beyond that, the summaries and transitions of the incident remain.

## States published for the Overview (T-18, T-4)

Read-only additions, decided by the maintainer on 2026-11-23 (mockups T-18 and T-4 approved): no new
command or setting, no new collection, no personal data (no host, port, address
or name). Each state is drawn from what the service already knows, by a tested pure decision; each field is absent
from files written before and is then read back empty, `false` or empty list. The codes are stable, in ASCII, translated by
the interface; the existing French texts remain alongside.

`etat.json` (and so `/api/v1/etat`):

| Field | Type | Values | From |
|---|---|---|---|
| `ReponsesAuto.Rancongiciel` | text | "Desactive", "Actif", "Partiel", "SansEffet", "NonVerifiable" | setting `ReponseAutoRancongiciel`, policy (`decider`, suspension on decoy), collections `Leurres` and `JournalSecurite`, and last state of the baseline rule `audit.fichiers` (audit subcategory "File System", without which no 4663 is written: `baseline::etat_audit_fichiers`, noted in memory at each evaluation, every 10 min); not compliant: "SansEffet", unknown or not yet evaluated: "NonVerifiable" (`politique::etat_rancongiciel`, pre-review of #308, D1) |
| `ReponsesAuto.BlocageListes` | text | "Desactive", "Actif", "Partiel", "SansEffet", "NonVerifiable" | setting `BlocageAutoMenaces`, policy (refusal when the data folder protection fails), level 3 lists loaded (`menaces::niveau3_charges`), collection `Connexions` (`politique::etat_blocage_listes`) |
| `Syslog.Actif`, `Syslog.Etat` | boolean, text | "Desactive", "Joignable", "EnEchec", "NonVerifiable" | setting, and outcome of the last sending of an alert since startup or the last setting (`export::etat_syslog`) |
| `Api.Actif`, `Api.Etat` | boolean, text | "Desactive", "Joignable", "EnEchec", "NonVerifiable" | setting, and opening of the listener by the service (`api::etat_api`) |

- Order of the sources of a response: an unavailable or disabled source gives "SansEffet" (even if another is
  not read yet), then a source never read "NonVerifiable", then a partial source "Partiel". Blocking: none
  of the three level 3 lists (Spamhaus DROP IPv4 and IPv6, Feodo Tracker) loaded, "SansEffet"; some of them,
  "Partiel"; folder protection failing, "SansEffet" (the suspension on decoy, for its part, remains: D6-10).
- Malformed response registry (`RegistreReponses` "ContenuIllisible"): every automatic action is held back
  (`Etat::passage`), hence "SansEffet" for both responses as long as the file is not removed and the service
  restarted (audit of #308, S308-01).
- Limit: blocking by the lists does not model the real effect when the Windows firewall is off or a
  rule is refused; "Actif" says that the policy and the sources allow blocking, not that the rule acts.
- Settings read: those of the monitor (`config.json` loaded, updated by the commands). The suspension on decoy reads
  `config.json` again at each event: the two differ only if the file is modified outside the service.
- Syslog: "Joignable" only over TCP, and means "last send accepted by Windows on an established
  connection" (`write_all` succeeded), not "received by the collector". Over UDP, a sent datagram is never confirmed:
  "NonVerifiable". No send as long as no alert of the chosen level is raised: "NonVerifiable". The
  "Test" button does not count. Limit: the settings reach the sending thread through the same queue as the alerts
  (`try_send`, 2,000 messages); with the queue full, a new setting is lost, the thread keeps the old destination and
  the published state stays that of the old destination until the next setting or restart.
- Blocking by the lists depends on no audit subcategory: it is decided on the connection table
  (collection `Connexions`) and applied at the firewall (limit above).
- API: "Joignable" says that the service has opened its port (the interface translates it as "Port open"); access
  from the SIEM (firewall, network, allowed addresses) is not checked. Token not created, port not obtained, or listening
  thread ended while its settings are still in force: "EnEchec" (audit of #308, S308-02).

`maj.json`:

| Field | Type | Values |
|---|---|---|
| `Controle` | text | existing (PR #294): "", "ManifesteAncien", "EchecRecent", "EchecProlonge" (Health page) |
| `StatutCode` | text | "AdresseRefusee", "ManifesteNonObtenu", "ManifesteInvalide", "AJour", "ManifesteAncien", "Disponible", "SansCleEpinglee", "InstallationRefusee", "InstallationLancee", "InstallationImpossible" (`maj::StatutMaj`); the text of `Statut` gives the detail |
| `AutoApplique` | boolean | automatic installation applied by this check (setting read at the time of the check) |
| `Installable` | boolean | true for "Disponible" if this binary has a pinned key, and for "InstallationLancee" (`maj::installable`) |
| `EchecInstallationPrecedente` | boolean | **added outside the list of 23 November, accepted by the maintainer on 2026-11-24 (« Oui, le garder » (Yes, keep it))**; `maj\echec.txt` present: the script of the previous installation failed (package modified, or rollback); its text is added to `Statut`. Independent of `StatutMaj`: an "AJour" check may follow a failed installation; cleared when a new installation starts (audit of #308, S308-03) |

`filtrage-etat.json` (never `etat.json` or the API): `EtatCode`, same cases as `Etat`: "Inactif",
"RemiseEnAttente", "SuspenduResolveur", "SuspenduAmont", "Contourne", "Actif", plus "ActifSansCategorie"
when filtering runs without any active category (`filtrage::code_etat`).

`trafic.json`: `NonAttribue`, list of `{ Raison, Entrant, Sortant }` (bytes since midnight, same scope as
`Applications`: public traffic only), reasons without bytes omitted, the largest first (`trafic::lignes_non_attribuees`).
Reasons (`capture::attribuer`): "HorsTcpUdp" (neither TCP nor UDP: ICMP, IPsec…); "SansPort" (local port 0: IP fragment
that is not the first, truncated TCP or UDP header, or port 0 forged by the sender); "SansProprietaire" (local
port absent from the Windows tables, even read again: connection closed before the second reading, packet of no program of the
computer, virtual machine, Windows Sandbox, connection sharing, unsolicited incoming packet to a port where nothing
listens, scanning included, and answers from the Windows stack itself, RST for example); their sum is the
"?" line of the programs. "ProcessusTermine" (port held by a PID absent from the process list read at the same time:
process ended between the two reads, or, if the process snapshot fails, all the PIDs of that reading) is the
sum of the "PID n" lines. Limit: "closed before the second reading" and "no program of the computer"
cannot be told apart without a new collection.

`trafic.json`, traffic map (T-19, step 1: service; decided by the maintainer on 2026-11-23): read-only
additions, computed on what `trafic.rs` and the monitor already know (no new collection, no command,
no setting); fields absent from files written before, read back empty (`serde(default)`).

| Field | Type | Bounds and meaning |
|---|---|---|
| `Pays[]` | list | existing; now 250 countries at most (`MAX_PAYS`), only those with traffic, the largest first; `Programmes` (names only, 8 at most) kept as is |
| `Pays[].ProgrammesVolumes` | list of `{ Nom, Entrant, Sortant }` | bytes since midnight per program in that country, the largest first; 10 at most (`MAX_PROGRAMMES_PAYS`); name as in `Applications` (name, "System", "PID n", "?") |
| `Pays[].DestinationsPrincipales` | list of `{ Ip, Nom, Programme, Entrant, Sortant }` | destinations of the country, the largest first; 10 at most (`MAX_DESTINATIONS_PAYS`); of the same nature as `Destinations` (same fields), up to 300 addresses in all (30 countries × 10), beyond the 100 lines of `Destinations`: remote public address, name drawn from the service's DNS cache or empty, program as in `Applications` |
| `Pays[].DebitEntrantRecent`, `Pays[].DebitSortantRecent` | integer (bytes per second) | throughput of the country since the second-to-last write of the file (about 10 s, measured duration), for the thickness of the arcs (`trafic::debit_recent`, `trafic::decaler_cliches`) |
| `PaysSignales` | list of country codes | countries of the connections flagged at the monitor's last reading, at the same threshold as the "Suspicious" tab of Connections (score at the alert threshold, or known threat); sorted, without duplicates; 50 at most (`MAX_PAYS_SIGNALES`); IPv4 addresses only, 500 at most (`moniteur::ips_signalees`) |

`ProgrammesVolumes` and `DestinationsPrincipales` are only filled for the 30 largest countries
(`MAX_PAYS_DETAILLES`), empty beyond that. Size of the `Pays` list at worst (250 countries, names of more than 250 characters, existing `Programmes` list
included): about 880 KB measured with ASCII names (audit of #311, S311-01); more with non-ASCII names
(length of DNS names and program names not bounded); a few tens of KB in practice. Pure decision `trafic::lignes_pays`.
Limits: each destination keeps the first named program that reached it (like `Destinations`); two programs
that reach the same address are counted under the first one. The country is that of the block holder (regional
Internet registries), not a location. An address removed from the table (pruning beyond 5,000 destinations, or ceiling
of 6,000) leaves the detail and the recent throughput. No account name or program path is published: only the
program name, as in the existing lists.

## Stability rules

- A field never changes type.
- A removed field is still read (default value).
- Any break moves `Modele` to 2, with a tested migration.
