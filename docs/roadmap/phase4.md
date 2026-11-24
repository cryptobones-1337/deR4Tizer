# Phase 4: incidents, timeline, health of the collectors and of the interface

Opened on 2026-10-27, when the last PR of phase 3 (PR 3.12) was merged, following the maintainer's answer of
2026-10-26 (`CLAUDE.md`, section 5, point 3). This document sets the scope, the split and the decisions of the phase.
Written before the code; the phase has since been delivered (PR 4.1 to 4.6): the state of each item is the one in the matrix
(`docs/roadmap/capability-matrix.md`). The maintainer's answer of 2026-10-26 is recorded in the decision log,
outside the repository; `CLAUDE.md` does not quote it.

## Need

The computer of a very small business or a small municipality has neither a SOC nor an administrator on site, and the provider only sees what
deR4Tizer sends. Four gaps:

1. **No tracking**: an alert remains an isolated message, which can be neither taken in charge nor closed.
2. **No timeline per incident**: reconstructing what happened around an alert is a manual search
   in the SIEM, and the response actions are not in it.
3. **An outage stays silent over time**: the state of the collections has been visible since phase 3, but it is neither
   kept as history nor escalated; a failed escalation is not retried.
4. **The interface can disappear without a sound**: the user, or a program of their account, can close it, and the
   service does not see it. Local notifications no longer appear without it; detection and escalation by the
   service go on.

## What the phase does not do

- no new detection, beyond the health findings (`SAN-*`);
- no new or modified response action (phase 6): the existing actions are only **recorded**;
- no automatic closing of an incident;
- no sending of the content of a timeline (command lines, accounts) to the provider: the summary only;
- nothing from phases 6 to 9, nor unfreezing of the IDS, the DPI or the NDR.

## Split

Each PR starts from an up-to-date `main`, without stacking, with its review and its full pass in a VM before the merge.

| PR | Content |
|---|---|
| 4.0 | This document, the planned model (`docs/detection/modele-evenement.md`), the "prévu" rows of the matrix |
| 4.1 | `HeureUtc` and `Seq` on alerts and events; losses of the SIEM queue counted; response actions in the SIEM (`Source` "reponse") |
| 4.2 | Incidents: model, attachment of alerts, `suivi-incidents.json`, `incident` command (administrators) |
| 4.3 | Timeline per incident (computed outside the monitor lock, collection gaps, bounds) |
| 4.4 | Health of the collections, in two PRs: **4.4a** history and findings SAN-001, SAN-002, SAN-003, SAN-012; **4.4b** retried escalation queue, SAN-004, daily heartbeat (touches `notifications.rs`, privileged path, audited separately) |
| 4.5 | Health of the interface, in two PRs: **4.5a** detection by the service, `Sessions` collection, SAN-010 and SAN-011 (and the follow-up S99-04 of escalation); **4.5b** restart through a scheduled task set by the MSI (D4-1, option C, maintainer's agreement on 2026-10-27), `--relance` without prompt, text of "Quit" |
| 4.6 | Interface: Incidents and Health pages, header badge, stale state reported (S104-14, interface side). The per-session interface is not published by the service: the page says so and refers to SAN-010 and SAN-011 |

The `SAN-*` sheets go into `docs/detection/regles.md` with their entry in the registry (`regles.rs`), their code and
their tests, in the PR that brings them (4.2, 4.4, 4.5): the registry test requires the sheets and the registry to
agree.

## Decisions

The maintainer asked, on 2026-10-26, to move on to phase 4 without waiting for his validation of phase 3 (answer
« Enchaîner sur la phase 4 » (Move on to phase 4)). Within this answer, the open decisions were **settled by the agent**,
following the recommendations of the design file; the maintainer can reverse each of them.

| # | Decision | Chosen |
|---|---|---|
| D4-1 | Interface gone: restart or alert | Detection and alert by the service (SAN-010 after 15 min of absence, level "Critical", maintainer's decision of 2026-10-31; SAN-011 after 3 stops within one hour, level "Alert", escalated only if escalation is configured at that level): chosen. The **restart** through a scheduled task set by the MSI, under the user's identity, is a privileged behavior (`CLAUDE.md`, section 4, "Before each lot", point 3): it awaited **the maintainer's explicit agreement**, given on 2026-10-27 ("the service may relaunch the interface through a scheduled task (decision D4-1) > validated"), then a test in a VM: task descriptor not modifiable by a standard account, done with PR 4.5b; **Remote Desktop sessions and fast user switching postponed to the end-of-phase-7 campaign, from the Kali VM, by decision of the maintainer on 2026-10-31, no version being published before**; rollback to a version without restart, **not tested** (the reference package 4.1.0 refuses to downgrade, which is not the real path), effect deduced from the code, limit accepted by the maintainer on 2026-10-31, 4.5b going into the first distributed version. Without this agreement, or if the test fails: alert only, without restart. A direct restart by the service (process creation in the session) is not considered. |
| D4-2 | Tracking file | New `suivi-incidents.json`, written by the monitor alone; `incidents.json` (SIEM correlations) unchanged. |
| D4-3 | Automatic closing of an incident | Never. An incident without activity for 7 days is only displayed as "inactif". |
| D4-4 | `HeureUtc` and `Seq` in `Alerte` and `Evenement` | Yes, as additions to model 1: without them, the timeline gets the order wrong during the repeated hour of the switch to winter time. |
| D4-5 | "Critical" collections for SAN-001 | `JournalDefender`, `EtatDefender`, `JournalSecurite`, `Connexions`, `Processus`, `ListesMenaces`, and `Persistance` since the audit of #103 (S103-04), which widens the initial choice. |
| D4-6 | Daily heartbeat to the provider | Yes, when escalation is configured: counters only, once a day. |
| D4-7 | Tracking and timeline in the export API | Not during phase 4 (to be taken up with phase 8, advanced mode). |
| D4-8 | Escalation queue on disk | No: in memory, bounded (100 items, 24 h); the loss at restart is a written limit. |
| D4-9 | New dependency | None. |
| D4-10 | "False positive" at closing | No exception set automatically; it is offered separately, with its own confirmation. |

## Proof

GitHub Actions was then disabled (from 2026-10-22 to 2026-11-17). `CLAUDE.md` only provides for the local VM proof in place of GitHub CI for
phase 3. For phase 4, it is **applied following the maintainer's answer of 2026-10-26**, until he
writes it into `CLAUDE.md`. Nothing changes for distribution: green GitHub CI, successful lot 3d, signed binaries and
independent review remain required.

## To be written into `CLAUDE.md` by the maintainer

Note of 2026-11-19: `CLAUDE.md` has since said that the local VM proof stands in for GitHub CI "as for phases 3,
4 and 6" (section 5, point 5, written on 2026-11-03 with the maintainer's authorization); the text proposed below was
not taken up there as it is. Text proposed at the time, under section 5, point 3:

- Opening: on 2026-10-26, the maintainer asked to move on to phase 4 at the end of phase 3, without waiting for his
  validation of it (answer « Enchaîner sur la phase 4 » (Move on to phase 4)). Decisions of the phase: `docs/roadmap/phase4.md`.
- As for phase 3, the local VM proof (section 4, "Temporary exception") stands in for GitHub CI for the
  PRs of phase 4. Nothing changes for distribution.
- D4-1: the restart of the interface through a scheduled task: explicit agreement of the maintainer on 2026-10-27, test in a VM with PR 4.5b.
