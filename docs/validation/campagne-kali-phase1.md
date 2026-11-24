# Kali validation campaign: initial audit and closed list of scenarios (phase 1)

| Field | Value |
|---|---|
| List version | **1.8** (2026-11-22: restart of the service by the lot 4 network bench, on decision of the maintainer; delays of S-22, S-25, S-27, N-12 and N-13 recalculated; passive capture proven after the restart; controls N-06 to N-13, full sheets of S-20 to S-27, rule D-3 and repetition protocol added in 1.7; S-19 rewritten in 1.6; S-20 to S-27 added in 1.5; version 1.4 for the rest) |
| Date of version 1.4 | 2026-11-15 |
| Previous versions | 1.7 of 2026-11-22; 1.6 of 2026-11-20; 1.5 of 2026-11-19; 1.4 of 2026-11-15; 1.3 of 2026-11-14; 1.2 of 2026-11-14; 1.1 and 1.0 of 2026-11-14 (published/transmitted under `docs/validation/campagne-kali-phase1.md`) |
| Audited code | (v1.3) `main` at commit `cde9468`; approval rule reread in `CLAUDE.md` at `8faf4f9`; baseline read in `service-rs/src/baseline.rs` and `gpo.rs` at `ede269f`. (v1.4) Correction of the statement of S-07, rewrite of the S-06 sheet and correction of an error of the initial draft ("DNS-002/filtering code absent"), established by **reading the full, up-to-date worktree of `main`** (after the merges of phase 7.3/7.4); the working checkout of v1.3 was on a stale branch (`passages-en-vm`) older than these merges, hence the error. No measurement is presented in it. |
| Status | **APPROVED BY THE VALIDATION AGENT** |

> **Note of 2026-11-19**: the mentions "IDS, DPI, NDR frozen" in this list (§2, §3, §5) and the class E that follows from them hold at the date of v1.4; the IDS and the NDR have been unfrozen since 2026-11-16, the DPI since 2026-11-18 (`CLAUDE.md`).

> **Reminder about the approval (v1.4).** The approval by the validation agent **is neither human nor independent** (same model as the one that runs the scenarios; their blind spots may coincide) and **lifts no rule** of `CLAUDE.md` or of the mandate. **Version 1.4 was transmitted to the maintainer, for information, on 2026-11-15, before any execution.** Main changes: **correction of the statement of S-07** (threat address placed in a **high confidence** source, and not a "level 3 list": a reputation source does not trigger automatic blocking); **decision rules D-1** (lab exposure artefact RES-004/005) **and D-2** ("Indisponible" collection after restore) recorded as scoring rules (5.4); **S-06** (DNS-002 and DNS filtering) **rewritten at the level of behaviour and testable** (DNS-002 = Alert; filtering = blocking without alert, noted in the latest blocks), after correction of the "code absent" error of the initial draft (stale checkout; the code is indeed in `main`, 5.5). The T1562.002 part of S-13 and DNS-003 (S-18) remain approved since v1.1 (5.2). **Nothing here is a result.**

## Approval

Approved on 2026-11-14, version 1.0, by the validation agent, in application of `CLAUDE.md` (section 5, phase 7,
Kali campaign: "Closed list of scenarios written and approved by the validation agent before any execution").

- **2026-11-14, version 1.1**: approved by the validation agent (T1562.002 part of S-13 and DNS-003 approved on the
  decision of the maintainer quoted in 5.2).
- **2026-11-14, version 1.2**: approved by the validation agent (campaign snapshots "campagne A" and
  "campagne B", dated approval). **Neither human nor independent**; lifts no rule; transmitted to the maintainer before
  any execution.
- **2026-11-14, version 1.3**: approved by the validation agent (main configuration C, baseline at 100 % on
  decision of the maintainer; expected result in configuration C per scenario; class P "prevented (baseline)"; S-19; defect
  D-BAS-01). **Neither human nor independent**; lifts no rule; transmitted to the maintainer on 2026-11-14 before any
  execution.
- **2026-11-15, version 1.4**: approved by the validation agent (correction of the statement of S-07: source of
  **high confidence**, not "level 3"; **decision rules D-1 and D-2** recorded; **S-06 rewritten at the level of
  behaviour and classed testable**: the code of DNS-002 and of filtering is present in `main`, the "code absent" error
  of an initial draft came from a stale checkout). **This approval is neither human
  nor independent**; it lifts no rule, and v1.4 was transmitted to the maintainer, for information, on 2026-11-15,
  before any execution.
- **2026-11-19, version 1.5**: S-20 to S-27 added on decision of the maintainer (`CLAUDE.md`, Kali campaign), **after
  their execution** (2026-11-16 and 2026-11-17); no prior approval by the validation agent (§6).
- **2026-11-20, version 1.6**: approved by the validation agent (S-19 rewritten after the review of the baseline of
  2026-11-20, PR #215 to #221: LSA protection expected at RunAsPPL = 2, 1 accepted only if it was already in place,
  RunAsPPLBoot recorded only; `reseau.bureau-distance` left aside by the application of the profile, then applied
  alone during the preparation of "campagne C"; Defender rules judged on their effective state and cross-checked with
  Get-MpPreference; Security log never reduced; expected scores 100/100/100; re-evaluation of the baseline requested
  from the service before the reading; hash of the binary checked). Actions and cleanups of the other scenarios unchanged.
  **Neither human nor independent**; lifts no rule; transmitted to the maintainer for information. **Executed before
  publication**: the approval of the agent (2026-11-20, around 22:50) preceded the trial (S-19 trial 3, 23:20: "RÉUSSI",
  3.1), but the v1.6 sheet was not yet merged on `main`, contrary to `CLAUDE.md` (publication before the
  first execution); deviation reported to the maintainer, who may take note of it as for S-20 to S-27.

- **2026-11-22, version 1.7**: approved by the validation agent for lot 4 of the ATT&CK coverage
  (consolidation by 10 trials of the "lab-tested, not consolidated" lines of `carte-attack.md`). Additions: negative
  controls N-06 to N-13 (3.2 and 3.2 bis); repetition protocol (3.4); decision rule D-3 (5.6); full sheets
  of S-20 to S-27 with quantified maximum delays (§7). No new offensive scenario, no new variant; actions
  and expected results of S-01 to S-19 unchanged. The service is never stopped or restarted by the bench (S-18 outside the lot): for the
  decoy and UPnP, the 600 s cycle of the NDR is awaited (provisional decision of the coordinator of 2026-11-22, in the absence
  of the maintainer, to whom the question will be put). **Neither human nor independent**; lifts no rule; transmitted to the
  maintainer for information before execution; published on `main` before the first execution of a trial of lot 4.
- **2026-11-22, version 1.8**: approved by the validation agent. Decision of the maintainer of 2026-11-22, quoted as
  is: to the question « Le banc réseau du lot 4 peut-il redémarrer le service entre deux essais ? » (May the lot 4 network bench restart the service between two trials?), the answer is
  « Oui » (Yes). The provisional decision of v1.7 (never restart, wait for the 600 s cycle) is lifted. Changes:
  point 8 of the repetition protocol (3.4); common rules of the network sheets (7.0); delays of S-22, S-25 and S-27 and
  of the controls N-12 and N-13 recalculated on the first iteration of the NDR after start-up (`ndr.rs`); passive capture
  proven after the restart. The restart applies only to the network sheets (S-20 to S-27, N-12, N-13); S-18 remains
  outside the lot; no other scenario, action or expected result changed. **Neither human nor independent**; lifts no rule;
  transmitted to the maintainer for information before execution; published on `main` before the first execution of a
  network trial of lot 4.

- **This approval is neither human nor independent**: the agent is the same model as the one that runs the
  scenarios; their blind spots may coincide. It is never presented as a validation.
- It lifts no rule: no scenario that would touch Defender, leave the lab, steal a real credential,
  carry a destructive payload or require typing a password is approved. Doubtful cases are left to the
  maintainer (section 5.2).
- This version is transmitted to the maintainer, for information, **before any execution**. He may withdraw a scenario or
  take back the approval at any time. Any addition or change is the subject of a new version approved before
  being executed.
- Execution starts only once the prerequisites of section 4 are checked, with N-01 then S-01 alone; the next
  scenario is launched only if the reference state is checked and the evidence of the previous one is complete.

**Retained (v1.4)**: N-01 to N-05; S-01 to S-05; **S-06 (DNS-002 and DNS filtering, testable)**; S-07 to
S-12; S-13 **including its T1562.002 part** (approved in v1.1); S-14 to S-19; S-16 with its long option (2 h, in
configuration A). **Added**: S-18 (DNS-003) in v1.1; S-19 (check of configuration C) in v1.3. Configurations:
C main, A comparison, B Sysmon collection (3.0, 5.1.2, 5.1.11).

**Also retained (v1.7)**: controls N-06 to N-13 (3.2, 3.2 bis); S-20 to S-27 with full sheets (§7); repetition protocol
(3.4) and rule D-3 (5.6) for the series of 10 trials. **Outside lot 4, not added**: Startup folder
(T1547.001), service launched from a system folder (T1569.002), regular beacon (T1071.001), passive NBNS responder
(T1557.001).

**Excluded (v1.1)**: T1567 (D); T1055 (not executed); T1562.001 against Defender, the Windows logs or deR4Tizer
(forbidden); Atomic sheets that download, disable a protection, read the memory of LSASS or clear a real log.

**Decided by the maintainer on 2026-11-14, approved in v1.1**: T1562.002 part of S-13; DNS-003 (became S-18).
Decision quoted word for word in section 5.2.

**Correction (v1.4)**: **S-06** (DNS-002 and DNS filtering) had been wrongly classed "code absent / awaiting the
maintainer" by an initial draft, because of a stale checkout (branch `passages-en-vm`, older than the merges
of phase 7.3/7.4). The code is indeed present in `main`: S-06 is **testable** and its sheet is rewritten at the level of
behaviour (3.1, 5.5).

**Changes from v1.0 to v1.1**: the two parts above go from "left to the maintainer" to approved; S-18
created for DNS-003; cross-references updated; header at version 1.1.

**Changes from v1.1 to v1.2** (review of PR #172): configurations A and B start from the snapshots "campagne A"
and "campagne B" (and not from "propre"); all resets target the snapshot of the configuration; the VM goes back
to "propre" only after the campaign; "not measured" made precise as "not measured in a VM". No scenario added, removed or
changed in its action or its expected result.

**Changes from v1.2 to v1.3** (decision of the maintainer of 2026-11-14: « pour les tests kali, tu as bien pris en
compte d'avoir la baseline à 100% ? C'est l'un des interêts du produit » (for the Kali tests, did you take into account having the baseline at 100%? It is one of the points of the product), then « ok parfait » (ok perfect)): configuration C added,
snapshot "campagne C" ("campagne A" plus the baseline applied by the service, three profiles), which became the
main measurement configuration; A remains the comparison, B the Sysmon collection; section 1.7; class P "prevented
(baseline)", never confused with a detection; an expected result in configuration C (HYPOTHESIS) per scenario and per negative
test; S-19; section 5.3 (defect D-BAS-01). Actions and cleanups of the existing scenarios unchanged.

**Changes from v1.3 to v1.4** (reading of the full worktree of `main`, after the merges of phase 7.3/7.4):
- **S-07 corrected.** v1.3 placed the threat address in a "level 3 list". **A reputation source (for
  example a level 3) does NOT trigger automatic blocking**; the 7-day automatic blocking requires a source of
  **high confidence**. The statement of S-07 (3.1), the mapping (2) and decision 5.1.5 are corrected: the threat
  address is placed in a **high confidence source** (for example a botnet C2 list or a DROP block). S-07 is
  described **at the level of behaviour**: known malicious domain (DNS-001) + known high confidence threat address
  (RES-001) + automatic blocking expiring after 7 days. No implementation file name, no detailed offensive command,
  no address outside the documentation range.
- **Decision rules D-1 and D-2 recorded** (5.4, reference in 3.0): D-1, the RES-004/RES-005 alerts carrying an address
  of the documentation range of the lab are **lab exposure artefacts**, excluded from TP as from FP, kept
  in the evidence; D-2, "Indisponible" collection criterion after restore (a collection on which a rule of the
  scenario depends must be "Active" at the start, proven by a reading after the restore, otherwise invalid trial,
  class D, never 0).
- **S-06 rewritten at the level of behaviour, testable** (1.5, 2, 3.1, 3.3, 5.5): an initial draft had classed S-06
  "code absent / class E"; it was an **error due to a stale checkout** (branch `passages-en-vm`, older than the
  merges of phase 7.3/7.4). The code of **DNS-002** (`dns_surveillance.rs`) and of **DNS filtering** (local resolver,
  `dns_local.rs`, `filtrage.rs`, `filtrage_cartes.rs`) is indeed in `main` and listed by the capability matrix. S-06
  now covers (a) DNS-002 = change of static DNS server on an adapter → Alert, and (b) filtering by
  local resolver = a `.test` name of the list is resolved to a null address and appears in the latest blocks,
  without alert. The control **N-05** becomes again a **normal negative control** (return to DHCP without alert). No action or
  cleanup of another scenario is changed.

**Changes from v1.7 to v1.8** (2026-11-22, decision of the maintainer quoted in the version 1.8 entry):
- **Restart of the service by the network bench**: stop then start by the administrator account of the bench, after the
  reorientation of the adapters and at the latest at the start time of the trial, with its evidence (3.4, point 8; 7.0).
- **Delays recalculated**: the decoy and the UPnP reading start at the first iteration of the NDR after start-up; 660 s
  become 180 s after start-up for S-22, S-25, S-27, N-12 and N-13.
- **Passive capture**: opened at start-up on the lab adapter; evidence through the service log and the state of the
  collections (7.0).
- **Precondition added** (7.0): DNS filtering disabled, state read after the restart; no expected result changes.
- Nothing else changes.

**Changes from v1.6 to v1.7** (2026-11-22, lot 4 of the ATT&CK coverage):
- **Negative controls N-06 to N-13**: legitimate activity close to each line to consolidate that had no control
  (3.2 and 3.2 bis).
- **Full sheets of S-20 to S-27** (§7): preconditions, action, expected result, quantified maximum delay, cleanup and evidence.
  §6 only gave "the delay of the NDR cycle".
- **Rule D-3** (5.6): the PER-001 of the execution task of the bench is an artefact.
- **Repetition protocol** (3.4): reset to the snapshot at each trial except S-09, distinct targets, learning
  finished, level checked, actions of S-13 outside SYSTEM, service never restarted by the bench.
- No offensive scenario added, no action or cleanup of S-01 to S-19 changed.

Document publishable as is (`docs/validation/`): level of behaviour, ATT&CK identifiers, expected results, cleanup and
evidence; no detailed offensive command; no personal data, no profile path, no account identifier
or password. Addresses in documentation ranges (RFC 5737), test names in `.test` (RFC 2606).

Everything marked **HYPOTHESIS** is deduced from reading the code and the documents, not measured. Nothing here is a
result.

---

## 1. State of the detection capabilities (from the code and `docs/`)

### 1.1 Architecture relevant to the campaign

- Rust service as SYSTEM, monitoring cycle about every 3 s, separate threads for the logs, persistence
  (1 min), health (30 s), DNS (60 s), filtering.
- Channel `\.\pipe\deR4Tizer`: remote clients refused by the pipe (PR #168); remote connection (IPC-03) **never
  tried** (capability matrix).
- Alerts with `Regle`, `Modele`, `HeureUtc`, `Seq`, `Collecte`; an Alert or Critical alert opens or joins an
  incident (entity, 24 h); an Info alert opens nothing.
- **Learning**: 7 days after the first installation, any "Alert" alert without a strong signal becomes "Info" and
  its behaviour is memorised. Never softened: Critical, SAN-*, REP-*, DNS-002, IDS, and the patterns code
  download, LOLBin, remote debugging, deletion of backups, macro, anomaly of the tasks folder. Consequence for
  the measurement (decision 5.1.1: learning finished).
- Baseline profile "logging" applied automatically at the first start-up on an unmanaged machine: audit of
  logons, process creation (4688) with command line, file system (4663), other objects
  (4698), accounts and groups, audit policy, security extensions, firewall rules, `pfirewall.log`, PowerShell script
  blocks (4104), modules (4103), DNS-Client and Task Scheduler logs. To check in the snapshot (section 4).

### 1.2 Event sources actually consumed

| Source | Consumed by | Remark |
|---|---|---|
| Security: 4624, 4625, 4648, 4672, 4688, 4697, 4719, 4720-4726, 4728, 4732, 4740, 4756, 4798, 1102 | COR-* | 4688 recorded but no PRC rule uses it; 4698, 5140, 5145 not subscribed |
| Security 4663 | VOL-001, LEU-002 | requires object auditing and the SACL set |
| System: 7045, 104, 7036 | SIEM | 7036 only for deR4Tizer, Defender, firewall, event log, Security Center |
| Sysmon 1 and 22 only | processes | **chosen at start-up if present**, otherwise WMI; the other Sysmon events are not read |
| WMI for processes | processes | short-lived processes lost, command lines often missing |
| DNS-Client (or Sysmon 22) | DNS-001, "direct IP" indicator | |
| Defender (log, state) | DEF-001 to 012 | DEF-003 to 006 and 010 to 012 assume a weakened Defender: never exercised |
| Firewall log (rules) | SYS-002, SYS-003 | |
| `pfirewall.log` | RES-005 | one alert per (source, port, action) and per 24 h |
| TCP table, listening ports | RES-001 to 003, 006, 007 | periodic reading: a short connection may be missed (HYPOTHESIS) |
| Automatic start-ups | PER-001, PER-002 | every minute |
| Decoys, hosts | LEU-001, SYS-001 | hashes |
| Network adapters | DNS-002, DNS-003 | 60 s: see reservation below |
| PowerShell 4104 | **no rule** | produced by Windows, never read |

> **Note (v1.4) on the line "Network adapters / DNS-002, DNS-003".** On reading the full worktree of `main` (after
> the merges of phase 7.3/7.4), the **monitoring of the adapter DNS server (DNS-002, `dns_surveillance.rs`)** and the
> **DNS filtering by local resolver** (`dns_local.rs` on `127.0.0.1:53` and `[::1]:53`, engine `filtrage.rs`, activation
> on the adapters `filtrage_cartes.rs`, state `filtrage-etat.json`) are indeed present, in addition to the reading of the
> DNS-Client log (3008) that feeds **DNS-001** and of the cache flush. An initial draft called them "absent": error
> due to a stale checkout, corrected here (5.5). **DNS-002, filtering and DNS-003 (S-18) are therefore testable.** Caution
> kept, not blocking: check that the installed binary indeed matches this source of `main` before measuring.

### 1.3 Rules (`regles.rs`, `docs/detection/regles.md`)

Measurement state: **not measured in a VM** for all the sheets, except PER-001 (Run key) and DNS-002, seen in scenario 3a.
The "DNS-002 seen in scenario 3a" simply comes from `main` (rule `DNS_002` of `regles.rs`, detection in
`dns_surveillance.rs`); the speculation of an initial draft (binary from an unmerged branch) came from a
stale checkout and is withdrawn (5.5).

- RES-001 (known threat, Critical, automatic blocking **if the source is of high confidence**, for example a DROP block
  or a botnet C2 list), RES-002 (score ≥ 3), RES-003 (Info), RES-004, RES-005, RES-006, RES-007.
- DNS-001 (domain lists disabled by default, restricted licences), DNS-002, DNS-003.
- PRC-001 to 005, CHA-001; PER-001, PER-002; DEF-001 to 012; LEU-001, LEU-002; VOL-001; SYS-001 to 003; PIL-001;
  EXT-001; VIE-001 to 003; BAS-001.
- COR-R1 (5 failures in 5 min, same source), COR-R2 (success after ≥ 5 failures in 30 min, Critical), COR-R3/R3b, COR-R4
  (1102/104), COR-R5, COR-R6, COR-R7, COR-R9 (Critical if Remote Desktop, Alert otherwise), COR-R10. No R8.
- SAN-001 to 004, SAN-010 to 012; REP-001 to 004; INT-001, INT-002; EXP-IDS/DPI/NDR (frozen).

### 1.4 Automatic responses and durations

| Action | Level | Expiry | At expiry |
|---|---|---|---|
| IP blocking from a high confidence source (DROP block / botnet C2 list) | 3, active by default | 7 days | lifted |
| Suspension of the program that touches a decoy | 3, active by default | 2 h | stays suspended; REP-001 Critical then every 24 h |
| IPS blocking | 2, IPS disabled by default | 24 h | lifted |
| Manual suspension, isolation, panic | 2 | 24 h, 7 d, 4 h | never lifted, reminder |
| Quarantine, manual blocking | 2 | 30 d, 90 d | Info reminder |
| DNS filtering | 2, mode disabled by default | none | · (a block is not an alert: it appears in the latest blocks, `filtrage-etat.json`; S-06) |

Guards: 3 blocks of the same address per 24 h, 30 blocks from lists per hour, human decision respected for 7 days;
REP-002 when an action is withheld.

### 1.5 DNS filtering (phase 7): **present in `main` (v1.4)**

Documented function (phase 7): local resolver on the loopback, physical adapters set to it on activation, original
servers as fallback, fail open; a block is not an alert (it appears in a state file). Documented
limit: as long as the upstream does not respond, the adapters stay on their original servers, without filtering; a lab
without Internet therefore requires a lab DNS upstream (decision 5.1.4).

**Reading finding (v1.4): this code is present in `main`** (`dns_local.rs`, `filtrage.rs`, `filtrage_cartes.rs`,
state `filtrage-etat.json`), and DNS-002 in `dns_surveillance.rs`; the capability matrix lists them (local resolver,
filtering engine, state/DNS-003, Quad9). An initial draft called them "absent": error due to a stale checkout
(branch `passages-en-vm`), corrected here. **Consequence**: scenario S-06 is **testable** (3.1) and control N-05 is
a **normal negative control** (3.2). Only caution kept, not blocking: confirm that the installed binary matches
this source before measuring (section 4).

### 1.6 Known limits that weigh on the campaign

- IDS, DPI, NDR frozen: HTTP content, TLS fingerprints, network detection of scanning: class E.
- No scan detection outside the IDS; expected effect: RES-005 per port touched (HYPOTHESIS).
- No telemetry of process access or injection consumed: T1003.001 and T1055 without a rule.
- 4104 never read: an obfuscation absent from the command line has no rule.
- "Active" guarantees the reading of a source, not the production of the events by Windows.
- Correlations deduplicated for one hour in memory and failure window of 30 min: two trials from the same source within
  the hour do not give two incidents (design of the trials, 3.0).
- The RFC 5737 documentation range counts as Internet for the service: this is what makes COR-R9 possible; side
  effects: VM seen as "exposed", RES-004/RES-005, RES-007, "direct IP" indicator. These RES-004/RES-005 on a lab address
  are **lab exposure artefacts** (decision rule D-1, 5.4).
- **DNS-002, DNS filtering and DNS-003 present in `main`** (1.5): S-06 and S-18 are testable; only caution, not
  blocking, confirm that the installed binary matches the source before measuring (section 4).

### 1.7 deR4Tizer baseline applied at 100 % (configuration C, added in v1.3)

Read in `service-rs/src/baseline.rs` (`main` at `ede269f`). The baseline goes through the local GPO; the original values
are saved for undo; application is refused on a managed machine (domain or MDM). Three profiles:
logging (applied by default), recommended, hardened. Expected effects on the campaign, all **HYPOTHESIS**:

| Baseline rule | Profile | Expected effect on the campaign |
|---|---|---|
| `reseau.bureau-distance` | recommended | S-01, S-02, S-05 (a), N-04: RDP impossible; COR-R1/R2 and the Critical variant of R9 through RDP not exercisable in C, measured in A. Left aside by the application of the profile when Remote Desktop is enabled; set alone during the preparation of C (v1.6) |
| `reseau.pare-feu` | recommended | local allow rules kept; more refused packets logged (S-08) |
| `reseau.smb1`, `reseau.invite-smb`; `reseau.signature-smb` | recommended; hardened | S-03, S-04, S-17: Kali must speak SMB 2 or 3; signing required on the client side, VM as server not touched |
| `asr.scripts-obscurcis`, `asr.scripts-telecharges` | recommended | S-10: obfuscated content possibly blocked; process creation and command line remain visible |
| `asr.lsass`; `systeme.lsa`; `systeme.wdigest` | recommended; hardened; recommended | S-15: "limited information" access allowed; a memory read would be refused (never exercised) |
| `asr.psexec-wmi` | hardened | no scenario executes remotely; possible side effect recorded |
| `asr.prevalence` (audit mode) | hardened | recent test programs (S-14, S-16, S-18): events 1122, without blocking |
| `asr.rancongiciel` | recommended | relies on the cloud, unreachable: uncertain effect on S-16 |
| `defender.dossiers-blocage` | hardened | S-16: decoys in Documents, Pictures, Desktop (protected): write by the unsigned test program refused; controls of S-09 outside these folders |
| `defender.pua`, `defender.cloud`, `defender.reseau` | recommended | without Internet, cloud and reputation unreachable: weak expected effect on S-07 and S-11; any reaction recorded |
| `systeme.wsh` | hardened | any .vbs or .js variant blocked; S-09 and S-10 go through PowerShell |
| `systeme.smartscreen` | recommended | N-03: warning when opening a downloaded file, not at download |
| `systeme.uac` | recommended | no expected effect on control through PowerShell Direct (checked by N-01 in C) |

In configuration C, an action may be **prevented** (Windows setting set by the baseline, or Defender hardened by
it) without being **detected** by deR4Tizer: the two are noted separately (class P, section 2). Defect found on
reading: D-BAS-01 (5.3).

---

## 2. ATT&CK mapping → expected alert

A priori class: **HYPOTHESIS** for all the lines. A detection expected; B event produced without a rule; C alert
expected but incorrect or too generic; D not executable in the lab; **E not testable with the current
architecture** (frozen, or function absent from the source read). Descriptive subclasses: B1 received by deR4Tizer without a rule, B2
produced by Windows or Sysmon but not read.

Class added in v1.3: **P, prevented (baseline)**. The behaviour is prevented, with evidence, by a Windows setting
set by the baseline (P-baseline) or by a Defender component hardened by it (P-Defender). **P is never
a detection**: a fully prevented trial leaves the detection denominator (neither TP nor FN) and is counted separately; if
deR4Tizer also alerts, the trial is noted "P + A" and only the A part enters the score. A Defender reaction in
configuration A or B (without hardened baseline) is noted "blocked by Defender", never attributed to the baseline.

| Technique | Simulated behaviour | Sensor required | Expected event | Rule | Expected alert | A priori class (HYPOTHESIS) |
|---|---|---|---|---|---|---|
| T1110.001 (RDP) | series of password failures against a test account | Logon audit | 4625 type 3 with source address | COR-R1 | COR-R1 Alert | A |
| T1110.001 then T1078.003 | failures then success from the same source | Logon audit | 4625 ×≥5 then 4624 | COR-R2 | COR-R2 Critical | A |
| T1133 / T1021.001 | Remote Desktop session from the documentation range of the lab | Logon audit | 4624 type 3 then type 10 | COR-R9 | COR-R9 Critical | **C**: the deduplication key of R9 would be taken by the type 3 4624 that precedes the type 10; R9 would come out "Session ouverte depuis Internet", Alert |
| T1021.001 | same session | TCP table | connection established on 3389 | RES-007 | RES-007 Alert | A |
| T1110.001 (SMB) | failures then success on the file share | Logon audit | 4625/4624 type 3 | COR-R1, R2, R9 | R1 Alert, R2 Critical, R9 Alert | A; if the source address is missing, "account" key and R9 silent |
| T1021.002 | authenticated access to an administrative share, read only | Logon audit | 4624 type 3, 4672, 5140 | COR-R9 | COR-R9 Alert | A for the session; B2 for the access to the share |
| T1046 | bounded TCP port scan | `pfirewall.log` | packets blocked from a "public" address | RES-005 | no "scan" rule | C (one RES-005 per port) or E |
| T1071.001 | regular HTTP requests to a lab server | TCP table, DNS-Client | repeated connections | RES-002 | RES-002 Alert (beacon, direct IP, port) | A if seen by the reading; otherwise collection FN |
| T1105 | download of a benign text file by PowerShell | Sysmon 1 or WMI, TCP table | process, connection | PRC-002, RES-002 | PRC-002 Alert | A with Sysmon; unstable without |
| T1105 | same download by a misused Windows tool | same; Defender | same | PRC-003, DEF-001 | PRC-003 Alert; DEF-001 if Defender reacts | A |
| T1059.001 + T1027 | long encoded PowerShell command, benign content | Sysmon 1 or WMI | command line | PRC-002 | PRC-002 Alert | A with Sysmon |
| T1027 | benign obfuscated script launched from a file | 4104 | 4104 | none | none | B2 |
| T1547.001 | Run value pointing to a benign command | automatic start-ups | new entry | PER-001 | PER-001 Alert | A |
| T1053.005 | benign scheduled task launched by an interpreter | reading of the tasks | new task; 4698 not read | PER-001 | PER-001 Alert | A |
| T1543.003 | local service, image in a writable folder, benign command | System log | 7045 | COR-R5, PER-001 | COR-R5 Critical | A |
| T1136.001 + T1098 | local account created then added to Administrators | accounts and groups audit | 4720, 4732 | COR-R3 | COR-R3 Critical | A |
| T1070.001 (SIMULATION) | clearing of a dedicated log created for the test | System log | 104 | COR-R4 | COR-R4 Critical | A (HYPOTHESIS: 104 emitted) |
| T1562.002 (SIMULATION) | audit subcategory outside the needs of the rules disabled then restored | policy audit; baseline | 4719; drift | COR-R7, BAS-001 | COR-R7 Alert; BAS-001 Alert if the subcategory is part of the profile | A |
| T1562.001 | Defender, logs and deR4Tizer untouchable | · | · | DEF-003 to 006, 010 to 012 | · | D (forbidden) |
| T1003.001 (SIMULATION) | opening of LSASS with "limited information" access, without memory read | Sysmon 10 if configured | 10 | none | none | B2 |
| T1555.003 (SIMULATION) | opening for reading of the credentials file of a browser of an empty test account, by an unsigned test program launched from a temporary folder | 4663 + SACL | 4663 | VOL-001 | VOL-001 Critical | A |
| T1055 (SIMULATION) | no action; available telemetry inventoried | · | · | none | none | not executed; no sensor consumed |
| T1486 (SIMULATION) | a test program modifies a single deR4Tizer decoy | 4663 + hash | 4663 | LEU-002, LEU-001 | LEU-002 Critical + automatic suspension; REP-001 at 2 h | A |
| T1041 | HTTP sending of a generated canary file to Kali | TCP table | outgoing connection | RES-002 | RES-002 Alert depending on the score | A for the connection; E for the content and the volume |
| T1567 | sending to a public web service | · | · | · | · | D (no real service authorised) |
| · (known threat) | connection to a lab address listed in a **high confidence source** | TCP table, local list | connection | RES-001 | RES-001 Critical; automatic blocking 7 d | A |
| · (DNS) | resolution of a `.test` name from a **high confidence** domain list | DNS-Client / Sysmon 22 | query | DNS-001 | DNS-001 Critical | A (restricted lists to enable) |
| · (DNS, S-06) | static DNS server set on the adapter | adapters, registry | change | DNS-002 | DNS-002 Alert | A |
| · (DNS, S-18) | loopback port 53 held by another program at restart | binding failure, adapter registry, UDP table | exclusive binding failure + PID | DNS-003 | DNS-003 Critical (PID) | A (approved in v1.1; filtering present in `main`) |
| · (filtering, S-06) | resolution of a `.test` name from the filtering list | local resolver | block | · | no alert; name in the latest blocks | A (functional trial: block expected, without alert) |
| IPC-03 | opening of the channel from Kali over the network | pipe | refusal | · | refusal, no command executed | A (refusal expected) |

---

## 3. Proposed closed list

### 3.0 Common rules

- Addressing: target VM and Kali on `d4t-labo`, in the RFC 5737 documentation range; administration link on a
  separate documentation range between the host machine and Kali only; "Default Switch" adapter of the VM unplugged.
- Starting snapshot depending on the configuration (decisions 5.1.2 and 5.1.11):
  - "campagne C" (configuration C, **main measurement configuration** since v1.3): "campagne A" plus the deR4Tizer
    baseline applied by the service itself (three profiles in one command, then `reseau.bureau-distance` alone), then
    restart; without Sysmon;
  - "campagne A" (configuration A, comparison): installation without baseline beyond the logging profile applied
    by default; without Sysmon;
  - "campagne B" (configuration B, Sysmon collection): with Sysmon and Atomic Red Team.
  All three are prepared outside the campaign with deR4Tizer installed, learning finished, the test accounts and the
  lab settings; in C, the baseline prevails when it contradicts them (Remote Desktop refused). Their names never
  start with "propre".
- **"Reset to the snapshot" means the reset to the campaign snapshot of the configuration of the trial**, **never to
  "propre"** (which would erase deR4Tizer, the test accounts and the lab settings). Reset before and after each lot,
  and **before each trial of the correlation scenarios** (COR-*).
- The VM is reset to "propre" only **after the campaign**, once the evidence is collected.
- Atomic Red Team exists only in "campagne B"; in A or C, the behaviour is produced without it.
- Each scenario carries an expected result in configuration C, marked HYPOTHESIS. Scenarios that C makes unexecutable or prevented
  (S-01, S-02, S-05 (a), N-04: Remote Desktop refused; S-16: decoys in protected folders): detection is
  measured in A, the trial in C remains a prevention measurement (class P). S-19 is executed at the start of each lot in C; if it
  fails, the lot is invalid (D).
- Scores separate per configuration (A, B, C), never merged; class P counted separately, never as detection.
- Dedicated local test accounts; lab passwords never written in a report or in the repository.
- Timestamping: start (UTC) read on the VM; latency = `HeureUtc` of the alert minus `TimeCreated` of the triggering
  event (and, secondarily, minus the start of the action).
- Valid trial: behaviour proven (Windows or Sysmon event, log on the Kali side), collections "Active" at the start and at
  the end. Otherwise D (invalid), never 0. **Criterion made precise by decision rule D-2 (5.4):** any collection on which
  a rule of the scenario depends must be "Active" at the start, proven by a successful reading **after the restore**
  of the snapshot; otherwise the trial is invalid (D).
- TP: expected rule, level and entity, within the delay; C: other rule or other level; FN: nothing within the delay; FP:
  Alert or Critical alert during a negative test or unrelated to the scenario. **Decision rule D-1 (5.4):** an
  **RES-004/RES-005** alert carrying an address of the **documentation range of the lab** is a **lab exposure
  artefact**, excluded from the count of TP as of FP (including in the negative tests), but kept in the evidence;
  an RES-004/005 carrying an address outside the lab range is investigated, never excluded by default.
- 10 valid trials per scenario before any consolidated measurement; SIMULATION and emulation never in the same score.
- Common evidence: `alertes.json`, `suivi-incidents.json`, `incidents.json`, SIEM events of the day, `etat.json`,
  `reponses.json`, `blocages.json`, `journal.txt`; extracts of the Windows and Sysmon logs over the window of the trial;
  versions of deR4Tizer, Windows, Sysmon, Atomic Red Team; state of Defender at the start and at the end. Raw results outside
  the repository.

### 3.1 Scenarios (from the most benign to the least benign)

**N-01 · Chain control: legitimate activity (negative, validates the collection and the evidence)**
- Technique: none (negative).
- Preconditions: campaign snapshot of the configuration; collections active; learning finished; clocks
  read.
- Action: local logon of the test account, a signed PowerShell administration command launched from a
  file, viewing of the interface.
- Expected: no Alert/Critical alert; 4624 present in the SIEM; no collection down.
- Delay: 10 min of observation.
- Cleanup: logoff.
- Evidence: common + state of the collections at the start and at the end.
- Expected in configuration C (HYPOTHESIS): identical; checks that control through PowerShell Direct and the collection of the
  evidence work under the baseline; no alert due to the baseline.

**S-01 · RDP brute force, failures only (first scenario: validates the measurement chain, COR-R1)**
- Technique: T1110.001. Nature: emulation (real failures against a test account, no access obtained).
- Preconditions: N-01 passed; Remote Desktop allowed on the profile of the lab adapter; test account outside
  Administrators; number of failures below the lockout threshold read.
- Action: from Kali, a series of authentication failures beyond the correlation threshold, in less than 2 min, then
  stop.
- Expected: several 4625 (source = Kali); COR-R1 Alert, entity `source:<adresse Kali>`; one incident opened. Accepted
  side alerts: RES-005, RES-007 (RES-004/005 on the lab address = lab artefact, D-1).
- Maximum delay: 120 s after the threshold is reached.
- Cleanup: reset to the snapshot before the next trial.
- Evidence: common + exported 4625; log on the Kali side (time, number, result; without password).
- Expected in configuration C (HYPOTHESIS): **prevented (P-baseline)**: Remote Desktop refused, connection refused on the
  Kali side, no 4625 through RDP, COR-R1 not exercised. This is not an FN: COR-R1 is measured in C by S-03 and in A by S-01.

**S-02 · RDP brute force followed by a success**
- Technique: T1110.001, T1078.003, T1133. Nature: emulation.
- Preconditions: as S-01.
- Action: a series of failures beyond the threshold then a successful logon of the test account, closed immediately.
- Expected: COR-R1 Alert; COR-R2 Critical; COR-R9 Critical according to the sheet (**HYPOTHESIS C**: Alert "Session ouverte
  depuis Internet"); R2 and R9 in the same incident `compte:<compte de test>`; RES-007.
- Delay: 120 s after the 4624. Cleanup: disconnection; reset to the snapshot.
- Evidence: common + 4624 (types 3 and 10), 4625.
- Expected in configuration C (HYPOTHESIS): **prevented (P-baseline)** as S-01; COR-R2 and the Critical variant of COR-R9
  (Remote Desktop) not exercisable in C, measured in A.

**S-03 · SMB brute force followed by a success**
- Technique: T1110.001, T1021.002. Nature: emulation.
- Preconditions: file sharing allowed on the profile of the lab adapter; test account.
- Action: a series of authentication failures on the share beyond the threshold, then a successful read connection
  to a test share.
- Expected: COR-R1, COR-R2, COR-R9 Alert; if the source address is missing in 4625, R1 by account and R9 silent (to
  be observed). Delay: 120 s. Cleanup: reset to the snapshot.
- Evidence: common + 4625/4624 with the source address field.
- Expected in configuration C (HYPOTHESIS): identical to A if the "file sharing" permission survives the blocking of
  inbound traffic by default; Kali in SMB 2 or 3. Access refused by the firewall: P-baseline, recorded.

**S-04 · Remote connection to the command channel (IPC-03)**
- Technique: none directly (privilege boundary). Nature: emulation.
- Preconditions: standard test account.
- Action: from Kali, attempt to open the deR4Tizer pipe over the network, with a version request.
- Expected: refusal; no command executed; COR-R9 Alert for the network session. Delay: 60 s. Cleanup: reset to
  the snapshot. Evidence: error on the Kali side, `journal.txt`, SIEM.
- Expected in configuration C (HYPOTHESIS): identical (refusal of the pipe, COR-R9 Alert); if the SMB session is refused
  upstream: P-baseline, and the refusal of the pipe is not exercised (D for IPC-03).

**S-05 · D4-1 trials: interface in a Remote Desktop session and at fast user switching**
- Technique: none (functional trial, decision D4-1). Nature: functional trial.
- Preconditions: two test accounts; relaunch task present.
- Action: (a) Remote Desktop session of account A from Kali; (b) fast switch to account B at the console.
- Expected: interface present in each active session at the latest 6 min after opening; no SAN-010 over
  25 min; control retained: interface closed on purpose for more than 15 min, SAN-010. Delay: 25 min per case.
- Cleanup: sessions closed; reset to the snapshot. Evidence: processes per session, SIEM, SAN alerts.
- Expected in configuration C (HYPOTHESIS): (a) **not executable** (Remote Desktop refused): D in C, measured in A;
  (b) identical to A.

**S-06 · Change of DNS server (DNS-002) and DNS filtering by local resolver**
- Technique: no exact ATT&CK match (redirection of resolution); phase 7 function. Nature: emulation
  (DNS-002, change of DNS server), functional trial (filtering by local resolver).
- **Status v1.4: testable.** The code is present in `main` (DNS-002: `dns_surveillance.rs`; filtering: local resolver
  `dns_local.rs`, engine `filtrage.rs`, activation on the adapters `filtrage_cartes.rs`, state `filtrage-etat.json`).
  An initial draft classed S-06 "code absent / class E": it was an error due to a stale checkout, corrected
  (5.5). The activation of the adapters on the local resolver as SYSTEM has the agreement of the maintainer (phase 7.4): it is not an
  open question.
- Preconditions: configuration A is enough; lab DNS upstream on Kali (the local resolver relays to it; without an upstream that
  responds, the adapters stay on their original servers, limit of 5.1.4); local resolver active; filtering enabled by
  the administrator's `filtrage` command (physical adapters set to the local resolver, original servers as
  fallback); local synthetic filtering list with a `.test` name (`.test` names only, no third-party list);
  state of the collections, of filtering and of the adapters read; criterion D-2 (5.4): the collections `ConfigDns` (DNS-002) and
  `FiltrageDns` must be "Active" at the start, proven by a reading after the restore.
- Action: (a) **DNS-002**: a static DNS server is set on an active physical adapter of the VM (network unchanged),
  then the reading of the adapters (every 60 s) compares it; (b) **filtering**: resolution by the Windows DNS client of a
  `.test` name present in the synthetic filtering list.
- Expected: (a) **DNS-002 Alert** (DNS server set by hand on a physical adapter; rule not softened by
  learning); (b) **no alert**: the listed `.test` name is resolved to a **null address** and appears in the
  latest blocks (`filtrage-etat.json`), the filtering state counting it; a `.test` name **outside** the list is relayed
  to the lab upstream (control). 1 incident for DNS-002 at most.
- Maximum delay: 120 s for DNS-002 (after the reading of the adapters); 60 s for filtering.
- Cleanup: static DNS server removed, adapter returned to DHCP (negative control N-05: no alert on return to DHCP,
  change given by the network); filtering disabled by the `filtrage` command (adapters returned to their original
  servers, port 53 released, local resolver stopped); synthetic filtering list removed; **check that the adapters
  and filtering are returned identically**; reset to the snapshot after the trial.
- Evidence: common + DNS setting of the adapters before/after (reading and registry `NameServer`), `alertes.json` (DNS-002),
  `filtrage-etat.json` (latest blocks, categories, active state), raw DNS event (resolved name), state of the collections
  `ConfigDns` and `FiltrageDns` at the start and at the end.
- Expected in configuration C (HYPOTHESIS): identical (DNS-002 Alert; block without alert); no baseline rule
  concerns the DNS setting of the adapters or filtering; if the machine is seen as "joined to a domain", the activation of
  filtering is refused (decision D7-5 of the code): record it, and then measure filtering in configuration A.

**S-07 · Domain and address listed in test threat lists (high confidence): DNS-001 / RES-001**
- Technique: T1071 (known infrastructure). Nature: emulation.
- Preconditions: local synthetic lists set by an administrator (owner SYSTEM or Administrators),
  erased by the reset to the snapshot:
  - a **`.test` domain name** (known malicious test name) in a **high confidence domain list**
    (restricted lists enabled for the test, decision 5.1.5);
  - a **dedicated secondary address of Kali** (in the documentation range of the lab, **never the main address of
    Kali**, otherwise the automatic blocking would cut off the lab) placed in a **high confidence source** (for example a
    botnet C2 list or a DROP block). **Correction v1.4:** a **reputation** source (for example of level 3) **does NOT
    trigger** automatic blocking; only a **high confidence** source does. v1.3 wrongly spoke of a
    "level 3 list".
  - criterion D-2 (5.4): the collections "threat lists" and "domain lists" must be **Active** at the start
    (synthetic lists actually loaded), proven **after** the restore; otherwise the trial is **invalid (D)**.
- Action: (a) resolution of the listed domain name by the Windows DNS client (query to the lab upstream on Kali, the
  private switch; no real domain contacted); (b) benign network connection, held a few seconds, to
  the listed threat address (lab server on Kali), so that it is seen by the periodic reading of the TCP table.
- Expected: **DNS-001 Critical** (resolution of a known malicious domain); **RES-001 Critical** (connection to a
  high confidence threat address) + **automatic blocking expiring after 7 days** with the connection cut;
  recovery through "Unblock" checked (after "Unblock", a new connection re-triggers as long as the list is
  present: to be noted). 1+ incident.
- Delay: 60 s (resolution and connection).
- Cleanup: "Unblock" the address in the interface; test lists removed; restricted lists returned to their
  original value; reset to the snapshot.
- Evidence: common + `menaces.json` (sources and counters before/after), raw DNS event (resolved name), `alertes.json`
  (DNS-001, RES-001), `blocages.json` (expiry +7 d), "deR4Tizer" firewall rules before and after.
- Expected in configuration C (HYPOTHESIS): identical (DNS-001, RES-001, 7-day blocking); without reachable cloud
  reputation, network protection should not block the lab address; if it does: P-Defender recorded separately,
  DNS-001 remaining expected (the resolution precedes the connection).

**S-08 · Port scan**
- Technique: T1046. Nature: emulation. Preconditions: packet log active on the profile of the lab adapter.
- Action: a bounded TCP scan, once.
- Expected: no dedicated rule; RES-005 per blocked port (HYPOTHESIS, to count; RES-004/005 on the lab address =
  lab artefact, D-1); possible EXP alerts recorded without scoring. Delay: 180 s. Cleanup: reset to the snapshot.
- Evidence: common + `pfirewall.log`, `exposition.json`, number of RES-005.
- Expected in configuration C (HYPOTHESIS): as A, with more refused packets logged if the adapter is on the
  public profile and port 3389 closed; number of RES-005 compared with A.

**S-09 · Persistence through Run key and scheduled task**
- Technique: T1547.001, T1053.005. Nature: emulation (benign command that writes a marker file).
- Preconditions: matching Atomic sheets read if they are used; excluded if they download or do not clean
  up after themselves.
- Action: (a) Run value pointing to an interpreter that writes a marker; (b) equivalent scheduled task.
- Expected: PER-001 Alert for each; 4698 produced (B2). Delay: 180 s. Cleanup: value and task deleted;
  no residual alert. Evidence: common + `demarrage.json`.
- Expected in configuration C (HYPOTHESIS): PER-001 Alert for (a) and (b); marker written outside the protected folders (otherwise
  P-Defender through controlled folder access, recorded); variant through Windows Script Host blocked (P-baseline), not
  used.

**S-10 · Encoded and obfuscated PowerShell (benign content)**
- Technique: T1059.001, T1027. Nature: emulation. Preconditions: configurations A and B.
- Action: (a) long encoded command that writes a marker; (b) obfuscated script with the same effect, launched from a file.
- Expected: (a) PRC-002 Alert; (b) no alert, 4104 present (B2). Delay: 60 s. Cleanup: marker deleted.
- Evidence: common + Sysmon 1, 4688, 4104.
- Expected in configuration C (HYPOTHESIS): (a) PRC-002 Alert, with a possible blocking of the content by
  `asr.scripts-obscurcis` (1121): "P + A"; (b) probable blocking of the obfuscated script (P-Defender), no alert from
  deR4Tizer, 4104 recorded if it is produced.

**S-11 · Simulated HTTP command and control, transfer of a benign file**
- Technique: T1071.001, T1105. Nature: emulation (HTTP server on Kali serving a text file).
- Preconditions: lab server on a port outside the common list; responses held a few seconds.
- Action: (a) regular requests for a few minutes; (b) download by PowerShell; (c) same download
  by a misused Windows tool.
- Expected: (a) RES-002 with "beacon" indicator; (b) PRC-002 and/or RES-002; (c) PRC-003 Alert, DEF-001 if Defender
  reacts (result, never bypassed); CHA-001 if two signals follow one another; HTTP content: E. Delay: 300 s (a), 60 s
  (b, c). Cleanup: files deleted; reset to the snapshot. Evidence: common + server log, Defender log.
- Expected in configuration C (HYPOTHESIS): identical (RES-002, PRC-002, PRC-003); cloud and network protection
  unreachable, weak expected effect; any detection or blocking by Defender noted separately (P-Defender or DEF-001).

**S-12 · Exfiltration of a canary file**
- Technique: T1041. Nature: emulation (generated file, marked CANARI, no real data). Preconditions: reception
  on Kali. Action: HTTP sending of the canary by a test program.
- Expected: RES-002 if the score is reached; nothing on the volume or the content (E). Delay: 60 s. Cleanup: canary
  deleted on both sides. Evidence: common + hash of the canary, server log.
- Expected in configuration C (HYPOTHESIS): identical (RES-002 depending on the score); no baseline rule concerns
  HTTP sending.

**S-13 · Service, administrator account, dedicated log cleared, audit modified**
- Technique: T1543.003, T1136.001, T1098, T1070.001 (SIMULATION), T1562.002 (SIMULATION). Nature: SIMULATION for
  T1070.001 and T1562.002; emulation for the others.
- Preconditions: dedicated log created for the test. **T1562.002 part approved in v1.1** (decision of the maintainer of
  2026-11-14, 5.2): executed with cleanup with verified restoration. Initial state of the audit subcategory read
  before the trial.
- Action: service created with an image in a writable folder (benign command); test account created then added
  to Administrators; dedicated log cleared; audit subcategory disabled then restored.
- Expected: COR-R5 Critical; COR-R3 Critical; COR-R4 Critical; COR-R7 Alert; BAS-001 Alert if the subcategory
  belongs to the "logging" profile. Delay: 120 s; 25 min for BAS-001.
- Cleanup: service, account, dedicated log deleted; audit subcategory returned to its initial state and the
  restoration checked (before/after comparison); reset to the snapshot after the trial.
- Evidence: common + 7045, 4720, 4732, 104, 4719; audit policy before and after.
- Expected in configuration C (HYPOTHESIS): identical (COR-R5, COR-R3, COR-R4, COR-R7); no ASR rule blocks the
  creation of the service or of the account; BAS-001 expected if the modified subcategory belongs to the logging profile;
  the local GPO may restore the subcategory by itself at its refresh: time of the restoration recorded.

**S-14 · Reading of a browser credentials file (SIMULATION)**
- Technique: T1555.003 (SIMULATION). Nature: SIMULATION: test account without any saved password; opening
  for reading then closing, no copy, no decryption.
- Preconditions: object auditing active, SACL set by deR4Tizer; "data audit" collection **Active** at the start,
  proven by an audited reading after the restore (D-2, 5.4): priming through a legitimate reading by the
  browser, which raises no alert.
- Action: an unsigned test program, launched from a temporary folder, opens the file for reading then closes it immediately.
- Expected: VOL-001 Critical. Delay: 60 s. Cleanup: test program deleted; reset to the snapshot. Evidence:
  common + 4663.
- Expected in configuration C (HYPOTHESIS): identical (VOL-001 Critical): controlled folder access only blocks
  writing and does not protect this file; ASR prevalence audit (1122) possible for the test program, without blocking.

**S-15 · Limited access to LSASS (SIMULATION)**
- Technique: T1003.001 (SIMULATION). Nature: SIMULATION: handle with "limited information" access only, no
  memory read, no credential theft tool. Preconditions: Sysmon configuration noted.
- Action: opening then immediate closing of the handle.
- Expected: no alert from deR4Tizer (no rule); Sysmon 10 if configured (B2); Defender reaction recorded.
  Delay: 60 s. Cleanup: none. Evidence: common + Sysmon 10.
- Expected in configuration C (HYPOTHESIS): identical (no alert from deR4Tizer, B2): LSA protection and `asr.lsass`
  let the "limited information" access through; any reaction (1121, opening refused) is recorded as P, without
  changing the detection class.

**S-16 · Anti-ransomware decoy touched (SIMULATION, automatic response)**
- Technique: T1486 (SIMULATION). Nature: SIMULATION: a test program modifies a single decoy; no encryption,
  no other file. Preconditions: decoys set (collection `Leurres` active); automatic response enabled (default).
- Action: writing of one byte into a decoy by a test program outside Program Files.
- Expected: LEU-002 Critical, automatic suspension, entry in `reponses.json`; LEU-001 at the next reading;
  long option: REP-001 Critical at 2 h, process still suspended; "Resume" checked. Delay: 60 s; 2 h 05 for
  the option. Cleanup: resume then stop of the test program; reset to the snapshot. Evidence: common + 4663, state
  of the process.
- Expected in configuration C (HYPOTHESIS): **prevented (P-Defender)**: decoys in Documents, Pictures and Desktop, protected
  by controlled folder access in block mode; write by the unsigned test program refused (1123), decoy intact;
  LEU-002 and the suspension probably not triggered (no successful modification). Detection and automatic response
  measured in A; long option in A only. LEU-002 nevertheless in C: "P + A", recorded.

**S-17 · Remote administrative session on an administrative share**
- Technique: T1021.002. Nature: emulation (listing of a directory only; no remote service, no remote
  execution). Preconditions: dedicated administrator test account.
- Action: from Kali, authenticated connection to the administrative share, listing of a directory, disconnection.
- Expected: COR-R9 Alert; 4672 in the SIEM; 5140 produced but not read (B2). Delay: 120 s. Cleanup: reset to
  the snapshot. Evidence: common + 4624, 4672, 5140.
- Expected in configuration C (HYPOTHESIS): identical (COR-R9 Alert, 4672); `asr.psexec-wmi` not applicable; Kali in SMB 2 or 3.

**S-18 · DNS-003: loopback port 53 held by another program at the restart of the service (approved in v1.1)**
- Technique: no exact ATT&CK match (interference with the local resolver); phase 7 function. Nature:
  emulation.
- Status: **approved in v1.1** (decision of the maintainer of 2026-11-14, 5.2). Requires a **stop of the deR4Tizer service then its
  relaunch**; executable only because the maintainer decided it (exception to the "deR4Tizer intact" principle).
- **Note v1.4:** S-18 relies on the **DNS filtering function** (adapters set to the local resolver), **present
  in `main`** (`dns_local.rs`, `filtrage.rs`, `filtrage_cartes.rs`, 1.5): S-18 is testable. Only caution, not
  blocking, confirm that the installed binary matches this source before measuring.
- Preconditions: configuration A is enough; DNS filtering enabled (adapters set to the local resolver); state of the
  collections, of filtering and of the adapters read; a benign lab listener program ready (it only opens port 53 for
  local listening, without serving real resolution).
- Action: (a) the service is stopped in such a way that the adapters stay set to the loopback (risk case of the
  threat model); (b) the benign lab program takes port 53; (c) the service is relaunched and cannot bind
  port 53, an adapter still pointing to the local resolver.
- Expected (**a priori HYPOTHESIS, class A expected**): DNS-003 Critical, with the PID of the program that holds port 53
  (rule not softened by learning); no other unrelated Alert/Critical alert. To be measured, never presented
  as a result. Maximum delay: 180 s after the relaunch.
- Cleanup: listener program stopped, port 53 freed; **deR4Tizer service relaunched and its proper operation checked**
  (pipe that responds, collections "Active", filtering and adapters returned identically); **reset to the snapshot after the trial**.
- Evidence: common + filtering state files before and after, setting of the adapters before and after, `journal.txt`
  (stop and relaunch, binding failure of port 53, PID recorded), state of the collections at the start and at the end.
- Expected in configuration C (HYPOTHESIS): identical (DNS-003 Critical with the PID); recent listener program: ASR
  prevalence audit (1122) possible, without blocking; cleanup unchanged (service relaunched and checked, reset to "campagne C").

**S-19 · Check of configuration C: compliance of the baseline and state of Defender (added in v1.3)**
- Technique: none (configuration check; prerequisite of each lot in configuration C). Nature: check, read
  only. The service is only asked to re-evaluate the baseline (no setting written).
- Preconditions (v1.6): "campagne A" carries the service from `main` (hash of the binary noted); "campagne C" is
  prepared from this "campagne A". Reference reading of Defender (Get-MpPreference, Get-MpComputerStatus), of
  `baseline.json`, of LSA protection and of the size of the Security log taken in "campagne A". Baseline applied by
  the service in two commands: first the logging, recommended and hardened profiles (the message must say that
  `reseau.bureau-distance` is left aside, the Remote Desktop of "campagne A" being enabled), then
  `reseau.bureau-distance` alone. Then, policy update, restart, taking of the snapshot. Windows 11 22H2
  or more recent (build 22621).
- Action: at preparation, then at the start of each lot in C: re-evaluation of the baseline requested from the service, then
  reading of `baseline.json` and of the state of Defender, comparison setting by setting with the reference reading.
- Expected (HYPOTHESIS):
  - Defender: **no setting weaker than before** (real-time protection, behaviour, scripts, downloads,
    tampering, cloud, PUA, network protection, controlled folder access, scanning of removable media); mode
    "Normal"; ASR rules never downgraded; no exclusion. "Weaker" is defined in a table written before
    the first reading.
  - Baseline: three profiles at 100 %, all rules "conforme" and applied. The 21 Defender rules (6 Defender,
    15 ASR) agree with Get-MpPreference: "conforme" if and only if Defender applies the value. No rule
    "sans effet" or "inconnu".
  - Effects beyond the registry: Remote Desktop and Remote Assistance refused by policy, port 3389 closed.
    LSA protection: RunAsPPL = 2 (1 accepted only if it was already in place in "campagne A"), Wininit event 12
    later than "campagne A" (RunAsPPLBoot recorded, not required). Security log of at least 1 GiB, never smaller
    than in "campagne A", policy absent or at least equal to the target. Firewall active on the three profiles, inbound
    blocked by default on the Public profile. `EnableControlledFolderAccess` = 1.
  - deR4Tizer: no Alert or Critical alert, no BAS-001 during the observation.
- Delay: immediate reading; 25 min of observation. Cleanup: none.
- Safeguard: a weaker Defender setting, or Defender outside Normal mode, stops configuration C and is escalated to the
  maintainer (`CLAUDE.md`, rule 2); nothing is corrected by hand to carry on.
- Verdict: "RÉUSSI" if all of the above is true; "ARRÊT" if Defender is weakened or outside Normal mode; "INVALIDE" (D)
  otherwise, separating the prerequisites (binary, re-evaluation, build), the configuration deviations and the product defects
  (disagreement between the baseline and Defender, alert during the observation).
- Evidence: `baseline.json`, `baseline-sauvegarde.json`, messages of the two application commands, Get-MpPreference and
  Get-MpComputerStatus before and after, comparison table, cross-check of the Defender rules, hash of the binary, state of
  Remote Desktop, of LSA protection, of the Security log, of the firewall and of controlled folder access.
- Measurement (v1.6, 2026-11-20, trial 3, only trial on v1.6; trials 1 and 2 of 2026-11-15 were on v1.3;
  executed before the publication of this sheet, see the version 1.6 entry): service built from the head of #221
  (eb399a4, not merged at the time of the trial; `main` c64e64e plus message changes only), service
  binary A67EDD13, Windows 11 build 26300: **"RÉUSSI"**. Preparation: the
  Remote Desktop rule left aside by the profile and stated, then applied alone; scores 100/100/100. S-19: 28 Defender
  settings compared, 0 weaker, Normal mode, 0 exclusion; 21 Defender rules cross-checked, 0 disagreement; Remote
  Desktop refused (3389 closed); RunAsPPL = 2 and Wininit 12 later than A; Security log 1 GiB; firewall active,
  Public inbound blocked; 0 Alert/Critical alert and 0 BAS-001 in 25 min.

### 3.2 Negative tests

| Id | Legitimate activity | Expected | Expected in configuration C (HYPOTHESIS) |
|---|---|---|---|
| N-01 | local sessions, PowerShell administration through a signed file | no Alert/Critical | identical; no alert due to the baseline |
| N-02 | scheduled task created by an administrator pointing to a signed program in Program Files | PER-001 Info at most | identical |
| N-03 | authorised download from Kali by the browser | no RES-002; RES-003 Info accepted | identical; SmartScreen warning when opening the file, without alert from deR4Tizer |
| N-04 | one password error then success in Remote Desktop | no COR-R1/R2; COR-R9 remains expected (the whole lab is "public" for the service) | not executable (Remote Desktop refused): D in C, measured in A |
| N-05 | DNS setting returned to DHCP (after S-06) | negative control: DNS-002 does not trigger on return to DHCP (change given by the network: mini-SIEM event, without alert) | identical |
| N-06 (v1.7) | Run value pointing to a signed program in Program Files, without argument | PER-001 Info at most | identical |
| N-07 (v1.7) | service declared pointing to a signed program in Program Files, manual start, never started | no COR-R5; 7045 produced; PER-001 Info at most | identical |
| N-08 (v1.7) | test account added to a non-administrator local group | no COR-R3 or COR-R3b | identical |
| N-09 (v1.7) | audit policy read by the administrator, then local policies reapplied by the system | no COR-R7, no BAS-001 | identical |
| N-10 (v1.7) | log dedicated to the test exported to a file, without clearing | no COR-R4; no 104 | identical |
| N-11 (v1.7) | the test program of S-16 writes into an ordinary file next to a decoy | no LEU-001 or LEU-002, no suspension | write possibly refused by controlled folder access: control D in C, measured in A |
| N-12 (v1.7) | Kali present on the lab segment, no NDR emitter active, during a full cycle of the decoy | no EXP-NDR-001 Alert or Critical; decoy emitted, without response | identical |
| N-13 (v1.7) | emulated box that announces a redirection to another address of the segment, not to this PC | no EXP-NDR-001; UPnP state "dont 0 vers ce PC" | identical |

### 3.2 bis Sheets of the controls added in v1.7

Common: negative test (legitimate activity close to a line of lot 4). An FP is an Alert or Critical alert linked to the
control (D-1 and D-3 apply). The control is valid only if the activity actually took place, proven by the event
indicated; otherwise D. The expected results in configuration C are a HYPOTHESIS. Common evidence (3.0) in addition to the specific evidence.

**N-06: Run value pointing to a signed program (close to T1547.001, S-09)**
- Preconditions: snapshot of the configuration; collection of automatic start-ups "Active"; reference reading noted.
- Action: a Run value of the test user, distinct name per trial, pointing to a signed program in Program Files,
  without argument.
- Expected: PER-001 Info at most (new entry, without remark). Delay: 180 s.
- Cleanup: value deleted; disappearance observed at the next reading.
- Evidence: `demarrage.json` before and after, registry value before and after.
- Configuration C: identical.

**N-07: signed service in Program Files (close to T1543.003 and T1569.002, S-13)**
- Preconditions: snapshot of the configuration; System log readable.
- Action: a service, distinct name per trial, declared pointing to a signed program in Program Files, with manual start;
  never started; no interpreter command line.
- Expected: 7045 produced; no COR-R5; PER-001 Info at most. Delay: 120 s after the 7045.
- Cleanup: service deleted; reset to the snapshot after the control.
- Evidence: 7045, list of services before and after.
- Configuration C: identical.

**N-08: account added to a non-administrator group (close to T1098, S-13)**
- Preconditions: snapshot of the configuration; audit of accounts and groups active.
- Action: a test account, distinct per trial, created then added to a non-administrator local group.
- Expected: 4720 and 4732 produced; no COR-R3 or COR-R3b. Delay: 120 s after the 4732.
- Cleanup: account deleted; reset to the snapshot.
- Evidence: 4720, 4732 (target group).
- Configuration C: identical.

**N-09: audit policy read, policies reapplied by the system (close to T1685.001, S-13)**
- Preconditions: snapshot of the configuration; audit policy read.
- Action: the administrator reads the audit policy, without changing anything, then requests the update of the local
  policies; their application is done by the system.
- Expected: no COR-R7 (a 4719 emitted by the system is not retained by the service); no BAS-001. Delay: 120 s
  after the update. Any 4719 produced is recorded with its emitter.
- Cleanup: none; audit policy compared before and after; reset to the snapshot.
- Evidence: audit policy before and after, possible 4719.
- Configuration C: identical.

**N-10: dedicated log exported without clearing (close to T1685.005, S-13)**
- Preconditions: a dedicated log created for the control, distinct per trial.
- Action: export of the dedicated log to a file, without clearing.
- Expected: no 104; no COR-R4. Delay: 120 s.
- Cleanup: export and dedicated log deleted; reset to the snapshot.
- Evidence: list of logs, System log over the window.
- Configuration C: identical.

**N-11: ordinary file next to a decoy (close to T1486, S-16)**
- Preconditions: as S-16 (decoys set, collection `Leurres` active).
- Action: the test program of S-16, distinct copy per trial, writes one byte into an ordinary file in the same
  folder as a decoy; no decoy is touched.
- Expected: no LEU-001 or LEU-002, no suspension. Delay: 60 s.
- Cleanup: file and program deleted; reset to the snapshot.
- Evidence: hashes of the decoys before and after, `reponses.json`.
- Configuration C: write possibly refused by controlled folder access (1123). The activity does not take place: control
  D in C, measured in A.

**N-12: segment without emitter (close to T1557.001 and T1557.002, S-20 to S-26)**
- Preconditions: common rules of §7 (restart included); no emission unit active on the Kali side.
- Action: none; observation from the start-up of the service, which is the start time.
- Expected: decoy emitted without response (`reseau.json`); no EXP-NDR-001 Alert or Critical. Delay: 180 s after the
  start-up of the service. Valid only if the decoy was emitted within the 120 s following start-up.
- Cleanup: reset to the snapshot.
- Evidence: evidence of the restart (7.0), `reseau.json` (time and result of the decoy), state of the units on the Kali side.
- Configuration C: identical.

**N-13: UPnP redirection to another machine (close to T1133, S-27)**
- Preconditions: as S-27 (emulated box started before the restart of the service).
- Action: the emulated box announces a redirection of a port to another address of the segment, not to this PC.
- Expected: box discovered; state "1 redirection(s) sur la box, dont 0 vers ce PC"; no EXP-NDR-001. Delay: 180 s
  after the start-up of the service. Valid only if the box is discovered within the 120 s following start-up.
- Cleanup: as S-27.
- Evidence: evidence of the restart (7.0), `reseau.json` (UPnP state), log of the emulated box.
- Configuration C: identical.

### 3.3 Excluded, not executed or pending

- T1567: D (no real web service authorised; a lab substitute would be T1041).
- T1055: not executed; no injection, even benign, without explicit agreement; no sensor consumed.
- T1562.001 against Defender, the Windows logs or deR4Tizer: D (forbidden).
- DNS-003: requires the stop then the relaunch of the service; **approved in v1.1** (5.2), became S-18; filtering present in
  `main` (5.5): S-18 testable.
- T1562.002 part of S-13: **approved in v1.1** (5.2), executed within S-13.
- **S-06 (DNS-002 + DNS filtering): testable (v1.4).** Code present in `main`; sheet rewritten at the level of behaviour
  (3.1). The "code absent" error of an initial draft came from a stale checkout (5.5). N-05 is a normal negative
  control.
- In configuration C only (v1.3): S-01, S-02, S-05 (a) and N-04 not executable as detection (Remote Desktop
  refused), S-16 expected prevented; measured in A. The trial in C remains a prevention measurement.
- Atomic sheets that download, disable a protection, read the memory of LSASS or clear a real log:
  excluded by default.

---

### 3.4 Repetition protocol for the 10 trials (v1.7, lot 4 of the ATT&CK coverage)

Applies to the consolidation series: S-02, S-09, S-11 (a), S-13, S-14, S-16, S-17, S-20, S-22 (optional), S-23,
S-25, S-26, S-27 and to their controls. It makes the execution precise without changing the actions, expected results or cleanups of the sheets.

1. **Count.** 10 valid trials per scenario and per configuration. An invalid trial (D) is replaced by an additional
   trial. The report gives the trials executed, valid, TP, C, FN, D and P, and the number of detections. Scores
   separate per configuration; P counted separately; SIMULATION and emulation parts never merged (S-13 scored per part).
2. **Reset to the snapshot of the configuration before each trial, except S-09.** S-09 chains its 10 trials in the
   same session, with a reset at the start and at the end of the series. Between two trials of S-09, the cleanup is proven by
   the next reading of the automatic start-ups (entries absent from `demarrage.json`) before the following trial.
3. **After each reset**, before the start time: clock of the VM resynchronised, end of Windows maintenance
   observed, criterion D-2 checked for each collection on which a rule of the scenario depends.
4. **Distinct targets at each trial**: task name, Run value name, service name (distinct in its first 20
   characters), test account, dedicated log, copy of the test program in a folder specific to the trial. The form of
   the action does not change: same type of folder, same interpreter, same benign command.
5. **Learning finished before the first trial.** State of learning read (end passed) at the start of each
   series. On a fresh installation, learning is finished by the administrator's command before any trial,
   and the first reading of the automatic start-ups has passed.
6. **Level checked.** A TP requires the expected rule, level and entity. An alert of the right rule at level
   "Info" with the mention "mode apprentissage" or "comportement appris" is scored C; the series stops until
   the configuration is explained.
7. **Actions of S-13 outside SYSTEM.** They are done by the administrator test account, in an elevated session.
   The emitter of the 4719 is recorded; a 4719 emitted by the system makes the trial invalid (D).
8. **Restart of the service: network sheets only** (decision of the maintainer of 2026-11-22). For S-20 to S-27, N-12
   and N-13, the administrator account of the bench stops then starts the deR4Tizer service through the Windows service
   manager, after the reorientation of the adapters and at the latest at the start time of the trial, with the evidence of 7.0.
   Elsewhere (S-02, S-09, S-11, S-13, S-14, S-16, S-17 and the other controls), the bench never stops or restarts the
   service. The restart does not replace the reset to the snapshot before each trial. S-18 remains outside the lot.
9. **Latency.** Main: `HeureUtc` of the alert minus `TimeCreated` of the triggering event, read on the clock of
   the VM. For the NDR: minus the time of emission of the decoy or of the UPnP reading (`reseau.json`), or minus the first
   observation in the VM (duplicate MAC address, threshold query). Secondary: minus the start time. Median and p95 per
   scenario and per configuration. A latency between machines is corrected by the clock offset recorded.
10. **Observation window.** Maximum delay of the sheet. In lot 4, BAS-001 (25 min) is not expected:
    "NON ÉVALUÉE", unless it is observed within the window. The T1685.001 line is judged on COR-R7.
11. **Controls.** Each control of the scenario (N-01 to N-13 as the case may be) is executed at least 3 times per configuration.
12. **Versions noted**: commit of `main` of the binary, SHA-256 hashes of the MSI and of the service, version of the list,
    Windows build, Sysmon (version and configuration, in B) or "absent", Atomic Red Team (version, in B; no
    sheet used) or "absent", snapshot and type of checkpoint.
13. **Stop.** Incomplete evidence or an unclean environment stops the series before the next trial.

## 4. Lab prerequisites to check before S-01

1. Network: target VM and Kali alone on `d4t-labo`; "Default Switch" of the VM unplugged; administration link without
   a route to the VM; no route to the Internet during the campaign.
2. Addresses: target VM and Kali in the RFC 5737 documentation range; secondary address of Kali reserved for S-07 (documentation
   range); network profile of the VM adapter read, Remote Desktop and file sharing allowed on this
   profile.
3. Clocks: offset between VM, Kali and host read at the start and at the end of each lot.
4. Campaign snapshots "campagne A", "campagne B" and "campagne C" present, prepared outside the campaign, each with
   deR4Tizer installed, learning finished, the test accounts and the lab settings; no name starts with
   "propre"; "propre" snapshot present for the return after the campaign only; Defender active, without exclusion,
   state read in each snapshot.
5. deR4Tizer: version and hash of the MSI; service running; no "Inconnue" collection; "logging" profile
   compliant; state of learning; source of processes (Sysmon or WMI) read. **Source version aligned with the
   installed binary recorded** (for S-06/S-18): confirm that the installed binary indeed matches the source of `main`
   (after the merges of phase 7.3/7.4) that exposes DNS-002 and filtering, before measuring these rules.
6. Independent collection: 4688, 4104, Task Scheduler, Defender, Sysmon (configuration noted) readable and exportable.
7. Test accounts created, lockout threshold read; no password in any evidence.
8. Kali: tools and versions noted; HTTP server and lab DNS upstream ready (S-07, S-11, S-06);
   timestamped log.
9. Collection of the evidence on the VM (PowerShell Direct) dry-run on N-01, in configuration A and in configuration C.
10. "campagne C": prepared from "campagne A" (service from `main` in A and C, hash noted); reference reading
    of Defender and of `baseline.json` taken before the application; baseline applied by the service (three profiles
    in one command, then `reseau.bureau-distance` alone); restart; S-19 passed; snapshot taken afterwards.

---

## 5. Design decisions and points left to the maintainer

### 5.1 Decisions taken by the validation agent (v1.0; 2 and 3 revised in v1.2; 2 revised and 11 added in v1.3; 5 corrected in v1.4)

1. **Learning finished in the campaign snapshot.** The normal regime of a machine after its first 7
   days is measured. The end of learning is recorded in each report; a measurement during learning may come later,
   noted separately.
2. **Three configurations, never merged** (revised in v1.2; in v1.3, C added and made the main one, 5.1.11).
   Configuration A "without Sysmon": independent collection through the native logs. Configuration B "with Sysmon":
   Sysmon and Atomic Red Team. Both prepared outside the campaign, learning finished, test accounts and lab
   settings; none starts from "propre". Scenarios without processes (COR-*, DNS, IPC-03, D4-1): A is enough; PRC and
   persistence scenarios: both.
3. **Reset to the campaign snapshot before each trial of the correlation scenarios** (S-01 to S-04, S-13, S-17;
   revised in v1.2). The one-hour deduplication and the 30-min failure window are in memory; without a reset, the
   trials are not independent. The reset targets the snapshot of the configuration, never "propre". The VM goes back to
   "propre" only after the campaign.
4. **Lab DNS resolver on Kali**, on `d4t-labo` only, for a `.test` zone and the lab names, without relaying
   to the Internet. Reason: to exercise DNS-001 (S-07) without Internet; phase 7 filtering (S-06) also requires it (upstream of the local
   resolver). Tool on the Kali side, outside the test VM.
5. **Restricted lists enabled for S-07, with local synthetic lists** (`.test` names, secondary address of
   Kali), set by an administrator, erased by the reset to the snapshot. **Correction v1.4:** the threat address
   is placed in a **high confidence source** (for example a botnet C2 list or a DROP block), **and not in
   a reputation source (for example a level 3)**: only a high confidence source triggers the 7-day automatic
   blocking (v1.3 wrongly spoke of a "level 3 list"). Without these lists, DNS-001 and RES-001 cannot
   trigger in a lab without Internet; no third-party content is used. The main address of
   Kali is never listed (otherwise the automatic blocking would cut off the lab).
6. **T1070.001 in SIMULATION on a dedicated log created for the test**: retained (no existing Windows log is
   touched). **T1562.002**: modifies Windows logging; first left to the maintainer, then **approved in v1.1**
   (5.2), executed within S-13 with verified restoration.
7. **Long option of S-16 (REP-001 at 2 h)**: retained, one observation per configuration, reported as not consolidated.
8. **T1555.003 (S-14) added**, in SIMULATION: test account without any saved password, opening for reading
   then closing, no copy, no decryption. S-15 (LSASS with "limited information" access) stays in the form
   provided for by the instruction.
9. **Classification**: T1567 in D; T1055 not executed (D); B1 and B2 remain subdivisions of B; **class E** reserved
   for what is frozen (IDS/DPI/NDR). S-06 is no longer in E: the code of DNS-002 and of filtering is present in `main` (5.5).
10. **Publication**: this document, once transmitted to the maintainer, is proposed under `docs/validation/` through a
    documentation-only PR, after the PII guard; the merge remains decided by the maintainer.
11. **Configuration C, main measurement configuration (v1.3), on decision of the maintainer of 2026-11-14**: the Kali tests are done
    with the deR4Tizer baseline applied at 100 % (decision quoted as is: « pour les tests kali, tu as bien pris
    en compte d'avoir la baseline à 100% ? C'est l'un des interêts du produit » (for the Kali tests, did you take into account having the baseline at 100%? It is one of the points of the product), then « ok parfait » (ok perfect)). The baseline is
    applied by the service itself; it only hardens Defender, which S-19 checks: rule 2 of `CLAUDE.md`
    remains whole. Reversible effect, confined to the test VM. A remains the comparison, B the Sysmon collection.

### 5.2 Points escalated to the maintainer, decided on 2026-11-14

These two parts went beyond the mandate of the agent (Windows logging or the service itself) and had been left to the
maintainer in v1.0. **Decision of the maintainer, 2026-11-14, quoted word for word: « J'autorise les deux » (I authorise both).** The two parts
go from not approved to approved in v1.1. It is a decision of the maintainer, not an approval by the agent (which remains
neither human nor independent and lifts no rule). v1.1 is transmitted to him, for information, before any execution;
he may withdraw a scenario or take back the approval at any time.

1. **T1562.002 part of S-13** (temporary disabling of an audit subcategory, then restoration): touches
   Windows logging. **Approved in v1.1.** S-13 executes it; cleanup with verified restoration (subcategory
   returned to its initial state, before/after comparison) then reset to the snapshot. No other subcategory or
   other audit setting is touched.
2. **DNS-003** (became S-18): requires stopping the deR4Tizer service, having port 53 held by another program, and
   relaunching the service. **Approved in v1.1**; only exception to the "deR4Tizer intact" principle, resting on this
   written decision. Cleanup with verified restoration (listener program stopped, port 53 freed, service relaunched and
   checked) then reset to the snapshot. Filtering present in `main` (5.5): S-18 is testable.

### 5.3 Product defects found on reading (added in v1.3)

**D-BAS-01: two baseline rules write the same registry value.** Reading finding of `baseline.rs` and
`gpo.rs` at `ede269f`, not measured in a VM.
- `defender.dossiers-audit` (recommended profile) and `defender.dossiers-blocage` (hardened profile) both set
  `EnableControlledFolderAccess`: 2 (audit) for one, 1 (block) for the other. Applied together, the block, written
  last, prevails (reading HYPOTHESIS, checked by S-19).
- `evaluer` compares rule by rule: `defender.dossiers-audit` is then seen as "non conforme" and the recommended profile cannot
  reach 100 %. **A compliance of 100 % on all profiles is therefore impossible.**
- Effects: a rule displayed "non conforme" while the effective setting is stronger; and, if the recommended
  then hardened profiles are applied by two successive commands, a BAS-001 "réglage modifié hors de deR4Tizer" would be
  raised wrongly (reading HYPOTHESIS, not measured).
- Proposed fix, minimal, submitted to the usual circuit: declare the two rules exclusive, the stronger replacing
  the weaker. Non-regression tests described. Effect on detection: none; removes a false "non conforme" and a
  possible false positive of BAS-001.
- Effect on the campaign: S-19 expected the recommended profile below 100 % (v1.3 to 1.5); this finding was not a failure
  of S-19.
- **Fixed**: review of the baseline of 2026-11-20, lot B3 (`PLUS_STRICTES`: controlled folder access in
  block mode satisfies the audit rule, and the write of the audit is withheld when the block is in place, PR #216).
  **Confirmed in a VM** by S-19 v1.6 (2026-11-20, trial 3): recommended profile at 100 %.

**Point to check P-BAS-02**: `systeme.lsa` (LSA protection) is seen as compliant as soon as the registry value is set,
while it only acts after a restart. Defect not established: S-19 checks the effective protection after restart
(v1.6: Wininit event 12 later than "campagne A"; checked on 2026-11-20). Still open: the rule remains judged
on the registry alone.

### 5.4 Decision rules D-1 and D-2 (added in v1.4, decided by the validation agent)

Two scoring rules that confirm and formalise proposals of the first pass. They lift no rule
of the mandate; they frame the count and the validity of the trials. Transmitted to the maintainer, for information.

**D-1 · RES-004 / RES-005 ("PC exposé à Internet") on a lab address: lab exposure artefact.**
- Cause established on reading: the documentation range of the lab is considered **"public"** by the service (neither
  private, nor local, nor reserved). Inbound traffic from Kali (brute force, scan) is read as a **real
  exposure** and raises RES-004/RES-005. On a real machine with a real public address, these alerts would be **true
  exposure positives**; filtering them would degrade a legitimate detection.
- **Rule (in all scenarios, including the negative tests):** an **RES-004/RES-005** alert whose peer
  address **belongs to the documentation range of the lab** is labelled **"lab exposure artefact"** and
  **excluded from the count of TP as of FP**. Before excluding, **check the peer address**: any RES-004/005 carrying
  an address **outside** the lab range is **investigated** (never excluded by default). These alerts are **kept in the
  raw evidence**.
- **No product fix**: the behaviour is correct on a real machine.

**D-2 · "Indisponible" collection criterion after snapshot restore.**
- Finding: a long-cycle collection may appear "Indisponible" just after a restore (last success dated from
  the taking of the snapshot), without a real failure of the telemetry.
- **Rule:** a collection **not exercised** by the scenario is **set aside from the verdict** only if the proven cause is
  "no reading since the restore". Any collection **on which a rule of the scenario depends** must be **"Active" at the
  start**, proven by a **successful reading after the restore**; otherwise the trial is **invalid (class D)**,
  **never counted 0**.
- **Application:** S-14, "data audit" collection Active (at least one audited reading since the restore, through
  a legitimate priming) before the trial; S-07, "threat lists" and "domain lists" collections Active (synthetic
  lists actually loaded) before the trial.
- **Postponed to phase 5 (product question, not blocking):** on a real machine coming out of a long sleep, does an
  event-driven or periodic collection wrongly go "Indisponible"? To be instrumented in phase 5, without impact on the
  scoring of the campaigns.

### 5.5 Correction v1.4: S-06 (DNS-002 and DNS filtering): "code absent" error of an initial draft

An initial draft of v1.4 asserted that the code of **DNS-002** and of **DNS filtering** (local resolver) was
"absent from the source", classed **S-06 in class E / awaiting the maintainer** and escalated four questions to the
maintainer. **This premise was false.** It came from a **stale working checkout** (branch `passages-en-vm`),
older than the merges of phase 7.3/7.4.

On reading the **full, up-to-date worktree of `main`**, the code is indeed present:
- **DNS-002**: `dns_surveillance.rs` (reading of the DNS servers of the adapters every 60 s; a static server changed
  on a physical adapter raises the rule `DNS_002`, level Alert), rule declared in `regles.rs`.
- **DNS filtering**: local resolver on `127.0.0.1:53` and `[::1]:53` (`dns_local.rs`), filtering engine and state
  (`filtrage.rs`, `EtatFiltrage`, `filtrage-etat.json`, latest blocks), activation on the adapters
  (`filtrage_cartes.rs`, administrator's `filtrage` command, phase 7.4, setting of the adapters as SYSTEM granted by the
  maintainer), **DNS-003** through the "port DNS tenu" alert (`alerte_port_dns_tenu`, Critical, at the start-up of the service).
- The **capability matrix** (`capability-matrix.md`) lists DNS-002, the filtering engine, the local resolver,
  the state/DNS-003 and Quad9.

**Consequences:** S-06 is **testable**, its sheet is rewritten at the level of behaviour (3.1); DNS-003 (S-18) is
testable (5.2); N-05 is a normal negative control (3.2). **There is no blocking question to the maintainer on this
point.** Only caution kept, not blocking: before measuring, confirm that the **installed binary** in
the test snapshot indeed matches this source of `main` (hash of the MSI and version recorded, section 4, point 5).

### 5.6 Decision rule D-3 (added in v1.7, decided by the validation agent)

**D-3: PER-001 or PER-002 of the execution task of the bench, bench artefact.**
- Reading finding (`persistance.rs`, `tests/vm/lancer.ps1`): the bench launches its executor through a scheduled task
  (interpreter, hidden window), which the reading of the automatic start-ups sees as a new and
  suspicious persistence.
- **Rule:** a PER-001 or PER-002 that concerns the execution task of the bench is labelled "bench artefact" and
  excluded from the count of TP as of FP, including in the controls. Three conditions, all checked: name of the
  task identical to the one the bench recorded; command identical to the one it recorded; creation
  earlier than the start time of the trial.
- Any other PER-001 or PER-002 is investigated, never excluded by default. The excluded alerts are kept in the
  raw evidence.
- No product fix: on a real machine, this task would be a real suspicious persistence.

## 6. Version 1.5 (2026-11-19): network detection scenarios S-20 to S-27, approved after execution

Added to the approved list on 2026-11-19 on decision of the maintainer (« Scénario S20 à S27, il faut les ajouter à la
liste approuvée » (Scenarios S20 to S27 must be added to the approved list), `CLAUDE.md`, Kali campaign). **Approval after the fact**: these scenarios were designed in the
"network detection" design file (outside the repository) and executed from 2026-11-16 to 2026-11-17, before being recorded here.
Levels and techniques according to the code (`ndr.rs`, `ids.rs`). Nature: benign and reversible emulation from the Kali VM,
on the laboratory segment (topology granted on 2026-11-19).

| Id | Behaviour | Technique | Expected rule and level | Report |
|---|---|---|---|---|
| S-20 | ARP spoofing of the gateway (two addresses on the same MAC address) | T1557.002 | EXP-NDR-001 Critical | `campagne-kali-detection-reseau-lot2.md` |
| S-21 | rogue DHCP server (a second server on the segment) | T1557.003 | EXP-NDR-001 Critical | "network detection" lot 2 and lot 5 (to be remeasured after PR #190) |
| S-22 | LLMNR responder that answers the active decoy | T1557.001 | EXP-NDR-001 Critical | `campagne-kali-detection-reseau-lot1.md` |
| S-23 | passive LLMNR responder (at least 3 names) | T1557.001 | EXP-NDR-001 Alert | `campagne-kali-detection-reseau-lot2.md` |
| S-24 | traffic carrying the pattern of the built-in test IDS rule (sid 9000000) | none set by the code | EXP-IDS-001, level of the rule | `campagne-kali-detection-reseau-lot1.md` |
| S-25 | real NBNS responder that answers the active decoy (NBNS leg of the decoy) | T1557.001 | EXP-NDR-001 Critical | `campagne-kali-detection-reseau-lot2.md` |
| S-26 | passive mDNS responder (at least 15 names) | T1557.001 | EXP-NDR-001 Alert | `campagne-kali-detection-reseau-lot3.md` |
| S-27 | UPnP redirection of a port to this PC announced by the emulated box | T1133 | EXP-NDR-001 Alert | `campagne-kali-detection-reseau-lot4.md` |

For each one: preconditions and cleanup described in its report; reset to the snapshot before and after each trial;
expected result = the alert above within the delay of the NDR cycle; measurements not consolidated as long as there are not 10
valid trials. Not covered: passive NBNS responder (not exercised), directional and content IDS, IPS mode.

## 7. Version 1.7 (2026-11-22): full sheets of S-20 to S-27

Approved by the validation agent on 2026-11-22. They complete the table of §6 without changing the expected behaviour, rule
or level. Nature: benign and reversible emulation from the Kali VM, on the lab segment. The expected results in
configuration C are a HYPOTHESIS when they do not rely on a quoted measurement.

### 7.0 Common rules (revised in v1.8)

- Start: snapshot of the configuration. Reversible reorientation of the VM onto the lab segment (other adapters
  disabled, gateway set on the lab adapter; topology granted on 2026-11-19).
- **Restart of the service (v1.8, decision of the maintainer of 2026-11-22)**:
  - Who and how: the administrator account of the bench stops then starts the deR4Tizer service through the Windows
    service manager.
  - When: after the reorientation, and after the start of the emitter on the Kali side when the sheet requires it (S-22, S-25,
    S-27, N-13). At the latest at the start time of the trial.
  - Start time: for S-22, S-25, S-27, N-12 and N-13, it is the start-up of the service, since the decoy and the UPnP
    reading start at the first iteration of the NDR (`ndr.rs`). For S-20, S-21, S-23, S-24 and S-26, it is the start of
    the action, after the evidence below.
  - Evidence, recorded within the minute following start-up: stop and start times (System log and
    `journal.txt`); channel reachable (a status request gets a response); state of the collections noted. The collections
    "capture réseau local" and "capture trafic" must be "Active" on the address of the lab segment, according to the
    line "capture des paquets (…) active sur <adresse>" of the service log. DNS filtering must be disabled,
    state recorded; S-18 remains outside the lot.
  - Failure: a service that does not restart, a silent channel or a capture opened on another address give a D trial, followed
    by a reset to the snapshot.
  - Side alerts: the stop of deR4Tizer is noted at Info level (no COR-R7 expected, reading HYPOTHESIS). An
    Alert or Critical alert between the stop and the start time is noted separately and investigated; it counts neither as
    TP nor as FP of the scenario.
  - The restart does not replace the reset to the snapshot before each trial.
- Network D-2 criterion: `reseau.json` rewritten after start-up, with the address of the lab segment as local address;
  otherwise D. For S-21, S-23, S-24 and S-26, the capture proven active on the lab adapter, as above, is required;
  otherwise D, never FN.
- Kali side: systemd units frozen and auditable, root rights bounded to these units, no password typed; a single
  behaviour per trial; timestamped log.
- Delay: counted from the reference event of the sheet. An absence of alert within the delay, preconditions held,
  is an FN.
- Common cleanup: unit stopped and stop proven on the Kali side; secondary addresses of Kali removed and removal checked;
  reset to the snapshot after the trial.
- Common evidence: 3.0; evidence of the restart; `reseau.json` before and after; state of the collections; log on the
  Kali side; clock offset between the VM and Kali.
- Controls: N-12 (S-20 to S-26), N-13 (S-27).

**S-20: ARP spoofing of the gateway (T1557.002)**
- Preconditions: 7.0, restart included; gateway of the VM held by Kali; neighbour table of the VM read.
- Action: after the evidence of the restart, Kali announces an unused address of the segment under its own MAC address.
  In the neighbour table of the VM, two addresses (the gateway and the unused address) then share the same MAC.
- Validity: duplicate MAC observed in the neighbour table of the VM; otherwise D.
- Expected: EXP-NDR-001 Critical "usurpation ARP probable" (T1557.002). Delay: 120 s after the first observation of
  the duplicate MAC (ARP reading every 10 s).
- Cleanup: announcements stopped; 7.0.
- Evidence: timestamped neighbour table, alert.
- Configuration C: identical (measured on 2026-11-16, not consolidated).

**S-21: rogue DHCP server (T1557.003)**: outside lot 4, to be remeasured after PR #190.
- Preconditions: 7.0, restart included; VM on DHCP with a lease from the legitimate DHCP server of the lab; DHCP server of
  the adapter read as non-empty by the service (`reseau.json`), otherwise D.
- Action: after the evidence of the restart, a second emitter of the segment sends unsolicited DHCP offers, with a
  server identifier different from that of the lease.
- Expected: EXP-NDR-001 Critical "serveur DHCP pirate" (T1557.003). Delay: 120 s after the first captured offer.
  Reservation: the server identifier is controlled by the emitter.
- Cleanup: emitter and legitimate server stopped; 7.0.
- Evidence: lease of the VM, captured offers, alert.
- Configuration C: identical.

**S-22: LLMNR decoy, responder without root rights (T1557.001)**: optional in lot 4 (S-25 covers the same path).
- Preconditions: 7.0; user-space LLMNR responder started before the restart of the service.
- Action: the service starts; the responder answers the non-existent name that the decoy queries at the first iteration of the
  NDR.
- Validity: emission of the decoy (`reseau.json`) within the 120 s following the start-up of the service; otherwise D (case of the
  decoy skipped after a binding failure, finding of the first network lot).
- Expected: EXP-NDR-001 Critical "empoisonnement LLMNR/NBNS" (T1557.001). Delay: 180 s after the start-up of the service,
  and 60 s at most after the emission of the decoy.
- Cleanup: responder stopped; 7.0.
- Evidence: evidence of the restart, time and result of the decoy, log of the responder, alert.
- Configuration C: identical (the decoy comes from the service, whatever the LLMNR policy of the client).

**S-23: passive LLMNR responder, at least 3 names (T1557.001)**
- Preconditions: 7.0, restart and proven capture included; response unit active on the Kali side.
- Action: after the evidence of the restart, the VM resolves, through the Windows DNS client, at least 6 distinct non-existent
  `.test` names; the responder answers each one.
- Validity: at least 3 distinct responses from the same host captured; otherwise D.
- Expected: EXP-NDR-001 Alert "répond en LLMNR pour au moins 3 noms" (T1557.001). Delay: 120 s after the 3rd captured
  response.
- Cleanup: unit stopped; 7.0.
- Evidence: queries emitted (times), captured responses, alert.
- Configuration C: **prevented (P-baseline)**: LLMNR disabled on the client side by the baseline (measured on 2026-11-16), no
  query emitted. Counted separately, outside the detection score.

**S-24: pattern of the built-in test IDS rule (sid 9000000)**: outside lot 4.
- Preconditions: 7.0, restart and proven capture included; IDS rules loaded.
- Action: after the evidence of the restart, Kali sends three datagrams carrying the pattern of the built-in test rule.
- Expected: EXP-IDS-001 at the level of the rule (Info). Delay: 60 s after the first datagram.
- Cleanup: 7.0.
- Evidence: state of the IDS (rules loaded), alert.
- Configuration C: identical.

**S-25: LLMNR and NBNS decoy, root responder (T1557.001)**
- Preconditions: 7.0; LLMNR and NBNS response unit active on the Kali side, without DHCP or WPAD poisoning, started before
  the restart of the service.
- Action: the service starts; the responder answers, in LLMNR and in NBNS, the non-existent name that the decoy queries at the
  first iteration of the NDR.
- Validity: as S-22. The result of the decoy must show a response on both protocols; a response on only
  one is noted.
- Expected: EXP-NDR-001 Critical "empoisonnement LLMNR/NBNS" (T1557.001). Delay: 180 s after the start-up of the service,
  and 60 s at most after the emission of the decoy.
- Cleanup: unit stopped; 7.0.
- Evidence: evidence of the restart, time and result of the decoy, log of the unit, alert.
- Configuration C: identical (measured on 2026-11-16, not consolidated).

**S-26: passive mDNS responder, at least 15 names (T1557.001)**
- Preconditions: 7.0, restart and proven capture included; mDNS response unit active on the Kali side.
- Action: after the evidence of the restart, a test program of the VM emits at least 20 mDNS queries for distinct
  names, directly on the network, without going through the Windows mDNS client; the responder answers each one.
- Validity: at least 15 distinct responses from the same host captured; otherwise D.
- Expected: EXP-NDR-001 Alert "répond en mDNS pour N noms" (T1557.001). Delay: 120 s after the 15th captured response.
  S-26 measures the detector, not the mDNS posture of the client.
- Cleanup: unit stopped, test program deleted; 7.0.
- Evidence: queries emitted (times), captured responses, alert.
- Configuration C: identical (measured on 2026-11-16, not consolidated).

**S-27: UPnP redirection of a port to this PC (T1133)**
- Preconditions: 7.0, plus a reversible re-addressing of the segment in 192.168.50.0/24 (VM, and secondary address of
  Kali), done before the restart: the UPnP module only queries private addresses (topology granted on
  2026-11-19). In this addressing, COR-R9 and the D-1 artefacts are not expected. User-space emulated box,
  on the Kali side, started before the restart of the service.
- Action: the service starts; at the first iteration of the NDR, the emulated box answers the UPnP discovery and announces a
  redirection of a port to the VM.
- Validity: box discovered by the service (UPnP state of `reseau.json`) within the 120 s following start-up; otherwise D.
- Expected: EXP-NDR-001 Alert "la box ouvre le port … vers ce PC" (T1133); state "dont 1 vers ce PC". Delay: 180 s
  after the start-up of the service, and 60 s at most after the UPnP reading.
- Cleanup: emulated box stopped; secondary address of Kali removed and removal checked; 7.0.
- Evidence: evidence of the restart, UPnP state before and after, log of the emulated box, alert.
- Configuration C: identical (measured on 2026-11-16, not consolidated).
