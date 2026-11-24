# Kali campaign: first pass

Date: 2026-11-15. List of scenarios: v1.3 (`campagne-kali-phase1.md`). Raw results outside the repository.

> **Note of 2026-11-19** (documentation audit; the results below are not rewritten): (1) The postponement of S-06 rested on a false premise ("filtering code absent from the checkout"): `campagne-kali-phase1.md`, §5.5, corrects it; S-06 was measured in the third and fourth lots. (2) The COR-R3 finding remains open, not fixed in the code as of 2026-11-19. (3) Apart from S-01 in configuration A (10 trials), no number of trials is given: measurements not consolidated; the simulated parts of S-13 are SIMULATIONS, not marked as such.

> **Note of 2026-11-20**: S-19 was replayed in v1.6 after the review of the baseline (trial 3: "RÉUSSI", recommended profile at 100%, D-BAS-01 confirmed fixed). This report of 2026-11-15 stays as it is; the sheet and the measurement are in `campagne-kali-phase1.md`, S-19.
No personal data, no workstation name, no password. Lab addresses: documentation ranges (RFC 5737),
not routable.

**Reservation (latencies)**: no latency is reported at this stage. The VM clock is ~9 h behind the host's
in the raw results; the latencies will be measured in phase 4, after normalisation to UTC from the recorded clock
offset (precondition 4.3). The TP verdicts rest on the presence of rule/level/entity, not on the time.

## Measurement chain validated

Three checks establish that the chain (behaviour → Windows event → collection → correlation → alert → incident)
works, in both configurations, before any consolidated offensive measurement.

| Scenario | Configuration | Verdict | Summary |
|---|---|---|---|
| N-01 (chain control, negative) | A (without baseline) | "RÉUSSI" | Legitimate activity: 0 Alert/Critical alerts, logon seen, no degraded collection. |
| N-01 (chain control, negative) | C (baseline 100%) | "RÉUSSI" | Identical under the hardened baseline: control and collection of the proofs operational (UAC secure desktop, ASR rules). |
| S-19 (check of configuration C) | C | "RÉUSSI" | Baseline compliant (logging 100, hardened 100, recommended 96 = expected D-BAS-01 gap). Defender: 27 settings compared with the reference, **none weakened, no exclusion**. Remote Desktop refused (port 3389 closed). LSA protection effective. Firewall active on the three profiles. 0 alerts in 25 min. The recommended score of 96 turns D-BAS-01 from a reading hypothesis into a **measured finding** (supports the fix planned in phase 6). |

## Brute force detection (COR-R1)

| Scenario | Configuration | Verdict | Summary |
|---|---|---|---|
| S-01 (RDP brute force, failures only) | A | TP | Series of RDP authentication failures (wrong passwords, no access obtained) → 6× event 4625 all from the source → COR-R1 **Alert** on the entity `source:<Kali>` ("5 échecs d'ouverture de session en 5 minutes") within the delay → 1 incident opened. Accepted side alerts: RES-004 (Alert) and RES-005 (Critical), classified as "lab exposure artefact" (lab address, excluded from the TP and FP counts). **Consolidation: 10 trials out of 10 = TP** (0 FN, 0 FP, 0 invalid; 6× 4625 and 1 COR-R1 per trial): deterministic detection. |

In configuration C, S-01 is **prevented** (Remote Desktop refused by the baseline): the COR-R1 detection is measured in A
(S-01); in C, COR-R1 **is measured** through a non-RDP logon vector (S-03, SMB), provided that
SMB sharing is allowed: detection confirmed in that case (see the SMB row of the grid).

## Persistence (PER-001)

| Scenario | Configuration | Verdict | Summary |
|---|---|---|---|
| S-09 (persistence: Run key + scheduled task) | C | TP | Two new startup entries launched by an interpreter → **2 PER-001 alerts (Alert)**, one per mechanism; event 4698 (task creation) produced. Detected under the hardened baseline; no ASR rule gets in the way. |
| S-09 (persistence: Run key + scheduled task) | A | TP | Identical (2 PER-001 Alert, 4698 produced). Persistence detected in both configurations. |

## System correlations (service, account, logs, audit)

| Scenario | Configuration | Verdict | Summary |
|---|---|---|---|
| S-13 (service + admin account + cleared log + audit modified) | C | C (3/4 + 1 finding) | **R4** (log cleared) and **R5** (service from a suspicious folder) at **Critical**; **R7** (protection weakened by modification of the audit) at **Alert**; **BAS-001** (baseline drift) confirmed. The 4th expected correlation, **R3**, does not fire: see the finding below. |
| S-13 (service + admin account + cleared log + audit modified) | A | C (3/4 + 1 finding) | Identical to C: **R4** and **R5** at **Critical**, **R7** at **Alert**, **BAS-001** confirmed; **R3** degrades into **R3b**. The R3 finding is therefore independent of the configuration. |

### Product finding: correlation R3 "new administrator account"

Correlation **R3** ("un compte créé il y a moins de 30 min a été ajouté aux Administrateurs", Critical, T1136.001)
**never fires through the standard vector**; instead one gets **R3b** ("Ajout au groupe Administrateurs",
Alert, T1098), of a lower level and without the link "new account → promoted admin".

Cause (reading of the `siem.rs` code + reproduction): the Windows event for addition to a local group (4732) logs the
member by **security identifier (SID)**, the account name being "-"; the engine then matches the member by
**SID**, whereas the table of recently created accounts is indexed by **name** (taken from event 4720). Name against
SID: the matching always fails, whatever the addition mode (by name or by SID). **Confirmed by raw
events**: the 4720 carries `TargetUserName` and `TargetSid=…-1004`; the 4732 carries `MemberName=« - »` (empty) and
`MemberSid=…-1004`: the same SID as the created account. The matching data therefore exists (identical SID), but the
product links by name, unavailable in the 4732. Cause **proven** by the raw events; **proposed fix**
(outside the campaign, to be decided by the maintainer): keep the **SID** of the created account (present in the 4720) and
match the **MemberSid** of the 4732.

## Coverage grid (first pass)

| Domain / technique | Expected rule | Config A | Config C |
|---|---|---|---|
| Legitimate activity (control) | · | "RÉUSSI" (0 FP) | "RÉUSSI" (0 FP) |
| Check of the hardening | · (S-19) | n/a | "RÉUSSI" (Defender 0 weakened; D-BAS-01 confirmed) |
| RDP brute force (T1110.001) | COR-R1 | **TP 10/10** | prevented (RDP refused); COR-R1 measured in C through S-03 |
| SMB brute force (T1110.001, T1021.002) | COR-R1 | **TP** (source IP present in the 4625) | **prevention** (baseline blocks SMB by default) **+ TP detection** if SMB allowed; COR-R2/R9 postponed (success part) |
| Persistence (T1547.001, T1053.005) | PER-001 ×2 | **TP** | **TP** |
| Service from a suspicious folder (T1543.003) | COR-R5 | **TP (Critical)** | **TP (Critical)** |
| Log clearing (T1070.001) | COR-R4 | **TP (Critical)** | **TP (Critical)** |
| Weakened protection / audit (T1562.002) | COR-R7 + BAS-001 | **TP (Alert + BAS-001)** | **TP (Alert + BAS-001)** |
| Account created then promoted admin (T1136.001) | COR-R3 | **finding: R3 unreachable, degrades into R3b** | **finding: R3 unreachable, degrades into R3b** |

No cell is marked "0": not evaluated ≠ failure.

### Remaining scenarios and their prerequisites (for what follows)

- **S-13 in A**: executed: identical to C (R4, R5, R7, BAS-001; R3 → R3b). R3 finding independent of the configuration.
- **S-06 (DNS, phase 7 filtering)**: postponed. The source code of the filtering (collections `FiltrageDns`/`ConfigDns`, rule
  DNS-002) is not in the checkout read (present only in the installed 4.3 binary). To be specified: source version
  matching 4.3, filtering activation command, format of the `.test` list.
- **S-14 (credential theft, VOL-001)**: prerequisite to set up: the service itself sets the audit SACL on the browser
  credential folders; these folders must exist in the VM (browser profile) and the
  `AuditDonnees` collection must be "Active" (one successful 4663 reading cycle) before the trial.
- **S-07 (threat lists, DNS-001/RES-001)**: prerequisite: collections `ListesMenaces` and `ListesDomaines` "Active";
  synthetic `.test` lists in place.
- **S-04 (command channel)**, **S-02/S-05** (RDP success), **S-08/S-10/S-15**: postponed (see the agent's analysis).

Common lab prerequisite observed: the campaign snapshots do not open file sharing (SMB-In); it had
to be enabled for S-03. To be included in the snapshots for S-03/S-04.

## Open points (to be decided by the purple team agent, for list v1.4)

1. RES-004 / RES-005 ("PC exposé à Internet") on the lab address (decision D-1): classified as "lab exposure
   artefact" (documentation range, not routable) and **excluded from the TP count as well as from the FP count in all
   scenarios**, including the negative tests. No product fix: on a real workstation with a real public
   address, these alerts would be true exposure positives; filtering them would degrade a legitimate detection.
2. Collection criterion of N-01 (decision D-2): a long-cycle collection may appear "Indisponible" just after a
   snapshot restore (last success dated from when the snapshot was taken). Convention adopted: a collection not
   exercised by the scenario is set aside from the verdict only if the proven cause is "no reading since the
   restore"; on the other hand, any collection on which a rule of the scenario depends must be "Active" at the start (otherwise
   invalid trial). Consequence: S-14 (AuditDonnees) and S-07 (ListesMenaces, ListesDomaines) can only be measured
   after activation of these collections. Product question recorded as a phase 5 check: on a real workstation
   coming out of a long sleep (> 3 h), does an event-driven or periodically refreshed collection wrongly turn
   "Indisponible"?

## Method (reminder)

Campaign snapshots "campagne A" (without baseline) and "campagne C" (baseline at 100% applied by the service),
prepared outside the campaign, learning finished. Reset to the snapshot before each trial of the correlation scenarios.
Defender never modified by hand (rule 2). S-19 executed at the start of each lot in C.
