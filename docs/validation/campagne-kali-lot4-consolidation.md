# Kali campaign, lot 4 of the ATT&CK coverage: consolidation (10 trials), part 1: S-09

- **Date**: 2026-11-22.
- **List**: v1.7 (`campagne-kali-phase1.md`, repetition protocol 3.4, controls N-02 and N-06, rule D-3).
- **Profile**: `carte-attack.md`, profile validated by the maintainer on 2026-11-21.
- **Raw results**: outside the repository, bench output folders named below. No personal data.

This part consolidates the two rows of the map that S-09 exercises: T1547.001 (Run key) and T1053.005 (scheduled
task). The other rows of lot 4 will follow in parts of this same report, as the series go.

## Environment

| Field | A | B | C |
|---|---|---|---|
| Service binary | built on the workstation by `preparer.ps1` from main 5c33e76 (plus test scripts only), installed in the three snapshots; SHA-256 8E97200A2820… recorded in each series and by S-19 | identical | identical |
| Snapshot | "campagne A 2026-11-22" | "campagne B 2026-11-22" (A + Sysmon + Atomic Red Team) | "campagne C 2026-11-22" (A + three profiles + bureau-distance only) |
| Windows | 26300.9974 | 26300.9974 | 26300.9974 |
| Sysmon | absent | 15.22 (SHA-256 83D31F24…, minimal configuration from the preparation script: process creations, network, remote threads, access to LSASS, Run keys) | absent |
| Atomic Red Team | absent | module 2.3.0, sheets at commit a0e3f9bc…; no sheet used | absent |
| Learning | finished (snapshot; command returned by the bench) | finished | finished |
| Configuration check | n/a | n/a | S-19 trial 4: "RÉUSSI" (Defender 28 settings, 0 weaker; scores 100/100/100; 0 alerts in 25 min) |

Preparation of B: Microsoft Defender detected 24 items in the Atomic Red Team files while they were being put in place
(noted, nothing is touched, as on 2026-11-14); no sheet was used for S-09.

## Protocol

Bench `tests/vm/s09.ps1` (#248, #250), launched by `tests/vm/lancer.ps1 -Scenario s09 -Instantane <instantané>`:
- series of 10 trials chained in a single session (3.4, point 2), with reset to the snapshot at the start and at the end;
- (a) user Run value pointing to an interpreter that writes a marker file; (b) equivalent scheduled task;
  distinct name at each trial;
- learning finished before the first trial;
- TP: PER-001 at level Alert naming the entry; C: learning Info or learned behaviour Info; FN: nothing within
  180 s;
- cleanup proven by the next reading of the automatic startups before the following trial; Persistance collection
  "Active" before each trial (D-2);
- controls N-06 (Run value pointing to a signed program) and N-02 (task pointing to a signed program), 3 trials each: compliant
  if the entry is seen at the reading and no alert exceeds level Info within the 180 s;
- latency: `HeureUtc` of the alert minus the time the entry was put in place (VM clock), rounded to the tenth (half
  up). The reading of the automatic startups runs every minute: the latency follows this rhythm.

## Results

| Row | Scenario | Config. | Executed | Valid | TP | C | FN | D | Detection | Median / max latency (s) | Control: trials, FP |
|---|---|---|---|---|---|---|---|---|---|---|---|
| T1547.001 | S-09 (a) | A | 10 | 10 | 10 | 0 | 0 | 0 | 10/10 | 60.8 / 62.2 | N-06: 3, 0 |
| T1547.001 | S-09 (a) | B | 10 | 10 | 10 | 0 | 0 | 0 | 10/10 | 60.7 / 62.2 | N-06: 3, 0 |
| T1547.001 | S-09 (a) | C | 10 | 10 | 10 | 0 | 0 | 0 | 10/10 | 60.4 / 61.8 | N-06: 3, 0 |
| T1053.005 | S-09 (b) | A | 10 | 10 | 10 | 0 | 0 | 0 | 10/10 | 60.1 / 61.7 | N-02: 3, 0 |
| T1053.005 | S-09 (b) | B | 10 | 10 | 10 | 0 | 0 | 0 | 10/10 | 61.2 / 62.7 | N-02: 3, 0 |
| T1053.005 | S-09 (b) | C | 10 | 10 | 10 | 0 | 0 | 0 | 10/10 | 60.1 / 62.6 | N-02: 3, 0 |

The controls all gave PER-001 at level Info (new entry, without remark), entry seen at the reading: compliant.
No series stopped. Rule D-3: one persistence alert (PER-001 Alert) on the bench's execution task in
each configuration (A, B and C), labelled as an artefact and excluded. Outputs: `sortie-vm-s09-20261122-083803` (A),
`-102956` (B), `-093213` (C).

Pilots, outside the count: two series in configuration A on the "clean" snapshot with installation, on 2026-11-22
(binary main 0bfea32 then final bench): 20/20 each, controls compliant.

## Before and after

| Row | Status before (map of 2026-11-21) | Status after | Row of the map modified |
|---|---|---|---|
| T1547.001 | Lab-tested, Run key (S-09, 2026-11-15) | Lab-tested, consolidated, Run key: 10/10 in A, B and C (Kali campaign, lot 4, 2026-11-22) | Persistence / T1547.001 (still to do: Startup folder, outside the list) |
| T1053.005 | Lab-tested (S-09, 2026-11-15) | Lab-tested, consolidated: 10/10 in A, B and C (Kali campaign, lot 4, 2026-11-22) | Execution / T1053.005 |

Assessment of the map: "consolidated" 1 → 3; "lab-tested, not consolidated" 13 → 11.

## Limits

- Campaign carried out by an agent in a test VM, on a list approved by the validation agent: neither human nor
  independent.
- A single form of action per technique (interpreter that writes a marker file); the Startup folder
  (T1547.001) is not exercised.
- The latency of about 60 s is that of the reading of the automatic startups, every minute; a persistence put in place
  and removed between two readings is not seen.
- False positives counted on the controls only; no measurement on a real workstation.
