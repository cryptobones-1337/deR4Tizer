# ATT&CK map: "ransomware and opportunistic intrusion, small organisation" profile

- **Date**: 2026-11-21.
- **Profile validated by the maintainer on 2026-11-21.**
- **ATT&CK version**: Enterprise v20.1 (13 October 2026), identifiers checked on 2026-11-21 on attack.mitre.org.
- **Origin**: starting map drawn up read-only by the auditor on `main` (`7421f82`), from
  `service-rs/src/mitre.rs`, `docs/detection/regles.md` and the reports of this folder; taken up here after two
  checks (section "Lot 0 checks") and three corrections.
- **What the map is not**: neither a coverage nor a validation. A status only changes on a campaign report
  published in this folder; the lab tests of the Kali campaign are done in a VM, by an agent, on a list approved
  by the validation agent (`README.md`, "Good to know").

## The profile

54 rows (about sixty techniques and sub-techniques, some grouped), chosen for a Windows workstation
of a small organisation: what ransomware and opportunistic intrusions use, from entry to impact. The
list comes from the auditor's knowledge of the public rankings (annual detection reports, work of the MITRE
center on ransomware); it has not been compared with their current edition.

## Reading the statuses

| Status | Meaning |
|---|---|
| **Lab-tested, consolidated** | 10 valid trials in a campaign report (`CLAUDE.md`) |
| **Lab-tested** | Detection observed in a campaign report, fewer than 10 trials: "not consolidated". "In part": only some of the variants of the rule were exercised; the row counts among the tested rows |
| **Rule, not tested** | A rule exists, with its unit tests, never exercised in a campaign |
| **Partial** | Only part of the behaviour is seen, or only in one case (public address, Sysmon present) |
| **Seen without alert** | The event is collected, no rule reads it |
| **Prevention only** | The baseline or Defender prevents it; deR4Tizer does not detect it itself |
| **No rule** | Nothing, but feasible with the current telemetry |
| **Out of reach** | Not feasible without a kernel driver or without a sensor that the product forbids itself |

Reports cited (all in this folder): S-01, S-09 and S-13 in `campagne-kali-premier-passage.md` (2026-11-15);
S-07 and S-14 in `campagne-kali-second-lot.md` (2026-11-15); S-02, S-08, S-10, S-11, S-12, S-15, S-16 and S-17 in
`campagne-kali-sixieme-lot.md` (2026-11-16); consolidation series of S-09 in `campagne-kali-lot4-consolidation.md`
(2026-11-22); S-20 to S-27 in `campagne-kali-detection-reseau-lot1.md` to `lot5.md`
(2026-11-16 and 2026-11-17). Reservation: S-20 to S-27 were executed before being entered in the approved list
(note of 2026-11-19 in these reports); the rows T1133, T1557.001 and T1557.002 depend on them.

## The map

The tactics follow ATT&CK v20: the former "Defense Evasion" (TA0005) is called "Stealth", and a
new tactic, "Defense Impairment" (TA0112), groups the neutralisation of protections.

### Initial access

| Technique | Rule | Status | What is missing |
|---|---|---|---|
| T1566.001 Malicious attachment | PRC-001; Office ASR (baseline) | Rule, not tested | Campaign scenario |
| T1566.002 Malicious link | DNS-001, DNS filtering | Partial: listed domain lab-tested (S-07, 2026-11-15) | Nothing for a non-listed domain |
| T1133 Exposed remote services | COR-R9, RES-005, RES-007, VIE-003, UPnP (EXP-NDR-001) | Lab-tested (S-02, S-17, 2026-11-16; S-27, 2026-11-16) | 10 trials |
| T1078.003 Valid local accounts | COR-R2, COR-R9 | Partial (after failures, or from a public address; S-02, 2026-11-16) | Successful logon without failure from the local network |
| T1091 Removable media | Baseline (ASR, autorun) | Prevention only | Rule on plugging in and running from a removable drive |

### Execution

| Technique | Rule | Status | What is missing |
|---|---|---|---|
| T1059.001 PowerShell | PRC-002 | Partial: lab-tested with Sysmon only (S-10, 2026-11-16) | Measurement without Sysmon (reading of the 4688 done, structural defect 1 dealt with); common forms (`irm … \| iex`, `-ec`, `/e`, `iwr -OutFile`, renamed copy seen by Sysmon) added after the audit of 2026-11-23 (A-7-1, lab-tested, to be tried in a VM); renamed copy without Sysmon not seen; 4104 script blocks not read (A-7-4) |
| T1059.003 Command prompt | CHA-001 | Partial | Same |
| T1059.005 / .007 VBScript, JScript | PRC-001; baseline (WSH, ASR) | Rule, not tested | wscript and cscript absent from PRC-003 |
| T1204.002 File launched by the user | PRC-001, CHA-001, RES-003 | Rule, not tested | Scenario |
| T1047 WMI | PRC-003 (`wmic process call create`); ASR (hardened profile) | Rule, not tested | Scenario; child processes of WmiPrvSE |
| T1053.005 Scheduled task | PER-001 | **Lab-tested, consolidated: 10/10 in A, B and C (S-09, Kali campaign, lot 4, 2026-11-22)** | Nothing in the list; other task forms outside the list |
| T1569.002 Execution through a service | COR-R5 | Lab-tested, in part (S-13, 2026-11-15) | Service launched from a system folder |
| T1218 Hijacked system binaries | PRC-003 (certutil, bitsadmin, mshta, regsvr32, rundll32, wmic; since A-7-7: rundll32 of a DLL from a writable folder T1218.011, msiexec from an address T1218.007, mshta and regsvr32 on a UNC path); PRC-001 (cmstp, odbcconf, regasm, regsvcs, msxsl launched by a document, A-7-8) | Rule, lab-tested (audit of 2026-11-23, A-7-7) | Scenario; installutil absent from PRC-003 |

### Persistence

| Technique | Rule | Status | What is missing |
|---|---|---|---|
| T1547.001 Run keys, Startup folder | PER-001, PER-002 | **Lab-tested, consolidated, Run key: 10/10 in A, B and C (S-09, Kali campaign, lot 4, 2026-11-22)** | Startup folder (outside the list) |
| T1543.003 Windows service | PER-001, COR-R5 | Lab-tested, in part (S-13, 2026-11-15) | 10 trials |
| T1546.003 WMI subscription | PER-001; ASR | Rule, not tested | Scenario |
| T1136.001 Local account created | COR-R3 | Defect fixed, lab-tested only (audit of 2026-11-23, B-5-02: matching by the SID, `cor_r3_bout_en_bout_par_sid`); S-13 gave COR-R3b before the fix | S-13 to be measured again in a VM |
| T1098 Account added to the administrators | COR-R3b | Lab-tested (S-13, 2026-11-15) | 10 trials |
| T1176.001 Browser extension | EXT-001 | Rule, not tested | Scenario |
| T1197 BITS jobs | PRC-003 (bitsadmin) | Partial | Job created by PowerShell |

### Privilege escalation

| Technique | Rule | Status | What is missing |
|---|---|---|---|
| T1548.002 UAC bypass | Baseline (UAC "Always notify") | Prevention only | Rule on the known bypasses |
| T1068 Vulnerable driver | PIL-001, COR-R10; ASR | Rule, not tested | Scenario (harmless sheet) |
| T1055 Process injection | none | Out of reach | Stated as a limit |

### Neutralisation of defences (Defense Impairment)

| Technique | Rule | Status | What is missing |
|---|---|---|---|
| T1685 Protections disabled (formerly T1562.001) | DEF-003 to 006, 010 to 012, BAS-001 | Rule, not tested: Defender untouchable in a VM | Stays "lab-tested" at best, by project rule |
| T1685.001 Logging cut off (formerly T1562.002) | COR-R7 | Lab-tested (S-13, 2026-11-15) | 10 trials |
| T1686.003 Host firewall modified (formerly T1562.004) | SYS-002, SYS-003 | Rule, not tested | Scenario |
| T1685.005 Logs cleared (formerly T1070.001) | COR-R4 | Lab-tested (S-13, 2026-11-15) | 10 trials |
| T1112 Registry modified | BAS-001, PER-002 | Partial | Limited to the tracked settings |

### Stealth

| Technique | Rule | Status | What is missing |
|---|---|---|---|
| T1027 Obfuscated code | PRC-002 | Partial (Sysmon) | Obfuscation seen on the command line only; all the abbreviations of `-EncodedCommand` recognised since the audit of 2026-11-23 (A-7-1, lab-tested); 4104 script blocks not read (A-7-4) |
| T1036 Disguised program | "non signé" label only | No rule | System tool copied or renamed (T1036.003) |

### Credential theft

| Technique | Rule | Status | What is missing |
|---|---|---|---|
| T1110 Brute force | COR-R1, COR-R2 | **Lab-tested, consolidated: 10 out of 10 (S-01, 2026-11-15)** | Nothing: only consolidated measurement |
| T1555.003 / T1539 Browser secrets and cookies | VOL-001, PRC-004 (Chrome, Edge, Brave; Vivaldi, Opera, Yandex, Arc since A-7-9) | Lab-tested (S-14, 2026-11-15) | 10 trials |
| T1003.001 LSASS memory | ASR (baseline); PRC-003 (comsvcs.dll MiniDump, Critical, since the audit of 2026-11-23, A-7-7) | Seen without alert (S-15, 2026-11-16, Sysmon); comsvcs form lab-tested, to be measured again | Rule; "Kernel Object" audit proposed |
| T1003.002 SAM database | none | No rule | `reg save` of the SAM and SYSTEM hives |
| T1557.001 Name resolution poisoning | EXP-NDR-001 | Lab-tested (S-22, S-23, S-25, S-26, 2026-11-16) | 10 trials; passive NBNS never exercised |
| T1557.002 ARP spoofing | EXP-NDR-001 | Lab-tested (S-20, 2026-11-16) | 10 trials |

### Discovery

| Technique | Rule | Status | What is missing |
|---|---|---|---|
| T1046 Port scan | none | No rule (S-08, 2026-11-16: not detected) | The firewall log is already read |
| T1087, T1018, T1135 Accounts, machines, shares | none | No rule | To be counted in the chain score (net, nltest, whoami) |

### Lateral movement

| Technique | Rule | Status | What is missing |
|---|---|---|---|
| T1021.001 Remote Desktop | COR-R9, VIE-003 | Partial (public address only) | Session from the local network |
| T1021.002 Administrative shares | COR-R9 | Partial (S-17, 2026-11-16); 5140 produced, not read | Reading of the 5140 |
| T1570 Tool transfer | none | No rule | Executable written to an administrative share |

### Collection, command and control

| Technique | Rule | Status | What is missing |
|---|---|---|---|
| T1560.001 Archiving before exfiltration | none | No rule | 7z, rar on the command line on user folders |
| T1123, T1125 Microphone, camera | VIE-001 | Rule, not tested | Scenario |
| T1056.001 Keylogger | none | Out of reach | Stated as a limit |
| T1071.001 Web protocol | RES-001, RES-002, RES-003, beacon | Lab-tested (S-11, 2026-11-16) | Beacon never tested; 10 trials |
| T1071.004 DNS | DNS-001, EXP-DPI-001 | Partial (listed domain) | DNS tunnel never tested |
| T1105 Tool download | RES-002, PRC-003 | Partial (connection seen, content not; S-11, 2026-11-16) | Scenario with certutil, bitsadmin |
| T1219 Remote access tools | VIE-002 | Rule, not tested | Scenario |
| T1572, T1090 Tunnel, proxy | VIE-002 (ngrok, by the process name) | **Partial**: ngrok only, rule not tested | chisel, plink; a renamed tunnel |

### Exfiltration and impact

| Technique | Rule | Status | What is missing |
|---|---|---|---|
| T1041 Exfiltration over the control channel | RES-002 | Partial (connection, not the volume, S-12, 2026-11-16) | Volume per program (the Trafic module has it) |
| T1567.002 To online storage | none | No rule | rclone, MEGA; unusual outbound volume |
| T1486 Data encryption | LEU-001, LEU-002, suspension | Lab-tested (S-16, 2026-11-16) | 10 trials |
| T1490 Backups deleted | PRC-005 (PowerShell forms, `resize shadowstorage`, `wbadmin delete backup`, `bootstatuspolicy`, `diskshadow` added after the audit of 2026-11-23, A-7-3) | Rule, lab-tested | Scenario (command carried without being executed) |
| T1489 Services stopped | COR-R7 | Partial (security services) | Stopping services in series |

## Assessment

| Status | Rows |
|---|---|
| Lab-tested, consolidated | 3 |
| Lab-tested, not consolidated | 11 |
| Partial | 14 |
| Rule, not tested | 13 |
| Seen without alert | 1 |
| Prevention only | 2 |
| No rule | 7 |
| Out of reach | 2 |
| Open defect (T1136.001) | 1 |
| **Total** | **54** |

The count covers the rows of the map: some group two neighbouring techniques.

## Lot 0 checks

### Identifiers (attack.mitre.org, ATT&CK v20.1, on 2026-11-21)

The identifiers of the starting map came from the auditor's memory. Each technique page was read; the
differences:

| Starting map | ATT&CK v20.1 | Remark |
|---|---|---|
| T1562.001 Disable or Modify Tools | **T1685** Disable or Modify Tools | The T1562.001 page redirects to T1685 (Defense Impairment tactic, created on 2026-04-14) |
| T1562.002 Disable Windows Event Logging | **T1685.001** Disable or Modify Windows Event Log | Page redirect |
| T1562.004 Disable or Modify System Firewall | **T1686.003** Windows Host Firewall | The page redirects to T1686; the Windows host sub-technique is T1686.003 |
| T1070.001 Clear Windows Event Logs | **T1685.005** Clear Windows Event Logs | Page redirect; T1070.001 no longer appears under T1070 |
| T1176 Browser Extensions | T1176 Software Extensions, sub-technique **T1176.001** Browser Extensions | Renamed; T1176.002 IDE Extensions |
| T1219 Remote Access Software | T1219 **Remote Access Tools** | Renamed; sub-techniques T1219.001 to .003 |
| T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay | T1557.001 **Name Resolution Poisoning and SMB Relay** | Renamed (also covers mDNS) |

The other identifiers are unchanged. Since lot 2 (technique taken from the rule identifier), the code sets the
v20.1 identifiers, through a single table aligned with this map (`regles.rs`).

### "No rule" rows against `docs/detection/regles.md`, read in full

| Row | Result |
|---|---|
| T1036 Disguised program | Confirmed. Two neighbouring guards, which are not disguise rules: VOL-001 raises the alert for a "chrome.exe" not signed by Google that reads secrets; SYS-003 treats a "svchost.exe" outside Windows as a third-party author |
| T1003.002 SAM database | Confirmed: VOL-001 only audits profile files |
| T1046 Port scan | Confirmed (S-08: not detected). The IDS ships a "Nmap Scripting Engine" content signature (EXP-IDS-001), which sees the Nmap scripts, not a scan |
| T1087, T1018, T1135 | Confirmed |
| T1570 Tool transfer | Confirmed |
| T1560.001 Archiving | Confirmed |
| T1572, T1090 Tunnel, proxy | **Corrected**: VIE-002 raises an alert for a process named `ngrok` ("ngrok (tunnel)", `surveillances.rs`). The row moves to "Partial" |
| T1567.002 Online storage | Confirmed |

### Other corrections

- **T1047 WMI**: the starting map said "Prevention only". PRC-003 already detects `wmic process call create`
  (pattern of `processus.rs`): the row moves to "Rule, not tested" (review of the PR).

- **T1053.005 Scheduled task**: the starting map said "Partial (negative control N-02 only)". The first
  pass (`campagne-kali-premier-passage.md`, 2026-11-15, S-09 "Run key + scheduled task") raised two
  PER-001 alerts, one per mechanism, in configurations A and C. The row moves to "Lab-tested", not consolidated; it
  joins the rows to be consolidated.

## Three structural defects, to be dealt with before adding rules

Status as of 2026-11-22: all three are fixed (lot 1: #244; lot 2: #246; lot 3: this PR). No status of the map
changes as a result: only a campaign report does that. S-10 replayed without Sysmon after lot 1: 10 detections out of 10
(measurement in a VM by the `tests/vm/s10.ps1` bench, comment on #244; outside the Kali campaign, not carried over to the map).

**1. The process rules do not read the 4688 events.** (fixed by lot 1, #244)
- The baseline enables auditing of process creations with the command line, and the mini-SIEM stores these 4688.
- Rules PRC-001 to PRC-005 and the chains take the command line from Sysmon if it is installed, otherwise from
  WMI after the fact (`processus.rs`). A short process ends before the query: the detection becomes random
  (S-10, 2026-11-16: without Sysmon, non-deterministic).
- Plugging these rules into the 4688 would make the "Partial (Sysmon)" rows reliable without Sysmon.

**2. The ATT&CK technique is assigned through French keywords in the text of the alert.** (fixed by lot 2, #246)
- `mitre.rs` looks for words ("leurre", "chaîne d'attaque", "pare-feu") in the reasons; the first
  match wins. Every chain receives T1204, whatever its content.
- Each alert already carries a rule identifier: the technique must come from it, in a single table.

**3. The rule sheets do not carry the technique.** (fixed by lot 3)
- `docs/detection/regles.md` cites a few techniques for about fifty rules: one "ATT&CK" line per sheet,
  taken from the same table as the code.

## Work order

1. Structural defects 1, 2 and 3 (lots 1 to 3, done).
2. Consolidate what is already lab-tested: 10 valid trials for the 13 non-consolidated rows (lot 4; T1547.001 and
   T1053.005 done on 2026-11-22, `campagne-kali-lot4-consolidation.md`; 11 remain).
3. Test the 13 "Rule, not tested" rows: no rule to write, only scenarios (lot 5).
4. Close the "Partial" and "Seen without alert" rows that only need an event already collected.
5. Write the rules of the "No rule" rows.
6. Publish the map, generated from the results, with the two "Out of reach" rows stated as such (lot 6).

Steps 4 and 5 add capabilities: they need a phase opened in writing by the maintainer in `CLAUDE.md`.

## Limits

- The statuses come from the reports of the repository, not from a trial done for this map.
- The profile has not been compared with the current edition of the public rankings it draws on.
- The Kali campaign is carried out by an agent, in a test VM, on a list approved by the validation agent:
  neither human nor independent.
