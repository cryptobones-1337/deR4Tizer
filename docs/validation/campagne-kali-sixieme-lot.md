# Kali campaign: sixth lot (remaining v1.4 scenarios: sessions, network, execution, simulations)

Date: 2026-11-16. List of scenarios: v1.4 (`campagne-kali-phase1.md`). Raw results outside the repository.

> **Note of 2026-11-19** (documentation audit; the results below are not rewritten): (1) "This lot completes the v1.4 scenarios not yet executed" is inaccurate: N-03, N-04, S-18, S-05 (a) and (b), S-10 (b), S-11 (b) and (c), the long option of S-16, "Unblock" of S-07 and the success part of S-03 remain without a result (list in `README.md` of this folder). (2) Grid of §5: N-02 "RÉUSSI" in configuration C and SAN-010 in C are hypotheses ("taken as identical"): not evaluated; the rows encoded PowerShell (PRC-002, VP with Sysmon) and limited access to LSASS (B2) are measurements of configuration B, not of A or C. (3) "IDS/DPI/NDR frozen" holds at the date of the lot; unfrozen since then (IDS and NDR on 2026-11-16, DPI on 2026-11-18, `CLAUDE.md`, « Unfreezing of the IDS, NDR and DPI » paragraph). (4) No number of trials is given: measurements not consolidated.
No personal data, no workstation name, no password. Lab addresses: documentation ranges
(RFC 5737); test names in `.test` (RFC 2606). This lot completes the v1.4 scenarios not yet executed.

**Reservation (latencies)**: as in the previous passes, the VM clock is offset in the raw results; the
verdicts rest on the presence (or absence) of the expected behaviour, not on the time. Self-validated preconditions
folded into each measurement (verdict D if a precondition is not met, never a false negative).

**Test credential mechanism** (session sub-lots): for the scenarios with a successful authenticated session, a **dedicated**
test account is created after the restore with a **generated password** (never a real password), sent to
the attacking VM through the encrypted SSH channel, **never logged or written as proof**, and erased by the reset to
the snapshot. The password of the attacking VM is never typed (key access only).

## 1. Sessions and correlations

| Scenario | Config A | Config C | Rule measured |
|---|---|---|---|
| S-17: remote administrative session on an admin share (T1021.002) | **VP** | **VP** | COR-R9 Alert "Session ouverte depuis Internet"; 4672 present (admin token); 5140 produced but not read (B2) |
| S-04: remote connection to the command channel (IPC-03) | **VP** | **VP** | COR-R9 Alert; remote `deR4Tizer` pipe **rejected** (`STATUS_ACCESS_DENIED`, `PIPE_REJECT_REMOTE_CLIENTS`), no command executed |
| S-02: RDP brute force **followed by a success** (T1110.001/T1078.003/T1133) | **VP** | **P-baseline** | COR-R1 Alert + **COR-R2 Critical** (≥ 5 failures) + COR-R9 Alert (success) |

**First measurement of COR-R2 (Critical) and of the "success" part of COR-R9** in the whole campaign (postponed at the first
pass). In configuration C, Remote Desktop is refused by the hardened baseline (3389 not listening): prevention
confirmed, COR-R2/R9 cannot be exercised.

**Product finding (honest): COR-R9 on RDP = Alert, not Critical.** For a successful Remote Desktop logon,
Windows emits the 4624 **type 3 (network NLA) before** the type 10 (RemoteInteractive), with the same IP and the same user. The
deduplication key `R9|ip|user` is taken by the type 3, whose message does not contain "bureau à distance": COR-R9
therefore comes out at **Alert** "Session ouverte depuis Internet", and not at **Critical** "Bureau à distance ouvert depuis
Internet". This is a **measurement finding** (similar to the R3 finding of the first pass), a candidate for a behavioural
fix (include the logon type in the key, or match the type 10 before using up the key): to be proposed
in phase 6, not in this validation lot.

## 2. Network (C2, exfiltration) and scanning

| Scenario | Config A | Config C | Rule measured |
|---|---|---|---|
| S-11: simulated HTTP C2 + transfer of a benign file (T1071.001/T1105) | **VP** | **VP** | RES-002 Alert (outbound flow of the unsigned program) + RES-003 (first connection) |
| S-12: exfiltration of a canary file (T1041) | **VP** | **VP** | RES-002 Alert (outbound exfil flow) + RES-003; volume/content = **E** (DPI frozen) |
| S-08: port scan (T1046) | **GAP** | **GAP** | *no scan rule* |

S-11 and S-12: an **unsigned** test program, launched from a temporary folder, opens an outbound connection
that is **kept open** (ESTABLISHED) to the lab HTTP server; deR4Tizer reads the native TCP table (`GetExtendedTcpTable`,
independent of the frozen packet capture) and scores the flow (unsigned, temporary folder, direct IP, unusual
port) above the threshold → **RES-002 Alert**. deR4Tizer detects the exfiltration **connection**; the exfiltrated **volume and
content** are not measured (IDS/DPI/NDR frozen): known limit (class E), not a false negative.

**S-08 (scan) = accepted architecture gap.** There is **no scan detection rule** (`parefeu.rs`);
the only strong alerts are RES-004 (public IPv4 self-exposure of the VM) and RES-005 (refused packets of the scan),
**all in the lab range** → exposure artefacts (decision D-1), excluded from the VP/FP. To be classified **C/E** (known missing
coverage), **never a false negative**, never 0.

## 3. Execution and simulations

| Scenario | Verdict | Detail |
|---|---|---|
| S-10: encoded PowerShell (T1059.001/T1027), benign payload | **VP (Sysmon)** | PRC-002 Alert on the `-EncodedCommand` command |
| S-15: limited access to LSASS (T1003.001, SIMULATION) | **B2** | Sysmon 10 (ProcessAccess) present; **no deR4Tizer rule** consumes the process access |
| S-16: anti-ransomware decoy touched (T1486, SIMULATION) | **VP (A) / P-Defender (C)** | LEU-002 Critical + automatic suspension of the process (A); controlled folder access refuses the write (C) |

**S-10: PRC-002 reliable with Sysmon; non-deterministic without Sysmon (honest finding).** The source of the command
line of PRC-002 is **Sysmon if installed, otherwise WMI** (`processus.rs`): deR4Tizer does **not** read the 4688 log.
In configuration B (Sysmon), the capture happens at process creation: PRC-002 fires **reliably** (VP). Without
Sysmon (WMI, by PID after the fact), a **short** encoded `powershell` may end before the WMI query, which then loses
the command line: the detection is **non-deterministic** (measured: two trials, one with PRC-002, the other
without). **This is not a false negative** but a known collection limit. Possible product improvement (also read the
4688 with command line): to be proposed, not in this lot.

**S-15: accepted gap.** LSASS handle opened with "limited information" (`PROCESS_QUERY_LIMITED_INFORMATION`) then closed
at once, no memory read. The telemetry (Sysmon 10) exists, but no deR4Tizer rule turns it into a detection:
**B2** (neither a false negative nor a detection), to be classified as known missing coverage.

**S-16: detection + automatic response, prevented under the baseline.** An unsigned program appends **a single byte** to a
decoy (reversible SIMULATION). In configuration A: **LEU-002 Critical** + **automatic suspension** of the process
(NtSuspendProcess, suspended threads checked). In configuration C: the controlled folder access of the hardened
baseline **refuses the write** (decoy intact, Defender event 1123) → **P-Defender** (prevention). Both count,
not merged.

## 4. Standard session (presence of the interface)

| Part | Verdict | Detail |
|---|---|---|
| S-05: specificity (interface present in an active session) | **"RÉUSSI"** | Interface present in the active console session; **no SAN-010/011** during the presence (no false positive) |
| S-05: negative control (interface absent > 15 min) | **"RÉUSSI"** | Restart task disabled + interface stopped → **SAN-010 Critical** raised after 15 min of absence for the session concerned |

The core mechanism of decision D4-1 is covered in the **existing interactive console session**: the service tracks
the interface **per session** and raises no alert as long as it is present (specificity), but raises **SAN-010
Critical** when it stays absent for more than 15 min (control). The measurement confirms that **the service restarts nothing
itself** (`sante.rs`): the interface only came back at the reset to the snapshot (restart task restored). SAN-010
is a health rule **independent of the baseline**; configuration C is taken as identical (hypothesis).

**Reproducibility limits (honest)**: the two parts of D4-1 that require a **second interactive session**,
(a) opening a **Remote Desktop** session and (b) **fast user switching**, are not reproduced in
this non-interactive harness (PowerShell Direct does not create an interactive session). The per-session interface tracking
mechanism that they exercise is covered by the console session above; their execution in a Remote Desktop session
or a second console remains a manual check in a VM.

## 5. Coverage grid: update (cumulative of the six lots)

| Domain / technique | Rule | Config A | Config C |
|---|---|---|---|
| Browser credential theft (T1555/T1539) | VOL-001 | **VP (Critical)** | **VP (Critical)** |
| Threat list domain / IP (T1071) | DNS-001 / RES-001 + 7-day block | **VP (Critical)** | **VP (Critical)** |
| DNS server change (T1557); DNS filtering | DNS-002; filtering | **VP** | **VP** |
| Fully active Defender does not flag the product | lot 3d | **VP** | **VP** |
| RDP/SMB brute force + correlations | COR-R1/R2/R9 | **VP** | VP (SMB) / P-baseline (RDP) |
| Remote admin session; remote command channel | COR-R9; pipe refusal | **VP** | **VP** |
| HTTP C2 / exfiltration (connection) | RES-002 | **VP** | **VP** |
| Encoded PowerShell | PRC-002 | **VP (Sysmon)** | VP (Sysmon); non-deterministic without Sysmon |
| Anti-ransomware decoy | LEU-002 + suspension | **VP** | P-Defender |
| Port scan | *none* | **GAP (C/E)** | **GAP (C/E)** |
| Limited access to LSASS | *none* | **B2** | **B2** |
| Legitimate session; benign scheduled task | N-01; N-02 | **"RÉUSSI"** | **"RÉUSSI"** |

## 6. Method (reminder)

Snapshots "campagne A" (without baseline), "campagne B" (+ Sysmon + Atomic Red Team), "campagne C" (baseline at
100%). Reset to the snapshot before and after each trial, VM put back to sleep at the end. Defender never modified by
hand. Single VM ⇒ scenarios strictly in series. Decisions D-1 (lab exposure artefacts excluded from the VP/FP) and
D-2 (collection of a rule = Active at the start, otherwise invalid trial) applied. The test programs are benign,
reversible, unsigned, launched from a temporary folder; no hostile payload, no real infrastructure
contacted.

**Product findings to pass on to the maintainer**: (1) COR-R9 through RDP = Alert and not Critical (order type 3 → type 10);
(2) PRC-002 non-deterministic without Sysmon (WMI source by PID). Two candidates for behavioural improvement, outside the
scope of this validation lot.

**Laboratory reproducibility limits**: the exfiltration volume/content (S-11/S-12) is not measured
(IDS/DPI/NDR frozen); the Remote Desktop (a) and fast user switching (b) parts of S-05 are not
reproduced in a non-interactive harness (see §4).
