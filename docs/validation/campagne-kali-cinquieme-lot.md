# Kali campaign: fifth lot (formal Defender lot 3d; standard sessions: specificity)

> **Note of 2026-11-19** (documentation audit; the results below are not rewritten): (1) The "lot 3d" measured here (Defender scan without detection, on the product of the snapshots, without the CI artefact, without quarantine or restore) is not the lot 3d of `CLAUDE.md` and of the matrix (`tests/vm/lot3d.ps1`, 12 checks): it is a non-detection trial. (2) N-02 in configuration C is a hypothesis, not evaluated. (3) No number of trials is given: measurements not consolidated.

Date: 2026-11-16. List of scenarios: v1.4 (`campagne-kali-phase1.md`). Raw results outside the repository.
No personal data, no workstation name, no password. Lab addresses: documentation ranges
(RFC 5737); test names in `.test` (RFC 2606). This lot covers two remaining hard criteria of step 1:
the **formal Defender scenario (lot 3d)** and the **standard sessions** (negative specificity tests).

**Reservation (latencies)**: as in the previous passes, the VM clock is offset in the raw results; the
verdicts rest on the presence (or absence) of the expected behaviour, not on the time. Self-validated preconditions
(below).

## Lot 3d: formal Defender (the installed product is not considered malicious)

Measurement on the **current** product (deR4Tizer 4.3, MSI `6AC1B4F15290`) as installed in the campaign snapshots,
with **Microsoft Defender fully active**. The CI artefact was not needed: the current build is already present
in the lab. Defender is **never** modified.

| Scenario | Configuration | Verdict | Summary |
|---|---|---|---|
| lot 3d (formal Defender) | C (hardened baseline) | **TP** | Real-time protection **and** behaviour monitoring **and** antivirus active; **no exclusion** covers deR4Tizer; custom scan of the installation folder + `C:\ProgramData\deR4Tizer` then quick scan **completed**; **zero detections** (`Get-MpThreatDetection`/`Get-MpThreat`); binary **intact** (not quarantined); service **Running**. |
| lot 3d (formal Defender) | A (without baseline) | **TP** | Identical, Defender active without hardening. |

**Self-validated precondition**: the trial is kept only if (1) Defender is **fully active** (real time +
behaviour + antivirus) and (2) **no exclusion** covers a deR4Tizer path or process; otherwise the trial is
declared invalid (D), never a false "no detection".

**Notable point (honest)**: the installed binary `deR4TizerSvc.exe` is **unsigned** (code signing, Certum /
SignPath, is step 5 of the launch, not yet done). *Note of 2026-11-19: "step 5 of the launch" refers to the maintainer's launch plan, outside the repository (signing of the version, then lot 3d replayed on the signed version); the certificate chosen is Certum Open Source (2026-11-11), SignPath is ruled out (`CLAUDE.md`, section 6).* The result is all the more significant: Defender, including
under the hardened baseline (ASR enabled, high cloud level, PUA), **does not flag** an unsigned SYSTEM service.

**Scope**: this is a **signal in a test VM**, not a proof on a real workstation. The distribution conditions remain
unchanged (see README): green GitHub CI, lot 3d passed on **the distributed and signed version**, independent review.

## Standard sessions: specificity (negative tests)

A legitimate activity must produce **no** alert of level Alert/Critical.

| Test | Configuration | Verdict | Summary |
|---|---|---|---|
| N-01 (local session + signed PowerShell administration + interface) | A | **"RÉUSSI"** | **Zero** Alert/Critical alerts; logon **collected** (4624 in the mini-SIEM: the collection works); no collection down. |
| N-01 | C (hardened baseline) | **"RÉUSSI"** | Identical; control and collection work under the baseline; no alert caused by the baseline. |
| N-02 (scheduled task created by an administrator pointing to a signed program in Program Files) | A | **"RÉUSSI"** | PER-001 at most at level **Info**; **no** Alert/Critical alert; task creation observed by the collection (precondition proven). |

**Self-validated precondition**: N-01 is "RÉUSSI" only if a **logon is actually collected**
(proof that the collection is running); N-02, only if the **task is actually created** and a creation event (or a
PER-001 entry) is observed. Without this proof, the trial is D: never a false "no alert" caused by a dead collection.

**Negative control already covered: N-05**: the return of the adapter to the network's DNS (DHCP) after the filtering **does not trigger**
DNS-002; this behaviour was exercised during the restoration of the third lot (S-06), the adapter being returned through
`ResetServerAddresses` without an alert.

## Coverage grid: update (cumulative of the five lots)

| Domain / technique | Expected rule | Config A | Config C |
|---|---|---|---|
| Browser credential theft (T1555 / T1539) | VOL-001 | **TP (Critical)** | **TP (Critical)** |
| Query to a known malicious domain (T1071 / intelligence) | DNS-001 | **TP (Critical)** | **TP (Critical)** |
| Connection to a known threat IP (T1071) | RES-001 + auto block | **TP (Critical + 7-day block)** | **TP (Critical + 7-day block)** |
| DNS server change on an adapter (T1557) | DNS-002 | **TP (Alert)** | **TP (Alert)** |
| DNS filtering: listed name blocked (null address) | filtering by local resolver | **TP** | **TP** |
| Fully active Defender does not flag the product | lot 3d (non-detection) | **TP** | **TP** |
| Legitimate session: no strong alert | N-01 (specificity) | **"RÉUSSI"** | **"RÉUSSI"** |
| Benign scheduled task: Info at most | N-02 (specificity) | **"RÉUSSI"** | · ("identical" hypothesis) |

## Method (reminder)

Snapshots "campagne A" (without baseline) and "campagne C" (baseline at 100%). Reset to the snapshot before and after
each trial, VM put back to sleep at the end. Defender never modified by hand. Lot 3d and standard sessions are
entirely local (the Kali VM does not take part in N-01/N-02; no real address contacted).
