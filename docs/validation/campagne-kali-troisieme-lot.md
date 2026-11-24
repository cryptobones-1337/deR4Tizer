# Kali campaign: third lot (DNS server change, rule DNS-002)

Date: 2026-11-15. List of scenarios: v1.4 (`campagne-kali-phase1.md`). Raw results outside the repository.

> **Note of 2026-11-19** (documentation audit; the results below are not rewritten): "coverage" and "measured true positives" refer to single trials: no number of trials is given, no measurement is consolidated (10 valid trials, `CLAUDE.md`). The COR-R3 finding remains open, not fixed as of 2026-11-19.
No personal data, no workstation name, no password. Lab addresses: documentation ranges
(RFC 5737), not routable. Extends the second lot (`campagne-kali-second-lot.md`), which noted S-06 "not executed":
this lot executes **the DNS-002 leg of S-06** (DNS server change). List v1.4 defines S-06 in **two legs**:
(a) DNS-002 and (b) filtering by local resolver (a `.test` name of the list resolved to the null address, in the
"derniers blocages"); **only leg (a) is executed here**. The filtering leg (b) and DNS-003 (S-18) remain for
a next lot (see "Scope of this lot").

**Reservation (latencies)**: as in the previous passes, the VM clock is offset in the raw results; the
VP verdict rests on the presence of rule/level/entity, not on the time. Self-validated precondition (see below).

## DNS server change on an adapter (DNS-002)

| Scenario | Configuration | Verdict | Summary |
|---|---|---|---|
| S-06 (a program sets a static DNS server on a physical adapter) | C (baseline 100%) | **VP (Alert)** | Setting a **static DNS server** (documentation address) on the active **physical adapter** makes its resolutions go through that server. The service detects it at the periodic reading of the adapters: **1 DNS-002 alert** (level Alert, score 3) "serveur DNS réglé à la main", naming the adapter and the new server. |
| S-06 | A (without baseline) | **VP (Alert)** | Identical. The detection rests on the reading of the adapters by the service itself (ConfigDns collection), independent of the baseline. |

**Self-validated precondition**: the trial is kept only if (1) the **ConfigDns** collection is "Active" (the service does
read the adapters), (2) the adapter chosen is **physical** (Ethernet or Wi-Fi) and (3) its DNS server was **not already
set by hand** at the start (reference taken on a configuration given by the network). Otherwise, the trial is declared
invalid, never a false negative. Both configurations met these three conditions.

**Negative control (N-05)**: after the measurement, the adapter is **put back into automatic configuration** (DNS server given again
by the network). This return must **not** produce a DNS-002 alert (expected change, not set by hand). Both
configurations confirmed it: **zero** DNS-002 **alerts** on the return. The rule therefore distinguishes a manual setting from a
normal change.

## Scope of this lot

This lot executes **the DNS-002 leg of S-06**: the detection of the DNS server change, entirely local and non
destructive (reversible setting, reset to the snapshot at the end of the trial). It **does not cover the filtering leg of S-06**
(activation of the local resolver filtering engine, setting of the adapters to the deR4Tizer resolver, a `.test` name
resolved to the null address and seen in the "derniers blocages"), **nor rule DNS-003** (loopback port held by
another program, S-18): two distinct scenarios. Both require an additional lab prerequisite (the lab DNS
upstream must answer the check name that the service queries before setting the adapters) and a more intrusive
orchestration, planned for a next lot.

## Coverage grid: update (cumulative first + second + third lot)

| Domain / technique | Expected rule | Config A | Config C |
|---|---|---|---|
| Browser credential theft (T1555 / T1539) | VOL-001 | **VP (Critical)** | **VP (Critical)** |
| Query to a known malicious domain (T1071 / intelligence) | DNS-001 | **VP (Critical)** | **VP (Critical)** |
| Connection to a known threat IP (T1071) | RES-001 + auto block | **VP (Critical + 7-day block)** | **VP (Critical + 7-day block)** |
| DNS server change on an adapter (T1557 / resolution hijacking) | DNS-002 | **VP (Alert)** | **VP (Alert)** |

With the first two lots, the campaign now covers, as measured true positives: **clean negative control,
hardening, brute force (RDP, SMB), persistence, system correlations, credential theft, threat
intelligence (domain + IP + block), and hijacking of an adapter's DNS server**. The product finding R3 (correlation
"new administrator account") remains open, fix proposed to the maintainer.

## Scenarios remaining for a next lot

- **Filtering leg of S-06** (local resolver plugged into the adapters: a `.test` name of the list resolved to the null
  address, seen in the "derniers blocages") and **S-18 (DNS-003)** (loopback port held by another
  program): two distinct scenarios, testable, code present in the source; same lab prerequisite to set up
  (lab DNS upstream answering the activation check name) and intrusive orchestration, but bounded by the snapshot.

## Method (reminder)

Campaign snapshots "campagne A" (without baseline) and "campagne C" (baseline at 100% applied by the service).
Reset to the snapshot before and after each trial. Defender never modified by hand. No detailed offensive tool;
S-06 is entirely local (no external orchestration); no real address is contacted (documentation DNS server,
never reached).
