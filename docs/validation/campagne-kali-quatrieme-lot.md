# Kali campaign: fourth lot (DNS filtering: filtering leg of S-06; testability limit of DNS-003)

Date: 2026-11-15. List of scenarios: v1.4 (`campagne-kali-phase1.md`). Raw results outside the repository.

> **Note of 2026-11-19** (documentation audit; the results below are not rewritten): "coverage" and "measured true positives" refer to single trials: no number of trials is given, no measurement is consolidated (10 valid trials, `CLAUDE.md`). The COR-R3 finding remains open, not fixed as of 2026-11-19.
No personal data, no workstation name, no password. Lab addresses: documentation ranges
(RFC 5737); test names in `.test` (RFC 2606). Extends the third lot (`campagne-kali-troisieme-lot.md`): it
executes **the filtering leg (b) of S-06**, after the DNS-002 leg (a) of the third lot. S-06 is therefore **covered in
full**. It also documents why **DNS-003 (S-18)** cannot be measured end to end in the laboratory.

**Reservation (latencies)**: as in the previous passes, the VM clock is offset in the raw results; the
VP verdict rests on the presence of the expected behaviour, not on the time. Self-validated preconditions (below).

## Filtering leg of S-06 (a name of the list is blocked by the local resolver)

| Scenario | Configuration | Verdict | Summary |
|---|---|---|---|
| S-06 leg (b) (filtering by local resolver) | C (baseline 100%) | **VP** | A synthetic filtering list (a single `.test` name, controlled file owner) is loaded into an active category; after activation of the local resolver on the adapter, a query for that name is **resolved to the null address** (0.0.0.0) and the block **appears in the "derniers blocages"** (name, list, category). A **non-listed** name is **not** blocked (negative control). |
| S-06 leg (b) | A (without baseline) | **VP** | Identical. Filtering is a function of the service itself, independent of the baseline. |

**Self-validated precondition**: the trial is kept only if (1) the synthetic list is **actually loaded**
(at least one entry, seen in the filtering status) and (2) the **activation of the resolver on the adapter succeeds**; otherwise
the trial is declared invalid, never a false negative. In the isolated laboratory, the actual download of the lists fails and
the service **keeps and loads the local copy**: expected behaviour, used here as for the threat lists.
**Negative control**: a name absent from the list is not resolved to the null address. Entirely reversible (deactivation
of the filtering + reset to the snapshot).

## Coverage grid: update (cumulative of the four lots)

| Domain / technique | Expected rule | Config A | Config C |
|---|---|---|---|
| Browser credential theft (T1555 / T1539) | VOL-001 | **VP (Critical)** | **VP (Critical)** |
| Query to a known malicious domain (T1071 / intelligence) | DNS-001 | **VP (Critical)** | **VP (Critical)** |
| Connection to a known threat IP (T1071) | RES-001 + auto block | **VP (Critical + 7-day block)** | **VP (Critical + 7-day block)** |
| DNS server change on an adapter (T1557) | DNS-002 | **VP (Alert)** | **VP (Alert)** |
| DNS filtering: listed name blocked (null address) | filtering by local resolver | **VP** | **VP** |

**S-06 is now covered in full**: leg (a) DNS-002 (third lot) and leg (b) filtering (this lot), in
configurations A and C.

## DNS-003 (S-18): testability limit, not a defect

**DNS-003** alerts when an adapter still points to the local resolver while **another program holds the loopback DNS
port**. On reading the source (`origin/main`), this alert is emitted only at **service startup**,
and **only if an adapter stays on the loopback after an attempt to reset the adapters**. Yet, for a working
adapter, this reset **succeeds** (the adapter is returned to its original state): an external scenario
"activate → abrupt stop of the service → a third party takes port 53 → restart" therefore **does not leave** an adapter on the
loopback, and the alert is not emitted. Making it fire would require **forcing the reset of an adapter to fail**, which
cannot be caused cleanly from outside without degrading the adapter in some other way.

**Conclusion**: DNS-003 is **not measurable as an end-to-end true positive** in the laboratory by external means.
The logic of the alert is correct and **covered by a unit test** of the repository. This point is a **laboratory
testability limit**, not a defect of the product; it is reported to the maintainer.

## Method (reminder)

Campaign snapshots "campagne A" (without baseline) and "campagne C" (baseline at 100%). Reset to the snapshot before
and after each trial. Defender never modified by hand. No detailed offensive tool; the filtering leg of S-06 is
entirely local (no real address contacted; a laboratory resolver serves as upstream, without access to the Internet).
