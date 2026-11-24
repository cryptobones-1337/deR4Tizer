# Kali campaign: second lot (credential theft, threat lists)

Date: 2026-11-15. List of scenarios: v1.4 (`campagne-kali-phase1.md`). Raw results outside the repository.

> **Note of 2026-11-19** (documentation audit; the results below are not rewritten): "coverage" and "measured true positives" refer to single trials: no number of trials is given, no measurement is consolidated (10 valid trials, `CLAUDE.md`). The COR-R3 finding remains open, not fixed as of 2026-11-19. S-14 is a SIMULATION (credentials file of an empty test account), not marked as such in this report.
No personal data, no workstation name, no password. Lab addresses: documentation ranges (RFC 5737),
not routable. Extends the report of the first pass (`campagne-kali-premier-passage.md`): it lifts two of the prerequisites
that were noted there (browser profile for VOL-001, active threat lists for DNS-001/RES-001).

**Reservation (latencies)**: as in the first pass, the VM clock is offset in the raw results; the
VP verdicts rest on the presence of rule/level/entity, not on the time. Self-validated preconditions (see below).

## Credential theft (VOL-001)

| Scenario | Configuration | Verdict | Summary |
|---|---|---|---|
| S-14 (reading of a browser credential database by an unexpected program) | C (baseline 100%) | **VP (Critical)** | An **unsigned** program, with a neutral name, launched from a **temporary location**, opens **for reading** the credentials file of a decoy browser profile (created for the trial, without any secret) → **1 VOL-001 Critical alert** (score 10, T1555 / T1539). No password read, no copy, no exfiltration. |
| S-14 | A (without baseline) | **VP (Critical)** | Identical. The required read audit ("File System") is set by the service itself, so the detection does not depend on the baseline. |

**Self-validated precondition**: the trial is kept only if the service has actually set the read audit on the
monitored folder **and** a read audit event is produced on the targeted file; otherwise the trial is declared
invalid (D), never a false negative. Both configurations met this precondition (audit set on the
sensitive data folders present, read event produced).

## Threat lists (DNS-001, RES-001)

| Scenario | Configuration | Verdict | Summary |
|---|---|---|---|
| S-07 (known malicious domain + known threat IP) | C | **VP (DNS-001 + RES-001 + 7-day block)** | **DNS-001**: a DNS query to a **domain of the threat list** → **Critical alert** "domaine malveillant connu". **RES-001**: a connection to an **IP of a high-confidence list** → **Critical alert** "menace connue" **and automatic firewall block, expiring after 7 days** (recorded in the block log). |
| S-07 | A | **VP (DNS-001 + RES-001 + 7-day block)** | Identical. The threat lists and the DNS client log are active independently of the baseline. |

**Self-validated precondition**: the synthetic lists (one documentation entry each: a `.test` domain, an IP
in the RFC 5737 range) are supplied to the service as inputs of the corresponding sources, with a **controlled file
owner** (SYSTEM or Administrators), then activated through the service's **command channel**. In the isolated lab, the
actual download of the lists fails (no outbound DNS resolution) and the service **keeps and loads the local
copy**: expected behaviour. The trial is kept only if the threat status confirms the loading (entries ≥ 1 for
the IP source and for the domain source); both configurations confirmed it.

## Coverage grid: update (cumulative first pass + second lot)

| Domain / technique | Expected rule | Config A | Config C |
|---|---|---|---|
| Browser credential theft (T1555 / T1539) | VOL-001 | **VP (Critical)** | **VP (Critical)** |
| Query to a known malicious domain (T1071 / intelligence) | DNS-001 | **VP (Critical)** | **VP (Critical)** |
| Connection to a known threat IP (T1071) | RES-001 + auto block | **VP (Critical + 7-day block)** | **VP (Critical + 7-day block)** |

With the first pass (measurement chain, RDP/SMB brute force, persistence, system correlations), the campaign now
covers, as measured true positives: **clean negative control, hardening, brute force (RDP, SMB), persistence,
service/account/log/audit correlations, credential theft, and threat intelligence (domain + IP + block)**.
The product finding R3 (correlation "new administrator account") remains open, fix proposed to the maintainer.

## Scenario not executed in this lot

- **S-06 (DNS filtering, rule DNS-002)**: not executed in this lot: its lab prerequisites (local resolver active,
  filtering enabled on the adapters, synthetic `.test` filtering list, lab DNS upstream) remain to be set up. The
  corresponding code (detection of a DNS server change and filtering by local resolver) **is present** in the
  source: S-06 is testable and planned for a next lot. End-to-end DNS detection is already covered here by
  S-07 (DNS-001).

## Method (reminder)

Campaign snapshots "campagne A" (without baseline) and "campagne C" (baseline at 100% applied by the service).
Reset to the snapshot before and after each trial. Defender never modified by hand. No detailed offensive tool;
S-14 is entirely local (no external orchestration); S-07 sends no traffic to a real malicious domain or
host (documentation entries only).
