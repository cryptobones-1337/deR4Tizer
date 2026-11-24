# Validation of deR4Tizer (Kali campaign, continuous loop)

This folder documents the end-of-phase-7 validation campaign and the continuous loop that follows it (CLAUDE.md,
section 5, Kali campaign).

| Document | Content |
|---|---|
| [campagne-kali-phase1.md](campagne-kali-phase1.md) | Initial audit of capabilities, ATT&CK mapping, closed list of scenarios (version 1.4, approved by the validation agent on 2026-11-15; version 1.5, S-20 to S-27 added on 2026-11-19 by decision of the maintainer, after their execution; version 1.6 of 2026-11-20; version 1.7 of 2026-11-22 for lot 4 of the ATT&CK coverage: controls N-06 to N-13, complete sheets of S-20 to S-27, rule D-3, protocol for repeating the 10 trials; version 1.8 of 2026-11-22: restart of the service allowed in the network bench, by decision of the maintainer) |
| [campagne-kali-premier-passage.md](campagne-kali-premier-passage.md) | Results of the first pass (list v1.3): measurement chain validated, RDP/SMB brute force, persistence, system correlations, and the product finding on correlation R3 |
| [campagne-kali-second-lot.md](campagne-kali-second-lot.md) | Results of the second lot (list v1.4): credential theft (VOL-001) and threat lists (DNS-001, RES-001 + automatic 7-day block), in configurations A and C |
| [campagne-kali-troisieme-lot.md](campagne-kali-troisieme-lot.md) | Results of the third lot (list v1.4): detection of a DNS server change on an adapter (DNS-002), in configurations A and C: the **DNS-002 leg of S-06** (the filtering leg of S-06 and DNS-003/S-18 remain to be executed) |
| [campagne-kali-quatrieme-lot.md](campagne-kali-quatrieme-lot.md) | Results of the fourth lot (list v1.4): **filtering leg of S-06** (a listed name blocked to the null address), in configurations A and C: S-06 is covered in full; and why **DNS-003 (S-18)** cannot be measured end to end in the lab |
| [campagne-kali-cinquieme-lot.md](campagne-kali-cinquieme-lot.md) | Results of the fifth lot (list v1.4): **formal Defender lot 3d** (the installed product is not detected by a fully active Defender, configurations A and C, binary not yet signed) and **standard sessions** (specificity: N-01 and N-02 without a strong alert; N-05 already covered) |
| [campagne-kali-sixieme-lot.md](campagne-kali-sixieme-lot.md) | Results of the sixth lot (list v1.4): remaining scenarios: sessions and correlations (S-17 remote admin session, S-04 IPC pipe, S-02 RDP brute force + success), network (S-11 HTTP C2, S-12 exfiltration, S-08 scan), execution and simulations (S-10 encoded PowerShell, S-15 LSASS, S-16 decoy), presence of the interface (S-05 SAN-010); two product findings (COR-R9 through RDP at Alert level; PRC-002 non-deterministic without Sysmon) |
| [campagne-kali-detection-reseau-lot1.md](campagne-kali-detection-reseau-lot1.md) | First lot of the "network detection" phase (NDR/IDS unfrozen): S-22 active LLMNR decoy (EXP-NDR-001 Critical, T1557.001) and S-24 test IDS signature (EXP-IDS-001, sid 9000000), TP in configurations A and C, **without root**; two product findings (decoy disarmed for 600 s on a bind failure; injection of DHCP/Responder false positives); accepted limits (root ceiling for ARP/DHCP/NBNS; directional IDS rules) |
| [campagne-kali-detection-reseau-lot2.md](campagne-kali-detection-reseau-lot2.md) | Second lot of the "network detection" phase: **S-20 ARP spoofing** (EXP-NDR-001 Critical, T1557.002) and **S-25 real NBNS** (NBNS leg of the active decoy, EXP-NDR-001 Critical, T1557.001), TP in configurations A and C; **S-23 passive LLMNR responder** (Alert, T1557.001) TP in A, P-baseline in C (the baseline disables LLMNR on the client side); root bounded by auditable systemd units; one product finding (rogue DHCP S-21 not measurable without a two-server setup); limits (directional IDS in RFC 1918) |
| [campagne-kali-detection-reseau-lot3.md](campagne-kali-detection-reseau-lot3.md) | Third lot of the "network detection" phase: **S-26 passive mDNS responder** (EXP-NDR-001 Alert, T1557.001, threshold 15 names), TP in configurations A and C; closes the passive responder coverage (LLMNR S-23 + NBNS S-25 + mDNS); honesty note (raw mDNS emission → tests the detector, not the client posture); rogue DHCP, UPnP and directional IDS remain, which require RFC 1918 re-addressing |
| [campagne-kali-detection-reseau-lot4.md](campagne-kali-detection-reseau-lot4.md) | Fourth lot of the "network detection" phase: **S-27 UPnP redirection to this PC** (EXP-NDR-001 Alert, T1133), TP in configurations A and C; IGD emulated in user space (WITHOUT root), lab re-addressed in RFC 1918 in a reversible way (the `locale()` guard of upnp.rs only accepts private addresses); assessment of the phase; rogue DHCP, directional IDS and hardening of the code remain |
| [campagne-kali-detection-reseau-lot5.md](campagne-kali-detection-reseau-lot5.md) | Fifth lot of the "network detection" phase: **hardening part 1: fuzzing of the decoders** (`nom_dns`/`nom_nbns`/`decoder`, ~151 M calls, **0 panics**); **S-21 rogue DHCP server**: **measured limit finding**: the detection does not arm because `dhcp_interface` stays empty (the service reads the DHCP server through `GetAdaptersInfo`, empty on a Hyper-V adapter while the OS has the server) → hardening identified: `GetAdaptersAddresses` (`Dhcpv4Server`); forgeable option 54 caveat kept |
| [carte-attack.md](carte-attack.md) | ATT&CK map of the "ransomware and opportunistic intrusion, small organisation" profile (54 rows, profile validated by the maintainer on 2026-11-21, ATT&CK v20.1): status of each row according to the reports of this folder, identifiers checked, three structural defects and work order |
| [campagne-kali-lot4-consolidation.md](campagne-kali-lot4-consolidation.md) | Lot 4 of the ATT&CK coverage, consolidation through 10 trials (list v1.7); part 1: S-09 in configurations A, B and C (Run key and scheduled task: 10/10 each, controls N-06 and N-02 compliant), 2026-11-22 |

## Good to know

- The scenarios are described at the level of behaviour: ATT&CK technique, simulation or emulation, preconditions,
  expected result, maximum delay, cleanup, proofs. No detailed offensive command.
- The a priori classes (A to E) of the mapping are **hypotheses**, not measured results.
- The approval of the list is that of the validation agent: it is **neither human nor independent**. Each
  approved version is sent to the maintainer before execution.
- A scenario is published here before its first execution; each campaign report, added to this folder, records the
  version of the list executed.
- First pass published on 2026-11-15 (list v1.3): see
  [campagne-kali-premier-passage.md](campagne-kali-premier-passage.md). The raw results stay outside the repository.

## Status as of 2026-11-19 (documentation audit)

- **List versions**: first pass, list v1.3; lots 2 to 6, list v1.4; five "network detection" lots,
  scenarios S-20 to S-27, entered in list v1.5 after their execution (approval after the fact, decision of the
  maintainer of 2026-11-19).
- **v1.4 scenarios still without a result**: N-03, N-04, S-18 (not reproducible end to end in the lab), S-05 (a)
  Remote Desktop and (b) fast user switching, S-10 (b), S-11 (b) and (c), the long option of S-16,
  "Unblock" of S-07, the success part of S-03; S-21 (v1.5) to be measured again after PR #190.
- **Deviations from the measurement rules (`CLAUDE.md`)**:
  - number of trials: only S-01 in configuration A has 10 trials (S-10: 2); all the other measurements are single
    trials, therefore **not consolidated**, even where a report writes "coverage" or "acquired";
  - delays: the TP verdicts are given without the maximum delay that the list requires, and the latencies are in no
    report (VM clock offset in the raw results);
  - versions of Sysmon, Atomic Red Team and Windows: absent from the reports;
  - vocabulary outside classes A to E: "RÉUSSI" (negative control without a strong alert), "P-baseline" and
    "P-Defender" (attack prevented upstream, class P of list v1.3), "GAP (C/E)" (no rule), "D/limite" (invalid trial, class D);
    "B2", for its part, is a subclass of B defined by the list (§2: produced by Windows or Sysmon but not read);
  - the simulated parts of S-13 (first pass) and S-14 (second lot) are simulations, not marked SIMULATION in
    their reports.
- **ATT&CK techniques: the code is authoritative**: DNS-002 carries no technique in the code (the reports that write
  T1557 do so on their own initiative; list v1.4 says "no exact match"); VOL-001 carries "T1555 / T1539"
  (the list writes T1555.003); COR-R1 and COR-R2 carry T1110 (the list writes T1110.001); levels and techniques
  of EXP-NDR-001 and EXP-IDS-001 in `docs/detection/regles.md`.
- **"Passive responder" coverage**: LLMNR (S-23) and mDNS (S-26) exercised; passive NBNS not exercised (S-25 is the
  NBNS leg of the active decoy).
- **Open findings, not fixed**: COR-R9 through Remote Desktop at
  Alert level; PRC-002 non-deterministic without Sysmon; active decoy skipped for 10 minutes after a `bind` failure; injection of
  DHCP and passive responder false positives. Fixed: inert rogue DHCP (PR #190, S-21 to be measured again); COR-R3 matched
  by the SID of the account, or its exact name, instead of a substring of the name (audit of 2026-11-23, B-5-02; tested in the lab,
  S-13 to be measured again in a VM).
