# Kali campaign: fourth "network detection" lot (UPnP redirection)

Date: 2026-11-16. This lot measures the detection of **UPnP port redirections** (`EXP-NDR-001`, T1133: the PC

> **Note of 2026-11-19** (documentation audit; the results below are not rewritten): These scenarios S-20 to S-27 were executed before being entered in the approved list: added to the list (version 1.5) on 2026-11-19 by decision of the maintainer, approval after the fact (`campagne-kali-phase1.md`, §6). No number of trials is given: measurements not consolidated. "Complete NDR coverage": without the rogue DHCP (S-21, to be measured again after PR #190) or the passive NBNS responder (not exercised, see the note of the third lot).
made reachable from the Internet). Isolated lab; raw results outside the repository; no personal data, no workstation
name, no password.

## Why an RFC 1918 re-addressing (honest)

The UPnP module only queries **private** addresses: the `locale()` guard of `upnp.rs` is
`is_private() || is_link_local()`. The campaign snapshots use documentation addresses (RFC 5737,
`203.0.113.0/24`), which this guard **rejects**, rightly (protection against a query to the Internet). To test
the detection, the harness **re-addresses the lab segment in RFC 1918 in a reversible way**: the attacking machine
adds a secondary IP `192.168.50.20` (through `nmcli`, without a password), the target is redirected to
`192.168.50.10` (through `netsh`); the snapshot **undoes everything** at the end of the trial (the secondary IP is also removed).
No lasting modification. The IGD is **emulated in user space, without root** (SSDP on the unprivileged port 1900
+ an HTTP server on a high port).

## 1. Scenario measured

| Scenario | Config A | Config C | Rule measured | Detail |
|---|---|---|---|---|
| **S-27**: UPnP redirection to this PC | **TP** | **TP** | `EXP-NDR-001` **Alert**, T1133 | the emulated IGD answers the M-SEARCH and announces a redirection of port 3389/TCP **to the target** → "la box ouvre le port 3389 (TCP) d'Internet vers ce PC" |

**S-27 (UPnP).** At the first iteration after startup (like the decoy), `verifier_upnp` sends an SSDP M-SEARCH;
the emulated IGD returns a `LOCATION`, deR4Tizer fetches the description, finds the `WANIPConnection` service, then
reads the redirections over SOAP (`GetGenericPortMappingEntry`). The first redirection designates the target
(`NewInternalClient = 192.168.50.10`, `NewExternalPort = 3389`, active); since `client == locale`, deR4Tizer raises
`EXP-NDR-001` **Alert** "le PC est joignable depuis Internet sur ce port" (T1133). The status field confirms the
discovery: "1 redirection(s) sur la box, dont 1 vers ce PC". **TP in A and C**: the check is **active**
(driven by the service), independent of the baseline configuration. **Precondition D-2** checked: without
discovery of an IGD (`Upnp` field), the trial would be D, never a false negative.

## 2. Accepted limits

- **Rogue DHCP (S-21)**: requires a **legitimate server + a rogue one** on the segment (setup file
  prepared, decision pending).
- **Directional IDS**: the `$HOME_NET`/`$EXTERNAL_NET` rules assume a **private** side (victim) and a
  **public** side (Internet); yet, on a single L2 segment, one cannot place both a public source and a
  private destination mutually reachable without a router/NAT. To be tested with an extended topology (lab router).
- **Hardening of the code** (fuzzing of the decoders, review of the `unsafe` blocks, anti-FP corroboration): privileged path,
  under security audit, requires compiling (file prepared, CI/exception decision pending).

## 3. Assessment of the "network detection" phase

Detections **measured as TP** (configurations A and C unless stated otherwise): active LLMNR decoy (S-22, Critical),
active NBNS decoy (S-25, Critical), ARP spoofing (S-20, Critical), passive LLMNR responder (S-23, Alert, TP A /
P-baseline C), passive mDNS responder (S-26, Alert), **UPnP redirection (S-27, Alert, T1133)**, and the test IDS
signature (S-24). The NDR coverage reachable through user-space emulation is **complete**. The
rogue DHCP and the directional IDS (documented infrastructure constraints), and the hardening of the code (audit), remain.
