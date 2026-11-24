# Kali campaign: first "network detection" lot (NDR / IDS unfrozen)

Date: 2026-11-16. The "network detection" phase was **opened by the maintainer** (unfreezing of 2026-11-16):

> **Note of 2026-11-19** (documentation audit; the results below are not rewritten): These scenarios S-20 to S-27 were executed before being entered in the approved list: added to the list (version 1.5) on 2026-11-19 by decision of the maintainer, approval after the fact (`campagne-kali-phase1.md`, §6). No number of trials is given: measurements not consolidated. The findings of §2 (active decoy skipped for 10 minutes after a `bind` failure, injection of false positives) are not fixed as of 2026-11-19.
the local NDR (`ndr.rs`, `EXP-NDR-001`) and the IDS (`ids.rs`, `EXP-IDS-001`), until then experimental and frozen,
enter validation. This first lot tests the detections reachable **without root privilege** on the attacking
machine. Isolated lab; addresses in documentation ranges (RFC 5737); test names in `.test` (RFC 2606);
raw results outside the repository. No personal data, no workstation name, no password.

## Topological context (honest)

The target VM has **two adapters**; the service monitors, through `adresse_lan()`/`adresse_locale()`, the adapter **that
carries a gateway** (host network), not the segment of the attacking machine. To test the detection on the
attacker's segment, the harness **redirects the target to the lab segment in a reversible way**: it
disables the other adapters, sets a gateway on the lab adapter (`netsh`), restarts the service, then
**restores the snapshot** at the end of the trial (no lasting modification of the baseline). This **single-LAN** topology
(one adapter, one gateway, attacker on the same network) is the **realistic case of an ordinary workstation**; the
dual adapter of the campaign snapshots is a lab artefact. The attacking machine uses **no root
right**: an LLMNR responder and a UDP sender in user space (unprivileged ports), in Python.

## 1. Scenarios measured

| Scenario | Config A | Config C | Rule measured | Detail |
|---|---|---|---|---|
| **S-22**: active LLMNR decoy (Responder-type poisoner) | **VP** | **VP** | `EXP-NDR-001` **Critical**, T1557.001 | an LLMNR responder **without root** on the lab segment answers the decoy's probe → "EMPOISONNEMENT LLMNR/NBNS … a répondu pour le nom inexistant" |
| **S-24**: IDS signature (built-in test rule) | **VP** | **VP** | `EXP-IDS-001`, sid 9000000 | 3 UDP datagrams carrying the test pattern captured → chain **capture (`SIO_RCVALL`) → IDS → alert** |

**S-22 (LLMNR decoy).** At service startup, the NDR sends an LLMNR question for a **random
non-existent name**; the lab responder answers it (30-byte answer received on the attacker side), which triggers
`EXP-NDR-001` **Critical** (`EMPOISONNEMENT LLMNR/NBNS … "srv-26dada1d" (A) / "srv-f5d3a5d6" (C)`, T1557.001).
The active decoy is the **most reliable signal** of the NDR (no plausible false positive: only a real poisoner
answers for the non-existent name). The **passive responder** part (≥ 3 distinct names in 10 min) was not exercised (a
single probe): next leg.

**S-24 (IDS).** The attacking machine sends three UDP datagrams containing the pattern of the **built-in test
rule** (sid 9000000, `deR4Tizer-test-IDS-7f3a`, priority 3 → Info). deR4Tizer captures them (raw socket
`SIO_RCVALL`, independent of any driver) and produces the `EXP-IDS-001` detection (15 rules loaded, 0 ignored).
This validates **the whole chain capture → Aho-Corasick analysis → rule → alert** on the lab segment, **without
root or Defender risk** (benign payload).

## 2. Product findings (to pass on to the maintainer)

1. **Active decoy disarmed for 600 s on a `bind` failure.** In `ndr.rs` `demarrer()`, `leurre_fait` and
   `dernier_leurre` are updated **unconditionally after** the call to `leurre()`, whereas `leurre()`
   returns early if `UdpSocket::bind(locale)` fails. So if the interface is **transiently unavailable** at the
   first iteration of the NDR (slow startup, resume from sleep, VPN reconnection, network change), the decoy
   is **silently skipped for 10 minutes**. *(Discovered while measuring: the first S-22 trial was D/limite
   for this reason; stabilising the interface before arming gave the VP.)* Candidate fix: only set
   `leurre_fait = true` if the decoy actually ran, or retry earlier after a failure.
2. **Injection of false positives (code review, to be measured when root is available).** Two passive detections
   rest on a **spoofable source**: the **rogue DHCP** identifies the server by **option 54,
   controlled by the attacker** (a forged packet can designate a benign IP ≠ server of the interface → false
   Critical aimed at an innocent party); the LLMNR/NBNS/mDNS **passive responder** can **frame a victim machine** through
   source spoofing. The **active decoy** cannot be injected in this way. Candidate: corroborate before
   raising a Critical, and carry the strong level through the decoy.

## 3. Accepted limits

- **Root ceiling.** `arpspoof` (ARP, S-20), `dnsmasq` in DHCP mode (rogue server, S-21) and real NBNS
  (port 137) require **root** on the attacking machine (only `systemctl`/`nmcli`/`apt` run there without a password,
  never typed). These scenarios **are not measured in this lot**: pending an infrastructure decision.
- **Directional IDS rules and content signatures.** The `$EXTERNAL_NET → $HOME_NET` rules and the
  content signatures (EICAR…) require **RFC 1918 addressing** (the lab is in RFC 5737, therefore outside
  `$HOME_NET`) and a **method that does not trigger Defender**; scoped for a next leg. This lot validates the
  engine through the `any any` test rule.
- **Passive responder** (≥ 3 names): not exercised (a single decoy probe); next leg.
- **Lab exposure artefacts (decision D-1).** In config C (firewall logging active), the decoy's NBNS
  (port 137) raises a Critical "PC EXPOSÉ À INTERNET" because `203.0.113.x` is outside RFC 1918 →
  **RFC 5737 addressing artefact**, excluded from the VP/FP.
- **Harness.** **Reversible** redirection (undone by the snapshot), deliberately single-LAN. The capture follows the
  **default route** (reliable after setting a metric 1 gateway on the lab adapter); the NDR
  (`adresse_lan`, choice by enumeration of the adapters) remains to be watched.

## 4. Method

Snapshots "campagne A" (without baseline) and "campagne C" (hardened baseline), 2026-11-14. Reversible
redirection, responder/sender **without root** (Python, unprivileged ports), reset to the snapshot **before and
after** each trial, VM put back to sleep at the end. Defender **never** modified by hand. Single VM ⇒ trials
**strictly in series**. Decision D-1 (lab exposure artefacts excluded from the VP/FP) applied. Never the
password of the attacking machine (SSH key access). Benign test programs (a signature string, an
LLMNR answer), reversible, no hostile payload, no real infrastructure contacted.
