# Kali campaign: third "network detection" lot (passive mDNS responder)

Date: 2026-11-16. This lot closes the **passive responder** coverage by adding the **mDNS** part, after LLMNR

> **Note of 2026-11-19** (documentation audit; the results below are not rewritten): These scenarios S-20 to S-27 were executed before being entered in the approved list: added to the list (version 1.5) on 2026-11-19 by decision of the maintainer, approval after the fact (`campagne-kali-phase1.md`, §6). No number of trials is given: measurements not consolidated. §3 counts the passive NBNS responder as covered "through the active decoy, S-25": S-25 is the NBNS leg of the active decoy; the passive NBNS responder was not exercised.
(S-23, second lot) and the NBNS leg of the active decoy (S-25). Isolated lab; addresses in documentation ranges
(RFC 5737); test names in `.test` / `.local` (RFC 2606, RFC 6762); raw results outside the repository. No personal
data, no workstation name, no password. Root bounded by the same auditable systemd units (driven by
`systemctl` without a password).

## 1. Scenario measured

| Scenario | Config A | Config C | Rule measured | Detail |
|---|---|---|---|---|
| **S-26**: passive mDNS responder (≥ 15 names) | **VP** | **VP** | `EXP-NDR-001` **Alert**, T1557.001 | the target sends ≥ 20 distinct mDNS queries, the root responder answers each one → the capture sees ≥ 15 distinct mDNS answers from the same host → "répond en mDNS pour N noms" |

**S-26 (passive mDNS responder).** The code applies a **higher threshold for mDNS (15 names, against 3 for
LLMNR/NBNS)**, because a legitimate mDNS device often announces several services; this threshold reduces false positives.
The target sends 22 mDNS queries for distinct service names (`svc-mdnsN-x.local`); the responder unit answers them;
`EXP-NDR-001` **Alert** "répond en mDNS pour N noms différents en 10 minutes : comportement d'empoisonneur de
type Responder" (T1557.001). The display of the names in `reseau.json` is capped at 10 per responder, but the
internal count (up to 100) triggers the alert at the real threshold of 15: the verdict therefore rests on **the alert**,
not on the display.

## 2. What S-26 measures (and does not measure): honesty note

To guarantee the emission independently of the configuration, the target sends **raw** mDNS queries (UDP
socket to `224.0.0.251:5353`), and **not** through the Windows mDNS client. S-26 therefore tests the **detection path**
(capture → engine → rule → alert), and the VP in **A and C** confirms that this path works in both
configurations. On the other hand, S-26 **does not measure** the **client-side** mDNS posture of the hardened baseline: that is
a separate question (unlike S-23, where the emission went through the Windows LLMNR client, which revealed
the client-side prevention, `EnableMulticast = 0`, and gave a P-baseline). In other words: S-26 validates the
detector, not the prevention.

## 3. Assessment

With this lot, **passive responder** detection is covered on its three protocols: **LLMNR** (S-23, Alert, VP A /
P-baseline C), **NBNS** (through the active decoy, S-25) and **mDNS** (S-26, Alert, VP A+C). Combined with the active decoy
(S-22/S-25, Critical) and ARP spoofing (S-20, Critical), the NDR coverage without an additional setup is
complete. What remains, each requiring an **RFC 1918 re-addressing** of the laboratory (the `locale()` guard of the
UPnP module only accepts private addresses; the directional IDS rules rely on `$HOME_NET`/`$EXTERNAL_NET`):
the **rogue DHCP** (S-21, setup with two servers), the **UPnP redirections** (T1133) and the **directional IDS**.
