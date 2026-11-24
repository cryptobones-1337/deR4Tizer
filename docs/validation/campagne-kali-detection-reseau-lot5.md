# Kali campaign: fifth "network detection" lot: hardening (fuzzing of the decoders) + rogue DHCP

Date: 2026-11-17. This lot covers two things: (1) **hardening part 1**: fuzzing of the packet decoders,

> **Note of 2026-11-19** (documentation audit; the results below are not rewritten): These scenarios S-20 to S-27 were executed before being entered in the approved list: added to the list (version 1.5) on 2026-11-19 by decision of the maintainer, approval after the fact (`campagne-kali-phase1.md`, §6). No number of trials is given: measurements not consolidated. The "proposed hardening" and the "fix identified" of §2 and §3 are done: PR #190, merged on 2026-11-17; S-21 remains to be measured again.
and (2) the scenario **S-21 (rogue DHCP server)**, which ends in a **measured limit finding** and a lead for
hardening. Isolated lab; raw results outside the repository; no personal data, no workstation name, no
password.

## 1. Hardening of the decoders: fuzzing (privileged part)

Three functions parse bytes **entirely controlled by the attacker** on the network: `nom_dns` and `nom_nbns`
(`ndr.rs`), and `decoder` (`capture.rs`, IPv4/TCP/UDP headers). A panic in the capture thread would kill
network monitoring: the criterion is **zero panics**, and the decoder must **always return `None`** on malformed
input.

**Method.** The three functions were extracted **verbatim** (identical copy, same guards) into a pure std
harness, without any dependency or Windows API: any panic of the harness would be a panic of the real decoder.
Local compilation **targeted at the decoders only** (not the service), optimised profile with the **arithmetic
overflow and slice checks enabled**. Driver: short exhaustive (all lengths 0 to 80, multiple
variants), biased random (lengths 0 to 1500, "interesting" bytes over-represented), then **semi-valid
seeds** (DNS/LLMNR, NBNS, DHCP, IPv4+UDP, IPv4+TCP) **mutated** (bit flipping, truncation, extension).
Each call under panic capture.

**Result.** **50,324,000 calls per function (~151 million in total), 0 panics.** The three decoders return
`None` on malformed input without ever panicking: a forged packet cannot kill the capture thread (on this
campaign). The manual review agrees: each slice access is guarded (e.g. `p + 1 + l > m.len()` for the
DNS labels; `m.len() < 46` and `m[12] != 32` for NBNS; `ihl`/`total` bounded for the IP header), the arithmetic is
in `wrapping`/`usize`, and `from_utf8_lossy`/`to_lowercase` do not panic. The corpus of mutated seeds is kept
as a non-regression base.

## 2. S-21: rogue DHCP server: measured limit finding

**Setup** (two servers from the target's point of view, because the rule `legitime = dhcp_interface.is_empty() ||
dhcp_interface == serveur` only alerts on a server **different** from that of the interface). **Legitimate**: a
lab DHCP server (RFC 5737, `203.0.113.20`, range `.100-.200`) gives a lease to the target. **Rogue**: an
injector sends unsolicited `OFFER` packets carrying **option 54 = `203.0.113.50`** (foreign server identifier),
as raw packets. Expected: `serveur = .50 ≠ dhcp_interface = .20` → Critical "SERVEUR DHCP PIRATE" (T1557.003).

**Measured result: the detection does not arm on this target.** The target obtains a correct lease (`203.0.113.180`,
gateway `.20`, and on the Windows side **`DHCP Server = 203.0.113.20`, `DHCPEnabled = True`**, confirmed by CIM and
`ipconfig /all`). But the `dhcp_interface` field that the service publishes **stays empty**, including after a lease
**acquired at restart** (normal path, not only a forced renewal). A full dump shows that
`interface`, `passerelle` and `masque` are **all** filled in: only `dhcp_interface` is empty.

**Root cause.** The service reads the DHCP server through **`GetAdaptersInfo`** (legacy API, deprecated by Microsoft):
`dhcp = if DhcpEnabled != 0 { texte_ip(&DhcpServer) } else { "" }`. On the synthetic network adapter of the VM, this
field comes back **empty** while the OS knows the server perfectly well. All the other fields of the **same**
structure (gateway, mask) come through: the weak point is precisely the reading of the DHCP server.

**Consequence (security).** When `dhcp_interface` is empty, `legitime = is_empty() || …` is **always true**: the
rogue DHCP server detection (`EXP-NDR-001`, T1557.003) is then **inert**. Scope of the finding: measured on a
Hyper-V target; not verifiable on physical hardware from the lab (VM only).

**Proposed hardening (follow-up, privileged code → audit + compiled pass).** Read the DHCP server through
**`GetAdaptersAddresses` (`Dhcpv4Server`)**, reliable and not deprecated, instead of `GetAdaptersInfo.DhcpServer`. After
this fix, S-21 becomes measurable again. The **honesty caveat** is kept for that moment: option 54 being
controlled by the attacker, a forged `OFFER` can designate a **benign** IP → the rule spots a **distinct**
server, it does not distinguish a real rogue server from spoofing aimed at an innocent party.

## 3. Assessment and limits

- **Decoders**: panic-free over ~151 M cases (part 1 of the hardening: acquired).
- **S-21 rogue DHCP**: **limit finding**: the detection does not arm as long as the source of the DHCP server remains
  `GetAdaptersInfo`. Fix identified (`GetAdaptersAddresses`), to be carried into the code then measured again.
- **Directional IDS**: out of reach of the current lab (it needs a public source and a private destination
  mutually reachable, therefore a router/NAT), left documented.
- **Review of the `unsafe` blocks** and **anti-false-positive corroboration**: written up (parts 2 and 3 of the hardening),
  to be examined with the fix above.

Isolated lab, raw results outside the repository. No personal data.
