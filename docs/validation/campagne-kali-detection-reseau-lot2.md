# Kali campaign: second "network detection" lot (ARP spoofing, real NBNS, passive responder)

Date: 2026-11-16. Continuation of the first lot of the "network detection" phase. This lot tests the detections that

> **Note of 2026-11-19** (documentation audit; the results below are not rewritten): These scenarios S-20 to S-27 were executed before being entered in the approved list: added to the list (version 1.5) on 2026-11-19 by decision of the maintainer, approval after the fact (`campagne-kali-phase1.md`, §6). No number of trials is given: measurements not consolidated. §2 concludes that the absence of a rogue DHCP alert "is not a defect": the fifth "network detection" lot measures the opposite (DHCP server of the interface read as empty on a Hyper-V adapter, inert detection), fixed by PR #190 (2026-11-17); S-21 remains to be measured again, never measured positive.
required **privileged access** on the attacking machine. Root is now available there but **strictly
bounded**: three **frozen and auditable systemd units** (an NBNS/LLMNR/mDNS responder (without poisoning DHCP or
WPAD), a `dnsmasq` in DHCP only, and an `arpspoof` aimed at the target's address alone) driven by
`systemctl` without a password. The password of the attacking machine is **never typed**. Isolated lab;
addresses in documentation ranges (RFC 5737); test names in `.test` (RFC 2606); raw results outside the repository.
No personal data, no workstation name, no password.

## Topological context (honest)

As in the first lot, the harness **redirects the target to the lab segment in a reversible way** (deactivation
of the other adapters, gateway set through `netsh`, restart of the service), then **restores the snapshot** at the end
of the trial: no lasting modification of the baseline. The **single-LAN** topology (one adapter, one gateway,
attacker on the same network) remains the realistic case of an ordinary workstation. Each trial first checks its
**measurement precondition** (rule D-2) before concluding: a trial whose precondition is not met is
**D (invalid)**, never a false negative.

## 1. Scenarios measured

| Scenario | Config A | Config C | Rule measured | Detail |
|---|---|---|---|---|
| **S-20**: ARP spoofing (man in the middle) | **VP** | **VP** | `EXP-NDR-001` **Critical**, T1557.002 | the target's neighbour table sees two IPs (a dummy address + the gateway) on the **same MAC** → "USURPATION ARP probable : la MAC de la passerelle est aussi annoncée par un autre appareil" |
| **S-25**: real NBNS (NBNS leg of the active decoy) | **VP** | **VP** | `EXP-NDR-001` **Critical**, T1557.001 | the root responder answers the decoy on **NBNS (137)** *and* **LLMNR (5355)** → "EMPOISONNEMENT LLMNR/NBNS … a répondu pour le nom inexistant" |
| **S-23**: passive LLMNR responder (≥ 3 names) | **VP** | **P-baseline** | `EXP-NDR-001` **Alert**, T1557.001 | the target queries several names, the responder answers each one → "répond en LLMNR pour ≥ 3 noms"; **in C, the baseline disables LLMNR on the client side** → attack **prevented upstream** |

**S-20 (ARP spoofing).** After redirection, the target's gateway is the attacking machine. The
`arpspoof` unit announces a dummy address (`203.0.113.1`) at the **attacker's MAC**. **Precondition D-2 checked**:
the harness first confirms that `203.0.113.1` **and** the gateway carry the **same MAC** in the target's neighbour
table (otherwise: D). `analyser_arp` (10 s cycle, through `GetIpNetTable2`) then raises `EXP-NDR-001`
**Critical** "USURPATION ARP probable … le trafic peut être intercepté (homme du milieu)" (T1557.002). Identical
VP in A and C (the detection is independent of the baseline).

**S-25 (real NBNS).** This scenario **completes S-22**: in the first lot, the decoy had only been tested on
**LLMNR** (Python responder without root, unprivileged port). With the root responder (privileged port 137), the
deR4Tizer active decoy (question **LLMNR (224.0.0.252:5355) *and* NBNS (137)** for a random non-existent name)
receives an answer **on both protocols**: `resultat_leurre = « RÉPONSE … 203.0.113.20 (LLMNR),
203.0.113.20 (NBNS) »`, and `EXP-NDR-001` **Critical** "EMPOISONNEMENT LLMNR/NBNS" (T1557.001). **VP in A and C**:
the decoy leaves **from the service side** whatever the client's LLMNR policy, unlike the passive responder
below. The active decoy remains the **most reliable signal** of the NDR.

**S-23 (passive LLMNR responder).** The target sends 6 LLMNR queries for distinct names; the responder answers
each one; the capture sees ≥ 3 distinct answers from the same host → `EXP-NDR-001` **Alert** "répond en LLMNR pour
≥ 3 noms" (T1557.001). **VP in A.** **In C: P-baseline (prevention)**: the reinforced baseline **disables LLMNR
on the client side** (`EnableMulticast(Policy) = 0`, checked in the VM): the target no longer sends LLMNR queries, so
passive poisoning is **prevented upstream**. This is not a detection defect: it is defence in
depth at work (and the **active decoy**, for its part, keeps watching even in C, see S-25). Passive detection
(`Alerte`) and active defence (`Critique` through the decoy) are complementary.

## 2. Product finding: rogue DHCP (S-21) not measurable as things stand (code review)

The **rogue DHCP** scenario (S-21) **is not measured** in this lot, for a design reason and not a
privilege reason. In `ndr.rs`, an observed DHCP server is judged rogue if `serveur != dhcp_interface`, with
`legitime = dhcp_interface.is_empty() || dhcp_interface == serveur`. Yet, after redirection, the target has a **static
IP** → `dhcp_interface` is **empty** → **every** DHCP server is judged legitimate, no alert. And if the target
switches to DHCP with the attacker as its **only** server, it takes its lease from the attacker → `dhcp_interface ==`
attacker → legitimate as well. **This is not a defect**: one cannot qualify as "rogue" the **only** DHCP
server present. A faithful VP requires a **legitimate server *and* a rogue one** on the segment (two servers), a setup to
prepare. The detection logic (reading of **option 54**, table bounded to ≤ 50 servers) is, for its part, correct on
review.

## 3. Accepted limits

- **S-21 (rogue DHCP)**: pending the setup with two DHCP servers (legitimate + rogue) on the lab segment.
- **Directional IDS / content**: the IDS rules depending on `$HOME_NET`/`$EXTERNAL_NET` assume **RFC 1918**
  addressing; the lab is in **RFC 5737** (outside `$HOME_NET`), so these rules cannot be exercised as they are.
  Next leg: replay in RFC 1918 addressing, or test non-directional rules.
- **Hardening of the code** (fuzzing of the ARP/DHCP/LLMNR/NBNS decoders, review of the `unsafe` blocks, anti-FP corroboration)
  remains the **preferred path** to the switch to "supported", under a **mandatory security audit** (privileged
  path), outside this validation lot.

## 4. Assessment

With this lot, the **LLMNR + NBNS + ARP** coverage is complete: active decoy (LLMNR **and** NBNS, Critical, A+C),
passive responder (Alert, A; prevented in C), ARP spoofing (Critical, A+C). The rogue DHCP (setup with
two servers) and the directional IDS (RFC 1918 addressing) remain.
