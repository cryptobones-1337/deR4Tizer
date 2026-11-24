# Domain lists for DNS filtering (phase 7): sources, licenses, choices

State: **in the code**: engine (PR 7.2, `filtrage.rs`), local resolver (7.3), activation on the adapters (7.4), "Browsing" page and log of blocks (7.5), third-party resolver Quad9 as an option (7.6); encrypted DNS (7.7, optional) not done. This document sets what domain-name
filtering in phase 7 downloads, and why. It follows the phase 7 design file (section 5, documentary
research of 2026-10-25).

## In the code (PR 7.2)

- **Compiled sources**: EasyPrivacy and EasyList, "ads and tracking" category (D7-3: recommendation of the design file
  applied, revisable by the maintainer before activation, PR 7.4). **No security list** (D7-2: non-commercial or
  unknown licenses; HaGeZi TIF only on a decision of the maintainer).
- **Nothing is downloaded** as long as no category is active (`Config.Filtrage.Categories`, empty by default).
  With a category active: its lists are downloaded every 12 h into `filtrage\` (HTTPS only, 32 MB at
  most), read back with the owner check. If protecting the data folder fails: nothing is downloaded or
  loaded.
- **Accepted formats**: hosts (`0.0.0.0 domaine`), domain alone, `||domaine^` and `@@||domaine^`. Any other rule
  (path, `$…` options, regular expressions, cosmetic rules) is discarded and counted. Name in ASCII, at least two
  labels (an accented name is expected as `xn--`), never a two-label public suffix (`co.uk`,
  `gouv.fr`, `com.br`…): such a rule would block every site under that suffix; it is discarded and counted.
- **Lookup**: the name and its parents (`a.b.exemple.fr` is blocked by `exemple.fr`), never the top-level
  domain alone; 10 lookups at most, the name itself then the shortest parents.
- **Order**: protection list, then the user's authorizations, then `@@` exceptions of a list (they only lift
  the blocks of their own category), then security lists, then ad lists.
- **Safeguards**: a new copy that is empty, collapsed (less than half of the previous one) or exploded (more than double)
  is refused and the previous one kept; a domain of the protection list found in a list is ignored and counted;
  1,000,000 entries at most in total (a list that would exceed this is not loaded).
- **Protection list** (never blocked, subdomains included): Windows Update, activation, Defender and SmartScreen,
  Windows connectivity test, time, revocation and OCSP of the common authorities, deR4Tizer update
  server, plus the configured reporting hosts (ntfy, Teams, SMTP) and the host of the update manifest. Drawn up
  from Microsoft's documentation; to be completed from the logs of a VM with PR 7.3, and to be reviewed.
- **User authorizations**: `filtrageAutoriser` and `filtrageRetirer` commands (administrators), 1000
  domains at most, in `config.json`; refused if protecting the folder fails.
- **Refused list** (empty, collapsed, exploded): previous copy kept, new attempt in 12 h.

## Activation on the adapters (PR 7.4)

`filtrage` command (`on` or `off`, administrators; in the interface since 7.5b, "Browsing" page). Activation: refused if the computer has a
primary DNS suffix (computer joined to a domain) or a DNS or NRPT policy (D7-5, recommendation applied);
origin of the adapters saved in `filtrage-origine.json` before any change; permanent resolver started and
checked; active physical Ethernet and Wi-Fi adapters set (HardwareInterface and ConnectorPresent flags read
from Windows, never a virtual adapter: audit of 2026-11-23, T-9; `127.0.0.1` then their servers, `::1` then their
IPv6 servers, without `fec0::/10` or link-local: T-10) and verified; at the slightest discrepancy, everything is restored. Resumed when the service starts. Departures from the design file:
the `FiltrageDns` collection and the display came with 7.5 (below); an adapter plugged in after activation is
not set (turn it on again); restoring before an update happens when msiexec stops the service, for any
update, not only a rollback.

- **After the computer starts**: as long as the upstream does not answer (network not ready yet), the adapters stay on
  their original servers, without filtering; the probe switches them back as soon as the upstream answers, within 5 minutes. Port 53
  is held during this whole window.
- **Adapter gone since activation** (docking station, USB dongle, disabled adapter): if Windows still knows
  it, its original setting is written directly into the registry and picked up when it comes back; if Windows no longer
  knows it, nothing points to the loopback and it counts as restored. Turning off, stopping and uninstalling
  are never blocked by it.

## Published state, browsing data (PR 7.5a)

- `filtrage-etat.json`, in the protected data folder (same readers as the rest): state ("actif",
  "contourné sur la carte …", "suspendu : …", "inactif"), categories, adapters, upstream, lists (name, category,
  license, date, entries, exceptions, discarded rules, protected domains ignored), counters per category and per list,
  **last 50 blocked names kept 24 h** (time, name, list; neither program nor account), authorizations.
- **Readers**: the resolver serves the whole computer; an account allowed to read deR4Tizer data therefore sees the blocked
  names of every user of the computer, as it already sees their connections (review of #165, R71; to be said also
  in the interface, 7.5b).
- **No relayed name is recorded.** The filtering state goes neither into `etat.json` nor into the API (test
  `filtrage_etat_hors_api`); nothing is reported to the provider, except the existing DNS-001 alert.
- `filtrageCategories` command (administrators): active categories, applied without restarting the resolver.
- `FiltrageDns` collection: active when filtering runs, unavailable when it is suspended, disabled otherwise.
- Rule DNS-003 (Critical): port 53 of the loopback held by another program while an adapter still points
  to the resolver (audit of #164, S164-05).
- "Browsing" page of the interface (PR 7.5b): state, categories (two separate switches), activation (the question
  says what changes), lists and licenses, last blocked names with "Allow this domain", authorizations with
  "Remove the authorization"; honest line ("Filtering does not protect against a program that uses its own DNS or encrypted DNS.") and
  readers stated. Commands confirmed through Canal in an elevated interface.

## Chosen third-party resolver (PR 7.6)

- **D7-8, decided by the maintainer on 2026-11-14** (Quad9's terms read and accepted by him): compiled
  and short list, **Quad9** only (Quad9 Foundation, Switzerland, non-profit; blocks malicious domains, not
  ads; 9.9.9.9, 149.112.112.112, 2620:fe::fe, 2620:fe::9). **Never by default**: "Your network's resolver"
  stays the upstream as long as the administrator does not choose Quad9 (`filtrageAmont` command, "Browsing" page).
- When Quad9 is chosen, **every query that is not blocked is sent to it**: said in the confirmation and on the
  page. This includes local names and reverse queries for private addresses that the computer did not resolve
  itself (audit of #167, S167-03); on a company network, keep "Your network's resolver".
- **Fallback at a captive portal** (`amont_tiers_repli`, pure): Quad9 silent and the network's DNS answering → fallback to the network's
  DNS, displayed; Quad9 answering again → it becomes the upstream again. Probes every 5 minutes. Before the
  fallback, up to 30 s may pass (fail-open: adapters restored, without filtering) then up to 5 minutes of probing
  (review of #167, R2).
- Quad9 already chosen and unreachable when turning filtering on (captive portal): activation is refused, with a
  message that names it; choose "Your network's resolver" then turn it on again (R1).
- Follow-ups of the review of #167: at activation, the confirmation states the upstream in force and offers Quad9 if it is
  not chosen (R4); without a security list, the page says "only Quad9 blocks the malicious domains it knows"
  when Quad9 is chosen and reachable, "nothing is blocked" otherwise, fallback included (R4); the confirmation of the choice of
  Quad9 also states that local names are sent, the advice for a company network and the delay without filtering before the
  relay (R6). Third party removed from `config.json` by hand during a fallback: the fallback is forgotten, with no switch back and no
  "third party unreachable" log (audit of #167, R-v2-1).
- DNS4EU stays ruled out (individuals only, no commercial use). Encrypted DNS: optional step 7.7, not done.

## Local resolver (PR 7.3; connected to the adapters by 7.4)

The local resolver (`dns_local.rs`) queries this engine. In 7.3, it only runs during a 10-minute **trial**
started by an administrator (`filtrageEssai` command), on `127.0.0.1:53` and `[::1]:53` only; no adapter is
set to it.

Decisions of the design file applied on its recommendation, still in force after 7.4 (D7-1: put into service on the adapters with the maintainer's explicit agreement for 7.4 (2026-11-12); the others: without a written decision of the maintainer):

- **D7-1** (mechanism): M2, the local resolver;
- **D7-4** (answer to a blocked name): A `0.0.0.0`, AAAA `::`, other types without answer (NODATA), TTL of 60 s;
- **D7-6** (Firefox special name): `use-application-dns.net` answers NXDOMAIN when filtering has an active
  category;
- **D7-9** (log of blocks, PR 7.5a): counters and last 50 blocked names kept 24 h, on the computer; no
  log of relayed names; nothing reported beyond DNS-001.

Intended departures from the design file:

- no queue of 256 queries: beyond 16 queries in progress (including 4 TCP connections), the query is ignored and the
  client retries;

- a truncated UDP answer is returned as is to the client, which retries over TCP with the resolver (which then relays
  over TCP), instead of a new TCP attempt by the resolver itself;
- fail-open stops the trial (the adapters do not point to the resolver yet); the `FiltrageDns`
  collection and the 5-minute suspension will come with activation (7.4);
- the VM case is in scenario 3a, not in a separate `filtrage` scenario (which would require extending the tooling
  of the full run); to be revisited in 7.4 if the cases multiply.

## Principle

- The computer will download each list **directly from its source**, like today's threat lists
  (`menaces.rs`: HTTPS only, bounded size and delay, previous copy kept if the new one collapses).
  deR4Tizer does not **redistribute** any list.
- The share-alike obligations of the GPL and CC BY-SA licenses apply to redistribution, not to use. A
  "non-commercial" license, on the other hand, restricts **use**, which excludes very small businesses and municipalities.
- What follows is a **technical reading** of the projects' pages, **not legal advice**. D7-8 was decided by the
  maintainer on 2026-11-14; D7-2 (no security list) and D7-3 (EasyPrivacy and EasyList) are applied on the
  recommendation of the design file, without a written decision of the maintainer.
- The sources will be compiled into the binary: no list address will be read from a file.

## Lists examined

| List | Category | License or terms (according to the project's page) | Use by a very small business | Proposal of the design file |
|---|---|---|---|---|
| EasyPrivacy, EasyList | ads, tracking | dual license GPLv3 or CC BY-SA 3.0, either; credit "The EasyList authors" | allowed | Default when "Ads and tracking" is turned on; `||domaine^` rules without options only; attribution displayed. |
| AdGuard DNS filter | ads, tracking | repository under GPL-3.0; aggregates third-party lists whose licenses are not given on the page | probably allowed, upstream sources to be checked | Alternative if EasyList breaks too many sites. |
| HaGeZi "Multi Light" | ads, tracking, part of malware | GPL-3.0 for the published lists, with no rights over the upstream data according to the project | uncertain | Alternative, on a decision of the maintainer. |
| HaGeZi "TIF" (Mini) | security | same reservation about the upstream sources | uncertain | Only free security list found that seems usable; only on a decision of the maintainer, reservation displayed. |
| URLhaus (abuse.ch) | security | commercial use subject to a paid subscription, according to abuse.ch's terms | no | Ruled out. |
| Phishing Army | security | CC BY-NC 4.0 | no | Stays under "restricted lists" for DNS-001, never for blocking. |
| ThreatView domains | security | to be checked | unknown | Same. |
| StevenBlack "unified" | ads, malware | repository under MIT, but aggregates non-commercial lists (MVPS, Dan Pollock) | no | Ruled out. |
| Quad9 resolver (instead of a list) | security | free service; terms read and accepted by the maintainer (D7-8, 2026-11-14) | allowed | Kept as upstream at the administrator's choice, never by default (PR 7.6). |

## What will be blocked by default: nothing

Filtering will be off at installation and after an upgrade.

| Activation | What would be blocked |
|---|---|
| "Safe browsing" | Domains of the security lists kept by the maintainer, plus the upstream's filtering if Quad9 is chosen. With no list and no Quad9, the interface will say "no active security list: nothing is blocked; DNS-001 alerts remain". |
| "Ads and tracking" | Domain rules of EasyPrivacy and EasyList. Never grouped with security: the risk of breaking a site is not the same. |
| Always | Nothing from the compiled protection list, nothing the user has allowed. |
