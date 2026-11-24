# Detection rules: rule sheets (phase 3)

Inventory of the detections **that already exist** in the service. No new rule. Each sheet gives the identifier
of the rule, what it covers, the telemetry it depends on and what happens if that telemetry is missing, its level,
its expected false positives, its tests and its measurement status.

**Since PR 3.2, every alert carries the identifier of its rule** (field `Regle`, registry `service-rs/src/regles.rs`). A test checks
that this document and the registry list the same identifiers.

**"ATT&CK" line of each sheet (ATT&CK coverage, batch 3)**: taken from the same table as the code; a test
(`attack_lot3_fiches_et_table_concordent`) compares each sheet with the table, so the documentation can no longer diverge.

**ATT&CK technique (ATT&CK coverage, batch 2)**: it comes from the rule identifier, through a single table placed
in the registry (`regles.rs`, field `techniques`, ATT&CK v20.1, based on `docs/validation/carte-attack.md`), and never
again from words in the alert text. Three cases: fixed list; techniques set by the code that produces the alert, for
rules with several behaviours (CHA-001: those of the signals of the chain; COR-R7: that of the event;
VIE-001: camera T1125 or microphone T1123; VIE-002: T1219, or T1572 for ngrok; EXP-NDR-001, EXP-DPI-001; EXP-IDS-001
sets none); "none", stated
explicitly (health, response, integrity, generic Defender detections, RES-006, COR-R6). The "What to do" advice
is still chosen by keywords (`mitre.rs`). Decisions with no gap from the map, taken in the maintainer's absence
(2026-11-22, decision log): DNS-002 and DNS-003 T1557; VOL-001 T1555.003 and T1539; COR-R1 T1110.

The levels given are those the code produces **before** learning and exceptions: `apprentissage::filtrer`
may turn an "Alert" into "Info". Only the "Critical" and "Info" levels are guaranteed as they are.

Measurement status: no sheet is **consolidated** (10 valid trials, `CLAUDE.md`) nor has false positives counted in the
field. Since this paragraph was written, each domain rule has its positive and negative tests in the lab, and
several have a measurement in a VM or in the Kali campaign, stated on their sheet (RES-003, PER-001, RES-001, DNS-001,
PRC-002, LEU-002, VOL-001, correlations). The domain PRs of phase 3 measure them one by one (in the lab, then in a VM when it is
allowed) and update the sheet and `docs/roadmap/capability-matrix.md`.

Form rules:

- identifier `DOM-NNN`, never reused; a withdrawn rule stays listed, marked "withdrawn";
- `COR-R1` to `COR-R10` keep the current SIEM numbers (`incidents.json`);
- `EXP-*`: experimental modules (IDS, DPI, NDR), frozen during phase 3: only a rule identifier line was
  added to their alerts (PR 3.2), with no other change of logic (maintainer, 2026-10-25, see `CLAUDE.md`);
  unfrozen since then (IDS and NDR on 2026-11-16, DPI on 2026-11-18, `CLAUDE.md`, « Unfreezing of the IDS, NDR and DPI » paragraph);
- an alert that gathers several clues from the same domain carries the identifier of the strongest rule it
  contains (for example PRC-001 and PRC-002 in the same alert: PRC-001; `processus::regle_retenue`). An alert
  carries only one rule. For command lines, all patterns are searched for and named in the reasons, and the
  deletion of backups (PRC-005) takes precedence over the other patterns (PR 3.7).

"If the telemetry is missing" describes the behaviour of the detections themselves: in most cases, the rule stays
silent. Since PR 3.3a, this silence is published in `etat.json`: `Collectes` gives the status of each telemetry
source and `ReglesSansCollecte` the rules for which a required source is not read (a source never recorded counts
as not read). Since PR 3.4, the interface shows it: the empty alert list says "No alerts." only if
each detection has its collection, otherwise it names the silent detections and the sources they lack; a
yellow badge counts the failed collections. Rule → sources mapping:
`collectes::besoins`. Since PR 3.3b, all sources are recorded: connections, process list, logs
(Defender, Security, System, firewall, DNS, Sysmon), Defender status, process WMI, threat and
domain lists, LOLDrivers, autostart inventory, process creation audit (4688), baseline, decoys, data audit (SACL), `pfirewall.log`,
extensions, consent store (camera, microphone), traffic and local network capture. Following no
source: RES-004, SYS-001, VIE-003, COR-R6, INT-001, INT-002, INT-003, and the SAN-* health findings (which concern the
collections themselves). By default, the domain lists are all under a restricted
licence and switched off: `ListesDomaines` is "Desactivee" and DNS-001 "sans collecte".

What "Active" guarantees: the source is **read** (for a followed log, the number of the last event and the
new events are read; an interrupted read turns "Indisponible" and the events are read again at the next
round; since PR 3.3c, a disabled log turns "Indisponible" even if it remains readable, and the
DNS-Client log is re-enabled: decision D4). It does not guarantee that Windows **produces** the expected events. Known
undetected cases:
- audit policy changed (logons not audited: COR-R1, R2, R3, R9 remain covered);
- Sysmon configured without event 22 (it still covers DNS-001), or Sysmon service stopped while its log
  remains readable;
- threat lists loaded from an old local copy (the age is not tracked);
- `JournalSecurite` recorded by three readers (SIEM, file access 4663, process creations 4688): a single one failing is not visible, the others
  continuing to read the same log;
- the data audit (SACL) being set does not prove that the object access audit policy is active: without it,
  no 4663 is produced (VOL-001, LEU-002); the audit set on the decoys themselves is not tracked (log only);
- capture: "Active" says that the capture thread is running, not that it receives packets (a reception that always
  fails is not seen);
- decoys: "Active" says that at least one decoy is followed, not that each profile has one;
- data audit: a folder whose traversal is truncated (20,000 items) or from which items are excluded
  (links) counts as audited;
- `pfirewall.log`: a file that is present while packet logging has been switched off is still read ("Active");
- autostarts: a partial but non-empty inventory counts as read;
- sleep or hibernation: the delay of three intervals is counted in wall-clock time; on wake-up, the sources with a long
  interval (baseline, Defender, extensions: 10 min; audit, lists: 1 h) may remain "Indisponible" until
  their next read (fail closed).

Reading a followed log:
- by windows of at most 5,000 numbers (PR 3.3c): a window read to the end advances to its bound, even without
  any retained event; a log flooded with events that the query discards therefore no longer freezes the read; the windows
  follow one another within a single round as long as they are read to the end, 1.5 s at most, then the next round resumes;
- disabled log (still readable, but Windows no longer writes to it): "Indisponible", one line in `journal.txt`; the
  DNS-Client log is re-enabled (one attempt per episode, D4), the others are only reported; a log switched off
  by the service itself (baseline rollback, requested by the administrator) is left off and recorded
  "Desactivee", until it is re-enabled by some other means (a later switch-off by a third party is then
  re-enabled again); limit: this switch-off is kept only in memory, and when the service restarts the
  DNS-Client log is re-enabled as at every start (the rollback only holds until then);
- blind spots of disabling: a switch-off followed by a re-enabling leaves no trace of the range during
  which Windows wrote nothing; a switch-off and a re-enabling by a third party between two rounds (2 s) are not
  seen; an unreadable channel configuration is taken as "enabled";
- an exceeded timeout (very busy log) is not a blockage: nothing is skipped, the read resumes at the next round where
  it stopped; the collection is "Partielle" as long as the read progresses;
- rounds without progress (exceeded timeouts and errors counted together): after 30 rounds (one minute), on a timeout, nothing
  is skipped and the collection turns "Indisponible"; on an error (unreadable event), a single number is skipped,
  just after the last one read, then 2, 4… if the blockage persists; the skip is written to `journal.txt`; the events
  lost are those of the skipped numbers: at most twice the gap between the last one read and the faulty event;
- events overwritten by log rotation before being read: checked before each window read (a small
  log, such as DNS-Client or Defender, rotates within a few thousand events); the read resumes at the oldest
  number still present, the loss is counted and written to `journal.txt`; a log that grows faster than the
  service reads it (more than 5,000 numbers per window, 1.5 s of reading per round of 2 s) thus ends up losing
  events, counted;
- after a skip or a rotation, the collection remains "Partielle" for one hour ("N numéro(s) d'événement perdu(s)").

A log that is unreadable at startup is followed anyway: its thread retries every 2 s and following starts from the
first successful read (events written in the meantime are not read again). Sysmon unreadable at startup: the audit
of process creations (4688) takes over, otherwise WMI.
Process creations without Sysmon (ATT&CK coverage, batch 1): rules PRC-001 to PRC-005 and the chains read the
4688 events of the Security log, which carry the program, its command line and its parent even for a
process that has already ended. Collection `AuditProcessus`, read again every 5 min, and earlier (at most once per minute) when a 4688 arrives while the audit is recorded as inactive, which happens just after installation, when the baseline enables the audit: "Active" (audit active, command line
configured and seen); "Partielle" (command line absent: PRC-001 reads the 4688, PRC-002 to PRC-005 take the command
line from WMI); "Desactivee" (audit never enabled: the baseline is not applied, like Sysmon absent);
"Indisponible" (audit switched off after having been active, unreadable setting, unreadable Security log). In the last three
cases, the fallback to WMI is stated in the reason, and a managed machine (baseline read-only) is named. Both
sources analyse each creation (no window without analysis when the audit is switched off or the log blocked); the same
rule raised for a PID and the same program within 30 s is not repeated by the other source. Limits: an audit
switched off before a restart of the service is reported "non activé" (the state is kept only in memory); a Windows whose
`auditpol` is neither in English nor in French makes the audit read as "non activé" (WMI takes over); a frozen `auditpol`
leaves the state at the last inventory (WMI analyses anyway); a late 4688 does not replace, in the tree of
chains, a living process with the same PID; command lines capped at 1,024 characters in the tree, 300 in the
published chains, 8,192 in the cache.
"Partielle" (WMI without Sysmon or active audit): short-lived processes may be missed, PRC-001 to PRC-005 are published
as degraded.

Domains: `RES` connections, `DNS`, `PRC` processes, `CHA` process chains, `PER` persistence, `DEF` Defender,
`LEU` decoys, `VOL` data theft, `SYS` hosts file and firewall, `PIL` drivers, `EXT` browser extensions,
`VIE` privacy and remote access, `BAS` baseline, `COR` SIEM correlations, `INT` service integrity, `EXP`
experimental modules.

---

## RES: connections

### RES-001 : connection to an address or a domain from the threat lists
- **ATT&CK** : T1071.001 Web protocols.
- **Code**: `moniteur.rs` (pass, "threat" branch, level Critical).
- **Rationale**: a program on the machine talks to a known malicious infrastructure (Spamhaus DROP, Feodo
  Tracker, domain lists); it is the most direct sign of an active infection.
- **Telemetry**: TCP connection table, loaded threat lists; DNS log to link a domain.
- **If it is missing**: unreadable table: no connection seen; empty or absent lists: the rule stays silent.
- **Level**: Critical. May trigger automatic blocking (level 3 of `docs/reponse/politique.md`).
- **Expected false positives**: shared address (shared hosting) added to a list; outdated list. False positives measured in a VM (`mesure` scenario, 22 min of synthetic activity, service in learning mode): none; no threat list is loaded in the VM. The
  measurement underestimates them: new account, few programs, local connections only.
- **Tests**: `res_001_positif` (address from a synthetic list found, score 10, alert even for a connection already
  open at startup), `res_001_negatif` (private address rejected when the list is loaded; absent address);
  pure decisions `moniteur::score_flux` and `moniteur::regle_flux` (PR 3.8). Not exercised in the VM scenarios; measured
  in the Kali campaign (`docs/validation/campagne-kali-second-lot.md`, 2026-11-15: TP in configurations A and C, with
  the 7-day blocking), not consolidated.

### RES-002 : new connection with a suspicious score (≥ 3)
- **ATT&CK** : T1071.001 Web protocols (the observed technique: a connection; exfiltration and download are not seen, auditor's review of 2026-11-22, point 1).
- **Code**: `moniteur.rs` (computation of the flow score, level Alert).
- **Rationale**: gathers weak clues which, together, describe a malicious program that goes out to the Internet.
- **Clues** (a single rule, each clue named in `Raisons`): unsigned program; temporary or
  downloads folder; recently downloaded file; suspicious command line; direct IP address without a DNS query;
  beacon (regular connections); unusual port; telemetry.
- **Telemetry**: connections, processes (path, signature, command line); the "direct IP" clue requires the
  DNS log.
- **If it is missing**: without a read of the DNS log for more than three intervals (90 s), the "direct IP" clue is
  not counted (PR 3.3b: it followed the state of the log at startup and could trigger wrongly); a switched-off DNS log
  is re-enabled, or, if it cannot be, recorded as unavailable (PR 3.3c, D4), and the clue drops 90 s later; without a command
  line (WMI), the corresponding clue is missing.
- **Command line read** (finding T-2 of 2026-11-23, fixed, tested in the lab, to be tried in a VM): the one from the process
  information cache only if the entry describes the program that holds the connection (identical full
  path, case ignored), otherwise a WMI query of the living process, kept under the same check. Before, an
  entry kept for one hour under a reused PID was attributed to the new program: a gh connection carried
  "PowerShell obscurci", coming from a cmd that had had the same PID 25 min earlier. Test:
  `processus_cache_pid_reutilise_jamais_prete`. Reservation from the pre-review of #283: a connection whose program
  path is unreadable (protected process, already ended) loses all this context: no command line is
  read, neither from the cache nor from WMI (cautious direction: never a borrowed line, at the cost of a missed clue).
- **Connections already open at startup** (audit of 2026-11-23, B-1-01, fixed; tested in the lab, to be tried in a VM):
  they do not get the "direct IP" clue as long as they stay open; once closed (TCP table read without them),
  they lose this mark, and if reopened later they are judged as new (`moniteur::purger_preexistants`).
  Before, the table of these connections was never purged: a connection reopened hours after startup
  no longer had the clue. A failed read of the TCP table purges nothing. Limit: a connection whose program
  path becomes unreadable for the duration of one pass changes key and also loses the mark.
- **Level**: Alert.
- **Expected false positives**: messaging or gaming applications that connect without DNS; unsigned internal
  tools. False positives measured in a VM (`mesure` scenario, 22 min of synthetic activity, service in learning mode): none. The
  measurement underestimates them: new account, few programs, local connections only.
- **Tests**: `res_002_positif` (unsigned; direct IP and unusual port; unsigned, downloaded yesterday and beacon),
  `res_002_negatif` (ordinary connection; Internet origin of a signed program; browser without DNS; DNS log not read;
  connection already open at startup; connection already seen or first pass),
  `res_002_preexistantes_purgees_a_la_fermeture` (mark kept as long as the connection is open, purged when it
  closes, nothing purged on a failed read; wiring); existing for the "direct IP" clue:
  `ip_directe_editeurs_exacts`. Pure decision `moniteur::score_flux` (PR 3.8): the clues are read in the cycle, the
  computation is tested separately. The clues not covered one by one: temporary folder, suspicious command line,
  telemetry (each adds its weight, like those tested).

### RES-003 : first Internet connection of a program
- **ATT&CK** : T1071.001 Web protocols (the observed technique; the launch by the user is not seen).
- **Code**: `moniteur.rs` (level Info).
- **Rationale**: gives the history of "who talks to the Internet"; useful for the investigation, not an alarm.
- **Telemetry**: connections.
- **If it is missing**: the rule stays silent.
- **Level**: Info.
- **Expected false positives**: each new program or new version (expected, by nature). Measured in a VM
  (`mesure` scenario, 22 min, new account): 9 to 13 Info alerts, i.e. 24 to 35 per hour, mostly at first use
  (OneDrive, Edge, Windows services).
- **Tests**: `res_003_positif`, `res_003_negatif` (learning; first pass); pure decision
  `moniteur::premiere_connexion_signalee` (PR 3.8). Exercised in a VM (Info alerts of the `mesure` scenario).

### RES-004 : public address directly on the PC
- **ATT&CK** : T1133 External remote services.
- **Code**: `moniteur.rs` ("PC EXPOSÉ À INTERNET : adresse publique directement sur le PC").
- **Rationale**: a PC with no router or NAT in front of it is reachable from the Internet.
- **Conditions**: check every 100 passes of the cycle; the alert fires when a public network appears on a network
  adapter since the previous inventory: a public IPv4 address, or a global IPv6 /64 prefix, regardless of the
  adapter name. Temporary IPv6 addresses, which Windows renews every day within the same prefix, do not count
  (review of #87, D1 and R2-D1). Before
  PR 3.8, only a rising **number** of addresses raised an alert. A PC already exposed when the service starts triggers no
  alert (addresses recorded at startup). Unchanged limit: an inventory that fails returns an empty list, and the addresses
  seen again at the next inventory pass for new ones.
- **Telemetry**: network adapter addresses.
- **If it is missing**: the rule stays silent.
- **Level**: Alert.
- **Expected false positives**: corporate network with deliberate public addresses; global IPv6 (depending on the case);
  ISP that changes the IPv6 prefix every day: at most one alert per day, consistent with the rule (review of
  #87).
  False positives measured in a VM (`mesure` scenario, 22 min of synthetic activity, service in learning mode): none; the VM has no public address. The
  measurement underestimates them: new account, few programs, local connections only.
- **Tests**: `res_004_positif` (address appeared; address that replaces another one; new IPv6 prefix),
  `res_004_negatif` (same addresses; address gone; temporary IPv6 address renewed within the same prefix; same
  address on another adapter), on the recorded form "address (adapter)", which `res_004_forme_du_releve` ties to the code that
  produces it; pure decision `moniteur::alerte_adresses_publiques`. PR 3.8: address-by-address comparison;
  before, only a rising number of addresses raised an alert, and a public address that replaced another one went
  unnoticed (false negative, fixed). Not exercised in a VM.

Note (U5c-2): the RES-004 alert is unchanged. Only the interface badge changes: a global IPv6 alone gives "exposure to watch" (orange), no longer "PC exposed" (red); a public IPv4 remains "PC exposed". A UPnP redirection to this PC seen only by a check older than 30 min no longer gives "PC exposed" (not verified, cited in the finding); the original UPnP alert is not withdrawn.

### RES-005 : incoming packet from the Internet
- **ATT&CK** : T1133 External remote services.
- **Code**: `parefeu.rs` (firewall log, "PC EXPOSÉ À INTERNET : paquet entrant …").
- **Rationale**: an incoming packet from a public address, especially an accepted one, shows an exposed PC.
- **Telemetry**: `pfirewall.log` (Windows firewall packet logging).
- **If it is missing**: firewall log disabled or unreadable: the rule stays silent.
- **Level**: Critical if the packet is accepted, Alert if it is blocked. One alert per source, port and action within
  24 h.
- **Expected false positives**: router in DMZ or intended port forwarding (also pointed out by the UX review).
- **Tests**: `res_005_positif` (packet to a listening port; echo request), `res_005_negatif` (reply to an ephemeral
  port; UDP reply; echo reply), on `parefeu::exposition_reelle`; existing, from the log to the alert:
  `exposition_reelle_sans_faux_positifs`, `exposition_udp_reponse_reconnue_par_le_flux`,
  `exposition_paquet_bloque_reponse_a_un_flux`. False positives measured in a VM (`mesure` scenario, 22 min of synthetic activity, service in learning mode): none; the VM is not exposed to the Internet. The
  measurement underestimates them: new account, few programs, local connections only.

### RES-006 : new port open and listening on the network
- **ATT&CK** : aucune (none).
- **Code**: `surveillances.rs` (`ports_ouverts`).
- **Rationale**: a program that starts listening on the network may be a backdoor.
- **Telemetry**: TCP connection table (listening ports), program signature.
- **If it is missing**: unreadable table: no port seen; first inventory (`ecoutes-connues.json` absent): learning,
  no alert, intended.
- **Level**: Alert if the program is not signed, Info otherwise.
- **Expected false positives**: software that opens a local service port (synchronisation, sharing).
  False positives measured in a VM (`mesure` scenario, 22 min of synthetic activity, service in learning mode): none. The
  measurement underestimates them: new account, few programs, local connections only.
- **Tests**: `res_006_positif` (learning at the first inventory; new port: Alert if unsigned, Info otherwise),
  `res_006_negatif` (loopback; Windows dynamic RPC port; port already known); `surveillances::ports_ouverts`
  made testable (path of a PID passed as a parameter, writing of `ecoutes-connues.json` left to the caller, PR 3.8).

### RES-007 : incoming connection from the Internet
- **ATT&CK** : T1133 External remote services.
- **Code**: `surveillances.rs` (`ports_ouverts`, "CONNEXION ENTRANTE depuis Internet").
- **Rationale**: someone from the Internet is connected to a listening port of the PC. Distinct from RES-005: it comes from
  the TCP table (established connection), not from the firewall log.
- **Telemetry**: TCP connection table, program signature.
- **If it is missing**: unreadable table: the rule stays silent.
- **Level**: Critical if the program is not signed, Alert otherwise.
- **Expected false positives**: deliberately exposed server (game, intended remote access). False positives measured in a VM (`mesure` scenario, 22 min of synthetic activity, service in learning mode): none; the VM is not exposed to the Internet. The
  measurement underestimates them: new account, few programs, local connections only.
- **Tests**: `res_007_positif` (connection established from the Internet on a listening port: Critical if unsigned, Alert
  otherwise), `res_007_negatif` (incoming connection from the local network; outgoing connection); `surveillances::ports_ouverts`.
  Not exercised in a VM.

## DNS

### DNS-001 : DNS query to a known malicious domain
- **ATT&CK** : T1071.004 DNS (the observed technique; the phishing link is not seen).
- **Code**: `moniteur.rs` ("requête DNS vers un domaine MALVEILLANT connu").
- **Rationale**: the resolution of a malware command or distribution domain, even without a connection.
- **Telemetry**: DNS-Client log (or Sysmon 22), domain lists.
- **If it is missing**: DNS log switched off after startup: never seen today, the rule stays silent.
- **Level**: Critical.
- **Expected false positives**: domain removed late from a list; resolution caused by a security tool.
  False positives measured in a VM (`mesure` scenario, 22 min of synthetic activity, service in learning mode): none; no domain list is enabled by default. The
  measurement underestimates them: new account, few programs, local connections only.
- **Tests**: `dns_001_positif` (domain from a synthetic list, case ignored), `dns_001_negatif` (other
  domain; subdomain, since the lists carry exact names; empty name); pure decision `moniteur::alerte_dns`
  (PR 3.8). Not exercised in the VM scenarios (it would need a test domain list loaded by the service);
  measured in the Kali campaign with a synthetic list (`campagne-kali-second-lot.md`, 2026-11-15: TP in
  configurations A and C), not consolidated.
- **Phase 7**: filtering by domain name is in the code (PR 7.2 to 7.6); the blocking of a name by the filtering is
  counted in the "latest blocks" of the "Browsing" page, without changing this alert.

### DNS-002 : DNS server changed on an adapter of the machine
- **ATT&CK** : T1557 Adversary-in-the-middle.
- **Code**: `dns_surveillance.rs` (`releve`, `changements_dns`); "dns" thread of `moniteur.rs` (phase 7, PR 7.1).
- **Rationale**: a program that sets a static DNS server on an adapter of the machine routes all
  resolutions through it (fake bank site, fake town hall portal); the hosts file (SYS-001) does not show it.
- **Limit**: a compromised router that hands out a malicious server through DHCP is not reported: a change given
  by the network is only an event (review of #159, finding 2).
- **Telemetry**: effective DNS servers, gateways and type of each active adapter (`GetAdaptersAddresses`), and
  any static server (`NameServer` under `Tcpip\Parameters\Interfaces\{GUID}` and its `Tcpip6` equivalent); inventory
  every 60 s, outside the monitor lock; the first inventory serves as the reference, without an alert.
- **Decision** (`changements_dns(avant, apres)`, pure; only the adapters whose DNS servers change are examined):
  - **static** server added or changed on a physical adapter (Ethernet, Wi-Fi): alert, even if the gateway
    changes at the same moment (a server set by hand does not come from the network; the gateway is cited);
  - non-static change that goes with a network change (another gateway): mini-SIEM event (`dns`,
    `serveur-dns`) only (laptop that changes Wi-Fi);
  - change given by DHCP on the same network: event only;
  - virtual and VPN adapters: event only;
  - new or vanished adapter: nothing.
  Nothing is restored (read-only). The case "filtering active and port 53 of the loopback held by another
  program" is rule DNS-003 (PR 7.5a); nothing is restored automatically after a change by a
  third party (D7-10, recommendation of the design file applied, without a written decision from the maintainer).
- **If it is missing**: `GetAdaptersAddresses` failing: collection `ConfigDns` unavailable, never "no change";
  the reference is kept, a change made during the outage is reported on recovery.
- **Level**: Alert. Strong signal: never learned nor softened by learning; a "stop alerting" exception
  only covers the set of servers of the alert (cited in the destination).
- **Expected false positives**: a user or a contractor who sets a DNS by hand (correct alert, but
  intended); a parental control software or a VPN that modifies the physical adapter.
- **Tests**: `dns002_statique_change_meme_reseau` (positive, Ethernet and Wi-Fi), `dns002_statique_change_avec_passerelle`,
  `dns002_jamais_appris_exception_par_serveurs`; `dns002_changement_de_reseau_sans_alerte`
  (another gateway, DHCP on the same network, DNS unchanged, new or vanished adapter), `dns002_carte_vpn_sans_alerte`,
  `dns002_lecture_impossible_collecte_indisponible` (negatives); in a VM (3a), retained control (static DNS set on the
  VM's adapter, network unchanged: alert) and discarded control (back to DHCP: no alert).

### DNS-003 : DNS port of the loopback held by another program, adapter still set to the resolver
- **ATT&CK** : T1557 Adversary-in-the-middle.
- **Code**: `moniteur.rs` (`reprendre_filtrage`, `alerte_port_dns_tenu`) (phase 7, PR 7.5a; audit of #164, S164-05).
- **Rationale**: filtering enabled, the service restarts and cannot bind port 53 of the loopback, while
  an adapter still points to `127.0.0.1` or `::1` (restoring impossible): the program that holds the port can
  answer all name resolutions of the machine, SYSTEM included.
- **Telemetry**: failure of the resolver's exclusive bind; re-read of the adapters' registry (`NameServer`);
  UDP table (`GetExtendedUdpTable`) for the PID that holds port 53.
- **If it is missing**: adapter inventory impossible (collection `ConfigDns` unavailable): the rule stays silent. It is not
  tied to `FiltrageDns`, which is unavailable precisely when it triggers (review of #165, R70).
- **Level**: Critical (strong signal, never softened by learning).
- **Expected false positives**: another legitimate resolver installed after filtering was enabled (connection
  sharing, Docker, WSL): the alert remains correct, the adapter points to it without anyone having wanted it.
- **Tests**: `filtrage_alerte_port_dns_tenu`.

## PRC: processes

### PRC-001 : office document that launches an interpreter
- **ATT&CK** : T1566.001 Spearphishing attachment; T1204.002 Malicious file launched by the user.
- **Code**: `processus.rs` (`analyser`, "macro ou exploit probable").
- **Rationale**: Word, Excel or a PDF reader that launches PowerShell, cmd, wscript… is the mark of a macro or
  of an exploit. Additions from the audit of 2026-11-23 (done by Claude, A-7-8, fixed, tested in the lab): document `olk` (name
  of the program of the new Outlook, olk.exe); interpreters `hh` (compiled help .chm, which runs a script),
  `msiexec` (MSI package that runs actions), `forfiles` (runs a command for each file), `cmstp`
  (connection profile that runs a script, T1218.003), `odbcconf` (loads a DLL), `regasm` and `regsvcs` (run
  the code of a .NET assembly), `msxsl` (XSL stylesheet that carries a script): none has any reason to be launched by
  a document. `conhost` is not retained: Windows creates it for every console, an Office add-in that opens one
  would give a Critical false positive, and the child of a `conhost --headless` is still seen by the other rules.
- **Telemetry**: process creation with the parent (Sysmon 1, otherwise event 4688 of the Security log, otherwise WMI).
- **If it is missing**: without Sysmon or process creation audit, WMI feed stopped: the source remains displayed as "WMI"
  and the rule stays silent.
- **Level**: Critical (strong signal, never softened by learning).
- **Expected false positives**: corporate templates that launch a legitimate script. False positives measured in a VM (`mesure` scenario, 22 min of synthetic activity: programs launched, files written, local
  connections): none, a figure that underestimates them: the VM has no Sysmon (command lines of short-lived processes lost by WMI),
  and the activity launches no interpreter, no LOLBin tool and no Office.
- **Tests**: `prc_001_positif` (Word that launches PowerShell, with or without a command line, and with a PowerShell pattern in
  addition: PRC-001 takes precedence), `prc_001_negatif` (PowerShell launched by Explorer; Word that launches a program that
  is not an interpreter), `prc_001_interpreteurs_elargis` (A-7-8: each of the added interpreters launched by Word,
  PowerShell launched by the new Outlook; conhost launched by Word: nothing); pure decision `processus::alerte_processus`.
  Not exercised in a VM: no Office in the VM.

### PRC-002 : obfuscated PowerShell or PowerShell that downloads code
- **ATT&CK** : posée par l'alerte (set by the alert), based on the patterns that matched: obfuscation (`-EncodedCommand` or one
  of its abbreviations with a long payload, `FromBase64String`) T1059.001 PowerShell and T1027 Obfuscated code;
  download, execution of a string or hidden window (`DownloadString`, `DownloadFile`, `Net.WebClient`,
  `Invoke-Expression`, `IEX` with a download, `irm`, `iwr`, `Invoke-WebRequest`, `Invoke-RestMethod` or
  `Start-BitsTransfer` to an http(s) address, `-WindowStyle Hidden`) T1059.001 alone. A line that has both carries
  both. Behaviour code `obscurci`, `telecharge` or both.
- **Code**: `processus.rs` (expression "PowerShell obscurci ou qui télécharge du code", `MOTIFS_PRC002`,
  `ligne_pour_motifs`).
- **Rationale**: long `-EncodedCommand`, `DownloadString`, `IEX` from an address: typical code loading.
- **Telemetry**: command line (Sysmon 1, otherwise event 4688 with its command line, otherwise WMI as long as the
  process is alive).
- **If it is missing**: without Sysmon or a 4688 carrying the command line, process ended before the WMI read: command
  line absent, the rule stays silent.
- **Level**: Alert.
- **Expected false positives**: encoded administration or installation scripts; since A-7-1, a download from the
  command line to an http(s) address, even to an intranet and without `iex`
  (`powershell -c "Invoke-WebRequest https://intranet/… -OutFile …"`). Choice: it alerts, because it is rare on a
  personal machine and it is the first step of code loading; it stays at the Alert level (never Critical),
  and an exception on its behaviour code (`PRC-002:telecharge`) silences it. A script launched by `-File` does
  not alert (its content is not read). False positives measured in a VM (`mesure` scenario, 22 min of synthetic activity: programs launched, files written, local
  connections): none, a figure that underestimates them: the VM has no Sysmon (command lines of short-lived processes lost by WMI),
  and the activity launches no interpreter, no LOLBin tool and no Office.
- **Tests**: `prc_002_positif` (`-enc` of a payload of more than 40 characters; `IEX` of a `DownloadString`),
  `prc_002_negatif` (script launched by `-File`; `-enc` of a short text; `Get-Help Invoke-WebRequest`; address
  displayed without download; `-ExecutionPolicy` followed by a long text; `-File` script with an address as argument),
  `prc_002_formes_elargies` (A-7-1: `irm … | iex`, `-ec`, `-enco`, `/e`, `-e "…"`, `-EncodedCommand` of pwsh,
  `iwr … -OutFile`, `Start-BitsTransfer`, `Invoke-RestMethod … | Invoke-Expression`, `iwr` then `iex`, download
  to an intranet, with the behaviour code of each), `prc_002_copie_renommee_par_nom_origine` (renamed copy
  recognised by the original name `PowerShell.EXE` or `pwsh.dll`, line shown as it is; without an original name or with
  that of another program: nothing). Kali campaign (`campagne-kali-sixieme-lot.md`,
  2026-11-16): TP with Sysmon (configuration B), non-deterministic without Sysmon; not consolidated. Not exercised in the
  VM scenarios: without Sysmon, the command
  line of a short-lived process is often lost by WMI, and a download pattern would make Defender react (AMSI),
  which we do not touch.
- **Fixed false negatives** (audit of 2026-11-23, done by Claude, A-7-1, fixed, tested in the lab, to be tried in a VM):
  `irm … | iex`, abbreviations of `-EncodedCommand` (`-e`, `-ec`, `-en`, `-enc`, `-enco`…, prefix `-`, `/` or typographic
  dash, payload in quotes), `iwr … -OutFile`, `Start-BitsTransfer`, renamed copy of powershell.exe
  when Sysmon gives the original name of the file (OriginalFileName field of event 1, read from the version
  resource of the program: `PowerShell.EXE`, `pwsh.dll`).
- **Known false negatives**: renamed copy of powershell.exe without Sysmon: the 4688 and WMI events do not carry the
  original name, and the service does not read the version resource of launched programs (it would have to open it at each
  process creation, while it may already be gone); the interpreter is still searched for by its name in the
  line. An obfuscation by concatenation (`&('i'+'ex')`) will always escape the patterns: only the script block
  log (4104), enabled by the baseline and read by no rule (A-7-4), would see it.

### PRC-003 : abuse of a Windows tool (LOLBin)
- **ATT&CK** : posée par l'alerte (set by the alert): the technique of each tool seen (patterns that matched): certutil T1105 Ingress tool transfer, bitsadmin T1197 BITS jobs, mshta, regsvr32 and rundll32 (`javascript:`) T1218 System binary proxy execution, rundll32 of a DLL from a writable folder T1218.011 Rundll32, comsvcs.dll MiniDump T1003.001 LSASS memory, msiexec from an address T1218.007 Msiexec, wmic T1047 Windows Management Instrumentation.
- **Code**: `processus.rs` (`MOTIFS_PROGRAMMES`, rule PRC-003: certutil, bitsadmin, mshta, regsvr32, rundll32,
  rundll32_dll, comsvcs, msiexec, wmic; behaviour code `PRC-003:<outils vus>`).
- **What is seen** (finding T-2 of 2026-11-23, fixed, tested in the lab, to be tried in a VM): each pattern is tied to the
  program that does it (certutil.exe, bitsadmin.exe, mshta.exe, regsvr32.exe, rundll32.exe for rundll32, rundll32_dll
  and comsvcs, msiexec.exe, wmic.exe). It is read on the line of that program, recognised by the file name of its image
  or, with Sysmon, by the original name of the file (OriginalFileName, mechanism of PRC-002); and on the command that cmd
  (`/c`, `/k`, `/r`), PowerShell or pwsh (`-Command` or an abbreviation) launches at the head, or after a separator `&`, `|`,
  `;` or a parenthesis (`cmd /c certutil -urlcache …`). Before, the pattern was searched for in any text: bash, git, grep
  or echo with an argument containing `certutil -urlcache` raised alerts (false positive seen by the maintainer on their machine,
  v4.3). The tool launched by an interpreter also creates its own process, seen through its creation event (4688,
  Sysmon 1 or WMI): reading the head of the command keeps the signal when this short-lived process is missed (WMI without
  audit), at the cost of a second alert, on the interpreter, when both are seen. This is not a trust
  decision (rule 5): the name is used to detect, never to grant.
- **Rationale**: Microsoft-signed tools used to download or run code. Additions from the audit of
  2026-11-23 (done by Claude, A-7-7, fixed, tested in the lab): `rundll32 …comsvcs.dll, MiniDump <pid> <fichier> full`
  (or its ordinal `#24`) dumps the memory of a process, in practice LSASS to steal credentials; rundll32 of a
  DLL from `Users\Public`, `AppData`, `Temp` or `ProgramData` (folders where the user writes); `msiexec … http(s)://`
  installs a remote package; mshta and regsvr32 on a network path (UNC `\\hôte\partage`), `regsvr32 -i:` with a
  dash; certutil that fetches an address through `-f` or `-verifyctl`. A local MSI package or one on a deployment
  share is not targeted (ordinary installation).
- **Telemetry**: command line.
- **If it is missing**: like PRC-002.
- **Level**: Alert; Critical (strong signal, never softened) when comsvcs.dll dumps the memory of a process (A-7-7).
- **Expected false positives**: `certutil -decode` in administration scripts; an installer that launches rundll32
  on a DLL dropped in `Temp` or `ProgramData`. False positives measured in a VM (`mesure` scenario, 22 min of synthetic activity: programs launched, files written, local
  connections): none, a figure that underestimates them: the VM has no Sysmon (command lines of short-lived processes lost by WMI),
  and the activity launches no interpreter, no LOLBin tool and no Office.
- **Tests**: `prc_003_positif` (`certutil -urlcache … http`, `mshta vbscript:`), `prc_003_negatif` (`certutil -store`,
  `rundll32 shell32.dll,Control_RunDLL`, msiexec of a local package or one on a share, regsvr32 of an installed DLL,
  `certutil -verifyctl` without an address, comsvcs.dll without MiniDump), `prc_003_formes_elargies` (A-7-7: each added
  form, with the tool, the technique and the level); T-2 (shared with PRC-005): `prc_003_005_mots_en_argument_negatif`
  (bash, sh, grep, git, notepad, cmd and PowerShell with an argument containing the words of the pattern: nothing),
  `prc_003_005_outil_en_tete_d_interpreteur` (`cmd /c certutil …`, `pwsh -co "certutil …"`, `pwsh -c rundll32 …comsvcs.dll,
  MiniDump …`: seen), `prc_003_005_commandes_en_tete` (programs at the head: path in quotes, `call`, `start`,
  nothing without a command option), `prc_003_005_copie_renommee_par_nom_origine`. Not exercised in a VM (like PRC-002).
- **Known false negatives**: renamed copy of a tool (`certutil.exe` copied as `c.exe`) without Sysmon: the 4688 and WMI
  events do not carry the original name of the file (declared blind spot, as for PowerShell under PRC-002); with
  Sysmon, the original name recognises it. A tool launched by a program other than cmd, PowerShell or pwsh (bash, a
  script, `Start-Process` that passes its arguments separately) is only seen through the process of the tool itself.
  8.3 short name of a tool (`BITSAD~1.EXE`, `VSSADM~1.EXE`) in the image or at the head of the command: the name read is
  not that of the tool, the pattern does not apply; not verified (to be tried in a VM: Windows in principle writes the long
  name in the 4688 and Sysmon, but a command line may carry the short name).

### PRC-004 : browser launched in remote debugging mode
- **ATT&CK** : T1539 Steal web session cookie.
- **Code**: `processus.rs` (`--remote-debugging-port` or `-pipe` on Chrome and Chromium, Edge, Brave, Vivaldi, Opera,
  Arc, and Yandex whose program `browser.exe` is only recognised in its `YandexBrowser\Application` folder, the name
  alone being too common). Additions from the audit of 2026-11-23 (done by Claude, A-7-9, fixed, tested in the lab). Firefox
  is not retained: its cookies can be read in its profile without going through debugging (VOL-001 watches these files),
  and its remote debugging is mostly used by test tools.
- **Rationale**: cookie theft technique that bypasses browser encryption.
- **Telemetry**: command line.
- **If it is missing**: like PRC-002.
- **Level**: Alert.
- **Expected false positives**: web developers, automated test tools. False positives measured in a VM (`mesure` scenario, 22 min of synthetic activity: programs launched, files written, local
  connections): none, a figure that underestimates them: the VM has no Sysmon (command lines of short-lived processes lost by WMI),
  and the activity launches no interpreter, no LOLBin tool and no Office.
- **Tests**: `prc_004_positif` (Chrome with `--remote-debugging-port`), `prc_004_negatif` (WebView2 in debugging mode;
  normal Chrome; A-7-9: Firefox in debugging mode, `browser.exe` outside the Yandex folder, normal Vivaldi),
  `prc_004_navigateurs_chromium` (Vivaldi, Opera, Yandex, Arc, Chromium in debugging mode); existing:
  `debogage_a_distance_ancre_sur_l_executable`. Not exercised in a VM (like PRC-002).

### PRC-005 : deletion of backups
- **ATT&CK** : T1490 Inhibit system recovery.
- **Code**: `processus.rs` (`MOTIFS_PROGRAMMES`, rule PRC-005: `vssadmin delete shadows`, `vssadmin resize
  shadowstorage` below 1,000 MB, `wbadmin delete catalog|systemstatebackup|backup`, `bcdedit … recoveryenabled no`,
  `bcdedit … bootstatuspolicy ignoreallfailures`, `wmic shadowcopy delete`, `diskshadow … delete shadows`;
  `Win32_ShadowCopy` deleted by `Remove-WmiObject`, `Remove-CimInstance` or `.Delete()` on the PowerShell line;
  text `delete shadows` passed to diskshadow launched after `|` or `&` on the cmd or PowerShell line).
- **What is seen** (finding T-2 of 2026-11-23, fixed, tested in the lab, to be tried in a VM): each pattern is tied to the
  launched program: vssadmin.exe, wbadmin.exe, bcdedit.exe, wmic.exe, diskshadow.exe, recognised by the file name of
  the image or, with Sysmon, by the original name of the file (OriginalFileName, mechanism of PRC-002 reused); the forms
  specific to PowerShell (WMI or CIM) on a powershell.exe, pwsh.exe or powershell_ise.exe image, or a renamed copy
  of PowerShell recognised by Sysmon. The tool launched at the head of the command by cmd (`/c`, `/k`, `/r`), PowerShell or pwsh
  (`-Command` or an abbreviation), or after a separator `&`, `|`, `;` or a parenthesis, is still seen on the line of
  the interpreter: `cmd /c vssadmin delete shadows /all`, `powershell -c "vssadmin delete shadows"`, `cmd /c call bcdedit
  …`. Decision: the tool also creates its own process, seen through its creation event (4688, Sysmon 1 or WMI), but
  such a short-lived process may be missed by WMI without audit; keeping the head of the command keeps the signal, at the cost of a
  second Critical alert (on the interpreter) when both are seen. Before, the pattern was searched for in any text:
  bash, git, grep or echo with an argument containing `vssadmin delete shadows` raised a Critical alert (false positive
  seen by the maintainer on their machine, v4.3). The file name is used here to detect, never to trust (rule 5
  does not apply).
- **Rationale**: step that almost always precedes encryption by ransomware.
- **Telemetry**: command line.
- **If it is missing**: like PRC-002.
- **Level**: Critical (strong signal, never softened), even when the line contains other patterns. Before PR 3.7,
  only the first pattern found counted: a line such as `… DownloadString(…); vssadmin delete shadows` carried only
  PRC-002, at the Alert level (false negative, fixed).
- **Expected false positives**: deliberate cleanup of snapshots by an administrator. False positives measured in a VM (`mesure` scenario, 22 min of synthetic activity: programs launched, files written, local
  connections): none, a figure that underestimates them: the VM has no Sysmon (command lines of short-lived processes lost by WMI),
  and the activity launches no interpreter, no LOLBin tool and no Office.
- **Tests**: `prc_005_positif` (`vssadmin delete shadows`, `bcdedit … recoveryenabled No`, and the line that downloads
  code then deletes the backups: PRC-005, Critical, both patterns in the reasons), `prc_005_negatif`
  (`vssadmin list shadows`, `wbadmin get versions`; A-7-3: reading snapshots through WMI, `vssadmin list shadowstorage`,
  enlarging the snapshot space in %, in GB or unlimited, `diskshadow /s` alone, `diskshadow list shadows`,
  `bootstatuspolicy displayallfailures`); the forms added by A-7-3 are in `prc_005_positif`; T-2:
  `prc_003_005_mots_en_argument_negatif` (`grep "vssadmin delete shadows" notes.txt`, `echo vssadmin delete shadows`,
  `git commit -m "certutil -urlcache …"`, bash, sh, cmd and PowerShell with these words as an argument, `findstr "delete shadows"
  diskshadow.log`: nothing), `prc_003_005_outil_en_tete_d_interpreteur` (`cmd /c vssadmin …`, `cmd /c ""…\vssadmin.exe"
  …"`, `cmd /c echo o & vssadmin …`, `cmd /k (wbadmin …)`, `powershell -c "vssadmin …"`, `& '…\vssadmin.exe' …`,
  `… ; wmic shadowcopy delete`, text passed to diskshadow), `prc_005_formes_powershell_liees_a_l_interpreteur`
  (PowerShell, pwsh, ISE, renamed copy with and without an original name; cmd, wmic, bash: nothing),
  `prc_003_005_copie_renommee_par_nom_origine` (copy of vssadmin: nothing without an original name, PRC-005 with it). Not exercised in a VM:
  without Sysmon, the command line of such a short-lived process is often lost by WMI, the scenario would be unstable.
- **Fixed false negatives** (audit of 2026-11-23, done by Claude, A-7-3, fixed, tested in the lab, to be tried in a VM):
  `Get-WmiObject Win32_ShadowCopy | Remove-WmiObject`, `Get-CimInstance Win32_ShadowCopy | Remove-CimInstance`,
  `vssadmin resize shadowstorage … /maxsize=401MB` (a size below 1,000 MB erases the snapshots),
  `wbadmin delete backup`, `bcdedit /set … bootstatuspolicy ignoreallfailures`, `diskshadow` whose line says
  `delete shadows` (including a script written then passed by `/s` in the same line).
- **Known false negatives**: `diskshadow /s script.txt` alone does not alert: the script is not read and the line does not say
  whether it deletes (diskshadow is also used for backups); nor does a size written in bytes with more than three digits
  (`/maxsize=400000000`). `wmic` is removed from Windows 11 24H2. Renamed copy of vssadmin, wbadmin, bcdedit,
  wmic or diskshadow (or of PowerShell for the WMI forms) without Sysmon: the 4688 and WMI events do not carry the
  original name of the file (declared blind spot, finding T-2); with Sysmon, it is seen. A tool launched by a
  program other than cmd, PowerShell or pwsh (bash, a script, `Start-Process` that passes its arguments separately) is only seen
  through the process of the tool itself. 8.3 short name of a tool (`BITSAD~1.EXE`, `VSSADM~1.EXE`) in the image or at the head of the command: the name read is
  not that of the tool, the pattern does not apply; not verified (to be tried in a VM: Windows in principle writes the
  long name in the 4688 and Sysmon, but a command line may carry the short name).

## CHA: process chains

### CHA-001 : process chain with a cumulative score
- **ATT&CK** : posée par l'alerte (set by the alert): the techniques of the signals of the chain, in their order.
- **Code**: `chaines.rs` (at least two signals and a score above the threshold).
- **Rationale**: several suspicious actions from the same process descent form an attack in stages.
- **Telemetry**: process tree (process list, and 4688 creations: a short-lived process, ended before the
  list was read, keeps its parent) and signals from the other rules.
- **If it is missing**: without processes, no chain.
- **Level**: Critical.
- **Expected false positives**: installers that chain reported tools; development tools that launch
  PowerShell with `-EncodedCommand` (one alert per session, at most three per hour since T-1). False positives measured in a VM (`mesure` scenario, 22 min of synthetic activity: programs launched, files written, local
  connections): none, a figure that underestimates them: the VM has no Sysmon (command lines of short-lived processes lost by WMI),
  and the activity launches no interpreter, no LOLBin tool and no Office.
- **Tests**: `cha_001_positif` (two signals in the same descent, cumulative score at the threshold of 12: one Critical
  alert, no new alert at the same score, another one when the score rises), `cha_001_negatif` (a single signal,
  even a strong one; two signals below the threshold; two signals in two distinct descents of Explorer, which is a
  root), `cha_001_racine_par_chemin` (A-7-5: `svchost.exe` in `AppData\Local\Temp` or `taskhostw.exe` in
  `Users\Public` that launches two reported steps: one chain, one Critical alert; the real svchost and the real
  Explorer under the Windows folder remain roots; `svchost.exe` in `Windows\Tasks` is not one; unreadable
  path: not a root). Not exercised in a VM (signals from the other rules needed). Audit of 2026-11-23, T-1 and
  T-3: `t1_pid_reutilise_meme_nom_aucune_chaine_commune` (PID taken over by a process with the same name, one signal on
  each: no common chain), `t1_parent_ne_apres_l_enfant_ecarte` (replayed sequence of 4688: cmd launches pwsh, its
  PID is taken over by git then by grep twice; pwsh is never linked to grep; same decision with the
  TimeCreated times received out of order), `t1_parent_mort_avant_l_enfant_ecarte`, `t1_descendants_du_service_hors_chaine`
  (auditpol, icacls, powershell launched by the service and their conhost: no chain; the PID of auditpol taken over by a
  user program: its chain does not go back up to the service), `t1_comportement_repete_sous_le_meme_parent`
  (200 `cmd /c … pwsh -EncodedCommand` under the same parent: score 12, a single alert),
  `t1_plafond_par_chaine_et_par_heure`, `t3_entite_stable_quand_la_chaine_grossit`, `t1_chaine_sans_nom_non_publiee`,
  `t1_heure_4688` (tortured parser), `t1_creation_heures_exactes`, `t1_parent_vivait_bornes`, `t1_enfant_du_service_usurpe_signale`
  (review of #282: child of the service outside its programs, or auditpol outside System32: in the chain, reported
  T1134.004; unknown path: in the chain, without a signal).
- **Fixed false positives** (audit of 2026-11-23, T-1 and T-3, done by Claude, fixed, tested in the lab, to be tried in a VM):
  on a development machine, about a hundred Critical alerts in one hour, impossible chains ("grep → pwsh",
  "tail → bash", "deR4TizerSvc → auditpol → conhost → git"). Causes reproduced on the events of the machine
  (patterns only, no data from the machine in the repository): an ended process stays in the tree for one hour and its
  PID is quickly taken over; the child kept the PID of its parent and was linked to the next process with that PID,
  born after it (a notable share of the links of the published chain was false); the takeover of a PID was only seen if the
  name changed; the programs launched by the service (auditpol, wevtutil, powershell, curl, several times per minute)
  entered the chains; finally a tool that launches `pwsh -EncodedCommand` hundreds of times under the same parent
  (PRC-002 each time) made the score rise endlessly, and each rise raised an alert. Fixed: each process
  carries its creation time (TimeCreated of the 4688 to the nearest 100 ns; failing that, the time of the first list that saw it) and
  the bound of its end (first list where it was missing); a parent is retained only if it was born before the child and was alive at
  its creation (`chaines::parent_vivait`), otherwise the child is its own chain head; a taken-over PID (other name, other
  parent, other creation time, entry seen as ended, or second creation of the same PID) starts again without signals, even with an equal
  name (`chaines::meme_processus`); the programs that the service launches (direct children of the service, recognised by its
  own PID, never a name, whose path is exactly that of auditpol, wevtutil, powershell, curl, icacls, netsh,
  gpupdate, schtasks or conhost under System32: `chaines::programme_du_service`) and their descendants leave the
  chains, marked on entry (a PID taken over afterwards does not bring them back in); another child of the service (spoofed
  parent, T1134.004) stays in the chains and carries a signal of 5 there ("parent usurpé ?", code
  `CHA-001#parent-service`); the
  same behaviour (signal code) repeated at the same place in the chain (same sequence of programs from the head) counts
  once; at most three CHA-001 alerts per chain and per hour for rises that bring nothing new, the
  surplus counted (`mesures.json`, counter `chaines.alertes_plafonnees`); an alert that brings a new ATT&CK technique
  into the chain or a strong signal (PRC-001, PRC-005, comsvcs, LEU: `chaines::signal_fort`) always gets through,
  counted separately (`chaines.alertes_hors_plafond`); all CHA-001 alerts are Critical, the level cannot
  rise; a signal on a PID unknown to the tree no longer publishes a "PID n" chain. T-3: the incident
  entity of a chain is its head program (its path if it is known and is not an interpreter or a generic
  launcher such as cmd or powershell, otherwise `chaine:<nom>#<pid>@<heure de création>`), plus the text of the chain: a chain that grows remains a single incident. Limits: a parent seen
  only through the list (its 4688 is missing) keeps a margin of 10 s; the takeover of a PID by a process with the same name and
  the same parent, between two lists and without a 4688, is not seen (the creation time of the processes of the list is not
  read); a process created with a program of the service as its parent while that program is running (a few seconds) leaves
  CHA-001 without a signal (`docs/security/threat-model.md`); reservation from the pre-review of #282: an administrator who
  takes the service as parent by launching one of the programs of the list (for example `powershell.exe` from System32)
  is treated as a program of the service, their chain leaves CHA-001 without a signal (the list says which programs, not
  which ones the service launched). Planned closure: the service will remember the PIDs it launches itself, with the registry
  of PowerShell instances launched by the service planned by the 4104 phase (reservation R3 of its design file); not done here. Still open, maintainer's decision: a signed development tool that encodes its commands
  (`-EncodedCommand`) still raises PRC-002 at each launch and one CHA-001 chain per session (one alert, then at
  most three per hour).
- **Fixed false negatives** (audit of 2026-11-23, done by Claude, A-7-5, fixed, tested in the lab, to be tried in a VM):
  a root was recognised by its name alone; it is now recognised by the exact path of the system program under the
  Windows folder (`chaines::racine`, same comparison as `reponse::chemin_critique`). The path comes from the process
  list (read for root candidates), from 4688 events or from connections; unreadable path: not a root
  (cautious direction, the chain continues), walk-up capped at 32 parents.
- **Known false negatives**: a parent chosen at process creation (T1134.004, parent PID spoofing) links the
  program to a real system launcher: the chain is cut there, as before. Not fixed here (parent spoofed to the
  service itself: reported since T-1, see above). If the path of
  Explorer were unreadable, two unrelated steps launched by it would form a chain (possible false positive, cautious
  direction).

## PER: persistence

### PER-001 : new autostart
- **ATT&CK** : posée par l'alerte (set by the alert): the technique of the entry type: Run key and Startup folder T1547.001, service and driver T1543.003, scheduled task T1053.005, WMI subscription T1546.003; none for Winlogon, IFEO and AppInit (not yet in the table).
- **Code**: `persistance.rs` ("NOUVEAU démarrage automatique").
- **Rationale**: malware almost always installs itself to survive a restart.
- **Telemetry**: autostart inventory (Run keys, services, tasks…), every minute.
- **If it is missing**: first inventory (learning): no alert, intended. **Partial** inventory, without a reported failure:
  an unreadable task is skipped, a WMI failure is only recorded in the log. The entry then leaves the reference, then
  comes back at the next inventory as a "NOUVEAU démarrage automatique": false positive (at the Alert level for a WMI
  entry, marked "technique de persistance rare"), not a silence.
- **Level**: Alert if the target is judged suspicious, otherwise Info.
- **Expected false positives**: installation of software; partial inventory (above); first session of an account
  (OneDrive, per-user Windows tasks).
- **Tasks, read from the Task Scheduler** (COM enumeration, hidden tasks included, actions read through its API, one entry per action, 4,096 characters per command, 30 s at most, 20,000 tasks at most, root last): a file dropped in `System32\Tasks` is not a task, and the service opens no file in this folder; the Task Scheduler, however, can: the effect of a lock goes through the check of 3a (audits of #102, #103, #106). An action beyond the first has its own entry (": action 2"); a truncated command carries the fingerprint of the whole command and makes the entry suspicious. An anomaly is recognised by a flag set by the service, never by its text. At most 16 new tasks per inventory: those of `\\Microsoft` first, then by age, the following ones at the later inventories, which an entry states; a task deleted while waiting is never raised; a backlog of 20,000 tasks would mean 20 h of waiting; a Windows update that adds more than 16 tasks, or an incomplete first inventory, also raises this entry, on a healthy machine. An unreadable definition, an error on a folder or a bound: incomplete inventory, known tasks kept. Task Scheduler unreachable or timed out: entry "Dossier des tâches : relevé incomplet", collection "Partielle", known tasks kept in the reference; beyond 30 min of delay, collection unavailable, and SAN-001 says so after its delay. An incomplete first inventory still ends learning: the unread tasks raise "NOUVEAU" once at the next complete inventory.
- **Tasks folder, examined for its anomalies** (enumeration and metadata only, 8 levels, 5,000 items per folder, 10,000 folders, 2 million items): authenticated accounts can create items there. Link not followed, file without a registered task, unreadable registered task (access denied to SYSTEM, corrupted image), two tasks with the same displayed name, bound reached: entry "Dossier des tâches :" at the Alert level, never softened nor learned, at each appearance, including at the first inventory, at most 16 per inventory, and at most 16 duplicates, then a generic entry. A bound of this examination does not make the inventory incomplete. Limits: a standard account can raise 16 anomalies and 16 new tasks per inventory, i.e. about 1,000 alerts in half an hour, which push out the real ones; **changes to already known tasks (PER-002) have no cap**: 1,000 tasks dropped then rewritten evict 1,000 alerts per inventory (S106-12, to be fixed before distribution, with a budget per account, S106-13); a saturated folder hides the following files from the examination, not the tasks; an old machine may keep orphan files from an uninstallation: up to 16 alerts, once (not measured); a task with a DACL excluding SYSTEM and the link between the file of a task and what runs remain to be tried (S106-08, S106-09).
- **Blocked read of a file** (signature, fingerprint, `hosts`, decoys): a mere read right allows an opportunistic lock to be placed on it. 8 s at most, one read at a time per file, 16 s of waiting per minute in total; its result, even late, is picked up at the next round. Signature: "non signé" as long as it does not respond, one line in the log, nothing in the cache. `hosts` and decoys: no comparison as long as they do not respond, so a locked decoy does not raise LEU-001 (LEU-002 remains). At most 8 blocked reads at a time: beyond that, any new file is "non signé", which makes real programs appear unsigned and may get a signed backup tool that touches a decoy suspended; the guard of critical processes, on the other hand, stays closed when timed out. Drivers (`hygiene.rs`), designated by the services registry, written by an administrator, are read without a deadline, like the update package, in a folder reserved for SYSTEM.
- **Measured in a VM on 2026-11-01, service as SYSTEM, lock placed as administrator**: an open for reading of `hosts` or of an ordinary file by another process stays blocked for more than 150 s; a lock held for 5 min on `journal.txt`, `etat.json` or `reseau.json`, or on `hosts` during a blocking command, does not freeze the service: a command takes 9 s at most, **cause not established**; startup under a lock on `alertes.json`, `config.json`, `journal.txt`, `suivi-incidents.json`: service running and channel reachable within 17 s. This is not a general property: outside the service, on another machine, an open for appending under the same lock stayed blocked for more than 150 s. During the lock, `etat.json` is no longer written, without any signal, and the blocking of a domain is refused with an error (`ecrire_bloc_hosts`).
- **To fix or to verify before distribution**: S103-07 remains open, for lack of an explanation, for what is read or written under the monitor lock, by the real reader account; S104-07, startup under a lock by this account; stale `etat.json`: the interface reports it beyond 2 min or if the time is in the future, and says "status unreadable" if it can no longer be read (PR 4.6); nothing is sent upstream, and the header still reads these files on the interface thread, which a lock could freeze (S104-14, S105-07, not tried); a standard account that gets the blocking of a domain refused, without cutting off its address, simply by keeping `hosts` open for reading (S104-16, trial on an ordinary file; under a lock, measured).
- **Measured false positives** (`mesure` scenario, 22 min in a VM, service in learning mode, before PR 3.6): PER-001 Info 11,
  PER-001 Alert 5 to 6. The alerts came from two causes, fixed at the source by PR 3.6:
  - Windows `\SoftLanding\…` tasks "serveur COM non enregistré pour la machine": their COM class is packaged
    (`Classes\PackagedCom`, written by the system, that is the package deployment service), now
    resolved to the file of its package, signed. Only for a Windows package (publisher Microsoft) installed under
    `Windows\SystemApps` or `Program Files\WindowsApps`; the path read from the registry cannot leave the folder of the
    package; a class overridden in the profile of a loaded user (HKCU) is never resolved: the remark
    remains, and the task is reported as before (possible COM hijacking);
  - OneDrive `RunOnce` "lancé via cmd": the exact cleanup command of its installer is no longer suspicious, in
    `RunOnce` only; the profile name accepts neither `%` (variable replaced by cmd before the line is analysed), nor
    `^ ! ( )`, nor a control character; any variant remains suspicious.
  Limit: an override in the profile of a user whose hive is not loaded is not seen.
  Remaining at Info: OneDrive entries, Windows services and tasks that appear at the first session.
- **Tests**: `per_001_positif`, `per_001_negatif` (`persistance::comparer`), `per_001_com_empaquete_chemin_borne`,
  `per_001_nettoyage_onedrive`; existing: `tache_com_cible_le_serveur_du_clsid`,
  `tache_com_hors_windows_sans_serveur_signalee`. In a VM: test Run key to `cmd.exe /c rem` (3a, "Alerte de
  persistance produite juste avant un arrêt", end to end). Status: passed in a test VM for the Run key (scenario 3a, Defender active).

### PER-002 : modified autostart
- **ATT&CK** : posée par l'alerte (set by the alert): the technique of the entry type, like PER-001 (Run key T1547.001…); without T1112, which was not observed on its own.
- **Code**: `persistance.rs` ("démarrage automatique MODIFIÉ").
- **Rationale**: a legitimate autostart diverted to another command.
- **Telemetry**: like PER-001.
- **If it is missing**: like PER-001 (partial inventory: false "new").
- **Level**: Alert if suspicious, otherwise Info.
- **Expected false positives**: software updates (new version path).
- **Measured false positives** (`mesure` scenario, 22 min in a VM): PER-002 Info 4, the Defender tasks whose command
  moves from `Program Files` to the folder of its platform after an update. Kept (Info): a change of command
  is exactly what the rule must see.
- **Became suspicious** (PR 3.6): a known entry whose command has not changed, without a remark at the previous inventory and
  with a remark now, also raises PER-002 ("DEVENU SUSPECT"): COM class overridden afterwards in the profile
  of a user, file replaced by an unsigned file or moved to a suspicious folder. A single alert, if the
  remark is still there at the next inventory (one minute later); none during learning. A signature
  verification failure is kept in the cache for only 30 s: the next inventory redoes the verification instead of
  confirming the failure. Limits: a verification that is impossible for at least two inventories in a row (cryptographic services
  slow for more than one minute at PC startup, file locked by an update) may raise a false alert
  "NON SIGNÉ"; no scenario restarts the VM with the service installed to measure it. The wait for confirmation
  lives only in memory: if the service stops between the two inventories, the entry that became suspicious is never reported
  (the re-read reference already carries the remark).
- **Tests**: `per_002_positif` (command changed to a suspicious folder; COM entry that became suspicious: Alert),
  `per_002_negatif` (signer changed alone, command changed during learning: no alert),
  `per_002_devenu_suspect_negatif` (already suspicious, clean again, learning). Status: tested in the lab.

## DEF: Microsoft Defender

Rules DEF-003 to DEF-006 and DEF-010 to DEF-012 assume a weakened Defender: they are **never** exercised in a
VM (Defender is untouchable) and remain at best "tested in the lab".

| Id | Event or state | Level | ATT&CK |
|---|---|---|---|
| DEF-001 | 1116: threat detected | Critical | aucune (none) |
| DEF-002 | 1117: threat handled | Info | aucune (none) |
| DEF-003 | 5001: real-time protection disabled | Critical | T1685 Disable or modify protections |
| DEF-004 | 5010 / 5012: antivirus scanning disabled | Critical | T1685 Disable or modify protections |
| DEF-005 | 5007: exclusion added | Critical | T1685 Disable or modify protections |
| DEF-006 | 5007: protection weakened (real time, antispyware, tampering) | Critical | T1685 Disable or modify protections |
| DEF-007 | 1121 / 1122: ASR rule (block / audit) | Alert / Info | aucune (none) |
| DEF-008 | 1123 / 1124: controlled folder access (block / audit) | Alert / Info | aucune (none) |
| DEF-009 | 1125 / 1126: network protection (block / audit) | Alert / Info | aucune (none) |
| DEF-010 | WMI state: real-time protection switched off between two inventories | Critical | T1685 Disable or modify protections |
| DEF-011 | WMI state: tamper protection disabled | Critical | T1685 Disable or modify protections |
| DEF-012 | WMI state: antivirus disabled | Critical | T1685 Disable or modify protections |

- **Code**: `defender.rs` (`traduire` for DEF-001 to 009, `ecarts` for DEF-010 to 012).
- **Rationale**: Defender is the baseline protection of the machine; its detections and any attempt to weaken it
  must be reported.
- **Telemetry**: Microsoft-Windows-Windows Defender/Operational log (DEF-001 to 009); Defender WMI state,
  every 10 min (DEF-010 to 012).
- **If it is missing**: unreadable or switched-off log: collection `JournalDefender` "Indisponible", DEF-001 to 009 published
  without collection (PR 3.3); unreadable WMI state: no gap computed, collection `EtatDefender` "Indisponible", DEF-010
  to 012 without collection.
- **Expected false positives**: DEF-005 and DEF-006 when an administrator configures Defender themselves; DEF-007 to 009 in
  audit mode on business software.
- **Measured false positives**: count per rule and per hour of the `mesure` scenario (22 min of synthetic activity in a VM,
  alerts produced after the start of the activity, PR 3.5); the service is freshly installed there, hence in learning mode
  (7 days: non-critical alerts are recorded as "Info" there); no DEF rule is expected there, which says nothing
  about a real machine (limit D12: no measurement on a real machine). Measured at the run of PR 3.5 (#81, head 68a4ce1):
  **0 DEF alerts** out of 33 alerts in 22 min (evidence in a comment of #81).
- **Limit**: DEF-006 only sees `DisableRealtimeMonitoring = 0x1`, `DisableAntiSpyware = 0x1` and
  `TamperProtection = 0x4`; the other `Disable*` settings (behaviour, IOAV, scripts) and `TamperProtection = 0x0`
  raise nothing (DEF-010 to 012 see the effect on the WMI state for real time, tampering and the antivirus).
- **Tests** (PR 3.5, `service-rs/src/tests_detection.rs`): one positive and one negative per rule, from `def_001_positif` to
  `def_012_negatif`, and `def_traduire_sans_panique` (mini-fuzz of `traduire`). Negatives: neighbouring event not followed
  (2000, 1118, 5000, 5009, 5011, 1120, 1127); exclusion removed and another setting modified (DEF-005); protection
  restored (DEF-006); audit never at the "Alert" level (1122 for DEF-007, 1124 for DEF-008); state already off at the previous inventory or unreadable (DEF-010 to 012). They describe the existing behaviour
  (no change to `defender.rs`); 9 mutations of `defender.rs` make them fail.
- **In a VM**: no DEF rule is exercised (Defender is untouchable, batch 3d); DEF-001 with an EICAR file: no, as long
  as batch 3d requires "no detection" (D10). The log and the state are read in a VM ("Active" collections in 3a).
  Status: tested in the lab.

## LEU: anti-ransomware decoys

### LEU-001 : decoy modified, deleted, renamed or replaced by a link
- **ATT&CK** : T1486 Data encrypted for impact (ransomware).
- **Code**: `hygiene.rs` (`verifier_leurres`, fingerprint read through a verified handle).
- **Rationale**: a file that nothing should touch has changed or disappeared: encryption probably in progress.
- **Telemetry**: decoys placed and their fingerprints. Decoys are not placed in console mode. They are placed
  in `Documents`, `Pictures` and `Desktop` at their real location, read from "User Shell Folders" in the
  user's hive (OneDrive backup of folders, redirection to another fixed local drive; audit of 2026-11-23,
  done by Claude, A-7-2, fixed: tests `a7_2_dossier_reel_des_leurres`, `a7_2_destination_des_leurres_admise`,
  `a7_2_bilan_des_leurres`, `a7_2_anciens_leurres_suivis_et_retires`). Remaining: hive not loaded (user without a
  session) or folder redirected to a network share or a removable drive: decoy in the default folder of the
  profile (refusal logged). Outside the profile, only a folder on a fixed local drive (as seen by SYSTEM: a mapped drive
  or a SUBST letter of the session is unknown, hence refused) owned by the user is admitted; a decoy
  that has more than one name (hard link) is neither audited nor followed, refusal logged (S268-01, `s268_01_leurre_lien_dur_refuse`);
  number of links, audit and fingerprint are read on a single handle (S268-04, `s268_04_pose_sur_un_seul_handle`), and the
  old locations go through this check again (S268-05).
  At most 3 old locations followed per profile and per decoy, beyond that removed (S268-02). Each creation failure is logged (once) and makes the `Leurres` collection
  partial; the health status publishes "leurres : n posés sur m attendus" (field `Detail` of the collection). A decoy
  left in an old folder remains followed as long as it exists and is removed at uninstallation. Decoys in a
  folder synchronised by OneDrive: they may be uploaded to the user's online storage and
  appear on the user's other devices; OneDrive, which runs under the user's account, is suspended if it writes
  to a decoy or deletes it (Files On-Demand space freeing, synchronisation conflict), which
  stops synchronisation until it is resumed. None of this has been tried in a VM yet (it needs a Microsoft account).
- **If it is missing**: decoys not placed: the rule stays silent.
- **Level**: Critical.
- **Expected false positives**: cleanup or synchronisation tool that rewrites a whole folder.
  False positives measured in a VM (`mesure` scenario, 22 min of synthetic activity): none; the measurement underestimates them:
  the decoys are placed (the check of 3a requires the `Leurres` collection "Active"), but no
  program of the synthetic activity touches them.
- **Tests**: `leu_001_positif` (decoy modified, decoy deleted, on real files: two Critical alerts, and the
  reported decoys are no longer followed, so as not to alert at each round), `leu_001_negatif` (decoy read without being
  modified); existing: `leurres_par_handle_jamais_a_travers_un_lien`. Placing of decoys exercised in a VM (scenario 3b);
  the rule itself is not triggered there.

### LEU-002 : decoy touched (access audit)
- **ATT&CK** : T1486 Data encrypted for impact (ransomware).
- **Code**: `vol_donnees.rs` (event 4663 on a decoy).
- **Rationale**: same reason as LEU-001, at the moment of access; may suspend the program (automatic response
  to ransomware, level 3).
- **Telemetry**: Security log 4663 and audit (SACL) set on the decoys.
- **If it is missing**: object audit disabled: the rule stays silent.
- **Level**: Critical; Info if the program is a known and signed software (backup, synchronisation, antivirus), with the exact name, installed in a folder normally closed to standard accounts: Program Files outside WindowsApps, directly in System32 or SysWOW64, Defender platform. In the profile or Temp, it is never known: software installed without administrator rights or from the Store is suspended (maintainer's decision, 2026-11-02). Since 2026-11-21 (maintainer's decision, S110-14, S114-01, S114-02): the program and each of its folders under the root must also be closed to writing: only SYSTEM, Administrators, TrustedInstaller or a service account may write there or own them (rights read; any other account, unrecognised entry or unreadable rights = open; audit of #228, S228-01), and the program must run as SYSTEM or with the Administrators group active; otherwise it is not known and it is suspended. **Consequence:** a synchronisation client that runs under the user's account (OneDrive, Dropbox, Box) and touches a decoy is suspended; likewise a software whose folder is owned by the account that installed it ("owner = creator" policy, software copied without an installer) is never known (audit of #229, S229-01, cautious direction). **Limit:** a hollowed process launched from an authorised binary, as SYSTEM or an administrator, keeps this status (S114-02),
  and is not suspended.
- **Expected false positives**: backup or indexing software not yet recognised.
  False positives measured in a VM (`mesure` scenario, 22 min of synthetic activity): none; the measurement underestimates them:
  no program of the activity touches a decoy.
- **Tests**: `leu_002_positif` (event 4663 on a decoy, name case ignored: Critical, suspension
  announced only if it took place), `leu_002_negatif` (other file; known software: Info, not suspended);
  pure decisions `hygiene::pid_touchant_leurre_parmi` and `vol_donnees::alerte_leurre_touche` (PR 3.9: names of the
  decoys passed as a parameter, without reading or creating the names file); existing: `b1_leurre_touche_par_rundll32_suspendu`
  (suspension decision). Not exercised in the VM scenarios; Kali campaign (`campagne-kali-sixieme-lot.md`,
  2026-11-16): TP in configuration A, prevented by Defender in configuration C; not consolidated.

## VOL: data theft

### VOL-001 : access to the secrets of a software by another program
- **ATT&CK** : T1555.003 Credentials from web browsers; T1539 Steal web session cookie.
- **Code**: `vol_donnees.rs` ("comportement typique d'un VOLEUR DE DONNÉES").
- **Rationale**: credential stealers read the password and cookie databases of browsers, the
  Discord and Telegram tokens, the cryptocurrency wallets (Ledger, Exodus, Electrum, MetaMask).
- **Conditions**: at most one alert per program and per target every 24 h.
- **Telemetry**: Security log 4663 and audit (SACL) on the profile files.
- **If it is missing**: audit disabled: the rule stays silent.
- **Level**: Critical if the program comes from a temporary folder, the downloads or the public profile, otherwise
  Alert.
- **Expected false positives**: password managers, profile migration tools.
  False positives measured in a VM (`mesure` scenario, 22 min of synthetic activity): none; the measurement underestimates them:
  no browser or wallet is installed or open during the measurement.
- **Tests**: `vol_001_positif` (read of a Chrome password database by a program from a temporary folder:
  Critical; from elsewhere: Alert; by a "chrome.exe" not signed by Google: alert), `vol_001_negatif` (file outside
  the watched folders; folder traversed without reading; our own service; one alert per program and per target
  within 24 h, `vol_donnees::premiere_en_24h`, PR 3.9); decision `vol_donnees::analyser` on synthetic 4663
  events. Not exercised in the VM scenarios; Kali campaign (`campagne-kali-second-lot.md`, 2026-11-15, simulation
  on an empty test account): Critical TP in configurations A and C; not consolidated.
- **Signer of the program** (second audit of 2026-11-23, B-2-01, fixed): kept in the cache under the identity of the file read
  through a handle with its USN number (failing that, the SHA-256 fingerprint of the content), and no longer under the path and the
  modification date, which a standard account restores identically after replacing an authorised program: the replacement is
  verified again and alerts. Test: `audit_b_2_01_programme_remplace_meme_date_reverifie` (lab).

## SYS: hosts file and firewall

### SYS-001 : hosts file modified by another program
- **ATT&CK** : T1565 Data manipulation.
- **Code**: `moniteur.rs` (fingerprint of the hosts file).
- **Rationale**: redirection of domains to a server of the attacker, or blocking of security updates.
- **Telemetry**: fingerprint of the hosts file.
- **If it is missing**: unreadable file: the fingerprint is "" (`empreinte_hosts`). Since PR 3.10, this inventory
  triggers nothing and the known fingerprint is kept: a change made during the outage is reported as soon as the file
  becomes readable again. Before, the alert fired **wrongly** at the outage, then fired again when the file came back.
- **Limits** (audit of #90):
  - a file kept permanently unreadable (a standard account can open it without sharing) makes the rule silent, without
    any signal in `etat.json` or in the log (S90-01). No modification is possible during this lock, and
    a modification made after it is lifted is reported;
  - an empty reference (file unreadable at service startup, or failed re-read just after a write by the
    service) makes the first readable inventory be adopted without an alert (S90-02);
  - the reference is not kept from one startup to the next: a modification made while the service is stopped is never
    reported (S90-03, prior to PR 3.10).
  These three limits require administrator rights to modify the file, which are already enough to modify it
  before the service starts. Planned fix: fingerprint kept in the data folder, computed on the
  content written by the service, and lasting outage recorded.
- **Level**: Alert.
- **Expected false positives**: ad-blocking software, development tools. False positives measured in a VM (`mesure` scenario, 22 min of synthetic activity): none.
- **Tests**: `sys_001_positif` (fingerprint changed; change made during a read outage, reported on recovery),
  `sys_001_negatif` (same fingerprint; unreadable file); pure decision `moniteur::alerte_hosts` (PR 3.10). Not
  exercised in a VM (the scenario does not write to the hosts file).

### SYS-002 : firewall rule added or modified
- **ATT&CK** : T1686.003 Windows firewall modified.
- **Code**: `parefeu.rs` (tracking of firewall changes).
- **Rationale**: opening an inbound port is a classic way to keep access to the machine.
- **Variants**: unsigned author: Critical; inbound port opened from the command line: Alert; inbound
  authorisation by an author that cannot be found: Alert; by a signed third-party program or an update installer: Info.
- **Telemetry**: firewall log (Windows Firewall With Advanced Security), signature of the author.
- **If it is missing**: the result of the subscription is ignored today (silence).
- **Expected false positives**: software installers that open their ports. False positives measured in a VM (`mesure` scenario, 22 min of synthetic activity): none.
- **Tests**: `sys_002_positif` (inbound port opened by netsh: Alert; rule modified by an unsigned program:
  Critical), `sys_002_negatif` (our own rules; outbound rule changed by Windows; unrelated event), on
  `parefeu::traduire` with synthetic events.

### SYS-003 : all firewall rules deleted
- **ATT&CK** : T1686.003 Windows firewall modified.
- **Code**: `parefeu.rs` ("all deleted" operation).
- **Rationale**: an emptied firewall disarms the machine.
- **Variants**:
  - by an author other than the Windows service (svchost, Windows binary): Critical, immediately;
  - by svchost (reload by group policy, `gpupdate`): Info ("règles du pare-feu rechargées par
    Windows"); then, if fewer than 50 rules have come back 60 s later: Critical ("pare-feu vidé").
- **Telemetry**: firewall log, number of rules.
- **If it is missing**: like SYS-002.
- **Level**: Critical; Info for the reload by group policy.
- **Expected false positives**: deliberate reset of the firewall by an administrator. False positives measured in a VM (`mesure` scenario, 22 min of synthetic activity): one Info alert per run, the reload of the rules by group policy at VM startup (expected, Info).
- **Tests**: `sys_003_positif` (all deleted by another program: Critical), `sys_003_negatif` (Windows
  svchost: Info; a "svchost.exe" outside Windows remains Critical), on `parefeu::traduire`. The check of the
  return of the rules, one minute later, is not tested (Windows call).

## PIL: drivers

### PIL-001 : known vulnerable driver present
- **ATT&CK** : T1068 Exploitation for privilege escalation (vulnerable driver).
- **Code**: `hygiene.rs` (LOLDrivers list, once a day).
- **Rationale**: a signed but vulnerable driver makes it possible to disable protections (BYOVD).
- **Telemetry**: loaded LOLDrivers list, drivers on disk.
- **If it is missing**: empty or unreadable list: no alert (silence), as if there were no vulnerable driver.
- **Level**: Critical.
- **Expected false positives**: old hardware driver still present but unused. False positives measured in a VM (`mesure` scenario, 22 min of synthetic activity): none; the LOLDrivers list is empty in the VM (PIL-001 without collection, check of 3a).
- **Tests**: `pil_001_positif` (.sys driver whose fingerprint is in the list: Critical, only once),
  `pil_001_negatif` (healthy driver; same content under another file type; absent driver), on real temporary
  files; decision `hygiene::pilotes_vulnerables` (PR 3.10). Existing: `chemins_des_pilotes`.

## EXT: browser extensions

### EXT-001 : new browser extension
- **ATT&CK** : T1176.001 Browser extensions.
- **Code**: `hygiene.rs` (`verifier_extensions`, every 10 min, except at the first inventory).
- **Rationale**: a malicious extension reads everything the user does in the browser.
- **Telemetry**: browser profiles.
- **If it is missing**: unreadable profile: the rule stays silent.
- **Level**: Alert if the extension has sensitive permissions, Info otherwise.
- **Expected false positives**: each extension installed deliberately. False positives measured in a VM (`mesure` scenario, 22 min of synthetic activity): none; no browser installs an extension during the measurement.
- **Tests**: `ext_001_positif` (learning at the first inventory; then new extension: Alert if its permissions
  are sensitive, otherwise Info; date first seen recorded), `ext_001_negatif` (extension already known, date carried over; same
  identifier in another browser: new); pure decision `hygiene::nouvelles_extensions` (PR 3.10, without a
  data file).

## VIE: privacy and remote access

| Id | Detection | Code | Level | ATT&CK |
|---|---|---|---|---|
| VIE-001 | Program that uses the camera or the microphone for the first time | `surveillances.rs` | Alert | posée par l'alerte (set by the alert): T1125 Video capture (camera) or T1123 Audio capture (microphone) |
| VIE-002 | Remote control tool running | `surveillances.rs` | Alert | posée par l'alerte (set by the alert): T1219 Remote access tools, or T1572 Protocol tunneling for ngrok |
| VIE-003 | Remote Desktop enabled | `surveillances.rs` | Alert | T1021.001 Remote Desktop Protocol |

- **Rationale**: spying through the camera or the microphone; fake support scams that get a remote control tool
  installed; Remote Desktop opened by an attacker.
- **Telemetry**: registry (device access consents, Remote Desktop setting), processes.
- **If it is missing**: unreadable registry: the rule stays silent; the interface displays "CAM / MIC OFF" as if nothing
  were in use.
- **Expected false positives**: VIE-001 during video conferencing; VIE-002 for legitimate IT support. False
  positives measured in a VM (`mesure` scenario, 22 min of synthetic activity): none; the measurement underestimates them, because
  the activity uses neither camera nor microphone and launches no remote control tool.
- **Tests** (PR 3.12), without registry or data file:
  - `vie_001_positif` (learning at the first inventory, then a new program that uses the camera: Alert),
    `vie_001_negatif` (known program; usage ended; usage already in progress at the previous inventory), on
    `surveillances::premiers_usages`;
  - `vie_002_positif` (tool launched, name case ignored; relaunched after it ended: new alert),
    `vie_002_negatif` (ordinary program; tool still running, a single alert), on
    `surveillances::outils_distants`, with the path of a PID passed as a parameter;
  - `vie_003_positif`, `vie_003_negatif` (first inventory, still enabled, disabled), on
    `surveillances::alerte_bureau_a_distance`.
  Not exercised in a VM; the inventory of the consent store and of the registry is not tested.

## BAS: baseline

### BAS-001 : baseline security setting undone
- **ATT&CK** : T1685 Disable or modify protections; T1112 Modify registry.
- **Code**: `baseline.rs` (`derives`, every 10 min).
- **Rationale**: a hardening setting that is rolled back (by malware, an update or a
  person) reopens a weakness.
- **Conditions**: only the settings applied by deR4Tizer are followed. Two cases: changed from "compliant" to
  "non-compliant" in the registry (the registry state is kept separately, so that an "unknown" or "no effect" inventory
  due to Defender does not mask a modification that follows, audit of #217, S217-01); changed from "compliant" to "no
  effect" (Microsoft Defender no longer applies the rule: passive antivirus or different effective value); several
  rules turned "no effect" at the same inventory give a single alert that names them (S217-04). A rule unreadable at
  an inventory keeps its last known state for the next comparison (S217-05).
- **Telemetry**: baseline evaluation.
- **If it is missing**: evaluation impossible: no drift computed.
- **Level**: Alert.
- **Expected false positives**: group policy or administrator that changes the setting deliberately. False
  positives measured in a VM (`mesure` scenario, 22 min): none; no setting is changed during the measurement.
- **Tests**: `bas_001_positif` (rule applied by deR4Tizer, compliant then non-compliant: Alert, expected
  and current values in the reasons), `bas_001_negatif` (rule not applied by deR4Tizer; already non-compliant; unknown
  state; new rule), `bas_001_s217_01_derive_vue_apres_un_tour_inconnu_ou_sans_effet` (modification seen after
  an "unknown" or "no effect" inventory; change to "no effect"), `bas_001_s217_04_et_05_regroupement_et_dernier_etat_connu`, on `baseline::derives`. Not exercised in a VM.

## COR: SIEM correlations

| Id | Correlation | Level | ATT&CK |
|---|---|---|---|
| COR-R1 | Password attempts in series | Alert | T1110 Brute force |
| COR-R2 | Session opened after a series of failures | Critical | T1110 Brute force; T1078.003 Valid local account |
| COR-R3 | New administrator account (created less than 30 min ago then added to Administrators) | Critical | T1136.001 Local account created |
| COR-R3b | Existing account added to the Administrators group | Alert | T1098 Account manipulation |
| COR-R4 | Event log cleared | Critical | T1685.005 Event logs cleared |
| COR-R5 | Service installed from a suspicious location | Critical | T1543.003 Windows service; T1569.002 Service execution |
| COR-R6 | Multi-stage attack (3 detections of the same program within 10 min) | Critical | aucune (none) |
| COR-R7 | Protection weakened (security service stopped, audit policy changed) | Alert | posée par l'alerte (set by the alert): T1685 Disable or modify protections and T1489 Service stop (security service stopped) or T1685.001 Logging disabled or modified (audit policy changed) |
| COR-R8 | **Numéro non attribué** (number not assigned): no R8 rule in `siem.rs` to date; the number stays free, it is not reused for another rule without a decision | not applicable | not applicable |
| COR-R9 | Session opened from a public address (Remote Desktop: Critical; other: Alert) | Critical / Alert | T1133 External remote services |
| COR-R10 | Vulnerable driver installed (BYOVD) | Critical | T1068 Exploitation for privilege escalation (vulnerable driver) |

- **Code**: `siem.rs` (`Correlation`).
- **Telemetry**: Security and System logs; advanced audit (baseline profile "journalisation").
- **If it is missing**: audit disabled or unreadable log: the correlation stays silent. Except COR-R6, which feeds on the
  alerts of the service and not on the audit.
- **Expected false positives**: COR-R1 on mistyped passwords; COR-R9 for deliberate remote access; COR-R3
  (Critical) for any local account created then added to Administrators within 30 minutes, including by a
  legitimate administrator or installer (before B-5-02, this case gave COR-R3b, Alert).
- **Matching of COR-R3** (audit of 2026-11-23, B-5-02, fixed; tested in the lab, to be tried in a VM): the account created
  (4720) and the account added to Administrators (4732) are the same if they have the same SID (`TargetSid`, `MemberSid`),
  otherwise the same exact name (after the last "\", case ignored): `siem::meme_compte`. Before, a substring was enough
  ("adm" created, existing "admin2" added: false Critical), and the 4732 of a local account, without a name (`MemberName` "-"),
  carried only the SID, which never matched the name of the 4720: COR-R3b instead of COR-R3. The SID is kept only in
  memory for the correlation, never written into the SIEM events.
- **Tests**: `cor_r1_positif` to `cor_r9_negatif` (PR 3.11), on `siem::Correlation::analyser` with already translated
  synthetic events:
  - COR-R1: five failures from the same source; not four, nor five spread over two sources;
  - COR-R2: session opened after five failures from the same source; not after four, nor from another source;
  - COR-R3 and COR-R3b: account created then added, existing account added, once per hour; exact name and not
    substring, SID that decides when both are known (`cor_r3_compte_exact_pas_sous_chaine`), and from the XML of the
    logs to the incident for a local account matched by its SID (`cor_r3_bout_en_bout_par_sid`);
  - COR-R4: clearing of a log, once per hour;
  - COR-R5: service from a temporary folder, `ProgramData` or PowerShell; not from Program Files or Windows;
  - COR-R6: three different detections of the same program, case ignored; not two, nor three
    programs, nor Info alerts;
  - COR-R7: security service stopped, audit policy changed; not an Info state change;
  - COR-R9: Remote Desktop from a public address (Critical), other session (Alert); not from the local
    network.
  The time windows (5 min, 30 min, 10 min, one hour) are not exercised: the engine reads the clock itself.
  COR-R10 is not tested: its check downloads the LOLDrivers list. None is exercised in the VM scenarios;
  the Kali campaign measures several of them (`campagne-kali-premier-passage.md` and `campagne-kali-sixieme-lot.md`): COR-R1,
  COR-R2, COR-R4, COR-R5, COR-R7 and COR-R9 as TP, not consolidated. Known limits, not fixed: COR-R3 does not
  trigger through the standard vector (the addition to the group, event 4732, carries the SID of the member, matched against the name of the
  created account: one gets COR-R3b, Alert); COR-R9 through Remote Desktop measured as Alert and not as Critical (order
  of logons type 3 then type 10). Threshold limits (audit of 2026-11-23, done by Claude, not fixed): a slow brute force (fewer
  than 5 failures in 5 minutes) is seen neither by COR-R1 nor by COR-R2; COR-R5 retains neither the Desktop nor Documents as a
  suspicious location for a service; COR-R6 counts by program name, steps under different names do not
  add up. False positives
  measured in a VM (`mesure` scenario, 22 min of synthetic activity): no incident; the measurement underestimates them, because
  the activity opens no session, installs no service and changes no account.

## INT: service integrity

| Id | Detection | Code | Level | ATT&CK |
|---|---|---|---|---|
| INT-001 | Failure of the protection of the data folder (fail closed) | `protection.rs` | Critical | aucune (none) |
| INT-002 | Command pipe already taken by another process (squatting) | `canal.rs` | Critical | aucune (none) |
| INT-003 | Installation folder modifiable by another account (audit of 2026-11-23, A-4-1) | `protection.rs` | Critical | aucune (none) |

- **Rationale**: a badly protected data folder or a squatted pipe would give control over the service; an installation
  folder modifiable by another account would let a program or a DLL be run there as SYSTEM.
- **Telemetry**: none external (checks by the service itself).
- **Expected false positives**: none known.
- **Tests**: existing: `lot1_alerte_critique_locale_en_echec` (INT-001), `lot5_canal_squat_pid_et_alerte_critique`
  (INT-002), `audit_a_4_1_dossier_installation_protege` (INT-003, decision and wiring); 3a (first startup in
  fail closed) for INT-001. INT-003 on a real redirected installation: to be measured in a VM.

## SAN: deR4Tizer health (phase 4)

| Id | Finding | Code | Level | ATT&CK |
|---|---|---|---|---|
| SAN-001 | Critical collection unavailable (or never read) for more than 30 min; critical collections (D4-5): `JournalDefender`, `EtatDefender`, `JournalSecurite`, `Connexions`, `Processus`, `ListesMenaces`, `Persistance` | `sante.rs` | Alert | aucune (none) |
| SAN-002 | Collection restored after a SAN-001 or SAN-003 finding ("rétablie après N min") | `sante.rs` | Info | aucune (none) |
| SAN-003 | Defender blind: log **and** state unreadable for more than 30 min (replaces SAN-001 for these two collections) | `sante.rs` | Critical | aucune (none) |
| SAN-004 | Alert forwarding configured and failing for more than one hour: **local** finding (never forwarded, it cannot be) | `sante.rs`, `notifications.rs` | Alert | aucune (none) |
| SAN-010 | Interface absent from an active session for more than 15 min (after a grace period of 5 min at session opening or at service startup), despite the restart task | `sante.rs`, `natif.rs` | Critical (maintainer's decision, 2026-10-31: without an interface, a local finding is seen by no one) | aucune (none) |
| SAN-011 | Interface repeatedly stopped: 3 disappearances within one hour in the same session | `sante.rs`, `natif.rs` | Alert | aucune (none) |
| SAN-012 | Alerts not followed for lack of room: more than 500 unclosed incidents (the alert stays in `alertes.json`) | `sante.rs` | Critical | aucune (none) |
| SAN-013 | Mini-SIEM history incomplete: events lost (queue of 20,000 full), events not written (file of the day at the cap of 1 GB / 30, about 34 MB), or file of a previous day deleted because of the total size (1 GB) | `sante.rs`, `siem.rs` | Alert | aucune (none) |
| SAN-014 | Configuration present but not loaded: `config.json` unreadable, refused (owner, hard links) or malformed after three attempts; the service runs with the default configuration and does not rewrite the file | `sante.rs`, `moniteur.rs`, `commun.rs` | Critical | aucune (none) |

- **Rationale**: a switched-off collection silences the rules that depend on it; without a finding, this silence looks like
  a quiet machine. Cutting off the view of Defender is what an attacker gains most by doing (SAN-003).
- **Telemetry**: the published status of the collections (`collectes::instantane`, PR 3.3); the monitor's counter of unfollowed
  alerts (SAN-012). "sante" thread, every 30 s, outside the monitor lock.
- **Bounds**: one finding per collection (SAN-001), or per rule (SAN-003, SAN-012), and per 24 h at most **for the same
  outage**: once restored, the collection can be reported again (audit of #98, S98-01). `Inconnue`
  counts as unavailable (fail closed); a collection read less often than every 15 min (threat lists:
  every hour) only counts the unavailability recorded by its source, not its mere silence, which it catches up on after
  a sleep (review of #98, D1); `Desactivee` (Sysmon absent, console mode) never raises anything. Never
  softened by learning (`apprentissage::signal_fort`). Decision in memory: after a restart, an outage
  already reported may be reported once more.
- **History**: each state change of a collection is written to the SIEM (`Source` "sante", `Type`
  "collecte"), on change only; the change from "Inconnue" to "Active" at startup is not recorded; more than 6
  changes within the hour: collection "instable", one line per hour at most. The timeline of an incident
  includes them (PR 4.3).
- **Expected false positives**: restart of Defender during an update of its platform; Security log full
  (to be measured in a VM); threat lists never downloaded (machine without Internet). Ruled out: the sleep of a laptop
  (silence of the threat lists until their next round, test `sante_veille_silence_des_listes_sans_constat`).
- **Limit**: a collection switched off repeatedly, for less than 30 min each time, never raises SAN-001 (the history calls it
  "instable" beyond 6 changes within the hour); an "instable" finding for the critical collections is to be
  taken up later.
- **Tests**: `sante_collecte_muette_30_min`, `sante_collecte_revenue_avant_30_min`, `sante_collecte_retablie`,
  `sante_desactivee_sans_alerte`, `sante_inconnue_compte_indisponible`, `sante_defender_aveugle_critique`,
  `sante_defender_un_seul_collecteur`, `sante_rappel_apres_24_h`, `sante_historique_au_changement_et_instable`,
  `sante_veille_silence_des_listes_sans_constat`, `sante_rappel_remis_a_zero_au_retablissement`,
  `incidents_plafond_non_clos`, `sante_jamais_adoucie_par_l_apprentissage`; 3a ("sante" event when a
  collection stops).
- **SAN-004** (PR 4.4b): a forwarding outage starts at the first batch not delivered (no channel attempted succeeded) and
  ends at the first batch delivered; one finding per outage and per 24 h at most; forwarding not configured: nothing. Tests:
  `sante_remontee_echec_1h`, `sante_remontee_non_configuree`.
- **SAN-010 and SAN-011** (PR 4.5a): collection `Sessions` ("sante" thread, every 30 s); `WTSActive` sessions with a
  user token; interface recognised by its full path **equal** to the installed path (`deR4Tizer.exe` next to
  the service): a copy placed elsewhere does not count. Installation with `LANCEMENT_SESSION=0` (no Run value): no session expected, no finding. Enumeration impossible: collection unavailable, never
  "interface present", and SAN-010/011 without collection. One finding per session, per episode (SAN-010: reset when
  the interface comes back, at most 3 findings per session and per 24 h, the last finding saying so, then one line in the SIEM; the cap is in memory: it starts again from zero when the service restarts and when the session closes) and per 24 h at most; each disappearance and each return are written to the SIEM (`Type`
  "interface"). The service restarts nothing: a scheduled task placed by the MSI does it under the user's identity (PR 4.5b), every 5 min, and SAN-010 reports the absence beyond that. It does not distinguish a deliberate
  "Quit" from a forced stop. Limit: an interface at the right path but suspended counts as present; a program under the user's account can therefore cut off local notifications without SAN-010 (audit of #100, S100-01); monitoring and forwarding continue; a sign of life from the interface would be needed to go further. Other expected false positives: restart task removed or forbidden (managed machine); account not authorised to read the data, which
  closes the interface; Remote Desktop session without a desktop. Tests: `sante_interface_absente_15_min`,
  `sante_grace_ouverture_session`, `sante_interface_trois_disparitions`, `sante_interface_deux_disparitions`,
  `sante_interface_retour_et_session_fermee`.
- **SAN-013** (audit of 2026-11-23, A-6-3): a standard account that creates processes in a loop filled the SIEM;
  the purge by size pushed out the oldest days, file of the day included, and the queue overflowed silently.
  Now the file of the day is never deleted; beyond its cap (1 GB / 30: 30 full days fit in
  1 GB, a one-day flood no longer pushes out the others), the events of the day are no longer written but counted (the
  correlation still sees them); the purge by size only touches the previous days (the current day counts
  for its bounded share). Finding at the first loss, at the first unwritten event and at the first purge by size,
  each immediately; a rise of an already reported counter, once per 24 h at most. Counters since startup, in
  memory. **Limit**: a standard account can still saturate the current day (what it does next that day is no
  longer written to the SIEM, the alerts stay in `alertes.json`): that is what SAN-013 says; cap to be measured in a
  VM on an ordinary machine. Tests: `siem_purge_par_jour`, `sante_san013_historique_incomplet`.
- **SAN-014** (audit of 2026-11-23, C-3): a `config.json` present but unreadable (lock, rights, owner refused,
  several hard links) or malformed passed for absent: the service ran with the default configuration, and
  the first settings command wrote it over the legitimate configuration. Now `commun::lire_etat` distinguishes
  "absent" from "present but not loaded" (three attempts 100 ms apart for a read error, none for a
  malformed content or a refusal); if not loaded at startup, the configuration stays the default one, `config.json` is
  never rewritten until the next startup, the commands that would write it are refused with the reason, the Health page
  says so ("Configuration" line) and SAN-014 is raised immediately, then once per 24 h at most as long as the state lasts. No
  finding when the protection of the folder fails (INT-001 already says so). The same rule applies to any file read by
  `commun::lire` (blocks, "known" databases, firewall history, network state…): present but not loaded, it
  is no longer rewritten as long as a read has not loaded it or seen it absent. Tests: `lot_a_lecture_absent_distinct_de_illisible`,
  `lot_a_fichier_non_charge_jamais_reecrit`, `lot_a_configuration_non_chargee_et_san014`. Trial in a VM still to be done.

## REP: response (phase 6)

| Id | Finding | Code | Level | ATT&CK |
|---|---|---|---|---|
| REP-001 | Response action still in progress at its deadline: suspension (2 h if automatic, 24 h otherwise), isolation (7 days), panic mode (4 h), quarantine (30 days), manual block (90 days), then at each period. One alert per kind of action and per hour at most (24 h for quarantine and manual block): the held reminders go out, counted, with the next one; beyond one action, the alert gives the number and names the first 5. Never a lifting: recovery is human, and the reminder says so | `politique.rs` | Critical (automatic suspension, panic), Alert (manual suspension, isolation), Info (quarantine, manual block) | aucune (none) |
| REP-002 | Action loop stopped: an automatic action is held back by the guard (same target, cap of the lists or of the IPS), or `reponses.json` is malformed, or the registry of actions in progress is full (recent automatic suspensions dropped from tracking, once per episode) | `politique.rs` | Critical | aucune (none) |
| REP-003 | Firewall silent for 5 min in a row (Alert level, once per outage: the published state may be old); or panic mode not set (a rule refused or inactive, flag not written: everything is removed) or not removed (a rule remains: flag kept), or become uncertain outside a command (rule or flag removed by a third party, seen within 30 s at most). States the effective state and the recovery | `moniteur.rs`, `reponse.rs` | Critical | aucune (none) |
| REP-004 | Isolation diverted: the isolated path leads to another program (folder replaced by a junction, file by a link), found at the 5-min inventory, reported once; or isolation not verifiable (path unreadable for 3 inventories in a row, Alert level); the rules are kept (never an automatic lifting), the decision is human | `moniteur.rs`, `reponse.rs` | Critical (isolation diverted), Alert (isolation not verifiable); never softened by learning (like any REP-*) | aucune (none) |

- **Rationale**: an automatic action repeated endlessly makes the machine unusable; a held-back action leaves a
  program or an address active, which the contractor must know. The original alert always goes out: RES-001 and LEU-002
  say that the action is held back, the IPS alert does not (`ids.rs`, not fixed to date), written as soon as the detection occurs.
- **Telemetry**: no collection, the history of automatic actions (`reponses.json`).
- **Bounds**: one alert per target and per 24 h, one per one-hour stop of the lists, one per hour for the IPS, one per
  startup for a malformed file. A hold for a human decision raises none: it is a choice of the administrator.
- **Expected false positives**: a legitimate software that touches the decoys repeatedly; a threat list heavily
  renewed after a long interruption.
- **What to do**: check the program or the address cited. A manual action always remains possible.

## EXP: experimental modules (unfrozen in November 2026, under validation)

| Id | Module | Code | ATT&CK |
|---|---|---|---|
| EXP-IDS-001 | IDS (rules in Suricata format); level according to the priority of the rule (1 Critical, 2 Alert, otherwise Info), no ATT&CK technique set by the code; the identifier (sid) and the file of the IDS rule stay in the reasons | `ids.rs` | posée par l'alerte (set by the alert): none to date (the identifier of the IDS rule is in the reasons) |
| EXP-DPI-001 | DPI (SNI, JA3, HTTP, DNS) | `dpi.rs` | posée par l'alerte (set by the alert) depending on the behaviour: T1187, T1021, T1048.003, T1071.001, T1071.004, T1552 |
| EXP-NDR-001 | NDR: ARP spoofing (Critical or Alert, T1557.002), LLMNR/NBNS poisoning detected by the active decoy (Critical, T1557.001), passive LLMNR/NBNS/mDNS responder (Alert, T1557.001), rogue DHCP server (Critical, T1557.003), UPnP redirection to this PC (Alert, T1133), based on `ndr.rs` | `ndr.rs` | posée par l'alerte (set by the alert) depending on the behaviour: T1557.002, T1557.001, T1557.003, T1133, T1200 |

- Frozen by `CLAUDE.md` during phase 3: only a line that sets the rule identifier was added to their
  alerts (PR 3.2), with no other change of logic (maintainer, 2026-10-25). Unfrozen since then (IDS and NDR on 2026-11-16, DPI on 2026-11-18, `CLAUDE.md`, « Unfreezing of the IDS, NDR and DPI » paragraph).
- One identifier per module (PR 3.2): each of these modules produces its alerts in a single place, and the precise rule
  (IDS sid, DPI or NDR pattern) stays in the reasons. A finer split remains to be done in their validation.
- **IDS, second audit (B-4-01 and B-4-02, fixed)**: a rule without positive content (no `content`, or only
  negated `content`) still evaluates all its conditions: it triggers only if none of its negated contents
  is present, with their options (`offset`, `depth`…); before, it triggered on its header alone (protocol,
  addresses, ports). As in Suricata, a rule that has at least one `content` (negated or not) never matches a
  packet without a payload (SYN, ACK): with the IPS, a `drop` rule with negated contents does not block a mere ACK.
  An unknown header variable makes the rule ignored and counted, like an unsupported
  option (`ids.json`, field `Ignorees`); before, it meant "all addresses" or "all ports". Known variables,
  unchanged: `$HOME_NET`, `$EXTERNAL_NET`, `$HTTP_PORTS`, `$SSH_PORTS`, `$FILE_DATA_PORTS`,
  `$ORACLE_PORTS`. The other standard variables take their value from the default `suricata.yaml` of Suricata 7
  (`suricata.yaml.in`, branch `main-7.0.x`): `$HTTP_SERVERS`, `$SMTP_SERVERS`, `$SQL_SERVERS`, `$DNS_SERVERS`,
  `$TELNET_SERVERS`, `$DC_SERVERS`, `$DNP3_SERVER`, `$DNP3_CLIENT`, `$MODBUS_SERVER`, `$MODBUS_CLIENT`, `$ENIP_SERVER`,
  `$ENIP_CLIENT` are `$HOME_NET`; `$AIM_SERVERS` is `$EXTERNAL_NET`; `$SHELLCODE_PORTS` is all ports
  except 80 (alone; in a list, the rule is ignored), `$DNP3_PORTS` 20000, `$MODBUS_PORTS` 502, `$FTP_PORTS` 21,
  `$GENEVE_PORTS` 6081, `$VXLAN_PORTS` 4789, `$TEREDO_PORTS` 3544. `$GTP_PORTS` (absent from the `suricata.yaml` of
  version 7) and any other variable remain unknown: rule ignored. Tested in the lab (`ids_regle_sans_contenu_positif_evalue_ses_negations`,
  `ids_variable_inconnue_ignoree`, `ids_variables_standard_de_suricata`); to be measured in a VM (count of ignored rules
  on an ET Open set).
- **Telemetry**: network capture.
- **Tests**: those of the modules, plus those of the second audit for the IDS (above); no false positive measurement
  during phase 3.
