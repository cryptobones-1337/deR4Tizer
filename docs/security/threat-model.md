# deR4Tizer threat model

State as of 2026-11-23 (`main`, commit `6ad1858`; version 4.3 signed and published). The measures cited refer to the code and, when they are proven under
real conditions, to the CI scenarios (`docs/roadmap/capability-matrix.md`). The open findings of the audit by passes of
2026-11-23 (done by Claude: it is not an independent review) are flagged by their number (A-x-y), with the mention
"not fixed".

Intended user: the individual or the small organization is often a member of the Administrators group, with UAC set to simple
consent. For them, the barrier between a malicious program and a privileged command is deR4Tizer's
confirmation window: any program of their account can write a command file and start the elevated helper,
signed in the publisher's name. The confirmation tells the truth and its default button is "Cancel"; for a command that
weakens protection, it says first that the request may not come from the user and only arms "Continue"
after 2 s (A-1-2, fixed, list extended by S277-02; tested by `tests\test-confirmations.ps1`, to be tried in a VM). The helper only accepts its
own command file, judged on the text of the path before any disk access: no network path is opened with
the administrator's identity (A-1-1, fixed; same test). Any program of the account can also start the full
interface as administrator (behind the UAC prompt) with the arguments of its choice: under an administrator token, the test
data folder (`--dossier`) is never applied and the elevated interface reads the normal data folder; without
elevation, `--dossier` is only accepted on a fixed local disk, same criterion as A-1-1 (`Programme.DossierDemande`;
audit of #298, A298-3, fixed; tested by `tests\test-langue.ps1`, to be tried in a VM). The other arguments change neither
the folder read nor the rights (page displayed, hidden start, classic interface); an unknown or malformed argument is
ignored and opens the ordinary interface.
Known limit (audit of #296, S296-01, not fixed): the fonts of the confirmation window are chosen by their name ("Segoe UI",
"Segoe UI Semibold"); a font installed by the user under that name could be used by the elevated helper (already true for Segoe UI before T-16).

## Privilege boundaries

| Boundary | Privileged side | Exposed side | Measures | Proof |
|---|---|---|---|---|
| Service | `deR4TizerSvc.exe`, SYSTEM account | The whole rest of the computer | No kernel driver; `panic = "abort"` (an out-of-bounds index stops the service instead of corrupting it) and mini-fuzzing of the parsers. After a stop, Windows restarts the service without limit (5 s, recovery actions set by the MSI): a repeated panic would make gaps of a few seconds in monitoring; the audit of 2026-11-23 found no panic reachable by attacker data (directed reading, without fuzzing). The service runs at normal priority; its heavy and periodic threads go to background, the decoy 4663 thread and the command channel above normal (A-8-1, fixed, test `a8_1_priorites_des_fils`; effect on the suspension delay under load not measured, to be measured in a VM). Exposure diagnostic (U5c-1): read-only access to the firewall policy (INetFwPolicy2: active profiles, state, default inbound action), without writing; published texts capped (200 characters, without control characters). | `cargo test` (mini-fuzz, `structure_diagnostic_lecture_seule`) |
| Interface | Service | `deR4Tizer.exe`, without administrator rights | The interface reads the state (JSON files of the data folder, read-only); every action goes through the channel, so through an administrator (UAC). Since the switchover (B1), the WPF shell is the default interface; the elevated helper (`--commande-fichier`) exits before the mutex and never loads WPF (mode decided by a pure function, driver in a method that is never inlined). Second instance (B2): a session event (`Local\deR4Tizer.Interface.Montrer`) asks the interface already open to show itself; it carries no data, and a program of the session that signals it can only make the window appear (at most a few times per second); if it pre-creates it, whatever its rights or mode, the first instance does not listen to it and the second one goes silent again; the right to come to the foreground is granted only to the PID of the first instance (same name, same session, same executable), never to any process (audit of #158). First-run setup (U7a, U7b, U7c): three commands only, those of the Settings and Threats pages (learning, two level 3 automatic responses, notification test message with the settings read again on click and without secret; the service applies these settings before sending the test, hence the re-reading on click and the confirmation as administrator, also from the Settings page: audit of #154, S154-01), through the channel and so confirmed; an interface already elevated has them confirmed by Canal, like any "config" or "apprentissage" command since the audit of #152 (S152-02: before, the Settings, Threats and Detection pages of an elevated interface sent them in one click), and like lifting a block, the syslog and API settings, the notifications, the update, authorizing a reader account (audit of #153, S153-01) and the lasting exception "No longer alert for this behaviour" (S153-02); only file written by the interface, a per-user marker in `%LOCALAPPDATA%\deR4Tizer` that means "already offered": a program of the account that deletes or creates it can only offer the helper again or silence it, never change a setting. An interface started as administrator never writes this marker, in a folder that the non-elevated programs of the account control (junction, link: audit of #151, S151-01), and does not consult it either: neither its path nor its existence is requested under an administrator token, because `%LOCALAPPDATA%` is redirected through HKCU without elevation and the existence test would go to a path chosen by the account (review of #304, A304-2; pure decision `RepereVu`, `tests/test-langue.ps1`), including when the "First-run setup" page opens (S307-01); `derniere-alerte-lue.txt` (same folder) is no longer written either by an elevated interface, nor read, nor its path computed: the last alert read stays in memory there (audit of #307). More broadly, under an administrator token, no call of the interface requests `%LOCALAPPDATA%` in a way that queries the folder (`GetFolderPath` without `DoNotVerify` checks its existence): the path of `langue.txt` is computed only outside administrator and outside the helper, and the expected folder of the elevated helper's command files is computed with `DoNotVerify` (audit of #307; structural test in `tests/test-langue.ps1`). | 3a (standard account refused) |
| Command channel `\\.\pipe\deR4Tizer` | Service | Local processes | Reserved to SYSTEM and administrators; first instance created with `FILE_FLAG_FIRST_PIPE_INSTANCE`, one instance always open; the interface and the update script check that the pipe server is the service process. Phase 1: bounded rate, authorization per command and validation of each field before any execution; names written to the hosts file validated (no more line injection). Hardening (channel review): remote clients refused by the pipe (`PIPE_REJECT_REMOTE_CLIENTS`); client identified on the token of the connection, after reading the command (`ImpersonateNamedPipeClient`, immediate return to the service's identity, stop if that return fails), and no longer on the PID of its process, which another process could take over; clients of the service at Identification level (the service reads their token, never acts with it); client at Anonymous level: "other"; answer written within 5 s at most, a client that never reads it no longer blocks the channel (IPC-04); reading of the answer bounded on the interface side (120 s). Remote connection (IPC-03): not yet tried from another machine. Availability (A-8-2, not fixed): the pipe name is fixed; a standard account that takes it during a restart of the service (update, upgrade, crash) cuts all commands and makes the update health check fail, and so revert to the previous version, as long as it holds it (critical alert with its PID). Creation of a pipe instance reserved to SYSTEM (audit of 2026-11-23, A-1-4, fixed, tested in the lab, to be tried in a VM): administrators now only have read and write data access (`0x12008B` = FILE_GENERIC_READ | FILE_WRITE_DATA, instead of GRGW, whose GENERIC_WRITE included FILE_CREATE_PIPE_INSTANCE, 0x4); the pipe belongs to SYSTEM (`O:SY`) and an OWNER RIGHTS entry (`OW`, same rights) removes the owner's implicit WRITE_DAC (review of #295, S295-01: before, the owner was Administrators, default owner of the SYSTEM token, and an elevated administrator could rewrite the DACL then create an instance); what is guaranteed: without an enabled privilege, no account other than SYSTEM can create an instance, nor change the DACL or the owner of the pipe; an administrator who enables a privilege (restore, debugging of SYSTEM) remains master of the computer; the interface and the scripts request only these rights (a client that requests GENERIC_WRITE, "InOut" direction, is refused); the server check by the interface and by the update script remains. | 3a (anonymous refused, IPC-04, 8 simultaneous clients); `lot2_canal_code_de_production_sur_un_vrai_tube`, `phase1_client_du_tube_identifie_sur_son_jeton`, `canal_reponse_bornee_client_qui_ne_lit_pas`, `audit_a14_tube_sans_creation_d_instance_hors_systeme`, `audit_a14_tube_reel_instance_refusee_client_minimal_servi`; 3a to come (owner SYSTEM, WRITE_DAC and instance refused to an administrator, A-1-4, S295-01) |
| Export API (HTTP) | Service | Local network (if enabled) or 127.0.0.1 | Disabled by default; read-only; token (`api-jeton.txt`, SYSTEM and administrators); on the network, allowed addresses mandatory (exact IPv4 or /8 to /32, validated before going into the firewall rule) and firewall rule (Domain and Private profiles, Public blocked); request read within 10 s at most. Slots (audit of 2026-11-23, A-1-3, fixed, tested in the lab, to be tried in a VM): 16 connections in all; API open on the network, the computer's own connections (loopback, or the computer to its own network address: review of #295, S295-02) only have 4 of them: a program of the computer that goes this way can no longer take those of the SIEM; limit: a connection from the computer to another of its addresses (computer with several adapters, chosen source address) is not recognized; a refusal for lack of a slot is reported in the log and to the SIEM (source "api", type "connexions-refusees", level Alerte), once per 10 minutes. When listening locally only, all clients, SIEM included, come from the loopback: no quota separates them, and a local process, even of a standard account, that keeps reopening 16 silent connections makes the export unavailable (reported, without leak or elevation). **In clear text** (HTTP): on the network, token and data travel in clear text (residual risk, like syslog). | 3a (witness port); `api_adresses_autorisees`, `audit_a13_api_places_boucle_locale_et_signal`, `audit_a13_api_saturation_boucle_locale` |
| Interactive installation (U8a) | Installer (SYSTEM for deferred actions) | Session of the user who installs | No action of the MSI user interface starts a program: the last page displays a text (property assignments, type 51), without a "Launch" box; the interface is started by the restart task, without elevation. Started from the installer, it could have run elevated and kept the session mutex. | `tests/test-msi.ps1` (sources and package); 3a (interface coming from the task, non-elevated token) |
| Automatic update | Service (installs an MSI as SYSTEM) | Publication server (GitHub), network | Strict manifest; SHA-256 hash; Authenticode signature with revocation; public key of the signer compared with the keys pinned in the binary; version read from the signed package; working folder reserved to SYSTEM; rollback through the MSI of the installed version, itself verified as well. Automatic installation disabled by default. Manifest older than the installed version (updates frozen by a replaced manifest) reported, never again "up to date", and check failing for 24 h or more stated on the Health page (audit of 2026-11-23, A-3-2, T-12). | `lot2_*`; `audit_a32_*`, `audit_t12_*`; A-3-4 scenarios of the `integration-maj` job (older manifest, second pinned key, expired timestamped certificate); 3c in Windows Sandbox only (never in CI) |
| Data folder `C:\ProgramData\deR4Tizer` | Service | Local accounts | Created with its rights (MSI and service); owner and rights imposed and verified at startup; elements of another owner set aside, never read; fail-closed (configuration and secrets ignored). When protection fails, a critical alert stays local: the reporting secrets are ignored, the provider is not notified. Audit of 2026-11-23, batch A: **C-1** (junction at the root set and held open by a standard account; v4.3 test in a VM: 42 elements written by the service into the folder of that account, rights set on the junction itself): the root is now only handled through a handle opened without following links, final path verified, owner and rights set then read back on that handle; as long as it is not, a single decision (`commun::racine_sure`) forbids any write below it, log included (lines in the Windows event log, source `deR4Tizer` not registered), the failure is also stated in `%SystemRoot%\Temp`, monitoring does not start and the service retries every minute; the MSI refuses a data folder that is a reparse point (read-only JScript action, fail-closed condition); uninstallation keeps the root protected (window "junction set between uninstallation and reinstallation" closed), empty or with only the non-empty quarantine: copies, index and marker kept if they belong to SYSTEM or the administrators (never taking ownership), with a single hard link, DACL reserved to SYSTEM and the administrators set and read back by handle, otherwise all deleted with the rest (audit of 2026-11-23, A-4-3; malicious content stays on the disk, unreadable for standard accounts, encoded and never executable as is, except a copy from before 4.3 never migrated, in clear, which the report flags). It also removes the read audit set in the profiles (A-6-4): by handle, only the entries identical to ours (an identical entry set by a third party goes with them, declared limit). Limit: as long as the junction is held, the service does not monitor and the interface does not reach it (local denial of service, visible in the event log). **C-2** (trust in the owner alone): first takeover of a pre-existing folder (marker `prise-en-charge.json`; folder of a previous version recognized by a trusted `etat.json`): all its content set aside; file with several hard links discarded at sorting and refused at reading. **C-3** (unreadable taken for absent): a file that is present but not loaded is no longer rewritten; configuration not loaded: SAN-014, Health page. **C-8** (check then read through two accesses): owner, links and content read through a single handle, absent file never read. Name of the discarded folder unpredictable. Direct writes (audit of #287, S287-01): all go through the same guard (`commun::garde_racine`: `ecrire_fichier`, `creer_dossiers`, `creer_dossier`, `ouvrir_pour_ecrire`, and in `natif` the protected creation of files, copies and folders), including those of the MSI actions (copies of the hosts file by `--nettoyer`, backup of the baseline GPO); only the hosts file and the local GPO, outside the folder, are written directly (structure test `lot_a_ecritures_directes_par_la_garde`). Limit (S287-02, already true before this batch): a junction set between the MSI launch condition and its CreateFolders action would receive the rights of the Donnees component (SYSTEM, administrators, owner Administrators) on the junction itself; the service then deletes the link at startup, or waits for it to be released without writing anything below it. Tested in the lab (`lot_a_*`) and by the "C-1" scenario of `installation.ps1` (CI); to be replayed in a VM. | 3a |
| SYSTEM file operations on user paths (quarantine, restore) | Service | User who owns the path | Opening by handle without following links, final path verified; restore under the user's identity, never as SYSTEM at the original location; fallback into the service's folder. Audit of 2026-11-14: name of the copy read from `quarantaine.json` limited to a simple name (B3: otherwise a rewritten entry made SYSTEM delete any file on resumption); address of the update manifest revalidated at each check and passed to curl through `--url` (B2); when the folder protection fails, the commands that rewrite `config.json` are refused (B8). | 3b; `audit_b3_reprise_entree_forgee_ne_supprime_rien`, `audit_b3_nom_de_copie_simple`, `audit_b2_b8_cablage` |
| Network capture | Service (raw socket) | Any packet received by the computer | Parsers bounded and tested (mini-fuzz); "deR4Tizer capture" rule required (all inbound traffic to the service); the service listens on no port, except the optional API. | `cargo test` (mini-fuzz) |
| Alert reporting | Service | ntfy, Teams, SMTP server | Secrets reserved to administrators, kept in the service's memory between two sends (file removed: ntfy and Teams cut at the next round, an SMTP server without an account stays reachable; edited by hand: not adopted before the next setting or restart); sends through Windows `curl.exe` (HTTPS, SMTP with TLS). | `notifications_*` |
| Syslog export | Service | Network | **In clear text** (UDP or TCP, without TLS). | none |

### Local DNS resolver (phase 7: PR 7.3, connected to the adapters by 7.4)

In the code (`dns_local.rs`), mechanism M2 of the design file (D7-1: recommendation applied;
put into service on the adapters with the maintainer's explicit agreement for 7.4 (2026-11-12)). In 7.3, it only listened during a **10-minute trial** started by an administrator (command
`filtrageEssai`); no adapter is set to it. It is the service's first network listener apart from the optional
API, and the first parser of untrusted DNS queries and answers running as SYSTEM (with `panic = "abort"`).
State of the requirements written before the code (audit of #157, S157-01; phase 7 design file, section 6):
- listening on `127.0.0.1` and `::1` only, never on a network adapter, and double check of the client address:
  **met** (proof: `Get-NetUDPEndpoint` and `Get-NetTCPConnection` in the 3a case);
- exclusive binding (`SO_EXCLUSIVEADDRUSE`) of the four listeners: **met** (audit of #161, S161-02; proof: a second
  socket cannot bind to port 53 of the loopback during the trial, 3a case);
- bounded queries and answers (one question, bounded sizes, answers to blocked names built, never copied
  beyond the question), with no possible panic: **met** (`dns_requete_bornee`, `dns_torturer`);
- bounded rate: 16 queries in progress including 4 TCP connections, 4 s in all for a TCP connection to send its query
  (S161-01), and 4 s in all for a TCP exchange with the upstream: an upstream that drips one byte at a time no longer holds a
  slot (audit of 2026-11-23, C-6; `dns_relais_tcp_echeance_totale`). **Departure**: no queue of 256; beyond the bound, the query is ignored and the client retries. No
  resolution for another host;
- upstream answers accepted only if the upstream, the identifier and the question match, random identifier and source
  port (port drawn from the dynamic range): **met** (`dns_reponse_amont_mal_assortie_ignoree`,
  `dns_port_source_dynamique`); random generator failing: nothing is relayed, never null values (audit of
  2026-11-23, C-10; `dns_alea_echec_ferme`);
- **prerequisites for activation (7.4)**, from the same audit, **met** by `filtrage_cartes.rs` and the monitor (test
  `activation_ordre_des_operations`, 3a case "Filtrage activé (7.4)"):
  - never an adapter set without the exclusive binding: the resolver starts and answers the check before the setting;
  - adapters restored before releasing the port: turning off (an adapter not restored keeps the resolver and its port),
    stopping the service, uninstalling (`--nettoyer`); upstream silence: adapters restored, port kept, switched back by
    a probe every 5 minutes; setting failing at activation and restore failing as well: port kept (simple
    relay) and restore pending as long as an adapter points to the loopback (audit of 2026-11-23, B-3-01;
    `activation_remise_ratee_garde_le_port`); an unreadable registry counts as "still on the loopback" and is
    never a verified restore; unreadable origin: nothing is saved or set (audit of #281, S281-02;
    `activation_registre_illisible_sur_la_boucle`);
  - only physical Ethernet and Wi-Fi adapters are set: HardwareInterface and ConnectorPresent flags read
    from Windows (`GetIfEntry2`), never the name; reading impossible: adapter treated as virtual; `fec0::/10`
    and link-local servers excluded from the upstreams and the fallback (audit of 2026-11-23, T-9 and T-10;
    `activation_cartes_virtuelles_ecartees`, `activation_amonts_sans_site_local`). Limit: Hyper-V host with an
    external switch, no adapter can be set;
  - check at startup: the port is taken before any restore or any setting; adapters set only if the
    resolver answers; otherwise restored while holding the port, and switched back by the probe; port released only when
    no adapter points to the loopback any more (audit of #164, S164-01).

  **Remaining risk**: if the service is killed (crash, forced stop), the port is released while the adapters still point
  to `127.0.0.1`, until the restart by the service manager (5 s) and the startup check. In that
  interval, a local program that took port 53 would answer the computer's resolutions. Same risk if, at a
  normal stop, restoring the adapters fails twice: a fallback then removes at least `127.0.0.1` and `::1` (original
  servers as static), but if it also fails, the port is released with the adapter on the loopback (S164-02).
  Written down, not closed; since PR 7.5a, this case at startup raises the critical alert DNS-003 with the PID of the program
  that holds the port;
- **suspension of filtering** (audit of 2026-11-23, C-7): upstream silence (adapters restored, filtering suspended
  for the whole computer) is no longer declared on client queries alone, which a program of the computer chooses (for
  example names whose server never answers): it takes 30 s without an answer AND the failure of the service's probe (a
  name from the protection list, sent to the upstreams). **Remaining risk**: an attacker who cuts the upstream on the network
  still suspends filtering (intended fail-open, the computer's DNS stays served); a program that occupies the
  16 slots of the resolver delays the answers without suspending filtering (`dns_silence_confirme_par_la_sonde`). A
  standard account that occupies the UDP ports of the dynamic range no longer gets silence declared: a relay that is impossible
  from the computer is counted and logged separately, and the relay falls back to a port chosen by Windows after 8 ports
  drawn (audit of #281, S281-01; `dns_echec_local_pas_un_silence`);
- **domain lists** (audit of 2026-11-23, C-4, C-11, C-12): a copy of more than 500,000 entries is never
  kept; the size-difference safeguard no longer locks a list behind an inflated copy (refusal lifted after 3
  downloads that agree within 10%, count in memory, forgotten when the service restarts; such a replacement
  is published in `filtrage-etat.json`, `Remplacement` field of the list); a file of more than
  32 MB is refused before reading; a name with an invalid label is judged like its longest valid parent.
  A compromised source can still replace a list with another of similar size (no signature of the lists);
- **third-party resolver** (PR 7.6): with Quad9 chosen, every DNS query of the computer that is not blocked is sent to it (in
  clear text: no encrypted DNS, 7.7 not done), local names and reverse queries for private addresses included; never by
  default, stated in the confirmation and on the page. The confirmation advises keeping the network's resolver on a
  company network, and says that at a captive portal the relay through the network's DNS comes after up to 30 s then
  up to 5 minutes without filtering (review of #167, R6);
- **browsing data** (PR 7.5a): only the last 50 **blocked** names are kept, 24 h, in
  `filtrage-etat.json` (protected folder); no relayed name is recorded; none of this goes into `etat.json` or into
  the API;
- what a local standard account can do with it: target the parser with forged packets, saturate the resolver (local denial
  of service that it can already cause otherwise), bypass filtering (possible: it is not a barrier;
  changing the DNS of the adapters requires being an administrator, and DNS-002 reports it).

## Attackers considered

### Local standard account
Wants to read the monitoring data (command lines, sessions, traffic), modify the configuration or the
lists to blind the service, hijack a SYSTEM operation (link, junction, pre-created file), or pass itself off
as the service on the channel.

- Phase 4 (PR 4.2): it can neither close nor modify an incident (`incident` command reserved to administrators,
  author read from the client's token). It can trigger alerts on many entities to saturate tracking
  (500 incidents not closed): only closed ones are removed, the surplus is counted (SAN-012, PR 4.4) and stays in
  `alertes.json`.
- Measures: data folder protected and verified, fail-closed; channel reserved to administrators; file operations
  by handle; restore under the user's identity; PowerShell started by its absolute path (a
  bare name was searched in the machine PATH); service log without control characters (fake lines).
- Proven in CI (3a, 3b): writing, creating and commands refused everywhere; pre-created folder, files with an empty
  DACL, file held open, configuration booby-trapped during an upgrade: discarded, never loaded; junctions:
  refused, canaries intact.
- Residual risks: a file set aside in `ecartes` stays modifiable by its author (never read); the
  scenario with a standard account signed in at the console is not run (VM); the
  check-create race of the restore is not reproduced.
- Published command lines (ATT&CK coverage, batch 1): since reading 4688 events, the process chains of
  `etat.json` can show the first 300 characters of the command line of processes of other accounts, SYSTEM
  included, to reader accounts (which the WMI trace already allowed for a process still alive). A secret passed
  as an argument (password on the command line) can appear there; the number of nodes of a chain was not bounded
  (audit of #244): since T-20 (step 1, lab-tested), 300 processes at most per published chain, the rest counted
  (`NoeudsTronques`). T-20 also publishes, for the same chains, the reason of each signal (same masked text as
  `Raisons`, 90 characters), creation and end times, the parent PID and the entity of the chain (head path, which can
  contain the account folder, as already in the CHA-001 alerts); nothing that the tree did not already hold, no new
  collection (`docs/detection/modele-evenement.md`). Size: the `Chaines` part of `etat.json` is kept under a 3 MiB
  budget, signals then processes of the chains with the lowest score removed first, `ChainesTronquees` set (audit of
  #323, S323-01: before, a built worst case reached 547 MB, read whole by the API); `Raisons` and `Chemin` of the
  published chains are cut at 1,000 and 1,024 characters. Feedback on detection (audit of #323, S323-02): `Lien` and
  `Signaux` tell reader accounts, and so any program running under the console account, what the detection sees:
  why a chain was cut at its head (`pid-reutilise`, `parent-termine`, `parent-service`...) and which rule codes fired
  on which process. This helps an attacker tune an evasion (check that a reused parent PID cuts the chain, or which
  command line stops raising a code); it opens no new evasion, since the rule itself is public in the repository and
  unchanged. Same category as the published blind spots (collections), accepted on the same basis. The SIEM also keeps 400 characters of the command line of each process creation (4688),
  all accounts, 30 days, readable by reader accounts, and the syslog export or the API transmits them. Since the audit
  of 2026-11-23 (A-6-1, fixed in the lab), recognized secrets are masked (`***`) before any storage or publication:
  SIEM, alerts (alertes.json, exports, notifications), chains and connections of `etat.json`; detection analyzes the
  whole line beforehand. Masking is applied to the whole text before any cut (pre-review of #323): a line cut first
  (PRC alert line at 300 characters, tree copy of a 4688 at 1,024, process cache at 8,192, scheduled task command at
  4,096, response event fields at 300, "downloaded from" address of a file's Mark of the Web at 120, also published
  as the `Origine` of connections in `etat.json`) could lose the `@` of an address cut before it, and its password was
  then published; every cut now only removes text that is already masked, and a cut cannot rebuild a secret (tests
  `alerte_processus_masque_avant_de_couper`, `copies_bornees_4688_masquees_avant_de_couper`,
  `chaines_ligne_masquee_avant_de_couper`, `commande_tache_masquee_avant_de_couper`,
  `evenement_reponse_masque_avant_de_couper`, `origine_internet_masquee_avant_de_couper`). Detection keeps reading the
  unmasked text: a scheduled task longer than 4,096 characters is published masked, but its remarks and target are
  computed on the same command bounded and unmasked, never written (review of #324, test
  `tache_longue_detection_sur_commande_non_masquee`). Each 4688 line is masked once, and masking costs linear time
  (a 32,768-character line built to slow it down is masked in a few milliseconds, test
  `masquer_secrets_cout_lineaire`). Alerts and response events written before this version keep the pieces of a
  secret cut before its `@` until they leave the history. Masking follows known patterns: for any tool (`net use`, `net user`, `/pass:`,
  `/password:`, `--password`, `-Password`, `-Credential`, `ConvertTo-SecureString`, `PGPASSWORD=` and similar
  variables, `compte:motdepasse@` in an address), and only for the tools that use them this way (`/p` and `/rp` of
  schtasks and of remote Windows tools, `-p` of mysql, psexec, sshpass, 7-Zip and RAR, `-pw` of the PuTTY tools, `-P`
  of sqlcmd, zip and unzip, `-pass` of openssl, `-u` of curl, `-U` of smbclient; list `OPTIONS_PAR_OUTIL`, review of
  #269: elsewhere `/p` is a flag and `-p` a port). A secret passed in another form (an `Authorization:` header, a
  `token=` parameter, a bearer token), or to a tool absent from the list, stays readable by reader accounts, and the SIEM files written before this version
  keep their whole lines until they are purged (30 days). The first account seen at the console becomes a reader;
  since A-6-2 (fixed in the lab), the Settings page and the first-run setup summary display the reader accounts and
  what they can read; no command removes a reader yet (to be planned: it would be a new privileged
  path).
- Published blind spots (phase 3, state of the collections): `etat.json` is readable by reader accounts, including the account
  signed in at the console by default. A program running under this account reads there which collections are missing
  (`Collectes`, `ReglesSansCollecte`, `ReglesDegradees`: Sysmon absent, log unreadable, PRC rules degraded under
  WMI) and can choose a technique that the service does not see. The "Source" field of the processes already showed it in
  part. Deliberate choice: the user must see what is not monitored; the published reasons carry no
  account name. Reserving these fields to administrators remains possible (maintainer's decision).

### Device on the local network
Wants to exploit the parsers (captured packets, UPnP answers), query the API, listen to the export, or poison
name resolution.

- Measures: parsers bounded and tested; API disabled by default, token, allowed addresses; NDR detection
  (ARP, DHCP, LLMNR/NBNS/mDNS), experimental.
- Residual risks: the syslog export goes out in clear text; the "deR4Tizer capture" rule allows all inbound traffic to
  the service (required for capture). API token fail-closed and `/api/v1/sante` without the machine name
  (PR #14), tested in the lab only.

### Compromised GitHub account
Wants to publish a malicious version that the computers would install.

- Measures: signing key pinned in the binaries already installed (a new key is only accepted by
  the binaries compiled with it); compilation by the CI ("a-signer" artifact), no signing in CI: the
  Certum key is in SimplySign and signing happens on the maintainer's computer (`signer-version.ps1` checks the hash
  of the artifact published by GitHub, the compiled key and the version); immutable releases enabled on the repository on
  2026-11-23 (from the next version on; v4.3 stays modifiable: a compromised account could replace the
  MSI and the notes there, which a first manual installation would only see in the publisher's name, A-3-1); the
  "tags-version" ruleset active on tags (seen on 2026-10-22, content not verified); `main` protected (PR mandatory, no force push; mandatory CI checks
  removed while GitHub Actions was disabled, from 2026-10-22 to 2026-11-17, and not yet restored: the CI
  runs, but a merge does not require it to be green); version read
  from the signed package, more recent than the installed one.
- Rollback: the MSI accepts an older version (`AllowDowngrades`, required for rollback); refusing
  an older version is ensured by the service, for the automatic update only: an administrator
  can always install an older version by hand (`capability-matrix.md`, installation).
- Residual risks: an attacker who controls the maintainer's account can have code of their choice compiled by the
  CI; they only get it signed if the maintainer signs that artifact. Signing computer: a trust boundary in its
  own right. The executables wait in a temporary folder of the maintainer's account between the hash check and
  the signing, and a program of that account during the SimplySign session can have whatever it wants signed: only
  the hygiene of that computer covers it. No independent rebuild. A-3-3 fixed (PR #284 for `ci.yml`, a
  separate PR for `publication.yml`, authorized by the maintainer on 2026-11-23): Rust toolchain pinned
  (`service-rs/rust-toolchain.toml`, 1.100.0, installed explicitly by both workflows) and `cargo test` and
  `cargo build` with `--locked` in `ci.yml` and `publication.yml` (proof: local trial of a modified `Cargo.toml` without
  `Cargo.lock`, refused, see `docs/testing/baseline.md`; `publication.yml` only runs on a `v*` tag: its
  change has not yet gone through a real run). MSI built on the maintainer's computer. An unreachable revocation list makes the signature be refused (PR #12; proven by 3c in
  Windows Sandbox, then in CI in run 44480286774 (PR #205, `cd36ee4`, 2026-11-19)). First signed version published: v4.3 (2026-11-23). The automatic update,
  inoperative in the test versions 4.2 and 4.3 installed by hand (fixed by PR #26, included in v4.3),
  only starts from the signed v4.3, toward a later version.
- Choice of certificate: pinning relies on the public key. Certificate chosen by the maintainer on 2026-11-11:
  Certum Open Source, in the maintainer's name; its public key is pinned (`CLE_SIGNATURE`). Pinning would
  also accept a package signed by this same key for another project of the same holder (the `UpgradeCode` and the version
  remain checked). The certificate is valid until
  2027-11-17. v4.3 pins only one key: the next one must be pinned in a version published before that date,
  otherwise the computers will no longer be able to update themselves. SignPath Foundation (certificate in the foundation's name,
  possibly shared by several projects) and Azure Trusted Signing (key that would change at each renewal) were
  ruled out: they made pinning useless or impossible. The behavior of revocation with an expired certificate
  and a timestamped signature was to be tried with the real certificate before any publication: not done, v4.3 published
  before (departure decided by the maintainer, 2026-11-23). Risk: after 2027-11-17, if revocation of the old
  certificate no longer answers, the rollback package, signed by it, would be refused, and no update would
  install any more (A-3-H1, to be verified in a VM).

### Corrupted threat list
A compromised or erroneous source publishes legitimate addresses (public DNS, update service, the provider's
server).

- Measures: download over HTTPS, bounded loading; a list that would cover more than 2^27 IPv4 addresses or
  2^48 IPv6 /64 networks or more (a /16) is rejected entirely (IPv6 bound: PR 6.15); Feodo Tracker only accepts
  single addresses, no network (PR 6.15); automatic blocking limited to Spamhaus DROP and Feodo
  Tracker, and to 30 per hour (a standard account can reach that on purpose: one-hour stop, alerts kept); a
  manual unblock takes precedence for 7 days; blocks lifted when the address leaves the list or at expiry.
- Residual risks: an automatic block of a legitimate address cuts a service until the next update
  of the list.

PID reuse: kill, suspend and resume require the PID and the creation time, compared on the handle used to act.

Standard account against suspension on decoy: a program named like a known software, signed by its publisher, no longer escapes suspension from a Program Files folder opened by a third-party installer (rights of the program and of its folders required, and SYSTEM or administrator account, since 2026-11-21: S110-14, S114-01, S228-01). Still open at the publication of v4.3: a hollowed process started from an allowed binary, under SYSTEM or an administrator, keeps that status (S114-02); the alert remains, at level Info.

Standard account against the decoys themselves: they are placed in `Documents`, `Pictures` and `Desktop` at their real location, read from the user's hive (OneDrive folder backup, redirection; A-7-2, fixed). The value read is written by the user: it is only accepted under their profile or, elsewhere, in a folder of a fixed local drive (as seen by SYSTEM) that they own, never on a network share nor with ".." or an unknown variable; a decoy with several names (hard link to another file) is neither audited nor tracked (S268-01); and creation stays by handle, without following links, under their identity. Remaining: user without a session (hive not loaded) or folder redirected to a share: decoy in the default folder, refusal logged. Under the load of an encryption, suspension depends on the priority of the 4663 thread, now above normal (A-8-1, fixed, effect not measured).

Privileged operations, audit of 2026-11-23: the local GPO is read fail-closed before any write (file unreadable, truncated or not understood: refusal, nothing is written) and written in one block without changing its rights; cancelling leaves a value hardened since then by a third party (A-2-2 and A-2-3, fixed; tested in the lab, to be verified in a VM). Fixed afterwards (batch 4b; tested in the lab, to be tried in a VM): the service no longer opens any network path, path without a letter or with an unknown drive type (local removable drives, CD-ROMs and RAM disks are still read: they contact no host) to read the signature, the catalog, the hash or the mark of a program (decision `natif::lisible_en_systeme`, applied before any access in `natif::lecture_fichier`; such a program is read as "unsigned"): the machine account is no longer sent to another host (A-5-2, `audit_a_5_2_aucun_chemin_reseau_lu_en_systeme`); a path that goes through a link (symbolic link, junction) is not traversed either: the identity is read by a descent element by element without following links, and a timed read on such a path returns "not read" (S277-04, `audit_s277_04_lien_du_chemin_jamais_traverse`); declared drivers and source of a quarantine on such a path: not read, quarantine refused (S277-03); limit: the signature, the catalog and the hash are then read through the path, a folder replaced by a link in between would be followed (race). The package sets the rights of the program folder (SYSTEM and administrators full control, Users read and execute, inheritance cut); the service reads them back at startup, by handle without following links, along with those of each parent folder up to the root of the volume (renaming the folder requires "delete child" on the parent; folder creation tolerated on the root only, S277-01): critical alert INT-003 and update refused if they allow another account to write, delete a child or change the rights, or if they are unreadable (A-4-1, `audit_a_4_1_dossier_installation_protege`, `tests\test-msi.ps1`). Windows tools started by their full path in the service and the interface (A-2-1, A-5-3). The signature caches (connections, learning, VOL-001) are keyed by the identity of the file read by handle with its USN number, or the SHA-256 hash of the content without USN (64 MB at most, otherwise no cache), instead of the path and modification date that a standard account can set back identically (B-2-01, second audit, `audit_b_2_01_programme_remplace_meme_date_reverifie`).

## Outside the model

- A program under the user's account can close or suspend the interface: the scheduled task restarts it (5 min at most), SAN-010 and SAN-011 report an absence or repeated stops, a suspended interface is not seen; monitoring and reporting continue. The task, set by SYSTEM after deleting any task with the same name, with its rights and read back afterwards, cannot be modified by a standard account. An administrator who removes the Run value cuts SAN-010 and SAN-011 (they can also stop the service).
- An attacker who is already administrator or SYSTEM: they can stop the service, modify its files and its rights. Since phase 4 (PR 4.4b), when reporting is configured, the daily heartbeat stops: the provider can see
  that a computer no longer answers, without knowing why (service stopped, computer off, network cut).
  deR4Tizer complements Microsoft Defender, it does not replace it.
  Process chains (CHA-001, audit of 2026-11-23, T-1): the programs that the service starts (auditpol, wevtutil,
  powershell, curl, icacls, netsh, gpupdate, schtasks, conhost, recognized by their exact path under System32) and their
  descendants leave the chains. An administrator who creates a process with the service as parent (T1134.004)
  does not leave them: a child of the service outside this list stays in the chains and carries a signal there (probable spoofed
  parent, T1134.004). Limits: if they choose one of these programs as parent while it runs (a few seconds),
  their chain leaves CHA-001 without a signal; if they take the service as parent by starting one of the programs of the
  list themselves (for example `powershell.exe` from System32), that program is treated as a program of the service and its chain
  leaves CHA-001 without a signal. Planned closure: the service will remember the PIDs it starts itself (registry of the
  PowerShell instances started by the service, phase 4104, reservation R3); not done.
- Preserving traces against this attacker, or after an intrusion discovered late. A standard account that creates
  processes in a loop no longer pushes the previous days out of the SIEM (A-6-3, fixed in the lab): the file of the day
  is never deleted, and beyond its ceiling (1 GB / 30) the events of the day are no longer written but counted;
  it can therefore still silence the SIEM for the rest of the day, and make its queue overflow: finding SAN-013 says so
  (first loss, first ceiling, first purge by size). The service log rotates over 5 generations
  (A-8-3, fixed in the lab): provoked noise must write more than 10 MB to erase a line. The SIEM (`siem\`, 30 days
  and 1 GB at most) and the service log (`journal.txt`, 2 MB, then `journal.1.txt` to `journal.5.txt`, each
  rotation stating the interval covered) stay on the monitored machine: an administrator can
  erase them, and an intrusion older than these limits is no longer there. Only a copy already sent elsewhere escapes this,
  and none is complete: the syslog export, if configured, only sends the alerts, in clear text (without TLS), without
  guarantee of receipt; reporting (ntfy, Teams, SMTP), encrypted in transit, only sends grouped and
  capped alerts; the export API, if a third-party tool reads it, also gives the SIEM events, in clear text (HTTP) on
  the local network. No encrypted and complete export of the traces exists.
- Code injection into a legitimate process (data theft is detected by the identity of the program that
  reads the files).
