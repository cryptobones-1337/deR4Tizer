# Changelog

## Unreleased

- Domain-name filtering, audit of 23 November 2026 (findings T-9, T-10, B-3-01, C-4, C-6, C-7, C-10, C-11, C-12;
  tested in the lab, not yet tried in the VM). Only hardware Ethernet and Wi-Fi cards are set when filtering is turned
  on: the service reads the HardwareInterface and ConnectorPresent flags of each card from Windows (`GetIfEntry2`),
  never its name, so Hyper-V switch cards ("vEthernet"), WSL, Docker and VPN TAP cards are left alone; a card whose
  flags cannot be read is treated as virtual. The cards that would be set are published before activation
  (`CartesARegler` in `filtrage-etat.json`); the confirmation window does not show them yet. Windows' default
  site-local IPv6 DNS servers (`fec0:0:0:ffff::1` to `::3`, and all of `fec0::/10`) and link-local addresses are no
  longer used as upstream or fallback, and the 10-minute trial tries IPv4 servers first. If setting a card fails and
  restoring it fails too, the resolver keeps port 53 (relay only) and the restore is retried every 5 minutes, instead
  of stopping and reporting "cards restored". The list guard is no longer one-way: a copy above 500,000 entries is
  always refused (first download included), and a list refused for its size is accepted after 3 downloads in a row give
  the same size (within 10%), so an inflated copy no longer locks out the healthy list; such a replacement is shown in
  the published filtering state (`Remplacement` field of the list in `filtrage-etat.json`, kept until the service
  restarts), not only in the log. A list file larger than 32 MB is
  refused before being read. A TCP exchange with the upstream now has a 4 s overall deadline. The upstream is declared
  silent (filtering suspended, cards restored) only when the service's own probe gets no answer either: queries chosen
  by a local program are no longer enough. A random-generator failure now stops relaying instead of using zero values.
  A name with an invalid label is judged as its longest valid parent, so it no longer escapes its domain's block.
  Review of the change (S281-01, S281-02): a card whose DNS registry values cannot be read counts as still pointing to
  the resolver (port 53 kept) and is never reported as restored; a relay that fails on the computer itself (busy
  dynamic UDP ports, random-generator failure) is counted and logged apart and never declares the upstream silent;
  after 8 random source ports, the relay falls back to a port chosen by Windows (the query ID stays random).
- Canaries in the real folders (audit of 23 November 2026, A-7-2): `Documents`, `Pictures` and `Desktop` are resolved
  from the user's own "User Shell Folders" registry values (OneDrive folder backup, redirection to another local fixed
  drive), with `%USERPROFILE%` and `%OneDrive%` expanded for that user; network shares, removable drives, unknown
  variables and `..` are refused (default folder kept, refusal logged). When the user's registry is not loaded (not
  signed in), the default folder is used as before. Creation failures are logged once and make the `Leurres` collection
  partial; the health status publishes "n placed out of m expected" (new `Detail` field of the collection). A canary
  left in a former folder stays watched while it exists and is removed on uninstall, as are canaries in redirected
  folders. Outside the profile, only a folder on a local fixed drive owned by the user is accepted, and a canary with more
  than one name (hard link) is neither audited nor watched (link count, audit and hash read through a single handle;
  former locations are checked again); at most 3 former locations are watched per canary. Canaries
  in a OneDrive-synced folder may be uploaded to the user's cloud storage, and OneDrive is suspended if it writes to or
  deletes one; not yet tried in a VM.
- Service priority (A-8-1): the service process now runs at normal priority instead of below normal; heavy periodic
  threads (startup entries, Defender and baseline checks, threat lists, LOLDrivers download, sensitive-data audit) run
  in background mode, and the canary event thread (4663) and the command pipe thread run above normal. The effect on
  the delay between the canary event and the suspension under load is not measured.
- IDS (experimental) and incident tracking, second audit (findings B-4-01, B-4-02, B-5-01; tested in the lab, not yet
  tried in the VM). An IDS rule whose `content` options are all negated now evaluates them: it fires only when none of
  them is present (before: on its header alone); as in Suricata, a rule with any `content` never matches a packet
  without payload (SYN, ACK), so an IPS `drop` rule with negated contents cannot block a plain ACK. The standard address and port variables of Suricata 7's default
  `suricata.yaml` (`$HTTP_SERVERS`, `$SMTP_SERVERS`, `$AIM_SERVERS`, `$SHELLCODE_PORTS`, `$MODBUS_PORTS`…) now take
  their default values; any other header variable makes the rule ignored and counted, instead of meaning "all
  addresses" or "all ports". An incident with more than 20 status changes now still gets its timeline recalculated: the total number of
  changes is counted (`NombreTransitions`), while only the last 20 are kept.
- Process detection, audit of 23 November 2026 (findings A-7-1, A-7-3, A-7-5, A-7-7, A-7-8, A-7-9; tested in the lab,
  not yet tried in the VM). PRC-002 now sees `irm … | iex`, every abbreviation of `-EncodedCommand` (`-e`, `-ec`,
  `-enco`, `/e`…), `iwr … -OutFile`, `Start-BitsTransfer`, and a renamed copy of PowerShell when Sysmon gives the
  program's original file name (not without Sysmon); a command-line download to an http(s) address alerts even without
  `iex`. PRC-005 sees shadow copies removed from PowerShell (WMI or CIM), `vssadmin resize shadowstorage` below
  1,000 MB, `wbadmin delete backup`, `bcdedit … bootstatuspolicy ignoreallfailures` and `diskshadow … delete shadows`.
  PRC-003 sees an LSASS memory dump through comsvcs.dll (Critical, T1003.001), rundll32 on a DLL from a user-writable
  folder (T1218.011), msiexec from an http(s) address (T1218.007), mshta and regsvr32 on a UNC path, `regsvr32 -i:` and
  `certutil -verifyctl -f … http`. PRC-001 counts hh, msiexec, forfiles, cmstp, odbcconf, regasm, regsvcs and msxsl as
  interpreters and the new Outlook (olk.exe) as a document. PRC-004 covers Vivaldi, Opera, Yandex and Arc. Process
  chains (CHA-001) stop only at a system launcher identified by its exact path under the Windows folder, no longer by
  its name: a fake `svchost.exe` in a temporary folder no longer cuts the chain. Still not seen: a parent chosen at
  process creation (parent process spoofing).
- Baseline (audit of 23 November 2026, A-2-2 and A-2-3): the local Group Policy files (`Registry.pol`, `audit.csv`,
  `gpt.ini`) are read fail-closed before anything is written; a file held by another program, truncated or not
  understood stops applying, cancelling or uninstalling the baseline, and the message says so, instead of erasing the
  other local policies (an audit subcategory line in an unexpected form or listed twice is refused). Each file is
  written in one block without changing its permissions, and leftover temporary files from a crash are removed; the
  original copy of the local policy is checked. Cancelling keeps a value changed or deleted outside deR4Tizer since
  it was applied: deR4Tizer's policy entry is removed and that value is set back after the policy update (the rule
  stays recorded if this fails); a current value that cannot be read (unreadable key, failed read, unexpected type)
  is never taken as deleted: nothing is changed for it and the rule stays recorded; a value set by a stricter rule still applied is not reported as someone else's. If
  uninstall cannot cancel the baseline, its rollback backup is still deleted without `GARDER_DONNEES=1` (known limit). `wevtutil`, `auditpol` and `gpupdate` are started from System32 by
  their full path (A-2-1, for the baseline only). To be checked in the VM.
- Data (audit of 23 November 2026, batch 5): known secret arguments in command lines (`net use` and `net user`
  passwords, `/pass:`, `/password:`, `--password`, `-Password`, `-Credential`, `ConvertTo-SecureString`, `PGPASSWORD=`
  and similar variables, `user:password@` in an address, and, for the tools that use them only, `/p` and `/rp`
  (schtasks and other remote Windows tools), `-p` (mysql, psexec, sshpass, 7-Zip, RAR), `-pw` (PuTTY tools), `-P`
  (sqlcmd, zip, unzip), `-pass` (openssl), `-u user:password` (curl), `-U user%password` (smbclient)) are masked (`***`) before being stored in the SIEM, in alerts (alert history, syslog
  and API exports, notifications) and in process chains and connections shown by the interface; detection rules still
  read the full command line (A-6-1). The SIEM never deletes the current day's file: beyond a daily cap (1 GB / 30),
  that day's events are counted and not written, the size purge only removes previous days, and a new health finding,
  SAN-013, reports dropped events, the daily cap and size purges (A-6-3). The service log rotates over 5 files
  (`journal.1.txt` to `journal.5.txt`) and each rotation writes the time span of the rotated file (A-8-3). Settings and
  the first-run summary say that reader accounts can read the history of every account (A-6-2).
- Documentation after the audit of 23 November 2026 (done by Claude, so not an independent review): v4.3 is now
  recorded as published with three unmet conditions (no independent review, D4-1 trials, revocation trial after
  certificate expiry); open findings declared as known limits (canaries and OneDrive folder backup, PowerShell forms
  missed by PRC-002 and PRC-005, process chains, SIEM command lines, local Group Policy, install folder, domain-joined
  computers); threat model updated (date, signing workstation, service restart, pipe availability); NDR, DPI and IDS/IPS
  marked experimental in the roadmap; uninstall the 4.3 test build before installing the signed v4.3.
- Installer license: says that the released installer and programs are signed (Certum certificate) and that only a build you compile
  yourself shows "unknown publisher"; the v4.3 installer still said the binaries were not signed.

## 4.3 · 2026-11-23

First signed release (tag `v4.3`, commit `46243f7`): executables and MSI signed with the Certum certificate (key
pinned in the service), then batch 3d passed in the test VM on this signed MSI, with Microsoft Defender fully active
(all scenarios passed, no detection). Published before the deferred D4-1 trials (interface restart in a Remote Desktop
session and on fast user switching), which remain to be run (README, "Known limits"). Builds 4.2 and 4.3 installed by
hand earlier were unsigned test builds and do not update on their own (README, "Known limit").

Main changes since the unsigned test build 4.3, most recent first:

- Local signing: `signer-version.ps1` no longer stops when reading the MSI version (the path built by `Join-Path`
  was refused by the Windows Installer COM call). Found by the signing rehearsal on a private copy; the CI now reads
  the version of the MSI it builds.
- PRC-002 (obfuscated or downloading PowerShell) now carries T1027 Obfuscated files or information only when an
  obfuscation pattern was seen (`-EncodedCommand` with a long payload, `FromBase64String`); a download, a string
  execution or a hidden window carries T1059.001 PowerShell alone. Its behaviour code names the patterns seen, so an
  exception set on a PRC-002 alert stops applying, once.
- When the exceptions file could not be loaded at startup, the Health page says so ("Exceptions", in memory only)
  and setting an exception says it will be lost when the service restarts; a malformed file that could not be set
  aside is never overwritten. The PRC-003 behaviour code names every tool seen, like its techniques (exceptions set
  on a two-tool alert stop applying, once).
- Local signing: before signing, `signer-version.ps1` checks that the certificate's key is one of the keys compiled
  into the service (the compiled value is joined to the build artifact and found again inside the executable), so a
  release that installed machines would refuse can no longer be signed.
- Alerts carry only the ATT&CK technique actually observed: PRC-003 the technique of the tool seen (certutil T1105,
  bitsadmin T1197, mshta, regsvr32 and rundll32 T1218, wmic T1047), PER-001 and PER-002 the technique of the startup
  entry type (Run key T1547.001, service T1543.003, scheduled task T1053.005, WMI subscription T1546.003); RES-002 and
  RES-003 keep T1071.001 and DNS-001 T1071.004 only. The ATT&CK map does not change. The PRC-003 behaviour code now
  names the tool whose pattern matched, not the first tool name seen in the command line: an exception set on such an
  alert can stop applying (the alert comes back).
- Exception fingerprints no longer depend on ATT&CK techniques or advice: they use the rule and a stable behaviour
  code set by the code that raises the alert (tool seen, startup entry type, connection indicators, IDS rule…), so
  editing the technique tables or moving to a new ATT&CK version no longer voids any exception. Exceptions from the
  previous fingerprint format cannot be converted: they are kept aside, counted, and shown in the Health page
  ("Exceptions" line, to set again, cleared by "Clear exceptions from a previous version" in the settings), never
  dropped silently; the old file is copied aside before the migration. Known limit: going back to an older build
  erases the exceptions set in the new format (their alerts come back).
- ATT&CK technique taken from the detection rule (one table next to the rule registry, ATT&CK v20.1), never from words
  in the alert text; attack chains carry the techniques of their own signals instead of a default one; an alert can
  carry several techniques, each translated in the interface.
- Process rules without Sysmon: PRC-001 to PRC-005 and process chains read the Security log's process creation events
  (4688), which carry the command line and the parent even after a short-lived program has exited; WMI is used only
  when this audit is off. New collection "Process creation auditing (4688)" in the Health page (active, partial when
  the command line is missing, disabled or unavailable, with the WMI fallback stated); one alert per process creation
  whatever the source.
- ATT&CK map of the "ransomware and opportunistic intrusion, small organisation" profile published
  (`docs/validation/carte-attack.md`, ATT&CK v20.1).
- Response register (`reponses.json`): an administrator's command waits for its copy to be written only after releasing
  the monitor lock, so a slow disk no longer delays the monitoring cycle.
- Canary files: a known, signed backup tool is spared only if its folder can be written to by administrators, SYSTEM,
  TrustedInstaller or services alone, and it runs as SYSTEM or an elevated administrator; sync clients running under
  the user's account (OneDrive, Dropbox, Box...) are no longer listed as known and are suspended if they touch a canary
  file; checked in a test VM with real permissions and tokens.
- Elevated confirmation: the publisher shown is read from the signature check itself, never by reading the file again;
  checked in a test VM for a signed and an unsigned program.
- Release signature check: the certificate chain must build with no error (or only "expired" when timestamped); the
  check script is run by the CI on real test packages.
- `reponses.json` that cannot be read is never overwritten; it is written by a dedicated thread.
- README and project page: real screenshots of the current interface, taken in the test VM, including a critical alert
  raised by a harmless demo attack.
- Release workflow: nothing is published unless the MSI and both executables carry a valid, timestamped signature from
  a pinned key; the tag name is validated and never inserted into a script; approval required on publishing.
- Security baseline review (November 2026): the rollback copy is written and read back before any change; a computer
  whose management cannot be read is treated as managed (read-only); Defender rules count as compliant only when
  Defender actually applies them ("no effect" state); LSA protection without the UEFI lock (Windows 11 22H2 or later);
  event logs are never shrunk; reverting restores the original values (checked rule by rule in a test VM); side effects
  (Remote Desktop, UAC prompts, guest shares) are stated before applying, and the full profile leaves Remote Desktop on
  when it is in use.
- Messages and logs: every form of a user profile path is masked.

Earlier work (phases 1 to 7, interface redesign, Kali lab campaign) is described in the README roadmap and in
[docs/validation/](docs/validation/).
