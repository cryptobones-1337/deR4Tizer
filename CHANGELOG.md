# Changelog

No version has been published yet. The first signed release will be the first entry below; builds 4.2 and 4.3 were
test builds, installed by hand and unsigned, and they do not update on their own (see the README, "Known limit").

## Unreleased

Main changes on `main` since build 4.3, most recent first:

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
