# Changelog

No version has been published yet. The first signed release will be the first entry below; builds 4.2 and 4.3 were
test builds, installed by hand and unsigned, and they do not update on their own (see the README, "Known limit").

## Unreleased

Main changes on `main` since build 4.3, most recent first:

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
