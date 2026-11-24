# Response policy of deR4Tizer

A response action cuts off or modifies something on the client's computer: it must be accurate, reversible
and predictable. This policy sets what deR4Tizer is allowed to do on its own. It has been applied in the
code since phase 6 (validated by the maintainer on 2026-11-03, `CLAUDE.md`, section 5, point 4); the gaps that
remain are listed below.

## Levels

| Level | Name | What happens | Examples |
|---|---|---|---|
| 0 | Observation | Event recorded (mini-SIEM, log), no alert. | New connection of a known program, learned behavior. |
| 1 | Alert | Local alert and, depending on severity, escalation to the provider. No action on the computer. | New persistence, suspicious connection, dangerous extension. |
| 2 | Action under human control | Action proposed and confirmed by an administrator (UAC), **or** automatic action disabled by default, knowingly enabled. | Kill, suspend, quarantine, isolate a program, panic mode, manual blocking; IPS (disabled by default). |
| 3 | Automatic action | Action taken by the service on its own, without confirmation. | Only the two actions below. |

## Only level 3 actions allowed

1. **Blocking of the IP addresses of Spamhaus DROP and Feodo Tracker** at the firewall (high-confidence lists,
   free to use), identified in the binary, whatever the "listes restreintes" setting: any other list
   gives an alert only. The block is lifted when the address leaves these lists, if all three are loaded, or on expiry (7 days).
   Feodo Tracker publishes server addresses: a network that appeared in it is discarded. A list whose coverage
   is aberrant (more than 2^27 IPv4 addresses, or 2^48 IPv6 /64 networks or more, that is a /16) is rejected entirely (PR 6.15).
2. **Suspension of the program that touches an anti-ransomware decoy.** Critical Windows processes
   (`reponse::protege`) are never suspended; known and signed backup, synchronization or antivirus software, with the exact name,
   installed outside the user's profile (folder rights not checked), triggers an alert without suspension. The program stays suspended until
   a human decision.

Everything else, IPS included, is at level 2 at most.

## Domain name filtering (phase 7, in the code)

Filtering is in the code: engine (PR 7.2, `filtrage.rs`), local resolver (PR 7.3, `dns_local.rs`), activation
on the adapters (PR 7.4), "Navigation" page and log of blocks (PR 7.5), third-party resolver Quad9 as an option (PR 7.6).
Blocking a domain name through filtering is an **automatic level 2 action**: disabled by default,
knowingly enabled by an administrator, categories enabled separately ("Navigation sécurisée", "Publicités et
pistage"). It does not add to level 3.

The rows marked "D7-x" refer to the phase 7 design file. D7-8 (Quad9) was settled by the maintainer on
2026-11-14; D7-1 (local resolver) is an applied recommendation of the file, put into service on the adapters with the maintainer's explicit agreement for 7.4 (2026-11-12);
D7-2, D7-3 and D7-10 are recommendations of the file applied in the code, without a written decision of the maintainer
(`docs/detection/listes-domaines.md`).

| | In the code |
|---|---|
| Duration | As long as filtering stays enabled: it is a **mode**, not a one-off action, hence without deadline (unlike the IPS, whose blocks last 24 h). So that a lasting false positive does not go unnoticed (a town hall's website in an advertising list), a counter of blocked names and a signal beyond a threshold, or a periodic reminder, are to be planned with the interface (PR 7.5) (audit of #157, S157-02). |
| Recovery | Disabling by the user, uninstallation, allowing of a name by the user, manual procedure written in the README. With the local resolver (D7-1, applied recommendation, put into service on the adapters with the maintainer's explicit agreement for 7.4 (2026-11-12)): network adapters restored exactly, DHCP included, on disabling, on service stop and on uninstallation. |
| Failure | Open, never a DNS cut: original servers as backup if the local resolver stops answering. |
| Guard against loops | Applied recommendation of the file (D7-10, without a written decision of the maintainer): never an automatic reinstatement after a DNS change by a third party (VPN client, provider); DNS-002 alert and reactivation by the user. |
| Never blocked | A protection list compiled into the binary (Windows and Defender updates, certification authorities) and the names allowed by the user. |
| What it is not | A security barrier: a program that has its own resolver (built-in encrypted DNS, hard-coded address) bypasses it. It reduces exposure, nothing more. |

Domain blocks set by hand in the hosts file stay what they are today (manual, the user's lines
never rewritten).

## Common rules

- A critical alert is never softened (learning, exceptions) nor held back by the escalation cap.
- Each automatic action is logged and produces an alert that says what to do.
- Each response action has a maximum duration and a tested recovery procedure. At the deadline, never an
  automatic resume of a suspended process nor an automatic lifting of an isolation: the alert is sent again
  to the provider, recovery is a human action (phase 6).

## Decision point and guard against loops

Blocking an address, suspension, resume, termination of a process, isolation and panic mode go through
`politique.rs`: none is executed without an authorization it issues (`execution.rs`). Domain blocking,
quarantine, restore and unblocking are manual and do not go through it. An automatic action is allowed only
in the cases written here.

**Revalidated identity.** Kill, suspend and resume apply to a process identified by its PID and its creation time.
The administrator instance reads and shows them, with the path and the verified signature, and the service compares them just
before acting, on the same handle; otherwise, no action. A command without identity is refused. For a decoy: process created
before the event. The path is not compared (maintainer's decision, 2026-11-01): a program that renames itself, or whose
path is very long, must remain suspendable and stoppable.

The guard only concerns automatic actions, has no setting and never holds back the alert: only the action
is held back. An administrator can always act by hand.

| Guard | Threshold | Effect |
|---|---|---|
| Same automatic block on the same address | 3 times per 24 h | then, alert only and "Critique" alert of a stopped loop (REP-002) |
| Suspension of a signed program installed in Program Files, interpreters excluded, closed to writing (only SYSTEM, Administrators, TrustedInstaller or a specific service write there or own it) and launched under SYSTEM or an administrator | 3 times per 24 h | then, alert only and "Critique" alert of a stopped loop (REP-002) |
| IP blocks by the lists, all targets | 30 per hour | beyond, stopped for 1 h, "Critique" alert once |
| Distinct addresses by the IPS (counter separate from the lists) | 50 per hour | beyond, alert only |
| Contrary human decision (unblocking, resume) | 7 days | no automatic action on this target, alert only |

- **Suspension without a global cap, and without threshold outside Program Files** (maintainer's decisions, 2026-11-01): a
  ransomware must not be able to exempt itself either with throwaway programs, or by launching itself four times, or through three hits
  via `powershell.exe`. Only a signed program installed in Program Files, interpreters excluded, has a threshold; since
  2026-11-21 (maintainer's decision, S110-14), the program and its folders must also be closed to writing
  (only SYSTEM, Administrators, TrustedInstaller or a service account write there or own them) and it must run under SYSTEM or an administrator, and the list of interpreters is
  completed (dotnet, deno, bun, Lua, R, Julia, Tcl, AutoHotkey, AutoIt, MSBuild, csi). In return,
  a legitimate program outside this case is suspended at each hit, and a program relaunched in a loop piles up, suspended,
  until an administrator resumes or stops it. The Program Files threshold remains usable by a signed program
  already installed that would touch the decoys three times: the alert remains.
- **Limit of the list cap**: a standard account can reach it by connecting to 31 listed addresses. Blocks
  by the lists then stop for one hour, renewable; the "Critique" alerts remain. The cap protects
  against a corrupted list.
- **Limit of the IPS**: `ids.rs`, not fixed to date, writes "bloquée" in its alert as soon as it detects, even if the action is then
  held back; the SIEM and the log state that it was held back.
- **Human decision on a program**: tied to the hash of the executable. A file replaced at the same path does not
  inherit it, and an unreadable hash gives no exception. A resume counts as one only if the program was
  suspended automatically in the last 7 days, and never for an interpreter (PowerShell, cmd, rundll32, python…)
  nor a program of the Windows folder: the exception would cover all the scripts it launches; the administrator reads this in
  the reply to the resume (PR 6.14). Limit: the interpreter is recognized by its file name; a renamed copy
  (powershell.exe copied as maj.exe) keeps the exception. The confirmation of a resume or of an unblocking states the 7-day effect before acting,
  and the signature shown is that of the file at that path, not necessarily that of the process (PR 6.14).
- **History**: `reponses.json`, bounded (2 000 traces, 500 human decisions), kept after a restart. Malformed
  content: no automatic action, REP-002 alert; removing the file from the data folder, then restarting the service,
  restores automatic response. Read refused (file held open, folder protection failed): the guard restarts
  in memory, without its history, and response remains; the file is then never overwritten, and the service log
  says so (S110-13, 2026-11-21). The file is read outside the guard lock, and written by a dedicated thread that keeps only the
  most recent copy: the cycle and the decoy thread drop off the copy without waiting for the disk; an administrator
  command (open, close, lift, human decision) replies only once its copy is written, 10 s at most, so that
  the interface rereads an up-to-date file; this wait happens only once, at the end of the command, after giving back
  the monitor lock: a slow disk no longer delays the cycle (auditor's review of 2026-11-21, point 2; measured
  with a write slowed down to 800 ms: the cycle waited 700 ms, it no longer waits); an older copy
  never overwrites a more recent one, and a failed write is retried 5 s later (S110-04, S110-16, S230-01,
  S230-02). Limit: the last copy can be lost if the service stops before it is written; a file refused at the
  initial read is not reread before the next start (S230-03). Since the auditor's review of 2026-11-21
  (point 1): the service log only states the first write failure of a series and the return to normal, and
  the Health page shows a "Registre des réponses" line as failed as long as the file is not written, or when the
  initial read was refused (the session's deadlines will then be lost at restart); the service publishes a
  code in etat.json (`RegistreReponses`: empty, `EcritureEnEchec` with `RegistreReponsesDepuis`, `LectureRefusee`,
  `ContenuIllisible` or `ProtectionEnEchec`: all the cases where nothing is written), translated by the interface.

## Durations and recovery (phase 6, in the code)

Decisions: `docs/roadmap/phase6.md`. These values have been in force since the PRs quoted in the table.

**Transactional panic mode (PR 6.5).** The two rules are set and checked (present, enabled, blocking),
and only then is the flag written; a failure at any step removes everything and raises the REP-003 alert "mode
panique NON activé". Deactivation removes, checks that no rule remains, then deletes the flag; a remaining
rule keeps the flag. The published state is the effective state, counted on the rules: "active", "inactive" or
"incertaine". A firewall profile disabled beforehand is enabled for the activation, and disabled again if it
fails. Limit: the machine's DNS servers and the addresses of the notification servers stay reachable, all
ports, for all programs (a DNS tunnel remains possible).

**Isolation on the final path (PR 6.6).** The program is opened by walking down its path element by element, each
folder opened relative to the handle of its parent, without following a reparse point (PR 6.13); a folder of the path that is a link, a junction or a mount point
is refused, and the administrator gives the real path (PR 6.13; before, a junction was resolved). Its final path
(short names expanded) is compared with the Windows folder, and
it is the one that carries the firewall rules. A network path, a pipe or a volume without a letter is refused on the text,
before any opening; so is a file that bears the name of a critical Windows program (svchost.exe, lsass.exe…) or
of a program shipped with Windows (present in the Windows folder, System32 or SysWOW64: dllhost.exe,
RuntimeBroker.exe…, PR 6.13) outside the Windows folder (quarantine is better suited). Limits: a malware
named svchost.exe in a user folder therefore cannot be isolated, only quarantined; nor can a legitimate
tool that bears the name of a Windows program (curl.exe or tar.exe shipped with Git, for example); a
program named like a piece of software of Program Files or of a Windows subfolder (browser, WmiPrvSE.exe…) remains
isolable, and a junction placed afterwards could make the real one cut off, until the human decision that
REP-004 asks for. Every 5 minutes, each isolation is checked again by the same walk down, folder by folder
without following a link (only the tags that redirect the path count, "name surrogate" bit: junctions, symbolic
links…, not OneDrive on-demand files or folders, PR 6.13; a path unreadable for 3 readings in a row
is stated by REP-004). The path is never handed back to Windows as a whole, neither at isolation nor at the recheck: a folder replaced by a link during the reading is not traversed
(PR 6.13; before, it could be between the reading of the folders and the opening of the file): if its path leads elsewhere (folder replaced by a junction or a link), the REP-004 alert says so, once; the rules are kept, never lifted
automatically, and can then cut off the network of the targeted program: the decision remains human. Limit: an isolated program copied
elsewhere is no longer cut off from the network (the rule targets a path, not a file).

**Interface (PR 6.7b).** The "Réponses en cours" page shows each active action: what, on what, trigger,
since when, reminder deadline, state ("relance en attente" in yellow, panic mode in red, always written out in
full), recovery procedure, service stopped included. Its button ("Reprendre", "Libérer",
"Débloquer", "Rétablir Internet", "Restaurer") sends the command over the channel: for a non-administrator account,
through the elevated assistant and its confirmation; for an administrator, after the page's confirmation (and that of
the assistant for "Reprendre"). "Reprendre" refuses a reused PID (creation time compared). The confirmation of the panic mode states
its scope (all of the Internet, IPv4 and IPv6; open IPv6 connections not cut; local network, DNS and notification
servers reachable), the reminder at 4 h and the rollback; the header shows the effective state published by the
service. The confirmation of an isolation shows the real path that will be isolated, also to an administrator, when it is on a
fixed local disk and readable within 2 s.

**Deadlines.** A deadline is a reminder appointment, not a lifting. Since PR 6.4, the action register
(`reponses.json`) tracks suspensions, isolation and panic mode, and since PR 6.4b quarantine and
manual blocks; a reminder is the REP-001 alert, one per kind of action and per hour at most (24 h for
quarantine and manual blocking; reminders held back go out, counted, with the next one). A suspended
process that no longer exists moves to "terminé", without alert. Beyond 500 actions in progress, the oldest
quarantines and manual blocks leave the tracking first, then the most recent automatic suspensions: the first one,
often the real program followed by throwaway ones, stays tracked; the number of what leaves is stated once by REP-002
"registre plein", until it is back under the bound (PR 6.14). Limit: an attacker who keeps 500 throwaway programs
suspended before launching the real payload makes it leave the tracking as soon as it enters; its LEU-002 Critical alert goes out
anyway, but neither reminder nor row on the "Réponses en cours" page. What leaves stays suspended, and its original alert remains. A panic mode, an
isolation or a manual suspension always stay tracked. The real state of the threads of a suspended process is not reread: the reminder says
that it may have been resumed outside deR4Tizer.

| Action | Deadline | At the deadline | State |
|---|---|---|---|
| Level 3 IP block (Spamhaus DROP, Feodo Tracker) | 7 days | lifted; earlier if the address leaves the list | done |
| IP block by the IPS | 24 h | lifted | done (PR 6.4) |
| Automatic suspension (decoy) | 2 h | stays suspended; "Critique" reminder, then every 24 h | done (PR 6.4) |
| Manual suspension | 24 h | stays suspended; "Alerte" reminder, then every 24 h | done (PR 6.4) |
| Isolation of a program | 7 days | stays isolated; "Alerte" reminder, then every 7 days | done (PR 6.4) |
| Panic mode | 4 h | stays active; "Critique" reminder, then every 24 h | done (PR 6.4) |
| Quarantine | 30 days | stays in quarantine, never deleted; "Info" reminder, then every 30 days; closed by a restore | done (PR 6.4b) |
| Manual block (hosts, IP) | 90 days | stays blocked; "Info" reminder, then every 90 days; closed by an unblocking | done (PR 6.4b) |
| Kill, kill a chain | not applicable | irreversible, logged | n/a |

An automatic block whose deadline was not written gets one at the next check: 24 h if it comes from the IPS,
7 days otherwise.

**Recovery.** With the service, isolating then releasing a program (scenario 3b) and enabling then disabling the panic mode (scenario 3a) are exercised at each full pass in a VM since phase 6 (for example the proof of PR #168: 3a 90 passed, 3b 34 passed, 0 failure). The procedures with the service stopped and after uninstallation are written, not exercised in a VM; the long deadlines (2 h, 24 h, 7 days) are only checked in the lab.

| Action | With the service | Service stopped or failed | After uninstallation |
|---|---|---|---|
| Suspension | "Reprendre" (identity revalidated) or "Tuer" | Windows Resource Monitor (`resmon`, "Reprendre le processus"), or termination of the process in Task Manager | the process stays suspended until it is stopped or until restart: restart the computer |
| Isolation | "Libérer" (on the final path; exercised in a VM in scenario 3b) | Windows Defender Firewall with Advanced Security: delete the rules "deR4Tizer - isole …" (group `deR4Tizer`) | `--nettoyer` removes the group, to be checked for the isolation rules |
| Panic mode | "Rétablir Internet"; also safe in the "incertain" state (VM signal, PR 6.5) | delete the rules "deR4Tizer PANIQUE" in the firewall, then the `panique-active` file of the data folder | `--nettoyer`, based on the rules and not only on the flag |
| IP block | "Débloquer" | "deR4Tizer" rules of the firewall | `--nettoyer` |
| Quarantine | "Restaurer" or fallback | none (encoded copy in the data folder) | with `GARDER_DONNEES=1`: reinstall then restore; without: lost, to be checked |

## Gaps between the current code (4.3) and this policy

| Gap | Where | To be handled |
|---|---|---|
| The IPS, once enabled, blocks at the firewall without confirmation (level 2 "disabled by default", compliant), but without its own maximum duration nor documented recovery procedure. | `ids.rs`, `moniteur.rs` | Handled in phase 6: 24 h block, lifted at the deadline (PR 6.4, table above). |
| No maximum duration nor reminder to the provider for a suspended process or an isolated program. | `vol_donnees.rs`, `reponse.rs` | Handled in phase 6: durations and reminders (PR 6.4, table above). |
