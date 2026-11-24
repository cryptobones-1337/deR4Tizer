# Phase 6: response policy applied in the code

Opened on 2026-11-01, at the end of phase 4, on the maintainer's explicit agreement (answer « Oui, selon le dossier » (Yes, according to the file),
`CLAUDE.md`, section 5, point 4). This document sets the scope, the split and the decisions of the phase. Written before the code; the phase has since been delivered and validated by the
maintainer on 2026-11-03 (`CLAUDE.md`, section 5, point 4): the state of each item is the one in the matrix
(`docs/roadmap/capability-matrix.md`).

## Need

A response action cuts off or modifies something on a computer with no IT person on site. Four gaps:

1. **Level 3 overflows**: with the "restricted lists" setting, automatic blocking extends to FireHOL level 1 and
   to ThreatView, which the policy does not allow.
2. **Identity is not revalidated**: between the decision and the action, a reused PID can designate another program.
3. **Nothing bounds repetition**: an address unblocked by hand is blocked again as soon as a connection to it reappears, and a program
   resumed can be suspended again without limit.
4. **Nothing has a deadline**: a suspended process, an isolated program or the panic mode stay so without anyone
   being reminded.

## What the phase does not do

- no new action, no new automatic trigger, no widening of level 3;
- no automatic termination of a process, no automatic quarantine;
- no change to the logic of the IDS, the DPI or the NDR, which stayed frozen during phase 6 (unfrozen since: IDS and NDR on 2026-11-16, DPI on 2026-11-18): the policy applies downstream, in
  the monitor;
- nothing about Microsoft Defender, nor anything from phases 7 to 9.

## Split

Each PR starts from an up-to-date `main`, without stacking, with its review, its audit and its full pass in a VM before the
merge. Those that touch the same file go one after the other.

| PR | Content |
|---|---|
| 6.0 | This document, the "Planned in phase 6" section of the policy, the "prévu" rows of the matrix |
| 6.1 | Level 3 restricted by the identity of the source: Spamhaus DROP and Feodo Tracker only, whatever the setting |
| 6.2 | Single decision point (`politique.rs`) and guard against loops; all automatic triggers go through it |
| 6.3 | Identity revalidated through a handle, action on that same handle; new command fields; complete confirmation |
| 6.4 | `reponses.json` register, deadlines, reminders (`REP-001`) |
| 6.4b | Quarantine and manual blocking in the register; grouped reminders; fixes from the review and the audit of #115 |
| 6.5 | Transactional panic mode, effective state, PowerShell outside the lock; first, two leftovers from the audit of #116 (`tout_debloquer`, in-memory list) |
| 6.6 | Isolation on the final path, read through a handle; first, two remarks from #117 (unreadable profile, panic command in progress) |
| 6.7a | Prerequisites from #118 on the service side: critical binary name refused, parent folders read without following a link, REP-003 at the first reading |
| 6.7b | Interface: "Ongoing responses" page, scope and rollback of the panic mode, effective state in the header, real path in the isolation confirmation (S118-02) |
| 6.8 | Prerequisites from #119 and #120: link tags through the "name surrogate" bit, unverifiable isolation stated (REP-004), "Resume" refused only on a time read and different, unreadable register distinguished from an empty register |
| 6.9 | Prerequisites from #116 and #117: reminders capped per kind and per duration (S116-01), reading of the firewall with a deadline on the "sante" thread (S117-02) |
| 6.10 | Silent firewall stated after 5 min (REP-003, "Alert"); removal of the panic mode with a deadline during uninstallation (D6-7; the other firewall calls of the uninstallation stay without deadline) |
| 6.11 | Uninstallation: removal of the firewall rules with a deadline (review of #123, D1); matrix: "incertaine" state displayed since 6.7b |
| 6.12 | Service rule PowerShell processes (API, capture) tracked and waited for at stop; uninstallation report with a unique name, without overwriting or following a link, with the code and the remaining rules |
| 6.13 | Isolation: path walked down element by element through handles, without race or traversed link; name of a program shipped with Windows refused outside the Windows folder |
| 6.14 | Resuming an interpreter or a Windows program: no 7-day exception; confirmations that state the 7-day effect and the scope of the signature; full register: recent automatic suspensions removed first, stated by REP-002 |
| 6.15 | Threat lists: Feodo Tracker as exact addresses; bounded IPv6 coverage (2^48 /64 networks, one /16), list rejected entirely beyond that |

Each PR brings the recovery procedure for its actions, written and checked in a VM; one that is only read is
declared "non exécutée". The planned procedures are in `docs/reponse/politique.md`.

The `REP-*` sheets go into `docs/detection/regles.md` with their entry in the registry (`regles.rs`), their code and their
tests, in the PR that brings them: the registry test requires the sheets and the registry to agree.

## Decisions

Explicit agreement of the maintainer on 2026-11-01 on the recommendations of the design file, for PRs 6.1 to 6.7
as long as they stay within it. The question asked recalled: restricted lists as alert only, identity revalidated before
each action, human decision takes priority for 7 days, never an automatic resume. It also recalled a cap of 3
suspensions per hour, later removed by the maintainer (see below).

| # | Decision | Chosen |
|---|---|---|
| D6-1 | Policy and IPS, without unfreezing the IDS | Downstream, in the monitor, on the blocking queue; `ids.rs` untouched. |
| D6-2 | Identity of a process | PID and creation time, revalidated and applied on one same handle. The path is shown, not compared (maintainer's decision, 2026-11-01, after the audit of PR 6.3: a program that renames itself escaped it). The SHA-256 hash of the executable is required only for the "human decision" list. |
| D6-3 | Deadlines | See the policy: they are reminder appointments, never a lifting for suspension, isolation and panic mode. |
| D6-4 | Duration of a block by the IPS | 24 h, instead of the inherited 7 days. |
| D6-5 | Thresholds of the guard | 3 actions per target and per 24 h (for a suspension: signed program in Program Files only, maintainer's decision, 2026-11-01); 30 blocks by the lists per hour; 50 addresses per hour for the IPS, separately; human decision takes priority for 7 days. No setting in the interface. The cap of 3 suspensions per hour from the file is removed (maintainer's decision, 2026-11-01). |
| D6-6 | Reminder without configured escalation | Local only, and the Health page says so. Without a channel, nobody is notified: written limit. |
| D6-7 | Failure of `--nettoyer` at uninstallation | Uninstallation is never blocked; a report is written and checked. |
| D6-8 | New dependency | None. |
| D6-9 | Automatic termination of a process | Outside level 3, as today. |
| D6-10 | Suspension on decoy, folder protection failed | Kept, as today: it depends on no file of the data folder. Only the actions fed by those files are refused. |

## Suspension cap removed

The file provided for at most 3 automatic suspensions per hour. The audit of PR 6.2 showed that a standard account
could use it up with 3 throwaway programs, then launch a ransomware that would not be suspended. The maintainer decided
to remove it on 2026-11-01. The audit then showed that the threshold of 3 per program in 24 h allowed the same attack,
through a program launched four times or through three hits via `powershell.exe`. The maintainer limited it the same day to
signed programs installed in Program Files, interpreters excluded. Everything else is always suspended, and only a
resume by an administrator stops a loop.

## Proof

GitHub Actions was then disabled (from 2026-10-22 to 2026-11-17). For phase 6, the local VM proof stands in for GitHub CI, following the same
answer of the maintainer, which also covered this proof regime, until he writes it into `CLAUDE.md`. Nothing
changes for distribution: green GitHub CI, successful lot 3d, signed binaries and independent review remain required.

The long deadlines (2 h, 24 h, 7 days) will only be checked in the lab: no test setting in the shipped binary.
Resuming through Windows Resource Monitor is described, not tested, and the case of a process suspended without
register is not reproduced. The scenarios will declare it "non exécuté".

## To be written into `CLAUDE.md` by the maintainer

Note of 2026-11-19: `CLAUDE.md` has since quoted the opening and the validation of phase 6 in the maintainer's words
(section 5, point 4) and says that the local VM proof stands in for GitHub CI "as for phases 3, 4 and 6"
(point 5). Text proposed at the time, under section 5, point 4:

- Opening: on 2026-11-01, at the end of phase 4, explicit agreement of the maintainer to code the phase according to the design
  file (answer « Oui, selon le dossier » (Yes, according to the file)). Decisions of the phase: `docs/roadmap/phase6.md`.
- As for phases 3 and 4, the local VM proof (section 4, "Temporary exception") stands in for GitHub CI for
  the PRs of phase 6. Nothing changes for distribution.
