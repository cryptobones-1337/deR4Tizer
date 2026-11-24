# deR4Tizer: instructions for Claude Code

This file frames all of Claude Code's work on this repository. It takes precedence over any other implicit request. When in doubt, stop and ask.

## 1. Mission

deR4Tizer is a defence-in-depth layer for Windows, complementary to Microsoft Defender, intended for small organisations without a SOC (very small businesses, shops, small municipalities) and for individuals. Everything runs locally; critical alerts go to the service provider or the designated contact. Apart from the downloads already documented (threat lists, JA3, GeoIP, LOLDrivers, update) and the alerts, no user data goes to a third party, except through a feature the user turns on themselves and that says so (phases 7 and 9, section 5).

It is not an antivirus, nor a replacement for Defender, nor an enterprise EDR. A capability exists only if it is demonstrated by reproducible tests. Code that compiles proves nothing.

## 2. Non-negotiable rules

1. **Feature freeze.** No new capability, no new module, no new package, no new option until the work queue in section 5 is finished, validated by the review (section 4) and by cryptobones-1337. Only exceptions: the « Interface and installation assistant » phase, phases 7, 8 and 9 and the « PowerShell script blocks (4104) » phase (section 5), opened in writing by the maintainer, each one once the phases before it have been validated by the review and by cryptobones-1337 (for the 4104 phase, its own start condition written in section 5), and for its own content only. Fix, test, document: yes. Add: no. If a fix seems to require a new function, stop and ask.
   Static analysis tooling in CI, permitted during the freeze (maintainer agreement of 2026-11-23): to the question « Gel des fonctionnalités (CLAUDE.md, règle 1) : confirmes-tu que l'outillage d'analyse statique en CI (cargo audit, cargo deny, clippy bloquant, CodeQL, chaîne Rust figée et --locked) est permis pendant le gel ? » (Feature freeze (CLAUDE.md, rule 1): do you confirm that static analysis tooling in CI (cargo audit, cargo deny, blocking clippy, CodeQL, pinned Rust toolchain and --locked) is permitted during the freeze?), the answer: « Oui, permis » (Yes, permitted). This tooling adds no capability to the product, no module and no dependency to the binary; none of these checks is an independent review in the sense of section 4.
2. **Defender is untouchable.** Never disable, weaken, stop or exclude anything in Microsoft Defender or in the Windows protections, not even to make a test pass.
3. **Fail closed** for everything that touches security: signature verification, authorisation, secret generation, setting permissions (ACL), update validation. If the security operation fails, the dependent operation does not take place, and the failure is logged and visible in the interface.
4. **No panic in the service.** The service is compiled with `panic = "abort"` and runs as SYSTEM: a panic stops it. No `[a..b]` on a `&str` that comes from outside (use `get()` or work on bytes), no `unwrap()` on external data. Every new or modified parser goes through `torturer` or `torturer_texte` in `service-rs/src/tests.rs`.
5. **No allowlist by file name.** Every trust decision about a program rests on the full path AND the exact signer (`vol_donnees::editeur_correspond`), or on `natif::binaire_windows`. Never on the name alone, never on a substring of the signer.
6. **Files in the data folder = untrusted data** as long as their owner and their permissions have not been checked (see lot 1).
7. **No release.** Never create a `v*` tag or a GitHub release, nor run `publication.yml`. Never push directly to `main` if branch protection is active: go through a pull request.
8. **No invented results.** Never state that a test passed, that Windows compatibility is verified or that a performance is measured without having done it. A test that cannot be run here is declared as such, with the reason.
9. **No destructive test on the host machine.** No real malware. Scenarios are benign and reproducible, in CI or in a VM.
10. **Small changes.** One lot = one coherent, reviewable commit (or pull request). No module rewrite when a targeted fix is enough. No new dependency without a justification (maintenance, licence, necessity) written in the commit message.
11. **No secret** in logs, error messages, the command line or files readable by the authorised accounts.
12. **Language.** Code, code comments, messages and commit messages in French, like the rest of the repository. Documentation (README, `docs/`, CHANGELOG, capability matrix, threat model, all `.md` files) in English since 2026-11-24 (maintainer decision, decision log outside the repository: « Oui, tout en anglais » (Yes, everything in English)). Before that date, the exception was (maintainer decision of 2026-11-18, confirmed on 2026-11-19 with these words: « C'est moi qui ai demandé anglais seul le 18 du 11 » (I am the one who asked for English only on 18/11)): the README and the presentation page (GitHub Pages) in English, for international reach. The application interface remains bilingual French/English.
13. **Personal data.** No personal data in the repository or on GitHub (commits, PRs, comments, screenshots),
    checked by the PII guard. Only exception, decided by the maintainer on 2026-11-19: his name, shown on his GitHub
    profile because he needs it for the signing certificate in his name (Certum), and picked up by GitHub as author
    or committer of the merges made on GitHub (since 2026-11-12); the history is not rewritten. With these words:
    « je dois laisser mon nom sur le profil GitHub. Donc ça, tu peux l'ajouter. C'est le seul P2I qui sera conservé
    parce que j'en ai besoin pour récupérer mon certificat signé à mon nom » (I have to leave my name on the GitHub
    profile. So that, you can add it. It is the only PII that will be kept because I need it to get my certificate
    signed in my name) and « Réécrire l'historique. Non, c'est pas nécessaire. » (Rewrite the history. No, it is not
    necessary.) Commits written by Claude Code stay under the `cryptobones-1337` identity; the name also appears in
    the signature of the binaries (decision of 2026-11-11), never in the files of the repository.

## 3. Architecture landmarks

- `service-rs/`: Windows service in Rust, SYSTEM account. Entry point `main.rs`, core `moniteur.rs`, commands received by `canal.rs` (pipe `\\.\pipe\deR4Tizer`), shared files `commun.rs`, update `maj.rs`, protection of the data folder `protection.rs`.
- `src/`: C# interface (.NET Framework 4.8), without admin rights; actions go through an elevated instance (`--commande-fichier`) that shows the command in plain text before sending it.
- `installeur/deR4Tizer.wxs` + `construire-msi.ps1`: MSI package (WiX 3.14).
- `C:\ProgramData\deR4Tizer`: state and data; `secrets\` reserved to SYSTEM and to administrators.
- Tests: `cargo test --release` in `service-rs`; CI in `.github/workflows/ci.yml` (runner `windows-latest`, administrator and disposable).

## 4. Working protocol

### Before each lot

1. Read the code concerned, its callers and its tests. Do not rely on the README.
2. Write a short plan in the conversation: files touched, current behaviour, target behaviour, tests to add, regression risks.
3. If the lot changes a privileged behaviour, the trust model of updates, or an irreversible action: wait for explicit agreement.

### During

- First write the test that fails on the current code when possible, then the fix. For every test
  added or modified, before the PR: the test fails when the fix is removed (or under a mutation of the fix),
  then passes when it is put back, each variant recompiled in its own build folder. A test that has
  never failed does not prove that it catches the defect.
- No « fixed », « passed » or « green » claim without fresh output from the command that proves it, on the
  announced commit and tree; an agent's report is not proof: reread the diff or the table.
- A cause remains a hypothesis, and is stated as such, until a test has confirmed it; record the state (log,
  registry, values) before fixing, and before any snapshot restore that would erase it (blocked pass included).
- A check that had nothing to verify (zero events, zero files, unreadable input) is not a success:
  provide a witness that must be kept and a witness that must be rejected, and make an unreadable input fail.
- Run `cargo test --release` and the interface build when the environment allows it.
- Reread your own diff: regressions, off-topic changes, secrets, string slicing.

### After each lot

Report in the conversation AND in the commit message (in French, like commit messages):

```
Lot N : <titre>

Corrigé
- <constat> : <ce qui a changé> (<fichier>:<fonction>)

Tests
- Ajoutés : <nom du test> : <ce qu'il prouve>
- Exécutés : <commande> : <résultat réel>
- Non exécutés : <test> : <raison>

Critères d'acceptation
- [x] / [ ] <critère repris de la section 5>

Risques restants
- <limite connue, ou « aucun identifié »>
```

Then stop: each PR is reviewed before the next lot starts.

### Review of PRs (since 2026-10-24)

By decision of cryptobones-1337, PRs are reviewed by a Claude Code review agent, instead of the
external reviewer:
1. Without the history of the session that wrote the code, but on an instruction written by it; no write to
   the repository or to GitHub (no push, no merge, no comment), check merges being done in a temporary
   clone; on the PR heads read on GitHub.
2. Checks: integrated tree reproduced and equal to the tree of the proof; no stacking; merge without conflict;
   `cargo test --release` (MSVC) and, for each fix, a test that fails without it; documentation and rules of
   this file; personal data; accurate description.
3. Verdict per PR: « Go » or « Pas go » (No go), with reasons; without proof of a pass on the announced tree (green CI since
   2026-11-19; before that, test VM or Windows Sandbox, « Temporary exception » section), « Go sous réserve du passage » (Go subject to the pass).
4. The verdict replaces neither this pass nor the merge decision, which remains with cryptobones-1337.

Limit: the agent is the same model as the author of the changes; their blind spots may coincide. This
review is therefore not an independent review, and nothing may present it as such (README, matrix,
publications).

### Temporary exception: GitHub Actions disabled on the repository (from 2026-10-22 to 2026-11-17)

End of the exception: GitHub CI was turned back on on 2026-11-17, by the maintainer's choice (« Rallumer la CI » (Turn the CI back on), to
merge PR #190). Since 2026-11-19, by his answer « CI seule suffit » (CI alone is enough) to the question « la preuve en VM
reste-t-elle exigée en plus de la CI pour fusionner une PR de code ? » (is the VM proof still required in addition to the CI to merge a code PR?): green CI (`windows`,
`integration-installation`, `integration-quarantaine`, `integration-maj`) is the merge proof for a code PR;
the test VM remains for what the CI does not cover (keyboard tests in an open session, lot 3d with Defender active,
Kali campaign). Point 5 below: required checks are not yet restored on `main` (checked on
2026-11-19: branch without protection; setting reserved to the maintainer, section 6). What follows describes the regime of
the exception, kept for the record and as a fallback if the CI becomes unavailable again.

As long as GitHub Actions is disabled, the required CI is replaced by a local proof, with the agreement of cryptobones-1337:
1. The reviewed PRs are merged, in the set order, onto a local integration branch started from main.
2. On that commit: cargo test --release (MSVC), MSI built from that commit, scenarios 3a, 3b and 3c in the Hyper-V test VM, restored to its « propre » (clean) snapshot before and after each scenario (tests/vm/lancer.ps1; snapshot taken with Microsoft Defender active and without exclusion: its state is recorded at each scenario, and is required to be « fully active » only by lot 3d, tests/vm/lot3d.ps1; standard account logged on at the console with -SessionStandard, otherwise the snapshot's session). Windows Sandbox (tests/bac-a-sable/lancer.ps1) remains a fallback, flagged as such in the proof. Full pass: tests/bac-a-sable/passage-complet.ps1. No ÉCHOUÉ (FAILED); only the NON EXÉCUTÉ (NOT RUN) results already known and justified. A pass in the VM is not, on its own, a success of lot 3d.
   Every pass is watched by a watchdog (tests/bac-a-sable/vigie.ps1, one check per minute) that reports each finished scenario, any blockage (sandbox never opened or closed without a result, VM stopped, no working file of the scenario written for 30 minutes) and the end. A blocked pass is stopped, cleaned up (sandbox closed, test keys erased, VM restored to its snapshot) and restarted; it never counts as proof.
   Exemption (maintainer, 2026-10-25: « No vm for documentation », in reply to the proposal « exempt PRs that touch only *.md files outside src/ and service-rs/ »): a PR that changes only Markdown files (`*.md`) outside `src/` and `service-rs/` has no VM pass. Review and the personal data check remain mandatory; the verdict is « Go » (without a pass reservation); the proof in a comment says so (« documentation seule : passage non requis » (documentation only: pass not required), list of the modified files, tree reviewed). Tree barrier: the reviewed commit stands in for the tested commit (`git diff <reviewed commit> main` empty after the merge). A PR that also touches another file, even a test script or a .md under `src/` or `service-rs/`, has its pass. A documentation PR merged between the pass of a code PR and its merge changes main: it goes before the pass, or the pass is redone.
   Acceleration (maintainer, 2026-10-25, with these words: « I want all 6 », then « Sorry not 6 », in reply to six numbered proposals; the sixth, a second test VM, is therefore set aside):
   - (1) before any review request, the author applies the reviewer's list himself: one mutation per changed line of code, each compiled separately, and each documentation sentence compared with the proof;
   - (2) a single VM pass can cover several PRs that do not modify the same files, merged in order onto the integration branch; if it fails, none is merged;
   - (3) the cycle measurement scenario (`tests/vm/mesure.ps1`) is run only for a PR that touches the monitoring cycle (`moniteur.rs` or a module called by the cycle);
   - (4) the design file of the following phases (4, 6, 7) can be prepared before the validation of the current phase, as documents only, kept outside the repository: no code of a phase before it starts (conditions of section 5 and of rule 1 of section 2); this is an exception, for documents only, to « one phase at a time » (section 5);
   - (5) during the back-and-forth of a PR, a pass reduced to the relevant scenarios (`tests/bac-a-sable/scenarios-concernes.ps1`) is enough; the full pass remains required on the integrated tree, before each merge.
3. Proof in a comment on each PR concerned: hash of the tested commit and tree, SHA-256 of the MSI, Windows version, full tables.
4. The PRs are merged in the same order, without modification after the test; then, git diff <tested commit> main must be empty, otherwise a new test.
5. When GitHub Actions returns: required checks restored by cryptobones-1337, full CI rerun on main, every failure fixed before any other work.

No distribution as long as GitHub CI is not green on main, lot 3d has not succeeded in a VM on the distributed and signed version (maintainer, 2026-11-19: « A5 lot 3D, il fallait bien rejouer sur la version distribuée et signée » (A5 lot 3D, it did have to be replayed on the distributed and signed version)), the binaries are not signed and an independent review (a person or organisation other than Claude) has not been done.
Assessment at the release of v4.3 (2026-11-23): green CI on main at the tag commit (run 45072779823, 46243f7), lot 3d succeeded in a VM on
the published signed MSI, binaries and MSI signed (Certum). Three conditions not met, deviations decided by the maintainer:
- independent review: the reviews of 2026-11-17 and 2026-11-21 were done by another Claude agent (Claude
  Fable), without the development history; they do not meet the condition above (deviation recorded on
  2026-11-23, the condition remains in full). The audit by passes of 2026-11-23, done by Claude, does not meet it either;
- tests D4-1 (section 5, end of phase 7 campaign);
- test of revocation with the real expired certificate and a timestamped signature (`docs/security/threat-model.md`,
  « Compte GitHub compromis » (Compromised GitHub account)): not done (deviation recorded on 2026-11-23).

## 5. Work queue (in this order)

### Lot 1: ownership and permissions of the data folder (blocking, privilege escalation)

**Finding:** the MSI does not create `C:\ProgramData\deR4Tizer`; the service creates it with the permissions inherited from `ProgramData` (`Users` can create files and folders in it); `protection.rs` sets the permissions only after a session is opened and never changes the owner. A standard account that creates the folder (or `maj\`) before the service remains its owner, and can therefore always rewrite its permissions. It can then replace `maj\<version>\deR4Tizer.msi` between the verification and `msiexec` (SYSTEM), or `maj\sauvegarde\*.exe` copied by the rollback into `Program Files`.

**To do:**

- MSI: create the folder (`CreateFolder` + `util:PermissionEx`), SYSTEM and Administrators with full control, without inheritance.
- Service, at start-up and before any read of a data file: force the Administrators owner (`S-1-5-32-544`) on the folder and all its contents, set the protected permissions (SYSTEM, Administrators, authorised readers with read access), without waiting for an open session. Check the result; on failure, log, report in the interface and load no configuration or secret file (safe default values).
- `commun::lire` (and the reading of secrets): reject a file whose owner is neither SYSTEM nor Administrators. Pure decision, testable separately from the Windows call.
- `maj.rs`: prepare the installation in a working folder reserved to SYSTEM under `%ProgramFiles%\deR4Tizer` (created by the service, owner checked); copy the verified files there; recheck hash and signature in that folder; also keep the rollback backup there.
- `api.rs` and `notifications.rs`: create token and secrets with their permissions at creation time (not a write followed by `icacls`), and treat a failure of `icacls` as a failure.

**Acceptance criteria:**

- After MSI installation: Administrators owner, no write permission for `Users`, `Authenticated Users` or the logged-on account (checked with `Get-Acl`).
- A standard account cannot create any file or folder in `C:\ProgramData\deR4Tizer`, neither before nor after the first logon.
- Folder pre-created by a standard account before installation: after installation, Administrators owner and no more write access for that account.
- A configuration file owned by a standard account is ignored and reported.
- Unit tests of the « acceptable owner » decision; CI integration test (lot 3) covering the three scenarios.

### Lot 1 bis: quarantine and set-aside without data loss

**Finding:** `protection.rs:trier` deletes an item when setting it aside fails; and `reponse.rs:mettre_en_quarantaine` moves the file with `fs::rename`, which keeps the original owner (the user's account). At the next start-up, the quarantined file is therefore set aside (restore impossible) or deleted (loss of the file of a false positive).

**To do:**

- `trier`: never delete; move impossible = item intact, failure logged, start-up fails closed.
- Quarantine: copy to a file created by the service with its permissions (SYSTEM owner), SHA-256 recorded in `quarantaine.json`, then deletion of the original; hash checked at restore.
- Migration: files in `quarantaine\` present in `quarantaine.json` copied again this way at start-up, not set aside.

**Criteria:** tests « quarantine, restart, restore », « old quarantined file migrated without loss », « move impossible: intact and fail closed », « creation of ecartes impossible: intact and fail closed ». Scenario « quarantine, restart, restore » added to lot 3.

### Lot 1 ter: SYSTEM file operations on user paths

**Finding:** several operations of the service, as SYSTEM, act on paths chosen or controlled by
the user, with a check and then an operation by path. A junction or a link placed between the two
redirects the operation to a system folder (privilege escalation):
- `reponse.rs`, restore: write of the file and of its Internet mark to `chemin_origine`;
- `reponse.rs`, quarantine: read then deletion of the original (500 ms pause between stopping
  the processes and the copy);
- `reponse.rs`, resumption at start-up: read of the hash of `chemin_origine` at each start-up.

**To do:**

- Quarantine: open the original only once by handle without following links
  (`FILE_FLAG_OPEN_REPARSE_POINT`), check its final path (`GetFinalPathNameByHandle`) against the expected
  path, read the content and the Internet mark, then delete through that same handle (`FileDispositionInfo`);
  no operation by path after the check.
- Restore: write the file and its mark by borrowing the token of the user who owns the
  location (open session), so that Windows permissions apply to that user and not to SYSTEM; if
  no session of that user is open, refuse and offer a restore into a folder created
  by the service.
- Resumption at start-up: read the hash of the original by handle without following links, with a check
  of the final path; a path element that is a link = original « different » (the copy is kept).
- Tooling: local build aligned with the CI (MSVC toolchain) in `compiler-rs.ps1` and the README; the
  tests on a machine are done with the CI artefact, never with a local GNU build.

**Acceptance criteria:**

- Test « junction placed before restore »: nothing is written outside the original folder.
- Test « junction placed during quarantine »: nothing is read or deleted outside the targeted file.
- Test « link in the original path at start-up »: the copy is kept, nothing is read outside the path.
- Restore without a session of the user: refused or directed to the service folder, never written
  as SYSTEM at the original location.
- Corresponding scenarios added to lot 3.

### Lot 2: update, rollback through the manifest, and transaction

**Finding:** the version is read only from the manifest, which is not signed. A forged manifest announcing « 99.0 » can get an old version installed that is signed with the right key but vulnerable. Since v4.3, the MSI carries `AllowDowngrades="yes"` (for the rollback): the refusal to install an older version, the only remaining barrier, has gone. Lot 2 must read the version from the signed artefact before any installation, or restore that refusal and do the rollback in another way.

**To do:**

- Read the real version from the artefact after signature verification: version resource of the executable, `ProductVersion` of the MSI. Require: artefact version = manifest version, and strictly newer than the installed version. Otherwise refuse.
- Strict manifest: known fields only, no duplicate file, complete expected list (MSI mandatory, consistent executables), bounded size.
- Health after installation: send the command `{"Action":"verification"}` through the pipe and require a valid JSON response from the service, not only the existence of the pipe. On failure: reinstall the previous MSI kept in the working folder (not a copy of executables that leaves the Windows Installer database inconsistent).
- Pinned keys: list (current key and next key) in `DER4TIZER_CLES_SIGNATURE`, each entry of 64 hexadecimal characters; the interface shows « pinned key » only if at least one entry is valid.

**Acceptance criteria:** unit tests on the installation decision covering: artefact version ≠ manifest, equal or older version, missing file, duplicate file, unexpected file, wrong hash, missing signature, unexpected key, empty or malformed key list. Rollback described and tested at least by simulation (service that does not respond).

### Lot 3: integration CI and release chain

- New CI job on `windows-latest` that, with the built MSI: installs; checks the service (account, start-up, recovery) and the folder permissions (lot 1); creates a standard local account and checks from that account (`Start-Process -Credential`) that the pipe refuses its commands and that it cannot write anything in the data folder; pre-created folder scenario, including with files with an empty DACL (`D:P`, owner unreadable for SYSTEM) such as `config.json`, `lecteurs.json` or `apprentissage.json`: they must be set aside and never loaded; trapped file held open (without delete sharing) during the start-up of the service, then restart: never loaded, neither at the first nor at the second start-up; quarantine of a file, restart of the service, restore: file restored identically; lot 1 ter with the real service: junction placed before a restore (nothing written outside the original folder), junction placed during a quarantine (nothing read or deleted outside the targeted file), link in the original path at start-up (copy kept), restore without a session of the owner (refused, fallback to the service folder, never a write as SYSTEM at the original location), restore with a session (file created under the user's identity); upgrade from the MSI of the previous version; uninstallation with and without `GARDER_DONNEES=1`.
- Run scenario with Microsoft Defender active, with the MSVC artefact of the CI: installation,
  quarantine of a benign test file, restart, restore. No detection.
  As long as this scenario has not succeeded, no distribution, not even to a tester.
- WiX: check the SHA-256 hash of `wix314-binaries.zip` (value pinned in the workflow) in `ci.yml` and `publication.yml`.
- `publication.yml`: separate build (without secret) and signing (receives only the artefacts, `publication` environment). No build and no dependency script in the job that holds the certificate.

**Criterion:** all these checks run on every pull request and fail loudly.

### Lot 4: documented inventory (phase 0, one day at most)

Create from the code and the reviews already done, without a full re-audit:

- `docs/roadmap/capability-matrix.md`: each capability with a state among « planned » (« prévu »), « implemented, not verified » (« implémenté non vérifié »), « lab-tested » (« testé en labo »), « validated on Windows » (« validé sur Windows »), « production-ready » (« prêt pour la production »); source files; Windows prerequisites; existing tests; limits. The IDS, the DPI and the NDR are classified as experimental. Known limit to record there: when the protection of the data folder fails, the critical alert stays local (the forwarding secrets are ignored), the service provider is not notified. Residual risk to record there: the MSI accepts an older version (`AllowDowngrades`, needed for the rollback); the refusal of an older version is ensured by the service, on the version read from the signed package, and an administrator can always install an older version by hand. Limit to record there: the syslog export (`export.rs`) is sent in plain text (UDP or TCP, without TLS); to be kept to a trusted local network.
- `docs/security/threat-model.md`: privilege boundaries (SYSTEM service, interface, pipe, API, update, data folder, network capture), attackers considered (local standard account, LAN device, compromised GitHub account, corrupted threat list), measures and residual risks.
- `docs/architecture/current-state.md` and `docs/testing/baseline.md` (build and test commands actually run, results).
- `docs/reponse/politique.md`: response levels 0 to 3. Only level 3 (automatic) actions allowed: blocking of the Spamhaus DROP and Feodo Tracker IPs, suspension of the program that touches a decoy. Everything else, IPS included, at level 2 at most (disabled by default or confirmation).
- README aligned with the matrix: no claim stronger than the real state.

### Lot 5: non-blocking fixes from the reviews

- `apprentissage.rs`, `editeur()`: cache key = path + modification date.
- `api.rs`, `nouveau_jeton()`: the result of `BCryptGenRandom` is ignored; on failure, a null token would be accepted. Fail closed: no API without a valid token.
- `api.rs`, `/api/v1/sante`: no longer return the machine name without a token.
- `canal.rs`: maximum read time for a command (a silent admin client blocks the whole channel today) and maximum size already bounded, to be tested.
- Document in the README that `msiexec /fa` (repair) by a standard account briefly stops and restarts the service.
- Reads of the data folder outside `commun::lire_fichier` (menaces.rs, ids.rs `regles\`, hygiene.rs
  `loldrivers.json`, dpi.rs JA3, siem.rs): owner checked everywhere; when failing closed, no automatic
  response fed by these files (automatic blocking, IPS).
- `commun::lisible_en_echec`: remove `dns.json`.
- `natif::avec_privilege_restauration`: if `RevertToSelf` fails, stop the service.
- canal.rs: pipe occupied by another process at start-up (squatting): local critical alert
  with the PID and the path of the process that holds it, rather than a mere log line.

### Next (after validation of lots 1 to 5, one phase at a time, with agreement)

1. Full phase 1: authorisation checked per command, validation of every field received, rate and concurrency limits, tests of malformed, truncated, silent messages.
   Architecture, in the same phase (to be done after the merge of the open PRs, which touch these files):
   - Precondition: measurement of the monitoring cycle (duration of each step, PowerShell processes launched during the cycle, time spent under the lock). Without these figures, neither splitting of `Moniteur` nor optimisation.
   - `Moniteur` (moniteur.rs), once the measurement is done and only where it justifies it: the long actions (quarantine, restore, baseline, panic) done outside the `Arc<Mutex<Moniteur>>` lock, taken only to record the result: a quarantine must no longer blind the monitoring, nor a slow cycle block the interface; `executer()` (28 commands in a single `match`) split into one handler per domain (response, blocks, configuration, update, protection); `passage()` (3 s cycle) split into steps, each with its own timer.
   - No splitting of `natif.rs` for its own sake: mere code moves, in conflict with all the open PRs. Only if a measurement or a fix justifies it, at the time of that measurement or fix.

   Validation by the maintainer, on 2026-10-25, with these words: « Yes: once the remaining Phase 1 fixes are merged with a clean VM pass, I validate Phase 1, and Phase 3 can open with the local VM proof replacing GitHub CI. Record it in CLAUDE.md. »
   - Last fixes of phase 1, those that had been presented to him:
     - #64: test tooling;
     - #65: alert queues resumed when the service stops;
     - text of the elevated assistant's confirmations passed through `Visible()` everywhere;
     - confirmation window that wraps lines and scrolls, and shows the registrable domain (S60-06/07).
   - Once these fixes are merged, each reviewed and covered by a VM pass without ÉCHOUÉ (FAILED) on the integrated tree, phase 1 is validated by cryptobones-1337.
   - Validation confirmed by the maintainer on 2026-11-19, with these words: « Phase 1 est validée. » (Phase 1 is validated.)
   - Phase 3 then opens. For its opening and for its PRs, the local VM proof (section 4, « Temporary exception ») stands in for GitHub CI.
   - On 2026-10-25, the maintainer lifted, for the opening of phase 3, the lot 3d condition, with these words: « Phase 3 can open ». Lot 3d was then « not run » in `docs/roadmap/capability-matrix.md` (succeeded in a VM since, 12 out of 12 in the green full passes of November 2026), whereas this heading sets the condition « after validation of lots 1 to 5 ». Phase 3 therefore opens at the validation of phase 1 (previous bullet), without waiting for lot 3d.
   - Nothing changes for distribution: the rule of section 4 remains in full (green GitHub CI, lot 3d succeeded, signed binaries, independent review).
2. Phase 3: a versioned event model; each detection rule with an identifier, a justification, the required telemetry, a positive test, a negative test, the expected false positives. Distinguish « nothing suspicious » from « collection unavailable ».
   Validated by the maintainer on 2026-11-19, with these words: « Phase 3 validée. » (Phase 3 validated.)
3. Phase 4: incident life cycle, reconstructable timeline, visible collector health.
   Validated by the maintainer on 2026-11-19, by his answer « Oui, validée » (Yes, validated) to the question « Phase 4 (incidents,
   chronologie, santé) : tu n'en as pas parlé. Est-elle validée ? » (Phase 4 (incidents, timeline, health): you have not mentioned it. Is it validated?).
   Health of the interface, in the same phase: the interface (deR4Tizer.exe) runs under the user's account, who can stop it, like any program launched under that account. The service (SYSTEM) detects that it has disappeared from an open session and, as a choice still to be made, restarts it in that session or raises an alert forwarded to the service provider. Local notifications no longer appear without it; detection and forwarding by the service continue.
4. Phase 6: application of `docs/reponse/politique.md` in the code, revalidation of the identity of the process just before each action, protection against action loops. Each response action has a maximum duration and a tested recovery procedure; when it expires, never an automatic resumption of a suspended process nor an automatic lifting of an isolation: the alert is sent again to the service provider, recovery is a human action.
   Validated by the maintainer on 2026-11-03, with these words: « Je valide » (I validate), in reply to the question « Valides-tu la phase 6 :
   « oui » ou « pas encore » ? » (Do you validate phase 6: « yes » or « not yet »?), once its PRs were merged (#108 to #128, except #111, fixes included; each
   reviewed; those that touch the code proven in a VM without failure, #117 in two passes). The rest of the inventory of
   phase 6 audit findings is kept for the pre-distribution step.
5. « Interface and installation assistant » phase, before phase 7. Opened by the maintainer on 2026-11-03, with these
   words: « fais la refonte avant la phase 7 » (do the redesign before phase 7). Starts once the phase 6 fixes are merged and this point
   recorded; phase 7 starts once this phase is validated by the review and by cryptobones-1337. Decisions,
   breakdown and safeguards: `docs/roadmap/interface.md`. As for phases 3, 4 and 6, the local VM proof stands
   in for GitHub CI for its PRs; nothing changes for distribution. Recorded on 2026-11-03 with the authorisation of the
   maintainer (« Ok pour modifier Claude. Md je t'autorise » (OK to modify Claude.md, I authorise you)).
   Phase 7 started before the validation of this phase (and before that of phases 1, 3 and 4, also validated
   on 2026-11-19), on the maintainer's instruction of 2026-11-11: « commence la phase 7 sans poser la question » (start phase 7 without asking the question)
   (decision log, outside the repository), interpreted as: finish the MSI U8 and the B1 switchover, already under way, then
   open phase 7 without asking for the validation of the Interface phase. Validated afterwards by the maintainer on 2026-11-19, with these words: « Tu as mon accord pour la
   validation. La phase interface maintenant, vu qu'elle a été revue par un externe » (You have my agreement for the validation. The interface phase now, since it has been reviewed by an outsider), then his answer « Validée
   maintenant » (Validated now). Remaining to do, after this validation: B3, B4 and U8b (`docs/roadmap/interface.md`).
6. Phase 7: filtering by domain name (DNS, ads, tracking). Opened by the maintainer on 2026-10-25, with these
   words: « Open a phase for the feature > do it like your example », the proposed example being « Phase 7: domain-name
   filtering (DNS, ads, tracking) ». Starts once phases 1, 3, 4 and 6 are validated by the review and by
   cryptobones-1337, and after the « Interface and installation assistant » phase; it is one of the exceptions to the freeze (section 2, rule 1), with phases 8 and 9.
   - Content: safe browsing through DNS (malicious domains from the threat lists, change of DNS server
     detected, encrypted DNS if the design file justifies it) and blocking of advertising and tracking domains,
     by one and the same mechanism.
   - For the whole phase: design file first (concepteur-fonctionnalites agent), then one PR per step;
     disabled by default; guaranteed rollback (uninstallation, service failure); no kernel driver; no
     new dependency without agreement; the user's lines in the hosts file never rewritten; never an exclusion
     or weakening of Defender (rule 2): if Defender flags the mechanism, the mechanism is changed; effects on VPNs,
     corporate networks and captive portals dealt with in the design file; a third-party DNS resolver is used only
     if the user chooses it, and it is named in the interface.
   - The IDS, the DPI and the NDR stay frozen during phase 7: it does not unfreeze them. (They have been unfrozen since then (IDS and NDR on 2026-11-16, DPI on 2026-11-18, `CLAUDE.md`, « Unfreezing of the IDS, NDR and DPI » paragraph).)
   - End of phase 7: full attack campaign from the Kali test VM (`d4t-kali`, already deployed by the
     maintainer), requested by the maintainer on 2026-10-27 (« I propose to do a full test after phase 7, add it to
     claude.md »). It targets the VM `deR4Tizer-test-26H2` and exercises together detection, incidents and their
     timeline (phase 4), response and its maximum durations (phase 6) and DNS filtering (phase 7).
     - Start: first tests on 2026-11-15, after the merge of PRs 7.1 to 7.6 (last one on 2026-11-14, #167).
       The maintainer, on 2026-11-19: « Considère que la campagne Kali a démarré après la phase 7. » (Consider that the Kali campaign started after phase 7.)
     - Scenarios S-20 to S-27 (network detection): run from 2026-11-16 to 2026-11-17 before being recorded in the
       approved list; added to the approved list (version 1.5), decided on 2026-11-19 with these words of the
       maintainer: « Scénario S20 à S27, il faut les ajouter à la liste approuvée. » (Scenarios S20 to S27 must be added to the approved list.) The list
       (`campagne-kali-phase1.md`, §6) and the reports say that this is an approval after the fact.
     - Topology: two deviations from the « Network » rule below, granted by the maintainer on 2026-11-19 (« Ok pour la
       topologie du labo » (OK for the lab topology)): the target VM has two network adapters, one of them on the host machine's network, disabled in a
       reversible way during the network tests (`campagne-kali-detection-reseau-lot1.md`); the lab segment is
       readdressed in 192.168.50.0/24 (RFC 1918) for the UPnP and directional IDS tests, reversibly through
       the snapshot (`campagne-kali-detection-reseau-lot4.md`).
     - Network: internal virtual switch between the two VMs only, never the host machine's network nor the Internet; VMs
       addressed in a documentation range (RFC 5737, for example 203.0.113.0/24), never a real public
       range, so that COR-R9 (session from a public address) can trigger. Only exception, chosen
       by the maintainer on 2026-11-14 (« Lien d'admin SSH » (SSH admin link)): an administration link on a separate switch,
       between the host machine and Kali only, in another documentation range (198.51.100.0/24), without routing to
       the test VM, the local network or the Internet, and used only for SSH, opened from the host machine to Kali (key,
       password login refused). The test VM, for its part, is driven without network (PowerShell Direct). Updates
       of Kali: outside the campaign only, through a temporary network adapter removed afterwards.
     - Target VM started from one of its three campaign snapshots, prepared outside the campaign: « campagne A » (without
       Sysmon), « campagne B » (with Sysmon and Atomic Red Team, see the dependencies below) and « campagne C » (main configuration, described further down). Each contains
       deR4Tizer installed, learning finished, the test accounts and the lab settings (Remote Desktop
       enabled for brute force, etc.). Their names never start with « propre », so that full
       passes (`tests/vm/lancer.ps1`, which takes the most recent « propre… » snapshot) never start from them. VM
       restored to its « propre » snapshot after the campaign.
     - Third snapshot, « campagne C », main measurement configuration, decided by the maintainer on
       2026-11-14 (« pour les tests kali, tu as bien pris en compte d'avoir la baseline à 100% ? C'est l'un des interêts du produit » (for the Kali tests, did you take into account having the baseline at 100%? It is one of the points of the product), then « ok parfait » (ok perfect)): « campagne A » plus the deR4Tizer baseline applied by the service itself
       (`baseline appliquer`, logging, recommended and hardened profiles in one command, then
       `reseau.bureau-distance` alone, since list v1.6 of 2026-11-20: applied with the profile, this rule is
       left aside when Remote Desktop is enabled, which it is in « campagne A »; applying it alone keeps
       the baseline at 100 % as wanted by the maintainer), then a restart. A remains the comparison without baseline, B the
       Sysmon collection. In C, the baseline refuses Remote Desktop: brute force through Remote Desktop and the
       D4-1 tests are done in configuration A.
     - Defender stays intact during the campaign (rule 2): a campaign tool detected by Defender is a
       result, never an obstacle to get around. In configuration C, Defender changes only through the deR4Tizer
       baseline, never by hand, and never by weakening it: its state is recorded before and after (scenario
       S-19); a setting weaker than before, or an exclusion, stops configuration C, the snapshot is not
       taken and the deviation is reported to the maintainer as a product defect.
     - Scenarios written before the campaign, each with the expected alerts, incidents and actions (for example RDP and SMB brute
       force for COR-R1, R2 and R9, port scanning, connections to blocked addresses and domains);
       results recorded in the capability matrix, deviations treated as defects.
     - Includes the tests postponed by decision D4-1 (maintainer decision, 2026-10-31): restart of the interface in a
       Remote Desktop session and on fast user switching. Condition lifted by the maintainer on 2026-11-23:
       v4.3 released before these tests, deviation recorded (README, « Known limits »); the tests remain to be done.
     - The credentials of the Kali VM appear nowhere in the repository, the logs or the published proofs;
       Claude Code does not type any password: access is through an SSH key that the maintainer sets up, or the
       maintainer runs the scenarios himself.
     - Continuous validation loop (purple team), decided by the maintainer on 2026-11-14: the campaign is not
       a one-off test but a repeated cycle, audit → test → collection → measurement → analysis → proposed fix →
       non-regression → report, on a versioned corpus based on MITRE ATT&CK (obfuscated PowerShell, persistence,
       command and control, exfiltration, lateral movement within the lab, and the scenarios above).
       - Roles: a validation agent (`.claude/agents/purple-team.md`, local) designs the scenarios, the
         mapping (technique → behaviour → sensor → event → rule → alert) and the measurements, analyses the
         results and writes the reports, read-only. Claude Code alone executes (SSH key on an
         administration link host ↔ Kali reserved for SSH; PowerShell Direct to the test VM).
       - Honest measurement: classes A (confirmed detection), B (event collected without an alert), C (incorrect
         or too generic alert), D (not run or invalid, « not evaluated », never 0), E (not testable with
         the current architecture, NDR, IDS and DPI frozen when this rule was written, unfrozen since then (IDS and NDR on 2026-11-16, DPI on 2026-11-18, `CLAUDE.md`, « Unfreezing of the IDS, NDR and DPI » paragraph)); simulations and emulations never merged into a single
         score; 10 valid repetitions before a consolidated measurement; negative tests (legitimate activity) for
         false positives; no hypothesis presented as a result.
       - Credential theft, injection and defence evasion: harmless and reversible simulations
         only, marked SIMULATION; no credential theft tool, no destructive payload.
       - Dependencies accepted by the maintainer on 2026-11-14 (« J ACCEPTE LES DEUX DEPENDANCES » (I ACCEPT BOTH DEPENDENCIES)), in the test
         VM only: Atomic Red Team (MIT; Windows tests read before use: prerequisites, command, cleanup;
         any test that downloads a payload, disables a protection or is not reversible is set aside) and
         Sysmon (Sysinternals licence, proprietary: no binary in the repository), for independent collection
         alongside the native Windows logs. Installed outside the campaign (Internet only at that time), versions
         pinned and noted in each report, **without any Defender exclusion**, not even for the folder of the tests,
         contrary to what the Atomic Red Team documentation advises: a quarantined file is a
         result. Only the « campagne B » snapshot contains them; « campagne A », « campagne C » and the « propre » snapshot of the
         full passes remain without them.
       - Closed list of scenarios written and approved by the validation agent before any execution (decision of the
         maintainer, 2026-11-14: « Je préfère que la liste soit de scénario soit b gérer par agent », then « L'agent
         apprpuve », quoted as is (I prefer the list of scenarios to be managed by the agent; The agent approves)). The scenarios are documented in the repository (request of the maintainer, 2026-11-14:
         « Il faudra bien mettre à jour les fichiers md et documenter les scénarios dans le github » (The md files will have to be updated and the scenarios documented in GitHub))
         (`docs/validation/`, in Markdown: ATT&CK technique, SIMULATION or emulation, preconditions, expected
         result, maximum delay, cleanup, expected evidence, at the level of behaviour, without a detailed offensive
         command), with the written approval (date, version), after the PII guard; a scenario is published (merged
         into `main`) before its first execution, and each report notes the version of the list that was run; each
         addition or change of a scenario is approved in the same way before being run, and each approved version is
         sent to the maintainer, for information, before execution. This approval is neither human nor
         independent (same model as the one that executes) and is never presented as such. It lifts none
         of the rules of this section: a scenario that would go outside them (Defender touched, network outside the lab, real credential
         theft, destructive payload, password entry) cannot be approved by the agent; if it
         is not clearly safe, reversible and confined to the lab, it goes up to the maintainer. The maintainer can
         withdraw a scenario or take back the approval at any time. The fixes resulting from the campaign follow the
         usual circuit (review, security audit for a privileged path, full pass in a VM, merge
         validator) and stay within the scope of the open phases: they unfreeze neither the IDS, nor the DPI, nor the NDR.
         No merge by the validation agent; the merge remains decided by cryptobones-1337. Raw results
         kept outside the repository; campaign reports (`docs/validation/`), capability matrix and README updated
         in the repository, after the PII guard; the matrix and the README say « lab-tested (Kali campaign, date) »
         with classes A to E, never « validated ». The validation agent is a local file, outside Git: its
         read-only instruction is an instruction, not a limit of its tools; what is authoritative is this section.
7. Phase 8: standard settings (end users) and advanced settings (technical users). Opened by the maintainer
   on 2026-10-25 (« Add the phases », in reply to the proposal « Phase 8: standard/advanced settings »). Starts
   once phase 7 is validated by the review and by cryptobones-1337. The mode changes only what the interface
   shows, never the rights nor the validation of the service; standard mode by default; visible and reversible switch;
   no option of the advanced mode weakens the protection. Same safeguards as phase 7 (design
   file first, one PR per step, no new dependency without agreement).
8. Phase 9: data breach monitoring. Opened by the maintainer on 2026-10-25 (« Add the phases », in reply
   to the proposal « Phase 9: breach monitoring »), with this condition: « Breach monitoring > ok to rely on third
   party as long as it's free ». Starts once phase 8 is validated by the review and by cryptobones-1337. For
   email addresses given by the user, through a free third-party service only (without a suitable free service,
   the feature is not built), never by reading files of stolen data; ownership of
   the address verified by the third-party service or by a code sent to the address (to be decided in the design file, which then names
   the sending server); address never logged nor sent anywhere other than to that service (and to the sending server of the
   code, if it is chosen); disabled by default; third-party service named in the interface. Same safeguards as phase
   7.
   The IDS, the DPI and the NDR stay frozen during phases 8 and 9. (They have been unfrozen since then (IDS and NDR on 2026-11-16, DPI on 2026-11-18, `CLAUDE.md`, « Unfreezing of the IDS, NDR and DPI » paragraph).)

The IDS, the DPI and the NDR remained frozen as they were (safety fixes only) until the unfreezings of 2026-11-16
and 2026-11-18 (« Unfreezing of the IDS, NDR and DPI » paragraph below).
Only exception, for phase 3 (maintainer, 2026-10-25, with these words: « Yes: add the rule identifier line to IDS, DPI and NDR alerts, with no other change to their logic. They stay frozen otherwise. »): a line that sets the rule identifier (`EXP-*`, `docs/detection/regles.md`) in their alerts, without any other change to their logic.

Unfreezing of the IDS, NDR and DPI: « network detection » phase opened by the maintainer on 2026-11-16 (opening
recorded in `docs/validation/campagne-kali-detection-reseau-lot1.md`), with these words, noted in the decision log
outside the repository: « Ok dégel repasse en boucle de déploiement autonome » (OK unfreeze, go back to the autonomous deployment loop); confirmed on 2026-11-17: « NDR/IDS sont bien
dégelés. » (NDR/IDS are indeed unfrozen.)
The DPI is unfrozen in turn on 2026-11-18, with the NDR and the IDS, confirmed on 2026-11-19 with these words: « Tout reste
dégelé » (Everything stays unfrozen). The IDS (`ids.rs`), the NDR (`ndr.rs`) and the DPI (`dpi.rs`) enter validation in the Kali campaign:
fixes, hardening and validation of their detections. This unfreezing takes precedence over the mentions of the freeze of the IDS, the DPI
and the NDR above (phases 7, 8 and 9, purple team loop, class E of the measurement). The rest applies without
change: rules of section 2, protocol and review of section 4, VM pass, « experimental » state in
the matrix as long as a measurement does not justify otherwise, and maintainer agreement for any new capability.

ATT&CK coverage work (objective set by the maintainer on 2026-11-21): « ransomware and opportunistic intrusion, small
organisation » profile of 54 rows, validated by the maintainer on 2026-11-21, published in `docs/validation/carte-attack.md`. Steps
1 to 3 (make process collection through 4688 events reliable, derive the technique from the rule
identifier, carry the technique on each rule sheet, then consolidate and test what exists) add no capability; the
« Aucune règle » (No rule) and « Partiel » (Partial) rows wait for a phase opened in writing. One lot per PR, explicit agreement of the
maintainer for the lot that touches process collection. Order of priority with the first signed version (block
1.1, local signing procedure), decided on 2026-11-21 by the answer « In parallel » to the question of that order:
the ATT&CK work moves forward while the version follows its course, when the maintainer does the signing rehearsal;
neither waits for the other, and nothing in this work blocks the version.

« PowerShell script blocks (4104) » phase: opened by the maintainer on 2026-11-23, with these words: « ouvrir la phase
de lecture des événements 4104 (A-7-4). » (open the phase of reading 4104 events (A-7-4).) Origin: finding A-7-4 of the audit of 2026-11-23 (the baseline enables
script block logging, event 4104 of the `Microsoft-Windows-PowerShell/Operational` channel, and no rule
reads it); the only source that sees PowerShell code after decoding, for T1059.001 and T1027 (`docs/validation/carte-attack.md`).
Start condition: the decision does not set one; the design file is prepared straight away, the code starts
after its review and after the merge of PR #269 (secret masking, below), in parallel with the fixes from
the audit. Same safeguards as phase 7: design file first (concepteur-fonctionnalites agent), one PR per
step, no new dependency without agreement; « implemented, not verified » state in the matrix before any test, « lab-tested »
afterwards, as long as a measurement in a VM does not justify better. Specific constraints: a script block can contain
secrets, it goes through the secret masking of A-6-1 (`commun::masquer_secrets`, PR #269) before any storage or
export, with a bounded size, and no script block is stored before the merge of that PR; read-only access to the log, no
PowerShell setting modified outside the existing baseline; new rule with its sheet in
`docs/detection/regles.md`, its positive and negative tests, and its false positive measurement.

## 6. Actions reserved to the human

Claude Code does not do them; it can remind of them.

- Check that all machines are on 4.2 or later. First signed version published on GitHub: v4.3, on 2026-11-23; versions 4.2 and 4.3 installed by hand before it do not update themselves.
- Turn on the protection of `main`: pull request required, green CI required, no force push.
- Protect the `v*` tags; require an approval on the `publication` environment.
- Sign the version: Certum Open Source certificate, chosen by the maintainer on 2026-11-11 (decision log; name of the holder visible in the signature of the binaries only), obtained, valid until 2027-11-17; `CLE_SIGNATURE` variable set. The key stays in the Certum cloud (SimplySign): signing is done on the maintainer's machine. SignPath Foundation and Azure Trusted Signing are set aside.
- CodeQL code scanning: turned on by the maintainer on 2026-11-23 in « default setup » (repository setting, no workflow file). Steps: repository page › **Settings** › « Security and quality » section of the sidebar › **Advanced Security** › under « Code Security », « CodeQL analysis » row › **Set up** › **Default** › **Edit**: languages GitHub Actions, C#, Python, Rust ticked, « Default » query suite › **Enable CodeQL**. Check: `gh api repos/cryptobones-1337/deR4Tizer/code-scanning/default-setup` returns `state: configured`, the four languages, `query_suite: default`. Analyses observed: hosted runner `ubuntu-latest`, build mode `none` for C# and Rust, on each push and PR to `main` and every week. Dismissing an alert (the maintainer only, after the written triage in a PR): repository page › **Security and quality** › **Code scanning** › the alert › **Dismiss alert** › reason (false positive, used in tests, won't fix) and a comment that says why, with the number of the triage PR; command-line equivalent: `gh api -X PATCH repos/cryptobones-1337/deR4Tizer/code-scanning/alerts/<n> -f state=dismissed -f dismissed_reason="false positive" -f dismissed_comment="<reason, PR>"` (`dismissed_reason`: `false positive`, `used in tests` or `won't fix`). Never a disabled rule, a reduced suite or an excluded path to get an empty report. Pages read: docs.github.com, « Configuring default setup for code scanning » and « Resolving code scanning alerts ».
- Decide on any release.

## 7. Definition of « done »

A change is done only if:

- its behaviour is documented;
- its failure modes have been examined, and those that touch security fail closed;
- positive, negative and boundary tests exist and have been run, or their non-execution is declared;
- no secret leaks into the logs or onto the command line;
- the capability matrix and the README reflect the demonstrated state, not the hoped-for state;
- the lot report (section 4) is written, the review has returned « Go » and cryptobones-1337 has agreed to the merge.
