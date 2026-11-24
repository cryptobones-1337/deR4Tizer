# Test baseline of deR4Tizer

Commands actually run and results observed. To be updated with each lot.

## Unit tests of the service

```
cd service-rs
cargo test --release
```

- 2026-10-24, tree `7ad06963` (`main` `1cf04fe`), local, toolchain `stable-x86_64-pc-windows-msvc`:
  **86 passed, 0 failed**.
- 2026-11-19, `windows` job of the CI (run 44476563634, PR #205, commit `774e3cb`, service identical to `main`), MSVC
  toolchain: **469 passed, 0 failed** (tests in `tests.rs` and `tests_detection.rs`).
- Content (`service-rs/src/tests.rs`): pure functions that read data from the network or from external files
  (packets, TLS, DNS, IDS rules, manifests, UPnP), security decisions (rights, sorting at start,
  quarantine, resume, restore, update, pinned key), with a mini-fuzz (all truncations of a
  valid message and thousands of pseudo-random inputs, never a panic: the service is built with
  `panic = "abort"`).
- The `windows` job of the CI runs the same command (MSVC toolchain) on every PR and on `main`, and checks that the
  service does not depend on the Visual C++ runtime (`dumpbin /dependents`). GitHub Actions was disabled from
  2026-10-22 to 2026-11-17; since then, this job runs on every PR (469 passed on 2026-11-19, run 44480286774 (PR #205, `cd36ee4`, 2026-11-19)).

## Build

| Command | Observed result |
|---|---|
| `./compiler.ps1 -InterfaceSeulement` | 2026-10-22, local: code 0, `bin\deR4Tizer.exe` (404 992 bytes). |
| `powershell -File tests\test-msi.ps1 [-Msi bin\deR4Tizer.msi [-Reference <MSI de main>]]` | 2026-11-11, local (U8a): sources and package, execution tables identical to the MSI of main; the sources of main fail there (5 cases). |
| `cargo build --release` (MSVC) then `./construire-msi.ps1` | `windows` job of every CI run: `deR4Tizer.msi`, `deR4TizerSvc.exe`, `deR4Tizer.exe` as artifacts. Since PR #284: `cargo test --release --locked` and `cargo build --release --locked`, toolchain pinned by `service-rs/rust-toolchain.toml` (rustc 1.100.0); `windows` job successful in run 45175958903 (`e2d2991`). |
| Local copy of `service-rs`, `Cargo.toml` modified (version 4.3.0 to 4.3.1) without `Cargo.lock`: `cargo build --release --locked` | 2026-11-23, local (MSVC toolchain 1.99.1, copy outside the repository, nothing pushed): failure, code 101 ("cannot update the lock file … because --locked was passed"), `Cargo.lock` unchanged. Without `--locked`, `cargo metadata` silently rewrites `Cargo.lock` (code 0, only difference: 4.3.0 to 4.3.1). Proof of the fix for A-3-3. |

## Static analysis in CI: dependencies of the service (lot 1, PR #284)

`dependances` job of `.github/workflows/ci.yml`, tools installed by `cargo install --locked` at a pinned version
(cargo-audit 0.22.2, cargo-deny 0.20.2), rustc 1.100.0 toolchain. Configuration of cargo deny: `service-rs/deny.toml`.

| Command (in `service-rs`) | Observed result |
|---|---|
| `cargo audit --file Cargo.lock` | Run 45175958903 (`e2d2991`, 2026-11-23): 1562 RustSec advisories loaded, 78 packages of `Cargo.lock` read, no vulnerability or warning, code 0. |
| `cargo deny --locked --config deny.toml check --show-stats advisories licenses sources` | Same run: `advisories ok: 0 errors, 0 warnings, 0 notes`; `licenses FAILED: 1 errors, 2 warnings, 63 notes`; `sources ok: 0 errors, 0 warnings, 0 notes`. Only error: `der4tizer-svc = 4.3.0 is unlicensed` (the service itself, without a `license` field in `Cargo.toml`). |
| Same command, after the maintainer's decisions of 2026-11-23 (`license = "EUPL-1.2"` in `Cargo.toml`, list of licenses validated, EUPL-1.2 added) | Run 45184585387 (`28eab0a`): `advisories ok: 0 errors, 0 warnings, 0 notes`; `licenses ok: 0 errors, 0 warnings, 64 notes`; `sources ok: 0 errors, 0 warnings, 0 notes`; `dependances` job successful. cargo audit: 1562 advisories, 78 packages, no alert. `windows` job in the same run: 565 tests passed, 0 failed (`--locked`). |

These checks only see published advisories (RustSec), declared licenses and the origin of the packages: no
logic flaw, no service code. This is not an independent review.

## Integration (CI, disposable Windows runner, real service installed by the MSI)

Each script writes a table ("RÉUSSI", "ÉCHOUÉ", "NON EXÉCUTÉ" with the reason) in the job summary; a single
"ÉCHOUÉ" fails the job; a "NON EXÉCUTÉ" is never counted as passed.

| Lot | Job | Script | Last validated run | Result |
|---|---|---|---|---|
| 3a | `integration-installation` | `tests/integration/installation.ps1` | run 39822711631 (`3194bb6`) | 42 scenarios, 0 failed, 0 not run |
| 3b | `integration-quarantaine` | `tests/integration/quarantaine.ps1` | run 39822711631 (`3194bb6`) | 21 scenarios, 0 failed, 1 not run |
| 3c | `integration-maj` | `tests/integration/maj.ps1` | run 44480286774 (PR #205, `cd36ee4`, 2026-11-19) | 20 scenarios, 0 failed, 1 not run |

Not run in 3b: refusal by `creer_sans_lien` of a junction placed between the owner check and the
creation (race that cannot be reproduced deterministically).

In the same run 44480286774 (PR #205, `cd36ee4`, 2026-11-19): 3a 91 scenarios, 0 failed, 4 not run; 3b 35, 0 failed, 1 not run.

## Integration in Windows Sandbox (local proof while GitHub Actions was disabled, from 2026-10-22 to 2026-11-17)

Same scripts, launched by `tests/bac-a-sable/preparer.ps1` then `lancer.ps1 -Scenario installation|quarantaine|maj`
(and `preparer.ps1 -Maj` for 3c), in a disposable Windows Sandbox. Signal, not proof: neither a real computer nor an active
Defender (disabled in the Sandbox); never counted as "validé sur Windows (VM)".

The build folder of the service is shared by all copies of the repository (worktrees). Cargo judges a file up to date
by its date: without precaution, a copy whose sources were older than the last build of another
copy delivered the other copy's binary. This happened on 2026-10-26, on a measurement-only pass: the binary of
`main` was tested under the head of a PR, with the number of unit tests of `main`. `cible-cargo.ps1`, loaded by
`compiler-rs.ps1` and `preparer.ps1`, gives each copy its own build folder
(`%USERPROFILE%\.der4tizer-build-msvc\<empreinte du chemin>`), which also covers two simultaneous builds; the
folders of removed copies are deleted. The reports keep the number of unit tests
run, to be compared with that of the tested head.

2026-10-24, tree `370e4d272d88515c1e6901882933bc8340995602`, identical to `main` after the merge of PRs #10 to #27
(the history was rewritten on 2026-10-24 to remove personal data from it: the tested tree `370e4d27`
is identical, except for the IP addresses of the test data, to that of `main` `7ff8309`; old commit
identifiers quoted for the record), Windows 11 Pro 10.0.26300.9711, MSI of scenarios 3a and 3b SHA-256
`D36263F9BC19170C25193A5642974E8FB33D969CF466CDAE96AF5AB4C30F38D5`:

| Lot | Passed | Failed | Not run |
|---|---|---|---|
| 3a | 41 | 0 | 2: no account at the console (read access granted to the console account; rights of 4.1.0, which only sets them with an account at the console) |
| 3b | 23 | 0 | 3: no interactive session (decoys of the session, restore with session); race of `creer_sans_lien` |
| 3c | 19 | 0 | 1: service silent after installation (simulation only) |

Full tables in comments on PRs #10 to #27.

2026-10-24, tree `4bdcc38dd6e99aa52376d1d44b78ebad7c61db15`, that of `main` `c60d9b3` after the merge of PRs #34,
#31, #32, #33, #35 (tested commit `bfaa412`, `git diff bfaa412 main` empty), Windows 11 Pro 10.0.26300.9711, MSI of
scenarios 3a and 3b SHA-256 `6F63CE69B91596A13BCECE69891BDDF5404EB3BE01CF2551CC1385857558E9D9`, 80 unit tests:

| Lot | Passed | Failed | Not run |
|---|---|---|---|
| 3a | 41 | 0 | 2 (same reasons) |
| 3b | 24 | 0 | 3 (same reasons) |
| 3c | 19 | 0 | 1 (same reason) |

New compared with the previous pass: decoy already present in a profile without an audited session (3b);
uninstallation without `GARDER_DONNEES` that does remove the data (3a, 3b). Tables in comments on PRs #31 to #35.

2026-10-24, tree `67978e1f8a2d8fc42b55c2c8624761ff50826949`, that of `main` `b72874f` after the merge of PRs #36,
#37, #40, #41, #42 (tested commit `51f8796`, `git diff 51f8796 main` empty), Windows 11 Pro 10.0.26300.9711, 83 unit
tests. MSI SHA-256: 3a `D8EE3E666BBDD0A11B8FB1844CF07598231BE521B5EE5DFD97F67F55B0B74F92`; 3b
`7322DF3A3E6F79E1F70EB23A49B2F14B2BD990FDA449053876C55DD7E41C8FB2` (same tree, rebuilt: rerun after a
Windows Sandbox start failure); 3c, rebuilt after the test packages,
`C72D73FD548489979886893411BBC167C93692B775438A47151FAB532299F555`.

| Lot | Passed | Failed | Not run |
|---|---|---|---|
| 3a | 41 | 0 | 2 (same reasons) |
| 3b | 24 | 0 | 3 (same reasons) |
| 3c | 19 | 0 | 1 (same reason) |

Tables in comments on PRs #36, #37, #40, #41, #42.

2026-10-24, tree `7ad0696305ea17de643b2c015aff497d7dadd10b`, that of `main` `1cf04fe` after the merge of PRs #43,
#44, #45, #46 (tested commit `b86e8d2`, `git diff b86e8d2 main` empty), Windows 11 Pro 10.0.26300.9711, 86 unit
tests. MSI SHA-256: 3a and 3b `E6EA86BA979D5DBB84E93F70BF837F9CDB22BA6C84A6B7130995E0977A4862C8`; 3c, rebuilt
after the test packages, `F7D7CFA1122C417D9C9250B8C0F3EFBC27B076090F75155049E6DE06340F5704`.

| Lot | Passed | Failed | Not run |
|---|---|---|---|
| 3a | 41 | 0 | 2 (same reasons) |
| 3b | 24 | 0 | 3 (same reasons) |
| 3c | 19 | 0 | 1 (same reason) |

Tables in comments on PRs #43, #44, #45, #46.

## Static analysis in CI: CodeQL (lot 3)

GitHub code scanning in "default setup", enabled by the maintainer on 2026-11-23 (repository setting, steps
in section 6 of `CLAUDE.md`): CodeQL 2.27.5, "default" query suite, `ubuntu-latest` runner
(ubuntu-26.04 image), build mode `none`, on every push and PR to `main` and every week. No workflow
file in the repository: the run is GitHub's dynamic "CodeQL" workflow.

| Language | Analysis on `main` (`edc2639`, run 45181833445, 2026-11-23) | Rules | Alerts | Extraction |
|---|---|---|---|---|
| Rust | 2229920801 | 27 | 5 | 49 files out of 49, of which 4 extracted with errors: `commun.rs` ("expected an item" at lines 1 and 2, a file that starts with a BOM), `main.rs` (macro `define_windows_service` not expanded), `natif.rs` and `reponse.rs` (macros `windows::core::s` and `w` not expanded) |
| C# | 2229883658 | 52 | 0 | 11 files out of 11; no project or solution found, references taken from CodeQL's .NET assemblies (203), "WPF usage detected: False"; diagnostic "Low C# analysis quality": 65 % of calls with a known target (threshold 85 %), 77 % of expressions of known type (threshold 85 %) |
| Python | 2229881103 | 43 | 1 | 1 file out of 1 (`tests/integration/serveur-maj.py`) |
| Actions | 2229879240 | 17 | 0 | workflows of `.github/workflows` |

Triage of the 6 open alerts on `main` (detail, reason and scenario in the PR of lot 3): no real flaw;
6 false positives, to be dismissed by the maintainer with their reason.

| No. | Rule (severity) | Location | Classification |
|---|---|---|---|
| 5 | `rust/hard-coded-cryptographic-value` (critical) | `service-rs/src/reponse.rs:280` | False positive: buffer `[0u8; 16]` entirely copied from the SHA-256 of the copy's name; the quarantine encoding is not encryption (public key, documented) |
| 6 | `rust/hard-coded-cryptographic-value` (critical) | `service-rs/src/reponse.rs:319` | False positive: same buffer, filled with the 16 bytes read from the copy's header |
| 2 | `rust/access-invalid-pointer` (high) | `service-rs/src/ndr.rs:250` | False positive: pointer filled by `GetIpNetTable2`, error return and null pointer ruled out just before |
| 3, 4 | `rust/access-invalid-pointer` (high) | `service-rs/src/natif.rs:918`, `:922` | False positives: pointer returned by `GetAce`, error and null pointer ruled out just before, DACL returned by Windows |
| 1 | `py/insecure-protocol` (high) | `tests/integration/serveur-maj.py:40` | False positive, test code: local server of lot 3c on 127.0.0.1, disposable runner; `PROTOCOL_TLS_SERVER` already refuses TLS 1.0 and 1.1 since Python 3.10 |

Alert no. 7 (`rust/cleartext-logging`, high): only on PRs #269 and #278 (`service-rs/src/tests.rs`),
not on `main`; false positive (message of a test `assert!` that displays text already passed through
`masquer_secrets`). No alert dismissed to date.

CodeQL sees neither logic flaws nor the product's own trust decisions; the C# analysis without
build remains partial (quality thresholds not reached). This is not an independent review.

## Not covered

- Run with Microsoft Defender active (lot 3d) on a real computer: the lot only runs in the test VM, and remains required on the distributed version.
- Scenarios that need an interactive session (none in Windows Sandbox; the one of the hosted runner is an
  administrator): decoys placed in the session profile, restore with the session of a standard
  user, reading of the data by the console account.
- Interface: automated tests of its decisions and of its off-screen rendering (`tests/rendu-pilote.ps1`,
  `tests/test-confirmations.ps1`, `tests/test-reponses-interface.ps1`, `tests/test-incidents-interface.ps1`), and real
  screenshots in a VM (`tests/vm/captures.ps1`); rendering at 125 % and 150 % not checked on a real screen; the
  confirmation windows are exercised by no scenario.
