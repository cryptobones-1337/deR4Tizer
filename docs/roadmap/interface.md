# « Interface and installation assistant » phase

Decided by the maintainer on 2026-11-03, in these words: « fais la refonte avant la phase 7 » (do the redesign before phase 7), in reply to the interface
design file of 2026-11-03 (UI/UX review after phase 6, kept outside the repository). It starts once the
fixes of phase 6 are merged **and the phase is written into `CLAUDE.md`** (section 2, rule 1; written on
2026-11-03 with the maintainer's authorization). Phase 7 starts once
this one is validated. This document sets the scope,
the split and the decisions of the phase. Written before the code; most PRs have since been delivered (table below): the state
of each item is the one in the matrix (`docs/roadmap/capability-matrix.md`).

## Need

Today's WinForms interface is functional but dated: "neon" look, forced capitals, insufficient contrast
of secondary text, flat navigation, dense pages. The external UX review of 2026-10-25 and the review made
after phase 6 point the same way: a user without an IT person must understand at a glance what is fine,
what is not and what they can do. Installation is limited to the standard Windows Installer dialogs, and nothing
explains the first settings.

## Decisions of the maintainer (2026-11-03)

| Question of the file | Answer |
|---|---|
| Technology | WPF on .NET Framework 4.8, without a style library (no new dependency). **Confirmed by the maintainer on 2026-11-09** on the real screenshots of the pilot in a VM (« Continuer en WPF » (Continue with WPF)): the WebView2 fallback is abandoned |
| Palette | Neutral, with a single accent; cyan remains the color of the logo |
| Fonts and icons | Segoe UI (Variable) and Segoe Fluent or MDL2 icons, shipped with Windows; nothing added |
| Installation assistant | Plain WiX MSI (images and texts reworked); the first-run assistant is in the interface |
| Order | Before phase 7 |

## Points not settled (default chosen, to be confirmed by the maintainer)

| Point | Default chosen |
|---|---|
| "PC exposed to the Internet" diagnostic (it touches the service) | In this phase, in U5, as the file proposed; confirmed by the maintainer on 2026-11-10 (« Oui » (Yes), question Q1); done (U5c-1, U5c-2) |
| "Automatic responses" step of the assistant | Today's setting is kept: automatic level 3 blocking enabled by default. The file proposed "disabled by default"; this change of default was not decided |

## Visual direction

Contrasts computed according to WCAG (at least 4.5:1 for text):

| Token | Value | Use |
|---|---|---|
| Background | `#141518` | window |
| Card | `#1E2024` | panels |
| Surface | `#262A30` | fields, hovered rows |
| Text | `#E6E8EB` | body text |
| Secondary text | `#9AA3AF` | replaces `#6B7A90`, too pale |
| Accent | `#3BA7F0` | a single accent, dark text on it |
| Danger | `#F0605A` | confirmed risk and destructive actions |
| Warning | `#F2A93B` | to watch |
| Success | `#2FBF71` | sparingly |

- Segoe UI everywhere; monospace reserved for paths and hashes; end of forced capitals. Temporary gap
  (review of #133, R2): in the pilot, today's hosted pages are entirely in Segoe UI, paths and
  hashes included (their single font `Theme.Mono` also serves the tables); monospace comes back with their
  rewrite (U3 to U6).
- Corners of 6 to 8 px; transitions of 100 to 200 ms, cut if Windows disables animations; no more sweeping nor
  "glitch" effect; a single blink at a time.
- Navigation: "Overview", then Monitoring, Protection, System and privacy; Ongoing responses, Health
  and Settings always visible. Details panel on the right, with explicit buttons.

## Split

| PR | Content |
|---|---|
| U0 | Script of real screenshots in a VM; reference screenshots; cheap WinForms fixes (texts through `L.T`, contrast): **done**: `tests/vm/captures.ps1` (`tests\vm\lancer.ps1 -Scenario captures`), 19 pages in French and in English at 96 dpi, captured in a VM before the fixes that follow (the screenshots after the fixes awaited the lifting of a detection of `deR4TizerSvc.exe` by Defender in the VM, on 2026-11-03: heuristic false positive `Wacatac`, installation refused; screenshots taken since, those of the README); secondary text `#9AA3AF`; header and status bar translated; badges never under the title, cut by severity ("+N" in the color of the most severe hidden one) |
| U1 | **Done** (pilot first opened by `--fluent`, default interface since B1): `src/Fluent.cs`, pure C# compiled by `csc` (no compiled XAML, no dependency: WPF assemblies of .NET Framework 4.8); tokens, grouped navigation, today's pages hosted by `WindowsFormsHost`; `tests/rendu-pilote.ps1` (contrasts, navigation, off-screen rendering at 100, 125 and 150 %, elevated assistant without WPF). Real screenshots of the pilot in a VM (`tests/vm/captures.ps1`, 20 pages, French and English). Software rendering forced (hardware rendering left the shell white in the Hyper-V VM); window brought back to the work area; in pilot mode, today's pages take the palette and the font of the shell (`Theme.cs`), without a doubled "//" title. **WPF confirmed by the maintainer (2026-11-09).** Still to measure: memory in the notification area, start through the restart task, sharpness at 125 and 150 % in a VM |
| U2a | **Done (#134)**: native Overview in the pilot: facts of today's header (same rules, same texts, put back in sentence case) sorted by severity, colored counters of the navigation at "to watch" at most, opening sentence without promise ("Unknown state" if nothing is published), panic button through the same path and the same confirmation as today, service status line; counters in the navigation; the notification area (open, double-click, click on a notification) shows the shell; closing the shell hides it, only "Quit" stops it (review of #133, R3) |
| U2b | **Done (#136)**: Alerts page rewritten in WPF: filters by level with their count, list of the most recent (500 at most), unread ones marked, details panel on the right (time, destination, rule, technique, what to do, reasons, path in monospace) with explicit buttons, offered according to what the alert allows (block, stop alerting except for a critical one, isolate, suspend, kill, quarantine, open the location) and going through the same methods and the same questions as today's menu; service texts neutralized; reading of the alerts marked from the shell |
| U2c | **Done (#137)**: Incidents and Ongoing responses rewritten in WPF, same details panel: list sorted as today, state always written, "Reading…" before the first reading (never a reassuring blank), last list kept if the file becomes unreadable; buttons through the same actions as today's pages (`ActionsIncidents`, `ActionsReponses`: same command, same closing dialog, same recovery checks, same elevated confirmation). Prerequisites from the review of #136: alert level neutralized; suspending or killing from an alert refused if the process that carries this PID was started after the alert, the two times stated otherwise (an alert does not keep the creation time of the process) |
| U3a | **Done (#138)**: Health and Detection in WPF: same rows as today's Health page (source and date of each row), "Reading…" before the first reading; Detection in five views (IDS, TLS, HTTP, DNS, JA3), network and rule texts neutralized (today's page too), IPS set through the same command and the same elevated confirmation, button hidden as long as its state is not read. Prerequisites from #137: unknown response kind neutralized, limits of the guard on the PID written in the matrix |
| U3b | **Done (#139)**: Events in WPF: same search as today's page (`RechercheSiem`, extracted without a logic change, read-only outside the interface thread), same filters (period, level, source), timeline in 48 clickable slices, correlation incidents then events (500 displayed at most), details panel; texts neutralized, today's page too. Prerequisites from #138: IPS state "unknown" if config.json is unreadable (no button, box greyed out); "Copy" gives back the original value, control and formatting characters escaped (audit of #139, S139-01) |
| U4a | **Done (#140)**: Connections and Chains in WPF: read from etat.json outside the interface thread, "Reading…" before the first reading, last list kept and stated if the state becomes unreadable, failed collection stated (incomplete list); Connections: filters (all, suspicious, threats), most severe first, 500 at most; Chains: "who launched what" tree in the panel, threshold of 12; buttons through the same methods and the same questions as today's menus; texts neutralized, today's pages too; "Copy" escaped. U4 split into U4a and U4b |
| U4b | **Done (#141)**: Traffic in WPF: same file as today's page (trafic.json, read outside the interface thread and only when it changes), summary of throughput and totals, map of countries (logarithmic scale, bubble per country, fixed arcs to the exchanges of the last 10 seconds, no continuous animation), curve of the last 10 minutes with its maximum, then programs, countries or destinations and their detail; "Reading…" before the first reading, nothing concluded without a file, last display kept and stated if it becomes unreadable; texts neutralized, today's page included |
| U5a | **Done (#142)**: Blocks, Quarantine and Threats in WPF: same files, read outside the interface thread (absent: nothing recorded; unreadable: nothing concluded, last display kept and stated); same commands and same questions in both interfaces (`ActionsProtection`); settings of automatic responses offered only when config.json is read (audit of #139, S139-02); texts neutralized, today's pages included; legend of the Traffic map cut cleanly. U5 split into U5a, U5b and U5c |
| U5b | **Done (#143)**: Baseline and Firewall in WPF: Baseline per profile (logging, recommended, hardened) with its score, same buttons and same questions as today (`ActionsProtection.Baseline`), apply or cancel a rule from its panel; Firewall in two views (exposure to the Internet, rule changes), read-only, inactive packet log stated; "Reading…", absent and unreadable distinguished; texts neutralized, today's pages included |
| U5c-0 | **Done (#144)**: interface only. With no exposure found, each check is stated as seen or not verified, and the verdict states what it rests on; "checks incomplete" if the packet log is inactive or if UPnP is not verified; never "aucune exposition". Finding C1 of the U5c design file |
| U5c-1 | **Done (#148)**: service. Diagnostic per check published in etat.json (Exposition.Diagnostic): public IPv4, global IPv6, accepted connections, blocked sources, UPnP (verified from the text and the freshness of reseau.json, NDR then frozen), state of the Windows firewall (INetFwPolicy2 reading); verdict with four values, never "protected"; read-only, no request to a third party nor to the router; `Exposee` unchanged. Decided by the maintainer on 2026-11-10 (« Oui » (Yes): in this phase) |
| U5c-2 | **Done (#149)**: `Exposee` follows the verdict of the diagnostic; global IPv6 alone and blocked sources alone as "exposure to watch" (orange, without blinking) rather than "PC exposed to the Internet", decided by the maintainer on 2026-11-10 (« Oui » (Yes)); Firewall page: "Why" view (finding, state, what to do), summary titled according to the verdict in both interfaces; old service without diagnostic: finding of U5c-0 |
| U6a | **Done (#145)**: Autostart, Extensions and Privacy in WPF: same files, read outside the interface thread; Autostart with the same filter (Microsoft and Windows hidden except with a remark), remarks first, quarantine of the target through the same question; Extensions, sensitive permissions first, read-only; Privacy in three views (camera and microphone, remote control, open ports), failed collection stated; texts neutralized, today's pages included. U6 split into U6a and U6b |
| U6b | **Done (#146)**: Local network in WPF (reseau.json, read-only, four views, decoy and rogue DHCP stated, texts neutralized, today's page included); questions of today's buttons translated (review of #143, finding 5), blocking question neutralized. U6 split again: Settings and removal of `WindowsFormsHost` in U6c |
| U6c | **Done (#147)**: Settings in WPF: same settings, same checks and same commands as today's page (`ActionsReglages`, shared); choices through buttons (no light drop-down list), secrets in masked fields never shown again; config.json unreadable: stated, nothing is saved (both interfaces); CSV export without formulas; texts neutralized; no action before the first reading. Removal of `WindowsFormsHost`: all the pages of the shell are native. Prerequisite from #146: test of the {0} {1} placeholders over the whole translation table |
| U7-0 | **Done (#150)**: prerequisites from the reviews. Leftovers of the WinForms hosting removed (`pages` parameter of the shell, `Fenetre.PageDe`, `WindowsFormsIntegration.dll` reference of the builds, review of #147); reading of the Windows firewall outside the monitor lock (review of #148); effect of an old UPnP check written (review of #149, finding 1) |
| U7a | **Done (#151)**: "First-run setup", read-only base (U7 design file). Page of the shell outside the navigation, six steps (welcome, verification, learning, who to notify, automatic responses, summary); no command: each step reads the service files and refers to Health, Settings or Threats; learning stated in three cases (in progress, finished, no automatic learning when the start equals the end); "Nobody is notified" stated as it is; per-user marker (`%LOCALAPPDATA%\deR4Tizer\premiers-reglages.txt`) written only by "Later" and "Finish"; opened automatically at the first launch of the shell, never as administrator, with `--page` or `--cache`; card in the Overview as long as the marker is missing, "See the first-run setup again" button in Settings |
| U7b | **Done (#152)**: actions of the steps. Learning: finish it if it is in progress, nothing otherwise; never restart from the assistant (for 7 days, any non-critical alert without a strong signal would be learned, active malicious program included: review of #152, finding 1), only in Settings, written warning; automatic responses: enable or disable the two at level 3 (blocking by the lists, suspension by decoy), the IPS staying in Detection; same commands as the Settings and Threats pages, built by the same functions for the confirmation and the sending (audit of #152, S152-01); elevated interface: detailed confirmation shown by the assistant before the action; result stated as "demandé" and state reread; texts reworked (remarks R2, R5, R6 of #151) |
| U7-1 | **Done (#153)**: follow-ups of the audits of #151 and #152. Elevated interface: "config" (automatic responses, IPS, lists) and "apprentissage" confirmed by Canal in all pages, the assistant no longer shows a second one (S152-02), as well as "debloquer", "reglages", "notifications", "majConfig", "autoriserLecteur" (S153-01) and "exception" (S153-02); confirmation with the readable name of the setting and, for "recommencer", the 7-day risk (R8); `derniere-alerte-lue.txt` never written by an elevated interface (S151-01) |
| U7c | **Done (#154)**: Who to notify, option B of the file (recipients, channels and secrets stay in Settings). The step sends a test message to the channels already set: settings reread on click (the service applies them before the test, S154-01), empty secrets (the service keeps its own), "testerNotifications" confirmed as administrator in all pages, command built by the function of the Settings page (`CommandeNotifications`); only if config.json is read and a channel is enabled |
| U7 | First-run assistant: **done** (U7a to U7c, #151 to #154) |
| U8a | **Done (#155)**: texts of the installer (U8 design file). License in French and in English (decoys, automatic responses and their durations, launch, downloads, Defender complemented and never weakened, uninstallation options, unsigned binaries); last page: a text set by four client-side property assignments (type 51), according to the language (UserLanguageID) and the actual launch (mirror of the execution condition), never a "Lancer" checkbox nor an action that launches the interface: launched from there, it could run elevated (depending on how the installer was launched) and keep the session mutex; "protection" removed from the descriptions; `tests/test-msi.ps1`; 3a: interface coming from the task, non-elevated token |
| U8b | Images of the installer (banner, dialog), generated at build time, on the new icon; screenshots of the dialogs in a VM |
| B1 | **Done (#156)**: switchover, the shell becomes the default interface (switchover file); `--classique` for the former interface; hidden start without a window, shell built at the first gesture; page unloaded when the shell is hidden; neutral palette except `--classique`; automatic fallback to the classic interface if the shell does not start, including at the first gesture after a hidden start, the hidden window released |
| B2 | **Done (#158)**, not yet exercised in a VM: second instance, show the interface already open (session event without data, listened to on a background thread; pure decision `SignalerPremiere`: never with `--cache`, `--relance`, `--commande-fichier`, `--dossier` or `--classique`; requested page ignored) |
| B3 | Last page of the MSI: "First-run setup" sentence, after B1 and B2 |
| B4 | Lightening (standby without WinForms pages), based on the measurements of B1; removal of `--classique` after the Kali campaign, on decision |

**First-run assistant (U7)**: non-elevated, replayable from the settings; each privileged choice goes through the
existing command and its elevated confirmation. Steps: Welcome; Verification (read-only, an unavailable collection
is stated); Learning (7 days); Who to notify; Automatic responses (level 3 only, today's
default: see the points not settled); Summary with "Later". Closing the assistant changes nothing; it never says "you are protected".

## Safeguards

- No new dependency without the maintainer's agreement (WebView2 included).
- XAML loaded only from the resource of the signed executable.
- Any untrusted string displayed goes through `Visible`, details panel included (fix S105-09 first).
- `--commande-fichier` does not load WPF: a test proves it.
- The service, the channel and the rights do not change, except the exposure diagnostic of U5.
- `tests/test-confirmations.ps1` unchanged: the elevated confirmations always say what the command does.
- "Collection unavailable" is never shown as "nothing suspicious".
- README (in English only since 2026-11-18; the app's interface stays bilingual) up to date with each PR that changes what one sees.

## Tests

- Unit, through reflection: a single panic mode badge; header texts through `L.T`; contrast of the tokens
  ≥ 4.5:1; `Visible` in the details panel; grouping of the navigation; Overview (unavailable
  collection); assistant (closing changes nothing).
- Integration: script of real screenshots in a VM (each page, 100, 125 and 150 %, French and English, synthetic
  data), keyboard, restart through the task, memory; full pass before each merge.

## Threat model

WPF option: more places that display untrusted strings (`Visible` everywhere), XAML only from the
resource of the executable. WebView2 fallback (abandoned on 2026-11-09, kept for the record): XSS surface and bridge between the host and the page, a new
boundary to be described in `docs/security/threat-model.md` before any code (content from the executable's resources only,
strict CSP and Trusted Types, neither JS framework nor npm, `textContent`, closed bridge, native elevated assistant, data under
`%LOCALAPPDATA%`, missing runtime stated and never installed silently).

## Risks

Cost of the pilot unknown as long as the build is not tried; WPF memory not measured; mix of WinForms and WPF
during the transition; a nicer screen can promise more than the service does; same model for the author and the
pre-reviewer.

## Entry in `CLAUDE.md`

Written on 2026-11-03, with the maintainer's authorization (« Ok pour modifier Claude. Md je t'autorise » (OK to modify Claude.md, I authorize you)); text
proposed then, taken up in `CLAUDE.md`:

- Section 2, rule 1: "Only exceptions: the « Interface and installation assistant » phase, phases 7, 8 and
  9 (section 5), …" (the first-run assistant is a new capability).
- Section 5, new point before phase 7: "« Interface and installation assistant » phase, before phase 7.
  Opened by the maintainer on 2026-11-03, with these words: « fais la refonte avant la phase 7 » (do the redesign before phase 7). Starts once the
  phase 6 fixes are merged and this point recorded; phase 7 starts once this phase is validated by the review and by
  cryptobones-1337. Decisions, breakdown and safeguards: `docs/roadmap/interface.md`. As for phases 3, 4 and 6,
  the local VM proof stands in for GitHub CI for its PRs; nothing changes for distribution."
- Section 5, phase 7: add "and after the « Interface and installation assistant » phase" to its start
  condition.

## Service texts in the English interface (auditor's review of 2026-11-21, point 3)

Decision of the maintainer (2026-11-21): the service emits stable codes (rule, ATT&CK technique, collection
identifier, state) and the interface translates them through its tables, as for response kinds and states. The reasons
of the alerts keep their French text: the hash of the exceptions (`apprentissage::signature_avec`), `mitre::enrichir`
and the interface tests on "MENACE" and "BLOQUÉ" read it; a code and parameters will be added to it.
Since the auditor's review of 2026-11-22 (point 2), the hash of the exceptions no longer reads the ATT&CK techniques
nor the advice at all: the rule and a behavior code set by the producer (`Comportement`, see
`docs/detection/modele-evenement.md`). A technique name or identifier can be reworded or translated without making
an exception obsolete; the exceptions of a previous format are counted and stated in the Health page ("Exceptions"
row), never lost silently. The interface translates
each label separately (`L.Mitre`), since an alert can carry several techniques.

- **Lot 1 (done)**: readable names of the 25 collections (alert banner, detail of an alert, Health page), Sysmon
  missing replaced by WMI stated by a neutral line with its real consequence (partial WMI: very short programs
  possibly missed, PRC-001 to PRC-005 degraded) instead of "disabled", missing consequences (Sessions, ConfigDns, FiltrageDns),
  techniques and advice of `mitre.rs` translated through the table (a text reworded without its translation fails
  `textes_du_service_traduits_dans_l_interface_lot1`), advice that referred to the old interface ("clic droit",
  "onglet") fixed in both languages.
- **Remaining**: reasons of the alerts (about 120 templates), reasons of the collections (about 35), fixed destinations (about
  30), titles and messages of the SIEM (about 25), SAN-* findings, notifications sent outside (French only).
