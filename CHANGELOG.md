# Changelog

What changed in each build, newest first. rMon's **what's new** tab shows
the section matching the version you are running, alongside the commit and
build time of the running binary, so "am I on the latest?" has an answer
that does not depend on remembering what you installed.

## Unreleased

### CPU percentages say which percentage they are

- Per-process `cpu_percent` is percent of **one core**, so a single-threaded
  process saturating a thread reads `100` on a 32-core machine. Reported
  bare, that reads as "consuming the whole machine" when it is about 3% of
  it — and it repeatedly sent investigations after the wrong process,
  including rMon itself three separate times.
- Snapshots now carry `logical_cores`, and every reporting surface pairs the
  per-core figure with a machine-relative one: `cpu_percent_of_machine` in
  the MCP and Analyze tool output, `CPU%/core` column headers in the CLI,
  TUI and GUI, and totals expressed as a share of the machine instead of a
  number that runs past 100. MCP results carry a `cpu_units` note so the
  convention travels with the data rather than living in a tool description.
- Ranking is unchanged: dividing every process by the same core count
  preserves the order. What changes is that the magnitude can now be read
  correctly.

### Orphan burners

- New trend verdict: a process still burning at least half a core whose
  parent has exited, so nothing is left that would notice or reap it. This
  is the runaway-background-process shape — a search or build whose shell
  died and that will spin until reboot.
- Being orphaned is on its own completely ordinary (anything launched from a
  closed shell qualifies), so it is reported as informational `orphaned` and
  never flags on its own; the CPU thresholds carry the verdict. Orphan
  burners sort above leak suspects, because they are wasting a core now
  rather than creeping.

### The WHEA scan is ~130x faster

- Hardware-health checks read the System channel through `EvtQuery`
  (`wevtapi`) instead of WMI's `Win32_NTLogEvent`. WMI cannot use the
  channel's per-provider index, so it walked the log record by record and
  its cost scaled with the *window*. Measured on a 30,138-record System log:

  | lookback | `Win32_NTLogEvent` | `EvtQuery` |
  |----------|-------------------:|-----------:|
  | 7 days   |            ~870 ms |    ~130 ms |
  | 30 days  |          ~6,690 ms |     ~47 ms |
  | 365 days |         ~43,945 ms |     ~52 ms |

- The default lookback rises from 7 days to **30**: the small window existed
  only to limit the WMI cost, and `EvtQuery` is flat in lookback.
- Reports carry `whea_query_ms`, so an expensive scan is attributable rather
  than being blamed on whatever process happens to be on screen.
- `Critical`-level entries now count toward `whea_error_count` alongside
  `Error`, matching what a caller asking "did this machine report a hardware
  fault" means.

## 0.2.0 — 2026-08-25

### Installed programs, provenance, and software diagnosis

- New **programs** tab and `rmon programs` command inventory conventional
  Win32/MSI installs from all per-user/per-machine 32/64-bit Uninstall
  registry views.
- Full executable paths associate running processes with install locations;
  parent chains expose launched children and inclusive resources, so a
  launcher such as Warp can show that it started `find.exe`.
- Known installer parent/dependent entries stay distinct from observed
  process parentage. rMon says explicitly that Windows does not expose a
  universal Win32 dependency graph or reliable last-used timestamp.
- Conservative **removal review** excludes active/session-observed software,
  system components, updates, entries without uninstallers, and entries with
  known dependents. Results are candidates to investigate, never “safe.”
  rMon does not run uninstall commands.
- Process and program details can ask Analyze for a purpose/suspicion/removal
  assessment. The model receives paths, publisher metadata, command lines,
  process lineage, and measured resources, and is told to separate evidence
  from familiarity and missing information.

### Windows Hello on the stored key

- **Settings → Analyze (LLM)** gained *Require Windows Hello to use this key*.
  With it on, reading the key needs a face, fingerprint, or PIN — closing the
  gap the DPAPI-only seal openly admits to, where any code already running as
  you can decrypt it silently.
- Hello signs rather than encrypts, so the signature becomes the secret: a
  stored random challenge is signed (deterministically, RSASSA-PKCS#1 v1.5)
  and the 256-byte result is handed to DPAPI as its entropy. The two
  protections compose — opening the blob needs your DPAPI master key *and* a
  live gesture. No cipher is implemented here; it is the same DPAPI call with
  different entropy.
- Turning it on clears the unprotected copy. Leaving one behind would keep a
  route around the gesture.
- One gesture per session rather than per question: the analyze tab has an
  **Unlock with Windows Hello** button, and the key is held in memory only
  until rMon exits.
- The checkbox hides itself where Hello is not enrolled, and a cancelled
  gesture resets it, so it never claims a protection that was not applied.
- **Losing the Hello credential loses the key.** A PIN reset, biometric
  re-enrolment, or TPM clear destroys it, and the gateway cannot reissue one —
  a lost key must be replaced and the old alias revoked.

### rMon costs a lot less to run

- **Sampling moved off the UI thread.** One tick asks the kernel for every
  process *and every thread* on the machine; on a busy box (1,352
  processes, 25,300 threads) that single call takes 85-100ms. rMon was
  paying it inside the repaint, so the window stalled for a tenth of a
  second every second. It now runs on its own thread.
- **The interval adapts to what a sample actually costs.** rMon measures
  each sample and spaces the next one so sampling stays under ~5% of one
  core. Ordinary machines are unaffected and keep the 1s tick; the loaded
  machines you would open a monitor to investigate back off on their own,
  instead of the monitor becoming part of the problem. **Settings →
  Sampling** shows the measured cost and lets you pin a fixed interval.
- **A minimized rMon samples nothing at all.** The window stops being
  drawn when you minimize it, and the sampling thread now requires proof
  that frames are still happening before it takes a sample — so it costs
  nothing while minimized, and picks up again the moment you restore it.
- **Tucked in the tray, it samples every 10s.** A tray-hidden window keeps
  drawing, so that case gets a slow cadence rather than a stop:
  accumulated totals and leak trends integrate CPU over elapsed time, so
  they still add up correctly, and 10s is exactly the per-tick cap the
  history keeps.
- **Leak/idle trend analysis runs every 30s, not every tick.** Its input
  series gains one point per minute and its verdicts need 30 minutes of
  history, so per-tick analysis was recomputing the same answer up to
  sixty times over — a cost that grew with every hour rMon stayed open.
- The system-wide port table is collected on the sampling thread too.

### About and what's new

- The About window is build provenance only: version, commit, dirty flag,
  build time, elevation, and a copy button. The changelog no longer scrolls
  underneath it.
- The **what's new** tab leads with the release notes for the version you
  are actually running, with the full history collapsed below it. A build
  whose version has no changelog entry now fails its own test rather than
  shipping an empty tab.

### Process-list navigation

- Removed the redundant **Process** menu. Its actions now live where the
  process does: right-click a row for open files, copy info, or kill.
- Process selection supports arrows, Page Up/Down, Home/End, and the numeric
  keypad. Left/right (keypad 4/6) collapse and expand tree rows.
- Added this changelog as a persistent **what's new** tab.

### Analyze tab — ask an LLM why the machine is slow

- New **analyze** tab. It runs a small agent over rMon's own telemetry:
  read-only tools for system metrics, the process list, per-process detail,
  and the throttle verdict.
- The agent **cannot act**. Its one action tool, `propose_kill_process`,
  returns a proposal that surfaces with kill/dismiss buttons; the kill runs
  from the button handler, never from the agent loop. The model is told
  explicitly that nothing was terminated.
- Readings rMon could not take are sent as `null`, never as zero. A model
  handed `"fraction_of_time_limited": 0` will confidently rule out a thermal
  cause it has no evidence about.
- Tool round-trips are capped, so a model that decides to enumerate every
  process one call at a time ends the turn rather than the budget.

### API key in the UI, encrypted at rest

- **Settings → Analyze (LLM)** takes the gateway key, model, and base URL.
  No more `setx` and restart.
- The key is sealed with DPAPI under your user account before it touches
  disk, in `%APPDATA%\rMon\config.json`. Copied to another machine or
  account, the file is unreadable. It is *not* protected from code already
  running as you — see the module docs for what that trade-off is.
- The model field is a picker populated from the gateway's own `/v1/models`,
  because a mistyped model is indistinguishable from a bad key until the
  first question fails.
- Saved settings take precedence over `RMON_LLM_API_KEY` / `OPENAI_API_KEY` /
  `RMON_LLM_MODEL` / `RMON_LLM_BASE_URL`, which still work as a fallback.
  The tab names which source is in effect.

### Hardware sensors read directly

- CPU temperature now comes from the CPU's own thermal MSRs via the PawnIO
  driver, not from HWiNFO's shared memory, so it works with no other tool
  running. Distance to TjMax and the throttle verdict come with it.
- Motherboard fan tachometers, temperatures, and voltages via the Super I/O
  chip (Nuvoton NCT6686D / NCT6796D and relatives).
- Throttling is *measured* from the MSR status bits where available and
  flagged as inferred from clock behaviour where not — the two are not
  presented as the same claim.
- Super I/O bank selection is cached rather than rediscovered every refresh,
  which was walking 255 logical devices twice per sample on the sampling
  thread. Chips with no fans connected are skipped and rescanned about once
  a minute.

### About and build provenance

- **App → About rMon** shows the version, the commit it was built from,
  whether that tree was dirty, the build time, and this changelog.
- The header carries the build time so a stale window is obvious at a glance.

## 0.1.0 — 2026-07-30

- Leak and idle trend analytics; sampling cost cut roughly tenfold.
- MCP server exposing snapshot/tree, per-process detail, ports, open-file and
  port search, and hardware health as tools.
- Historic process tree and ETW exit history, including reconnecting exited
  parents in the tree view.
- Sortable, resizable process table with subtree and accumulated ranking;
  tray icon; start-with-Windows; MSI packaging.
- Open-files and listening-ports views per process.
- GitLab CI: build, test, clippy, and a published installer artifact.
