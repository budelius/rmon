# Changelog

What changed in each build, newest first. rMon's **what's new** tab shows
the section matching the version you are running, alongside the commit and
build time of the running binary, so "am I on the latest?" has an answer
that does not depend on remembering what you installed.

## 0.2.0 — 2026-08-25

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
- **A hidden window samples every 10s instead of every second.** Minimized
  or tucked in the tray counts. Not paused — accumulated totals and leak
  trends integrate CPU over elapsed time, so a slower cadence still adds
  up correctly, and 10s is exactly the per-tick cap the history keeps.
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
