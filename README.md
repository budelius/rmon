# rMon

A Rust process explorer for Windows that tracks per-process CPU and GPU usage
over time. Ships as three binaries sharing one core sampling/storage crate:

- `rmon` (crate `rmon-cli`) — headless snapshot/record CLI
- `rmon-tui` — live terminal dashboard (ratatui)
- `rmon-gui` — live desktop dashboard (egui/eframe)

## Workspace layout

```
crates/
  rmon-core/  sampling (CPU + GPU), SQLite storage, rolling in-memory history
  rmon-cli/   `rmon snapshot` / `rmon record`
  rmon-tui/   terminal dashboard
  rmon-gui/   desktop dashboard
```

## GPU data source

Per-process GPU utilization comes from two sources, tried in order:

1. **NVML** (NVIDIA only) — more accurate SM/compute utilization, used when an
   NVIDIA driver is present.
2. **PDH "GPU Engine" counters** (vendor-agnostic) — the same data source
   Task Manager's GPU column uses. Works for AMD/Intel/NVIDIA on any WDDM
   driver, used as a fallback.

If neither is available, GPU columns read `0.0` and the UI shows a warning.

## Usage

```powershell
# One-off ranked snapshot of current CPU/GPU usage
cargo run -p rmon-cli -- snapshot --top 20
cargo run -p rmon-cli -- snapshot --top 20 --tree   # as a parent/child process tree

# Record continuously to SQLite (and optionally CSV) until Ctrl+C
cargo run -p rmon-cli -- record --db rmon.sqlite --csv rmon.csv --interval-ms 1000

# Live terminal dashboard
cargo run -p rmon-tui

# Live desktop dashboard (has its own "record to SQLite" toggle)
cargo run -p rmon-gui
cargo run -p rmon-gui -- --minimized   # start hidden in the tray (used by autostart)
```

Both live dashboards show, per process: current CPU%/GPU% plus an inline
sparkline of each over the last ~30 samples, and can switch between a flat
ranked list and a parent/child process tree. Both also have a live
substring search box and a header line with CPU/GPU temperature and
throttle status (see below).

### Sorting

Two independent axes, both available in the CLI (`--tree`/`--subtree`), TUI
(`c`/`g`/`t`, `a`, `s`), and GUI (buttons in the header):

- **Metric**: CPU%, GPU%, or CPU%+GPU%.
- **Window**: *instant* (current sample) or *accumulated* — total usage
  integrated over however long rMon has been running this session, up to a
  24h rolling cap (`RollingHistory::accum_window()`; this is in-memory only
  and does not survive a restart — the header always shows how much of the
  window is actually covered so far).
- **Tree ranking**: in tree view, ranking normally uses each process's own
  usage. Toggling "subtree total" (`s` in the TUI, a checkbox in the GUI)
  instead ranks by the summed usage of the process *and all its
  descendants* — so e.g. a browser's main process outranks unrelated
  processes based on the total usage of all its renderer/GPU-process
  children, not just its own (often near-zero) share.

In the GUI, the process table's column headers (PID, Name, CPU%, GPU%, Src)
are also independently clickable: clicking one sorts by that column, and a
▲/▼ marks the active one — click again to reverse direction. This is on top
of, not instead of, the header buttons above (which drive the CPU%/GPU%
metric and instant/accumulated window); clicking a CPU% or GPU% column
header is equivalent to clicking the matching button. Columns are also
individually resizable by dragging their border. Clicking anywhere on a row
selects it (not just the PID cell), and `↑`/`↓` move the selection up/down
through the current row order once no text field has focus.

### Open files

Press `f` (TUI) or click "📂 open files" (GUI) on a selected process to see
the files it currently has open, with its own live substring search
(`rmon files <pid>` in the CLI). This is inherently on-demand — it walks
the process's kernel handle table via the same undocumented NT APIs
Process Explorer / Sysinternals `handle.exe` use (there is no documented
Win32 API for this), so results appear after a short background scan
(typically well under a second, up to a few seconds for processes with a
very large handle table) rather than instantly. Two real limitations fall
out of that:

- Seeing another user's or a protected/system process's open files
  requires `SeDebugPrivilege`, which requires running rMon as
  Administrator. Without it, you'll only see your own processes' files.
- A small number of handles (typically named pipes waiting on a peer) can
  hang the underlying kernel query indefinitely. Each file-name lookup runs
  on its own thread with a ~200ms timeout and is abandoned (not killed —
  Windows has no way to force that) if it doesn't return in time; the scan
  reports how many handles this happened to instead of hanging or silently
  under-reporting.

### TUI keys

`↑`/`↓` or `j`/`k` select a process (or scroll the file list) · `c`/`g`/`t`
sort metric · `a` toggle instant/accumulated · `s` toggle subtree/own
ranking (tree view) · `p` toggle flat/tree view · `f` open the selected
process's files · `/` search (Enter to keep, Esc to clear) · `r` rescan
(files view) · `Esc` back to the process view (or quit, from the process
view) · `q` quit.

### Tray icon and autostart (GUI)

`rmon-gui` has a system tray icon so it can keep sampling (and recording, if
enabled) in the background instead of quitting: closing the window (✕)
hides it to the tray rather than exiting; left-clicking the tray icon or its
"Show rMon" menu item brings the window back, and "Quit" is the only way to
actually terminate the process. The tray icon is drawn procedurally at
startup (no icon asset needed) and if tray creation fails for any reason
(e.g. no tray support on the platform), the app falls back to the window's
✕ actually quitting.

The "start with Windows" checkbox in the header writes (or removes) a
per-user `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` entry
pointing at the current executable with `--minimized` — no Administrator
rights needed, and unchecking it fully reverses it. A `--minimized` launch
starts with the window hidden, straight into the tray, so logging in
doesn't pop a window up.

## Temperature and throttle telemetry

- **GPU** (NVIDIA only, via NVML): per-GPU temperature and whether NVML
  reports an unambiguous thermal throttle reason (`SwThermalSlowdown` /
  `HwThermalSlowdown`) — i.e. clocks are being cut specifically because of
  temperature, not just power capping or idle states.
- **CPU**: Windows has no vendor-neutral "CPU temperature" or "throttled
  because of temperature" API without a kernel driver (which is how tools
  like HWiNFO read MSRs directly — rMon deliberately doesn't ship one).
  Instead:
  - Temperature comes from the ACPI thermal zone (`MSAcpi_ThermalZoneTemperature`
    over WMI) when the system exposes one — on many machines it doesn't, in
    which case it reads `n/a`.
  - "Possibly throttled" is a heuristic: current clock speed is well below
    the rated max (`Win32_Processor`) while overall CPU load is high. The
    cause (thermal vs. power vs. something else) is **not** confirmed —
    unlike the GPU signal, which NVML reports directly.

## Data model

Every sample is one row per process: `(timestamp, pid, ppid, name,
cpu_percent, gpu_percent, gpu_source)`. `rmon-core::Store` persists these to
SQLite; `rmon-core::RollingHistory` keeps an in-memory rolling window (5
minutes of raw samples for the live charts/sparklines, plus a 1-minute-
bucketed accumulator good for up to 24h) indexed by pid so both are O(1)
per-process lookups. `rmon-core::build_tree` turns a flat process list into
a depth-first parent/child ordering for the tree view, optionally ranked by
subtree-total usage instead of each process's own. `rmon-core::list_open_files`
does the on-demand kernel-handle-table walk behind the Files view.

## Diagnostics (crash reporting)

All three binaries call `rmon_core::observability::init_sentry()` at
startup and report panics/errors to Sentry/rustrak, plus structured events
to ELK. This is env-var driven and a no-op until `SENTRY_DSN` (and/or
`ELASTICSEARCH_HOST`) is set — see `crates/rmon-core/OBSERVABILITY.md` for
the full list of environment variables and write transports. The module was
scaffolded with [ojiichan](https://gitlab.com/martin-wieser/ojiichan) so it
follows the same conventions as the Python services reporting to the same
stack.

## Building a Windows installer

**Download the latest build:** every push to `master` runs the `installer`
CI job on a GitLab.com Windows SaaS runner and publishes the resulting
`.msi` as a job artifact, so the latest one is always at:
<https://gitlab.com/martin-wieser/rmon/-/jobs/artifacts/master/download?job=installer>
(no login needed -- the project is public). See `.gitlab-ci.yml`: the
`build` job compiles, tests, and clippy-checks the whole workspace (on
merge requests and `master`); `installer` additionally installs the WiX
Toolset via Chocolatey and runs `cargo wix` (`master` only).

To build one locally instead:

`crates/rmon-gui` is set up for [cargo-wix](https://github.com/volks73/cargo-wix)
to produce a `.msi`:

```powershell
cargo install cargo-wix        # once
# then install the WiX Toolset v3 (candle.exe/light.exe), e.g.:
winget install --id WiXToolset.WiXToolset

cargo wix -p rmon-gui           # from the repo root; installer lands in target\wix\
```

The exe's icon (`crates/rmon-gui/assets/rmon.ico`) is embedded as a Win32
resource by `build.rs` (via `winresource`) and also used for the Start Menu
shortcut the installer creates. `crates/rmon-gui/examples/gen_icon.rs`
regenerates that `.ico` from the same procedural design as the tray/window
icon (`src/icon.rs`) if you ever change it — run
`cargo run -p rmon-gui --example gen_icon` and re-commit the result.
