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

# TCP/UDP endpoints (system-wide, or for one process)
cargo run -p rmon-cli -- ports --listening
cargo run -p rmon-cli -- ports 1234

# Search open files and ports across every process at once
cargo run -p rmon-cli -- search "chrome"

# Hardware health: WHEA event log entries, BIOS version, CPU microcode revision
cargo run -p rmon-cli -- health --days 7

# MCP server (stdio) for MCP clients such as Claude Desktop/Code
cargo run -p rmon-cli -- mcp

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

### Listening ports

Every process detail view (the GUI's right-hand panel, the TUI's history
panel) shows a "Listening ports" section for the selected process: its TCP
`LISTEN` and bound UDP endpoints. Unlike open files, this comes from a
single system-wide `GetExtendedTcpTable`/`GetExtendedUdpTable` call
(`rmon-core::list_all_ports`) refreshed every tick — no elevation, no
handle-table walk, no per-process cost — so it's just filtered by pid for
display (`rmon ports [pid]` in the CLI; add `--listening` to drop
established/non-listening rows).

### Search across all processes

Click "🔎 search all" (GUI), press `S` (TUI), or run `rmon search <query>`
(CLI) to search open files and TCP/UDP ports across *every* process at
once, not just the selected one:

- **Ports** match instantly against the already-cached system-wide port
  table — pid, process name, protocol, address, or port.
- **Open files** require an explicit scan (a button/key in the GUI/TUI, or
  a full scan is where the CLI's `search` starts by default — pass
  `--ports-only` to skip it): `rmon-core::list_open_files_many` fans the
  existing single-process `list_open_files` scan out across every process,
  bounded to `DEFAULT_SCAN_WORKERS` (8) concurrent process scans so a
  system with hundreds of processes doesn't spawn unbounded threads at
  once. Same best-effort rules as the single-process Files view apply per
  process (inaccessible processes are skipped, not fatal).

### Historic process tree (exited parents)

A live snapshot's `ppid` breaks the moment a parent exits — its children
just become orphans (badged `⚠ orphan`) with no record of who they used to
belong to. Tree view fixes this when it can: rMon tracks process
start/exit via the `Microsoft-Windows-Kernel-Process` ETW provider (needs
Administrator), which records each process's parent PID *at the moment it
started* rather than reading it live — so that record survives the parent
dying. When building the tree, `rmon-core::merge_recent_exits` walks an
orphan's parent chain through that exit history (up to 8 hops back,
`DEFAULT_GHOST_MAX_DEPTH`) and reconnects it under synthetic "ghost" nodes
for any exited ancestors it can identify, instead of promoting every
orphan straight to a root. Ghost nodes render dimmed with a "👻 exited"
marker (GUI and TUI) — they have no CPU/GPU history, since they were never
actually sampled. The MCP server's `process_tree` tool does the same
reconnection (`"is_ghost": true` on those rows), and its `recent_exits`
tool exposes the raw exit history directly.

This only works going forward: a chain can only be reconstructed for
processes whose entire start-to-exit lifetime happened while rMon was
running elevated. It can't recover lineage from before that — Windows
doesn't retain process-parentage history by default (Sysmon or Windows'
own Process Creation auditing, event 4688, are the standard ways to get
that further back, neither of which rMon uses today).

### Hardware health (WHEA events, BIOS, microcode)

Accurate temperature alone never confirms silicon degradation — that's
usually inferred from new instability under load, actual hardware-reported
faults, or whether your BIOS/CPU microcode has a vendor's known fix (e.g.
Intel's 13th/14th-gen voltage erratum). Open "🩺 Hardware health" from the
GUI's App menu, press `H` (TUI), or run `rmon health` (CLI) for:

- **WHEA events** — `Microsoft-Windows-WHEA-Logger` entries from the
  System event log (`rmon-core::check_hardware_health`), with counts by
  level (Error/Warning/Information) and the most recent entries shown.
  An `Error`-level entry is real hardware-reported evidence; by itself it
  still doesn't confirm degradation.
- **BIOS version/release date** and **CPU microcode revision** (the same
  registry technique CPU-Z/HWiNFO use, no kernel driver needed) — facts to
  cross-reference against your motherboard/CPU vendor's own advisories.
  rMon deliberately doesn't try to know which versions fix which errata,
  since that guidance changes over time and varies by vendor.

This is genuinely slow — `Win32_NTLogEvent` (the only way to read the event
log via WMI without a separate `EvtQuery`/`wevtapi.dll` FFI layer) has no
useful server-side filtering beyond `Logfile`/`SourceName`, so a query can
take anywhere from under a second to 30+ seconds depending on how often the
system logs WHEA entries. The GUI/TUI run it on a background thread (same
on-demand philosophy as the Files scan) so it doesn't freeze the UI; the
CLI and MCP tool just take as long as they take.

### TUI keys

`↑`/`↓` or `j`/`k` select a process (or scroll the file/search/health list)
· `c`/`g`/`t` sort metric · `a` toggle instant/accumulated · `s` toggle
subtree/own ranking (tree view) · `p` toggle flat/tree view · `f` open the
selected process's files · `S` search open files and ports across every
process · `H` hardware health (WHEA events, BIOS, microcode) · `/` search
(Enter to keep, Esc to clear) · `r` rescan (files/health view) · `Esc` back
to the process view (or quit, from the process view) · `q` quit.

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

## MCP server

`rmon mcp` runs an [MCP](https://modelcontextprotocol.io) server over
stdio (via the official [`rmcp`](https://crates.io/crates/rmcp) Rust SDK),
so any MCP client — Claude Desktop, Claude Code, etc. — can query a running
system's process/network/file state directly, without a GUI/TUI open. Add
it to a client's MCP server config the normal way, pointing at
`rmon mcp` (or the built `rmon.exe mcp`). It exposes eight read-only tools:

- `snapshot` — process list ranked by combined CPU%+GPU%, plus system-wide totals.
- `process_tree` — the same, as a parent/child tree (optionally ranked by subtree totals). Also
  reconnects exited parents via ETW exit history the same way the GUI/TUI tree views do (see
  "Historic process tree" above) — reconnected rows carry `"is_ghost": true` and have no
  CPU/GPU data, since they were never actually sampled.
- `recent_exits` — the raw ETW-tracked exit history `process_tree` reconnects orphans from:
  every process that started and fully exited since the MCP server itself started, with
  wall-clock duration and exit code. Needs Administrator; reports why it's unavailable
  otherwise rather than silently returning nothing.
- `process_detail` — one pid's basic info, open handle count, open files, and listening ports.
- `list_ports` — TCP/UDP endpoints system-wide or for one pid, with optional listening-only/substring filtering.
- `search_open_files` — substring search over open file paths across every process.
- `system_metrics` — CPU/GPU thermal and throttle telemetry.
- `hardware_health` — WHEA event log entries, BIOS version, CPU microcode revision (see
  "Hardware health" above; this one can legitimately take up to ~30 seconds).

CPU%/GPU% are deltas since the previous sample, same as everywhere else in
rMon, so consecutive `snapshot`/`process_tree` calls (from any client) are
what make them meaningful — the very first call after the server starts
warms up internally rather than reporting all zeros. The sampler (which
holds a WMI connection for CPU thermal data) runs on one dedicated
background thread for the server's lifetime, since WMI's COM connection is
tied to the thread that created it; every tool call reaches it through a
request/response channel instead of touching it from whichever async
worker thread happens to handle that call.

## Data model

Every sample is one row per process: `(timestamp, pid, ppid, name,
cpu_percent, gpu_percent, gpu_source)`. `rmon-core::Store` persists these to
SQLite; `rmon-core::RollingHistory` keeps an in-memory rolling window (5
minutes of raw samples for the live charts/sparklines, plus a 1-minute-
bucketed accumulator good for up to 24h) indexed by pid so both are O(1)
per-process lookups. `rmon-core::build_tree` turns a flat process list into
a depth-first parent/child ordering for the tree view, optionally ranked by
subtree-total usage instead of each process's own. `rmon-core::merge_recent_exits`
runs before `build_tree` to splice in synthetic "ghost" nodes for exited
ancestors reconnected from ETW-tracked exit history (see "Historic process
tree" above). `rmon-core::list_open_files`
does the on-demand kernel-handle-table walk behind the Files view (fanned
out across every process by `list_open_files_many`, behind the cross-process
search). `rmon-core::list_all_ports` reads the system-wide TCP/UDP table
(`GetExtendedTcpTable`/`GetExtendedUdpTable`) behind the ports views.
`rmon-core::check_hardware_health` queries WHEA event log entries (via WMI's
`Win32_NTLogEvent`), BIOS info (`Win32_BIOS`), and the CPU microcode
revision (registry) behind the hardware-health views.

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
CI job on a GitLab.com Windows SaaS runner and publishes both the standalone
`rmon.exe` CLI and the `.msi` as job artifacts. The MSI installs the GUI and
CLI (including the ports, search, and MCP commands) and adds their directory
to `PATH`. Download the latest artifact bundle at:
<https://gitlab.com/martin-wieser/rmon/-/jobs/artifacts/master/download?job=installer>
(no login needed -- the project is public). The standalone CLI is also
available directly at:
<https://gitlab.com/martin-wieser/rmon/-/jobs/artifacts/master/raw/target/release/rmon.exe?job=installer>

See `.gitlab-ci.yml`: the `build` job compiles, tests, and clippy-checks the
whole workspace (on merge requests and `master`); `installer` additionally
builds the release CLI, installs the WiX Toolset via Chocolatey, and runs
`cargo wix` (`master` only).

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
