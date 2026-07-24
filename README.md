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
