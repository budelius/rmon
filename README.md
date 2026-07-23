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

### TUI keys

`↑`/`↓` or `j`/`k` select a process · `c`/`g`/`t` sort by CPU / GPU / combined ·
`p` toggle flat/tree view · `/` search by name (Enter to keep, Esc to clear) ·
`q`/`Esc` quit.

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
minutes by default, indexed by pid) for the live charts and sparklines
without touching disk. `rmon-core::build_tree` turns a flat process list
into a depth-first parent/child ordering for the tree view, using `ppid`.
