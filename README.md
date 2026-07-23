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

# Record continuously to SQLite (and optionally CSV) until Ctrl+C
cargo run -p rmon-cli -- record --db rmon.sqlite --csv rmon.csv --interval-ms 1000

# Live terminal dashboard
cargo run -p rmon-tui

# Live desktop dashboard (has its own "record to SQLite" toggle)
cargo run -p rmon-gui
```

### TUI keys

`↑`/`↓` or `j`/`k` select a process · `c`/`g`/`t` sort by CPU / GPU / combined ·
`q`/`Esc` quit.

## Data model

Every sample is one row per process: `(timestamp, pid, name, cpu_percent,
gpu_percent, gpu_source)`. `rmon-core::Store` persists these to SQLite;
`rmon-core::RollingHistory` keeps an in-memory rolling window (5 minutes by
default) for the live charts without touching disk.
