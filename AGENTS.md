# AGENTS.md

## Project overview

rMon is a Windows-only Rust workspace for process CPU/GPU monitoring. Keep shared sampling and OS integration in `rmon-core`; the CLI, TUI, and GUI should consume that shared API rather than duplicating Win32 logic.

- `crates/rmon-core`: sampling, process trees, history, storage, ports/files, telemetry, and observability
- `crates/rmon-cli`: `rmon` commands and the stdio MCP server
- `crates/rmon-tui`: ratatui dashboard
- `crates/rmon-gui`: egui dashboard, tray/autostart support, and WiX installer source

## Development

Run commands from the workspace root. A native Windows MSVC toolchain is required because `rmon-core` uses Win32, WMI, PDH, and NVML APIs.

```powershell
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace --all-targets
```

For a quick CLI run:

```powershell
cargo run -p rmon-cli -- snapshot --top 20
cargo run -p rmon-cli -- mcp
```

## Change guidelines

- Preserve best-effort behavior for inaccessible/protected processes; one failed process lookup must not fail a system-wide scan.
- Keep expensive handle/file scans on demand and bounded. Port-table reads are system-wide and can be filtered after collection.
- CPU/GPU percentages are sample deltas: tests and callers may need a warm-up sample.
- The MCP server uses stdout exclusively for JSON-RPC framing. Never print diagnostics or progress to stdout while serving MCP; use stderr/logging.
- WMI/COM-backed sampler state is thread-affine. Do not move sampling between arbitrary async worker threads.
- Keep GUI/TUI sampling work off rendering/input paths when it can block.
- Observability is environment-driven and must remain a no-op when its variables are unset. See `crates/rmon-core/OBSERVABILITY.md`.
- Do not commit `target/`, SQLite/CSV runtime output, or `hook_outputs/`.

## Packaging

The GitLab `installer` job builds `target/release/rmon.exe` before invoking cargo-wix because the MSI contains both `rmon-gui.exe` and `rmon.exe`. If either binary or its path changes, update `.gitlab-ci.yml`, `crates/rmon-gui/wix/main.wxs`, and the download section in `README.md` together.

Local package commands:

```powershell
cargo build --release -p rmon-cli
cargo wix -p rmon-gui
```
