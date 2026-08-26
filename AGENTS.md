# AGENTS.md

## Project overview

rMon is a Windows-only Rust workspace for process CPU/GPU monitoring. Keep shared sampling and OS integration in `rmon-core`; the CLI, TUI, and GUI should consume that shared API rather than duplicating Win32 logic.

- `crates/rmon-core`: sampling, process trees, history, storage, ports/files, telemetry, and observability
  - `pawnio.rs` + `sensors/`: kernel-level hardware access (CPU thermal MSRs, Super I/O fan tachometers) through the PawnIO driver, with vendored signed module blobs in `vendor/pawnio/`
- `crates/rmon-agent`: LLM agent core (OpenAI-compatible transport, read-only tools over `rmon-core`, approval-gated actions)
- `crates/rmon-cli`: `rmon` commands and the stdio MCP server
- `crates/rmon-tui`: ratatui dashboard
- `crates/rmon-gui`: egui dashboard, tray/autostart support, and WiX installer source

## Development

Run commands from the workspace root. A native Windows MSVC toolchain is required because `rmon-core` uses Win32, WMI, PDH, and NVML APIs.

```powershell
rustup update stable          # CI installs stable fresh on every run
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace --all-targets
```

Update the toolchain before trusting a green clippy run. `.gitlab-ci.yml`
bootstraps `stable` from scratch each pipeline, so CI is always on the
newest release while a dev machine can sit several behind — and clippy
gains lints in every one of them. A local pass on an older toolchain is not
evidence the build job will pass; it has already cost a red pipeline over
a lint that did not exist locally.

`-D warnings` also stops at the first crate that trips, which hides the
rest. To see everything in one go, drop the deny flag:
`cargo clippy --workspace --all-targets` and read all the warnings.

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
- Keep GUI/TUI sampling work off rendering/input paths when it can block. In the GUI this is `crates/rmon-gui/src/sampling.rs`: the `Sampler` is created on, and never leaves, one dedicated thread. Two invariants there are easy to break — the UI must call `mark_alive()` every frame (eframe stops calling `App::ui` while the window is minimized, so without it rMon samples forever into a channel nobody drains), and the sampling interval must stay derived from measured cost rather than hardcoded, since a sample costs a few ms on a quiet box and ~100ms on a busy one.
- Anything recomputed per tick must be cheap at the *largest* history rMon retains, not just at startup. Trend analysis walks every pid's bucketed series, so it runs on its own slower timer; check the growth curve before adding another per-tick pass over history.
- Kernel-backed sensors are strictly optional. rMon never installs the PawnIO driver and must degrade to the HWiNFO/ACPI fallbacks (and say so) when it is absent, when rMon isn't elevated, or when the hardware isn't recognised.
- Do not rebuild or substitute the blobs in `vendor/pawnio/`: the driver only accepts modules carrying the upstream signature. Update them by re-vendoring a PawnIO.Modules release and bumping `MODULES_VERSION`.
- Super I/O access must hold the `Access_ISABUS.HTP.Method` mutex, and skip the read rather than block when another tool holds it. Adding fan *writes* means also handling the conflict with a running FanControl and restoring the initial PWM state on exit.
- Keep measured and inferred throttling distinguishable all the way to the UI (`cpu_throttle_confirmed`); never render a heuristic guess with the same words as a hardware-reported fact.
- The analysis agent must stay unable to change the machine. `propose_kill_process` returns a proposal; the kill runs from the UI's button handler only. Do not add a tool that mutates state without an explicit human approval step, and keep telling the model that nothing was executed.
- Tool output must preserve the "measured zero" vs "could not measure" distinction as `null`. A model handed a fabricated zero will rule out causes it has no evidence about.
- Installed-program inventory is best-effort Win32/MSI Uninstall-registry data, not a complete Store/portable-app inventory. `ParentKeyName` links and observed process parentage must never be presented as a universal package dependency graph, and session inactivity must never be labeled “unused” or “safe to uninstall.” rMon does not execute uninstall commands.
- LLM credentials may come from `RMON_LLM_API_KEY`/`OPENAI_API_KEY` or the Settings UI. Saved keys must remain DPAPI/Windows-Hello protected and must never be persisted in plaintext, SQLite, or logs.
- Observability is environment-driven and must remain a no-op when its variables are unset. See `crates/rmon-core/OBSERVABILITY.md`.
- Do not commit `target/`, SQLite/CSV runtime output, or `hook_outputs/`.

## Packaging

The GitLab `installer` job builds `target/release/rmon.exe` before invoking cargo-wix because the MSI contains both `rmon-gui.exe` and `rmon.exe`. If either binary or its path changes, update `.gitlab-ci.yml`, `crates/rmon-gui/wix/main.wxs`, and the download section in `README.md` together.

Local package commands:

```powershell
cargo build --release -p rmon-cli
cargo wix -p rmon-gui
```
