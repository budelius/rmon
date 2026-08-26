# rMon

A Rust process explorer for Windows that tracks per-process CPU and GPU usage
over time. Ships as three binaries sharing one core sampling/storage crate:

- `rmon` (crate `rmon-cli`) — headless snapshot/record CLI
- `rmon-tui` — live terminal dashboard (ratatui)
- `rmon-gui` — live desktop dashboard (egui/eframe)

## Workspace layout

```
crates/
  rmon-core/  sampling, installed-program inventory/attribution, storage, history
  rmon-agent/ read-only analysis agent and OpenAI-compatible transport
  rmon-cli/   `rmon snapshot` / `rmon record` / `rmon programs`
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

# Installed Win32/MSI programs, live processes, and conservative removal review
cargo run -p rmon-cli -- programs
cargo run -p rmon-cli -- programs --filter warp --active
cargo run -p rmon-cli -- programs --review

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

The GUI's left column is a tab strip — **processes · programs · suspects ·
analyze · sensors · health · exited · search · what's new · settings** — so every view is one click from
every other. (These were previously buried in the App menu, each opening a
panel with its own "back" button, which meant the only route from one view
to another ran through the process table.) The suspects tab shows its count
in the tab label when anything is flagged, so it can become urgent while
you're looking at something else. The sort/filter toolbar is specific to
the process table and hides on the other tabs.

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
selects it (not just the PID cell). `↑`/`↓`, Page Up/Down, Home/End, and the
numeric keypad navigate the current row order once no text field has focus;
left/right (keypad 4/6) collapse or expand tree rows. Right-clicking a row
opens its context menu for open files, copy info, explain/assess, and kill. The redundant
Process menu is gone.

### Installed programs, provenance, and removal review

The GUI's **programs** tab (and `rmon programs` in the CLI) reads the
per-machine/per-user, 32/64-bit Windows Uninstall registry views used by
classic Programs and Features. It shows publisher/version/location/size,
then associates live processes by their full executable path. Parent chains
are kept separately from package ownership, so a terminal such as Warp can
show `warp.exe → find.exe` and include the child in its live CPU/GPU/memory
total even though `find.exe` is a Windows executable rather than a Warp
binary.

The dependency view is deliberately honest about scope. Windows uninstall
entries expose some explicit `ParentKeyName` update/bundle relationships,
but there is no universal Windows package dependency graph for arbitrary
Win32 software. rMon shows those known links and the observed process tree;
it does not invent links from similar names. Portable executables and some
Store packages may also be absent from this registry inventory.

**Removal review** filters to entries that are not running/observed in this
rMon session, have a registered uninstaller, are not marked as a system
component/update, and have no known dependent uninstall entry. That means
“candidate to investigate,” never “safe to uninstall”: session inactivity is
not a reliable last-used timestamp, and unknown dependencies remain unknown.
rMon never runs an uninstall command.

Both process details and program details have **explain / assess** actions.
The configured analysis model gets the executable path, publisher/install
metadata, command line, parent/children, resource readings, and rMon's
path-based warning signals. It is instructed to separate familiar-purpose
knowledge from measured evidence, not call an unfamiliar/unsigned item
malware merely from its name, offer read-only verification commands, and
avoid declaring software safe to remove when usage/dependencies are unknown.

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
Intel's 13th/14th-gen voltage erratum). Open the GUI's **health** tab,
press `H` (TUI), or run `rmon health` (CLI) for:

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

### What rMon costs to run (GUI)

Sampling happens on its own thread, and how often it happens depends on
what a sample costs on your machine. Most of a sample is one
`NtQuerySystemInformation` call that returns every process *and every
thread* on the system, so the price is set by how loaded the box is: a few
milliseconds on an ordinary desktop, but 85-100ms on one carrying 1,350
processes and 25,000 threads. rMon measures each sample and spaces out the
next one to keep its own CPU use under about 5% of one core, so it stays a
1s tick where that is affordable and slows down where it isn't — rather
than becoming part of the problem on exactly the machines you opened it to
investigate. **Settings → Sampling** shows the measured cost and the
interval in effect, and lets you pin a fixed interval instead.

Two things make it cheaper still. Minimizing the window stops sampling
outright (Windows stops drawing the window, and rMon will not sample into
a screen nobody is updating); it resumes when you restore it. Hidden in
the tray, where the window does keep drawing, it drops to one sample every
10s — slow rather than stopped, because the accumulated-usage ranking and
the leak/idle trends integrate CPU over elapsed time and so still total
correctly at that cadence.

## Temperature, fans, and throttle telemetry

Throttling is the one system-wide condition that silently invalidates every
other number rMon shows: while a CPU is trimming duty cycle at its thermal
limit, or a GPU is in thermal slowdown, every per-process CPU%/GPU% figure
is measuring the *limit* rather than the workload, and nothing in the
process table hints that this is what happened. So rMon shows it in the
header, always — including when everything is fine, because a header that
only speaks up when something is wrong leaves "fine" and "we have no idea"
looking identical.

Alongside the live badge there's a **throttle strip**: one column per second
over the last five minutes, oldest on the left, with a summary such as
"throttled 3% of last 4m12s". Amber marks the CPU being held back, red a GPU
thermal slowdown, grey a tick where no thermal source could answer. Episodes
that distort a benchmark or stretch a compile are often over in seconds, so
the instantaneous badge alone would miss exactly the ones worth knowing
about.

### Where the numbers come from

Windows exposes no vendor-neutral API for CPU package temperature, TjMax, a
"throttled because of temperature" flag, or fan speed. Every tool that shows
those reads model-specific registers (MSRs) and legacy LPC I/O ports, which
are ring-0 only. rMon reads them itself, through **[PawnIO]** — the
sandboxed, signed kernel driver that LibreHardwareMonitor and FanControl
also moved to. Sources are tried strongest first:

1. **CPU MSRs, via PawnIO** (needs PawnIO installed and rMon running as
   Administrator). `IA32_TEMPERATURE_TARGET` gives this exact part's TjMax;
   `IA32_PACKAGE_THERM_STATUS` gives temperature as a digital readout *below*
   TjMax — so remaining headroom is the raw measurement rather than a
   derived guess — plus status bits saying whether the thermal control
   circuit is engaged right now, whether PROCHOT# is asserted, whether the
   part is at critical temperature, and whether it's being held back by a
   *power* cap instead of by heat. When this path is live, rMon reports
   throttling as measured fact (`cpu_throttle_confirmed`), not as a
   heuristic. Its sticky log bit also reveals whether throttling happened at
   all since boot, catching episodes shorter than the one-second sampling
   tick — shown as "has throttled since boot", never as a current state.
2. **The Super I/O CPU sensor, via the same direct SensorHub**, when package
   MSRs do not apply or cannot be opened. This is especially useful on AMD
   systems. A socket-only input is not misrepresented as package temperature.
3. **HWiNFO's export**, but only as a necessary CPU-temperature fallback
   when neither direct source can answer. HWiNFO must already be running
   with "Support of Value Sensors Bank" or "Shared Memory Support" enabled;
   rMon does not install or launch it. The GUI's full supplemental HWiNFO
   sensor tree is separate and off by default until explicitly enabled for
   the session.
4. **ACPI thermal zone** (`MSAcpi_ThermalZoneTemperature` over WMI) plus
   the kernel's processor-power clock ratio. On many machines the zone is
   absent, inaccurate, or not measuring the CPU package at all, and "throttled" here
   is only an inference from clocks running below the rated maximum under
   load — shown as "likely throttled", with the cause unconfirmed.

**GPU** telemetry is separate and needs no driver: NVML reports per-GPU
temperature and whether an unambiguous thermal slowdown
(`SwThermalSlowdown` / `HwThermalSlowdown`) is active, distinct from power
capping. NVIDIA only.

### Motherboard temperatures, voltages, and fans

The existing SensorHub reads all three classes directly from the
motherboard's Super I/O chip through PawnIO's `LpcIO` module; no HWiNFO or
.NET hardware-monitoring library is involved. NCT668x exposes named board,
VRM, PCH, socket, PCIe, and M.2 temperature channels plus fourteen voltage
channels. NCT67xx exposes routed temperature inputs and 8 mV voltage ADC
pins. On NCT67xx, rMon intentionally labels voltages as `VINn (ADC pin)`:
turning a pin voltage into a +5V/+12V rail requires motherboard-specific
resistor-divider data, and a generic scaling factor would look credible
while being wrong.

Fan tachometers live in the same Super I/O block (Nuvoton, ITE and Fintek
make nearly all of them). rMon identifies the chip over the LPC
configuration ports and reads its fan counters through PawnIO's `LpcIO`
module. Two Nuvoton families are decoded:

- **NCT67xx** (NCT6771F through NCT6799D): a banked register space, with
  fan speed as a 13-bit period counter — `RPM = 1.35e6 / count`.
- **NCT668x** (NCT6683D/6686D/6687D, used on MSI boards): a *paged EC
  space* with its own claim/release handshake on the page register, and
  fan speed as a direct 16-bit RPM value.

ITE IT87xx chips are identified and named but not read, because a
plausible-looking wrong RPM is worse than an honest "not decoded".

A board can carry a Super I/O on **both** configuration ports, and the one
that owns the fan headers is not necessarily the first to answer. The
machine this was developed on is exactly that: an NCT6796D-R sits at 0x4E
with every channel empty, while the NCT6686D at 0x2E has the actual fans.
rMon therefore keeps and reads every chip it finds — stopping at the first
match produces a confident, fully working read of nothing at all.

A channel with nothing spinning on it reads "no fan connected" rather than
"0 rpm", since an unused header and a stalled CPU fan must not look the
same. Readings above 40,000 RPM are rejected outright: an empty NCT67xx
channel reads `0xFF 0x1F`, which is a saturated counter but would decode to
a plausible-looking "65311 rpm" if it were read as a direct value.

The LPC bus has no arbitration of its own — reading a register means writing
an index and then reading a data port, so an interleaved access from another
tool makes both sides read the wrong register. rMon holds the conventional
`Access_ISABUS.HTP.Method` named mutex that HWiNFO, LibreHardwareMonitor and
vendor utilities also honour, and skips the read rather than racing if it
can't get it.

Fan **control** (writing PWM duty) is not implemented yet. Reading is
deliberately first: two controllers writing the same registers fight each
other, and a crash mid-write can leave fans pinned or stopped until reboot.

### How FanControl does it, and what the write path would need

FanControl itself is closed source, but it doesn't talk to hardware
directly: its sensor and control layer is `LibreHardwareMonitorLib` (open,
MPL-2.0) on top of PawnIO, i.e. the same two components rMon now uses. Its
own contribution is the architecture around them — `FanControl.Service.exe`
runs elevated as a Windows service and the UI talks to it over a gRPC
named pipe (`FanControl.IPC` on `GrpcDotNetNamedPipes`), which is how the
UI avoids running as Administrator; plus a plugin surface
(`FanControl.Plugins`: `IPluginSensor`, `IPluginControlSensor`) that lets
third parties add sensors, including one that reads HWiNFO.

So "independent of FanControl" mostly means reimplementing what LHM's
`Nct677X` does. For writes on the NCT668x parts that is:

1. Request a configuration window: write `0x80` to `0xA01`, wait ~50 ms.
2. Set the channel's manual-mode bit: read `0xA00`, OR in `1 << channel`,
   write it back. This takes the channel off the EC's SmartFAN curve.
3. Write the duty value (0–255) to `0xA28 + channel`.
4. Commit: write `0x40` to `0xA01`, wait ~50 ms.

The NCT67xx parts are simpler: write `0` to the channel's control-mode
register to select manual, then the duty to its PWM command register.

Two things have to come with that, not after it. The initial mode and duty
of every channel must be saved before the first write and restored on exit,
or quitting rMon leaves the fans wherever it last set them. And a running
FanControl writes these same registers on its own schedule, so both would
fight over every channel — the ISA mutex serialises individual register
accesses but cannot arbitrate *policy*. Detecting FanControl and refusing
to take over a channel it owns is part of the work, not a nicety.

### Why PawnIO and not WinRing0

The traditional way to do all of the above is WinRing0, which hands
unrestricted MSR and port I/O to whoever can open it. That generality is the
problem: it is a well-known privilege-escalation primitive (CVE-2020-14979),
it appears on Microsoft's vulnerable-driver blocklist, and Defender flags it
as a HackTool. Shipping it would mean shipping a local privilege-escalation
vulnerability alongside a process monitor.

PawnIO instead runs small signed [Pawn] bytecode modules in a sandbox inside
the driver, and enforces what each one may touch. The `IntelMSR` module
permits about thirty thermal and power MSRs and returns `STATUS_ACCESS_DENIED`
for anything else; `LpcIO` refuses any port outside the Super I/O
configuration pair and the base addresses it discovered, and blacklists the
PCI configuration ports outright. There is no IOCTL that means "give me
arbitrary kernel memory".

rMon **does not install the driver** — it detects `PawnIOLib.dll` and uses it
if present. Install PawnIO yourself from <https://pawnio.eu> if you want the
direct path; without it, rMon uses HWiNFO only when needed for the CPU
thermal fallback, then ACPI, and says so in the sensors tab. Supplemental
HWiNFO sensors remain explicit opt-in. The signed module blobs rMon loads
are vendored under `crates/rmon-core/vendor/pawnio/` from the upstream
[PawnIO.Modules] release (LGPL-2.1-or-later; see the `COPYING` file beside
them). They cannot be rebuilt locally — the driver only accepts modules
carrying the upstream signature, which is exactly the property that makes
the sandbox worth trusting.

[PawnIO]: https://pawnio.eu
[Pawn]: https://github.com/compuphase/pawn
[PawnIO.Modules]: https://github.com/namazso/PawnIO.Modules

## Analysis agent (LLM)

The **analyze** tab asks a language model to explain what is making the
machine slow, using rMon's own telemetry as its only evidence. It is a Rust
agent core (`crates/rmon-agent`) talking to any OpenAI-compatible
`/v1/chat/completions` endpoint — by default [Passiv], which fronts models
through LiteLLM.

```powershell
$env:RMON_LLM_API_KEY = "<passiv gateway key>"
$env:RMON_LLM_MODEL   = "<a model the gateway serves>"
# optional: staging instead of production
$env:RMON_LLM_BASE_URL = "https://gateway-dev.mezzanin.eu/v1"
```

The same values can be entered under **Settings → Analyze (LLM)**. A saved
key is DPAPI-sealed for the current Windows account in
`%APPDATA%\rMon\config.json`; it is never written to SQLite, logs, or the
repo. Environment variables remain the fallback. With no key/model the tab
explains what to configure instead of failing.

### What it can and cannot do

Its tools are rMon's read paths: system thermal/throttle/fan state, ranked
process listings, per-process detail, installed-program inventory/detail
with live attribution, and the leak/idle trend suspects.

The only action it can reach is `propose_kill_process`, and that **does not
kill anything** — it returns a proposal that appears in the tab with
"kill it" / "dismiss" buttons, and the kill runs from the button handler,
never from the agent loop. The model is told explicitly that nothing was
terminated, so it cannot proceed as though its suggestion had been carried
out. An LLM misreading a CPU spike and terminating a system process on a
monitoring tool's authority is not a risk worth the convenience saved.

Two other bounds are structural rather than advisory: tool iterations are
capped, and on hitting the cap the agent is asked to conclude from what it
has (with tools withdrawn) rather than looping; and a tool that errors
reports the error back to the model instead of aborting the turn, so a
malformed argument is recoverable.

### On honesty in the tool output

rMon distinguishes "measured zero" from "could not measure" everywhere, and
the tool layer carries that into JSON as `null`. This matters more for a
model than for a person: asked why a machine is slow, a model handed
`"fraction_of_time_limited": 0` will confidently rule out thermal causes it
has no evidence about. The system prompt states the rule, the tools emit
`null`, and the throttle verdict ships with
`throttle_measured_not_inferred` so the model can tell the CPU's own status
register from the clock-speed heuristic.

The agent runs on a worker thread; sampling and rendering are untouched
while it waits on the network.

[Passiv]: https://gateway.mezzanin.eu

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
