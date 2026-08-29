//! MCP (Model Context Protocol) server exposing rMon's full read surface —
//! process snapshot/tree, per-process detail (open files, listening ports,
//! handle count), per-process trend analytics (handle/memory leak suspects,
//! idle CPU burners), system thermal telemetry, and cross-process file/port
//! search — over stdio, so any MCP client (Claude Desktop/Code, etc.) can
//! query a running system the same way the GUI/TUI/CLI do.
//!
//! `rmon-core::Sampler` holds a WMI connection (for CPU thermal telemetry)
//! that's tied to the OS thread that created it — COM connections aren't
//! safe to hop across tokio's worker pool. So the sampler lives on one
//! dedicated thread for the server's whole lifetime, and every tool call
//! reaches it through a request/response channel instead of touching it
//! directly.
//!
//! `process_tree` also reconnects exited parents (via `ShortLivedWatcher`'s
//! ETW-tracked exit history, same as the GUI/TUI tree views) so an MCP
//! client sees the same historic lineage a human would in the GUI, not
//! just orphans. `ShortLivedWatcher` needs Administrator elevation; if
//! that fails, `process_tree` silently falls back to today's live-only
//! behavior and `recent_exits` reports the failure reason.

use std::collections::HashMap;
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::transport::stdio;
use rmcp::{ErrorData as McpError, ServiceExt, schemars, tool, tool_router};
use rmon_core::{
    DEFAULT_GHOST_MAX_DEPTH, DEFAULT_SCAN_WORKERS, DEFAULT_WHEA_LOOKBACK_DAYS,
    DEFAULT_WHEA_MAX_EVENTS, PortEntry, ProcessSample, RollingHistory, Sampler, ShortLivedWatcher,
    Snapshot, SystemMetrics, build_tree, check_hardware_health, handle_count, list_all_ports,
    list_open_files, list_open_files_many, listening_ports_for, merge_recent_exits, trends,
};
use serde::Deserialize;
use serde_json::json;

/// Cadence of the background samples that feed trend history. A tick is a
/// single NtQuerySystemInformation process walk (a few ms) — 5s keeps the
/// CPU accumulator honest (its per-tick delta clamp is 10s) while staying
/// negligible as background load.
const TREND_TICK: Duration = Duration::from_secs(5);
/// Raw short-window retention for the shared history; the ~24h bucketed
/// accumulator that trend detection actually reads lives inside
/// `RollingHistory` regardless of this.
const TREND_RETAIN: Duration = Duration::from_secs(300);

/// Builds the server, serves it over stdio, and blocks until the client
/// disconnects.
pub fn run() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let service = RmonMcpServer::new().serve(stdio()).await?;
        service.waiting().await?;
        anyhow::Ok(())
    })
}

/// Attached to every tool result carrying per-process CPU numbers.
///
/// rMon reports CPU the way Process Explorer does — percent of one core —
/// and a reader that assumes Task Manager's convention overstates a
/// single-threaded process by the core count. That misreading repeatedly
/// sent investigations after the wrong process, so the units travel with
/// the data rather than living only in a tool description.
const CPU_UNITS_NOTE: &str = "cpu_percent is percent of ONE core (Process Explorer convention), so it reaches 100 * logical_cores on a fully loaded machine; cpu_percent_of_machine is the same figure as a 0-100 share of the whole machine (Task Manager convention). Rank and reason about load using cpu_percent_of_machine unless you specifically mean per-thread saturation — a single-threaded process pegging one core reads 100 here but is only ~3% of a 32-core machine.";

fn to_mcp_err(e: impl std::fmt::Display) -> McpError {
    McpError::internal_error(e.to_string(), None)
}

fn text_result(value: &serde_json::Value) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(value).map_err(to_mcp_err)?,
    )]))
}

/// `logical_cores` is passed in rather than read from the process because
/// a `ProcessSample` has no idea how big the machine is — and a CPU
/// percentage without that divisor is exactly the ambiguity that kept
/// getting read as "this process is eating the box".
fn process_json(p: &ProcessSample, logical_cores: u32) -> serde_json::Value {
    json!({
        "pid": p.pid,
        "ppid": p.ppid,
        "name": p.name,
        "cpu_percent": p.cpu_percent,
        "cpu_percent_of_machine": p.cpu_percent / logical_cores.max(1) as f32,
        "gpu_percent": p.gpu_percent,
        "gpu_source": p.gpu_source.as_str(),
        "user": p.user,
        "command_line": p.command_line,
        "handle_count": p.handle_count,
        "mem_bytes": p.mem_bytes,
    })
}

fn port_json(p: &PortEntry) -> serde_json::Value {
    json!({
        "protocol": p.protocol.as_str(),
        "local_addr": p.local_addr.to_string(),
        "local_port": p.local_port,
        "remote_addr": p.remote_addr.map(|a| a.to_string()),
        "remote_port": p.remote_port,
        "state": p.state.map(|s| s.as_str()),
        "pid": p.pid,
    })
}

fn system_json(s: &SystemMetrics) -> serde_json::Value {
    json!({
        "cpu_temp_c": s.cpu_temp_c,
        "cpu_temp_source": s.cpu_temp_source,
        "cpu_clock_ratio": s.cpu_clock_ratio,
        "cpu_thermal_headroom_c": s.cpu_thermal_headroom_c,
        "cpu_throttled": s.cpu_throttled,
        "cpu_throttle_reason": s.cpu_throttle_reason,
        // Whether the throttle verdict was read from the CPU or inferred
        // from clock speed. An agent acting on this needs to know which:
        // the first is a fact, the second is a guess that a busy but
        // healthy machine can also produce.
        "cpu_throttle_confirmed": s.cpu_throttle_confirmed,
        "cpu_thermal_throttled_since_boot": s.cpu_thermal_throttled_since_boot,
        "sensor_source": s.sensor_source,
        // The divisor for every per-process cpu_percent in this server's
        // output. Without it those numbers cannot be read correctly.
        "logical_cores": s.logical_cores,
        "fans": s.fans.iter().map(|f| json!({
            "label": f.label,
            "rpm": f.rpm,
        })).collect::<Vec<_>>(),
        "board_temperatures": s.board_temperatures.iter().map(|t| json!({
            "label": t.label,
            "temp_c": t.temp_c,
        })).collect::<Vec<_>>(),
        "voltages": s.voltages.iter().map(|v| json!({
            "label": v.label,
            "volts": v.volts,
        })).collect::<Vec<_>>(),
        "gpus": s.gpus.iter().map(|g| json!({
            "index": g.index,
            "name": g.name,
            "temp_c": g.temp_c,
            "thermal_throttled": g.thermal_throttled,
            "throttle_reasons": g.throttle_reasons,
        })).collect::<Vec<_>>(),
    })
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SnapshotArgs {
    /// Only return the top N processes by combined CPU%+GPU% usage (default: all).
    #[serde(default)]
    top: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct TreeArgs {
    /// Only return the top N rows by combined CPU%+GPU% usage (default: all).
    #[serde(default)]
    top: Option<usize>,
    /// Rank each subtree by the summed usage of the process and all its
    /// descendants, instead of just its own usage.
    #[serde(default)]
    subtree_totals: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ProcessDetailArgs {
    /// Process ID.
    pid: u32,
    /// Include the process's open files (on-demand kernel handle-table scan).
    #[serde(default = "default_true")]
    include_files: bool,
    /// Include the process's listening TCP/UDP ports.
    #[serde(default = "default_true")]
    include_ports: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ListPortsArgs {
    /// Only endpoints owned by this pid (default: every process).
    #[serde(default)]
    pid: Option<u32>,
    /// Only TCP LISTEN / UDP-bound endpoints (default: all, including established connections).
    #[serde(default)]
    listening_only: bool,
    /// Only endpoints whose address, port, or pid contains this substring.
    #[serde(default)]
    filter: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SearchFilesArgs {
    /// Substring to match against open file paths (case-insensitive).
    query: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct TrendsArgs {
    /// Only return flagged suspects — possible handle/memory leaks and
    /// idle burners (default: false, return every analyzed process,
    /// most interesting first).
    #[serde(default)]
    suspects_only: bool,
    /// Cap on how many entries to return.
    #[serde(default)]
    top: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct HealthArgs {
    /// How many days back to search the System event log for WHEA entries (default 30).
    #[serde(default)]
    days: Option<i64>,
    /// Cap on how many WHEA events to return, most recent first (default 200).
    #[serde(default)]
    max_events: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct WmiActivityArgs {
    /// How far back to look, in seconds (default 3600).
    #[serde(default)]
    secs: Option<i64>,
    /// Cap on operations returned, most recent first (default 5000).
    #[serde(default)]
    max_events: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct OrphanArgs {
    /// Only return groups holding at least this many processes (default 2).
    #[serde(default)]
    min_size: Option<usize>,
}

enum SamplerMsg {
    Sample(std_mpsc::Sender<Snapshot>),
}

#[derive(Clone)]
struct RmonMcpServer {
    tx: std_mpsc::Sender<SamplerMsg>,
    /// Trend history fed by the sampler thread's background ticks (and by
    /// every on-demand sample). Only covers this server's uptime — leak
    /// detection needs the server to have been running ≥30 min.
    history: Arc<Mutex<RollingHistory>>,
    /// `Arc` (not just `Option<ShortLivedWatcher>`) because the tool
    /// router requires `Self: Clone`, and the ETW trace session inside
    /// `ShortLivedWatcher` isn't cloneable itself — only shareable.
    short_lived: Option<Arc<ShortLivedWatcher>>,
    short_lived_error: Option<Arc<str>>,
}

#[tool_router(server_handler)]
impl RmonMcpServer {
    fn new() -> Self {
        let (tx, rx) = std_mpsc::channel::<SamplerMsg>();
        let history = Arc::new(Mutex::new(RollingHistory::new(TREND_RETAIN)));
        let history_writer = Arc::clone(&history);
        std::thread::spawn(move || {
            let mut sampler = Sampler::new();
            sampler.sample(); // warm up — CPU%/GPU% are deltas since the previous sample
            loop {
                // Instead of blocking on requests forever, wake up every
                // TREND_TICK to sample into the trend history — that's what
                // gives `process_trends` hours of data even when no client
                // has called a tool in the meantime.
                match rx.recv_timeout(TREND_TICK) {
                    Ok(SamplerMsg::Sample(reply)) => {
                        let snap = sampler.sample();
                        history_writer
                            .lock()
                            .expect("history mutex poisoned")
                            .push(snap.clone());
                        let _ = reply.send(snap);
                    }
                    Err(std_mpsc::RecvTimeoutError::Timeout) => {
                        let snap = sampler.sample();
                        history_writer
                            .lock()
                            .expect("history mutex poisoned")
                            .push(snap);
                    }
                    Err(std_mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        });
        let (short_lived, short_lived_error) = match ShortLivedWatcher::start() {
            Ok(w) => (Some(Arc::new(w)), None),
            Err(e) => (None, Some(Arc::from(format!("{e:#}")))),
        };
        Self {
            tx,
            history,
            short_lived,
            short_lived_error,
        }
    }

    /// Takes a fresh sample from the dedicated sampler thread. CPU%/GPU% on
    /// the returned snapshot reflect the delta since whichever tool call
    /// (from any client) last sampled — same semantics as `rmon record`.
    async fn snapshot_now(&self) -> Snapshot {
        let tx = self.tx.clone();
        tokio::task::spawn_blocking(move || {
            let (reply_tx, reply_rx) = std_mpsc::channel();
            tx.send(SamplerMsg::Sample(reply_tx))
                .expect("sampler thread died");
            reply_rx.recv().expect("sampler thread died")
        })
        .await
        .expect("spawn_blocking panicked")
    }

    #[tool(
        description = "Current process list ranked by combined CPU%+GPU% usage, plus system-wide totals. CPU%/GPU% reflect the delta since the last snapshot/tree tool call from any client. cpu_percent is percent of ONE core (Process Explorer convention), so it reaches 100 * logical_cores on a fully loaded machine; cpu_percent_of_machine is the same figure as a 0-100 share of the whole machine (Task Manager convention). Rank and reason about load using cpu_percent_of_machine unless you specifically mean per-thread saturation — a single-threaded process pegging one core reads 100 here but is only ~3% of a 32-core machine."
    )]
    async fn snapshot(
        &self,
        Parameters(args): Parameters<SnapshotArgs>,
    ) -> Result<CallToolResult, McpError> {
        let snap = self.snapshot_now().await;
        let mut processes = snap.sorted_by_usage();
        if let Some(top) = args.top {
            processes.truncate(top);
        }
        let cores = snap.logical_cores();
        text_result(&json!({
            "timestamp": snap.timestamp.to_rfc3339(),
            "process_count": snap.processes.len(),
            "logical_cores": cores,
            "total_cpu_percent": snap.total_cpu_percent(),
            "total_cpu_percent_of_machine": snap.total_cpu_percent_of_machine(),
            "total_gpu_percent": snap.total_gpu_percent(),
            "cpu_units": CPU_UNITS_NOTE,
            "processes": processes.iter().map(|p| process_json(p, cores)).collect::<Vec<_>>(),
        }))
    }

    #[tool(
        description = "Process list as a parent/child tree (depth-first; each row includes its tree depth), ranked by combined CPU%+GPU% usage. Reconnects orphans under exited parents when ETW exit history (see `recent_exits`) can identify one, instead of promoting every orphan to a root — those rows have `is_ghost: true`, zero CPU/GPU (they were never sampled), and only exist going forward from whenever this server's process-exit tracking started (needs Administrator; see `recent_exits`)."
    )]
    async fn process_tree(
        &self,
        Parameters(args): Parameters<TreeArgs>,
    ) -> Result<CallToolResult, McpError> {
        let snap = self.snapshot_now().await;
        let recent_exits = self
            .short_lived
            .as_ref()
            .map(|w| w.recent())
            .unwrap_or_default();
        let (augmented, ghosts) =
            merge_recent_exits(&snap.processes, &recent_exits, DEFAULT_GHOST_MAX_DEPTH);
        let cores = snap.logical_cores();
        let key = |p: &ProcessSample| p.cpu_percent + p.gpu_percent;
        let mut rows = build_tree(&augmented, key, args.subtree_totals);
        if let Some(top) = args.top {
            rows.truncate(top);
        }
        let value: Vec<serde_json::Value> = rows
            .iter()
            .map(|(depth, p)| {
                let mut v = process_json(p, cores);
                v["depth"] = json!(depth);
                v["is_ghost"] = json!(ghosts.contains(&p.pid));
                v
            })
            .collect();
        text_result(&json!(value))
    }

    #[tool(
        description = "Processes that started and fully exited since this MCP server started, via ETW (Microsoft-Windows-Kernel-Process provider) — catches short-lived processes a point-in-time snapshot would miss entirely, and is what lets `process_tree` reconnect orphans to a real exited parent. Needs Administrator; if unavailable, `available` is false and `error` explains why. Duration is wall-clock, not CPU time — these events don't carry CPU usage."
    )]
    async fn recent_exits(&self) -> Result<CallToolResult, McpError> {
        let Some(watcher) = &self.short_lived else {
            return text_result(&json!({
                "available": false,
                "error": self.short_lived_error.as_deref(),
                "exits": [],
            }));
        };
        let exits = watcher.recent();
        let value: Vec<_> = exits
            .iter()
            .map(|e| {
                json!({
                    "pid": e.pid,
                    "ppid": e.ppid,
                    "name": e.name,
                    "start_time": e.start_time.to_rfc3339(),
                    "duration_ms": e.duration_ms,
                    "exit_code": e.exit_code,
                })
            })
            .collect();
        text_result(&json!({
            "available": true,
            "error": null,
            "exits": value,
        }))
    }

    #[tool(
        description = "Full detail for one process: basic info, open handle count, open files (on-demand kernel handle-table scan), and listening TCP/UDP ports."
    )]
    async fn process_detail(
        &self,
        Parameters(args): Parameters<ProcessDetailArgs>,
    ) -> Result<CallToolResult, McpError> {
        let snap = self.snapshot_now().await;
        let info = snap
            .processes
            .iter()
            .find(|p| p.pid == args.pid)
            .map(|p| process_json(p, snap.logical_cores()));
        let handles = handle_count(args.pid);

        let files = if args.include_files {
            let pid = args.pid;
            let result = tokio::task::spawn_blocking(move || {
                list_open_files(pid).map_err(|e| e.to_string())
            })
            .await
            .map_err(to_mcp_err)?;
            Some(match result {
                Ok(scan) => json!({
                    "paths": scan.paths,
                    "handles_seen": scan.handles_seen,
                    "file_handles": scan.file_handles,
                    "timed_out": scan.timed_out,
                }),
                Err(e) => json!({ "error": e }),
            })
        } else {
            None
        };

        let ports = if args.include_ports {
            let pid = args.pid;
            let all_ports = tokio::task::spawn_blocking(list_all_ports)
                .await
                .map_err(to_mcp_err)?
                .map_err(to_mcp_err)?;
            Some(
                listening_ports_for(&all_ports, pid)
                    .iter()
                    .map(port_json)
                    .collect::<Vec<_>>(),
            )
        } else {
            None
        };

        let trend = {
            let history = self.history.lock().expect("history mutex poisoned");
            trends::analyze(&history)
                .into_iter()
                .find(|t| t.pid == args.pid)
        };

        text_result(&json!({
            "pid": args.pid,
            "process": info,
            "handle_count": handles,
            "trend": trend,
            "open_files": files,
            "listening_ports": ports,
        }))
    }

    #[tool(
        description = "Per-process trend analytics over this server's uptime: handle-count and working-set growth (least-squares slope, monotonicity, leak-suspect flags for sustained monotonic growth over >=30 min) and accumulated CPU/GPU core-seconds with 'idle burner' flags (large accumulated CPU while currently near-idle — the classic quietly-misbehaving background process) and 'orphan burner' flags (still burning >=50% of one core with no living parent — a runaway whose launcher exited, which nothing is left to reap). `orphaned` on its own is informational, not a fault: anything started from a shell that has since closed is an orphan. History is sampled in the background every few seconds but only exists since this MCP server started: with under ~30 minutes of uptime nothing will be flagged yet, and `observed_window_secs` says how much history the verdicts rest on. Flags are conservative heuristics — treat a flagged process as a suspect worth investigating (e.g. restart it and watch whether the count resets then climbs again), not a confirmed leak."
    )]
    async fn process_trends(
        &self,
        Parameters(args): Parameters<TrendsArgs>,
    ) -> Result<CallToolResult, McpError> {
        // Take a fresh sample first so `latest()` (the process list trends
        // are computed for) is current rather than up to TREND_TICK stale.
        let _ = self.snapshot_now().await;
        let (window_secs, mut all) = {
            let history = self.history.lock().expect("history mutex poisoned");
            (history.accum_window().as_secs(), trends::analyze(&history))
        };
        if args.suspects_only {
            all.retain(trends::ProcessTrend::flagged);
        }
        let suspect_count = all.iter().filter(|t| t.flagged()).count();
        if let Some(top) = args.top {
            all.truncate(top);
        }
        text_result(&json!({
            "observed_window_secs": window_secs,
            "suspect_count": suspect_count,
            "trends": all,
        }))
    }

    #[tool(
        description = "List TCP/UDP endpoints system-wide or for one process, via GetExtendedTcpTable/GetExtendedUdpTable."
    )]
    async fn list_ports(
        &self,
        Parameters(args): Parameters<ListPortsArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut ports = tokio::task::spawn_blocking(list_all_ports)
            .await
            .map_err(to_mcp_err)?
            .map_err(to_mcp_err)?;
        if let Some(pid) = args.pid {
            ports.retain(|p| p.pid == pid);
        }
        if args.listening_only {
            ports.retain(PortEntry::is_listening);
        }
        if let Some(f) = &args.filter {
            let f = f.to_lowercase();
            ports.retain(|p| {
                format!(
                    "{} {}:{} {}",
                    p.pid,
                    p.local_addr,
                    p.local_port,
                    p.protocol.as_str()
                )
                .to_lowercase()
                .contains(&f)
            });
        }
        text_result(&json!(ports.iter().map(port_json).collect::<Vec<_>>()))
    }

    #[tool(
        description = "Search open file paths across every currently running process — walks each process's kernel handle table. Best-effort: processes rMon can't open (other users', protected, without Administrator) are skipped rather than failing the search. Can take several seconds on a busy system."
    )]
    async fn search_open_files(
        &self,
        Parameters(args): Parameters<SearchFilesArgs>,
    ) -> Result<CallToolResult, McpError> {
        let snap = self.snapshot_now().await;
        let names: HashMap<u32, String> = snap
            .processes
            .iter()
            .map(|p| (p.pid, p.name.clone()))
            .collect();
        let pids: Vec<u32> = snap.processes.iter().map(|p| p.pid).collect();
        let total = pids.len();
        let query = args.query.to_lowercase();

        let matches = tokio::task::spawn_blocking(move || {
            let (tx, rx) = std_mpsc::channel();
            list_open_files_many(pids, DEFAULT_SCAN_WORKERS, tx);
            rx.into_iter()
                .flat_map(|entry| {
                    let paths = entry.scan.map(|scan| scan.paths).unwrap_or_default();
                    paths
                        .into_iter()
                        .filter(|p| p.to_lowercase().contains(&query))
                        .map(move |path| (entry.pid, path))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        })
        .await
        .map_err(to_mcp_err)?;

        let value: Vec<_> = matches
            .iter()
            .map(|(pid, path)| {
                json!({
                    "pid": pid,
                    "name": names.get(pid),
                    "path": path,
                })
            })
            .collect();
        text_result(&json!({
            "processes_scanned": total,
            "matches": value,
        }))
    }

    #[tool(
        description = "System-wide hardware telemetry: CPU temperature, distance to TjMax, clock ratio, and throttle state (read from the CPU's own thermal status register when PawnIO is available and rMon is elevated — `cpu_throttle_confirmed` says which), motherboard temperatures, voltages and fan RPM from rMon's direct SensorHub, and per-GPU temperature and throttle status (NVIDIA only, via NVML)."
    )]
    async fn system_metrics(&self) -> Result<CallToolResult, McpError> {
        let snap = self.snapshot_now().await;
        text_result(&system_json(&snap.system))
    }

    #[tool(
        description = "Best-effort hardware health signals: WHEA (Windows Hardware Error Architecture) event log entries from the System log, BIOS version, and CPU microcode revision. Facts only — this does not itself diagnose silicon degradation; weigh Error-level WHEA entries alongside other evidence like new instability under load, and cross-reference the microcode/BIOS versions against your CPU/motherboard vendor's own advisories. The WHEA query uses EvtQuery against the System channel's per-provider index, so it costs tens of milliseconds and does not get slower with a longer lookback; `whea_query_ms` reports what it actually took."
    )]
    async fn hardware_health(
        &self,
        Parameters(args): Parameters<HealthArgs>,
    ) -> Result<CallToolResult, McpError> {
        let days = args.days.unwrap_or(DEFAULT_WHEA_LOOKBACK_DAYS);
        let max_events = args.max_events.unwrap_or(DEFAULT_WHEA_MAX_EVENTS);
        let report = tokio::task::spawn_blocking(move || check_hardware_health(days, max_events))
            .await
            .map_err(to_mcp_err)?;
        text_result(&serde_json::to_value(&report).map_err(to_mcp_err)?)
    }

    #[tool(
        description = "Attribute WMI activity to the processes that caused it — the tool to reach for when WmiPrvSE.exe is burning CPU, because that host does work other processes asked for and no process list will say who. Reads the Windows WMI-Activity event channels directly via EvtQuery, never through WMI itself (querying WMI to diagnose WMI saturation would add to the load being measured). Each caller is returned with its operation count, whether it is still running, and the queries it issued. IMPORTANT: `trace_channel` says whether full tracing is on. When it is not `Enabled`, Windows only records operations slow enough to cross an internal threshold, `sampling_warning` is set, and the results are a biased sample in which the busiest caller may be absent entirely — a quiet result is then NOT evidence that nothing is hammering WMI. Enabling the complete channel needs Administrator and is done from rMon's `wmi` tab or `rmon wmi --trace on`. Callers that already exited are still listed by pid, with `alive: false`; a caller that keeps exiting and being replaced is a different problem from one long-lived process polling in a loop."
    )]
    async fn wmi_activity(
        &self,
        Parameters(args): Parameters<WmiActivityArgs>,
    ) -> Result<CallToolResult, McpError> {
        let secs = args.secs.unwrap_or(rmon_core::wmi_activity::DEFAULT_LOOKBACK_SECS);
        let max_events = args
            .max_events
            .unwrap_or(rmon_core::wmi_activity::DEFAULT_MAX_EVENTS);
        let snap = self.snapshot_now().await;
        let live: std::collections::HashMap<u32, String> = snap
            .processes
            .iter()
            .map(|p| (p.pid, p.name.clone()))
            .collect();

        let report = tokio::task::spawn_blocking(move || {
            rmon_core::wmi_activity::read_operations(secs, max_events).map(|ops| {
                rmon_core::wmi_activity::attribute(
                    ops,
                    secs,
                    |pid| live.get(&pid).cloned(),
                    |pid| live.contains_key(&pid),
                )
            })
        })
        .await
        .map_err(to_mcp_err)?
        .map_err(to_mcp_err)?;
        text_result(&serde_json::to_value(&report).map_err(to_mcp_err)?)
    }

    #[tool(
        description = "Clusters of live processes whose parent process no longer exists, grouped by that dead parent — abandoned sessions still holding processes. Being orphaned is not itself a fault: anything started from a shell that has since closed is an orphan, so a single one means nothing. What this surfaces is the shape — dozens of processes all naming the same departed parent is one abandoned launcher, and a large total is worth knowing because everything that enumerates processes (including WMI queries and rMon's own sampling) costs in proportion to how many exist. Groups are ranked largest first with their composition (e.g. 38x bash.exe), combined CPU and memory. The dead parent is named only when ETW exit history saw it exit (needs Administrator, and only covers parents that died while rMon was watching); otherwise only its pid is known, which does not make the group less real. Note Windows reuses pids, so a group means 'these processes recorded that pid as their parent', usually one abandoned launcher."
    )]
    async fn orphan_groups(
        &self,
        Parameters(args): Parameters<OrphanArgs>,
    ) -> Result<CallToolResult, McpError> {
        let min_size = args.min_size.unwrap_or(rmon_core::DEFAULT_MIN_GROUP);
        let snap = self.snapshot_now().await;
        let exits = self
            .short_lived
            .as_ref()
            .map(|w| w.recent())
            .unwrap_or_default();
        let groups = rmon_core::significant_groups(&snap.processes, &exits, min_size);
        text_result(&serde_json::json!({
            "total_processes": snap.processes.len(),
            "groups_held_processes": groups.iter().map(|g| g.len()).sum::<usize>(),
            "parent_naming_available": !exits.is_empty(),
            "groups": groups,
        }))
    }
}
