//! MCP (Model Context Protocol) server exposing rMon's full read surface —
//! process snapshot/tree, per-process detail (open files, listening ports,
//! handle count), system thermal telemetry, and cross-process file/port
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
use std::sync::Arc;

use anyhow::Result;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::transport::stdio;
use rmcp::{schemars, tool, tool_router, ErrorData as McpError, ServiceExt};
use rmon_core::{
    build_tree, check_hardware_health, handle_count, list_all_ports, list_open_files,
    list_open_files_many, listening_ports_for, merge_recent_exits, PortEntry, ProcessSample,
    Sampler, ShortLivedWatcher, Snapshot, SystemMetrics, DEFAULT_GHOST_MAX_DEPTH,
    DEFAULT_SCAN_WORKERS, DEFAULT_WHEA_LOOKBACK_DAYS, DEFAULT_WHEA_MAX_EVENTS,
};
use serde::Deserialize;
use serde_json::json;

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

fn to_mcp_err(e: impl std::fmt::Display) -> McpError {
    McpError::internal_error(e.to_string(), None)
}

fn text_result(value: &serde_json::Value) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(value).map_err(to_mcp_err)?,
    )]))
}

fn process_json(p: &ProcessSample) -> serde_json::Value {
    json!({
        "pid": p.pid,
        "ppid": p.ppid,
        "name": p.name,
        "cpu_percent": p.cpu_percent,
        "gpu_percent": p.gpu_percent,
        "gpu_source": p.gpu_source.as_str(),
        "user": p.user,
        "command_line": p.command_line,
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
        "cpu_throttled": s.cpu_throttled,
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
struct HealthArgs {
    /// How many days back to search the System event log for WHEA entries (default 30).
    #[serde(default)]
    days: Option<i64>,
    /// Cap on how many WHEA events to return, most recent first (default 200).
    #[serde(default)]
    max_events: Option<usize>,
}

enum SamplerMsg {
    Sample(std_mpsc::Sender<Snapshot>),
}

#[derive(Clone)]
struct RmonMcpServer {
    tx: std_mpsc::Sender<SamplerMsg>,
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
        std::thread::spawn(move || {
            let mut sampler = Sampler::new();
            sampler.sample(); // warm up — CPU%/GPU% are deltas since the previous sample
            for msg in rx {
                match msg {
                    SamplerMsg::Sample(reply) => {
                        let _ = reply.send(sampler.sample());
                    }
                }
            }
        });
        let (short_lived, short_lived_error) = match ShortLivedWatcher::start() {
            Ok(w) => (Some(Arc::new(w)), None),
            Err(e) => (None, Some(Arc::from(format!("{e:#}")))),
        };
        Self { tx, short_lived, short_lived_error }
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
        description = "Current process list ranked by combined CPU%+GPU% usage, plus system-wide totals. CPU%/GPU% reflect the delta since the last snapshot/tree tool call from any client."
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
        text_result(&json!({
            "timestamp": snap.timestamp.to_rfc3339(),
            "process_count": snap.processes.len(),
            "total_cpu_percent": snap.total_cpu_percent(),
            "total_gpu_percent": snap.total_gpu_percent(),
            "processes": processes.iter().map(|p| process_json(p)).collect::<Vec<_>>(),
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
        let recent_exits = self.short_lived.as_ref().map(|w| w.recent()).unwrap_or_default();
        let (augmented, ghosts) =
            merge_recent_exits(&snap.processes, &recent_exits, DEFAULT_GHOST_MAX_DEPTH);
        let key = |p: &ProcessSample| p.cpu_percent + p.gpu_percent;
        let mut rows = build_tree(&augmented, key, args.subtree_totals);
        if let Some(top) = args.top {
            rows.truncate(top);
        }
        let value: Vec<serde_json::Value> = rows
            .iter()
            .map(|(depth, p)| {
                let mut v = process_json(p);
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
        let info = snap.processes.iter().find(|p| p.pid == args.pid).map(process_json);
        let handles = handle_count(args.pid);

        let files = if args.include_files {
            let pid = args.pid;
            let result = tokio::task::spawn_blocking(move || list_open_files(pid).map_err(|e| e.to_string()))
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

        text_result(&json!({
            "pid": args.pid,
            "process": info,
            "handle_count": handles,
            "open_files": files,
            "listening_ports": ports,
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
                format!("{} {}:{} {}", p.pid, p.local_addr, p.local_port, p.protocol.as_str())
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
        let names: HashMap<u32, String> =
            snap.processes.iter().map(|p| (p.pid, p.name.clone())).collect();
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
        description = "System-wide thermal and GPU telemetry: CPU temperature/clock ratio/throttle heuristic, and per-GPU temperature and throttle status (NVIDIA only, via NVML)."
    )]
    async fn system_metrics(&self) -> Result<CallToolResult, McpError> {
        let snap = self.snapshot_now().await;
        text_result(&system_json(&snap.system))
    }

    #[tool(
        description = "Best-effort hardware health signals: WHEA (Windows Hardware Error Architecture) event log entries from the System log, BIOS version, and CPU microcode revision. Facts only — this does not itself diagnose silicon degradation; weigh Error-level WHEA entries alongside other evidence like new instability under load, and cross-reference the microcode/BIOS versions against your CPU/motherboard vendor's own advisories. The WHEA query walks the System event log via WMI (Win32_NTLogEvent), which is slow and can take up to ~30 seconds (more on a system that logs WHEA entries frequently) — this is normal, not a hang."
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
}
