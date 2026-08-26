//! The tools the model may call, and their implementations over
//! `rmon-core`.
//!
//! Every tool here is a *read*. The one action rMon can take on a user's
//! behalf — killing a process — is deliberately not executable by the
//! model: [`Tool::KillProcess`] returns a proposal that the UI presents
//! for confirmation, and the kill happens only if a human approves it. An
//! LLM misreading a CPU spike and terminating a system process on a
//! monitoring tool's authority is not a failure mode worth risking for the
//! convenience saved.
//!
//! Tool output is JSON, shaped for a model rather than for a screen:
//! compact, unambiguous units, and explicit `null` where a reading is
//! genuinely unavailable. The distinction rMon maintains everywhere else —
//! "we measured zero" versus "we could not measure" — matters more here
//! than anywhere, because a model asked to explain a slowdown will happily
//! build a confident story on a missing number it read as a zero.

use anyhow::{Result, anyhow};
use rmon_core::{RollingHistory, Sampler, Snapshot};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::chat::{FunctionSpec, ToolSpec};

/// How many processes a listing returns unless asked otherwise. Enough to
/// contain any plausible culprit, small enough not to spend the context
/// window on idle processes.
const DEFAULT_TOP: usize = 15;
const MAX_TOP: usize = 60;

/// Everything the tools read from. Held by the agent for the duration of a
/// conversation so successive calls see a consistent machine.
pub struct ToolContext {
    pub snapshot: Snapshot,
    pub trends: Vec<rmon_core::trends::ProcessTrend>,
    pub throttle: ThrottleSummary,
}

/// The throttle history, already reduced — the agent does not need the
/// per-tick series, only what it means.
#[derive(Debug, Clone, Default)]
pub struct ThrottleSummary {
    pub observed_secs: u64,
    /// `None` when no thermal source was available, which must not be
    /// reported as "0% throttled".
    pub fraction_limited: Option<f32>,
}

impl ToolContext {
    /// Captures the current machine state.
    pub fn capture(sampler: &mut Sampler, history: &RollingHistory) -> Self {
        let snapshot = sampler.sample();
        Self {
            trends: rmon_core::trends::analyze(history),
            throttle: ThrottleSummary::default(),
            snapshot,
        }
    }
}

/// A proposed action awaiting human approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAction {
    pub tool_call_id: String,
    pub pid: u32,
    pub process_name: String,
    pub reason: String,
}

/// Outcome of dispatching one tool call.
pub enum ToolOutcome {
    /// A result to feed straight back to the model.
    Value(Value),
    /// Something a human must approve before it happens.
    NeedsApproval(PendingAction),
}

/// The tools, as the model sees them.
pub fn specs() -> Vec<ToolSpec> {
    vec![
        spec(
            "system_metrics",
            "CPU temperature, distance to TjMax, clock ratio, throttle state and why, \
             motherboard temperatures, voltages and fan RPM, and per-GPU temperature and \
             throttle status. Call this \
             first when asked about slowness: throttling depresses every per-process CPU% \
             and GPU% figure at once, so it changes how all other numbers should be read.",
            json!({"type": "object", "properties": {}}),
        ),
        spec(
            "top_processes",
            "Processes ranked by current CPU%+GPU% usage, with memory and handle counts.",
            json!({
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": format!("How many to return (default {DEFAULT_TOP}, max {MAX_TOP})")
                    },
                    "sort_by": {
                        "type": "string",
                        "enum": ["total", "cpu", "gpu", "memory"],
                        "description": "Ranking metric (default: total)"
                    }
                }
            }),
        ),
        spec(
            "process_detail",
            "Everything known about one process: usage, owner, command line, memory, \
             handles, and any leak or idle-burner trend flagged for it.",
            json!({
                "type": "object",
                "properties": {"pid": {"type": "integer", "description": "Process ID"}},
                "required": ["pid"]
            }),
        ),
        spec(
            "trend_suspects",
            "Processes flagged by rMon's trend analysis as possible handle or memory \
             leaks (sustained monotonic growth over 30+ minutes) or idle burners (large \
             accumulated CPU while currently near-idle). These are heuristics over this \
             session's history, not confirmed diagnoses.",
            json!({"type": "object", "properties": {}}),
        ),
        spec(
            "propose_kill_process",
            "Propose terminating a process. This does NOT kill anything: it returns a \
             proposal that a human must approve in the UI. Use it only when a specific \
             process is clearly responsible for the problem, and always say why.",
            json!({
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Process ID to propose killing"},
                    "reason": {
                        "type": "string",
                        "description": "Why this process should be terminated, in one sentence"
                    }
                },
                "required": ["pid", "reason"]
            }),
        ),
    ]
}

fn spec(name: &str, description: &str, parameters: Value) -> ToolSpec {
    ToolSpec {
        kind: "function",
        function: FunctionSpec {
            name: name.to_string(),
            description: description.to_string(),
            parameters,
        },
    }
}

#[derive(Deserialize, Default)]
struct TopArgs {
    limit: Option<usize>,
    sort_by: Option<String>,
}

#[derive(Deserialize)]
struct PidArgs {
    pid: u32,
}

#[derive(Deserialize)]
struct KillArgs {
    pid: u32,
    reason: String,
}

/// Runs one tool call against the captured machine state.
pub fn dispatch(
    ctx: &ToolContext,
    call_id: &str,
    name: &str,
    arguments: &str,
) -> Result<ToolOutcome> {
    // Models occasionally send an empty string rather than "{}" for a
    // no-argument call; treating that as a parse failure would strand the
    // conversation on a purely cosmetic difference.
    let args = arguments.trim();
    let args = if args.is_empty() { "{}" } else { args };

    match name {
        "system_metrics" => Ok(ToolOutcome::Value(system_metrics(ctx))),
        "top_processes" => {
            let a: TopArgs = serde_json::from_str(args).unwrap_or_default();
            Ok(ToolOutcome::Value(top_processes(ctx, a)))
        }
        "process_detail" => {
            let a: PidArgs = serde_json::from_str(args)?;
            Ok(ToolOutcome::Value(process_detail(ctx, a.pid)))
        }
        "trend_suspects" => Ok(ToolOutcome::Value(trend_suspects(ctx))),
        "propose_kill_process" => {
            let a: KillArgs = serde_json::from_str(args)?;
            let process_name = ctx
                .snapshot
                .processes
                .iter()
                .find(|p| p.pid == a.pid)
                .map(|p| p.name.clone())
                .ok_or_else(|| anyhow!("no process with pid {} in the current snapshot", a.pid))?;
            Ok(ToolOutcome::NeedsApproval(PendingAction {
                tool_call_id: call_id.to_string(),
                pid: a.pid,
                process_name,
                reason: a.reason,
            }))
        }
        other => Err(anyhow!("unknown tool {other}")),
    }
}

fn system_metrics(ctx: &ToolContext) -> Value {
    let s = &ctx.snapshot.system;
    json!({
        "cpu": {
            "temperature_c": s.cpu_temp_c,
            "temperature_source": s.cpu_temp_source,
            "degrees_below_tjmax": s.cpu_thermal_headroom_c,
            "clock_ratio": s.cpu_clock_ratio,
            "throttled": s.cpu_throttled,
            "throttle_reason": s.cpu_throttle_reason,
            // The model must be able to tell a measurement from a guess:
            // the fallback heuristic fires on low clocks alone, which a
            // healthy idle machine also produces.
            "throttle_measured_not_inferred": s.cpu_throttle_confirmed,
            "has_throttled_since_boot": s.cpu_thermal_throttled_since_boot,
        },
        "gpus": s.gpus.iter().map(|g| json!({
            "name": g.name,
            "temperature_c": g.temp_c,
            "thermal_throttled": g.thermal_throttled,
            "throttle_reasons": g.throttle_reasons,
        })).collect::<Vec<_>>(),
        "fans": s.fans.iter().map(|f| json!({
            "label": f.label,
            // null means no fan on that header, NOT a stopped fan.
            "rpm": f.rpm,
        })).collect::<Vec<_>>(),
        "motherboard_temperatures": s.board_temperatures.iter().map(|t| json!({
            "label": t.label,
            "temperature_c": t.temp_c,
        })).collect::<Vec<_>>(),
        "voltages": s.voltages.iter().map(|v| json!({
            "label": v.label,
            "volts": v.volts,
        })).collect::<Vec<_>>(),
        "throttle_history": {
            "observed_seconds": ctx.throttle.observed_secs,
            "fraction_of_time_limited": ctx.throttle.fraction_limited,
            "note": "fraction_of_time_limited is null when no thermal source was available; \
                     that is not the same as zero",
        },
        "sensor_source": s.sensor_source,
        "totals": {
            "cpu_percent_all_processes": ctx.snapshot.total_cpu_percent(),
            "gpu_percent_all_processes": ctx.snapshot.total_gpu_percent(),
        },
    })
}

fn top_processes(ctx: &ToolContext, args: TopArgs) -> Value {
    let limit = args.limit.unwrap_or(DEFAULT_TOP).clamp(1, MAX_TOP);
    let mut procs: Vec<_> = ctx.snapshot.processes.iter().collect();
    let key = args.sort_by.as_deref().unwrap_or("total");
    procs.sort_by(|a, b| {
        let score = |p: &rmon_core::ProcessSample| match key {
            "cpu" => p.cpu_percent as f64,
            "gpu" => p.gpu_percent as f64,
            "memory" => p.mem_bytes.unwrap_or(0) as f64,
            _ => (p.cpu_percent + p.gpu_percent) as f64,
        };
        score(b)
            .partial_cmp(&score(a))
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    json!({
        "sorted_by": key,
        "processes": procs.iter().take(limit).map(|p| json!({
            "pid": p.pid,
            "name": p.name,
            "cpu_percent": p.cpu_percent,
            "gpu_percent": p.gpu_percent,
            "memory_bytes": p.mem_bytes,
            "handle_count": p.handle_count,
            "user": p.user,
        })).collect::<Vec<_>>(),
        "total_process_count": ctx.snapshot.processes.len(),
    })
}

fn process_detail(ctx: &ToolContext, pid: u32) -> Value {
    let Some(p) = ctx.snapshot.processes.iter().find(|p| p.pid == pid) else {
        return json!({"error": format!("no process with pid {pid} in the current snapshot")});
    };
    let trend = ctx.trends.iter().find(|t| t.pid == pid);
    json!({
        "pid": p.pid,
        "parent_pid": p.ppid,
        "name": p.name,
        "cpu_percent": p.cpu_percent,
        "gpu_percent": p.gpu_percent,
        "gpu_source": p.gpu_source.as_str(),
        "memory_bytes": p.mem_bytes,
        "handle_count": p.handle_count,
        "user": p.user,
        "command_line": p.command_line,
        "trend": trend.map(|t| json!({
            "handle_leak_suspect": t.handle_leak_suspect,
            "memory_leak_suspect": t.mem_leak_suspect,
            "idle_burner": t.idle_burner,
            "verdict": t.verdict,
        })),
    })
}

fn trend_suspects(ctx: &ToolContext) -> Value {
    let flagged: Vec<_> = ctx
        .trends
        .iter()
        .filter(|t| t.flagged())
        .map(|t| {
            json!({
                "pid": t.pid,
                "name": t.name,
                "handle_leak_suspect": t.handle_leak_suspect,
                "memory_leak_suspect": t.mem_leak_suspect,
                "idle_burner": t.idle_burner,
                "verdict": t.verdict,
            })
        })
        .collect();
    json!({
        "suspects": flagged,
        "note": "Heuristics over this session's in-memory history only. Leak detection needs \
                 30+ minutes of sustained growth before it flags anything, so an empty list \
                 on a freshly started rMon means 'not enough history', not 'no leaks'.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmon_core::{
        BoardTemperatureSample, FanSample, GpuSource, ProcessSample, SystemMetrics, VoltageSample,
    };

    fn ctx() -> ToolContext {
        let mut system = SystemMetrics {
            cpu_temp_c: Some(70.0),
            cpu_throttled: false,
            ..Default::default()
        };
        system.fans.push(FanSample {
            label: "fan 1".into(),
            rpm: Some(1500),
        });
        system.fans.push(FanSample {
            label: "fan 2".into(),
            rpm: None,
        });
        system.board_temperatures.push(BoardTemperatureSample {
            label: "system".into(),
            temp_c: None,
        });
        system.voltages.push(VoltageSample {
            label: "VIN0 (ADC pin)".into(),
            volts: None,
        });
        ToolContext {
            snapshot: Snapshot {
                timestamp: chrono::Utc::now(),
                processes: vec![
                    ProcessSample {
                        pid: 10,
                        ppid: Some(1),
                        name: "busy.exe".into(),
                        cpu_percent: 90.0,
                        gpu_percent: 0.0,
                        gpu_source: GpuSource::Unavailable,
                        user: None,
                        command_line: None,
                        handle_count: Some(100),
                        mem_bytes: Some(1024),
                    },
                    ProcessSample {
                        pid: 11,
                        ppid: Some(1),
                        name: "fat.exe".into(),
                        cpu_percent: 1.0,
                        gpu_percent: 0.0,
                        gpu_source: GpuSource::Unavailable,
                        user: None,
                        command_line: None,
                        handle_count: Some(10),
                        mem_bytes: Some(999_999),
                    },
                ],
                system,
            },
            trends: Vec::new(),
            throttle: ThrottleSummary {
                observed_secs: 60,
                fraction_limited: None,
            },
        }
    }

    #[test]
    fn top_processes_respects_sort_key_and_limit() {
        let v = match dispatch(
            &ctx(),
            "c",
            "top_processes",
            r#"{"sort_by":"memory","limit":1}"#,
        ) {
            Ok(ToolOutcome::Value(v)) => v,
            _ => panic!("expected a value"),
        };
        assert_eq!(v["processes"][0]["name"], "fat.exe");
        assert_eq!(v["processes"].as_array().unwrap().len(), 1);
    }

    /// An absent reading must reach the model as `null`, never as 0 — a
    /// model told "0% of the time throttled" will confidently rule out
    /// thermal causes it has no evidence about.
    #[test]
    fn unavailable_readings_serialise_as_null() {
        let v = match dispatch(&ctx(), "c", "system_metrics", "") {
            Ok(ToolOutcome::Value(v)) => v,
            _ => panic!("expected a value"),
        };
        assert!(v["throttle_history"]["fraction_of_time_limited"].is_null());
        assert!(v["fans"][1]["rpm"].is_null());
        assert_eq!(v["fans"][0]["rpm"], 1500);
        assert!(v["motherboard_temperatures"][0]["temperature_c"].is_null());
        assert!(v["voltages"][0]["volts"].is_null());
    }

    /// Empty arguments are a cosmetic quirk of some models, not an error.
    #[test]
    fn empty_arguments_are_treated_as_no_arguments() {
        assert!(matches!(
            dispatch(&ctx(), "c", "trend_suspects", ""),
            Ok(ToolOutcome::Value(_))
        ));
    }

    /// The whole safety design in one test: the kill tool never kills.
    #[test]
    fn kill_is_a_proposal_not_an_action() {
        let outcome = dispatch(
            &ctx(),
            "call_9",
            "propose_kill_process",
            r#"{"pid":10,"reason":"pegged at 90% CPU"}"#,
        )
        .unwrap();
        match outcome {
            ToolOutcome::NeedsApproval(a) => {
                assert_eq!(a.pid, 10);
                assert_eq!(a.process_name, "busy.exe");
                assert_eq!(a.tool_call_id, "call_9");
            }
            ToolOutcome::Value(_) => panic!("a kill must never resolve to a plain result"),
        }
    }

    #[test]
    fn proposing_a_kill_for_an_unknown_pid_fails() {
        assert!(
            dispatch(
                &ctx(),
                "c",
                "propose_kill_process",
                r#"{"pid":4242,"reason":"x"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn unknown_tools_are_rejected() {
        assert!(dispatch(&ctx(), "c", "rm_rf", "{}").is_err());
    }
}
