use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Where a process's GPU utilization figure came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GpuSource {
    /// NVIDIA Management Library (per-process compute/SM utilization).
    Nvml,
    /// Windows "GPU Engine" performance counters (vendor-agnostic).
    Pdh,
    /// No GPU utilization could be attributed to this process.
    Unavailable,
}

impl GpuSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            GpuSource::Nvml => "nvml",
            GpuSource::Pdh => "pdh",
            GpuSource::Unavailable => "unavailable",
        }
    }

}

impl FromStr for GpuSource {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "nvml" => GpuSource::Nvml,
            "pdh" => GpuSource::Pdh,
            _ => GpuSource::Unavailable,
        })
    }
}

/// One process's resource usage at a single point in time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessSample {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub cpu_percent: f32,
    pub gpu_percent: f32,
    pub gpu_source: GpuSource,
    /// Owning account name (e.g. "DOMAIN\\user"), when resolvable.
    pub user: Option<String>,
    /// Full command line, when readable (own processes always; others
    /// require running elevated).
    pub command_line: Option<String>,
    /// Total open handle count (all types, not just files) — cheap via
    /// `GetProcessHandleCount`, unlike the full file-handle scan in
    /// `handles.rs`.
    pub handle_count: Option<u32>,
}

/// Per-GPU temperature and throttle telemetry (NVIDIA only, via NVML).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuTelemetry {
    pub index: u32,
    pub name: String,
    pub temp_c: Option<f32>,
    /// True when NVML reports an unambiguous thermal throttle reason
    /// (SW or HW thermal slowdown), i.e. clocks are being reduced because
    /// of temperature specifically.
    pub thermal_throttled: bool,
    /// Human-readable active throttle reasons (may include non-thermal ones
    /// such as power capping), for display.
    pub throttle_reasons: Vec<String>,
}

/// System-wide (not per-process) thermal telemetry for one sampling tick.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SystemMetrics {
    /// Average ACPI thermal zone temperature, in °C. Best-effort: many
    /// systems don't expose an accurate (or any) reading here without
    /// vendor tools, so this is frequently `None`.
    pub cpu_temp_c: Option<f32>,
    /// Where `cpu_temp_c` came from, e.g. `"HWiNFO"` or `"ACPI zone
    /// (approximate)"` — surfaced so the UI can show its trustworthiness
    /// rather than implying a precision the reading doesn't have.
    pub cpu_temp_source: Option<String>,
    /// Current clock speed / max clock speed, averaged across logical
    /// processors reported by `Win32_Processor` (0.0..=1.0).
    pub cpu_clock_ratio: Option<f32>,
    /// Heuristic: clocks are running well below the rated maximum while the
    /// CPU is busy. This is NOT confirmed to be thermal specifically —
    /// Windows exposes no vendor-neutral "throttled because of temperature"
    /// flag for CPUs the way NVML does for GPUs.
    pub cpu_throttled: bool,
    pub gpus: Vec<GpuTelemetry>,
}

/// All process samples collected at a single point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub timestamp: DateTime<Utc>,
    pub processes: Vec<ProcessSample>,
    pub system: SystemMetrics,
}

impl Snapshot {
    /// Total CPU percent across all sampled processes (can exceed 100 on multi-core systems).
    pub fn total_cpu_percent(&self) -> f32 {
        self.processes.iter().map(|p| p.cpu_percent).sum()
    }

    /// Total GPU percent across all sampled processes.
    pub fn total_gpu_percent(&self) -> f32 {
        self.processes.iter().map(|p| p.gpu_percent).sum()
    }

    /// Processes sorted by combined CPU+GPU usage, descending.
    pub fn sorted_by_usage(&self) -> Vec<&ProcessSample> {
        let mut v: Vec<&ProcessSample> = self.processes.iter().collect();
        v.sort_by(|a, b| {
            let ua = a.cpu_percent + a.gpu_percent;
            let ub = b.cpu_percent + b.gpu_percent;
            ub.partial_cmp(&ua).unwrap_or(std::cmp::Ordering::Equal)
        });
        v
    }
}
