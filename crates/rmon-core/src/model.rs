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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessSample {
    pub pid: u32,
    pub name: String,
    pub cpu_percent: f32,
    pub gpu_percent: f32,
    pub gpu_source: GpuSource,
}

/// All process samples collected at a single point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub timestamp: DateTime<Utc>,
    pub processes: Vec<ProcessSample>,
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
