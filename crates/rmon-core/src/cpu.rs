use std::collections::HashMap;

use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

/// One process's CPU-side info from a single sampling tick.
pub struct ProcCpuInfo {
    pub name: String,
    pub cpu_percent: f32,
    pub ppid: Option<u32>,
}

/// Wraps `sysinfo` to report per-process CPU usage.
///
/// `sysinfo` computes CPU percent as a delta since the previous refresh, so
/// the first `sample()` call after construction always reports near-zero
/// values. Callers that sample on an interval (the normal use case here)
/// get meaningful numbers from the second call onward.
pub struct CpuMonitor {
    sys: System,
}

impl CpuMonitor {
    pub fn new() -> Self {
        let mut sys = System::new();
        sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing()
                .with_cpu()
                .with_memory()
                .with_exe(UpdateKind::OnlyIfNotSet),
        );
        Self { sys }
    }

    /// Returns pid -> per-process CPU info.
    pub fn sample(&mut self) -> HashMap<u32, ProcCpuInfo> {
        self.sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing()
                .with_cpu()
                .with_memory()
                .with_exe(UpdateKind::OnlyIfNotSet),
        );
        self.sys.refresh_cpu_usage();

        self.sys
            .processes()
            .iter()
            .map(|(pid, proc_)| {
                let name = proc_.name().to_string_lossy().to_string();
                let info = ProcCpuInfo {
                    name,
                    cpu_percent: proc_.cpu_usage(),
                    ppid: proc_.parent().map(|p| p.as_u32()),
                };
                (pid.as_u32(), info)
            })
            .collect()
    }

    /// Average CPU utilization across all logical cores, 0..=100, as of the
    /// last `sample()` call.
    pub fn global_usage(&self) -> f32 {
        self.sys.global_cpu_usage()
    }
}

impl Default for CpuMonitor {
    fn default() -> Self {
        Self::new()
    }
}
