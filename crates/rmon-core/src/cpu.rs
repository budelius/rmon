use std::collections::HashMap;

use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

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

    /// Returns pid -> (process name, cpu percent 0..=100*num_cores).
    pub fn sample(&mut self) -> HashMap<u32, (String, f32)> {
        self.sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing()
                .with_cpu()
                .with_memory()
                .with_exe(UpdateKind::OnlyIfNotSet),
        );

        self.sys
            .processes()
            .iter()
            .map(|(pid, proc_)| {
                let name = proc_.name().to_string_lossy().to_string();
                (pid.as_u32(), (name, proc_.cpu_usage()))
            })
            .collect()
    }
}

impl Default for CpuMonitor {
    fn default() -> Self {
        Self::new()
    }
}
