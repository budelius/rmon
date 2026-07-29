use chrono::Utc;

use crate::cpu::CpuMonitor;
use crate::gpu::GpuMonitor;
use crate::model::{GpuSource, ProcessSample, Snapshot, SystemMetrics};
use crate::thermal::CpuThermalMonitor;

/// Below this clock ratio (current/max), combined with high concurrent CPU
/// load, we call the CPU "throttled" (heuristic — cause unconfirmed).
const CPU_THROTTLE_CLOCK_RATIO: f32 = 0.7;
/// Minimum average core utilization before we consider low clocks
/// meaningful rather than just normal idle power-saving.
const CPU_THROTTLE_MIN_LOAD: f32 = 60.0;

/// Combines CPU and GPU per-process monitoring, plus system-wide thermal
/// telemetry, into a single sampling interface. Construct once and call
/// `sample()` on your desired interval; the underlying monitors compute
/// deltas since their previous read.
pub struct Sampler {
    cpu: CpuMonitor,
    gpu: GpuMonitor,
    thermal: CpuThermalMonitor,
}

impl Sampler {
    pub fn new() -> Self {
        Self {
            cpu: CpuMonitor::new(),
            gpu: GpuMonitor::new(),
            thermal: CpuThermalMonitor::new(),
        }
    }

    /// True if at least one GPU data source (NVML or PDH) is usable on this system.
    pub fn has_gpu_source(&self) -> bool {
        self.gpu.has_source()
    }

    pub fn sample(&mut self) -> Snapshot {
        let t = std::time::Instant::now();
        let cpu_samples = self.cpu.sample();
        let cpu_elapsed = t.elapsed();

        let t = std::time::Instant::now();
        let mut gpu_samples = self.gpu.sample();
        let gpu_elapsed = t.elapsed();

        let t = std::time::Instant::now();
        let processes = cpu_samples
            .into_iter()
            .map(|(pid, info)| {
                let (gpu_percent, gpu_source) = gpu_samples
                    .remove(&pid)
                    .unwrap_or((0.0, GpuSource::Unavailable));
                ProcessSample {
                    pid,
                    ppid: info.ppid,
                    name: info.name,
                    cpu_percent: info.cpu_percent,
                    gpu_percent,
                    gpu_source,
                    user: info.user,
                    command_line: info.command_line,
                    // Both come free with the SystemProcessInformation
                    // walk — no per-process syscalls on the tick path.
                    handle_count: info.handle_count,
                    mem_bytes: Some(info.mem_bytes),
                }
            })
            .collect();
        let merge_elapsed = t.elapsed();

        let t = std::time::Instant::now();
        let (cpu_temp_c, cpu_temp_source, cpu_clock_ratio) = self.thermal.sample();
        let thermal_elapsed = t.elapsed();
        log::debug!(
            "sample timings: cpu={cpu_elapsed:?} gpu={gpu_elapsed:?} \
             merge+handles={merge_elapsed:?} thermal={thermal_elapsed:?}"
        );
        let global_load = self.cpu.global_usage();
        let cpu_throttled = cpu_clock_ratio
            .is_some_and(|r| r < CPU_THROTTLE_CLOCK_RATIO && global_load > CPU_THROTTLE_MIN_LOAD);

        let system = SystemMetrics {
            cpu_temp_c,
            cpu_temp_source: cpu_temp_source.map(str::to_string),
            cpu_clock_ratio,
            cpu_throttled,
            gpus: self.gpu.telemetry(),
        };

        Snapshot {
            timestamp: Utc::now(),
            processes,
            system,
        }
    }
}

impl Default for Sampler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live smoke test: a real sample must carry handle counts and memory
    /// at least for our own process (which never needs elevation), and a
    /// steady-state tick must stay far below the 1s UI tick — the process
    /// walk is a single NtQuerySystemInformation call, so a whole sample
    /// is expected in the low milliseconds.
    #[test]
    fn sample_includes_handles_and_memory_for_own_process() {
        let mut sampler = Sampler::new();
        sampler.sample(); // warm up

        let start = std::time::Instant::now();
        let snap = sampler.sample();
        let elapsed = start.elapsed();
        println!("full sample of {} processes took {elapsed:?}", snap.processes.len());
        assert!(elapsed < std::time::Duration::from_millis(100), "tick took {elapsed:?}");

        let me = std::process::id();
        let p = snap
            .processes
            .iter()
            .find(|p| p.pid == me)
            .expect("own process should be in the snapshot");
        assert!(p.handle_count.is_some_and(|h| h > 0), "handle_count: {:?}", p.handle_count);
        assert!(p.mem_bytes.is_some_and(|m| m > 0), "mem_bytes: {:?}", p.mem_bytes);
    }
}
