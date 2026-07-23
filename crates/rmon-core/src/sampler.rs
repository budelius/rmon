use chrono::Utc;

use crate::cpu::CpuMonitor;
use crate::gpu::GpuMonitor;
use crate::model::{GpuSource, ProcessSample, Snapshot};

/// Combines CPU and GPU per-process monitoring into a single sampling
/// interface. Construct once and call `sample()` on your desired interval;
/// both underlying monitors compute deltas since their previous read.
pub struct Sampler {
    cpu: CpuMonitor,
    gpu: GpuMonitor,
}

impl Sampler {
    pub fn new() -> Self {
        Self {
            cpu: CpuMonitor::new(),
            gpu: GpuMonitor::new(),
        }
    }

    /// True if at least one GPU data source (NVML or PDH) is usable on this system.
    pub fn has_gpu_source(&self) -> bool {
        self.gpu.has_source()
    }

    pub fn sample(&mut self) -> Snapshot {
        let cpu_samples = self.cpu.sample();
        let mut gpu_samples = self.gpu.sample();

        let processes = cpu_samples
            .into_iter()
            .map(|(pid, (name, cpu_percent))| {
                let (gpu_percent, gpu_source) = gpu_samples
                    .remove(&pid)
                    .unwrap_or((0.0, GpuSource::Unavailable));
                ProcessSample {
                    pid,
                    name,
                    cpu_percent,
                    gpu_percent,
                    gpu_source,
                }
            })
            .collect();

        Snapshot {
            timestamp: Utc::now(),
            processes,
        }
    }
}

impl Default for Sampler {
    fn default() -> Self {
        Self::new()
    }
}
