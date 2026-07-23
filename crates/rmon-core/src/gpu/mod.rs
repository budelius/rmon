mod nvml;
mod pdh;

use std::collections::HashMap;

use crate::model::{GpuSource, GpuTelemetry};
use nvml::NvmlGpuMonitor;
use pdh::PdhGpuMonitor;

/// Combines NVML (preferred, NVIDIA-only, more accurate) and the
/// vendor-agnostic PDH "GPU Engine" counters (fallback) into one source of
/// per-process GPU utilization.
pub struct GpuMonitor {
    nvml: Option<NvmlGpuMonitor>,
    pdh: Option<PdhGpuMonitor>,
}

impl GpuMonitor {
    pub fn new() -> Self {
        let nvml = NvmlGpuMonitor::new()
            .inspect_err(|e| log::info!("NVML unavailable, will use PDH GPU counters: {e:#}"))
            .ok();
        let pdh = PdhGpuMonitor::new()
            .inspect_err(|e| log::warn!("PDH 'GPU Engine' counters unavailable: {e:#}"))
            .ok();
        Self { nvml, pdh }
    }

    pub fn has_source(&self) -> bool {
        self.nvml.is_some() || self.pdh.is_some()
    }

    /// Returns pid -> (gpu percent, source) for this sampling tick. Prefers
    /// NVML data when it produces results; falls back to PDH otherwise.
    pub fn sample(&mut self) -> HashMap<u32, (f32, GpuSource)> {
        if let Some(nvml) = self.nvml.as_mut() {
            match nvml.sample() {
                Ok(map) if !map.is_empty() => {
                    return map
                        .into_iter()
                        .map(|(pid, pct)| (pid, (pct, GpuSource::Nvml)))
                        .collect();
                }
                Ok(_) => {}
                Err(e) => log::debug!("NVML sample failed: {e:#}"),
            }
        }

        if let Some(pdh) = self.pdh.as_mut() {
            match pdh.sample() {
                Ok(map) => {
                    return map
                        .into_iter()
                        .map(|(pid, pct)| (pid, (pct, GpuSource::Pdh)))
                        .collect();
                }
                Err(e) => log::debug!("PDH sample failed: {e:#}"),
            }
        }

        HashMap::new()
    }

    /// Per-GPU temperature/throttle telemetry (empty when NVML is unavailable —
    /// PDH counters don't expose temperature or throttle reasons).
    pub fn telemetry(&self) -> Vec<GpuTelemetry> {
        self.nvml.as_ref().map(|n| n.telemetry()).unwrap_or_default()
    }
}

impl Default for GpuMonitor {
    fn default() -> Self {
        Self::new()
    }
}
