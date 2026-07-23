//! Per-process GPU utilization via NVIDIA Management Library (NVML).
//! Only works with NVIDIA GPUs, but gives more accurate compute (SM)
//! utilization than the vendor-agnostic PDH counters.

use std::collections::HashMap;

use anyhow::{Context, Result};
use nvml_wrapper::Nvml;
use nvml_wrapper::bitmasks::device::ThrottleReasons;
use nvml_wrapper::enum_wrappers::device::TemperatureSensor;

use crate::model::GpuTelemetry;

pub struct NvmlGpuMonitor {
    nvml: Nvml,
    device_count: u32,
    /// Per-device "last seen" timestamp (microseconds), required by NVML's
    /// process-utilization query to bound how far back it looks.
    last_seen: HashMap<u32, u64>,
}

impl NvmlGpuMonitor {
    /// Attempts to load NVML and initialize it. Returns `Err` (not a panic)
    /// when there's no NVIDIA driver present, which callers use to fall
    /// back to PDH-based monitoring.
    pub fn new() -> Result<Self> {
        let nvml = Nvml::init().context("NVML not available (no NVIDIA driver?)")?;
        let device_count = nvml.device_count().context("nvmlDeviceGetCount failed")?;
        Ok(Self {
            nvml,
            device_count,
            last_seen: HashMap::new(),
        })
    }

    /// Returns pid -> summed SM (compute) utilization percent across all
    /// NVIDIA GPUs in the system.
    pub fn sample(&mut self) -> Result<HashMap<u32, f32>> {
        let mut totals: HashMap<u32, f32> = HashMap::new();

        for idx in 0..self.device_count {
            let device = match self.nvml.device_by_index(idx) {
                Ok(d) => d,
                Err(_) => continue,
            };

            let since = *self.last_seen.get(&idx).unwrap_or(&0);
            let samples = match device.process_utilization_stats(since) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let mut max_ts = since;
            for sample in samples {
                if sample.timestamp > max_ts {
                    max_ts = sample.timestamp;
                }
                *totals.entry(sample.pid).or_insert(0.0) += sample.sm_util as f32;
            }
            self.last_seen.insert(idx, max_ts);
        }

        Ok(totals)
    }

    /// Per-GPU temperature and throttle-reason telemetry.
    pub fn telemetry(&self) -> Vec<GpuTelemetry> {
        (0..self.device_count)
            .filter_map(|idx| {
                let device = self.nvml.device_by_index(idx).ok()?;
                let name = device
                    .name()
                    .unwrap_or_else(|_| format!("GPU {idx}"));
                let temp_c = device
                    .temperature(TemperatureSensor::Gpu)
                    .ok()
                    .map(|t| t as f32);
                let reasons = device
                    .current_throttle_reasons()
                    .unwrap_or(ThrottleReasons::NONE);
                let thermal_throttled = reasons.intersects(
                    ThrottleReasons::SW_THERMAL_SLOWDOWN | ThrottleReasons::HW_THERMAL_SLOWDOWN,
                );
                Some(GpuTelemetry {
                    index: idx,
                    name,
                    temp_c,
                    thermal_throttled,
                    throttle_reasons: throttle_reason_labels(reasons),
                })
            })
            .collect()
    }
}

fn throttle_reason_labels(reasons: ThrottleReasons) -> Vec<String> {
    const FLAGS: &[(ThrottleReasons, &str)] = &[
        (ThrottleReasons::SW_THERMAL_SLOWDOWN, "sw-thermal"),
        (ThrottleReasons::HW_THERMAL_SLOWDOWN, "hw-thermal"),
        (ThrottleReasons::HW_SLOWDOWN, "hw-slowdown"),
        (
            ThrottleReasons::HW_POWER_BRAKE_SLOWDOWN,
            "hw-power-brake",
        ),
        (ThrottleReasons::SW_POWER_CAP, "power-cap"),
        (ThrottleReasons::SYNC_BOOST, "sync-boost"),
        (
            ThrottleReasons::APPLICATIONS_CLOCKS_SETTING,
            "app-clock-setting",
        ),
        (ThrottleReasons::DISPLAY_CLOCK_SETTING, "display-clock"),
    ];
    FLAGS
        .iter()
        .filter(|(flag, _)| reasons.contains(*flag))
        .map(|(_, label)| label.to_string())
        .collect()
}
