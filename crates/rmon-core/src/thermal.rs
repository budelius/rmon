//! Best-effort CPU temperature and clock-scaling telemetry via WMI.
//!
//! Windows has no vendor-neutral API for per-core CPU temperature or a
//! "throttled because of temperature" flag (that's what tools like HWiNFO
//! use vendor MSR-reading kernel drivers for). What IS available without a
//! kernel driver:
//!
//! - `MSAcpi_ThermalZoneTemperature` (namespace `ROOT\WMI`) — an ACPI
//!   thermal zone reading. Present on many systems, but frequently absent,
//!   inaccurate, or not actually the CPU package on others.
//! - `Win32_Processor.CurrentClockSpeed` vs `MaxClockSpeed` — lets us detect
//!   that the CPU is running below its rated clock, which we surface as a
//!   heuristic "throttled" flag (cause unconfirmed: could be thermal, power,
//!   or an idle power-saving state).

use std::time::{Duration, Instant};

use serde::Deserialize;
use wmi::WMIConnection;

/// How often the WMI-backed readings (ACPI thermal zone, Win32_Processor
/// clock speeds) are actually re-queried. WMI queries cost anywhere from
/// ~5ms to ~100ms each — far too much to pay every 1s sampling tick for
/// values that move on multi-second timescales. In between, `sample()`
/// returns the cached readings. (The HWiNFO shared-memory path is a plain
/// memory read and stays per-tick.)
const WMI_REFRESH: Duration = Duration::from_secs(5);

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct AcpiThermalZone {
    CurrentTemperature: u32,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct ProcessorClock {
    CurrentClockSpeed: u32,
    MaxClockSpeed: u32,
}

pub struct CpuThermalMonitor {
    acpi: Option<WMIConnection>,
    cimv2: Option<WMIConnection>,
    last_wmi_query: Option<Instant>,
    cached_acpi_temp: Option<f32>,
    cached_clock_ratio: Option<f32>,
}

impl CpuThermalMonitor {
    pub fn new() -> Self {
        let acpi = WMIConnection::with_namespace_path("ROOT\\WMI")
            .inspect_err(|e| log::info!("ACPI thermal zone WMI unavailable: {e:#}"))
            .ok();
        let cimv2 = WMIConnection::new()
            .inspect_err(|e| log::warn!("WMI ROOT\\CIMV2 unavailable: {e:#}"))
            .ok();
        Self {
            acpi,
            cimv2,
            last_wmi_query: None,
            cached_acpi_temp: None,
            cached_clock_ratio: None,
        }
    }

    /// Returns (avg CPU temp °C, temp source label, avg clock ratio 0..=1).
    /// Whether the temp amounts to "throttled" depends on concurrent load,
    /// which callers combine this with (see `Sampler`).
    ///
    /// Prefers real per-core/package readings from HWiNFO's Shared Memory
    /// Support (when HWiNFO is running with it enabled) over the ACPI
    /// thermal zone, which is frequently absent, inaccurate, or not
    /// actually the CPU package on many systems.
    pub fn sample(&mut self) -> (Option<f32>, Option<&'static str>, Option<f32>) {
        let refresh_wmi = self
            .last_wmi_query
            .is_none_or(|t| t.elapsed() >= WMI_REFRESH);
        if refresh_wmi {
            self.last_wmi_query = Some(Instant::now());
            self.cached_acpi_temp = self.acpi.as_ref().and_then(|conn| {
                let rows: Vec<AcpiThermalZone> = conn
                    .raw_query("SELECT CurrentTemperature FROM MSAcpi_ThermalZoneTemperature")
                    .ok()?;
                average(
                    rows.iter()
                        .map(|r| r.CurrentTemperature as f32 / 10.0 - 273.15)
                        .filter(|c| (-50.0..150.0).contains(c)),
                )
            });
            self.cached_clock_ratio = self.cimv2.as_ref().and_then(|conn| {
                let rows: Vec<ProcessorClock> = conn
                    .raw_query("SELECT CurrentClockSpeed, MaxClockSpeed FROM Win32_Processor")
                    .ok()?;
                average(
                    rows.iter()
                        .filter(|r| r.MaxClockSpeed > 0)
                        .map(|r| r.CurrentClockSpeed as f32 / r.MaxClockSpeed as f32),
                )
            });
        }

        let (temp_c, temp_source) = match crate::hwinfo::read_cpu_temp() {
            Some(t) => (Some(t), Some("HWiNFO")),
            None => (
                self.cached_acpi_temp,
                self.cached_acpi_temp.map(|_| "ACPI zone (approximate)"),
            ),
        };
        (temp_c, temp_source, self.cached_clock_ratio)
    }
}

impl Default for CpuThermalMonitor {
    fn default() -> Self {
        Self::new()
    }
}

fn average(values: impl Iterator<Item = f32>) -> Option<f32> {
    let mut sum = 0.0;
    let mut count = 0u32;
    for v in values {
        sum += v;
        count += 1;
    }
    (count > 0).then(|| sum / count as f32)
}
