//! Fallback CPU temperature and clock-scaling telemetry, for machines
//! where the direct MSR path in [`crate::sensors`] isn't available.
//!
//! When PawnIO is installed and rMon is elevated, the CPU reports its own
//! temperature, its own TjMax, and whether its thermal control circuit is
//! engaged — see [`crate::sensors::intel_msr`], whose readings this module
//! prefers over everything below. A CPU-scoped temperature from the same
//! SensorHub's Super I/O path is accepted next. This file is what's left
//! when those paths are closed: no vendor-neutral Windows API exposes per-core temperature
//! or a "throttled because of temperature" flag, so all that remains is:
//!
//! - `MSAcpi_ThermalZoneTemperature` (namespace `ROOT\WMI`) — an ACPI
//!   thermal zone reading. Present on many systems, but frequently absent,
//!   inaccurate, or not actually the CPU package on others.
//! - The kernel's processor power state — lets us detect that the CPU is
//!   running below its rated clock, which we surface as a heuristic
//!   "throttled" flag (cause unconfirmed: could be thermal, power, or an
//!   idle power-saving state).
//!
//! # Cost
//!
//! Both readings above were originally WMI queries, and WMI is not a
//! library call: every `SELECT` is dispatched to the shared `WmiPrvSE.exe`
//! provider host, which does the work in kernel on rMon's behalf and bills
//! it to a process rMon doesn't appear in. That made rMon's own cost
//! invisible in rMon. Measured on a 32-thread box carrying ~1,200
//! processes, `SELECT ... FROM Win32_Processor` cost the CIMWin32 provider
//! roughly 0.5 core-seconds per call — paid every 5s, in every running
//! rMon instance, for a number the kernel will hand over directly. So:
//!
//! - Clock ratio comes from `CallNtPowerInformation`, one syscall against
//!   state the kernel already maintains. No WMI at all.
//! - The ACPI thermal zone is queried only when it is the source we would
//!   actually display — never when the MSR or HWiNFO path already answered
//!   — and gives up permanently once the class proves unsupported, which
//!   is a fixed property of the machine rather than a transient failure.

use std::time::{Duration, Instant};

use serde::Deserialize;
use windows::Win32::System::Power::{
    CallNtPowerInformation, PROCESSOR_POWER_INFORMATION, ProcessorInformation,
};
use windows::Win32::System::Threading::{ALL_PROCESSOR_GROUPS, GetActiveProcessorCount};
use wmi::WMIConnection;

use crate::sensors::PackageThermal;

/// How often the ACPI thermal zone is re-queried, on the machines where
/// it is reached at all. A WMI query costs anywhere from ~5ms to ~100ms
/// of provider-host CPU — far too much to pay every 1s sampling tick for
/// a value that moves on multi-second timescales. In between, `sample()`
/// returns the cached reading. (The HWiNFO shared-memory path is a plain
/// memory read and stays per-tick, as does the clock ratio now that it no
/// longer goes through WMI.)
const WMI_REFRESH: Duration = Duration::from_secs(5);

/// How many consecutive failed ACPI thermal zone queries before the source
/// is abandoned for the life of the process.
///
/// `MSAcpi_ThermalZoneTemperature` is either implemented by the firmware
/// or it isn't; a box that answers `WBEM_E_NOT_SUPPORTED` will answer it
/// forever. Retrying every 5s produced nothing but event-log noise — on
/// the machine that prompted this, 398 of the last 400 WMI-Activity events
/// were this one query failing. The strike count exists only so a single
/// transient hiccup doesn't cost us a source that does work.
const ACPI_MAX_STRIKES: u8 = 3;

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct AcpiThermalZone {
    CurrentTemperature: u32,
}

/// One tick's worth of CPU thermal telemetry.
#[derive(Debug, Clone, Default)]
pub struct CpuThermalSample {
    /// Average CPU temperature in °C, if any source could provide one.
    pub temp_c: Option<f32>,
    /// Which source `temp_c` came from, for display honesty.
    pub temp_source: Option<&'static str>,
    /// Current/max clock speed averaged across logical processors.
    pub clock_ratio: Option<f32>,
    /// °C below TjMax. `None` means unknown — not "plenty of headroom".
    pub tjmax_distance_c: Option<f32>,
    /// A hardware-reported reason the CPU is being held back, available
    /// only on the MSR path. When this is `Some`, callers should use it
    /// verbatim and skip the clock-ratio heuristic entirely: the CPU has
    /// told us what is happening, so there is nothing left to infer.
    pub hardware_limit_reason: Option<String>,
    /// Sticky since-boot thermal throttle flag from the MSR path.
    pub thermal_since_boot: bool,
}

pub struct CpuThermalMonitor {
    /// `None` once the ACPI thermal zone has been ruled out — either it
    /// was never reachable, or it failed [`ACPI_MAX_STRIKES`] times.
    acpi: Option<WMIConnection>,
    acpi_strikes: u8,
    last_acpi_query: Option<Instant>,
    cached_acpi_temp: Option<f32>,
    /// Logical processor count, fixed for the life of the process and used
    /// to size the buffer `CallNtPowerInformation` writes into.
    cpu_count: u32,
}

impl CpuThermalMonitor {
    pub fn new() -> Self {
        let acpi = WMIConnection::with_namespace_path(r"ROOT\WMI")
            .inspect_err(|e| log::info!("ACPI thermal zone WMI unavailable: {e:#}"))
            .ok();
        // SAFETY: no arguments beyond a constant; the call only reads
        // kernel-maintained topology.
        let cpu_count = unsafe { GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) };
        Self {
            acpi,
            acpi_strikes: 0,
            last_acpi_query: None,
            cached_acpi_temp: None,
            cpu_count,
        }
    }

    /// Samples current CPU thermal state. How this maps to "throttled" is
    /// decided by the caller (see `Sampler`).
    ///
    /// Sources are tried strongest first, and a stronger source that
    /// answers means the weaker ones are never consulted — which is a cost
    /// decision as much as a correctness one, since the weakest source is
    /// the only one that costs a WMI round-trip. `package`, when present,
    /// is the CPU's own report of its temperature and limit state and
    /// needs no interpretation. A direct CPU-scoped Super I/O reading is
    /// next (useful when Intel MSRs do not apply). Only when neither direct
    /// source answers is HWiNFO consulted; ACPI remains last.
    pub fn sample(
        &mut self,
        package: Option<&PackageThermal>,
        superio_cpu_temp: Option<f32>,
    ) -> CpuThermalSample {
        let clock_ratio = self.clock_ratio();

        if let Some(p) = package {
            return CpuThermalSample {
                temp_c: Some(p.temp_c),
                temp_source: Some("CPU MSR"),
                clock_ratio,
                tjmax_distance_c: Some(p.headroom_c),
                hardware_limit_reason: p.limit_reason(),
                thermal_since_boot: p.thermal_since_boot,
            };
        }

        if let Some(temp_c) = superio_cpu_temp {
            return CpuThermalSample {
                temp_c: Some(temp_c),
                temp_source: Some("Super I/O CPU sensor"),
                clock_ratio,
                tjmax_distance_c: None,
                hardware_limit_reason: None,
                thermal_since_boot: false,
            };
        }

        let (hw_temp, tjmax_distance_c) = crate::hwinfo::read_cpu_thermal();
        let (temp_c, temp_source) = match hw_temp {
            Some(t) => (Some(t), Some("HWiNFO")),
            None => {
                let acpi = self.acpi_temp();
                (acpi, acpi.map(|_| "ACPI zone (approximate)"))
            }
        };
        CpuThermalSample {
            temp_c,
            temp_source,
            clock_ratio,
            tjmax_distance_c,
            hardware_limit_reason: None,
            thermal_since_boot: false,
        }
    }

    /// Current/max clock ratio averaged across logical processors.
    ///
    /// This reads the same processor performance state that
    /// `Win32_Processor.CurrentClockSpeed` reports, without routing the
    /// question through the WMI provider host — see the module's cost
    /// note. Processors the kernel didn't write to keep the zeroed
    /// `MaxMhz` they were allocated with and are filtered out, which is
    /// also what makes an over-allocated buffer harmless on machines with
    /// more than one processor group.
    fn clock_ratio(&self) -> Option<f32> {
        if self.cpu_count == 0 {
            return None;
        }
        let mut info = vec![PROCESSOR_POWER_INFORMATION::default(); self.cpu_count as usize];
        let bytes = std::mem::size_of_val(info.as_slice()) as u32;
        // SAFETY: `info` is a live, zeroed array of exactly the struct the
        // kernel writes for `ProcessorInformation`, and `bytes` is its true
        // length in bytes. The call writes only within that buffer, and
        // takes no input buffer at this information level.
        let status = unsafe {
            CallNtPowerInformation(
                ProcessorInformation,
                None,
                0,
                Some(info.as_mut_ptr().cast()),
                bytes,
            )
        };
        // NTSTATUS: negative is failure, and there is nothing to fall back
        // to — the clock ratio is simply unknown this tick.
        if status.0 < 0 {
            return None;
        }
        average(
            info.iter()
                .filter(|p| p.MaxMhz > 0)
                .map(|p| p.CurrentMhz as f32 / p.MaxMhz as f32),
        )
    }

    /// Cached ACPI thermal zone temperature, refreshed at most every
    /// [`WMI_REFRESH`] and only while the source is still believed to work.
    fn acpi_temp(&mut self) -> Option<f32> {
        let due = self
            .last_acpi_query
            .is_none_or(|t| t.elapsed() >= WMI_REFRESH);
        let Some(conn) = self.acpi.as_ref().filter(|_| due) else {
            return self.cached_acpi_temp;
        };
        self.last_acpi_query = Some(Instant::now());

        let rows: Option<Vec<AcpiThermalZone>> = conn
            .raw_query("SELECT CurrentTemperature FROM MSAcpi_ThermalZoneTemperature")
            .inspect_err(|e| log::debug!("ACPI thermal zone query failed: {e:#}"))
            .ok();
        let reading = rows.and_then(|rows| {
            average(
                rows.iter()
                    .map(|r| r.CurrentTemperature as f32 / 10.0 - 273.15)
                    .filter(|c| (-50.0..150.0).contains(c)),
            )
        });

        // A query that errors and a query that returns nothing usable are
        // the same outcome here: this machine has no ACPI thermal zone we
        // can read, and asking again costs the provider host real CPU.
        match reading {
            Some(_) => self.acpi_strikes = 0,
            None => {
                self.acpi_strikes = self.acpi_strikes.saturating_add(1);
                if self.acpi_strikes >= ACPI_MAX_STRIKES {
                    log::info!(
                        "ACPI thermal zone unusable after {ACPI_MAX_STRIKES} attempts; \
                         not querying it again this session"
                    );
                    self.acpi = None;
                }
            }
        }
        self.cached_acpi_temp = reading;
        reading
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole reason this reading left WMI: it has to be cheap enough
    /// to take on every sampling tick, in every running rMon instance,
    /// without billing a shared provider host for it. A WMI round-trip
    /// for the same numbers was measured at ~0.5 core-seconds on a busy
    /// box; this budget is loose enough not to flake on a loaded machine
    /// and still three orders of magnitude below that.
    #[test]
    fn clock_ratio_is_plausible_and_cheap() {
        let monitor = CpuThermalMonitor::new();
        assert!(monitor.cpu_count > 0, "no active processors reported");

        monitor.clock_ratio(); // first call warms the powrprof.dll load
        let start = Instant::now();
        let ratio = monitor.clock_ratio();
        let elapsed = start.elapsed();

        println!(
            "clock ratio {ratio:?} read in {elapsed:?} over {} cpus",
            monitor.cpu_count
        );
        assert!(
            elapsed < Duration::from_millis(5),
            "native clock read took {elapsed:?}, which defeats the point of leaving WMI"
        );
        // The kernel always knows its own p-states, so unlike the thermal
        // sources this one has no legitimate "unavailable" outcome.
        let ratio = ratio.expect("kernel reported no usable processor clocks");
        assert!(
            (0.01..=2.0).contains(&ratio),
            "implausible clock ratio {ratio}"
        );
    }

    /// A machine whose firmware has no thermal zone must stop asking.
    /// Without this the query is reissued every 5s forever, which is what
    /// filled the WMI-Activity log on the machine that prompted the fix.
    #[test]
    fn acpi_gives_up_after_repeated_failures() {
        let mut monitor = CpuThermalMonitor::new();
        if monitor.acpi.is_none() {
            return; // already ruled out at construction; nothing to prove
        }
        for _ in 0..ACPI_MAX_STRIKES {
            monitor.last_acpi_query = None; // defeat the refresh interval
            monitor.acpi_temp();
        }
        println!(
            "after {ACPI_MAX_STRIKES} attempts: acpi_dropped={} reading={:?}",
            monitor.acpi.is_none(),
            monitor.cached_acpi_temp
        );
        assert_eq!(
            monitor.acpi.is_none(),
            monitor.cached_acpi_temp.is_none(),
            "the connection must be dropped exactly when the source never answered"
        );
    }
}
