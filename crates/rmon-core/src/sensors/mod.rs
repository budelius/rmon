//! Direct hardware sensor access, independent of any other running
//! application.
//!
//! rMon's original thermal telemetry read whatever HWiNFO happened to be
//! exporting, which means it only worked while HWiNFO was running, with
//! the right export setting enabled, and with the right sensors in its
//! tray list. This layer replaces that dependency with the hardware
//! itself, through the [PawnIO](crate::pawnio) sandboxed kernel driver:
//! CPU package thermals from the CPU's own MSRs, and temperatures,
//! voltages, and fan tachometers from the motherboard's Super I/O chip.
//!
//! `SensorHub` is always preferred. HWiNFO is used only as a CPU thermal
//! fallback when that direct path is unavailable, or when a caller
//! explicitly requests HWiNFO's supplemental sensor tree.

pub mod intel_msr;
pub mod intel_power;
pub mod superio;

use std::time::{Duration, Instant};

pub use intel_msr::{IntelMsr, PackageThermal};
pub use intel_power::{
    CStateConfig, CurrentLimit, LimitReason, PackagePowerLimits, PlatformInfo, PowerControl,
    PowerLimit, Probe as MsrProbe, RaplUnits, Register as MsrRegister,
};
pub use superio::{
    BoardTemperatureReading, Chip, Family, FanReading, RawDump, SlotProbe, SuperIo,
    SuperIoReadings, VoltageReading, probe_slots,
};

use crate::pawnio::Availability;

/// How often the motherboard Super I/O block is re-read.
///
/// One sweep is dozens of port operations taken under a machine-wide
/// mutex that other monitoring tools also want. These values move slowly,
/// so paying that every one-second process tick would add contention for
/// no useful information.
const SUPERIO_REFRESH: Duration = Duration::from_secs(3);

fn pick_superio_cpu_temperature(readings: &[BoardTemperatureReading]) -> Option<f32> {
    const PRIORITIES: [&str; 3] = ["CPU package", "CPU (PECI)", "CPU"];
    PRIORITIES.into_iter().find_map(|wanted| {
        readings
            .iter()
            .find(|reading| {
                reading.temp_c.is_some()
                    && (reading.label == wanted
                        || reading
                            .label
                            .strip_suffix(wanted)
                            .is_some_and(|prefix| prefix.ends_with(' ')))
            })
            .and_then(|reading| reading.temp_c)
    })
}

/// Everything the kernel-backed sensor path could establish about this
/// machine, plus why anything missing is missing.
pub struct SensorHub {
    availability: Availability,
    msr: Option<IntelMsr>,
    superio: Option<SuperIo>,
    /// Why Super I/O access failed, when it did. Kept for display: "no
    /// chip recognised" and "needs Administrator" call for different
    /// responses from the user.
    superio_error: Option<String>,
    cached_fans: Vec<FanReading>,
    cached_temperatures: Vec<BoardTemperatureReading>,
    cached_voltages: Vec<VoltageReading>,
    last_superio_read: Option<Instant>,
}

impl SensorHub {
    /// Opens whatever is available. Never fails: a machine with no
    /// PawnIO, an unsupported chip, or no elevation is an ordinary
    /// outcome, recorded in [`availability`](Self::availability) rather
    /// than raised.
    pub fn new() -> Self {
        let availability = crate::pawnio::availability();
        if !availability.is_ready() {
            log::info!(
                "kernel sensor access unavailable: {}",
                availability.message()
            );
            // Carry the real reason forward rather than leaving it empty:
            // callers that report per-subsystem status would otherwise say
            // "no chip found", which blames the hardware for what is
            // actually a missing driver or missing elevation.
            let superio_error = Some(availability.message());
            return Self {
                availability,
                msr: None,
                superio: None,
                superio_error,
                cached_fans: Vec::new(),
                cached_temperatures: Vec::new(),
                cached_voltages: Vec::new(),
                last_superio_read: None,
            };
        }

        // An AMD part legitimately fails here (the IntelMSR module
        // refuses to load on non-Intel CPUs), so this is logged as
        // information, not as a problem.
        let msr = match IntelMsr::open() {
            Ok(m) => {
                log::info!("Intel MSR thermal access active, TjMax {}°C", m.tjmax_c());
                Some(m)
            }
            Err(e) => {
                log::info!("Intel MSR thermal access unavailable: {}", e.message());
                None
            }
        };

        let (superio, superio_error) = match SuperIo::detect() {
            Ok(s) => {
                for chip in s.chips() {
                    log::info!(
                        "Super I/O {} (id {:#04x} rev {:#04x}) on port {:#06x}, {} fan channel(s){}",
                        chip.name,
                        chip.id,
                        chip.revision,
                        chip.register_port,
                        chip.fan_count,
                        if chip.family.fans_supported() {
                            ""
                        } else {
                            " (not decoded)"
                        }
                    );
                }
                (Some(s), None)
            }
            Err(e) => (None, Some(e.message())),
        };

        Self {
            availability,
            msr,
            superio,
            superio_error,
            cached_fans: Vec::new(),
            cached_temperatures: Vec::new(),
            cached_voltages: Vec::new(),
            last_superio_read: None,
        }
    }

    pub fn availability(&self) -> &Availability {
        &self.availability
    }

    /// True when at least one kernel-backed source is actually producing
    /// readings — which is not the same as PawnIO being available, since
    /// the driver can open fine on hardware none of the modules support.
    pub fn has_any_source(&self) -> bool {
        self.msr.is_some()
            || self.superio.as_ref().is_some_and(|sio| {
                sio.chips()
                    .any(|chip| chip.family.board_sensors_supported())
            })
    }

    /// The Super I/O chip whose fans rMon can read, if any.
    pub fn chip(&self) -> Option<&Chip> {
        self.superio.as_ref().and_then(SuperIo::primary)
    }

    /// Every Super I/O chip found, decodable or not. Boards routinely
    /// carry two, and which one owns the fan headers is not something the
    /// chips themselves advertise.
    pub fn chips(&self) -> Vec<&Chip> {
        self.superio
            .as_ref()
            .map(|s| s.chips().collect())
            .unwrap_or_default()
    }

    pub fn superio_error(&self) -> Option<&str> {
        self.superio_error.as_deref()
    }

    /// Raw Super I/O register bytes for every detected chip, for
    /// diagnosing implausible fan readings.
    pub fn raw_dump(&self) -> Vec<RawDump> {
        self.superio
            .as_ref()
            .map(SuperIo::raw_dump)
            .unwrap_or_default()
    }

    /// Current CPU package thermal state, straight from the MSRs.
    pub fn cpu_package(&self) -> Option<PackageThermal> {
        let msr = self.msr.as_ref()?;
        match msr.read() {
            Ok(p) => Some(p),
            Err(e) => {
                log::debug!("package thermal read failed: {e:#}");
                None
            }
        }
    }

    /// Refreshes all motherboard sensor classes together. Between
    /// refreshes, and after a transient failure (normally another tool
    /// holding the ISA mutex), callers keep seeing the last good set.
    fn refresh_superio(&mut self) {
        let due = self
            .last_superio_read
            .is_none_or(|t| t.elapsed() >= SUPERIO_REFRESH);
        if !due {
            return;
        }
        let Some(sio) = self.superio.as_ref() else {
            return;
        };

        let started = Instant::now();
        self.last_superio_read = Some(started);
        match sio.read_sensors() {
            Ok(readings) => {
                self.cached_fans = readings.fans;
                self.cached_temperatures = readings.temperatures;
                self.cached_voltages = readings.voltages;
            }
            Err(e) => log::debug!("Super I/O sensor read failed: {e:#}"),
        }
        // Logged because this is ISA port traffic on the sampling thread:
        // if it ever grows past a few milliseconds it belongs on a worker.
        log::debug!("Super I/O sensor read took {:?}", started.elapsed());
    }

    /// Fan tachometer readings, refreshed at most every
    /// [`SUPERIO_REFRESH`].
    pub fn fans(&mut self) -> &[FanReading] {
        self.refresh_superio();
        &self.cached_fans
    }

    /// Motherboard temperatures read directly from the Super I/O chip.
    pub fn board_temperatures(&mut self) -> &[BoardTemperatureReading] {
        self.refresh_superio();
        &self.cached_temperatures
    }

    /// Best direct CPU-scoped Super I/O temperature, used before asking
    /// HWiNFO when package MSRs are unavailable (notably on AMD). Socket
    /// temperature is deliberately not treated as package temperature.
    pub fn cpu_temperature(&mut self) -> Option<f32> {
        self.refresh_superio();
        pick_superio_cpu_temperature(&self.cached_temperatures)
    }

    /// Motherboard voltage inputs read directly from the Super I/O chip.
    pub fn voltages(&mut self) -> &[VoltageReading] {
        self.refresh_superio();
        &self.cached_voltages
    }

    /// A one-line description of where sensor data is coming from, for
    /// the UI's sensors view.
    pub fn status_line(&self) -> String {
        if !self.availability.is_ready() {
            return self.availability.message();
        }
        let mut parts = Vec::new();
        match &self.msr {
            Some(m) => parts.push(format!("CPU MSRs (TjMax {}°C)", m.tjmax_c())),
            None => parts.push("no CPU MSR access".to_string()),
        }
        let chips = self.chips();
        if chips.is_empty() {
            parts.push(
                self.superio_error
                    .clone()
                    .unwrap_or_else(|| "no Super I/O chip found".to_string()),
            );
        } else {
            for c in chips {
                if c.family.board_sensors_supported() {
                    parts.push(format!(
                        "{} (temperatures, voltages, {} fan channels)",
                        c.name, c.fan_count
                    ));
                } else {
                    parts.push(format!("{} — sensor registers not decoded by rMon", c.name));
                }
            }
        }
        format!("PawnIO: {}", parts.join(" · "))
    }
}

impl Default for SensorHub {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_or_peci_temperature_wins_over_generic_cpu() {
        let readings = vec![
            BoardTemperatureReading {
                chip: "b".into(),
                index: 0,
                label: "NCT6686D CPU".into(),
                temp_c: Some(61.0),
            },
            BoardTemperatureReading {
                chip: "a".into(),
                index: 1,
                label: "NCT6799D CPU (PECI)".into(),
                temp_c: Some(57.0),
            },
        ];
        assert_eq!(pick_superio_cpu_temperature(&readings), Some(57.0));
    }

    /// Live probe: prints what this machine can do. Asserts only
    /// invariants that must hold everywhere, since CI has no PawnIO and
    /// no motherboard sensors. Run with `cargo test -- --nocapture`.
    #[test]
    fn sensor_hub_reports_honestly() {
        let mut hub = SensorHub::new();
        println!("{}", hub.status_line());
        if let Some(p) = hub.cpu_package() {
            println!(
                "package: {:.0}°C ({:.0}°C below TjMax {:.0}°C) throttling={} prochot={} \
                 power_limited={} thermal_since_boot={}",
                p.temp_c,
                p.headroom_c,
                p.tjmax_c,
                p.thermal_throttling,
                p.prochot,
                p.power_limited,
                p.thermal_since_boot
            );
            assert!(
                (-20.0..=150.0).contains(&p.temp_c),
                "implausible package temperature {}",
                p.temp_c
            );
        }
        for f in hub.fans() {
            println!("{}: {:?}", f.label, f.rpm);
        }
        for t in hub.board_temperatures() {
            println!("{}: {:?}°C", t.label, t.temp_c);
        }
        for v in hub.voltages() {
            println!("{}: {:?}V", v.label, v.volts);
        }
        if !hub.has_any_source() {
            assert!(
                hub.cpu_package().is_none(),
                "no source must mean no readings"
            );
        }
    }
}
