//! Intel CPU package thermal state read straight from the hardware's own
//! model-specific registers, via PawnIO's `IntelMSR` module.
//!
//! This is the source rMon actually wants, and the reason the kernel
//! driver path exists at all. Everything the WMI/HWiNFO path guesses at,
//! the CPU states outright:
//!
//! - **`IA32_TEMPERATURE_TARGET`** carries this exact part's TjMax, so we
//!   no longer have to pick between a hardcoded 100°C (wrong on AMD and
//!   on many mobile Intel parts) and giving up.
//! - **`IA32_PACKAGE_THERM_STATUS`** reports temperature as a *digital
//!   readout below TjMax*, which is how the silicon natively measures it
//!   — headroom comes free and exactly, instead of depending on whether
//!   the user happened to add "Distance to TjMAX" to HWiNFO's tray list.
//! - The same register's status bits say whether the thermal control
//!   circuit is engaged *right now*. That replaces the clock-ratio
//!   heuristic in `sampler.rs` with the hardware's own answer: no more
//!   inferring "probably throttling" from `Win32_Processor` reporting a
//!   low clock, and no more missing throttling that happens at a
//!   nominally full clock (which is the normal case, since a part at
//!   TjMax sheds heat by trimming duty cycle rather than by dropping its
//!   reported frequency).
//!
//! The module is allowlisted inside the driver: it will read these
//! registers and about thirty other thermal/power ones, and returns
//! `STATUS_ACCESS_DENIED` for anything else. That bound is the whole
//! point of using PawnIO instead of a general-purpose MSR driver.

use anyhow::{Result, bail};

use crate::pawnio::{Availability, Module, PawnIo};

/// Per-core thermal status. Used only as a fallback: it reports the core
/// the call happened to land on, not the package.
const IA32_THERM_STATUS: u64 = 0x19C;
/// Package-wide thermal status: digital readout plus the status/log bits.
const IA32_PACKAGE_THERM_STATUS: u64 = 0x1B1;
/// Bits 23:16 hold TjMax (the TCC activation temperature) in °C.
const IA32_TEMPERATURE_TARGET: u64 = 0x1A2;

/// Used only if `IA32_TEMPERATURE_TARGET` reports something implausible.
/// Intel desktop parts have run TjMax at 100°C for many generations.
const TJMAX_FALLBACK_C: f32 = 100.0;
/// Plausibility window for a TjMax reading. Mobile parts go as low as
/// ~85°C; nothing ships above ~115°C.
const TJMAX_PLAUSIBLE: std::ops::RangeInclusive<f32> = 70.0..=115.0;

/// One reading of the CPU package's thermal state.
///
/// The `*_since_boot` fields come from the register's sticky log bits,
/// which latch on the first event and stay latched. They are reported
/// separately from the live bits precisely because they mean something
/// weaker but useful: they catch episodes far shorter than rMon's
/// one-second sampling tick, at the cost of never being able to say
/// *when* it happened, or to clear once it stops.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PackageThermal {
    pub temp_c: f32,
    pub tjmax_c: f32,
    /// °C below TjMax. This is the raw hardware measurement; `temp_c` is
    /// the derived value, not the other way round.
    pub headroom_c: f32,
    /// The thermal control circuit is engaged right now: the part is
    /// actively being slowed to stay within its thermal limit. Unlike
    /// the clock-ratio heuristic, this is not an inference.
    pub thermal_throttling: bool,
    /// PROCHOT# is asserted — the platform (not just the die) is
    /// signalling an over-temperature condition, e.g. VRM or a
    /// board-level sensor.
    pub prochot: bool,
    /// Critical temperature reached: past the point of clock trimming,
    /// the part is close to shutting itself down.
    pub critical: bool,
    /// Clocks are being limited by a *power* cap (PL1/PL2/EDP) rather
    /// than by temperature. It depresses the same per-process numbers, so
    /// it matters here, but it calls for a completely different fix.
    pub power_limited: bool,
    /// Thermal throttling has occurred at least once since boot.
    pub thermal_since_boot: bool,
    /// Power limiting has occurred at least once since boot.
    pub power_limited_since_boot: bool,
}

impl PackageThermal {
    /// A short human-readable cause, or `None` when nothing is limiting
    /// the package. Ordered by severity: a critical-temperature part is
    /// also thermally throttling, and saying so is the more useful fact.
    pub fn limit_reason(&self) -> Option<String> {
        if self.critical {
            return Some(format!(
                "critical temperature ({:.0}°C, {:.0}°C from TjMax)",
                self.temp_c, self.headroom_c
            ));
        }
        if self.thermal_throttling {
            return Some(format!(
                "thermal limit reached — TCC active at {:.0}°C",
                self.temp_c
            ));
        }
        if self.prochot {
            return Some("PROCHOT# asserted by the platform".to_string());
        }
        if self.power_limited {
            return Some("power limit (PL1/PL2/EDP), not temperature".to_string());
        }
        None
    }
}

/// An open `IntelMSR` executor plus this part's TjMax, read once.
pub struct IntelMsr {
    io: PawnIo,
    tjmax_c: f32,
}

impl IntelMsr {
    /// Opens the module. Fails cleanly on non-Intel parts: `IntelMSR`'s
    /// own `main()` refuses to load unless the CPU vendor is Intel, so
    /// an AMD machine lands here as a normal "unavailable", not an error.
    pub fn open() -> std::result::Result<Self, Availability> {
        let io = PawnIo::load(Module::IntelMsr)?;
        let tjmax_c = read_tjmax(&io);
        Ok(Self { io, tjmax_c })
    }

    pub fn tjmax_c(&self) -> f32 {
        self.tjmax_c
    }

    /// Reads the package's current thermal state.
    pub fn read(&self) -> Result<PackageThermal> {
        let pkg = self
            .io
            .execute1("ioctl_read_msr", IA32_PACKAGE_THERM_STATUS)?;
        let (readout, status) = match digital_readout(pkg) {
            // Some parts (and some VM/microcode combinations) leave the
            // package register empty. The per-core register is a worse
            // answer — it describes whichever core we ran on — but it
            // beats reporting nothing.
            None => {
                let core = self.io.execute1("ioctl_read_msr", IA32_THERM_STATUS)?;
                match digital_readout(core) {
                    Some(r) => (r, core),
                    None => bail!("neither package nor core thermal status carried a readout"),
                }
            }
            Some(r) => (r, pkg),
        };

        let headroom_c = readout as f32;
        Ok(PackageThermal {
            temp_c: self.tjmax_c - headroom_c,
            tjmax_c: self.tjmax_c,
            headroom_c,
            thermal_throttling: status & (1 << 0) != 0,
            prochot: status & (1 << 2) != 0,
            critical: status & (1 << 4) != 0,
            power_limited: status & (1 << 10) != 0,
            thermal_since_boot: status & (1 << 1) != 0,
            power_limited_since_boot: status & (1 << 11) != 0,
        })
    }
}

/// Bits 22:16 of either thermal status register: °C below TjMax.
///
/// `None` for a readout of zero, which nominally means "exactly at
/// TjMax" but in practice almost always means the register was never
/// populated — reporting a CPU as sitting precisely at its limit on the
/// strength of an all-zero register would be a spectacular false alarm.
/// A part genuinely at TjMax reports the thermal status bit as well, and
/// [`IntelMsr::read`] surfaces that regardless.
fn digital_readout(status: u64) -> Option<u32> {
    let readout = ((status >> 16) & 0x7F) as u32;
    (readout != 0).then_some(readout)
}

fn read_tjmax(io: &PawnIo) -> f32 {
    let raw = match io.execute1("ioctl_read_msr", IA32_TEMPERATURE_TARGET) {
        Ok(v) => v,
        Err(e) => {
            log::info!("IA32_TEMPERATURE_TARGET unreadable ({e:#}); assuming {TJMAX_FALLBACK_C}°C");
            return TJMAX_FALLBACK_C;
        }
    };
    let tjmax = ((raw >> 16) & 0xFF) as f32;
    if TJMAX_PLAUSIBLE.contains(&tjmax) {
        tjmax
    } else {
        log::warn!("implausible TjMax {tjmax}°C from MSR; assuming {TJMAX_FALLBACK_C}°C");
        TJMAX_FALLBACK_C
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(readout: u64, bits: u64) -> u64 {
        (readout << 16) | bits
    }

    #[test]
    fn readout_of_zero_is_treated_as_absent() {
        assert_eq!(digital_readout(status(0, 0)), None);
        assert_eq!(digital_readout(status(40, 0)), Some(40));
    }

    #[test]
    fn readout_ignores_bits_above_the_field() {
        // Bit 31 (reading-valid, on the per-core register) must not leak
        // into the temperature.
        assert_eq!(digital_readout(status(40, 0) | (1 << 31)), Some(40));
    }

    /// Critical outranks plain thermal throttling in the reason string:
    /// both bits are set at that point, and "critical" is the one worth
    /// reading.
    #[test]
    fn limit_reason_prefers_the_severe_cause() {
        let p = PackageThermal {
            temp_c: 100.0,
            tjmax_c: 100.0,
            headroom_c: 0.0,
            thermal_throttling: true,
            prochot: true,
            critical: true,
            power_limited: true,
            thermal_since_boot: true,
            power_limited_since_boot: true,
        };
        assert!(p.limit_reason().unwrap().contains("critical"));
    }

    #[test]
    fn no_active_bits_means_no_reason() {
        let p = PackageThermal {
            temp_c: 55.0,
            tjmax_c: 100.0,
            headroom_c: 45.0,
            thermal_throttling: false,
            prochot: false,
            critical: false,
            power_limited: false,
            // Sticky history alone must not read as "throttling now".
            thermal_since_boot: true,
            power_limited_since_boot: true,
        };
        assert_eq!(p.limit_reason(), None);
    }
}
