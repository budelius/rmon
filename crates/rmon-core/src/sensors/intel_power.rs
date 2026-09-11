//! Intel package *power* configuration and limit attribution, read from
//! the CPU's own MSRs through the same PawnIO `IntelMSR` module that
//! [`super::intel_msr`] uses for thermals.
//!
//! # Why this exists
//!
//! `IA32_PACKAGE_THERM_STATUS` bit 10 says only that *a* power limit is
//! engaged. [`super::intel_msr::PackageThermal::limit_reason`] therefore
//! has to report the unhelpfully broad "power limit (PL1/PL2/EDP)",
//! which is three completely different problems wearing one label:
//!
//! - **PL1** — the sustained package budget is exhausted. Expected on a
//!   long all-core load; the fix, if any, is a higher PL1 or less work.
//! - **PL2** — the short-burst budget. Bumping this for a few hundred
//!   milliseconds at the start of a load is *designed* behaviour and
//!   almost never worth acting on.
//! - **EDP/IccMax** — the electrical current ceiling. A different
//!   ceiling with different causes, and the one that most often
//!   surprises people, because it can trip well below the wattage cap.
//!
//! `MSR_CORE_PERF_LIMIT_REASONS` separates them, and the RAPL registers
//! say what the limits were actually *configured* to — which is the
//! question anyone comparing their machine against a BIOS profile is
//! really asking.
//!
//! # The allowlist problem
//!
//! PawnIO's `IntelMSR` module permits roughly thirty thermal/power MSRs
//! and answers `STATUS_ACCESS_DENIED` for everything else. Which thirty
//! is a property of the vendored module blob, not something rMon gets to
//! decide, and it is not documented in a form worth hardcoding a belief
//! about. So this module treats every register as *possibly* denied:
//! [`probe`] reports per-MSR what happened, and every decoded field is
//! an `Option` that stays `None` when its source register could not be
//! read.
//!
//! That distinction is load-bearing per the crate's rules: a register we
//! were refused must never be rendered as a measured zero.

use crate::pawnio::PawnIo;

/// One MSR this module would like to read, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Register {
    pub addr: u64,
    pub name: &'static str,
    /// What the register contributes, for the probe's output.
    pub purpose: &'static str,
}

/// Every register the power path wants, in the order the probe reports
/// them. Thermal registers already covered by [`super::intel_msr`] are
/// deliberately absent.
pub const REGISTERS: &[Register] = &[
    Register {
        addr: MSR_RAPL_POWER_UNIT,
        name: "MSR_RAPL_POWER_UNIT",
        purpose: "scaling for every other RAPL register",
    },
    Register {
        addr: MSR_PKG_POWER_LIMIT,
        name: "MSR_PKG_POWER_LIMIT",
        purpose: "PL1/PL2 in watts, their time windows, and the lock bit",
    },
    Register {
        addr: MSR_PKG_POWER_INFO,
        name: "MSR_PKG_POWER_INFO",
        purpose: "the part's TDP and its min/max power",
    },
    Register {
        addr: MSR_PKG_ENERGY_STATUS,
        name: "MSR_PKG_ENERGY_STATUS",
        purpose: "running energy counter; two reads give actual package watts",
    },
    Register {
        addr: MSR_CORE_PERF_LIMIT_REASONS,
        name: "MSR_CORE_PERF_LIMIT_REASONS",
        purpose: "which limit is throttling: PL1 vs PL2 vs EDP vs the rest",
    },
    Register {
        addr: MSR_VR_CURRENT_CONFIG,
        name: "MSR_VR_CURRENT_CONFIG",
        purpose: "IccMax, the EDP current ceiling a BIOS profile sets",
    },
    Register {
        addr: MSR_PKG_CST_CONFIG_CONTROL,
        name: "MSR_PKG_CST_CONFIG_CONTROL",
        purpose: "package C-state limit and whether BIOS locked it",
    },
    Register {
        addr: MSR_POWER_CTL,
        name: "MSR_POWER_CTL",
        purpose: "C1E enable and bi-directional PROCHOT",
    },
    Register {
        addr: MSR_PLATFORM_INFO,
        name: "MSR_PLATFORM_INFO",
        purpose: "base ratio, and whether ratio/TDP limits are unlocked",
    },
    Register {
        addr: MSR_TURBO_RATIO_LIMIT,
        name: "MSR_TURBO_RATIO_LIMIT",
        purpose: "per-active-core turbo bins, as OC Tweaker writes them",
    },
    Register {
        addr: IA32_PERF_STATUS,
        name: "IA32_PERF_STATUS",
        purpose: "current core VID, for judging an undervolt",
    },
];

const MSR_PLATFORM_INFO: u64 = 0xCE;
const MSR_PKG_CST_CONFIG_CONTROL: u64 = 0xE2;
const IA32_PERF_STATUS: u64 = 0x198;
const MSR_TURBO_RATIO_LIMIT: u64 = 0x1AD;
const MSR_POWER_CTL: u64 = 0x1FC;
const MSR_VR_CURRENT_CONFIG: u64 = 0x601;
const MSR_RAPL_POWER_UNIT: u64 = 0x606;
const MSR_PKG_POWER_LIMIT: u64 = 0x610;
const MSR_PKG_ENERGY_STATUS: u64 = 0x611;
const MSR_PKG_POWER_INFO: u64 = 0x614;
const MSR_CORE_PERF_LIMIT_REASONS: u64 = 0x64F;

/// What happened when the probe asked for one register.
#[derive(Debug, Clone)]
pub struct Probe {
    pub register: Register,
    /// `Ok` carries the raw 64-bit value; `Err` carries the driver's
    /// refusal, which for a register outside the module's allowlist is
    /// an access-denied and not a hardware fault.
    pub value: Result<u64, String>,
}

impl Probe {
    pub fn raw(&self) -> Option<u64> {
        self.value.as_ref().ok().copied()
    }
}

/// Reads every register in [`REGISTERS`], recording refusals rather than
/// failing on them.
///
/// This is the discovery step: on a machine whose `IntelMSR` blob does
/// not allowlist a register, the only way to find out is to ask.
pub fn probe(io: &PawnIo) -> Vec<Probe> {
    REGISTERS
        .iter()
        .map(|&register| Probe {
            register,
            value: io
                .execute1("ioctl_read_msr", register.addr)
                .map_err(|e| e.to_string()),
        })
        .collect()
}

/// RAPL's per-part scaling factors. Every power and time field in the
/// RAPL registers is a raw integer that means nothing without these.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RaplUnits {
    pub power_w: f64,
    pub energy_j: f64,
    pub time_s: f64,
}

impl RaplUnits {
    /// Decodes `MSR_RAPL_POWER_UNIT`. Each field is an exponent: the
    /// unit is 1/2^field.
    pub fn decode(raw: u64) -> Self {
        let power = (raw & 0xF) as i32;
        let energy = ((raw >> 8) & 0x1F) as i32;
        let time = ((raw >> 16) & 0xF) as i32;
        Self {
            power_w: 1.0 / f64::from(1u32 << power),
            energy_j: 1.0 / f64::from(1u32 << energy),
            time_s: 1.0 / f64::from(1u32 << time),
        }
    }
}

/// One of the two package power limits.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PowerLimit {
    pub watts: f64,
    /// The averaging window the limit is enforced over. PL2's is short
    /// (milliseconds); PL1's is typically tens of seconds.
    pub window_s: f64,
    pub enabled: bool,
    /// The part may drop below its guaranteed base frequency to stay
    /// inside this limit.
    pub clamping: bool,
}

/// `MSR_PKG_POWER_LIMIT`, decoded.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PackagePowerLimits {
    pub pl1: PowerLimit,
    pub pl2: PowerLimit,
    /// BIOS has locked the register until the next reset — the usual
    /// state on a board that applied an Intel profile, and the reason a
    /// Windows tool may silently fail to change these.
    pub locked: bool,
}

impl PackagePowerLimits {
    pub fn decode(raw: u64, units: RaplUnits) -> Self {
        Self {
            pl1: PowerLimit {
                watts: (raw & 0x7FFF) as f64 * units.power_w,
                window_s: decode_time_window((raw >> 17) & 0x7F, units),
                enabled: raw & (1 << 15) != 0,
                clamping: raw & (1 << 16) != 0,
            },
            pl2: PowerLimit {
                watts: ((raw >> 32) & 0x7FFF) as f64 * units.power_w,
                window_s: decode_time_window((raw >> 49) & 0x7F, units),
                enabled: raw & (1 << 47) != 0,
                clamping: raw & (1 << 48) != 0,
            },
            locked: raw & (1 << 63) != 0,
        }
    }
}

/// RAPL encodes a time window as `2^Y * (1 + Z/4)` time units, with Y in
/// the low five bits and Z in the top two.
fn decode_time_window(field: u64, units: RaplUnits) -> f64 {
    let y = (field & 0x1F) as i32;
    let z = (field >> 5) & 0x3;
    f64::from(1u32 << y.min(31)) * (1.0 + z as f64 / 4.0) * units.time_s
}

/// A single reason the cores were held back, as reported by
/// `MSR_CORE_PERF_LIMIT_REASONS`.
///
/// Each reason has two bits: a live status bit, and a sticky log bit 16
/// positions higher that latches until cleared. They mean different
/// things and are kept apart deliberately — a set log bit on an idle
/// machine is history, not an active alarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitReason {
    pub name: &'static str,
    /// True while the condition is actually holding clocks down.
    pub active: bool,
    /// True if it has happened at least once since the log was cleared.
    pub since_cleared: bool,
}

/// Bit assignments for client parts (6th generation through Raptor
/// Lake), per the SDM's `MSR_CORE_PERF_LIMIT_REASONS` table.
const LIMIT_BITS: &[(u32, &str)] = &[
    (0, "PROCHOT"),
    (1, "thermal"),
    (4, "residency state regulation"),
    (5, "running average thermal limit"),
    (6, "VR thermal alert"),
    (7, "VR thermal design current"),
    (8, "other"),
    (10, "PL1 (sustained package power)"),
    (11, "PL2 (short-burst package power)"),
    (12, "max turbo limit"),
    (13, "turbo transition attenuation"),
];

/// Decodes every reason in `MSR_CORE_PERF_LIMIT_REASONS`.
pub fn decode_limit_reasons(raw: u64) -> Vec<LimitReason> {
    LIMIT_BITS
        .iter()
        .map(|&(bit, name)| LimitReason {
            name,
            active: raw & (1 << bit) != 0,
            since_cleared: raw & (1 << (bit + 16)) != 0,
        })
        .collect()
}

/// `MSR_VR_CURRENT_CONFIG`: the IccMax ceiling, in amps.
///
/// This is the "EDP" of the PL1/PL2/EDP triple, and the value an ASRock
/// or ASUS "Intel Default Settings" profile is really choosing between
/// (307 A for Performance, 400 A for Extreme, on a K-series desktop
/// part).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CurrentLimit {
    pub amps: f64,
    pub locked: bool,
}

impl CurrentLimit {
    pub fn decode(raw: u64) -> Self {
        Self {
            // The field is in 1/8 A units.
            amps: (raw & 0x1FFF) as f64 / 8.0,
            locked: raw & (1 << 31) != 0,
        }
    }
}

/// `MSR_PKG_CST_CONFIG_CONTROL`: how deep the package is allowed to
/// idle, and whether BIOS froze the setting.
///
/// A limit of C0/C1 on a desktop part is the signature of C-states
/// having been disabled in firmware, which keeps every core awake and
/// shows up as high temperature at low utilisation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CStateConfig {
    pub package_limit: &'static str,
    pub locked: bool,
    pub c1_auto_demotion: bool,
    pub c3_auto_demotion: bool,
}

impl CStateConfig {
    pub fn decode(raw: u64) -> Self {
        let limit = match raw & 0xF {
            0 => "C0/C1 (no package idle)",
            1 => "C2",
            2 => "C3",
            3 => "C6",
            4 => "C7",
            5 => "C7s",
            6 => "C8",
            7 => "C9",
            8 => "C10",
            _ => "unspecified",
        };
        Self {
            package_limit: limit,
            locked: raw & (1 << 15) != 0,
            c3_auto_demotion: raw & (1 << 25) != 0,
            c1_auto_demotion: raw & (1 << 26) != 0,
        }
    }
}

/// `MSR_POWER_CTL`, the bits of it worth naming.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PowerControl {
    pub bidirectional_prochot: bool,
    /// C1E is the cheap idle state. With it off, an otherwise idle core
    /// holds its full voltage.
    pub c1e_enabled: bool,
}

impl PowerControl {
    pub fn decode(raw: u64) -> Self {
        Self {
            bidirectional_prochot: raw & (1 << 0) != 0,
            c1e_enabled: raw & (1 << 1) != 0,
        }
    }
}

/// `MSR_PLATFORM_INFO`: the part's fixed ratios, plus what firmware is
/// permitted to change.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PlatformInfo {
    /// Guaranteed all-core ratio — 100 MHz per step on modern parts.
    pub base_ratio: u32,
    /// The lowest ratio the part will run at.
    pub max_efficiency_ratio: u32,
    /// Turbo ratios are unlocked: this is a K-series part, or an
    /// unlocked platform. Its absence means OC Tweaker's ratio controls
    /// cannot do anything.
    pub programmable_ratio: bool,
    pub programmable_tdp: bool,
    pub programmable_tj_offset: bool,
}

impl PlatformInfo {
    pub fn decode(raw: u64) -> Self {
        Self {
            base_ratio: ((raw >> 8) & 0xFF) as u32,
            max_efficiency_ratio: ((raw >> 40) & 0xFF) as u32,
            programmable_ratio: raw & (1 << 28) != 0,
            programmable_tdp: raw & (1 << 29) != 0,
            programmable_tj_offset: raw & (1 << 30) != 0,
        }
    }
}

/// `MSR_TURBO_RATIO_LIMIT`: eight bytes, one maximum turbo ratio per
/// active-core count, starting at one active core.
pub fn decode_turbo_ratios(raw: u64) -> [u32; 8] {
    let mut out = [0u32; 8];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = ((raw >> (i * 8)) & 0xFF) as u32;
    }
    out
}

/// Current core voltage from `IA32_PERF_STATUS` bits 47:32, which carry
/// a VID in 1/8192 V steps.
///
/// Returns `None` for a zero field: some parts and microcode revisions
/// leave it unpopulated, and reporting 0 V as a measurement would be
/// worse than admitting we don't know.
pub fn decode_core_voltage(raw: u64) -> Option<f64> {
    let vid = (raw >> 32) & 0xFFFF;
    (vid != 0).then(|| vid as f64 / 8192.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Desktop client parts report power in 1/8 W, energy in 1/65536 J,
    /// time in 1/1024 s.
    fn desktop_units() -> RaplUnits {
        RaplUnits::decode(0x000A_0E03)
    }

    #[test]
    fn rapl_units_are_reciprocal_powers_of_two() {
        let u = desktop_units();
        assert_eq!(u.power_w, 0.125);
        assert_eq!(u.energy_j, 1.0 / 16384.0);
        assert_eq!(u.time_s, 1.0 / 1024.0);
    }

    #[test]
    fn package_limits_decode_to_intel_default_settings() {
        let units = desktop_units();
        // 253 W in 1/8 W units is 2024, for both PL1 and PL2, each
        // enabled — the "Performance" profile a Z790 board applies.
        let pl = 2024u64;
        let raw = pl | (1 << 15) | (pl << 32) | (1 << 47);
        let decoded = PackagePowerLimits::decode(raw, units);

        assert_eq!(decoded.pl1.watts, 253.0);
        assert_eq!(decoded.pl2.watts, 253.0);
        assert!(decoded.pl1.enabled && decoded.pl2.enabled);
        assert!(!decoded.locked);
    }

    #[test]
    fn a_locked_limit_register_is_reported_as_locked() {
        let decoded = PackagePowerLimits::decode(1 << 63, desktop_units());
        assert!(decoded.locked);
    }

    #[test]
    fn time_window_uses_the_mantissa_bits() {
        let units = desktop_units();
        // Y = 10, Z = 0 -> 1024 time units -> 1 s at 1/1024 s per unit.
        assert_eq!(decode_time_window(10, units), 1.0);
        // Y = 10, Z = 2 -> 1.5x that.
        assert_eq!(decode_time_window(10 | (2 << 5), units), 1.5);
    }

    #[test]
    fn limit_reasons_separate_live_bits_from_sticky_log_bits() {
        // PL2 active now (bit 11); EDP-adjacent VR TDC only in the log
        // (bit 7 + 16).
        let raw = (1 << 11) | (1 << (7 + 16));
        let reasons = decode_limit_reasons(raw);

        let pl2 = reasons.iter().find(|r| r.name.starts_with("PL2")).unwrap();
        assert!(pl2.active);
        assert!(!pl2.since_cleared);

        let tdc = reasons
            .iter()
            .find(|r| r.name == "VR thermal design current")
            .unwrap();
        assert!(!tdc.active);
        assert!(tdc.since_cleared);
    }

    #[test]
    fn nothing_set_means_no_reason_is_active() {
        assert!(decode_limit_reasons(0).iter().all(|r| !r.active));
    }

    #[test]
    fn current_limit_decodes_the_two_common_bios_profiles() {
        // 307 A and 400 A in 1/8 A units.
        assert_eq!(CurrentLimit::decode(307 * 8).amps, 307.0);
        assert_eq!(CurrentLimit::decode(400 * 8).amps, 400.0);
    }

    #[test]
    fn a_package_limit_of_zero_reads_as_no_package_idle() {
        let cfg = CStateConfig::decode(0);
        assert_eq!(cfg.package_limit, "C0/C1 (no package idle)");
        assert!(!cfg.locked);

        assert_eq!(CStateConfig::decode(8).package_limit, "C10");
        assert!(CStateConfig::decode(1 << 15).locked);
    }

    #[test]
    fn platform_info_reports_base_ratio_and_unlock_bits() {
        // Base ratio 30 (3.0 GHz), efficiency ratio 8, ratio-unlocked.
        let raw = (30u64 << 8) | (8u64 << 40) | (1 << 28);
        let info = PlatformInfo::decode(raw);

        assert_eq!(info.base_ratio, 30);
        assert_eq!(info.max_efficiency_ratio, 8);
        assert!(info.programmable_ratio);
        assert!(!info.programmable_tdp);
    }

    #[test]
    fn turbo_ratios_come_out_one_per_active_core_count() {
        let raw = 0x2A2B_2C2D_2E2F_3031;
        assert_eq!(
            decode_turbo_ratios(raw),
            [0x31, 0x30, 0x2F, 0x2E, 0x2D, 0x2C, 0x2B, 0x2A]
        );
    }

    #[test]
    fn core_voltage_of_zero_is_absent_rather_than_zero_volts() {
        assert_eq!(decode_core_voltage(0), None);
        // 1.25 V is 10240 in 1/8192 V steps.
        let v = decode_core_voltage(10240u64 << 32).unwrap();
        assert!((v - 1.25).abs() < 1e-9);
    }

    #[test]
    fn power_control_names_the_c1e_bit() {
        assert!(!PowerControl::decode(0).c1e_enabled);
        assert!(PowerControl::decode(0b10).c1e_enabled);
        assert!(PowerControl::decode(0b01).bidirectional_prochot);
    }
}
