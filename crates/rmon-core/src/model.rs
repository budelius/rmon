use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Where a process's GPU utilization figure came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GpuSource {
    /// NVIDIA Management Library (per-process compute/SM utilization).
    Nvml,
    /// Windows "GPU Engine" performance counters (vendor-agnostic).
    Pdh,
    /// No GPU utilization could be attributed to this process.
    Unavailable,
}

impl GpuSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            GpuSource::Nvml => "nvml",
            GpuSource::Pdh => "pdh",
            GpuSource::Unavailable => "unavailable",
        }
    }
}

impl FromStr for GpuSource {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "nvml" => GpuSource::Nvml,
            "pdh" => GpuSource::Pdh,
            _ => GpuSource::Unavailable,
        })
    }
}

/// One process's resource usage at a single point in time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessSample {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub cpu_percent: f32,
    pub gpu_percent: f32,
    pub gpu_source: GpuSource,
    /// Owning account name (e.g. "DOMAIN\\user"), when resolvable.
    pub user: Option<String>,
    /// Full command line, when readable (own processes always; others
    /// require running elevated).
    pub command_line: Option<String>,
    /// Total open handle count (all types, not just files) — cheap via
    /// `GetProcessHandleCount`, unlike the full file-handle scan in
    /// `handles.rs`.
    pub handle_count: Option<u32>,
    /// Working-set (resident) memory in bytes, when available.
    pub mem_bytes: Option<u64>,
}

/// Per-GPU temperature and throttle telemetry (NVIDIA only, via NVML).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuTelemetry {
    pub index: u32,
    pub name: String,
    pub temp_c: Option<f32>,
    /// True when NVML reports an unambiguous thermal throttle reason
    /// (SW or HW thermal slowdown), i.e. clocks are being reduced because
    /// of temperature specifically.
    pub thermal_throttled: bool,
    /// Human-readable active throttle reasons (may include non-thermal ones
    /// such as power capping), for display.
    pub throttle_reasons: Vec<String>,
}

/// One motherboard fan tachometer channel.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FanSample {
    pub label: String,
    /// `None` means the channel exists but nothing is spinning on it —
    /// an unused header, not a stalled fan.
    pub rpm: Option<u32>,
}

/// One temperature input from the motherboard's Super I/O chip.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BoardTemperatureSample {
    pub label: String,
    /// `None` means the channel is present but unconnected or invalid.
    pub temp_c: Option<f32>,
}

/// One voltage ADC input from the motherboard's Super I/O chip.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VoltageSample {
    pub label: String,
    /// `None` means the channel exists but could not be measured.
    pub volts: Option<f32>,
}

/// System-wide (not per-process) thermal telemetry for one sampling tick.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SystemMetrics {
    /// CPU temperature in °C from the best source available this tick.
    /// `None` when none of them could answer.
    pub cpu_temp_c: Option<f32>,
    /// Where `cpu_temp_c` came from — `"CPU MSR"`, `"Super I/O CPU
    /// sensor"`, `"HWiNFO"`, or `"ACPI zone (approximate)"`. Surfaced
    /// because these differ by
    /// more than provenance: the first is the die's own measurement,
    /// the last is frequently not even the CPU package.
    pub cpu_temp_source: Option<String>,
    /// Current clock speed / max clock speed, averaged across logical
    /// processors from the kernel's processor power state (0.0..=1.0).
    pub cpu_clock_ratio: Option<f32>,
    /// °C of remaining headroom below TjMax. Native on the MSR path
    /// (where it is the raw measurement and `cpu_temp_c` is derived from
    /// it); otherwise present only if HWiNFO exposes a "Distance to
    /// TjMAX" sensor. `None` means the limit is unknown, not that there
    /// is plenty of room.
    pub cpu_thermal_headroom_c: Option<f32>,
    /// The CPU is being held back — either sitting at its thermal limit,
    /// or running well below its rated clock while busy.
    ///
    /// Deliberately not clock-only: clocks staying at 100% is perfectly
    /// compatible with thermal throttling, because a CPU pinned at TjMax
    /// sheds heat by cutting *duty cycle* and skipping turbo bins rather
    /// than by dropping its reported nominal frequency. A clock-only test
    /// therefore reports "fine" during exactly the episodes that matter
    /// most — throttling at low load, where the cause is cooling or
    /// runaway background work rather than the workload itself.
    pub cpu_throttled: bool,
    /// Why `cpu_throttled` is set, for display. `None` when it isn't.
    /// Callers should show this rather than a bare "throttled" badge:
    /// thermal limiting and unexplained low clocks call for completely
    /// different investigations.
    pub cpu_throttle_reason: Option<String>,
    /// The throttle verdict came from the CPU's own status registers
    /// rather than from the clock-ratio heuristic.
    ///
    /// Worth surfacing separately because the two deserve different
    /// confidence: the hardware signal states that the thermal control
    /// circuit is engaged, while the heuristic only observes that clocks
    /// are low and guesses why. A UI that renders them identically
    /// invites acting on a guess as though it were a measurement.
    pub cpu_throttle_confirmed: bool,
    /// The CPU has thermally throttled at least once since boot, from
    /// the sticky log bit in `IA32_PACKAGE_THERM_STATUS`.
    ///
    /// This catches episodes far shorter than the sampling tick, at the
    /// cost of saying nothing about *when* — and it never clears until
    /// reboot, so it must never be rendered as a current state.
    pub cpu_thermal_throttled_since_boot: bool,
    /// Motherboard fan tachometers, when a Super I/O chip rMon can
    /// decode was found. Empty otherwise.
    pub fans: Vec<FanSample>,
    /// Motherboard / socket / VRM temperature inputs read from the same
    /// Super I/O block. Individual values remain `None` when a channel is
    /// unconnected; no zero is fabricated.
    #[serde(default)]
    pub board_temperatures: Vec<BoardTemperatureSample>,
    /// Motherboard voltage inputs. NCT67xx values are labeled as ADC pins
    /// because converting them to rail voltages requires board-specific
    /// resistor-divider data.
    #[serde(default)]
    pub voltages: Vec<VoltageSample>,
    /// One-line description of which sensor backends are live, for the
    /// UI to show instead of leaving unavailable readings unexplained.
    pub sensor_source: Option<String>,
    pub gpus: Vec<GpuTelemetry>,
}

/// All process samples collected at a single point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub timestamp: DateTime<Utc>,
    pub processes: Vec<ProcessSample>,
    pub system: SystemMetrics,
}

impl Snapshot {
    /// Total CPU percent across all sampled processes (can exceed 100 on multi-core systems).
    pub fn total_cpu_percent(&self) -> f32 {
        self.processes.iter().map(|p| p.cpu_percent).sum()
    }

    /// Total GPU percent across all sampled processes.
    pub fn total_gpu_percent(&self) -> f32 {
        self.processes.iter().map(|p| p.gpu_percent).sum()
    }

    /// Processes sorted by combined CPU+GPU usage, descending.
    pub fn sorted_by_usage(&self) -> Vec<&ProcessSample> {
        let mut v: Vec<&ProcessSample> = self.processes.iter().collect();
        v.sort_by(|a, b| {
            let ua = a.cpu_percent + a.gpu_percent;
            let ub = b.cpu_percent + b.gpu_percent;
            ub.partial_cmp(&ua).unwrap_or(std::cmp::Ordering::Equal)
        });
        v
    }
}
