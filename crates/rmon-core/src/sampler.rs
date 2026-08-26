use chrono::Utc;

use crate::cpu::CpuMonitor;
use crate::gpu::GpuMonitor;
use crate::model::{
    BoardTemperatureSample, FanSample, GpuSource, ProcessSample, Snapshot, SystemMetrics,
    VoltageSample,
};
use crate::sensors::SensorHub;
use crate::thermal::{CpuThermalMonitor, CpuThermalSample};

/// Below this clock ratio (current/max), combined with high concurrent CPU
/// load, we call the CPU "throttled" (heuristic — cause unconfirmed).
const CPU_THROTTLE_CLOCK_RATIO: f32 = 0.7;
/// Minimum average core utilization before we consider low clocks
/// meaningful rather than just normal idle power-saving.
const CPU_THROTTLE_MIN_LOAD: f32 = 60.0;
/// Within this many °C of TjMax, treat the CPU as thermally limited.
/// Not zero: both Intel and AMD begin pulling turbo bins back a couple of
/// degrees before the hard limit, so requiring an exact hit would miss
/// throttling that has already started.
const CPU_TJMAX_HEADROOM_C: f32 = 3.0;
/// Fallback ceiling used only when HWiNFO doesn't expose a TjMax
/// distance. Intel desktop parts run TjMax at 100°C, so 95°C means
/// throttling is imminent or underway. Intentionally *not* applied when
/// a real headroom figure is available — AMD's Tctl reads 95°C under
/// entirely normal operation and would false-positive here.
const CPU_TEMP_LIMIT_C: f32 = 95.0;

/// Combines CPU and GPU per-process monitoring, plus system-wide thermal
/// telemetry, into a single sampling interface. Construct once and call
/// `sample()` on your desired interval; the underlying monitors compute
/// deltas since their previous read.
pub struct Sampler {
    cpu: CpuMonitor,
    gpu: GpuMonitor,
    thermal: CpuThermalMonitor,
    /// Direct kernel-backed sensor access (CPU MSRs and motherboard
    /// temperatures, voltages, and fans). Present but inert on machines
    /// without PawnIO or elevation; only then may `thermal` use HWiNFO as
    /// a necessary CPU-temperature fallback.
    sensors: SensorHub,
}

impl Sampler {
    pub fn new() -> Self {
        Self {
            cpu: CpuMonitor::new(),
            gpu: GpuMonitor::new(),
            thermal: CpuThermalMonitor::new(),
            sensors: SensorHub::new(),
        }
    }

    /// One-line description of which sensor backends are live.
    pub fn sensor_status(&self) -> String {
        self.sensors.status_line()
    }

    /// The identified motherboard Super I/O chip, when there is one.
    pub fn superio_chip(&self) -> Option<&crate::sensors::Chip> {
        self.sensors.chip()
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
                    executable_path: info.executable_path,
                    // Both come free with the SystemProcessInformation
                    // walk — no per-process syscalls on the tick path.
                    handle_count: info.handle_count,
                    mem_bytes: Some(info.mem_bytes),
                }
            })
            .collect();
        let merge_elapsed = t.elapsed();

        let t = std::time::Instant::now();
        let package = self.sensors.cpu_package();
        let superio_cpu_temp = package
            .is_none()
            .then(|| self.sensors.cpu_temperature())
            .flatten();
        let thermal = self.thermal.sample(package.as_ref(), superio_cpu_temp);
        let fans = self
            .sensors
            .fans()
            .iter()
            .map(|f| FanSample {
                label: f.label.clone(),
                rpm: f.rpm,
            })
            .collect();
        let board_temperatures = self
            .sensors
            .board_temperatures()
            .iter()
            .map(|t| BoardTemperatureSample {
                label: t.label.clone(),
                temp_c: t.temp_c,
            })
            .collect();
        let voltages = self
            .sensors
            .voltages()
            .iter()
            .map(|v| VoltageSample {
                label: v.label.clone(),
                volts: v.volts,
            })
            .collect();
        let thermal_elapsed = t.elapsed();
        log::debug!(
            "sample timings: cpu={cpu_elapsed:?} gpu={gpu_elapsed:?} \
             merge+handles={merge_elapsed:?} thermal={thermal_elapsed:?}"
        );
        let global_load = self.cpu.global_usage();

        let cpu_throttle_reason = throttle_reason(&thermal, global_load);

        let system = SystemMetrics {
            cpu_temp_c: thermal.temp_c,
            cpu_temp_source: thermal.temp_source.map(str::to_string),
            cpu_clock_ratio: thermal.clock_ratio,
            cpu_thermal_headroom_c: thermal.tjmax_distance_c,
            cpu_throttled: cpu_throttle_reason.is_some(),
            cpu_throttle_confirmed: thermal.hardware_limit_reason.is_some(),
            cpu_thermal_throttled_since_boot: thermal.thermal_since_boot,
            cpu_throttle_reason,
            fans,
            board_temperatures,
            voltages,
            sensor_source: Some(self.sensors.status_line()),
            logical_cores: self.cpu.logical_cores(),
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

/// Decides whether the CPU is being held back, and why. `None` means it
/// isn't (as far as we can tell).
///
/// The two causes are tested independently and thermal wins, because they
/// are not alternatives: a part pinned at TjMax throttles by trimming duty
/// cycle and turbo bins, which `Win32_Processor` still reports as a full
/// clock ratio. Gating the temperature check behind the clock/load test —
/// as this code originally did — makes throttling at low load structurally
/// undetectable, which is exactly the case worth alarming on, since its
/// cause is cooling or runaway background work rather than the workload.
fn throttle_reason(thermal: &CpuThermalSample, global_load: f32) -> Option<String> {
    // When the CPU's own status registers are readable there is nothing
    // to infer: they say whether the thermal control circuit is engaged,
    // and everything below this line exists only to approximate that
    // answer from indirect evidence.
    if let Some(reason) = &thermal.hardware_limit_reason {
        return Some(reason.clone());
    }

    let thermally_limited = match thermal.tjmax_distance_c {
        Some(d) => d <= CPU_TJMAX_HEADROOM_C,
        None => thermal.temp_c.is_some_and(|t| t >= CPU_TEMP_LIMIT_C),
    };
    if thermally_limited {
        return Some(match thermal.tjmax_distance_c {
            Some(d) => format!("at thermal limit ({d:.0}°C from TjMax)"),
            None => format!("at thermal limit (>={CPU_TEMP_LIMIT_C:.0}°C)"),
        });
    }

    let clock_limited = thermal
        .clock_ratio
        .is_some_and(|r| r < CPU_THROTTLE_CLOCK_RATIO && global_load > CPU_THROTTLE_MIN_LOAD);
    clock_limited.then(|| "clocks below rated max under load (cause unconfirmed)".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn thermal_sample(
        temp_c: Option<f32>,
        clock_ratio: Option<f32>,
        tjmax: Option<f32>,
    ) -> CpuThermalSample {
        CpuThermalSample {
            temp_c,
            temp_source: Some("test"),
            clock_ratio,
            tjmax_distance_c: tjmax,
            hardware_limit_reason: None,
            thermal_since_boot: false,
        }
    }

    /// A hardware-reported reason must win outright, including over the
    /// heuristics that would otherwise have said "not throttled".
    #[test]
    fn hardware_reason_overrides_every_heuristic() {
        let mut s = thermal_sample(Some(55.0), Some(1.0), Some(45.0));
        s.hardware_limit_reason = Some("power limit (PL1/PL2/EDP), not temperature".to_string());
        assert_eq!(
            throttle_reason(&s, 5.0).as_deref(),
            Some("power limit (PL1/PL2/EDP), not temperature")
        );
    }

    /// The sticky since-boot flag describes history, never the present.
    #[test]
    fn since_boot_flag_alone_is_not_current_throttling() {
        let mut s = thermal_sample(Some(55.0), Some(1.0), Some(45.0));
        s.thermal_since_boot = true;
        assert_eq!(throttle_reason(&s, 5.0), None);
    }

    /// The regression this function exists for: an i9-13900K sitting at
    /// 96°C while nearly idle, with `Win32_Processor` still reporting a
    /// full clock ratio. The previous clock-only heuristic returned
    /// "not throttled" here.
    #[test]
    fn thermal_limit_detected_at_low_load_and_full_clocks() {
        let reason = throttle_reason(&thermal_sample(Some(96.0), Some(1.0), None), 7.0);
        assert!(
            reason
                .as_deref()
                .is_some_and(|r| r.contains("thermal limit")),
            "expected thermal limit, got {reason:?}"
        );
    }

    /// A real TjMax distance must override the fallback ceiling: 95°C is
    /// normal operating temperature for AMD's Tctl, so a part reporting
    /// 20°C of headroom is fine despite tripping `CPU_TEMP_LIMIT_C`.
    #[test]
    fn tjmax_distance_overrides_absolute_ceiling() {
        assert_eq!(
            throttle_reason(&thermal_sample(Some(95.0), Some(1.0), Some(20.0)), 10.0),
            None
        );
    }

    #[test]
    fn tjmax_distance_within_band_is_throttling() {
        let reason = throttle_reason(&thermal_sample(Some(89.0), Some(1.0), Some(2.0)), 5.0);
        assert!(
            reason
                .as_deref()
                .is_some_and(|r| r.contains("2°C from TjMax")),
            "got {reason:?}"
        );
    }

    #[test]
    fn low_clocks_under_load_still_reported() {
        let reason = throttle_reason(&thermal_sample(Some(60.0), Some(0.5), None), 80.0);
        assert!(
            reason
                .as_deref()
                .is_some_and(|r| r.contains("clocks below")),
            "got {reason:?}"
        );
    }

    /// Low clocks while *idle* are ordinary power saving, not throttling.
    #[test]
    fn low_clocks_while_idle_is_not_throttling() {
        assert_eq!(
            throttle_reason(&thermal_sample(Some(45.0), Some(0.3), None), 5.0),
            None
        );
    }

    /// With no temperature source at all we must not invent one.
    #[test]
    fn no_signals_reports_nothing() {
        assert_eq!(
            throttle_reason(&thermal_sample(None, None, None), 90.0),
            None
        );
    }

    /// Live smoke test: a real sample must carry handle counts and memory
    /// at least for our own process (which never needs elevation), and a
    /// steady-state tick must stay within a per-process budget.
    ///
    /// The budget scales with the machine because most of a tick is one
    /// `NtQuerySystemInformation` call, whose cost is set by how many
    /// processes and threads exist, not by anything rMon does — on a
    /// 1,350-process box it alone is ~90ms. A flat millisecond ceiling
    /// here only measured how busy the test machine was. What this guards
    /// is the part rMon owns: per-process work must stay off the tick
    /// path, so reintroducing something like an `OpenProcess` per process
    /// per tick blows the budget on any machine. Callers adapt to the
    /// absolute number rather than assuming it is small (see the GUI's
    /// `sampling` module).
    #[test]
    fn sample_includes_handles_and_memory_for_own_process() {
        let mut sampler = Sampler::new();
        sampler.sample(); // warm up

        // Best of several, not one shot. The rest of the suite runs in
        // parallel on the same machine and also samples, so any single
        // reading includes contention this test is not about; the best of
        // a few is the cost actually achievable here. Still catches the
        // regression that matters — per-process work sneaking back onto
        // the tick path shows up in *every* reading, not just the worst.
        let mut snap = sampler.sample();
        let mut best = std::time::Duration::MAX;
        for _ in 0..3 {
            let start = std::time::Instant::now();
            snap = sampler.sample();
            best = best.min(start.elapsed());
        }

        let n = snap.processes.len();
        let budget =
            std::time::Duration::from_millis(25) + std::time::Duration::from_micros(150) * n as u32;
        println!(
            "best of 3 samples over {n} processes: {best:?} (budget {budget:?}, \
             {:.0}µs/process)",
            best.as_secs_f64() * 1e6 / n.max(1) as f64
        );
        assert!(
            best < budget,
            "tick took {best:?} for {n} processes, over {budget:?}"
        );

        let me = std::process::id();
        let p = snap
            .processes
            .iter()
            .find(|p| p.pid == me)
            .expect("own process should be in the snapshot");
        assert!(
            p.handle_count.is_some_and(|h| h > 0),
            "handle_count: {:?}",
            p.handle_count
        );
        assert!(
            p.mem_bytes.is_some_and(|m| m > 0),
            "mem_bytes: {:?}",
            p.mem_bytes
        );
    }
}
