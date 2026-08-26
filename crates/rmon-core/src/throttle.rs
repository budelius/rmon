//! A short rolling record of whether the machine was being held back —
//! system-wide, and deliberately separate from the per-process history in
//! `history.rs`.
//!
//! Throttling is the one condition that silently invalidates every other
//! number rMon shows. A CPU trimming duty cycle at TjMax, or a GPU in
//! thermal slowdown, turns every per-process CPU%/GPU% figure into a
//! measurement of the *limit* rather than of the workload, and nothing in
//! the process table hints that this happened. An instantaneous badge
//! isn't enough to catch it either: the episodes that distort a benchmark
//! or a compile are frequently seconds long and over before anyone looks
//! at the header. Keeping the last few minutes lets the UI answer both
//! "is it happening now" and "did it happen while I wasn't watching".

use std::collections::VecDeque;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::model::SystemMetrics;

/// How far back the strip and its statistics look. Long enough to cover a
/// short benchmark run or a compile, short enough that one pixel column
/// per tick still fits a header-sized widget.
pub const THROTTLE_WINDOW: Duration = Duration::from_secs(300);

/// One sampling tick's system-wide limiting state.
///
/// Both fields are `Option` rather than `bool` because "no source could
/// tell us" and "we checked and it's fine" are different facts that must
/// not render alike — a blank strip segment has to be distinguishable
/// from a healthy one, or the widget quietly promises reassurance it
/// never actually gathered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThrottleTick {
    pub at: DateTime<Utc>,
    /// The CPU was being held back. `None` when no temperature, TjMax
    /// distance, or clock-ratio source was available this tick.
    pub cpu: Option<bool>,
    /// At least one GPU reported a thermal slowdown. `None` when no GPU
    /// telemetry source was available.
    pub gpu: Option<bool>,
}

impl ThrottleTick {
    /// Reduces this tick from a system snapshot. See the struct docs for
    /// why "unavailable" is preserved rather than collapsed to `false`.
    pub fn from_system(at: DateTime<Utc>, system: &SystemMetrics) -> Self {
        let cpu_observable = system.cpu_thermal_headroom_c.is_some()
            || system.cpu_temp_c.is_some()
            || system.cpu_clock_ratio.is_some();
        let cpu = cpu_observable.then_some(system.cpu_throttled);
        let gpu =
            (!system.gpus.is_empty()).then(|| system.gpus.iter().any(|g| g.thermal_throttled));
        Self { at, cpu, gpu }
    }

    /// Something was limiting the machine this tick.
    pub fn limited(&self) -> bool {
        self.cpu == Some(true) || self.gpu == Some(true)
    }

    /// At least one of the two states was actually observable.
    pub fn known(&self) -> bool {
        self.cpu.is_some() || self.gpu.is_some()
    }
}

/// A bounded, time-windowed series of [`ThrottleTick`]s.
pub struct ThrottleHistory {
    window: Duration,
    ticks: VecDeque<ThrottleTick>,
}

impl ThrottleHistory {
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            ticks: VecDeque::new(),
        }
    }

    pub fn push(&mut self, system: &SystemMetrics) {
        self.push_at(Utc::now(), system);
    }

    /// Timestamp-explicit form, so tests don't have to sleep.
    pub fn push_at(&mut self, at: DateTime<Utc>, system: &SystemMetrics) {
        self.ticks.push_back(ThrottleTick::from_system(at, system));
        let cutoff = at - chrono::Duration::from_std(self.window).unwrap_or_default();
        while self.ticks.front().is_some_and(|t| t.at < cutoff) {
            self.ticks.pop_front();
        }
    }

    pub fn window(&self) -> Duration {
        self.window
    }

    pub fn ticks(&self) -> impl ExactSizeIterator<Item = &ThrottleTick> {
        self.ticks.iter()
    }

    /// The most recent tick, if any.
    pub fn latest(&self) -> Option<&ThrottleTick> {
        self.ticks.back()
    }

    /// How much wall-clock the retained ticks actually span. Callers
    /// should label the fraction with this rather than with [`window`],
    /// so a freshly started rMon says "of the last 40s" instead of
    /// claiming five minutes of evidence it doesn't have.
    ///
    /// [`window`]: Self::window
    pub fn observed(&self) -> Duration {
        match (self.ticks.front(), self.ticks.back()) {
            (Some(first), Some(last)) => (last.at - first.at).to_std().unwrap_or_default(),
            _ => Duration::ZERO,
        }
    }

    /// Fraction (0.0..=1.0) of the *observable* ticks in the window that
    /// were limited.
    ///
    /// `None` when nothing in the window had a usable source — and
    /// pointedly not `Some(0.0)`, which would read as "never throttled"
    /// on a machine where we simply cannot tell.
    pub fn fraction_limited(&self) -> Option<f32> {
        let known = self.ticks.iter().filter(|t| t.known()).count();
        if known == 0 {
            return None;
        }
        let limited = self.ticks.iter().filter(|t| t.limited()).count();
        Some(limited as f32 / known as f32)
    }
}

impl Default for ThrottleHistory {
    fn default() -> Self {
        Self::new(THROTTLE_WINDOW)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::GpuTelemetry;

    fn system(temp: Option<f32>, throttled: bool) -> SystemMetrics {
        SystemMetrics {
            cpu_temp_c: temp,
            cpu_throttled: throttled,
            ..Default::default()
        }
    }

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000 + secs, 0).unwrap()
    }

    #[test]
    fn fraction_counts_only_observable_ticks() {
        let mut h = ThrottleHistory::new(Duration::from_secs(300));
        h.push_at(at(0), &system(Some(60.0), false));
        h.push_at(at(1), &system(Some(99.0), true));
        h.push_at(at(2), &system(None, false)); // no source: not a "fine" tick
        assert_eq!(h.fraction_limited(), Some(0.5));
    }

    /// The distinction the whole `Option` design exists for: a machine
    /// with no thermal source must not report a reassuring 0%.
    #[test]
    fn no_source_reports_unknown_not_zero() {
        let mut h = ThrottleHistory::new(Duration::from_secs(300));
        for i in 0..5 {
            h.push_at(at(i), &system(None, false));
        }
        assert_eq!(h.fraction_limited(), None);
    }

    #[test]
    fn gpu_throttle_alone_counts_as_limited() {
        let mut h = ThrottleHistory::new(Duration::from_secs(300));
        let mut s = system(None, false);
        s.gpus.push(GpuTelemetry {
            index: 0,
            name: "test".into(),
            temp_c: Some(88.0),
            thermal_throttled: true,
            throttle_reasons: vec!["HwThermalSlowdown".into()],
        });
        h.push_at(at(0), &s);
        assert_eq!(h.fraction_limited(), Some(1.0));
    }

    #[test]
    fn ticks_outside_the_window_are_dropped() {
        let mut h = ThrottleHistory::new(Duration::from_secs(10));
        h.push_at(at(0), &system(Some(60.0), true));
        h.push_at(at(100), &system(Some(60.0), false));
        assert_eq!(h.ticks().len(), 1);
        assert_eq!(h.fraction_limited(), Some(0.0));
    }

    #[test]
    fn observed_reports_actual_span_not_the_window() {
        let mut h = ThrottleHistory::new(Duration::from_secs(300));
        h.push_at(at(0), &system(Some(60.0), false));
        h.push_at(at(40), &system(Some(60.0), false));
        assert_eq!(h.observed(), Duration::from_secs(40));
    }
}
