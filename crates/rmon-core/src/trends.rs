//! Trend analytics over per-process history: resource-leak detection on
//! slow-moving counters (open handle count, working set) and "idle burner"
//! detection on accumulated CPU.
//!
//! This answers the question a point-in-time snapshot can't: "which
//! process has been *quietly creeping up* for hours?" — the classic
//! background handle/memory leak (e.g. a broken IPC reconnect loop opening
//! a fresh handle every few seconds forever) that never shows up in an
//! instantaneous top-by-CPU view.
//!
//! Everything here is a heuristic over observed history, not a diagnosis:
//! a flagged process is a *suspect* worth looking at (restart it and watch
//! whether the count resets and starts climbing again), not proof of a
//! leak. Thresholds are deliberately conservative to keep false positives
//! rare; all of them are documented constants below.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::history::RollingHistory;

/// Minimum observed span before a leak verdict is even considered — with
/// less history than this, steady growth is indistinguishable from a
/// process still warming up (browsers, IDEs and games legitimately climb
/// for minutes after launch).
pub const LEAK_MIN_SPAN_SECS: f64 = 30.0 * 60.0;
/// Minimum points in the (bucketed, ~1/min) series for a trend to count.
const LEAK_MIN_SAMPLES: usize = 10;
/// Fraction of minute-over-minute deltas that must be non-decreasing.
/// Separates steady creep from noisy churn that happens to end higher.
const LEAK_MIN_MONOTONICITY: f64 = 0.75;
/// Handle leak: sustained growth rate and absolute net growth floors.
const HANDLE_LEAK_MIN_SLOPE_PER_HOUR: f64 = 100.0;
const HANDLE_LEAK_MIN_NET: f64 = 500.0;
/// Memory leak: working sets are noisier than handle tables (GC, caches,
/// allocator trim), so the floors are higher.
const MEM_LEAK_MIN_SLOPE_PER_HOUR: f64 = 64.0 * 1024.0 * 1024.0;
const MEM_LEAK_MIN_NET: f64 = 256.0 * 1024.0 * 1024.0;

/// Idle burner: accumulated at least this much CPU over the window...
const IDLE_BURNER_MIN_CORE_SEC: f64 = 300.0;
/// ...while currently sitting at (below) this instantaneous CPU%.
const IDLE_BURNER_MAX_CURRENT_CPU: f32 = 2.0;
/// ...and observed for at least this long (avoids flagging a busy process
/// that merely paused the moment we looked).
const IDLE_BURNER_MIN_WINDOW_SECS: u64 = 15 * 60;

/// Orphan burner: still burning at least this much CPU (percent of one
/// core, so this is "half a thread" on any machine) with no living
/// parent. Set high because being orphaned is on its own extremely
/// common and completely benign — anything launched from a shell that has
/// since closed is an orphan — so CPU is what has to carry the signal.
const ORPHAN_BURNER_MIN_CURRENT_CPU: f32 = 50.0;
/// ...having already accumulated this much, so a process that merely
/// spikes in the tick we happened to look at is not flagged.
const ORPHAN_BURNER_MIN_CORE_SEC: f64 = 120.0;
/// ...over at least this much observed history. Much shorter than the
/// leak windows on purpose: a runaway with nobody left to reap it is
/// worth surfacing in minutes, not after half an hour.
const ORPHAN_BURNER_MIN_WINDOW_SECS: u64 = 5 * 60;

/// Least-squares trend over one metric's time series.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TrendStats {
    /// Wall-clock span actually covered by the series, in seconds.
    pub span_secs: f64,
    pub samples: usize,
    pub first: f64,
    pub last: f64,
    pub net_change: f64,
    /// Least-squares slope, in metric units per hour.
    pub slope_per_hour: f64,
    /// Least-squares slope over only the most recent half of the span —
    /// "is it *still* climbing?". A one-time allocation burst followed by a
    /// flat hour has a large overall slope but a near-zero recent one.
    pub recent_slope_per_hour: f64,
    /// Fraction of consecutive deltas that are >= 0 — 1.0 means the series
    /// never decreased once.
    pub monotonicity: f64,
}

/// Fits `TrendStats` to a `(timestamp, value)` series (oldest first).
/// `None` when there are fewer than 2 points or no time actually elapsed.
pub fn trend_stats(series: &[(DateTime<Utc>, f64)]) -> Option<TrendStats> {
    if series.len() < 2 {
        return None;
    }
    let t0 = series[0].0;
    let span_secs = (series[series.len() - 1].0 - t0).num_milliseconds() as f64 / 1000.0;
    if span_secs <= 0.0 {
        return None;
    }

    let slope_per_hour = ls_slope_per_hour(series);
    let midpoint = t0 + chrono::TimeDelta::milliseconds((span_secs * 500.0) as i64);
    let recent_start = series.partition_point(|(ts, _)| *ts < midpoint);
    let recent = &series[recent_start.min(series.len().saturating_sub(2))..];
    let recent_slope_per_hour = ls_slope_per_hour(recent);

    let rising = series.windows(2).filter(|w| w[1].1 >= w[0].1).count();
    let monotonicity = rising as f64 / (series.len() - 1) as f64;

    Some(TrendStats {
        span_secs,
        samples: series.len(),
        first: series[0].1,
        last: series[series.len() - 1].1,
        net_change: series[series.len() - 1].1 - series[0].1,
        slope_per_hour,
        recent_slope_per_hour,
        monotonicity,
    })
}

/// Least-squares slope of y over x-in-hours; 0.0 when degenerate.
fn ls_slope_per_hour(series: &[(DateTime<Utc>, f64)]) -> f64 {
    if series.len() < 2 {
        return 0.0;
    }
    let t0 = series[0].0;
    let n = series.len() as f64;
    let xs = series
        .iter()
        .map(|(ts, _)| (*ts - t0).num_milliseconds() as f64 / 3_600_000.0);
    let mean_x = xs.clone().sum::<f64>() / n;
    let mean_y = series.iter().map(|(_, v)| v).sum::<f64>() / n;
    let (mut cov, mut var) = (0.0, 0.0);
    for (x, (_, y)) in xs.zip(series.iter()) {
        cov += (x - mean_x) * (y - mean_y);
        var += (x - mean_x) * (x - mean_x);
    }
    if var > 0.0 { cov / var } else { 0.0 }
}

/// Large accumulated CPU while currently near-idle: the classic
/// quietly-misbehaving background process, which an instantaneous
/// top-by-CPU view never shows.
fn is_idle_burner(window_secs: u64, cpu_core_sec: f64, current_cpu: f32) -> bool {
    window_secs >= IDLE_BURNER_MIN_WINDOW_SECS
        && cpu_core_sec >= IDLE_BURNER_MIN_CORE_SEC
        && current_cpu < IDLE_BURNER_MAX_CURRENT_CPU
}

/// Still burning CPU with no living parent. `orphaned` alone is not
/// evidence of anything — it is the normal end state for anything whose
/// launcher exited — so the CPU thresholds carry the verdict.
///
/// Pure rather than inlined into `analyze` because the observation window
/// it gates on is wall-clock since the history began, which no test can
/// fabricate; separating the decision from the data makes the thresholds
/// themselves checkable.
fn is_orphan_burner(orphaned: bool, window_secs: u64, cpu_core_sec: f64, current_cpu: f32) -> bool {
    orphaned
        && window_secs >= ORPHAN_BURNER_MIN_WINDOW_SECS
        && cpu_core_sec >= ORPHAN_BURNER_MIN_CORE_SEC
        && current_cpu >= ORPHAN_BURNER_MIN_CURRENT_CPU
}

fn is_leak(stats: &TrendStats, min_slope: f64, min_net: f64) -> bool {
    stats.span_secs >= LEAK_MIN_SPAN_SECS
        && stats.samples >= LEAK_MIN_SAMPLES
        && stats.monotonicity >= LEAK_MIN_MONOTONICITY
        && stats.slope_per_hour >= min_slope
        && stats.net_change >= min_net
        // A leak keeps leaking: a one-time step (burst then flat) passes
        // every check above but has a near-zero recent slope.
        && stats.recent_slope_per_hour >= min_slope / 2.0
}

/// One process's trend analysis. `verdict` is a human-readable one-liner,
/// present only when at least one flag is set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTrend {
    pub pid: u32,
    pub name: String,
    /// The parent this process names, whether or not it is still alive —
    /// see `orphaned`.
    pub parent_pid: Option<u32>,
    pub current_cpu_percent: f32,
    pub handles: Option<TrendStats>,
    pub mem: Option<TrendStats>,
    /// Approximate core-seconds of CPU/GPU accumulated over the observed
    /// window (percent-seconds / 100).
    pub cpu_core_sec: f64,
    pub gpu_core_sec: f64,
    pub handle_leak_suspect: bool,
    pub mem_leak_suspect: bool,
    pub idle_burner: bool,
    /// The parent pid recorded for this process is not itself running.
    ///
    /// Windows never re-parents, so this is the normal end state for
    /// anything whose launcher has exited — informational on its own, and
    /// deliberately not part of `flagged()`. Two caveats: a recycled pid
    /// now held by an unrelated process makes an orphan look parented, and
    /// this only sees processes present in the same snapshot.
    pub orphaned: bool,
    /// Orphaned *and* still burning CPU: nothing is left that would
    /// notice or reap it. This is the runaway-background-process shape —
    /// a search or build whose shell died and that will now spin until
    /// the machine reboots.
    pub orphan_burner: bool,
    pub verdict: Option<String>,
}

impl ProcessTrend {
    pub fn flagged(&self) -> bool {
        self.handle_leak_suspect || self.mem_leak_suspect || self.idle_burner || self.orphan_burner
    }
}

/// Analyzes every process in the history's latest snapshot. Results are
/// sorted most-interesting first: flagged processes (by handle slope, then
/// accumulated CPU), then everything else by handle slope.
pub fn analyze(history: &RollingHistory) -> Vec<ProcessTrend> {
    let Some(snapshot) = history.latest() else {
        return Vec::new();
    };
    let window_secs = history.accum_window().as_secs();
    // A process is orphaned when the parent it names is absent from this
    // same snapshot. Collected once rather than scanned per process, which
    // would make this quadratic on a 1,500-process machine.
    let live_pids: std::collections::HashSet<u32> =
        snapshot.processes.iter().map(|p| p.pid).collect();

    let mut out: Vec<ProcessTrend> = snapshot
        .processes
        .iter()
        .map(|p| {
            let handles = trend_stats(&history.handle_series(p.pid));
            let mem = trend_stats(&history.mem_series(p.pid));
            let (cpu_pct_sec, gpu_pct_sec) = history.accumulated(p.pid);
            let (cpu_core_sec, gpu_core_sec) = (cpu_pct_sec / 100.0, gpu_pct_sec / 100.0);

            let handle_leak_suspect = handles
                .as_ref()
                .is_some_and(|s| is_leak(s, HANDLE_LEAK_MIN_SLOPE_PER_HOUR, HANDLE_LEAK_MIN_NET));
            let mem_leak_suspect = mem
                .as_ref()
                .is_some_and(|s| is_leak(s, MEM_LEAK_MIN_SLOPE_PER_HOUR, MEM_LEAK_MIN_NET));
            let idle_burner = is_idle_burner(window_secs, cpu_core_sec, p.cpu_percent);
            let orphaned = p.ppid.is_some_and(|ppid| !live_pids.contains(&ppid));
            let orphan_burner =
                is_orphan_burner(orphaned, window_secs, cpu_core_sec, p.cpu_percent);

            let mut trend = ProcessTrend {
                pid: p.pid,
                name: p.name.clone(),
                parent_pid: p.ppid,
                current_cpu_percent: p.cpu_percent,
                handles,
                mem,
                cpu_core_sec,
                gpu_core_sec,
                handle_leak_suspect,
                mem_leak_suspect,
                idle_burner,
                orphaned,
                orphan_burner,
                verdict: None,
            };
            trend.verdict = build_verdict(&trend);
            trend
        })
        .collect();

    out.sort_by(rank);
    out
}

/// Most-interesting-first ordering: flagged before unflagged, then
/// orphan burners, then by handle slope, then by accumulated CPU.
///
/// Orphan burners jump the queue because they are wasting a core *right
/// now*, whereas a leak suspect has merely been creeping for half an hour
/// and a bigger handle slope does not make it more urgent.
fn rank(a: &ProcessTrend, b: &ProcessTrend) -> std::cmp::Ordering {
    b.flagged()
        .cmp(&a.flagged())
        .then_with(|| b.orphan_burner.cmp(&a.orphan_burner))
        .then_with(|| {
            let slope = |t: &ProcessTrend| t.handles.map(|s| s.slope_per_hour).unwrap_or(0.0);
            slope(b)
                .partial_cmp(&slope(a))
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .then_with(|| {
            b.cpu_core_sec
                .partial_cmp(&a.cpu_core_sec)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
}

/// Only the processes worth surfacing to a human ("Suspects" panel).
pub fn suspects(history: &RollingHistory) -> Vec<ProcessTrend> {
    let mut all = analyze(history);
    all.retain(ProcessTrend::flagged);
    all
}

fn build_verdict(t: &ProcessTrend) -> Option<String> {
    let mut parts = Vec::new();
    if let (true, Some(s)) = (t.handle_leak_suspect, &t.handles) {
        parts.push(format!(
            "possible handle leak: {:+} handles over {} (~{:.0}/h, {:.0}% rising)",
            s.net_change as i64,
            fmt_span(s.span_secs),
            s.slope_per_hour,
            s.monotonicity * 100.0,
        ));
    }
    if let (true, Some(s)) = (t.mem_leak_suspect, &t.mem) {
        parts.push(format!(
            "possible memory leak: {} over {} (~{}/h, {:.0}% rising)",
            fmt_bytes_signed(s.net_change),
            fmt_span(s.span_secs),
            fmt_bytes(s.slope_per_hour),
            s.monotonicity * 100.0,
        ));
    }
    if t.idle_burner {
        parts.push(format!(
            "idle burner: {:.1} core-minutes of CPU accumulated while currently at {:.1}%",
            t.cpu_core_sec / 60.0,
            t.current_cpu_percent,
        ));
    }
    if t.orphan_burner {
        parts.push(format!(
            "orphan burner: parent pid {} is gone, yet still at {:.0}% of one core              ({:.1} core-minutes so far) — nothing is left to reap it",
            t.parent_pid
                .map(|p| p.to_string())
                .unwrap_or_else(|| "?".to_string()),
            t.current_cpu_percent,
            t.cpu_core_sec / 60.0,
        ));
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("; "))
    }
}

fn fmt_span(secs: f64) -> String {
    if secs >= 5400.0 {
        format!("{:.1}h", secs / 3600.0)
    } else {
        format!("{:.0}min", secs / 60.0)
    }
}

fn fmt_bytes(b: f64) -> String {
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    if b.abs() >= GIB {
        format!("{:.1} GiB", b / GIB)
    } else {
        format!("{:.0} MiB", b / MIB)
    }
}

fn fmt_bytes_signed(b: f64) -> String {
    if b >= 0.0 {
        format!("+{}", fmt_bytes(b))
    } else {
        format!("-{}", fmt_bytes(-b))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;

    fn series(values: &[f64], step_secs: i64) -> Vec<(DateTime<Utc>, f64)> {
        let t0 = Utc::now() - TimeDelta::seconds(step_secs * values.len() as i64);
        values
            .iter()
            .enumerate()
            .map(|(i, v)| (t0 + TimeDelta::seconds(step_secs * i as i64), *v))
            .collect()
    }

    #[test]
    fn linear_growth_has_correct_slope_and_monotonicity() {
        // +10 handles per minute for an hour -> 600/h.
        let values: Vec<f64> = (0..=60).map(|i| 1000.0 + 10.0 * i as f64).collect();
        let s = trend_stats(&series(&values, 60)).unwrap();
        assert!(
            (s.slope_per_hour - 600.0).abs() < 1.0,
            "slope {}",
            s.slope_per_hour
        );
        assert_eq!(s.monotonicity, 1.0);
        assert_eq!(s.net_change, 600.0);
        assert!(is_leak(
            &s,
            HANDLE_LEAK_MIN_SLOPE_PER_HOUR,
            HANDLE_LEAK_MIN_NET
        ));
    }

    #[test]
    fn noisy_flat_series_is_not_a_leak() {
        // Oscillates around 1000 with no net direction.
        let values: Vec<f64> = (0..=60)
            .map(|i| 1000.0 + if i % 2 == 0 { 50.0 } else { -50.0 })
            .collect();
        let s = trend_stats(&series(&values, 60)).unwrap();
        assert!(s.monotonicity < LEAK_MIN_MONOTONICITY);
        assert!(!is_leak(
            &s,
            HANDLE_LEAK_MIN_SLOPE_PER_HOUR,
            HANDLE_LEAK_MIN_NET
        ));
    }

    #[test]
    fn short_span_is_not_a_leak_even_if_steep() {
        // Climbing fast, but only observed for 10 minutes.
        let values: Vec<f64> = (0..=10).map(|i| 1000.0 + 100.0 * i as f64).collect();
        let s = trend_stats(&series(&values, 60)).unwrap();
        assert!(s.slope_per_hour > HANDLE_LEAK_MIN_SLOPE_PER_HOUR);
        assert!(!is_leak(
            &s,
            HANDLE_LEAK_MIN_SLOPE_PER_HOUR,
            HANDLE_LEAK_MIN_NET
        ));
    }

    #[test]
    fn step_change_without_sustained_growth_is_not_a_leak() {
        // One allocation burst 30 min in, then flat for an hour: large net
        // change, fully monotonic, big overall slope — but the recent half
        // is flat, which is what rules it out.
        let mut values = vec![1000.0; 30];
        values.extend(vec![5000.0; 60]);
        let s = trend_stats(&series(&values, 60)).unwrap();
        assert!(s.net_change >= HANDLE_LEAK_MIN_NET);
        assert!(s.monotonicity >= LEAK_MIN_MONOTONICITY);
        assert!(
            s.recent_slope_per_hour.abs() < 1.0,
            "recent slope {}",
            s.recent_slope_per_hour
        );
        assert!(!is_leak(
            &s,
            HANDLE_LEAK_MIN_SLOPE_PER_HOUR,
            HANDLE_LEAK_MIN_NET
        ));
    }

    fn trend(pid: u32, parent: Option<u32>, cpu: f32) -> ProcessTrend {
        ProcessTrend {
            pid,
            name: format!("proc{pid}"),
            parent_pid: parent,
            current_cpu_percent: cpu,
            handles: None,
            mem: None,
            cpu_core_sec: 0.0,
            gpu_core_sec: 0.0,
            handle_leak_suspect: false,
            mem_leak_suspect: false,
            idle_burner: false,
            orphaned: parent.is_some(),
            orphan_burner: false,
            verdict: None,
        }
    }

    /// Well past every threshold: the runaway this flag exists for.
    const LONG_WINDOW: u64 = 60 * 60;
    const BUSY_CPU: f32 = 100.0;
    const MUCH_CPU: f64 = 600.0;

    #[test]
    fn orphan_pegging_a_core_is_flagged() {
        assert!(is_orphan_burner(true, LONG_WINDOW, MUCH_CPU, BUSY_CPU));
    }

    /// Being orphaned is completely ordinary — anything started from a
    /// shell that has since closed qualifies — so CPU must carry the
    /// verdict on its own.
    #[test]
    fn a_living_parent_rules_it_out_however_busy() {
        assert!(!is_orphan_burner(false, LONG_WINDOW, MUCH_CPU, BUSY_CPU));
    }

    #[test]
    fn idle_orphan_is_not_a_burner() {
        assert!(!is_orphan_burner(true, LONG_WINDOW, MUCH_CPU, 0.1));
    }

    /// Too little history to judge: a process seen burning for one minute
    /// may simply have just started.
    #[test]
    fn short_window_does_not_flag_an_orphan_burner() {
        let just_under = ORPHAN_BURNER_MIN_WINDOW_SECS - 1;
        assert!(!is_orphan_burner(true, just_under, MUCH_CPU, BUSY_CPU));
        assert!(is_orphan_burner(
            true,
            ORPHAN_BURNER_MIN_WINDOW_SECS,
            MUCH_CPU,
            BUSY_CPU
        ));
    }

    /// A momentary spike in the tick we happened to look at is not a
    /// runaway; it has to have been burning for a while.
    #[test]
    fn a_spike_without_accumulation_is_not_flagged() {
        let just_under = ORPHAN_BURNER_MIN_CORE_SEC - 1.0;
        assert!(!is_orphan_burner(true, LONG_WINDOW, just_under, BUSY_CPU));
    }

    #[test]
    fn cpu_floor_is_exact() {
        assert!(is_orphan_burner(
            true,
            LONG_WINDOW,
            MUCH_CPU,
            ORPHAN_BURNER_MIN_CURRENT_CPU
        ));
        assert!(!is_orphan_burner(
            true,
            LONG_WINDOW,
            MUCH_CPU,
            ORPHAN_BURNER_MIN_CURRENT_CPU - 0.1
        ));
    }

    /// The two burner verdicts describe opposite present-tense states, so
    /// nothing may ever satisfy both.
    #[test]
    fn a_process_is_never_both_kinds_of_burner() {
        for cpu in [0.0, 0.5, 1.9, 2.0, 49.0, 50.0, 100.0, 3200.0] {
            let idle = is_idle_burner(LONG_WINDOW, MUCH_CPU, cpu);
            let orphan = is_orphan_burner(true, LONG_WINDOW, MUCH_CPU, cpu);
            assert!(!(idle && orphan), "cpu={cpu} produced both flags");
        }
    }

    /// An orphan burner outranks a leak suspect with a steeper handle
    /// slope, because it is wasting a core right now.
    #[test]
    fn orphan_burners_sort_ahead_of_leak_suspects() {
        let mut burner = trend(10, Some(99), 100.0);
        burner.orphan_burner = true;
        let mut leaker = trend(11, Some(1), 0.0);
        leaker.handle_leak_suspect = true;
        leaker.handles = Some(trend_stats(&series(&[0.0, 10_000.0], 60)).unwrap());

        let mut v = [leaker, burner, trend(12, None, 0.0)];
        v.sort_by(rank);
        assert_eq!(v[0].pid, 10, "the orphan burner must lead");
        assert_eq!(
            v[1].pid, 11,
            "the leak suspect still beats the unflagged one"
        );
    }

    /// The verdict has to name the dead parent — "some orphan is busy" is
    /// not actionable, "parent pid 99 is gone" is.
    #[test]
    fn orphan_burner_verdict_names_the_dead_parent() {
        let mut t = trend(10, Some(99), 100.0);
        t.orphan_burner = true;
        t.cpu_core_sec = 600.0;
        let verdict = build_verdict(&t).expect("a flagged trend must explain itself");
        assert!(verdict.contains("orphan burner"), "{verdict}");
        assert!(verdict.contains("99"), "should name the parent: {verdict}");
        assert!(
            verdict.contains("100%"),
            "should give the CPU figure: {verdict}"
        );
    }

    /// Orphan detection itself is snapshot-only and independent of any
    /// observation window, so it is checked through the real `analyze`
    /// path: a process whose named parent is absent is an orphan, one
    /// whose parent is present is not, and no recorded parent at all is
    /// not the same as a dead one.
    #[test]
    fn analyze_marks_orphans_from_the_live_pid_set() {
        let mut history = RollingHistory::new(std::time::Duration::from_secs(600));
        history.push(crate::model::Snapshot {
            timestamp: Utc::now(),
            processes: vec![
                proc_sample(1, None),        // root
                proc_sample(10, Some(1)),    // parented by a live pid
                proc_sample(11, Some(9999)), // parent absent -> orphan
            ],
            system: crate::model::SystemMetrics::default(),
        });
        let by_pid = |pid: u32| {
            analyze(&history)
                .into_iter()
                .find(|t| t.pid == pid)
                .unwrap()
        };

        assert!(!by_pid(1).orphaned, "no ppid recorded is not a dead ppid");
        assert!(!by_pid(10).orphaned, "parent 1 is in the snapshot");
        assert!(by_pid(11).orphaned, "parent 9999 is absent");
        assert_eq!(by_pid(11).parent_pid, Some(9999));
    }

    fn proc_sample(pid: u32, ppid: Option<u32>) -> crate::model::ProcessSample {
        crate::model::ProcessSample {
            pid,
            ppid,
            name: format!("proc{pid}"),
            cpu_percent: 0.0,
            gpu_percent: 0.0,
            gpu_source: crate::model::GpuSource::Unavailable,
            user: None,
            command_line: None,
            executable_path: None,
            handle_count: Some(100),
            mem_bytes: Some(1024),
        }
    }

    #[test]
    fn empty_and_single_point_series_yield_none() {
        assert!(trend_stats(&[]).is_none());
        assert!(trend_stats(&series(&[1.0], 60)).is_none());
    }
}
