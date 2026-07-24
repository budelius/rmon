use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::model::Snapshot;

/// Width of each accumulation bucket. Bounds memory for the long-window
/// accumulator to `ACCUM_RETAIN / ACCUM_BUCKET` entries per live pid
/// (1440 for the defaults below) instead of one entry per raw sample.
const ACCUM_BUCKET: Duration = Duration::from_secs(60);
/// How far back the accumulator sums usage. This is a rolling window
/// bounded by how long the process has actually been running (in-memory
/// only — it does not survive an app restart).
const ACCUM_RETAIN: Duration = Duration::from_secs(24 * 3600);
/// Clamp on the delta between two `push()` calls, e.g. after the process
/// was suspended/debugged, so a huge gap doesn't get misattributed as a
/// huge chunk of accumulated usage.
const MAX_TICK_SECONDS: f64 = 10.0;

#[derive(Clone, Copy)]
struct AccumBucket {
    start: DateTime<Utc>,
    /// CPU/GPU percent integrated over time in this bucket (percent-seconds
    /// — e.g. 100% for 2 seconds contributes 200). Dividing by 100 gives an
    /// approximate "core-seconds" figure.
    cpu_pct_sec: f64,
    gpu_pct_sec: f64,
}

/// An in-memory rolling window of recent samples, used by the live UIs
/// (TUI/GUI) to draw sparklines/graphs without touching the database, plus
/// a coarser long-window accumulator (bucketed, up to ~24h) used to rank
/// processes by total usage over time rather than their instantaneous %.
///
/// Internally indexed by pid so that per-process history lookups (used for
/// every visible row's inline sparkline, every tick) are O(1) instead of
/// rescanning every retained snapshot.
pub struct RollingHistory {
    retain: Duration,
    latest: Option<Snapshot>,
    per_pid: HashMap<u32, VecDeque<(DateTime<Utc>, f32, f32)>>,
    accum: HashMap<u32, VecDeque<AccumBucket>>,
    last_push_ts: Option<DateTime<Utc>>,
    started_at: DateTime<Utc>,
}

impl RollingHistory {
    pub fn new(retain: Duration) -> Self {
        Self {
            retain,
            latest: None,
            per_pid: HashMap::new(),
            accum: HashMap::new(),
            last_push_ts: None,
            started_at: Utc::now(),
        }
    }

    pub fn push(&mut self, snapshot: Snapshot) {
        let ts = snapshot.timestamp;
        let dt = self
            .last_push_ts
            .map(|prev| (ts - prev).num_milliseconds() as f64 / 1000.0)
            .unwrap_or(0.0)
            .clamp(0.0, MAX_TICK_SECONDS);
        self.last_push_ts = Some(ts);

        for p in &snapshot.processes {
            self.per_pid
                .entry(p.pid)
                .or_default()
                .push_back((ts, p.cpu_percent, p.gpu_percent));
            if dt > 0.0 {
                accumulate(
                    self.accum.entry(p.pid).or_default(),
                    ts,
                    p.cpu_percent as f64 * dt,
                    p.gpu_percent as f64 * dt,
                );
            }
        }
        self.latest = Some(snapshot);
        self.evict_old();
        self.evict_old_accum();
    }

    fn evict_old(&mut self) {
        let cutoff = Utc::now() - chrono::Duration::from_std(self.retain).unwrap_or_default();
        self.per_pid.retain(|_, dq| {
            while let Some(front) = dq.front() {
                if front.0 < cutoff {
                    dq.pop_front();
                } else {
                    break;
                }
            }
            !dq.is_empty()
        });
    }

    fn evict_old_accum(&mut self) {
        let cutoff = Utc::now() - chrono::Duration::from_std(ACCUM_RETAIN).unwrap_or_default();
        self.accum.retain(|_, dq| {
            while let Some(front) = dq.front() {
                if front.start < cutoff {
                    dq.pop_front();
                } else {
                    break;
                }
            }
            !dq.is_empty()
        });
    }

    pub fn latest(&self) -> Option<&Snapshot> {
        self.latest.as_ref()
    }

    pub fn is_empty(&self) -> bool {
        self.latest.is_none()
    }

    /// (timestamp, cpu_percent, gpu_percent) series for a single pid, oldest first.
    pub fn series_for_pid(&self, pid: u32) -> Vec<(DateTime<Utc>, f32, f32)> {
        self.per_pid
            .get(&pid)
            .map(|dq| dq.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Last `n` (cpu_percent, gpu_percent) points for a pid, oldest first —
    /// cheap enough to call per visible row per frame for inline sparklines.
    pub fn tail_for_pid(&self, pid: u32, n: usize) -> Vec<(f32, f32)> {
        let Some(dq) = self.per_pid.get(&pid) else {
            return Vec::new();
        };
        let len = dq.len();
        let skip = len.saturating_sub(n);
        dq.iter().skip(skip).map(|(_, c, g)| (*c, *g)).collect()
    }

    /// Total accumulated (cpu_percent_seconds, gpu_percent_seconds) for a
    /// pid across the retained window (see `accum_window`). Divide by 100
    /// for an approximate core-seconds figure.
    pub fn accumulated(&self, pid: u32) -> (f64, f64) {
        let Some(dq) = self.accum.get(&pid) else {
            return (0.0, 0.0);
        };
        dq.iter()
            .fold((0.0, 0.0), |(c, g), b| (c + b.cpu_pct_sec, g + b.gpu_pct_sec))
    }

    /// How much of the (up to `ACCUM_RETAIN`) accumulation window is
    /// actually covered so far — i.e. how long this `RollingHistory` has
    /// been running. Accumulated totals are only as meaningful as this is
    /// large; a session open for 5 minutes will show ~5 minutes of usage,
    /// not a full day's.
    pub fn accum_window(&self) -> Duration {
        let elapsed = (Utc::now() - self.started_at).num_seconds().max(0) as u64;
        Duration::from_secs(elapsed).min(ACCUM_RETAIN)
    }

    pub fn accum_retain(&self) -> Duration {
        ACCUM_RETAIN
    }
}

fn accumulate(dq: &mut VecDeque<AccumBucket>, ts: DateTime<Utc>, cpu_pct_sec: f64, gpu_pct_sec: f64) {
    let bucket_start = floor_to_bucket(ts, ACCUM_BUCKET);
    match dq.back_mut() {
        Some(b) if b.start == bucket_start => {
            b.cpu_pct_sec += cpu_pct_sec;
            b.gpu_pct_sec += gpu_pct_sec;
        }
        _ => dq.push_back(AccumBucket {
            start: bucket_start,
            cpu_pct_sec,
            gpu_pct_sec,
        }),
    }
}

fn floor_to_bucket(ts: DateTime<Utc>, span: Duration) -> DateTime<Utc> {
    let span_secs = span.as_secs().max(1) as i64;
    let secs = ts.timestamp();
    let floored = secs - secs.rem_euclid(span_secs);
    DateTime::from_timestamp(floored, 0).unwrap_or(ts)
}
