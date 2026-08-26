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
    /// Last-seen open handle count / working-set bytes in this bucket.
    /// Point-in-time values (not integrated like CPU): a 60s-spaced series
    /// of these is what leak-trend detection consumes.
    handles: Option<u32>,
    mem_bytes: Option<u64>,
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
    /// Process name last seen for each tracked pid. Windows reuses pids, so
    /// when a pid comes back under a different name its accumulated history
    /// belongs to a dead process — it's dropped rather than letting the old
    /// series fabricate totals/trends for the new one.
    names: HashMap<u32, String>,
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
            names: HashMap::new(),
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
            match self.names.get(&p.pid) {
                Some(name) if *name == p.name => {}
                Some(_) => {
                    // pid reused by a different process — old history is
                    // the dead process's, not this one's.
                    self.per_pid.remove(&p.pid);
                    self.accum.remove(&p.pid);
                    self.names.insert(p.pid, p.name.clone());
                }
                None => {
                    self.names.insert(p.pid, p.name.clone());
                }
            }
            self.per_pid
                .entry(p.pid)
                .or_default()
                .push_back((ts, p.cpu_percent, p.gpu_percent));
            accumulate(
                self.accum.entry(p.pid).or_default(),
                ts,
                p.cpu_percent as f64 * dt,
                p.gpu_percent as f64 * dt,
                p.handle_count,
                p.mem_bytes,
            );
        }
        self.latest = Some(snapshot);
        self.evict_old();
        self.evict_old_accum();
        let (per_pid, accum) = (&self.per_pid, &self.accum);
        self.names
            .retain(|pid, _| per_pid.contains_key(pid) || accum.contains_key(pid));
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
        dq.iter().fold((0.0, 0.0), |(c, g), b| {
            (c + b.cpu_pct_sec, g + b.gpu_pct_sec)
        })
    }

    /// Open-handle-count series for a pid over the long accumulation window
    /// (one point per `ACCUM_BUCKET`, up to `ACCUM_RETAIN` back), oldest
    /// first. This — not the short raw window — is what trend/leak
    /// detection should consume.
    pub fn handle_series(&self, pid: u32) -> Vec<(DateTime<Utc>, f64)> {
        self.bucket_series(pid, |b| b.handles.map(|h| h as f64))
    }

    /// Working-set-bytes series for a pid, same shape as `handle_series`.
    pub fn mem_series(&self, pid: u32) -> Vec<(DateTime<Utc>, f64)> {
        self.bucket_series(pid, |b| b.mem_bytes.map(|m| m as f64))
    }

    fn bucket_series(
        &self,
        pid: u32,
        value: impl Fn(&AccumBucket) -> Option<f64>,
    ) -> Vec<(DateTime<Utc>, f64)> {
        let Some(dq) = self.accum.get(&pid) else {
            return Vec::new();
        };
        dq.iter()
            .filter_map(|b| value(b).map(|v| (b.start, v)))
            .collect()
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

fn accumulate(
    dq: &mut VecDeque<AccumBucket>,
    ts: DateTime<Utc>,
    cpu_pct_sec: f64,
    gpu_pct_sec: f64,
    handles: Option<u32>,
    mem_bytes: Option<u64>,
) {
    let bucket_start = floor_to_bucket(ts, ACCUM_BUCKET);
    match dq.back_mut() {
        Some(b) if b.start == bucket_start => {
            b.cpu_pct_sec += cpu_pct_sec;
            b.gpu_pct_sec += gpu_pct_sec;
            b.handles = handles.or(b.handles);
            b.mem_bytes = mem_bytes.or(b.mem_bytes);
        }
        _ => dq.push_back(AccumBucket {
            start: bucket_start,
            cpu_pct_sec,
            gpu_pct_sec,
            handles,
            mem_bytes,
        }),
    }
}

fn floor_to_bucket(ts: DateTime<Utc>, span: Duration) -> DateTime<Utc> {
    let span_secs = span.as_secs().max(1) as i64;
    let secs = ts.timestamp();
    let floored = secs - secs.rem_euclid(span_secs);
    DateTime::from_timestamp(floored, 0).unwrap_or(ts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{GpuSource, ProcessSample, SystemMetrics};

    fn snapshot(ts: DateTime<Utc>, pid: u32, name: &str, handles: u32, cpu: f32) -> Snapshot {
        Snapshot {
            timestamp: ts,
            processes: vec![ProcessSample {
                pid,
                ppid: None,
                name: name.to_string(),
                cpu_percent: cpu,
                gpu_percent: 0.0,
                gpu_source: GpuSource::Unavailable,
                user: None,
                command_line: None,
                executable_path: None,
                handle_count: Some(handles),
                mem_bytes: Some(1024),
            }],
            system: SystemMetrics::default(),
        }
    }

    #[test]
    fn handle_series_tracks_bucketed_values() {
        let mut h = RollingHistory::new(Duration::from_secs(300));
        let t0 = Utc::now() - chrono::Duration::seconds(180);
        for i in 0..3 {
            h.push(snapshot(
                t0 + chrono::Duration::seconds(60 * i),
                1,
                "a.exe",
                100 + i as u32,
                50.0,
            ));
        }
        let series = h.handle_series(1);
        assert_eq!(series.len(), 3);
        assert_eq!(series.last().unwrap().1, 102.0);
    }

    #[test]
    fn pid_reuse_under_different_name_resets_history() {
        let mut h = RollingHistory::new(Duration::from_secs(300));
        let t0 = Utc::now() - chrono::Duration::seconds(180);
        h.push(snapshot(t0, 1, "a.exe", 5000, 50.0));
        h.push(snapshot(
            t0 + chrono::Duration::seconds(60),
            1,
            "a.exe",
            6000,
            50.0,
        ));
        let (cpu_before, _) = h.accumulated(1);
        assert!(cpu_before > 0.0);

        // Same pid comes back as a different (idle) executable — the old
        // process's accumulated CPU must not be attributed to it.
        h.push(snapshot(
            t0 + chrono::Duration::seconds(120),
            1,
            "b.exe",
            10,
            0.0,
        ));
        let (cpu_after, _) = h.accumulated(1);
        assert_eq!(cpu_after, 0.0);
        let series = h.handle_series(1);
        assert_eq!(series.len(), 1, "old process's series must be dropped");
        assert_eq!(series[0].1, 10.0);
    }
}
