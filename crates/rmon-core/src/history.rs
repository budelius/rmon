use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::model::Snapshot;

/// An in-memory rolling window of recent samples, used by the live UIs
/// (TUI/GUI) to draw sparklines/graphs without touching the database.
///
/// Internally indexed by pid so that per-process history lookups (used for
/// every visible row's inline sparkline, every tick) are O(1) instead of
/// rescanning every retained snapshot.
pub struct RollingHistory {
    retain: Duration,
    latest: Option<Snapshot>,
    per_pid: HashMap<u32, VecDeque<(DateTime<Utc>, f32, f32)>>,
}

impl RollingHistory {
    pub fn new(retain: Duration) -> Self {
        Self {
            retain,
            latest: None,
            per_pid: HashMap::new(),
        }
    }

    pub fn push(&mut self, snapshot: Snapshot) {
        let ts = snapshot.timestamp;
        for p in &snapshot.processes {
            self.per_pid
                .entry(p.pid)
                .or_default()
                .push_back((ts, p.cpu_percent, p.gpu_percent));
        }
        self.latest = Some(snapshot);
        self.evict_old();
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
}
