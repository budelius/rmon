use std::collections::VecDeque;
use std::time::Duration;

use chrono::Utc;

use crate::model::Snapshot;

/// An in-memory rolling window of recent snapshots, used by the live UIs
/// (TUI/GUI) to draw sparklines/graphs without touching the database.
pub struct RollingHistory {
    retain: Duration,
    snapshots: VecDeque<Snapshot>,
}

impl RollingHistory {
    pub fn new(retain: Duration) -> Self {
        Self {
            retain,
            snapshots: VecDeque::new(),
        }
    }

    pub fn push(&mut self, snapshot: Snapshot) {
        self.snapshots.push_back(snapshot);
        self.evict_old();
    }

    fn evict_old(&mut self) {
        let cutoff = Utc::now() - chrono::Duration::from_std(self.retain).unwrap_or_default();
        while let Some(front) = self.snapshots.front() {
            if front.timestamp < cutoff {
                self.snapshots.pop_front();
            } else {
                break;
            }
        }
    }

    pub fn snapshots(&self) -> impl DoubleEndedIterator<Item = &Snapshot> {
        self.snapshots.iter()
    }

    pub fn latest(&self) -> Option<&Snapshot> {
        self.snapshots.back()
    }

    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }

    /// (timestamp, cpu_percent, gpu_percent) series for a single pid, oldest first.
    pub fn series_for_pid(&self, pid: u32) -> Vec<(chrono::DateTime<Utc>, f32, f32)> {
        self.snapshots
            .iter()
            .filter_map(|snap| {
                snap.processes
                    .iter()
                    .find(|p| p.pid == pid)
                    .map(|p| (snap.timestamp, p.cpu_percent, p.gpu_percent))
            })
            .collect()
    }
}
