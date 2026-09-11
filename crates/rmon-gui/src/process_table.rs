//! Process-table ordering: exact resource values, unavailable readings last,
//! and the same column semantics in flat and tree views.

use std::cmp::Ordering;
use std::collections::HashMap;

use rmon_core::{ProcessSample, RollingHistory, build_tree, build_tree_by};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortMetric {
    Cpu,
    Gpu,
    Total,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortWindow {
    Instant,
    Accumulated,
}

/// Only CPU/GPU metrics use the toolbar's time window or subtree sums.
/// Resource columns always show and sort each process's current value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortColumn {
    Metric,
    Pid,
    Name,
    Memory,
    Handles,
    Children,
    Src,
}

pub struct ProcessSort<'a> {
    pub history: &'a RollingHistory,
    pub metric: SortMetric,
    pub window: SortWindow,
    pub column: SortColumn,
    pub ascending: bool,
    /// Cached from the full live snapshot, never the filtered tree.
    pub child_counts: &'a HashMap<u32, u32>,
}

impl ProcessSort<'_> {
    fn score(&self, p: &ProcessSample) -> f32 {
        match self.window {
            SortWindow::Instant => match self.metric {
                SortMetric::Cpu => p.cpu_percent,
                SortMetric::Gpu => p.gpu_percent,
                SortMetric::Total => p.cpu_percent + p.gpu_percent,
            },
            SortWindow::Accumulated => {
                let (cpu_s, gpu_s) = self.history.accumulated(p.pid);
                match self.metric {
                    SortMetric::Cpu => cpu_s as f32,
                    SortMetric::Gpu => gpu_s as f32,
                    SortMetric::Total => (cpu_s + gpu_s) as f32,
                }
            }
        }
    }

    pub fn compare(&self, a: &ProcessSample, b: &ProcessSample) -> Ordering {
        let order = match self.column {
            SortColumn::Memory => optional_cmp(a.mem_bytes, b.mem_bytes, self.ascending),
            SortColumn::Handles => optional_cmp(a.handle_count, b.handle_count, self.ascending),
            SortColumn::Children => optional_cmp(
                self.child_counts.get(&a.pid),
                self.child_counts.get(&b.pid),
                self.ascending,
            ),
            column => {
                let order = match column {
                    SortColumn::Metric => self.score(a).total_cmp(&self.score(b)),
                    SortColumn::Pid => a.pid.cmp(&b.pid),
                    SortColumn::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                    SortColumn::Src => crate::gpu_source_label(a.gpu_source)
                        .cmp(crate::gpu_source_label(b.gpu_source)),
                    _ => unreachable!(),
                };
                if self.ascending {
                    order
                } else {
                    order.reverse()
                }
            }
        };
        // Stable across snapshots even when their process enumeration order changes.
        order.then_with(|| a.pid.cmp(&b.pid))
    }

    pub fn tree(&self, processes: &[ProcessSample], subtree: bool) -> Vec<(usize, ProcessSample)> {
        if self.column == SortColumn::Metric && subtree {
            let sign = if self.ascending { -1.0 } else { 1.0 };
            build_tree(processes, |p| sign * self.score(p), true)
        } else {
            build_tree_by(processes, |a, b| self.compare(a, b))
        }
    }
}

fn optional_cmp<T: Ord>(a: Option<T>, b: Option<T>, ascending: bool) -> Ordering {
    match (a, b) {
        (Some(a), Some(b)) => {
            if ascending {
                a.cmp(&b)
            } else {
                b.cmp(&a)
            }
        }
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use rmon_core::{GpuSource, Snapshot, SystemMetrics};

    fn process(pid: u32, ppid: Option<u32>, value: Option<u64>) -> ProcessSample {
        ProcessSample {
            pid,
            ppid,
            name: format!("p{pid}"),
            cpu_percent: 0.0,
            gpu_percent: 0.0,
            gpu_source: GpuSource::Unavailable,
            user: None,
            command_line: None,
            executable_path: None,
            handle_count: value.map(|v| v as u32),
            mem_bytes: value,
        }
    }

    fn pids(rows: &[(usize, ProcessSample)]) -> Vec<(usize, u32)> {
        rows.iter().map(|(depth, p)| (*depth, p.pid)).collect()
    }

    #[test]
    fn resource_sort_is_exact_and_unknown_is_last_in_both_directions() {
        let history = RollingHistory::new(Duration::from_secs(300));
        // Adjacent large integers compare equal if converted to f32.
        let big = 1 << 30;
        let processes = vec![
            process(1, None, None),
            process(2, None, Some(big)),
            process(3, None, Some(big + 1)),
            process(4, None, Some(0)),
            process(5, None, Some(big)),
        ];
        let child_counts = HashMap::from([
            (2, big as u32),
            (3, big as u32 + 1),
            (4, 0),
            (5, big as u32),
        ]);
        for column in [
            SortColumn::Memory,
            SortColumn::Handles,
            SortColumn::Children,
        ] {
            for ascending in [false, true] {
                let sort = ProcessSort {
                    history: &history,
                    metric: SortMetric::Cpu,
                    // Resource values must not become accumulated CPU scores.
                    window: SortWindow::Accumulated,
                    column,
                    ascending,
                    child_counts: &child_counts,
                };
                let mut flat = processes.clone();
                flat.sort_by(|a, b| sort.compare(a, b));
                let expected = if ascending {
                    vec![4, 2, 5, 3, 1]
                } else {
                    vec![3, 2, 5, 4, 1]
                };
                assert_eq!(
                    flat.iter().map(|p| p.pid).collect::<Vec<_>>(),
                    expected,
                    "{column:?}"
                );
                // A stale subtree checkbox must not sum resource values or
                // let an unknown ghost's made-up zero outrank a live row.
                assert_eq!(
                    pids(&sort.tree(&processes, true)),
                    expected.into_iter().map(|pid| (0, pid)).collect::<Vec<_>>()
                );
            }
        }
    }

    #[test]
    fn tree_sorts_roots_and_siblings_without_changing_parentage() {
        let history = RollingHistory::new(Duration::from_secs(300));
        let child_counts = HashMap::new();
        let processes = vec![
            process(1, None, Some(10)),
            process(2, Some(1), Some(5)),
            process(3, Some(1), Some(50)),
            process(4, Some(3), Some(100)),
            process(5, None, Some(20)),
        ];
        let mut sort = ProcessSort {
            history: &history,
            metric: SortMetric::Total,
            window: SortWindow::Instant,
            column: SortColumn::Memory,
            ascending: false,
            child_counts: &child_counts,
        };
        assert_eq!(
            pids(&sort.tree(&processes, false)),
            vec![(0, 5), (0, 1), (1, 3), (2, 4), (1, 2)]
        );
        sort.ascending = true;
        assert_eq!(
            pids(&sort.tree(&processes, false)),
            vec![(0, 1), (1, 2), (1, 3), (2, 4), (0, 5)]
        );
    }

    #[test]
    fn cpu_subtree_sort_still_sums_usage_and_respects_direction() {
        let history = RollingHistory::new(Duration::from_secs(300));
        let child_counts = HashMap::new();
        let mut processes = vec![
            process(1, None, None),
            process(2, Some(1), None),
            process(3, None, None),
        ];
        for (p, cpu) in processes.iter_mut().zip([1.0, 90.0, 50.0]) {
            p.cpu_percent = cpu;
        }
        let mut sort = ProcessSort {
            history: &history,
            metric: SortMetric::Cpu,
            window: SortWindow::Instant,
            column: SortColumn::Metric,
            ascending: false,
            child_counts: &child_counts,
        };
        assert_eq!(
            pids(&sort.tree(&processes, false)),
            vec![(0, 3), (0, 1), (1, 2)]
        );
        assert_eq!(
            pids(&sort.tree(&processes, true)),
            vec![(0, 1), (1, 2), (0, 3)]
        );
        sort.ascending = true;
        assert_eq!(
            pids(&sort.tree(&processes, true)),
            vec![(0, 3), (0, 1), (1, 2)]
        );
    }

    #[test]
    fn child_sort_uses_full_snapshot_even_when_children_are_filtered_out() {
        let history = RollingHistory::new(Duration::from_secs(300));
        let snapshot = Snapshot {
            timestamp: chrono::Utc::now(),
            processes: vec![
                process(1, None, None),
                process(2, None, None),
                process(3, Some(2), None),
                process(4, Some(2), None),
                process(5, Some(1), None),
            ],
            system: SystemMetrics::default(),
        };
        let child_counts = snapshot.child_counts();
        let sort = ProcessSort {
            history: &history,
            metric: SortMetric::Total,
            window: SortWindow::Instant,
            column: SortColumn::Children,
            ascending: false,
            child_counts: &child_counts,
        };
        assert_eq!(
            pids(&sort.tree(&snapshot.processes[..2], false)),
            vec![(0, 2), (0, 1)]
        );
    }
}
