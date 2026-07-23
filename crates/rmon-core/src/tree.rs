use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use crate::model::ProcessSample;

/// Builds a parent/child process tree from a flat process list and flattens
/// it into a depth-first, pre-order sequence: top-level processes (whose
/// parent isn't in `processes`, e.g. already exited or a kernel process)
/// ranked by `key` descending, each followed immediately by its own
/// children (recursively), also ranked by `key` within their siblings.
pub fn build_tree<F>(processes: &[ProcessSample], mut key: F) -> Vec<(usize, ProcessSample)>
where
    F: FnMut(&ProcessSample) -> f32,
{
    let pid_set: HashSet<u32> = processes.iter().map(|p| p.pid).collect();

    let mut children: HashMap<Option<u32>, Vec<&ProcessSample>> = HashMap::new();
    for p in processes {
        // `contains` and `!= p.pid` guard against self-parented and (rarer)
        // cyclic entries — e.g. Windows' System Idle Process is pid 0 with
        // ppid 0 — which would otherwise loop the DFS below forever.
        let parent = p.ppid.filter(|ppid| pid_set.contains(ppid) && *ppid != p.pid);
        children.entry(parent).or_default().push(p);
    }
    for kids in children.values_mut() {
        kids.sort_by(|a, b| key(b).partial_cmp(&key(a)).unwrap_or(Ordering::Equal));
    }

    let mut out = Vec::with_capacity(processes.len());
    let mut visited: HashSet<u32> = HashSet::with_capacity(processes.len());
    let mut stack: Vec<(usize, &ProcessSample)> = children
        .get(&None)
        .into_iter()
        .flatten()
        .rev()
        .map(|p| (0, *p))
        .collect();

    while let Some((depth, p)) = stack.pop() {
        if !visited.insert(p.pid) {
            continue; // defensive: never revisit a pid (guards any parent-chain cycle)
        }
        out.push((depth, p.clone()));
        if let Some(kids) = children.get(&Some(p.pid)) {
            for k in kids.iter().rev() {
                stack.push((depth + 1, k));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::GpuSource;

    fn proc(pid: u32, ppid: Option<u32>, cpu: f32) -> ProcessSample {
        ProcessSample {
            pid,
            ppid,
            name: format!("p{pid}"),
            cpu_percent: cpu,
            gpu_percent: 0.0,
            gpu_source: GpuSource::Unavailable,
        }
    }

    #[test]
    fn orders_children_under_parents_by_key_desc() {
        // 1 (root, cpu 10)
        //   2 (child of 1, cpu 5)
        //   3 (child of 1, cpu 50)
        //     4 (child of 3, cpu 1)
        // 5 (root, cpu 90)
        let procs = vec![
            proc(1, None, 10.0),
            proc(2, Some(1), 5.0),
            proc(3, Some(1), 50.0),
            proc(4, Some(3), 1.0),
            proc(5, None, 90.0),
        ];
        let tree = build_tree(&procs, |p| p.cpu_percent);
        let pids_and_depths: Vec<(u32, usize)> = tree.iter().map(|(d, p)| (p.pid, *d)).collect();
        assert_eq!(
            pids_and_depths,
            vec![(5, 0), (1, 0), (3, 1), (4, 2), (2, 1)]
        );
    }

    #[test]
    fn missing_parent_becomes_a_root() {
        // pid 2's parent (99) isn't in the process list (e.g. already exited).
        let procs = vec![proc(2, Some(99), 1.0)];
        let tree = build_tree(&procs, |p| p.cpu_percent);
        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0], (0, procs[0].clone()));
    }

    #[test]
    fn self_parented_pid_does_not_infinite_loop() {
        // Mirrors Windows' System Idle Process: pid 0 with ppid 0.
        let procs = vec![proc(0, Some(0), 0.0)];
        let tree = build_tree(&procs, |p| p.cpu_percent);
        assert_eq!(tree, vec![(0, procs[0].clone())]);
    }
}
