use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};

use crate::model::ProcessSample;

/// Builds a parent/child process tree from a flat process list and flattens
/// it into a depth-first, pre-order sequence: top-level processes (whose
/// parent isn't in `processes`, e.g. already exited or a kernel process)
/// ranked descending, each followed immediately by its own children
/// (recursively), also ranked within their siblings.
///
/// `key` gives each process's own score. When `by_subtree` is true, ranking
/// instead uses the sum of `key` across the process and all of its
/// descendants — so e.g. a browser's main process outranks unrelated
/// processes based on the total usage of all its renderer/GPU children, not
/// just its own (often small) share.
pub fn build_tree<F>(processes: &[ProcessSample], mut key: F, by_subtree: bool) -> Vec<(usize, ProcessSample)>
where
    F: FnMut(&ProcessSample) -> f32,
{
    let pid_set: HashSet<u32> = processes.iter().map(|p| p.pid).collect();

    let mut children: HashMap<Option<u32>, Vec<&ProcessSample>> = HashMap::new();
    let mut by_pid: HashMap<u32, &ProcessSample> = HashMap::with_capacity(processes.len());
    for p in processes {
        // `contains` and `!= p.pid` guard against self-parented and (rarer)
        // cyclic entries — e.g. Windows' System Idle Process is pid 0 with
        // ppid 0 — which would otherwise loop the DFS below forever.
        let parent = p.ppid.filter(|ppid| pid_set.contains(ppid) && *ppid != p.pid);
        children.entry(parent).or_default().push(p);
        by_pid.insert(p.pid, p);
    }

    let rank: HashMap<u32, f32> = if by_subtree {
        subtree_sums(&children, &by_pid, &mut key)
    } else {
        processes.iter().map(|p| (p.pid, key(p))).collect()
    };

    for kids in children.values_mut() {
        kids.sort_by(|a, b| {
            let ka = *rank.get(&a.pid).unwrap_or(&0.0);
            let kb = *rank.get(&b.pid).unwrap_or(&0.0);
            kb.partial_cmp(&ka).unwrap_or(Ordering::Equal)
        });
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

/// pid -> (own key + sum of all descendants' keys), computed bottom-up.
fn subtree_sums<F>(
    children: &HashMap<Option<u32>, Vec<&ProcessSample>>,
    by_pid: &HashMap<u32, &ProcessSample>,
    key: &mut F,
) -> HashMap<u32, f32>
where
    F: FnMut(&ProcessSample) -> f32,
{
    // BFS from the roots gives an order where every node appears after its
    // parent; reversing it guarantees every node appears after all of its
    // descendants (since descendants always have strictly greater BFS
    // depth), which is exactly what a bottom-up accumulation needs.
    let mut order: Vec<u32> = Vec::new();
    let mut queue: VecDeque<u32> = children
        .get(&None)
        .into_iter()
        .flatten()
        .map(|p| p.pid)
        .collect();
    while let Some(pid) = queue.pop_front() {
        order.push(pid);
        if let Some(kids) = children.get(&Some(pid)) {
            queue.extend(kids.iter().map(|p| p.pid));
        }
    }

    let mut sums: HashMap<u32, f32> = HashMap::with_capacity(order.len());
    for pid in order.into_iter().rev() {
        let Some(node) = by_pid.get(&pid) else { continue };
        let own = key(node);
        let child_sum: f32 = children
            .get(&Some(pid))
            .into_iter()
            .flatten()
            .map(|c| *sums.get(&c.pid).unwrap_or(&0.0))
            .sum();
        sums.insert(pid, own + child_sum);
    }
    sums
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
            user: None,
            command_line: None,
            handle_count: None,
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
        let tree = build_tree(&procs, |p| p.cpu_percent, false);
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
        let tree = build_tree(&procs, |p| p.cpu_percent, false);
        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0], (0, procs[0].clone()));
    }

    #[test]
    fn self_parented_pid_does_not_infinite_loop() {
        // Mirrors Windows' System Idle Process: pid 0 with ppid 0.
        let procs = vec![proc(0, Some(0), 0.0)];
        let tree = build_tree(&procs, |p| p.cpu_percent, false);
        assert_eq!(tree, vec![(0, procs[0].clone())]);
    }

    #[test]
    fn subtree_sum_ranks_by_total_descendant_usage() {
        // Root A (cpu 5) has children summing to 90 (child 2 has grandchild 40).
        // Root B (cpu 50) has no children.
        // By own value B (50) would outrank A (5); by subtree sum A
        // (5+20+70=95, since child pid 3's subtree is 70+... let's compute
        // precisely below) should outrank B.
        let procs = vec![
            proc(1, None, 5.0),   // A, subtree = 5 + 20 + (30 + 40) = 95
            proc(2, Some(1), 20.0),
            proc(3, Some(1), 30.0),
            proc(4, Some(3), 40.0),
            proc(10, None, 50.0), // B, subtree = 50
        ];
        let tree = build_tree(&procs, |p| p.cpu_percent, true);
        let top_level: Vec<u32> = tree.iter().filter(|(d, _)| *d == 0).map(|(_, p)| p.pid).collect();
        assert_eq!(top_level, vec![1, 10]);
    }
}
