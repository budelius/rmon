//! Groups orphaned processes back under the dead parent they came from.
//!
//! An orphan on its own is unremarkable — anything started from a shell that
//! has since closed is one, and [`crate::trends`] deliberately refuses to
//! treat that as a fault. What is worth seeing is the *shape*: forty
//! processes all naming the same departed parent is one abandoned session,
//! not forty independent facts, and it reads as a single line instead of
//! forty scattered rows.
//!
//! This is the view that turns "1,400 processes, why?" into "these three
//! dead launchers are holding 250 of them".
//!
//! # What a group is not
//!
//! Windows reuses pids, and a process records its parent's pid at creation
//! and never updates it. So a group keyed on pid 1234 means "these
//! processes were started by whatever pid 1234 was at the time", which is
//! usually one abandoned launcher and occasionally a coincidence of reuse.
//! [`crate::tree::merge_recent_exits`] can name the dead parent when ETW
//! exit history saw it go; without that the group carries the bare pid
//! rather than inventing a name for it.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::model::ProcessSample;
use crate::proc_events::RecentExit;

/// A cluster of live processes whose common parent is gone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrphanGroup {
    /// The parent pid every member names. Not currently running.
    pub dead_ppid: u32,
    /// The dead parent's image name, when ETW exit history saw it exit.
    /// `None` means it died before rMon was watching — common, and not a
    /// reason to hide the group.
    pub parent_name: Option<String>,
    /// Live members, most expensive first.
    pub members: Vec<ProcessSample>,
    /// Distinct image names in the group, most common first — the summary
    /// that makes a group recognisable at a glance ("38x bash.exe").
    pub composition: Vec<NameCount>,
    pub total_cpu_percent: f32,
    pub total_mem_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameCount {
    pub name: String,
    pub count: usize,
}

impl OrphanGroup {
    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// One line a human can act on.
    pub fn summary(&self) -> String {
        let what = self
            .composition
            .iter()
            .take(3)
            .map(|c| format!("{}x {}", c.count, c.name))
            .collect::<Vec<_>>()
            .join(", ");
        let parent = match &self.parent_name {
            Some(name) => format!("{name} (pid {})", self.dead_ppid),
            None => format!("pid {}", self.dead_ppid),
        };
        format!(
            "{} processes [{what}] orphaned by {parent}, {:.1}% CPU, {} MiB",
            self.members.len(),
            self.total_cpu_percent,
            self.total_mem_bytes / (1024 * 1024)
        )
    }
}

/// Finds every cluster of live processes sharing a parent that no longer
/// exists, largest first.
///
/// `exits` is optional ETW history used only to *name* the dead parent; the
/// grouping itself needs nothing but the snapshot.
pub fn orphan_groups(processes: &[ProcessSample], exits: &[RecentExit]) -> Vec<OrphanGroup> {
    let live: HashSet<u32> = processes.iter().map(|p| p.pid).collect();
    let names: HashMap<u32, &str> = exits
        .iter()
        .map(|e| (e.pid, e.name.as_str()))
        .collect();

    let mut by_parent: HashMap<u32, Vec<&ProcessSample>> = HashMap::new();
    for p in processes {
        let Some(ppid) = p.ppid else { continue };
        // pid 0 is the idle pseudo-process and is every top-level process's
        // recorded parent; treating those as orphans would put most of the
        // machine in one meaningless group.
        if ppid == 0 || live.contains(&ppid) {
            continue;
        }
        by_parent.entry(ppid).or_default().push(p);
    }

    let mut groups: Vec<OrphanGroup> = by_parent
        .into_iter()
        .map(|(dead_ppid, members)| {
            let mut counts: HashMap<&str, usize> = HashMap::new();
            for m in &members {
                *counts.entry(m.name.as_str()).or_default() += 1;
            }
            let mut composition: Vec<NameCount> = counts
                .into_iter()
                .map(|(name, count)| NameCount { name: name.to_string(), count })
                .collect();
            composition.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));

            let total_cpu_percent = members.iter().map(|m| m.cpu_percent).sum();
            let total_mem_bytes = members.iter().filter_map(|m| m.mem_bytes).sum();

            let mut members: Vec<ProcessSample> = members.into_iter().cloned().collect();
            members.sort_by(|a, b| {
                b.cpu_percent
                    .partial_cmp(&a.cpu_percent)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| a.pid.cmp(&b.pid))
            });

            OrphanGroup {
                dead_ppid,
                parent_name: names.get(&dead_ppid).map(|n| n.to_string()),
                members,
                composition,
                total_cpu_percent,
                total_mem_bytes,
            }
        })
        .collect();

    groups.sort_by(|a, b| {
        b.members
            .len()
            .cmp(&a.members.len())
            .then_with(|| {
                b.total_cpu_percent
                    .partial_cmp(&a.total_cpu_percent)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| a.dead_ppid.cmp(&b.dead_ppid))
    });
    groups
}

/// Groups holding at least `min_size` processes — the ones worth a human's
/// attention rather than every one-off orphan on the machine.
pub fn significant_groups(
    processes: &[ProcessSample],
    exits: &[RecentExit],
    min_size: usize,
) -> Vec<OrphanGroup> {
    let mut groups = orphan_groups(processes, exits);
    groups.retain(|g| g.members.len() >= min_size);
    groups
}

/// Default floor for "worth showing": two processes sharing a dead parent
/// is a pattern, one is just a process.
pub const DEFAULT_MIN_GROUP: usize = 2;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::GpuSource;

    fn proc(pid: u32, ppid: Option<u32>, name: &str, cpu: f32, mem_mb: u64) -> ProcessSample {
        ProcessSample {
            pid,
            ppid,
            name: name.to_string(),
            cpu_percent: cpu,
            gpu_percent: 0.0,
            gpu_source: GpuSource::Unavailable,
            user: None,
            command_line: None,
            executable_path: None,
            handle_count: None,
            mem_bytes: Some(mem_mb * 1024 * 1024),
        }
    }

    /// The case this module exists for: one departed launcher still holding
    /// a pile of shells.
    #[test]
    fn clusters_orphans_under_their_dead_parent() {
        let mut procs = vec![proc(1, None, "System", 0.0, 0)];
        for pid in 100..138 {
            procs.push(proc(pid, Some(9999), "bash.exe", 0.5, 10));
        }
        for pid in 200..219 {
            procs.push(proc(pid, Some(8888), "powershell.exe", 1.0, 20));
        }

        let groups = orphan_groups(&procs, &[]);
        assert_eq!(groups.len(), 2, "two dead parents, two groups");

        let bash = &groups[0];
        assert_eq!(bash.dead_ppid, 9999);
        assert_eq!(bash.len(), 38, "largest group must sort first");
        assert_eq!(
            bash.composition,
            vec![NameCount { name: "bash.exe".into(), count: 38 }]
        );
        assert_eq!(bash.total_mem_bytes, 38 * 10 * 1024 * 1024);
        assert!((bash.total_cpu_percent - 19.0).abs() < 0.01);

        assert_eq!(groups[1].dead_ppid, 8888);
        assert_eq!(groups[1].len(), 19);
    }

    /// A living parent is not a dead one, however many children it has —
    /// otherwise every browser would look like an abandoned session.
    #[test]
    fn processes_with_a_living_parent_are_not_orphans() {
        let procs = vec![
            proc(10, None, "warp.exe", 0.0, 0),
            proc(11, Some(10), "pwsh.exe", 0.0, 0),
            proc(12, Some(10), "pwsh.exe", 0.0, 0),
        ];
        assert!(orphan_groups(&procs, &[]).is_empty());
    }

    /// Every top-level process records parent 0. Grouping on it would put
    /// most of the machine into one meaningless cluster.
    #[test]
    fn parent_zero_is_not_a_dead_parent() {
        let procs = vec![
            proc(4, Some(0), "System", 0.0, 0),
            proc(88, Some(0), "wininit.exe", 0.0, 0),
        ];
        assert!(orphan_groups(&procs, &[]).is_empty());
    }

    #[test]
    fn names_the_dead_parent_from_exit_history_when_available() {
        let procs = vec![
            proc(1, None, "init", 0.0, 0),
            proc(2, Some(500), "bash.exe", 0.0, 0),
            proc(3, Some(500), "bash.exe", 0.0, 0),
        ];
        let exits = vec![RecentExit {
            pid: 500,
            ppid: None,
            name: "warpspeed.exe".into(),
            start_time: chrono::Utc::now(),
            duration_ms: 10,
            exit_code: Some(0),
        }];

        let named = orphan_groups(&procs, &exits);
        assert_eq!(named[0].parent_name.as_deref(), Some("warpspeed.exe"));
        assert!(named[0].summary().contains("warpspeed.exe"));

        // Without history the group still stands; it just cannot name it.
        let unnamed = orphan_groups(&procs, &[]);
        assert_eq!(unnamed[0].parent_name, None);
        assert_eq!(unnamed[0].len(), 2, "an unnameable parent is still a group");
    }

    #[test]
    fn significant_groups_filters_out_lone_orphans() {
        let procs = vec![
            proc(1, None, "init", 0.0, 0),
            proc(2, Some(700), "stray.exe", 0.0, 0),
            proc(3, Some(800), "pair.exe", 0.0, 0),
            proc(4, Some(800), "pair.exe", 0.0, 0),
        ];
        let groups = significant_groups(&procs, &[], DEFAULT_MIN_GROUP);
        assert_eq!(groups.len(), 1, "a single orphan is not a pattern");
        assert_eq!(groups[0].dead_ppid, 800);
    }

    #[test]
    fn summary_reads_as_one_actionable_line() {
        let procs = vec![
            proc(1, None, "init", 0.0, 0),
            proc(2, Some(42), "bash.exe", 1.5, 100),
            proc(3, Some(42), "bash.exe", 2.5, 100),
            proc(4, Some(42), "node.exe", 1.0, 100),
        ];
        let line = orphan_groups(&procs, &[])[0].summary();
        println!("{line}");
        assert!(line.contains("3 processes"), "{line}");
        assert!(line.contains("2x bash.exe"), "{line}");
        assert!(line.contains("pid 42"), "{line}");
        assert!(line.contains("300 MiB"), "{line}");
    }
}
