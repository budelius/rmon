#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod autostart;
mod icon;
mod tray;

use std::collections::{HashMap, HashSet};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use eframe::egui;
use egui_plot::{Legend, Line, Plot, PlotPoints};
use rmon_core::{
    build_tree, check_hardware_health, list_all_ports, list_open_files, list_open_files_many,
    listening_ports_for, merge_recent_exits, AllFilesEntry, GpuSource, HardwareHealthReport,
    OpenFilesScan, PortEntry, ProcessSample, RollingHistory, Sampler, ShortLivedWatcher, Store,
    SystemMetrics, DEFAULT_GHOST_MAX_DEPTH, DEFAULT_SCAN_WORKERS, DEFAULT_WHEA_LOOKBACK_DAYS,
    DEFAULT_WHEA_MAX_EVENTS,
};
use tray::{Tray, TrayAction};

const RETAIN: Duration = Duration::from_secs(300);
const TICK: Duration = Duration::from_millis(1000);
const SPARK_POINTS: usize = 30;

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortMetric {
    Cpu,
    Gpu,
    Total,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortWindow {
    Instant,
    Accumulated,
}

/// Which table column currently drives row order. `Metric` defers to
/// `sort_metric`/`sort_window` (the toolbar controls); the rest sort
/// directly on that column's own value.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SortColumn {
    Metric,
    Pid,
    Name,
    Src,
}

fn score(history: &RollingHistory, metric: SortMetric, window: SortWindow, p: &ProcessSample) -> f32 {
    match window {
        SortWindow::Instant => match metric {
            SortMetric::Cpu => p.cpu_percent,
            SortMetric::Gpu => p.gpu_percent,
            SortMetric::Total => p.cpu_percent + p.gpu_percent,
        },
        SortWindow::Accumulated => {
            let (cpu_s, gpu_s) = history.accumulated(p.pid);
            match metric {
                SortMetric::Cpu => cpu_s as f32,
                SortMetric::Gpu => gpu_s as f32,
                SortMetric::Total => (cpu_s + gpu_s) as f32,
            }
        }
    }
}

/// Formats a duration compactly, e.g. "3h12m", "45m", "38s".
fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h}h{m:02}m")
    } else if m > 0 {
        format!("{m}m{s:02}s")
    } else {
        format!("{s}s")
    }
}

/// Formats accumulated percent-seconds as approximate core-time, e.g. "4m12s".
fn format_core_time(pct_seconds: f64) -> String {
    format_duration(Duration::from_secs_f64((pct_seconds / 100.0).max(0.0)))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ViewMode {
    Flat,
    Tree,
}

enum FilesStatus {
    Scanning(mpsc::Receiver<Result<OpenFilesScan, String>>),
    Done(OpenFilesScan),
    Error(String),
}

struct FilesState {
    pid: u32,
    status: FilesStatus,
    search: String,
}

impl FilesState {
    fn start(pid: u32) -> Self {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let result = list_open_files(pid).map_err(|e| e.to_string());
            let _ = tx.send(result);
        });
        Self {
            pid,
            status: FilesStatus::Scanning(rx),
            search: String::new(),
        }
    }

    fn poll(&mut self) {
        if let FilesStatus::Scanning(rx) = &self.status
            && let Ok(result) = rx.try_recv()
        {
            self.status = match result {
                Ok(scan) => FilesStatus::Done(scan),
                Err(e) => FilesStatus::Error(e),
            };
        }
    }

    fn filtered_paths(&self) -> Vec<&str> {
        let FilesStatus::Done(scan) = &self.status else {
            return Vec::new();
        };
        let f = self.search.to_lowercase();
        scan.paths
            .iter()
            .filter(|p| f.is_empty() || p.to_lowercase().contains(&f))
            .map(|s| s.as_str())
            .collect()
    }
}

/// Cross-process search: ports come from the already-cached global port
/// table (cheap, always fresh), open files require an explicit on-demand
/// scan across every process (same on-demand philosophy as `FilesState`,
/// just fanned out to all pids via `list_open_files_many`).
struct SearchState {
    query: String,
    files: Vec<AllFilesEntry>,
    scanned: usize,
    total: usize,
    rx: Option<mpsc::Receiver<AllFilesEntry>>,
}

impl SearchState {
    fn new() -> Self {
        Self {
            query: String::new(),
            files: Vec::new(),
            scanned: 0,
            total: 0,
            rx: None,
        }
    }

    fn start_scan(&mut self, pids: Vec<u32>) {
        let (tx, rx) = mpsc::channel();
        self.total = pids.len();
        self.scanned = 0;
        self.files.clear();
        self.rx = Some(rx);
        std::thread::spawn(move || {
            list_open_files_many(pids, DEFAULT_SCAN_WORKERS, tx);
        });
    }

    fn poll(&mut self) {
        let Some(rx) = &self.rx else { return };
        loop {
            match rx.try_recv() {
                Ok(entry) => {
                    self.scanned += 1;
                    self.files.push(entry);
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.rx = None;
                    break;
                }
            }
        }
    }

    fn scanning(&self) -> bool {
        self.rx.is_some()
    }
}

enum HealthStatus {
    Scanning(mpsc::Receiver<HardwareHealthReport>),
    Done(HardwareHealthReport),
}

/// WHEA event log query is slow (`Win32_NTLogEvent` has no useful
/// server-side filtering beyond Logfile/SourceName) — up to ~30s on a
/// system that logs frequently — so like `FilesState`, this always runs on
/// a background thread rather than blocking the UI.
struct HealthState {
    status: HealthStatus,
}

impl HealthState {
    fn start(days: i64, max_events: usize) -> Self {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(check_hardware_health(days, max_events));
        });
        Self { status: HealthStatus::Scanning(rx) }
    }

    fn poll(&mut self) {
        if let HealthStatus::Scanning(rx) = &self.status
            && let Ok(report) = rx.try_recv()
        {
            self.status = HealthStatus::Done(report);
        }
    }

    fn scanning(&self) -> bool {
        matches!(self.status, HealthStatus::Scanning(_))
    }
}

struct RmonApp {
    sampler: Sampler,
    history: RollingHistory,
    has_gpu_source: bool,
    sort_metric: SortMetric,
    sort_window: SortWindow,
    sort_column: SortColumn,
    sort_ascending: bool,
    subtree_sort: bool,
    view_mode: ViewMode,
    filter: String,
    orphans_only: bool,
    /// Pids in the current (unfiltered) snapshot whose ppid no longer
    /// belongs to any running process — the parent already exited.
    /// Recomputed every `resort()` regardless of `orphans_only`, so rows
    /// can be badged even when the filter itself is off.
    orphan_pids: HashSet<u32>,
    /// Pids in the current tree layout that are synthetic "ghost" nodes —
    /// exited processes reconnected from `ShortLivedWatcher`'s history via
    /// `merge_recent_exits`, not real live rows (see `resort`). Always
    /// empty in flat view.
    tree_ghosts: HashSet<u32>,
    rows: Vec<(usize, ProcessSample)>,
    /// Pids whose children are hidden in tree view.
    collapsed: HashSet<u32>,
    /// Pids that have at least one child in the current tree layout —
    /// recomputed each `resort()`; drives whether a row gets a
    /// collapse/expand arrow.
    tree_has_children: HashSet<u32>,
    selected_pid: Option<u32>,
    scroll_to_selected: bool,
    last_tick: Instant,
    system: SystemMetrics,
    /// System-wide TCP/UDP endpoint table, refreshed every tick — cheap
    /// enough to poll continuously, unlike `files`. Backs both the
    /// per-process "listening ports" section and the global search view.
    ports: Vec<PortEntry>,
    files: Option<FilesState>,
    settings_open: bool,
    search_open: bool,
    search: SearchState,
    exited_open: bool,
    hardware_open: bool,
    health_open: bool,
    /// WHEA events / BIOS / microcode revision — `None` until the view is
    /// opened for the first time (or "rescan" is clicked again).
    health: Option<HealthState>,
    /// `None` if not elevated or the ETW trace failed to start (see
    /// `short_lived_error` for why); catches processes that start and
    /// fully exit between polling ticks, which `Sampler` alone can't see.
    short_lived: Option<ShortLivedWatcher>,
    short_lived_error: Option<String>,
    kill_error: Option<String>,
    elevation_error: Option<String>,

    recording: bool,
    db_path: String,
    store: Option<Store>,
    record_error: Option<String>,

    tray: Option<Tray>,
    really_quit: bool,
    autostart_enabled: bool,
    autostart_error: Option<String>,
}

impl RmonApp {
    fn new() -> Self {
        let mut sampler = Sampler::new();
        let has_gpu_source = sampler.has_gpu_source();
        sampler.sample(); // warm up
        let tray = match Tray::new() {
            Ok(tray) => Some(tray),
            Err(e) => {
                eprintln!("tray icon unavailable: {e:#}");
                None
            }
        };
        Self {
            sampler,
            history: RollingHistory::new(RETAIN),
            has_gpu_source,
            sort_metric: SortMetric::Total,
            sort_window: SortWindow::Instant,
            sort_column: SortColumn::Metric,
            sort_ascending: false,
            subtree_sort: false,
            view_mode: ViewMode::Flat,
            filter: String::new(),
            orphans_only: false,
            orphan_pids: HashSet::new(),
            tree_ghosts: HashSet::new(),
            rows: Vec::new(),
            collapsed: HashSet::new(),
            tree_has_children: HashSet::new(),
            selected_pid: None,
            scroll_to_selected: false,
            last_tick: Instant::now() - TICK,
            system: SystemMetrics::default(),
            ports: Vec::new(),
            files: None,
            settings_open: false,
            search_open: false,
            search: SearchState::new(),
            exited_open: false,
            hardware_open: false,
            health_open: false,
            health: None,
            short_lived: match ShortLivedWatcher::start() {
                Ok(w) => Some(w),
                Err(e) => {
                    eprintln!("short-lived process tracking unavailable: {e:#}");
                    None
                }
            },
            short_lived_error: None,
            kill_error: None,
            elevation_error: None,
            recording: false,
            db_path: "rmon.sqlite".to_string(),
            store: None,
            record_error: None,

            tray,
            really_quit: false,
            autostart_enabled: autostart::is_enabled(),
            autostart_error: None,
        }
    }

    fn tick(&mut self) {
        let snapshot = self.sampler.sample();
        self.system = snapshot.system.clone();
        self.ports = list_all_ports().unwrap_or_default();

        if self.recording {
            if self.store.is_none() {
                match Store::open(&self.db_path) {
                    Ok(s) => self.store = Some(s),
                    Err(e) => {
                        self.record_error = Some(format!("failed to open {}: {e:#}", self.db_path));
                        self.recording = false;
                        rmon_core::observability::capture_anyhow(&e);
                    }
                }
            }
            if let Some(store) = self.store.as_mut()
                && let Err(e) = store.insert_snapshot(&snapshot)
            {
                self.record_error = Some(format!("write failed: {e:#}"));
                self.recording = false;
                rmon_core::observability::capture_anyhow(&e);
            }
        }

        self.history.push(snapshot);
        self.resort();
    }

    fn resort(&mut self) {
        let Some(snapshot) = self.history.latest() else {
            return;
        };
        let all_pids: HashSet<u32> = snapshot.processes.iter().map(|p| p.pid).collect();
        self.orphan_pids = snapshot
            .processes
            .iter()
            .filter(|p| p.ppid.is_some_and(|ppid| !all_pids.contains(&ppid)))
            .map(|p| p.pid)
            .collect();

        let filter = self.filter.to_lowercase();
        let orphans_only = self.orphans_only;
        let orphan_pids = &self.orphan_pids;
        let filtered: Vec<ProcessSample> = snapshot
            .processes
            .iter()
            .filter(|p| filter.is_empty() || p.name.to_lowercase().contains(&filter))
            .filter(|p| !orphans_only || orphan_pids.contains(&p.pid))
            .cloned()
            .collect();

        let history = &self.history;
        let metric = self.sort_metric;
        let window = self.sort_window;
        let column = self.sort_column;
        let ascending = self.sort_ascending;

        self.rows = match self.view_mode {
            ViewMode::Flat => {
                self.tree_has_children.clear();
                self.tree_ghosts.clear();
                let mut v = filtered;
                v.sort_by(|a, b| {
                    let ord = match column {
                        SortColumn::Metric => score(history, metric, window, a)
                            .partial_cmp(&score(history, metric, window, b))
                            .unwrap_or(std::cmp::Ordering::Equal),
                        SortColumn::Pid => a.pid.cmp(&b.pid),
                        SortColumn::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                        SortColumn::Src => {
                            gpu_source_label(a.gpu_source).cmp(gpu_source_label(b.gpu_source))
                        }
                    };
                    if ascending { ord } else { ord.reverse() }
                });
                v.into_iter().map(|p| (0, p)).collect()
            }
            ViewMode::Tree => {
                // Reconnect orphans to a recently-exited real parent when
                // possible (`ShortLivedWatcher` records each process's
                // ppid at the moment it started, so it survives the
                // parent exiting) instead of promoting every orphan
                // straight to a root.
                let recent_exits = self.short_lived.as_ref().map(|w| w.recent()).unwrap_or_default();
                let (augmented, ghosts) =
                    merge_recent_exits(&filtered, &recent_exits, DEFAULT_GHOST_MAX_DEPTH);
                self.tree_ghosts = ghosts;

                // build_tree always ranks descending by key; negate to flip to ascending.
                let sign = if ascending { -1.0 } else { 1.0 };
                let key = |p: &ProcessSample| sign * score(history, metric, window, p);
                let full = build_tree(&augmented, key, self.subtree_sort);

                self.tree_has_children.clear();
                for w in full.windows(2) {
                    let (d0, p0) = &w[0];
                    let (d1, _) = &w[1];
                    if *d1 > *d0 {
                        self.tree_has_children.insert(p0.pid);
                    }
                }

                // Drop every row whose ancestor chain passes through a
                // collapsed pid. `full` is DFS pre-order, so a collapsed
                // node's children are exactly the contiguous run right
                // after it with strictly greater depth.
                let collapsed = &self.collapsed;
                let mut out = Vec::with_capacity(full.len());
                let mut skip_below: Option<usize> = None;
                for (depth, p) in full {
                    if let Some(d) = skip_below {
                        if depth > d {
                            continue;
                        }
                        skip_below = None;
                    }
                    if collapsed.contains(&p.pid) {
                        skip_below = Some(depth);
                    }
                    out.push((depth, p));
                }
                out
            }
        };

        if let Some(pid) = self.selected_pid
            && !self.rows.iter().any(|(_, p)| p.pid == pid)
        {
            self.selected_pid = None;
        }
        if self.selected_pid.is_none() {
            self.selected_pid = self.rows.first().map(|(_, p)| p.pid);
        }
    }

    /// Sets `sort_column` to a literal (non-metric) column, toggling
    /// direction if it's already the active column.
    fn apply_column_sort(&mut self, column: SortColumn, default_ascending: bool) {
        if self.sort_column == column {
            self.sort_ascending = !self.sort_ascending;
        } else {
            self.sort_column = column;
            self.sort_ascending = default_ascending;
        }
        self.resort();
    }

    /// Sorts by a CPU/GPU metric (as clicked from a column header), toggling
    /// direction if it's already the active metric.
    fn apply_metric_sort(&mut self, metric: SortMetric) {
        if self.sort_column == SortColumn::Metric && self.sort_metric == metric {
            self.sort_ascending = !self.sort_ascending;
        } else {
            self.sort_column = SortColumn::Metric;
            self.sort_metric = metric;
            self.sort_ascending = false;
        }
        self.resort();
    }

    /// Moves `selected_pid` by `delta` rows (wrapping) within the current
    /// row order, for keyboard arrow navigation.
    fn move_selection(&mut self, delta: i32) {
        if self.rows.is_empty() {
            return;
        }
        let current = self
            .selected_pid
            .and_then(|pid| self.rows.iter().position(|(_, p)| p.pid == pid));
        let len = self.rows.len() as i32;
        let next = match current {
            Some(i) => (i as i32 + delta).rem_euclid(len),
            None => 0,
        };
        self.selected_pid = self.rows.get(next as usize).map(|(_, p)| p.pid);
        self.scroll_to_selected = true;
    }

    /// Toggles whether `pid`'s children are hidden in tree view.
    fn toggle_collapsed(&mut self, pid: u32) {
        if !self.collapsed.remove(&pid) {
            self.collapsed.insert(pid);
        }
        self.resort();
    }

    /// Closes every full-width "mode" panel (settings, search, exited,
    /// hardware) — call before opening one so only one is ever active.
    fn close_side_panels(&mut self) {
        self.settings_open = false;
        self.search_open = false;
        self.exited_open = false;
        self.hardware_open = false;
        self.health_open = false;
        self.files = None;
    }

    /// Builds the same clipboard-ready process summary used by both the
    /// detail panel's "copy info" button and the Process menu.
    fn copy_info_text(&self, pid: u32) -> Option<String> {
        let p = self.rows.iter().find(|(_, p)| p.pid == pid).map(|(_, p)| p)?;
        let (cpu_accum, gpu_accum) = self.history.accumulated(pid);
        Some(format!(
            "Process: {} (PID {})\n\
             Parent PID: {}{}\n\
             Owner: {}\n\
             Command line: {}\n\
             CPU: {:.1}% instant, {} accumulated (over {})\n\
             GPU: {:.1}% instant, {} accumulated  [source: {}]\n\
             Open handles: {}\n",
            p.name,
            p.pid,
            p.ppid.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string()),
            if self.orphan_pids.contains(&p.pid) {
                " (exited — this process is orphaned)"
            } else {
                ""
            },
            p.user.as_deref().unwrap_or("unknown"),
            p.command_line.as_deref().unwrap_or("unknown"),
            p.cpu_percent,
            format_core_time(cpu_accum),
            format_duration(self.history.accum_window()),
            p.gpu_percent,
            format_core_time(gpu_accum),
            gpu_source_label(p.gpu_source),
            rmon_core::handle_count(pid)
                .map(|n| n.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
        ))
    }
}

fn gpu_source_label(src: GpuSource) -> &'static str {
    match src {
        GpuSource::Nvml => "nvml",
        GpuSource::Pdh => "pdh",
        GpuSource::Unavailable => "-",
    }
}

impl eframe::App for RmonApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if self.last_tick.elapsed() >= TICK {
            self.tick();
            self.last_tick = Instant::now();
        }
        if let Some(fs) = self.files.as_mut() {
            fs.poll();
        }
        self.search.poll();
        if let Some(h) = self.health.as_mut() {
            h.poll();
        }

        // Redrawing (a full egui layout pass + wgpu present) is real,
        // continuous CPU/GPU cost — there's no reason to pay it 5x/sec
        // forever when the data underneath only changes once per TICK.
        // Only wake up faster than that while something is actually
        // animating (a files/search scan spinner); otherwise align the
        // repaint cadence with the sampling tick itself.
        let animating = self
            .files
            .as_ref()
            .is_some_and(|fs| matches!(fs.status, FilesStatus::Scanning(_)))
            || self.search.scanning()
            || self.health.as_ref().is_some_and(HealthState::scanning);
        let repaint_interval = if animating { Duration::from_millis(200) } else { TICK };
        ui.ctx().request_repaint_after(repaint_interval);

        if let Some(tray) = &self.tray {
            match tray.poll() {
                Some(TrayAction::Show) => {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Focus);
                }
                Some(TrayAction::Quit) => {
                    self.really_quit = true;
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
                None => {}
            }
        }
        if self.tray.is_some()
            && !self.really_quit
            && ui.input(|i| i.viewport().close_requested())
        {
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }

        if self.files.is_none() && ui.memory(|mem| mem.focused()).is_none() {
            let (up, down) = ui.input(|i| {
                (
                    i.key_pressed(egui::Key::ArrowUp),
                    i.key_pressed(egui::Key::ArrowDown),
                )
            });
            if up {
                self.move_selection(-1);
            } else if down {
                self.move_selection(1);
            }
        }

        egui::Panel::top("header").show(ui, |ui| {
            egui::MenuBar::new().ui(ui, |ui| {
                ui.menu_button("App", |ui| {
                    if ui.button("⚙ Settings").clicked() {
                        self.close_side_panels();
                        self.settings_open = true;
                        ui.close();
                    }
                    if ui.button("🔎 Search all processes").clicked() {
                        self.close_side_panels();
                        self.search_open = true;
                        ui.close();
                    }
                    if ui.button("⏱ Recently exited").clicked() {
                        self.close_side_panels();
                        self.exited_open = true;
                        ui.close();
                    }
                    if ui.button("🌡 Hardware sensors").clicked() {
                        self.close_side_panels();
                        self.hardware_open = true;
                        ui.close();
                    }
                    if ui.button("🩺 Hardware health").clicked() {
                        self.close_side_panels();
                        self.health_open = true;
                        if self.health.is_none() {
                            self.health =
                                Some(HealthState::start(DEFAULT_WHEA_LOOKBACK_DAYS, DEFAULT_WHEA_MAX_EVENTS));
                        }
                        ui.close();
                    }
                    ui.separator();
                    if !rmon_core::elevate::is_elevated() && ui.button("Restart as Administrator").clicked() {
                        match rmon_core::elevate::restart_elevated() {
                            Ok(()) => {
                                self.elevation_error = None;
                                self.really_quit = true;
                                ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                            }
                            Err(e) => self.elevation_error = Some(format!("{e:#}")),
                        }
                        ui.close();
                    }
                    ui.separator();
                    if ui.button("Quit").clicked() {
                        self.really_quit = true;
                        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                        ui.close();
                    }
                });
                ui.menu_button("Process", |ui| {
                    let pid = self.selected_pid;
                    if ui
                        .add_enabled(pid.is_some(), egui::Button::new("📂 Open files"))
                        .clicked()
                        && let Some(pid) = pid
                    {
                        self.files = Some(FilesState::start(pid));
                        ui.close();
                    }
                    if ui
                        .add_enabled(pid.is_some(), egui::Button::new("📋 Copy info"))
                        .clicked()
                        && let Some(pid) = pid
                        && let Some(text) = self.copy_info_text(pid)
                    {
                        ui.ctx().copy_text(text);
                        ui.close();
                    }
                    if ui
                        .add_enabled(
                            pid.is_some(),
                            egui::Button::new(
                                egui::RichText::new("⛔ Kill process")
                                    .color(egui::Color32::from_rgb(235, 87, 87)),
                            ),
                        )
                        .clicked()
                        && let Some(pid) = pid
                    {
                        match rmon_core::kill_process(pid) {
                            Ok(()) => {
                                self.kill_error = None;
                                self.selected_pid = None;
                            }
                            Err(e) => self.kill_error = Some(format!("{e:#}")),
                        }
                        ui.close();
                    }
                });
                ui.add_space(12.0);
                ui.heading("rMon");
                ui.weak("live process CPU/GPU monitor");
                if !self.has_gpu_source {
                    ui.colored_label(egui::Color32::from_rgb(220, 120, 0), "no GPU data source found");
                }
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let mut changed = false;
                ui.label("view:");
                changed |= ui.selectable_value(&mut self.view_mode, ViewMode::Flat, "flat").changed();
                changed |= ui.selectable_value(&mut self.view_mode, ViewMode::Tree, "tree").changed();
                if self.view_mode == ViewMode::Tree {
                    changed |= ui.checkbox(&mut self.subtree_sort, "rank by subtree total").changed();
                }
                ui.separator();
                ui.label("sort:");
                let mut metric_changed = false;
                metric_changed |= ui.selectable_value(&mut self.sort_metric, SortMetric::Total, "CPU+GPU").changed();
                metric_changed |= ui.selectable_value(&mut self.sort_metric, SortMetric::Cpu, "CPU%").changed();
                metric_changed |= ui.selectable_value(&mut self.sort_metric, SortMetric::Gpu, "GPU%").changed();
                metric_changed |= ui.selectable_value(&mut self.sort_window, SortWindow::Instant, "instant").changed();
                metric_changed |= ui.selectable_value(&mut self.sort_window, SortWindow::Accumulated, "accumulated (24h)").changed();
                if metric_changed {
                    self.sort_column = SortColumn::Metric;
                }
                changed |= metric_changed;
                ui.separator();
                ui.label("search:");
                changed |= ui.text_edit_singleline(&mut self.filter).changed();
                ui.separator();
                changed |= ui
                    .checkbox(&mut self.orphans_only, "orphans only")
                    .on_hover_text("show only processes whose parent has already exited")
                    .changed();
                if changed {
                    self.resort();
                }
            });
            ui.horizontal(|ui| {
                thermal_line(ui, &self.system);
                ui.separator();
                ui.weak(format!(
                    "accumulation window: {} of up to 24h",
                    format_duration(self.history.accum_window())
                ));
                if self.recording {
                    ui.separator();
                    ui.colored_label(egui::Color32::from_rgb(220, 90, 90), "● recording");
                }
            });
            ui.add_space(4.0);
        });

        egui::Panel::right("detail").default_size(640.0).show(ui, |ui| {
            self.draw_detail(ui);
        });

        egui::CentralPanel::default().show(ui, |ui| {
            if self.settings_open {
                self.draw_settings(ui);
            } else if self.search_open {
                self.draw_search_all(ui);
            } else if self.exited_open {
                self.draw_recent_exits(ui);
            } else if self.hardware_open {
                self.draw_hardware(ui);
            } else if self.health_open {
                self.draw_health(ui);
            } else {
                self.draw_table(ui);
            }
        });
    }
}

fn thermal_line(ui: &mut egui::Ui, system: &SystemMetrics) {
    let cpu_temp = match (system.cpu_temp_c, &system.cpu_temp_source) {
        (Some(t), Some(src)) => format!("{t:.0}°C ({src})"),
        (Some(t), None) => format!("{t:.0}°C"),
        (None, _) => "n/a".to_string(),
    };
    let cpu_clock = system
        .cpu_clock_ratio
        .map(|r| format!("{:.0}% clock", r * 100.0))
        .unwrap_or_else(|| "clock n/a".to_string());
    ui.label(format!("CPU: {cpu_temp} {cpu_clock}"));
    if system.cpu_throttled {
        ui.colored_label(egui::Color32::from_rgb(230, 180, 0), "possibly throttled");
    }
    for gpu in &system.gpus {
        ui.separator();
        let temp = gpu
            .temp_c
            .map(|t| format!("{t:.0}°C"))
            .unwrap_or_else(|| "n/a".to_string());
        ui.label(format!("{}: {temp}", gpu.name));
        if gpu.thermal_throttled {
            ui.colored_label(egui::Color32::RED, "THERMAL THROTTLE");
        }
    }
}

/// Draws a clickable, sort-aware column header label; returns `true` if clicked.
fn sort_header(ui: &mut egui::Ui, label: &str, active: bool, ascending: bool) -> bool {
    let text = if active {
        format!("{label} {}", if ascending { "^" } else { "v" })
    } else {
        label.to_string()
    };
    ui.add(
        egui::Label::new(egui::RichText::new(text).strong())
            .sense(egui::Sense::click())
            .selectable(false),
    )
    .clicked()
}

fn draw_sparkline(ui: &mut egui::Ui, values: &[f32], color: egui::Color32) {
    let size = egui::vec2(60.0, 16.0);
    let (rect, _response) = ui.allocate_exact_size(size, egui::Sense::hover());
    if values.len() < 2 {
        return;
    }
    let max = values.iter().cloned().fold(0.0f32, f32::max).max(1.0);
    let n = values.len();
    let points: Vec<egui::Pos2> = values
        .iter()
        .enumerate()
        .map(|(i, &v)| {
            let x = rect.left() + (i as f32 / (n - 1) as f32) * rect.width();
            let y = rect.bottom() - (v / max) * rect.height();
            egui::pos2(x, y)
        })
        .collect();
    ui.painter()
        .add(egui::Shape::line(points, egui::Stroke::new(1.5, color)));
}

impl RmonApp {
    fn draw_table(&mut self, ui: &mut egui::Ui) {
        use egui_extras::{Column, TableBuilder};

        let total_cpu: f32 = self.rows.iter().map(|(_, p)| p.cpu_percent).sum();
        let total_gpu: f32 = self.rows.iter().map(|(_, p)| p.gpu_percent).sum();
        ui.label(format!(
            "{} processes shown   total CPU {:.1}%   total GPU {:.1}%",
            self.rows.len(),
            total_cpu,
            total_gpu
        ));
        ui.add_space(4.0);

        let cur_column = self.sort_column;
        let cur_metric = self.sort_metric;
        let ascending = self.sort_ascending;
        let window = self.sort_window;
        let view_mode = self.view_mode;

        enum HeaderClick {
            Pid,
            Name,
            Cpu,
            Gpu,
            Src,
        }
        let mut header_click = None;
        let mut clicked_pid = None;
        let mut toggle_pid = None;

        let mut builder = TableBuilder::new(ui)
            .striped(true)
            .sense(egui::Sense::click())
            .column(Column::initial(70.0).range(45.0..=160.0).resizable(true))
            .column(Column::remainder().at_least(80.0).resizable(true))
            .column(Column::initial(140.0).range(90.0..=280.0).resizable(true))
            .column(Column::initial(140.0).range(90.0..=280.0).resizable(true))
            .column(Column::initial(50.0).range(35.0..=120.0).resizable(true));

        if self.scroll_to_selected
            && let Some(pid) = self.selected_pid
            && let Some(idx) = self.rows.iter().position(|(_, p)| p.pid == pid)
        {
            builder = builder.scroll_to_row(idx, Some(egui::Align::Center));
        }
        self.scroll_to_selected = false;

        builder
            .header(20.0, |mut header| {
                header.col(|ui| {
                    let active = cur_column == SortColumn::Pid;
                    if sort_header(ui, "PID", active, ascending) {
                        header_click = Some(HeaderClick::Pid);
                    }
                });
                header.col(|ui| {
                    let active = cur_column == SortColumn::Name;
                    if sort_header(ui, "Name", active, ascending) {
                        header_click = Some(HeaderClick::Name);
                    }
                });
                header.col(|ui| {
                    let active = cur_column == SortColumn::Metric && cur_metric == SortMetric::Cpu;
                    let label = if window == SortWindow::Accumulated { "CPU" } else { "CPU%" };
                    if sort_header(ui, label, active, ascending) {
                        header_click = Some(HeaderClick::Cpu);
                    }
                });
                header.col(|ui| {
                    let active = cur_column == SortColumn::Metric && cur_metric == SortMetric::Gpu;
                    let label = if window == SortWindow::Accumulated { "GPU" } else { "GPU%" };
                    if sort_header(ui, label, active, ascending) {
                        header_click = Some(HeaderClick::Gpu);
                    }
                });
                header.col(|ui| {
                    let active = cur_column == SortColumn::Src;
                    if sort_header(ui, "Src", active, ascending) {
                        header_click = Some(HeaderClick::Src);
                    }
                });
            })
            .body(|body| {
                let history = &self.history;
                let rows = &self.rows;
                let selected_pid = self.selected_pid;
                let has_children = &self.tree_has_children;
                let collapsed = &self.collapsed;
                let orphan_pids = &self.orphan_pids;
                let tree_ghosts = &self.tree_ghosts;
                body.rows(20.0, rows.len(), |mut row| {
                    let (depth, p) = &rows[row.index()];
                    let selected = selected_pid == Some(p.pid);
                    row.set_selected(selected);

                    row.col(|ui| {
                        ui.label(p.pid.to_string());
                    });
                    row.col(|ui| {
                        ui.horizontal(|ui| {
                            ui.add_space(*depth as f32 * 14.0);
                            if view_mode == ViewMode::Tree {
                                if has_children.contains(&p.pid) {
                                    let is_collapsed = collapsed.contains(&p.pid);
                                    let arrow = if is_collapsed { ">" } else { "v" };
                                    if ui
                                        .add(
                                            egui::Label::new(egui::RichText::new(arrow).weak())
                                                .sense(egui::Sense::click())
                                                .selectable(false),
                                        )
                                        .clicked()
                                    {
                                        toggle_pid = Some(p.pid);
                                    }
                                } else {
                                    ui.add_space(14.0);
                                }
                            }
                            if tree_ghosts.contains(&p.pid) {
                                ui.weak(&p.name).on_hover_text(
                                    "exited — reconstructed from ETW process tracking, \
                                     no CPU/GPU history was ever sampled for it",
                                );
                                ui.colored_label(egui::Color32::from_rgb(140, 140, 150), "👻 exited");
                            } else {
                                ui.label(&p.name);
                            }
                            if orphan_pids.contains(&p.pid) {
                                ui.colored_label(egui::Color32::from_rgb(230, 180, 0), "⚠ orphan")
                                    .on_hover_text("parent process has already exited");
                            }
                        });
                    });
                    row.col(|ui| {
                        let tail = history.tail_for_pid(p.pid, SPARK_POINTS);
                        ui.horizontal(|ui| {
                            let label = if window == SortWindow::Accumulated {
                                let (cpu_s, _) = history.accumulated(p.pid);
                                format_core_time(cpu_s)
                            } else {
                                format!("{:>5.1}", p.cpu_percent)
                            };
                            ui.label(label);
                            draw_sparkline(
                                ui,
                                &tail.iter().map(|(c, _)| *c).collect::<Vec<_>>(),
                                egui::Color32::from_rgb(90, 200, 90),
                            );
                        });
                    });
                    row.col(|ui| {
                        let tail = history.tail_for_pid(p.pid, SPARK_POINTS);
                        ui.horizontal(|ui| {
                            let label = if window == SortWindow::Accumulated {
                                let (_, gpu_s) = history.accumulated(p.pid);
                                format_core_time(gpu_s)
                            } else {
                                format!("{:>5.1}", p.gpu_percent)
                            };
                            ui.label(label);
                            draw_sparkline(
                                ui,
                                &tail.iter().map(|(_, g)| *g).collect::<Vec<_>>(),
                                egui::Color32::from_rgb(200, 90, 200),
                            );
                        });
                    });
                    row.col(|ui| {
                        ui.label(gpu_source_label(p.gpu_source));
                    });

                    if row.response().clicked() {
                        clicked_pid = Some(p.pid);
                    }
                });
            });

        if let Some(pid) = clicked_pid {
            self.selected_pid = Some(pid);
        }
        if let Some(pid) = toggle_pid {
            self.toggle_collapsed(pid);
        }

        match header_click {
            Some(HeaderClick::Pid) => self.apply_column_sort(SortColumn::Pid, true),
            Some(HeaderClick::Name) => self.apply_column_sort(SortColumn::Name, true),
            Some(HeaderClick::Src) => self.apply_column_sort(SortColumn::Src, true),
            Some(HeaderClick::Cpu) => self.apply_metric_sort(SortMetric::Cpu),
            Some(HeaderClick::Gpu) => self.apply_metric_sort(SortMetric::Gpu),
            None => {}
        }
    }

    fn draw_detail(&mut self, ui: &mut egui::Ui) {
        let Some(pid) = self.selected_pid else {
            ui.label("Select a process to see its history.");
            return;
        };
        let proc_info = self
            .rows
            .iter()
            .find(|(_, p)| p.pid == pid)
            .map(|(_, p)| p.clone());
        let name = proc_info
            .as_ref()
            .map(|p| p.name.clone())
            .unwrap_or_else(|| "?".to_string());
        ui.horizontal(|ui| {
            ui.heading(format!("{name} ({pid})"));
            if ui.button("📂 open files").clicked() {
                self.files = Some(FilesState::start(pid));
            }
            if ui.button("📋 copy info").clicked()
                && let Some(text) = self.copy_info_text(pid)
            {
                ui.ctx().copy_text(text);
            }
            if ui
                .add(egui::Button::new(
                    egui::RichText::new("⛔ kill process").color(egui::Color32::from_rgb(235, 87, 87)),
                ))
                .clicked()
            {
                match rmon_core::kill_process(pid) {
                    Ok(()) => {
                        self.kill_error = None;
                        self.selected_pid = None;
                    }
                    Err(e) => self.kill_error = Some(format!("{e:#}")),
                }
            }
        });
        if let Some(err) = &self.kill_error {
            ui.colored_label(egui::Color32::RED, err);
        }

        ui.horizontal(|ui| {
            ui.weak("owner:");
            ui.label(
                proc_info
                    .as_ref()
                    .and_then(|p| p.user.clone())
                    .unwrap_or_else(|| "—".to_string()),
            );
            ui.add_space(16.0);
            ui.weak("open handles:");
            ui.label(
                rmon_core::handle_count(pid)
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "—".to_string()),
            );
        });
        if let Some(cmd) = proc_info.as_ref().and_then(|p| p.command_line.clone()) {
            ui.weak("command line:");
            ui.label(egui::RichText::new(cmd).monospace().small());
        }
        ui.add_space(4.0);
        ui.separator();

        let series = self.history.series_for_pid(pid);
        let now_line = match (series.last(), proc_info.as_ref()) {
            (Some(last), Some(latest)) => {
                let t0 = series[0].0;
                Some(format!(
                    "now: CPU {:.1}%  GPU {:.1}%   ({} samples over {:.0}s)",
                    latest.cpu_percent,
                    latest.gpu_percent,
                    series.len(),
                    (last.0 - t0).num_milliseconds() as f64 / 1000.0
                ))
            }
            _ => None,
        };
        let (cpu_accum, gpu_accum) = self.history.accumulated(pid);
        let accum_line = format!(
            "accumulated: CPU {} · GPU {}  (over {})",
            format_core_time(cpu_accum),
            format_core_time(gpu_accum),
            format_duration(self.history.accum_window()),
        );

        ui.horizontal_top(|ui| {
            ui.allocate_ui(egui::vec2(260.0, ui.available_height()), |ui| {
                ui.set_max_width(260.0);
                ui.vertical(|ui| {
                    if let Some(line) = &now_line {
                        ui.label(line);
                    }
                    ui.label(accum_line);
                    ui.add_space(6.0);
                    ui.separator();
                    ui.label(egui::RichText::new("Open files").strong());

                    match self.files.as_mut().filter(|fs| fs.pid == pid) {
                        Some(fs) => {
                            match &fs.status {
                                FilesStatus::Scanning(_) => {
                                    ui.horizontal(|ui| {
                                        ui.spinner();
                                        ui.weak("scanning...");
                                    });
                                }
                                FilesStatus::Done(scan) => {
                                    ui.weak(format!(
                                        "{} file(s)   ({} handles, {} timed out)",
                                        scan.paths.len(),
                                        scan.handles_seen,
                                        scan.timed_out
                                    ));
                                }
                                FilesStatus::Error(e) => {
                                    ui.colored_label(egui::Color32::RED, format!("error: {e}"));
                                }
                            }
                            ui.text_edit_singleline(&mut fs.search);
                            let paths = fs.filtered_paths();
                            let row_height = ui.text_style_height(&egui::TextStyle::Body);
                            egui::ScrollArea::vertical()
                                .id_salt("detail-open-files")
                                .max_height(220.0)
                                .auto_shrink([false, false])
                                .show_rows(ui, row_height, paths.len(), |ui, range| {
                                    for i in range {
                                        ui.label(egui::RichText::new(paths[i]).small());
                                    }
                                });
                        }
                        None => {
                            ui.weak("click \"open files\" above to scan");
                        }
                    }

                    ui.add_space(6.0);
                    ui.separator();
                    ui.label(egui::RichText::new("Listening ports").strong());
                    let ports = listening_ports_for(&self.ports, pid);
                    ui.weak(format!("{} listening", ports.len()));
                    let row_height = ui.text_style_height(&egui::TextStyle::Body);
                    egui::ScrollArea::vertical()
                        .id_salt("detail-ports")
                        .max_height(160.0)
                        .auto_shrink([false, false])
                        .show_rows(ui, row_height, ports.len(), |ui, range| {
                            for i in range {
                                let p = &ports[i];
                                ui.label(
                                    egui::RichText::new(format!(
                                        "{:<3} {}:{}",
                                        p.protocol.as_str(),
                                        p.local_addr,
                                        p.local_port
                                    ))
                                    .small()
                                    .monospace(),
                                );
                            }
                        });
                });
            });

            ui.separator();

            ui.vertical(|ui| {
                if series.is_empty() {
                    ui.label("No history yet.");
                    return;
                }
                let t0 = series[0].0;
                let cpu_points: Vec<[f64; 2]> = series
                    .iter()
                    .map(|(t, cpu, _)| [(*t - t0).num_milliseconds() as f64 / 1000.0, *cpu as f64])
                    .collect();
                let gpu_points: Vec<[f64; 2]> = series
                    .iter()
                    .map(|(t, _, gpu)| [(*t - t0).num_milliseconds() as f64 / 1000.0, *gpu as f64])
                    .collect();

                Plot::new(format!("history-{pid}"))
                    .legend(Legend::default())
                    .height(320.0)
                    .include_y(0.0)
                    .show(ui, |plot_ui| {
                        plot_ui.line(Line::new("CPU%", PlotPoints::new(cpu_points)));
                        plot_ui.line(Line::new("GPU%", PlotPoints::new(gpu_points)));
                    });
            });
        });
    }

    /// Substring search for open files and listening ports across *every*
    /// process at once, not just the selected one. Ports are answered
    /// instantly from the already-cached `self.ports`; open files require
    /// an explicit scan (kicked off with the button below) since it means
    /// walking every scannable process's kernel handle table.
    fn draw_search_all(&mut self, ui: &mut egui::Ui) {
        let names: HashMap<u32, String> = self
            .rows
            .iter()
            .map(|(_, p)| (p.pid, p.name.clone()))
            .collect();

        ui.horizontal(|ui| {
            if ui.button("← back").clicked() {
                self.search_open = false;
            }
            ui.heading("Search all processes");
        });
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            ui.label("query:");
            ui.text_edit_singleline(&mut self.search.query);
        });
        ui.horizontal(|ui| {
            let scanning = self.search.scanning();
            if ui
                .add_enabled(!scanning, egui::Button::new("🔍 scan open files (all processes)"))
                .on_hover_text(
                    "walks every process's kernel handle table — may need Administrator \
                     to see other users' processes, and can take a few seconds for \
                     processes with very large handle tables",
                )
                .clicked()
            {
                let pids: Vec<u32> = self.rows.iter().map(|(_, p)| p.pid).collect();
                self.search.start_scan(pids);
            }
            if scanning {
                ui.spinner();
                ui.weak(format!("{}/{} processes scanned", self.search.scanned, self.search.total));
            } else if self.search.total > 0 {
                ui.weak(format!("{} processes scanned", self.search.total));
            }
        });

        let query = self.search.query.to_lowercase();

        ui.add_space(8.0);
        ui.label(egui::RichText::new("Matching ports").strong());
        if query.is_empty() {
            ui.weak("type a query above (PID, process name, address, or port) — showing listening ports only until you do");
        }
        egui::ScrollArea::vertical()
            .id_salt("search-ports")
            .max_height(220.0)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for p in &self.ports {
                    let name = names.get(&p.pid).map(|s| s.as_str()).unwrap_or("?");
                    let haystack = format!(
                        "{} {} {} {}:{}",
                        p.pid,
                        name,
                        p.protocol.as_str(),
                        p.local_addr,
                        p.local_port
                    )
                    .to_lowercase();
                    if !query.is_empty() {
                        if !haystack.contains(&query) {
                            continue;
                        }
                    } else if !p.is_listening() {
                        continue;
                    }
                    ui.label(egui::RichText::new(format!(
                        "{:<3} {}:{:<6} pid {} ({})  {}",
                        p.protocol.as_str(),
                        p.local_addr,
                        p.local_port,
                        p.pid,
                        name,
                        p.state.map(|s| s.as_str()).unwrap_or("-"),
                    )).small().monospace());
                }
            });

        ui.add_space(8.0);
        ui.label(egui::RichText::new("Matching open files").strong());
        if self.search.files.is_empty() && !self.search.scanning() {
            ui.weak("click \"scan open files\" above to search file paths across all processes");
        }
        egui::ScrollArea::vertical()
            .id_salt("search-files")
            .max_height(300.0)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for entry in &self.search.files {
                    let Ok(scan) = &entry.scan else { continue };
                    let name = names.get(&entry.pid).map(|s| s.as_str()).unwrap_or("?");
                    for path in &scan.paths {
                        if !query.is_empty() && !path.to_lowercase().contains(&query) {
                            continue;
                        }
                        ui.label(
                            egui::RichText::new(format!("[{} ({})] {path}", entry.pid, name)).small(),
                        );
                    }
                }
            });
    }

    /// Processes that started and fully exited between polling ticks, so
    /// `Sampler` never saw them — caught instead via an ETW subscription
    /// to process start/stop events (see `rmon_core::proc_events`).
    /// Durations are wall-clock only; these events don't carry CPU time.
    fn draw_recent_exits(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("← back").clicked() {
                self.exited_open = false;
            }
            ui.heading("Recently exited processes");
        });
        ui.add_space(8.0);

        let Some(watcher) = &self.short_lived else {
            ui.colored_label(
                egui::Color32::from_rgb(220, 120, 0),
                "unavailable — this needs Administrator elevation (kernel ETW provider).",
            );
            if let Some(err) = &self.short_lived_error {
                ui.weak(err);
            }
            if !rmon_core::elevate::is_elevated() && ui.button("Restart as Administrator").clicked()
            {
                match rmon_core::elevate::restart_elevated() {
                    Ok(()) => {
                        self.elevation_error = None;
                        self.really_quit = true;
                        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                    Err(e) => self.elevation_error = Some(format!("{e:#}")),
                }
            }
            return;
        };

        let recent = watcher.recent();
        ui.weak(format!(
            "{} process(es) caught since rMon started — wall-clock duration, not CPU time",
            recent.len()
        ));
        ui.add_space(4.0);

        egui::ScrollArea::vertical()
            .id_salt("recent-exits")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for e in &recent {
                    let exit_code = e
                        .exit_code
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "?".to_string());
                    ui.label(
                        egui::RichText::new(format!(
                            "{}  pid {}  ppid {}  ran {}ms  exit {}  started {}",
                            e.name,
                            e.pid,
                            e.ppid.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string()),
                            e.duration_ms,
                            exit_code,
                            e.start_time.format("%H:%M:%S"),
                        ))
                        .small()
                        .monospace(),
                    );
                }
            });
    }

    /// Full hardware sensor tree, mirroring HWiNFO's own Sensors window
    /// (grouped by device/category) — sourced from whichever of HWiNFO's
    /// export mechanisms is available (see `rmon_core::read_all_sensors`).
    fn draw_hardware(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("← back").clicked() {
                self.hardware_open = false;
            }
            ui.heading("Hardware sensors");
        });
        ui.add_space(8.0);

        let groups = rmon_core::read_all_sensors();
        if groups.is_empty() {
            ui.colored_label(
                egui::Color32::from_rgb(220, 120, 0),
                "No sensor data found — this needs HWiNFO running with either \"Support of Value \
                 Sensors Bank\" or \"Shared Memory Support\" enabled (HWiNFO's Settings, gear icon \
                 in its Sensors window). Shared Memory Support exposes every sensor; the Value \
                 Sensors Bank only mirrors whatever's in HWiNFO's own tray/summary list.",
            );
            return;
        }

        egui::ScrollArea::vertical()
            .id_salt("hardware-sensors")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for group in &groups {
                    egui::CollapsingHeader::new(egui::RichText::new(&group.name).strong())
                        .default_open(true)
                        .show(ui, |ui| {
                            for reading in &group.readings {
                                ui.horizontal(|ui| {
                                    ui.label(&reading.label);
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            ui.monospace(&reading.value);
                                        },
                                    );
                                });
                            }
                        });
                }
            });
    }

    /// WHEA event log entries, BIOS version, and CPU microcode revision —
    /// facts to weigh alongside other evidence (new instability under
    /// load), not a degradation diagnosis in themselves. The scan runs on
    /// a background thread (see `HealthState`) since it's slow.
    fn draw_health(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("← back").clicked() {
                self.health_open = false;
            }
            ui.heading("Hardware health");
            let scanning = self.health.as_ref().is_some_and(HealthState::scanning);
            if ui.add_enabled(!scanning, egui::Button::new("🔄 rescan")).clicked() {
                self.health = Some(HealthState::start(DEFAULT_WHEA_LOOKBACK_DAYS, DEFAULT_WHEA_MAX_EVENTS));
            }
        });
        ui.add_space(8.0);

        let Some(health) = &self.health else {
            ui.weak("click \"rescan\" above to check");
            return;
        };
        let HealthStatus::Done(report) = &health.status else {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.weak(
                    "querying the System event log for WHEA entries via WMI — this is a \
                     slow, unindexed query and can take up to ~30 seconds, more on a system \
                     that logs frequently",
                );
            });
            return;
        };

        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.weak("BIOS:");
                ui.label(format!(
                    "{} {} (released {})",
                    report.bios_manufacturer.as_deref().unwrap_or("unknown"),
                    report.bios_version.as_deref().unwrap_or("unknown"),
                    report.bios_release_date.as_deref().unwrap_or("unknown"),
                ));
            });
            ui.horizontal(|ui| {
                ui.weak("CPU microcode revision:");
                ui.monospace(report.microcode_revision.as_deref().unwrap_or("unknown"));
            });
            ui.weak(
                "Cross-reference these against your motherboard/CPU vendor's own advisories \
                 — rMon doesn't know which versions fix which errata.",
            );
        });

        ui.add_space(8.0);
        match &report.whea_query_error {
            Some(e) => {
                ui.colored_label(egui::Color32::RED, format!("WHEA event query failed: {e}"));
            }
            None => {
                ui.label(format!(
                    "{} WHEA event(s) shown, {} error(s), {} warning(s)",
                    report.whea_events.len(),
                    report.whea_error_count,
                    report.whea_warning_count,
                ));
                ui.weak(
                    "A WHEA entry (especially Error-level) is real hardware-reported evidence, \
                     but by itself doesn't confirm degradation — weigh it alongside new \
                     instability under load.",
                );
                ui.add_space(4.0);
                egui::ScrollArea::vertical()
                    .id_salt("whea-events")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for e in &report.whea_events {
                            let color = match e.level.as_str() {
                                "Error" => egui::Color32::from_rgb(235, 87, 87),
                                "Warning" => egui::Color32::from_rgb(230, 180, 0),
                                _ => ui.visuals().text_color(),
                            };
                            ui.horizontal(|ui| {
                                ui.monospace(e.time.format("%Y-%m-%d %H:%M:%S").to_string());
                                ui.colored_label(color, format!("[{}]", e.level));
                                ui.weak(format!("id={} rec={}", e.event_id, e.record_number));
                            });
                            ui.label(egui::RichText::new(&e.message).small());
                            ui.separator();
                        }
                    });
            }
        }
    }

    fn draw_settings(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("← back").clicked() {
                self.settings_open = false;
            }
            ui.heading("Settings");
        });
        ui.add_space(8.0);

        ui.group(|ui| {
            ui.label(egui::RichText::new("Recording").strong());
            ui.add_space(4.0);
            ui.checkbox(&mut self.recording, "record to SQLite");
            ui.horizontal(|ui| {
                ui.label("database path:");
                ui.add_enabled(
                    !self.recording,
                    egui::TextEdit::singleline(&mut self.db_path).desired_width(280.0),
                );
            });
            if let Some(err) = &self.record_error {
                ui.colored_label(egui::Color32::RED, err);
            }
        });

        ui.add_space(8.0);

        ui.group(|ui| {
            ui.label(egui::RichText::new("Startup").strong());
            ui.add_space(4.0);
            if ui.checkbox(&mut self.autostart_enabled, "start with Windows").changed() {
                if let Err(e) = autostart::set_enabled(self.autostart_enabled) {
                    self.autostart_enabled = !self.autostart_enabled;
                    self.autostart_error = Some(format!("autostart failed: {e}"));
                } else {
                    self.autostart_error = None;
                }
            }
            if let Some(err) = &self.autostart_error {
                ui.colored_label(egui::Color32::RED, err);
            }
        });

        ui.add_space(8.0);

        ui.group(|ui| {
            ui.label(egui::RichText::new("Elevation").strong());
            ui.add_space(4.0);
            if rmon_core::elevate::is_elevated() {
                ui.label("rMon is running as Administrator.");
            } else {
                ui.label(
                    "rMon is not elevated — killing or inspecting other users' processes may fail.",
                );
                if ui.button("Restart as Administrator").clicked() {
                    match rmon_core::elevate::restart_elevated() {
                        Ok(()) => {
                            self.elevation_error = None;
                            self.really_quit = true;
                            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                        Err(e) => self.elevation_error = Some(format!("{e:#}")),
                    }
                }
            }
            if let Some(err) = &self.elevation_error {
                ui.colored_label(egui::Color32::RED, err);
            }
            ui.add_space(4.0);
            if self.short_lived.is_some() {
                ui.label("Short-lived process tracking (⏱ exited) is active.");
            } else {
                ui.weak("Short-lived process tracking (⏱ exited) needs Administrator.");
            }
        });

        ui.add_space(8.0);

        ui.group(|ui| {
            ui.label(egui::RichText::new("History").strong());
            ui.add_space(4.0);
            ui.label(format!(
                "accumulation retains up to {}",
                format_duration(self.history.accum_retain())
            ));
        });
    }
}

/// A dark, muted, high-contrast theme in the vein of linear.app: near-black
/// backgrounds, subtle borders instead of heavy chrome, an indigo accent,
/// and slightly rounded corners throughout.
fn apply_linear_theme(ctx: &egui::Context) {
    let bg0 = egui::Color32::from_rgb(13, 14, 17);
    let bg1 = egui::Color32::from_rgb(19, 20, 24);
    let bg2 = egui::Color32::from_rgb(28, 29, 34);
    let bg3 = egui::Color32::from_rgb(40, 42, 49);
    let border = egui::Color32::from_rgb(45, 47, 54);
    let text = egui::Color32::from_rgb(237, 237, 240);
    let text_weak = egui::Color32::from_rgb(139, 141, 152);
    let accent = egui::Color32::from_rgb(94, 106, 210);
    let accent_hover = egui::Color32::from_rgb(116, 128, 226);

    let widget = |bg: egui::Color32, fg: egui::Color32, stroke: egui::Color32| egui::style::WidgetVisuals {
        bg_fill: bg,
        weak_bg_fill: bg,
        bg_stroke: egui::Stroke::new(1.0, stroke),
        corner_radius: egui::CornerRadius::same(6),
        fg_stroke: egui::Stroke::new(1.0, fg),
        expansion: 0.0,
    };

    ctx.set_theme(egui::ThemePreference::Dark);

    let mut visuals = egui::Visuals::dark();
    visuals.override_text_color = Some(text);
    visuals.weak_text_color = Some(text_weak);
    visuals.panel_fill = bg0;
    visuals.window_fill = bg1;
    visuals.extreme_bg_color = bg0;
    visuals.faint_bg_color = bg1;
    visuals.code_bg_color = bg2;
    visuals.hyperlink_color = accent;
    visuals.selection.bg_fill = egui::Color32::from_rgba_unmultiplied(94, 106, 210, 60);
    visuals.selection.stroke = egui::Stroke::new(1.0, accent_hover);
    visuals.window_stroke = egui::Stroke::new(1.0, border);
    visuals.window_corner_radius = egui::CornerRadius::same(10);
    visuals.menu_corner_radius = egui::CornerRadius::same(8);
    visuals.widgets.noninteractive = widget(bg0, text_weak, border);
    visuals.widgets.inactive = widget(bg2, text, border);
    visuals.widgets.hovered = widget(bg3, text, accent);
    visuals.widgets.active = widget(accent, egui::Color32::WHITE, accent);
    visuals.widgets.open = widget(bg2, text, accent);
    ctx.set_visuals(visuals);

    ctx.all_styles_mut(|style| {
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        style.spacing.button_padding = egui::vec2(10.0, 5.0);
        style.spacing.window_margin = egui::Margin::same(12);
        style.spacing.indent = 16.0;
    });
}

fn main() -> eframe::Result {
    // Held for the process lifetime so buffered Sentry/rustrak events flush on exit.
    let _sentry = rmon_core::observability::init_sentry();

    // Passed by the autostart Run-key entry so a login launch doesn't pop
    // the window up; it starts tucked away in the tray instead.
    let start_minimized = std::env::args().any(|a| a == "--minimized");

    let icon_size = 64;
    let icon = egui::IconData {
        rgba: icon::rgba(icon_size),
        width: icon_size,
        height: icon_size,
    };

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 700.0])
            .with_icon(icon)
            .with_visible(!start_minimized),
        ..Default::default()
    };
    eframe::run_native(
        "rMon",
        options,
        Box::new(|cc| {
            apply_linear_theme(&cc.egui_ctx);
            Ok(Box::new(RmonApp::new()))
        }),
    )
}
