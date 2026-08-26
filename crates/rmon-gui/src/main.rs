#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod about;
mod autostart;
mod credentials;
mod icon;
mod sampling;
mod tray;

use std::collections::{HashMap, HashSet};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use credentials::CredentialsEditor;
use eframe::egui;
use egui_plot::{Legend, Line, Plot, PlotPoints};
use rmon_agent::{AgentConfig, AgentEvent, PendingAction, ThrottleSummary, ToolContext};
use rmon_core::{
    AllFilesEntry, DEFAULT_GHOST_MAX_DEPTH, DEFAULT_SCAN_WORKERS, DEFAULT_WHEA_LOOKBACK_DAYS,
    DEFAULT_WHEA_MAX_EVENTS, GpuSource, HardwareHealthReport, InstalledProgram,
    InstalledProgramsScan, OpenFilesScan, PortEntry, ProcessSample, ProgramAttribution,
    ProgramRelationship, RollingHistory, ShortLivedWatcher, Store, SystemMetrics, ThrottleHistory,
    attribute_processes, build_tree, check_hardware_health, list_installed_programs,
    list_open_files, list_open_files_many, listening_ports_for, merge_recent_exits,
    process_attention_reasons, program_relationships,
};
use sampling::{BackgroundSampler, IntervalChoice, Tick};
use tray::{Tray, TrayAction};

const RETAIN: Duration = Duration::from_secs(300);
/// Status colors, shared by the thermal line and the throttle strip so the
/// same condition never gets two different colors in the same header.
const OK_COLOR: egui::Color32 = egui::Color32::from_rgb(96, 172, 122);
const WARN_COLOR: egui::Color32 = egui::Color32::from_rgb(230, 180, 0);
const BAD_COLOR: egui::Color32 = egui::Color32::from_rgb(235, 87, 87);
/// Deliberately grey rather than a dim green: "we could not tell" must not
/// be mistakable for "fine".
const UNKNOWN_COLOR: egui::Color32 = egui::Color32::from_rgb(88, 90, 100);
const SPARK_POINTS: usize = 30;
/// How often leak/idle trends are recomputed. Their inputs are bucketed at
/// one point per minute and their verdicts need half an hour of history
/// before they fire at all, so anything faster is wasted work.
const TRENDS_INTERVAL: Duration = Duration::from_secs(30);
/// Program ownership walks executable paths and parent chains. It is cheap
/// after matcher preprocessing, but does not need the one-second precision
/// of CPU sampling; keeping it slower matters on machines with thousands of
/// processes and hundreds of uninstall entries.
const PROGRAM_ACTIVITY_INTERVAL: Duration = Duration::from_secs(3);

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

fn score(
    history: &RollingHistory,
    metric: SortMetric,
    window: SortWindow,
    p: &ProcessSample,
) -> f32 {
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

fn format_bytes(b: u64) -> String {
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    let b = b as f64;
    if b >= GIB {
        format!("{:.2} GiB", b / GIB)
    } else {
        format!("{:.0} MiB", b / MIB)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ViewMode {
    Flat,
    Tree,
}

/// Which view the left column is showing.
///
/// Replaces the older one-boolean-per-panel scheme, where every panel
/// carried its own back button and the only route between two of them ran
/// through the process table. Every view is now one click from every
/// other, and there is no hidden navigation state to get stranded in.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Processes,
    Programs,
    Suspects,
    Analyze,
    Sensors,
    Health,
    Exited,
    Search,
    WhatsNew,
    Settings,
}

impl Tab {
    /// Strip order, left to right: the live table first, then the views
    /// that explain why it looks the way it does, then the tools, then
    /// settings.
    const ALL: [Tab; 10] = [
        Tab::Processes,
        Tab::Programs,
        Tab::Suspects,
        Tab::Analyze,
        Tab::Sensors,
        Tab::Health,
        Tab::Exited,
        Tab::Search,
        Tab::WhatsNew,
        Tab::Settings,
    ];

    /// Lowercase to match the existing toolbar controls ("flat", "tree",
    /// "instant") rather than the menu bar's title case.
    fn label(self) -> &'static str {
        match self {
            Tab::Processes => "processes",
            Tab::Programs => "programs",
            Tab::Suspects => "suspects",
            Tab::Analyze => "analyze",
            Tab::Sensors => "sensors",
            Tab::Health => "health",
            Tab::Exited => "exited",
            Tab::Search => "search",
            Tab::WhatsNew => "what's new",
            Tab::Settings => "settings",
        }
    }

    fn hover(self) -> &'static str {
        match self {
            Tab::Processes => "live process table",
            Tab::Programs => {
                "installed software, live resource use, launched children, and removal review"
            }
            Tab::Suspects => {
                "processes with a possible handle/memory leak or sustained background CPU"
            }
            Tab::Analyze => "ask an LLM to explain what is making this machine slow",
            Tab::Sensors => "every hardware sensor reading rMon can see",
            Tab::Health => "WHEA hardware error events, BIOS version, CPU microcode revision",
            Tab::Exited => {
                "processes that started and exited between sampling ticks (needs Administrator)"
            }
            Tab::Search => "search open files and listening ports across every process",
            Tab::WhatsNew => "changes included in this build",
            Tab::Settings => "recording, autostart, elevation",
        }
    }
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

/// The WHEA query is fast now (`EvtQuery` against the System channel's
/// per-provider index, tens of milliseconds), but it is still I/O and a
/// cold channel carries no guarantee, so like `FilesState` it runs on a
/// background thread rather than blocking the UI.
struct HealthState {
    status: HealthStatus,
}

impl HealthState {
    fn start(days: i64, max_events: usize) -> Self {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(check_hardware_health(days, max_events));
        });
        Self {
            status: HealthStatus::Scanning(rx),
        }
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

/// One line of the analysis transcript.
enum AnalyzeLine {
    Question(String),
    Step(String),
    Answer(String),
    Error(String),
}

/// State for the analyze tab.
///
/// The agent runs on a background thread and reports through a channel:
/// a request involves network round-trips measured in seconds, and the
/// sampling tick shares this thread.
struct AnalyzeState {
    /// Why the agent can't run, or what it will run as.
    availability: std::result::Result<String, String>,
    /// The key, once a Windows Hello gesture has released it this session.
    ///
    /// Held in memory rather than re-prompting per question: the key is
    /// resolved on every turn, and a gesture per question would make the tab
    /// unusable. The gesture still gates the *process* getting the key at
    /// all, and it is gone when rMon exits.
    unlocked: Option<String>,
    /// `Some` while a gesture is pending on a worker thread.
    unlock_rx: Option<mpsc::Receiver<std::result::Result<String, String>>>,
    input: String,
    lines: Vec<AnalyzeLine>,
    /// `Some` while a turn is in flight.
    rx: Option<mpsc::Receiver<AgentUpdate>>,
    /// Kill proposals awaiting a decision.
    pending: Vec<PendingAction>,
}

/// What the worker thread sends back.
enum AgentUpdate {
    Event(AgentEvent),
    Done,
}

impl AnalyzeState {
    fn new() -> Self {
        Self {
            availability: AgentConfig::describe_availability(None),
            unlocked: None,
            unlock_rx: None,
            input: String::new(),
            lines: Vec::new(),
            rx: None,
            pending: Vec::new(),
        }
    }

    fn running(&self) -> bool {
        self.rx.is_some()
    }

    /// Re-reads the configuration after the user changed it, so a saved key
    /// takes effect without restarting rMon.
    fn refresh_availability(&mut self) {
        self.availability = AgentConfig::describe_availability(self.unlocked.as_deref());
    }

    /// Asks for a Windows Hello gesture on a worker thread.
    ///
    /// The prompt blocks until the user responds, so it cannot run on the UI
    /// thread — that would freeze the window, including the sampling tick.
    fn start_unlock(&mut self) {
        if self.unlock_rx.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        self.unlock_rx = Some(rx);
        std::thread::spawn(move || {
            let result = rmon_core::config::load()
                .map_err(|e| format!("{e:#}"))
                .and_then(|s| s.llm.unlock_with_hello().map_err(|e| format!("{e:#}")));
            let _ = tx.send(result);
        });
    }

    /// Whether a gesture is pending.
    fn unlocking(&self) -> bool {
        self.unlock_rx.is_some()
    }

    /// Collects a finished gesture.
    fn poll_unlock(&mut self) {
        let Some(rx) = &self.unlock_rx else { return };
        match rx.try_recv() {
            Ok(Ok(key)) => {
                self.unlocked = Some(key);
                self.unlock_rx = None;
                self.refresh_availability();
            }
            Ok(Err(e)) => {
                self.lines.push(AnalyzeLine::Error(e));
                self.unlock_rx = None;
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => self.unlock_rx = None,
        }
    }

    fn poll(&mut self) {
        let Some(rx) = &self.rx else { return };
        loop {
            match rx.try_recv() {
                Ok(AgentUpdate::Event(e)) => match e {
                    AgentEvent::ToolCall { name, arguments } => {
                        let args = arguments.trim();
                        let shown = if args.is_empty() || args == "{}" {
                            String::new()
                        } else {
                            format!(" {args}")
                        };
                        self.lines
                            .push(AnalyzeLine::Step(format!("→ {name}{shown}")));
                    }
                    AgentEvent::ToolResult { name, bytes } => {
                        self.lines
                            .push(AnalyzeLine::Step(format!("← {name} ({bytes} bytes)")));
                    }
                    AgentEvent::ActionProposed(a) => {
                        self.lines.push(AnalyzeLine::Step(format!(
                            "⚠ proposed: kill {} ({}) — {}",
                            a.process_name, a.pid, a.reason
                        )));
                        self.pending.push(a);
                    }
                    AgentEvent::Answer(text) => self.lines.push(AnalyzeLine::Answer(text)),
                    AgentEvent::Failed(e) => self.lines.push(AnalyzeLine::Error(e)),
                },
                Ok(AgentUpdate::Done) => {
                    self.rx = None;
                    break;
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.rx = None;
                    break;
                }
            }
        }
    }
}

struct ProgramListRow {
    id: String,
    name: String,
    version: Option<String>,
    active: bool,
    observed: bool,
    process_count: usize,
    cpu_percent: f32,
}

/// Installed-program inventory is loaded only when its tab is first opened.
/// Registry reads are usually fast, but keeping even that work off the UI
/// thread preserves the same no-blocking rule as health/file scans.
struct ProgramsState {
    scan: Option<InstalledProgramsScan>,
    rx: Option<mpsc::Receiver<InstalledProgramsScan>>,
    attribution: ProgramAttribution,
    activity_at: Option<Instant>,
    relationships: Vec<ProgramRelationship>,
    /// Programs for which a directly owned process or launched descendant
    /// has been observed since this inventory was loaded. This is explicitly
    /// session evidence, not a Windows-wide "last used" timestamp.
    observed_ids: HashSet<String>,
    selected_id: Option<String>,
    filter: String,
    active_only: bool,
    review_only: bool,
    include_system: bool,
}

impl ProgramsState {
    fn new() -> Self {
        Self {
            scan: None,
            rx: None,
            attribution: ProgramAttribution::default(),
            activity_at: None,
            relationships: Vec::new(),
            observed_ids: HashSet::new(),
            selected_id: None,
            filter: String::new(),
            active_only: false,
            review_only: false,
            include_system: false,
        }
    }

    fn start(&mut self) {
        if self.scan.is_some() || self.rx.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        std::thread::spawn(move || {
            let _ = tx.send(list_installed_programs());
        });
    }

    /// Returns true when a newly completed inventory needs attribution
    /// against the latest process sample.
    fn poll(&mut self) -> bool {
        let Some(rx) = &self.rx else { return false };
        match rx.try_recv() {
            Ok(scan) => {
                self.relationships = program_relationships(&scan.programs);
                self.activity_at = None;
                if self.selected_id.is_none() {
                    self.selected_id = scan
                        .programs
                        .iter()
                        .find(|program| !program.system_component && !program.update_or_hotfix)
                        .or_else(|| scan.programs.first())
                        .map(|program| program.id.clone());
                }
                self.scan = Some(scan);
                self.rx = None;
                true
            }
            Err(mpsc::TryRecvError::Empty) => false,
            Err(mpsc::TryRecvError::Disconnected) => {
                self.rx = None;
                false
            }
        }
    }

    fn scanning(&self) -> bool {
        self.rx.is_some()
    }

    fn refresh_activity(&mut self, processes: &[ProcessSample]) {
        let Some(scan) = &self.scan else { return };
        if self
            .activity_at
            .is_some_and(|at| at.elapsed() < PROGRAM_ACTIVITY_INTERVAL)
        {
            return;
        }
        self.attribution = attribute_processes(&scan.programs, processes);
        self.activity_at = Some(Instant::now());
        self.observed_ids.extend(
            self.attribution
                .activities
                .iter()
                .filter(|activity| activity.active())
                .map(|activity| activity.program_id.clone()),
        );
    }

    fn activity(&self, id: &str) -> Option<&rmon_core::ProgramActivity> {
        self.attribution
            .activities
            .iter()
            .find(|activity| activity.program_id == id)
    }
}

struct RmonApp {
    /// Sampling runs on its own thread; see [`sampling`] for why, and for
    /// how it decides how often to run.
    sampler: BackgroundSampler,
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
    /// False while the window is hidden to the tray or minimized, which is
    /// what lets sampling drop to its background cadence.
    window_visible: bool,
    /// Closing the window with a tray icon present hides it rather than
    /// quitting; egui reports such a viewport as neither closed nor
    /// minimized, so rMon has to remember it did that.
    hidden_to_tray: bool,
    system: SystemMetrics,
    /// Supplemental HWiNFO's full sensor tree is session-only opt-in. CPU
    /// thermal fallback remains automatic only when rMon's direct CPU
    /// sources are unavailable; this flag never changes that preference.
    hwinfo_sensors_enabled: bool,
    hwinfo_sensor_groups: Vec<rmon_core::SensorGroup>,
    hwinfo_sensor_rx: Option<mpsc::Receiver<Vec<rmon_core::SensorGroup>>>,
    last_hwinfo_sensor_read: Option<Instant>,
    /// The last few minutes of system-wide throttle state, so the header
    /// can show whether the CPU/GPU numbers everything else is built on
    /// were measured against a limit rather than against the workload —
    /// including during episodes that ended before anyone looked.
    throttle: ThrottleHistory,
    /// System-wide TCP/UDP endpoint table, refreshed every tick — cheap
    /// enough to poll continuously, unlike `files`. Backs both the
    /// per-process "listening ports" section and the global search view.
    ports: Vec<PortEntry>,
    files: Option<FilesState>,
    /// Which view the left column is showing (see [`Tab`]).
    tab: Tab,
    analyze: AnalyzeState,
    search: SearchState,
    programs: ProgramsState,
    /// Per-process trend analysis (leak suspects, idle burners), sorted
    /// most-interesting first. Recomputed on [`TRENDS_INTERVAL`], not every
    /// tick: it walks every pid's whole bucketed history, and the series it
    /// reads only gains a point once a minute, so per-tick analysis was
    /// paying up to sixty times over for the same answer.
    trends: Vec<rmon_core::trends::ProcessTrend>,
    trends_at: Option<Instant>,
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

    /// Editor for the analyze tab's gateway credentials, shared by the
    /// settings tab and the analyze tab's own empty state.
    credentials: CredentialsEditor,
    about_open: bool,

    tray: Option<Tray>,
    really_quit: bool,
    autostart_enabled: bool,
    autostart_error: Option<String>,
}

impl RmonApp {
    fn new() -> Self {
        let sampler = BackgroundSampler::start();
        let has_gpu_source = sampler.has_gpu_source();
        let tray = match Tray::new() {
            Ok(tray) => Some(tray),
            Err(e) => {
                eprintln!("tray icon unavailable: {e:#}");
                None
            }
        };
        let mut programs = ProgramsState::new();
        programs.start();
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
            window_visible: true,
            hidden_to_tray: false,
            system: SystemMetrics::default(),
            hwinfo_sensors_enabled: false,
            hwinfo_sensor_groups: Vec::new(),
            hwinfo_sensor_rx: None,
            last_hwinfo_sensor_read: None,
            throttle: ThrottleHistory::default(),
            ports: Vec::new(),
            files: None,
            tab: Tab::Processes,
            credentials: CredentialsEditor::new(),
            about_open: false,
            analyze: AnalyzeState::new(),
            search: SearchState::new(),
            programs,
            trends: Vec::new(),
            trends_at: None,
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

    /// Folds one completed sample into the app's state. Called only when
    /// the sampling thread has actually produced something, which is why
    /// none of this is on a timer of its own any more.
    fn tick(&mut self, tick: Tick) {
        let Tick {
            snapshot, ports, ..
        } = tick;
        self.system = snapshot.system.clone();
        self.throttle.push(&snapshot.system);
        self.ports = ports;

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

        self.programs.refresh_activity(&snapshot.processes);
        self.history.push(snapshot);
        if self
            .trends_at
            .is_none_or(|at| at.elapsed() >= TRENDS_INTERVAL)
        {
            self.trends = rmon_core::trends::analyze(&self.history);
            self.trends_at = Some(Instant::now());
        }
        self.resort();
    }

    fn trend_for(&self, pid: u32) -> Option<&rmon_core::trends::ProcessTrend> {
        self.trends.iter().find(|t| t.pid == pid)
    }

    fn suspect_count(&self) -> usize {
        self.trends.iter().filter(|t| t.flagged()).count()
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
                let recent_exits = self
                    .short_lived
                    .as_ref()
                    .map(|w| w.recent())
                    .unwrap_or_default();
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

    /// Selects the first or last visible process row.
    fn select_edge(&mut self, last: bool) {
        self.selected_pid = if last {
            self.rows.last()
        } else {
            self.rows.first()
        }
        .map(|(_, process)| process.pid);
        self.scroll_to_selected = self.selected_pid.is_some();
    }

    /// Expands/collapses the selected process when it has children in tree
    /// view. Left/right and keypad 4/6 call this without changing flat view.
    fn set_selected_expanded(&mut self, expanded: bool) {
        if self.view_mode != ViewMode::Tree {
            return;
        }
        let Some(pid) = self.selected_pid else {
            return;
        };
        if !self.tree_has_children.contains(&pid) {
            return;
        }
        let is_collapsed = self.collapsed.contains(&pid);
        if expanded == is_collapsed {
            self.toggle_collapsed(pid);
            self.scroll_to_selected = true;
        }
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
    /// Switches the left column's view, kicking off any scan the target
    /// view needs on first visit.
    fn set_tab(&mut self, tab: Tab) {
        self.tab = tab;
        // Scanned on first view rather than at startup: the report is a
        // point-in-time fact a user asks for, not something worth doing on
        // every launch. Re-selecting the tab must not throw away a report
        // that already completed.
        if tab == Tab::Health && self.health.is_none() {
            self.health = Some(HealthState::start(
                DEFAULT_WHEA_LOOKBACK_DAYS,
                DEFAULT_WHEA_MAX_EVENTS,
            ));
        }
        if tab == Tab::Programs {
            self.programs.start();
        }
    }

    /// Builds the same clipboard-ready process summary used by both the
    /// detail panel's "copy info" button and the row context menu.
    fn copy_info_text(&self, pid: u32) -> Option<String> {
        let p = self
            .rows
            .iter()
            .find(|(_, p)| p.pid == pid)
            .map(|(_, p)| p)?;
        let (cpu_accum, gpu_accum) = self.history.accumulated(pid);
        let mut text = format!(
            "Process: {} (PID {})\n\
             Parent PID: {}{}\n\
             Owner: {}\n\
             Executable: {}\n\
             Command line: {}\n\
             CPU: {:.1}% instant, {} accumulated (over {})\n\
             GPU: {:.1}% instant, {} accumulated  [source: {}]\n\
             Open handles: {}\n\
             Memory: {}\n",
            p.name,
            p.pid,
            p.ppid
                .map(|v| v.to_string())
                .unwrap_or_else(|| "none".to_string()),
            if self.orphan_pids.contains(&p.pid) {
                " (exited — this process is orphaned)"
            } else {
                ""
            },
            p.user.as_deref().unwrap_or("unknown"),
            p.executable_path.as_deref().unwrap_or("unknown"),
            p.command_line.as_deref().unwrap_or("unknown"),
            p.cpu_percent,
            format_core_time(cpu_accum),
            format_duration(self.history.accum_window()),
            p.gpu_percent,
            format_core_time(gpu_accum),
            gpu_source_label(p.gpu_source),
            p.handle_count
                .map(|n| n.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            p.mem_bytes
                .map(format_bytes)
                .unwrap_or_else(|| "unknown".to_string()),
        );
        if let Some(verdict) = self.trend_for(pid).and_then(|t| t.verdict.as_deref()) {
            text.push_str(&format!("Trend: {verdict}\n"));
        }
        Some(text)
    }
}

fn gpu_source_label(src: GpuSource) -> &'static str {
    match src {
        GpuSource::Nvml => "nvml",
        GpuSource::Pdh => "pdh",
        GpuSource::Unavailable => "-",
    }
}

fn detail_field(ui: &mut egui::Ui, label: &str, value: Option<&str>) {
    ui.horizontal_wrapped(|ui| {
        ui.weak(format!("{label}:"));
        ui.label(value.unwrap_or("not recorded"));
    });
}

fn program_removal_blockers(
    program: &InstalledProgram,
    relationships: &[ProgramRelationship],
    activity: Option<&rmon_core::ProgramActivity>,
    observed_this_session: bool,
) -> Vec<String> {
    let mut blockers = Vec::new();
    if activity.is_some_and(rmon_core::ProgramActivity::active) {
        blockers.push("the program or a descendant it launched is running now".to_string());
    } else if observed_this_session {
        blockers.push("it was observed running earlier in this rMon session".to_string());
    }
    if relationships
        .iter()
        .any(|relationship| relationship.parent_id == program.id)
    {
        blockers.push("Windows records one or more dependent uninstall entries".to_string());
    }
    if program.system_component {
        blockers.push("the installer marks it as a system component".to_string());
    }
    if program.update_or_hotfix {
        blockers.push("the entry is an update or hotfix".to_string());
    }
    if !program.has_uninstaller() {
        blockers.push("no enabled uninstall command is registered".to_string());
    }
    blockers
}

fn program_relationship_names(
    program: &InstalledProgram,
    programs: &[InstalledProgram],
    relationships: &[ProgramRelationship],
) -> (Option<String>, Vec<String>) {
    let name_for = |id: &str| {
        programs
            .iter()
            .find(|candidate| candidate.id == id)
            .map(|candidate| candidate.name.clone())
    };
    let parent = relationships
        .iter()
        .find(|relationship| relationship.dependent_id == program.id)
        .and_then(|relationship| name_for(&relationship.parent_id));
    let dependents = relationships
        .iter()
        .filter(|relationship| relationship.parent_id == program.id)
        .filter_map(|relationship| name_for(&relationship.dependent_id))
        .collect();
    (parent, dependents)
}

impl eframe::App for RmonApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // Proof of life for the sampling thread. Without it, a window that
        // stops being drawn — minimized, most obviously — would have rMon
        // sampling forever into a channel nobody reads.
        self.sampler.mark_alive();
        if let Some(tick) = self.sampler.newest() {
            self.tick(tick);
        }
        if let Some(fs) = self.files.as_mut() {
            fs.poll();
        }
        self.search.poll();
        self.analyze.poll();
        self.analyze.poll_unlock();
        self.credentials.poll();
        if self.credentials.poll_save() {
            self.analyze.refresh_availability();
        }
        if let Some(h) = self.health.as_mut() {
            h.poll();
        }
        if self.programs.poll() {
            let processes = self
                .history
                .latest()
                .map(|snapshot| snapshot.processes.clone())
                .unwrap_or_default();
            self.programs.refresh_activity(&processes);
        }

        about::window(ui.ctx(), &mut self.about_open);

        // A window nobody can see does not need the same attention as one
        // being watched. This covers hiding to the tray, where egui keeps
        // drawing an invisible window; a minimized one stops being drawn
        // altogether and is handled by `mark_alive` above.
        let visible = !self.hidden_to_tray;
        if visible != self.window_visible {
            self.window_visible = visible;
            self.sampler.set_hidden(!visible);
        }

        // Redrawing (a full egui layout pass + wgpu present) is real,
        // continuous CPU/GPU cost — there's no reason to pay it 5x/sec
        // forever when the data underneath only changes once per sample.
        // Only wake up faster than that while something is actually
        // animating (a files/search scan spinner); otherwise follow the
        // sampling thread's own cadence, whatever it has settled on.
        let animating = self
            .files
            .as_ref()
            .is_some_and(|fs| matches!(fs.status, FilesStatus::Scanning(_)))
            || self.search.scanning()
            || self.analyze.running()
            || self.credentials.fetching()
            || self.analyze.unlocking()
            || self.hwinfo_sensor_rx.is_some()
            || self.health.as_ref().is_some_and(HealthState::scanning)
            || self.programs.scanning();
        let repaint_interval = if animating {
            Duration::from_millis(200)
        } else {
            self.sampler.interval()
        };
        ui.ctx().request_repaint_after(repaint_interval);

        if let Some(tray) = &self.tray {
            match tray.poll() {
                Some(TrayAction::Show) => {
                    self.hidden_to_tray = false;
                    ui.ctx()
                        .send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Focus);
                }
                Some(TrayAction::Quit) => {
                    self.really_quit = true;
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
                None => {}
            }
        }
        if self.tray.is_some() && !self.really_quit && ui.input(|i| i.viewport().close_requested())
        {
            self.hidden_to_tray = true;
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }

        // Keep list navigation active without first requiring a click, but
        // never steal keys from a text editor or another tab. Numpad keys
        // work with Num Lock on; with it off Windows reports the matching
        // Arrow/Home/Page keys instead.
        if self.tab == Tab::Processes
            && self.files.is_none()
            && ui.memory(|mem| mem.focused()).is_none()
        {
            let nav = ui.input(|i| {
                if i.key_pressed(egui::Key::ArrowUp) || i.key_pressed(egui::Key::Num8) {
                    Some((-1, false))
                } else if i.key_pressed(egui::Key::ArrowDown) || i.key_pressed(egui::Key::Num2) {
                    Some((1, false))
                } else if i.key_pressed(egui::Key::PageUp) || i.key_pressed(egui::Key::Num9) {
                    Some((-10, false))
                } else if i.key_pressed(egui::Key::PageDown) || i.key_pressed(egui::Key::Num3) {
                    Some((10, false))
                } else if i.key_pressed(egui::Key::Home) || i.key_pressed(egui::Key::Num7) {
                    Some((0, true))
                } else if i.key_pressed(egui::Key::End) || i.key_pressed(egui::Key::Num1) {
                    Some((1, true))
                } else {
                    None
                }
            });
            match nav {
                Some((delta, false)) => self.move_selection(delta),
                Some((edge, true)) => self.select_edge(edge > 0),
                _ => {}
            }

            let (collapse, expand) = ui.input(|i| {
                (
                    i.key_pressed(egui::Key::ArrowLeft) || i.key_pressed(egui::Key::Num4),
                    i.key_pressed(egui::Key::ArrowRight) || i.key_pressed(egui::Key::Num6),
                )
            });
            if collapse {
                self.set_selected_expanded(false);
            } else if expand {
                self.set_selected_expanded(true);
            }
        }

        egui::Panel::top("header").show(ui, |ui| {
            egui::MenuBar::new().ui(ui, |ui| {
                // No view entries here: the tab strip below reaches every
                // view, and listing them in a menu as well would give each
                // destination two names and two states to keep in sync.
                ui.menu_button("App", |ui| {
                    if !rmon_core::elevate::is_elevated()
                        && ui.button("Restart as Administrator").clicked()
                    {
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
                    if ui.button("About rMon").clicked() {
                        self.about_open = true;
                        ui.close();
                    }
                    ui.separator();
                    if ui.button("Quit").clicked() {
                        self.really_quit = true;
                        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                        ui.close();
                    }
                });
                ui.add_space(12.0);
                ui.heading("rMon");
                ui.weak("live process CPU/GPU monitor");
                // A stale window looks exactly like a fresh one, so the
                // build that produced it is worth a permanent line.
                ui.weak(about::short_line())
                    .on_hover_text("App → About rMon for the commit and what changed");
                if !self.has_gpu_source {
                    ui.colored_label(
                        egui::Color32::from_rgb(220, 120, 0),
                        "no GPU data source found",
                    );
                }
            });
            ui.add_space(4.0);
            self.draw_tab_strip(ui);
            ui.add_space(2.0);
            // The sort/filter controls only drive the process table, so on
            // every other tab they would be dead UI.
            if self.tab == Tab::Processes {
                self.draw_process_toolbar(ui);
            }
            ui.horizontal(|ui| {
                thermal_line(ui, &self.system);
            });
            ui.horizontal(|ui| {
                draw_throttle_strip(ui, &self.throttle);
                for fan in self.system.fans.iter().filter(|f| f.rpm.is_some()) {
                    ui.separator();
                    ui.weak(format!("{}: {} rpm", fan.label, fan.rpm.unwrap_or(0)));
                }
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

        // Three equal, independently draggable columns: process list, process
        // detail, and its CPU/GPU history graph. Each `Panel::left` remembers
        // its own width (keyed by id) via egui's persisted memory, so the
        // layout survives restarts once eframe's "persistence" feature is on.
        let column_width = ui.available_width() / 3.0;

        egui::Panel::left("column_processes")
            .resizable(true)
            .default_size(column_width)
            .min_size(200.0)
            .show(ui, |ui| match self.tab {
                Tab::Processes => self.draw_table(ui),
                Tab::Programs => self.draw_programs(ui),
                Tab::Suspects => self.draw_suspects(ui),
                Tab::Analyze => self.draw_analyze(ui),
                Tab::Sensors => self.draw_hardware(ui),
                Tab::Health => self.draw_health(ui),
                Tab::Exited => self.draw_recent_exits(ui),
                Tab::Search => self.draw_search_all(ui),
                Tab::WhatsNew => about::whats_new_tab(ui),
                Tab::Settings => self.draw_settings(ui),
            });

        egui::Panel::left("column_details")
            .resizable(true)
            .default_size(column_width)
            .min_size(200.0)
            .show(ui, |ui| {
                if self.tab == Tab::Programs {
                    self.draw_program_detail(ui);
                } else {
                    self.draw_detail_info(ui);
                }
            });

        egui::CentralPanel::default().show(ui, |ui| {
            if self.tab == Tab::Programs {
                self.draw_program_processes(ui);
            } else {
                self.draw_detail_graph(ui);
            }
        });
    }
}

impl RmonApp {
    /// The tab strip: one click to any view, from any view.
    fn draw_tab_strip(&mut self, ui: &mut egui::Ui) {
        let suspects = self.suspect_count();
        ui.horizontal_wrapped(|ui| {
            for tab in Tab::ALL {
                // The suspect count is the one thing worth pulling onto the
                // strip itself: it is the only tab whose contents can turn
                // urgent while you are looking at a different one.
                let text = match tab {
                    Tab::Suspects if suspects > 0 => {
                        egui::RichText::new(format!("suspects ({suspects})"))
                            .color(egui::Color32::from_rgb(220, 120, 0))
                    }
                    _ => egui::RichText::new(tab.label()),
                };
                if ui
                    .selectable_label(self.tab == tab, text)
                    .on_hover_text(tab.hover())
                    .clicked()
                {
                    self.set_tab(tab);
                }
            }
        });
    }

    fn draw_programs(&mut self, ui: &mut egui::Ui) {
        ui.heading("Installed programs");
        ui.weak("Win32/MSI inventory · live process attribution");
        ui.add_space(6.0);

        if self.programs.scan.is_none() {
            if self.programs.scanning() {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("reading Windows uninstall registry…");
                });
            } else if ui.button("scan installed programs").clicked() {
                self.programs.start();
            }
            return;
        }

        ui.horizontal(|ui| {
            ui.label("search:");
            ui.text_edit_singleline(&mut self.programs.filter);
        });
        ui.horizontal_wrapped(|ui| {
            ui.checkbox(&mut self.programs.active_only, "active now");
            ui.checkbox(&mut self.programs.review_only, "removal review");
            ui.checkbox(
                &mut self.programs.include_system,
                "include system components/updates",
            );
            if ui.button("↻ rescan").clicked() {
                self.programs.scan = None;
                self.programs.selected_id = None;
                self.programs.start();
            }
        });
        ui.add_space(4.0);

        let filter = self.programs.filter.to_ascii_lowercase();
        let Some(scan) = &self.programs.scan else {
            return;
        };
        let mut visible: Vec<ProgramListRow> = scan
            .programs
            .iter()
            .filter(|program| {
                self.programs.include_system
                    || (!program.system_component && !program.update_or_hotfix)
            })
            .filter(|program| {
                filter.is_empty()
                    || program.name.to_ascii_lowercase().contains(&filter)
                    || program
                        .publisher
                        .as_deref()
                        .is_some_and(|value| value.to_ascii_lowercase().contains(&filter))
                    || program
                        .version
                        .as_deref()
                        .is_some_and(|value| value.to_ascii_lowercase().contains(&filter))
                    || program
                        .install_location
                        .as_deref()
                        .is_some_and(|value| value.to_ascii_lowercase().contains(&filter))
            })
            .filter_map(|program| {
                let activity = self.programs.activity(&program.id);
                let active = activity.is_some_and(rmon_core::ProgramActivity::active);
                let observed = self.programs.observed_ids.contains(&program.id);
                let reviewable = program_removal_blockers(
                    program,
                    &self.programs.relationships,
                    activity,
                    observed,
                )
                .is_empty();
                if (self.programs.active_only && !active)
                    || (self.programs.review_only && !reviewable)
                {
                    return None;
                }
                Some(ProgramListRow {
                    id: program.id.clone(),
                    name: program.name.clone(),
                    version: program.version.clone(),
                    active,
                    observed,
                    process_count: activity.map_or(0, rmon_core::ProgramActivity::process_count),
                    cpu_percent: activity.map_or(0.0, |activity| activity.cpu_percent),
                })
            })
            .collect();
        visible.sort_by(|a, b| {
            b.active.cmp(&a.active).then_with(|| {
                a.name
                    .to_ascii_lowercase()
                    .cmp(&b.name.to_ascii_lowercase())
            })
        });

        ui.label(format!(
            "{} shown · {} inventory entries",
            visible.len(),
            scan.programs.len()
        ));
        ui.weak("active totals include child processes launched by the app");
        let mut selected = None;
        egui::ScrollArea::vertical()
            .id_salt("installed-program-list")
            .show(ui, |ui| {
                for row in &visible {
                    let status = if row.active {
                        format!("● {} proc · {:.1}% CPU", row.process_count, row.cpu_percent)
                    } else if row.observed {
                        "seen this session".to_string()
                    } else {
                        "not observed this session".to_string()
                    };
                    let text = format!(
                        "{}{}\n  {status}",
                        row.name,
                        row.version
                            .as_deref()
                            .map(|version| format!("  {version}"))
                            .unwrap_or_default(),
                    );
                    let response = ui.selectable_label(
                        self.programs.selected_id.as_deref() == Some(row.id.as_str()),
                        text,
                    );
                    if row.active {
                        let dot = egui::Rect::from_center_size(
                            response.rect.left_center() + egui::vec2(4.0, 0.0),
                            egui::vec2(4.0, 4.0),
                        );
                        ui.painter().rect_filled(dot, 2.0, OK_COLOR);
                    }
                    if response.clicked() {
                        selected = Some(row.id.clone());
                    }
                }
            });
        if let Some(id) = selected {
            self.programs.selected_id = Some(id);
        }

        if !scan.warnings.is_empty() {
            ui.collapsing(
                format!("{} inventory warning(s)", scan.warnings.len()),
                |ui| {
                    for warning in &scan.warnings {
                        ui.weak(warning);
                    }
                },
            );
        }
    }

    fn draw_program_detail(&mut self, ui: &mut egui::Ui) {
        ui.set_max_width(ui.available_width());
        let Some(id) = self.programs.selected_id.as_deref() else {
            ui.label("Select an installed program.");
            return;
        };
        let Some(program) = self
            .programs
            .scan
            .as_ref()
            .and_then(|scan| scan.programs.iter().find(|program| program.id == id))
            .cloned()
        else {
            ui.label("The selected program is no longer in the inventory.");
            return;
        };
        let activity = self.programs.activity(&program.id).cloned();
        let observed = self.programs.observed_ids.contains(&program.id);
        let blockers = program_removal_blockers(
            &program,
            &self.programs.relationships,
            activity.as_ref(),
            observed,
        );

        ui.heading(&program.name);
        if let Some(version) = &program.version {
            ui.label(format!("version {version}"));
        }
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    !self.analyze.running(),
                    egui::Button::new("✨ explain purpose & assess"),
                )
                .on_hover_text(
                    "Ask the configured analysis model to explain identity, purpose, evidence, and removal risk",
                )
                .clicked()
            {
                self.ask_program_diagnosis(&program);
            }
            if self.analyze.running() {
                ui.spinner();
                ui.weak("analysis already running");
            }
        });
        ui.add_space(6.0);

        detail_field(ui, "publisher", program.publisher.as_deref());
        detail_field(ui, "install location", program.install_location.as_deref());
        detail_field(ui, "installed", program.install_date.as_deref());
        detail_field(ui, "scope", Some(program.scope.as_str()));
        if let Some(size) = program.estimated_size_bytes {
            detail_field(ui, "estimated size", Some(&format_bytes(size)));
        }
        if let Some(comments) = &program.comments {
            ui.add_space(4.0);
            ui.label(comments);
        }
        if let Some(website) = &program.website {
            ui.hyperlink_to("publisher website", website);
        }

        ui.add_space(8.0);
        ui.separator();
        ui.label(egui::RichText::new("Use observed by rMon").strong());
        match activity.as_ref() {
            Some(activity) if activity.active() => {
                ui.colored_label(
                    OK_COLOR,
                    format!(
                        "active now · {} process(es) · {:.1}% CPU · {:.1}% GPU · {} memory",
                        activity.process_count(),
                        activity.cpu_percent,
                        activity.gpu_percent,
                        format_bytes(activity.memory_bytes),
                    ),
                );
                ui.weak("inclusive of descendants launched by this program");
            }
            _ if observed => {
                ui.label("not active now; a process was observed earlier in this rMon session");
            }
            _ => {
                ui.label("not observed during this rMon session");
                ui.weak("this is not a system-wide last-used timestamp and does not mean unused");
            }
        }

        ui.add_space(8.0);
        ui.separator();
        ui.label(egui::RichText::new("Known relationships").strong());
        let (parent, dependents) = program_relationship_names(
            &program,
            self.programs
                .scan
                .as_ref()
                .map(|scan| scan.programs.as_slice())
                .unwrap_or_default(),
            &self.programs.relationships,
        );
        if let Some(parent) = parent {
            ui.label(format!("installer parent: {parent}"));
        }
        for dependent in &dependents {
            ui.label(format!("dependent uninstall entry: {dependent}"));
        }
        if program.parent_key_name.is_none() && dependents.is_empty() {
            ui.weak("no installer relationship recorded");
        }
        ui.weak(
            "Windows records only some update/bundle relationships here; this is not a complete dependency graph.",
        );

        ui.add_space(8.0);
        ui.separator();
        ui.label(egui::RichText::new("Suspicion / verification").strong());
        let attention = program.attention_reasons();
        if attention.is_empty() {
            ui.label("no obvious warning in installer metadata or install path");
        } else {
            for reason in attention {
                ui.colored_label(WARN_COLOR, format!("⚠ {reason}"));
            }
        }
        ui.weak("This is triage, not an antivirus scan or a digital-signature verdict.");

        ui.add_space(8.0);
        ui.separator();
        ui.label(egui::RichText::new("Removal review").strong());
        if blockers.is_empty() {
            ui.colored_label(WARN_COLOR, "candidate to review — no current blocker found");
            ui.label(
                "It is idle in the observed session, has an uninstaller, and no dependent entry is known.",
            );
        } else {
            for blocker in blockers {
                ui.label(format!("• {blocker}"));
            }
        }
        ui.weak(
            "Never read ‘candidate’ as ‘safe’: confirm project/config usage and backups first. rMon does not uninstall software.",
        );
    }

    fn draw_program_processes(&mut self, ui: &mut egui::Ui) {
        ui.set_max_width(ui.available_width());
        ui.heading("Live process provenance");
        let Some(id) = self.programs.selected_id.as_deref() else {
            ui.label("Select an installed program.");
            return;
        };
        let Some(program) = self
            .programs
            .scan
            .as_ref()
            .and_then(|scan| scan.programs.iter().find(|program| program.id == id))
        else {
            return;
        };
        let Some(activity) = self.programs.activity(id) else {
            ui.label("Waiting for a process sample…");
            return;
        };
        let pids = activity.all_pids();
        if pids.is_empty() {
            ui.label("No process from this program is active now.");
            ui.weak(
                "When it runs, this panel shows its executable plus descendants it launched — for example Warp → find.exe.",
            );
            return;
        }

        ui.label(format!(
            "{} process(es), inclusive {:.1}% CPU · {:.1}% GPU · {} memory",
            pids.len(),
            activity.cpu_percent,
            activity.gpu_percent,
            format_bytes(activity.memory_bytes),
        ));
        ui.weak("inclusive totals can overlap a child that belongs to another installed program");
        ui.add_space(6.0);

        let Some(snapshot) = self.history.latest() else {
            return;
        };
        let processes: Vec<_> = snapshot
            .processes
            .iter()
            .filter(|process| pids.contains(&process.pid))
            .cloned()
            .collect();
        let rows = build_tree(
            &processes,
            |process| process.cpu_percent + process.gpu_percent,
            false,
        );
        let program_names: HashMap<_, _> = self
            .programs
            .scan
            .as_ref()
            .into_iter()
            .flat_map(|scan| &scan.programs)
            .map(|program| (program.id.as_str(), program.name.as_str()))
            .collect();
        let links: HashMap<_, _> = self
            .programs
            .attribution
            .links
            .iter()
            .map(|link| (link.pid, link))
            .collect();
        let mut selected_pid = None;
        egui::ScrollArea::vertical()
            .id_salt("program-process-tree")
            .show(ui, |ui| {
                for (depth, process) in &rows {
                    let link = links.get(&process.pid).copied();
                    let direct_name = link
                        .and_then(|link| link.direct_program_id.as_deref())
                        .and_then(|id| program_names.get(id).copied());
                    let relation = if direct_name == Some(program.name.as_str()) {
                        "program executable".to_string()
                    } else if let Some(owner) = direct_name {
                        format!("{owner}; launched by {}", program.name)
                    } else {
                        format!("launched by {}", program.name)
                    };
                    ui.horizontal(|ui| {
                        ui.add_space(*depth as f32 * 16.0);
                        if ui
                            .selectable_label(
                                self.selected_pid == Some(process.pid),
                                format!("{} ({})", process.name, process.pid),
                            )
                            .clicked()
                        {
                            selected_pid = Some(process.pid);
                        }
                        ui.weak(format!(
                            "{:.1}% CPU · {:.1}% GPU · {relation}",
                            process.cpu_percent, process.gpu_percent
                        ));
                    });
                    if let Some(path) = &process.executable_path {
                        ui.horizontal(|ui| {
                            ui.add_space((*depth as f32 + 1.0) * 16.0);
                            ui.label(egui::RichText::new(path).small().monospace().weak());
                        });
                    }
                    for reason in process_attention_reasons(process) {
                        ui.horizontal(|ui| {
                            ui.add_space((*depth as f32 + 1.0) * 16.0);
                            ui.colored_label(WARN_COLOR, format!("⚠ {reason}"));
                        });
                    }
                }
            });
        if let Some(pid) = selected_pid {
            self.selected_pid = Some(pid);
        }
    }

    fn ask_process_diagnosis(&mut self, pid: u32, name: &str) {
        self.analyze.input = format!(
            "Explain and assess process {name:?} (PID {pid}). Use process_detail and, when it maps \
             to installed software, program_detail. Tell me its normal purpose, executable identity, \
             who launched it and what it launched, why it may be using resources, concrete suspicious \
             indicators versus missing evidence, and read-only verification steps. Do not label it \
             malware or safe from the filename alone."
        );
        self.tab = Tab::Analyze;
        self.start_analysis();
    }

    fn ask_program_diagnosis(&mut self, program: &InstalledProgram) {
        self.analyze.input = format!(
            "Explain and assess the installed program {:?} (inventory id {:?}). Use program_detail. \
             Tell me what it is normally used for, what rMon actually observes it doing now, which \
             parent/child processes and known dependents it has, any concrete suspicious indicators \
             versus merely missing evidence, read-only verification commands, and whether it is only \
             a candidate to review for uninstall. Do not call it safe to uninstall when usage or \
             dependencies are unknown.",
            program.name, program.id
        );
        self.tab = Tab::Analyze;
        self.start_analysis();
    }

    /// Asks an LLM to explain the current machine state, using rMon's own
    /// telemetry as its evidence.
    ///
    /// The agent is read-only apart from proposing a process kill, which
    /// lands here as a confirmation prompt rather than as an action — see
    /// `rmon_agent::tools`.
    fn draw_analyze(&mut self, ui: &mut egui::Ui) {
        ui.heading("Analyze");

        match &self.analyze.availability {
            Ok(what) => {
                ui.weak(format!("using {what}"));
            }
            Err(why) => {
                let why = why.clone();
                ui.colored_label(WARN_COLOR, why);
                ui.add_space(6.0);

                // A key held behind Windows Hello is configured, not missing.
                // Offering the editor first would invite someone to re-enter
                // a key they already have, when all that is needed is a
                // gesture.
                if self.credentials.requires_hello() {
                    ui.horizontal(|ui| {
                        let pending = self.analyze.unlocking();
                        if ui
                            .add_enabled(
                                !pending,
                                egui::Button::new("🔓 Unlock with Windows Hello"),
                            )
                            .on_hover_text(
                                "Releases the key for this session only.                                  rMon forgets it when it exits.",
                            )
                            .clicked()
                        {
                            self.analyze.start_unlock();
                        }
                        if pending {
                            ui.spinner();
                            ui.weak("waiting for your gesture…");
                        }
                    });
                    ui.add_space(6.0);
                    ui.collapsing("Change credentials", |ui| {
                        if self.credentials.draw(ui) {
                            self.analyze.refresh_availability();
                        }
                    });
                    return;
                }

                // The editor is drawn here, not merely pointed at, because
                // this is where someone discovers the tab is unconfigured.
                ui.group(|ui| {
                    if self.credentials.draw(ui) {
                        self.analyze.refresh_availability();
                    }
                });
                return;
            }
        }
        ui.add_space(6.0);

        let running = self.analyze.running();
        ui.horizontal(|ui| {
            let submitted = ui
                .add_enabled(
                    !running,
                    egui::TextEdit::singleline(&mut self.analyze.input)
                        .desired_width(ui.available_width() - 90.0)
                        .hint_text("why is this machine slow?"),
                )
                .lost_focus()
                && ui.input(|i| i.key_pressed(egui::Key::Enter));
            let clicked = ui.add_enabled(!running, egui::Button::new("ask")).clicked();
            if (submitted || clicked) && !running {
                self.start_analysis();
            }
        });
        if running {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.weak("thinking — tool calls appear below as they happen");
            });
        }

        // Proposals are drawn above the transcript: an action awaiting a
        // decision should not be something the user has to scroll to find.
        let mut approve: Option<usize> = None;
        let mut dismiss: Option<usize> = None;
        for (i, action) in self.analyze.pending.iter().enumerate() {
            ui.add_space(6.0);
            ui.group(|ui| {
                ui.colored_label(
                    WARN_COLOR,
                    format!("Kill {} (pid {})?", action.process_name, action.pid),
                );
                ui.label(&action.reason);
                ui.horizontal(|ui| {
                    if ui
                        .button(egui::RichText::new("⛔ kill it").color(BAD_COLOR))
                        .clicked()
                    {
                        approve = Some(i);
                    }
                    if ui.button("dismiss").clicked() {
                        dismiss = Some(i);
                    }
                });
            });
        }
        if let Some(i) = approve {
            let action = self.analyze.pending.remove(i);
            // The kill happens here, in response to a click — never inside
            // the agent loop.
            match rmon_core::kill_process(action.pid) {
                Ok(()) => {
                    self.kill_error = None;
                    self.analyze.lines.push(AnalyzeLine::Step(format!(
                        "✓ killed {} ({}) on your approval",
                        action.process_name, action.pid
                    )));
                }
                Err(e) => self.kill_error = Some(format!("{e:#}")),
            }
        }
        if let Some(i) = dismiss {
            let action = self.analyze.pending.remove(i);
            self.analyze.lines.push(AnalyzeLine::Step(format!(
                "✗ declined to kill {} ({})",
                action.process_name, action.pid
            )));
        }
        if let Some(err) = &self.kill_error {
            ui.colored_label(BAD_COLOR, err);
        }

        ui.add_space(8.0);
        egui::ScrollArea::vertical()
            .id_salt("analyze-transcript")
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for line in &self.analyze.lines {
                    match line {
                        AnalyzeLine::Question(q) => {
                            ui.add_space(6.0);
                            ui.label(egui::RichText::new(q).strong());
                        }
                        // Tool traffic is deliberately dim and monospaced:
                        // it is there to make the agent's reasoning
                        // auditable, not to compete with its answer.
                        AnalyzeLine::Step(t) => {
                            ui.label(egui::RichText::new(t).small().monospace().weak());
                        }
                        AnalyzeLine::Answer(a) => {
                            ui.add_space(4.0);
                            ui.label(a);
                        }
                        AnalyzeLine::Error(e) => {
                            ui.colored_label(BAD_COLOR, e);
                        }
                    }
                }
            });
    }

    /// Captures the current machine state and runs one agent turn on a
    /// worker thread.
    fn start_analysis(&mut self) {
        let question = std::mem::take(&mut self.analyze.input);
        let question = if question.trim().is_empty() {
            "Why is this machine slow right now?".to_string()
        } else {
            question
        };
        self.analyze
            .lines
            .push(AnalyzeLine::Question(question.clone()));

        // Snapshot the state now, on this thread, so the agent reasons
        // about one consistent moment rather than a machine that keeps
        // moving under it.
        let Some(snapshot) = self.history.latest().cloned() else {
            self.analyze
                .lines
                .push(AnalyzeLine::Error("no sample taken yet".into()));
            return;
        };
        let ctx = ToolContext {
            snapshot,
            trends: self.trends.clone(),
            throttle: ThrottleSummary {
                observed_secs: self.throttle.observed().as_secs(),
                fraction_limited: self.throttle.fraction_limited(),
            },
            installed_programs: self
                .programs
                .scan
                .as_ref()
                .map(|scan| scan.programs.clone())
                .unwrap_or_default(),
        };

        let config = match AgentConfig::resolve(self.analyze.unlocked.as_deref()) {
            Ok(c) => c,
            Err(e) => {
                self.analyze
                    .lines
                    .push(AnalyzeLine::Error(format!("{e:#}")));
                return;
            }
        };

        let (tx, rx) = mpsc::channel();
        self.analyze.rx = Some(rx);
        std::thread::spawn(move || {
            let send = |u| {
                let _ = tx.send(u);
            };
            match rmon_agent::Agent::new(&config) {
                Ok(mut agent) => {
                    if let Err(e) = agent.ask(&question, &ctx, |e| send(AgentUpdate::Event(e))) {
                        send(AgentUpdate::Event(AgentEvent::Failed(format!("{e:#}"))));
                    }
                }
                Err(e) => send(AgentUpdate::Event(AgentEvent::Failed(format!("{e:#}")))),
            }
            send(AgentUpdate::Done);
        });
    }

    /// Readings rMon obtains itself, through the PawnIO kernel driver,
    /// with no other monitoring application involved.
    ///
    /// Drawn above the HWiNFO section, and shown even when it has nothing
    /// to report: on a machine where this path is closed, saying *why* is
    /// the most useful thing on the page, and an empty space would just
    /// look like the feature doesn't exist.
    fn draw_direct_sensors(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.label(egui::RichText::new("Direct hardware access").strong());
            ui.weak(
                self.system
                    .sensor_source
                    .as_deref()
                    .unwrap_or("waiting for the first sample"),
            );
            ui.add_space(4.0);

            // Only the MSR path's own readings belong under this heading.
            // `system.cpu_temp_c` is the merged best-available value, so
            // rendering it here unconditionally would credit this section
            // with a number HWiNFO supplied — the section would look like
            // it was working on a machine where it plainly isn't.
            if self.system.cpu_temp_source.as_deref() == Some("CPU MSR") {
                if let Some(t) = self.system.cpu_temp_c {
                    ui.horizontal(|ui| {
                        ui.label("CPU package");
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.monospace(format!("{t:.0} °C"));
                        });
                    });
                }
                if let Some(h) = self.system.cpu_thermal_headroom_c {
                    ui.horizontal(|ui| {
                        ui.label("below TjMax");
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.monospace(format!("{h:.0} °C"));
                        });
                    });
                }
            }

            ui.add_space(6.0);
            ui.label(egui::RichText::new("Motherboard temperatures").strong());
            let (temperatures, unavailable_temperatures): (Vec<_>, Vec<_>) = self
                .system
                .board_temperatures
                .iter()
                .partition(|reading| reading.temp_c.is_some());
            if temperatures.is_empty() {
                ui.weak("No valid Super I/O temperature inputs were available.");
            }
            for reading in temperatures {
                let Some(temp_c) = reading.temp_c else {
                    continue;
                };
                ui.horizontal(|ui| {
                    ui.label(&reading.label);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.monospace(format!("{temp_c:.1} °C"));
                    });
                });
            }
            if !unavailable_temperatures.is_empty() {
                ui.weak(format!(
                    "{} further temperature input(s) unconnected or unavailable",
                    unavailable_temperatures.len()
                ));
            }

            ui.add_space(6.0);
            ui.label(egui::RichText::new("Voltages").strong());
            let (voltages, unavailable_voltages): (Vec<_>, Vec<_>) = self
                .system
                .voltages
                .iter()
                .partition(|reading| reading.volts.is_some());
            if voltages.is_empty() {
                ui.weak("No valid Super I/O voltage inputs were available.");
            }
            for reading in voltages {
                let Some(volts) = reading.volts else {
                    continue;
                };
                ui.horizontal(|ui| {
                    ui.label(&reading.label);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.monospace(format!("{volts:.3} V"));
                    });
                });
            }
            if self
                .system
                .voltages
                .iter()
                .any(|reading| reading.label.contains("ADC pin"))
            {
                ui.weak(
                    "VIN values are the Super I/O pin voltages. +5V/+12V rail scaling depends \
                     on motherboard-specific resistor dividers, so rMon does not guess it.",
                );
            }
            if !unavailable_voltages.is_empty() {
                ui.weak(format!(
                    "{} further voltage input(s) unavailable",
                    unavailable_voltages.len()
                ));
            }

            ui.add_space(6.0);
            ui.label(egui::RichText::new("Fans").strong());
            if self.system.fans.is_empty() {
                ui.weak(
                    "No fan tachometers. These need a supported Super I/O chip, PawnIO, and \
                     Administrator access.",
                );
            } else {
                // A board exposes far more tachometer channels than it has
                // headers in use, so list live channels and state the empty
                // count separately.
                let (live, empty): (Vec<_>, Vec<_>) =
                    self.system.fans.iter().partition(|f| f.rpm.is_some());
                for fan in live {
                    let Some(rpm) = fan.rpm else {
                        continue;
                    };
                    ui.horizontal(|ui| {
                        ui.label(&fan.label);
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.monospace(format!("{rpm} rpm"));
                        });
                    });
                }
                if !empty.is_empty() {
                    ui.weak(format!(
                        "{} further channel(s) with no fan connected",
                        empty.len()
                    ));
                }
            }
        });
    }

    fn draw_process_toolbar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let mut changed = false;
            ui.label("view:");
            changed |= ui
                .selectable_value(&mut self.view_mode, ViewMode::Flat, "flat")
                .changed();
            changed |= ui
                .selectable_value(&mut self.view_mode, ViewMode::Tree, "tree")
                .changed();
            if self.view_mode == ViewMode::Tree {
                changed |= ui
                    .checkbox(&mut self.subtree_sort, "rank by subtree total")
                    .changed();
            }
            ui.separator();
            ui.label("sort:");
            let mut metric_changed = false;
            metric_changed |= ui
                .selectable_value(&mut self.sort_metric, SortMetric::Total, "CPU+GPU")
                .changed();
            metric_changed |= ui
                .selectable_value(&mut self.sort_metric, SortMetric::Cpu, "CPU%/core")
                .changed();
            metric_changed |= ui
                .selectable_value(&mut self.sort_metric, SortMetric::Gpu, "GPU%")
                .changed();
            metric_changed |= ui
                .selectable_value(&mut self.sort_window, SortWindow::Instant, "instant")
                .changed();
            metric_changed |= ui
                .selectable_value(
                    &mut self.sort_window,
                    SortWindow::Accumulated,
                    "accumulated (24h)",
                )
                .changed();
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
    }
}

/// The header's system thermal and limit line.
///
/// Every element is drawn unconditionally, healthy case included. A header
/// that only speaks up when something is wrong leaves "fine" and "we have
/// no idea" looking identical — and that ambiguity is exactly what makes a
/// throttling episode get read as a slow workload instead, since throttling
/// depresses every per-process CPU%/GPU% number on the screen at once.
fn thermal_line(ui: &mut egui::Ui, system: &SystemMetrics) {
    let cpu_temp = match (system.cpu_temp_c, &system.cpu_temp_source) {
        (Some(t), Some(src)) => format!("{t:.0}°C ({src})"),
        (Some(t), None) => format!("{t:.0}°C"),
        (None, _) => "temp n/a".to_string(),
    };
    let cpu_clock = system
        .cpu_clock_ratio
        .map(|r| format!("{:.0}% clock", r * 100.0))
        .unwrap_or_else(|| "clock n/a".to_string());
    ui.label(format!("CPU: {cpu_temp} · {cpu_clock}"));

    // Headroom, not raw temperature, is what actually decides whether a
    // part is about to be limited — TjMax differs by vendor and SKU.
    match system.cpu_thermal_headroom_c {
        Some(d) => {
            let color = if d <= 5.0 {
                BAD_COLOR
            } else if d <= 15.0 {
                WARN_COLOR
            } else {
                OK_COLOR
            };
            ui.colored_label(color, format!("{d:.0}°C to TjMax"));
        }
        None => {
            ui.weak("TjMax distance n/a").on_hover_text(
                "no source exposed a distance-to-TjMax reading, so remaining thermal \
                     headroom is unknown — not that there is plenty of it",
            );
        }
    }

    // Measured and inferred throttling get different words on purpose.
    // The MSR path reports that the thermal control circuit is engaged;
    // the fallback only notices low clocks and guesses. Rendering them
    // identically would invite acting on a guess as though it were a
    // measurement.
    match &system.cpu_throttle_reason {
        Some(reason) if system.cpu_throttle_confirmed => {
            ui.colored_label(BAD_COLOR, format!("⚠ THROTTLED — {reason}"))
                .on_hover_text("reported directly by the CPU's own thermal status register");
        }
        Some(reason) => {
            ui.colored_label(WARN_COLOR, format!("⚠ likely throttled — {reason}"))
                .on_hover_text(
                    "inferred from temperature and clock speed, not read from the CPU — \
                     install PawnIO and run rMon as Administrator for the hardware's own answer",
                );
        }
        None if system.cpu_temp_c.is_some() || system.cpu_clock_ratio.is_some() => {
            ui.colored_label(OK_COLOR, "not throttled");
        }
        None => {
            ui.colored_label(UNKNOWN_COLOR, "throttle state unknown")
                .on_hover_text(
                    "no CPU temperature or clock source is available, so rMon cannot tell \
                     whether this CPU is being limited",
                );
        }
    }

    // Sticky since-boot evidence. Shown only when nothing is happening
    // now, because during an active episode it adds nothing, and it must
    // never be mistaken for the current state — the bit latches at the
    // first event and stays set until reboot.
    if system.cpu_thermal_throttled_since_boot && !system.cpu_throttled {
        ui.weak("(has throttled since boot)").on_hover_text(
            "the CPU's sticky thermal log bit is set, so throttling happened at least once \
             since this machine booted — possibly in an episode shorter than rMon's sampling \
             tick. It cannot say when, and never clears until reboot.",
        );
    }

    for gpu in &system.gpus {
        ui.separator();
        let temp = gpu
            .temp_c
            .map(|t| format!("{t:.0}°C"))
            .unwrap_or_else(|| "n/a".to_string());
        ui.label(format!("{}: {temp}", gpu.name));
        if gpu.thermal_throttled {
            ui.colored_label(BAD_COLOR, "THERMAL THROTTLE");
        } else if !gpu.throttle_reasons.is_empty() {
            // NVML reports non-thermal limits too (power cap, reliability
            // voltage, idle clocks). They still cut clocks, so they still
            // distort the GPU% column — just for a different reason.
            ui.colored_label(
                WARN_COLOR,
                format!("limited: {}", gpu.throttle_reasons.join(", ")),
            );
        } else {
            ui.colored_label(OK_COLOR, "not throttled");
        }
    }
}

/// A one-column-per-second strip of recent system-wide throttle state,
/// oldest at the left, plus a summary of how much of the window was spent
/// limited.
///
/// The instantaneous badge in [`thermal_line`] can only report the tick
/// you happen to be looking at, and the episodes that matter most —
/// the ones that quietly depress a benchmark or stretch a compile — are
/// often over in seconds. This is the part that survives not watching.
fn draw_throttle_strip(ui: &mut egui::Ui, history: &ThrottleHistory) {
    ui.label("limits:");

    let width = 180.0;
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, 12.0), egui::Sense::hover());
    let cols = width as usize;
    // 0 = no sample covered this column, 1 = sampled but nothing could be
    // observed, 2 = observed and clear, 3 = CPU limited, 4 = GPU limited.
    let mut buckets = vec![0u8; cols];

    let window_secs = history.window().as_secs_f32().max(1.0);
    if let Some(last) = history.latest() {
        for t in history.ticks() {
            let age = (last.at - t.at).num_milliseconds() as f32 / 1000.0;
            // Placed by timestamp rather than by index so a gap in
            // sampling (app paused, machine asleep) reads as a gap
            // instead of silently compressing into a continuous run.
            let frac = 1.0 - (age / window_secs).clamp(0.0, 1.0);
            let idx = ((frac * (cols - 1) as f32) as usize).min(cols - 1);
            let state = if t.gpu == Some(true) {
                4
            } else if t.cpu == Some(true) {
                3
            } else if t.known() {
                2
            } else {
                1
            };
            buckets[idx] = buckets[idx].max(state);
        }
    }

    let painter = ui.painter();
    painter.rect_filled(rect, 3.0, ui.visuals().extreme_bg_color);
    for (i, state) in buckets.iter().enumerate() {
        let color = match state {
            1 => UNKNOWN_COLOR,
            2 => OK_COLOR.gamma_multiply(0.45),
            3 => WARN_COLOR,
            4 => BAD_COLOR,
            _ => continue,
        };
        let x = rect.left() + i as f32;
        painter.rect_filled(
            egui::Rect::from_min_size(egui::pos2(x, rect.top()), egui::vec2(1.0, rect.height())),
            0.0,
            color,
        );
    }

    let observed = format_duration(history.observed());
    match history.fraction_limited() {
        Some(f) if f > 0.0 => {
            ui.colored_label(
                WARN_COLOR,
                format!("throttled {:.0}% of last {observed}", f * 100.0),
            );
        }
        Some(_) => {
            ui.weak(format!("no throttling in last {observed}"));
        }
        None => {
            ui.colored_label(UNKNOWN_COLOR, "throttle history unavailable");
        }
    }

    response.on_hover_text(format!(
        "system-wide limiting over the last {}, oldest on the left — amber: CPU held back, \
         red: GPU thermal slowdown, grey: no thermal source that tick",
        format_duration(history.window()),
    ));
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

        // Rows show percent of one core; this total shows the share of
        // the whole machine, so it stays inside 0-100 and means what a
        // reader expects "total CPU" to mean.
        let cores = self
            .history
            .latest()
            .map_or(1, |s| s.logical_cores())
            .max(1);
        let total_cpu: f32 =
            self.rows.iter().map(|(_, p)| p.cpu_percent).sum::<f32>() / cores as f32;
        let total_gpu: f32 = self.rows.iter().map(|(_, p)| p.gpu_percent).sum();
        ui.label(format!(
            "{} processes shown   total CPU {:.1}% of {} cores   total GPU {:.1}%",
            self.rows.len(),
            total_cpu,
            cores,
            total_gpu
        ));
        ui.weak("keyboard: ↑/↓, PgUp/PgDn, Home/End or keypad · right-click a row for actions");
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
        enum ProcessContextAction {
            OpenFiles(u32),
            CopyInfo(u32),
            Explain(u32),
            Kill(u32),
        }
        let mut header_click = None;
        let mut clicked_pid = None;
        let mut toggle_pid = None;
        let mut context_action = None;

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
                    let label = if window == SortWindow::Accumulated {
                        "CPU"
                    } else {
                        // Percent of one core, not of the machine.
                        "CPU%/core"
                    };
                    if sort_header(ui, label, active, ascending) {
                        header_click = Some(HeaderClick::Cpu);
                    }
                });
                header.col(|ui| {
                    let active = cur_column == SortColumn::Metric && cur_metric == SortMetric::Gpu;
                    let label = if window == SortWindow::Accumulated {
                        "GPU"
                    } else {
                        "GPU%"
                    };
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
                                ui.colored_label(
                                    egui::Color32::from_rgb(140, 140, 150),
                                    "👻 exited",
                                );
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

                    let response = row.response();
                    response.context_menu(|ui| {
                        ui.set_min_width(180.0);
                        let is_live = !tree_ghosts.contains(&p.pid);
                        if ui
                            .add_enabled(is_live, egui::Button::new("📂 Open files"))
                            .on_disabled_hover_text(
                                "this is an exited process reconstructed from history",
                            )
                            .clicked()
                        {
                            context_action = Some(ProcessContextAction::OpenFiles(p.pid));
                            ui.close();
                        }
                        if ui.button("📋 Copy process info").clicked() {
                            context_action = Some(ProcessContextAction::CopyInfo(p.pid));
                            ui.close();
                        }
                        if ui
                            .add_enabled(is_live, egui::Button::new("✨ Explain / assess"))
                            .clicked()
                        {
                            context_action = Some(ProcessContextAction::Explain(p.pid));
                            ui.close();
                        }
                        ui.separator();
                        if ui
                            .add_enabled(
                                is_live,
                                egui::Button::new(
                                    egui::RichText::new("⛔ Kill process").color(BAD_COLOR),
                                ),
                            )
                            .on_disabled_hover_text(
                                "this is an exited process reconstructed from history",
                            )
                            .clicked()
                        {
                            context_action = Some(ProcessContextAction::Kill(p.pid));
                            ui.close();
                        }
                    });
                    if response.clicked()
                        || response.secondary_clicked()
                        || response.context_menu_opened()
                    {
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

        if let Some(action) = context_action {
            match action {
                ProcessContextAction::OpenFiles(pid) => {
                    self.selected_pid = Some(pid);
                    self.files = Some(FilesState::start(pid));
                }
                ProcessContextAction::CopyInfo(pid) => {
                    self.selected_pid = Some(pid);
                    if let Some(text) = self.copy_info_text(pid) {
                        ui.ctx().copy_text(text);
                    }
                }
                ProcessContextAction::Explain(pid) => {
                    self.selected_pid = Some(pid);
                    let name = self
                        .rows
                        .iter()
                        .find(|(_, process)| process.pid == pid)
                        .map(|(_, process)| process.name.clone())
                        .unwrap_or_else(|| "unknown".to_string());
                    self.ask_process_diagnosis(pid, &name);
                }
                ProcessContextAction::Kill(pid) => {
                    self.selected_pid = Some(pid);
                    match rmon_core::kill_process(pid) {
                        Ok(()) => {
                            self.kill_error = None;
                            self.selected_pid = None;
                        }
                        Err(error) => self.kill_error = Some(format!("{error:#}")),
                    }
                }
            }
        }
    }

    fn draw_detail_info(&mut self, ui: &mut egui::Ui) {
        // Pin the width explicitly: without it, the unwrapped file-path
        // labels in the "Open files" list (nested `ScrollArea`s default to
        // growing to fit their content on the cross axis) balloon this
        // panel's measured size every frame instead of wrapping.
        ui.set_max_width(ui.available_width());
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
                .add_enabled(
                    !self.analyze.running(),
                    egui::Button::new("✨ explain / assess"),
                )
                .clicked()
            {
                self.ask_process_diagnosis(pid, &name);
            }
            if ui
                .add(egui::Button::new(
                    egui::RichText::new("⛔ kill process")
                        .color(egui::Color32::from_rgb(235, 87, 87)),
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
            let mut handles_text = proc_info
                .as_ref()
                .and_then(|p| p.handle_count)
                .map(|n| n.to_string())
                .unwrap_or_else(|| "—".to_string());
            if let Some(s) = self.trend_for(pid).and_then(|t| t.handles)
                && s.span_secs >= 120.0
                && s.slope_per_hour.abs() >= 1.0
            {
                handles_text.push_str(&format!(
                    "  ({:+.0}/h over {})",
                    s.slope_per_hour,
                    format_duration(Duration::from_secs_f64(s.span_secs)),
                ));
            }
            ui.label(handles_text);
            ui.add_space(16.0);
            ui.weak("memory:");
            ui.label(
                proc_info
                    .as_ref()
                    .and_then(|p| p.mem_bytes)
                    .map(format_bytes)
                    .unwrap_or_else(|| "—".to_string()),
            );
        });
        if let Some(link) = self
            .programs
            .attribution
            .links
            .iter()
            .find(|link| link.pid == pid)
        {
            let name_for = |id: &str| {
                self.programs
                    .scan
                    .as_ref()
                    .and_then(|scan| scan.programs.iter().find(|program| program.id == id))
                    .map(|program| program.name.as_str())
            };
            if let Some(program) = link.direct_program_id.as_deref().and_then(name_for) {
                ui.label(format!("installed program: {program}"));
            } else {
                ui.weak("installed program: not attributed by executable path");
            }
            if let Some(launcher) = link.launcher_program_id.as_deref().and_then(name_for) {
                ui.label(format!("launched under: {launcher}"));
            }
        }
        if let Some(path) = proc_info
            .as_ref()
            .and_then(|process| process.executable_path.as_deref())
        {
            ui.weak("executable:");
            ui.label(egui::RichText::new(path).monospace().small());
        }
        if let Some(cmd) = proc_info.as_ref().and_then(|p| p.command_line.clone()) {
            ui.weak("command line:");
            ui.label(egui::RichText::new(cmd).monospace().small());
        }
        if let Some(process) = &proc_info {
            let reasons = process_attention_reasons(process);
            if reasons.is_empty() {
                ui.weak("no obvious path-based warning (not a security verification)");
            } else {
                for reason in reasons {
                    ui.colored_label(WARN_COLOR, format!("⚠ {reason}"));
                }
            }
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

        if let Some(line) = &now_line {
            ui.label(line);
        }
        ui.label(accum_line);
        if let Some(verdict) = self.trend_for(pid).and_then(|t| t.verdict.clone()) {
            ui.colored_label(egui::Color32::from_rgb(220, 120, 0), format!("⚠ {verdict}"));
        }
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
    }

    fn draw_detail_graph(&mut self, ui: &mut egui::Ui) {
        let Some(pid) = self.selected_pid else {
            return;
        };
        let series = self.history.series_for_pid(pid);
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
            .include_y(0.0)
            .show(ui, |plot_ui| {
                plot_ui.line(Line::new("CPU%", PlotPoints::new(cpu_points)));
                plot_ui.line(Line::new("GPU%", PlotPoints::new(gpu_points)));
            });
    }

    /// Full-width panel listing trend-flagged processes: possible handle/
    /// memory leaks (sustained monotonic growth over ≥30 min) and idle
    /// burners (large accumulated CPU while currently near-idle). All of it
    /// is heuristic over this session's in-memory history — a flagged
    /// process is a suspect worth looking at, not a confirmed leak.
    fn draw_suspects(&mut self, ui: &mut egui::Ui) {
        ui.heading("Leak & idle suspects");
        ui.weak(format!(
            "based on {} of observed history (resets when rMon restarts)",
            format_duration(self.history.accum_window())
        ));
        ui.add_space(8.0);

        let suspects: Vec<rmon_core::trends::ProcessTrend> = self
            .trends
            .iter()
            .filter(|t| t.flagged())
            .cloned()
            .collect();
        if suspects.is_empty() {
            ui.label("Nothing flagged right now.");
            ui.weak(
                "Leak detection needs ≥30 minutes of sustained, mostly-monotonic growth in a \
                 process's handle count or working set before it flags anything; idle burners \
                 need ≥5 core-minutes of accumulated CPU. Leave rMon running and check back.",
            );
            return;
        }

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for t in &suspects {
                    let selected = self.selected_pid == Some(t.pid);
                    let resp = ui.group(|ui| {
                        ui.horizontal(|ui| {
                            let mut kinds = Vec::new();
                            if t.handle_leak_suspect {
                                kinds.push("handle leak?");
                            }
                            if t.mem_leak_suspect {
                                kinds.push("memory leak?");
                            }
                            if t.idle_burner {
                                kinds.push("idle burner");
                            }
                            ui.label(
                                egui::RichText::new(format!("{} ({})", t.name, t.pid)).strong(),
                            );
                            ui.colored_label(
                                egui::Color32::from_rgb(220, 120, 0),
                                kinds.join(" · "),
                            );
                            if selected {
                                ui.weak("(selected)");
                            }
                        });
                        if let Some(v) = &t.verdict {
                            ui.label(egui::RichText::new(v).small());
                        }
                    });
                    if resp.response.interact(egui::Sense::click()).clicked() {
                        self.selected_pid = Some(t.pid);
                        self.scroll_to_selected = true;
                    }
                }
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

        ui.heading("Search all processes");
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            ui.label("query:");
            ui.text_edit_singleline(&mut self.search.query);
        });
        ui.horizontal(|ui| {
            let scanning = self.search.scanning();
            if ui
                .add_enabled(
                    !scanning,
                    egui::Button::new("🔍 scan open files (all processes)"),
                )
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
                ui.weak(format!(
                    "{}/{} processes scanned",
                    self.search.scanned, self.search.total
                ));
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
                    ui.label(
                        egui::RichText::new(format!(
                            "{:<3} {}:{:<6} pid {} ({})  {}",
                            p.protocol.as_str(),
                            p.local_addr,
                            p.local_port,
                            p.pid,
                            name,
                            p.state.map(|s| s.as_str()).unwrap_or("-"),
                        ))
                        .small()
                        .monospace(),
                    );
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
                            egui::RichText::new(format!("[{} ({})] {path}", entry.pid, name))
                                .small(),
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
        ui.heading("Recently exited processes");
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
                            e.ppid
                                .map(|v| v.to_string())
                                .unwrap_or_else(|| "-".to_string()),
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

    /// rMon's own SensorHub is always shown first. HWiNFO's supplemental
    /// tree is read only after an explicit, session-only opt-in; automatic
    /// HWiNFO access is otherwise limited to the necessary CPU-temperature
    /// fallback when neither direct CPU path can answer.
    fn draw_hardware(&mut self, ui: &mut egui::Ui) {
        ui.heading("Hardware sensors");
        ui.add_space(8.0);
        self.draw_direct_sensors(ui);
        ui.add_space(8.0);

        ui.label(egui::RichText::new("Supplemental HWiNFO sensors").strong());
        let changed = ui
            .checkbox(
                &mut self.hwinfo_sensors_enabled,
                "read HWiNFO's exported sensor tree for this session",
            )
            .changed();
        if changed {
            self.last_hwinfo_sensor_read = None;
            if !self.hwinfo_sensors_enabled {
                self.hwinfo_sensor_groups.clear();
                self.hwinfo_sensor_rx = None;
            }
        }
        ui.weak(
            "Off by default: rMon uses its own SensorHub above. Independently, HWiNFO may be \
             used as a CPU-temperature fallback only when direct MSR and Super I/O CPU sensors \
             are unavailable.",
        );
        if !self.hwinfo_sensors_enabled {
            return;
        }

        let received = self.hwinfo_sensor_rx.as_ref().map(mpsc::Receiver::try_recv);
        match received {
            Some(Ok(groups)) => {
                self.hwinfo_sensor_groups = groups;
                self.hwinfo_sensor_rx = None;
            }
            Some(Err(mpsc::TryRecvError::Disconnected)) => {
                self.hwinfo_sensor_rx = None;
            }
            _ => {}
        }

        let due = self
            .last_hwinfo_sensor_read
            .is_none_or(|last| last.elapsed() >= Duration::from_secs(2));
        if due && self.hwinfo_sensor_rx.is_none() {
            let (tx, rx) = mpsc::channel();
            self.hwinfo_sensor_rx = Some(rx);
            self.last_hwinfo_sensor_read = Some(Instant::now());
            std::thread::spawn(move || {
                let _ = tx.send(rmon_core::read_all_sensors());
            });
        }
        if self.hwinfo_sensor_groups.is_empty() {
            if self.hwinfo_sensor_rx.is_some() {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.weak("reading HWiNFO's export…");
                });
                return;
            }
            ui.weak(
                "No HWiNFO sensor data — HWiNFO must be running with either \"Support of Value \
                 Sensors Bank\" or \"Shared Memory Support\" enabled. Shared memory exposes every \
                 sensor; the Value Sensors Bank only mirrors its configured summary list.",
            );
            return;
        }

        egui::ScrollArea::vertical()
            .id_salt("hardware-sensors")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for group in &self.hwinfo_sensor_groups {
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
            ui.heading("Hardware health");
            let scanning = self.health.as_ref().is_some_and(HealthState::scanning);
            if ui
                .add_enabled(!scanning, egui::Button::new("🔄 rescan"))
                .clicked()
            {
                self.health = Some(HealthState::start(
                    DEFAULT_WHEA_LOOKBACK_DAYS,
                    DEFAULT_WHEA_MAX_EVENTS,
                ));
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
                ui.weak("querying the System event log for WHEA entries…");
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
        ui.heading("Settings");
        ui.add_space(8.0);

        ui.group(|ui| {
            ui.label(egui::RichText::new("Analyze (LLM)").strong());
            ui.weak("Credentials for the analyze tab's Passiv gateway agent.");
            ui.add_space(4.0);
            if self.credentials.draw(ui) {
                self.analyze.refresh_availability();
            }
        });

        ui.add_space(8.0);

        ui.group(|ui| {
            ui.label(egui::RichText::new("Sampling").strong());
            ui.weak(
                "One sample walks every process and thread on the machine, so what it \
                 costs depends on the machine. On automatic, rMon spreads samples out \
                 far enough to keep its own CPU use under a twentieth of one core.",
            );
            ui.add_space(4.0);

            let mut choice = self.sampler.choice();
            egui::ComboBox::from_label("interval")
                .selected_text(choice.label())
                .show_ui(ui, |ui| {
                    for option in IntervalChoice::ALL {
                        ui.selectable_value(&mut choice, option, option.label());
                    }
                });
            if choice != self.sampler.choice() {
                self.sampler.set_choice(choice);
            }

            ui.add_space(4.0);
            if let Some(cost) = self.sampler.last_cost() {
                let interval = self.sampler.interval();
                let duty = cost.as_secs_f64() / interval.as_secs_f64() * 100.0;
                ui.label(format!(
                    "A sample costs {:.0}ms here; sampling every {:.1}s ≈ {duty:.1}% of one core.",
                    cost.as_secs_f64() * 1000.0,
                    interval.as_secs_f64(),
                ));
                if !self.window_visible {
                    ui.weak("The window is hidden, so sampling is at its background rate.");
                }
            } else {
                ui.weak("Waiting for the first sample...");
            }
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
            if ui
                .checkbox(&mut self.autostart_enabled, "start with Windows")
                .changed()
            {
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

    let widget =
        |bg: egui::Color32, fg: egui::Color32, stroke: egui::Color32| egui::style::WidgetVisuals {
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
