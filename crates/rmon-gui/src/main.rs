#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod autostart;
mod icon;
mod tray;

use std::sync::mpsc;
use std::time::{Duration, Instant};

use eframe::egui;
use egui_plot::{Legend, Line, Plot, PlotPoints};
use rmon_core::{
    build_tree, list_open_files, GpuSource, OpenFilesScan, ProcessSample, RollingHistory, Sampler,
    Store, SystemMetrics,
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
    name: String,
    status: FilesStatus,
    search: String,
}

impl FilesState {
    fn start(pid: u32, name: String) -> Self {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let result = list_open_files(pid).map_err(|e| e.to_string());
            let _ = tx.send(result);
        });
        Self {
            pid,
            name,
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
    rows: Vec<(usize, ProcessSample)>,
    selected_pid: Option<u32>,
    scroll_to_selected: bool,
    last_tick: Instant,
    system: SystemMetrics,
    files: Option<FilesState>,

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
            rows: Vec::new(),
            selected_pid: None,
            scroll_to_selected: false,
            last_tick: Instant::now() - TICK,
            system: SystemMetrics::default(),
            files: None,
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
        let filter = self.filter.to_lowercase();
        let filtered: Vec<ProcessSample> = snapshot
            .processes
            .iter()
            .filter(|p| filter.is_empty() || p.name.to_lowercase().contains(&filter))
            .cloned()
            .collect();

        let history = &self.history;
        let metric = self.sort_metric;
        let window = self.sort_window;
        let column = self.sort_column;
        let ascending = self.sort_ascending;

        self.rows = match self.view_mode {
            ViewMode::Flat => {
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
                // build_tree always ranks descending by key; negate to flip to ascending.
                let sign = if ascending { -1.0 } else { 1.0 };
                let key = |p: &ProcessSample| sign * score(history, metric, window, p);
                build_tree(&filtered, key, self.subtree_sort)
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
        ui.ctx().request_repaint_after(Duration::from_millis(200));

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
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.heading("rMon");
                ui.label("live process CPU/GPU monitor");
                if !self.has_gpu_source {
                    ui.colored_label(egui::Color32::from_rgb(220, 120, 0), "no GPU data source found");
                }
            });
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
                ui.checkbox(&mut self.recording, "record to SQLite");
                ui.add_enabled(
                    !self.recording,
                    egui::TextEdit::singleline(&mut self.db_path).desired_width(160.0),
                );
                if let Some(err) = &self.record_error {
                    ui.colored_label(egui::Color32::RED, err);
                }
                ui.separator();
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
            });
            ui.add_space(4.0);
        });

        egui::Panel::right("detail").default_size(420.0).show(ui, |ui| {
            self.draw_detail(ui);
        });

        egui::CentralPanel::default().show(ui, |ui| {
            if self.files.is_some() {
                self.draw_files(ui);
            } else {
                self.draw_table(ui);
            }
        });
    }
}

fn thermal_line(ui: &mut egui::Ui, system: &SystemMetrics) {
    let cpu_temp = system
        .cpu_temp_c
        .map(|t| format!("{t:.0}°C"))
        .unwrap_or_else(|| "n/a".to_string());
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
        format!("{label} {}", if ascending { "\u{25b2}" } else { "\u{25bc}" })
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

        enum HeaderClick {
            Pid,
            Name,
            Cpu,
            Gpu,
            Src,
        }
        let mut header_click = None;
        let mut clicked_pid = None;

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
                    if sort_header(ui, "CPU%", active, ascending) {
                        header_click = Some(HeaderClick::Cpu);
                    }
                });
                header.col(|ui| {
                    let active = cur_column == SortColumn::Metric && cur_metric == SortMetric::Gpu;
                    if sort_header(ui, "GPU%", active, ascending) {
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
                body.rows(20.0, rows.len(), |mut row| {
                    let (depth, p) = &rows[row.index()];
                    let selected = selected_pid == Some(p.pid);
                    row.set_selected(selected);

                    row.col(|ui| {
                        ui.label(p.pid.to_string());
                    });
                    row.col(|ui| {
                        ui.horizontal(|ui| {
                            if *depth > 0 {
                                ui.add_space(*depth as f32 * 14.0);
                                ui.weak(">");
                            }
                            ui.label(&p.name);
                        });
                    });
                    row.col(|ui| {
                        let tail = history.tail_for_pid(p.pid, SPARK_POINTS);
                        ui.horizontal(|ui| {
                            ui.label(format!("{:>5.1}", p.cpu_percent));
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
                            ui.label(format!("{:>5.1}", p.gpu_percent));
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
        let name = self
            .rows
            .iter()
            .find(|(_, p)| p.pid == pid)
            .map(|(_, p)| p.name.clone())
            .unwrap_or_else(|| "?".to_string());
        ui.horizontal(|ui| {
            ui.heading(format!("{name} ({pid})"));
            if ui.button("📂 open files").clicked() {
                self.files = Some(FilesState::start(pid, name.clone()));
            }
        });

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

        if let (Some(last), Some((_, latest))) =
            (series.last(), self.rows.iter().find(|(_, p)| p.pid == pid))
        {
            ui.label(format!(
                "now: CPU {:.1}%  GPU {:.1}%   ({} samples over {:.0}s)",
                latest.cpu_percent,
                latest.gpu_percent,
                series.len(),
                (last.0 - t0).num_milliseconds() as f64 / 1000.0
            ));
        }
        let (cpu_accum, gpu_accum) = self.history.accumulated(pid);
        ui.label(format!(
            "accumulated: CPU {} · GPU {}  (over {})",
            format_core_time(cpu_accum),
            format_core_time(gpu_accum),
            format_duration(self.history.accum_window()),
        ));

        Plot::new(format!("history-{pid}"))
            .legend(Legend::default())
            .height(260.0)
            .view_aspect(1.4)
            .include_y(0.0)
            .show(ui, |plot_ui| {
                plot_ui.line(Line::new("CPU%", PlotPoints::new(cpu_points)));
                plot_ui.line(Line::new("GPU%", PlotPoints::new(gpu_points)));
            });
    }

    fn draw_files(&mut self, ui: &mut egui::Ui) {
        let mut go_back = false;
        let mut rescan = false;

        if let Some(fs) = self.files.as_mut() {
            ui.horizontal(|ui| {
                if ui.button("← back to process list").clicked() {
                    go_back = true;
                }
                ui.heading(format!("Open files: {} ({})", fs.name, fs.pid));
                if !matches!(fs.status, FilesStatus::Scanning(_)) && ui.button("rescan").clicked() {
                    rescan = true;
                }
            });

            match &fs.status {
                FilesStatus::Scanning(_) => {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(
                            "scanning... (walks the process's kernel handle table; can take a few seconds)",
                        );
                    });
                }
                FilesStatus::Done(scan) => {
                    ui.label(format!(
                        "{} open file(s)   ({} handles scanned, {} timed out)",
                        scan.paths.len(),
                        scan.handles_seen,
                        scan.timed_out
                    ));
                }
                FilesStatus::Error(e) => {
                    ui.colored_label(egui::Color32::RED, format!("error: {e}"));
                }
            }

            ui.horizontal(|ui| {
                ui.label("search:");
                ui.text_edit_singleline(&mut fs.search);
            });
            ui.separator();

            let paths = fs.filtered_paths();
            let row_height = ui.text_style_height(&egui::TextStyle::Body);
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show_rows(ui, row_height, paths.len(), |ui, range| {
                    for i in range {
                        ui.label(paths[i]);
                    }
                });
        }

        if go_back {
            self.files = None;
        } else if rescan
            && let Some(fs) = &self.files
        {
            let pid = fs.pid;
            let name = fs.name.clone();
            self.files = Some(FilesState::start(pid, name));
        }
    }
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
        Box::new(|_cc| Ok(Box::new(RmonApp::new()))),
    )
}
