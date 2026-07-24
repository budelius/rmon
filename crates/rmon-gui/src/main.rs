use std::sync::mpsc;
use std::time::{Duration, Instant};

use eframe::egui;
use egui_plot::{Legend, Line, Plot, PlotPoints};
use rmon_core::{
    build_tree, list_open_files, GpuSource, OpenFilesScan, ProcessSample, RollingHistory, Sampler,
    Store, SystemMetrics,
};

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
    subtree_sort: bool,
    view_mode: ViewMode,
    filter: String,
    rows: Vec<(usize, ProcessSample)>,
    selected_pid: Option<u32>,
    last_tick: Instant,
    system: SystemMetrics,
    files: Option<FilesState>,

    recording: bool,
    db_path: String,
    store: Option<Store>,
    record_error: Option<String>,
}

impl RmonApp {
    fn new() -> Self {
        let mut sampler = Sampler::new();
        let has_gpu_source = sampler.has_gpu_source();
        sampler.sample(); // warm up
        Self {
            sampler,
            history: RollingHistory::new(RETAIN),
            has_gpu_source,
            sort_metric: SortMetric::Total,
            sort_window: SortWindow::Instant,
            subtree_sort: false,
            view_mode: ViewMode::Flat,
            filter: String::new(),
            rows: Vec::new(),
            selected_pid: None,
            last_tick: Instant::now() - TICK,
            system: SystemMetrics::default(),
            files: None,
            recording: false,
            db_path: "rmon.sqlite".to_string(),
            store: None,
            record_error: None,
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
                    }
                }
            }
            if let Some(store) = self.store.as_mut()
                && let Err(e) = store.insert_snapshot(&snapshot)
            {
                self.record_error = Some(format!("write failed: {e:#}"));
                self.recording = false;
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
        let key = |p: &ProcessSample| score(history, metric, window, p);

        self.rows = match self.view_mode {
            ViewMode::Flat => {
                let mut v = filtered;
                v.sort_by(|a, b| key(b).partial_cmp(&key(a)).unwrap_or(std::cmp::Ordering::Equal));
                v.into_iter().map(|p| (0, p)).collect()
            }
            ViewMode::Tree => build_tree(&filtered, key, self.subtree_sort),
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
                changed |= ui.selectable_value(&mut self.sort_metric, SortMetric::Total, "CPU+GPU").changed();
                changed |= ui.selectable_value(&mut self.sort_metric, SortMetric::Cpu, "CPU%").changed();
                changed |= ui.selectable_value(&mut self.sort_metric, SortMetric::Gpu, "GPU%").changed();
                changed |= ui.selectable_value(&mut self.sort_window, SortWindow::Instant, "instant").changed();
                changed |= ui.selectable_value(&mut self.sort_window, SortWindow::Accumulated, "accumulated (24h)").changed();
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

        let mut clicked_pid = None;
        TableBuilder::new(ui)
            .striped(true)
            .column(Column::exact(70.0))
            .column(Column::remainder().at_least(120.0))
            .column(Column::exact(140.0))
            .column(Column::exact(140.0))
            .column(Column::exact(50.0))
            .header(20.0, |mut header| {
                header.col(|ui| {
                    ui.strong("PID");
                });
                header.col(|ui| {
                    ui.strong("Name");
                });
                header.col(|ui| {
                    ui.strong("CPU%");
                });
                header.col(|ui| {
                    ui.strong("GPU%");
                });
                header.col(|ui| {
                    ui.strong("Src");
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
                        if ui.selectable_label(selected, p.pid.to_string()).clicked() {
                            clicked_pid = Some(p.pid);
                        }
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
                        let src = match p.gpu_source {
                            GpuSource::Nvml => "nvml",
                            GpuSource::Pdh => "pdh",
                            GpuSource::Unavailable => "-",
                        };
                        ui.label(src);
                    });
                });
            });

        if let Some(pid) = clicked_pid {
            self.selected_pid = Some(pid);
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
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1200.0, 700.0]),
        ..Default::default()
    };
    eframe::run_native(
        "rMon",
        options,
        Box::new(|_cc| Ok(Box::new(RmonApp::new()))),
    )
}
