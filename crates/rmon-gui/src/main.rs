use std::time::{Duration, Instant};

use eframe::egui;
use egui_plot::{Legend, Line, Plot, PlotPoints};
use rmon_core::{build_tree, GpuSource, ProcessSample, RollingHistory, Sampler, Store, SystemMetrics};

const RETAIN: Duration = Duration::from_secs(300);
const TICK: Duration = Duration::from_millis(1000);
const SPARK_POINTS: usize = 30;

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortMode {
    Cpu,
    Gpu,
    Total,
}

impl SortMode {
    fn key(self, p: &ProcessSample) -> f32 {
        match self {
            SortMode::Cpu => p.cpu_percent,
            SortMode::Gpu => p.gpu_percent,
            SortMode::Total => p.cpu_percent + p.gpu_percent,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ViewMode {
    Flat,
    Tree,
}

struct RmonApp {
    sampler: Sampler,
    history: RollingHistory,
    has_gpu_source: bool,
    sort_mode: SortMode,
    view_mode: ViewMode,
    filter: String,
    rows: Vec<(usize, ProcessSample)>,
    selected_pid: Option<u32>,
    last_tick: Instant,
    system: SystemMetrics,

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
            sort_mode: SortMode::Total,
            view_mode: ViewMode::Flat,
            filter: String::new(),
            rows: Vec::new(),
            selected_pid: None,
            last_tick: Instant::now() - TICK,
            system: SystemMetrics::default(),
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

        self.rows = match self.view_mode {
            ViewMode::Flat => {
                let mut v = filtered;
                v.sort_by(|a, b| {
                    self.sort_mode
                        .key(b)
                        .partial_cmp(&self.sort_mode.key(a))
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
                v.into_iter().map(|p| (0, p)).collect()
            }
            ViewMode::Tree => build_tree(&filtered, |p| self.sort_mode.key(p)),
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
                ui.separator();
                ui.label("sort:");
                changed |= ui.selectable_value(&mut self.sort_mode, SortMode::Total, "CPU+GPU").changed();
                changed |= ui.selectable_value(&mut self.sort_mode, SortMode::Cpu, "CPU%").changed();
                changed |= ui.selectable_value(&mut self.sort_mode, SortMode::Gpu, "GPU%").changed();
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
            });
            ui.add_space(4.0);
        });

        egui::Panel::right("detail").default_size(420.0).show(ui, |ui| {
            self.draw_detail(ui);
        });

        egui::CentralPanel::default().show(ui, |ui| {
            self.draw_table(ui);
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

    fn draw_detail(&self, ui: &mut egui::Ui) {
        let Some(pid) = self.selected_pid else {
            ui.label("Select a process to see its history.");
            return;
        };
        let name = self
            .rows
            .iter()
            .find(|(_, p)| p.pid == pid)
            .map(|(_, p)| p.name.as_str())
            .unwrap_or("?");
        ui.heading(format!("{name} ({pid})"));

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
