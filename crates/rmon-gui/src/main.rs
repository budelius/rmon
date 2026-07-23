use std::time::{Duration, Instant};

use eframe::egui;
use egui_plot::{Legend, Line, Plot, PlotPoints};
use rmon_core::{GpuSource, ProcessSample, RollingHistory, Sampler, Store};

const RETAIN: Duration = Duration::from_secs(300);
const TICK: Duration = Duration::from_millis(1000);

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortMode {
    Cpu,
    Gpu,
    Total,
}

struct RmonApp {
    sampler: Sampler,
    history: RollingHistory,
    has_gpu_source: bool,
    sort_mode: SortMode,
    filter: String,
    rows: Vec<ProcessSample>,
    selected_pid: Option<u32>,
    last_tick: Instant,

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
            filter: String::new(),
            rows: Vec::new(),
            selected_pid: None,
            last_tick: Instant::now() - TICK,
            recording: false,
            db_path: "rmon.sqlite".to_string(),
            store: None,
            record_error: None,
        }
    }

    fn tick(&mut self) {
        let snapshot = self.sampler.sample();

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
        let mut rows: Vec<ProcessSample> = snapshot
            .processes
            .iter()
            .filter(|p| filter.is_empty() || p.name.to_lowercase().contains(&filter))
            .cloned()
            .collect();
        rows.sort_by(|a, b| {
            let key = |p: &ProcessSample| match self.sort_mode {
                SortMode::Cpu => p.cpu_percent,
                SortMode::Gpu => p.gpu_percent,
                SortMode::Total => p.cpu_percent + p.gpu_percent,
            };
            key(b).partial_cmp(&key(a)).unwrap_or(std::cmp::Ordering::Equal)
        });
        self.rows = rows;

        if let Some(pid) = self.selected_pid
            && !self.rows.iter().any(|p| p.pid == pid)
        {
            self.selected_pid = None;
        }
        if self.selected_pid.is_none() {
            self.selected_pid = self.rows.first().map(|p| p.pid);
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
                ui.label("sort:");
                ui.selectable_value(&mut self.sort_mode, SortMode::Total, "CPU+GPU");
                ui.selectable_value(&mut self.sort_mode, SortMode::Cpu, "CPU%");
                ui.selectable_value(&mut self.sort_mode, SortMode::Gpu, "GPU%");
                ui.separator();
                ui.label("filter:");
                if ui.text_edit_singleline(&mut self.filter).changed() {
                    self.resort();
                }
                ui.separator();
                ui.checkbox(&mut self.recording, "record to SQLite");
                ui.add_enabled(
                    !self.recording,
                    egui::TextEdit::singleline(&mut self.db_path).desired_width(160.0),
                );
                if let Some(err) = &self.record_error {
                    ui.colored_label(egui::Color32::RED, err);
                }
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

impl RmonApp {
    fn draw_table(&mut self, ui: &mut egui::Ui) {
        use egui_extras::{Column, TableBuilder};

        let total_cpu: f32 = self.rows.iter().map(|p| p.cpu_percent).sum();
        let total_gpu: f32 = self.rows.iter().map(|p| p.gpu_percent).sum();
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
            .column(Column::exact(70.0))
            .column(Column::exact(70.0))
            .column(Column::exact(60.0))
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
                body.rows(18.0, self.rows.len(), |mut row| {
                    let p = &self.rows[row.index()];
                    let selected = self.selected_pid == Some(p.pid);
                    row.set_selected(selected);

                    row.col(|ui| {
                        if ui.selectable_label(selected, p.pid.to_string()).clicked() {
                            clicked_pid = Some(p.pid);
                        }
                    });
                    row.col(|ui| {
                        ui.label(&p.name);
                    });
                    row.col(|ui| {
                        ui.label(format!("{:.1}", p.cpu_percent));
                    });
                    row.col(|ui| {
                        ui.label(format!("{:.1}", p.gpu_percent));
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
            .find(|p| p.pid == pid)
            .map(|p| p.name.as_str())
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

        if let (Some(last), Some(latest)) = (series.last(), self.rows.iter().find(|p| p.pid == pid)) {
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
        viewport: egui::ViewportBuilder::default().with_inner_size([1000.0, 640.0]),
        ..Default::default()
    };
    eframe::run_native(
        "rMon",
        options,
        Box::new(|_cc| Ok(Box::new(RmonApp::new()))),
    )
}
