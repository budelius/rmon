use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Axis, Block, Borders, Cell, Chart, Dataset, GraphType, Row, Table, TableState,
};
use ratatui::Frame;
use rmon_core::{build_tree, GpuSource, ProcessSample, RollingHistory, Sampler, SystemMetrics};

const RETAIN: Duration = Duration::from_secs(300);
const TICK: Duration = Duration::from_millis(1000);
const SPARK_POINTS: usize = 12;
const BLOCKS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortMode {
    Cpu,
    Gpu,
    Total,
}

impl SortMode {
    fn label(self) -> &'static str {
        match self {
            SortMode::Cpu => "CPU%",
            SortMode::Gpu => "GPU%",
            SortMode::Total => "CPU%+GPU%",
        }
    }

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

/// One rendered row: tree depth (0 for flat view) plus the process it shows.
type TreeRow = (usize, ProcessSample);

struct App {
    sampler: Sampler,
    history: RollingHistory,
    sort_mode: SortMode,
    view_mode: ViewMode,
    search: String,
    search_active: bool,
    rows: Vec<TreeRow>,
    table_state: TableState,
    selected_pid: Option<u32>,
    has_gpu_source: bool,
    system: SystemMetrics,
}

impl App {
    fn new() -> Self {
        let mut sampler = Sampler::new();
        let has_gpu_source = sampler.has_gpu_source();
        // Warm up so the first rendered frame isn't all zeroes.
        sampler.sample();
        let mut table_state = TableState::default();
        table_state.select(Some(0));
        Self {
            sampler,
            history: RollingHistory::new(RETAIN),
            sort_mode: SortMode::Total,
            view_mode: ViewMode::Flat,
            search: String::new(),
            search_active: false,
            rows: Vec::new(),
            table_state,
            selected_pid: None,
            has_gpu_source,
            system: SystemMetrics::default(),
        }
    }

    fn tick(&mut self) {
        let snapshot = self.sampler.sample();
        self.system = snapshot.system.clone();
        self.history.push(snapshot);
        self.resort();
    }

    fn resort(&mut self) {
        let Some(snapshot) = self.history.latest() else {
            return;
        };
        let filter = self.search.to_lowercase();
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

        // Keep the same process selected across re-sorts when possible.
        if let Some(pid) = self.selected_pid
            && let Some(idx) = self.rows.iter().position(|(_, p)| p.pid == pid)
        {
            self.table_state.select(Some(idx));
            return;
        }
        let idx = self
            .table_state
            .selected()
            .unwrap_or(0)
            .min(self.rows.len().saturating_sub(1));
        self.table_state.select(Some(idx));
        self.selected_pid = self.rows.get(idx).map(|(_, p)| p.pid);
    }

    fn select_next(&mut self) {
        if self.rows.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) if i + 1 < self.rows.len() => i + 1,
            Some(_) => 0,
            None => 0,
        };
        self.table_state.select(Some(i));
        self.selected_pid = self.rows.get(i).map(|(_, p)| p.pid);
    }

    fn select_prev(&mut self) {
        if self.rows.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(0) | None => self.rows.len() - 1,
            Some(i) => i - 1,
        };
        self.table_state.select(Some(i));
        self.selected_pid = self.rows.get(i).map(|(_, p)| p.pid);
    }
}

fn sparkline(values: &[f32]) -> String {
    if values.is_empty() {
        return String::new();
    }
    let max = values.iter().cloned().fold(0.0f32, f32::max).max(1.0);
    values
        .iter()
        .map(|&v| {
            let idx = ((v / max) * (BLOCKS.len() as f32 - 1.0))
                .round()
                .clamp(0.0, (BLOCKS.len() - 1) as f32) as usize;
            BLOCKS[idx]
        })
        .collect()
}

fn main() -> Result<()> {
    let mut terminal = ratatui::init();
    let result = run(&mut terminal);
    ratatui::restore();
    result
}

fn run(terminal: &mut ratatui::DefaultTerminal) -> Result<()> {
    let mut app = App::new();
    app.tick();
    let mut last_tick = Instant::now();

    loop {
        let timeout = TICK.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            if app.search_active {
                match key.code {
                    KeyCode::Enter => app.search_active = false,
                    KeyCode::Esc => {
                        app.search.clear();
                        app.search_active = false;
                        app.resort();
                    }
                    KeyCode::Backspace => {
                        app.search.pop();
                        app.resort();
                    }
                    KeyCode::Char(c) => {
                        app.search.push(c);
                        app.resort();
                    }
                    _ => {}
                }
            } else {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Down | KeyCode::Char('j') => app.select_next(),
                    KeyCode::Up | KeyCode::Char('k') => app.select_prev(),
                    KeyCode::Char('c') => {
                        app.sort_mode = SortMode::Cpu;
                        app.resort();
                    }
                    KeyCode::Char('g') => {
                        app.sort_mode = SortMode::Gpu;
                        app.resort();
                    }
                    KeyCode::Char('t') => {
                        app.sort_mode = SortMode::Total;
                        app.resort();
                    }
                    KeyCode::Char('p') => {
                        app.view_mode = match app.view_mode {
                            ViewMode::Flat => ViewMode::Tree,
                            ViewMode::Tree => ViewMode::Flat,
                        };
                        app.resort();
                    }
                    KeyCode::Char('/') => app.search_active = true,
                    _ => {}
                }
            }
        }

        if last_tick.elapsed() >= TICK {
            app.tick();
            last_tick = Instant::now();
        }

        terminal.draw(|f| ui(f, &app))?;
    }
}

fn ui(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(10),
            Constraint::Length(1),
        ])
        .split(f.area());

    draw_header(f, app, chunks[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(chunks[1]);

    draw_table(f, app, body[0]);
    draw_detail(f, app, body[1]);

    draw_footer(f, chunks[2]);
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let total_cpu: f32 = app.rows.iter().map(|(_, p)| p.cpu_percent).sum();
    let total_gpu: f32 = app.rows.iter().map(|(_, p)| p.gpu_percent).sum();
    let gpu_note = if app.has_gpu_source {
        ""
    } else {
        "  (no GPU data source found)"
    };
    let view_label = match app.view_mode {
        ViewMode::Flat => "flat",
        ViewMode::Tree => "tree",
    };
    let line1 = Line::from(vec![
        Span::styled(
            "rMon",
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan),
        ),
        Span::raw(format!(
            " — live process CPU/GPU monitor    view: {view_label}   sort: {}{}",
            app.sort_mode.label(),
            gpu_note
        )),
    ]);
    let line2 = Line::from(format!(
        "processes: {}   total CPU: {:.1}%   total GPU: {:.1}%",
        app.rows.len(),
        total_cpu,
        total_gpu
    ));
    let line3 = thermal_line(app);
    let line4 = if app.search_active {
        Line::from(vec![
            Span::styled("search: ", Style::default().fg(Color::Yellow)),
            Span::raw(&app.search),
            Span::styled("█", Style::default().fg(Color::Yellow)),
        ])
    } else if !app.search.is_empty() {
        Line::from(vec![
            Span::styled("search: ", Style::default().fg(Color::DarkGray)),
            Span::raw(&app.search),
            Span::styled("  (press / to edit, Esc while editing clears)", Style::default().fg(Color::DarkGray)),
        ])
    } else {
        Line::from(Span::styled(
            "press / to search by name",
            Style::default().fg(Color::DarkGray),
        ))
    };
    f.render_widget(
        ratatui::widgets::Paragraph::new(vec![line1, line2, line3, line4]),
        area,
    );
}

fn thermal_line(app: &App) -> Line<'static> {
    let mut spans = Vec::new();
    let cpu_temp = app
        .system
        .cpu_temp_c
        .map(|t| format!("{t:.0}°C"))
        .unwrap_or_else(|| "n/a".to_string());
    let cpu_clock = app
        .system
        .cpu_clock_ratio
        .map(|r| format!("{:.0}% clock", r * 100.0))
        .unwrap_or_else(|| "clock n/a".to_string());
    spans.push(Span::raw(format!("CPU: {cpu_temp} {cpu_clock}")));
    if app.system.cpu_throttled {
        spans.push(Span::styled(
            " [possibly throttled]",
            Style::default().fg(Color::Yellow),
        ));
    }
    for gpu in &app.system.gpus {
        let temp = gpu
            .temp_c
            .map(|t| format!("{t:.0}°C"))
            .unwrap_or_else(|| "n/a".to_string());
        spans.push(Span::raw(format!("   {}: {temp}", gpu.name)));
        if gpu.thermal_throttled {
            spans.push(Span::styled(
                " [THERMAL THROTTLE]",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ));
        }
    }
    Line::from(spans)
}

fn draw_footer(f: &mut Frame, area: Rect) {
    let line = Line::from(
        "↑/↓ j/k: select   c/g/t: sort   p: tree/flat   /: search   q/Esc: quit",
    )
    .style(Style::default().fg(Color::DarkGray));
    f.render_widget(ratatui::widgets::Paragraph::new(line), area);
}

fn draw_table(f: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec![
        Cell::from("PID"),
        Cell::from("NAME"),
        Cell::from("CPU% (trend)"),
        Cell::from("GPU% (trend)"),
        Cell::from("SRC"),
    ])
    .style(Style::default().add_modifier(Modifier::BOLD));

    let rows = app.rows.iter().map(|(depth, p)| {
        let src = match p.gpu_source {
            GpuSource::Nvml => "nvml",
            GpuSource::Pdh => "pdh",
            GpuSource::Unavailable => "-",
        };
        let tail = app.history.tail_for_pid(p.pid, SPARK_POINTS);
        let cpu_spark = sparkline(&tail.iter().map(|(c, _)| *c).collect::<Vec<_>>());
        let gpu_spark = sparkline(&tail.iter().map(|(_, g)| *g).collect::<Vec<_>>());

        let indent = "  ".repeat(*depth);
        let name = format!("{indent}{}{}", if *depth > 0 { "└ " } else { "" }, p.name);

        Row::new(vec![
            Cell::from(p.pid.to_string()),
            Cell::from(name),
            Cell::from(format!("{:>5.1} {cpu_spark}", p.cpu_percent)),
            Cell::from(format!("{:>5.1} {gpu_spark}", p.gpu_percent)),
            Cell::from(src),
        ])
    });

    let widths = [
        Constraint::Length(8),
        Constraint::Min(18),
        Constraint::Length(20),
        Constraint::Length(20),
        Constraint::Length(6),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title("Processes"))
        .row_highlight_style(Style::default().bg(Color::Blue).add_modifier(Modifier::BOLD))
        .highlight_symbol("▶ ");

    let mut state = app.table_state;
    f.render_stateful_widget(table, area, &mut state);
}

fn draw_detail(f: &mut Frame, app: &App, area: Rect) {
    let Some(pid) = app.selected_pid else {
        f.render_widget(
            Block::default().borders(Borders::ALL).title("History"),
            area,
        );
        return;
    };
    let name = app
        .rows
        .iter()
        .find(|(_, p)| p.pid == pid)
        .map(|(_, p)| p.name.as_str())
        .unwrap_or("?");

    let series = app.history.series_for_pid(pid);
    if series.is_empty() {
        f.render_widget(
            Block::default()
                .borders(Borders::ALL)
                .title(format!("History: {name} ({pid})")),
            area,
        );
        return;
    }

    let t0 = series[0].0;
    let cpu_points: Vec<(f64, f64)> = series
        .iter()
        .map(|(t, cpu, _)| ((*t - t0).num_milliseconds() as f64 / 1000.0, *cpu as f64))
        .collect();
    let gpu_points: Vec<(f64, f64)> = series
        .iter()
        .map(|(t, _, gpu)| ((*t - t0).num_milliseconds() as f64 / 1000.0, *gpu as f64))
        .collect();

    let max_x = cpu_points.last().map(|(x, _)| *x).unwrap_or(1.0).max(1.0);
    let max_y = cpu_points
        .iter()
        .chain(gpu_points.iter())
        .map(|(_, y)| *y)
        .fold(100.0_f64, f64::max);

    let datasets = vec![
        Dataset::default()
            .name("CPU%")
            .marker(ratatui::symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(Color::Green))
            .data(&cpu_points),
        Dataset::default()
            .name("GPU%")
            .marker(ratatui::symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(Color::Magenta))
            .data(&gpu_points),
    ];

    let chart = Chart::new(datasets)
        .block(Block::default().borders(Borders::ALL).title(format!(
            "History: {name} ({pid})"
        )))
        .x_axis(
            Axis::default()
                .title("seconds ago")
                .bounds([0.0, max_x])
                .labels(vec![
                    Line::from("0"),
                    Line::from(format!("{max_x:.0}")),
                ]),
        )
        .y_axis(
            Axis::default()
                .title("%")
                .bounds([0.0, max_y])
                .labels(vec![
                    Line::from("0"),
                    Line::from(format!("{max_y:.0}")),
                ]),
        );

    f.render_widget(chart, area);
}
