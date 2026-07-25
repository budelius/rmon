use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Axis, Block, Borders, Cell, Chart, Dataset, GraphType, List, ListItem, ListState, Row, Table,
    TableState,
};
use ratatui::Frame;
use rmon_core::{
    build_tree, list_open_files, GpuSource, OpenFilesScan, ProcessSample, RollingHistory, Sampler,
    SystemMetrics,
};

const RETAIN: Duration = Duration::from_secs(300);
const TICK: Duration = Duration::from_millis(1000);
const SPARK_POINTS: usize = 12;
const BLOCKS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortMetric {
    Cpu,
    Gpu,
    Total,
}

impl SortMetric {
    fn label(self) -> &'static str {
        match self {
            SortMetric::Cpu => "CPU%",
            SortMetric::Gpu => "GPU%",
            SortMetric::Total => "CPU%+GPU%",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortWindow {
    Instant,
    Accumulated,
}

impl SortWindow {
    fn label(self) -> &'static str {
        match self {
            SortWindow::Instant => "instant",
            SortWindow::Accumulated => "accumulated",
        }
    }
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum ViewMode {
    Flat,
    Tree,
}

/// One rendered row: tree depth (0 for flat view) plus the process it shows.
type TreeRow = (usize, ProcessSample);

#[derive(Clone, Copy, PartialEq, Eq)]
enum AppView {
    Processes,
    Files,
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
    search_active: bool,
    list_state: ListState,
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
            search_active: false,
            list_state: ListState::default(),
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
            self.list_state.select(Some(0));
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

    fn select_next(&mut self) {
        let len = self.filtered_paths().len();
        if len == 0 {
            return;
        }
        let i = match self.list_state.selected() {
            Some(i) if i + 1 < len => i + 1,
            Some(_) => 0,
            None => 0,
        };
        self.list_state.select(Some(i));
    }

    fn select_prev(&mut self) {
        let len = self.filtered_paths().len();
        if len == 0 {
            return;
        }
        let i = match self.list_state.selected() {
            Some(0) | None => len - 1,
            Some(i) => i - 1,
        };
        self.list_state.select(Some(i));
    }
}

struct App {
    sampler: Sampler,
    history: RollingHistory,
    sort_metric: SortMetric,
    sort_window: SortWindow,
    subtree_sort: bool,
    view_mode: ViewMode,
    search: String,
    search_active: bool,
    rows: Vec<TreeRow>,
    table_state: TableState,
    selected_pid: Option<u32>,
    has_gpu_source: bool,
    system: SystemMetrics,
    app_view: AppView,
    files: Option<FilesState>,
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
            sort_metric: SortMetric::Total,
            sort_window: SortWindow::Instant,
            subtree_sort: false,
            view_mode: ViewMode::Flat,
            search: String::new(),
            search_active: false,
            rows: Vec::new(),
            table_state,
            selected_pid: None,
            has_gpu_source,
            system: SystemMetrics::default(),
            app_view: AppView::Processes,
            files: None,
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

fn main() -> Result<()> {
    // Held for the process lifetime so buffered Sentry/rustrak events flush on exit.
    let _sentry = rmon_core::observability::init_sentry();
    let mut terminal = ratatui::init();
    let result = run(&mut terminal);
    ratatui::restore();
    if let Err(err) = &result {
        rmon_core::observability::capture_anyhow(err);
    }
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
            && !handle_key(&mut app, key.code)
        {
            return Ok(());
        }

        if let Some(fs) = app.files.as_mut() {
            fs.poll();
        }

        if last_tick.elapsed() >= TICK {
            app.tick();
            last_tick = Instant::now();
        }

        terminal.draw(|f| ui(f, &app))?;
    }
}

/// Returns `false` when the app should quit.
fn handle_key(app: &mut App, code: KeyCode) -> bool {
    match app.app_view {
        AppView::Processes => handle_key_processes(app, code),
        AppView::Files => handle_key_files(app, code),
    }
}

fn handle_key_processes(app: &mut App, code: KeyCode) -> bool {
    if app.search_active {
        match code {
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
        return true;
    }
    match code {
        KeyCode::Char('q') | KeyCode::Esc => return false,
        KeyCode::Down | KeyCode::Char('j') => app.select_next(),
        KeyCode::Up | KeyCode::Char('k') => app.select_prev(),
        KeyCode::Char('c') => {
            app.sort_metric = SortMetric::Cpu;
            app.resort();
        }
        KeyCode::Char('g') => {
            app.sort_metric = SortMetric::Gpu;
            app.resort();
        }
        KeyCode::Char('t') => {
            app.sort_metric = SortMetric::Total;
            app.resort();
        }
        KeyCode::Char('a') => {
            app.sort_window = match app.sort_window {
                SortWindow::Instant => SortWindow::Accumulated,
                SortWindow::Accumulated => SortWindow::Instant,
            };
            app.resort();
        }
        KeyCode::Char('s') => {
            app.subtree_sort = !app.subtree_sort;
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
        KeyCode::Char('f') => {
            if let Some(pid) = app.selected_pid {
                let name = app
                    .rows
                    .iter()
                    .find(|(_, p)| p.pid == pid)
                    .map(|(_, p)| p.name.clone())
                    .unwrap_or_default();
                app.files = Some(FilesState::start(pid, name));
                app.app_view = AppView::Files;
            }
        }
        _ => {}
    }
    true
}

fn handle_key_files(app: &mut App, code: KeyCode) -> bool {
    let Some(fs) = app.files.as_mut() else {
        app.app_view = AppView::Processes;
        return true;
    };
    if fs.search_active {
        match code {
            KeyCode::Enter => fs.search_active = false,
            KeyCode::Esc => {
                fs.search.clear();
                fs.search_active = false;
            }
            KeyCode::Backspace => {
                fs.search.pop();
            }
            KeyCode::Char(c) => fs.search.push(c),
            _ => {}
        }
        return true;
    }
    match code {
        KeyCode::Char('q') => return false,
        KeyCode::Esc => app.app_view = AppView::Processes,
        KeyCode::Down | KeyCode::Char('j') => fs.select_next(),
        KeyCode::Up | KeyCode::Char('k') => fs.select_prev(),
        KeyCode::Char('/') => fs.search_active = true,
        KeyCode::Char('r') => *fs = FilesState::start(fs.pid, fs.name.clone()),
        _ => {}
    }
    true
}

fn ui(f: &mut Frame, app: &App) {
    match app.app_view {
        AppView::Processes => ui_processes(f, app),
        AppView::Files => ui_files(f, app),
    }
}

fn ui_processes(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
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

fn ui_files(f: &mut Frame, app: &App) {
    let Some(fs) = &app.files else { return };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(1),
        ])
        .split(f.area());

    let title = Line::from(vec![
        Span::styled(
            "Open files",
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan),
        ),
        Span::raw(format!(": {} ({})", fs.name, fs.pid)),
    ]);
    let status_line = match &fs.status {
        FilesStatus::Scanning(_) => Line::from(Span::styled(
            "scanning... (this walks the process's kernel handle table; can take a few seconds)",
            Style::default().fg(Color::Yellow),
        )),
        FilesStatus::Done(scan) => Line::from(format!(
            "{} open file(s)   ({} handles scanned, {} timed out)",
            scan.paths.len(),
            scan.handles_seen,
            scan.timed_out
        )),
        FilesStatus::Error(e) => {
            Line::from(Span::styled(format!("error: {e}"), Style::default().fg(Color::Red)))
        }
    };
    let search_line = if fs.search_active {
        Line::from(vec![
            Span::styled("search: ", Style::default().fg(Color::Yellow)),
            Span::raw(&fs.search),
            Span::styled("█", Style::default().fg(Color::Yellow)),
        ])
    } else if !fs.search.is_empty() {
        Line::from(format!("search: {}  (press / to edit)", fs.search))
    } else {
        Line::from(Span::styled(
            "press / to filter paths",
            Style::default().fg(Color::DarkGray),
        ))
    };
    f.render_widget(
        ratatui::widgets::Paragraph::new(vec![title, status_line, search_line]),
        chunks[0],
    );

    let items: Vec<ListItem> = fs.filtered_paths().into_iter().map(ListItem::new).collect();
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Files"))
        .highlight_style(Style::default().bg(Color::Blue).add_modifier(Modifier::BOLD))
        .highlight_symbol("▶ ");
    let mut state = fs.list_state;
    f.render_stateful_widget(list, chunks[1], &mut state);

    let footer = Line::from("↑/↓ j/k: scroll   /: search   r: rescan   Esc: back to processes   q: quit")
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(ratatui::widgets::Paragraph::new(footer), chunks[2]);
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
    let subtree_note = if app.subtree_sort && app.view_mode == ViewMode::Tree {
        " (by subtree total)"
    } else {
        ""
    };
    let line1 = Line::from(vec![
        Span::styled(
            "rMon",
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan),
        ),
        Span::raw(format!(
            " — live process CPU/GPU monitor    view: {view_label}   sort: {} {}{}{}",
            app.sort_metric.label(),
            app.sort_window.label(),
            subtree_note,
            gpu_note
        )),
    ]);
    let line2 = Line::from(format!(
        "processes: {}   total CPU: {:.1}%   total GPU: {:.1}%   accumulation window: {} of up to 24h",
        app.rows.len(),
        total_cpu,
        total_gpu,
        format_duration(app.history.accum_window()),
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
        "↑/↓ j/k: select   c/g/t: sort   a: instant/accum   s: subtree/own (tree)   p: tree/flat   f: open files   /: search   q/Esc: quit",
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

    let (cpu_accum, gpu_accum) = app.history.accumulated(pid);
    let title = format!(
        "History: {name} ({pid})  —  accumulated: CPU {} GPU {} (over {})",
        format_core_time(cpu_accum),
        format_core_time(gpu_accum),
        format_duration(app.history.accum_window()),
    );

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
        .block(Block::default().borders(Borders::ALL).title(title))
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
