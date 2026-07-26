mod mcp;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};
use rmon_core::{
    build_tree, check_hardware_health, list_all_ports, list_open_files, list_open_files_many,
    GpuSource, PortEntry, ProcessSample, Sampler, Snapshot, Store, SystemMetrics,
    DEFAULT_SCAN_WORKERS,
};

#[derive(Parser)]
#[command(name = "rmon", about = "rMon: see what process is using your CPU and GPU")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print a single ranked snapshot of current CPU/GPU usage per process.
    Snapshot {
        /// Only show the top N processes by combined CPU+GPU usage.
        #[arg(long, default_value_t = 20)]
        top: usize,
        /// Print as a parent/child process tree instead of a flat ranked list.
        #[arg(long)]
        tree: bool,
        /// With --tree, rank each subtree by the summed CPU+GPU usage of the
        /// process and all its descendants, instead of its own usage.
        #[arg(long, requires = "tree")]
        subtree: bool,
    },
    /// Sample on an interval and persist to SQLite (and optionally CSV) until stopped with Ctrl+C.
    Record {
        /// SQLite database file to write samples to.
        #[arg(long, default_value = "rmon.sqlite")]
        db: PathBuf,
        /// Optional CSV file to also append samples to.
        #[arg(long)]
        csv: Option<PathBuf>,
        /// Sampling interval in milliseconds.
        #[arg(long, default_value_t = 1000)]
        interval_ms: u64,
        /// Stop automatically after this many seconds (omit to run until Ctrl+C).
        #[arg(long)]
        duration_secs: Option<u64>,
    },
    /// Best-effort list of files a process currently has open (may need Administrator for other users' processes).
    Files {
        pid: u32,
        /// Only show paths containing this substring.
        #[arg(long)]
        filter: Option<String>,
    },
    /// List TCP/UDP endpoints (from GetExtendedTcpTable/UdpTable), system-wide or for one process.
    Ports {
        /// Only show endpoints owned by this pid.
        pid: Option<u32>,
        /// Only show listening (TCP LISTEN, or any UDP) endpoints.
        #[arg(long)]
        listening: bool,
        /// Only show endpoints whose address, port, or pid contains this substring.
        #[arg(long)]
        filter: Option<String>,
    },
    /// Search open files and TCP/UDP ports across every process at once.
    Search {
        /// Substring to match against file paths, addresses, ports, or pids/names.
        query: String,
        /// Skip the open-files scan (ports only) — much faster, no per-process handle walk.
        #[arg(long)]
        ports_only: bool,
    },
    /// Run an MCP (Model Context Protocol) server over stdio, exposing snapshot/tree,
    /// per-process detail, ports, and cross-process search as tools for MCP clients.
    Mcp,
    /// Best-effort hardware health signals: WHEA event log entries, BIOS version,
    /// and CPU microcode revision. Facts only — doesn't diagnose degradation itself.
    /// The WHEA query is slow (a notoriously unindexed WMI class) and can take up
    /// to 30+ seconds on a system that logs WHEA entries frequently.
    Health {
        /// How many days back to search the System event log for WHEA entries.
        #[arg(long, default_value_t = rmon_core::DEFAULT_WHEA_LOOKBACK_DAYS)]
        days: i64,
        /// Cap on how many WHEA events to print (most recent first).
        #[arg(long, default_value_t = rmon_core::DEFAULT_WHEA_MAX_EVENTS)]
        max_events: usize,
    },
}

fn main() -> Result<()> {
    env_logger::init();
    // Held for the process lifetime so buffered Sentry/rustrak events flush on exit.
    let _sentry = rmon_core::observability::init_sentry();
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Snapshot { top, tree, subtree } => run_snapshot(top, tree, subtree),
        Command::Record {
            db,
            csv,
            interval_ms,
            duration_secs,
        } => run_record(db, csv, interval_ms, duration_secs),
        Command::Files { pid, filter } => run_files(pid, filter),
        Command::Ports { pid, listening, filter } => run_ports(pid, listening, filter),
        Command::Search { query, ports_only } => run_search(query, ports_only),
        Command::Mcp => mcp::run(),
        Command::Health { days, max_events } => run_health(days, max_events),
    };
    if let Err(err) = &result {
        rmon_core::observability::capture_anyhow(err);
    }
    result
}

fn run_files(pid: u32, filter: Option<String>) -> Result<()> {
    let scan = list_open_files(pid)?;
    let filter = filter.map(|f| f.to_lowercase());
    let mut shown = 0usize;
    for path in &scan.paths {
        if let Some(f) = &filter
            && !path.to_lowercase().contains(f.as_str())
        {
            continue;
        }
        println!("{path}");
        shown += 1;
    }
    println!(
        "\n{shown} of {} open file(s) shown ({} handles scanned, {} timed out)",
        scan.paths.len(),
        scan.handles_seen,
        scan.timed_out
    );
    Ok(())
}

fn run_ports(pid: Option<u32>, listening: bool, filter: Option<String>) -> Result<()> {
    let mut ports = list_all_ports()?;
    if let Some(pid) = pid {
        ports.retain(|p| p.pid == pid);
    }
    if listening {
        ports.retain(PortEntry::is_listening);
    }
    let filter = filter.map(|f| f.to_lowercase());

    println!("{:<5} {:<24} {:<24} {:<8} PID", "PROTO", "LOCAL", "REMOTE", "STATE");
    let mut shown = 0usize;
    for p in &ports {
        let local = format!("{}:{}", p.local_addr, p.local_port);
        let remote = match (p.remote_addr, p.remote_port) {
            (Some(a), Some(port)) => format!("{a}:{port}"),
            _ => "-".to_string(),
        };
        let state = p.state.map(|s| s.as_str()).unwrap_or("-");
        if let Some(f) = &filter {
            let haystack = format!("{local} {remote} {state} {}", p.pid).to_lowercase();
            if !haystack.contains(f.as_str()) {
                continue;
            }
        }
        println!("{:<5} {local:<24} {remote:<24} {state:<8} {}", p.protocol.as_str(), p.pid);
        shown += 1;
    }
    println!("\n{shown} of {} endpoint(s) shown", ports.len());
    Ok(())
}

fn run_search(query: String, ports_only: bool) -> Result<()> {
    let mut sampler = Sampler::new();
    let snapshot = sampler.sample();
    let names: std::collections::HashMap<u32, String> = snapshot
        .processes
        .iter()
        .map(|p| (p.pid, p.name.clone()))
        .collect();
    let q = query.to_lowercase();

    println!("=== matching ports ===");
    let ports = list_all_ports()?;
    let mut port_hits = 0usize;
    for p in &ports {
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
        if !haystack.contains(&q) {
            continue;
        }
        println!(
            "{:<5} {}:{:<6} pid {} ({})  {}",
            p.protocol.as_str(),
            p.local_addr,
            p.local_port,
            p.pid,
            name,
            p.state.map(|s| s.as_str()).unwrap_or("-"),
        );
        port_hits += 1;
    }
    println!("{port_hits} matching port(s)\n");

    if ports_only {
        return Ok(());
    }

    println!("=== matching open files (scanning every process — can take a while) ===");
    let pids: Vec<u32> = snapshot.processes.iter().map(|p| p.pid).collect();
    let total = pids.len();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || list_open_files_many(pids, DEFAULT_SCAN_WORKERS, tx));

    let mut file_hits = 0usize;
    let mut scanned = 0usize;
    for entry in rx {
        scanned += 1;
        let Ok(scan) = entry.scan else { continue };
        let name = names.get(&entry.pid).map(|s| s.as_str()).unwrap_or("?");
        for path in &scan.paths {
            if !path.to_lowercase().contains(&q) {
                continue;
            }
            println!("[{} ({})] {path}", entry.pid, name);
            file_hits += 1;
        }
    }
    println!("\n{file_hits} matching file(s) across {scanned}/{total} processes scanned");
    Ok(())
}

fn run_health(days: i64, max_events: usize) -> Result<()> {
    let report = check_hardware_health(days, max_events);

    println!(
        "BIOS: {} {} (released {})",
        report.bios_manufacturer.as_deref().unwrap_or("unknown"),
        report.bios_version.as_deref().unwrap_or("unknown"),
        report.bios_release_date.as_deref().unwrap_or("unknown"),
    );
    println!(
        "CPU microcode revision: {}",
        report.microcode_revision.as_deref().unwrap_or("unknown")
    );
    println!(
        "(cross-reference the BIOS version and microcode revision above against your \
         motherboard/CPU vendor's own advisories — rMon doesn't know which versions fix \
         which errata)"
    );

    println!();
    match &report.whea_query_error {
        Some(e) => println!("WHEA event query failed: {e}"),
        None => {
            println!(
                "WHEA events in the last {days} day(s): {} shown (capped at {max_events}), \
                 {} error(s), {} warning(s) among those shown",
                report.whea_events.len(),
                report.whea_error_count,
                report.whea_warning_count,
            );
            for e in &report.whea_events {
                println!(
                    "  {} [{:<24}] id={:<4} rec={:<8} {}",
                    e.time.format("%Y-%m-%d %H:%M:%S UTC"),
                    e.level,
                    e.event_id,
                    e.record_number,
                    e.message,
                );
            }
        }
    }
    println!(
        "\nA WHEA entry (especially Error-level) is real hardware-reported evidence, but by \
         itself doesn't confirm degradation — weigh it alongside new instability under load."
    );
    Ok(())
}

fn run_snapshot(top: usize, tree: bool, subtree: bool) -> Result<()> {
    let mut sampler = Sampler::new();
    if !sampler.has_gpu_source() {
        eprintln!("warning: no GPU data source available (no NVIDIA driver and no 'GPU Engine' perf counters); GPU column will read 0.0");
    }

    // CPU/GPU percentages are deltas since the last sample, so the very
    // first read is meaningless. Warm up, then take the real reading.
    sampler.sample();
    std::thread::sleep(Duration::from_millis(600));
    let snapshot = sampler.sample();

    if tree {
        print_tree(&snapshot, top, subtree);
    } else {
        print_table(&snapshot, top);
    }
    println!("{}", thermal_summary(&snapshot.system));
    Ok(())
}

fn gpu_src_label(src: GpuSource) -> &'static str {
    match src {
        GpuSource::Nvml => "nvml",
        GpuSource::Pdh => "pdh",
        GpuSource::Unavailable => "-",
    }
}

fn truncate(name: &str, max: usize) -> &str {
    if name.len() > max { &name[..max] } else { name }
}

fn print_table(snapshot: &Snapshot, top: usize) {
    println!(
        "{:<8} {:<32} {:>8} {:>8} {:<6}",
        "PID", "NAME", "CPU%", "GPU%", "SRC"
    );
    for p in snapshot.sorted_by_usage().into_iter().take(top) {
        println!(
            "{:<8} {:<32} {:>8.1} {:>8.1} {:<6}",
            p.pid,
            truncate(&p.name, 32),
            p.cpu_percent,
            p.gpu_percent,
            gpu_src_label(p.gpu_source)
        );
    }
    println!(
        "\n{} processes, total CPU {:.1}%, total GPU {:.1}%",
        snapshot.processes.len(),
        snapshot.total_cpu_percent(),
        snapshot.total_gpu_percent()
    );
}

fn print_tree(snapshot: &Snapshot, top: usize, subtree: bool) {
    println!(
        "{:<8} {:<40} {:>8} {:>8} {:<6}",
        "PID", "NAME", "CPU%", "GPU%", "SRC"
    );
    let rows = build_tree(
        &snapshot.processes,
        |p: &ProcessSample| p.cpu_percent + p.gpu_percent,
        subtree,
    );
    for (depth, p) in rows.into_iter().take(top) {
        let indent = "  ".repeat(depth);
        let prefix = if depth > 0 { "└ " } else { "" };
        let name = format!("{indent}{prefix}{}", p.name);
        println!(
            "{:<8} {:<40} {:>8.1} {:>8.1} {:<6}",
            p.pid,
            truncate(&name, 40),
            p.cpu_percent,
            p.gpu_percent,
            gpu_src_label(p.gpu_source)
        );
    }
}

fn thermal_summary(system: &SystemMetrics) -> String {
    let cpu_temp = system
        .cpu_temp_c
        .map(|t| format!("{t:.0}°C"))
        .unwrap_or_else(|| "n/a".to_string());
    let cpu_clock = system
        .cpu_clock_ratio
        .map(|r| format!("{:.0}% clock", r * 100.0))
        .unwrap_or_else(|| "clock n/a".to_string());
    let throttle = if system.cpu_throttled { " [possibly throttled]" } else { "" };
    let mut out = format!("CPU: {cpu_temp} {cpu_clock}{throttle}");
    for gpu in &system.gpus {
        let temp = gpu
            .temp_c
            .map(|t| format!("{t:.0}°C"))
            .unwrap_or_else(|| "n/a".to_string());
        let throttle = if gpu.thermal_throttled { " [THERMAL THROTTLE]" } else { "" };
        out.push_str(&format!("   {}: {temp}{throttle}", gpu.name));
    }
    out
}

fn run_record(
    db_path: PathBuf,
    csv_path: Option<PathBuf>,
    interval_ms: u64,
    duration_secs: Option<u64>,
) -> Result<()> {
    let mut sampler = Sampler::new();
    if !sampler.has_gpu_source() {
        eprintln!("warning: no GPU data source available; GPU column will read 0.0");
    }
    let mut store = Store::open(&db_path)?;
    let mut csv_writer = match &csv_path {
        Some(p) => {
            let is_new = !p.exists();
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)?;
            let mut w = csv::WriterBuilder::new()
                .has_headers(false)
                .from_writer(file);
            if is_new {
                w.write_record([
                    "timestamp_ms",
                    "pid",
                    "name",
                    "cpu_percent",
                    "gpu_percent",
                    "gpu_source",
                ])?;
                w.flush()?;
            }
            Some(w)
        }
        None => None,
    };

    let running = Arc::new(AtomicBool::new(true));
    {
        let running = running.clone();
        ctrlc::set_handler(move || {
            eprintln!("\nstopping...");
            running.store(false, Ordering::SeqCst);
        })?;
    }

    println!(
        "recording every {interval_ms}ms to {} {}",
        db_path.display(),
        csv_path
            .as_ref()
            .map(|p| format!("(and {})", p.display()))
            .unwrap_or_default()
    );

    let start = std::time::Instant::now();
    let interval = Duration::from_millis(interval_ms);
    let mut ticks: u64 = 0;

    while running.load(Ordering::SeqCst) {
        if let Some(secs) = duration_secs
            && start.elapsed().as_secs() >= secs
        {
            break;
        }

        let snapshot = sampler.sample();
        store.insert_snapshot(&snapshot)?;
        if let Some(w) = csv_writer.as_mut() {
            let ts = snapshot.timestamp.timestamp_millis();
            for p in &snapshot.processes {
                w.write_record([
                    ts.to_string(),
                    p.pid.to_string(),
                    p.name.clone(),
                    p.cpu_percent.to_string(),
                    p.gpu_percent.to_string(),
                    p.gpu_source.as_str().to_string(),
                ])?;
            }
            w.flush()?;
        }

        ticks += 1;
        if ticks.is_multiple_of(10) {
            println!(
                "{ticks} samples taken, {} processes, total CPU {:.1}%, total GPU {:.1}%   {}",
                snapshot.processes.len(),
                snapshot.total_cpu_percent(),
                snapshot.total_gpu_percent(),
                thermal_summary(&snapshot.system)
            );
        }

        std::thread::sleep(interval);
    }

    println!("stopped after {ticks} samples");
    Ok(())
}
