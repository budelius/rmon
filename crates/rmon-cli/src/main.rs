use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};
use rmon_core::{build_tree, list_open_files, GpuSource, ProcessSample, Sampler, Snapshot, Store, SystemMetrics};

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
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Command::Snapshot { top, tree, subtree } => run_snapshot(top, tree, subtree),
        Command::Record {
            db,
            csv,
            interval_ms,
            duration_secs,
        } => run_record(db, csv, interval_ms, duration_secs),
        Command::Files { pid, filter } => run_files(pid, filter),
    }
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
