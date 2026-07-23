use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};
use rmon_core::{GpuSource, Sampler, Snapshot, Store};

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
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Command::Snapshot { top } => run_snapshot(top),
        Command::Record {
            db,
            csv,
            interval_ms,
            duration_secs,
        } => run_record(db, csv, interval_ms, duration_secs),
    }
}

fn run_snapshot(top: usize) -> Result<()> {
    let mut sampler = Sampler::new();
    if !sampler.has_gpu_source() {
        eprintln!("warning: no GPU data source available (no NVIDIA driver and no 'GPU Engine' perf counters); GPU column will read 0.0");
    }

    // CPU/GPU percentages are deltas since the last sample, so the very
    // first read is meaningless. Warm up, then take the real reading.
    sampler.sample();
    std::thread::sleep(Duration::from_millis(600));
    let snapshot = sampler.sample();

    print_table(&snapshot, top);
    Ok(())
}

fn print_table(snapshot: &Snapshot, top: usize) {
    println!(
        "{:<8} {:<32} {:>8} {:>8} {:<6}",
        "PID", "NAME", "CPU%", "GPU%", "SRC"
    );
    for p in snapshot.sorted_by_usage().into_iter().take(top) {
        let src = match p.gpu_source {
            GpuSource::Nvml => "nvml",
            GpuSource::Pdh => "pdh",
            GpuSource::Unavailable => "-",
        };
        let name = if p.name.len() > 32 {
            &p.name[..32]
        } else {
            &p.name
        };
        println!(
            "{:<8} {:<32} {:>8.1} {:>8.1} {:<6}",
            p.pid, name, p.cpu_percent, p.gpu_percent, src
        );
    }
    println!(
        "\n{} processes, total CPU {:.1}%, total GPU {:.1}%",
        snapshot.processes.len(),
        snapshot.total_cpu_percent(),
        snapshot.total_gpu_percent()
    );
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
                "{ticks} samples taken, {} processes, total CPU {:.1}%, total GPU {:.1}%",
                snapshot.processes.len(),
                snapshot.total_cpu_percent(),
                snapshot.total_gpu_percent()
            );
        }

        std::thread::sleep(interval);
    }

    println!("stopped after {ticks} samples");
    Ok(())
}
