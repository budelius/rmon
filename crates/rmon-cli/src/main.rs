mod mcp;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};
use rmon_core::{
    DEFAULT_SCAN_WORKERS, GpuSource, PortEntry, ProcessSample, Sampler, Snapshot, Store,
    SystemMetrics, attribute_processes, build_tree, check_hardware_health, list_all_ports,
    list_installed_programs, list_open_files, list_open_files_many, program_relationships,
};

#[derive(Parser)]
#[command(
    name = "rmon",
    about = "rMon: see what process is using your CPU and GPU"
)]
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
    /// Inventory conventional installed Win32/MSI programs and correlate them
    /// with live processes, including children launched by an app.
    Programs {
        /// Match display name, publisher, version, or install location.
        #[arg(long)]
        filter: Option<String>,
        /// Show only programs with a live executable or launched child.
        #[arg(long)]
        active: bool,
        /// Show conservative uninstall-review candidates. This is not a
        /// claim that they are unused or safe to remove.
        #[arg(long)]
        review: bool,
    },
    /// Run an MCP (Model Context Protocol) server over stdio, exposing snapshot/tree,
    /// per-process detail, ports, and cross-process search as tools for MCP clients.
    Mcp,
    /// Best-effort hardware health signals: WHEA event log entries, BIOS version,
    /// and CPU microcode revision. Facts only — doesn't diagnose degradation itself.
    /// The WHEA query reads the System channel through `EvtQuery`, which
    /// answers from the channel's per-provider index — tens of
    /// milliseconds, and flat in `--days`.
    Health {
        /// How many days back to search the System event log for WHEA entries.
        #[arg(long, default_value_t = rmon_core::DEFAULT_WHEA_LOOKBACK_DAYS)]
        days: i64,
        /// Cap on how many WHEA events to print (most recent first).
        #[arg(long, default_value_t = rmon_core::DEFAULT_WHEA_MAX_EVENTS)]
        max_events: usize,
    },
    /// Name the processes driving WMI, when `WmiPrvSE.exe` is burning CPU
    /// that Task Manager cannot attribute to anyone.
    ///
    /// Reads the WMI-Activity event channels natively — never through WMI
    /// itself, which would add load to the thing being measured. The
    /// always-on Operational channel only records operations slow enough to
    /// cross a threshold, so the busiest caller can be missing from it
    /// entirely; `--trace on` enables the analytic channel that records
    /// every operation, which is what actually names the caller.
    Wmi {
        /// How far back to look, in seconds.
        #[arg(long, default_value_t = rmon_core::wmi_activity::DEFAULT_LOOKBACK_SECS)]
        secs: i64,
        /// Cap on events read.
        #[arg(long, default_value_t = rmon_core::wmi_activity::DEFAULT_MAX_EVENTS)]
        max_events: usize,
        /// How many callers to list.
        #[arg(long, default_value_t = 15)]
        top: usize,
        /// Turn the complete-but-noisy analytic trace channel on or off.
        /// Needs Administrator. Turn it back off when finished.
        #[arg(long, value_name = "on|off")]
        trace: Option<String>,
    },
    /// Find clusters of live processes whose parent is gone — abandoned
    /// sessions still holding processes.
    ///
    /// One orphan is unremarkable; anything started from a shell that has
    /// since closed is one. Dozens sharing a single dead parent is one
    /// abandoned launcher, and that is what this surfaces.
    Orphans {
        /// Only show groups holding at least this many processes.
        #[arg(long, default_value_t = rmon_core::DEFAULT_MIN_GROUP)]
        min_size: usize,
        /// Also list every process in each group, not just the summary.
        #[arg(long)]
        members: bool,
    },
    /// Report what rMon can read directly from the hardware: CPU thermal
    /// MSRs plus motherboard temperatures, voltages, and fan tachometers,
    /// via the PawnIO driver.
    ///
    /// Needs PawnIO installed (<https://pawnio.eu>) and Administrator. Without
    /// either, it prints which of the two is missing and what the fallback
    /// sources can still see, rather than failing.
    Sensors {
        /// Also dump raw Super I/O register bytes and probe both
        /// configuration ports. Use when fan readings look implausible:
        /// it distinguishes a chip that isn't answering from one whose
        /// register map rMon has wrong.
        #[arg(long)]
        raw: bool,
    },
    /// Read the CPU's power-limit configuration and say which limit, if
    /// any, is currently holding clocks down.
    ///
    /// `sensors` can only report that *a* power limit is engaged, because
    /// that is all the thermal status register says. This asks the RAPL
    /// and perf-limit-reason registers instead, which separate PL1 from
    /// PL2 from the EDP/IccMax current ceiling, and report what the BIOS
    /// actually configured each one to.
    ///
    /// Requires Administrator and the PawnIO driver. Registers outside
    /// the driver module's allowlist are reported as refused rather than
    /// guessed at.
    Power {
        /// Print every candidate register with its raw value and whether
        /// the driver permitted the read. Use when a decoded field is
        /// missing and you need to know if the register was denied or
        /// simply empty.
        #[arg(long)]
        raw: bool,
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
        Command::Ports {
            pid,
            listening,
            filter,
        } => run_ports(pid, listening, filter),
        Command::Search { query, ports_only } => run_search(query, ports_only),
        Command::Programs {
            filter,
            active,
            review,
        } => run_programs(filter, active, review),
        Command::Mcp => mcp::run(),
        Command::Health { days, max_events } => run_health(days, max_events),
        Command::Wmi {
            secs,
            max_events,
            top,
            trace,
        } => run_wmi(secs, max_events, top, trace),
        Command::Orphans { min_size, members } => run_orphans(min_size, members),
        Command::Sensors { raw } => run_sensors(raw),
        Command::Power { raw } => run_power(raw),
    };
    if let Err(err) = &result {
        rmon_core::observability::capture_anyhow(err);
    }
    result
}

fn run_programs(filter: Option<String>, active_only: bool, review_only: bool) -> Result<()> {
    let scan = list_installed_programs();
    let mut sampler = Sampler::new();
    let snapshot = sampler.sample();
    let attribution = attribute_processes(&scan.programs, &snapshot.processes);
    let activities: std::collections::HashMap<_, _> = attribution
        .activities
        .iter()
        .map(|activity| (activity.program_id.as_str(), activity))
        .collect();
    let relationships = program_relationships(&scan.programs);
    let filter = filter.unwrap_or_default().to_ascii_lowercase();

    println!(
        "{:<42} {:<16} {:<24} {:>5} {:>8} {:>10}",
        "PROGRAM", "VERSION", "PUBLISHER", "PROCS", "CPU%", "MEMORY"
    );
    let mut shown = 0usize;
    for program in &scan.programs {
        let haystack = format!(
            "{} {} {} {}",
            program.name,
            program.version.as_deref().unwrap_or(""),
            program.publisher.as_deref().unwrap_or(""),
            program.install_location.as_deref().unwrap_or("")
        )
        .to_ascii_lowercase();
        if !filter.is_empty() && !haystack.contains(&filter) {
            continue;
        }
        let activity = activities.get(program.id.as_str()).copied();
        let active = activity.is_some_and(|activity| activity.active());
        if active_only && !active {
            continue;
        }
        let has_dependents = relationships
            .iter()
            .any(|relationship| relationship.parent_id == program.id);
        let reviewable = !active
            && !has_dependents
            && !program.system_component
            && !program.update_or_hotfix
            && program.has_uninstaller();
        if review_only && !reviewable {
            continue;
        }
        println!(
            "{:<42} {:<16} {:<24} {:>5} {:>8.1} {:>10}",
            truncate_column(&program.name, 42),
            truncate_column(program.version.as_deref().unwrap_or("-"), 16),
            truncate_column(program.publisher.as_deref().unwrap_or("unknown"), 24),
            activity.map_or(0, |activity| activity.process_count()),
            activity.map_or(0.0, |activity| activity.cpu_percent),
            activity.map_or_else(
                || "-".to_string(),
                |activity| format_bytes(activity.memory_bytes)
            ),
        );
        shown += 1;
    }
    println!(
        "\n{shown} of {} installed-program entries shown",
        scan.programs.len()
    );
    println!(
        "Inventory coverage: conventional Win32/MSI Uninstall registry entries. Portable and some Store apps may be absent."
    );
    if review_only {
        println!(
            "Review list only: idle now and no registry blocker is not proof an app is unused or safe to uninstall."
        );
    }
    for warning in scan.warnings {
        eprintln!("warning: {warning}");
    }
    Ok(())
}

fn truncate_column(value: &str, max: usize) -> String {
    let count = value.chars().count();
    if count <= max {
        value.to_string()
    } else {
        value
            .chars()
            .take(max.saturating_sub(1))
            .collect::<String>()
            + "…"
    }
}

fn format_bytes(bytes: u64) -> String {
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * MIB;
    if bytes as f64 >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB)
    } else {
        format!("{:.0} MiB", bytes as f64 / MIB)
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

fn run_ports(pid: Option<u32>, listening: bool, filter: Option<String>) -> Result<()> {
    let mut ports = list_all_ports()?;
    if let Some(pid) = pid {
        ports.retain(|p| p.pid == pid);
    }
    if listening {
        ports.retain(PortEntry::is_listening);
    }
    let filter = filter.map(|f| f.to_lowercase());

    println!(
        "{:<5} {:<24} {:<24} {:<8} PID",
        "PROTO", "LOCAL", "REMOTE", "STATE"
    );
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
        println!(
            "{:<5} {local:<24} {remote:<24} {state:<8} {}",
            p.protocol.as_str(),
            p.pid
        );
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

/// Dumps the direct-hardware sensor path's own view of the machine.
///
/// Deliberately separate from `snapshot`, which reports whichever source
/// won: this one answers "is the kernel path working, and what exactly is
/// it giving me", which is the question when setting it up or checking a
/// reading against another tool.
fn run_sensors(raw: bool) -> Result<()> {
    let elevated = rmon_core::elevate::is_elevated();
    let mut hub = rmon_core::SensorHub::new();

    println!("{}", hub.status_line());
    if !elevated {
        println!("(rMon is not running as Administrator — the kernel driver cannot be opened)");
    }
    println!();

    match hub.cpu_package() {
        Some(p) => {
            println!("CPU package temperature: {:.0}°C", p.temp_c);
            println!("  TjMax:                 {:.0}°C", p.tjmax_c);
            println!("  headroom:              {:.0}°C below TjMax", p.headroom_c);
            println!("  thermal throttling:    {}", yes_no(p.thermal_throttling));
            println!("  PROCHOT# asserted:     {}", yes_no(p.prochot));
            println!("  critical temperature:  {}", yes_no(p.critical));
            println!("  power limited:         {}", yes_no(p.power_limited));
            // Sticky bits: history, not current state. Labelled as such so
            // a set flag on an idle machine isn't read as an active alarm.
            println!(
                "  thermal throttled at least once since boot: {}",
                yes_no(p.thermal_since_boot)
            );
            println!(
                "  power limited at least once since boot:     {}",
                yes_no(p.power_limited_since_boot)
            );
            match p.limit_reason() {
                Some(r) => println!("  currently limited: {r}"),
                None => println!("  currently limited: no"),
            }
        }
        None => println!("CPU thermal MSRs: unavailable"),
    }

    println!();
    let chips = hub.chips();
    if chips.is_empty() {
        println!(
            "Super I/O: {}",
            hub.superio_error().unwrap_or("no chip found")
        );
    }
    for c in chips {
        println!(
            "Super I/O: {} (id {:#04x} rev {:#04x}) on port {:#06x}, {} fan channel(s){}",
            c.name,
            c.id,
            c.revision,
            c.register_port,
            c.fan_count,
            if c.family.fans_supported() {
                ""
            } else {
                " - not decoded by rMon"
            }
        );
    }
    let fans = hub.fans();
    if fans.is_empty() {
        println!("no fan tachometers available");
    }
    for f in fans {
        match f.rpm {
            Some(rpm) => println!("  {}: {rpm} rpm", f.label),
            None => println!("  {}: no fan connected", f.label),
        }
    }

    println!();
    println!("Motherboard temperatures:");
    let temperatures = hub.board_temperatures();
    if temperatures.is_empty() {
        println!("  unavailable");
    }
    for reading in temperatures {
        match reading.temp_c {
            Some(temp_c) => println!("  {}: {temp_c:.1}°C", reading.label),
            None => println!("  {}: unconnected/unavailable", reading.label),
        }
    }

    println!();
    println!("Voltages:");
    let voltages = hub.voltages();
    if voltages.is_empty() {
        println!("  unavailable");
    }
    for reading in voltages {
        match reading.volts {
            Some(volts) => println!("  {}: {volts:.3} V", reading.label),
            None => println!("  {}: unavailable", reading.label),
        }
    }
    if voltages
        .iter()
        .any(|reading| reading.label.contains("ADC pin"))
    {
        println!(
            "  note: VIN values are ADC pin voltages; motherboard-specific +5V/+12V divider scaling is not guessed"
        );
    }

    if raw {
        print_raw_diagnostics(&hub);
    }

    println!();
    println!("Optional: cross-check unfamiliar channels against firmware or HWiNFO.");
    Ok(())
}

/// Raw Super I/O bytes plus what each configuration port answered.
///
/// The vendor ID is the load-bearing line: reading 0x5CA3 back through the
/// same banked path the fan registers use proves the base address and bank
/// switching are right, which means implausible fan numbers are a wrong
/// register map. All-0xFF means the block isn't answering at all.
fn print_raw_diagnostics(hub: &rmon_core::SensorHub) {
    println!();
    println!("--- raw diagnostics ---");

    match rmon_core::sensors::probe_slots() {
        Ok(probes) => {
            for p in probes {
                println!(
                    "  port {:#06x}: id {:#04x} rev {:#04x} -> {}",
                    p.register_port,
                    p.id,
                    p.revision,
                    p.recognised
                        .as_deref()
                        .unwrap_or("not in rMon's chip table")
                );
            }
        }
        Err(e) => println!("  slot probe failed: {}", e.message()),
    }

    let dumps = hub.raw_dump();
    if dumps.is_empty() {
        println!("  no Super I/O chip to dump");
    }
    for d in dumps {
        println!();
        println!("  {} at base {:#06x} ({:?})", d.chip, d.hm_base, d.family);
        if let Some(vendor_id) = d.vendor_id {
            println!(
                "    vendor id: {vendor_id:#06x} ({})",
                if d.vendor_id_ok() {
                    "correct - banked reads are working"
                } else {
                    "WRONG - expected 0x5ca3, so the block is not answering"
                }
            );
        }
        if let Some(e) = &d.error {
            println!("    dump failed: {e}");
        }
        for (reg, high, low) in &d.registers {
            let counter = ((*high as u32) << 5) | (*low as u32 & 0x1F);
            let direct = ((*high as u32) << 8) | *low as u32;
            println!(
                "    {reg:#05x}: {high:#04x} {low:#04x}  as-counter={counter} as-rpm={direct}"
            );
        }
    }
}

fn yes_no(v: bool) -> &'static str {
    if v { "yes" } else { "no" }
}

fn run_power(raw: bool) -> Result<()> {
    use rmon_core::pawnio::{Module, PawnIo};
    use rmon_core::sensors::intel_power;

    if !rmon_core::elevate::is_elevated() {
        println!("rMon is not running as Administrator — the kernel driver cannot be opened.");
        println!("Re-run this command from an elevated terminal.");
        return Ok(());
    }

    let io = match PawnIo::load(Module::IntelMsr) {
        Ok(io) => io,
        Err(a) => {
            println!("Intel MSR access unavailable: {}", a.message());
            return Ok(());
        }
    };

    let probes = intel_power::probe(&io);
    let find = |addr: u64| {
        probes
            .iter()
            .find(|p| p.register.addr == addr)
            .and_then(|p| p.raw())
    };

    // Refusals are the expected outcome for anything the vendored module
    // does not allowlist, so they are reported as a count rather than as
    // errors, and only enumerated under --raw.
    let denied = probes.iter().filter(|p| p.value.is_err()).count();
    println!(
        "Read {} of {} power registers ({} refused by the driver module).",
        probes.len() - denied,
        probes.len(),
        denied
    );
    println!();

    // Everything below is gated on its own source register: a decoded
    // line appears only when the register behind it was actually read.
    let units = find(0x606).map(intel_power::RaplUnits::decode);

    match (find(0x610), units) {
        (Some(raw), Some(units)) => {
            let limits = intel_power::PackagePowerLimits::decode(raw, units);
            println!("Package power limits");
            for (label, l) in [("PL1", limits.pl1), ("PL2", limits.pl2)] {
                println!(
                    "  {label}: {:6.1} W over {:6.3} s   enabled={} clamping={}",
                    l.watts,
                    l.window_s,
                    yes_no(l.enabled),
                    yes_no(l.clamping)
                );
            }
            println!("  register locked by firmware: {}", yes_no(limits.locked));
        }
        (Some(_), None) => {
            println!("Package power limits: read, but MSR_RAPL_POWER_UNIT was refused")
        }
        _ => println!("Package power limits: unavailable"),
    }
    println!();

    match find(0x601) {
        Some(raw) => {
            let c = intel_power::CurrentLimit::decode(raw);
            println!(
                "IccMax (the EDP ceiling): {:.1} A   locked={}",
                c.amps,
                yes_no(c.locked)
            );
        }
        None => println!("IccMax: unavailable"),
    }
    println!();

    match find(0x64F) {
        Some(raw) => {
            let reasons = intel_power::decode_limit_reasons(raw);
            println!("Why the cores are being held back");
            let active: Vec<_> = reasons.iter().filter(|r| r.active).collect();
            if active.is_empty() {
                println!("  nothing is limiting the cores right now");
            }
            for r in active {
                println!("  ACTIVE NOW: {}", r.name);
            }
            let logged: Vec<_> = reasons
                .iter()
                .filter(|r| r.since_cleared && !r.active)
                .collect();
            for r in logged {
                println!("  since boot: {}", r.name);
            }
        }
        // This is the register the whole command exists for, so its
        // absence is worth naming rather than silently skipping.
        None => println!(
            "Limit attribution: MSR_CORE_PERF_LIMIT_REASONS was refused — \
             the driver module does not allowlist it, so PL1/PL2/EDP \
             cannot be separated on this machine."
        ),
    }
    println!();

    match find(0xE2) {
        Some(raw) => {
            let c = intel_power::CStateConfig::decode(raw);
            println!("Package C-state limit: {}", c.package_limit);
            println!("  locked by firmware:  {}", yes_no(c.locked));
            println!("  C1 auto-demotion:    {}", yes_no(c.c1_auto_demotion));
        }
        None => println!("Package C-state limit: unavailable"),
    }
    if let Some(raw) = find(0x1FC) {
        let p = intel_power::PowerControl::decode(raw);
        println!("  C1E enabled:         {}", yes_no(p.c1e_enabled));
    }
    println!();

    if let Some(raw) = find(0xCE) {
        let info = intel_power::PlatformInfo::decode(raw);
        println!(
            "Base ratio {}x, minimum ratio {}x, turbo ratios unlocked: {}",
            info.base_ratio,
            info.max_efficiency_ratio,
            yes_no(info.programmable_ratio)
        );
    }
    if let Some(r) = find(0x1AD) {
        let ratios = intel_power::decode_turbo_ratios(r);
        let shown: Vec<String> = ratios
            .iter()
            .take_while(|&&r| r != 0)
            .enumerate()
            .map(|(i, r)| format!("{}c:{}x", i + 1, r))
            .collect();
        if !shown.is_empty() {
            println!("Turbo bins: {}", shown.join("  "));
        }
    }
    if let Some(v) = find(0x198).and_then(intel_power::decode_core_voltage) {
        println!("Core voltage: {v:.4} V");
    }

    if raw {
        println!();
        println!("Raw register reads");
        for p in &probes {
            match &p.value {
                Ok(v) => println!(
                    "  {:#06x} {:<30} {v:#018x}",
                    p.register.addr, p.register.name
                ),
                Err(e) => println!(
                    "  {:#06x} {:<30} REFUSED: {e}",
                    p.register.addr, p.register.name
                ),
            }
            println!("         {}", p.register.purpose);
        }
    }

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
                 {} error(s), {} warning(s) among those shown — queried in {}ms",
                report.whea_events.len(),
                report.whea_error_count,
                report.whea_warning_count,
                report.whea_query_ms,
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
        eprintln!(
            "warning: no GPU data source available (no NVIDIA driver and no 'GPU Engine' perf counters); GPU column will read 0.0"
        );
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
    // "CPU%" alone is ambiguous: this column is percent of one core, so a
    // process saturating a single thread shows 100 on a 32-core machine.
    println!(
        "{:<8} {:<32} {:>9} {:>8} {:<6}",
        "PID", "NAME", "CPU%/CORE", "GPU%", "SRC"
    );
    for p in snapshot.sorted_by_usage().into_iter().take(top) {
        println!(
            "{:<8} {:<32} {:>9.1} {:>8.1} {:<6}",
            p.pid,
            truncate(&p.name, 32),
            p.cpu_percent,
            p.gpu_percent,
            gpu_src_label(p.gpu_source)
        );
    }
    println!(
        "\n{} processes, total CPU {:.1}% of machine ({:.1}% in the single-core units \
         used above, across {} logical cores), total GPU {:.1}%",
        snapshot.processes.len(),
        snapshot.total_cpu_percent_of_machine(),
        snapshot.total_cpu_percent(),
        snapshot.logical_cores(),
        snapshot.total_gpu_percent()
    );
}

fn print_tree(snapshot: &Snapshot, top: usize, subtree: bool) {
    println!(
        "{:<8} {:<40} {:>9} {:>8} {:<6}",
        "PID", "NAME", "CPU%/CORE", "GPU%", "SRC"
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
            "{:<8} {:<40} {:>9.1} {:>8.1} {:<6}",
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
    let throttle = match &system.cpu_throttle_reason {
        Some(reason) if system.cpu_throttle_confirmed => format!(" [THROTTLED: {reason}]"),
        Some(reason) => format!(" [likely throttled: {reason}]"),
        None => String::new(),
    };
    let mut out = format!("CPU: {cpu_temp} {cpu_clock}{throttle}");
    for gpu in &system.gpus {
        let temp = gpu
            .temp_c
            .map(|t| format!("{t:.0}°C"))
            .unwrap_or_else(|| "n/a".to_string());
        let throttle = if gpu.thermal_throttled {
            " [THERMAL THROTTLE]"
        } else {
            ""
        };
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
                "{ticks} samples taken, {} processes, total CPU {:.1}% of machine, \
                 total GPU {:.1}%   {}",
                snapshot.processes.len(),
                snapshot.total_cpu_percent_of_machine(),
                snapshot.total_gpu_percent(),
                thermal_summary(&snapshot.system)
            );
        }

        std::thread::sleep(interval);
    }

    println!("stopped after {ticks} samples");
    Ok(())
}

/// Names the processes driving WMI. See the `Wmi` command docs for why the
/// two channels give very different answers.
fn run_wmi(secs: i64, max_events: usize, top: usize, trace: Option<String>) -> Result<()> {
    use rmon_core::wmi_activity::{self, ChannelState};

    if let Some(want) = trace {
        let enable = match want.to_ascii_lowercase().as_str() {
            "on" | "true" | "enable" | "enabled" => true,
            "off" | "false" | "disable" | "disabled" => false,
            other => anyhow::bail!("--trace expects on or off, got {other:?}"),
        };
        wmi_activity::set_trace_enabled(enable)?;
        println!(
            "{} {}",
            wmi_activity::TRACE_CHANNEL,
            if enable { "enabled" } else { "disabled" }
        );
        if enable {
            // An analytic channel is write-only while it records, so the
            // obvious next move ("read it now") does not work and saying
            // so here saves a confusing empty result.
            println!(
                "Every WMI operation on this machine is now being recorded — but an analytic \
                 channel cannot be read while it records. Let the load reproduce, then:"
            );
            println!("    rmon wmi --trace off    # stop recording, which makes it readable");
            println!("    rmon wmi                # read what it captured");
        } else {
            println!("The captured trace is now readable — run `rmon wmi` to see the callers.");
        }
        return Ok(());
    }

    let operations = wmi_activity::read_operations(secs, max_events)?;
    let snapshot = Sampler::new().sample();
    let live: std::collections::HashMap<u32, String> = snapshot
        .processes
        .iter()
        .map(|p| (p.pid, p.name.clone()))
        .collect();

    let report = wmi_activity::attribute(
        operations,
        secs,
        |pid| live.get(&pid).cloned(),
        |pid| live.contains_key(&pid),
    );

    println!(
        "trace channel: {}",
        match report.trace_channel {
            ChannelState::Enabled => "enabled (complete)",
            ChannelState::Disabled => "disabled — only slow operations are recorded",
            ChannelState::Unknown => "unknown (needs Administrator to read the config)",
        }
    );
    println!(
        "{} operation(s) from {} caller(s) in the last {}s\n",
        report.operations.len(),
        report.clients.len(),
        report.window_secs,
    );

    if report.clients.is_empty() {
        println!("No WMI activity recorded in the window.");
    }
    for client in report.clients.iter().take(top) {
        println!(
            "{:>6} ops  pid {:<8} {:<24} {}",
            client.operations,
            client.pid,
            client.name.as_deref().unwrap_or("(exited, unnamed)"),
            if client.alive { "running" } else { "exited" },
        );
        if client.failed_operations > 0 {
            println!("            {} failed", client.failed_operations);
        }
        for q in client.queries.iter().take(3) {
            let text: String = q.query.chars().take(140).collect();
            println!("            {:>4}x {text}", q.count);
        }
    }

    if let Some(warning) = &report.sampling_warning {
        println!("\n{warning}");
    }
    if let Some(err) = &report.trace_read_error {
        println!("(the full trace was not read: {err})");
    }
    Ok(())
}

/// Groups orphaned processes under the dead parent that launched them.
fn run_orphans(min_size: usize, members: bool) -> Result<()> {
    let snapshot = Sampler::new().sample();

    // ETW exit history can name the dead parent, but only when elevated and
    // only for parents that died while rMon was watching. Its absence
    // changes the label, never whether the group is found.
    let exits = match rmon_core::ShortLivedWatcher::start() {
        Ok(w) => {
            std::thread::sleep(std::time::Duration::from_millis(500));
            w.recent()
        }
        Err(e) => {
            eprintln!("(dead parents cannot be named: {e})");
            Vec::new()
        }
    };

    let groups = rmon_core::significant_groups(&snapshot.processes, &exits, min_size);
    let held: usize = groups.iter().map(|g| g.len()).sum();
    println!(
        "{} orphan group(s) holding {held} of {} processes\n",
        groups.len(),
        snapshot.processes.len(),
    );

    for g in &groups {
        println!("{}", g.summary());
        if members {
            for m in &g.members {
                println!(
                    "    pid {:<8} {:<28} {:>6.1}% CPU  {:>8} MiB",
                    m.pid,
                    m.name,
                    m.cpu_percent,
                    m.mem_bytes.unwrap_or(0) / (1024 * 1024),
                );
            }
        }
    }
    if groups.is_empty() {
        println!("(nothing above the --min-size threshold)");
    }
    Ok(())
}
