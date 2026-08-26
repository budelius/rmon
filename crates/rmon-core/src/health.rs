//! Best-effort hardware health signals beyond temperature: WHEA (Windows
//! Hardware Error Architecture) event log entries, BIOS version, and CPU
//! microcode revision.
//!
//! None of this *confirms* silicon degradation on its own — accurate
//! temperature alone never does either. It's evidence a human (or an LLM
//! looking at it) can weigh alongside new instability under load: WHEA
//! `Error`-level entries are actual hardware-reported faults, not a
//! heuristic; the microcode revision and BIOS version are just facts to
//! cross-reference against your CPU vendor's own advisories (e.g. Intel's
//! 13th/14th-gen voltage erratum) — this module deliberately does not try
//! to encode "which microcode version fixes which erratum" itself, since
//! that guidance changes over time and varies by motherboard vendor.
//!
//! The WHEA query is genuinely slow (see `check_hardware_health`) — always
//! run it off whatever thread is driving UI/responsiveness (a background
//! thread in the GUI/TUI, `spawn_blocking` for the MCP server), the same
//! way the open-files scan already has to be.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use winreg::RegKey;
use winreg::enums::HKEY_LOCAL_MACHINE;
use wmi::{WMIConnection, WMIDateTime};

/// Kept modest because `Win32_NTLogEvent` (the only way to read the event
/// log without adding a whole separate `EvtQuery`/`wevtapi.dll` FFI layer)
/// is slow and doesn't filter server-side on anything but `Logfile`/
/// `SourceName` — a wider window means enumerating more matching rows, not
/// just displaying more of them. On a system that logs WHEA entries
/// frequently, even 7 days can take 10-30+ seconds; this is normal for this
/// WMI class, not a hang.
pub const DEFAULT_WHEA_LOOKBACK_DAYS: i64 = 7;
pub const DEFAULT_WHEA_MAX_EVENTS: usize = 200;

/// One `Microsoft-Windows-WHEA-Logger` entry from the System event log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WheaEvent {
    pub time: DateTime<Utc>,
    /// "Error" / "Warning" / "Information" / "Security Audit
    /// Success"/"Failure" / "Unknown" — the classic NT event type, not a
    /// WHEA-specific severity.
    pub level: String,
    pub event_id: u32,
    pub record_number: u32,
    pub message: String,
}

/// Snapshot of hardware-health-relevant facts, gathered on demand (not
/// something to poll every tick — the WHEA query walks the System event
/// log via `Win32_NTLogEvent`, a notoriously slow WMI class with no useful
/// server-side filtering beyond `Logfile`/`SourceName`. Expect this to take
/// anywhere from under a second to 30+ seconds depending on how much the
/// system logs to `Microsoft-Windows-WHEA-Logger` and `lookback_days`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HardwareHealthReport {
    pub whea_events: Vec<WheaEvent>,
    pub whea_error_count: usize,
    pub whea_warning_count: usize,
    /// Set instead of `whea_events` being merely empty when the WMI query
    /// itself failed (vs. legitimately finding nothing).
    pub whea_query_error: Option<String>,
    pub bios_manufacturer: Option<String>,
    pub bios_version: Option<String>,
    pub bios_release_date: Option<String>,
    /// The CPU's loaded microcode revision, as hex (e.g. `"0x12F"`) — read
    /// from the same `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0`
    /// `Update Revision` registry value CPU-Z/HWiNFO read without a kernel
    /// driver. This says *which* microcode is loaded, not whether it's "the
    /// fix" for any specific erratum — check that hex value against your
    /// CPU vendor's own advisory.
    pub microcode_revision: Option<String>,
}

/// Gathers a `HardwareHealthReport`: WHEA events from the last
/// `lookback_days` (capped at `max_events`, most recent first), plus BIOS
/// version and CPU microcode revision. Best-effort throughout — a failure
/// to read BIOS info or the microcode revision just leaves that field
/// `None`; only the WHEA query records its own error, since it's the part
/// most likely to fail (WMI unavailable, permissions) or be worth knowing
/// came back empty vs. errored.
pub fn check_hardware_health(lookback_days: i64, max_events: usize) -> HardwareHealthReport {
    let mut report = HardwareHealthReport::default();

    match query_whea_events(lookback_days, max_events) {
        Ok(events) => {
            report.whea_error_count = events.iter().filter(|e| e.level == "Error").count();
            report.whea_warning_count = events.iter().filter(|e| e.level == "Warning").count();
            report.whea_events = events;
        }
        Err(e) => report.whea_query_error = Some(format!("{e:#}")),
    }

    if let Some((manufacturer, version, release_date)) = query_bios() {
        report.bios_manufacturer = manufacturer;
        report.bios_version = version;
        report.bios_release_date = release_date;
    }

    report.microcode_revision = read_microcode_revision();

    report
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct NtLogEventRow {
    TimeGenerated: WMIDateTime,
    EventCode: u16,
    EventType: u8,
    RecordNumber: u32,
    Message: Option<String>,
}

fn event_type_label(t: u8) -> &'static str {
    match t {
        1 => "Error",
        2 => "Warning",
        3 => "Information",
        4 => "Security Audit Success",
        5 => "Security Audit Failure",
        _ => "Unknown",
    }
}

fn query_whea_events(lookback_days: i64, max_events: usize) -> Result<Vec<WheaEvent>> {
    let conn = WMIConnection::new().context("WMI ROOT\\CIMV2 unavailable")?;
    let since = Utc::now() - chrono::Duration::days(lookback_days);
    // CIM_DATETIME format: yyyymmddHHMMSS.mmmmmm+UUU (UUU = UTC offset in minutes).
    let since_wmi = format!("{}.000000+000", since.format("%Y%m%d%H%M%S"));
    let query = format!(
        "SELECT TimeGenerated, EventCode, EventType, RecordNumber, Message FROM Win32_NTLogEvent \
         WHERE Logfile='System' AND SourceName='Microsoft-Windows-WHEA-Logger' AND TimeGenerated > '{since_wmi}'"
    );
    let rows: Vec<NtLogEventRow> = conn
        .raw_query(&query)
        .context("Win32_NTLogEvent query failed")?;

    let mut events: Vec<WheaEvent> = rows
        .into_iter()
        .map(|r| WheaEvent {
            time: r.TimeGenerated.0.with_timezone(&Utc),
            level: event_type_label(r.EventType).to_string(),
            event_id: r.EventCode as u32,
            record_number: r.RecordNumber,
            message: r.Message.unwrap_or_default(),
        })
        .collect();
    events.sort_by(|a, b| b.time.cmp(&a.time));
    events.truncate(max_events);
    Ok(events)
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct BiosRow {
    Manufacturer: Option<String>,
    SMBIOSBIOSVersion: Option<String>,
    ReleaseDate: Option<WMIDateTime>,
}

fn query_bios() -> Option<(Option<String>, Option<String>, Option<String>)> {
    let conn = WMIConnection::new().ok()?;
    let rows: Vec<BiosRow> = conn
        .raw_query("SELECT Manufacturer, SMBIOSBIOSVersion, ReleaseDate FROM Win32_BIOS")
        .ok()?;
    let row = rows.into_iter().next()?;
    let release_date = row.ReleaseDate.map(|d| d.0.format("%Y-%m-%d").to_string());
    Some((row.Manufacturer, row.SMBIOSBIOSVersion, release_date))
}

/// Reads the CPU's loaded microcode revision from the registry — the same
/// technique CPU-Z/HWiNFO use to surface it without a kernel driver. The
/// `Update Revision` value's last 4 bytes, read little-endian, are the
/// revision number (verified against this technique's well-known
/// convention; on a 13th-gen Intel test system this reads e.g. `0x12F`).
fn read_microcode_revision() -> Option<String> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm
        .open_subkey("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0")
        .ok()?;
    let value = key.get_raw_value("Update Revision").ok()?;
    let bytes = &value.bytes;
    if bytes.len() < 4 {
        return None;
    }
    let last4: [u8; 4] = bytes[bytes.len() - 4..].try_into().ok()?;
    Some(format!("0x{:X}", u32::from_le_bytes(last4)))
}
