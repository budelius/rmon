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
//! The WHEA query reads the System channel through `wevtapi`'s
//! `EvtQuery`, which the channel's per-provider index answers in tens of
//! milliseconds regardless of lookback. It still runs off the UI thread
//! (a background thread in the GUI/TUI, `spawn_blocking` for the MCP
//! server) because it is I/O and nothing guarantees a cold channel stays
//! fast — but it is no longer the multi-second stall it was under WMI.
//! See `query_whea_events` for the measurements behind that change.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use windows::Win32::System::EventLog::{
    EVT_HANDLE, EVT_SYSTEM_PROPERTY_ID, EVT_VARIANT, EvtCreateRenderContext, EvtFormatMessage,
    EvtFormatMessageEvent, EvtNext, EvtOpenPublisherMetadata, EvtQuery, EvtQueryChannelPath,
    EvtQueryReverseDirection, EvtRender, EvtRenderContextSystem, EvtRenderEventValues,
    EvtSystemEventID, EvtSystemEventRecordId, EvtSystemLevel, EvtSystemTimeCreated, EvtVarTypeByte,
    EvtVarTypeFileTime, EvtVarTypeUInt16, EvtVarTypeUInt64,
};
use windows_core::{HSTRING, Owned};
use winreg::RegKey;
use winreg::enums::HKEY_LOCAL_MACHINE;
use wmi::{WMIConnection, WMIDateTime};

/// A month of history, which is enough to see whether new instability
/// under load coincides with the machine starting to log hardware errors.
///
/// This was 7 days when the query went through WMI's `Win32_NTLogEvent`,
/// purely as damage control: that provider walks the log record by record
/// and its cost scales with the *window*, so 30 days cost ~6.7s and a year
/// ~44s on the 30k-record log this was measured on. `EvtQuery` answers
/// from the channel's provider index instead, so the same 30 days cost
/// ~47ms and a year ~52ms — flat. With the reason for the small window
/// gone, the window is no longer small.
pub const DEFAULT_WHEA_LOOKBACK_DAYS: i64 = 30;
pub const DEFAULT_WHEA_MAX_EVENTS: usize = 200;

/// One `Microsoft-Windows-WHEA-Logger` entry from the System event log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WheaEvent {
    pub time: DateTime<Utc>,
    /// "Critical" / "Error" / "Warning" / "Information" / "Verbose" —
    /// the event's own severity level, not a WHEA-specific one. A
    /// corrected (and therefore survivable) machine-check normally logs
    /// as "Warning" or "Information"; "Error" and "Critical" are the
    /// levels worth reacting to.
    pub level: String,
    pub event_id: u32,
    pub record_number: u32,
    pub message: String,
}

/// Snapshot of hardware-health-relevant facts, gathered on demand. Not
/// something to poll every tick — it is still three separate I/O trips
/// (event channel, WMI for BIOS, registry) — but the WHEA query now costs
/// tens of milliseconds rather than tens of seconds, so calling it on a
/// human-driven refresh is entirely reasonable. `whea_query_ms` reports
/// what it actually cost.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HardwareHealthReport {
    pub whea_events: Vec<WheaEvent>,
    pub whea_error_count: usize,
    pub whea_warning_count: usize,
    /// Set instead of `whea_events` being merely empty when the query
    /// itself failed (vs. legitimately finding nothing).
    pub whea_query_error: Option<String>,
    /// How long the event-log query actually took.
    ///
    /// Reported because this scan used to be the most expensive thing
    /// rMon did, and an unattributed multi-second stall inside a
    /// monitoring tool gets blamed on whatever the tool happens to be
    /// displaying at the time — including, repeatedly, rMon itself.
    #[serde(default)]
    pub whea_query_ms: u64,
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

    let started = std::time::Instant::now();
    let queried = query_whea_events(lookback_days, max_events);
    report.whea_query_ms = started.elapsed().as_millis() as u64;
    match queried {
        Ok(events) => {
            // "Critical" counts as an error: it is the more severe level,
            // and a caller checking `whea_error_count > 0` is asking
            // "did this machine report a hardware fault", which it did.
            report.whea_error_count = events
                .iter()
                .filter(|e| e.level == "Error" || e.level == "Critical")
                .count();
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

/// The provider whose System-channel events describe machine-check and
/// other hardware-error reports.
const WHEA_PROVIDER: &str = "Microsoft-Windows-WHEA-Logger";

/// `EvtNext` batch size. Large enough that a full `max_events` result set
/// takes a couple of round trips, small enough to keep the handle array on
/// the stack.
const EVT_BATCH: usize = 64;

fn level_label(level: u8) -> &'static str {
    match level {
        1 => "Critical",
        2 => "Error",
        3 => "Warning",
        // 0 is "LogAlways", which carries no severity of its own; grouping
        // it with Information keeps it out of the error and warning counts,
        // which is the honest placement for "the provider didn't say".
        0 | 4 => "Information",
        5 => "Verbose",
        _ => "Unknown",
    }
}

/// Converts a Win32 FILETIME (100ns ticks since 1601-01-01 UTC) to a
/// `DateTime<Utc>`.
fn filetime_to_utc(ticks: u64) -> Option<DateTime<Utc>> {
    // Seconds between 1601-01-01 and the Unix epoch.
    const EPOCH_DIFF_SECS: i64 = 11_644_473_600;
    let secs = (ticks / 10_000_000) as i64 - EPOCH_DIFF_SECS;
    let nanos = (ticks % 10_000_000) as u32 * 100;
    DateTime::from_timestamp(secs, nanos)
}

/// Reads the most recent WHEA events from the System channel.
///
/// Uses `EvtQuery` (`wevtapi`) rather than WMI's `Win32_NTLogEvent`. The
/// two are not close: `Win32_NTLogEvent` cannot use the channel's
/// per-provider index, so it walks records one at a time and its cost
/// scales with how many records fall inside the time window. Measured on a
/// 30,138-record System log, querying this provider:
///
/// | lookback | `Win32_NTLogEvent` | `EvtQuery` |
/// |----------|-------------------:|-----------:|
/// | 7 days   |            ~870 ms |    ~130 ms |
/// | 30 days  |          ~6,690 ms |     ~47 ms |
/// | 365 days |         ~43,945 ms |     ~52 ms |
///
/// WMI's cost grows with the window; `EvtQuery`'s is flat, because the
/// filtering happens in the index instead of in a scan. (The obvious
/// suspect for the WMI cost — formatting each record's `Message` — turned
/// out to be noise: dropping `Message` from the `SELECT` changed nothing
/// measurable once the WMI service was warm.)
///
/// The query runs in reverse (newest first), so `max_events` bounds the
/// work done rather than just trimming a full result set afterwards.
fn query_whea_events(lookback_days: i64, max_events: usize) -> Result<Vec<WheaEvent>> {
    if max_events == 0 {
        return Ok(Vec::new());
    }
    // `timediff` takes milliseconds back from now. Clamped at zero so a
    // negative lookback asks for "since now" rather than being reinterpreted
    // as an enormous window.
    let window_ms = lookback_days.max(0).saturating_mul(86_400_000);
    let xpath = format!(
        "*[System[Provider[@Name='{WHEA_PROVIDER}'] \
         and TimeCreated[timediff(@SystemTime) <= {window_ms}]]]"
    );

    let results = unsafe {
        Owned::new(
            EvtQuery(
                None,
                &HSTRING::from("System"),
                &HSTRING::from(xpath.as_str()),
                EvtQueryChannelPath.0 | EvtQueryReverseDirection.0,
            )
            .context("EvtQuery on the System channel failed")?,
        )
    };

    // A system render context yields the fixed <System> properties
    // (provider, level, times, record id) without parsing any XML.
    let context = unsafe {
        Owned::new(
            EvtCreateRenderContext(None, EvtRenderContextSystem.0)
                .context("EvtCreateRenderContext failed")?,
        )
    };

    // Message text comes from the publisher's own message tables. Opened
    // once for the whole batch rather than per event; if the publisher is
    // not registered we still return every event, just without prose.
    let publisher = unsafe {
        EvtOpenPublisherMetadata(None, &HSTRING::from(WHEA_PROVIDER), None, 0, 0)
            .ok()
            .map(|h| Owned::new(h))
    };
    let publisher_handle = publisher.as_ref().map(|h| **h);

    let mut events = Vec::new();
    let mut render_buf = vec![0u8; 4096];
    let mut message_buf = vec![0u16; 2048];

    'outer: loop {
        let mut handles = [0isize; EVT_BATCH];
        let mut returned = 0u32;
        // Timeout 0: everything is already on disk, so there is nothing to
        // wait for. This returns what is available, then fails with
        // ERROR_NO_MORE_ITEMS, which is the loop's normal exit.
        if unsafe { EvtNext(*results, &mut handles, 0, 0, &mut returned) }.is_err() {
            break;
        }
        for &raw in handles.iter().take(returned as usize) {
            let event = unsafe { Owned::new(EVT_HANDLE(raw)) };
            if let Some(e) = unsafe { render_event(*context, *event, &mut render_buf) } {
                events.push(unsafe { with_message(e, *event, publisher_handle, &mut message_buf) });
                if events.len() >= max_events {
                    break 'outer;
                }
            }
        }
        if (returned as usize) < EVT_BATCH {
            break;
        }
    }

    // The query already returns newest first; sorting makes that a
    // guarantee of this function rather than of the flag we passed.
    events.sort_by(|a, b| b.time.cmp(&a.time));
    Ok(events)
}

/// Renders one event's `<System>` block into a `WheaEvent` with an empty
/// message. `None` when the event cannot be rendered or carries no
/// timestamp, which would leave it unplaceable in the timeline.
unsafe fn render_event(
    context: EVT_HANDLE,
    event: EVT_HANDLE,
    buf: &mut Vec<u8>,
) -> Option<WheaEvent> {
    let mut used = 0u32;
    let mut count = 0u32;
    let flags = EvtRenderEventValues.0;
    let mut ok = unsafe {
        EvtRender(
            Some(context),
            event,
            flags,
            buf.len() as u32,
            Some(buf.as_mut_ptr() as *mut _),
            &mut used,
            &mut count,
        )
    };
    if ok.is_err() && used as usize > buf.len() {
        buf.resize(used as usize, 0);
        ok = unsafe {
            EvtRender(
                Some(context),
                event,
                flags,
                buf.len() as u32,
                Some(buf.as_mut_ptr() as *mut _),
                &mut used,
                &mut count,
            )
        };
    }
    ok.ok()?;

    // The buffer is an array of EVT_VARIANT indexed by EVT_SYSTEM_PROPERTY_ID.
    let values =
        unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const EVT_VARIANT, count as usize) };
    let at = |id: EVT_SYSTEM_PROPERTY_ID| values.get(id.0 as usize);

    // EvtVarTypeNull (0) marks a property the event does not carry, and its
    // union payload is meaningless — so every read below is guarded on the
    // variant's own type tag rather than assuming the property is present.
    let time = at(EvtSystemTimeCreated)
        .filter(|v| v.Type == EvtVarTypeFileTime.0 as u32)
        .and_then(|v| filetime_to_utc(unsafe { v.Anonymous.FileTimeVal }))?;
    let level = at(EvtSystemLevel)
        .filter(|v| v.Type == EvtVarTypeByte.0 as u32)
        .map_or(0, |v| unsafe { v.Anonymous.ByteVal });
    let event_id = at(EvtSystemEventID)
        .filter(|v| v.Type == EvtVarTypeUInt16.0 as u32)
        .map_or(0, |v| unsafe { v.Anonymous.UInt16Val });
    let record_number = at(EvtSystemEventRecordId)
        .filter(|v| v.Type == EvtVarTypeUInt64.0 as u32)
        .map_or(0, |v| unsafe { v.Anonymous.UInt64Val });

    Some(WheaEvent {
        time,
        level: level_label(level).to_string(),
        event_id: event_id as u32,
        // Record ids are 64-bit in the modern API but only exceed 32 bits
        // on logs far larger than Windows retains; saturating keeps the
        // public type stable without wrapping to a misleadingly small id.
        record_number: record_number.min(u32::MAX as u64) as u32,
        message: String::new(),
    })
}

/// Fills in `message` by formatting the event against its publisher's
/// message tables. Leaves it empty when the publisher is unregistered or
/// the string cannot be resolved — the event itself is still worth
/// reporting without prose.
unsafe fn with_message(
    mut e: WheaEvent,
    event: EVT_HANDLE,
    publisher: Option<EVT_HANDLE>,
    buf: &mut Vec<u16>,
) -> WheaEvent {
    let Some(publisher) = publisher else {
        return e;
    };
    let flags = EvtFormatMessageEvent.0;
    let mut used = 0u32;
    let ok = unsafe {
        EvtFormatMessage(
            Some(publisher),
            Some(event),
            0,
            None,
            flags,
            Some(buf.as_mut_slice()),
            &mut used,
        )
    };
    if ok.is_err() && used as usize > buf.len() {
        buf.resize(used as usize, 0);
        let _ = unsafe {
            EvtFormatMessage(
                Some(publisher),
                Some(event),
                0,
                None,
                flags,
                Some(buf.as_mut_slice()),
                &mut used,
            )
        };
    }
    // A partially-resolved message (ERROR_EVT_UNRESOLVED_VALUE_INSERT and
    // friends) still fills the buffer and is far more useful than nothing,
    // so the buffer contents decide this, not the return code.
    if used > 0 {
        let len = (used as usize).min(buf.len());
        let text = String::from_utf16_lossy(&buf[..len]);
        let text = text.trim_end_matches('\0').trim();
        if !text.is_empty() {
            e.message = text.to_string();
        }
    }
    e
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every documented NT level maps to a label, and only the two that
    /// mean "the hardware reported a fault" feed `whea_error_count`.
    #[test]
    fn level_labels_cover_the_documented_range() {
        assert_eq!(level_label(1), "Critical");
        assert_eq!(level_label(2), "Error");
        assert_eq!(level_label(3), "Warning");
        assert_eq!(level_label(4), "Information");
        assert_eq!(level_label(5), "Verbose");
        // LogAlways carries no severity; it must not inflate either count.
        assert_eq!(level_label(0), "Information");
        assert_eq!(level_label(200), "Unknown");
    }

    #[test]
    fn filetime_converts_against_a_known_epoch() {
        // 11_644_473_600s of 100ns ticks is exactly the Unix epoch.
        let unix_epoch = filetime_to_utc(11_644_473_600 * 10_000_000).unwrap();
        assert_eq!(unix_epoch.timestamp(), 0);
        // One second later, with 100ns of sub-second precision preserved.
        let t = filetime_to_utc(11_644_473_601 * 10_000_000 + 5_000_000).unwrap();
        assert_eq!(t.timestamp(), 1);
        assert_eq!(t.timestamp_subsec_nanos(), 500_000_000);
    }

    /// `max_events` must bound the work, not just trim the output — the
    /// whole point of querying in reverse.
    #[test]
    fn zero_max_events_queries_nothing() {
        assert!(query_whea_events(3650, 0).unwrap().is_empty());
    }

    /// Live check against this machine's System channel. Asserts the
    /// shape of whatever comes back rather than that anything does: a
    /// healthy machine legitimately has no WHEA events at all.
    #[test]
    fn whea_query_is_well_formed_and_fast() {
        let started = std::time::Instant::now();
        let events = query_whea_events(365, 200).expect("EvtQuery must succeed on Windows");
        let elapsed = started.elapsed();
        println!("{} WHEA events over 365 days in {elapsed:?}", events.len());

        // The regression this rewrite exists for: under WMI a 365-day
        // lookback on a 30k-record System log took ~44 seconds. Two
        // seconds is far above EvtQuery's measured ~50ms while still
        // failing loudly if anyone reintroduces a full log walk.
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "365-day WHEA query took {elapsed:?}; a scan-based query has crept back in"
        );

        assert!(
            events.len() <= 200,
            "max_events not honored: {}",
            events.len()
        );
        for w in events.windows(2) {
            assert!(w[0].time >= w[1].time, "events must be newest first");
        }
        let now = Utc::now();
        for e in &events {
            assert!(e.time <= now, "event from the future: {}", e.time);
            assert!(
                (now - e.time).num_days() <= 366,
                "event outside the requested window: {}",
                e.time
            );
            assert!(
                matches!(
                    e.level.as_str(),
                    "Critical" | "Error" | "Warning" | "Information" | "Verbose" | "Unknown"
                ),
                "unexpected level {:?}",
                e.level
            );
        }
        // WHEA's publisher ships message tables on every Windows install,
        // so if we got events at all, at least one must have resolved
        // prose — an all-empty result would mean EvtFormatMessage is
        // silently failing.
        if !events.is_empty() {
            assert!(
                events.iter().any(|e| !e.message.is_empty()),
                "no event resolved a message; EvtFormatMessage is failing"
            );
        }
    }

    /// A narrower window can never return more than a wider one, and both
    /// must stay fast — the property that WMI violated so expensively.
    #[test]
    fn lookback_bounds_results_without_bounding_speed() {
        let wide = query_whea_events(365, 200).unwrap();
        let started = std::time::Instant::now();
        let narrow = query_whea_events(1, 200).unwrap();
        let elapsed = started.elapsed();
        assert!(narrow.len() <= wide.len());
        assert!(elapsed < std::time::Duration::from_secs(2), "{elapsed:?}");
    }

    /// The report must time its own query, so a slow one is attributable
    /// instead of being blamed on whatever process is on screen.
    #[test]
    fn report_records_what_the_query_cost() {
        let report = check_hardware_health(30, 50);
        println!(
            "whea: {} events ({} error, {} warning) in {}ms; bios {:?}; microcode {:?}",
            report.whea_events.len(),
            report.whea_error_count,
            report.whea_warning_count,
            report.whea_query_ms,
            report.bios_version,
            report.microcode_revision,
        );
        assert!(
            report.whea_query_error.is_none(),
            "{:?}",
            report.whea_query_error
        );
        assert!(
            report.whea_query_ms < 2000,
            "WHEA query took {}ms",
            report.whea_query_ms
        );
        let counted = report
            .whea_events
            .iter()
            .filter(|e| e.level == "Error" || e.level == "Critical")
            .count();
        assert_eq!(counted, report.whea_error_count);
    }
}
