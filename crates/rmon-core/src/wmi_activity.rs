//! Who is driving WMI, and what are they asking for.
//!
//! A saturated `WmiPrvSE.exe` is a symptom with the cause hidden one
//! process away: the provider host does the work, but some *other* process
//! asked for it, and Task Manager attributes the CPU to the host. This
//! module names the caller.
//!
//! # Why not read this through WMI
//!
//! Because the thing being diagnosed is WMI overload, and `Win32_NTLogEvent`
//! would dispatch another query into the very provider host that is already
//! pinned — measurement that changes what it measures. (It also cannot read
//! this log at all: `Win32_NTLogEvent` only exposes the classic
//! System/Application/Security logs, not modern ETW channels.) So this goes
//! through `wevtapi.dll`'s `EvtQuery` directly: a plain read of an event
//! channel, no provider host involved.
//!
//! # The two channels, and why the quiet one lies
//!
//! - **`Microsoft-Windows-WMI-Activity/Operational`** is enabled by default,
//!   but only records operations that cross a slowness threshold. On a busy
//!   machine that is a small and badly biased sample: it shows *that* heavy
//!   `Win32_Process` enumerations are happening while routinely missing the
//!   caller, because the client has usually exited by the time anyone reads
//!   the log.
//! - **`Microsoft-Windows-WMI-Activity/Trace`** is an analytic channel,
//!   disabled by default, that records *every* operation with its client pid.
//!   That is what actually names the caller. Enabling it needs Administrator
//!   and costs log volume, so it is opt-in and meant to be turned back off —
//!   see [`set_trace_enabled`].
//!
//! # Tracing is capture-then-read, and reading it needs elevation
//!
//! Measured on Windows 11, not assumed: the analytic channel refuses a
//! query by *channel path* with "the request is not supported" whether it
//! is recording or not. Its events are only reachable through the backing
//! `Microsoft-Windows-WMI-Activity%4Trace.evtx` under
//! `%SystemRoot%\System32\Winevt\Logs`, so [`read_channel`] queries that
//! file directly — and because that directory is not user-readable, a
//! non-elevated read gets nothing and quietly falls back to the sampled
//! channel.
//!
//! The practical consequence is that tracing is capture-then-read rather
//! than live: enable, let the load reproduce, disable, then read. So
//! [`sampling_warning`] separates "tracing is off" from "tracing is on but
//! nothing traced was readable" — telling someone to enable a channel that
//! is already recording would send them in a circle.
//!
//! # Naming callers that already exited
//!
//! The interesting clients are often short-lived: they run one enumeration
//! over every process on the machine and exit before anyone can look them up
//! by pid. A live process table cannot name them. rMon's ETW exit history
//! can (see [`crate::proc_events::ShortLivedWatcher`]), so [`attribute`]
//! takes a resolver and callers should feed it both.

use std::collections::HashMap;

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use windows::Win32::Foundation::ERROR_NO_MORE_ITEMS;
use windows::Win32::System::EventLog::{
    EVT_HANDLE, EVT_VARIANT, EvtChannelConfigEnabled, EvtChannelLoggingConfigLogFilePath, EvtClose,
    EvtGetChannelConfigProperty, EvtNext, EvtOpenChannelConfig, EvtQuery, EvtQueryChannelPath,
    EvtQueryFilePath, EvtQueryReverseDirection, EvtRender, EvtRenderEventXml, EvtSaveChannelConfig,
    EvtSetChannelConfigProperty, EvtVarTypeBoolean,
};
use windows::core::PCWSTR;

/// Always on, but only records operations slow enough to cross a threshold.
pub const OPERATIONAL_CHANNEL: &str = "Microsoft-Windows-WMI-Activity/Operational";
/// Off by default; records every operation, which is what names the caller.
pub const TRACE_CHANNEL: &str = "Microsoft-Windows-WMI-Activity/Trace";

/// How far back to look by default.
pub const DEFAULT_LOOKBACK_SECS: i64 = 3600;
/// Cap on events pulled in one read, so a busy trace channel cannot make
/// this unbounded.
pub const DEFAULT_MAX_EVENTS: usize = 5000;

/// One WMI operation, as recorded by either channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WmiOperation {
    pub time: DateTime<Utc>,
    /// The process that *asked* for the work — the point of this module.
    pub client_pid: Option<u32>,
    /// Namespace the query ran against, e.g. `root\cimv2`.
    pub namespace: Option<String>,
    /// The query text or method name, when the event carries one.
    pub query: Option<String>,
    /// Raw operation string, kept whole because the structured fields above
    /// are parsed out of it best-effort.
    pub operation: String,
    /// Non-zero means the operation failed; `0x80041010` is "class not
    /// found", a common source of repeated pointless queries.
    pub result_code: Option<String>,
    /// Which channel this came from, since their coverage differs sharply.
    pub channel: WmiChannel,
}

/// Which WMI-Activity channel an operation came from. The distinction is
/// not cosmetic: one is a biased sample and the other is complete, so a
/// count means something different depending on its source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WmiChannel {
    /// Sampled: only operations slow enough to cross a threshold.
    Operational,
    /// Complete: every operation, once the channel is enabled.
    Trace,
}

/// Everything one client process asked WMI to do in the window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WmiClient {
    pub pid: u32,
    /// `None` when the process is gone and no exit history named it.
    pub name: Option<String>,
    /// Whether the process still exists. A client that keeps exiting and
    /// being replaced is a very different problem from one long-lived
    /// process polling in a loop, and the fix differs accordingly.
    pub alive: bool,
    pub operations: usize,
    pub failed_operations: usize,
    /// Distinct queries this client issued, most frequent first.
    pub queries: Vec<QueryCount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryCount {
    pub query: String,
    pub count: usize,
}

/// Whether a channel is enabled, and whether we could even tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelState {
    Enabled,
    Disabled,
    /// The channel config could not be read (usually not elevated).
    Unknown,
}

/// A full picture of who is driving WMI right now.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WmiActivityReport {
    pub trace_channel: ChannelState,
    pub window_secs: i64,
    pub operations: Vec<WmiOperation>,
    /// Clients ranked by how much they asked for.
    pub clients: Vec<WmiClient>,
    /// Set when the operational channel was the only source, because then
    /// the ranking below is a biased sample rather than the whole truth.
    pub sampling_warning: Option<String>,
    /// Why the complete channel contributed nothing, when it didn't.
    ///
    /// Almost always "Access is denied": the capture lives in an `.evtx`
    /// under `System32\Winevt\Logs`, which needs Administrator to open.
    /// Carried on the report rather than left in a debug log, because a
    /// silently sampled result looks identical to a complete one.
    pub trace_read_error: Option<String>,
}

impl WmiActivityReport {
    /// The heaviest caller, if there is one.
    pub fn top_client(&self) -> Option<&WmiClient> {
        self.clients.first()
    }
}

/// Reads recent WMI operations from whichever channels are available.
///
/// The trace channel is preferred and merged in when enabled; the
/// operational channel is always read so there is something to show even
/// before anyone opts in to tracing.
pub fn read_operations(lookback_secs: i64, max_events: usize) -> Result<WmiRead> {
    let mut all = Vec::new();

    // Operational is always present; a failure to read it is worth
    // reporting, unlike the analytic channel which is usually just off.
    match read_channel(OPERATIONAL_CHANNEL, lookback_secs, max_events) {
        Ok(mut ops) => all.append(&mut ops),
        Err(e) => log::debug!("operational channel unreadable: {e:#}"),
    }
    // Kept rather than swallowed: without the reason, a silently sampled
    // result is indistinguishable from a complete one, and the usual cause
    // (the capture file needs Administrator) is something the reader can
    // act on.
    let trace_read_error = match read_channel(TRACE_CHANNEL, lookback_secs, max_events) {
        Ok(mut ops) => {
            log::debug!("trace channel yielded {} operation(s)", ops.len());
            all.append(&mut ops);
            None
        }
        Err(e) => {
            log::debug!("trace channel unreadable: {e:#}");
            Some(format!("{e:#}"))
        }
    };

    all.sort_by_key(|o| std::cmp::Reverse(o.time));
    all.truncate(max_events);
    Ok(WmiRead {
        operations: all,
        trace_read_error,
    })
}

/// What one read of the channels produced, and why the complete one did
/// not contribute if it didn't.
pub struct WmiRead {
    pub operations: Vec<WmiOperation>,
    pub trace_read_error: Option<String>,
}

/// Builds the full report, naming clients through `resolve_name`.
///
/// `resolve_name` should consult the live process table *and* ETW exit
/// history — the clients worth catching are frequently already gone.
pub fn attribute(
    read: WmiRead,
    lookback_secs: i64,
    resolve_name: impl Fn(u32) -> Option<String>,
    is_alive: impl Fn(u32) -> bool,
) -> WmiActivityReport {
    let WmiRead {
        operations,
        trace_read_error,
    } = read;
    let trace_channel = trace_state();
    let saw_trace = operations.iter().any(|o| o.channel == WmiChannel::Trace);

    let mut by_pid: HashMap<u32, Vec<&WmiOperation>> = HashMap::new();
    for op in &operations {
        if let Some(pid) = op.client_pid {
            by_pid.entry(pid).or_default().push(op);
        }
    }

    let mut clients: Vec<WmiClient> = by_pid
        .into_iter()
        .map(|(pid, ops)| {
            let mut counts: HashMap<&str, usize> = HashMap::new();
            for op in &ops {
                let key = op.query.as_deref().unwrap_or(op.operation.as_str());
                *counts.entry(key).or_default() += 1;
            }
            let mut queries: Vec<QueryCount> = counts
                .into_iter()
                .map(|(query, count)| QueryCount {
                    query: query.to_string(),
                    count,
                })
                .collect();
            queries.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.query.cmp(&b.query)));

            WmiClient {
                pid,
                name: resolve_name(pid),
                alive: is_alive(pid),
                operations: ops.len(),
                failed_operations: ops
                    .iter()
                    .filter(|o| o.result_code.as_deref().is_some_and(|c| c != "0x0"))
                    .count(),
                queries,
            }
        })
        .collect();
    clients.sort_by(|a, b| {
        b.operations
            .cmp(&a.operations)
            .then_with(|| a.pid.cmp(&b.pid))
    });

    let sampling_warning = sampling_warning(saw_trace, trace_channel, trace_read_error.as_deref());

    WmiActivityReport {
        trace_channel,
        window_secs: lookback_secs,
        operations,
        clients,
        sampling_warning,
        trace_read_error,
    }
}

/// How far to trust the counts, in words, or `None` when they are complete.
///
/// Three genuinely different situations, and separating them is the
/// difference between a useful instruction and one that sends the reader in
/// a circle — notably, never telling someone to enable a channel that is
/// already recording.
pub fn sampling_warning(
    saw_trace: bool,
    trace_channel: ChannelState,
    trace_read_error: Option<&str>,
) -> Option<String> {
    // Complete data: nothing to caveat.
    if saw_trace {
        return None;
    }

    let base = "The counts below come only from the operational channel, which records just \
                the operations slow enough to cross a threshold — so they are a biased sample \
                and the busiest caller may be missing entirely.";

    // Permission is the most common reason the capture contributes nothing,
    // and it is the one the reader can actually fix, so it outranks the
    // channel's on/off state as an explanation.
    if trace_read_error.is_some_and(|e| e.contains("Access is denied")) {
        return Some(format!(
            "{base} The full trace could not be read: its capture file lives under \
             System32\\Winevt\\Logs and needs Administrator. Re-run rMon elevated to read it."
        ));
    }

    Some(match trace_channel {
        // Already recording — telling the reader to enable it would send
        // them in a circle. The step that makes a capture readable is
        // turning it off.
        ChannelState::Enabled => format!(
            "Full tracing is ON and capturing, but nothing from it was readable yet. {base} \
             Turn tracing off to read what {TRACE_CHANNEL} captured."
        ),
        _ => format!(
            "{base} Enable {TRACE_CHANNEL} to record every operation, reproduce the load, then \
             turn it back off and read it as Administrator."
        ),
    })
}

/// Whether the analytic trace channel is currently enabled.
pub fn trace_state() -> ChannelState {
    match channel_enabled(TRACE_CHANNEL) {
        Ok(true) => ChannelState::Enabled,
        Ok(false) => ChannelState::Disabled,
        Err(e) => {
            log::debug!("could not read {TRACE_CHANNEL} config: {e:#}");
            ChannelState::Unknown
        }
    }
}

/// Turns the analytic trace channel on or off.
///
/// **Needs Administrator**, and while enabled every WMI operation on the
/// machine is written to the log — which is the point, and also why this is
/// something to turn back off once the caller has been identified rather
/// than leave running.
pub fn set_trace_enabled(enabled: bool) -> Result<()> {
    if !crate::elevate::is_elevated() {
        return Err(anyhow!(
            "changing the {TRACE_CHANNEL} channel needs Administrator"
        ));
    }
    let path = wide(TRACE_CHANNEL);
    // SAFETY: `path` is a live NUL-terminated UTF-16 buffer for the duration
    // of the call, and the handle is closed on every path out.
    unsafe {
        let handle = EvtOpenChannelConfig(None, PCWSTR(path.as_ptr()), 0)
            .with_context(|| format!("opening the {TRACE_CHANNEL} channel config"))?;
        let result = (|| -> Result<()> {
            let mut value = EVT_VARIANT {
                Type: EvtVarTypeBoolean.0 as u32,
                ..Default::default()
            };
            value.Anonymous.BooleanVal = enabled.into();
            EvtSetChannelConfigProperty(handle, EvtChannelConfigEnabled, 0, &value)
                .context("setting the channel's enabled property")?;
            EvtSaveChannelConfig(handle, 0).context("saving the channel config")?;
            Ok(())
        })();
        let _ = EvtClose(handle);
        result
    }
}

fn channel_enabled(channel: &str) -> Result<bool> {
    let path = wide(channel);
    // SAFETY: as in `set_trace_enabled`; the buffer outlives the call and
    // the handle is always closed.
    unsafe {
        let handle = EvtOpenChannelConfig(None, PCWSTR(path.as_ptr()), 0)
            .context("opening the channel config")?;
        let mut used = 0u32;
        let mut buf = vec![0u8; std::mem::size_of::<EVT_VARIANT>() + 64];
        let result = EvtGetChannelConfigProperty(
            handle,
            EvtChannelConfigEnabled,
            0,
            buf.len() as u32,
            Some(buf.as_mut_ptr().cast()),
            &mut used,
        );
        let enabled = result.map(|()| {
            let variant = &*(buf.as_ptr() as *const EVT_VARIANT);
            variant.Anonymous.BooleanVal.as_bool()
        });
        let _ = EvtClose(handle);
        enabled.context("reading the channel's enabled property")
    }
}

/// The `.evtx` a channel writes to, from its own configuration.
///
/// Needed because an analytic channel is never queryable by channel path —
/// Windows answers "the request is not supported" whether it is recording
/// or not. Its captured events are only reachable through the backing file,
/// which also means reading them needs Administrator, since
/// `%SystemRoot%\System32\Winevt\Logs` is not user-readable.
fn channel_log_path(channel: &str) -> Result<String> {
    let path = wide(channel);
    // SAFETY: `path` outlives the call and the handle is always closed.
    unsafe {
        let handle = EvtOpenChannelConfig(None, PCWSTR(path.as_ptr()), 0)
            .context("opening the channel config")?;
        let mut used = 0u32;
        // Size the buffer first; this call is expected to fail short.
        let _ = EvtGetChannelConfigProperty(
            handle,
            EvtChannelLoggingConfigLogFilePath,
            0,
            0,
            None,
            &mut used,
        );
        let mut buf = vec![0u8; used.max(512) as usize];
        let got = EvtGetChannelConfigProperty(
            handle,
            EvtChannelLoggingConfigLogFilePath,
            0,
            buf.len() as u32,
            Some(buf.as_mut_ptr().cast()),
            &mut used,
        );
        let result = got.map(|()| {
            let variant = &*(buf.as_ptr() as *const EVT_VARIANT);
            variant.Anonymous.StringVal.to_string().unwrap_or_default()
        });
        let _ = EvtClose(handle);
        let raw = result.context("reading the channel's log file path")?;
        Ok(expand_env(&raw))
    }
}

/// Expands `%SystemRoot%`-style variables, which channel configs use.
fn expand_env(path: &str) -> String {
    let mut out = path.to_string();
    while let Some(start) = out.find('%') {
        let Some(len) = out[start + 1..].find('%') else {
            break;
        };
        let name = &out[start + 1..start + 1 + len];
        let Ok(value) = std::env::var(name) else {
            break;
        };
        out.replace_range(start..start + len + 2, &value);
    }
    out
}

/// Pulls rendered events from one channel, newest first.
fn read_channel(channel: &str, lookback_secs: i64, max_events: usize) -> Result<Vec<WmiOperation>> {
    // Server-side time filter: pushing this into the query means the log
    // service skips old records instead of us rendering and discarding them.
    let ms = lookback_secs.max(0) * 1000;
    let query = format!("*[System[TimeCreated[timediff(@SystemTime) <= {ms}]]]");

    // The analytic channel is never queryable by channel path — Windows
    // refuses with "the request is not supported" whether it is recording
    // or not — so it has to be read from its backing .evtx instead. That
    // file lives under System32 and needs Administrator to open, which is
    // why a non-elevated read silently falls back to the sampled channel.
    let is_trace = channel == TRACE_CHANNEL;
    let (target, flags) = if is_trace {
        (
            channel_log_path(channel)?,
            EvtQueryFilePath.0 | EvtQueryReverseDirection.0,
        )
    } else {
        (
            channel.to_string(),
            EvtQueryChannelPath.0 | EvtQueryReverseDirection.0,
        )
    };
    let channel_name = if is_trace {
        WmiChannel::Trace
    } else {
        WmiChannel::Operational
    };

    let channel_w = wide(&target);
    let query_w = wide(&query);

    // SAFETY: both wide buffers outlive every call below, and each handle
    // (the result set and every event) is closed exactly once.
    unsafe {
        let results = EvtQuery(
            None,
            PCWSTR(channel_w.as_ptr()),
            PCWSTR(query_w.as_ptr()),
            flags,
        )
        .with_context(|| format!("querying {channel}"))?;

        let mut out = Vec::new();
        let mut batch = [0isize; 32];
        while out.len() < max_events {
            let mut returned = 0u32;
            let next = EvtNext(results, &mut batch, 5000, 0, &mut returned);
            if let Err(e) = next {
                // Running out of events is the normal way this loop ends.
                if e.code().0 as u32 & 0xFFFF == ERROR_NO_MORE_ITEMS.0 {
                    break;
                }
                let _ = EvtClose(results);
                return Err(e).with_context(|| format!("reading events from {channel}"));
            }
            if returned == 0 {
                break;
            }
            for handle in batch.iter().take(returned as usize) {
                let event = EVT_HANDLE(*handle);
                if let Some(xml) = render(event)
                    && let Some(op) = parse_event(&xml, channel_name)
                {
                    out.push(op);
                }
                let _ = EvtClose(event);
            }
        }
        let _ = EvtClose(results);
        Ok(out)
    }
}

/// Renders one event to XML, growing the buffer once if needed.
unsafe fn render(event: EVT_HANDLE) -> Option<String> {
    let mut used = 0u32;
    let mut props = 0u32;
    // First call sizes the buffer; it is expected to fail with
    // ERROR_INSUFFICIENT_BUFFER, so the error is deliberately ignored.
    unsafe {
        let _ = EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            0,
            None,
            &mut used,
            &mut props,
        );
        if used == 0 {
            return None;
        }
        let mut buf = vec![0u16; used as usize / 2 + 1];
        EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            used,
            Some(buf.as_mut_ptr().cast()),
            &mut used,
            &mut props,
        )
        .ok()?;
        let end = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
        Some(String::from_utf16_lossy(&buf[..end]))
    }
}

/// Pulls the fields we care about out of rendered event XML.
///
/// Deliberately a scan rather than a parse: the two channels use different
/// element names for the same ideas, the payload is a flat set of scalars,
/// and a real XML dependency would buy nothing for it.
fn parse_event(xml: &str, channel: WmiChannel) -> Option<WmiOperation> {
    let time = element_attr(xml, "TimeCreated", "SystemTime")
        .and_then(|t| DateTime::parse_from_rfc3339(&t).ok())
        .map(|t| t.with_timezone(&Utc))
        .unwrap_or_else(Utc::now);

    // The trace channel uses named fields; the operational channel packs
    // everything into one unnamed `Data` element as `Key = value;` pairs.
    // Pull that blob out once and read both shapes from it.
    let blob = data_blob(xml).unwrap_or_default();

    // Read `Operation` out of the blob rather than taking the blob whole:
    // the fields that follow it (`ResultCode`, `PossibleCause`) would
    // otherwise be swallowed into the query text.
    let operation = data_field(xml, "Operation")
        .or_else(|| tagged(xml, "Operation"))
        .or_else(|| field_in_blob(&blob, "Operation"))
        .unwrap_or_else(|| blob.clone());
    if operation.is_empty() {
        return None;
    }

    let client_pid = data_field(xml, "ClientProcessId")
        .or_else(|| tagged(xml, "ClientProcessId"))
        .or_else(|| field_in_blob(&blob, "ClientProcessId"))
        .and_then(|v| v.trim().parse().ok());

    let result_code = data_field(xml, "ResultCode")
        .or_else(|| tagged(xml, "ResultCode"))
        .or_else(|| field_in_blob(&blob, "ResultCode"))
        .map(|c| c.trim().to_string());

    let (namespace, query) = split_operation(&operation);

    Some(WmiOperation {
        time,
        client_pid,
        namespace,
        query,
        operation,
        result_code,
        channel,
    })
}

/// Splits `... - root\cimv2 : SELECT ...` into its namespace and query.
fn split_operation(operation: &str) -> (Option<String>, Option<String>) {
    let Some(rest) = operation.split(" - ").nth(1) else {
        return (None, None);
    };
    match rest.split_once(" : ") {
        Some((ns, q)) => (
            Some(ns.trim().to_string()),
            Some(q.trim().trim_end_matches(';').to_string()),
        ),
        None => (Some(rest.trim().to_string()), None),
    }
}

/// `<Data Name="X">value</Data>`
fn data_field(xml: &str, name: &str) -> Option<String> {
    let needle = format!("<Data Name=\"{name}\">");
    let start = xml.find(&needle)? + needle.len();
    let end = xml[start..].find("</Data>")? + start;
    Some(unescape(&xml[start..end]))
}

/// `<X>value</X>`
fn tagged(xml: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(unescape(&xml[start..end]))
}

/// The first unnamed `<Data>` element, which is where the operational
/// channel puts its whole semicolon-separated message.
fn data_blob(xml: &str) -> Option<String> {
    let start = xml.find("<Data>")? + "<Data>".len();
    let end = xml[start..].find("</Data>")? + start;
    Some(unescape(&xml[start..end]))
}

/// `Key = value;` inside the operational channel's flat message.
fn field_in_blob(blob: &str, key: &str) -> Option<String> {
    let needle = format!("{key} = ");
    let start = blob.find(&needle)? + needle.len();
    let rest = &blob[start..];
    let end = rest.find(';').unwrap_or(rest.len());
    Some(rest[..end].trim().to_string())
}

fn element_attr(xml: &str, element: &str, attr: &str) -> Option<String> {
    let el = xml.find(&format!("<{element} "))?;
    let needle = format!("{attr}='");
    let start = xml[el..].find(&needle)? + el + needle.len();
    let end = xml[start..].find('\'')? + start;
    Some(xml[start..end].to_string())
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPERATIONAL_XML: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
<System><Provider Name='Microsoft-Windows-WMI-Activity'/><EventID>5858</EventID>
<TimeCreated SystemTime='2026-08-27T09:15:04.1234567Z'/></System>
<UserData><Operation_ClientFailure xmlns='http://manifests.microsoft.com/win/2006/windows/WMI'>
<Data>Id = {ABC}; ClientMachine = BUDDY; User = BUDDY\budel; ClientProcessId = 4242; Component = Unknown; Operation = Start IWbemServices::ExecQuery - root\cimv2 : SELECT __PATH, ProcessId FROM Win32_Process; ResultCode = 0x80041010; PossibleCause = Unknown</Data>
</Operation_ClientFailure></UserData></Event>"#;

    #[test]
    fn parses_the_client_out_of_an_operational_event() {
        let op = parse_event(OPERATIONAL_XML, WmiChannel::Operational).expect("should parse");
        assert_eq!(op.client_pid, Some(4242), "the caller is the whole point");
        assert_eq!(op.namespace.as_deref(), Some(r"root\cimv2"));
        assert_eq!(
            op.query.as_deref(),
            Some("SELECT __PATH, ProcessId FROM Win32_Process")
        );
        assert_eq!(op.result_code.as_deref(), Some("0x80041010"));
        assert_eq!(op.time.to_rfc3339(), "2026-08-27T09:15:04.123456700+00:00");
    }

    #[test]
    fn ranks_clients_by_how_much_they_asked_for() {
        let mut ops = Vec::new();
        for _ in 0..5 {
            ops.push(op_from(7, "SELECT * FROM Win32_Process", "0x0"));
        }
        ops.push(op_from(9, "SELECT * FROM Win32_BIOS", "0x80041010"));

        let report = attribute(
            read_of(ops),
            60,
            |pid| Some(format!("proc{pid}")),
            |pid| pid == 7,
        );

        let top = report.top_client().expect("a top client");
        assert_eq!(top.pid, 7, "the busiest caller must rank first");
        assert_eq!(top.operations, 5);
        assert_eq!(top.name.as_deref(), Some("proc7"));
        assert!(top.alive);

        let second = &report.clients[1];
        assert_eq!(second.pid, 9);
        assert_eq!(second.failed_operations, 1, "non-zero result codes count");
        assert!(!second.alive, "an exited caller must not be reported alive");
    }

    /// The operational channel is a biased sample. Saying so is the
    /// difference between "this is your culprit" and "this is what was slow
    /// enough to get logged".
    #[test]
    fn warns_when_only_the_sampled_channel_was_available() {
        let report = attribute(
            read_of(vec![op_from(1, "q", "0x0")]),
            60,
            |_| None,
            |_| false,
        );
        assert!(
            report.sampling_warning.is_some(),
            "operational-only results must carry the caveat"
        );

        let mut traced = op_from(1, "q", "0x0");
        traced.channel = WmiChannel::Trace;
        let report = attribute(read_of(vec![traced]), 60, |_| None, |_| false);
        assert!(report.sampling_warning.is_none(), "trace data is complete");
    }

    /// An analytic channel cannot be read while it records, so "tracing is
    /// on but produced nothing readable" must not tell the reader to turn
    /// on the thing they already turned on.
    #[test]
    fn the_warning_never_says_to_enable_what_is_already_enabled() {
        let warning =
            sampling_warning(false, ChannelState::Enabled, None).expect("recording but unreadable");
        assert!(
            !warning.contains("Enable "),
            "must not ask for an already-enabled channel: {warning}"
        );
        assert!(
            warning.contains("Turn tracing off"),
            "must give the step that actually makes it readable: {warning}"
        );

        let off = sampling_warning(false, ChannelState::Disabled, None).expect("sampled only");
        assert!(
            off.contains("Enable "),
            "with tracing off, enabling it is the right advice: {off}"
        );

        assert_eq!(
            sampling_warning(true, ChannelState::Enabled, None),
            None,
            "trace data needs no caveat"
        );
        assert_eq!(
            sampling_warning(true, ChannelState::Disabled, None),
            None,
            "trace events are complete whatever the channel says now"
        );
    }

    /// The capture file needs Administrator. That is the one cause the
    /// reader can act on, so it must outrank the channel's on/off state as
    /// an explanation — otherwise an elevated-read problem reads as a
    /// "you forgot to enable tracing" problem.
    #[test]
    fn permission_failures_are_reported_as_permission_failures() {
        let denied = Some("querying the trace channel: Access is denied. (0x80070005)");

        for state in [
            ChannelState::Enabled,
            ChannelState::Disabled,
            ChannelState::Unknown,
        ] {
            let warning = sampling_warning(false, state, denied).expect("a warning");
            assert!(
                warning.contains("Administrator"),
                "{state:?} must name the real blocker: {warning}"
            );
            assert!(
                !warning.contains("Turn tracing off"),
                "{state:?} must not blame the channel state: {warning}"
            );
        }

        // Complete data still needs no caveat, even if the read errored.
        assert_eq!(sampling_warning(true, ChannelState::Enabled, denied), None);
    }

    #[test]
    fn an_unnamed_exited_client_is_still_reported() {
        let report = attribute(
            read_of(vec![op_from(123, "q", "0x0")]),
            60,
            |_| None,
            |_| false,
        );
        let client = report.top_client().expect("client");
        assert_eq!(client.pid, 123, "an unnameable pid is still evidence");
        assert_eq!(client.name, None);
    }

    #[test]
    fn splits_namespace_from_query() {
        let (ns, q) = split_operation("Start IWbemServices::ExecQuery - root\\cimv2 : SELECT 1;");
        assert_eq!(ns.as_deref(), Some(r"root\cimv2"));
        assert_eq!(q.as_deref(), Some("SELECT 1"));

        let (ns, q) = split_operation("Provider::Something - ROOT\\WMI");
        assert_eq!(ns.as_deref(), Some(r"ROOT\WMI"));
        assert_eq!(q, None);

        assert_eq!(split_operation("no separators here"), (None, None));
    }

    /// The channel state must never be guessed: reporting "disabled" when
    /// we simply could not read the config would send someone to enable a
    /// channel that is already on.
    #[test]
    fn trace_state_is_answerable() {
        let state = trace_state();
        println!("trace channel: {state:?}");
        assert!(matches!(
            state,
            ChannelState::Enabled | ChannelState::Disabled | ChannelState::Unknown
        ));
    }

    fn read_of(operations: Vec<WmiOperation>) -> WmiRead {
        WmiRead {
            operations,
            trace_read_error: None,
        }
    }

    fn op_from(pid: u32, query: &str, code: &str) -> WmiOperation {
        WmiOperation {
            time: Utc::now(),
            client_pid: Some(pid),
            namespace: Some("root\\cimv2".into()),
            query: Some(query.into()),
            operation: format!("ExecQuery - root\\cimv2 : {query}"),
            result_code: Some(code.into()),
            channel: WmiChannel::Operational,
        }
    }
}
