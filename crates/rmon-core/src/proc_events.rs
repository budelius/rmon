//! Catches processes that start and fully exit between rMon's polling
//! ticks, via the `Microsoft-Windows-Kernel-Process` ETW provider — the
//! only reliable way to see a process that never survives long enough to
//! be caught by periodic sampling (see `sampler.rs`).
//!
//! Requires Administrator elevation (kernel ETW providers are privileged;
//! see `elevate.rs`). Measures wall-clock duration only: these events
//! don't carry CPU time, so a short-lived process's actual CPU usage is
//! not reported here — only that it ran, for how long, and its exit code.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::KernelTrace;
use ferrisetw::EventRecord;

const KERNEL_PROCESS_PROVIDER_GUID: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
const EVENT_ID_PROCESS_START: u16 = 1;
const EVENT_ID_PROCESS_STOP: u16 = 2;
/// Bounds memory use; oldest entries drop off as new ones arrive.
const MAX_RECENT: usize = 500;

#[derive(Debug, Clone)]
pub struct RecentExit {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub start_time: DateTime<Utc>,
    /// Wall-clock lifetime, not CPU time — see module docs.
    pub duration_ms: i64,
    pub exit_code: Option<u32>,
}

struct StartInfo {
    ppid: Option<u32>,
    name: String,
    start_time: DateTime<Utc>,
}

struct Shared {
    starts: Mutex<HashMap<u32, StartInfo>>,
    recent: Mutex<VecDeque<RecentExit>>,
}

/// Owns the live ETW trace session for as long as it's kept alive;
/// dropping it stops the trace.
pub struct ShortLivedWatcher {
    shared: Arc<Shared>,
    _trace: KernelTrace,
}

impl ShortLivedWatcher {
    /// Starts watching for process start/stop events. Fails if not
    /// elevated, or if the trace session can't be created (e.g. another
    /// exclusive kernel logger session is already active).
    pub fn start() -> Result<Self> {
        let shared = Arc::new(Shared {
            starts: Mutex::new(HashMap::new()),
            recent: Mutex::new(VecDeque::new()),
        });

        let callback_shared = Arc::clone(&shared);
        let callback = move |record: &EventRecord, schema_locator: &SchemaLocator| {
            handle_event(&callback_shared, record, schema_locator);
        };

        let provider = Provider::by_guid(KERNEL_PROCESS_PROVIDER_GUID)
            .add_callback(callback)
            .build();

        let trace = KernelTrace::new()
            .named("rmon-shortlived".to_string())
            .enable(provider)
            .start_and_process()
            .map_err(|e| {
                anyhow!(
                    "failed to start Kernel-Process ETW trace (requires Administrator): {e:?}"
                )
            })?;

        Ok(Self {
            shared,
            _trace: trace,
        })
    }

    /// Snapshot of every exit caught so far, newest first.
    pub fn recent(&self) -> Vec<RecentExit> {
        let recent = self.shared.recent.lock().unwrap();
        recent.iter().rev().cloned().collect()
    }
}

fn handle_event(shared: &Shared, record: &EventRecord, schema_locator: &SchemaLocator) {
    let Ok(schema) = schema_locator.event_schema(record) else {
        return;
    };
    let parser = Parser::create(record, &schema);

    match record.event_id() {
        EVENT_ID_PROCESS_START => {
            let Ok(pid) = parser.try_parse::<u32>("ProcessID") else {
                return;
            };
            let ppid = parser.try_parse::<u32>("ParentProcessID").ok();
            let name = parser
                .try_parse::<String>("ImageName")
                .unwrap_or_else(|_| "?".to_string());
            shared.starts.lock().unwrap().insert(
                pid,
                StartInfo {
                    ppid,
                    name,
                    start_time: Utc::now(),
                },
            );
        }
        EVENT_ID_PROCESS_STOP => {
            let Ok(pid) = parser.try_parse::<u32>("ProcessID") else {
                return;
            };
            let Some(start) = shared.starts.lock().unwrap().remove(&pid) else {
                return; // was already running before we started watching
            };
            let exit_code = parser.try_parse::<u32>("ExitCode").ok();
            let now = Utc::now();
            let duration_ms = (now - start.start_time).num_milliseconds();

            let mut recent = shared.recent.lock().unwrap();
            recent.push_back(RecentExit {
                pid,
                ppid: start.ppid,
                name: start.name,
                start_time: start.start_time,
                duration_ms,
                exit_code,
            });
            while recent.len() > MAX_RECENT {
                recent.pop_front();
            }
        }
        _ => {}
    }
}
