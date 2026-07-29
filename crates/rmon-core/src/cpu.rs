//! Per-process CPU/memory/handle sampling via a single
//! `NtQuerySystemInformation(SystemProcessInformation)` walk — the same
//! primitive Task Manager and Process Hacker are built on.
//!
//! rMon originally used the `sysinfo` crate here, but its Windows process
//! refresh does per-process work that costs 200-800ms *per tick* on a
//! system with ~1600 processes — dominating rMon's entire sampling loop.
//! One `SystemProcessInformation` query returns, for every process in one
//! syscall: image name, pid/ppid, kernel+user CPU times, working set,
//! and open handle count. That covers everything rMon needs every tick.
//!
//! The two fields that genuinely require opening each process — the owning
//! user and the command line — are resolved once per *new* pid and cached
//! (a handful per tick in steady state), not re-queried for every process
//! every tick. Processes we can't open (other users', protected, when not
//! elevated) just get `None` for both, same as before.

use std::collections::HashMap;
use std::ffi::c_void;
use std::time::Instant;

use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{
    GetTokenInformation, LookupAccountSidW, TokenUser, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::handles::{read_unicode_string_at, UnicodeString};

const SYSTEM_PROCESS_INFORMATION_CLASS: u32 = 5;
const SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_CLASS: u32 = 8;
const PROCESS_COMMAND_LINE_INFORMATION_CLASS: u32 = 60;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004u32 as i32;
const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023u32 as i32;

/// One process's info from a single sampling tick.
pub struct ProcCpuInfo {
    pub name: String,
    /// Percent of a single core (Task Manager style: the sum across all
    /// processes can exceed 100 on a multi-core system).
    pub cpu_percent: f32,
    pub ppid: Option<u32>,
    pub user: Option<String>,
    pub command_line: Option<String>,
    /// Working-set bytes, straight from the process list snapshot.
    pub mem_bytes: u64,
    /// Total open handle count, straight from the process list snapshot —
    /// no per-process `OpenProcess` needed.
    pub handle_count: Option<u32>,
}

/// Leading fields of the kernel's `SYSTEM_PROCESS_INFORMATION` entry, up
/// to the last field rMon reads. Entries are traversed via
/// `next_entry_offset`, never `size_of` this struct, so declaring only a
/// prefix is safe. Layout per the documented/reverse-engineered NT struct
/// (`#[repr(C)]` reproduces the natural alignment padding).
#[repr(C)]
#[derive(Clone, Copy)]
struct SpiEntry {
    next_entry_offset: u32,
    number_of_threads: u32,
    working_set_private_size: i64,
    hard_fault_count: u32,
    number_of_threads_high_watermark: u32,
    cycle_time: u64,
    create_time: i64,
    user_time: i64,
    kernel_time: i64,
    image_name: UnicodeString,
    base_priority: i32,
    unique_process_id: usize,
    inherited_from_unique_process_id: usize,
    handle_count: u32,
    session_id: u32,
    unique_process_key: usize,
    peak_virtual_size: usize,
    virtual_size: usize,
    page_fault_count: u32,
    peak_working_set_size: usize,
    working_set_size: usize,
}

/// `SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION` — one per logical CPU.
#[repr(C)]
#[derive(Clone, Copy)]
struct ProcessorPerf {
    idle_time: i64,
    kernel_time: i64,
    user_time: i64,
    dpc_time: i64,
    interrupt_time: i64,
    interrupt_count: u32,
}

/// Cross-tick per-pid state that's expensive to recompute: the previous
/// CPU time reading (for the delta) and the once-resolved user/cmdline.
struct ProcCache {
    name: String,
    cpu_time_100ns: u64,
    user: Option<String>,
    command_line: Option<String>,
}

pub struct CpuMonitor {
    /// Reused across ticks so the (multi-MB) process list query doesn't
    /// reallocate and zero its buffer every second.
    buf: Vec<u8>,
    perf_buf: Vec<u8>,
    cache: HashMap<u32, ProcCache>,
    last_sample_at: Option<Instant>,
    prev_idle_100ns: u64,
    prev_busy_100ns: u64,
    global_usage: f32,
}

impl CpuMonitor {
    pub fn new() -> Self {
        let mut monitor = Self {
            buf: vec![0u8; 4 << 20],
            perf_buf: vec![0u8; 4096],
            cache: HashMap::new(),
            last_sample_at: None,
            prev_idle_100ns: 0,
            prev_busy_100ns: 0,
            global_usage: 0.0,
        };
        // Establish CPU-time baselines so the caller's own warm-up sample
        // behaves the same as it did with sysinfo (first sample ~0%).
        monitor.sample();
        monitor
    }

    /// Returns pid -> per-process info. CPU percentages are deltas since
    /// the previous `sample()` call; the first call reports ~0 for all.
    pub fn sample(&mut self) -> HashMap<u32, ProcCpuInfo> {
        let now = Instant::now();
        let dt_100ns = self
            .last_sample_at
            .map(|prev| (now - prev).as_nanos() as u64 / 100)
            .unwrap_or(0);
        self.last_sample_at = Some(now);

        let entries = match query_system_buffer(
            SYSTEM_PROCESS_INFORMATION_CLASS,
            &mut self.buf,
        ) {
            Ok(len) => len,
            Err(status) => {
                log::warn!("SystemProcessInformation query failed: 0x{:08X}", status as u32);
                return HashMap::new();
            }
        };

        let mut out = HashMap::new();
        let mut cache = HashMap::with_capacity(self.cache.len());
        let mut offset = 0usize;
        loop {
            if offset + std::mem::size_of::<SpiEntry>() > entries {
                break;
            }
            let entry = unsafe {
                std::ptr::read_unaligned(self.buf.as_ptr().add(offset) as *const SpiEntry)
            };
            let pid = entry.unique_process_id as u32;
            // pid 0 is the Idle pseudo-process — skip it, as sysinfo did.
            if pid != 0 {
                let name = unsafe {
                    read_unicode_string_at(
                        &self.buf[..entries],
                        offset + std::mem::offset_of!(SpiEntry, image_name),
                    )
                }
                .unwrap_or_else(|| "System".to_string());

                let cpu_time = (entry.kernel_time.max(0) + entry.user_time.max(0)) as u64;
                // Reuse the cached user/cmdline only while the pid still
                // belongs to the same image; a reused pid re-resolves (and
                // resets the CPU-time baseline rather than producing a
                // bogus delta against the dead process's counters).
                let prior = self.cache.remove(&pid).filter(|c| c.name == name);
                let cpu_percent = match &prior {
                    Some(c) if dt_100ns > 0 && cpu_time >= c.cpu_time_100ns => {
                        (cpu_time - c.cpu_time_100ns) as f32 / dt_100ns as f32 * 100.0
                    }
                    _ => 0.0,
                };
                let (user, command_line) = match prior {
                    Some(c) => (c.user, c.command_line),
                    None => query_user_and_cmdline(pid),
                };

                out.insert(
                    pid,
                    ProcCpuInfo {
                        name: name.clone(),
                        cpu_percent,
                        ppid: (entry.inherited_from_unique_process_id != 0)
                            .then_some(entry.inherited_from_unique_process_id as u32),
                        user: user.clone(),
                        command_line: command_line.clone(),
                        mem_bytes: entry.working_set_size as u64,
                        handle_count: Some(entry.handle_count),
                    },
                );
                cache.insert(
                    pid,
                    ProcCache { name, cpu_time_100ns: cpu_time, user, command_line },
                );
            }

            if entry.next_entry_offset == 0 {
                break;
            }
            offset += entry.next_entry_offset as usize;
        }
        // Replacing (not merging) the cache drops entries for exited pids.
        self.cache = cache;

        self.refresh_global_usage();
        out
    }

    /// Average CPU utilization across all logical cores, 0..=100, as of
    /// the last `sample()` call.
    pub fn global_usage(&self) -> f32 {
        self.global_usage
    }

    fn refresh_global_usage(&mut self) {
        let Ok(len) = query_system_buffer(
            SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_CLASS,
            &mut self.perf_buf,
        ) else {
            return;
        };
        let stride = std::mem::size_of::<ProcessorPerf>();
        let (mut idle, mut busy) = (0u64, 0u64);
        for i in 0..len / stride {
            let p = unsafe {
                std::ptr::read_unaligned(self.perf_buf.as_ptr().add(i * stride) as *const ProcessorPerf)
            };
            // KernelTime includes IdleTime, so busy = kernel - idle + user.
            idle += p.idle_time.max(0) as u64;
            busy += (p.kernel_time.max(0) as u64).saturating_sub(p.idle_time.max(0) as u64)
                + p.user_time.max(0) as u64;
        }
        let d_idle = idle.saturating_sub(self.prev_idle_100ns);
        let d_busy = busy.saturating_sub(self.prev_busy_100ns);
        if self.prev_idle_100ns != 0 && d_idle + d_busy > 0 {
            self.global_usage = d_busy as f32 / (d_idle + d_busy) as f32 * 100.0;
        }
        self.prev_idle_100ns = idle;
        self.prev_busy_100ns = busy;
    }
}

impl Default for CpuMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Runs `NtQuerySystemInformation(class)` into `buf`, growing it as needed
/// (the process list legitimately needs several MB on a busy system).
/// Returns the number of valid bytes.
fn query_system_buffer(class: u32, buf: &mut Vec<u8>) -> Result<usize, i32> {
    loop {
        let mut ret_len = 0u32;
        let status = unsafe { nt_query_system_information(class, buf, &mut ret_len) };
        if status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL {
            if buf.len() >= (1 << 28) {
                return Err(status);
            }
            // ret_len is a hint that can be stale by the next call; grow
            // past it so we converge in one retry, not many.
            let target = (ret_len as usize).max(buf.len()) + (1 << 20);
            buf.resize(target, 0);
            continue;
        }
        if status < 0 {
            return Err(status);
        }
        return Ok(ret_len as usize);
    }
}

unsafe fn nt_query_system_information(class: u32, buf: &mut [u8], ret_len: &mut u32) -> i32 {
    windows::core::link!("ntdll.dll" "system" fn NtQuerySystemInformation(
        SystemInformationClass: u32, SystemInformation: *mut c_void,
        SystemInformationLength: u32, ReturnLength: *mut u32
    ) -> i32);
    unsafe {
        NtQuerySystemInformation(class, buf.as_mut_ptr() as *mut c_void, buf.len() as u32, ret_len)
    }
}

unsafe fn nt_query_information_process(
    process: HANDLE,
    class: u32,
    buf: &mut [u8],
    ret_len: &mut u32,
) -> i32 {
    windows::core::link!("ntdll.dll" "system" fn NtQueryInformationProcess(
        ProcessHandle: HANDLE, ProcessInformationClass: u32,
        ProcessInformation: *mut c_void, ProcessInformationLength: u32, ReturnLength: *mut u32
    ) -> i32);
    unsafe {
        NtQueryInformationProcess(
            process,
            class,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
            ret_len,
        )
    }
}

/// Best-effort owning user name and command line for `pid` — the two
/// fields that need an open process handle. Called once per newly seen
/// pid, not per tick.
fn query_user_and_cmdline(pid: u32) -> (Option<String>, Option<String>) {
    let Ok(process) = (unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) })
    else {
        return (None, None);
    };
    let user = unsafe { query_user(process) };
    let command_line = unsafe { query_cmdline(process) };
    unsafe {
        let _ = CloseHandle(process);
    }
    (user, command_line)
}

unsafe fn query_cmdline(process: HANDLE) -> Option<String> {
    let mut buf = vec![0u8; 1024];
    loop {
        let mut ret_len = 0u32;
        let status = unsafe {
            nt_query_information_process(
                process,
                PROCESS_COMMAND_LINE_INFORMATION_CLASS,
                &mut buf,
                &mut ret_len,
            )
        };
        if status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL {
            if ret_len as usize <= buf.len() || ret_len as usize > (1 << 20) {
                return None;
            }
            buf.resize(ret_len as usize, 0);
            continue;
        }
        if status < 0 {
            return None;
        }
        // The result is a UNICODE_STRING whose buffer points into `buf`.
        return unsafe { read_unicode_string_at(&buf, 0) }.filter(|s| !s.is_empty());
    }
}

unsafe fn query_user(process: HANDLE) -> Option<String> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }.ok()?;

    let result = (|| {
        let mut buf = vec![0u8; 256];
        let mut ret_len = 0u32;
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                Some(buf.as_mut_ptr() as *mut c_void),
                buf.len() as u32,
                &mut ret_len,
            )
        }
        .is_err()
        {
            if ret_len as usize <= buf.len() {
                return None;
            }
            buf.resize(ret_len as usize, 0);
            unsafe {
                GetTokenInformation(
                    token,
                    TokenUser,
                    Some(buf.as_mut_ptr() as *mut c_void),
                    buf.len() as u32,
                    &mut ret_len,
                )
            }
            .ok()?;
        }
        let token_user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };

        let mut name = [0u16; 256];
        let mut name_len = name.len() as u32;
        let mut domain = [0u16; 256];
        let mut domain_len = domain.len() as u32;
        let mut sid_use = SID_NAME_USE::default();
        unsafe {
            LookupAccountSidW(
                None,
                token_user.User.Sid,
                Some(PWSTR(name.as_mut_ptr())),
                &mut name_len,
                Some(PWSTR(domain.as_mut_ptr())),
                &mut domain_len,
                &mut sid_use,
            )
        }
        .ok()?;
        Some(String::from_utf16_lossy(&name[..name_len as usize]))
    })();

    unsafe {
        let _ = CloseHandle(token);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live validation against the running system: our own process must
    /// appear with the right name and plausible values for every field the
    /// NT walk provides.
    #[test]
    fn own_process_is_reported_correctly() {
        let mut monitor = CpuMonitor::new();
        // Burn a little CPU so the second sample has a nonzero delta.
        let spin_until = Instant::now() + std::time::Duration::from_millis(50);
        while Instant::now() < spin_until {
            std::hint::black_box(0u64.wrapping_add(1));
        }
        let procs = monitor.sample();
        assert!(procs.len() > 50, "only {} processes reported", procs.len());

        let me = procs
            .get(&std::process::id())
            .expect("own process must be in the list");
        let exe_name = std::env::current_exe()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        assert_eq!(me.name, exe_name);
        assert!(me.mem_bytes > 1024 * 1024, "working set: {}", me.mem_bytes);
        assert!(me.handle_count.is_some_and(|h| h > 0));
        assert!(me.user.is_some(), "own process user must resolve");
        assert!(
            me.command_line.as_deref().is_some_and(|c| c.contains("rmon")),
            "command line: {:?}",
            me.command_line
        );
        assert!(me.ppid.is_some());
        assert!(me.cpu_percent > 0.0, "spun for 50ms but cpu% is 0");

        // Cross-check the snapshot's handle count against the direct API.
        let direct = crate::handles::handle_count(std::process::id()).unwrap();
        let reported = me.handle_count.unwrap();
        assert!(
            reported.abs_diff(direct) < 200,
            "snapshot handle count {reported} vs direct {direct}"
        );
    }

    #[test]
    fn global_usage_is_a_sane_percentage() {
        let mut monitor = CpuMonitor::new();
        std::thread::sleep(std::time::Duration::from_millis(30));
        monitor.sample();
        let g = monitor.global_usage();
        assert!((0.0..=100.0).contains(&g), "global usage {g}");
    }
}
