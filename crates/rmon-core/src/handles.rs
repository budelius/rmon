//! Best-effort "what files does this process have open" lookup.
//!
//! This is inherently on-demand (not something to poll every tick): it
//! walks a process's kernel handle table and, for every handle of type
//! "File", duplicates it into rMon and asks the kernel for its path. There
//! is no documented Win32 API for this — it's the same approach Process
//! Explorer / Sysinternals `handle.exe` use, via undocumented NT APIs
//! (`NtQueryInformationProcess` / `NtQueryObject`).
//!
//! Two real constraints fall out of that:
//! - Opening another user's (or a protected/system) process for handle
//!   duplication requires `SeDebugPrivilege`, which in turn requires
//!   running rMon elevated (as Administrator). Without it, this only sees
//!   your own processes.
//! - `NtQueryObject(..., ObjectNameInformation, ...)` is documented (by
//!   community/tooling knowledge, not Microsoft) to be able to hang
//!   indefinitely on certain handle types — notably named pipes waiting on
//!   a peer. Every such query therefore runs on its own thread with a
//!   short timeout; a handle that hangs contributes a leaked thread (which
//!   may complete and clean up on its own later, or never) instead of
//!   freezing the scan. This is the standard, accepted mitigation real
//!   tools use for the same issue.

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_DEBUG_NAME,
    SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetProcessHandleCount, OpenProcess, OpenProcessToken, TerminateProcess,
    PROCESS_DUP_HANDLE, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_TERMINATE,
};

const PROCESS_HANDLE_INFORMATION_CLASS: u32 = 51; // ProcessHandleInformation
const OBJECT_NAME_INFORMATION_CLASS: u32 = 1; // ObjectNameInformation
const OBJECT_TYPE_INFORMATION_CLASS: u32 = 2; // ObjectTypeInformation
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004u32 as i32;
const NAME_QUERY_TIMEOUT: Duration = Duration::from_millis(200);
/// Hard cap on handles inspected per scan so a process with an
/// unreasonably large handle table can't make this run away.
const MAX_HANDLES: usize = 20_000;

/// Cheap total open-handle count for `pid` (all handle types, not just
/// files) via a single `GetProcessHandleCount` call — unlike
/// `list_open_files`, this is safe to poll for a process every tick.
pub fn handle_count(pid: u32) -> Option<u32> {
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut count = 0u32;
        let status = GetProcessHandleCount(process, &mut count);
        let _ = CloseHandle(process);
        status.ok()?;
        Some(count)
    }
}

/// Terminates `pid` outright (`TerminateProcess`, exit code 1) — the same
/// operation as Task Manager's "End task". Best-effort elevation via
/// `SeDebugPrivilege` so this can reach processes owned by other users when
/// rMon itself is running elevated.
pub fn kill_process(pid: u32) -> Result<()> {
    enable_debug_privilege();
    unsafe {
        let process = OpenProcess(PROCESS_TERMINATE, false, pid).with_context(|| {
            format!("OpenProcess({pid}, PROCESS_TERMINATE) failed — try running rMon as Administrator")
        })?;
        let result = TerminateProcess(process, 1).context("TerminateProcess failed");
        let _ = CloseHandle(process);
        result
    }
}

pub struct OpenFilesScan {
    pub paths: Vec<String>,
    pub handles_seen: usize,
    pub file_handles: usize,
    /// Name queries that didn't return within `NAME_QUERY_TIMEOUT` (worker
    /// thread abandoned, not joined). Surfaced so the UI can say "N handles
    /// didn't respond" instead of silently under-reporting.
    pub timed_out: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct UnicodeString {
    pub(crate) length: u16,
    pub(crate) maximum_length: u16,
    pub(crate) buffer: *mut u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcessHandleTableEntryInfo {
    handle_value: HANDLE,
    handle_count: usize,
    pointer_count: usize,
    granted_access: u32,
    object_type_index: u32,
    handle_attributes: u32,
    reserved: u32,
}

/// Enumerates every "File" handle open in `pid` and resolves each to a
/// path. Best-effort throughout: individual handles that fail to duplicate,
/// fail to query, or time out are skipped rather than failing the whole
/// scan; only a failure to even open the target process is a hard error.
pub fn list_open_files(pid: u32) -> Result<OpenFilesScan> {
    enable_debug_privilege();

    let process = unsafe {
        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, false, pid)
    }
    .with_context(|| {
        format!("OpenProcess({pid}) failed — try running rMon as Administrator for full access")
    })?;

    let entries = unsafe { query_process_handles(process) };
    let result = (|| -> Result<OpenFilesScan> {
        let entries = entries?;
        let dos_map = build_dos_device_map();
        let mut type_names: HashMap<u32, Option<String>> = HashMap::new();
        let mut paths = Vec::new();
        let mut file_handles = 0usize;
        let mut timed_out = 0usize;

        for entry in &entries {
            let type_name = type_names
                .entry(entry.object_type_index)
                .or_insert_with(|| unsafe { duplicate_and_query_type(process, entry.handle_value) });
            if type_name.as_deref() != Some("File") {
                continue;
            }
            file_handles += 1;
            match unsafe { duplicate_and_query_name_with_timeout(process, entry.handle_value) } {
                Some(Some(raw_path)) => paths.push(resolve_dos_path(&raw_path, &dos_map)),
                Some(None) => {}
                None => timed_out += 1,
            }
        }

        paths.sort();
        paths.dedup();
        Ok(OpenFilesScan {
            paths,
            handles_seen: entries.len(),
            file_handles,
            timed_out,
        })
    })();

    unsafe {
        let _ = CloseHandle(process);
    }
    result
}

/// Default number of processes scanned concurrently by
/// `list_open_files_many` — bounds how many of these (potentially
/// handle-table-sized) scans run at once, independent of how many threads
/// any single scan spawns internally for its own handle-name queries.
pub const DEFAULT_SCAN_WORKERS: usize = 8;

/// One process's result from a `list_open_files_many` batch.
pub struct AllFilesEntry {
    pub pid: u32,
    pub scan: Result<OpenFilesScan, String>,
}

/// Runs `list_open_files` for every pid in `pids`, using up to `workers`
/// concurrent worker threads (see `DEFAULT_SCAN_WORKERS`), and streams one
/// `AllFilesEntry` per pid to `tx` as each scan completes.
///
/// This is the "search open files across all processes" primitive: it's
/// just `list_open_files` fanned out, so it inherits the same on-demand,
/// best-effort characteristics (processes rMon can't open — other users',
/// protected, without `SeDebugPrivilege` — simply come back as an error for
/// that one pid rather than failing the whole batch). Blocks the calling
/// thread until every pid has been scanned, so callers normally run this on
/// a background thread, same as a single `list_open_files` call.
pub fn list_open_files_many(pids: Vec<u32>, workers: usize, tx: mpsc::Sender<AllFilesEntry>) {
    let queue = Arc::new(Mutex::new(pids));
    let mut threads = Vec::new();
    for _ in 0..workers.max(1) {
        let queue = Arc::clone(&queue);
        let tx = tx.clone();
        threads.push(std::thread::spawn(move || {
            loop {
                let pid = {
                    let mut q = queue.lock().expect("scan queue mutex poisoned");
                    q.pop()
                };
                let Some(pid) = pid else { break };
                let scan = list_open_files(pid).map_err(|e| e.to_string());
                if tx.send(AllFilesEntry { pid, scan }).is_err() {
                    break; // receiver dropped; no point continuing this worker
                }
            }
        }));
    }
    for t in threads {
        let _ = t.join();
    }
}

unsafe fn nt_query_information_process(process: HANDLE, buf: &mut [u8], ret_len: &mut u32) -> i32 {
    windows::core::link!("ntdll.dll" "system" fn NtQueryInformationProcess(
        ProcessHandle: HANDLE, ProcessInformationClass: u32,
        ProcessInformation: *mut c_void, ProcessInformationLength: u32, ReturnLength: *mut u32
    ) -> i32);
    unsafe {
        NtQueryInformationProcess(
            process,
            PROCESS_HANDLE_INFORMATION_CLASS,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
            ret_len,
        )
    }
}

unsafe fn nt_query_object(handle: HANDLE, class: u32, buf: &mut [u8], ret_len: &mut u32) -> i32 {
    windows::core::link!("ntdll.dll" "system" fn NtQueryObject(
        Handle: HANDLE, ObjectInformationClass: u32,
        ObjectInformation: *mut c_void, ObjectInformationLength: u32, ReturnLength: *mut u32
    ) -> i32);
    unsafe {
        NtQueryObject(
            handle,
            class,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
            ret_len,
        )
    }
}

/// Best-effort: enable SeDebugPrivilege for the current process so we can
/// open handles belonging to other users'/elevated processes. Silently
/// no-ops on failure (e.g. not running as Administrator) — callers just
/// get "access denied" for those specific processes instead.
fn enable_debug_privilege() {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
        .is_err()
        {
            return;
        }
        let mut luid = Default::default();
        if LookupPrivilegeValueW(PCWSTR::null(), SE_DEBUG_NAME, &mut luid).is_ok() {
            let privileges = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            let _ = AdjustTokenPrivileges(token, false, Some(&privileges), 0, None, None);
        }
        let _ = CloseHandle(token);
    }
}

unsafe fn query_process_handles(process: HANDLE) -> Result<Vec<ProcessHandleTableEntryInfo>> {
    let header_size = 2 * std::mem::size_of::<usize>();
    let entry_size = std::mem::size_of::<ProcessHandleTableEntryInfo>();
    let mut size = 1usize << 16;

    loop {
        let mut buf = vec![0u8; size];
        let mut ret_len = 0u32;
        let status = unsafe { nt_query_information_process(process, &mut buf, &mut ret_len) };

        if status == STATUS_INFO_LENGTH_MISMATCH {
            if size >= (1 << 28) {
                bail!("process handle table too large to query");
            }
            size *= 2;
            continue;
        }
        if status < 0 {
            bail!("NtQueryInformationProcess failed: 0x{:08X}", status as u32);
        }

        let number_of_handles =
            usize::from_ne_bytes(buf[0..8].try_into().expect("8-byte header field"));
        let number_of_handles = number_of_handles.min(MAX_HANDLES);
        let mut out = Vec::with_capacity(number_of_handles);
        for i in 0..number_of_handles {
            let offset = header_size + i * entry_size;
            if offset + entry_size > buf.len() {
                break;
            }
            let entry = unsafe {
                std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const ProcessHandleTableEntryInfo)
            };
            out.push(entry);
        }
        return Ok(out);
    }
}

unsafe fn duplicate_and_query_type(process: HANDLE, handle_value: HANDLE) -> Option<String> {
    let current = unsafe { GetCurrentProcess() };
    let mut dup = HANDLE::default();
    unsafe {
        DuplicateHandle(process, handle_value, current, &mut dup, 0, false, DUPLICATE_SAME_ACCESS)
    }
    .ok()?;

    let mut buf = vec![0u8; 1024];
    let mut ret_len = 0u32;
    let status = unsafe { nt_query_object(dup, OBJECT_TYPE_INFORMATION_CLASS, &mut buf, &mut ret_len) };
    let result = if status >= 0 {
        unsafe { read_unicode_string_at(&buf, 0) }
    } else {
        None
    };
    unsafe {
        let _ = CloseHandle(dup);
    }
    result
}

/// `Some(Some(path))` — resolved. `Some(None)` — duplicate/query failed
/// outright (not a hang). `None` — timed out; the query thread is
/// abandoned rather than joined.
unsafe fn duplicate_and_query_name_with_timeout(process: HANDLE, handle_value: HANDLE) -> Option<Option<String>> {
    let current = unsafe { GetCurrentProcess() };
    let mut dup = HANDLE::default();
    if unsafe {
        DuplicateHandle(process, handle_value, current, &mut dup, 0, false, DUPLICATE_SAME_ACCESS)
    }
    .is_err()
    {
        return Some(None);
    }

    let dup_raw = dup.0 as isize;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let dup = HANDLE(dup_raw as *mut c_void);
        let mut buf = vec![0u8; 8192];
        let mut ret_len = 0u32;
        let status = unsafe { nt_query_object(dup, OBJECT_NAME_INFORMATION_CLASS, &mut buf, &mut ret_len) };
        let result = if status >= 0 {
            unsafe { read_unicode_string_at(&buf, 0) }
        } else {
            None
        };
        unsafe {
            let _ = CloseHandle(dup);
        }
        let _ = tx.send(result);
    });

    rx.recv_timeout(NAME_QUERY_TIMEOUT).ok()
}

/// Reads a `UNICODE_STRING` at `offset` in `buf`, where `buffer` points
/// somewhere *inside `buf` itself* (NtQueryObject — and several other NT
/// query APIs, see `cpu.rs` — lay the string data out contiguously after
/// the struct in the same output buffer).
pub(crate) unsafe fn read_unicode_string_at(buf: &[u8], offset: usize) -> Option<String> {
    if offset + std::mem::size_of::<UnicodeString>() > buf.len() {
        return None;
    }
    let us = unsafe { std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const UnicodeString) };
    if us.buffer.is_null() || us.length == 0 {
        return None;
    }
    let base = buf.as_ptr() as usize;
    let ptr = us.buffer as usize;
    let len = us.length as usize;
    if ptr < base || ptr.checked_add(len)? > base + buf.len() {
        return None; // kernel-written pointer/length didn't land inside our buffer; don't trust it
    }
    let byte_offset = ptr - base;
    let slice = unsafe { std::slice::from_raw_parts(buf.as_ptr().add(byte_offset) as *const u16, len / 2) };
    Some(String::from_utf16_lossy(slice))
}

/// Maps `\Device\HarddiskVolumeN\...`-style NT paths to `X:\...` drive
/// letters, longest device prefix first.
fn build_dos_device_map() -> Vec<(String, String)> {
    let mut map = Vec::new();
    for letter in b'A'..=b'Z' {
        let drive = format!("{}:", letter as char);
        let drive_wide: Vec<u16> = drive.encode_utf16().chain(std::iter::once(0)).collect();
        let mut buf = [0u16; 1024];
        let len = unsafe { QueryDosDeviceW(PCWSTR(drive_wide.as_ptr()), Some(&mut buf)) };
        if len == 0 {
            continue;
        }
        let raw = String::from_utf16_lossy(&buf[..len as usize]);
        if let Some(device) = raw.split('\0').next().filter(|s| !s.is_empty()) {
            map.push((device.to_string(), format!("{drive}\\")));
        }
    }
    map.sort_by_key(|(device, _)| std::cmp::Reverse(device.len()));
    map
}

fn resolve_dos_path(nt_path: &str, map: &[(String, String)]) -> String {
    for (device, drive) in map {
        if let Some(rest) = nt_path.strip_prefix(device.as_str()) {
            return format!("{drive}{}", rest.trim_start_matches('\\'));
        }
    }
    nt_path.to_string()
}
