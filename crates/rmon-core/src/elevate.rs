//! Checking and requesting Administrator elevation for the current process.
//!
//! rMon runs fine unelevated, but several features (killing/inspecting other
//! users' processes, full open-file scans) silently see less without
//! `SeDebugPrivilege`-worthy elevation. This lets the UI offer a one-click
//! "restart as Administrator" instead of just telling the user to do it
//! themselves.

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;

use anyhow::{bail, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

/// True if the current process is running with an elevated (Administrator) token.
pub fn is_elevated() -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut ret_len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut TOKEN_ELEVATION as *mut c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

fn to_wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Relaunches the current executable elevated (triggers a UAC prompt) with
/// the same command-line args. Does not exit the current process — the
/// caller decides whether/when to quit once this returns `Ok`. Fails (e.g.
/// the user dismisses the UAC prompt) without side effects.
pub fn restart_elevated() -> Result<()> {
    let exe = std::env::current_exe()?;
    let exe_wide = to_wide(&exe.to_string_lossy());
    let args_joined = std::env::args().skip(1).collect::<Vec<_>>().join(" ");
    let args_wide = to_wide(&args_joined);
    let verb_wide = to_wide("runas");

    let result = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(verb_wide.as_ptr()),
            PCWSTR(exe_wide.as_ptr()),
            PCWSTR(args_wide.as_ptr()),
            None,
            SW_SHOWNORMAL,
        )
    };
    // ShellExecuteW returns a pseudo-HINSTANCE; per Win32 docs, values > 32
    // indicate success, anything else is an error code (e.g. 5 = access
    // denied/cancelled UAC prompt).
    if (result.0 as isize) <= 32 {
        bail!("ShellExecuteW(runas) failed (code {})", result.0 as isize);
    }
    Ok(())
}
