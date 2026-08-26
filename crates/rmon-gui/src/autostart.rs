//! Auto-start at Windows login via the per-user Registry Run key
//! (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`). No admin rights
//! needed, and unchecking the box in the UI fully reverses it.

use std::io;

use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};

const RUN_KEY_PATH: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const VALUE_NAME: &str = "rMon";

/// The command line autostart launches: quoted exe path plus `--minimized`
/// so login doesn't pop the window up, just starts monitoring in the tray.
fn autostart_command() -> io::Result<String> {
    let exe = std::env::current_exe()?;
    Ok(format!("\"{}\" --minimized", exe.display()))
}

/// Whether rMon is currently registered to launch at login.
pub fn is_enabled() -> bool {
    let Ok(hkcu) = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(RUN_KEY_PATH, KEY_READ)
    else {
        return false;
    };
    hkcu.get_value::<String, _>(VALUE_NAME).is_ok()
}

/// Registers or unregisters rMon to launch at login.
pub fn set_enabled(enabled: bool) -> io::Result<()> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(RUN_KEY_PATH, KEY_READ | KEY_WRITE)?;
    if enabled {
        hkcu.set_value(VALUE_NAME, &autostart_command()?)
    } else {
        match hkcu.delete_value(VALUE_NAME) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}
