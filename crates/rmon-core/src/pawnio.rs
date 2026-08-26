//! Kernel-level hardware access through [PawnIO], so rMon can read CPU
//! MSRs and Super I/O registers itself instead of scraping another
//! running application's export.
//!
//! # Why a kernel driver at all
//!
//! Windows exposes no vendor-neutral userspace API for real CPU package
//! temperature, its actual TjMax, whether the part is *currently* being
//! thermally limited, or motherboard fan tachometers. Every tool that
//! shows those numbers — HWiNFO, LibreHardwareMonitor, FanControl —
//! reads model-specific registers (MSRs) and legacy ISA/LPC I/O ports,
//! both of which are ring-0-only. Until now rMon's answer was to read
//! HWiNFO's export, which works only while HWiNFO is running with the
//! right setting enabled, and gives us whatever subset of sensors the
//! user happened to put in its tray list.
//!
//! # Why PawnIO specifically, and not WinRing0
//!
//! The traditional answer is WinRing0 (`WinRing0x64.sys`), which offers
//! unrestricted MSR and port I/O to any caller that can open it. That
//! generality is exactly its problem: it is a well-known privilege
//! escalation primitive (CVE-2020-14979), it appears on Microsoft's
//! vulnerable-driver blocklist, and Defender flags it as a HackTool.
//! Shipping it would mean shipping a local-privilege-escalation
//! vulnerability alongside a process monitor.
//!
//! [PawnIO] is the modern replacement by the same community — the one
//! LibreHardwareMonitor and FanControl themselves moved to. Instead of
//! exposing raw ring-0 primitives, it runs small signed [Pawn] bytecode
//! modules in a sandbox inside the driver: a module declares which MSRs
//! and which I/O ports it will touch, and the driver enforces that.
//! `IntelMSR` permits exactly the ~30 thermal/power MSRs it lists (and
//! rejects a read of anything else with `STATUS_ACCESS_DENIED`);
//! `LpcIO` refuses any port outside the Super I/O config pair and the
//! base addresses it discovered, and specifically blacklists the PCI
//! configuration ports. A caller cannot ask it for arbitrary kernel
//! memory, because there is no IOCTL that means that.
//!
//! # What this module is, and what it is not
//!
//! This is the thin, safe Rust binding: find the installation, load
//! `PawnIOLib.dll`, open an executor, load a module blob, call its
//! functions. It deliberately does *not* install the driver — see
//! [`Availability`] for how absence is reported to the UI, which asks
//! the user to install PawnIO rather than dropping a kernel driver on
//! their machine as a side effect of opening a process monitor.
//!
//! Everything here is best-effort in the same sense as the rest of
//! rmon-core: on a machine without PawnIO, every entry point returns a
//! clean "unavailable" and callers fall back to the HWiNFO/ACPI path.
//!
//! [PawnIO]: https://pawnio.eu
//! [Pawn]: https://github.com/compuphase/pawn

use std::ffi::{CString, c_void};
use std::sync::OnceLock;

use anyhow::{Context, Result, anyhow, bail};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::core::{HRESULT, PCSTR, s, w};

/// Official signed module blobs, vendored from the PawnIO.Modules
/// release matching [`MODULES_VERSION`].
///
/// They are embedded rather than downloaded or built because the driver
/// only accepts modules carrying the upstream signature — we could not
/// compile our own even if we wanted to, which is precisely the property
/// that makes the sandbox worth trusting.
mod blobs {
    /// Intel thermal/power MSRs: package temperature, TjMax, and the
    /// thermal status bits.
    pub const INTEL_MSR: &[u8] = include_bytes!("../vendor/pawnio/IntelMSR.bin");
    /// Super I/O (LPC) access: motherboard hardware-monitor chips, which
    /// is where fan tachometers live.
    pub const LPC_IO: &[u8] = include_bytes!("../vendor/pawnio/LpcIO.bin");
}

/// Upstream release the blobs in `vendor/pawnio` came from. Surfaced in
/// the UI so a stale vendored module is diagnosable rather than just
/// mysteriously failing to load on a newer driver.
pub const MODULES_VERSION: &str = "0.2.10";

/// Minimum PawnIO version we ask for, in `pawnio_version`'s packed
/// `major << 16 | minor << 8 | patch` encoding. Deliberately generous:
/// the authoritative compatibility check is whether the module actually
/// loads, and refusing on a version number we merely dislike would
/// disable working machines for no reason.
const MIN_DRIVER_VERSION: u32 = 0x0001_0000; // 1.0.0

/// Why kernel-level sensor access isn't working, in terms a user can act
/// on. Every variant except [`Ready`](Self::Ready) is a normal, expected
/// state on some machine — none of them is an error to report loudly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Availability {
    Ready,
    /// PawnIO isn't installed. The one case with a clear user action.
    NotInstalled,
    /// Installed, but the driver refused to give us an executor. Almost
    /// always because rMon isn't elevated.
    NeedsElevation,
    /// Installed but too old for the vendored modules.
    DriverTooOld {
        found: String,
    },
    /// Something else went wrong; carries the message for display.
    Failed(String),
}

impl Availability {
    pub fn is_ready(&self) -> bool {
        matches!(self, Availability::Ready)
    }

    /// One-line explanation for the UI.
    pub fn message(&self) -> String {
        match self {
            Availability::Ready => "kernel sensor access active (PawnIO)".to_string(),
            Availability::NotInstalled => {
                "PawnIO is not installed — install it from https://pawnio.eu to let rMon read \
                 CPU thermal MSRs and motherboard fan sensors directly, without HWiNFO running"
                    .to_string()
            }
            Availability::NeedsElevation => {
                "PawnIO is installed but rMon could not open it — this needs Administrator"
                    .to_string()
            }
            Availability::DriverTooOld { found } => {
                format!("PawnIO {found} is older than the modules rMon ships ({MODULES_VERSION})")
            }
            Availability::Failed(e) => format!("PawnIO unavailable: {e}"),
        }
    }
}

type PawnIoVersion = unsafe extern "system" fn(*mut u32) -> HRESULT;
type PawnIoOpen = unsafe extern "system" fn(*mut HANDLE) -> HRESULT;
type PawnIoLoad = unsafe extern "system" fn(HANDLE, *const u8, usize) -> HRESULT;
type PawnIoExecute = unsafe extern "system" fn(
    HANDLE,
    PCSTR,
    *const u64,
    usize,
    *mut u64,
    usize,
    *mut usize,
) -> HRESULT;
type PawnIoClose = unsafe extern "system" fn(HANDLE) -> HRESULT;

/// `PawnIOLib.dll`'s entry points, resolved once per process.
///
/// Loaded dynamically rather than linked, because rMon has to keep
/// running normally on machines that have never heard of PawnIO — a
/// static import would make the executable fail to start there.
struct Lib {
    version: PawnIoVersion,
    open: PawnIoOpen,
    load: PawnIoLoad,
    execute: PawnIoExecute,
    close: PawnIoClose,
}

// The DLL is loaded for the process lifetime and its entry points are
// plain function pointers into it; PawnIOLib itself is thread-safe (each
// executor handle is independent).
unsafe impl Send for Lib {}
unsafe impl Sync for Lib {}

impl Lib {
    fn load_once() -> std::result::Result<Self, Availability> {
        // The installer puts the DLL next to the driver and does not add
        // it to PATH, so try the known install location first and fall
        // back to the normal search order (which also covers a portable
        // copy sitting next to rmon.exe).
        let module = unsafe {
            LoadLibraryW(w!("C:\\Program Files\\PawnIO\\PawnIOLib.dll"))
                .or_else(|_| LoadLibraryW(w!("PawnIOLib.dll")))
        }
        .map_err(|_| Availability::NotInstalled)?;

        let proc = |name: PCSTR| -> std::result::Result<*const c_void, Availability> {
            unsafe { GetProcAddress(module, name) }
                .map(|f| f as *const c_void)
                .ok_or_else(|| {
                    Availability::Failed("PawnIOLib.dll is missing expected exports".to_string())
                })
        };

        // SAFETY: the addresses come from GetProcAddress on this DLL and
        // the signatures are transcribed from the shipped PawnIOLib.h.
        unsafe {
            Ok(Self {
                version: std::mem::transmute::<*const c_void, PawnIoVersion>(proc(s!(
                    "pawnio_version"
                ))?),
                open: std::mem::transmute::<*const c_void, PawnIoOpen>(proc(s!("pawnio_open"))?),
                load: std::mem::transmute::<*const c_void, PawnIoLoad>(proc(s!("pawnio_load"))?),
                execute: std::mem::transmute::<*const c_void, PawnIoExecute>(proc(s!(
                    "pawnio_execute"
                ))?),
                close: std::mem::transmute::<*const c_void, PawnIoClose>(proc(s!("pawnio_close"))?),
            })
        }
    }

    fn get() -> std::result::Result<&'static Self, Availability> {
        static LIB: OnceLock<std::result::Result<Lib, Availability>> = OnceLock::new();
        LIB.get_or_init(Self::load_once)
            .as_ref()
            .map_err(Clone::clone)
    }
}

/// Which vendored module a [`PawnIo`] executor should run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Module {
    IntelMsr,
    LpcIo,
}

impl Module {
    fn blob(self) -> &'static [u8] {
        match self {
            Module::IntelMsr => blobs::INTEL_MSR,
            Module::LpcIo => blobs::LPC_IO,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Module::IntelMsr => "IntelMSR",
            Module::LpcIo => "LpcIO",
        }
    }
}

/// One loaded PawnIO module, ready to execute functions.
///
/// Each executor owns an independent driver handle, so two of these
/// (say `IntelMsr` and `LpcIo`) can be held at once without interfering.
pub struct PawnIo {
    handle: HANDLE,
    module: Module,
}

impl PawnIo {
    /// Opens an executor and loads `module` into it.
    ///
    /// A module's `main()` runs at load time and can legitimately reject
    /// the machine — `IntelMSR` returns `STATUS_NOT_SUPPORTED` on an AMD
    /// part, for instance — so a failure here is frequently "not
    /// applicable" rather than "broken".
    pub fn load(module: Module) -> std::result::Result<Self, Availability> {
        let lib = Lib::get()?;

        let mut version = 0u32;
        // A version failure is not fatal on its own; only refuse when we
        // actually got a number and it's too old.
        if unsafe { (lib.version)(&mut version) }.is_ok()
            && version != 0
            && version < MIN_DRIVER_VERSION
        {
            return Err(Availability::DriverTooOld {
                found: format_version(version),
            });
        }

        let mut handle = HANDLE::default();
        unsafe { (lib.open)(&mut handle) }.ok().map_err(|e| {
            // The driver denies non-elevated opens, which is by far the
            // most common failure and the only one with an obvious fix.
            if e.code() == HRESULT::from_win32(5) {
                Availability::NeedsElevation
            } else {
                Availability::Failed(format!("pawnio_open failed: {e}"))
            }
        })?;

        let blob = module.blob();
        if let Err(e) = unsafe { (lib.load)(handle, blob.as_ptr(), blob.len()) }.ok() {
            unsafe { (lib.close)(handle) }.ok().ok();
            return Err(Availability::Failed(format!(
                "loading the {} module failed: {e}",
                module.name()
            )));
        }

        Ok(Self { handle, module })
    }

    /// Calls one of the module's `ioctl_*` functions.
    ///
    /// `out_len` must match the count the module declares, since PawnIO
    /// rejects a mismatched buffer size outright rather than truncating.
    pub fn execute(&self, name: &str, input: &[u64], out_len: usize) -> Result<Vec<u64>> {
        let lib = Lib::get().map_err(|a| anyhow!(a.message()))?;
        let cname = CString::new(name).context("function name contained a NUL")?;
        let mut out = vec![0u64; out_len];
        let mut written = 0usize;

        unsafe {
            (lib.execute)(
                self.handle,
                PCSTR(cname.as_ptr().cast()),
                input.as_ptr(),
                input.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut written,
            )
        }
        .ok()
        .with_context(|| format!("{}::{name} failed", self.module.name()))?;

        if written < out_len {
            bail!(
                "{}::{name} returned {written} value(s), expected {out_len}",
                self.module.name()
            );
        }
        Ok(out)
    }

    /// Convenience for the common one-in/one-out shape.
    pub fn execute1(&self, name: &str, input: u64) -> Result<u64> {
        Ok(self.execute(name, &[input], 1)?[0])
    }
}

impl Drop for PawnIo {
    fn drop(&mut self) {
        if let Ok(lib) = Lib::get() {
            unsafe { (lib.close)(self.handle) }.ok().ok();
        }
    }
}

fn format_version(v: u32) -> String {
    format!("{}.{}.{}", (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF)
}

/// Whether kernel-level sensor access is usable right now, without
/// keeping an executor open.
///
/// Probes with `IntelMsr` on Intel parts and `LpcIo` otherwise, so an
/// AMD machine (where `IntelMSR`'s `main()` correctly refuses to load)
/// isn't reported as broken.
pub fn availability() -> Availability {
    match PawnIo::load(Module::LpcIo) {
        Ok(_) => Availability::Ready,
        Err(e) => e,
    }
}

/// True when `PawnIOLib.dll` could be found at all — i.e. PawnIO is
/// installed, whatever happens next.
pub fn is_installed() -> bool {
    !matches!(Lib::get(), Err(Availability::NotInstalled))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Not hermetic — it reports what this machine can actually do.
    /// Asserts only that probing never panics and never lies about
    /// being ready, since CI runners have no PawnIO installed.
    #[test]
    fn availability_probe_is_honest() {
        let a = availability();
        println!("PawnIO availability: {a:?} — {}", a.message());
        if a.is_ready() {
            assert!(is_installed(), "ready implies installed");
        }
    }
}
