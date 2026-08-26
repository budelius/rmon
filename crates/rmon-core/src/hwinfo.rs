//! Reads CPU temperature from HWiNFO, via whichever of its two "publish
//! sensors to other processes" mechanisms is actually turned on.
//!
//! Windows has no vendor-neutral API for real per-core CPU temperature (see
//! `thermal.rs`); HWiNFO gets it via a kernel driver reading vendor MSRs.
//! Getting that number out of HWiNFO and into rMon *without* also shipping
//! and loading our own kernel driver (a much bigger, riskier undertaking —
//! driver signing, Windows' vulnerable-driver blocklist, real crash/BSOD
//! risk from a bug) means reading one of HWiNFO's own export mechanisms:
//!
//! - **Registry Value Sensor Bank ("VSB")**: when HWiNFO's Settings ->
//!   "Support of Value Sensors Bank" is enabled, it mirrors whatever
//!   sensors are in its tray/summary list to
//!   `HKCU\Software\HWiNFO64\VSB` as `Label{N}`/`Value{N}`/`ValueRaw{N}`
//!   string values, refreshed continuously. Simple registry reads, no
//!   binary parsing — tried first since it's what this codebase's target
//!   user already has enabled. Caveat: only covers sensors the user has
//!   added to that list, not every sensor HWiNFO can see.
//! - **Shared Memory Support**: a named shared-memory section
//!   (`Global\HWiNFO_SENS_SM2`) exposing *every* sensor HWiNFO tracks,
//!   regardless of the tray list. More complete, but requires a separate
//!   settings toggle and a binary struct layout — HWiNFO's own interface
//!   headers are proprietary; the layout below is the community
//!   reverse-engineered format used by several third-party integrations:
//!   <https://gist.github.com/namazso/0c37be5a53863954c8c8279f66cfb1cc>.
//!
//! Both are best-effort and return `None` if HWiNFO isn't running or has
//! neither mechanism enabled — callers fall back to the ACPI thermal zone.

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Memory::{
    FILE_MAP_READ, MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile, OpenFileMappingW, UnmapViewOfFile,
};
use windows::core::PCWSTR;
use winreg::RegKey;
use winreg::enums::HKEY_CURRENT_USER;

/// HWiNFO mirrors at most a few hundred sensors to the VSB registry key
/// even on elaborate rigs, and indices aren't contiguous (a sensor can
/// disappear from the middle of the list) — scan generously rather than
/// stopping at the first gap.
const MAX_VSB_INDEX: u32 = 512;

/// True for sensor labels belonging to the CPU rather than another
/// component. HWiNFO labels CPU readings with either "CPU" ("CPU
/// Package", "CPU IA Cores") or "Core" ("Core Max", "Core Distance to
/// TjMAX"). The "core" spelling also appears on GPU sensors ("GPU Core
/// Temperature"), so an explicit GPU exclusion keeps those out.
fn is_cpu_scoped_label(label: &str) -> bool {
    !label.contains("gpu") && (label.contains("cpu") || label.contains("core"))
}

/// Picks a CPU temperature out of a list of (label, value) readings
/// already known to be CPU-scoped: prefers the whole-package number,
/// then an average of individual core readings, then an average of
/// whatever's left. Shared between the VSB and shared-memory readers.
fn pick_cpu_temp(readings: &[(String, f32)]) -> Option<f32> {
    if let Some((_, t)) = readings
        .iter()
        .find(|(label, _)| label.contains("package") || label.contains("tdie"))
    {
        return Some(*t);
    }

    let core_temps: Vec<f32> = readings
        .iter()
        .filter(|(label, _)| {
            label.contains("core") && !label.contains("distance") && !label.contains("max")
        })
        .map(|(_, t)| *t)
        .collect();
    if !core_temps.is_empty() {
        return Some(core_temps.iter().sum::<f32>() / core_temps.len() as f32);
    }

    (!readings.is_empty())
        .then(|| readings.iter().map(|(_, t)| *t).sum::<f32>() / readings.len() as f32)
}

/// Reads CPU-scoped temperature readings out of HWiNFO's Registry Value
/// Sensor Bank (`HKCU\Software\HWiNFO64\VSB`), if that feature is
/// enabled. Empty when it isn't, or when the user's tray list happens to
/// contain no CPU temperatures.
fn read_vsb_cpu_temps() -> Vec<(String, f32)> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let Ok(vsb) = hkcu.open_subkey("Software\\HWiNFO64\\VSB") else {
        return Vec::new();
    };

    let mut readings = Vec::new();
    for i in 0..MAX_VSB_INDEX {
        let Ok(label) = vsb.get_value::<String, _>(format!("Label{i}")) else {
            continue;
        };
        let label = label.to_lowercase();
        if !is_cpu_scoped_label(&label) {
            continue;
        }
        // `Value{i}` carries the unit (e.g. "65 °C") so we can confirm
        // this is a temperature reading before trusting `ValueRaw{i}`,
        // which is just the bare number and could belong to any sensor
        // type (volts, MHz, RPM, ...).
        let Ok(value_str) = vsb.get_value::<String, _>(format!("Value{i}")) else {
            continue;
        };
        if !value_str.contains("°C") {
            continue;
        }
        let Ok(raw) = vsb.get_value::<String, _>(format!("ValueRaw{i}")) else {
            continue;
        };
        let Ok(temp) = raw.trim().parse::<f32>() else {
            continue;
        };
        readings.push((label, temp));
    }

    readings
}

const SHARED_MEM_PATH: &str = "Global\\HWiNFO_SENS_SM2";
const HEADER_MAGIC: u32 = 0x4869_5753; // 'SiWH'
const SENSOR_TYPE_TEMPERATURE: u32 = 1;
/// Defensive cap on section element counts, in case a future format
/// version (or garbage data) makes the header lie — mirrors the same
/// `MAX_HANDLES`-style guard in `handles.rs`.
const MAX_ELEMENTS: u32 = 8192;

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Header {
    magic: u32,
    _version: u32,
    _version2: u32,
    _last_update: i64,
    sensor_section_offset: u32,
    sensor_element_size: u32,
    sensor_element_count: u32,
    entry_section_offset: u32,
    entry_element_size: u32,
    entry_element_count: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Sensor {
    _id: u32,
    _instance: u32,
    name_original: [u8; 128],
    _name_user: [u8; 128],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Entry {
    kind: u32,
    sensor_index: u32,
    _id: u32,
    name_original: [u8; 128],
    _name_user: [u8; 128],
    unit: [u8; 16],
    value: f64,
    _value_min: f64,
    _value_max: f64,
    _value_avg: f64,
}

fn c_str(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}

fn c_str_lower(bytes: &[u8]) -> String {
    c_str(bytes).to_lowercase()
}

/// One labeled reading within a [`SensorGroup`], e.g. `("CPU Package",
/// "74.00 °C")` — formatted for direct display, not further parsing.
pub struct SensorReading {
    pub label: String,
    pub value: String,
}

/// A group of related readings as HWiNFO itself groups them (e.g. "CPU
/// [#0]: Intel Core i9-13900K: DTS", "CPU [#0]: ... Enhanced", "Memory
/// Timings") — mirrors the tree structure of HWiNFO's own Sensors window.
pub struct SensorGroup {
    pub name: String,
    pub readings: Vec<SensorReading>,
}

struct SharedMem {
    view: MEMORY_MAPPED_VIEW_ADDRESS,
    handle: HANDLE,
}

impl SharedMem {
    fn open() -> Option<Self> {
        let path_wide: Vec<u16> = SHARED_MEM_PATH
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        unsafe {
            let handle =
                OpenFileMappingW(FILE_MAP_READ.0, false, PCWSTR(path_wide.as_ptr())).ok()?;
            let view = MapViewOfFile(handle, FILE_MAP_READ, 0, 0, 0);
            if view.Value.is_null() {
                let _ = CloseHandle(handle);
                return None;
            }
            Some(Self { view, handle })
        }
    }

    /// Reads a `T` at byte `offset` into the mapped view. Unsafe: the
    /// caller must keep `offset + size_of::<T>()` within whatever HWiNFO
    /// actually committed — we only have the header's own word for that.
    unsafe fn read<T: Copy>(&self, offset: usize) -> T {
        unsafe { std::ptr::read_unaligned(self.view.Value.cast::<u8>().add(offset).cast::<T>()) }
    }
}

impl Drop for SharedMem {
    fn drop(&mut self) {
        unsafe {
            let _ = UnmapViewOfFile(self.view);
            let _ = CloseHandle(self.handle);
        }
    }
}

/// Reads CPU-scoped temperature readings out of HWiNFO's shared memory
/// section, if Shared Memory Support is enabled. `None` when it isn't.
fn read_shm_cpu_temps() -> Option<Vec<(String, f32)>> {
    let mem = SharedMem::open()?;
    let header: Header = unsafe { mem.read(0) };
    if header.magic != HEADER_MAGIC
        || header.sensor_element_count > MAX_ELEMENTS
        || header.entry_element_count > MAX_ELEMENTS
        || (header.sensor_element_size as usize) < std::mem::size_of::<Sensor>()
        || (header.entry_element_size as usize) < std::mem::size_of::<Entry>()
    {
        return None;
    }

    let sensors: Vec<Sensor> = (0..header.sensor_element_count)
        .map(|i| unsafe {
            mem.read(
                header.sensor_section_offset as usize
                    + i as usize * header.sensor_element_size as usize,
            )
        })
        .collect();
    let is_cpu_sensor = |idx: u32| {
        sensors
            .get(idx as usize)
            .is_some_and(|s| c_str_lower(&s.name_original).contains("cpu"))
    };

    let readings: Vec<(String, f32)> = (0..header.entry_element_count)
        .map(|i| unsafe {
            mem.read::<Entry>(
                header.entry_section_offset as usize
                    + i as usize * header.entry_element_size as usize,
            )
        })
        .filter(|e| e.kind == SENSOR_TYPE_TEMPERATURE && is_cpu_sensor(e.sensor_index))
        .map(|e| (c_str_lower(&e.name_original), e.value as f32))
        .collect();

    Some(readings)
}

/// CPU-scoped temperature readings from whichever HWiNFO export is
/// available, trying the registry Value Sensor Bank first (works today
/// for anyone with "Support of Value Sensors Bank" enabled, which this
/// codebase's target user already has), then shared memory.
fn cpu_temp_readings() -> Vec<(String, f32)> {
    let vsb = read_vsb_cpu_temps();
    if !vsb.is_empty() {
        return vsb;
    }
    read_shm_cpu_temps().unwrap_or_default()
}

/// Best-effort CPU temperature (°C). Returns `None` if HWiNFO isn't
/// running or has neither export mechanism enabled.
pub fn read_cpu_temp() -> Option<f32> {
    pick_cpu_temp(&cpu_temp_readings())
}

/// Both CPU thermal facts — `(temperature °C, °C below TjMax)` — from a
/// single pass over HWiNFO's export.
///
/// The second value is the honest way to answer "is this CPU at its
/// thermal limit": TjMax is vendor- and part-specific (100°C on Intel
/// desktop parts, but AMD's Tctl sits at 95°C during *normal*
/// operation), so comparing a raw temperature against a hardcoded
/// ceiling false-positives on some CPUs and false-negatives on others.
/// When present, the CPU is telling us its own remaining headroom and no
/// threshold is needed. It's the *minimum* distance across cores, since
/// the hottest core is what triggers throttling. `None` means HWiNFO
/// doesn't expose it — not that there's headroom to spare.
///
/// Returned together because the VSB path scans up to [`MAX_VSB_INDEX`]
/// registry entries; callers sampling every tick would otherwise pay
/// that twice for no benefit.
pub fn read_cpu_thermal() -> (Option<f32>, Option<f32>) {
    let readings = cpu_temp_readings();
    (pick_cpu_temp(&readings), tjmax_distance(&readings))
}

fn tjmax_distance(readings: &[(String, f32)]) -> Option<f32> {
    readings
        .iter()
        .filter(|(label, _)| label.contains("tjmax"))
        .map(|(_, v)| *v)
        .fold(None, |acc: Option<f32>, v| {
            Some(acc.map_or(v, |a| a.min(v)))
        })
}

/// Every sensor reading HWiNFO exposes, grouped the same way its own
/// Sensors window groups them. This is an explicitly requested,
/// supplemental view; [`crate::Sampler`] never calls it. Tries shared
/// memory first (comprehensive — every sensor HWiNFO tracks, regardless of
/// what's in its tray list), falling back to whatever is mirrored in the
/// VSB registry key. Returns an empty `Vec` if HWiNFO is not running or
/// exposes nothing via either mechanism.
pub fn read_all_sensors() -> Vec<SensorGroup> {
    read_all_sensors_shm().unwrap_or_else(read_all_sensors_vsb)
}

fn format_reading_value(raw: f64, unit: &str) -> String {
    if unit.is_empty() {
        format!("{raw:.2}")
    } else {
        format!("{raw:.2} {unit}")
    }
}

fn read_all_sensors_shm() -> Option<Vec<SensorGroup>> {
    let mem = SharedMem::open()?;
    let header: Header = unsafe { mem.read(0) };
    if header.magic != HEADER_MAGIC
        || header.sensor_element_count > MAX_ELEMENTS
        || header.entry_element_count > MAX_ELEMENTS
        || (header.sensor_element_size as usize) < std::mem::size_of::<Sensor>()
        || (header.entry_element_size as usize) < std::mem::size_of::<Entry>()
    {
        return None;
    }

    let mut groups: Vec<SensorGroup> = (0..header.sensor_element_count)
        .map(|i| unsafe {
            mem.read::<Sensor>(
                header.sensor_section_offset as usize
                    + i as usize * header.sensor_element_size as usize,
            )
        })
        .map(|s| SensorGroup {
            name: c_str(&s.name_original),
            readings: Vec::new(),
        })
        .collect();

    for i in 0..header.entry_element_count {
        let entry: Entry = unsafe {
            mem.read(
                header.entry_section_offset as usize
                    + i as usize * header.entry_element_size as usize,
            )
        };
        let Some(group) = groups.get_mut(entry.sensor_index as usize) else {
            continue;
        };
        group.readings.push(SensorReading {
            label: c_str(&entry.name_original),
            value: format_reading_value(entry.value, &c_str(&entry.unit)),
        });
    }

    groups.retain(|g| !g.readings.is_empty());
    Some(groups)
}

fn read_all_sensors_vsb() -> Vec<SensorGroup> {
    let mut groups: Vec<SensorGroup> = Vec::new();
    let Ok(vsb) = RegKey::predef(HKEY_CURRENT_USER).open_subkey("Software\\HWiNFO64\\VSB") else {
        return groups;
    };

    for i in 0..MAX_VSB_INDEX {
        let Ok(label) = vsb.get_value::<String, _>(format!("Label{i}")) else {
            continue;
        };
        let Ok(value) = vsb.get_value::<String, _>(format!("Value{i}")) else {
            continue;
        };
        let group_name = vsb
            .get_value::<String, _>(format!("Sensor{i}"))
            .unwrap_or_else(|_| "HWiNFO".to_string());

        let group_idx = match groups.iter().position(|g| g.name == group_name) {
            Some(idx) => idx,
            None => {
                groups.push(SensorGroup {
                    name: group_name,
                    readings: Vec::new(),
                });
                groups.len() - 1
            }
        };
        groups[group_idx]
            .readings
            .push(SensorReading { label, value });
    }

    groups
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Not a hermetic test (depends on HWiNFO actually running on the
    /// machine executing it) — a smoke check confirming the reader
    /// doesn't panic and, when it can, prints what it found so a human
    /// can eyeball plausibility. Run with `cargo test -- --nocapture`.
    #[test]
    fn read_cpu_temp_smoke() {
        match read_cpu_temp() {
            Some(t) => {
                println!("read_cpu_temp() -> {t} °C");
                assert!((-50.0..150.0).contains(&t), "implausible temperature: {t}");
            }
            None => {
                println!("read_cpu_temp() -> None (HWiNFO not running / no mechanism enabled here)")
            }
        }
    }

    #[test]
    fn read_all_sensors_smoke() {
        let groups = read_all_sensors();
        println!("read_all_sensors() -> {} group(s)", groups.len());
        for g in &groups {
            println!("  [{}]", g.name);
            for r in &g.readings {
                println!("    {}: {}", r.label, r.value);
            }
        }
    }
}
