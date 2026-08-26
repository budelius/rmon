//! Motherboard Super I/O access — chip identification, temperatures,
//! voltages, and fan tachometers — through PawnIO's `LpcIO` module.
//!
//! These readings are not exposed by a useful vendor-neutral Windows API.
//! They live in a Super I/O chip hanging off the LPC bus (Nuvoton, ITE and
//! Fintek make nearly all of them), reachable only through legacy ISA port
//! I/O from ring 0. That is why every hardware-monitoring tool on Windows
//! ships a driver.
//!
//! The sequence is the same one LibreHardwareMonitor and lm-sensors use:
//!
//! 1. Knock on the chip's configuration port pair (0x2E/0x2F, or
//!    0x4E/0x4F for a second chip) with the vendor's unlock sequence.
//! 2. Read the chip ID and revision to work out which register map
//!    applies.
//! 3. Ask the chip where its hardware-monitor block was mapped, and read
//!    fan counters out of that block.
//!
//! # Two chips, not one
//!
//! A board can carry a Super I/O on *both* configuration ports, and the
//! one that owns the fan headers is not necessarily the first to answer.
//! The machine this was developed against is exactly that case: an
//! NCT6796D-R sits at 0x4E with every tachometer channel empty, while the
//! NCT6686D at 0x2E has the actual fans. Stopping at the first chip found
//! yields a confident, fully working read of nothing at all — so every
//! detected chip is kept and read.
//!
//! # Two register layouts
//!
//! The NCT67xx line exposes a banked register space: select a bank through
//! the index port, then the register. The NCT668x line (NCT6683D,
//! NCT6686D, NCT6687D — the parts MSI boards use) instead exposes a *paged
//! EC space* with its own handshake, and reports fan speed as a direct
//! 16-bit RPM value rather than as a period counter. Both are implemented;
//! see [`Family`].
//!
//! # Sharing the bus
//!
//! This bus has no arbitration of its own. Reading one register means
//! writing an index and then reading a data port as two separate
//! operations, so if HWiNFO (or FanControl, or the vendor's own utility)
//! interleaves its own index write between ours, both sides silently read
//! the wrong register. The long-standing convention every such tool
//! follows is a named mutex, `Access_ISABUS.HTP.Method`; see [`IsaLock`].
//! We refuse to touch the bus without holding it rather than racing.
//!
//! # Scope
//!
//! Nuvoton NCT67xx and NCT668x temperatures, voltage inputs, and fan
//! tachometers are decoded. NCT67xx voltage labels deliberately remain
//! `VIN` pin names: the resistor-divider scaling from a pin voltage to a
//! +5V/+12V rail is motherboard-specific, so inventing a rail label would
//! produce a plausible but wrong value. ITE IT87xx chips are identified
//! and named but not read: their map varies per model in ways this code
//! cannot verify against real hardware.

use std::cell::{Cell, RefCell};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{
    CreateMutexW, OpenMutexW, ReleaseMutex, SYNCHRONIZATION_SYNCHRONIZE, WaitForSingleObject,
};
use windows::core::w;

use crate::pawnio::{Availability, Module, PawnIo};

/// Configuration port pairs to probe, in the order chips conventionally
/// occupy them.
const REGISTER_PORTS: [u16; 2] = [0x2E, 0x4E];

const CHIP_ID_REGISTER: u64 = 0x20;
const CHIP_REVISION_REGISTER: u64 = 0x21;
const DEVICE_SELECT_REGISTER: u64 = 0x07;
const BASE_ADDRESS_REGISTER: u64 = 0x60;
/// Nuvoton's hardware-monitor logical device.
const NUVOTON_HM_LDN: u64 = 0x0B;
/// Nuvoton register whose bit 4 locks the hardware-monitor I/O space.
const NUVOTON_IO_SPACE_LOCK: u64 = 0x28;

// Register addresses and conversion rules below are cross-checked against
// LibreHardwareMonitor's Nct677X implementation (MPL-2.0) and the chip
// datasheet conventions it follows.
//
// --- NCT67xx banked register space ---------------------------------------

/// Offsets from the hardware-monitor base address to its index and data
/// ports.
const ADDRESS_REGISTER_OFFSET: u16 = 0x05;
const DATA_REGISTER_OFFSET: u16 = 0x06;
/// The index value that selects a bank.
const BANK_SELECT_REGISTER: u64 = 0x4E;

/// Banked registers holding the chip's vendor ID. Reading
/// [`NUVOTON_VENDOR_ID`] back through them proves the whole path works —
/// correct base address, correct bank switching, hardware-monitor block
/// awake — which is the one fact worth establishing before believing (or
/// disbelieving) any fan number read the same way.
const VENDOR_ID_HIGH_REGISTER: u16 = 0x804F;
const VENDOR_ID_LOW_REGISTER: u16 = 0x004F;
const NUVOTON_VENDOR_ID: u16 = 0x5CA3;

/// 13-bit fan period counters on NCT67xx.
const NCT67XX_FAN_COUNT_REGISTERS: [u16; 7] = [0x4B0, 0x4B2, 0x4B4, 0x4B6, 0x4B8, 0x4BA, 0x4CC];
/// Counter ceiling: at or above this the counter has saturated, which
/// means no fan is connected or it is stopped.
const MAX_FAN_COUNT: u32 = 0x1FFF;
/// Below this the count implies an impossible RPM and is noise.
const MIN_FAN_COUNT: u32 = 0x15;
/// Tachometer clock: counts per minute, so `RPM = CLOCK / count`.
const FAN_CLOCK: f32 = 1.35e6;

/// NCT6771F/6776F expose nine 8 mV voltage ADC channels here. Later
/// NCT67xx parts expose sixteen channels in bank 4.
const NCT677X_VOLTAGE_REGISTERS: [u16; 9] = [
    0x020, 0x021, 0x022, 0x023, 0x024, 0x025, 0x026, 0x550, 0x551,
];
const NCT679X_VOLTAGE_REGISTERS: [u16; 16] = [
    0x480, 0x481, 0x482, 0x483, 0x484, 0x485, 0x486, 0x487, 0x488, 0x489, 0x48A, 0x48B, 0x48C,
    0x48D, 0x48E, 0x48F,
];
const NCT67XX_VOLTAGE_STEP_V: f32 = 0.008;
/// A temperature outside the Super I/O parts' documented input range is
/// an unconnected diode or a register that is not active, not a reading.
const MIN_BOARD_TEMP_C: f32 = -55.0;
const MAX_BOARD_TEMP_C: f32 = 125.0;

// --- NCT668x paged EC space ----------------------------------------------

/// Offsets from the base address to the EC space's page, index and data
/// ports.
const EC_PAGE_REGISTER_OFFSET: u16 = 0x04;
const EC_INDEX_REGISTER_OFFSET: u16 = 0x05;
const EC_DATA_REGISTER_OFFSET: u16 = 0x06;
/// Written to the page register to claim, and then release, access. The EC
/// parks it at this value when idle, so reading it back is how a caller
/// waits its turn.
const EC_PAGE_SELECT: u8 = 0xFF;
/// How long to wait for the EC to park the page register before forcing
/// access, matching LibreHardwareMonitor's behaviour.
const EC_ACCESS_TIMEOUT: Duration = Duration::from_millis(500);

/// Direct 16-bit RPM registers on NCT668x. Which physical header each
/// index corresponds to varies by board — hence the generic labels; the
/// addresses themselves are stable across the family.
const NCT668X_FAN_RPM_REGISTERS: [u16; 17] = [
    0x140, 0x142, 0x144, 0x146, 0x148, 0x14A, 0x14C, 0x14E, 0x150, 0x152, 0x154, 0x156, 0x158,
    0x15A, 0x15C, 0x15E, 0x852,
];
/// The one NCT668x fan register that is a 13-bit counter rather than a
/// direct RPM value.
const NCT668X_COUNTER_REGISTERS: [u16; 1] = [0x852];

/// Signed whole-degree byte followed by a half-degree bit in bit 7.
const NCT668X_TEMPERATURE_REGISTERS: [u16; 11] = [
    0x100, 0x102, 0x104, 0x106, 0x108, 0x10A, 0x10C, 0x10E, 0x110, 0x112, 0x114,
];
const NCT668X_TEMPERATURE_LABELS: [&str; 11] = [
    "CPU",
    "system",
    "VRM MOS",
    "PCH",
    "CPU socket",
    "PCIe sensor 1",
    "M.2 sensor 1",
    "PCIe sensor 2",
    "PCIe sensor 3",
    "M.2 sensor 2",
    "M.2 sensor 4",
];
/// Twelve-bit millivolt samples: high byte plus the high nibble of the
/// following byte. The first, second, and fifth channels have fixed
/// internal scaling on this family; unlike NCT67xx this is not a
/// motherboard resistor-divider guess.
const NCT668X_VOLTAGE_REGISTERS: [u16; 14] = [
    0x120, 0x122, 0x124, 0x126, 0x128, 0x12A, 0x12C, 0x12E, 0x130, 0x13A, 0x13E, 0x136, 0x138,
    0x13C,
];
const NCT668X_VOLTAGE_LABELS: [&str; 14] = [
    "+12V",
    "+5V",
    "Vcore",
    "SIO voltage 1",
    "DRAM",
    "CPU I/O",
    "CPU system agent",
    "SIO voltage 2",
    "+3.3V I/O",
    "CPU termination",
    "Vref",
    "standby",
    "analog standby",
    "CMOS battery",
];
const NCT668X_VOLTAGE_FACTORS: [f32; 14] = [
    12.0, 5.0, 1.0, 1.0, 2.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0,
];

/// Bit 7 of this register enables the monitoring block. Boards normally
/// ship with it set; clearing it is not something rMon ever does.
const NCT668X_INIT_REGISTER: u16 = 0x180;
/// Routes the five SIO ADC sources into the voltage monitor. These are
/// monitor-selection bytes, not power-rail controls; LibreHardwareMonitor
/// applies the same family-wide setup.
const NCT668X_VOLTAGE_ENABLE: [(u16, u8); 5] = [
    (0x1BB, 0x61),
    (0x1BC, 0x62),
    (0x1BD, 0x63),
    (0x1BE, 0x64),
    (0x1BF, 0x65),
];
/// Above this an RPM reading is not a fan, it is a stuck register.
const MAX_PLAUSIBLE_RPM: u32 = 40_000;

/// How many refreshes to skip a chip that reported no spinning fan before
/// trying it again. A board's second Super I/O routinely has nothing
/// plugged into it, and re-selecting its slot costs a full base-address
/// walk; but a fan can be connected while rMon runs, so "never again" would
/// be wrong. At the three-second refresh interval this retries roughly
/// once a minute.
const BARREN_CHIP_RESCAN_EVERY: u64 = 20;

/// How long to wait for the shared ISA-bus mutex before giving up on this
/// tick. Deliberately short: another tool holding the bus is completely
/// normal, and skipping a fan reading is free, whereas blocking the
/// sampler is not.
const ISA_LOCK_TIMEOUT: Duration = Duration::from_millis(150);

#[derive(Clone, Copy)]
enum TemperatureSourceMap {
    Nct6771,
    Nct6776,
    Nct67xx,
}

/// One routed temperature register on a banked NCT67xx part. The source
/// register matters: firmware can route (for example) SYSTIN through a
/// different ADC slot, so the fallback label is used only when that route
/// byte is absent or unknown.
#[derive(Clone, Copy)]
struct BankedTemperatureChannel {
    fallback_label: &'static str,
    register: u16,
    half: Option<(u16, u8)>,
    source_register: Option<u16>,
    alternate_register: Option<u16>,
}

const NCT677X_TEMPERATURES: [BankedTemperatureChannel; 4] = [
    BankedTemperatureChannel {
        fallback_label: "CPU (PECI)",
        register: 0x027,
        half: None,
        source_register: Some(0x621),
        alternate_register: None,
    },
    BankedTemperatureChannel {
        fallback_label: "CPU socket",
        register: 0x073,
        half: Some((0x074, 7)),
        source_register: Some(0x100),
        alternate_register: None,
    },
    BankedTemperatureChannel {
        fallback_label: "auxiliary",
        register: 0x075,
        half: Some((0x076, 7)),
        source_register: Some(0x200),
        alternate_register: None,
    },
    BankedTemperatureChannel {
        fallback_label: "system",
        register: 0x077,
        half: Some((0x078, 7)),
        source_register: Some(0x300),
        alternate_register: None,
    },
];

const NCT6779_TEMPERATURES: [BankedTemperatureChannel; 7] = [
    banked_temp("CPU (PECI)", 0x027, None, 0x621, None),
    banked_temp("CPU socket", 0x073, Some((0x074, 7)), 0x100, Some(0x491)),
    banked_temp("system", 0x075, Some((0x076, 7)), 0x200, Some(0x490)),
    banked_temp("auxiliary 0", 0x077, Some((0x078, 7)), 0x300, Some(0x492)),
    banked_temp("auxiliary 1", 0x079, Some((0x07A, 7)), 0x800, Some(0x493)),
    banked_temp("auxiliary 2", 0x07B, Some((0x07C, 7)), 0x900, Some(0x494)),
    banked_temp("auxiliary 3", 0x150, Some((0x151, 7)), 0x622, Some(0x495)),
];

const NCT6791_TO_95_TEMPERATURES: [BankedTemperatureChannel; 8] = [
    banked_temp("CPU (PECI)", 0x073, Some((0x074, 7)), 0x100, None),
    banked_temp("CPU socket", 0x075, Some((0x076, 7)), 0x200, Some(0x491)),
    banked_temp("system", 0x077, Some((0x078, 7)), 0x300, Some(0x490)),
    banked_temp("auxiliary 0", 0x079, Some((0x07A, 7)), 0x800, Some(0x492)),
    banked_temp("auxiliary 1", 0x07B, Some((0x07C, 7)), 0x900, Some(0x493)),
    banked_temp("auxiliary 2", 0x07D, Some((0x07E, 7)), 0xA00, Some(0x494)),
    banked_temp("auxiliary 3", 0x4A0, Some((0x49E, 6)), 0xB00, Some(0x495)),
    banked_temp("auxiliary 4", 0x027, None, 0x621, None),
];

const NCT6798_TO_99_TEMPERATURES: [BankedTemperatureChannel; 9] = [
    NCT6791_TO_95_TEMPERATURES[0],
    NCT6791_TO_95_TEMPERATURES[1],
    NCT6791_TO_95_TEMPERATURES[2],
    NCT6791_TO_95_TEMPERATURES[3],
    NCT6791_TO_95_TEMPERATURES[4],
    NCT6791_TO_95_TEMPERATURES[5],
    NCT6791_TO_95_TEMPERATURES[6],
    NCT6791_TO_95_TEMPERATURES[7],
    banked_temp("thermistor", 0x4A2, Some((0x4A1, 7)), 0xC00, Some(0x496)),
];

const fn banked_temp(
    fallback_label: &'static str,
    register: u16,
    half: Option<(u16, u8)>,
    source_register: u16,
    alternate_register: Option<u16>,
) -> BankedTemperatureChannel {
    BankedTemperatureChannel {
        fallback_label,
        register,
        half,
        source_register: Some(source_register),
        alternate_register,
    }
}

/// The Super I/O families this code can tell apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// Nuvoton NCT67xx: banked register space, 13-bit period counters.
    NuvotonNct67xx,
    /// Nuvoton NCT668x: paged EC space, direct 16-bit RPM values.
    NuvotonNct668x,
    /// ITE IT87xx — identified only; see the module docs.
    IteIt87xx,
}

impl Family {
    /// Whether [`SuperIo::read_fans`] can return readings for this chip.
    pub fn fans_supported(self) -> bool {
        matches!(self, Family::NuvotonNct67xx | Family::NuvotonNct668x)
    }

    /// Whether temperatures and voltage inputs are decoded for this chip.
    pub fn board_sensors_supported(self) -> bool {
        matches!(self, Family::NuvotonNct67xx | Family::NuvotonNct668x)
    }
}

/// An identified Super I/O chip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chip {
    pub name: String,
    pub family: Family,
    pub id: u8,
    pub revision: u8,
    /// Number of fan tachometer channels the chip exposes.
    pub fan_count: usize,
    /// Configuration port the chip answered on (0x2E or 0x4E).
    pub register_port: u16,
}

/// One fan tachometer reading.
#[derive(Debug, Clone, PartialEq)]
pub struct FanReading {
    /// Chip the channel belongs to. Present because a board can have two
    /// Super I/O chips and "fan 1" alone would be ambiguous.
    pub chip: String,
    /// Channel index on that chip, 0-based.
    pub index: usize,
    /// Display label. Deliberately not "CPU fan"/"chassis fan": which
    /// header a channel corresponds to is a board-layout fact the chip
    /// does not know and rMon cannot infer.
    pub label: String,
    /// `None` when the channel is present but nothing is spinning on it
    /// (no fan connected, or stopped in a zero-RPM mode).
    pub rpm: Option<u32>,
}

/// One temperature input in the motherboard's Super I/O block.
#[derive(Debug, Clone, PartialEq)]
pub struct BoardTemperatureReading {
    pub chip: String,
    pub index: usize,
    pub label: String,
    /// `None` means the channel exists but is unconnected or invalid.
    pub temp_c: Option<f32>,
}

/// One voltage ADC input in the motherboard's Super I/O block.
#[derive(Debug, Clone, PartialEq)]
pub struct VoltageReading {
    pub chip: String,
    pub index: usize,
    pub label: String,
    /// `None` means the ADC channel could not provide a valid sample.
    pub volts: Option<f32>,
}

/// One complete Super I/O sweep. Keeping the three sensor classes in one
/// operation avoids selecting each chip and walking its LPC base addresses
/// three times on a board with multiple Super I/O devices.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SuperIoReadings {
    pub fans: Vec<FanReading>,
    pub temperatures: Vec<BoardTemperatureReading>,
    pub voltages: Vec<VoltageReading>,
}

/// A detected chip and where its hardware-monitor block lives.
struct Device {
    chip: Chip,
    /// Configuration port slot index, as `ioctl_select_slot` numbers them.
    slot: u64,
    /// Base address of the hardware-monitor / EC register block.
    hm_base: u16,
    /// Whether the last read found any spinning fan on this chip.
    has_live_fans: Cell<bool>,
    /// The last readings, reused on refreshes where this chip is skipped
    /// so its channels don't blink in and out of the display.
    last: RefCell<Vec<FanReading>>,
}

/// Every Super I/O chip found on this board.
pub struct SuperIo {
    io: PawnIo,
    devices: Vec<Device>,
    /// Which configuration slot the executor currently has selected, and
    /// therefore whose base addresses it currently permits.
    ///
    /// Tracked because re-selecting is expensive: `ioctl_select_slot`
    /// discards the module's list of allowed base addresses, so it must be
    /// followed by `ioctl_find_bars`, which walks all 255 logical devices
    /// twice with a sleep in between. Paying that on every refresh — for
    /// each chip — would put milliseconds of ISA port traffic on the
    /// sampling thread every few seconds for no new information, since
    /// base addresses do not move while the machine is running.
    current_slot: Cell<Option<u64>>,
    /// Refresh counter, used to periodically retry chips that reported no
    /// fans. See [`BARREN_CHIP_RESCAN_EVERY`].
    read_count: Cell<u64>,
}

impl SuperIo {
    /// Probes both configuration ports and keeps every chip found.
    pub fn detect() -> std::result::Result<Self, Availability> {
        let io = PawnIo::load(Module::LpcIo)?;
        detect_with(io).map_err(|e| Availability::Failed(format!("{e:#}")))
    }

    /// Every chip found, in probe order.
    pub fn chips(&self) -> impl ExactSizeIterator<Item = &Chip> {
        self.devices.iter().map(|d| &d.chip)
    }

    /// The first chip whose fans rMon can decode.
    pub fn primary(&self) -> Option<&Chip> {
        self.devices
            .iter()
            .find(|d| d.chip.family.fans_supported())
            .map(|d| &d.chip)
    }

    /// Reads every decoded sensor class in one pass. Errors are isolated
    /// per chip: one inaccessible secondary controller must not hide the
    /// primary controller's readings.
    pub fn read_sensors(&self) -> Result<SuperIoReadings> {
        let decodable = self
            .devices
            .iter()
            .filter(|d| d.chip.family.board_sensors_supported())
            .count();
        let round = self.read_count.get();
        self.read_count.set(round.wrapping_add(1));

        let mut out = SuperIoReadings::default();
        let mut successful_chips = 0usize;
        let mut first_error = None;

        for device in self
            .devices
            .iter()
            .filter(|d| d.chip.family.board_sensors_supported())
        {
            let result = (|| {
                let _lock = IsaLock::acquire()?;
                self.select(device)?;
                if device.chip.family == Family::NuvotonNct668x {
                    self.init_nct668x(device)?;
                }

                // Empty fan blocks are rechecked periodically. Board
                // temperatures and voltages are still read every sweep;
                // selecting the device once serves all three classes.
                let due =
                    device.has_live_fans.get() || round.is_multiple_of(BARREN_CHIP_RESCAN_EVERY);
                let fans = if due {
                    self.read_device_fans_selected(device, decodable > 1)?
                } else {
                    device.last.borrow().clone()
                };
                let (temperatures, voltages) =
                    self.read_device_board_sensors_selected(device, decodable > 1)?;
                Ok::<_, anyhow::Error>((fans, temperatures, voltages))
            })();

            match result {
                Ok((fans, temperatures, voltages)) => {
                    device
                        .has_live_fans
                        .set(fans.iter().any(|f| f.rpm.is_some()));
                    *device.last.borrow_mut() = fans.clone();
                    out.fans.extend(fans);
                    out.temperatures.extend(temperatures);
                    out.voltages.extend(voltages);
                    successful_chips += 1;
                }
                Err(e) => {
                    log::debug!("reading {} sensors failed: {e:#}", device.chip.name);
                    out.fans.extend(device.last.borrow().iter().cloned());
                    if first_error.is_none() {
                        first_error = Some(e);
                    }
                }
            }
        }

        if decodable > 0 && successful_chips == 0 {
            return Err(
                first_error.unwrap_or_else(|| anyhow!("no Super I/O sensor read succeeded"))
            );
        }
        Ok(out)
    }

    /// Reads every fan channel on every chip that can be decoded.
    pub fn read_fans(&self) -> Result<Vec<FanReading>> {
        Ok(self.read_sensors()?.fans)
    }

    /// Reads motherboard temperatures and voltage inputs without involving
    /// HWiNFO or another monitoring process.
    pub fn read_board_sensors(
        &self,
    ) -> Result<(Vec<BoardTemperatureReading>, Vec<VoltageReading>)> {
        let readings = self.read_sensors()?;
        Ok((readings.temperatures, readings.voltages))
    }

    /// Reads fan registers after the caller has selected the device and
    /// acquired the shared ISA lock.
    fn read_device_fans_selected(&self, device: &Device, qualify: bool) -> Result<Vec<FanReading>> {
        let label = |i: usize| qualify_label(&device.chip.name, &format!("fan {}", i + 1), qualify);

        match device.chip.family {
            Family::NuvotonNct67xx => (0..device.chip.fan_count)
                .map(|i| {
                    let reg = NCT67XX_FAN_COUNT_REGISTERS[i];
                    let high = self.read_banked(device, reg)?;
                    let low = self.read_banked(device, reg + 1)?;
                    Ok(FanReading {
                        chip: device.chip.name.clone(),
                        index: i,
                        label: label(i),
                        rpm: counter_to_rpm(high, low),
                    })
                })
                .collect(),
            Family::NuvotonNct668x => (0..device.chip.fan_count)
                .map(|i| {
                    let reg = NCT668X_FAN_RPM_REGISTERS[i];
                    let high = self.read_ec(device, reg)?;
                    let low = self.read_ec(device, reg + 1)?;
                    let rpm = if NCT668X_COUNTER_REGISTERS.contains(&reg) {
                        counter_to_rpm(high, low)
                    } else {
                        direct_rpm(high, low)
                    };
                    Ok(FanReading {
                        chip: device.chip.name.clone(),
                        index: i,
                        label: label(i),
                        rpm,
                    })
                })
                .collect(),
            Family::IteIt87xx => Ok(Vec::new()),
        }
    }

    fn read_device_board_sensors_selected(
        &self,
        device: &Device,
        qualify: bool,
    ) -> Result<(Vec<BoardTemperatureReading>, Vec<VoltageReading>)> {
        match device.chip.family {
            Family::NuvotonNct67xx => Ok((
                self.read_nct67xx_temperatures(device, qualify)?,
                self.read_nct67xx_voltages(device, qualify)?,
            )),
            Family::NuvotonNct668x => Ok((
                self.read_nct668x_temperatures(device, qualify)?,
                self.read_nct668x_voltages(device, qualify)?,
            )),
            Family::IteIt87xx => Ok((Vec::new(), Vec::new())),
        }
    }

    fn read_nct668x_temperatures(
        &self,
        device: &Device,
        qualify: bool,
    ) -> Result<Vec<BoardTemperatureReading>> {
        NCT668X_TEMPERATURE_REGISTERS
            .iter()
            .enumerate()
            .map(|(index, &register)| {
                let whole = self.read_ec(device, register)?;
                let fraction = self.read_ec(device, register + 1)?;
                let temp_c =
                    decode_temperature(whole as i8 as f32 + 0.5 * ((fraction >> 7) & 1) as f32);
                Ok(BoardTemperatureReading {
                    chip: device.chip.name.clone(),
                    index,
                    label: qualify_label(
                        &device.chip.name,
                        NCT668X_TEMPERATURE_LABELS[index],
                        qualify,
                    ),
                    temp_c,
                })
            })
            .collect()
    }

    fn read_nct668x_voltages(&self, device: &Device, qualify: bool) -> Result<Vec<VoltageReading>> {
        NCT668X_VOLTAGE_REGISTERS
            .iter()
            .enumerate()
            .map(|(index, &register)| {
                let high = self.read_ec(device, register)?;
                let low = self.read_ec(device, register + 1)?;
                let volts = decode_nct668x_voltage(index, high, low);
                Ok(VoltageReading {
                    chip: device.chip.name.clone(),
                    index,
                    label: qualify_label(&device.chip.name, NCT668X_VOLTAGE_LABELS[index], qualify),
                    volts,
                })
            })
            .collect()
    }

    fn read_nct67xx_voltages(&self, device: &Device, qualify: bool) -> Result<Vec<VoltageReading>> {
        let registers: &[u16] = if matches!(device.chip.name.as_str(), "NCT6771F" | "NCT6776F") {
            &NCT677X_VOLTAGE_REGISTERS
        } else {
            &NCT679X_VOLTAGE_REGISTERS
        };
        let vbat_index = 8;
        let vbat_enabled = self
            .read_banked(device, 0x05D)
            .map(|v| v & 1 != 0)
            .unwrap_or(false);

        registers
            .iter()
            .enumerate()
            .map(|(index, &register)| {
                let raw = self.read_banked(device, register)?;
                let volts = (raw > 0 && (index != vbat_index || vbat_enabled))
                    .then_some(raw as f32 * NCT67XX_VOLTAGE_STEP_V);
                let label = format!("VIN{index} (ADC pin)");
                Ok(VoltageReading {
                    chip: device.chip.name.clone(),
                    index,
                    label: qualify_label(&device.chip.name, &label, qualify),
                    volts,
                })
            })
            .collect()
    }

    fn read_nct67xx_temperatures(
        &self,
        device: &Device,
        qualify: bool,
    ) -> Result<Vec<BoardTemperatureReading>> {
        if device.chip.name == "NCT6701D" {
            const CHANNELS: [(&str, u16); 9] = [
                ("CPU socket", 0x491),
                ("system", 0x490),
                ("auxiliary 0", 0x492),
                ("auxiliary 1", 0x493),
                ("auxiliary 2", 0x494),
                ("auxiliary 3", 0x495),
                ("CPU package", 0x409),
                ("PCH", 0x401),
                ("DIMM 0", 0x405),
            ];
            return CHANNELS
                .iter()
                .enumerate()
                .map(|(index, &(label, register))| {
                    let raw = self.read_banked(device, register)?;
                    Ok(BoardTemperatureReading {
                        chip: device.chip.name.clone(),
                        index,
                        label: qualify_label(&device.chip.name, label, qualify),
                        temp_c: decode_nct6701_temperature(raw),
                    })
                })
                .collect();
        }

        let (channels, source_map): (&[BankedTemperatureChannel], TemperatureSourceMap) =
            match device.chip.name.as_str() {
                "NCT6771F" => (&NCT677X_TEMPERATURES, TemperatureSourceMap::Nct6771),
                "NCT6776F" => (&NCT677X_TEMPERATURES, TemperatureSourceMap::Nct6776),
                "NCT6779D" => (&NCT6779_TEMPERATURES, TemperatureSourceMap::Nct67xx),
                "NCT6791D" | "NCT6792D" | "NCT6792DA" | "NCT6793D" | "NCT6795D" | "NCT6796D"
                | "NCT6796D-R" | "NCT6797D" => {
                    (&NCT6791_TO_95_TEMPERATURES, TemperatureSourceMap::Nct67xx)
                }
                "NCT6798D" | "NCT6799D" => {
                    (&NCT6798_TO_99_TEMPERATURES, TemperatureSourceMap::Nct67xx)
                }
                _ => (&NCT6779_TEMPERATURES, TemperatureSourceMap::Nct67xx),
            };

        let mut seen_sources = Vec::new();
        let mut out = Vec::with_capacity(channels.len());
        for channel in channels {
            let source = channel
                .source_register
                .map(|register| self.read_banked(device, register).map(|v| v & 0x1F))
                .transpose()?;
            if let Some(source) = source
                && source != 0
                && seen_sources.contains(&source)
            {
                continue;
            }
            if let Some(source) = source
                && source != 0
            {
                seen_sources.push(source);
            }

            let whole = self.read_banked(device, channel.register)?;
            let half = channel
                .half
                .map(|(register, bit)| self.read_banked(device, register).map(|v| (v >> bit) & 1))
                .transpose()?
                .unwrap_or(0);
            let mut temp_c = decode_temperature(whole as i8 as f32 + 0.5 * half as f32);
            if temp_c.is_none()
                && let Some(alternate) = channel.alternate_register
            {
                temp_c = decode_temperature(self.read_banked(device, alternate)? as i8 as f32);
            }
            let label = source
                .and_then(|value| temperature_source_label(source_map, value))
                .unwrap_or(channel.fallback_label);
            out.push(BoardTemperatureReading {
                chip: device.chip.name.clone(),
                index: out.len(),
                label: qualify_label(&device.chip.name, label, qualify),
                temp_c,
            });
        }
        Ok(out)
    }

    /// Points the executor at this chip's slot and re-establishes which
    /// ports it may touch.
    ///
    /// Both steps are required every time, because `ioctl_select_slot`
    /// resets the module's record of the allowed base addresses — so
    /// reading from a second chip and then back from the first without
    /// repeating this would be refused.
    fn select(&self, device: &Device) -> Result<()> {
        if self.current_slot.get() == Some(device.slot) {
            return Ok(());
        }
        // Clear first: if anything below fails we must not leave a stale
        // slot recorded, or the next call would skip the re-selection and
        // read through whichever slot actually ended up selected.
        self.current_slot.set(None);

        self.io.execute("ioctl_select_slot", &[device.slot], 0)?;
        let config_port = device.chip.register_port as u64;
        enter_nuvoton_config(&self.io, config_port)?;
        let bars = self.io.execute("ioctl_find_bars", &[], 0);
        exit_nuvoton_config(&self.io, config_port)?;
        bars.context("enumerating Super I/O base addresses")?;

        self.current_slot.set(Some(device.slot));
        Ok(())
    }

    /// Ensures the NCT668x monitoring block and its voltage ADC routes are
    /// enabled. These are sensor-selection bits only; no rail or fan-control
    /// setting is changed.
    fn init_nct668x(&self, device: &Device) -> Result<()> {
        let data = self.read_ec(device, NCT668X_INIT_REGISTER)?;
        if data & 0x80 == 0 {
            log::info!("enabling the {} monitoring block", device.chip.name);
            self.write_ec(device, NCT668X_INIT_REGISTER, data | 0x80)?;
        }
        for &(register, expected) in &NCT668X_VOLTAGE_ENABLE {
            if self.read_ec(device, register)? != expected {
                self.write_ec(device, register, expected)?;
            }
        }
        Ok(())
    }

    /// Reads one byte from an NCT67xx banked register space.
    fn read_banked(&self, device: &Device, address: u16) -> Result<u8> {
        let bank = (address >> 8) as u64;
        let register = (address & 0xFF) as u64;
        let index_port = (device.hm_base + ADDRESS_REGISTER_OFFSET) as u64;
        let data_port = (device.hm_base + DATA_REGISTER_OFFSET) as u64;

        pio_outb(&self.io, index_port, BANK_SELECT_REGISTER)?;
        pio_outb(&self.io, data_port, bank)?;
        pio_outb(&self.io, index_port, register)?;
        pio_inb(&self.io, data_port)
    }

    /// Reads one byte from an NCT668x paged EC space.
    ///
    /// The page register doubles as a lock: the EC parks it at
    /// [`EC_PAGE_SELECT`] when idle, so a caller waits for that value,
    /// claims the space by writing its page, reads, and parks it again on
    /// the way out. This handshake is with the EC's own firmware, and is
    /// separate from the machine-wide [`IsaLock`], which arbitrates
    /// between *applications*.
    fn read_ec(&self, device: &Device, address: u16) -> Result<u8> {
        self.claim_ec(device)?;
        let page_port = (device.hm_base + EC_PAGE_REGISTER_OFFSET) as u64;
        let index_port = (device.hm_base + EC_INDEX_REGISTER_OFFSET) as u64;
        let data_port = (device.hm_base + EC_DATA_REGISTER_OFFSET) as u64;

        pio_outb(&self.io, page_port, (address >> 8) as u64)?;
        pio_outb(&self.io, index_port, (address & 0xFF) as u64)?;
        let value = pio_inb(&self.io, data_port)?;
        // Release even if the caller is about to read again: leaving the
        // page register claimed would block the EC's own firmware.
        pio_outb(&self.io, page_port, EC_PAGE_SELECT as u64)?;
        Ok(value)
    }

    fn write_ec(&self, device: &Device, address: u16, value: u8) -> Result<()> {
        self.claim_ec(device)?;
        let page_port = (device.hm_base + EC_PAGE_REGISTER_OFFSET) as u64;
        let index_port = (device.hm_base + EC_INDEX_REGISTER_OFFSET) as u64;
        let data_port = (device.hm_base + EC_DATA_REGISTER_OFFSET) as u64;

        pio_outb(&self.io, page_port, (address >> 8) as u64)?;
        pio_outb(&self.io, index_port, (address & 0xFF) as u64)?;
        pio_outb(&self.io, data_port, value as u64)?;
        pio_outb(&self.io, page_port, EC_PAGE_SELECT as u64)?;
        Ok(())
    }

    /// Waits for the EC to park its page register, then forces access if
    /// it never does.
    fn claim_ec(&self, device: &Device) -> Result<()> {
        let page_port = (device.hm_base + EC_PAGE_REGISTER_OFFSET) as u64;
        let deadline = Instant::now() + EC_ACCESS_TIMEOUT;
        loop {
            if pio_inb(&self.io, page_port)? == EC_PAGE_SELECT {
                return Ok(());
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        log::debug!("{} EC space busy; forcing access", device.chip.name);
        pio_outb(&self.io, page_port, EC_PAGE_SELECT as u64)
    }

    /// Raw register bytes for every chip, for diagnosing readings that
    /// decode to nonsense.
    pub fn raw_dump(&self) -> Vec<RawDump> {
        self.devices
            .iter()
            .map(|d| {
                let mut dump = RawDump {
                    chip: d.chip.name.clone(),
                    family: d.chip.family,
                    hm_base: d.hm_base,
                    vendor_id: None,
                    registers: Vec::new(),
                    error: None,
                };
                if let Err(e) = self.fill_dump(d, &mut dump) {
                    dump.error = Some(format!("{e:#}"));
                }
                dump
            })
            .collect()
    }

    fn fill_dump(&self, device: &Device, dump: &mut RawDump) -> Result<()> {
        let _lock = IsaLock::acquire()?;
        self.select(device)?;
        match device.chip.family {
            Family::NuvotonNct67xx => {
                let high = self.read_banked(device, VENDOR_ID_HIGH_REGISTER)?;
                let low = self.read_banked(device, VENDOR_ID_LOW_REGISTER)?;
                dump.vendor_id = Some(((high as u16) << 8) | low as u16);
                for &reg in &NCT67XX_FAN_COUNT_REGISTERS {
                    dump.registers.push((
                        reg,
                        self.read_banked(device, reg)?,
                        self.read_banked(device, reg + 1)?,
                    ));
                }
            }
            Family::NuvotonNct668x => {
                for &reg in &NCT668X_FAN_RPM_REGISTERS {
                    dump.registers.push((
                        reg,
                        self.read_ec(device, reg)?,
                        self.read_ec(device, reg + 1)?,
                    ));
                }
            }
            Family::IteIt87xx => {}
        }
        Ok(())
    }
}

/// Raw Super I/O register bytes for one chip. See [`SuperIo::raw_dump`].
#[derive(Debug, Clone)]
pub struct RawDump {
    pub chip: String,
    pub family: Family,
    pub hm_base: u16,
    /// Only meaningful on the banked family; should be
    /// [`NUVOTON_VENDOR_ID`].
    pub vendor_id: Option<u16>,
    /// `(register, high byte, low byte)` for each fan register.
    pub registers: Vec<(u16, u8, u8)>,
    pub error: Option<String>,
}

impl RawDump {
    pub fn vendor_id_ok(&self) -> bool {
        self.vendor_id == Some(NUVOTON_VENDOR_ID)
    }
}

/// What one configuration port answered with, before interpretation.
///
/// Reported separately from [`Chip`] so an unrecognised chip is visible as
/// its raw ID rather than as silence — a board whose sensors live on a part
/// missing from [`identify_nuvoton`]'s table looks identical to a board
/// with no Super I/O at all unless the raw bytes are shown. That is exactly
/// how the NCT6686D support below came to be written.
#[derive(Debug, Clone)]
pub struct SlotProbe {
    pub register_port: u16,
    pub id: u8,
    pub revision: u8,
    pub recognised: Option<String>,
}

/// Knocks on both configuration ports and reports what each answered,
/// recognised or not.
pub fn probe_slots() -> std::result::Result<Vec<SlotProbe>, Availability> {
    let io = PawnIo::load(Module::LpcIo)?;
    probe_slots_with(&io).map_err(|e| Availability::Failed(format!("{e:#}")))
}

fn probe_slots_with(io: &PawnIo) -> Result<Vec<SlotProbe>> {
    let _lock = IsaLock::acquire()?;
    let mut probes = Vec::new();
    for (slot, &register_port) in REGISTER_PORTS.iter().enumerate() {
        io.execute("ioctl_select_slot", &[slot as u64], 0)?;
        let port = register_port as u64;
        enter_nuvoton_config(io, port)?;
        let id = superio_inb(io, CHIP_ID_REGISTER)?;
        let revision = superio_inb(io, CHIP_REVISION_REGISTER)?;
        exit_nuvoton_config(io, port)?;
        probes.push(SlotProbe {
            register_port,
            id,
            revision,
            recognised: identify_nuvoton(id, revision, register_port).map(|c| c.name),
        });
    }
    Ok(probes)
}

/// Converts a 13-bit fan period counter to RPM.
///
/// A saturated counter means "no fan on this channel", which is a perfectly
/// ordinary state on a board with more headers than fans, so it maps to
/// `None` rather than to zero.
fn counter_to_rpm(high: u8, low: u8) -> Option<u32> {
    let count = ((high as u32) << 5) | (low as u32 & 0x1F);
    (MIN_FAN_COUNT..MAX_FAN_COUNT)
        .contains(&count)
        .then(|| (FAN_CLOCK / count as f32).round() as u32)
}

/// Interprets an NCT668x direct 16-bit RPM register pair.
///
/// Zero is an empty header, and an implausibly large value is a register
/// that isn't a tachometer at all rather than a fan running at 60,000 RPM.
fn direct_rpm(high: u8, low: u8) -> Option<u32> {
    let rpm = ((high as u32) << 8) | low as u32;
    (rpm > 0 && rpm <= MAX_PLAUSIBLE_RPM).then_some(rpm)
}

fn decode_nct668x_voltage(index: usize, high: u8, low: u8) -> Option<f32> {
    let millivolts = 16 * high as u16 + (low >> 4) as u16;
    let value = millivolts as f32 * 0.001 * NCT668X_VOLTAGE_FACTORS[index];
    (millivolts > 0 && value <= 20.0).then_some(value)
}

fn decode_temperature(temp_c: f32) -> Option<f32> {
    (MIN_BOARD_TEMP_C..=MAX_BOARD_TEMP_C)
        .contains(&temp_c)
        .then_some(temp_c)
}

/// NCT6701 uses whole signed degrees and reserves a few byte patterns for
/// disconnected/disabled inputs.
fn decode_nct6701_temperature(raw: u8) -> Option<f32> {
    if raw == 0x00 || raw == 0xA0 || (0x7E..=0x80).contains(&raw) {
        None
    } else {
        decode_temperature(raw as i8 as f32)
    }
}

fn qualify_label(chip: &str, label: &str, qualify: bool) -> String {
    if qualify {
        format!("{chip} {label}")
    } else {
        label.to_string()
    }
}

fn temperature_source_label(map: TemperatureSourceMap, source: u8) -> Option<&'static str> {
    match map {
        TemperatureSourceMap::Nct6771 => match source {
            1 => Some("system"),
            2 => Some("CPU socket"),
            3 => Some("auxiliary"),
            5 => Some("CPU (PECI)"),
            _ => None,
        },
        TemperatureSourceMap::Nct6776 => match source {
            1 => Some("system"),
            2 => Some("CPU socket"),
            3 => Some("auxiliary"),
            12 => Some("CPU (PECI)"),
            _ => None,
        },
        TemperatureSourceMap::Nct67xx => match source {
            1 => Some("system"),
            2 => Some("CPU socket"),
            3 => Some("auxiliary 0"),
            4 => Some("auxiliary 1"),
            5 => Some("auxiliary 2"),
            6 => Some("auxiliary 3"),
            7 => Some("auxiliary 4"),
            8 => Some("SMBus temperature 0"),
            9 => Some("SMBus temperature 1"),
            10 => Some("thermistor"),
            16 => Some("CPU (PECI)"),
            17 => Some("CPU 2 (PECI)"),
            18 => Some("PCH/CPU maximum"),
            19 => Some("PCH"),
            20 => Some("PCH CPU"),
            21 => Some("PCH memory controller"),
            22 => Some("DIMM agent 0 channel 0"),
            23 => Some("DIMM agent 0 channel 1"),
            24 => Some("DIMM agent 1 channel 0"),
            25 => Some("DIMM agent 1 channel 1"),
            26 => Some("byte temperature 0"),
            27 => Some("byte temperature 1"),
            28 => Some("CPU PECI calibrated"),
            29 => Some("CPU 2 PECI calibrated"),
            31 => Some("virtual temperature"),
            _ => None,
        },
    }
}

fn detect_with(io: PawnIo) -> Result<SuperIo> {
    let _lock = IsaLock::acquire()?;
    let mut devices = Vec::new();

    for (slot, &register_port) in REGISTER_PORTS.iter().enumerate() {
        let slot = slot as u64;
        io.execute("ioctl_select_slot", &[slot], 0)
            .with_context(|| format!("selecting Super I/O slot {slot}"))?;

        let port = register_port as u64;
        enter_nuvoton_config(&io, port)?;
        let id = superio_inb(&io, CHIP_ID_REGISTER)?;
        let revision = superio_inb(&io, CHIP_REVISION_REGISTER)?;

        if let Some(chip) = identify_nuvoton(id, revision, register_port) {
            match map_nuvoton_hm(&io, port, chip.family) {
                Ok(hm_base) => devices.push(Device {
                    chip,
                    slot,
                    hm_base,
                    // Assumed live so the first refresh reads every chip;
                    // the first result replaces the guess with a fact.
                    has_live_fans: Cell::new(true),
                    last: RefCell::new(Vec::new()),
                }),
                Err(e) => log::info!("{} found but not mappable: {e:#}", chip.name),
            }
            continue;
        }

        exit_nuvoton_config(&io, port)?;
        if let Some(chip) = probe_ite(&io, register_port)? {
            devices.push(Device {
                chip,
                slot,
                hm_base: 0,
                has_live_fans: Cell::new(false),
                last: RefCell::new(Vec::new()),
            });
        }
    }

    if devices.is_empty() {
        return Err(anyhow!("no Super I/O chip responded on port 0x2E or 0x4E"));
    }
    // Detection left the last probed slot selected, but its base addresses
    // were discovered under a different selection, so nothing is cached.
    Ok(SuperIo {
        io,
        devices,
        current_slot: Cell::new(None),
        read_count: Cell::new(0),
    })
}

/// Finds the hardware-monitor block's base address and leaves configuration
/// mode.
fn map_nuvoton_hm(io: &PawnIo, config_port: u64, family: Family) -> Result<u16> {
    // Must happen before selecting our logical device: finding the base
    // address registers walks every logical device, so it clobbers the
    // current selection.
    io.execute("ioctl_find_bars", &[], 0)
        .context("enumerating Super I/O base addresses")?;

    superio_outb(io, DEVICE_SELECT_REGISTER, NUVOTON_HM_LDN)?;
    let address = superio_inw(io, BASE_ADDRESS_REGISTER)?;
    // Read twice: an address that changes between reads means the chip is
    // not actually answering and we are looking at bus noise.
    std::thread::sleep(Duration::from_millis(1));
    let verify = superio_inw(io, BASE_ADDRESS_REGISTER)?;
    if address != verify {
        exit_nuvoton_config(io, config_port)?;
        bail!("hardware monitor address did not verify ({address:#06x} vs {verify:#06x})");
    }

    // Some parts report the address with the register offset already folded
    // in. Left uncorrected, every subsequent read lands five bytes past the
    // index port and returns 0xFF — which decodes to a saturated fan
    // counter, i.e. a chip that looks present and reports every channel as
    // empty.
    let address = if address & 0x07 == 0x05 {
        address & 0xFFF8
    } else {
        address
    };
    if address < 0x100 || address == 0xFFFF {
        exit_nuvoton_config(io, config_port)?;
        bail!("implausible hardware monitor address {address:#06x}");
    }

    // Some boards ship with the hardware-monitor I/O window locked, in
    // which case every register read returns 0xFF. Clearing the lock bit is
    // what makes the block readable at all; it is a configuration bit only,
    // and does not change any fan or voltage setting. The NCT668x parts
    // have no such lock.
    if family == Family::NuvotonNct67xx {
        let options = superio_inb(io, NUVOTON_IO_SPACE_LOCK)?;
        if options & 0x10 != 0 {
            superio_outb(io, NUVOTON_IO_SPACE_LOCK, (options & !0x10) as u64)?;
        }
    }

    exit_nuvoton_config(io, config_port)?;
    Ok(address)
}

/// Identifies a chip from the ID/revision pair, following the same table
/// LibreHardwareMonitor uses. The ID byte selects a group and the revision
/// distinguishes members within it.
fn identify_nuvoton(id: u8, revision: u8, register_port: u16) -> Option<Chip> {
    // (name, family, tachometer channels)
    let (name, family, fan_count) = match (id, revision) {
        (0xB4, r) if r & 0xF0 == 0x70 => ("NCT6771F", Family::NuvotonNct67xx, 5),
        (0xC3, r) if r & 0xF0 == 0x30 => ("NCT6776F", Family::NuvotonNct67xx, 5),
        (0xC5, r) if r & 0xF0 == 0x60 => ("NCT6779D", Family::NuvotonNct67xx, 5),
        (0xC7, 0x32) => ("NCT6683D", Family::NuvotonNct668x, 17),
        (0xC8, 0x03) => ("NCT6791D", Family::NuvotonNct67xx, 6),
        (0xC9, 0x11) => ("NCT6792D", Family::NuvotonNct67xx, 6),
        (0xC9, 0x13) => ("NCT6792DA", Family::NuvotonNct67xx, 6),
        (0xD1, 0x21) => ("NCT6793D", Family::NuvotonNct67xx, 6),
        (0xD3, 0x52) => ("NCT6795D", Family::NuvotonNct67xx, 6),
        (0xD4, 0x23) => ("NCT6796D", Family::NuvotonNct67xx, 6),
        (0xD4, 0x2A) => ("NCT6796D-R", Family::NuvotonNct67xx, 7),
        (0xD4, 0x2B) => ("NCT6798D", Family::NuvotonNct67xx, 7),
        (0xD4, 0x51) => ("NCT6797D", Family::NuvotonNct67xx, 7),
        (0xD8, 0x02) => ("NCT6799D", Family::NuvotonNct67xx, 7),
        (0xD8, 0x06) => ("NCT6701D", Family::NuvotonNct67xx, 7),
        // The EC-style parts, used on MSI boards. All share the same fan
        // register addresses; only which physical header each index maps to
        // differs by board, which is why the labels stay generic.
        (0xD4, 0x40 | 0x41) => ("NCT6686D", Family::NuvotonNct668x, 17),
        (0xD5, 0x92) => ("NCT6687D", Family::NuvotonNct668x, 17),
        _ => return None,
    };
    Some(Chip {
        name: name.to_string(),
        family,
        id,
        revision,
        fan_count,
        register_port,
    })
}

/// Knocks with ITE's unlock sequence purely to *name* the chip. Its fan
/// registers are not read — see the module docs.
fn probe_ite(io: &PawnIo, register_port: u16) -> Result<Option<Chip>> {
    let port = register_port as u64;
    pio_outb(io, port, 0x87)?;
    pio_outb(io, port, 0x01)?;
    pio_outb(io, port, 0x55)?;
    pio_outb(io, port, if register_port == 0x4E { 0xAA } else { 0x55 })?;

    let id = superio_inw(io, CHIP_ID_REGISTER)?;
    if id == 0 || id == 0xFFFF || id >> 8 != 0x86 {
        return Ok(None);
    }
    let revision = superio_inb(io, CHIP_REVISION_REGISTER)?;
    Ok(Some(Chip {
        name: format!("IT{id:04X}"),
        family: Family::IteIt87xx,
        id: (id >> 8) as u8,
        revision,
        fan_count: 0,
        register_port,
    }))
}

/// Winbond/Nuvoton/Fintek unlock: the magic byte twice on the index port.
fn enter_nuvoton_config(io: &PawnIo, config_port: u64) -> Result<()> {
    pio_outb(io, config_port, 0x87)?;
    pio_outb(io, config_port, 0x87)
}

fn exit_nuvoton_config(io: &PawnIo, config_port: u64) -> Result<()> {
    pio_outb(io, config_port, 0xAA)
}

fn pio_inb(io: &PawnIo, port: u64) -> Result<u8> {
    Ok(io.execute1("ioctl_pio_inb", port)? as u8)
}

fn pio_outb(io: &PawnIo, port: u64, value: u64) -> Result<()> {
    io.execute("ioctl_pio_outb", &[port, value], 0)?;
    Ok(())
}

fn superio_inb(io: &PawnIo, register: u64) -> Result<u8> {
    Ok(io.execute1("ioctl_superio_inb", register)? as u8)
}

fn superio_inw(io: &PawnIo, register: u64) -> Result<u16> {
    Ok(io.execute1("ioctl_superio_inw", register)? as u16)
}

fn superio_outb(io: &PawnIo, register: u64, value: u64) -> Result<()> {
    io.execute("ioctl_superio_outb", &[register, value], 0)?;
    Ok(())
}

/// The cross-application lock for legacy ISA/LPC port access.
///
/// `Access_ISABUS.HTP.Method` is a convention, not an OS mechanism:
/// hardware monitoring tools (HWiNFO, LibreHardwareMonitor, AIDA64, vendor
/// utilities) all agree to hold this named mutex while driving index/data
/// port pairs. Nothing enforces it, but everything that matters on a
/// typical machine honours it, and without it two tools interleaving their
/// index writes read each other's registers.
///
/// Failing to acquire is not an error worth surfacing — it means someone
/// else is mid-read — so callers skip the tick.
struct IsaLock {
    handle: HANDLE,
    /// False when the wait returned `WAIT_ABANDONED`: we own it, but the
    /// previous holder died mid-sequence, so the chip may be left with a
    /// stale index selected.
    clean: bool,
}

impl IsaLock {
    fn acquire() -> Result<Self> {
        let name = w!("Global\\Access_ISABUS.HTP.Method");
        // Prefer joining an existing mutex; create one only if we are the
        // first tool on the machine to want it.
        let handle = unsafe { OpenMutexW(SYNCHRONIZATION_SYNCHRONIZE, false, name) }
            .or_else(|_| unsafe { CreateMutexW(None, false, name) })
            .context("opening the shared ISA bus mutex")?;

        let wait = unsafe { WaitForSingleObject(handle, ISA_LOCK_TIMEOUT.as_millis() as u32) };
        match wait {
            WAIT_OBJECT_0 => Ok(Self {
                handle,
                clean: true,
            }),
            WAIT_ABANDONED => Ok(Self {
                handle,
                clean: false,
            }),
            _ => {
                unsafe { CloseHandle(handle) }.ok();
                bail!("another tool is holding the ISA bus; skipping this read")
            }
        }
    }
}

impl Drop for IsaLock {
    fn drop(&mut self) {
        if !self.clean {
            log::debug!("ISA bus mutex was abandoned by its previous holder");
        }
        unsafe {
            ReleaseMutex(self.handle).ok();
            CloseHandle(self.handle).ok();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 1.35e6 / 1500 = 900 RPM, encoded as a 13-bit count split across the
    /// register pair.
    #[test]
    fn counter_converts_to_rpm() {
        let count: u32 = 1500;
        assert_eq!(
            counter_to_rpm((count >> 5) as u8, (count & 0x1F) as u8),
            Some(900)
        );
    }

    /// A saturated counter is an empty header, not a 0 RPM fan — the
    /// distinction matters, since "0 RPM" on a CPU header would be an
    /// emergency and an unused chassis header is not.
    #[test]
    fn saturated_counter_reports_no_fan() {
        assert_eq!(counter_to_rpm(0xFF, 0xFF), None);
        // The exact bytes this machine's empty NCT6796D-R channels return.
        assert_eq!(counter_to_rpm(0xFF, 0x1F), None);
    }

    #[test]
    fn implausibly_small_counter_is_rejected() {
        assert_eq!(counter_to_rpm(0, 0x10), None);
    }

    #[test]
    fn direct_rpm_reads_big_endian_pairs() {
        assert_eq!(direct_rpm(0x04, 0xD2), Some(1234));
    }

    /// Zero is an unused header; a wild value is a register that is not a
    /// tachometer, not a fan at 60,000 RPM.
    #[test]
    fn direct_rpm_rejects_zero_and_nonsense() {
        assert_eq!(direct_rpm(0x00, 0x00), None);
        assert_eq!(direct_rpm(0xFF, 0xFF), None);
    }

    #[test]
    fn nct668x_voltage_uses_high_byte_and_high_nibble() {
        // 0x064 = 100 mV at the ADC. VIN0's fixed x12 scale makes 1.2 V.
        let value = decode_nct668x_voltage(0, 0x06, 0x40).unwrap();
        assert!((value - 1.2).abs() < 0.001, "got {value}");
        assert_eq!(decode_nct668x_voltage(2, 0, 0), None);
    }

    #[test]
    fn invalid_board_temperatures_stay_unknown() {
        assert_eq!(decode_temperature(30.5), Some(30.5));
        assert_eq!(decode_temperature(126.0), None);
        assert_eq!(decode_nct6701_temperature(0), None);
        assert_eq!(decode_nct6701_temperature(42), Some(42.0));
    }

    /// The regression behind this whole family being added: the chip that
    /// owns the fans on the development machine sits at 0x2E behind an
    /// ID/revision pair the first version of this table did not list, so
    /// detection settled for a working-but-empty chip at 0x4E.
    #[test]
    fn nct668x_parts_are_recognised_as_ec_parts() {
        let nct6683 = identify_nuvoton(0xC7, 0x32, 0x2E).expect("NCT6683D should be known");
        assert_eq!(nct6683.name, "NCT6683D");
        assert_eq!(nct6683.family, Family::NuvotonNct668x);

        for rev in [0x40, 0x41] {
            let chip = identify_nuvoton(0xD4, rev, 0x2E).expect("NCT6686D should be known");
            assert_eq!(chip.name, "NCT6686D");
            assert_eq!(chip.family, Family::NuvotonNct668x);
            assert!(chip.family.fans_supported());
        }
    }

    #[test]
    fn known_chips_identify_and_unknown_ones_do_not() {
        let chip = identify_nuvoton(0xD4, 0x2B, 0x2E).expect("NCT6798D should be known");
        assert_eq!(chip.name, "NCT6798D");
        assert_eq!(chip.fan_count, 7);
        assert!(identify_nuvoton(0x00, 0x00, 0x2E).is_none());
        assert!(identify_nuvoton(0xFF, 0xFF, 0x2E).is_none());
    }

    /// Every decoded chip's channel count must fit its family's register
    /// table, or `read_fans` would index out of bounds.
    #[test]
    fn fan_counts_fit_their_register_tables() {
        for id in 0u8..=255 {
            for rev in 0u8..=255 {
                let Some(chip) = identify_nuvoton(id, rev, 0x2E) else {
                    continue;
                };
                let limit = match chip.family {
                    Family::NuvotonNct67xx => NCT67XX_FAN_COUNT_REGISTERS.len(),
                    Family::NuvotonNct668x => NCT668X_FAN_RPM_REGISTERS.len(),
                    Family::IteIt87xx => 0,
                };
                assert!(
                    chip.fan_count <= limit,
                    "{} claims {} fans, table holds {limit}",
                    chip.name,
                    chip.fan_count
                );
            }
        }
    }
}
