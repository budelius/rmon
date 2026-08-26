//! Core sampling, storage, and data model for rMon: a process explorer that
//! tracks per-process CPU and GPU usage over time.

pub mod config;
mod cpu;
pub mod elevate;
mod gpu;
mod handles;
mod health;
mod history;
mod hwinfo;
mod model;
pub mod observability;
pub mod pawnio;
mod ports;
mod proc_events;
mod sampler;
pub mod sensors;
mod storage;
mod thermal;
pub mod throttle;
mod tree;
pub mod trends;

pub use handles::{
    AllFilesEntry, DEFAULT_SCAN_WORKERS, OpenFilesScan, handle_count, kill_process,
    list_open_files, list_open_files_many,
};
pub use health::{
    DEFAULT_WHEA_LOOKBACK_DAYS, DEFAULT_WHEA_MAX_EVENTS, HardwareHealthReport, WheaEvent,
    check_hardware_health,
};
pub use history::RollingHistory;
pub use hwinfo::{SensorGroup, SensorReading, read_all_sensors, read_cpu_temp, read_cpu_thermal};
pub use model::{
    BoardTemperatureSample, FanSample, GpuSource, GpuTelemetry, ProcessSample, Snapshot,
    SystemMetrics, VoltageSample,
};
pub use ports::{PortEntry, Protocol, TcpState, list_all_ports, listening_ports_for};
pub use proc_events::{RecentExit, ShortLivedWatcher};
pub use sampler::Sampler;
pub use sensors::{
    BoardTemperatureReading, Chip as SuperIoChip, FanReading, PackageThermal, SensorHub,
    SuperIoReadings, VoltageReading,
};
pub use storage::Store;
pub use throttle::{THROTTLE_WINDOW, ThrottleHistory, ThrottleTick};
pub use tree::{DEFAULT_GHOST_MAX_DEPTH, build_tree, merge_recent_exits};
