//! Core sampling, storage, and data model for rMon: a process explorer that
//! tracks per-process CPU and GPU usage over time.

mod cpu;
pub mod elevate;
mod gpu;
mod handles;
mod health;
mod history;
mod hwinfo;
mod model;
pub mod observability;
mod ports;
mod proc_events;
mod sampler;
mod storage;
mod thermal;
mod tree;

pub use handles::{
    handle_count, kill_process, list_open_files, list_open_files_many, AllFilesEntry,
    OpenFilesScan, DEFAULT_SCAN_WORKERS,
};
pub use health::{
    check_hardware_health, HardwareHealthReport, WheaEvent, DEFAULT_WHEA_LOOKBACK_DAYS,
    DEFAULT_WHEA_MAX_EVENTS,
};
pub use history::RollingHistory;
pub use hwinfo::{read_all_sensors, SensorGroup, SensorReading};
pub use model::{GpuSource, GpuTelemetry, ProcessSample, Snapshot, SystemMetrics};
pub use ports::{list_all_ports, listening_ports_for, PortEntry, Protocol, TcpState};
pub use proc_events::{RecentExit, ShortLivedWatcher};
pub use sampler::Sampler;
pub use storage::Store;
pub use tree::build_tree;
