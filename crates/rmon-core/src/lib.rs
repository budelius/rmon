//! Core sampling, storage, and data model for rMon: a process explorer that
//! tracks per-process CPU and GPU usage over time.

mod cpu;
mod gpu;
mod handles;
mod history;
mod model;
pub mod observability;
mod sampler;
mod storage;
mod thermal;
mod tree;

pub use handles::{list_open_files, OpenFilesScan};
pub use history::RollingHistory;
pub use model::{GpuSource, GpuTelemetry, ProcessSample, Snapshot, SystemMetrics};
pub use sampler::Sampler;
pub use storage::Store;
pub use tree::build_tree;
