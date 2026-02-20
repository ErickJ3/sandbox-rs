//! Monitoring layer: Process and syscall monitoring
//!
//! Provides real-time monitoring of sandboxed processes,
//! including resource usage tracking via /proc and syscall tracing via eBPF.

pub mod ebpf;
pub mod monitor;

pub use ebpf::EBpfMonitor;
pub use monitor::{ProcessMonitor, ProcessState, ProcessStats};
