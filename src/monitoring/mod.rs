//! Monitoring layer: Process and syscall monitoring
//!
//! This module provides real-time monitoring of sandboxed processes,
//! including resource usage tracking via /proc and syscall tracing via eBPF.
//!
//! # Features
//!
//! - **/proc-based monitoring**: Track memory, CPU, and process state
//! - **eBPF syscall tracing**: Event-driven syscall monitoring
//! - **Performance metrics**: Detect slow operations (>10ms)
//! - **Resource statistics**: Peak memory, CPU time, thread count
//! - **Graceful shutdown**: SIGTERM → SIGKILL progression
//!
//! # Examples
//!
//! ```ignore
//! use sandbox_rs::monitoring::ProcessMonitor;
//!
//! let monitor = ProcessMonitor::new(pid)?;
//! let stats = monitor.collect_stats()?;
//! println!("Memory: {}MB", stats.memory_usage_mb);
//! println!("CPU time: {}ms", stats.cpu_time_ms);
//! ```

pub mod ebpf;
pub mod monitor;
pub use ebpf::EBpfMonitor;
pub use monitor::{ProcessMonitor, ProcessState, ProcessStats};

#[cfg(test)]
mod tests;
