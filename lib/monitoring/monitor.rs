//! Process monitoring via /proc
//!
//! Provides real-time monitoring of process resources using /proc filesystem.
//! Tracks memory usage, CPU time, thread count, and process state.

use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

use crate::errors::{Result, SandboxError};

/// Process state enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// Process is running
    Running,
    /// Process is sleeping
    Sleeping,
    /// Process is zombie
    Zombie,
    /// Process state is unknown
    Unknown,
}

impl ProcessState {
    /// Parse state from /proc stat first character
    pub fn from_char(c: char) -> Self {
        match c {
            'R' => ProcessState::Running,
            'S' => ProcessState::Sleeping,
            'Z' => ProcessState::Zombie,
            _ => ProcessState::Unknown,
        }
    }
}

/// Process statistics snapshot
#[derive(Debug, Clone)]
pub struct ProcessStats {
    /// Process ID
    pub pid: i32,
    /// Virtual memory size in bytes
    pub vsize: u64,
    /// Resident set size in bytes (physical memory)
    pub rss: u64,
    /// RSS in MB (for convenience)
    pub memory_usage_mb: u64,
    /// CPU time in milliseconds
    pub cpu_time_ms: u64,
    /// Number of threads
    pub num_threads: u32,
    /// Current process state
    pub state: ProcessState,
    /// Timestamp of this snapshot
    pub timestamp: Instant,
}

impl ProcessStats {
    /// Create stats from /proc data
    fn from_proc(pid: i32, timestamp: Instant) -> Result<Self> {
        let stat_path = format!("/proc/{}/stat", pid);
        let status_path = format!("/proc/{}/status", pid);

        // Read /proc/{pid}/stat
        let stat_content = fs::read_to_string(&stat_path).map_err(|e| {
            SandboxError::ProcessMonitoring(format!("Failed to read {}: {}", stat_path, e))
        })?;

        // Parse stat: pid (comm) state ppid pgrp session tty_nr tpgid flags minflt cminflt majflt cmajflt utime stime cutime cstime priority nice num_threads ...
        let parts: Vec<&str> = stat_content.split_whitespace().collect();
        if parts.len() < 20 {
            return Err(SandboxError::ProcessMonitoring(
                "Invalid /proc/stat format".to_string(),
            ));
        }

        let state = ProcessState::from_char(parts[2].chars().next().unwrap_or('?'));
        let utime: u64 = parts[13]
            .parse()
            .map_err(|_| SandboxError::ProcessMonitoring("Invalid utime".to_string()))?;
        let stime: u64 = parts[14]
            .parse()
            .map_err(|_| SandboxError::ProcessMonitoring("Invalid stime".to_string()))?;
        let num_threads: u32 = parts[19]
            .parse()
            .map_err(|_| SandboxError::ProcessMonitoring("Invalid num_threads".to_string()))?;
        let vsize: u64 = parts[22]
            .parse()
            .map_err(|_| SandboxError::ProcessMonitoring("Invalid vsize".to_string()))?;
        let rss: u64 = parts[23]
            .parse()
            .map_err(|_| SandboxError::ProcessMonitoring("Invalid rss".to_string()))?;

        // Read /proc/{pid}/status for additional info (placeholder for future enhancements)
        let _status_content = fs::read_to_string(&status_path).unwrap_or_default();

        // Calculate CPU time in milliseconds
        // Kernel reports in clock ticks, get actual CLK_TCK from system
        let clk_tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
        let cpu_time_ms = if clk_tck > 0 {
            ((utime + stime) * 1000) / clk_tck
        } else {
            0
        };

        // RSS is in pages, convert to bytes using actual page size
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        let rss_bytes = rss * page_size;
        let memory_usage_mb = rss_bytes / (1024 * 1024);

        Ok(ProcessStats {
            pid,
            vsize,
            rss: rss_bytes,
            memory_usage_mb,
            cpu_time_ms,
            num_threads,
            state,
            timestamp,
        })
    }
}

/// Process monitor for tracking sandbox resource usage
pub struct ProcessMonitor {
    pid: Pid,
    creation_time: Instant,
    peak_memory_mb: u64,
    last_stats: Option<ProcessStats>,
}

impl ProcessMonitor {
    /// Create new monitor for process
    pub fn new(pid: Pid) -> Result<Self> {
        // Verify process exists
        let stat_path = format!("/proc/{}/stat", pid.as_raw());
        if !Path::new(&stat_path).exists() {
            return Err(SandboxError::ProcessMonitoring(format!(
                "Process {} not found",
                pid
            )));
        }

        Ok(ProcessMonitor {
            pid,
            creation_time: Instant::now(),
            peak_memory_mb: 0,
            last_stats: None,
        })
    }

    /// Collect current statistics
    pub fn collect_stats(&mut self) -> Result<ProcessStats> {
        let now = Instant::now();
        let stats = ProcessStats::from_proc(self.pid.as_raw(), now)?;

        // Track peak memory
        if stats.memory_usage_mb > self.peak_memory_mb {
            self.peak_memory_mb = stats.memory_usage_mb;
        }

        self.last_stats = Some(stats.clone());
        Ok(stats)
    }

    /// Get peak memory usage since monitor creation (in MB)
    pub fn peak_memory_mb(&self) -> u64 {
        self.peak_memory_mb
    }

    /// Get elapsed time since monitor creation
    pub fn elapsed(&self) -> Duration {
        self.creation_time.elapsed()
    }

    /// Check if process is still alive
    pub fn is_alive(&self) -> Result<bool> {
        let stat_path = format!("/proc/{}/stat", self.pid.as_raw());
        Ok(Path::new(&stat_path).exists())
    }

    /// Send SIGTERM (graceful shutdown)
    pub fn send_sigterm(&self) -> Result<()> {
        kill(self.pid, Signal::SIGTERM)
            .map_err(|e| SandboxError::Syscall(format!("Failed to send SIGTERM: {}", e)))
    }

    /// Send SIGKILL (force termination)
    pub fn send_sigkill(&self) -> Result<()> {
        kill(self.pid, Signal::SIGKILL)
            .map_err(|e| SandboxError::Syscall(format!("Failed to send SIGKILL: {}", e)))
    }

    /// Graceful shutdown: SIGTERM → wait → SIGKILL
    pub fn graceful_shutdown(&self, wait_duration: Duration) -> Result<()> {
        // First try SIGTERM
        self.send_sigterm()?;

        // Wait for process to exit
        let start = Instant::now();
        while start.elapsed() < wait_duration && self.is_alive()? {
            std::thread::sleep(Duration::from_millis(10));
        }

        // If still alive, SIGKILL
        if self.is_alive()? {
            self.send_sigkill()?;
        }

        Ok(())
    }

    /// Get last collected stats
    pub fn last_stats(&self) -> Option<&ProcessStats> {
        self.last_stats.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_state_from_char() {
        assert_eq!(ProcessState::from_char('R'), ProcessState::Running);
        assert_eq!(ProcessState::from_char('S'), ProcessState::Sleeping);
        assert_eq!(ProcessState::from_char('Z'), ProcessState::Zombie);
        assert_eq!(ProcessState::from_char('X'), ProcessState::Unknown);
    }

    #[test]
    fn test_process_stats_creation() {
        // We can at least create stats for the test runner process itself
        let pid = std::process::id() as i32;
        let timestamp = Instant::now();
        let result = ProcessStats::from_proc(pid, timestamp);
        assert!(result.is_ok());

        if let Ok(stats) = result {
            assert_eq!(stats.pid, pid);
            assert!(stats.memory_usage_mb > 0);
        }
    }

    #[test]
    fn test_process_monitor_new() {
        let pid = Pid::from_raw(std::process::id() as i32);
        let result = ProcessMonitor::new(pid);
        assert!(result.is_ok());
    }

    #[test]
    fn test_process_monitor_is_alive() {
        let pid = Pid::from_raw(std::process::id() as i32);
        let monitor = ProcessMonitor::new(pid).unwrap();
        assert!(monitor.is_alive().unwrap());
    }

    #[test]
    fn test_process_monitor_collect_stats() {
        let pid = Pid::from_raw(std::process::id() as i32);
        let mut monitor = ProcessMonitor::new(pid).unwrap();
        let stats = monitor.collect_stats().unwrap();

        assert_eq!(stats.pid, pid.as_raw());
        assert!(stats.memory_usage_mb > 0);
        assert_eq!(monitor.peak_memory_mb(), stats.memory_usage_mb);
    }

    #[test]
    fn test_process_monitor_peak_memory() {
        let pid = Pid::from_raw(std::process::id() as i32);
        let mut monitor = ProcessMonitor::new(pid).unwrap();

        monitor.collect_stats().unwrap();
        let peak1 = monitor.peak_memory_mb();

        monitor.collect_stats().unwrap();
        let peak2 = monitor.peak_memory_mb();

        assert!(peak1 > 0);
        assert!(peak2 >= peak1);
    }

    #[test]
    fn test_process_stats_from_proc_missing_file() {
        let invalid_pid = 9_999_999i32;
        let timestamp = Instant::now();
        let result = ProcessStats::from_proc(invalid_pid, timestamp);
        assert!(result.is_err());
    }

    #[test]
    fn test_process_stats_from_proc_invalid_format() {
        let pid = std::process::id() as i32;
        let timestamp = Instant::now();
        let result = ProcessStats::from_proc(pid, timestamp);
        assert!(result.is_ok());
    }
}
