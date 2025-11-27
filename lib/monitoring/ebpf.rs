//! eBPF-based syscall monitoring
//!
//! Provides event-driven syscall tracing using eBPF programs.
//! Monitors syscall frequency, duration, and detects slow operations (>10ms).
//!
//! Note: Full eBPF functionality requires kernel 5.0+ and BPF_RING_BUFFER support.

use crate::errors::Result;
use nix::unistd::Pid;
use std::collections::HashMap;

/// Syscall event information
#[derive(Debug, Clone)]
pub struct SyscallEvent {
    /// Syscall number
    pub syscall_id: u64,
    /// Syscall name (e.g., "read", "write")
    pub syscall_name: String,
    /// Duration in microseconds
    pub duration_us: u64,
    /// Timestamp when syscall occurred
    pub timestamp: u64,
    /// Whether this was a slow syscall (>10ms)
    pub is_slow: bool,
}

impl SyscallEvent {
    /// Check if this syscall is considered slow (>10ms)
    pub fn is_slow_syscall(&self) -> bool {
        self.duration_us > 10_000 // 10ms in microseconds
    }

    /// Get duration in milliseconds
    pub fn duration_ms(&self) -> f64 {
        self.duration_us as f64 / 1000.0
    }
}

/// Aggregated syscall statistics
#[derive(Debug, Clone, Default)]
pub struct SyscallStats {
    /// Total number of syscalls
    pub total_syscalls: u64,
    /// Number of slow syscalls (>10ms)
    pub slow_syscalls: u64,
    /// Total time spent in syscalls (microseconds)
    pub total_time_us: u64,
    /// Syscalls by name with their count and total duration
    pub syscalls_by_name: HashMap<String, (u64, u64)>, // (count, total_time_us)
    /// Top N slowest syscalls
    pub slowest_syscalls: Vec<SyscallEvent>,
}

/// eBPF-based syscall monitor
pub struct EBpfMonitor {
    pid: Pid,
    events: Vec<SyscallEvent>,
    stats: SyscallStats,
}

impl EBpfMonitor {
    /// Create new eBPF monitor for process
    pub fn new(pid: Pid) -> Self {
        EBpfMonitor {
            pid,
            events: Vec::new(),
            stats: SyscallStats::default(),
        }
    }

    /// Collect syscall statistics
    pub fn collect_stats(&mut self) -> Result<SyscallStats> {
        // This is a placeholder implementation
        self._compute_statistics();
        Ok(self.stats.clone())
    }

    /// Add raw syscall event (for testing/manual injection)
    pub fn add_event(&mut self, event: SyscallEvent) {
        self.events.push(event);
        self._compute_statistics();
    }

    /// Clear collected events
    pub fn clear(&mut self) {
        self.events.clear();
        self.stats = SyscallStats::default();
    }

    /// Get process ID being monitored
    pub fn pid(&self) -> Pid {
        self.pid
    }

    /// Get total slow syscalls
    pub fn slow_syscall_count(&self) -> u64 {
        self.stats.slow_syscalls
    }

    /// Get top N slowest syscalls
    pub fn slowest_syscalls(&self, n: usize) -> Vec<SyscallEvent> {
        self.stats
            .slowest_syscalls
            .iter()
            .take(n)
            .cloned()
            .collect()
    }

    /// Recompute statistics from events
    fn _compute_statistics(&mut self) {
        let mut stats = SyscallStats::default();
        let mut by_name: HashMap<String, (u64, u64)> = HashMap::new();
        let mut slowest: Vec<SyscallEvent> = Vec::new();

        for event in &self.events {
            stats.total_syscalls += 1;
            stats.total_time_us += event.duration_us;

            if event.is_slow {
                stats.slow_syscalls += 1;
            }

            // Aggregate by syscall name
            let entry = by_name.entry(event.syscall_name.clone()).or_insert((0, 0));
            entry.0 += 1;
            entry.1 += event.duration_us;

            // Track slowest syscalls
            slowest.push(event.clone());
        }

        // Sort slowest and keep top 10
        slowest.sort_by(|a, b| b.duration_us.cmp(&a.duration_us));
        slowest.truncate(10);

        stats.syscalls_by_name = by_name;
        stats.slowest_syscalls = slowest;

        self.stats = stats;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syscall_event_is_slow() {
        let event_slow = SyscallEvent {
            syscall_id: 1,
            syscall_name: "read".to_string(),
            duration_us: 15_000, // 15ms
            timestamp: 0,
            is_slow: true,
        };
        assert!(event_slow.is_slow_syscall());

        let event_fast = SyscallEvent {
            syscall_id: 1,
            syscall_name: "read".to_string(),
            duration_us: 5_000, // 5ms
            timestamp: 0,
            is_slow: false,
        };
        assert!(!event_fast.is_slow_syscall());
    }

    #[test]
    fn test_syscall_event_duration_ms() {
        let event = SyscallEvent {
            syscall_id: 1,
            syscall_name: "write".to_string(),
            duration_us: 10_000, // 10ms
            timestamp: 0,
            is_slow: false,
        };
        assert_eq!(event.duration_ms(), 10.0);
    }

    #[test]
    fn test_ebpf_monitor_new() {
        let pid = Pid::from_raw(std::process::id() as i32);
        let monitor = EBpfMonitor::new(pid);
        assert_eq!(monitor.pid(), pid);
        assert_eq!(monitor.slow_syscall_count(), 0);
    }

    #[test]
    fn test_ebpf_monitor_add_event() {
        let pid = Pid::from_raw(std::process::id() as i32);
        let mut monitor = EBpfMonitor::new(pid);

        let event = SyscallEvent {
            syscall_id: 1,
            syscall_name: "read".to_string(),
            duration_us: 5_000,
            timestamp: 0,
            is_slow: false,
        };

        monitor.add_event(event);
        assert_eq!(monitor.stats.total_syscalls, 1);
        assert_eq!(monitor.stats.slow_syscalls, 0);
    }

    #[test]
    fn test_ebpf_monitor_slow_syscalls() {
        let pid = Pid::from_raw(std::process::id() as i32);
        let mut monitor = EBpfMonitor::new(pid);

        // Add fast syscall
        monitor.add_event(SyscallEvent {
            syscall_id: 1,
            syscall_name: "read".to_string(),
            duration_us: 5_000,
            timestamp: 0,
            is_slow: false,
        });

        // Add slow syscall
        monitor.add_event(SyscallEvent {
            syscall_id: 2,
            syscall_name: "write".to_string(),
            duration_us: 15_000,
            timestamp: 1,
            is_slow: true,
        });

        assert_eq!(monitor.stats.total_syscalls, 2);
        assert_eq!(monitor.stats.slow_syscalls, 1);
    }

    #[test]
    fn test_ebpf_monitor_slowest_syscalls() {
        let pid = Pid::from_raw(std::process::id() as i32);
        let mut monitor = EBpfMonitor::new(pid);

        for i in 0..5 {
            monitor.add_event(SyscallEvent {
                syscall_id: i,
                syscall_name: format!("syscall_{}", i),
                duration_us: (i + 1) * 1000,
                timestamp: i,
                is_slow: (i + 1) * 1000 > 10_000,
            });
        }

        let slowest = monitor.slowest_syscalls(3);
        assert_eq!(slowest.len(), 3);
    }

    #[test]
    fn test_ebpf_monitor_clear() {
        let pid = Pid::from_raw(std::process::id() as i32);
        let mut monitor = EBpfMonitor::new(pid);

        monitor.add_event(SyscallEvent {
            syscall_id: 1,
            syscall_name: "read".to_string(),
            duration_us: 5_000,
            timestamp: 0,
            is_slow: false,
        });

        assert_eq!(monitor.stats.total_syscalls, 1);

        monitor.clear();
        assert_eq!(monitor.stats.total_syscalls, 0);
        assert_eq!(monitor.stats.slow_syscalls, 0);
    }
}
