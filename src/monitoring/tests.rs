use crate::monitoring::{EBpfMonitor, ProcessMonitor, ProcessState};
use crate::test_support::serial_guard;
use nix::unistd::Pid;
use std::time::Duration;

#[test]
fn process_monitor_collects_and_caches_stats() {
    let pid = Pid::from_raw(std::process::id() as i32);
    let mut monitor = ProcessMonitor::new(pid).expect("current process exists");

    let first = monitor.collect_stats().expect("collect stats");
    assert_eq!(first.pid, pid.as_raw());
    assert!(monitor.peak_memory_mb() >= first.memory_usage_mb);

    let cached = monitor.last_stats().expect("stats cached");
    assert_eq!(cached.pid, first.pid);
    assert!(monitor.elapsed() >= Duration::from_millis(0));
}

#[test]
fn process_monitor_rejects_missing_pid() {
    let invalid_pid = Pid::from_raw(9_999_999);
    let result = ProcessMonitor::new(invalid_pid);
    assert!(result.is_err());
}

#[test]
fn process_monitor_graceful_shutdown_terminates_child() {
    let _guard = serial_guard();
    let mut child = std::process::Command::new("sleep")
        .arg("5")
        .spawn()
        .expect("failed to spawn sleep");

    let pid = Pid::from_raw(child.id() as i32);
    let monitor = ProcessMonitor::new(pid).expect("child process exists");
    monitor
        .graceful_shutdown(Duration::from_millis(50))
        .expect("graceful shutdown");

    let status = child.wait().expect("wait on child");
    assert!(!status.success());
}

#[test]
fn process_monitor_send_sigterm_stops_child() {
    let _guard = serial_guard();
    let mut child = std::process::Command::new("sleep")
        .arg("5")
        .spawn()
        .expect("spawn sleep");
    let pid = Pid::from_raw(child.id() as i32);
    let monitor = ProcessMonitor::new(pid).expect("child process exists");
    monitor.send_sigterm().expect("send sigterm");
    let status = child.wait().expect("wait on child");
    assert!(!status.success());
}

#[test]
fn process_monitor_send_sigkill_always_stops_child() {
    let _guard = serial_guard();
    let mut child = std::process::Command::new("sleep")
        .arg("5")
        .spawn()
        .expect("spawn sleep");
    let pid = Pid::from_raw(child.id() as i32);
    let monitor = ProcessMonitor::new(pid).expect("child process exists");
    monitor.send_sigkill().expect("send sigkill");
    let status = child.wait().expect("wait on child");
    assert!(!status.success());
}

#[test]
fn process_monitor_is_alive_false_after_exit() {
    let _guard = serial_guard();
    let mut child = std::process::Command::new("true")
        .spawn()
        .expect("spawn true");
    let pid = Pid::from_raw(child.id() as i32);
    let monitor = ProcessMonitor::new(pid).expect("child process exists");
    child.wait().expect("wait on child");
    assert!(!monitor.is_alive().expect("is_alive result"));
}

#[test]
fn ebpf_monitor_aggregates_events_and_slowest_calls() {
    let pid = Pid::from_raw(std::process::id() as i32);
    let mut monitor = EBpfMonitor::new(pid);

    monitor.add_event(crate::monitoring::ebpf::SyscallEvent {
        syscall_id: 1,
        syscall_name: "read".to_string(),
        duration_us: 5_000,
        timestamp: 0,
        is_slow: false,
    });
    monitor.add_event(crate::monitoring::ebpf::SyscallEvent {
        syscall_id: 2,
        syscall_name: "write".to_string(),
        duration_us: 25_000,
        timestamp: 1,
        is_slow: true,
    });

    let stats = monitor.collect_stats().expect("collect ebpf stats");
    assert_eq!(stats.total_syscalls, 2);
    assert_eq!(stats.slow_syscalls, 1);
    assert_eq!(monitor.slowest_syscalls(1).len(), 1);
    assert_eq!(monitor.slowest_syscalls(1)[0].syscall_name, "write");
}

#[test]
fn ebpf_monitor_clear_resets_state() {
    let pid = Pid::from_raw(std::process::id() as i32);
    let mut monitor = EBpfMonitor::new(pid);

    monitor.add_event(crate::monitoring::ebpf::SyscallEvent {
        syscall_id: 3,
        syscall_name: "open".to_string(),
        duration_us: 1_000,
        timestamp: 2,
        is_slow: false,
    });
    assert_eq!(monitor.slow_syscall_count(), 0);

    monitor.clear();
    let stats = monitor.collect_stats().expect("collect stats after clear");
    assert_eq!(stats.total_syscalls, 0);
    assert_eq!(monitor.slow_syscall_count(), 0);
}

#[test]
fn process_state_from_char_variants() {
    assert_eq!(ProcessState::from_char('R'), ProcessState::Running);
    assert_eq!(ProcessState::from_char('S'), ProcessState::Sleeping);
    assert_eq!(ProcessState::from_char('Z'), ProcessState::Zombie);
    assert_eq!(ProcessState::from_char('X'), ProcessState::Unknown);
}
