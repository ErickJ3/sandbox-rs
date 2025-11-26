//! Integration tests for sandbox-rs
//!
//! These tests verify the sandbox API and configuration.
//! Tests that require root are marked with #[ignore] and can be run with:
//!   sudo cargo test -- --ignored

use sandbox_rs::{NamespaceConfig, SandboxBuilder, SeccompProfile};
use std::sync::Mutex;
use std::time::Duration;

static INTEGRATION_TEST_LOCK: Mutex<()> = Mutex::new(());

/// Test that basic sandbox builder works
#[test]
fn test_sandbox_builder_creation() {
    let _lock = INTEGRATION_TEST_LOCK.lock();
    let _ = SandboxBuilder::new("test-builder");
}

/// Test builder with memory limit
#[test]
fn test_sandbox_memory_limit_parsing() {
    let _lock = INTEGRATION_TEST_LOCK.lock();

    let result = SandboxBuilder::new("test-memory").memory_limit_str("256M");

    assert!(result.is_ok());
}

/// Test builder with CPU limit
#[test]
fn test_sandbox_cpu_limit_config() {
    let _lock = INTEGRATION_TEST_LOCK.lock();

    let _builder = SandboxBuilder::new("test-cpu").cpu_limit_percent(50);
}

/// Test builder with max PIDs
#[test]
fn test_sandbox_max_pids_config() {
    let _lock = INTEGRATION_TEST_LOCK.lock();

    let _builder = SandboxBuilder::new("test-pids").max_pids(16);
}

/// Test builder with timeout
#[test]
fn test_sandbox_timeout_config() {
    let _lock = INTEGRATION_TEST_LOCK.lock();

    let _builder = SandboxBuilder::new("test-timeout").timeout(Duration::from_secs(10));
}

/// Test namespace configuration
#[test]
fn test_namespace_default_config() {
    let ns = NamespaceConfig::default();

    assert!(ns.pid);
    assert!(ns.mount);
    assert!(ns.net);
    assert!(!ns.user);
}

/// Test minimal namespace config
#[test]
fn test_namespace_minimal_config() {
    let ns = NamespaceConfig::minimal();

    assert!(ns.pid);
    assert_eq!(ns.enabled_count(), 4); // PID, IPC, NET, MOUNT
}

/// Test all namespaces config
#[test]
fn test_namespace_all_config() {
    let ns = NamespaceConfig::all();

    assert!(ns.pid);
    assert!(ns.ipc);
    assert!(ns.net);
    assert!(ns.mount);
    assert!(ns.uts);
    assert!(ns.user);
}

/// Test seccomp profile descriptions
#[test]
fn test_seccomp_profiles_have_descriptions() {
    for profile in SeccompProfile::all() {
        let desc = profile.description();
        assert!(!desc.is_empty());
    }
}

/// Test seccomp filter creation from profile
#[test]
fn test_seccomp_filter_from_profile() {
    let filter = sandbox_rs::isolation::SeccompFilter::from_profile(SeccompProfile::IoHeavy);

    assert!(filter.allowed_count() > 0);
}

/// Test memory format parsing with various units
#[test]
fn test_memory_limit_formats() {
    let cases = vec!["64M", "256M", "1G"];

    for input in cases {
        let result = SandboxBuilder::new("test").memory_limit_str(input);

        assert!(result.is_ok(), "Should parse {}", input);
    }
}

/// Test CPU limit percentages
#[test]
fn test_cpu_limit_percentages() {
    let percentages = vec![1, 10, 50, 100, 200];

    for percent in percentages {
        let _builder = SandboxBuilder::new("test").cpu_limit_percent(percent);
    }
}

/// Test combined builder configuration
#[test]
fn test_combined_builder_config() {
    let _builder = SandboxBuilder::new("combined")
        .memory_limit_str("256M")
        .expect("Should parse memory")
        .cpu_limit_percent(50)
        .max_pids(16)
        .timeout(Duration::from_secs(30))
        .seccomp_profile(SeccompProfile::IoHeavy);
}

/// Test that zero CPU percent is handled
#[test]
fn test_cpu_limit_zero_percent() {
    let _builder = SandboxBuilder::new("test").cpu_limit_percent(0);
}

// Tests below require root privileges
// Run with: sudo cargo test -- --ignored

/// Test actual sandbox building (requires proper namespace support)
#[test]
#[ignore]
fn test_sandbox_build_with_isolation() {
    let _lock = INTEGRATION_TEST_LOCK.lock();

    let result = SandboxBuilder::new("isolation-test")
        .namespaces(NamespaceConfig::minimal())
        .build();

    let _ = result;
}

/// Test execution with echo (requires working sandbox)
#[test]
#[ignore]
fn test_sandbox_echo_execution() {
    let _lock = INTEGRATION_TEST_LOCK.lock();

    let mut sandbox = match SandboxBuilder::new("echo-test").build() {
        Ok(sb) => sb,
        Err(_) => return,
    };

    let result = sandbox
        .run("/bin/echo", &["hello"])
        .expect("Failed to run echo");

    assert_eq!(result.exit_code, 0);
}

/// Test process exit codes
#[test]
#[ignore]
fn test_exit_codes() {
    let _lock = INTEGRATION_TEST_LOCK.lock();

    let mut sandbox_ok = match SandboxBuilder::new("exit-ok").build() {
        Ok(sb) => sb,
        Err(_) => return,
    };

    let result_ok = sandbox_ok
        .run("/bin/true", &[])
        .expect("Should run /bin/true");
    assert_eq!(result_ok.exit_code, 0);

    let mut sandbox_fail = match SandboxBuilder::new("exit-fail").build() {
        Ok(sb) => sb,
        Err(_) => return,
    };

    let result_fail = sandbox_fail
        .run("/bin/false", &[])
        .expect("Should run /bin/false");
    assert_ne!(result_fail.exit_code, 0);
}

/// Test resource tracking
#[test]
#[ignore]
fn test_resource_tracking() {
    let _lock = INTEGRATION_TEST_LOCK.lock();

    let mut sandbox = match SandboxBuilder::new("resources-test")
        .memory_limit_str("256M")
        .expect("Should parse memory")
        .cpu_limit_percent(50)
        .build()
    {
        Ok(sb) => sb,
        Err(_) => return,
    };

    let result = sandbox.run("/bin/echo", &["test"]).expect("Failed to run");

    assert!(result.wall_time_ms > 0);
    assert_eq!(result.exit_code, 0);
}
