//! Stress tests for sandbox-rs builder and configuration
//!
//! These tests verify that the sandbox configuration API is robust.

use sandbox_rs::{NamespaceConfig, SandboxBuilder, SeccompProfile};
use std::sync::Mutex;
use std::time::Duration;

static STRESS_TEST_LOCK: Mutex<()> = Mutex::new(());

/// Test rapid builder creation
#[test]
fn stress_rapid_builder_creation() {
    let _lock = STRESS_TEST_LOCK.lock();

    for i in 0..50 {
        let _builder = SandboxBuilder::new(&format!("stress-builder-{}", i))
            .memory_limit_str("256M")
            .expect("Should parse memory");
    }
}

/// Test many CPU limit configurations
#[test]
fn stress_cpu_limit_configurations() {
    let _lock = STRESS_TEST_LOCK.lock();

    let cpu_limits = vec![1, 5, 10, 25, 50, 75, 100, 150, 200, 300, 400];

    for (i, percent) in cpu_limits.iter().enumerate() {
        let _builder =
            SandboxBuilder::new(&format!("stress-cpu-{}", i)).cpu_limit_percent(*percent);
    }
}

/// Test many memory limit configurations
#[test]
fn stress_memory_limit_configurations() {
    let _lock = STRESS_TEST_LOCK.lock();

    let memory_limits = vec![
        "4M", "8M", "16M", "32M", "64M", "128M", "256M", "512M", "1G", "2G",
    ];

    for (i, limit) in memory_limits.iter().enumerate() {
        let _builder = SandboxBuilder::new(&format!("stress-mem-{}", i))
            .memory_limit_str(limit)
            .unwrap_or_else(|_| panic!("Should parse {}", limit));
    }
}

/// Test combined configurations
#[test]
fn stress_combined_configurations() {
    let _lock = STRESS_TEST_LOCK.lock();

    let configs = [(64, 10), (128, 25), (256, 50), (512, 75), (1024, 100)];

    for (i, (mem_mb, cpu_percent)) in configs.iter().enumerate() {
        let _builder = SandboxBuilder::new(&format!("stress-combined-{}", i))
            .memory_limit_str(&format!("{}M", mem_mb))
            .expect("Should parse memory")
            .cpu_limit_percent(*cpu_percent);
    }
}

/// Test timeout variety
#[test]
fn stress_timeout_configurations() {
    let _lock = STRESS_TEST_LOCK.lock();

    let timeouts = [
        Duration::from_millis(100),
        Duration::from_millis(500),
        Duration::from_secs(1),
        Duration::from_secs(5),
        Duration::from_secs(10),
        Duration::from_secs(60),
    ];

    for (i, timeout) in timeouts.iter().enumerate() {
        let _builder = SandboxBuilder::new(&format!("stress-timeout-{}", i)).timeout(*timeout);
    }
}

/// Test max_pids variety
#[test]
fn stress_max_pids_configurations() {
    let _lock = STRESS_TEST_LOCK.lock();

    let max_pids = vec![1, 2, 4, 8, 16, 32, 64, 128, 256];

    for (i, pids) in max_pids.iter().enumerate() {
        let _builder = SandboxBuilder::new(&format!("stress-pids-{}", i)).max_pids(*pids);
    }
}

/// Test seccomp profile changes
#[test]
fn stress_seccomp_profiles() {
    let _lock = STRESS_TEST_LOCK.lock();

    let profiles = [
        SeccompProfile::Minimal,
        SeccompProfile::IoHeavy,
        SeccompProfile::Compute,
        SeccompProfile::Network,
        SeccompProfile::Unrestricted,
    ];

    for (i, profile) in profiles.iter().enumerate() {
        let _builder =
            SandboxBuilder::new(&format!("stress-seccomp-{}", i)).seccomp_profile(profile.clone());
    }
}

/// Test namespace variety
#[test]
fn stress_namespace_configurations() {
    let _lock = STRESS_TEST_LOCK.lock();

    let configs = [
        NamespaceConfig::minimal(),
        NamespaceConfig::default(),
        NamespaceConfig::all(),
    ];

    for (i, config) in configs.iter().enumerate() {
        let _builder = SandboxBuilder::new(&format!("stress-ns-{}", i)).namespaces(config.clone());
    }
}

/// Test extreme memory limits
#[test]
fn stress_extreme_memory_limits() {
    let _lock = STRESS_TEST_LOCK.lock();

    let limits = vec!["1M", "4M", "8M", "512M", "1G", "2G", "4G", "8G", "16G"];

    for (i, limit) in limits.iter().enumerate() {
        let result =
            SandboxBuilder::new(&format!("stress-mem-extreme-{}", i)).memory_limit_str(limit);

        assert!(result.is_ok(), "Should parse {}", limit);
    }
}

/// Test extreme CPU limits
#[test]
fn stress_extreme_cpu_limits() {
    let _lock = STRESS_TEST_LOCK.lock();

    let limits = [1, 10, 50, 100, 200, 400, 800];

    for (i, percent) in limits.iter().enumerate() {
        let _builder =
            SandboxBuilder::new(&format!("stress-cpu-extreme-{}", i)).cpu_limit_percent(*percent);
    }
}

/// Test all seccomp profiles available
#[test]
fn stress_all_seccomp_profiles() {
    let _lock = STRESS_TEST_LOCK.lock();

    let all_profiles = SeccompProfile::all();
    assert!(!all_profiles.is_empty());

    for (i, profile) in all_profiles.iter().enumerate() {
        let _builder =
            SandboxBuilder::new(&format!("stress-profile-{}", i)).seccomp_profile(profile.clone());
    }
}

/// Test very long sandbox IDs
#[test]
fn stress_long_sandbox_ids() {
    let _lock = STRESS_TEST_LOCK.lock();

    let long_id = "very_long_sandbox_id_".repeat(5);
    let _builder = SandboxBuilder::new(&long_id);
}

/// Test special characters in sandbox IDs
#[test]
fn stress_special_char_sandbox_ids() {
    let _lock = STRESS_TEST_LOCK.lock();

    let ids = [
        "sandbox-with-dashes",
        "sandbox_with_underscores",
        "sandbox123numbers",
        "UPPERCASE",
        "MixedCase",
    ];

    for id in ids.iter() {
        let _builder = SandboxBuilder::new(id);
    }
}

/// Test memory format parsing edge cases
#[test]
fn stress_memory_format_variations() {
    let _lock = STRESS_TEST_LOCK.lock();

    let formats = ["1M", "10M", "100M", "256M", "512M", "1G", "2G", "10G"];

    for (i, format) in formats.iter().enumerate() {
        let result = SandboxBuilder::new(&format!("stress-fmt-{}", i)).memory_limit_str(format);

        assert!(result.is_ok(), "Should parse {}", format);
    }
}
