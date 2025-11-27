use super::{Cgroup, CgroupConfig};
use nix::unistd::Pid;
use std::path::Path;

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[test]
fn cgroup_config_combines_multiple_limits() {
    let mut config = CgroupConfig::with_memory(256 * 1024 * 1024);
    config.cpu_weight = Some(500);
    config.cpu_quota = Some(50_000);
    config.cpu_period = Some(100_000);
    config.max_pids = Some(32);

    assert!(config.validate().is_ok());
    assert_eq!(config.memory_limit, Some(256 * 1024 * 1024));
    assert_eq!(config.cpu_weight, Some(500));
    assert_eq!(config.max_pids, Some(32));
}

#[test]
fn cgroup_config_rejects_invalid_values() {
    let bad_memory = CgroupConfig {
        memory_limit: Some(0),
        ..Default::default()
    };
    assert!(bad_memory.validate().is_err());

    let bad_weight_low = CgroupConfig {
        cpu_weight: Some(10),
        ..Default::default()
    };
    assert!(bad_weight_low.validate().is_err());

    let bad_weight_high = CgroupConfig {
        cpu_weight: Some(20_000),
        ..Default::default()
    };
    assert!(bad_weight_high.validate().is_err());
}

#[test]
fn cgroup_config_helpers_set_expected_fields() {
    let memory = CgroupConfig::with_memory(64 * 1024 * 1024);
    assert_eq!(memory.memory_limit, Some(64 * 1024 * 1024));

    let quota = CgroupConfig::with_cpu_quota(100_000, 200_000);
    assert_eq!(quota.cpu_quota, Some(100_000));
    assert_eq!(quota.cpu_period, Some(200_000));
}

#[test]
#[ignore]
fn cgroup_creation_handles_permissions_gracefully() {
    let pid = Pid::from_raw(std::process::id() as i32);
    let name = format!("sandbox-rs-test-{}", pid);
    let result = Cgroup::new(&name, pid);

    if Path::new("/sys/fs/cgroup").exists() && is_root() {
        let cgroup = result.expect("root should create cgroup");
        assert!(cgroup.exists());
        let _ = cgroup.delete();
    } else {
        assert!(result.is_err());
    }
}
