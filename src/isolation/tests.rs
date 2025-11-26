use super::namespace::{get_namespace_inode, shares_namespace};
use super::{NamespaceConfig, SeccompFilter, SeccompProfile};
use crate::isolation::seccomp_bpf::SeccompBpf;
use nix::sched::CloneFlags;

#[test]
fn namespace_configuration_can_toggle_individual_namespaces() {
    let mut config = NamespaceConfig::default();
    assert!(config.pid);
    config.user = true;
    assert!(config.all_enabled());

    config.uts = false;
    assert!(!config.all_enabled());
    assert_eq!(config.enabled_count(), 5);

    let flags = config.to_clone_flags();
    assert!(flags.contains(CloneFlags::CLONE_NEWUSER));
}

#[test]
fn namespace_inode_queries_fail_for_invalid_target() {
    let result = get_namespace_inode("nonexistent");
    assert!(result.is_err());
}

#[test]
fn namespace_sharing_detects_matching_inodes() {
    let shared = shares_namespace("pid", None, None).expect("pid namespace should be readable");
    assert!(shared);
}

#[test]
fn seccomp_profiles_cover_expected_variants() {
    let profiles = SeccompProfile::all();
    assert!(profiles.contains(&SeccompProfile::Minimal));
    assert!(profiles.contains(&SeccompProfile::Network));
    assert_eq!(profiles.len(), 5);
}

#[test]
fn seccomp_filter_export_is_sorted_and_non_empty() {
    let filter = SeccompFilter::from_profile(SeccompProfile::Compute);
    let exported = filter.export().expect("export should succeed");

    assert!(!exported.is_empty());
    let mut sorted = exported.clone();
    sorted.sort();
    assert_eq!(exported, sorted);
}

#[test]
fn seccomp_filter_blocking_compiles_successfully() {
    let mut filter = SeccompFilter::minimal();
    filter.block_syscall("read");
    filter.set_kill_on_violation(false);

    let result = SeccompBpf::compile(&filter);
    assert!(result.is_ok());
    let instrs = result.unwrap();
    assert!(instrs.len() > 5);
}

#[test]
fn seccomp_bpf_compiles_with_kill_and_trap_modes() {
    let filter_kill = SeccompFilter::minimal();
    assert!(filter_kill.is_kill_on_violation());
    let result_kill = SeccompBpf::compile(&filter_kill);
    assert!(result_kill.is_ok());
    let instrs_kill = result_kill.unwrap();
    assert!(instrs_kill.len() > 5);

    let mut filter_trap = SeccompFilter::minimal();
    filter_trap.set_kill_on_violation(false);
    assert!(!filter_trap.is_kill_on_violation());
    let result_trap = SeccompBpf::compile(&filter_trap);
    assert!(result_trap.is_ok());
    let instrs_trap = result_trap.unwrap();
    assert!(instrs_trap.len() > 5);
}
