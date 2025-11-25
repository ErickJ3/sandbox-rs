use super::namespace::{get_namespace_inode, shares_namespace};
use super::{NamespaceConfig, SeccompFilter, SeccompProfile};
use crate::isolation::seccomp_bpf::{SeccompCompiler, SyscallNumber, actions};
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
fn seccomp_filter_blocking_removes_syscall_from_bpf() {
    let mut filter = SeccompFilter::minimal();
    filter.block_syscall("read");
    filter.set_kill_on_violation(false);

    let instrs = SeccompCompiler::compile(&filter).expect("compile succeeds");
    let read_number = SyscallNumber::from_name("read").unwrap().0;
    assert!(
        instrs
            .iter()
            .all(|instr| instr.code != 0x15 || instr.k != read_number)
    );
}

#[test]
fn seccomp_compiler_respects_kill_flag() {
    let filter_kill = SeccompFilter::minimal();
    let instrs_kill = SeccompCompiler::compile(&filter_kill).unwrap();
    assert_eq!(instrs_kill.last().unwrap().k, actions::SECCOMP_RET_KILL);

    let mut filter_trap = SeccompFilter::minimal();
    filter_trap.set_kill_on_violation(false);
    let instrs_trap = SeccompCompiler::compile(&filter_trap).unwrap();
    assert_eq!(instrs_trap.last().unwrap().k, actions::SECCOMP_RET_TRAP);
}
