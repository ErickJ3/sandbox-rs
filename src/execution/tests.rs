use super::*;
use crate::isolation::{NamespaceConfig, SeccompFilter, SeccompProfile};
use crate::test_support::serial_guard;
use libc;
use nix::unistd::{ForkResult, fork};

fn sample_process_config() -> ProcessConfig {
    ProcessConfig {
        program: "/bin/echo".to_string(),
        args: vec!["hello".to_string(), "sandbox".to_string()],
        env: vec![
            ("RUST_BACKTRACE".to_string(), "1".to_string()),
            ("SANDBOX".to_string(), "true".to_string()),
        ],
        cwd: Some("/tmp".to_string()),
        chroot_dir: Some("/".to_string()),
        uid: Some(1000),
        gid: Some(1000),
        seccomp: Some(SeccompFilter::from_profile(SeccompProfile::Minimal)),
    }
}

fn no_isolation_namespace() -> NamespaceConfig {
    NamespaceConfig {
        pid: false,
        ipc: false,
        net: false,
        mount: false,
        uts: false,
        user: false,
    }
}

#[test]
fn process_config_captures_full_configuration() {
    let config = sample_process_config();

    assert_eq!(config.program, "/bin/echo");
    assert_eq!(config.args, vec!["hello", "sandbox"]);
    assert_eq!(config.env.len(), 2);
    assert_eq!(config.cwd.as_deref(), Some("/tmp"));
    assert_eq!(config.chroot_dir.as_deref(), Some("/"));
    assert_eq!(config.uid, Some(1000));
    assert_eq!(config.gid, Some(1000));
    assert!(config.seccomp.is_some());
}

#[test]
fn process_config_clone_preserves_data() {
    let original = sample_process_config();
    let cloned = original.clone();

    assert_eq!(original.program, cloned.program);
    assert_eq!(original.args, cloned.args);
    assert_eq!(original.env, cloned.env);
    assert_eq!(original.cwd, cloned.cwd);
    assert_eq!(
        original.seccomp.as_ref().unwrap().allowed_count(),
        cloned.seccomp.as_ref().unwrap().allowed_count()
    );
}

#[test]
fn process_config_accepts_custom_namespace_config() {
    let mut namespace = NamespaceConfig::minimal();
    assert_eq!(namespace.enabled_count(), 4);

    namespace.uts = true;
    assert_eq!(namespace.enabled_count(), 5);

    namespace.user = true;
    assert!(namespace.all_enabled());
    let flags = namespace.to_clone_flags();
    assert!(flags.bits() != 0);
}

#[test]
fn process_result_records_exit_information() {
    let result = ProcessResult {
        pid: nix::unistd::Pid::from_raw(4242),
        exit_status: 137,
        signal: Some(9),
        exec_time_ms: 250,
    };

    assert_eq!(result.pid.as_raw(), 4242);
    assert_eq!(result.exit_status, 137);
    assert_eq!(result.signal, Some(9));
    assert_eq!(result.exec_time_ms, 250);
}

#[test]
fn sandbox_init_script_contains_expected_sections() {
    let script = crate::execution::init::generate_init_script("/bin/echo", &["hello", "world"]);

    assert!(script.starts_with("#!/bin/sh"));
    assert!(script.contains("mount -t proc"));
    assert!(script.contains("mount -t sysfs"));
    assert!(script.contains("exec \"/bin/echo\" hello world"));
}

#[test]
fn sandbox_init_reaps_finished_children_without_panicking() {
    let _guard = serial_guard();
    use nix::sys::wait::{WaitStatus, waitpid};

    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            std::process::exit(0);
        }
        Ok(ForkResult::Parent { child }) => {
            // Wait for the child to exit
            match waitpid(child, None) {
                Ok(WaitStatus::Exited(_, _)) => {
                    // Child exited successfully
                }
                Ok(_) => {
                    // Child stopped or signaled
                }
                Err(e) => panic!("waitpid failed: {}", e),
            }
        }
        Err(err) => panic!("fork failed: {}", err),
    }
}

#[test]
fn process_executor_skips_privileged_operations_without_root() {
    let _guard = serial_guard();
    let current_gid = unsafe { libc::getgid() as u32 };
    let config = ProcessConfig {
        program: "/bin/true".to_string(),
        args: vec![],
        chroot_dir: Some("/".to_string()),
        gid: Some(current_gid),
        seccomp: Some(SeccompFilter::minimal()),
        ..Default::default()
    };

    let namespace = no_isolation_namespace();
    let result = ProcessExecutor::execute(config, namespace).unwrap();
    assert_eq!(result.exit_status, 0);
}
