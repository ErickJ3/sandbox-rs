//! Minimal init process for sandbox

use nix::sys::signal::{SigHandler, Signal, signal};
use nix::unistd::execv;
use std::ffi::CString;
use std::process::exit;

/// Simple init process that manages sandbox
pub struct SandboxInit {
    /// Arguments to pass to user program
    pub program: String,
    pub args: Vec<String>,
}

impl SandboxInit {
    /// Create new init process
    pub fn new(program: String, args: Vec<String>) -> Self {
        Self { program, args }
    }

    /// Run init process
    /// This becomes PID 1 inside the sandbox
    pub fn run(&self) -> ! {
        // Setup signal handlers
        Self::setup_signals();

        Self::mount_procfs();
        Self::mount_sysfs();

        // Execute user program
        self.exec_user_program();
    }

    /// Setup signal handlers for init
    fn setup_signals() {
        // Ignore SIGCHLD so we don't become zombie
        unsafe {
            let _ = signal(Signal::SIGCHLD, SigHandler::SigIgn);
            let _ = signal(Signal::SIGTERM, SigHandler::SigDfl);
        }
    }

    fn mount_procfs() {
        let _ = std::fs::create_dir("/proc");
        let _ = std::process::Command::new("mount")
            .args(["-t", "proc", "proc", "/proc"])
            .output();
    }

    fn mount_sysfs() {
        let _ = std::fs::create_dir("/sys");
        let _ = std::process::Command::new("mount")
            .args(["-t", "sysfs", "sysfs", "/sys"])
            .output();
    }

    /// Execute user program
    fn exec_user_program(&self) -> ! {
        let program_cstr = match CString::new(self.program.clone()) {
            Ok(s) => s,
            Err(_) => {
                eprintln!("Invalid program name");
                exit(1);
            }
        };

        let args_cstr: Vec<CString> = self
            .args
            .iter()
            .map(|arg| CString::new(arg.clone()).unwrap_or_else(|_| CString::new("").unwrap()))
            .collect();

        let args_refs: Vec<&CString> = vec![&program_cstr]
            .into_iter()
            .chain(args_cstr.iter())
            .collect();

        match execv(&program_cstr, &args_refs) {
            Ok(_) => {
                // execv replaces process, never returns on success
                exit(0);
            }
            Err(e) => {
                eprintln!("Failed to execute program: {}", e);
                exit(1);
            }
        }
    }

    /// Reap zombie children
    pub fn reap_children() {
        use nix::sys::wait::{WaitStatus, waitpid};
        use nix::unistd::Pid;

        loop {
            match waitpid(
                Pid::from_raw(-1),
                Some(nix::sys::wait::WaitPidFlag::WNOHANG),
            ) {
                Ok(WaitStatus::Exited(pid, _status)) => {
                    eprintln!("[init] Child {} exited", pid);
                }
                Ok(WaitStatus::Signaled(pid, signal, _core)) => {
                    eprintln!("[init] Child {} killed by {:?}", pid, signal);
                }
                Ok(WaitStatus::StillAlive) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    }
}

/// Write init process binary
/// This is used for containerized execution
pub fn generate_init_script(program: &str, args: &[&str]) -> String {
    format!(
        r#"#!/bin/sh
set -e

# Mount essential filesystems
mkdir -p /proc /sys /dev /tmp

# Don't mount if already mounted (in case of nested)
mountpoint -q /proc || mount -t proc proc /proc
mountpoint -q /sys || mount -t sysfs sysfs /sys

# Execute program
exec "{}" {}
"#,
        program,
        args.join(" ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_creation() {
        let init = SandboxInit::new("/bin/echo".to_string(), vec!["hello".to_string()]);

        assert_eq!(init.program, "/bin/echo");
        assert_eq!(init.args.len(), 1);
        assert_eq!(init.args[0], "hello");
    }

    #[test]
    fn test_init_with_multiple_args() {
        let init = SandboxInit::new(
            "/bin/echo".to_string(),
            vec![
                "hello".to_string(),
                "world".to_string(),
                "from".to_string(),
                "init".to_string(),
            ],
        );

        assert_eq!(init.args.len(), 4);
    }

    #[test]
    fn test_generate_init_script_simple() {
        let script = generate_init_script("/bin/echo", &["hello"]);

        assert!(script.contains("#!/bin/sh"));
        assert!(script.contains("/proc"));
        assert!(script.contains("/bin/echo"));
        assert!(script.contains("hello"));
    }

    #[test]
    fn test_generate_init_script_multiple_args() {
        let script = generate_init_script("/bin/echo", &["hello", "world"]);

        assert!(script.contains("hello"));
        assert!(script.contains("world"));
        assert!(script.contains("exec"));
    }

    #[test]
    fn test_generate_init_script_contains_mounts() {
        let script = generate_init_script("/usr/bin/test", &[]);

        assert!(script.contains("mount -t proc"));
        assert!(script.contains("mount -t sysfs"));
        assert!(script.contains("mkdir -p /proc /sys /dev /tmp"));
    }

    #[test]
    fn test_init_empty_args() {
        let init = SandboxInit::new("/bin/sh".to_string(), Vec::new());

        assert!(init.args.is_empty());
    }

    #[test]
    fn test_mount_helpers_are_best_effort() {
        SandboxInit::mount_procfs();
        SandboxInit::mount_sysfs();
    }

    #[test]
    fn test_setup_signals_runs() {
        // Store original handlers so we can restore them
        let original_sigchld = unsafe { signal(Signal::SIGCHLD, SigHandler::SigDfl) };

        // Test the setup
        SandboxInit::setup_signals();

        // Restore original handlers to not affect other tests
        unsafe {
            let _ = signal(
                Signal::SIGCHLD,
                original_sigchld.unwrap_or(SigHandler::SigDfl),
            );
        }
    }
}
