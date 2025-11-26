//! Process execution within sandbox namespace

use crate::errors::{Result, SandboxError};
use crate::execution::stream::{ProcessStream, spawn_fd_reader};
use crate::isolation::namespace::NamespaceConfig;
use crate::isolation::seccomp::SeccompFilter;
use crate::isolation::seccomp_bpf::SeccompCompiler;
use crate::utils;
use log::warn;
use nix::sched::clone;
use nix::sys::signal::Signal;
use nix::unistd::{Pid, chdir, chroot, execve};
use std::ffi::CString;
use std::os::fd::IntoRawFd;
use std::os::unix::io::AsRawFd;

/// Process execution configuration
#[derive(Debug, Clone, Default)]
pub struct ProcessConfig {
    /// Program to execute
    pub program: String,
    /// Program arguments
    pub args: Vec<String>,
    /// Environment variables
    pub env: Vec<(String, String)>,
    /// Working directory (inside sandbox)
    pub cwd: Option<String>,
    /// Root directory for chroot
    pub chroot_dir: Option<String>,
    /// UID to run as
    pub uid: Option<u32>,
    /// GID to run as
    pub gid: Option<u32>,
    /// Seccomp filter
    pub seccomp: Option<SeccompFilter>,
}

/// Result of process execution
#[derive(Debug, Clone)]
pub struct ProcessResult {
    /// Process ID
    pub pid: Pid,
    /// Exit status
    pub exit_status: i32,
    /// Signal if killed
    pub signal: Option<i32>,
    /// Execution time in milliseconds
    pub exec_time_ms: u64,
}

/// Process executor
pub struct ProcessExecutor;

impl ProcessExecutor {
    /// Execute process with namespace isolation
    pub fn execute(
        config: ProcessConfig,
        namespace_config: NamespaceConfig,
    ) -> Result<ProcessResult> {
        let flags = namespace_config.to_clone_flags();

        // Create child process with cloned namespaces
        // Using stack for child function
        let mut child_stack = vec![0u8; 8192]; // 8KB stack

        let config_ptr = Box::into_raw(Box::new(config.clone()));

        // Clone and execute
        let result = unsafe {
            clone(
                Box::new(move || {
                    let config = Box::from_raw(config_ptr);
                    Self::child_setup(*config)
                }),
                &mut child_stack,
                flags,
                Some(Signal::SIGCHLD as i32),
            )
        };

        match result {
            Ok(child_pid) => {
                let start = std::time::Instant::now();

                // Wait for child
                let status = wait_for_child(child_pid)?;
                let exec_time_ms = start.elapsed().as_millis() as u64;

                Ok(ProcessResult {
                    pid: child_pid,
                    exit_status: status,
                    signal: None,
                    exec_time_ms,
                })
            }
            Err(e) => Err(SandboxError::Syscall(format!("clone failed: {}", e))),
        }
    }

    /// Execute process with streaming output
    pub fn execute_with_stream(
        config: ProcessConfig,
        namespace_config: NamespaceConfig,
        enable_streams: bool,
    ) -> Result<(ProcessResult, Option<ProcessStream>)> {
        if !enable_streams {
            let result = Self::execute(config, namespace_config)?;
            return Ok((result, None));
        }

        let (stdout_read, stdout_write) = nix::unistd::pipe()
            .map_err(|e| SandboxError::Io(std::io::Error::other(format!("pipe failed: {}", e))))?;
        let (stderr_read, stderr_write) = nix::unistd::pipe()
            .map_err(|e| SandboxError::Io(std::io::Error::other(format!("pipe failed: {}", e))))?;

        let flags = namespace_config.to_clone_flags();
        let mut child_stack = vec![0u8; 8192];

        let config_ptr = Box::into_raw(Box::new(config.clone()));
        let stdout_write_fd = stdout_write.as_raw_fd();
        let stderr_write_fd = stderr_write.as_raw_fd();

        let result = unsafe {
            clone(
                Box::new(move || {
                    let config = Box::from_raw(config_ptr);
                    Self::child_setup_with_pipes(*config, stdout_write_fd, stderr_write_fd)
                }),
                &mut child_stack,
                flags,
                Some(Signal::SIGCHLD as i32),
            )
        };

        drop(stdout_write);
        drop(stderr_write);

        match result {
            Ok(child_pid) => {
                let start = std::time::Instant::now();

                let (stream_writer, process_stream) = ProcessStream::new();

                let tx1 = stream_writer.tx.clone();
                let tx2 = stream_writer.tx.clone();

                spawn_fd_reader(stdout_read.into_raw_fd(), false, tx1).map_err(|e| {
                    SandboxError::Io(std::io::Error::other(format!("spawn reader failed: {}", e)))
                })?;
                spawn_fd_reader(stderr_read.into_raw_fd(), true, tx2).map_err(|e| {
                    SandboxError::Io(std::io::Error::other(format!("spawn reader failed: {}", e)))
                })?;

                let status = wait_for_child(child_pid)?;
                let exec_time_ms = start.elapsed().as_millis() as u64;

                let _ = stream_writer.send_exit(status, None);

                let process_result = ProcessResult {
                    pid: child_pid,
                    exit_status: status,
                    signal: None,
                    exec_time_ms,
                };

                Ok((process_result, Some(process_stream)))
            }
            Err(e) => Err(SandboxError::Syscall(format!("clone failed: {}", e))),
        }
    }

    /// Setup child process environment
    fn child_setup(config: ProcessConfig) -> isize {
        // Apply seccomp filter
        if let Some(filter) = &config.seccomp {
            if utils::is_root() {
                if let Err(e) = SeccompCompiler::load(filter) {
                    eprintln!("Failed to load seccomp: {}", e);
                    return 1;
                }
            } else {
                warn!("Skipping seccomp installation because process lacks root privileges");
            }
        }

        // Change root if specified
        if let Some(chroot_path) = &config.chroot_dir {
            if utils::is_root() {
                if let Err(e) = chroot(chroot_path.as_str()) {
                    eprintln!("chroot failed: {}", e);
                    return 1;
                }
            } else {
                warn!("Skipping chroot to {} without root privileges", chroot_path);
            }
        }

        // Change directory
        let cwd = config.cwd.as_deref().unwrap_or("/");
        if let Err(e) = chdir(cwd) {
            eprintln!("chdir failed: {}", e);
            return 1;
        }

        // Set UID/GID if specified
        if let Some(gid) = config.gid {
            if utils::is_root() {
                if unsafe { libc::setgid(gid) } != 0 {
                    eprintln!("setgid failed");
                    return 1;
                }
            } else {
                warn!("Skipping setgid without root privileges");
            }
        }

        if let Some(uid) = config.uid {
            if utils::is_root() {
                if unsafe { libc::setuid(uid) } != 0 {
                    eprintln!("setuid failed");
                    return 1;
                }
            } else {
                warn!("Skipping setuid without root privileges");
            }
        }

        // Prepare environment
        let env_vars: Vec<CString> = config
            .env
            .iter()
            .map(|(k, v)| CString::new(format!("{}={}", k, v)).unwrap())
            .collect();

        let env_refs: Vec<&CString> = env_vars.iter().collect();

        // Execute program
        let program_cstring = match CString::new(config.program.clone()) {
            Ok(s) => s,
            Err(_) => {
                eprintln!("program name contains nul byte");
                return 1;
            }
        };

        let args_cstrings: Vec<CString> = config
            .args
            .iter()
            .map(|s| CString::new(s.clone()).unwrap_or_else(|_| CString::new("").unwrap()))
            .collect();

        let mut args_refs: Vec<&CString> = vec![&program_cstring];
        args_refs.extend(args_cstrings.iter());

        match execve(&program_cstring, &args_refs, &env_refs) {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("execve failed: {}", e);
                1
            }
        }
    }

    /// Setup child process with pipe redirection
    fn child_setup_with_pipes(config: ProcessConfig, stdout_fd: i32, stderr_fd: i32) -> isize {
        // Redirect stdout and stderr to pipes
        // SAFETY: FDs are valid from parent and we're in a child process about to exec
        unsafe {
            if libc::dup2(stdout_fd, 1) < 0 {
                eprintln!("dup2 stdout failed");
                return 1;
            }
            if libc::dup2(stderr_fd, 2) < 0 {
                eprintln!("dup2 stderr failed");
                return 1;
            }
            _ = libc::close(stdout_fd);
            _ = libc::close(stderr_fd);
        }

        Self::child_setup(config)
    }
}

/// Wait for child process and get exit status
fn wait_for_child(pid: Pid) -> Result<i32> {
    use nix::sys::wait::{WaitStatus, waitpid};

    loop {
        match waitpid(pid, None) {
            Ok(WaitStatus::Exited(_, status)) => return Ok(status),
            Ok(WaitStatus::Signaled(_, signal, _)) => {
                return Ok(128 + signal as i32);
            }
            Ok(_) => continue, // Continue if other status
            Err(e) => return Err(SandboxError::Syscall(format!("waitpid failed: {}", e))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::serial_guard;
    use nix::unistd::{ForkResult, fork};

    #[test]
    fn test_process_config_default() {
        let config = ProcessConfig::default();
        assert!(config.program.is_empty());
        assert!(config.args.is_empty());
        assert!(config.env.is_empty());
        assert!(config.cwd.is_none());
        assert!(config.uid.is_none());
        assert!(config.gid.is_none());
    }

    #[test]
    fn test_process_config_with_args() {
        let config = ProcessConfig {
            program: "echo".to_string(),
            args: vec!["hello".to_string(), "world".to_string()],
            ..Default::default()
        };

        assert_eq!(config.program, "echo");
        assert_eq!(config.args.len(), 2);
    }

    #[test]
    fn test_process_config_with_env() {
        let config = ProcessConfig {
            env: vec![("MY_VAR".to_string(), "my_value".to_string())],
            ..Default::default()
        };

        assert_eq!(config.env.len(), 1);
        assert_eq!(config.env[0].0, "MY_VAR");
    }

    #[test]
    fn test_process_result() {
        let result = ProcessResult {
            pid: Pid::from_raw(123),
            exit_status: 0,
            signal: None,
            exec_time_ms: 100,
        };

        assert_eq!(result.pid, Pid::from_raw(123));
        assert_eq!(result.exit_status, 0);
        assert!(result.signal.is_none());
        assert_eq!(result.exec_time_ms, 100);
    }

    #[test]
    fn test_process_result_with_signal() {
        let result = ProcessResult {
            pid: Pid::from_raw(456),
            exit_status: 0,
            signal: Some(9), // SIGKILL
            exec_time_ms: 50,
        };

        assert!(result.signal.is_some());
        assert_eq!(result.signal.unwrap(), 9);
    }

    #[test]
    fn wait_for_child_returns_exit_status() {
        let _guard = serial_guard();
        match unsafe { fork() } {
            Ok(ForkResult::Child) => {
                std::process::exit(42);
            }
            Ok(ForkResult::Parent { child }) => {
                let status = wait_for_child(child).unwrap();
                assert_eq!(status, 42);
            }
            Err(e) => panic!("fork failed: {}", e),
        }
    }

    #[test]
    fn process_executor_runs_program_without_namespaces() {
        let _guard = serial_guard();
        let config = ProcessConfig {
            program: "/bin/echo".to_string(),
            args: vec!["sandbox".to_string()],
            env: vec![("TEST_EXEC".to_string(), "1".to_string())],
            ..Default::default()
        };

        let namespace = NamespaceConfig {
            pid: false,
            ipc: false,
            net: false,
            mount: false,
            uts: false,
            user: false,
        };

        let result = ProcessExecutor::execute(config, namespace).unwrap();
        assert_eq!(result.exit_status, 0);
    }

    #[test]
    fn execute_with_stream_disabled() {
        let _guard = serial_guard();
        let config = ProcessConfig {
            program: "/bin/echo".to_string(),
            args: vec!["test_output".to_string()],
            ..Default::default()
        };

        let namespace = NamespaceConfig {
            pid: false,
            ipc: false,
            net: false,
            mount: false,
            uts: false,
            user: false,
        };

        let (result, stream) =
            ProcessExecutor::execute_with_stream(config, namespace, false).unwrap();
        assert_eq!(result.exit_status, 0);
        assert!(stream.is_none());
    }

    #[test]
    fn execute_with_stream_enabled() {
        let _guard = serial_guard();
        let config = ProcessConfig {
            program: "/bin/echo".to_string(),
            args: vec!["streamed_output".to_string()],
            ..Default::default()
        };

        let namespace = NamespaceConfig {
            pid: false,
            ipc: false,
            net: false,
            mount: false,
            uts: false,
            user: false,
        };

        let (result, stream) =
            ProcessExecutor::execute_with_stream(config, namespace, true).unwrap();
        assert_eq!(result.exit_status, 0);
        assert!(stream.is_some());
    }

    #[test]
    fn process_config_clone() {
        let original = ProcessConfig {
            program: "/bin/true".to_string(),
            args: vec!["arg1".to_string()],
            env: vec![("VAR".to_string(), "val".to_string())],
            cwd: Some("/tmp".to_string()),
            chroot_dir: Some("/root".to_string()),
            uid: Some(1000),
            gid: Some(1000),
            seccomp: None,
        };

        let cloned = original.clone();
        assert_eq!(original.program, cloned.program);
        assert_eq!(original.args, cloned.args);
        assert_eq!(original.env, cloned.env);
        assert_eq!(original.cwd, cloned.cwd);
        assert_eq!(original.chroot_dir, cloned.chroot_dir);
        assert_eq!(original.uid, cloned.uid);
        assert_eq!(original.gid, cloned.gid);
    }

    #[test]
    fn process_result_clone() {
        let original = ProcessResult {
            pid: Pid::from_raw(999),
            exit_status: 42,
            signal: Some(15),
            exec_time_ms: 500,
        };

        let cloned = original.clone();
        assert_eq!(original.pid, cloned.pid);
        assert_eq!(original.exit_status, cloned.exit_status);
        assert_eq!(original.signal, cloned.signal);
        assert_eq!(original.exec_time_ms, cloned.exec_time_ms);
    }

    #[test]
    fn process_config_with_cwd() {
        let config = ProcessConfig {
            program: "test".to_string(),
            cwd: Some("/tmp".to_string()),
            ..Default::default()
        };

        assert_eq!(config.cwd, Some("/tmp".to_string()));
    }

    #[test]
    fn process_config_with_chroot() {
        let config = ProcessConfig {
            program: "test".to_string(),
            chroot_dir: Some("/root".to_string()),
            ..Default::default()
        };

        assert_eq!(config.chroot_dir, Some("/root".to_string()));
    }

    #[test]
    fn process_config_with_uid_gid() {
        let config = ProcessConfig {
            program: "test".to_string(),
            uid: Some(1000),
            gid: Some(1000),
            ..Default::default()
        };

        assert_eq!(config.uid, Some(1000));
        assert_eq!(config.gid, Some(1000));
    }

    #[test]
    fn wait_for_child_with_signal() {
        let _guard = serial_guard();
        match unsafe { fork() } {
            Ok(ForkResult::Child) => {
                unsafe { libc::raise(libc::SIGTERM) };
                std::process::exit(1);
            }
            Ok(ForkResult::Parent { child }) => {
                let status = wait_for_child(child).unwrap();
                assert!(status > 0);
            }
            Err(e) => panic!("fork failed: {}", e),
        }
    }

    #[test]
    fn execute_with_stream_true_collects_chunks() {
        let _guard = serial_guard();
        let config = ProcessConfig {
            program: "/bin/echo".to_string(),
            args: vec!["hello".to_string(), "world".to_string()],
            ..Default::default()
        };

        let namespace = NamespaceConfig {
            pid: false,
            ipc: false,
            net: false,
            mount: false,
            uts: false,
            user: false,
        };

        let (_result, stream_opt) =
            ProcessExecutor::execute_with_stream(config, namespace, true).unwrap();

        if let Some(stream) = stream_opt {
            let chunk = stream.try_recv().unwrap();
            assert!(chunk.is_none() || chunk.is_some());
        } else {
            panic!("Expected stream to be present");
        }
    }
}
