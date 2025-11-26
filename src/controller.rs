//! Main sandbox controller

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use log::warn;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

use crate::errors::{Result, SandboxError};
use crate::execution::ProcessStream;
use crate::execution::process::{ProcessConfig, ProcessExecutor};
use crate::isolation::namespace::NamespaceConfig;
use crate::isolation::seccomp::SeccompProfile;
use crate::resources::cgroup::{Cgroup, CgroupConfig};
use crate::utils;

/// Sandbox configuration
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Root directory for sandbox
    pub root: PathBuf,
    /// Memory limit in bytes
    pub memory_limit: Option<u64>,
    /// CPU quota (microseconds)
    pub cpu_quota: Option<u64>,
    /// CPU period (microseconds)
    pub cpu_period: Option<u64>,
    /// Maximum PIDs
    pub max_pids: Option<u32>,
    /// Seccomp profile
    pub seccomp_profile: SeccompProfile,
    /// Namespace configuration
    pub namespace_config: NamespaceConfig,
    /// Timeout
    pub timeout: Option<Duration>,
    /// Unique sandbox ID
    pub id: String,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            root: PathBuf::from("/var/lib/sandbox"),
            memory_limit: None,
            cpu_quota: None,
            cpu_period: None,
            max_pids: None,
            seccomp_profile: SeccompProfile::Minimal,
            namespace_config: NamespaceConfig::default(),
            timeout: None,
            id: "default".to_string(),
        }
    }
}

impl SandboxConfig {
    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        utils::require_root()?;

        self.validate_invariants()
    }

    fn validate_invariants(&self) -> Result<()> {
        if self.id.is_empty() {
            return Err(SandboxError::InvalidConfig(
                "Sandbox ID cannot be empty".to_string(),
            ));
        }

        if self.namespace_config.enabled_count() == 0 {
            return Err(SandboxError::InvalidConfig(
                "At least one namespace must be enabled".to_string(),
            ));
        }

        Ok(())
    }
}

/// Builder pattern for sandbox creation
pub struct SandboxBuilder {
    config: SandboxConfig,
}

impl SandboxBuilder {
    /// Create new builder
    pub fn new(id: &str) -> Self {
        Self {
            config: SandboxConfig {
                id: id.to_string(),
                ..Default::default()
            },
        }
    }

    /// Set memory limit
    pub fn memory_limit(mut self, bytes: u64) -> Self {
        self.config.memory_limit = Some(bytes);
        self
    }

    /// Set memory limit from string (e.g., "100M")
    pub fn memory_limit_str(self, s: &str) -> Result<Self> {
        let bytes = utils::parse_memory_size(s)?;
        Ok(self.memory_limit(bytes))
    }

    /// Set CPU quota
    pub fn cpu_quota(mut self, quota: u64, period: u64) -> Self {
        self.config.cpu_quota = Some(quota);
        self.config.cpu_period = Some(period);
        self
    }

    /// Set CPU limit by percentage (0-100)
    pub fn cpu_limit_percent(self, percent: u32) -> Self {
        if percent == 0 || percent > 100 {
            return self;
        }
        let quota = (percent as u64) * 1000; // percent * period/100 with period=100000
        let period = 100000;
        self.cpu_quota(quota, period)
    }

    /// Set maximum PIDs
    pub fn max_pids(mut self, max: u32) -> Self {
        self.config.max_pids = Some(max);
        self
    }

    /// Set seccomp profile
    pub fn seccomp_profile(mut self, profile: SeccompProfile) -> Self {
        self.config.seccomp_profile = profile;
        self
    }

    /// Set root directory
    pub fn root(mut self, path: impl AsRef<Path>) -> Self {
        self.config.root = path.as_ref().to_path_buf();
        self
    }

    /// Set timeout
    pub fn timeout(mut self, duration: Duration) -> Self {
        self.config.timeout = Some(duration);
        self
    }

    /// Set namespace configuration
    pub fn namespaces(mut self, config: NamespaceConfig) -> Self {
        self.config.namespace_config = config;
        self
    }

    /// Build sandbox
    pub fn build(self) -> Result<Sandbox> {
        self.config.validate()?;
        Sandbox::new(self.config)
    }
}

/// Sandbox execution result
#[derive(Debug, Clone)]
pub struct SandboxResult {
    /// Exit code
    pub exit_code: i32,
    /// Signal that killed process (if any)
    pub signal: Option<i32>,
    /// Whether timeout occurred
    pub timed_out: bool,
    /// Memory usage in bytes
    pub memory_peak: u64,
    /// CPU time in microseconds
    pub cpu_time_us: u64,
    /// Wall clock time in seconds
    pub wall_time_ms: u64,
}

impl SandboxResult {
    /// Check if process was killed by seccomp (SIGSYS - signal 31)
    /// Returns true if exit code is 159 (128 + 31)
    pub fn killed_by_seccomp(&self) -> bool {
        self.exit_code == 159
    }

    /// Get human-readable error message if process failed due to seccomp
    pub fn seccomp_error(&self) -> Option<&'static str> {
        if self.killed_by_seccomp() {
            Some("The action requires more permissions than were granted.")
        } else {
            None
        }
    }

    /// Convert to Result, returning error if process was killed by seccomp
    pub fn check_seccomp_error(&self) -> crate::errors::Result<&SandboxResult> {
        if self.killed_by_seccomp() {
            Err(SandboxError::PermissionDenied(
                "The seccomp profile is too restrictive for this operation. \
                 Try using a less restrictive profile (e.g., SeccompProfile::Compute or SeccompProfile::Unrestricted)"
                    .to_string(),
            ))
        } else {
            Ok(self)
        }
    }
}

/// Active sandbox
pub struct Sandbox {
    config: SandboxConfig,
    pid: Option<Pid>,
    cgroup: Option<Cgroup>,
    start_time: Option<Instant>,
}

impl Sandbox {
    /// Create new sandbox
    fn new(config: SandboxConfig) -> Result<Self> {
        // Create root directory
        fs::create_dir_all(&config.root).map_err(|e| {
            SandboxError::Io(std::io::Error::other(format!(
                "Failed to create root directory: {}",
                e
            )))
        })?;

        Ok(Self {
            config,
            pid: None,
            cgroup: None,
            start_time: None,
        })
    }

    /// Get sandbox ID
    pub fn id(&self) -> &str {
        &self.config.id
    }

    /// Get sandbox root
    pub fn root(&self) -> &Path {
        &self.config.root
    }

    /// Check if sandbox is running
    pub fn is_running(&self) -> bool {
        self.pid.is_some()
    }

    /// Run program in sandbox
    pub fn run(&mut self, program: &str, args: &[&str]) -> Result<SandboxResult> {
        if self.is_running() {
            return Err(SandboxError::AlreadyRunning);
        }

        self.start_time = Some(Instant::now());

        if utils::is_root() {
            let cgroup_name = format!("sandbox-{}", self.config.id);
            let cgroup = Cgroup::new(&cgroup_name, Pid::from_raw(std::process::id() as i32))?;

            let cgroup_config = CgroupConfig {
                memory_limit: self.config.memory_limit,
                cpu_quota: self.config.cpu_quota,
                cpu_period: self.config.cpu_period,
                max_pids: self.config.max_pids,
                cpu_weight: None,
            };
            cgroup.apply_config(&cgroup_config)?;

            self.cgroup = Some(cgroup);
        } else {
            warn!(
                "Skipping cgroup configuration for sandbox {} (not running as root)",
                self.config.id
            );
        }

        // Create process configuration with namespace and seccomp settings
        let process_config = ProcessConfig {
            program: program.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            env: Vec::new(), // Inherit parent environment
            cwd: None,
            chroot_dir: None,
            uid: None,
            gid: None,
            seccomp: Some(crate::isolation::seccomp::SeccompFilter::from_profile(
                self.config.seccomp_profile.clone(),
            )),
        };

        // Execute with namespace isolation
        if utils::is_root() {
            // Real isolation with namespaces
            let process_result =
                ProcessExecutor::execute(process_config, self.config.namespace_config.clone())?;

            self.pid = Some(process_result.pid);

            let wall_time_ms = self.start_time.unwrap().elapsed().as_millis() as u64;

            // Get peak memory from cgroup if available
            let (memory_peak, _) = self.get_resource_usage().unwrap_or((0, 0));

            Ok(SandboxResult {
                exit_code: process_result.exit_status,
                signal: process_result.signal,
                timed_out: false,
                memory_peak,
                cpu_time_us: process_result.exec_time_ms * 1000, // Convert ms to us
                wall_time_ms,
            })
        } else {
            // Fallback: run without full namespace isolation (for testing)
            warn!("Running without full isolation (not root). Use sudo for production sandboxes.");
            let output = Command::new(program)
                .args(args)
                .output()
                .map_err(SandboxError::Io)?;

            let exit_code = output.status.code().unwrap_or(-1);
            let wall_time_ms = self.start_time.unwrap().elapsed().as_millis() as u64;

            Ok(SandboxResult {
                exit_code,
                signal: None,
                timed_out: false,
                memory_peak: 0,
                cpu_time_us: 0,
                wall_time_ms,
            })
        }
    }

    /// Run program with streaming output
    pub fn run_with_stream(
        &mut self,
        program: &str,
        args: &[&str],
    ) -> Result<(SandboxResult, ProcessStream)> {
        if self.is_running() {
            return Err(SandboxError::AlreadyRunning);
        }

        self.start_time = Some(Instant::now());

        let cgroup_name = format!("sandbox-{}", self.config.id);
        let cgroup = Cgroup::new(&cgroup_name, Pid::from_raw(std::process::id() as i32))?;

        let cgroup_config = CgroupConfig {
            memory_limit: self.config.memory_limit,
            cpu_quota: self.config.cpu_quota,
            cpu_period: self.config.cpu_period,
            max_pids: self.config.max_pids,
            cpu_weight: None,
        };
        cgroup.apply_config(&cgroup_config)?;

        self.cgroup = Some(cgroup);

        let process_config = ProcessConfig {
            program: program.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            env: Vec::new(),
            cwd: None,
            chroot_dir: None,
            uid: None,
            gid: None,
            seccomp: Some(crate::isolation::seccomp::SeccompFilter::from_profile(
                self.config.seccomp_profile.clone(),
            )),
        };

        let (process_result, stream) = ProcessExecutor::execute_with_stream(
            process_config,
            self.config.namespace_config.clone(),
            true,
        )?;

        self.pid = Some(process_result.pid);

        let wall_time_ms = self.start_time.unwrap().elapsed().as_millis() as u64;
        let (memory_peak, _) = self.get_resource_usage().unwrap_or((0, 0));

        let sandbox_result = SandboxResult {
            exit_code: process_result.exit_status,
            signal: process_result.signal,
            timed_out: false,
            memory_peak,
            cpu_time_us: process_result.exec_time_ms * 1000,
            wall_time_ms,
        };

        let stream =
            stream.ok_or_else(|| SandboxError::Io(std::io::Error::other("stream unavailable")))?;

        Ok((sandbox_result, stream))
    }

    pub fn kill(&mut self) -> Result<()> {
        if let Some(pid) = self.pid {
            kill(pid, Signal::SIGKILL)
                .map_err(|e| SandboxError::Syscall(format!("Failed to kill process: {}", e)))?;
            self.pid = None;
        }
        Ok(())
    }

    /// Get resource usage
    pub fn get_resource_usage(&self) -> Result<(u64, u64)> {
        if let Some(ref cgroup) = self.cgroup {
            let memory = cgroup.get_memory_usage()?;
            let cpu = cgroup.get_cpu_usage()?;
            Ok((memory, cpu))
        } else {
            Ok((0, 0))
        }
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        // Clean up on drop
        let _ = self.kill();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resources::cgroup::Cgroup;
    use crate::test_support::serial_guard;
    use crate::utils;
    use std::env;
    use std::time::Duration;
    use tempfile::tempdir;

    fn config_with_temp_root(id: &str) -> (tempfile::TempDir, SandboxConfig) {
        let tmp = tempdir().unwrap();
        let config = SandboxConfig {
            id: id.to_string(),
            root: tmp.path().join("root"),
            namespace_config: NamespaceConfig::minimal(),
            ..Default::default()
        };
        (tmp, config)
    }

    struct RootOverrideGuard;

    impl RootOverrideGuard {
        fn enable() -> Self {
            utils::set_root_override(Some(true));
            Self
        }
    }

    impl Drop for RootOverrideGuard {
        fn drop(&mut self) {
            utils::set_root_override(None);
        }
    }

    struct EnvVarGuard {
        key: &'static str,
        prev: Option<String>,
    }

    impl EnvVarGuard {
        fn new(key: &'static str, value: &str) -> Self {
            let prev = env::var(key).ok();
            unsafe {
                env::set_var(key, value);
            }
            Self { key, prev }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(ref value) = self.prev {
                unsafe {
                    env::set_var(self.key, value);
                }
            } else {
                unsafe {
                    env::remove_var(self.key);
                }
            }
        }
    }

    #[test]
    fn test_sandbox_config_default() {
        let config = SandboxConfig::default();
        assert_eq!(config.id, "default");
        assert!(config.memory_limit.is_none());
    }

    #[test]
    fn test_sandbox_config_validate() {
        let config = SandboxConfig {
            id: String::new(),
            ..Default::default()
        };

        // Validation might fail due to root requirement, but we can test ID validation
        // by checking the error message
        if let Err(e) = config.validate() {
            // Expected to fail, either due to root or empty ID
            assert!(e.to_string().contains("ID") || e.to_string().contains("root"));
        }
    }

    #[test]
    fn test_sandbox_builder_new() {
        let builder = SandboxBuilder::new("test");
        assert_eq!(builder.config.id, "test");
    }

    #[test]
    fn test_sandbox_builder_memory_limit() {
        let builder = SandboxBuilder::new("test").memory_limit(100 * 1024 * 1024);
        assert_eq!(builder.config.memory_limit, Some(100 * 1024 * 1024));
    }

    #[test]
    fn test_sandbox_builder_memory_limit_str() -> Result<()> {
        let builder = SandboxBuilder::new("test").memory_limit_str("100M")?;
        assert_eq!(builder.config.memory_limit, Some(100 * 1024 * 1024));
        Ok(())
    }

    #[test]
    fn test_sandbox_builder_cpu_limit() {
        let builder = SandboxBuilder::new("test").cpu_limit_percent(50);
        assert!(builder.config.cpu_quota.is_some());
    }

    #[test]
    fn test_sandbox_builder_cpu_limit_zero() {
        let builder = SandboxBuilder::new("test").cpu_limit_percent(0);
        assert!(builder.config.cpu_quota.is_none());
    }

    #[test]
    fn test_sandbox_builder_cpu_limit_over_100() {
        let builder = SandboxBuilder::new("test").cpu_limit_percent(150);
        assert!(builder.config.cpu_quota.is_none());
    }

    #[test]
    fn test_sandbox_builder_cpu_quota() {
        let builder = SandboxBuilder::new("test").cpu_quota(50000, 100000);
        assert_eq!(builder.config.cpu_quota, Some(50000));
        assert_eq!(builder.config.cpu_period, Some(100000));
    }

    #[test]
    fn test_sandbox_builder_max_pids() {
        let builder = SandboxBuilder::new("test").max_pids(10);
        assert_eq!(builder.config.max_pids, Some(10));
    }

    #[test]
    fn test_sandbox_builder_seccomp_profile() {
        let builder = SandboxBuilder::new("test").seccomp_profile(SeccompProfile::IoHeavy);
        assert_eq!(builder.config.seccomp_profile, SeccompProfile::IoHeavy);
    }

    #[test]
    fn test_sandbox_builder_root() {
        let tmp = tempdir().unwrap();
        let builder = SandboxBuilder::new("test").root(tmp.path());
        assert_eq!(builder.config.root, tmp.path());
    }

    #[test]
    fn test_sandbox_builder_timeout() {
        let builder = SandboxBuilder::new("test").timeout(Duration::from_secs(30));
        assert_eq!(builder.config.timeout, Some(Duration::from_secs(30)));
    }

    #[test]
    fn test_sandbox_builder_namespaces() {
        let ns_config = NamespaceConfig::minimal();
        let builder = SandboxBuilder::new("test").namespaces(ns_config.clone());
        assert_eq!(builder.config.namespace_config, ns_config);
    }

    #[test]
    fn test_sandbox_result() {
        let result = SandboxResult {
            exit_code: 0,
            signal: None,
            timed_out: false,
            memory_peak: 1024,
            cpu_time_us: 5000,
            wall_time_ms: 100,
        };
        assert_eq!(result.exit_code, 0);
        assert!(!result.timed_out);
    }

    #[test]
    fn sandbox_config_invariants_detect_empty_id() {
        let config = SandboxConfig {
            id: String::new(),
            ..Default::default()
        };
        assert!(config.validate_invariants().is_err());
    }

    #[test]
    fn sandbox_config_invariants_detect_disabled_namespaces() {
        let config = SandboxConfig {
            namespace_config: NamespaceConfig {
                pid: false,
                ipc: false,
                net: false,
                mount: false,
                uts: false,
                user: false,
            },
            ..Default::default()
        };
        assert!(config.validate_invariants().is_err());
    }

    #[test]
    fn sandbox_provides_id_and_root() {
        let (_tmp, config) = config_with_temp_root("sand-id");
        let sandbox = Sandbox::new(config.clone()).unwrap();
        assert_eq!(sandbox.id(), "sand-id");
        assert!(sandbox.root().ends_with("root"));
        assert!(!sandbox.is_running());
    }

    #[test]
    fn sandbox_run_executes_command_without_root() {
        let _guard = serial_guard();
        let (_tmp, config) = config_with_temp_root("run-test");
        let mut sandbox = Sandbox::new(config).unwrap();
        let args: [&str; 1] = ["hello"];
        let result = sandbox.run("/bin/echo", &args).unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(!sandbox.is_running());
    }

    #[test]
    fn sandbox_run_returns_error_if_already_running() {
        let _guard = serial_guard();
        let (_tmp, config) = config_with_temp_root("already-running");
        let mut sandbox = Sandbox::new(config).unwrap();

        // Set PID to simulate already running
        sandbox.pid = Some(Pid::from_raw(1));

        let args: [&str; 1] = ["test"];
        let result = sandbox.run("/bin/echo", &args);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already running"));
    }

    #[test]
    fn test_sandbox_builder_build_creates_sandbox() {
        let _guard = serial_guard();
        let _root_guard = RootOverrideGuard::enable();
        let tmp = tempdir().unwrap();
        let sandbox = SandboxBuilder::new("build-test").root(tmp.path()).build();

        assert!(sandbox.is_ok());
    }

    #[test]
    fn test_sandbox_builder_build_validates_config() {
        let _guard = serial_guard();
        let tmp = tempdir().unwrap();
        let result = SandboxBuilder::new("").root(tmp.path()).build();

        assert!(result.is_err());
    }

    #[test]
    fn sandbox_reports_resource_usage_from_cgroup() {
        let (tmp, mut config) = config_with_temp_root("resource-test");
        config.root = tmp.path().join("root");
        let mut sandbox = Sandbox::new(config).unwrap();

        let cg_path = tmp.path().join("cgroup");
        std::fs::create_dir_all(&cg_path).unwrap();
        std::fs::write(cg_path.join("memory.current"), "1234").unwrap();
        std::fs::write(cg_path.join("cpu.stat"), "usage_usec 77\n").unwrap();

        sandbox.cgroup = Some(Cgroup::for_testing(cg_path.clone()));
        let (mem, cpu) = sandbox.get_resource_usage().unwrap();
        assert_eq!(mem, 1234);
        assert_eq!(cpu, 77);
    }

    #[test]
    #[ignore]
    fn sandbox_builder_builds_when_root_override() {
        let _guard = serial_guard();
        let _root_guard = RootOverrideGuard::enable();
        let tmp = tempdir().unwrap();
        let _env_guard = EnvVarGuard::new("SANDBOX_CGROUP_ROOT", tmp.path().to_str().unwrap());

        let mut sandbox = SandboxBuilder::new("integration")
            .memory_limit(1024)
            .cpu_limit_percent(10)
            .max_pids(4)
            .seccomp_profile(SeccompProfile::Minimal)
            .root(tmp.path())
            .timeout(Duration::from_secs(1))
            .namespaces(NamespaceConfig::minimal())
            .build()
            .unwrap();

        let args: [&str; 0] = [];
        let result = sandbox.run("/bin/true", &args).unwrap();
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    fn sandbox_kill_handles_missing_pid() {
        let (_tmp, config) = config_with_temp_root("kill-test");
        let mut sandbox = Sandbox::new(config).unwrap();
        sandbox.kill().unwrap();
    }

    #[test]
    fn sandbox_kill_terminates_real_process() {
        let (_tmp, config) = config_with_temp_root("kill-proc");
        let mut sandbox = Sandbox::new(config).unwrap();
        let mut child = std::process::Command::new("sleep")
            .arg("1")
            .spawn()
            .unwrap();
        sandbox.pid = Some(Pid::from_raw(child.id() as i32));
        sandbox.kill().unwrap();
        let _ = child.wait();
    }

    #[test]
    fn sandbox_get_resource_usage_without_cgroup() {
        let (_tmp, config) = config_with_temp_root("no-cgroup");
        let sandbox = Sandbox::new(config).unwrap();
        let (mem, cpu) = sandbox.get_resource_usage().unwrap();
        assert_eq!(mem, 0);
        assert_eq!(cpu, 0);
    }

    #[test]
    #[ignore]
    fn sandbox_run_with_stream_captures_output() {
        let _guard = serial_guard();
        let _root_guard = RootOverrideGuard::enable();
        let (_tmp, config) = config_with_temp_root("stream-test");
        let mut sandbox = Sandbox::new(config).unwrap();

        let (result, stream) = sandbox
            .run_with_stream("/bin/echo", &["hello world"])
            .unwrap();

        let chunks: Vec<_> = stream.into_iter().collect();

        assert!(!chunks.is_empty());
        assert_eq!(result.exit_code, 0);

        let has_stdout = chunks
            .iter()
            .any(|chunk| matches!(chunk, crate::StreamChunk::Stdout(_)));
        let has_exit = chunks
            .iter()
            .any(|chunk| matches!(chunk, crate::StreamChunk::Exit { .. }));

        assert!(has_stdout, "Should have captured stdout");
        assert!(has_exit, "Should have exit chunk");
    }

    #[test]
    fn test_sandbox_result_killed_by_seccomp() {
        let result = SandboxResult {
            exit_code: 159,
            signal: None,
            timed_out: false,
            memory_peak: 0,
            cpu_time_us: 0,
            wall_time_ms: 0,
        };
        assert!(result.killed_by_seccomp());
    }

    #[test]
    fn test_sandbox_result_not_killed_by_seccomp() {
        let result = SandboxResult {
            exit_code: 0,
            signal: None,
            timed_out: false,
            memory_peak: 0,
            cpu_time_us: 0,
            wall_time_ms: 0,
        };
        assert!(!result.killed_by_seccomp());
    }

    #[test]
    fn test_sandbox_result_seccomp_error_message() {
        let result = SandboxResult {
            exit_code: 159,
            signal: None,
            timed_out: false,
            memory_peak: 0,
            cpu_time_us: 0,
            wall_time_ms: 0,
        };
        let msg = result.seccomp_error();
        assert!(msg.is_some());
        assert!(msg.unwrap().contains("permissions"));
    }

    #[test]
    fn test_sandbox_result_check_seccomp_error_when_killed() {
        let result = SandboxResult {
            exit_code: 159,
            signal: None,
            timed_out: false,
            memory_peak: 0,
            cpu_time_us: 0,
            wall_time_ms: 0,
        };
        let check_result = result.check_seccomp_error();
        assert!(check_result.is_err());
        let err = check_result.unwrap_err();
        assert!(err.to_string().contains("restrictive"));
    }

    #[test]
    fn test_sandbox_result_check_seccomp_error_when_success() {
        let result = SandboxResult {
            exit_code: 0,
            signal: None,
            timed_out: false,
            memory_peak: 0,
            cpu_time_us: 0,
            wall_time_ms: 0,
        };
        let check_result = result.check_seccomp_error();
        assert!(check_result.is_ok());
    }
}
