//! Main sandbox controller with privilege mode support

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

use sandbox_cgroup::cgroup::{Cgroup, CgroupConfig};
use sandbox_cgroup::rlimit::RlimitConfig;
use sandbox_core::capabilities::SystemCapabilities;
use sandbox_core::privilege::{PrivilegeMode, ResolvedMode};
use sandbox_core::{Result, SandboxError};
use sandbox_namespace::NamespaceConfig;
use sandbox_seccomp::{SeccompFilter, SeccompProfile};

use crate::execution::ProcessStream;
use crate::execution::process::{ProcessConfig, ProcessExecutor};

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
    /// Privilege mode
    pub privilege_mode: PrivilegeMode,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            root: PathBuf::from("/tmp/sandbox"),
            memory_limit: None,
            cpu_quota: None,
            cpu_period: None,
            max_pids: None,
            seccomp_profile: SeccompProfile::Minimal,
            namespace_config: NamespaceConfig::default(),
            timeout: None,
            id: "default".to_string(),
            privilege_mode: PrivilegeMode::Auto,
        }
    }
}

impl SandboxConfig {
    /// Validate configuration (no longer requires root!)
    pub fn validate(&self) -> Result<()> {
        self.validate_invariants()?;

        let caps = SystemCapabilities::detect();
        let mode = self.privilege_mode.resolve(&caps);

        match mode {
            ResolvedMode::Privileged => {
                if !caps.has_root {
                    return Err(SandboxError::PermissionDenied(
                        "Privileged mode requires root privileges".to_string(),
                    ));
                }
            }
            ResolvedMode::Unprivileged => {
                if !caps.has_seccomp {
                    return Err(SandboxError::FeatureNotAvailable(
                        "Seccomp is required for unprivileged sandboxing".to_string(),
                    ));
                }
            }
        }

        Ok(())
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
        let bytes = sandbox_core::util::parse_memory_size(s)?;
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
        let quota = (percent as u64) * 1000;
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

    /// Set privilege mode
    pub fn privilege_mode(mut self, mode: PrivilegeMode) -> Self {
        self.config.privilege_mode = mode;
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
    /// Peak memory usage in bytes.
    /// Requires privileged mode (cgroups v2). Returns `0` in unprivileged mode.
    pub memory_peak: u64,
    /// CPU time in microseconds.
    /// Requires privileged mode (cgroups v2). Returns `0` in unprivileged mode.
    pub cpu_time_us: u64,
    /// Wall clock time in milliseconds
    pub wall_time_ms: u64,
}

impl SandboxResult {
    /// Check if process was killed by seccomp (SIGSYS - signal 31)
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
    pub fn check_seccomp_error(&self) -> Result<&SandboxResult> {
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
    resolved_mode: ResolvedMode,
    pid: Option<Pid>,
    cgroup: Option<Cgroup>,
    start_time: Option<Instant>,
}

impl Sandbox {
    /// Create new sandbox
    fn new(config: SandboxConfig) -> Result<Self> {
        let caps = SystemCapabilities::detect();
        let resolved_mode = config.privilege_mode.resolve(&caps);

        // Adjust namespace config based on resolved mode
        let mut config = config;
        if resolved_mode.is_unprivileged() && !config.namespace_config.user {
            // Force user namespace on for unprivileged mode
            config.namespace_config.user = true;
        }

        // Create root directory
        fs::create_dir_all(&config.root).map_err(|e| {
            SandboxError::Io(std::io::Error::other(format!(
                "Failed to create root directory: {}",
                e
            )))
        })?;

        Ok(Self {
            config,
            resolved_mode,
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

    /// Get the resolved privilege mode
    pub fn privilege_mode(&self) -> ResolvedMode {
        self.resolved_mode
    }

    /// Build a ProcessConfig from the sandbox configuration (shared setup)
    fn build_process_config(&self) -> ProcessConfig {
        ProcessConfig {
            program: String::new(), // filled in by caller
            args: Vec::new(),       // filled in by caller
            env: Vec::new(),
            cwd: None,
            chroot_dir: None,
            uid: None,
            gid: None,
            seccomp: Some(SeccompFilter::from_profile(
                self.config.seccomp_profile.clone(),
            )),
            rlimits: if self.resolved_mode.is_unprivileged() {
                Some(self.build_rlimit_config())
            } else {
                None
            },
            inherit_env: true,
            use_user_namespace: self.config.namespace_config.user,
        }
    }

    /// Build rlimit config from sandbox config (unprivileged fallback)
    ///
    /// Note: cpu_quota is a rate limit (microseconds per period) for cgroups,
    /// which has no rlimit equivalent. RLIMIT_CPU is a total CPU-seconds cap,
    /// so we derive it from the timeout instead.
    fn build_rlimit_config(&self) -> RlimitConfig {
        RlimitConfig {
            max_memory: self.config.memory_limit,
            max_cpu_seconds: self.config.timeout.map(|t| t.as_secs()),
            max_processes: self.config.max_pids.map(|p| p as u64),
            ..Default::default()
        }
    }

    /// Setup cgroup for privileged mode, returns memory/cpu usage reader
    fn setup_cgroup(&mut self) -> Result<()> {
        if self.resolved_mode.is_unprivileged() {
            return Ok(());
        }

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
        Ok(())
    }

    /// Run program in sandbox
    pub fn run(&mut self, program: &str, args: &[&str]) -> Result<SandboxResult> {
        if self.is_running() {
            return Err(SandboxError::AlreadyRunning);
        }

        self.start_time = Some(Instant::now());
        self.setup_cgroup()?;

        let mut process_config = self.build_process_config();
        process_config.program = program.to_string();
        process_config.args = args.iter().map(|s| s.to_string()).collect();

        let process_result =
            ProcessExecutor::execute(process_config, self.config.namespace_config.clone())?;

        self.pid = Some(process_result.pid);

        let wall_time_ms = self.start_time.unwrap().elapsed().as_millis() as u64;
        let (memory_peak, cpu_time_us) = self.get_resource_usage().unwrap_or((0, 0));

        Ok(SandboxResult {
            exit_code: process_result.exit_status,
            signal: process_result.signal,
            timed_out: false,
            memory_peak,
            cpu_time_us,
            wall_time_ms,
        })
    }

    /// Run program with streaming output.
    /// Returns (ProcessHandle, ProcessStream) - the handle provides the actual exit status.
    pub fn run_with_stream(
        &mut self,
        program: &str,
        args: &[&str],
    ) -> Result<(SandboxResult, ProcessStream)> {
        if self.is_running() {
            return Err(SandboxError::AlreadyRunning);
        }

        self.start_time = Some(Instant::now());
        self.setup_cgroup()?;

        let mut process_config = self.build_process_config();
        process_config.program = program.to_string();
        process_config.args = args.iter().map(|s| s.to_string()).collect();

        let (process_result, stream) = ProcessExecutor::execute_with_stream(
            process_config,
            self.config.namespace_config.clone(),
            true,
        )?;

        self.pid = Some(process_result.pid);

        let wall_time_ms = self.start_time.unwrap().elapsed().as_millis() as u64;
        let (memory_peak, cpu_time_us) = self.get_resource_usage().unwrap_or((0, 0));

        let sandbox_result = SandboxResult {
            exit_code: process_result.exit_status,
            signal: process_result.signal,
            timed_out: false,
            memory_peak,
            cpu_time_us,
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
            // In unprivileged mode without cgroups, we can't get precise usage
            Ok((0, 0))
        }
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = self.kill();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn test_sandbox_config_default() {
        let config = SandboxConfig::default();
        assert_eq!(config.id, "default");
        assert!(config.memory_limit.is_none());
        assert_eq!(config.privilege_mode, PrivilegeMode::Auto);
    }

    #[test]
    fn test_sandbox_config_validate_empty_id() {
        let config = SandboxConfig {
            id: String::new(),
            ..Default::default()
        };
        assert!(config.validate_invariants().is_err());
    }

    #[test]
    fn test_sandbox_config_validate_no_namespaces() {
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
    fn test_sandbox_builder_privilege_mode() {
        let builder = SandboxBuilder::new("test").privilege_mode(PrivilegeMode::Unprivileged);
        assert_eq!(builder.config.privilege_mode, PrivilegeMode::Unprivileged);
    }

    #[test]
    fn test_sandbox_builder_build_creates_sandbox() {
        let tmp = tempdir().unwrap();
        let sandbox = SandboxBuilder::new("build-test").root(tmp.path()).build();
        // Should succeed without root in Auto mode (falls back to unprivileged)
        assert!(sandbox.is_ok());
    }

    #[test]
    fn test_sandbox_builder_build_validates_config() {
        let tmp = tempdir().unwrap();
        let result = SandboxBuilder::new("").root(tmp.path()).build();
        assert!(result.is_err());
    }

    #[test]
    fn sandbox_provides_id_and_root() {
        let (_tmp, config) = config_with_temp_root("sand-id");
        let sandbox = Sandbox::new(config).unwrap();
        assert_eq!(sandbox.id(), "sand-id");
        assert!(sandbox.root().ends_with("root"));
        assert!(!sandbox.is_running());
    }

    #[test]
    fn sandbox_run_returns_error_if_already_running() {
        let (_tmp, config) = config_with_temp_root("already-running");
        let mut sandbox = Sandbox::new(config).unwrap();
        sandbox.pid = Some(Pid::from_raw(1));

        let args: [&str; 1] = ["test"];
        let result = sandbox.run("/bin/echo", &args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already running"));
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
    fn sandbox_get_resource_usage_without_cgroup_returns_zeros() {
        let (_tmp, config) = config_with_temp_root("no-cgroup");
        let sandbox = Sandbox::new(config).unwrap();
        // In unprivileged mode without cgroups, returns (0, 0) instead of error
        let result = sandbox.get_resource_usage();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), (0, 0));
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

        sandbox.cgroup = Some(Cgroup::for_testing(cg_path));
        let (mem, cpu) = sandbox.get_resource_usage().unwrap();
        assert_eq!(mem, 1234);
        assert_eq!(cpu, 77);
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
    fn test_sandbox_result_check_seccomp_error() {
        let result = SandboxResult {
            exit_code: 159,
            signal: None,
            timed_out: false,
            memory_peak: 0,
            cpu_time_us: 0,
            wall_time_ms: 0,
        };
        assert!(result.check_seccomp_error().is_err());

        let ok_result = SandboxResult {
            exit_code: 0,
            signal: None,
            timed_out: false,
            memory_peak: 0,
            cpu_time_us: 0,
            wall_time_ms: 0,
        };
        assert!(ok_result.check_seccomp_error().is_ok());
    }
}
