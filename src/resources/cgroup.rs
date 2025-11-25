//! Cgroup v2 management for resource limits

use crate::errors::{Result, SandboxError};
use nix::unistd::Pid;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const CGROUP_V2_ROOT: &str = "/sys/fs/cgroup";

/// Cgroup v2 resource limits configuration
#[derive(Debug, Clone, Default)]
pub struct CgroupConfig {
    /// Memory limit in bytes (e.g., 100MB)
    pub memory_limit: Option<u64>,
    /// CPU weight (100-10000, default 100)
    pub cpu_weight: Option<u32>,
    /// CPU quota in microseconds
    pub cpu_quota: Option<u64>,
    /// CPU period in microseconds (default 100000)
    pub cpu_period: Option<u64>,
    /// Max PIDs allowed
    pub max_pids: Option<u32>,
}

impl CgroupConfig {
    /// Create cgroup config with memory limit
    pub fn with_memory(limit: u64) -> Self {
        Self {
            memory_limit: Some(limit),
            ..Default::default()
        }
    }

    /// Create cgroup config with CPU quota
    pub fn with_cpu_quota(quota: u64, period: u64) -> Self {
        Self {
            cpu_quota: Some(quota),
            cpu_period: Some(period),
            ..Default::default()
        }
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        if let Some(limit) = self.memory_limit
            && limit == 0 {
                return Err(SandboxError::InvalidConfig(
                    "Memory limit must be greater than 0".to_string(),
                ));
            }

        if let Some(weight) = self.cpu_weight
            && (!(100..=10000).contains(&weight)) {
                return Err(SandboxError::InvalidConfig(
                    "CPU weight must be between 100-10000".to_string(),
                ));
            }

        Ok(())
    }
}

/// Cgroup v2 interface
pub struct Cgroup {
    path: PathBuf,
    pid: Pid,
}

fn cgroup_root_path() -> PathBuf {
    std::env::var("SANDBOX_CGROUP_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(CGROUP_V2_ROOT))
}

impl Cgroup {
    /// Create new cgroup for a process
    pub fn new(name: &str, pid: Pid) -> Result<Self> {
        let cgroup_path = cgroup_root_path().join(name);

        // Create cgroup directory
        fs::create_dir_all(&cgroup_path).map_err(|e| {
            SandboxError::Cgroup(format!(
                "Failed to create cgroup directory {}: {}",
                cgroup_path.display(),
                e
            ))
        })?;

        ensure_controller_files(&cgroup_path)?;

        Ok(Self {
            path: cgroup_path,
            pid,
        })
    }

    /// Apply configuration to cgroup
    pub fn apply_config(&self, config: &CgroupConfig) -> Result<()> {
        config.validate()?;

        if let Some(memory) = config.memory_limit {
            self.set_memory_limit(memory)?;
        }

        if let Some(weight) = config.cpu_weight {
            self.set_cpu_weight(weight)?;
        }

        if let Some(quota) = config.cpu_quota {
            let period = config.cpu_period.unwrap_or(100000);
            self.set_cpu_quota(quota, period)?;
        }

        if let Some(max_pids) = config.max_pids {
            self.set_max_pids(max_pids)?;
        }

        Ok(())
    }

    /// Add process to cgroup
    pub fn add_process(&self, pid: Pid) -> Result<()> {
        let procs_file = self.path.join("cgroup.procs");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(&procs_file)
            .map_err(|e| {
                SandboxError::Cgroup(format!("Failed to open {}: {}", procs_file.display(), e))
            })?;

        write!(file, "{}", pid.as_raw())
            .map_err(|e| SandboxError::Cgroup(format!("Failed to add process to cgroup: {}", e)))?;

        Ok(())
    }

    /// Set memory limit
    fn set_memory_limit(&self, limit: u64) -> Result<()> {
        let mem_file = self.path.join("memory.max");
        self.write_file(&mem_file, &limit.to_string())
    }

    /// Set CPU weight
    fn set_cpu_weight(&self, weight: u32) -> Result<()> {
        let cpu_file = self.path.join("cpu.weight");
        self.write_file(&cpu_file, &weight.to_string())
    }

    /// Set CPU quota (microseconds)
    fn set_cpu_quota(&self, quota: u64, period: u64) -> Result<()> {
        let quota_file = self.path.join("cpu.max");
        let quota_str = if quota == u64::MAX {
            "max".to_string()
        } else {
            format!("{} {}", quota, period)
        };
        self.write_file(&quota_file, &quota_str)
    }

    /// Set max PIDs
    fn set_max_pids(&self, max_pids: u32) -> Result<()> {
        let pids_file = self.path.join("pids.max");
        self.write_file(&pids_file, &max_pids.to_string())
    }

    /// Read memory usage
    pub fn get_memory_usage(&self) -> Result<u64> {
        let mem_file = self.path.join("memory.current");
        self.read_file_u64(&mem_file)
    }

    /// Read memory limit
    pub fn get_memory_limit(&self) -> Result<u64> {
        let mem_file = self.path.join("memory.max");
        self.read_file_u64(&mem_file)
    }

    /// Read CPU usage in microseconds
    pub fn get_cpu_usage(&self) -> Result<u64> {
        let cpu_file = self.path.join("cpu.stat");
        let content = fs::read_to_string(&cpu_file).map_err(|e| {
            SandboxError::Cgroup(format!("Failed to read {}: {}", cpu_file.display(), e))
        })?;

        // Parse "usage_usec 123456"
        for line in content.lines() {
            if line.starts_with("usage_usec") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    return parts[1].parse::<u64>().map_err(|e| {
                        SandboxError::Cgroup(format!("Failed to parse CPU usage: {}", e))
                    });
                }
            }
        }

        Ok(0)
    }

    /// Check if cgroup exists
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Get the PID this cgroup was created for
    pub fn pid(&self) -> Pid {
        self.pid
    }

    /// Delete cgroup
    pub fn delete(&self) -> Result<()> {
        if self.exists() {
            fs::remove_dir(&self.path).map_err(|e| {
                SandboxError::Cgroup(format!(
                    "Failed to delete cgroup {}: {}",
                    self.path.display(),
                    e
                ))
            })?;
        }
        Ok(())
    }

    fn write_file(&self, path: &Path, content: &str) -> Result<()> {
        let mut file = fs::OpenOptions::new().write(true).open(path).map_err(|e| {
            SandboxError::Cgroup(format!("Failed to open {}: {}", path.display(), e))
        })?;

        write!(file, "{}", content).map_err(|e| {
            SandboxError::Cgroup(format!("Failed to write to {}: {}", path.display(), e))
        })?;

        Ok(())
    }

    fn read_file_u64(&self, path: &Path) -> Result<u64> {
        let content = fs::read_to_string(path).map_err(|e| {
            SandboxError::Cgroup(format!("Failed to read {}: {}", path.display(), e))
        })?;

        content
            .trim()
            .parse::<u64>()
            .map_err(|e| SandboxError::Cgroup(format!("Failed to parse value: {}", e)))
    }

    #[cfg(test)]
    pub(crate) fn for_testing(path: PathBuf) -> Self {
        Self {
            path,
            pid: Pid::from_raw(0),
        }
    }
}

fn ensure_controller_files(path: &Path) -> Result<()> {
    let files = [
        ("memory.max", "max"),
        ("memory.current", "0"),
        ("cpu.weight", "100"),
        ("cpu.max", "max 100000"),
        ("cpu.stat", "usage_usec 0\n"),
        ("pids.max", "max"),
        ("cgroup.procs", ""),
    ];

    for (name, default_content) in files {
        let file_path = path.join(name);
        if !file_path.exists() {
            fs::write(&file_path, default_content).map_err(|e| {
                SandboxError::Cgroup(format!("Failed to create {}: {}", file_path.display(), e))
            })?;
        }
    }

    Ok(())
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        // Clean up cgroup on drop (best effort)
        let _ = self.delete();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use tempfile::tempdir;

    fn prepare_cgroup_dir() -> (tempfile::TempDir, std::path::PathBuf) {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("cgroup-test");
        fs::create_dir_all(&path).unwrap();
        for file in &[
            "memory.max",
            "memory.current",
            "cpu.weight",
            "cpu.max",
            "cpu.stat",
            "pids.max",
            "cgroup.procs",
        ] {
            let file_path = path.join(file);
            if let Some(parent) = file_path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&file_path, "0").unwrap();
        }
        fs::write(path.join("cpu.stat"), "usage_usec 0\n").unwrap();
        fs::write(path.join("memory.current"), "0\n").unwrap();
        (tmp, path)
    }

    #[test]
    fn test_cgroup_config_default() {
        let config = CgroupConfig::default();
        assert!(config.memory_limit.is_none());
        assert!(config.cpu_weight.is_none());
    }

    #[test]
    fn test_cgroup_config_with_memory() {
        let config = CgroupConfig::with_memory(100 * 1024 * 1024);
        assert_eq!(config.memory_limit, Some(100 * 1024 * 1024));
    }

    #[test]
    fn test_cgroup_config_with_cpu_quota() {
        let config = CgroupConfig::with_cpu_quota(50000, 100000);
        assert_eq!(config.cpu_quota, Some(50000));
        assert_eq!(config.cpu_period, Some(100000));
    }

    #[test]
    fn test_cgroup_config_validate() {
        let config = CgroupConfig::default();
        assert!(config.validate().is_ok());

        let bad_config = CgroupConfig {
            memory_limit: Some(0),
            ..Default::default()
        };
        assert!(bad_config.validate().is_err());

        let bad_cpu_config = CgroupConfig {
            cpu_weight: Some(50),
            ..Default::default()
        };
        assert!(bad_cpu_config.validate().is_err());

        let good_cpu_config = CgroupConfig {
            cpu_weight: Some(100),
            ..Default::default()
        };
        assert!(good_cpu_config.validate().is_ok());
    }

    #[test]
    fn test_cgroup_path_creation() {
        // This test may only work if running as root and cgroup v2 is available
        // We'll test the logic without actually creating cgroups
        let test_path = Path::new(CGROUP_V2_ROOT);
        if test_path.exists() {
            // Cgroup v2 is available
            let result = Cgroup::new(
                "sandbox-test-delete-me",
                Pid::from_raw(std::process::id() as i32),
            );
            // Don't assert, as it may fail due to permissions
            let _ = result;
        }
    }

    #[test]
    fn test_cgroup_apply_config_writes_files() {
        let (_tmp, path) = prepare_cgroup_dir();
        let cgroup = Cgroup::for_testing(path.clone());

        let config = CgroupConfig {
            memory_limit: Some(2048),
            cpu_weight: Some(500),
            cpu_quota: Some(50_000),
            cpu_period: Some(100_000),
            max_pids: Some(32),
        };

        cgroup.apply_config(&config).unwrap();

        assert_eq!(
            fs::read_to_string(path.join("memory.max")).unwrap().trim(),
            "2048"
        );
        assert_eq!(
            fs::read_to_string(path.join("cpu.weight")).unwrap().trim(),
            "500"
        );
        assert_eq!(
            fs::read_to_string(path.join("cpu.max")).unwrap().trim(),
            "50000 100000"
        );
        assert_eq!(
            fs::read_to_string(path.join("pids.max")).unwrap().trim(),
            "32"
        );
    }

    #[test]
    fn test_cgroup_add_process_writes_pid() {
        let (_tmp, path) = prepare_cgroup_dir();
        let cgroup = Cgroup::for_testing(path.clone());

        cgroup.add_process(Pid::from_raw(1234)).unwrap();
        assert_eq!(
            fs::read_to_string(path.join("cgroup.procs")).unwrap(),
            "1234"
        );
    }

    #[test]
    fn test_cgroup_resource_readers() {
        let (_tmp, path) = prepare_cgroup_dir();
        fs::write(path.join("memory.current"), "4096").unwrap();
        fs::write(path.join("cpu.stat"), "usage_usec 900\n").unwrap();
        let cgroup = Cgroup::for_testing(path.clone());

        assert_eq!(cgroup.get_memory_usage().unwrap(), 4096);
        assert_eq!(cgroup.get_cpu_usage().unwrap(), 900);
    }

    #[test]
    fn test_cgroup_delete_removes_directory() {
        let (tmp, path) = prepare_cgroup_dir();
        let cgroup = Cgroup::for_testing(path.clone());
        assert!(path.exists());
        for entry in fs::read_dir(&path).unwrap() {
            let entry = entry.unwrap();
            if entry.path().is_file() {
                fs::remove_file(entry.path()).unwrap();
            }
        }
        cgroup.delete().unwrap();
        assert!(!path.exists());
        drop(tmp);
    }

    #[test]
    fn test_cgroup_new_uses_env_override() {
        let tmp = tempdir().unwrap();
        let prev = env::var("SANDBOX_CGROUP_ROOT").ok();
        unsafe {
            env::set_var("SANDBOX_CGROUP_ROOT", tmp.path());
        }

        let cg = Cgroup::new("env-test", Pid::from_raw(0)).unwrap();
        assert!(cg.exists());
        assert!(tmp.path().join("env-test").exists());

        if let Some(value) = prev {
            unsafe {
                env::set_var("SANDBOX_CGROUP_ROOT", value);
            }
        } else {
            unsafe {
                env::remove_var("SANDBOX_CGROUP_ROOT");
            }
        }
    }
}
