//! Cgroup v2 management for resource limits

use nix::unistd::Pid;
use sandbox_core::{Result, SandboxError};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const CGROUP_V2_ROOT: &str = "/sys/fs/cgroup";

/// Cgroup v2 resource limits configuration
#[derive(Debug, Clone, Default)]
pub struct CgroupConfig {
    pub memory_limit: Option<u64>,
    pub cpu_weight: Option<u32>,
    pub cpu_quota: Option<u64>,
    pub cpu_period: Option<u64>,
    pub max_pids: Option<u32>,
}

impl CgroupConfig {
    pub fn with_memory(limit: u64) -> Self {
        Self {
            memory_limit: Some(limit),
            ..Default::default()
        }
    }

    pub fn with_cpu_quota(quota: u64, period: u64) -> Self {
        Self {
            cpu_quota: Some(quota),
            cpu_period: Some(period),
            ..Default::default()
        }
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(limit) = self.memory_limit
            && limit == 0
        {
            return Err(SandboxError::InvalidConfig(
                "Memory limit must be greater than 0".to_string(),
            ));
        }
        if let Some(weight) = self.cpu_weight
            && (!(100..=10000).contains(&weight))
        {
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

/// Try to find a delegated cgroup for the current unprivileged user
pub fn find_delegated_cgroup() -> Option<PathBuf> {
    let uid = unsafe { libc::geteuid() };
    if uid == 0 {
        return Some(PathBuf::from(CGROUP_V2_ROOT));
    }

    let user_slice = format!("/sys/fs/cgroup/user.slice/user-{}.slice", uid);
    let path = PathBuf::from(&user_slice);

    if !path.exists() {
        return None;
    }

    // Check if we can write to the cgroup directory
    let test_path = path.join("sandbox-cgroup-probe");
    match std::fs::create_dir(&test_path) {
        Ok(()) => {
            let _ = std::fs::remove_dir(&test_path);
            Some(path)
        }
        Err(_) => None,
    }
}

impl Cgroup {
    pub fn new(name: &str, pid: Pid) -> Result<Self> {
        let cgroup_path = cgroup_root_path().join(name);
        fs::create_dir_all(&cgroup_path).map_err(|e| {
            SandboxError::Cgroup(format!(
                "Failed to create cgroup directory {}: {}",
                cgroup_path.display(),
                e
            ))
        })?;
        Ok(Self {
            path: cgroup_path,
            pid,
        })
    }

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

    pub fn add_process(&self, pid: Pid) -> Result<()> {
        let procs_file = self.path.join("cgroup.procs");
        self.write_file(&procs_file, &pid.as_raw().to_string())
    }

    fn set_memory_limit(&self, limit: u64) -> Result<()> {
        self.write_file(&self.path.join("memory.max"), &limit.to_string())
    }

    fn set_cpu_weight(&self, weight: u32) -> Result<()> {
        self.write_file(&self.path.join("cpu.weight"), &weight.to_string())
    }

    fn set_cpu_quota(&self, quota: u64, period: u64) -> Result<()> {
        let quota_str = if quota == u64::MAX {
            "max".to_string()
        } else {
            format!("{} {}", quota, period)
        };
        self.write_file(&self.path.join("cpu.max"), &quota_str)
    }

    fn set_max_pids(&self, max_pids: u32) -> Result<()> {
        self.write_file(&self.path.join("pids.max"), &max_pids.to_string())
    }

    pub fn get_memory_usage(&self) -> Result<u64> {
        self.read_file_u64(&self.path.join("memory.current"))
    }

    pub fn get_memory_limit(&self) -> Result<u64> {
        self.read_file_u64(&self.path.join("memory.max"))
    }

    pub fn get_cpu_usage(&self) -> Result<u64> {
        let cpu_file = self.path.join("cpu.stat");
        let content = fs::read_to_string(&cpu_file).map_err(|e| {
            SandboxError::Cgroup(format!("Failed to read {}: {}", cpu_file.display(), e))
        })?;
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

    pub fn exists(&self) -> bool {
        self.path.exists()
    }
    pub fn pid(&self) -> Pid {
        self.pid
    }

    pub fn delete(&self) -> Result<()> {
        match fs::remove_dir(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(SandboxError::Cgroup(format!(
                "Failed to delete cgroup {}: {}",
                self.path.display(),
                e
            ))),
        }
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

    /// Create a Cgroup backed by an arbitrary directory path (for testing)
    #[doc(hidden)]
    pub fn for_testing(path: PathBuf) -> Self {
        Self {
            path,
            pid: Pid::from_raw(0),
        }
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        let _ = self.delete();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn prepare_cgroup_dir() -> (tempfile::TempDir, PathBuf) {
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
            fs::write(path.join(file), "0").unwrap();
        }
        fs::write(path.join("cpu.stat"), "usage_usec 0\n").unwrap();
        fs::write(path.join("memory.current"), "0\n").unwrap();
        (tmp, path)
    }

    #[test]
    fn test_cgroup_config_default() {
        let config = CgroupConfig::default();
        assert!(config.memory_limit.is_none());
    }

    #[test]
    fn test_cgroup_config_validate() {
        assert!(CgroupConfig::default().validate().is_ok());
        assert!(
            CgroupConfig {
                memory_limit: Some(0),
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            CgroupConfig {
                cpu_weight: Some(50),
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            CgroupConfig {
                cpu_weight: Some(100),
                ..Default::default()
            }
            .validate()
            .is_ok()
        );
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
    fn test_cgroup_resource_readers() {
        let (_tmp, path) = prepare_cgroup_dir();
        fs::write(path.join("memory.current"), "4096").unwrap();
        fs::write(path.join("cpu.stat"), "usage_usec 900\n").unwrap();
        let cgroup = Cgroup::for_testing(path);
        assert_eq!(cgroup.get_memory_usage().unwrap(), 4096);
        assert_eq!(cgroup.get_cpu_usage().unwrap(), 900);
    }
}
