//! setrlimit-based resource limits (no privileges needed)
//!
//! Provides process resource limits using setrlimit/prlimit64.
//! This is the fallback when cgroups are not available.

use sandbox_core::{Result, SandboxError};

/// Resource limits via setrlimit (unprivileged fallback)
#[derive(Debug, Clone, Default)]
pub struct RlimitConfig {
    /// Maximum address space size in bytes (RLIMIT_AS)
    pub max_memory: Option<u64>,
    /// Maximum CPU time in seconds (RLIMIT_CPU)
    pub max_cpu_seconds: Option<u64>,
    /// Maximum number of processes (RLIMIT_NPROC)
    pub max_processes: Option<u64>,
    /// Maximum file size in bytes (RLIMIT_FSIZE)
    pub max_file_size: Option<u64>,
    /// Maximum number of open files (RLIMIT_NOFILE)
    pub max_open_files: Option<u64>,
}

impl RlimitConfig {
    /// Apply resource limits to the current process.
    /// This should be called in the child process after fork/clone.
    pub fn apply(&self) -> Result<()> {
        if let Some(mem) = self.max_memory {
            set_rlimit(libc::RLIMIT_AS, mem)?;
        }
        if let Some(cpu) = self.max_cpu_seconds {
            set_rlimit(libc::RLIMIT_CPU, cpu)?;
        }
        if let Some(nproc) = self.max_processes {
            set_rlimit(libc::RLIMIT_NPROC, nproc)?;
        }
        if let Some(fsize) = self.max_file_size {
            set_rlimit(libc::RLIMIT_FSIZE, fsize)?;
        }
        if let Some(nofile) = self.max_open_files {
            set_rlimit(libc::RLIMIT_NOFILE, nofile)?;
        }
        Ok(())
    }
}

fn set_rlimit(resource: libc::__rlimit_resource_t, limit: u64) -> Result<()> {
    let rlim = libc::rlimit {
        rlim_cur: limit,
        rlim_max: limit,
    };

    let ret = unsafe { libc::setrlimit(resource, &rlim) };
    if ret != 0 {
        let resource_name = match resource {
            libc::RLIMIT_AS => "RLIMIT_AS",
            libc::RLIMIT_CPU => "RLIMIT_CPU",
            libc::RLIMIT_NPROC => "RLIMIT_NPROC",
            libc::RLIMIT_FSIZE => "RLIMIT_FSIZE",
            libc::RLIMIT_NOFILE => "RLIMIT_NOFILE",
            _ => "UNKNOWN",
        };
        return Err(SandboxError::Syscall(format!(
            "setrlimit({}) failed: {}",
            resource_name,
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rlimit_config_default() {
        let config = RlimitConfig::default();
        assert!(config.max_memory.is_none());
        assert!(config.max_cpu_seconds.is_none());
    }

    #[test]
    fn test_empty_config_apply_succeeds() {
        let config = RlimitConfig::default();
        assert!(config.apply().is_ok());
    }
}
