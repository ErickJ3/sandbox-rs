//! Landlock filesystem access control
//!
//! Provides unprivileged filesystem sandboxing via the Landlock LSM (Linux 5.13+).
//! This is the replacement for chroot which requires root.

use sandbox_core::{Result, SandboxError};
use std::path::PathBuf;

// Landlock ABI constants
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;

// Access rights for files
const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1;
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;

const ALL_ACCESS_FS: u64 = LANDLOCK_ACCESS_FS_EXECUTE
    | LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_READ_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SYM;

const READ_ACCESS: u64 = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
const WRITE_ACCESS: u64 = LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SYM;
const EXEC_ACCESS: u64 = LANDLOCK_ACCESS_FS_EXECUTE;

/// Landlock filesystem access configuration
#[derive(Debug, Clone, Default)]
pub struct LandlockConfig {
    /// Paths with read access
    pub read_paths: Vec<PathBuf>,
    /// Paths with write access
    pub write_paths: Vec<PathBuf>,
    /// Paths with execute access
    pub exec_paths: Vec<PathBuf>,
}

// Kernel structures for landlock syscalls
#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
}

#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

impl LandlockConfig {
    /// Check if landlock is available on this system
    pub fn is_available() -> bool {
        let ret = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<libc::c_void>(),
                0usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        if ret >= 0 {
            unsafe { libc::close(ret as i32); }
            return true;
        }
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        errno != libc::ENOSYS
    }

    /// Apply landlock restrictions to the current process.
    /// WARNING: This is irreversible for the current process.
    pub fn apply(&self) -> Result<()> {
        if !Self::is_available() {
            return Err(SandboxError::FeatureNotAvailable(
                "Landlock is not available on this kernel (requires Linux 5.13+)".to_string(),
            ));
        }

        // Create ruleset
        let attr = LandlockRulesetAttr {
            handled_access_fs: ALL_ACCESS_FS,
            handled_access_net: 0,
        };

        let ruleset_fd = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &attr as *const LandlockRulesetAttr,
                std::mem::size_of::<LandlockRulesetAttr>(),
                0u32,
            )
        };

        if ruleset_fd < 0 {
            return Err(SandboxError::Landlock(format!(
                "landlock_create_ruleset failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let ruleset_fd = ruleset_fd as i32;

        // Add rules for each path
        let result = self.add_all_rules(ruleset_fd);

        if result.is_err() {
            unsafe { libc::close(ruleset_fd); }
            return result;
        }

        // Enforce ruleset
        unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                libc::close(ruleset_fd);
                return Err(SandboxError::Landlock(format!(
                    "PR_SET_NO_NEW_PRIVS failed: {}",
                    std::io::Error::last_os_error()
                )));
            }

            let ret = libc::syscall(
                libc::SYS_landlock_restrict_self,
                ruleset_fd,
                0u32,
            );

            libc::close(ruleset_fd);

            if ret < 0 {
                return Err(SandboxError::Landlock(format!(
                    "landlock_restrict_self failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
        }

        Ok(())
    }

    fn add_all_rules(&self, ruleset_fd: i32) -> Result<()> {
        for path in &self.read_paths {
            self.add_path_rule(ruleset_fd, path, READ_ACCESS)?;
        }
        for path in &self.write_paths {
            self.add_path_rule(ruleset_fd, path, READ_ACCESS | WRITE_ACCESS)?;
        }
        for path in &self.exec_paths {
            self.add_path_rule(ruleset_fd, path, READ_ACCESS | EXEC_ACCESS)?;
        }
        Ok(())
    }

    fn add_path_rule(&self, ruleset_fd: i32, path: &PathBuf, access: u64) -> Result<()> {
        use std::os::unix::io::IntoRawFd;

        let file = std::fs::File::open(path).map_err(|e| {
            SandboxError::Landlock(format!(
                "Failed to open path for landlock rule {}: {}",
                path.display(), e
            ))
        })?;

        let fd = file.into_raw_fd();

        let attr = LandlockPathBeneathAttr {
            allowed_access: access,
            parent_fd: fd,
        };

        let ret = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset_fd,
                LANDLOCK_RULE_PATH_BENEATH,
                &attr as *const LandlockPathBeneathAttr,
                0u32,
            )
        };

        unsafe { libc::close(fd); }

        if ret < 0 {
            return Err(SandboxError::Landlock(format!(
                "landlock_add_rule failed for {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_landlock_config_default() {
        let config = LandlockConfig::default();
        assert!(config.read_paths.is_empty());
        assert!(config.write_paths.is_empty());
        assert!(config.exec_paths.is_empty());
    }

    #[test]
    fn test_landlock_availability_check() {
        // Just check it doesn't panic
        let _ = LandlockConfig::is_available();
    }
}
