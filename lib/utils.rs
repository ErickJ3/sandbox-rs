//! Utility functions for sandbox operations

use crate::errors::{Result, SandboxError};
#[cfg(test)]
use std::cell::Cell;
use std::path::Path;

#[cfg(test)]
thread_local! {
    static ROOT_OVERRIDE: Cell<Option<bool>> = const { Cell::new(None) };
}

/// Check if running as root
pub fn is_root() -> bool {
    #[cfg(test)]
    {
        if let Some(value) = ROOT_OVERRIDE.with(|cell| cell.get()) {
            return value;
        }
    }

    unsafe { libc::geteuid() == 0 }
}

/// Get current UID
pub fn get_uid() -> u32 {
    unsafe { libc::geteuid() }
}

/// Get current GID
pub fn get_gid() -> u32 {
    unsafe { libc::getegid() }
}

/// Ensure we have root privileges
pub fn require_root() -> Result<()> {
    if !is_root() {
        Err(SandboxError::PermissionDenied(
            "This operation requires root privileges".to_string(),
        ))
    } else {
        Ok(())
    }
}

/// Check if cgroup v2 is available
pub fn has_cgroup_v2() -> bool {
    Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
}

/// Check if a cgroup path exists
pub fn cgroup_exists(path: &Path) -> bool {
    path.exists()
}

/// Parse memory size string (e.g., "100M", "1G")
pub fn parse_memory_size(s: &str) -> Result<u64> {
    let s = s.trim().to_uppercase();

    let (num_str, multiplier) = if s.ends_with("G") {
        (&s[..s.len() - 1], 1024u64 * 1024 * 1024)
    } else if s.ends_with("M") {
        (&s[..s.len() - 1], 1024u64 * 1024)
    } else if s.ends_with("K") {
        (&s[..s.len() - 1], 1024u64)
    } else if s.ends_with("B") {
        (&s[..s.len() - 1], 1u64)
    } else {
        (s.as_str(), 1u64)
    };

    let num: u64 = num_str
        .parse()
        .map_err(|_| SandboxError::InvalidConfig(format!("Invalid memory size: {}", s)))?;

    num.checked_mul(multiplier)
        .ok_or_else(|| SandboxError::InvalidConfig(format!("Memory size overflow: {}", s)))
}

#[cfg(test)]
pub fn set_root_override(value: Option<bool>) {
    ROOT_OVERRIDE.with(|cell| cell.set(value));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_memory_size_bytes() {
        assert_eq!(parse_memory_size("100").unwrap(), 100);
        assert_eq!(parse_memory_size("100B").unwrap(), 100);
    }

    #[test]
    fn test_parse_memory_size_kilobytes() {
        assert_eq!(parse_memory_size("1K").unwrap(), 1024);
        assert_eq!(parse_memory_size("10K").unwrap(), 10 * 1024);
    }

    #[test]
    fn test_parse_memory_size_megabytes() {
        assert_eq!(parse_memory_size("1M").unwrap(), 1024 * 1024);
        assert_eq!(parse_memory_size("100M").unwrap(), 100 * 1024 * 1024);
    }

    #[test]
    fn test_parse_memory_size_gigabytes() {
        assert_eq!(parse_memory_size("1G").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_memory_size("2G").unwrap(), 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn test_parse_memory_size_case_insensitive() {
        assert_eq!(parse_memory_size("1m").unwrap(), 1024 * 1024);
        assert_eq!(parse_memory_size("1g").unwrap(), 1024 * 1024 * 1024);
    }

    #[test]
    fn test_parse_memory_size_whitespace() {
        assert_eq!(parse_memory_size("  100M  ").unwrap(), 100 * 1024 * 1024);
    }

    #[test]
    fn test_parse_memory_size_invalid() {
        assert!(parse_memory_size("not_a_number").is_err());
        assert!(parse_memory_size("10X").is_err());
    }

    #[test]
    fn test_get_uid_gid() {
        let uid = get_uid();
        let gid = get_gid();
        assert!(uid < u32::MAX);
        assert!(gid < u32::MAX);
    }

    #[test]
    fn test_is_root() {
        let is_root = is_root();
        assert_eq!(is_root, get_uid() == 0);
    }

    #[test]
    fn test_root_override() {
        set_root_override(Some(true));
        assert!(is_root());
        set_root_override(Some(false));
        assert!(!is_root());
        set_root_override(None);
    }

    #[test]
    fn test_has_cgroup_v2() {
        let result = has_cgroup_v2();
        let _valid = match result {
            true | false => true,
        };
    }

    #[test]
    fn test_cgroup_exists() {
        use std::path::Path;
        assert!(cgroup_exists(Path::new("/")));
        assert!(!cgroup_exists(Path::new(
            "/nonexistent/path/that/should/not/exist"
        )));
    }
}
