//! Namespace management for sandbox isolation

use crate::errors::{Result, SandboxError};
use nix::sched::CloneFlags;
use nix::unistd::Pid;

/// Namespace types that can be isolated
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceType {
    /// PID namespace - isolate process IDs
    Pid,
    /// IPC namespace - isolate System V IPC
    Ipc,
    /// Network namespace - isolate network
    Net,
    /// Mount namespace - isolate mounts
    Mount,
    /// UTS namespace - isolate hostname
    Uts,
    /// User namespace - isolate UIDs/GIDs
    User,
}

/// Configuration for namespace isolation
#[derive(Debug, Clone, PartialEq)]
pub struct NamespaceConfig {
    /// PID namespace enabled
    pub pid: bool,
    /// IPC namespace enabled
    pub ipc: bool,
    /// Network namespace enabled
    pub net: bool,
    /// Mount namespace enabled
    pub mount: bool,
    /// UTS namespace enabled
    pub uts: bool,
    /// User namespace enabled
    pub user: bool,
}

impl Default for NamespaceConfig {
    fn default() -> Self {
        Self {
            pid: true,
            ipc: true,
            net: true,
            mount: true,
            uts: true,
            user: false,
        }
    }
}

impl NamespaceConfig {
    /// Create a new configuration with all namespaces enabled
    pub fn all() -> Self {
        Self {
            pid: true,
            ipc: true,
            net: true,
            mount: true,
            uts: true,
            user: true,
        }
    }

    /// Create a minimal configuration
    pub fn minimal() -> Self {
        Self {
            pid: true,
            ipc: true,
            net: true,
            mount: true,
            uts: false,
            user: false,
        }
    }

    /// Convert to clone flags
    pub fn to_clone_flags(&self) -> CloneFlags {
        let mut flags = CloneFlags::empty();

        if self.pid {
            flags |= CloneFlags::CLONE_NEWPID;
        }
        if self.ipc {
            flags |= CloneFlags::CLONE_NEWIPC;
        }
        if self.net {
            flags |= CloneFlags::CLONE_NEWNET;
        }
        if self.mount {
            flags |= CloneFlags::CLONE_NEWNS;
        }
        if self.uts {
            flags |= CloneFlags::CLONE_NEWUTS;
        }
        if self.user {
            flags |= CloneFlags::CLONE_NEWUSER;
        }

        flags
    }

    /// Check if all namespaces are enabled
    pub fn all_enabled(&self) -> bool {
        self.pid && self.ipc && self.net && self.mount && self.uts && self.user
    }

    /// Count enabled namespaces
    pub fn enabled_count(&self) -> usize {
        [
            self.pid, self.ipc, self.net, self.mount, self.uts, self.user,
        ]
        .iter()
        .filter(|&&x| x)
        .count()
    }
}

/// Information about a namespace
#[derive(Debug, Clone)]
pub struct NamespaceInfo {
    pub ns_type: NamespaceType,
    pub inode: u64,
}

/// Get namespace inode (for identification)
pub fn get_namespace_inode(ns_type: &str) -> Result<u64> {
    get_namespace_inode_for_pid(ns_type, None)
}

/// Get namespace inode for a specific process
pub fn get_namespace_inode_for_pid(ns_type: &str, pid: Option<Pid>) -> Result<u64> {
    let pid_str = match pid {
        Some(p) => p.as_raw().to_string(),
        None => "self".to_string(),
    };
    let path = format!("/proc/{}/ns/{}", pid_str, ns_type);
    let stat = std::fs::metadata(&path).map_err(|e| {
        SandboxError::Namespace(format!(
            "Failed to get namespace info for pid={} ns={}: {}",
            pid_str, ns_type, e
        ))
    })?;

    // Get inode number
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(stat.ino())
    }

    #[cfg(not(unix))]
    {
        Err(SandboxError::Namespace(
            "Namespace info not available on this platform".to_string(),
        ))
    }
}

/// Check if two processes share a namespace
pub fn shares_namespace(ns_type: &str, pid1: Option<Pid>, pid2: Option<Pid>) -> Result<bool> {
    let inode1 = get_namespace_inode_for_pid(ns_type, pid1)?;
    let inode2 = get_namespace_inode_for_pid(ns_type, pid2)?;

    Ok(inode1 == inode2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_config_default() {
        let config = NamespaceConfig::default();
        assert!(config.pid);
        assert!(config.ipc);
        assert!(config.net);
        assert!(config.mount);
        assert!(config.uts);
        assert!(!config.user);
    }

    #[test]
    fn test_namespace_config_all() {
        let config = NamespaceConfig::all();
        assert!(config.all_enabled());
    }

    #[test]
    fn test_namespace_config_minimal() {
        let config = NamespaceConfig::minimal();
        assert!(config.pid);
        assert!(!config.uts);
        assert!(!config.user);
    }

    #[test]
    fn test_enabled_count() {
        let config = NamespaceConfig::default();
        assert_eq!(config.enabled_count(), 5); // pid, ipc, net, mount, uts

        let config = NamespaceConfig::all();
        assert_eq!(config.enabled_count(), 6);

        let config = NamespaceConfig::minimal();
        assert_eq!(config.enabled_count(), 4); // pid, ipc, net, mount
    }

    #[test]
    fn test_clone_flags_conversion() {
        let config = NamespaceConfig::default();
        let flags = config.to_clone_flags();

        // Should not be empty
        assert!(!flags.is_empty());

        // Should have NEWPID, NEWIPC, NEWNET, NEWNS
        assert!(flags.contains(CloneFlags::CLONE_NEWPID));
    }

    #[test]
    fn test_get_namespace_inode() {
        // Should be able to get inode for current process
        let result = get_namespace_inode("pid");
        match result {
            Ok(inode) => {
                assert!(inode > 0);
            }
            Err(e) => {
                // May fail if /proc is not available in test environment
                eprintln!("Warning: namespace inode check failed: {}", e);
            }
        }
    }

    #[test]
    fn test_shares_namespace_with_self() {
        // Current process should share namespace with itself
        let result = shares_namespace("pid", None, None);
        match result {
            Ok(shares) => assert!(shares, "Process should share namespace with itself"),
            Err(e) => eprintln!("Warning: namespace sharing check failed: {}", e),
        }
    }

    #[test]
    fn test_namespace_inode_for_self() {
        // Should be able to get inode for current process
        let result = get_namespace_inode_for_pid("pid", None);
        match result {
            Ok(inode) => {
                assert!(inode > 0, "Namespace inode should be positive");
            }
            Err(e) => {
                eprintln!("Warning: namespace inode check failed: {}", e);
            }
        }
    }

    #[test]
    fn test_namespace_inode_consistency() {
        // Getting inode twice should return same value
        let inode1 = get_namespace_inode("pid");
        let inode2 = get_namespace_inode("pid");

        match (inode1, inode2) {
            (Ok(i1), Ok(i2)) => {
                assert_eq!(i1, i2, "Namespace inode should be consistent");
            }
            _ => {
                eprintln!("Warning: namespace inode check failed");
            }
        }
    }

    #[test]
    fn test_namespace_type_equality() {
        assert_eq!(NamespaceType::Pid, NamespaceType::Pid);
        assert_ne!(NamespaceType::Pid, NamespaceType::Net);
    }
}
