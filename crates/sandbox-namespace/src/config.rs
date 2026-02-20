//! Namespace management for sandbox isolation

use nix::sched::CloneFlags;
use sandbox_core::{Result, SandboxError};
use nix::unistd::Pid;

/// Namespace types that can be isolated
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceType {
    Pid,
    Ipc,
    Net,
    Mount,
    Uts,
    User,
}

/// Configuration for namespace isolation
#[derive(Debug, Clone, PartialEq)]
pub struct NamespaceConfig {
    pub pid: bool,
    pub ipc: bool,
    pub net: bool,
    pub mount: bool,
    pub uts: bool,
    pub user: bool,
}

impl Default for NamespaceConfig {
    fn default() -> Self {
        // CHANGED: user namespace now enabled by default for unprivileged operation
        Self {
            pid: true,
            ipc: true,
            net: true,
            mount: true,
            uts: true,
            user: true,
        }
    }
}

impl NamespaceConfig {
    /// All namespaces enabled
    pub fn all() -> Self {
        Self { pid: true, ipc: true, net: true, mount: true, uts: true, user: true }
    }

    /// Minimal configuration (PID, IPC, NET, MOUNT)
    pub fn minimal() -> Self {
        Self { pid: true, ipc: true, net: true, mount: true, uts: false, user: false }
    }

    /// Unprivileged mode: user namespace enabled to allow other namespaces without root
    pub fn unprivileged() -> Self {
        Self { pid: true, ipc: true, net: true, mount: true, uts: true, user: true }
    }

    /// Privileged mode: no user namespace needed (running as root)
    pub fn privileged() -> Self {
        Self { pid: true, ipc: true, net: true, mount: true, uts: true, user: false }
    }

    /// Convert to clone flags
    pub fn to_clone_flags(&self) -> CloneFlags {
        let mut flags = CloneFlags::empty();
        if self.pid { flags |= CloneFlags::CLONE_NEWPID; }
        if self.ipc { flags |= CloneFlags::CLONE_NEWIPC; }
        if self.net { flags |= CloneFlags::CLONE_NEWNET; }
        if self.mount { flags |= CloneFlags::CLONE_NEWNS; }
        if self.uts { flags |= CloneFlags::CLONE_NEWUTS; }
        if self.user { flags |= CloneFlags::CLONE_NEWUSER; }
        flags
    }

    pub fn all_enabled(&self) -> bool {
        self.pid && self.ipc && self.net && self.mount && self.uts && self.user
    }

    pub fn enabled_count(&self) -> usize {
        [self.pid, self.ipc, self.net, self.mount, self.uts, self.user]
            .iter().filter(|&&x| x).count()
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

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(stat.ino())
    }

    #[cfg(not(unix))]
    {
        let _ = stat;
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
    fn test_namespace_config_default_includes_user() {
        let config = NamespaceConfig::default();
        assert!(config.user, "Default should now include user namespace");
        assert!(config.pid);
        assert!(config.ipc);
        assert!(config.net);
        assert!(config.mount);
        assert!(config.uts);
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
    fn test_unprivileged_enables_user_ns() {
        let config = NamespaceConfig::unprivileged();
        assert!(config.user);
        assert_eq!(config.enabled_count(), 6);
    }

    #[test]
    fn test_privileged_disables_user_ns() {
        let config = NamespaceConfig::privileged();
        assert!(!config.user);
        assert_eq!(config.enabled_count(), 5);
    }

    #[test]
    fn test_enabled_count() {
        assert_eq!(NamespaceConfig::default().enabled_count(), 6);
        assert_eq!(NamespaceConfig::all().enabled_count(), 6);
        assert_eq!(NamespaceConfig::minimal().enabled_count(), 4);
    }

    #[test]
    fn test_clone_flags_conversion() {
        let config = NamespaceConfig::default();
        let flags = config.to_clone_flags();
        assert!(!flags.is_empty());
        assert!(flags.contains(CloneFlags::CLONE_NEWPID));
        assert!(flags.contains(CloneFlags::CLONE_NEWUSER));
    }
}
