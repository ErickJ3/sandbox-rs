//! User namespace UID/GID mapping support
//!
//! When using user namespaces, the child process needs UID/GID mappings
//! written to /proc/{pid}/uid_map and /proc/{pid}/gid_map.

use sandbox_core::{Result, SandboxError};
use nix::unistd::Pid;
use std::fs;

/// Setup user namespace UID/GID mapping for a child process.
///
/// Maps the calling user's UID/GID to root (0) inside the namespace.
/// This is required for user namespace isolation to work properly.
pub fn setup_user_namespace(child_pid: Pid, uid: u32, gid: u32) -> Result<()> {
    let pid = child_pid.as_raw();

    // Write uid_map: map uid inside namespace (0) to uid outside namespace
    let uid_map = format!("0 {} 1\n", uid);
    fs::write(format!("/proc/{}/uid_map", pid), &uid_map).map_err(|e| {
        SandboxError::Namespace(format!("Failed to write uid_map for pid {}: {}", pid, e))
    })?;

    // Deny setgroups (required before writing gid_map as unprivileged user)
    fs::write(format!("/proc/{}/setgroups", pid), "deny\n").map_err(|e| {
        SandboxError::Namespace(format!("Failed to write setgroups for pid {}: {}", pid, e))
    })?;

    // Write gid_map: map gid inside namespace (0) to gid outside namespace
    let gid_map = format!("0 {} 1\n", gid);
    fs::write(format!("/proc/{}/gid_map", pid), &gid_map).map_err(|e| {
        SandboxError::Namespace(format!("Failed to write gid_map for pid {}: {}", pid, e))
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_setup_user_namespace_invalid_pid() {
        // Using an invalid PID should fail gracefully
        let result = super::setup_user_namespace(
            nix::unistd::Pid::from_raw(999_999_999),
            1000,
            1000,
        );
        assert!(result.is_err());
    }
}
