//! Privilege mode configuration for sandbox execution

use crate::capabilities::SystemCapabilities;

/// Determines how the sandbox operates with respect to privileges
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PrivilegeMode {
    /// Use only unprivileged mechanisms: user namespaces + seccomp + landlock + setrlimit.
    /// Does NOT require root. Fails if essential unprivileged features are unavailable.
    Unprivileged,

    /// Use all available mechanisms including privileged ones: all namespaces + cgroups + chroot + seccomp.
    /// Requires root. Fails if not running as root.
    Privileged,

    /// Automatically detect the best available mode.
    /// Uses privileged mode if running as root, otherwise falls back to unprivileged.
    #[default]
    Auto,
}

impl PrivilegeMode {
    /// Resolve Auto mode to a concrete mode based on system capabilities
    pub fn resolve(&self, caps: &SystemCapabilities) -> ResolvedMode {
        match self {
            PrivilegeMode::Privileged => ResolvedMode::Privileged,
            PrivilegeMode::Unprivileged => ResolvedMode::Unprivileged,
            PrivilegeMode::Auto => {
                if caps.has_root && caps.has_cgroup_v2 {
                    ResolvedMode::Privileged
                } else {
                    ResolvedMode::Unprivileged
                }
            }
        }
    }
}

/// A resolved (non-Auto) privilege mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedMode {
    Unprivileged,
    Privileged,
}

impl ResolvedMode {
    pub fn is_privileged(&self) -> bool {
        matches!(self, ResolvedMode::Privileged)
    }

    pub fn is_unprivileged(&self) -> bool {
        matches!(self, ResolvedMode::Unprivileged)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_auto() {
        assert_eq!(PrivilegeMode::default(), PrivilegeMode::Auto);
    }

    #[test]
    fn privileged_always_resolves_to_privileged() {
        let caps = SystemCapabilities {
            has_root: false,
            has_user_namespaces: false,
            has_seccomp: false,
            has_landlock: false,
            has_cgroup_v2: false,
            has_cgroup_delegation: false,
        };
        assert_eq!(
            PrivilegeMode::Privileged.resolve(&caps),
            ResolvedMode::Privileged
        );
    }

    #[test]
    fn unprivileged_always_resolves_to_unprivileged() {
        let caps = SystemCapabilities {
            has_root: true,
            has_user_namespaces: true,
            has_seccomp: true,
            has_landlock: true,
            has_cgroup_v2: true,
            has_cgroup_delegation: true,
        };
        assert_eq!(
            PrivilegeMode::Unprivileged.resolve(&caps),
            ResolvedMode::Unprivileged
        );
    }

    #[test]
    fn auto_resolves_to_privileged_when_root_with_cgroups() {
        let caps = SystemCapabilities {
            has_root: true,
            has_user_namespaces: true,
            has_seccomp: true,
            has_landlock: true,
            has_cgroup_v2: true,
            has_cgroup_delegation: true,
        };
        assert_eq!(
            PrivilegeMode::Auto.resolve(&caps),
            ResolvedMode::Privileged
        );
    }

    #[test]
    fn auto_resolves_to_unprivileged_without_root() {
        let caps = SystemCapabilities {
            has_root: false,
            has_user_namespaces: true,
            has_seccomp: true,
            has_landlock: true,
            has_cgroup_v2: true,
            has_cgroup_delegation: false,
        };
        assert_eq!(
            PrivilegeMode::Auto.resolve(&caps),
            ResolvedMode::Unprivileged
        );
    }

    #[test]
    fn resolved_mode_helpers() {
        assert!(ResolvedMode::Privileged.is_privileged());
        assert!(!ResolvedMode::Privileged.is_unprivileged());
        assert!(ResolvedMode::Unprivileged.is_unprivileged());
        assert!(!ResolvedMode::Unprivileged.is_privileged());
    }
}
