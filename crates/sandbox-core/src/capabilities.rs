//! Runtime detection of available system capabilities
//!
//! Probes the running kernel and system configuration to determine which
//! sandboxing features are available, allowing graceful degradation.

use std::path::Path;

/// Detected system capabilities for sandboxing
#[derive(Debug, Clone)]
pub struct SystemCapabilities {
    /// Running as root (euid == 0)
    pub has_root: bool,
    /// Unprivileged user namespaces are available
    pub has_user_namespaces: bool,
    /// Seccomp BPF filtering is available
    pub has_seccomp: bool,
    /// Landlock LSM is available (Linux 5.13+)
    pub has_landlock: bool,
    /// Cgroup v2 unified hierarchy is mounted
    pub has_cgroup_v2: bool,
    /// Cgroup delegation is available for current user
    pub has_cgroup_delegation: bool,
}

impl SystemCapabilities {
    /// Detect all available capabilities on the current system
    pub fn detect() -> Self {
        Self {
            has_root: detect_root(),
            has_user_namespaces: detect_user_namespaces(),
            has_seccomp: detect_seccomp(),
            has_landlock: detect_landlock(),
            has_cgroup_v2: detect_cgroup_v2(),
            has_cgroup_delegation: detect_cgroup_delegation(),
        }
    }

    /// Check if unprivileged sandboxing is possible (without root)
    pub fn can_sandbox_unprivileged(&self) -> bool {
        // At minimum we need seccomp (always available on modern kernels)
        // User namespaces and landlock are bonuses
        self.has_seccomp
    }

    /// Check if full privileged sandboxing is possible
    pub fn can_sandbox_privileged(&self) -> bool {
        self.has_root && self.has_cgroup_v2
    }

    /// Get a human-readable summary of capabilities
    pub fn summary(&self) -> String {
        let mut lines = Vec::new();
        let check = |available: bool| if available { "[ok]" } else { "[--]" };

        lines.push(format!("{} Root privileges", check(self.has_root)));
        lines.push(format!(
            "{} User namespaces",
            check(self.has_user_namespaces)
        ));
        lines.push(format!("{} Seccomp BPF", check(self.has_seccomp)));
        lines.push(format!("{} Landlock LSM", check(self.has_landlock)));
        lines.push(format!("{} Cgroup v2", check(self.has_cgroup_v2)));
        lines.push(format!(
            "{} Cgroup delegation",
            check(self.has_cgroup_delegation)
        ));

        lines.join("\n")
    }
}

fn detect_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn detect_user_namespaces() -> bool {
    // Check if unprivileged user namespaces are enabled
    if let Ok(content) = std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
        && content.trim() == "0"
    {
        return false;
    }

    // Also check max_user_namespaces > 0
    if let Ok(content) = std::fs::read_to_string("/proc/sys/user/max_user_namespaces")
        && let Ok(max) = content.trim().parse::<u64>()
    {
        return max > 0;
    }

    // If we can't read the files, assume available on modern kernels
    true
}

fn detect_seccomp() -> bool {
    // Check if seccomp is available via prctl
    let ret = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) };
    // Returns 0 if seccomp mode is disabled (available but not active)
    // Returns -1 with EINVAL if seccomp is not built into kernel
    ret >= 0
}

fn detect_landlock() -> bool {
    // Use LANDLOCK_CREATE_RULESET_VERSION to query ABI version.
    // With flags=1 and NULL attrs, this returns the highest supported
    // ABI version (an integer >= 1), NOT a file descriptor.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            1u32, // LANDLOCK_CREATE_RULESET_VERSION
        )
    };

    if ret >= 0 {
        // ret is the ABI version number, not a fd — do NOT close it
        return true;
    }

    // ENOSYS means landlock syscall doesn't exist
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    errno != libc::ENOSYS
}

fn detect_cgroup_v2() -> bool {
    Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
}

fn detect_cgroup_delegation() -> bool {
    // Check if current user has a delegated cgroup slice
    let uid = unsafe { libc::geteuid() };
    if uid == 0 {
        return true; // root always has access
    }

    let user_slice = format!("/sys/fs/cgroup/user.slice/user-{}.slice", uid);
    let path = Path::new(&user_slice);

    if !path.exists() {
        return false;
    }

    // Check if we can write to the cgroup directory
    let test_path = path.join("sandbox-test-probe");
    match std::fs::create_dir(&test_path) {
        Ok(()) => {
            let _ = std::fs::remove_dir(&test_path);
            true
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_returns_valid_capabilities() {
        let caps = SystemCapabilities::detect();
        // Just verify detection doesn't panic
        let _ = caps.has_root;
        let _ = caps.has_seccomp;
        let _ = caps.has_user_namespaces;
        let _ = caps.has_landlock;
        let _ = caps.has_cgroup_v2;
        let _ = caps.has_cgroup_delegation;
    }

    #[test]
    fn summary_produces_output() {
        let caps = SystemCapabilities::detect();
        let summary = caps.summary();
        assert!(!summary.is_empty());
        assert!(summary.contains("Root privileges"));
        assert!(summary.contains("Seccomp BPF"));
    }

    #[test]
    fn seccomp_detection_works() {
        // On any modern Linux kernel, seccomp should be available
        let has = detect_seccomp();
        // We can't assert true universally, but it shouldn't panic
        let _ = has;
    }

    #[test]
    fn root_detection_matches_euid() {
        let detected = detect_root();
        let actual = unsafe { libc::geteuid() == 0 };
        assert_eq!(detected, actual);
    }
}
