//! Seccomp filter building and management

use sandbox_core::{Result, SandboxError};
use std::collections::HashSet;

/// Seccomp filter profile
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeccompProfile {
    /// Minimal profile - only essential syscalls
    Minimal,
    /// IO-heavy profile - includes file operations
    IoHeavy,
    /// Compute profile - includes memory operations
    Compute,
    /// Network profile - includes socket operations
    Network,
    /// Unrestricted - allow most syscalls
    Unrestricted,
}

impl SeccompProfile {
    /// Get all profiles
    pub fn all() -> Vec<Self> {
        vec![
            SeccompProfile::Minimal,
            SeccompProfile::IoHeavy,
            SeccompProfile::Compute,
            SeccompProfile::Network,
            SeccompProfile::Unrestricted,
        ]
    }

    /// Get description of profile
    pub fn description(&self) -> &'static str {
        match self {
            SeccompProfile::Minimal => "Minimal syscalls only",
            SeccompProfile::IoHeavy => "With file I/O operations",
            SeccompProfile::Compute => "With memory operations",
            SeccompProfile::Network => "With socket operations",
            SeccompProfile::Unrestricted => "Allow most syscalls",
        }
    }
}

/// Seccomp filter builder
#[derive(Debug, Clone)]
pub struct SeccompFilter {
    allowed: HashSet<String>,
    blocked: HashSet<String>,
    kill_on_violation: bool,
    profile: SeccompProfile,
}

impl SeccompFilter {
    /// Create filter from profile
    pub fn from_profile(profile: SeccompProfile) -> Self {
        let allowed = Self::syscalls_for_profile(&profile);
        Self {
            allowed,
            blocked: HashSet::new(),
            kill_on_violation: true,
            profile,
        }
    }

    /// Create minimal filter
    pub fn minimal() -> Self {
        Self::from_profile(SeccompProfile::Minimal)
    }

    /// Get syscalls for a profile
    fn syscalls_for_profile(profile: &SeccompProfile) -> HashSet<String> {
        let mut syscalls = HashSet::new();

        // Always allowed
        let always_allowed = vec![
            // Process management
            "exit",
            "exit_group",
            "clone",
            "clone3",
            "fork",
            "vfork",
            // Signal handling
            "rt_sigaction",
            "rt_sigprocmask",
            "rt_sigpending",
            "rt_sigtimedwait",
            "rt_sigqueueinfo",
            "rt_sigreturn",
            "kill",
            "tkill",
            "tgkill",
            "sigaltstack",
            // Basic I/O
            "read",
            "write",
            "readv",
            "writev",
            "pread64",
            "pwrite64",
            "lseek",
            "access",
            "faccessat",
            "faccessat2",
            "readlink",
            "readlinkat",
            "flock",
            // File operations
            "open",
            "openat",
            "close",
            "close_range",
            "stat",
            "fstat",
            "lstat",
            "fcntl",
            "ioctl",
            // Memory
            "mmap",
            "munmap",
            "mremap",
            "mprotect",
            "madvise",
            "brk",
            "mlock",
            "munlock",
            "mlockall",
            "munlockall",
            "memfd_create",
            // Process execution
            "execve",
            "execveat",
            // Waiting
            "wait4",
            "waitpid",
            "waitid",
            // File descriptors
            "dup",
            "dup2",
            "dup3",
            "pipe",
            "pipe2",
            "eventfd2",
            // Getting time
            "clock_gettime",
            "clock_getres",
            "gettimeofday",
            "time",
            "nanosleep",
            "clock_nanosleep",
            // Timers
            "timer_create",
            "timer_settime",
            "timer_gettime",
            "timer_getoverrun",
            "timer_delete",
            // Process info
            "getpid",
            "getppid",
            "getuid",
            "geteuid",
            "getgid",
            "getegid",
            "gettid",
            "getresuid",
            "getresgid",
            "uname",
            "umask",
            "sysinfo",
            "getpgrp",
            "getpgid",
            "setpgid",
            "getsid",
            "setsid",
            // Scheduling
            "sched_getaffinity",
            "sched_yield",
            // Limits
            "getrlimit",
            "setrlimit",
            "getrusage",
            // Misc allowed
            "futex",
            "set_tid_address",
            "set_robust_list",
            "get_robust_list",
            "pselect6",
            "ppoll",
            "epoll_create1",
            "epoll_ctl",
            "epoll_wait",
            "poll",
            "select",
            "getcwd",
            "chdir",
            "fchdir",
            "getdents",
            "getdents64",
            "prctl",
            "arch_prctl",
            "rseq",
            "newfstatat",
            "getrandom",
            "statx",
            "prlimit64",
        ];

        for syscall in always_allowed {
            syscalls.insert(syscall.to_string());
        }

        // Profile-specific syscalls
        match profile {
            SeccompProfile::Minimal => {
                // Just the basics above
            }
            SeccompProfile::IoHeavy => {
                for syscall in &[
                    "mkdir",
                    "mkdirat",
                    "rmdir",
                    "unlink",
                    "unlinkat",
                    "rename",
                    "renameat",
                    "link",
                    "linkat",
                    "symlink",
                    "symlinkat",
                    "chmod",
                    "fchmod",
                    "fchmodat",
                    "chown",
                    "fchown",
                    "fchownat",
                    "lchown",
                    "utimes",
                    "futimesat",
                    "utime",
                    "utimensat",
                    "truncate",
                    "ftruncate",
                    "fallocate",
                    "sendfile",
                    "splice",
                    "tee",
                    "vmsplice",
                    "statfs",
                    "fstatfs",
                    "fsync",
                    "fdatasync",
                ] {
                    syscalls.insert(syscall.to_string());
                }
            }
            SeccompProfile::Compute => {
                for syscall in &[
                    "sched_getscheduler",
                    "sched_setscheduler",
                    "sched_getparam",
                    "sched_setparam",
                    "sched_get_priority_max",
                    "sched_get_priority_min",
                    "sched_rr_get_interval",
                    "sched_setaffinity",
                    "mbind",
                    "get_mempolicy",
                    "set_mempolicy",
                    "migrate_pages",
                    "move_pages",
                    "membarrier",
                ] {
                    syscalls.insert(syscall.to_string());
                }
            }
            SeccompProfile::Network => {
                for syscall in &[
                    "socket",
                    "socketpair",
                    "bind",
                    "listen",
                    "accept",
                    "accept4",
                    "connect",
                    "shutdown",
                    "sendto",
                    "recvfrom",
                    "sendmsg",
                    "recvmsg",
                    "sendmmsg",
                    "recvmmsg",
                    "setsockopt",
                    "getsockopt",
                    "getsockname",
                    "getpeername",
                ] {
                    syscalls.insert(syscall.to_string());
                }
                // Also include IoHeavy syscalls
                for syscall in &["open", "openat", "read", "write", "close"] {
                    syscalls.insert(syscall.to_string());
                }
            }
            SeccompProfile::Unrestricted => {
                // Add many more syscalls for unrestricted
                for syscall in &[
                    "ptrace",
                    "process_vm_readv",
                    "process_vm_writev",
                    "perf_event_open",
                    "bpf",
                    "seccomp",
                    "mount",
                    "umount2",
                    "pivot_root",
                    "capget",
                    "capset",
                    "setuid",
                    "setgid",
                    "setreuid",
                    "setregid",
                    "setresuid",
                    "setresgid",
                    "getgroups",
                    "setgroups",
                    "setfsgid",
                    "setfsuid",
                ] {
                    syscalls.insert(syscall.to_string());
                }
            }
        }

        syscalls
    }

    /// Add syscall to whitelist
    pub fn allow_syscall(&mut self, name: impl Into<String>) {
        self.allowed.insert(name.into());
    }

    /// Block a syscall (deny even if in whitelist)
    pub fn block_syscall(&mut self, name: impl Into<String>) {
        self.blocked.insert(name.into());
    }

    /// Check if syscall is allowed
    pub fn is_allowed(&self, name: &str) -> bool {
        if self.blocked.contains(name) {
            return false;
        }
        self.allowed.contains(name)
    }

    /// Get allowed syscalls
    pub fn allowed_syscalls(&self) -> &HashSet<String> {
        &self.allowed
    }

    /// Get blocked syscalls
    pub fn blocked_syscalls(&self) -> &HashSet<String> {
        &self.blocked
    }

    /// Count allowed syscalls
    pub fn allowed_count(&self) -> usize {
        self.allowed.len() - self.blocked.len()
    }

    /// Check if killing on violation
    pub fn is_kill_on_violation(&self) -> bool {
        self.kill_on_violation
    }

    /// Set kill on violation
    pub fn set_kill_on_violation(&mut self, kill: bool) {
        self.kill_on_violation = kill;
    }

    /// Get the profile used to create this filter
    pub fn profile(&self) -> SeccompProfile {
        self.profile.clone()
    }

    /// Validate that filter is correct
    pub fn validate(&self) -> Result<()> {
        if self.allowed.is_empty() && self.profile != SeccompProfile::Unrestricted {
            return Err(SandboxError::Seccomp(
                "Filter has no allowed syscalls".to_string(),
            ));
        }
        Ok(())
    }

    /// Export as BPF program (simplified - just returns syscall names)
    pub fn export(&self) -> Result<Vec<String>> {
        self.validate()?;
        let mut list: Vec<_> = self.allowed.iter().cloned().collect();
        list.sort();
        Ok(list)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seccomp_profile_all() {
        let profiles = SeccompProfile::all();
        assert_eq!(profiles.len(), 5);
    }

    #[test]
    fn test_seccomp_profile_description() {
        assert!(!SeccompProfile::Minimal.description().is_empty());
        assert_ne!(
            SeccompProfile::Minimal.description(),
            SeccompProfile::Network.description()
        );
    }

    #[test]
    fn test_seccomp_filter_minimal() {
        let filter = SeccompFilter::minimal();
        assert!(filter.is_allowed("read"));
        assert!(filter.is_allowed("write"));
        assert!(filter.is_allowed("exit"));
        assert!(filter.is_allowed("clone3"));
        assert!(filter.is_allowed("lseek"));
        assert!(filter.is_allowed("sched_getaffinity"));
        assert!(filter.is_allowed("nanosleep"));
        assert!(filter.is_allowed("gettid"));
        assert!(!filter.is_allowed("ptrace"));
        assert!(
            filter.allowed_count() > 100,
            "Minimal profile should have > 100 syscalls for runtime compatibility, got {}",
            filter.allowed_count()
        );
    }

    #[test]
    fn test_seccomp_filter_io_heavy() {
        let filter = SeccompFilter::from_profile(SeccompProfile::IoHeavy);
        assert!(filter.is_allowed("read"));
        assert!(filter.is_allowed("mkdir"));
        assert!(filter.is_allowed("unlink"));
        let io_count = filter.allowed_count();

        let minimal = SeccompFilter::minimal();
        assert!(io_count > minimal.allowed_count());
    }

    #[test]
    fn test_seccomp_filter_network() {
        let filter = SeccompFilter::from_profile(SeccompProfile::Network);
        assert!(filter.is_allowed("socket"));
        assert!(filter.is_allowed("connect"));
        assert!(filter.is_allowed("bind"));
    }

    #[test]
    fn test_seccomp_filter_allow_syscall() {
        let mut filter = SeccompFilter::minimal();
        filter.allow_syscall("custom_syscall");
        assert!(filter.is_allowed("custom_syscall"));
    }

    #[test]
    fn test_seccomp_filter_block_syscall() {
        let mut filter = SeccompFilter::minimal();
        filter.block_syscall("read");
        assert!(!filter.is_allowed("read"));
    }

    #[test]
    fn test_seccomp_filter_block_overrides_allow() {
        let mut filter = SeccompFilter::minimal();
        assert!(filter.is_allowed("write"));
        filter.block_syscall("write");
        assert!(!filter.is_allowed("write"));
    }

    #[test]
    fn test_seccomp_filter_validate() {
        let filter = SeccompFilter::minimal();
        assert!(filter.validate().is_ok());

        let empty_filter = SeccompFilter {
            allowed: HashSet::new(),
            blocked: HashSet::new(),
            kill_on_violation: true,
            profile: SeccompProfile::Minimal,
        };
        assert!(empty_filter.validate().is_err());
    }

    #[test]
    fn test_seccomp_filter_export() {
        let filter = SeccompFilter::minimal();
        let syscalls = filter.export().unwrap();
        assert!(!syscalls.is_empty());
        assert!(syscalls.contains(&"read".to_string()));

        // Should be sorted
        let mut sorted = syscalls.clone();
        sorted.sort();
        assert_eq!(syscalls, sorted);
    }

    #[test]
    fn test_seccomp_kill_on_violation() {
        let mut filter = SeccompFilter::minimal();
        assert!(filter.is_kill_on_violation());

        filter.set_kill_on_violation(false);
        assert!(!filter.is_kill_on_violation());
    }

    #[test]
    fn test_validate_unrestricted_with_no_allowed() {
        let filter = SeccompFilter {
            allowed: HashSet::new(),
            blocked: HashSet::new(),
            kill_on_violation: true,
            profile: SeccompProfile::Unrestricted,
        };
        assert!(filter.validate().is_ok());
    }
}
