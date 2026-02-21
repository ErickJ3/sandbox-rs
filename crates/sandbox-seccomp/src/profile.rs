//! Seccomp filter building and management

use sandbox_core::{Result, SandboxError};
use std::collections::HashSet;

/// Seccomp filter profile.
///
/// Each profile includes all syscalls from profiles below it (cumulative):
/// `Essential < Minimal < IoHeavy < Compute < Network < Unrestricted`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeccompProfile {
    /// Essential — only the ~40 syscalls needed for process bootstrap (linker, glibc init, exit)
    Essential,
    /// Minimal — Essential + signals, pipes, timers, process control (~110 total)
    Minimal,
    /// IO-heavy — Minimal + file manipulation (mkdir, chmod, rename, fsync, …)
    IoHeavy,
    /// Compute — IoHeavy + advanced scheduling and NUMA (sched_setscheduler, mbind, …)
    Compute,
    /// Network — Compute + sockets (socket, bind, listen, connect, …)
    Network,
    /// Unrestricted — Network + privileged ops (ptrace, mount, bpf, setuid, …)
    Unrestricted,
}

impl SeccompProfile {
    /// Get all profiles
    pub fn all() -> Vec<Self> {
        vec![
            SeccompProfile::Essential,
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
            SeccompProfile::Essential => "Process bootstrap only (~40 syscalls)",
            SeccompProfile::Minimal => "Essential + signals, pipes, timers, process control",
            SeccompProfile::IoHeavy => "Minimal + file manipulation (mkdir, chmod, rename, …)",
            SeccompProfile::Compute => "IoHeavy + advanced scheduling/NUMA",
            SeccompProfile::Network => "Compute + socket operations",
            SeccompProfile::Unrestricted => "Network + privileged operations",
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

    /// Syscalls needed for process bootstrap (linker, glibc init, exit).
    fn essential_syscalls() -> Vec<&'static str> {
        vec![
            // Lifecycle
            "exit",
            "exit_group",
            // Exec
            "execve",
            "execveat",
            // Memory (linker)
            "brk",
            "mmap",
            "munmap",
            "mprotect",
            "madvise",
            // File (linker)
            "openat",
            "open",
            "read",
            "write",
            "close",
            "close_range",
            // Stat
            "fstat",
            "stat",
            "lstat",
            "newfstatat",
            "statx",
            // Access
            "access",
            "faccessat",
            "faccessat2",
            // Seek
            "lseek",
            // Links
            "readlink",
            "readlinkat",
            // glibc init
            "arch_prctl",
            "set_tid_address",
            "set_robust_list",
            "futex",
            "getrandom",
            "rseq",
            "prlimit64",
            "prctl",
            // CWD
            "getcwd",
            // Identity
            "getpid",
            "gettid",
            "getuid",
            "geteuid",
            "getgid",
            "getegid",
            // FD
            "fcntl",
        ]
    }

    /// Extra syscalls for a typical program (signals, pipes, timers, etc).
    fn minimal_extras() -> Vec<&'static str> {
        vec![
            // Signals
            "rt_sigaction",
            "rt_sigprocmask",
            "rt_sigpending",
            "rt_sigtimedwait",
            "rt_sigqueueinfo",
            "rt_sigreturn",
            "sigaltstack",
            "kill",
            "tkill",
            "tgkill",
            // Processes
            "clone",
            "clone3",
            "fork",
            "vfork",
            "wait4",
            "waitpid",
            "waitid",
            // I/O avançado
            "readv",
            "writev",
            "pread64",
            "pwrite64",
            "ioctl",
            "flock",
            // FDs
            "dup",
            "dup2",
            "dup3",
            "pipe",
            "pipe2",
            "eventfd2",
            // Time
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
            // Info
            "getppid",
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
            // Polling
            "pselect6",
            "ppoll",
            "epoll_create1",
            "epoll_ctl",
            "epoll_wait",
            "poll",
            "select",
            // Dir
            "chdir",
            "fchdir",
            "getdents",
            "getdents64",
            // Memory
            "mremap",
            "mlock",
            "munlock",
            "mlockall",
            "munlockall",
            "memfd_create",
            // Misc
            "get_robust_list",
        ]
    }

    /// Extra syscalls for file manipulation.
    fn io_heavy_extras() -> Vec<&'static str> {
        vec![
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
        ]
    }

    /// Extra syscalls for compute-intensive workloads.
    fn compute_extras() -> Vec<&'static str> {
        vec![
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
        ]
    }

    /// Extra syscalls for networking.
    fn network_extras() -> Vec<&'static str> {
        vec![
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
        ]
    }

    /// Extra syscalls for unrestricted / privileged mode.
    fn unrestricted_extras() -> Vec<&'static str> {
        vec![
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
        ]
    }

    /// Get syscalls for a profile (cumulative).
    fn syscalls_for_profile(profile: &SeccompProfile) -> HashSet<String> {
        let mut syscalls = HashSet::new();

        let mut add = |list: Vec<&str>| {
            for s in list {
                syscalls.insert(s.to_string());
            }
        };

        // Cumulative: each level includes all levels below it
        add(Self::essential_syscalls());

        if matches!(
            profile,
            SeccompProfile::Minimal
                | SeccompProfile::IoHeavy
                | SeccompProfile::Compute
                | SeccompProfile::Network
                | SeccompProfile::Unrestricted
        ) {
            add(Self::minimal_extras());
        }

        if matches!(
            profile,
            SeccompProfile::IoHeavy
                | SeccompProfile::Compute
                | SeccompProfile::Network
                | SeccompProfile::Unrestricted
        ) {
            add(Self::io_heavy_extras());
        }

        if matches!(
            profile,
            SeccompProfile::Compute | SeccompProfile::Network | SeccompProfile::Unrestricted
        ) {
            add(Self::compute_extras());
        }

        if matches!(
            profile,
            SeccompProfile::Network | SeccompProfile::Unrestricted
        ) {
            add(Self::network_extras());
        }

        if matches!(profile, SeccompProfile::Unrestricted) {
            add(Self::unrestricted_extras());
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
        assert_eq!(profiles.len(), 6);
    }

    #[test]
    fn test_seccomp_profile_description() {
        assert!(!SeccompProfile::Essential.description().is_empty());
        assert!(!SeccompProfile::Minimal.description().is_empty());
        assert_ne!(
            SeccompProfile::Essential.description(),
            SeccompProfile::Minimal.description()
        );
        assert_ne!(
            SeccompProfile::Minimal.description(),
            SeccompProfile::Network.description()
        );
    }

    #[test]
    fn test_seccomp_filter_essential() {
        let filter = SeccompFilter::from_profile(SeccompProfile::Essential);
        // Bootstrap syscalls
        assert!(filter.is_allowed("read"));
        assert!(filter.is_allowed("write"));
        assert!(filter.is_allowed("exit"));
        assert!(filter.is_allowed("execve"));
        assert!(filter.is_allowed("mmap"));
        assert!(filter.is_allowed("brk"));
        assert!(filter.is_allowed("openat"));
        assert!(filter.is_allowed("close"));
        assert!(filter.is_allowed("arch_prctl"));
        assert!(filter.is_allowed("futex"));
        assert!(filter.is_allowed("getpid"));
        assert!(filter.is_allowed("gettid"));
        assert!(filter.is_allowed("lseek"));
        assert!(filter.is_allowed("fcntl"));

        // NOT in Essential
        assert!(!filter.is_allowed("clone"));
        assert!(!filter.is_allowed("rt_sigaction"));
        assert!(!filter.is_allowed("nanosleep"));
        assert!(!filter.is_allowed("socket"));
        assert!(!filter.is_allowed("ptrace"));
        assert!(!filter.is_allowed("mkdir"));

        let count = filter.allowed_count();
        assert!(
            (35..=50).contains(&count),
            "Essential profile should have ~40 syscalls, got {}",
            count
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
        assert!(filter.is_allowed("rt_sigaction"));
        assert!(!filter.is_allowed("ptrace"));
        assert!(!filter.is_allowed("mkdir"));
        assert!(!filter.is_allowed("socket"));
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
        // Also has Minimal extras (cumulative)
        assert!(filter.is_allowed("clone"));
        assert!(filter.is_allowed("rt_sigaction"));
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
        // Cumulative: also has IoHeavy extras
        assert!(filter.is_allowed("mkdir"));
        // Cumulative: also has Compute extras
        assert!(filter.is_allowed("sched_setscheduler"));
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

    #[test]
    fn test_profiles_are_cumulative() {
        let essential = SeccompFilter::from_profile(SeccompProfile::Essential);
        let minimal = SeccompFilter::from_profile(SeccompProfile::Minimal);
        let io_heavy = SeccompFilter::from_profile(SeccompProfile::IoHeavy);
        let compute = SeccompFilter::from_profile(SeccompProfile::Compute);
        let network = SeccompFilter::from_profile(SeccompProfile::Network);
        let unrestricted = SeccompFilter::from_profile(SeccompProfile::Unrestricted);

        // Each profile must be a strict superset of the one below
        assert!(
            essential
                .allowed_syscalls()
                .is_subset(minimal.allowed_syscalls()),
            "Essential should be a subset of Minimal"
        );
        assert!(
            minimal
                .allowed_syscalls()
                .is_subset(io_heavy.allowed_syscalls()),
            "Minimal should be a subset of IoHeavy"
        );
        assert!(
            io_heavy
                .allowed_syscalls()
                .is_subset(compute.allowed_syscalls()),
            "IoHeavy should be a subset of Compute"
        );
        assert!(
            compute
                .allowed_syscalls()
                .is_subset(network.allowed_syscalls()),
            "Compute should be a subset of Network"
        );
        assert!(
            network
                .allowed_syscalls()
                .is_subset(unrestricted.allowed_syscalls()),
            "Network should be a subset of Unrestricted"
        );

        // And strictly more syscalls at each level
        assert!(minimal.allowed_count() > essential.allowed_count());
        assert!(io_heavy.allowed_count() > minimal.allowed_count());
        assert!(compute.allowed_count() > io_heavy.allowed_count());
        assert!(network.allowed_count() > compute.allowed_count());
        assert!(unrestricted.allowed_count() > network.allowed_count());
    }
}
