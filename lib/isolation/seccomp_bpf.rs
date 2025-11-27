//! Seccomp BPF filter compilation and loading using seccompiler

use super::seccomp::SeccompFilter;
use crate::errors::{Result, SandboxError};
use log::warn;
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter as SeccompilerFilter, apply_filter};
use std::collections::BTreeMap;
use std::convert::TryInto;

/// Seccomp BPF filter compiler and loader
pub struct SeccompBpf;

impl SeccompBpf {
    /// Compile a filter to BPF bytecode
    pub fn compile(filter: &SeccompFilter) -> Result<Vec<u8>> {
        let bpf_program = Self::compile_to_bpf(filter)?;
        let bpf_bytes: Vec<u8> = unsafe {
            let ptr = bpf_program.as_ptr() as *const u8;
            let len = bpf_program.len() * std::mem::size_of::<seccompiler::sock_filter>();
            std::slice::from_raw_parts(ptr, len).to_vec()
        };
        Ok(bpf_bytes)
    }

    /// Compile filter to BpfProgram with validation
    fn compile_to_bpf(filter: &SeccompFilter) -> Result<BpfProgram> {
        filter.validate()?;

        let allowed = filter.allowed_syscalls();
        let blocked = filter.blocked_syscalls();
        let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
        let is_unrestricted = filter.profile() == super::seccomp::SeccompProfile::Unrestricted;

        if is_unrestricted {
            for syscall_name in blocked.iter() {
                match get_syscall_number_from_name(syscall_name) {
                    Some(num) => {
                        rules.entry(num).or_default();
                    }
                    None => {
                        if filter.allows_unknown_syscalls() {
                            warn!("Unknown syscall '{}' in block list (ignored)", syscall_name);
                        } else {
                            return Err(SandboxError::Seccomp(format!(
                                "Unknown syscall to block: '{}'. This syscall is not supported on this architecture.",
                                syscall_name
                            )));
                        }
                    }
                }
            }
        } else {
            for syscall_name in allowed.iter() {
                if blocked.contains(syscall_name) {
                    continue;
                }

                match get_syscall_number_from_name(syscall_name) {
                    Some(num) => {
                        rules.entry(num).or_default();
                    }
                    None => {
                        if filter.allows_unknown_syscalls() {
                            warn!("Unknown syscall '{}' in allow list (ignored)", syscall_name);
                        } else {
                            return Err(SandboxError::Seccomp(format!(
                                "Unknown syscall to allow: '{}'. This syscall is not supported on this architecture.",
                                syscall_name
                            )));
                        }
                    }
                }
            }
        }

        // Configure actions based on mode
        let (mismatch_action, match_action) = if is_unrestricted {
            (SeccompAction::Allow, SeccompAction::Trap)
        } else {
            let deny_action = if filter.is_kill_on_violation() {
                SeccompAction::KillProcess
            } else {
                SeccompAction::Trap
            };
            (deny_action, SeccompAction::Allow)
        };

        let seccompiler_filter = SeccompilerFilter::new(
            rules,
            mismatch_action,
            match_action,
            seccompiler::TargetArch::x86_64,
        )
        .map_err(|e| SandboxError::Seccomp(format!("Failed to create filter: {}", e)))?;

        let bpf_program: BpfProgram = seccompiler_filter
            .try_into()
            .map_err(|e| SandboxError::Seccomp(format!("Failed to compile filter: {}", e)))?;

        Ok(bpf_program)
    }

    /// Load BPF filter via seccompiler's apply_filter
    pub fn load(filter: &SeccompFilter) -> Result<()> {
        filter.validate()?;
        unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(SandboxError::Seccomp(format!(
                    "Failed to set PR_SET_NO_NEW_PRIVS: {}",
                    std::io::Error::last_os_error()
                )));
            }
        }

        let bpf_program = Self::compile_to_bpf(filter)?;

        apply_filter(&bpf_program)
            .map_err(|e| SandboxError::Seccomp(format!("Failed to apply seccomp filter: {}", e)))?;

        Ok(())
    }
}

/// Get syscall number from name using libc constants
fn get_syscall_number_from_name(name: &str) -> Option<i64> {
    match name {
        "read" => Some(libc::SYS_read),
        "write" => Some(libc::SYS_write),
        "open" => Some(libc::SYS_open),
        "close" => Some(libc::SYS_close),
        "stat" => Some(libc::SYS_stat),
        "fstat" => Some(libc::SYS_fstat),
        "lstat" => Some(libc::SYS_lstat),
        "poll" => Some(libc::SYS_poll),
        "lseek" => Some(libc::SYS_lseek),
        "mmap" => Some(libc::SYS_mmap),
        "mprotect" => Some(libc::SYS_mprotect),
        "munmap" => Some(libc::SYS_munmap),
        "brk" => Some(libc::SYS_brk),
        "rt_sigaction" => Some(libc::SYS_rt_sigaction),
        "rt_sigprocmask" => Some(libc::SYS_rt_sigprocmask),
        "rt_sigpending" => Some(libc::SYS_rt_sigpending),
        "rt_sigtimedwait" => Some(libc::SYS_rt_sigtimedwait),
        "rt_sigqueueinfo" => Some(libc::SYS_rt_sigqueueinfo),
        "rt_sigreturn" => Some(libc::SYS_rt_sigreturn),
        "ioctl" => Some(libc::SYS_ioctl),
        "pread64" => Some(libc::SYS_pread64),
        "pwrite64" => Some(libc::SYS_pwrite64),
        "readv" => Some(libc::SYS_readv),
        "writev" => Some(libc::SYS_writev),
        "access" => Some(libc::SYS_access),
        "pipe" => Some(libc::SYS_pipe),
        "select" => Some(libc::SYS_select),
        "sched_yield" => Some(libc::SYS_sched_yield),
        "mremap" => Some(libc::SYS_mremap),
        "msync" => Some(libc::SYS_msync),
        "mincore" => Some(libc::SYS_mincore),
        "madvise" => Some(libc::SYS_madvise),
        "shmget" => Some(libc::SYS_shmget),
        "shmat" => Some(libc::SYS_shmat),
        "shmctl" => Some(libc::SYS_shmctl),
        "dup" => Some(libc::SYS_dup),
        "dup2" => Some(libc::SYS_dup2),
        "pause" => Some(libc::SYS_pause),
        "nanosleep" => Some(libc::SYS_nanosleep),
        "getitimer" => Some(libc::SYS_getitimer),
        "alarm" => Some(libc::SYS_alarm),
        "setitimer" => Some(libc::SYS_setitimer),
        "getpid" => Some(libc::SYS_getpid),
        "sendfile" => Some(libc::SYS_sendfile),
        "socket" => Some(libc::SYS_socket),
        "connect" => Some(libc::SYS_connect),
        "accept" => Some(libc::SYS_accept),
        "sendto" => Some(libc::SYS_sendto),
        "recvfrom" => Some(libc::SYS_recvfrom),
        "sendmsg" => Some(libc::SYS_sendmsg),
        "recvmsg" => Some(libc::SYS_recvmsg),
        "shutdown" => Some(libc::SYS_shutdown),
        "bind" => Some(libc::SYS_bind),
        "listen" => Some(libc::SYS_listen),
        "getsockname" => Some(libc::SYS_getsockname),
        "getpeername" => Some(libc::SYS_getpeername),
        "socketpair" => Some(libc::SYS_socketpair),
        "setsockopt" => Some(libc::SYS_setsockopt),
        "getsockopt" => Some(libc::SYS_getsockopt),
        "clone" => Some(libc::SYS_clone),
        "fork" => Some(libc::SYS_fork),
        "vfork" => Some(libc::SYS_vfork),
        "execve" => Some(libc::SYS_execve),
        "exit" => Some(libc::SYS_exit),
        "wait4" => Some(libc::SYS_wait4),
        "waitpid" => Some(libc::SYS_wait4),
        "kill" => Some(libc::SYS_kill),
        "uname" => Some(libc::SYS_uname),
        "fcntl" => Some(libc::SYS_fcntl),
        "flock" => Some(libc::SYS_flock),
        "fsync" => Some(libc::SYS_fsync),
        "fdatasync" => Some(libc::SYS_fdatasync),
        "truncate" => Some(libc::SYS_truncate),
        "ftruncate" => Some(libc::SYS_ftruncate),
        "getdents" => Some(libc::SYS_getdents),
        "getcwd" => Some(libc::SYS_getcwd),
        "chdir" => Some(libc::SYS_chdir),
        "fchdir" => Some(libc::SYS_fchdir),
        "rename" => Some(libc::SYS_rename),
        "mkdir" => Some(libc::SYS_mkdir),
        "rmdir" => Some(libc::SYS_rmdir),
        "creat" => Some(libc::SYS_creat),
        "link" => Some(libc::SYS_link),
        "unlink" => Some(libc::SYS_unlink),
        "symlink" => Some(libc::SYS_symlink),
        "readlink" => Some(libc::SYS_readlink),
        "chmod" => Some(libc::SYS_chmod),
        "fchmod" => Some(libc::SYS_fchmod),
        "chown" => Some(libc::SYS_chown),
        "fchown" => Some(libc::SYS_fchown),
        "lchown" => Some(libc::SYS_lchown),
        "umask" => Some(libc::SYS_umask),
        "gettimeofday" => Some(libc::SYS_gettimeofday),
        "getrlimit" => Some(libc::SYS_getrlimit),
        "getrusage" => Some(libc::SYS_getrusage),
        "sysinfo" => Some(libc::SYS_sysinfo),
        "times" => Some(libc::SYS_times),
        "ptrace" => Some(libc::SYS_ptrace),
        "getuid" => Some(libc::SYS_getuid),
        "syslog" => Some(libc::SYS_syslog),
        "getgid" => Some(libc::SYS_getgid),
        "setuid" => Some(libc::SYS_setuid),
        "setgid" => Some(libc::SYS_setgid),
        "geteuid" => Some(libc::SYS_geteuid),
        "getegid" => Some(libc::SYS_getegid),
        "setpgid" => Some(libc::SYS_setpgid),
        "getppid" => Some(libc::SYS_getppid),
        "getpgrp" => Some(libc::SYS_getpgrp),
        "setsid" => Some(libc::SYS_setsid),
        "setreuid" => Some(libc::SYS_setreuid),
        "setregid" => Some(libc::SYS_setregid),
        "getgroups" => Some(libc::SYS_getgroups),
        "setgroups" => Some(libc::SYS_setgroups),
        "setresuid" => Some(libc::SYS_setresuid),
        "getresuid" => Some(libc::SYS_getresuid),
        "setresgid" => Some(libc::SYS_setresgid),
        "getresgid" => Some(libc::SYS_getresgid),
        "getpgid" => Some(libc::SYS_getpgid),
        "setfsuid" => Some(libc::SYS_setfsuid),
        "setfsgid" => Some(libc::SYS_setfsgid),
        "getsid" => Some(libc::SYS_getsid),
        "capget" => Some(libc::SYS_capget),
        "capset" => Some(libc::SYS_capset),
        "rt_sigsuspend" => Some(libc::SYS_rt_sigsuspend),
        "sigaltstack" => Some(libc::SYS_sigaltstack),
        "utime" => Some(libc::SYS_utime),
        "mknod" => Some(libc::SYS_mknod),
        "uselib" => Some(libc::SYS_uselib),
        "personality" => Some(libc::SYS_personality),
        "ustat" => Some(libc::SYS_ustat),
        "statfs" => Some(libc::SYS_statfs),
        "fstatfs" => Some(libc::SYS_fstatfs),
        "sysfs" => Some(libc::SYS_sysfs),
        "getpriority" => Some(libc::SYS_getpriority),
        "setpriority" => Some(libc::SYS_setpriority),
        "sched_setparam" => Some(libc::SYS_sched_setparam),
        "sched_getparam" => Some(libc::SYS_sched_getparam),
        "sched_setscheduler" => Some(libc::SYS_sched_setscheduler),
        "sched_getscheduler" => Some(libc::SYS_sched_getscheduler),
        "sched_get_priority_max" => Some(libc::SYS_sched_get_priority_max),
        "sched_get_priority_min" => Some(libc::SYS_sched_get_priority_min),
        "sched_rr_get_interval" => Some(libc::SYS_sched_rr_get_interval),
        "mlock" => Some(libc::SYS_mlock),
        "munlock" => Some(libc::SYS_munlock),
        "mlockall" => Some(libc::SYS_mlockall),
        "munlockall" => Some(libc::SYS_munlockall),
        "vhangup" => Some(libc::SYS_vhangup),
        "modify_ldt" => Some(libc::SYS_modify_ldt),
        "_sysctl" => Some(libc::SYS__sysctl),
        "prctl" => Some(libc::SYS_prctl),
        "arch_prctl" => Some(libc::SYS_arch_prctl),
        "adjtimex" => Some(libc::SYS_adjtimex),
        "setrlimit" => Some(libc::SYS_setrlimit),
        "chroot" => Some(libc::SYS_chroot),
        "sync" => Some(libc::SYS_sync),
        "acct" => Some(libc::SYS_acct),
        "settimeofday" => Some(libc::SYS_settimeofday),
        "mount" => Some(libc::SYS_mount),
        "pivot_root" => Some(libc::SYS_pivot_root),
        "umount2" => Some(libc::SYS_umount2),
        "swapon" => Some(libc::SYS_swapon),
        "swapoff" => Some(libc::SYS_swapoff),
        "reboot" => Some(libc::SYS_reboot),
        "sethostname" => Some(libc::SYS_sethostname),
        "setdomainname" => Some(libc::SYS_setdomainname),
        "iopl" => Some(libc::SYS_iopl),
        "ioperm" => Some(libc::SYS_ioperm),
        "init_module" => Some(libc::SYS_init_module),
        "delete_module" => Some(libc::SYS_delete_module),
        "quotactl" => Some(libc::SYS_quotactl),
        "nfsservctl" => Some(libc::SYS_nfsservctl),
        "getpmsg" => Some(libc::SYS_getpmsg),
        "putpmsg" => Some(libc::SYS_putpmsg),
        "afs_syscall" => Some(libc::SYS_afs_syscall),
        "tuxcall" => Some(libc::SYS_tuxcall),
        "security" => Some(libc::SYS_security),
        "gettid" => Some(libc::SYS_gettid),
        "readahead" => Some(libc::SYS_readahead),
        "setxattr" => Some(libc::SYS_setxattr),
        "lsetxattr" => Some(libc::SYS_lsetxattr),
        "fsetxattr" => Some(libc::SYS_fsetxattr),
        "getxattr" => Some(libc::SYS_getxattr),
        "lgetxattr" => Some(libc::SYS_lgetxattr),
        "fgetxattr" => Some(libc::SYS_fgetxattr),
        "listxattr" => Some(libc::SYS_listxattr),
        "llistxattr" => Some(libc::SYS_llistxattr),
        "flistxattr" => Some(libc::SYS_flistxattr),
        "removexattr" => Some(libc::SYS_removexattr),
        "lremovexattr" => Some(libc::SYS_lremovexattr),
        "fremovexattr" => Some(libc::SYS_fremovexattr),
        "tkill" => Some(libc::SYS_tkill),
        "time" => Some(libc::SYS_time),
        "futex" => Some(libc::SYS_futex),
        "sched_setaffinity" => Some(libc::SYS_sched_setaffinity),
        "sched_getaffinity" => Some(libc::SYS_sched_getaffinity),
        "set_thread_area" => Some(libc::SYS_set_thread_area),
        "io_setup" => Some(libc::SYS_io_setup),
        "io_destroy" => Some(libc::SYS_io_destroy),
        "io_getevents" => Some(libc::SYS_io_getevents),
        "io_submit" => Some(libc::SYS_io_submit),
        "io_cancel" => Some(libc::SYS_io_cancel),
        "get_thread_area" => Some(libc::SYS_get_thread_area),
        "lookup_dcookie" => Some(libc::SYS_lookup_dcookie),
        "epoll_create" => Some(libc::SYS_epoll_create),
        "epoll_ctl_old" => Some(libc::SYS_epoll_ctl_old),
        "epoll_wait_old" => Some(libc::SYS_epoll_wait_old),
        "remap_file_pages" => Some(libc::SYS_remap_file_pages),
        "getdents64" => Some(libc::SYS_getdents64),
        "set_tid_address" => Some(libc::SYS_set_tid_address),
        "restart_syscall" => Some(libc::SYS_restart_syscall),
        "semtimedop" => Some(libc::SYS_semtimedop),
        "fadvise64" => Some(libc::SYS_fadvise64),
        "timer_create" => Some(libc::SYS_timer_create),
        "timer_settime" => Some(libc::SYS_timer_settime),
        "timer_gettime" => Some(libc::SYS_timer_gettime),
        "timer_getoverrun" => Some(libc::SYS_timer_getoverrun),
        "timer_delete" => Some(libc::SYS_timer_delete),
        "clock_settime" => Some(libc::SYS_clock_settime),
        "clock_gettime" => Some(libc::SYS_clock_gettime),
        "clock_getres" => Some(libc::SYS_clock_getres),
        "clock_nanosleep" => Some(libc::SYS_clock_nanosleep),
        "exit_group" => Some(libc::SYS_exit_group),
        "epoll_wait" => Some(libc::SYS_epoll_wait),
        "epoll_ctl" => Some(libc::SYS_epoll_ctl),
        "tgkill" => Some(libc::SYS_tgkill),
        "utimes" => Some(libc::SYS_utimes),
        "vserver" => Some(libc::SYS_vserver),
        "mbind" => Some(libc::SYS_mbind),
        "set_mempolicy" => Some(libc::SYS_set_mempolicy),
        "get_mempolicy" => Some(libc::SYS_get_mempolicy),
        "mq_open" => Some(libc::SYS_mq_open),
        "mq_unlink" => Some(libc::SYS_mq_unlink),
        "mq_timedsend" => Some(libc::SYS_mq_timedsend),
        "mq_timedreceive" => Some(libc::SYS_mq_timedreceive),
        "mq_notify" => Some(libc::SYS_mq_notify),
        "mq_getsetattr" => Some(libc::SYS_mq_getsetattr),
        "kexec_load" => Some(libc::SYS_kexec_load),
        "waitid" => Some(libc::SYS_waitid),
        "add_key" => Some(libc::SYS_add_key),
        "request_key" => Some(libc::SYS_request_key),
        "keyctl" => Some(libc::SYS_keyctl),
        "ioprio_set" => Some(libc::SYS_ioprio_set),
        "ioprio_get" => Some(libc::SYS_ioprio_get),
        "inotify_init" => Some(libc::SYS_inotify_init),
        "inotify_add_watch" => Some(libc::SYS_inotify_add_watch),
        "inotify_rm_watch" => Some(libc::SYS_inotify_rm_watch),
        "migrate_pages" => Some(libc::SYS_migrate_pages),
        "openat" => Some(libc::SYS_openat),
        "mkdirat" => Some(libc::SYS_mkdirat),
        "mknodat" => Some(libc::SYS_mknodat),
        "fchownat" => Some(libc::SYS_fchownat),
        "futimesat" => Some(libc::SYS_futimesat),
        "newfstatat" => Some(libc::SYS_newfstatat),
        "unlinkat" => Some(libc::SYS_unlinkat),
        "renameat" => Some(libc::SYS_renameat),
        "linkat" => Some(libc::SYS_linkat),
        "symlinkat" => Some(libc::SYS_symlinkat),
        "readlinkat" => Some(libc::SYS_readlinkat),
        "fchmodat" => Some(libc::SYS_fchmodat),
        "faccessat" => Some(libc::SYS_faccessat),
        "pselect6" => Some(libc::SYS_pselect6),
        "ppoll" => Some(libc::SYS_ppoll),
        "unshare" => Some(libc::SYS_unshare),
        "set_robust_list" => Some(libc::SYS_set_robust_list),
        "get_robust_list" => Some(libc::SYS_get_robust_list),
        "splice" => Some(libc::SYS_splice),
        "tee" => Some(libc::SYS_tee),
        "sync_file_range" => Some(libc::SYS_sync_file_range),
        "vmsplice" => Some(libc::SYS_vmsplice),
        "move_pages" => Some(libc::SYS_move_pages),
        "utimensat" => Some(libc::SYS_utimensat),
        "epoll_pwait" => Some(libc::SYS_epoll_pwait),
        "signalfd" => Some(libc::SYS_signalfd),
        "timerfd_create" => Some(libc::SYS_timerfd_create),
        "eventfd" => Some(libc::SYS_eventfd),
        "fallocate" => Some(libc::SYS_fallocate),
        "timerfd_settime" => Some(libc::SYS_timerfd_settime),
        "timerfd_gettime" => Some(libc::SYS_timerfd_gettime),
        "accept4" => Some(libc::SYS_accept4),
        "signalfd4" => Some(libc::SYS_signalfd4),
        "eventfd2" => Some(libc::SYS_eventfd2),
        "epoll_create1" => Some(libc::SYS_epoll_create1),
        "dup3" => Some(libc::SYS_dup3),
        "pipe2" => Some(libc::SYS_pipe2),
        "inotify_init1" => Some(libc::SYS_inotify_init1),
        "preadv" => Some(libc::SYS_preadv),
        "pwritev" => Some(libc::SYS_pwritev),
        "rt_tgsigqueueinfo" => Some(libc::SYS_rt_tgsigqueueinfo),
        "perf_event_open" => Some(libc::SYS_perf_event_open),
        "recvmmsg" => Some(libc::SYS_recvmmsg),
        "fanotify_init" => Some(libc::SYS_fanotify_init),
        "fanotify_mark" => Some(libc::SYS_fanotify_mark),
        "prlimit64" => Some(libc::SYS_prlimit64),
        "name_to_handle_at" => Some(libc::SYS_name_to_handle_at),
        "open_by_handle_at" => Some(libc::SYS_open_by_handle_at),
        "clock_adjtime" => Some(libc::SYS_clock_adjtime),
        "syncfs" => Some(libc::SYS_syncfs),
        "sendmmsg" => Some(libc::SYS_sendmmsg),
        "setns" => Some(libc::SYS_setns),
        "getcpu" => Some(libc::SYS_getcpu),
        "process_vm_readv" => Some(libc::SYS_process_vm_readv),
        "process_vm_writev" => Some(libc::SYS_process_vm_writev),
        "kcmp" => Some(libc::SYS_kcmp),
        "finit_module" => Some(libc::SYS_finit_module),
        "sched_setattr" => Some(libc::SYS_sched_setattr),
        "sched_getattr" => Some(libc::SYS_sched_getattr),
        "renameat2" => Some(libc::SYS_renameat2),
        "seccomp" => Some(libc::SYS_seccomp),
        "getrandom" => Some(libc::SYS_getrandom),
        "memfd_create" => Some(libc::SYS_memfd_create),
        "kexec_file_load" => Some(libc::SYS_kexec_file_load),
        "bpf" => Some(libc::SYS_bpf),
        "execveat" => Some(libc::SYS_execveat),
        "userfaultfd" => Some(libc::SYS_userfaultfd),
        "membarrier" => Some(libc::SYS_membarrier),
        "mlock2" => Some(libc::SYS_mlock2),
        "copy_file_range" => Some(libc::SYS_copy_file_range),
        "preadv2" => Some(libc::SYS_preadv2),
        "pwritev2" => Some(libc::SYS_pwritev2),
        "pkey_mprotect" => Some(libc::SYS_pkey_mprotect),
        "pkey_alloc" => Some(libc::SYS_pkey_alloc),
        "pkey_free" => Some(libc::SYS_pkey_free),
        "statx" => Some(libc::SYS_statx),
        "rseq" => Some(libc::SYS_rseq),
        "pidfd_send_signal" => Some(libc::SYS_pidfd_send_signal),
        "io_uring_setup" => Some(libc::SYS_io_uring_setup),
        "io_uring_enter" => Some(libc::SYS_io_uring_enter),
        "io_uring_register" => Some(libc::SYS_io_uring_register),
        "open_tree" => Some(libc::SYS_open_tree),
        "move_mount" => Some(libc::SYS_move_mount),
        "fsopen" => Some(libc::SYS_fsopen),
        "fsconfig" => Some(libc::SYS_fsconfig),
        "fsmount" => Some(libc::SYS_fsmount),
        "fspick" => Some(libc::SYS_fspick),
        "pidfd_open" => Some(libc::SYS_pidfd_open),
        "clone3" => Some(libc::SYS_clone3),
        "close_range" => Some(libc::SYS_close_range),
        "openat2" => Some(libc::SYS_openat2),
        "pidfd_getfd" => Some(libc::SYS_pidfd_getfd),
        "faccessat2" => Some(libc::SYS_faccessat2),
        "process_madvise" => Some(libc::SYS_process_madvise),
        "epoll_pwait2" => Some(libc::SYS_epoll_pwait2),
        "mount_setattr" => Some(libc::SYS_mount_setattr),
        "quotactl_fd" => Some(libc::SYS_quotactl_fd),
        "landlock_create_ruleset" => Some(libc::SYS_landlock_create_ruleset),
        "landlock_add_rule" => Some(libc::SYS_landlock_add_rule),
        "landlock_restrict_self" => Some(libc::SYS_landlock_restrict_self),
        "memfd_secret" => Some(libc::SYS_memfd_secret),
        "process_mrelease" => Some(libc::SYS_process_mrelease),
        "futex_waitv" => Some(libc::SYS_futex_waitv),
        "set_mempolicy_home_node" => Some(libc::SYS_set_mempolicy_home_node),
        "fchmodat2" => Some(libc::SYS_fchmodat2),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::super::seccomp::{SeccompFilter, SeccompProfile};
    use super::*;

    #[test]
    fn test_compile_minimal_filter() {
        let filter = SeccompFilter::minimal();
        let result = SeccompBpf::compile(&filter);
        assert!(result.is_ok());
        let bpf_code = result.unwrap();
        assert!(!bpf_code.is_empty());
    }

    #[test]
    fn test_compile_io_heavy_filter() {
        let filter = SeccompFilter::from_profile(SeccompProfile::IoHeavy);
        let result = SeccompBpf::compile(&filter);
        assert!(result.is_ok());
        let bpf_code = result.unwrap();
        assert!(!bpf_code.is_empty());
    }

    #[test]
    fn test_compile_network_filter() {
        let filter = SeccompFilter::from_profile(SeccompProfile::Network);
        let result = SeccompBpf::compile(&filter);
        assert!(result.is_ok());
        let bpf_code = result.unwrap();
        assert!(!bpf_code.is_empty());
    }

    #[test]
    fn test_all_allowed_syscalls_have_numbers() {
        for profile in SeccompProfile::all() {
            let filter = SeccompFilter::from_profile(profile);
            for syscall in filter.allowed_syscalls() {
                assert!(
                    get_syscall_number_from_name(syscall).is_some(),
                    "missing number for syscall '{}'",
                    syscall
                );
            }
        }
    }

    #[test]
    fn test_compile_compute_filter() {
        let filter = SeccompFilter::from_profile(SeccompProfile::Compute);
        let result = SeccompBpf::compile(&filter);
        assert!(result.is_ok());
        let bpf_code = result.unwrap();
        assert!(!bpf_code.is_empty());
    }

    #[test]
    fn test_compile_with_blocked_syscall() {
        let mut filter = SeccompFilter::minimal();
        filter.block_syscall("ptrace");
        let result = SeccompBpf::compile(&filter);
        assert!(result.is_ok());
    }

    #[test]
    fn test_compile_kill_on_violation_true() {
        let filter = SeccompFilter::minimal();
        assert!(filter.is_kill_on_violation());
        let result = SeccompBpf::compile(&filter);
        assert!(result.is_ok());
    }

    #[test]
    fn test_compile_kill_on_violation_false() {
        let mut filter = SeccompFilter::minimal();
        filter.set_kill_on_violation(false);
        assert!(!filter.is_kill_on_violation());
        let result = SeccompBpf::compile(&filter);
        assert!(result.is_ok());
    }

    #[test]
    fn test_compile_unrestricted_profile() {
        let filter = SeccompFilter::from_profile(SeccompProfile::Unrestricted);
        let result = SeccompBpf::compile(&filter);
        assert!(result.is_ok());
        let bpf_code = result.unwrap();
        assert!(!bpf_code.is_empty());
    }

    #[test]
    fn test_get_syscall_number_returns_none_for_invalid() {
        let result = get_syscall_number_from_name("nonexistent_syscall_xyz");
        assert!(result.is_none());
    }

    #[test]
    fn test_get_syscall_number_returns_some_for_valid() {
        let result = get_syscall_number_from_name("read");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), libc::SYS_read);
    }

    #[test]
    fn test_compile_with_blocked_syscalls() {
        let mut filter = SeccompFilter::minimal();
        filter.block_syscall("ptrace");
        let result = SeccompBpf::compile(&filter);
        assert!(result.is_ok());
    }

    #[test]
    fn test_compile_io_heavy_profile() {
        let filter = SeccompFilter::from_profile(SeccompProfile::IoHeavy);
        let result = SeccompBpf::compile(&filter);
        assert!(result.is_ok());
        let bpf_code = result.unwrap();
        assert!(!bpf_code.is_empty());
    }

    #[test]
    fn test_compile_network_profile() {
        let filter = SeccompFilter::from_profile(SeccompProfile::Network);
        let result = SeccompBpf::compile(&filter);
        assert!(result.is_ok());
        let bpf_code = result.unwrap();
        assert!(!bpf_code.is_empty());
    }

    #[test]
    fn test_load_rejects_unknown_syscalls() {
        let mut filter = SeccompFilter::minimal();
        filter.allow_syscall("syscall_que_nao_existe_xyz_123");

        let result = SeccompBpf::compile(&filter);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Unknown syscall"));
    }

    #[test]
    fn test_load_with_unknown_syscalls_allowed() {
        let mut filter = SeccompFilter::minimal();
        filter.allow_syscall("syscall_inexistente");
        filter.set_allow_unknown_syscalls(true);
        let result = SeccompBpf::compile(&filter);
        assert!(result.is_ok());
    }

    #[test]
    fn test_unrestricted_blocks_specified_syscalls() {
        let mut filter = SeccompFilter::from_profile(SeccompProfile::Unrestricted);
        filter.block_syscall("ptrace");

        let result = SeccompBpf::compile(&filter);
        assert!(result.is_ok());
    }

    #[test]
    fn test_unknown_blocked_syscall_error() {
        let mut filter = SeccompFilter::from_profile(SeccompProfile::Unrestricted);
        filter.block_syscall("syscall_invalida_xyz");

        let result = SeccompBpf::compile(&filter);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Unknown syscall to block"));
    }
}
