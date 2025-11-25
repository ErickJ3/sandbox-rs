//! Seccomp BPF filter compilation and loading

use super::seccomp::SeccompFilter;
use crate::errors::{Result, SandboxError};

/// Compiled BPF instruction
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BpfInstr {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// Seccomp action codes
pub mod actions {
    /// Kill the process
    pub const SECCOMP_RET_KILL: u32 = 0x00000000;
    /// Trigger SIGSYS with architecture-specific si_code
    pub const SECCOMP_RET_TRAP: u32 = 0x00030000;
    /// Return errno value
    pub const SECCOMP_RET_ERRNO: u32 = 0x00050000;
    /// Load into trace_syscall_table (not recommended)
    pub const SECCOMP_RET_TRACE: u32 = 0x7ff00000;
    /// Allow syscall
    pub const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;
}

/// BPF architecture codes
pub mod arch {
    pub const AUDIT_ARCH_X86_64: u32 = 0xc000003e;
    pub const AUDIT_ARCH_I386: u32 = 0x40000003;
    pub const AUDIT_ARCH_ARM: u32 = 0x40000028;
    pub const AUDIT_ARCH_AARCH64: u32 = 0xc00000b7;
}

/// Get current architecture code
pub fn get_arch() -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        arch::AUDIT_ARCH_X86_64
    }
    #[cfg(target_arch = "x86")]
    {
        arch::AUDIT_ARCH_I386
    }
    #[cfg(target_arch = "arm")]
    {
        arch::AUDIT_ARCH_ARM
    }
    #[cfg(target_arch = "aarch64")]
    {
        arch::AUDIT_ARCH_AARCH64
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "arm",
        target_arch = "aarch64"
    )))]
    {
        0
    }
}

/// Syscall number mapping for x86_64
#[derive(Debug, Clone, Copy)]
pub struct SyscallNumber(pub u32);

impl SyscallNumber {
    /// Get syscall number by name (x86_64)
    pub fn from_name(name: &str) -> Option<Self> {
        let num = match name {
            // Process management
            "exit" => 60,
            "exit_group" => 231,
            "clone" => 56,
            "fork" => 57,
            "vfork" => 58,
            // Signal handling
            "rt_sigaction" => 13,
            "rt_sigprocmask" => 14,
            "rt_sigpending" => 127,
            "rt_sigtimedwait" => 128,
            "rt_sigqueueinfo" => 129,
            "rt_sigreturn" => 15,
            "kill" => 62,
            "tkill" => 200,
            "tgkill" => 268,
            "sigaltstack" => 131,
            // Basic I/O
            "read" => 0,
            "write" => 1,
            "readv" => 19,
            "writev" => 20,
            "pread64" => 17,
            "pwrite64" => 18,
            // File operations
            "open" => 2,
            "openat" => 257,
            "close" => 3,
            "stat" => 4,
            "fstat" => 5,
            "lstat" => 6,
            "fcntl" => 72,
            "ioctl" => 16,
            // Memory
            "mmap" => 9,
            "munmap" => 11,
            "mremap" => 25,
            "mprotect" => 10,
            "madvise" => 28,
            "brk" => 12,
            "mlock" => 149,
            "munlock" => 150,
            "mlockall" => 151,
            "munlockall" => 152,
            // Process execution
            "execve" => 59,
            "execveat" => 322,
            // Waiting
            "wait4" => 114,
            "waitpid" => 114,
            "waitid" => 247,
            // File descriptors
            "dup" => 32,
            "dup2" => 33,
            "dup3" => 292,
            // Getting time
            "clock_gettime" => 228,
            "clock_getres" => 229,
            "gettimeofday" => 96,
            "time" => 201,
            // Process info
            "getpid" => 39,
            "getppid" => 110,
            "getuid" => 102,
            "geteuid" => 107,
            "getgid" => 104,
            "getegid" => 108,
            "getpgrp" => 111,
            "getpgid" => 121,
            "getsid" => 124,
            // Limits
            "getrlimit" => 97,
            "setrlimit" => 160,
            "getrusage" => 98,
            // Misc
            "futex" => 202,
            "set_tid_address" => 218,
            "set_robust_list" => 273,
            "get_robust_list" => 274,
            "pselect6" => 270,
            "ppoll" => 271,
            "epoll_create1" => 291,
            "epoll_ctl" => 233,
            "epoll_wait" => 232,
            "poll" => 7,
            "select" => 23,
            "getcwd" => 79,
            "chdir" => 80,
            "fchdir" => 81,
            "getdents" => 78,
            "getdents64" => 217,
            "prctl" => 157,
            "arch_prctl" => 158,
            // File operations (IO heavy)
            "mkdir" => 83,
            "mkdirat" => 258,
            "rmdir" => 84,
            "unlink" => 87,
            "unlinkat" => 263,
            "rename" => 82,
            "renameat" => 264,
            "link" => 86,
            "linkat" => 265,
            "symlink" => 88,
            "symlinkat" => 266,
            "readlink" => 89,
            "readlinkat" => 267,
            "chmod" => 90,
            "fchmod" => 91,
            "fchmodat" => 268,
            "chown" => 92,
            "fchown" => 93,
            "fchownat" => 260,
            "lchown" => 94,
            "utimes" => 235,
            "futimes" => 271,
            "utime" => 132,
            "utimensat" => 280,
            "truncate" => 76,
            "ftruncate" => 77,
            "fallocate" => 285,
            "access" => 21,
            "faccessat" => 269,
            "sendfile" => 40,
            "splice" => 275,
            "tee" => 276,
            "vmsplice" => 278,
            "statfs" => 137,
            "fstatfs" => 138,
            "fsync" => 74,
            "fdatasync" => 75,
            // Network
            "socket" => 41,
            "socketpair" => 53,
            "bind" => 49,
            "listen" => 50,
            "accept" => 43,
            "accept4" => 288,
            "connect" => 42,
            "shutdown" => 48,
            "sendto" => 44,
            "recvfrom" => 45,
            "sendmsg" => 46,
            "recvmsg" => 47,
            "sendmmsg" => 307,
            "recvmmsg" => 299,
            "setsockopt" => 54,
            "getsockopt" => 55,
            "setsockname" => 106,
            "getsockname" => 51,
            "getpeername" => 52,
            // Dangerous (unrestricted)
            "ptrace" => 101,
            "process_vm_readv" => 310,
            "process_vm_writev" => 311,
            "perf_event_open" => 298,
            "bpf" => 321,
            "seccomp" => 317,
            "mount" => 165,
            "umount2" => 166,
            "pivot_root" => 155,
            "capget" => 125,
            "capset" => 126,
            "setuid" => 105,
            "setgid" => 106,
            "setreuid" => 113,
            "setregid" => 114,
            "setresuid" => 164,
            "setresgid" => 170,
            "getgroups" => 115,
            "setgroups" => 116,
            "setfsgid" => 123,
            "setfsuid" => 122,
            _ => return None,
        };
        Some(SyscallNumber(num as u32))
    }
}

/// BPF filter compiler
pub struct SeccompCompiler;

impl SeccompCompiler {
    /// Compile a filter to BPF instructions
    pub fn compile(filter: &SeccompFilter) -> Result<Vec<BpfInstr>> {
        let mut instrs = Vec::new();

        // Check architecture
        instrs.push(BpfInstr {
            code: 0x20, // LD.W M[0] (load word from memory offset 0)
            jt: 0,
            jf: 0,
            k: 4, // offset of arch in seccomp_data
        });

        let arch = get_arch();
        instrs.push(BpfInstr {
            code: 0x15, // JEQ (jump if equal)
            jt: 1,      // jump if true
            jf: 0,      // jump if false (skip next)
            k: arch,
        });

        // Reject if wrong architecture
        instrs.push(BpfInstr {
            code: 0x06, // RET
            jt: 0,
            jf: 0,
            k: actions::SECCOMP_RET_KILL,
        });

        // Load syscall number
        instrs.push(BpfInstr {
            code: 0x20, // LD.W
            jt: 0,
            jf: 0,
            k: 0, // offset of syscall number in seccomp_data
        });

        // Build jump table for allowed syscalls
        let allowed = filter.allowed_syscalls();
        let blocked = filter.blocked_syscalls();

        for syscall_name in allowed.iter() {
            if blocked.contains(syscall_name) {
                continue; // Skip blocked syscalls
            }

            if let Some(SyscallNumber(num)) = SyscallNumber::from_name(syscall_name) {
                instrs.push(BpfInstr {
                    code: 0x15, // JEQ
                    jt: 1,      // jump if equal
                    jf: 0,      // default
                    k: num,
                });

                // Allow this syscall
                instrs.push(BpfInstr {
                    code: 0x06, // RET
                    jt: 0,
                    jf: 0,
                    k: actions::SECCOMP_RET_ALLOW,
                });
            }
        }

        // Default: reject if no match
        if filter.is_kill_on_violation() {
            instrs.push(BpfInstr {
                code: 0x06, // RET
                jt: 0,
                jf: 0,
                k: actions::SECCOMP_RET_KILL,
            });
        } else {
            instrs.push(BpfInstr {
                code: 0x06, // RET
                jt: 0,
                jf: 0,
                k: actions::SECCOMP_RET_TRAP,
            });
        }

        Ok(instrs)
    }

    /// Load BPF filter via prctl
    pub fn load(filter: &SeccompFilter) -> Result<()> {
        let instrs = Self::compile(filter)?;

        // Convert to raw format for prctl (keep native_instrs alive while loading)
        let (_native_instrs, prog) = instrs_to_sock_fprog(&instrs);

        unsafe {
            // Kernel requires NO_NEW_PRIVS before enabling seccomp filters when unprivileged
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(SandboxError::Seccomp(format!(
                    "Failed to set PR_SET_NO_NEW_PRIVS: {}",
                    std::io::Error::last_os_error()
                )));
            }

            let ret = libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &prog as *const _,
            );

            if ret != 0 {
                return Err(SandboxError::Seccomp(format!(
                    "Failed to load seccomp filter: {}",
                    std::io::Error::last_os_error()
                )));
            }
        }

        Ok(())
    }
}

/// Convert BpfInstr to sock_fprog format
fn instrs_to_sock_fprog(instrs: &[BpfInstr]) -> (Vec<bpf_insn>, sockfprog) {
    let native_instrs: Vec<bpf_insn> = instrs.iter().copied().map(bpf_insn::from).collect();
    let prog = sockfprog {
        len: native_instrs.len() as u16,
        filter: native_instrs.as_ptr() as *mut bpf_insn,
    };
    (native_instrs, prog)
}

/// BPF instruction struct (same as kernel)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct bpf_insn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl From<BpfInstr> for bpf_insn {
    fn from(instr: BpfInstr) -> Self {
        bpf_insn {
            code: instr.code,
            jt: instr.jt,
            jf: instr.jf,
            k: instr.k,
        }
    }
}

/// Socket filter program (for prctl)
#[repr(C)]
struct sockfprog {
    len: u16,
    filter: *mut bpf_insn,
}

#[cfg(test)]
mod tests {
    use super::super::seccomp::{SeccompFilter, SeccompProfile};
    use super::*;

    #[test]
    fn test_get_arch() {
        let arch = get_arch();
        #[cfg(target_arch = "x86_64")]
        assert_eq!(arch, arch::AUDIT_ARCH_X86_64);
    }

    #[test]
    fn test_syscall_number_read() {
        let num = SyscallNumber::from_name("read").unwrap();
        assert_eq!(num.0, 0);
    }

    #[test]
    fn test_syscall_number_write() {
        let num = SyscallNumber::from_name("write").unwrap();
        assert_eq!(num.0, 1);
    }

    #[test]
    fn test_syscall_number_invalid() {
        let num = SyscallNumber::from_name("invalid_syscall");
        assert!(num.is_none());
    }

    #[test]
    fn test_syscall_number_exit() {
        let num = SyscallNumber::from_name("exit").unwrap();
        assert_eq!(num.0, 60);
    }

    #[test]
    fn test_syscall_number_execve() {
        let num = SyscallNumber::from_name("execve").unwrap();
        assert_eq!(num.0, 59);
    }

    #[test]
    fn test_compile_minimal_filter() {
        let filter = SeccompFilter::minimal();
        let result = SeccompCompiler::compile(&filter);
        assert!(result.is_ok());

        let instrs = result.unwrap();
        assert!(!instrs.is_empty());
    }

    #[test]
    fn test_compile_io_heavy_filter() {
        let filter = SeccompFilter::from_profile(SeccompProfile::IoHeavy);
        let result = SeccompCompiler::compile(&filter);
        assert!(result.is_ok());

        let instrs = result.unwrap();
        assert!(instrs.len() > 5);
    }

    #[test]
    fn test_bpf_instr_creation() {
        let instr = BpfInstr {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: actions::SECCOMP_RET_ALLOW,
        };

        assert_eq!(instr.code, 0x06);
        assert_eq!(instr.k, actions::SECCOMP_RET_ALLOW);
    }

    #[test]
    fn test_actions_values() {
        assert_eq!(actions::SECCOMP_RET_KILL, 0x00000000);
        assert_eq!(actions::SECCOMP_RET_ALLOW, 0x7fff0000);
    }

    #[test]
    fn test_multiple_syscall_numbers() {
        let syscalls = vec!["read", "write", "open", "close", "fork"];

        for syscall in syscalls {
            let num = SyscallNumber::from_name(syscall);
            assert!(num.is_some(), "Failed to get number for {}", syscall);
        }
    }
}
