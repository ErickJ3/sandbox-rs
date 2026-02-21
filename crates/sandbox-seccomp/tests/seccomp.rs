//! Seccomp enforcement tests
//!
//! These tests verify that seccomp BPF actually blocks forbidden syscalls.
//! They do NOT require root - seccomp only needs PR_SET_NO_NEW_PRIVS.
//!
//! Each test forks a child process, applies a seccomp filter, and verifies
//! that forbidden syscalls result in process termination via SIGSYS.

use sandbox_seccomp::{SeccompBpf, SeccompFilter, SeccompProfile};

/// Verify that a Minimal seccomp filter kills the process when
/// a forbidden syscall (socket) is attempted.
#[test]
fn seccomp_minimal_blocks_socket() {
    unsafe {
        let pid = libc::fork();
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());

        if pid == 0 {
            // Child: apply Minimal seccomp filter
            let filter = SeccompFilter::from_profile(SeccompProfile::Minimal);
            if SeccompBpf::load(&filter).is_err() {
                libc::_exit(99);
            }

            // socket() is NOT in Minimal profile - should cause SIGSYS
            libc::syscall(libc::SYS_socket, libc::AF_INET, libc::SOCK_STREAM, 0);

            // Should never reach here
            libc::_exit(42);
        } else {
            // Parent: wait for child to be killed
            let mut status: i32 = 0;
            let ret = libc::waitpid(pid, &mut status, 0);
            assert_eq!(ret, pid);

            // Child should have been killed by signal (SIGSYS from seccomp KillProcess)
            assert!(
                libc::WIFSIGNALED(status),
                "Child should have been killed by signal, status=0x{:x}",
                status
            );
            let sig = libc::WTERMSIG(status);
            assert_eq!(
                sig,
                libc::SIGSYS,
                "Expected SIGSYS ({}), got signal {}",
                libc::SIGSYS,
                sig
            );
        }
    }
}

/// Verify that allowed syscalls still work after seccomp is applied.
/// read/write/exit are in the Minimal profile and should succeed.
#[test]
fn seccomp_minimal_allows_basic_io() {
    unsafe {
        let pid = libc::fork();
        assert!(pid >= 0, "fork failed");

        if pid == 0 {
            let filter = SeccompFilter::from_profile(SeccompProfile::Minimal);
            if SeccompBpf::load(&filter).is_err() {
                libc::_exit(99);
            }

            // These are all in Minimal profile and should succeed
            let _ = libc::getpid();
            let buf = b"ok\n";
            libc::write(libc::STDOUT_FILENO, buf.as_ptr() as *const libc::c_void, 3);

            libc::_exit(0);
        } else {
            let mut status: i32 = 0;
            libc::waitpid(pid, &mut status, 0);

            assert!(
                libc::WIFEXITED(status),
                "Child should have exited normally, status=0x{:x}",
                status
            );
            assert_eq!(
                libc::WEXITSTATUS(status),
                0,
                "Child should exit with 0 (allowed syscalls worked)"
            );
        }
    }
}

/// Verify that blocking a specific syscall via block_syscall() works.
/// We allow everything in Minimal but explicitly block getpid.
#[test]
fn seccomp_block_specific_syscall() {
    unsafe {
        let pid = libc::fork();
        assert!(pid >= 0, "fork failed");

        if pid == 0 {
            let mut filter = SeccompFilter::from_profile(SeccompProfile::Minimal);
            filter.block_syscall("getpid");

            if SeccompBpf::load(&filter).is_err() {
                libc::_exit(99);
            }

            // getpid is now blocked - should cause SIGSYS
            libc::getpid();

            libc::_exit(42);
        } else {
            let mut status: i32 = 0;
            libc::waitpid(pid, &mut status, 0);

            assert!(
                libc::WIFSIGNALED(status),
                "Child should have been killed by signal"
            );
            assert_eq!(libc::WTERMSIG(status), libc::SIGSYS);
        }
    }
}

/// Verify that the Network profile allows socket() calls.
#[test]
fn seccomp_network_allows_socket() {
    unsafe {
        let pid = libc::fork();
        assert!(pid >= 0, "fork failed");

        if pid == 0 {
            let filter = SeccompFilter::from_profile(SeccompProfile::Network);
            if SeccompBpf::load(&filter).is_err() {
                libc::_exit(99);
            }

            // socket() IS in Network profile - should succeed
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            if fd >= 0 {
                libc::close(fd);
                libc::_exit(0);
            } else {
                // socket() returned error but wasn't killed - still OK
                // (might fail for non-seccomp reasons like permission)
                libc::_exit(0);
            }
        } else {
            let mut status: i32 = 0;
            libc::waitpid(pid, &mut status, 0);

            assert!(
                libc::WIFEXITED(status),
                "Child should have exited normally (socket allowed in Network profile)"
            );
            assert_eq!(libc::WEXITSTATUS(status), 0);
        }
    }
}

/// Verify that the Essential profile allows process bootstrap (execve, read, write, exit).
#[test]
fn seccomp_essential_allows_bootstrap() {
    unsafe {
        let pid = libc::fork();
        assert!(pid >= 0, "fork failed");

        if pid == 0 {
            let filter = SeccompFilter::from_profile(SeccompProfile::Essential);
            if SeccompBpf::load(&filter).is_err() {
                libc::_exit(99);
            }

            // These are all in Essential profile and should succeed
            let _ = libc::getpid();
            let buf = b"ok\n";
            libc::write(libc::STDOUT_FILENO, buf.as_ptr() as *const libc::c_void, 3);

            libc::_exit(0);
        } else {
            let mut status: i32 = 0;
            libc::waitpid(pid, &mut status, 0);

            assert!(
                libc::WIFEXITED(status),
                "Child should have exited normally, status=0x{:x}",
                status
            );
            assert_eq!(
                libc::WEXITSTATUS(status),
                0,
                "Child should exit with 0 (bootstrap syscalls worked)"
            );
        }
    }
}

/// Verify that the Essential profile blocks socket (not in Essential).
#[test]
fn seccomp_essential_blocks_socket() {
    unsafe {
        let pid = libc::fork();
        assert!(pid >= 0, "fork failed");

        if pid == 0 {
            let filter = SeccompFilter::from_profile(SeccompProfile::Essential);
            if SeccompBpf::load(&filter).is_err() {
                libc::_exit(99);
            }

            // socket() is NOT in Essential profile - should cause SIGSYS
            libc::syscall(libc::SYS_socket, libc::AF_INET, libc::SOCK_STREAM, 0);

            libc::_exit(42);
        } else {
            let mut status: i32 = 0;
            libc::waitpid(pid, &mut status, 0);

            assert!(
                libc::WIFSIGNALED(status),
                "Child should have been killed by signal, status=0x{:x}",
                status
            );
            assert_eq!(libc::WTERMSIG(status), libc::SIGSYS);
        }
    }
}

/// Verify that Network profile can call mkdir (cumulative from IoHeavy).
#[test]
fn seccomp_network_includes_mkdir_from_io_heavy() {
    unsafe {
        let pid = libc::fork();
        assert!(pid >= 0, "fork failed");

        if pid == 0 {
            let filter = SeccompFilter::from_profile(SeccompProfile::Network);
            if SeccompBpf::load(&filter).is_err() {
                libc::_exit(99);
            }

            // mkdir is in IoHeavy extras — Network should include it cumulatively
            let path = b"/tmp/seccomp_cumulative_test_dir\0";
            let ret = libc::mkdir(path.as_ptr() as *const libc::c_char, 0o755);
            if ret == 0 {
                libc::rmdir(path.as_ptr() as *const libc::c_char);
            }
            // Whether mkdir succeeded or failed (e.g. EEXIST) doesn't matter —
            // the point is we were NOT killed by seccomp.
            libc::_exit(0);
        } else {
            let mut status: i32 = 0;
            libc::waitpid(pid, &mut status, 0);

            assert!(
                libc::WIFEXITED(status),
                "Child should have exited normally (mkdir allowed in Network via cumulative IoHeavy)"
            );
            assert_eq!(libc::WEXITSTATUS(status), 0);
        }
    }
}

/// Verify that all profiles compile and load successfully in a forked child.
#[test]
fn seccomp_all_profiles_load_successfully() {
    for profile in SeccompProfile::all() {
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0, "fork failed for profile {:?}", profile);

            if pid == 0 {
                let filter = SeccompFilter::from_profile(profile);
                match SeccompBpf::load(&filter) {
                    Ok(()) => libc::_exit(0),
                    Err(_) => libc::_exit(1),
                }
            } else {
                let mut status: i32 = 0;
                libc::waitpid(pid, &mut status, 0);

                assert!(
                    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                    "Profile {:?} should load successfully",
                    profile
                );
            }
        }
    }
}

/// Verify that the Minimal profile allows runtime-essential syscalls
/// (lseek, gettid, sched_getaffinity, sysinfo) that common runtimes need.
#[test]
fn seccomp_minimal_allows_runtime_essentials() {
    unsafe {
        let pid = libc::fork();
        assert!(pid >= 0, "fork failed");

        if pid == 0 {
            let filter = SeccompFilter::from_profile(SeccompProfile::Minimal);
            if SeccompBpf::load(&filter).is_err() {
                libc::_exit(99);
            }

            // lseek - file seeking (reading .pyc, shared libs)
            // Using lseek on stdin with offset 0, SEEK_CUR just queries position
            libc::lseek(libc::STDIN_FILENO, 0, libc::SEEK_CUR);

            // gettid - thread ID (glibc internal)
            libc::syscall(libc::SYS_gettid);

            // sched_getaffinity - CPU count (os.cpu_count())
            let mut cpuset: libc::cpu_set_t = std::mem::zeroed();
            libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut cpuset);

            // sysinfo - memory/CPU info (Python resource module)
            let mut info: libc::sysinfo = std::mem::zeroed();
            libc::sysinfo(&mut info);

            // If we get here, all syscalls were allowed
            libc::_exit(0);
        } else {
            let mut status: i32 = 0;
            libc::waitpid(pid, &mut status, 0);

            assert!(
                libc::WIFEXITED(status),
                "Child should have exited normally (runtime-essential syscalls allowed), status=0x{:x}",
                status
            );
            assert_eq!(
                libc::WEXITSTATUS(status),
                0,
                "Child should exit with 0 (all runtime-essential syscalls worked)"
            );
        }
    }
}
