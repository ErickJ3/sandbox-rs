//! Rlimit enforcement tests
//!
//! These tests verify that setrlimit actually enforces resource limits.
//! They do NOT require root.

use sandbox_cgroup::RlimitConfig;

/// Verify that RLIMIT_NOFILE limits the number of open file descriptors.
/// Forks a child, sets max_open_files=8, then tries to open many files.
#[test]
fn rlimit_nofile_enforced() {
    unsafe {
        let pid = libc::fork();
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());

        if pid == 0 {
            let config = RlimitConfig {
                max_open_files: Some(8),
                ..Default::default()
            };
            if config.apply().is_err() {
                libc::_exit(99);
            }

            // Try to open many files - should hit the limit
            // stdin(0), stdout(1), stderr(2) are already open = 3 fds used
            // With limit of 8, we can open at most 5 more (fds 3-7)
            let mut opened = 0;
            let path = b"/dev/null\0";
            for _ in 0..20 {
                let fd = libc::open(path.as_ptr() as *const libc::c_char, libc::O_RDONLY);
                if fd >= 0 {
                    opened += 1;
                } else {
                    break;
                }
            }

            // We should NOT have been able to open all 20
            if opened < 20 {
                libc::_exit(0); // Success: limit was enforced
            } else {
                libc::_exit(1); // Failure: limit not enforced
            }
        } else {
            let mut status: i32 = 0;
            libc::waitpid(pid, &mut status, 0);

            assert!(libc::WIFEXITED(status), "Child should exit normally");
            assert_eq!(
                libc::WEXITSTATUS(status),
                0,
                "RLIMIT_NOFILE should have been enforced"
            );
        }
    }
}

/// Verify that RLIMIT_FSIZE limits file writes.
/// Forks a child, sets max_file_size, then tries to write a large file.
#[test]
fn rlimit_fsize_enforced() {
    unsafe {
        let pid = libc::fork();
        assert!(pid >= 0, "fork failed");

        if pid == 0 {
            // Limit file size to 1024 bytes
            let config = RlimitConfig {
                max_file_size: Some(1024),
                ..Default::default()
            };
            if config.apply().is_err() {
                libc::_exit(99);
            }

            // Create a temp file and try to write more than 1024 bytes
            let path = b"/tmp/sandbox-rlimit-test-fsize\0";
            let fd = libc::open(
                path.as_ptr() as *const libc::c_char,
                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                0o644,
            );
            if fd < 0 {
                libc::_exit(98);
            }

            // Write 2048 bytes (exceeds 1024 limit)
            let buf = [b'A'; 2048];
            let written = libc::write(fd, buf.as_ptr() as *const libc::c_void, 2048);
            libc::close(fd);
            libc::unlink(path.as_ptr() as *const libc::c_char);

            // write() should have been limited (returns < 2048 or -1)
            if written < 2048 {
                libc::_exit(0); // Success: limit was enforced
            } else {
                libc::_exit(1); // Failure: limit not enforced
            }
        } else {
            let mut status: i32 = 0;
            libc::waitpid(pid, &mut status, 0);

            // The child might be killed by SIGXFSZ when exceeding RLIMIT_FSIZE
            if libc::WIFSIGNALED(status) {
                let sig = libc::WTERMSIG(status);
                assert_eq!(
                    sig,
                    libc::SIGXFSZ,
                    "If killed by signal, should be SIGXFSZ"
                );
                // Being killed by SIGXFSZ means the limit was enforced
            } else {
                assert!(libc::WIFEXITED(status), "Child should exit normally");
                assert_eq!(
                    libc::WEXITSTATUS(status),
                    0,
                    "RLIMIT_FSIZE should have been enforced"
                );
            }
        }
    }
}

/// Verify that applying an empty RlimitConfig is a no-op.
#[test]
fn rlimit_empty_config_is_noop() {
    let config = RlimitConfig::default();
    assert!(config.apply().is_ok());
}

/// Verify that RLIMIT_NOFILE can be read back after setting.
#[test]
fn rlimit_nofile_getrlimit_matches() {
    unsafe {
        let pid = libc::fork();
        assert!(pid >= 0, "fork failed");

        if pid == 0 {
            let config = RlimitConfig {
                max_open_files: Some(42),
                ..Default::default()
            };
            if config.apply().is_err() {
                libc::_exit(99);
            }

            // Verify the limit was actually set
            let mut rlim: libc::rlimit = std::mem::zeroed();
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) != 0 {
                libc::_exit(98);
            }

            if rlim.rlim_cur == 42 && rlim.rlim_max == 42 {
                libc::_exit(0);
            } else {
                libc::_exit(1);
            }
        } else {
            let mut status: i32 = 0;
            libc::waitpid(pid, &mut status, 0);

            assert!(libc::WIFEXITED(status));
            assert_eq!(
                libc::WEXITSTATUS(status),
                0,
                "getrlimit should reflect the set value"
            );
        }
    }
}
