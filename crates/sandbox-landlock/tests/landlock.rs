//! Landlock enforcement tests
//!
//! These tests verify that landlock filesystem restrictions work.
//! They do NOT require root (Landlock is designed for unprivileged use).
//! They DO require Linux 5.13+ with Landlock support.
//!
//! Tests that require Landlock availability will skip gracefully on
//! systems where it's not supported.

use sandbox_landlock::LandlockConfig;
use std::path::PathBuf;

/// Check if landlock is available on this system.
/// Tests that need it will skip if not available.
fn require_landlock() -> bool {
    LandlockConfig::is_available()
}

/// Verify that LandlockConfig::is_available() doesn't panic.
#[test]
fn landlock_availability_check_is_safe() {
    let _ = LandlockConfig::is_available();
}

/// Verify that applying landlock restricts file access.
/// Forks a child, allows read to /tmp only, then tries to read /etc/hostname.
#[test]
fn landlock_restricts_file_access() {
    if !require_landlock() {
        eprintln!("SKIP: Landlock not available on this kernel");
        return;
    }

    unsafe {
        let pid = libc::fork();
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());

        if pid == 0 {
            // Allow read access only to /tmp and /proc (needed for libc)
            let config = LandlockConfig {
                read_paths: vec![PathBuf::from("/tmp"), PathBuf::from("/proc")],
                write_paths: vec![PathBuf::from("/tmp")],
                exec_paths: vec![],
            };

            if config.apply().is_err() {
                libc::_exit(99);
            }

            // Try to read /etc/hostname - should fail with EACCES
            let path = b"/etc/hostname\0";
            let fd = libc::open(path.as_ptr() as *const libc::c_char, libc::O_RDONLY);
            if fd < 0 {
                // Expected: access denied
                let errno = *libc::__errno_location();
                if errno == libc::EACCES {
                    libc::_exit(0); // Success: access correctly denied
                } else {
                    libc::_exit(2); // Failed for unexpected reason
                }
            } else {
                libc::close(fd);
                libc::_exit(1); // Failure: file was accessible despite landlock
            }
        } else {
            let mut status: i32 = 0;
            libc::waitpid(pid, &mut status, 0);

            assert!(libc::WIFEXITED(status), "Child should exit normally");
            let exit_code = libc::WEXITSTATUS(status);
            assert!(
                exit_code == 0 || exit_code == 2,
                "Landlock should restrict access to /etc/hostname (exit={})",
                exit_code,
            );
        }
    }
}

/// Verify that landlock still allows access to permitted paths.
#[test]
fn landlock_allows_permitted_paths() {
    if !require_landlock() {
        eprintln!("SKIP: Landlock not available on this kernel");
        return;
    }

    unsafe {
        let pid = libc::fork();
        assert!(pid >= 0, "fork failed");

        if pid == 0 {
            // Create a test file in /tmp before applying landlock
            let test_path = b"/tmp/sandbox-landlock-test-read\0";
            let fd = libc::open(
                test_path.as_ptr() as *const libc::c_char,
                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                0o644,
            );
            if fd >= 0 {
                let data = b"test data";
                libc::write(fd, data.as_ptr() as *const libc::c_void, data.len());
                libc::close(fd);
            }

            // Allow read/write to /tmp
            let config = LandlockConfig {
                read_paths: vec![PathBuf::from("/tmp")],
                write_paths: vec![PathBuf::from("/tmp")],
                exec_paths: vec![],
            };

            if config.apply().is_err() {
                libc::_exit(99);
            }

            // Reading from /tmp should succeed
            let fd = libc::open(
                test_path.as_ptr() as *const libc::c_char,
                libc::O_RDONLY,
            );
            if fd >= 0 {
                libc::close(fd);
                libc::unlink(test_path.as_ptr() as *const libc::c_char);
                libc::_exit(0); // Success: permitted path is accessible
            } else {
                libc::_exit(1); // Failure: permitted path was denied
            }
        } else {
            let mut status: i32 = 0;
            libc::waitpid(pid, &mut status, 0);

            assert!(libc::WIFEXITED(status));
            assert_eq!(
                libc::WEXITSTATUS(status),
                0,
                "Landlock should allow access to permitted paths"
            );
        }
    }
}

/// Verify that landlock write restriction works.
/// Allow read to /tmp but NOT write, then try to create a file.
#[test]
fn landlock_restricts_write_access() {
    if !require_landlock() {
        eprintln!("SKIP: Landlock not available on this kernel");
        return;
    }

    unsafe {
        let pid = libc::fork();
        assert!(pid >= 0, "fork failed");

        if pid == 0 {
            // Allow only read access to /tmp (no write)
            let config = LandlockConfig {
                read_paths: vec![PathBuf::from("/tmp")],
                write_paths: vec![], // No write access anywhere
                exec_paths: vec![],
            };

            if config.apply().is_err() {
                libc::_exit(99);
            }

            // Try to create a new file in /tmp - should fail
            let path = b"/tmp/sandbox-landlock-test-write-deny\0";
            let fd = libc::open(
                path.as_ptr() as *const libc::c_char,
                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                0o644,
            );
            if fd < 0 {
                libc::_exit(0); // Success: write correctly denied
            } else {
                libc::close(fd);
                libc::unlink(path.as_ptr() as *const libc::c_char);
                libc::_exit(1); // Failure: write was allowed
            }
        } else {
            let mut status: i32 = 0;
            libc::waitpid(pid, &mut status, 0);

            assert!(libc::WIFEXITED(status));
            assert_eq!(
                libc::WEXITSTATUS(status),
                0,
                "Landlock should deny write to read-only paths"
            );
        }
    }
}

/// Verify that apply() returns an appropriate error when landlock is unavailable.
#[test]
fn landlock_apply_fails_gracefully_when_unavailable() {
    if require_landlock() {
        // Can't test "unavailable" behavior on a system that has it
        return;
    }

    let config = LandlockConfig {
        read_paths: vec![PathBuf::from("/tmp")],
        ..Default::default()
    };

    let result = config.apply();
    assert!(result.is_err(), "apply() should fail when landlock is unavailable");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("not available"),
        "Error should mention landlock is not available: {}",
        err_msg
    );
}
