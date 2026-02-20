//! Error types for sandbox operations

use std::io;
use thiserror::Error;

/// Result type for sandbox operations
pub type Result<T> = std::result::Result<T, SandboxError>;

/// Errors that can occur during sandbox operations
#[derive(Error, Debug)]
pub enum SandboxError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Syscall error: {0}")]
    Syscall(String),

    #[error("Cgroup error: {0}")]
    Cgroup(String),

    #[error("Namespace error: {0}")]
    Namespace(String),

    #[error("Seccomp error: {0}")]
    Seccomp(String),

    #[error("Landlock error: {0}")]
    Landlock(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Sandbox already running")]
    AlreadyRunning,

    #[error("Sandbox not running")]
    NotRunning,

    #[error("Timeout exceeded")]
    Timeout,

    #[error("Process exited with code {code}")]
    ProcessExit { code: i32 },

    #[error("Process killed by signal {signal}")]
    ProcessSignal { signal: i32 },

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),

    #[error("Process monitoring error: {0}")]
    ProcessMonitoring(String),

    #[error("Feature not available: {0}")]
    FeatureNotAvailable(String),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = SandboxError::Timeout;
        assert_eq!(err.to_string(), "Timeout exceeded");
    }

    #[test]
    fn test_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let sandbox_err = SandboxError::from(io_err);
        assert!(sandbox_err.to_string().contains("IO error"));
    }

    #[test]
    fn test_result_type() {
        fn returns_result() -> Result<i32> {
            Ok(42)
        }
        assert_eq!(returns_result().unwrap(), 42);
    }

    #[test]
    fn test_result_error() {
        fn returns_error() -> Result<i32> {
            Err(SandboxError::Timeout)
        }
        assert!(returns_error().is_err());
    }

    #[test]
    fn test_feature_not_available() {
        let err = SandboxError::FeatureNotAvailable("landlock".to_string());
        assert!(err.to_string().contains("landlock"));
    }

    #[test]
    fn test_landlock_error() {
        let err = SandboxError::Landlock("ruleset failed".to_string());
        assert!(err.to_string().contains("Landlock"));
    }
}
