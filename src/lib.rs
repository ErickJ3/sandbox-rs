//! sandbox-rs: sandbox in Rust
//!
//! A comprehensive Rust sandbox solution, implements Linux namespace isolation, Cgroup v2
//! resource limits, Seccomp BPF filtering, and eBPF-based syscall monitoring.
//!
//! # Modules
//!
//! - **isolation**: Namespace + Seccomp filtering
//! - **resources**: Cgroup v2 resource limits
//! - **execution**: Process execution and initialization
//! - **monitoring**: Process and syscall monitoring
//! - **storage**: Filesystem and volume management
//! - **network**: Network isolation and configuration
//! - **controller**: Main sandbox orchestration
//!
//! # Example
//!
//! ```ignore
//! use sandbox_rs::SandboxBuilder;
//! use std::time::Duration;
//!
//! let mut sandbox = SandboxBuilder::new("my-sandbox")
//!     .memory_limit_str("256M")?
//!     .cpu_limit_percent(50)
//!     .timeout(Duration::from_secs(30))
//!     .build()?;
//!
//! let result = sandbox.run("/bin/echo", &["hello world"])?;
//! println!("Exit code: {}", result.exit_code);
//! ```

// Core modules
pub mod errors;
pub mod utils;

// Layered modules
pub mod execution;
pub mod isolation;
pub mod monitoring;
pub mod network;
pub mod resources;
pub mod storage;

// Main controller
pub mod controller;

// Public API
pub use controller::{Sandbox, SandboxBuilder, SandboxConfig};
pub use errors::{Result, SandboxError};
pub use execution::{ProcessConfig, ProcessResult};
pub use isolation::{NamespaceConfig, SeccompProfile};
pub use monitoring::{ProcessMonitor, ProcessState, ProcessStats};
pub use network::{NetworkConfig, NetworkMode};
pub use storage::{OverlayConfig, OverlayFS};

#[cfg(test)]
mod tests {
    use crate::SandboxBuilder;

    #[test]
    fn test_module_imports() {
        // Verify core API is accessible
        let _builder = SandboxBuilder::new("test");
    }
}

#[cfg(test)]
pub mod test_support {
    use std::sync::{Mutex, MutexGuard, OnceLock};

    pub fn serial_guard() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}
