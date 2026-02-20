//! sandbox-rs: Process isolation library for Linux
//!
//! A comprehensive Rust sandbox solution with Linux namespace isolation, Cgroup v2
//! resource limits, Seccomp BPF filtering, Landlock filesystem restrictions,
//! and process monitoring.
//!
//! # Privilege Modes
//!
//! - **Unprivileged** (default): Uses user namespaces + seccomp + landlock + setrlimit.
//!   Works without root on modern kernels.
//! - **Privileged**: Uses all namespaces + cgroups + chroot + seccomp. Requires root.
//! - **Auto**: Detects the best available mode at runtime.
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

pub mod controller;
pub mod execution;
pub mod monitoring;

// Re-export sub-crate types for convenience
pub use sandbox_cgroup::{Cgroup, CgroupConfig, RlimitConfig};
pub use sandbox_core::{
    self as core, Result, SandboxError, capabilities::SystemCapabilities, privilege::PrivilegeMode,
    util,
};
pub use sandbox_fs::{LayerInfo, OverlayConfig, OverlayFS, VolumeManager, VolumeMount, VolumeType};
pub use sandbox_landlock::LandlockConfig;
pub use sandbox_namespace::{NamespaceConfig, NamespaceType};
pub use sandbox_seccomp::{SeccompBpf, SeccompFilter, SeccompProfile};

pub use controller::{Sandbox, SandboxBuilder, SandboxConfig, SandboxResult};
pub use execution::{ProcessConfig, ProcessResult, ProcessStream, StreamChunk};
pub use monitoring::{ProcessMonitor, ProcessState, ProcessStats};

/// Alias for backwards compatibility
pub mod utils {
    pub use sandbox_core::util::*;
}
