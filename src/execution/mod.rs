//! Execution layer: Process management and initialization
//!
//! This module handles process execution within sandboxes,
//! including namespace cloning, initialization, and lifecycle management.
//!
//! # Features
//!
//! - **Process execution**: Clone with namespace isolation
//! - **Init process**: Zombie reaping and signal handling
//! - **Chroot support**: Filesystem root isolation
//! - **Credential switching**: UID/GID management
//!
//! # Examples
//!
//! ```ignore
//! use sandbox_rs::execution::ProcessConfig;
//!
//! let config = ProcessConfig {
//!     program: "/bin/bash".to_string(),
//!     args: vec![],
//!     ..Default::default()
//! };
//! ```

pub mod init;
pub mod process;
pub use init::SandboxInit;
pub use process::{ProcessConfig, ProcessExecutor, ProcessResult};

#[cfg(test)]
mod tests;
