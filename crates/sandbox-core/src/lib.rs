//! sandbox-core: shared types, errors, and capability detection for sandbox-rs
//!
//! This crate provides the foundational types used by all sandbox-rs sub-crates:
//! - Error types and Result alias
//! - Utility functions (memory parsing, UID/GID queries)
//! - Runtime capability detection (user namespaces, seccomp, landlock, cgroups)
//! - Privilege mode configuration

pub mod capabilities;
pub mod error;
pub mod privilege;
pub mod util;

pub use error::{Result, SandboxError};
pub use privilege::PrivilegeMode;
