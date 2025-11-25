//! Isolation layer: Namespace + Seccomp filtering
//!
//! This module provides namespace isolation and syscall filtering
//! for sandboxed processes.
//!
//! # Features
//!
//! - **Namespaces**: PID, IPC, NET, MOUNT, UTS, User
//! - **Seccomp**: BPF-based syscall filtering with profiles
//!
//! # Examples
//!
//! ```ignore
//! use sandbox_rs::isolation::{NamespaceConfig, SeccompProfile};
//!
//! let ns = NamespaceConfig::default();
//! let profile = SeccompProfile::IoHeavy;
//! ```

pub mod namespace;
pub mod seccomp;
pub mod seccomp_bpf;
pub use namespace::{NamespaceConfig, NamespaceType};
pub use seccomp::{SeccompFilter, SeccompProfile};
pub use seccomp_bpf::SeccompCompiler;

#[cfg(test)]
mod tests;
