//! sandbox-namespace: Linux namespace isolation with user namespace support
//!
//! Provides namespace configuration and user namespace UID/GID mapping
//! for both privileged and unprivileged sandboxing.

pub mod config;
pub mod user_ns;

pub use config::{NamespaceConfig, NamespaceType};
