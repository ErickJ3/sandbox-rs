//! Resource limits layer: Cgroup v2 management
//!
//! This module provides resource limit enforcement via Cgroup v2.
//!
//! # Features
//!
//! - **Memory limits**: Hard ceiling with OOM enforcement
//! - **CPU limits**: Weight-based and quota-based scheduling
//! - **Process limits**: Max PID restrictions
//! - **Runtime statistics**: Real-time resource usage tracking
//!
//! # Examples
//!
//! ```ignore
//! use sandbox_rs::resources::CgroupConfig;
//!
//! let config = CgroupConfig::with_memory(100 * 1024 * 1024);
//! ```

pub mod cgroup;
pub use cgroup::{Cgroup, CgroupConfig};

#[cfg(test)]
mod tests;
