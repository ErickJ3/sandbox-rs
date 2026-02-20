//! sandbox-cgroup: Resource limits via Cgroup v2 with setrlimit fallback
//!
//! Provides resource limiting through cgroup v2 (privileged) or setrlimit (unprivileged).

pub mod cgroup;
pub mod rlimit;

pub use cgroup::{Cgroup, CgroupConfig};
pub use rlimit::RlimitConfig;
