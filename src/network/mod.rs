//! Network layer: Network isolation and configuration
//!
//! This module manages network namespace isolation and configuration,
//! including bridge setup and port mapping.
//!
//! # Features
//!
//! - **Network modes**: Isolated, bridge, host, or custom
//! - **Interface configuration**: IP addresses and gateways
//! - **Port mapping**: Container to host port translation
//! - **DNS management**: Custom DNS server configuration
//! - **Bandwidth limiting**: Optional network rate limiting
//!
//! # Examples
//!
//! ```ignore
//! use sandbox_rs::network::{NetworkConfig, NetworkMode};
//!
//! let config = NetworkConfig::isolated()
//!     .with_dns_server("8.8.8.8")?;
//! ```

pub mod config;
pub use config::{NetworkConfig, NetworkInterface, NetworkMode, NetworkStats, PortMapping};

#[cfg(test)]
mod tests;
