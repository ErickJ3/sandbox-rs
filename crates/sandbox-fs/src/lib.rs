//! sandbox-fs: Filesystem management for sandbox-rs
//!
//! Provides OverlayFS support and volume management.

pub mod filesystem;
pub mod volumes;

pub use filesystem::{LayerInfo, OverlayConfig, OverlayFS};
pub use volumes::{VolumeManager, VolumeMount, VolumeType};
