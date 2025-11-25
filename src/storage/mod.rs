//! Storage layer: Filesystem and volume management
//!
//! This module provides persistent storage capabilities including
//! overlay filesystems and volume mounts.
//!
//! # Features
//!
//! - **Overlay FS**: Copy-on-write filesystem with layers
//! - **Volume mounts**: Bind mounts and tmpfs support
//! - **Layered storage**: Efficient snapshot management
//! - **Persistence**: Optional state between sandbox runs
//!
//! # Examples
//!
//! ```ignore
//! use sandbox_rs::storage::{OverlayFS, OverlayConfig};
//!
//! let config = OverlayConfig::new("/base", "/upper");
//! let fs = OverlayFS::new(config)?;
//! ```

pub mod filesystem;
pub mod volumes;
pub use filesystem::{LayerInfo, OverlayConfig, OverlayFS};
pub use volumes::{VolumeManager, VolumeMount, VolumeType};

#[cfg(test)]
mod tests;
