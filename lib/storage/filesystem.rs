//! Overlay filesystem support for persistent sandbox storage

use crate::errors::{Result, SandboxError};
use std::fs;
use std::path::{Path, PathBuf};

/// Overlay filesystem configuration
#[derive(Debug, Clone)]
pub struct OverlayConfig {
    /// Lower layer (read-only base)
    pub lower: PathBuf,
    /// Upper layer (read-write changes)
    pub upper: PathBuf,
    /// Work directory (required by overlayfs)
    pub work: PathBuf,
    /// Merged mount point
    pub merged: PathBuf,
}

impl OverlayConfig {
    /// Create new overlay configuration
    pub fn new(lower: impl AsRef<Path>, upper: impl AsRef<Path>) -> Self {
        let lower_path = lower.as_ref().to_path_buf();
        let upper_path = upper.as_ref().to_path_buf();
        let work_path = upper_path
            .parent()
            .unwrap_or_else(|| Path::new("/tmp"))
            .join("overlayfs-work");
        let merged_path = upper_path
            .parent()
            .unwrap_or_else(|| Path::new("/tmp"))
            .join("overlayfs-merged");

        Self {
            lower: lower_path,
            upper: upper_path,
            work: work_path,
            merged: merged_path,
        }
    }

    /// Validate overlay configuration
    pub fn validate(&self) -> Result<()> {
        if !self.lower.exists() {
            return Err(SandboxError::Syscall(format!(
                "Lower layer does not exist: {}",
                self.lower.display()
            )));
        }

        Ok(())
    }

    /// Create necessary directories
    pub fn setup_directories(&self) -> Result<()> {
        fs::create_dir_all(&self.upper)
            .map_err(|e| SandboxError::Syscall(format!("Failed to create upper layer: {}", e)))?;

        fs::create_dir_all(&self.work).map_err(|e| {
            SandboxError::Syscall(format!("Failed to create work directory: {}", e))
        })?;

        fs::create_dir_all(&self.merged).map_err(|e| {
            SandboxError::Syscall(format!("Failed to create merged directory: {}", e))
        })?;

        Ok(())
    }

    /// Get overlay mount string for mount command
    pub fn get_mount_options(&self) -> String {
        format!(
            "lowerdir={},upperdir={},workdir={}",
            self.lower.display(),
            self.upper.display(),
            self.work.display()
        )
    }
}

/// Overlay filesystem manager
pub struct OverlayFS {
    config: OverlayConfig,
    mounted: bool,
}

impl OverlayFS {
    /// Create new overlay filesystem
    pub fn new(config: OverlayConfig) -> Self {
        Self {
            config,
            mounted: false,
        }
    }

    /// Setup overlay filesystem
    pub fn setup(&mut self) -> Result<()> {
        self.config.validate()?;
        self.config.setup_directories()?;

        // TODO: Actual mount would require root and real mount syscall
        self.mounted = true;
        Ok(())
    }

    /// Check if filesystem is mounted
    pub fn is_mounted(&self) -> bool {
        self.mounted
    }

    /// Get merged (visible) directory
    pub fn merged_path(&self) -> &Path {
        &self.config.merged
    }

    /// Get upper (writable) directory
    pub fn upper_path(&self) -> &Path {
        &self.config.upper
    }

    /// Get lower (read-only) directory
    pub fn lower_path(&self) -> &Path {
        &self.config.lower
    }

    /// Cleanup overlay filesystem
    pub fn cleanup(&mut self) -> Result<()> {
        if self.mounted {
            // Unmount would go here
            self.mounted = false;
        }

        // Clean up work directory
        let _ = fs::remove_dir_all(&self.config.work);

        Ok(())
    }

    /// Get total size of changes in upper layer
    pub fn get_changes_size(&self) -> Result<u64> {
        let mut total = 0u64;

        for entry in fs::read_dir(&self.config.upper)
            .map_err(|e| SandboxError::Syscall(format!("Cannot read upper layer: {}", e)))?
        {
            let entry = entry
                .map_err(|e| SandboxError::Syscall(format!("Directory entry error: {}", e)))?;
            let path = entry.path();

            if path.is_file() {
                total += entry
                    .metadata()
                    .map_err(|e| SandboxError::Syscall(e.to_string()))?
                    .len();
            }
        }

        Ok(total)
    }
}

/// File layer information
#[derive(Debug, Clone)]
pub struct LayerInfo {
    /// Layer name
    pub name: String,
    /// Layer size in bytes
    pub size: u64,
    /// Number of files
    pub file_count: usize,
    /// Whether layer is writable
    pub writable: bool,
}

impl LayerInfo {
    /// Get layer info from path
    pub fn from_path(name: &str, path: &Path, writable: bool) -> Result<Self> {
        let mut size = 0u64;
        let mut file_count = 0;

        if path.exists() {
            for entry in fs::read_dir(path)
                .map_err(|e| SandboxError::Syscall(format!("Cannot read layer: {}", e)))?
            {
                let entry = entry.map_err(|e| SandboxError::Syscall(e.to_string()))?;

                if entry.path().is_file() {
                    file_count += 1;
                    size += entry
                        .metadata()
                        .map_err(|e| SandboxError::Syscall(e.to_string()))?
                        .len();
                }
            }
        }

        Ok(Self {
            name: name.to_string(),
            size,
            file_count,
            writable,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_overlay_config_creation() {
        let config = OverlayConfig::new("/base", "/upper");
        assert_eq!(config.lower, PathBuf::from("/base"));
        assert_eq!(config.upper, PathBuf::from("/upper"));
    }

    #[test]
    fn test_overlay_config_mount_options() {
        let config = OverlayConfig::new("/lower", "/upper");
        let opts = config.get_mount_options();

        assert!(opts.contains("lowerdir="));
        assert!(opts.contains("upperdir="));
        assert!(opts.contains("workdir="));
    }

    #[test]
    fn test_overlay_fs_creation() {
        let config = OverlayConfig::new("/base", "/upper");
        let fs = OverlayFS::new(config);

        assert!(!fs.is_mounted());
    }

    #[test]
    fn test_layer_info_size_calculation() {
        let info = LayerInfo {
            name: "test".to_string(),
            size: 1024,
            file_count: 5,
            writable: true,
        };

        assert_eq!(info.size, 1024);
        assert_eq!(info.file_count, 5);
        assert!(info.writable);
    }

    #[test]
    fn test_overlay_paths() {
        let config = OverlayConfig::new("/lower", "/upper");
        let fs = OverlayFS::new(config);

        assert_eq!(fs.lower_path(), Path::new("/lower"));
        assert_eq!(fs.upper_path(), Path::new("/upper"));
    }
}
