//! Overlay filesystem support for persistent sandbox storage

use sandbox_core::{Result, SandboxError};
use std::fs;
use std::path::{Path, PathBuf};

/// Overlay filesystem configuration
#[derive(Debug, Clone)]
pub struct OverlayConfig {
    pub lower: PathBuf,
    pub upper: PathBuf,
    pub work: PathBuf,
    pub merged: PathBuf,
}

impl OverlayConfig {
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

    pub fn validate(&self) -> Result<()> {
        if !self.lower.exists() {
            return Err(SandboxError::Syscall(format!(
                "Lower layer does not exist: {}",
                self.lower.display()
            )));
        }
        Ok(())
    }

    pub fn setup_directories(&self) -> Result<()> {
        fs::create_dir_all(&self.upper)
            .map_err(|e| SandboxError::Syscall(format!("Failed to create upper layer: {}", e)))?;
        if self.work.exists() {
            fs::remove_dir_all(&self.work).map_err(|e| {
                SandboxError::Syscall(format!("Failed to clean work directory: {}", e))
            })?;
        }
        fs::create_dir_all(&self.work).map_err(|e| {
            SandboxError::Syscall(format!("Failed to create work directory: {}", e))
        })?;
        fs::create_dir_all(&self.merged).map_err(|e| {
            SandboxError::Syscall(format!("Failed to create merged directory: {}", e))
        })?;
        Ok(())
    }

    pub fn get_mount_options(&self) -> Result<String> {
        let lower_str = self
            .lower
            .to_str()
            .ok_or_else(|| SandboxError::Syscall("Lower path is not valid UTF-8".to_string()))?;
        let upper_str = self
            .upper
            .to_str()
            .ok_or_else(|| SandboxError::Syscall("Upper path is not valid UTF-8".to_string()))?;
        let work_str = self
            .work
            .to_str()
            .ok_or_else(|| SandboxError::Syscall("Work path is not valid UTF-8".to_string()))?;
        Ok(format!(
            "lowerdir={},upperdir={},workdir={}",
            lower_str, upper_str, work_str
        ))
    }
}

/// Overlay filesystem manager
pub struct OverlayFS {
    config: OverlayConfig,
    mounted: bool,
}

impl OverlayFS {
    pub fn new(config: OverlayConfig) -> Self {
        Self {
            config,
            mounted: false,
        }
    }

    pub fn setup(&mut self) -> Result<()> {
        self.config.validate()?;
        self.config.setup_directories()?;
        use std::ffi::CString;
        let fstype = CString::new("overlay")
            .map_err(|_| SandboxError::Syscall("Invalid filesystem type".to_string()))?;
        let source = CString::new("overlay")
            .map_err(|_| SandboxError::Syscall("Invalid source".to_string()))?;
        let target_str =
            self.config.merged.to_str().ok_or_else(|| {
                SandboxError::Syscall("Merged path is not valid UTF-8".to_string())
            })?;
        let target = CString::new(target_str)
            .map_err(|_| SandboxError::Syscall("Invalid target path".to_string()))?;
        let options_str = self.config.get_mount_options()?;
        let options = CString::new(options_str.as_str())
            .map_err(|_| SandboxError::Syscall("Invalid mount options".to_string()))?;
        let ret = unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                fstype.as_ptr(),
                0,
                options.as_ptr() as *const libc::c_void,
            )
        };
        if ret != 0 {
            return Err(SandboxError::Syscall(format!(
                "Failed to mount overlay filesystem: {}",
                std::io::Error::last_os_error()
            )));
        }
        self.mounted = true;
        Ok(())
    }

    pub fn is_mounted(&self) -> bool {
        self.mounted
    }
    pub fn merged_path(&self) -> &Path {
        &self.config.merged
    }
    pub fn upper_path(&self) -> &Path {
        &self.config.upper
    }
    pub fn lower_path(&self) -> &Path {
        &self.config.lower
    }

    pub fn cleanup(&mut self) -> Result<()> {
        if self.mounted {
            use std::ffi::CString;
            use std::os::unix::ffi::OsStrExt;
            let target = CString::new(self.config.merged.as_os_str().as_bytes()).map_err(|_| {
                SandboxError::Syscall("Invalid target path for unmount".to_string())
            })?;
            let ret = unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) };
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::EINVAL)
                    && err.raw_os_error() != Some(libc::ENOENT)
                {
                    return Err(SandboxError::Syscall(format!(
                        "Failed to unmount overlay filesystem: {}",
                        err
                    )));
                }
            }
            self.mounted = false;
        }
        let _ = fs::remove_dir_all(&self.config.work);
        Ok(())
    }

    pub fn get_changes_size(&self) -> Result<u64> {
        use walkdir::WalkDir;
        let mut total = 0u64;
        for entry in WalkDir::new(&self.config.upper)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
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
    pub name: String,
    pub size: u64,
    pub file_count: usize,
    pub writable: bool,
}

impl LayerInfo {
    pub fn from_path(name: &str, path: &Path, writable: bool) -> Result<Self> {
        use walkdir::WalkDir;
        let mut size = 0u64;
        let mut file_count = 0;
        if path.exists() {
            for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().is_file() {
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
        let opts = config.get_mount_options().unwrap();
        assert!(opts.contains("lowerdir=/lower"));
        assert!(opts.contains("upperdir=/upper"));
    }

    #[test]
    fn test_overlay_fs_creation() {
        let config = OverlayConfig::new("/base", "/upper");
        let fs = OverlayFS::new(config);
        assert!(!fs.is_mounted());
    }

    #[test]
    fn test_overlay_paths() {
        let config = OverlayConfig::new("/lower", "/upper");
        let fs = OverlayFS::new(config);
        assert_eq!(fs.lower_path(), Path::new("/lower"));
        assert_eq!(fs.upper_path(), Path::new("/upper"));
    }
}
