//! Volume management for persistent storage in sandbox

use sandbox_core::{Result, SandboxError};
use std::fs;
use std::path::{Path, PathBuf};

/// Volume mount type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeType {
    Bind,
    Tmpfs,
    Named,
    ReadOnly,
}

impl std::fmt::Display for VolumeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VolumeType::Bind => write!(f, "bind"),
            VolumeType::Tmpfs => write!(f, "tmpfs"),
            VolumeType::Named => write!(f, "named"),
            VolumeType::ReadOnly => write!(f, "readonly"),
        }
    }
}

/// Volume mount configuration
#[derive(Debug, Clone)]
pub struct VolumeMount {
    pub volume_type: VolumeType,
    pub source: String,
    pub destination: PathBuf,
    pub read_only: bool,
    pub size_limit: Option<u64>,
}

impl VolumeMount {
    pub fn bind(source: impl AsRef<Path>, destination: impl AsRef<Path>) -> Self {
        Self {
            volume_type: VolumeType::Bind,
            source: source.as_ref().display().to_string(),
            destination: destination.as_ref().to_path_buf(),
            read_only: false,
            size_limit: None,
        }
    }

    pub fn bind_readonly(source: impl AsRef<Path>, destination: impl AsRef<Path>) -> Self {
        Self {
            volume_type: VolumeType::ReadOnly,
            source: source.as_ref().display().to_string(),
            destination: destination.as_ref().to_path_buf(),
            read_only: true,
            size_limit: None,
        }
    }

    pub fn tmpfs(destination: impl AsRef<Path>, size_limit: Option<u64>) -> Self {
        Self {
            volume_type: VolumeType::Tmpfs,
            source: "tmpfs".to_string(),
            destination: destination.as_ref().to_path_buf(),
            read_only: false,
            size_limit,
        }
    }

    pub fn named(name: &str, destination: impl AsRef<Path>) -> Self {
        Self {
            volume_type: VolumeType::Named,
            source: name.to_string(),
            destination: destination.as_ref().to_path_buf(),
            read_only: false,
            size_limit: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.source.is_empty() {
            return Err(SandboxError::InvalidConfig(
                "Volume source cannot be empty".to_string(),
            ));
        }
        if self.destination.as_os_str().is_empty() {
            return Err(SandboxError::InvalidConfig(
                "Volume destination cannot be empty".to_string(),
            ));
        }
        if self.volume_type == VolumeType::Bind || self.volume_type == VolumeType::ReadOnly {
            let source_path = Path::new(&self.source);
            if !source_path.exists() {
                return Err(SandboxError::InvalidConfig(format!(
                    "Bind mount source does not exist: {}",
                    self.source
                )));
            }
        }
        Ok(())
    }

    pub fn get_mount_options(&self) -> String {
        match self.volume_type {
            VolumeType::Bind | VolumeType::ReadOnly => {
                if self.read_only {
                    "bind,ro".to_string()
                } else {
                    "bind".to_string()
                }
            }
            VolumeType::Tmpfs => {
                if let Some(size) = self.size_limit {
                    format!("size={}", size)
                } else {
                    String::new()
                }
            }
            VolumeType::Named => "named".to_string(),
        }
    }
}

/// Volume manager
pub struct VolumeManager {
    mounts: Vec<VolumeMount>,
    volume_root: PathBuf,
}

impl VolumeManager {
    pub fn new(volume_root: impl AsRef<Path>) -> Self {
        Self {
            mounts: Vec::new(),
            volume_root: volume_root.as_ref().to_path_buf(),
        }
    }

    pub fn add_mount(&mut self, mount: VolumeMount) -> Result<()> {
        mount.validate()?;
        self.mounts.push(mount);
        Ok(())
    }

    pub fn mounts(&self) -> &[VolumeMount] {
        &self.mounts
    }

    pub fn create_volume(&self, name: &str) -> Result<PathBuf> {
        let vol_path = self.volume_root.join(name);
        fs::create_dir_all(&vol_path).map_err(|e| {
            SandboxError::Syscall(format!("Failed to create volume {}: {}", name, e))
        })?;
        Ok(vol_path)
    }

    pub fn delete_volume(&self, name: &str) -> Result<()> {
        let vol_path = self.volume_root.join(name);
        if vol_path.exists() {
            fs::remove_dir_all(&vol_path).map_err(|e| {
                SandboxError::Syscall(format!("Failed to delete volume {}: {}", name, e))
            })?;
        }
        Ok(())
    }

    pub fn list_volumes(&self) -> Result<Vec<String>> {
        let mut volumes = Vec::new();
        if self.volume_root.exists() {
            for entry in fs::read_dir(&self.volume_root)
                .map_err(|e| SandboxError::Syscall(format!("Cannot list volumes: {}", e)))?
            {
                let entry = entry.map_err(|e| SandboxError::Syscall(e.to_string()))?;
                if let Ok(name) = entry.file_name().into_string() {
                    volumes.push(name);
                }
            }
        }
        Ok(volumes)
    }

    pub fn get_volume_size(&self, name: &str) -> Result<u64> {
        use walkdir::WalkDir;
        let vol_path = self.volume_root.join(name);
        if !vol_path.exists() {
            return Err(SandboxError::Syscall(format!(
                "Volume does not exist: {}",
                name
            )));
        }
        let mut total = 0u64;
        for entry in WalkDir::new(&vol_path).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                total += entry
                    .metadata()
                    .map_err(|e| SandboxError::Syscall(e.to_string()))?
                    .len();
            }
        }
        Ok(total)
    }

    pub fn clear_mounts(&mut self) {
        self.mounts.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_volume_type_display() {
        assert_eq!(VolumeType::Bind.to_string(), "bind");
        assert_eq!(VolumeType::Tmpfs.to_string(), "tmpfs");
    }

    #[test]
    fn test_volume_mount_bind() {
        let mount = VolumeMount::bind("/tmp", "/mnt");
        assert_eq!(mount.volume_type, VolumeType::Bind);
        assert!(!mount.read_only);
    }

    #[test]
    fn test_volume_mount_options() {
        let bind_mount = VolumeMount::bind("/tmp", "/mnt");
        assert_eq!(bind_mount.get_mount_options(), "bind");
        let ro_mount = VolumeMount::bind_readonly("/tmp", "/mnt");
        assert_eq!(ro_mount.get_mount_options(), "bind,ro");
    }

    #[test]
    fn test_volume_manager_creation() {
        let manager = VolumeManager::new("/tmp");
        assert!(manager.mounts().is_empty());
    }
}
