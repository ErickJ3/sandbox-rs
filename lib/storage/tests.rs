use super::{LayerInfo, OverlayConfig, OverlayFS, VolumeManager, VolumeMount};
use std::fs;
use std::io::Write;
use std::path::Path;
use tempfile::tempdir;

fn overlay_environment() -> (tempfile::TempDir, OverlayConfig) {
    let base = tempdir().expect("tempdir");
    let lower = base.path().join("lower");
    let upper = base.path().join("upper/layer");
    fs::create_dir_all(&lower).unwrap();
    fs::create_dir_all(upper.parent().unwrap()).unwrap();

    let config = OverlayConfig::new(&lower, &upper);
    (base, config)
}

#[test]
fn overlay_config_validation_checks_lower_layer() {
    let config = OverlayConfig::new("/does/not/exist", "/tmp/upper");
    assert!(config.validate().is_err());
}

#[test]
#[ignore] // Requires root privileges for mount syscall
fn overlay_fs_setup_creates_directories() {
    let (_temp, config) = overlay_environment();
    assert!(config.validate().is_ok());

    let mut overlay = OverlayFS::new(config.clone());
    overlay.setup().expect("overlay setup");
    assert!(overlay.is_mounted());
    assert!(
        overlay
            .merged_path()
            .starts_with(config.upper.parent().unwrap())
    );
}

#[test]
#[ignore] // Requires root privileges for mount syscall
fn overlay_fs_reports_changes_size() {
    let (_temp, config) = overlay_environment();
    config.setup_directories().unwrap();

    let mut overlay = OverlayFS::new(config.clone());
    overlay.setup().unwrap();

    let sample_file = overlay.upper_path().join("file.txt");
    fs::write(&sample_file, b"hello world").unwrap();
    let size = overlay.get_changes_size().unwrap();

    assert!(size >= 11);
    overlay.cleanup().unwrap();
}

#[test]
fn layer_info_counts_files_and_bytes() {
    let temp = tempdir().unwrap();
    let layer_path = temp.path().join("layer");
    fs::create_dir_all(&layer_path).unwrap();
    let file_path = layer_path.join("data.bin");
    let mut file = fs::File::create(&file_path).unwrap();
    file.write_all(&[0u8; 32]).unwrap();

    let info = LayerInfo::from_path("layer", &layer_path, true).unwrap();
    assert_eq!(info.file_count, 1);
    assert!(info.size >= 32);
    assert!(info.writable);
}

#[test]
fn overlay_config_setup_directories_create_paths() {
    let (_temp, config) = overlay_environment();
    config.setup_directories().unwrap();
    assert!(config.upper.exists());
    assert!(config.work.exists());
    assert!(config.merged.exists());
}

#[test]
#[ignore] // Requires root privileges for mount syscall
fn overlay_fs_cleanup_resets_state_and_removes_workdir() {
    let (_temp, config) = overlay_environment();
    let work_dir = config.work.clone();
    let mut overlay = OverlayFS::new(config);
    overlay.setup().unwrap();
    assert!(overlay.is_mounted());
    overlay.cleanup().unwrap();
    assert!(!overlay.is_mounted());
    assert!(!work_dir.exists());
}

#[test]
fn volume_mount_validation_for_bind_paths() {
    let temp = tempdir().unwrap();
    let src = temp.path().join("src");
    fs::create_dir_all(&src).unwrap();

    let mount = VolumeMount::bind(&src, "/data");
    assert!(mount.validate().is_ok());

    let invalid = VolumeMount::bind("/missing", "/data");
    assert!(invalid.validate().is_err());
}

#[test]
fn volume_manager_lifecycle_for_named_volumes() {
    let temp = tempdir().unwrap();
    let manager = VolumeManager::new(temp.path());

    manager.create_volume("vol1").expect("create volume");
    let volumes = manager.list_volumes().expect("list volumes");
    assert!(volumes.contains(&"vol1".to_string()));

    manager.delete_volume("vol1").expect("delete volume");
    let volumes_after = manager.list_volumes().expect("list volumes");
    assert!(!volumes_after.contains(&"vol1".to_string()));
}

#[test]
fn volume_manager_adds_and_clears_mounts() {
    let temp = tempdir().unwrap();
    let mut manager = VolumeManager::new(temp.path());
    let mount = VolumeMount::tmpfs(Path::new("/data"), Some(1024));

    manager.add_mount(mount).expect("add mount");
    assert_eq!(manager.mounts().len(), 1);

    manager.clear_mounts();
    assert!(manager.mounts().is_empty());
}

#[test]
fn volume_mount_validation_rejects_empty_destination() {
    let mount = VolumeMount::bind("/tmp", Path::new(""));
    assert!(mount.validate().is_err());
}

#[test]
fn volume_manager_reports_volume_size() {
    let temp = tempdir().unwrap();
    let manager = VolumeManager::new(temp.path());
    let vol_path = manager.create_volume("metrics").unwrap();
    fs::write(vol_path.join("file.txt"), b"abc").unwrap();

    let size = manager.get_volume_size("metrics").unwrap();
    assert!(size >= 3);
}

#[test]
fn volume_manager_delete_nonexistent_volume_is_noop() {
    let temp = tempdir().unwrap();
    let manager = VolumeManager::new(temp.path());
    manager.delete_volume("missing").unwrap();
}

#[test]
fn volume_mount_options_cover_variants() {
    let bind = VolumeMount::bind("/tmp", "/data");
    assert_eq!(bind.get_mount_options(), "bind");

    let readonly = VolumeMount::bind_readonly("/tmp", "/data");
    assert_eq!(readonly.get_mount_options(), "bind,ro");

    let tmpfs = VolumeMount::tmpfs("/run", Some(2048));
    assert!(tmpfs.get_mount_options().contains("2048"));

    let named = VolumeMount::named("cache", "/cache");
    assert_eq!(named.get_mount_options(), "named");
}

#[test]
fn volume_mount_named_validate() {
    let mount = VolumeMount::named("workspace", "/workspace");
    assert!(mount.validate().is_ok());
}
