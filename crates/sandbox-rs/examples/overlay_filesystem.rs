//! Overlay Filesystem Example
//!
//! This example demonstrates how to use overlay filesystems with sandboxes
//! for persistent storage with copy-on-write semantics.
//!
//! ## Overview
//!
//! An overlay filesystem combines:
//! - **Lower layer**: Read-only base filesystem (immutable)
//! - **Upper layer**: Read-write changes (modifications)
//! - **Merged view**: Combined view of both layers
//! - **Work directory**: Kernel internal state for overlayfs
//!
//! ## Use Cases
//!
//! 1. **Snapshots**: Run programs with same base, but isolate changes
//! 2. **Recovery**: Revert to base state by deleting upper layer
//! 3. **Efficiency**: Share common base across multiple sandboxes
//! 4. **Auditing**: Track exactly what files changed during execution
//!
//! ## Running this example
//!
//! ```bash
//! cargo run --example overlay_filesystem
//! ```

use sandbox_rs::{OverlayConfig, OverlayFS};
use std::fs;
use tempfile::TempDir;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Sandbox-rs: Overlay Filesystem Example ===\n");

    // Create temporary directories for demonstration
    let temp_base = TempDir::new()?;
    let base_dir = temp_base.path().join("base");
    let upper_dir = temp_base.path().join("upper");

    println!("[1] Setting up overlay filesystem layers\n");

    // Create base directory with initial content
    fs::create_dir_all(&base_dir)?;
    fs::write(
        base_dir.join("original.txt"),
        "This is the original immutable file\n",
    )?;
    fs::write(base_dir.join("readme.txt"), "Base layer - read-only\n")?;

    println!("  Created base layer at: {}", base_dir.display());
    println!("    - original.txt");
    println!("    - readme.txt\n");

    // Create overlay configuration
    println!("[2] Creating overlay configuration\n");
    let overlay_config = OverlayConfig::new(&base_dir, &upper_dir);

    println!(
        "  Lower layer (read-only): {}",
        overlay_config.lower.display()
    );
    println!(
        "  Upper layer (read-write): {}",
        overlay_config.upper.display()
    );
    println!("  Work directory: {}", overlay_config.work.display());
    println!("  Merged view: {}\n", overlay_config.merged.display());

    // Initialize overlay filesystem
    println!("[3] Initializing overlay filesystem\n");
    let mut overlay = OverlayFS::new(overlay_config);
    overlay.setup()?;

    println!("  Overlay filesystem initialized");
    println!("  Mounted: {}\n", overlay.is_mounted());

    // Simulate operations in the sandbox
    println!("[4] Simulating sandbox operations\n");

    // Create new file in upper layer (simulating sandbox write)
    let upper_path = overlay.upper_path();
    fs::create_dir_all(upper_path)?;

    let new_file_path = upper_path.join("sandbox-output.txt");
    fs::write(
        &new_file_path,
        "This file was created in the sandbox\nModified during execution\n",
    )?;
    println!("  Created new file: {}", new_file_path.display());

    let modified_file_path = upper_path.join("modified.txt");
    fs::write(
        &modified_file_path,
        "This original file was modified in the sandbox\n",
    )?;
    println!(
        "  Created modified file: {}\n",
        modified_file_path.display()
    );

    // Query layer information
    println!("[5] Layer Information\n");

    let lower_info = sandbox_rs::LayerInfo::from_path("lower", overlay.lower_path(), false)?;
    println!("  Lower Layer (Read-only):");
    println!("    Files: {}", lower_info.file_count);
    println!("    Total size: {} bytes", lower_info.size);
    println!("    Writable: {}\n", lower_info.writable);

    let upper_info = sandbox_rs::LayerInfo::from_path("upper", overlay.upper_path(), true)?;
    println!("  Upper Layer (Read-write changes):");
    println!("    Files: {}", upper_info.file_count);
    println!("    Total size: {} bytes", upper_info.size);
    println!("    Writable: {}\n", upper_info.writable);

    // Get total changes size
    println!("[6] Sandbox Modifications Summary\n");
    let changes_size = overlay.get_changes_size()?;
    println!("  Total changes in upper layer: {} bytes", changes_size);
    println!("  Files modified/created: {}\n", upper_info.file_count);

    // Show how to use the merged view
    println!("[7] Accessing Merged View\n");
    println!("  In a real mount, you would access both layers transparently:");
    println!("    - {} (combined view)", overlay.merged_path().display());
    println!("    - Files from lower layer are visible");
    println!("    - Files from upper layer override lower layer");
    println!("    - New files only appear in upper layer\n");

    // Demonstrate cleanup and recovery
    println!("[8] Cleanup and Recovery Options\n");
    println!("  Option A: Keep upper layer for audit trail");
    println!(
        "    - Preserve {} for reviewing changes",
        upper_path.display()
    );
    println!("    - Original base layer remains untouched\n");

    println!("  Option B: Discard changes (reset to base)");
    println!("    - Delete upper layer: {}", upper_path.display());
    println!("    - Next execution gets fresh base\n");

    println!("  Option C: Commit changes to new base");
    println!("    - Copy merged view to new base layer");
    println!("    - Create fresh upper layer for next sandbox\n");

    // Cleanup
    println!("[9] Cleaning up\n");
    overlay.cleanup()?;
    println!("  Overlay filesystem cleaned up\n");

    // Practical use case demonstration
    println!("=== Practical Use Case ===\n");
    println!("Scenario: Run Python data processing pipeline with multiple stages\n");

    println!("Stage 1: Initial execution");
    println!("  Base layer:  /data/pipeline-v1.0 (read-only)");
    println!("  Upper layer: /sandbox-run-1/changes");
    println!("  Output:      preprocessing complete, 1.2GB changes\n");

    println!("Stage 2: Different parameters");
    println!("  Base layer:  /data/pipeline-v1.0 (same - shared!)");
    println!("  Upper layer: /sandbox-run-2/changes (fresh)");
    println!("  Output:      processing complete, 2.1GB changes\n");

    println!("Benefits:");
    println!("  - Disk efficient: Base shared across runs");
    println!("  - Isolation: Each run has independent changes");
    println!("  - Auditability: See exactly what each run produced");
    println!("  - Recoverability: Can revert to base state\n");

    // Volume mount for persistent storage
    println!("=== Combined with Volume Mounts ===\n");
    println!("For persistent storage across sandbox runs:");
    println!("  - Overlay FS: For temporary isolation per execution");
    println!("  - Volume mounts: For data that needs to survive");
    println!("  - Example setup:");
    println!("    - Mount /home/user/data as /data (read-write)");
    println!("    - Overlay base /usr/lib as /lib (read-only with changes)");
    println!("    - Any writes to /data persist beyond sandbox");
    println!("    - Any writes to /lib are isolated per run\n");

    println!("=== Example completed successfully ===");
    Ok(())
}
