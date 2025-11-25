//! Cgroup resource limits example

use sandbox_rs::SandboxBuilder;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Sandbox RS - Cgroup Resource Limits ===\n");

    // Example 1: Memory limited sandbox
    println!("[1] Example: Memory-limited sandbox (100MB)");
    let sandbox1 = SandboxBuilder::new("mem-limited")
        .memory_limit_str("100M")?
        .cpu_limit_percent(100)
        .build()?;
    println!("[*] Created: {}", sandbox1.id());
    println!("[*] Root: {}\n", sandbox1.root().display());

    // Example 2: CPU limited sandbox
    println!("[2] Example: CPU-limited sandbox (25% of one core)");
    let sandbox2 = SandboxBuilder::new("cpu-limited")
        .cpu_limit_percent(25)
        .memory_limit(512 * 1024 * 1024) // 512MB
        .timeout(Duration::from_secs(10))
        .build()?;
    println!("[*] Created: {}", sandbox2.id());
    println!("[*] Root: {}\n", sandbox2.root().display());

    // Example 3: Tight limits for untrusted code
    println!("[3] Example: Tight limits for untrusted code");
    let sandbox3 = SandboxBuilder::new("untrusted")
        .memory_limit_str("64M")?
        .cpu_limit_percent(10)
        .max_pids(8)
        .timeout(Duration::from_secs(5))
        .seccomp_profile(sandbox_rs::SeccompProfile::Minimal)
        .build()?;
    println!("[*] Created: {}", sandbox3.id());
    println!("[*] Root: {}\n", sandbox3.root().display());

    println!("[*] All sandboxes created successfully!");
    println!("[*] Note: Actual resource enforcement requires root permissions");

    Ok(())
}
