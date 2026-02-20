//! Basic sandbox example

use sandbox_rs::{SandboxBuilder, SeccompProfile};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Sandbox RS - Basic Example ===\n");

    // Create a sandbox with basic configuration
    println!("[1] Creating sandbox with memory limit...");
    let mut sandbox = SandboxBuilder::new("example-1")
        .memory_limit(50 * 1024 * 1024) // 50MB
        .cpu_limit_percent(50) // 50% of one CPU
        .timeout(Duration::from_secs(5))
        .seccomp_profile(SeccompProfile::Minimal)
        .build()?;

    println!("[*] Sandbox created: {}", sandbox.id());
    println!("[*] Root: {}", sandbox.root().display());
    println!(
        "[*] Status: {}\n",
        if sandbox.is_running() {
            "running"
        } else {
            "idle"
        }
    );

    // Try to run a simple command
    println!("[2] Running 'echo hello' in sandbox...");
    let result = sandbox.run("/bin/echo", &["hello", "world"])?;

    println!("[*] Execution result:");
    println!("Exit code: {}", result.exit_code);
    println!("Wall time: {} ms", result.wall_time_ms);
    println!("Memory peak: {} bytes", result.memory_peak);
    println!("CPU time: {} μs", result.cpu_time_us);
    println!("Timed out: {}\n", result.timed_out);

    Ok(())
}
