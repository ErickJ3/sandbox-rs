//! Example: Basic streaming output from sandboxed process
//!
//! This example demonstrates how to capture and stream stdout/stderr
//! from a sandboxed process in real-time.

use sandbox_rs::{SandboxBuilder, StreamChunk};
use std::time::Duration;
use tempfile::tempdir;

fn main() -> sandbox_rs::Result<()> {
    // Create a temporary directory for the sandbox
    let tmp = tempdir().expect("Failed to create temp dir");

    // Create a sandbox with streaming enabled
    let mut sandbox = SandboxBuilder::new("stream-example")
        .memory_limit_str("256M")?
        .cpu_limit_percent(50)
        .timeout(Duration::from_secs(30))
        .root(tmp.path())
        .build()?;

    println!("Starting sandboxed process with streaming...\n");

    // Run process with streaming
    let (result, stream) = sandbox.run_with_stream("/bin/echo", &["Hello from sandbox!"])?;

    println!("Process output (streaming):");

    // Iterate through all output chunks
    let mut final_exit_code = result.exit_code;
    let mut final_signal = result.signal;

    for chunk in stream.into_iter() {
        match chunk {
            StreamChunk::Stdout(line) => {
                println!("[STDOUT] {}", line);
            }
            StreamChunk::Stderr(line) => {
                eprintln!("[STDERR] {}", line);
            }
            StreamChunk::Exit { exit_code, signal } => {
                println!("\nProcess exited with code: {}", exit_code);
                if let Some(sig) = signal {
                    println!("Killed by signal: {}", sig);
                }
                final_exit_code = exit_code;
                final_signal = signal;
            }
        }
    }

    // Update result with the actual exit code from streaming
    let mut result = result;
    result.exit_code = final_exit_code;
    result.signal = final_signal;

    println!("\nExecution stats:");
    println!("  Exit code: {}", result.exit_code);
    println!("  Wall time: {} ms", result.wall_time_ms);
    println!("  Memory peak: {} bytes", result.memory_peak);

    // Check for seccomp errors and return error if found
    result.check_seccomp_error()?;

    Ok(())
}
