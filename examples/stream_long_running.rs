//! Example: Streaming from a long-running process
//!
//! This example shows how to stream output from a process that outputs
//! multiple lines over time, including both stdout and stderr.
//!
//! Note: This example uses SeccompProfile::Unrestricted because bash requires
//! many syscalls for proper operation. For simple commands like `echo`, you can
//! use more restrictive profiles like Minimal or Compute.

use sandbox_rs::{SandboxBuilder, SeccompProfile, StreamChunk};
use std::time::Duration;
use tempfile::tempdir;

fn main() -> sandbox_rs::Result<()> {
    let tmp = tempdir().expect("Failed to create temp dir");

    let mut sandbox = SandboxBuilder::new("long-running-example")
        .memory_limit_str("512M")?
        .cpu_limit_percent(100)
        .timeout(Duration::from_secs(30))
        .seccomp_profile(SeccompProfile::Unrestricted)
        .root(tmp.path())
        .build()?;

    println!("Running bash script with streaming output...\n");

    // Run a bash script that outputs multiple lines
    let (result, stream) = sandbox.run_with_stream(
        "/bin/bash",
        &[
            "-c",
            "for i in {1..5}; do echo \"Line $i from stdout\"; echo \"Error line $i\" >&2; done",
        ],
    )?;

    println!("Streaming output:");

    let mut stdout_count = 0;
    let mut stderr_count = 0;
    let mut final_exit_code = result.exit_code;

    for chunk in stream.into_iter() {
        match chunk {
            StreamChunk::Stdout(line) => {
                stdout_count += 1;
                println!("  [OUT #{}] {}", stdout_count, line);
            }
            StreamChunk::Stderr(line) => {
                stderr_count += 1;
                eprintln!("  [ERR #{}] {}", stderr_count, line);
            }
            StreamChunk::Exit {
                exit_code,
                signal: _,
            } => {
                println!("Process finished with exit code: {}", exit_code);
                final_exit_code = exit_code;
            }
        }
    }

    let mut result = result;
    result.exit_code = final_exit_code;

    println!("\nSummary:");
    println!("  Stdout lines: {}", stdout_count);
    println!("  Stderr lines: {}", stderr_count);
    println!("  Wall time: {} ms", result.wall_time_ms);
    println!("  Exit code: {}", result.exit_code);

    result.check_seccomp_error()?;

    Ok(())
}
