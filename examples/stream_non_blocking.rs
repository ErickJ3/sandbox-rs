//! Example: Non-blocking stream reading
//!
//! This example demonstrates how to do non-blocking reads from the process stream,
//! allowing your application to continue doing other work while checking for output.
//!
//! Note: This example uses SeccompProfile::Unrestricted because bash requires
//! many syscalls for proper operation. For simple commands like `echo`, you can
//! use more restrictive profiles like Minimal or Compute.

use sandbox_rs::{SandboxBuilder, StreamChunk, SeccompProfile};
use std::time::Duration;
use tempfile::tempdir;

fn main() -> sandbox_rs::Result<()> {
    let tmp = tempdir().expect("Failed to create temp dir");

    let mut sandbox = SandboxBuilder::new("non-blocking-example")
        .memory_limit_str("256M")?
        .cpu_limit_percent(50)
        .seccomp_profile(SeccompProfile::Unrestricted)
        .root(tmp.path())
        .build()?;

    println!("Running process with non-blocking stream reads...\n");

    // Run a process that outputs slowly
    let (result, stream) = sandbox.run_with_stream(
        "/bin/bash",
        &[
            "-c",
            "for i in {1..3}; do echo \"Message $i\"; sleep 0.1; done",
        ],
    )?;

    println!("Non-blocking polling:");

    let mut received_chunks = 0;
    let mut polling_attempts = 0;
    let mut final_exit_code = result.exit_code;

    loop {
        polling_attempts += 1;

        // Try to read without blocking
        match stream.try_recv()? {
            Some(chunk) => match chunk {
                StreamChunk::Stdout(line) => {
                    println!("[STDOUT] {}", line);
                    received_chunks += 1;
                }
                StreamChunk::Stderr(line) => {
                    eprintln!("[STDERR] {}", line);
                    received_chunks += 1;
                }
                StreamChunk::Exit {
                    exit_code,
                    signal: _,
                } => {
                    println!("Process exited with code: {}", exit_code);
                    // Capture the real exit code from the stream
                    final_exit_code = exit_code;
                    break;
                }
            },
            None => {
                // No data available right now, we could do other work here
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        // Safety limit to prevent infinite loop in case of issues
        if polling_attempts > 10000 {
            println!("Safety timeout reached");
            break;
        }
    }

    // Update result with the actual exit code from streaming
    let mut result = result;
    result.exit_code = final_exit_code;

    println!("\nStatistics:");
    println!("  Chunks received: {}", received_chunks);
    println!("  Polling attempts: {}", polling_attempts);
    println!("  Exit code: {}", result.exit_code);
    println!("  Wall time: {} ms", result.wall_time_ms);

    // Check for seccomp errors and return error if found
    result.check_seccomp_error()?;

    Ok(())
}
