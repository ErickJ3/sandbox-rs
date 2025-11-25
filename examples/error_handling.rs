//! Error Handling and Resource Limits Example
//!
//! This example demonstrates how to handle common error scenarios
//! when using sandboxes, including:
//! - Timeout handling
//! - Out-of-memory (OOM) conditions
//! - Seccomp violations
//! - Invalid configurations
//! - Resource exhaustion
//!
//! ## Running this example
//!
//! ```bash
//! cargo run --example error_handling
//! ```
//!
//! Note: Some scenarios require root privileges for full enforcement

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Sandbox Error Handling Examples ===\n");

    // Scenario 1: Timeout handling
    println!("[Scenario 1] Timeout Handling\n");
    scenario_timeout()?;
    println!();

    // Scenario 2: Invalid configuration
    println!("[Scenario 2] Invalid Configuration Detection\n");
    scenario_invalid_config();
    println!();

    // Scenario 3: Proper error matching
    println!("[Scenario 3] Error Matching and Recovery\n");
    scenario_error_matching()?;
    println!();

    // Scenario 4: Resource-limited execution
    println!("[Scenario 4] Resource Enforcement\n");
    scenario_resource_limits()?;
    println!();

    // Scenario 5: Seccomp violation (informational)
    println!("[Scenario 5] Seccomp Violation Handling\n");
    scenario_seccomp_violation();
    println!();

    // Scenario 6: Best practices
    println!("[Scenario 6] Error Handling Best Practices\n");
    best_practices();
    println!();

    println!("=== All scenarios completed ===");
    Ok(())
}

/// Example 1: Timeout handling
fn scenario_timeout() -> Result<(), Box<dyn std::error::Error>> {
    println!("When a sandbox times out:");
    println!("  - The process is killed");
    println!("  - SandboxResult.timed_out = true");
    println!("  - Exit code may be None (killed by signal)\n");

    println!("Code example:");
    println!("  let mut sandbox = SandboxBuilder::new(\"timeout-test\")");
    println!("    .timeout(Duration::from_secs(2))");
    println!("    .build()?;\n");

    println!("  let result = sandbox.run(\"/bin/sleep\", &[\"10\"])?;");
    println!("  if result.timed_out {{");
    println!("    println!(\"Sandbox exceeded 2 second timeout\");");
    println!("    // Handle timeout: cleanup, retry, report error, etc.");
    println!("  }}\n");

    println!("Common timeout scenarios:");
    println!("  1. Process hangs indefinitely");
    println!("  2. Infinite loop in sandboxed code");
    println!("  3. Deadlock or resource contention");
    println!("  4. Network I/O waiting for external service\n");

    println!("Mitigation strategies:");
    println!("  - Set appropriate timeout based on expected runtime");
    println!("  - Use shorter timeouts for untrusted code");
    println!("  - Log which operations timeout for debugging");
    println!("  - Increase timeout for I/O intensive operations");

    Ok(())
}

/// Example 2: Invalid configuration detection
fn scenario_invalid_config() {
    println!("The sandbox validates configuration at build time:");
    println!("  1. Requires at least one namespace");
    println!("  2. Validates sandbox ID is non-empty");
    println!("  3. Checks resource limits are reasonable");
    println!("  4. May require root privileges\n");

    println!("Example: Building with invalid config\n");
    println!("  // This would fail at build time:");
    println!("  let result = SandboxBuilder::new(\"\")  // Empty ID!");
    println!("    .build();");
    println!("  // result is Err: \"Sandbox ID cannot be empty\"\n");

    println!("Another example: Disabled all namespaces\n");
    println!("  let config = NamespaceConfig {{");
    println!("    pid: false,");
    println!("    ipc: false,");
    println!("    net: false,");
    println!("    mount: false,");
    println!("    uts: false,");
    println!("    user: false,");
    println!("  }};");
    println!("  // Error: \"At least one namespace must be enabled\"\n");

    println!("Best practice:");
    println!("  - Always check build() result");
    println!("  - Use ? operator for early error propagation");
    println!("  - Log configuration errors for debugging\n");
}

/// Example 3: Error matching and recovery
fn scenario_error_matching() -> Result<(), Box<dyn std::error::Error>> {
    println!("Handling different error types:\n");

    println!("Example: Create sandbox with detailed error handling\n");
    println!("  match SandboxBuilder::new(\"test\")");
    println!("    .memory_limit_str(\"invalid\")");
    println!("    .build() {{");
    println!("      Ok(sandbox) => {{ /* success */ }},");
    println!("      Err(e) => {{");
    println!("        match e {{");
    println!("          SandboxError::InvalidConfig(msg) => {{");
    println!("            eprintln!(\"Config error: {{}}\", msg);");
    println!("            // Recover: use defaults or prompt user");
    println!("          }},");
    println!("          SandboxError::Io(io_err) => {{");
    println!("            eprintln!(\"IO error: {{}}\", io_err);");
    println!("            // Recover: check permissions, disk space");
    println!("          }},");
    println!("          SandboxError::Syscall(msg) => {{");
    println!("            eprintln!(\"Syscall failed: {{}}\", msg);");
    println!("            // Recover: may need root or kernel features");
    println!("          }},");
    println!("          _ => {{");
    println!("            eprintln!(\"Other error: {{}}\", e);");
    println!("          }}");
    println!("        }}");
    println!("      }}");
    println!("    }}\n");

    println!("Common error sources:");
    println!("  - InvalidConfig: User provided bad parameters");
    println!("  - Io: File system operations failed");
    println!("  - Syscall: Kernel operations failed (may need root)");
    println!("  - AlreadyRunning: Tried to run program twice");
    println!("  - ProcessMonitoring: Failed to read process stats\n");

    Ok(())
}

/// Example 4: Resource limits enforcement
fn scenario_resource_limits() -> Result<(), Box<dyn std::error::Error>> {
    println!("Memory limit example:");
    println!("  let mut sandbox = SandboxBuilder::new(\"memory-test\")");
    println!("    .memory_limit(100 * 1024 * 1024)  // 100MB");
    println!("    .build()?;");
    println!("  let result = sandbox.run(\"/usr/bin/yes\", &[])?;");
    println!("  if result.memory_peak > 100 * 1024 * 1024 {{");
    println!("    println!(\"Process exceeded memory limit!\");");
    println!("  }}\n");

    println!("CPU limit example:");
    println!("  let mut sandbox = SandboxBuilder::new(\"cpu-test\")");
    println!("    .cpu_limit_percent(50)  // Max 50% of one core");
    println!("    .build()?;");
    println!("  let result = sandbox.run(\"/bin/sh\", &[\"-c\", \"...\"])?;");
    println!("  println!(\"CPU time: {{}} us\", result.cpu_time_us);\n");

    println!("What happens when limits are exceeded:");
    println!("  Memory: Process is OOMkilled by kernel");
    println!("  CPU: Process is throttled (runs slower)");
    println!("  PIDs: New fork() calls fail with EAGAIN\n");

    println!("Recommended limits by use case:");
    println!("  Untrusted code:     64MB memory, 10-25% CPU, 5s timeout");
    println!("  Data processing:   512MB-1GB memory, 50-100% CPU, 60s timeout");
    println!("  Compute intensive:  1-2GB memory, 100%+ CPU, 120s+ timeout\n");

    Ok(())
}

/// Example 5: Seccomp violation information
fn scenario_seccomp_violation() {
    println!("Seccomp filtering prevents dangerous syscalls:");
    println!("  - Minimal profile: Only exit, read, write");
    println!("  - IoHeavy: Adds file operations");
    println!("  - Compute: Adds memory operations");
    println!("  - Network: Adds socket operations\n");

    println!("Example: Attempting forbidden syscall with Minimal profile\n");
    println!("  let mut sandbox = SandboxBuilder::new(\"strict\")");
    println!("    .seccomp_profile(SeccompProfile::Minimal)");
    println!("    .build()?;");
    println!("  // Running code that tries to open a file:");
    println!("  sandbox.run(\"/bin/sh\", &[\"-c\", \"cat /etc/passwd\"])?;");
    println!("  // Result: Process is killed (SIGSYS or similar)\n");

    println!("Checking which syscalls are allowed:");
    println!("  for profile in SeccompProfile::all() {{");
    println!("    println!(\"{{}}: {{}}\", profile.description());");
    println!("  }}\n");

    println!("Design principles:");
    println!("  - Use strictest profile that allows needed operations");
    println!("  - Test sandbox before deploying to production");
    println!("  - Monitor for seccomp violations (SIGSYS signals)");
    println!("  - Log violations for security analysis\n");
}

/// Example 6: Best practices
fn best_practices() {
    println!("Error Handling Best Practices:\n");

    println!("1. VALIDATE EARLY");
    println!("   - Check sandbox.build() result immediately");
    println!("   - Fail fast with clear error messages\n");

    println!("2. USE APPROPRIATE TIMEOUTS");
    println!("   - Set realistic timeouts based on expected runtime");
    println!("   - Use shorter timeouts (5-10s) for untrusted code");
    println!("   - Increase for I/O intensive operations\n");

    println!("3. LIMIT RESOURCES APPROPRIATELY");
    println!("   - Start with tight limits, relax if needed");
    println!("   - Memory: Match actual requirements + safety margin");
    println!("   - CPU: Based on system capacity and fairness");
    println!("   - PIDs: Prevent fork-bomb (usually 4-16)\n");

    println!("4. LOG COMPREHENSIVELY");
    println!("   - Log sandbox creation parameters");
    println!("   - Log execution results (exit code, resources used)");
    println!("   - Log errors with full context");
    println!("   - Example:");
    println!("     info!(\"Sandbox {{id}} created with {{memory}} memory\");");
    println!("     match sandbox.run(...) {{");
    println!("       Ok(result) => warn!(\"{{id}} timed out\"),");
    println!("       Err(e) => error!(\"{{id}} failed: {{}}\", e),");
    println!("     }}\n");

    println!("5. HANDLE CLEANUP");
    println!("   - Always cleanup even on error");
    println!("   - Use guard patterns for automatic cleanup:");
    println!("     struct SandboxGuard(Sandbox);");
    println!("     impl Drop for SandboxGuard {{ ... }}\n");

    println!("6. MONITOR RESOURCE USAGE");
    println!("   - Check memory_peak, cpu_time_us");
    println!("   - Alert if approaching limits");
    println!("   - Adjust limits based on actual usage\n");

    println!("7. TEST ERROR PATHS");
    println!("   - Test with invalid configs");
    println!("   - Test with tight resource limits");
    println!("   - Test with short timeouts");
    println!("   - Test seccomp violations\n");
}
