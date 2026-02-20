//! Namespace Configuration Example
//!
//! This example demonstrates different namespace isolation configurations
//! and when to use each one.
//!
//! ## Overview
//!
//! Linux namespaces isolate different aspects of the system:
//! - **PID**: Process IDs (each namespace has independent PID 1)
//! - **IPC**: Inter-process communication (message queues, shared memory)
//! - **NET**: Network interfaces, routing tables, ports
//! - **MOUNT**: Filesystem mount points
//! - **UTS**: Hostname and domain name
//! - **USER**: User and group IDs
//!
//! ## Running this example
//!
//! ```bash
//! cargo run --example namespace_config
//! ```

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Namespace Configuration Examples ===\n");

    // Show default configuration
    println!("[1] Default Namespace Configuration\n");
    show_default_config();
    println!();

    // Minimal configuration
    println!("[2] Minimal Namespace Configuration\n");
    show_minimal_config()?;
    println!();

    // All namespaces enabled
    println!("[3] All Namespaces Enabled\n");
    show_all_namespaces_config()?;
    println!();

    // Use case 1: Compute jobs
    println!("[4] Use Case: Compute Job\n");
    show_compute_job_config();
    println!();

    // Use case 2: Web server
    println!("[5] Use Case: Web Service\n");
    show_web_service_config();
    println!();

    // Use case 3: Data processing
    println!("[6] Use Case: Data Processing\n");
    show_data_processing_config();
    println!();

    // Use case 4: Untrusted code
    println!("[7] Use Case: Untrusted Code Execution\n");
    show_untrusted_code_config();
    println!();

    // Namespace isolation levels
    println!("[8] Isolation Levels\n");
    show_isolation_levels();
    println!();

    // Performance and trade-offs
    println!("[9] Performance and Trade-offs\n");
    show_performance_considerations();
    println!();

    println!("=== Example completed ===");
    Ok(())
}

/// Show default namespace configuration
fn show_default_config() {
    println!("Default configuration enables most namespaces for balance:");
    println!("  - PID namespace:   YES (isolated process IDs)");
    println!("  - IPC namespace:   YES (isolated IPC)");
    println!("  - NET namespace:   YES (isolated network)");
    println!("  - MOUNT namespace: YES (isolated mounts)");
    println!("  - UTS namespace:   YES (isolated hostname)");
    println!("  - USER namespace:  NO (same UID/GID as host)\n");

    println!("Good for: Most general-purpose sandboxes\n");

    println!("Code:");
    println!("  let config = NamespaceConfig::default();");
    println!("  let mut sandbox = SandboxBuilder::new(\"test\")");
    println!("    .namespaces(config)");
    println!("    .build()?;\n");

    println!("Result:");
    println!("  - Process isolation: Full");
    println!("  - Network isolation: Full");
    println!("  - Filesystem isolation: Partial (can see host mounts)");
    println!("  - User privileges: Inherited from parent\n");
}

/// Show minimal configuration
fn show_minimal_config() -> Result<(), Box<dyn std::error::Error>> {
    println!("Minimal configuration uses smallest set of namespaces:");
    println!("  - PID namespace:   YES (required, minimal)");
    println!("  - IPC namespace:   NO");
    println!("  - NET namespace:   NO");
    println!("  - MOUNT namespace: NO");
    println!("  - UTS namespace:   NO");
    println!("  - USER namespace:  NO\n");

    println!("Good for: Lightweight isolation, maximum compatibility\n");

    println!("Code:");
    println!("  let config = NamespaceConfig::minimal();");
    println!("  let mut sandbox = SandboxBuilder::new(\"minimal\")");
    println!("    .namespaces(config)");
    println!("    .build()?;\n");

    println!("Result:");
    println!("  - Process isolation: PID only");
    println!("  - Network isolation: None (shares host network)");
    println!("  - Filesystem isolation: None (sees host filesystem)");
    println!("  - IPC sharing: Uses host IPC\n");

    println!("Trade-offs:");
    println!("  Pro:  Faster, lower overhead, easier debugging");
    println!("  Con:  Less isolation, higher security risk\n");

    Ok(())
}

/// Show all namespaces enabled
fn show_all_namespaces_config() -> Result<(), Box<dyn std::error::Error>> {
    println!("Full isolation enables all available namespaces:");
    println!("  - PID namespace:   YES");
    println!("  - IPC namespace:   YES");
    println!("  - NET namespace:   YES");
    println!("  - MOUNT namespace: YES");
    println!("  - UTS namespace:   YES");
    println!("  - USER namespace:  YES (requires careful setup)\n");

    println!("Good for: Maximum isolation, security-critical workloads\n");

    println!("Code:");
    println!("  let config = NamespaceConfig::all();");
    println!("  let mut sandbox = SandboxBuilder::new(\"isolated\")");
    println!("    .namespaces(config)");
    println!("    .build()?;\n");

    println!("Result:");
    println!("  - Process isolation: Complete");
    println!("  - Network isolation: Complete");
    println!("  - Filesystem isolation: Complete");
    println!("  - User privileges: Mapped (UID 0 in container != root)");
    println!("  - Hostname: Isolated\n");

    println!("Trade-offs:");
    println!("  Pro:  Maximum isolation and security");
    println!("  Con:  Higher overhead, requires root, more complex setup\n");

    Ok(())
}

/// Use case: Compute job
fn show_compute_job_config() {
    println!("Scenario: Run mathematical/statistical computations\n");

    println!("Required isolation:");
    println!("  - PID: YES (independent process tree)");
    println!("  - MOUNT: YES (can provide fresh filesystem)");
    println!("  - NET: NO (doesn't need network)");
    println!("  - USER: NO (can use host user)\n");

    println!("Configuration:");
    println!("  NamespaceConfig {{");
    println!("    pid: true,");
    println!("    mount: true,");
    println!("    net: false,");
    println!("    ipc: false,");
    println!("    uts: false,");
    println!("    user: false,");
    println!("  }}\n");

    println!("Benefits:");
    println!("  - Lightweight (skip network isolation)");
    println!("  - Process tree isolation");
    println!("  - Filesystem isolation\n");

    println!("Example:");
    println!("  let config = NamespaceConfig {{");
    println!("    pid: true, mount: true, ..Default::default()");
    println!("  }};");
    println!("  let mut sandbox = SandboxBuilder::new(\"compute-job\")");
    println!("    .namespaces(config)");
    println!("    .memory_limit_str(\"512M\")?");
    println!("    .cpu_limit_percent(100)");
    println!("    .timeout(Duration::from_secs(60))");
    println!("    .build()?;\n");
}

/// Use case: Web service
fn show_web_service_config() {
    println!("Scenario: Run isolated web server (nginx, node.js, etc.)\n");

    println!("Required isolation:");
    println!("  - PID: YES (manage server lifecycle)");
    println!("  - NET: YES (custom ports, isolated network)");
    println!("  - MOUNT: YES (custom root filesystem)");
    println!("  - UTS: YES (different hostname)");
    println!("  - IPC: YES (prevent IPC attacks)\n");

    println!("Configuration:");
    println!("  NamespaceConfig {{");
    println!("    pid: true,");
    println!("    net: true,   // Critical for web service");
    println!("    mount: true,");
    println!("    uts: true,");
    println!("    ipc: true,");
    println!("    user: false,");
    println!("  }}\n");

    println!("Why each namespace:");
    println!("  - PID: Control server process and children");
    println!("  - NET: Bind to isolated ports, no host port interference");
    println!("  - MOUNT: Serve from isolated root");
    println!("  - UTS: Show service name in hostname");
    println!("  - IPC: Prevent socket attacks\n");

    println!("Example:");
    println!("  let config = NamespaceConfig {{");
    println!("    pid: true, net: true, mount: true,");
    println!("    uts: true, ipc: true, ..Default::default()");
    println!("  }};");
    println!("  let mut sandbox = SandboxBuilder::new(\"web-server\")");
    println!("    .namespaces(config)");
    println!("    .memory_limit_str(\"256M\")?");
    println!("    .cpu_limit_percent(50)");
    println!("    .build()?;\n");
}

/// Use case: Data processing
fn show_data_processing_config() {
    println!("Scenario: Run data processing (MapReduce, ETL, etc.)\n");

    println!("Required isolation:");
    println!("  - PID: YES (manage worker processes)");
    println!("  - MOUNT: YES (isolated temporary files)");
    println!("  - NET: NO (typically no network needed)");
    println!("  - IPC: YES (prevent interference between workers)\n");

    println!("Configuration:");
    println!("  NamespaceConfig {{");
    println!("    pid: true,");
    println!("    mount: true,");
    println!("    ipc: true,    // Prevent inter-worker IPC");
    println!("    net: false,   // Usually not needed");
    println!("    uts: false,");
    println!("    user: false,");
    println!("  }}\n");

    println!("Considerations:");
    println!("  - Shared filesystem via volume mounts");
    println!("  - Isolated temp directories per worker");
    println!("  - No network isolation (backend operation)\n");

    println!("Example:");
    println!("  let config = NamespaceConfig {{");
    println!("    pid: true, mount: true, ipc: true,");
    println!("    ..Default::default()");
    println!("  }};");
    println!("  let mut sandbox = SandboxBuilder::new(\"data-worker\")");
    println!("    .namespaces(config)");
    println!("    .memory_limit_str(\"1G\")?");
    println!("    .cpu_limit_percent(100)");
    println!("    .timeout(Duration::from_secs(300))");
    println!("    .build()?;\n");
}

/// Use case: Untrusted code
fn show_untrusted_code_config() {
    println!("Scenario: Execute untrusted user code (CTF, code challenges)\n");

    println!("Required isolation: MAXIMUM");
    println!("  - PID: YES");
    println!("  - NET: YES (prevent exfiltration)");
    println!("  - MOUNT: YES");
    println!("  - IPC: YES");
    println!("  - UTS: YES");
    println!("  - USER: YES (privilege escalation defense)\n");

    println!("Configuration:");
    println!("  NamespaceConfig::all()\n");

    println!("Additional security:");
    println!("  - Tight memory limit (64-128MB)");
    println!("  - Tight CPU limit (10-25%)");
    println!("  - Short timeout (5-10s)");
    println!("  - Minimal seccomp profile\n");

    println!("Example:");
    println!("  let mut sandbox = SandboxBuilder::new(\"untrusted-code\")");
    println!("    .namespaces(NamespaceConfig::all())");
    println!("    .memory_limit_str(\"64M\")?");
    println!("    .cpu_limit_percent(10)");
    println!("    .timeout(Duration::from_secs(5))");
    println!("    .seccomp_profile(sandbox_rs::SeccompProfile::Minimal)");
    println!("    .build()?;\n");
}

/// Show isolation levels
fn show_isolation_levels() {
    println!("Isolation can be thought of in levels:\n");

    println!("Level 1: Process isolation only");
    println!("  Namespaces: PID");
    println!("  Use: Quick isolation, same filesystem/network");
    println!("  Risk: High\n");

    println!("Level 2: Process + filesystem isolation");
    println!("  Namespaces: PID, MOUNT");
    println!("  Use: Different root filesystem");
    println!("  Risk: Medium-high\n");

    println!("Level 3: Process + filesystem + network isolation");
    println!("  Namespaces: PID, MOUNT, NET");
    println!("  Use: Full isolation, different network");
    println!("  Risk: Medium\n");

    println!("Level 4: Complete namespace isolation");
    println!("  Namespaces: All (PID, MOUNT, NET, UTS, IPC)");
    println!("  Use: Strong isolation");
    println!("  Risk: Low-medium\n");

    println!("Level 5: Complete isolation + user mapping");
    println!("  Namespaces: All + USER namespace");
    println!("  Use: Container-like isolation");
    println!("  Risk: Low\n");

    println!("Choosing the right level:");
    println!("  - Consider threat model");
    println!("  - Balance isolation vs performance");
    println!("  - Start strict, loosen only if needed");
}

/// Show performance considerations
fn show_performance_considerations() {
    println!("Overhead by namespace:\n");

    println!("PID namespace:");
    println!("  Overhead: <1%");
    println!("  Benefit: Process tree isolation");
    println!("  Use: Nearly always\n");

    println!("MOUNT namespace:");
    println!("  Overhead: <2%");
    println!("  Benefit: Filesystem isolation");
    println!("  Use: Most cases\n");

    println!("NET namespace:");
    println!("  Overhead: 2-5%");
    println!("  Benefit: Network isolation");
    println!("  Use: When network isolation needed\n");

    println!("USER namespace:");
    println!("  Overhead: 3-5%");
    println!("  Benefit: UID/GID mapping");
    println!("  Use: High security requirements\n");

    println!("IPC namespace:");
    println!("  Overhead: <1%");
    println!("  Benefit: IPC isolation");
    println!("  Use: Generally include\n");

    println!("UTS namespace:");
    println!("  Overhead: <1%");
    println!("  Benefit: Hostname isolation");
    println!("  Use: Nice to have\n");

    println!("Recommendations:");
    println!("  - Start with default (PID, MOUNT, NET, IPC, UTS)");
    println!("  - Add USER namespace if running untrusted code");
    println!("  - Remove NET/MOUNT if truly not needed");
    println!("  - Measure impact for performance-critical apps\n");
}
