//! CLI-based Sandbox Examples
//!
//! This example demonstrates how to use the sandbox-ctl CLI to create and manage sandboxes
//! from the command line. It shows various ways to invoke the sandbox with different options.
//!
//! ## Prerequisites
//!
//! 1. Build the sandbox-ctl CLI:
//!    cargo build --bin sandbox-ctl
//!
//! 2. Run with root privileges (required for full isolation):
//!    sudo ./target/debug/sandbox-ctl run --id test-1 /bin/echo "hello world"
//!
//! ## Examples shown
//!
//! This file documents the CLI usage patterns. Here are the common invocations:
//!
//! ### 1. Basic execution (no resource limits)
//! ```bash
//! sandbox-ctl run --id my-sandbox /bin/echo "hello"
//! ```
//!
//! ### 2. With memory limit
//! ```bash
//! sandbox-ctl run --id memory-limited \
//!   --memory 100M \
//!   /bin/bash -c "echo 'Running with 100MB memory limit'"
//! ```
//!
//! ### 3. With CPU limit (50% of one core)
//! ```bash
//! sandbox-ctl run --id cpu-limited \
//!   --cpu 50 \
//!   /bin/stress-ng --cpu 1 --timeout 5s
//! ```
//!
//! ### 4. With timeout
//! ```bash
//! sandbox-ctl run --id timeout-example \
//!   --timeout 2 \
//!   /bin/sleep 10  # Will be killed after 2 seconds
//! ```
//!
//! ### 5. With seccomp profile
//! ```bash
//! sandbox-ctl run --id minimal-syscalls \
//!   --seccomp minimal \
//!   /bin/echo "Only essential syscalls allowed"
//! ```
//!
//! ### 6. Combined: Memory + CPU + Timeout + Seccomp
//! ```bash
//! sandbox-ctl run --id restricted \
//!   --memory 256M \
//!   --cpu 25 \
//!   --timeout 30 \
//!   --seccomp io-heavy \
//!   /usr/bin/python3 script.py
//! ```
//!
//! ### 7. With custom sandbox root directory
//! ```bash
//! sandbox-ctl run --id custom-root \
//!   --root /tmp/my-sandbox-root \
//!   /bin/ls -la
//! ```
//!
//! ### 8. List available seccomp profiles
//! ```bash
//! sandbox-ctl profiles
//! ```
//!
//! ### 9. Check system requirements
//! ```bash
//! sandbox-ctl check
//! ```
//!
//! ## Memory limit formats
//!
//! The --memory flag supports multiple formats:
//! - "64M" or "64MB" - megabytes
//! - "1G" or "1GB" - gigabytes
//! - "512K" or "512KB" - kilobytes
//! - Direct bytes as number
//!
//! ## CPU limit (percentage)
//!
//! The --cpu flag accepts 0-100:
//! - 25 = 25% of one CPU core
//! - 50 = 50% of one CPU core (half core)
//! - 100 = One full CPU core
//! - 200 = Two CPU cores (on multi-core systems)
//!
//! ## Seccomp profiles
//!
//! Available profiles (use with --seccomp):
//! - minimal: Only essential syscalls (exit, read, write)
//! - io-heavy: Minimal + file I/O (open, close, seek, stat)
//! - compute: IO-heavy + memory operations (mmap, brk, mprotect)
//! - network: Compute + socket operations (socket, bind, listen)
//! - unrestricted: Most syscalls allowed (for debugging)
//!
//! ## Running with sudo
//!
//! Since full isolation requires root:
//! ```bash
//! # Option 1: Run entire command as root
//! sudo ./target/debug/sandbox-ctl run --id test /bin/echo "hello"
//!
//! # Option 2: Configure sudo to allow without password (advanced)
//! # Add to /etc/sudoers:
//! # user ALL=(ALL) NOPASSWD: /path/to/sandbox-ctl
//! ```
//!
//! ## Exit codes
//!
//! The CLI returns:
//! - Exit code of the sandboxed program (0-255)
//! - 1 if sandbox creation or execution failed
//!
//! ## Performance considerations
//!
//! - Memory limits are enforced at kernel level via Cgroup v2
//! - CPU limits use CFS scheduler quotas
//! - Seccomp filtering happens in kernel BPF
//! - Namespace isolation has minimal overhead

fn main() {
    println!("=== Sandbox-ctl CLI Usage Examples ===\n");

    println!("This is a documentation file showing CLI usage patterns.");
    println!("Build and run sandbox-ctl with the examples below:\n");

    println!("Basic usage:");
    println!("  cargo build --bin sandbox-ctl");
    println!("  sudo ./target/debug/sandbox-ctl run --id my-box /bin/echo hello\n");

    println!("With resource limits:");
    println!("  sudo ./target/debug/sandbox-ctl run \\");
    println!("    --id limited \\");
    println!("    --memory 256M \\");
    println!("    --cpu 50 \\");
    println!("    --timeout 30 \\");
    println!("    --seccomp io-heavy \\");
    println!("    /bin/bash -c 'echo test && sleep 2'\n");

    println!("Check system requirements:");
    println!("  sudo ./target/debug/sandbox-ctl check\n");

    println!("List seccomp profiles:");
    println!("  ./target/debug/sandbox-ctl profiles\n");

    println!("Try memory-limited execution:");
    println!("  sudo ./target/debug/sandbox-ctl run \\");
    println!("    --id memory-test \\");
    println!("    --memory 100M \\");
    println!("    /usr/bin/yes > /dev/null\n");

    println!("Try CPU-limited execution:");
    println!("  sudo ./target/debug/sandbox-ctl run \\");
    println!("    --id cpu-test \\");
    println!("    --cpu 25 \\");
    println!("    /bin/sh -c 'for i in $(seq 1 1000000); do :; done'\n");

    println!("Try timeout:");
    println!("  sudo ./target/debug/sandbox-ctl run \\");
    println!("    --id timeout-test \\");
    println!("    --timeout 2 \\");
    println!("    /bin/sleep 10\n");

    println!("Minimal seccomp profile (restricted syscalls):");
    println!("  sudo ./target/debug/sandbox-ctl run \\");
    println!("    --id strict \\");
    println!("    --seccomp minimal \\");
    println!("    /bin/echo 'Only essential syscalls'\n");

    println!("See the source code comments for more details on each option.");
}
