# sandbox-rs

A comprehensive Rust sandbox implementation that provides process isolation, resource limiting, and syscall filtering for secure program execution.

![Tests](https://img.shields.io/github/actions/workflow/status/ErickJ3/sandbox-rs/ci.yml?branch=main&label=test)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Rust](https://img.shields.io/badge/rust-1.91%2B-orange.svg)

## Overview

sandbox-rs is a library and CLI tool for creating lightweight, secure sandboxes on Linux systems. It combines multiple isolation mechanisms—Linux namespaces, Seccomp BPF filtering, Cgroup v2 resource limits, and filesystem isolation—into a unified, easy-to-use interface.

## Features

### Isolation
- **Linux Namespaces**: PID, IPC, network, mount, UTS, and user namespaces for complete process isolation
- **Seccomp Filtering**: BPF-based syscall filtering with five predefined profiles (minimal, io-heavy, compute, network, unrestricted)
- **Filesystem Isolation**: Overlay filesystem with copy-on-write semantics and volume mount support

### Resource Management
- **Memory Limits**: Hard ceiling with out-of-memory enforcement
- **CPU Limits**: Quota-based scheduling with percentage-based controls
- **Process Limits**: Maximum PID restrictions per sandbox
- **Runtime Monitoring**: Real-time resource usage tracking

### Execution
- **Process Isolation**: Namespace-based cloning with independent lifecycles
- **Init Process**: Zombie reaping and signal handling
- **Root Isolation**: Chroot support with credential switching (UID/GID)

## Requirements

- Linux kernel 5.10+ (Cgroup v2 support required)
- Root privileges for full isolation features
- libc support for namespace and seccomp operations

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
sandbox-rs = "0.1"
```

## Usage

### Library

```rust
use sandbox_rs::{SandboxBuilder, SeccompProfile};
use std::time::Duration;

let mut sandbox = SandboxBuilder::new("my-sandbox")
    .memory_limit_str("256M")?
    .cpu_limit_percent(50)?
    .timeout(Duration::from_secs(30))?
    .seccomp_profile(SeccompProfile::IoHeavy)?
    .build()?;

let result = sandbox.run("/bin/echo", &["hello world"])?;
println!("Exit code: {}", result.exit_code);
println!("Memory peak: {} bytes", result.memory_peak);
println!("CPU time: {} μs", result.cpu_time_us);
```

### CLI

```bash
# Run program with sandbox
sandbox-ctl run --id test-run --memory 256M --cpu 50 --timeout 30 /bin/echo "hello world"

# List available seccomp profiles
sandbox-ctl profiles

# Check system requirements
sandbox-ctl check
```

## Architecture

sandbox-rs is organized into modular layers:

- **isolation**: Namespace and Seccomp filtering mechanisms
- **resources**: Cgroup v2 resource limit enforcement
- **execution**: Process lifecycle management and initialization
- **storage**: Filesystem isolation with overlay and volume support
- **monitoring**: Process and syscall observation
- **network**: Network namespace configuration
- **controller**: Main orchestration layer coordinating all subsystems

## Configuration

### Memory Limits

Accepts human-readable formats:
- `100M` - 100 megabytes
- `1G` - 1 gigabyte
- Direct byte count as u64

### CPU Limits

CPU quotas are enforced per sandbox:
- Percentage mode (0-100): `cpu_limit_percent(50)` → 50% of one CPU core
- Raw quota mode: `cpu_quota(50000, 100000)` → 50ms per 100ms period

### Seccomp Profiles

Five builtin profiles control allowed syscalls:

- **minimal**: Basic syscalls only (exit, read, write)
- **io-heavy**: Minimal + file operations (open, close, seek, stat)
- **compute**: IO-heavy + memory operations (mmap, brk, mprotect)
- **network**: Compute + socket operations (socket, bind, listen, connect)
- **unrestricted**: Most syscalls allowed (for debugging)

## Security Considerations

This implementation provides defense-in-depth through multiple isolation layers. However:

- Sandbox escapes are possible through kernel vulnerabilities
- Not suitable for untrusted code execution without additional hardening
- Should be combined with AppArmor or SELinux for production use
- Requires ongoing kernel security updates

## Testing

```bash
cargo test
```

Tests are marked `serial` where required due to global state (root and cgroup manipulation).

## License

See LICENSE file for details.
