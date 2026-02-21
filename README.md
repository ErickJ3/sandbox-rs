# sandbox-rs

> Lightweight process sandboxing for Linux

![Tests](https://img.shields.io/github/actions/workflow/status/ErickJ3/sandbox-rs/ci.yml?branch=main&label=tests)
[![codecov](https://codecov.io/gh/ErickJ3/sandbox-rs/branch/main/graph/badge.svg)](https://codecov.io/gh/ErickJ3/sandbox-rs)
[![Crates.io](https://img.shields.io/crates/v/sandbox-rs.svg)](https://crates.io/crates/sandbox-rs)
[![Documentation](https://docs.rs/sandbox-rs/badge.svg)](https://docs.rs/sandbox-rs)
![Rust](https://img.shields.io/badge/rust-1.91%2B-orange.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## Things

- **Unprivileged mode** — works without root via user namespaces, Landlock, and setrlimit
- **Privileged mode** — full isolation with cgroups v2, chroot, and all namespace types
- **Auto-detection** — automatically picks the best mode for the current environment
- **Seccomp BPF** — six built-in syscall filtering profiles
- **Landlock** — filesystem access control without root (Linux 5.13+)
- **Resource limits** — memory, CPU, and PID constraints
- **Streaming output** — real-time stdout/stderr capture

## Requirements

- **Linux kernel 5.10+** (5.13+ for Landlock support)
- Root is **optional** — unprivileged mode uses user namespaces + seccomp + Landlock + setrlimit

## Quick Start

### Library

```toml
[dependencies]
sandbox-rs = "0.1"
```

```rust
use sandbox_rs::{SandboxBuilder, SeccompProfile, PrivilegeMode};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut sandbox = SandboxBuilder::new("my-sandbox")
        .privilege_mode(PrivilegeMode::Unprivileged)
        .memory_limit_str("256M")?
        .cpu_limit_percent(50)
        .timeout(Duration::from_secs(30))
        .seccomp_profile(SeccompProfile::IoHeavy)
        .build()?;

    let result = sandbox.run("/bin/echo", &["hello world"])?;
    println!("exit={} mem={}B cpu={}μs", result.exit_code, result.memory_peak, result.cpu_time_us);
    Ok(())
}
```

> **Note:** `memory_peak` and `cpu_time_us` require privileged mode (cgroups v2). In unprivileged mode these values are `0`.

### CLI

```bash
# Run a program in a sandbox (auto-detects privilege mode)
sandbox-ctl /bin/echo "hello world"

# Use a security profile with resource limits
sandbox-ctl --profile moderate --memory 512M --cpu 50 python script.py

# Check system capabilities
sandbox-ctl check

# List seccomp profiles
sandbox-ctl seccomp
```

## Seccomp Profiles

Each profile includes all syscalls from profiles below it (cumulative).

| Profile | Syscalls |
|---------|----------|
| `Essential` | Process bootstrap only (~40): `execve`, `mmap`, `brk`, `read`, `write`, `exit`, ... |
| `Minimal` | Essential + signals, pipes, timers, process control (~110 total) |
| `IoHeavy` | Minimal + file manipulation: `mkdir`, `chmod`, `unlink`, `rename`, `fsync`, ... |
| `Compute` | IoHeavy + scheduling/NUMA: `sched_setscheduler`, `mbind`, `membarrier`, ... |
| `Network` | Compute + sockets: `socket`, `bind`, `listen`, `connect`, `sendto`, ... |
| `Unrestricted` | Network + privileged: `ptrace`, `mount`, `bpf`, `setuid`, ... |

## Security

- Defense-in-depth: multiple isolation layers (namespaces, seccomp, Landlock, cgroups)
- Combine with AppArmor or SELinux for production use
- Kernel vulnerabilities can bypass sandbox boundaries — keep your kernel updated
- Not a replacement for VM-level isolation for fully untrusted code

## License

MIT — see [LICENSE](LICENSE) for details.
