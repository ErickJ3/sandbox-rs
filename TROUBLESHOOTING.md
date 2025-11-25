# Troubleshooting Guide - sandbox-rs

This guide helps you diagnose and resolve common issues when using sandbox-rs.

## Permission Denied Errors

### "This operation requires root privileges"

**Cause:** Full sandbox isolation (namespaces, cgroups, seccomp) requires root privileges on Linux.

**Solution:**

```bash
# Option 1: Run with sudo
sudo cargo run --example basic_sandbox

# Option 2: Run CLI with sudo
sudo ./target/debug/sandbox-ctl run --id test /bin/echo "hello"

# Option 3: Add user to sudoers (use with caution)
# Edit with: sudo visudo
# Add line: username ALL=(ALL) NOPASSWD: /path/to/sandbox-ctl
```

**Why:** Linux namespaces and cgroups are privileged kernel features. They require root to prevent unprivileged users from escalating privileges or affecting the entire system.

---

## Cgroup Not Found

### "cgroup directory {x} does not exist"

**Cause:** Cgroup v2 is not mounted on your system, or the cgroup root path is incorrect.

**Solution:**

Check if cgroup v2 is available:
```bash
mount | grep cgroup
# Should show: cgroup2 on /sys/fs/cgroup type cgroup2
```

If not mounted, try:
```bash
sudo mount -t cgroup2 none /sys/fs/cgroup
```

**Verify cgroup v2 support:**
```bash
ls /sys/fs/cgroup/
# Should show files like: cgroup.max.depth, cgroup.max.pids, cpu.max, memory.max
```

If your system uses cgroup v1 only:
- This is older kernel (pre-5.10)
- Upgrade kernel or use container runtime instead
- sandbox-rs targets cgroup v2

---

## Memory Limit Not Enforced

### Process exceeds memory limit without being killed

**Cause (non-root):** Without root privileges, memory limits cannot be enforced at the kernel level.

**Verification:**

```bash
# Check if running as root
sudo cargo run --example basic_sandbox

# Run with memory limit
sudo cargo run --example cgroup_limits
```

**Expected behavior:**
- With root: Process killed when exceeding limit
- Without root: Limit is set but not enforced

---

## Namespace Isolation Not Working

### Processes see same PID or network as host

**Cause:** Running without root means no actual namespace isolation.

**Solution:**

```bash
# Verify you're running as root
whoami  # Should output: root

# Run with full isolation
sudo cargo build
sudo ./target/debug/sandbox-ctl run --id test /bin/echo "in sandbox"
```

**Check namespace support:**
```bash
# Verify Linux has namespace support
ls /proc/self/ns/
# Should show: cgroup ipc mnt net pid uts user

# Verify seccomp is available
grep SECCOMP /boot/config-$(uname -r) || echo "Check kernel config"
```

---

## Seccomp Setup Issues

### "Failed to load seccomp filter"

**Cause:** Seccomp BPF loading requires specific kernel capabilities and proper setup.

**Solution:**

Check seccomp support:
```bash
sudo cat /proc/sys/kernel/unprivileged_userns_clone
# 0 = restricted, 1 = allowed

# Check seccomp is compiled in
grep CONFIG_SECCOMP /boot/config-$(uname -r)
# Should show: CONFIG_SECCOMP=y
```

If seccomp doesn't work:
1. Kernel might not support BPF seccomp
2. SELinux or AppArmor might block it
3. Use permissive seccomp profile:
   ```bash
   ./sandbox-ctl run --id test --seccomp unrestricted /bin/echo "test"
   ```

---

## Process Execution Fails

### "execve failed: No such file or directory"

**Cause:** Program path doesn't exist in the sandbox environment.

**Solution:**

1. Use absolute paths:
   ```bash
   # Wrong:
   sandbox-ctl run --id test echo "hello"

   # Correct:
   sandbox-ctl run --id test /bin/echo "hello"
   ```

2. Verify program exists:
   ```bash
   which echo
   # Output: /usr/bin/echo or /bin/echo
   ```

3. If using chroot or overlay FS, ensure program exists in sandbox root:
   ```bash
   ls /sandbox/root/bin/echo  # Should exist
   ```

---

## Timeout Not Enforced

### Process continues running past timeout

**Cause:** Timeout enforcement requires root privileges and proper process monitoring.

**Solution:**

1. Ensure running as root
2. Verify timeout is reasonable:
   ```bash
   # Wrong: timeout longer than actual operation
   sudo sandbox-ctl run --id test --timeout 60 /bin/echo "test"

   # Correct: timeout shorter than operation
   sudo sandbox-ctl run --id test --timeout 1 /bin/sleep 10
   # Should be killed after 1 second
   ```

---

## Out of Memory (OOM) Behavior

### Process killed with no output

**Cause:** Memory limit exceeded - kernel's OOM killer activated.

**Solution:**

1. Increase memory limit:
   ```bash
   # Before:
   --memory 64M  # Too tight

   # After:
   --memory 256M  # More reasonable
   ```

2. Profile memory usage:
   ```bash
   time -v ./my-program
   # Shows peak memory usage
   ```

3. Check if it's a true leak or just normal memory use:
   ```bash
   # Monitor memory during execution
   watch -n 0.1 'ps aux | grep my-program'
   ```

---

## CPU Limit Seems Ineffective

### Process runs at full speed despite CPU limit

**Cause:** CPU limits throttle the scheduler, but execution still completes. Effect is visible with sustained load.

**Solution:**

CPU limits work differently than you might expect:
- **CPU limit 50%:** Process gets interrupted more often, takes 2x longer on single workload
- **CPU limit 100%:** Can use all resources of one core (system dependent)
- Effect only visible with sustained compute

Test proper limits:
```bash
# Monitor CPU usage
watch -n 1 'ps aux | grep process-name'

# Should see consistent CPU% around the limit
```

---

## Tests Failing with "PermissionDenied"

### Test suite requires root

**Solution:**

Run tests with root privileges:
```bash
# Run all tests with root
sudo cargo test

# Run specific test file
sudo cargo test --test integration_tests

# Run with output
sudo cargo test -- --nocapture
```

**Or configure test environment:**
```bash
# Set test to skip if not root
export SANDBOX_SKIP_ROOT_TESTS=1
cargo test
```

---

## Building Fails with Missing Dependencies

### "cannot find -lnix" or similar

**Cause:** Native library dependencies not installed.

**Solution:**

Install development libraries:
```bash
# Ubuntu/Debian:
sudo apt-get install build-essential libssl-dev pkg-config

# Fedora/RHEL:
sudo dnf install gcc openssl-devel pkg-config

# Arch:
sudo pacman -S base-devel openssl
```

---

## Nix Development Environment

### "nix: command not found"

**Solution:**

Install Nix and use flake.nix:
```bash
# Install Nix (on non-NixOS systems)
curl -L https://nixos.org/nix/install | sh

# Enter development environment
nix flake update
nix develop

# Now building should work
cargo build
```

---

## Common Configuration Issues

### Invalid Memory Format

```bash
# Wrong formats:
--memory 256      # No unit
--memory "256MB"  # Wrong unit (use M not MB)

# Correct formats:
--memory 256M     # 256 megabytes
--memory 1G       # 1 gigabyte
--memory 1024K    # 1024 kilobytes
```

### Invalid CPU Limit

```bash
# CPU limits should be 1-400+ percent:
--cpu 0           # Invalid (ignored)
--cpu 50          # OK: 50% of one core
--cpu 100         # OK: 100% of one core (full core)
--cpu 200         # OK: 200% (can use 2 cores)
```

---

## Performance Issues

### Sandbox creation is slow

**Cause:** Namespace cloning and cgroup setup have overhead.

**Solutions:**
1. Reuse sandbox instances instead of creating new ones
2. Use minimal namespace configuration
3. Disable unused features (e.g., `--seccomp unrestricted`)

### Memory overhead per sandbox

Expected overhead:
- Base process: 1-2 MB
- With namespaces: +2-5 MB
- With cgroups: +1-2 MB
- Total typical: 5-10 MB per inactive sandbox

---

## Debug Mode

### Enable detailed logging

```bash
# Set log level to debug
RUST_LOG=debug cargo run --example basic_sandbox

# With components
RUST_LOG=sandbox_rs=debug cargo run --example basic_sandbox

# Very verbose
RUST_LOG=trace cargo run --example basic_sandbox
```

### Run with strace (for system calls)

```bash
# See all syscalls made by sandbox process
sudo strace -f ./target/debug/sandbox-ctl run --id test /bin/echo "hello"

# Filter to specific syscalls
sudo strace -f -e trace=open,read,write,clone ./target/debug/sandbox-ctl run --id test /bin/echo "hello"
```

---

## Getting Help

If you encounter an issue not listed here:

1. **Check the logs:**
   ```bash
   RUST_LOG=debug cargo run --example basic_sandbox 2>&1 | head -100
   ```

2. **Check system requirements:**
   ```bash
   ./target/debug/sandbox-ctl check
   ```

3. **Verify your kernel:**
   ```bash
   uname -a
   # Should be Linux 5.10+ for full support
   ```

4. **Test with minimal setup:**
   ```bash
   sudo cargo run --example basic_sandbox
   ```

5. **Report issue with:**
   - Full error message
   - Kernel version (`uname -r`)
   - Whether running with root
   - Reproducible test case
