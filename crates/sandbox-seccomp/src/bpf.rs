//! Seccomp BPF filter compilation and loading using seccompiler

use crate::profile::{SeccompFilter, SeccompProfile};
use crate::syscall_table::get_syscall_number_from_name;
use sandbox_core::{Result, SandboxError};
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter as SeccompilerFilter, apply_filter};
use std::collections::BTreeMap;
use std::convert::TryInto;

/// Seccomp BPF filter compiler and loader
pub struct SeccompBpf;

impl SeccompBpf {
    /// Compile a filter to BPF bytecode
    pub fn compile(filter: &SeccompFilter) -> Result<Vec<u8>> {
        let bpf_program = Self::compile_to_bpf(filter)?;
        let bpf_bytes: Vec<u8> = unsafe {
            let ptr = bpf_program.as_ptr() as *const u8;
            let len = bpf_program.len() * std::mem::size_of::<seccompiler::sock_filter>();
            std::slice::from_raw_parts(ptr, len).to_vec()
        };
        Ok(bpf_bytes)
    }

    /// Compile filter to BpfProgram with validation
    fn compile_to_bpf(filter: &SeccompFilter) -> Result<BpfProgram> {
        filter.validate()?;

        let allowed = filter.allowed_syscalls();
        let blocked = filter.blocked_syscalls();
        let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
        let is_unrestricted = filter.profile() == SeccompProfile::Unrestricted;

        if is_unrestricted {
            for syscall_name in blocked.iter() {
                match get_syscall_number_from_name(syscall_name) {
                    Some(num) => {
                        rules.entry(num).or_default();
                    }
                    None => {
                        return Err(SandboxError::Seccomp(format!(
                            "Unknown syscall to block: '{}'. This syscall is not supported on this architecture.",
                            syscall_name
                        )));
                    }
                }
            }
        } else {
            for syscall_name in allowed.iter() {
                if blocked.contains(syscall_name) {
                    continue;
                }

                match get_syscall_number_from_name(syscall_name) {
                    Some(num) => {
                        rules.entry(num).or_default();
                    }
                    None => {
                        return Err(SandboxError::Seccomp(format!(
                            "Unknown syscall to allow: '{}'. This syscall is not supported on this architecture.",
                            syscall_name
                        )));
                    }
                }
            }
        }

        // Configure actions based on mode
        let (mismatch_action, match_action) = if is_unrestricted {
            (SeccompAction::Allow, SeccompAction::Trap)
        } else {
            let deny_action = if filter.is_kill_on_violation() {
                SeccompAction::KillProcess
            } else {
                SeccompAction::Trap
            };
            (deny_action, SeccompAction::Allow)
        };

        let seccompiler_filter = SeccompilerFilter::new(
            rules,
            mismatch_action,
            match_action,
            seccompiler::TargetArch::x86_64,
        )
        .map_err(|e| SandboxError::Seccomp(format!("Failed to create filter: {}", e)))?;

        let bpf_program: BpfProgram = seccompiler_filter
            .try_into()
            .map_err(|e| SandboxError::Seccomp(format!("Failed to compile filter: {}", e)))?;

        Ok(bpf_program)
    }

    /// Load BPF filter via seccompiler's apply_filter.
    /// NOTE: This does NOT require root - only PR_SET_NO_NEW_PRIVS is needed.
    pub fn load(filter: &SeccompFilter) -> Result<()> {
        filter.validate()?;
        unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(SandboxError::Seccomp(format!(
                    "Failed to set PR_SET_NO_NEW_PRIVS: {}",
                    std::io::Error::last_os_error()
                )));
            }
        }

        let bpf_program = Self::compile_to_bpf(filter)?;

        apply_filter(&bpf_program)
            .map_err(|e| SandboxError::Seccomp(format!("Failed to apply seccomp filter: {}", e)))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_minimal_filter() {
        let filter = SeccompFilter::minimal();
        let result = SeccompBpf::compile(&filter);
        assert!(result.is_ok());
        let bpf_code = result.unwrap();
        assert!(!bpf_code.is_empty());
    }

    #[test]
    fn test_compile_io_heavy_filter() {
        let filter = SeccompFilter::from_profile(SeccompProfile::IoHeavy);
        let result = SeccompBpf::compile(&filter);
        assert!(result.is_ok());
    }

    #[test]
    fn test_compile_network_filter() {
        let filter = SeccompFilter::from_profile(SeccompProfile::Network);
        let result = SeccompBpf::compile(&filter);
        assert!(result.is_ok());
    }

    #[test]
    fn test_compile_compute_filter() {
        let filter = SeccompFilter::from_profile(SeccompProfile::Compute);
        let result = SeccompBpf::compile(&filter);
        assert!(result.is_ok());
    }

    #[test]
    fn test_compile_unrestricted_profile() {
        let filter = SeccompFilter::from_profile(SeccompProfile::Unrestricted);
        let result = SeccompBpf::compile(&filter);
        assert!(result.is_ok());
    }

    #[test]
    fn test_all_allowed_syscalls_have_numbers() {
        for profile in SeccompProfile::all() {
            let filter = SeccompFilter::from_profile(profile);
            for syscall in filter.allowed_syscalls() {
                assert!(
                    get_syscall_number_from_name(syscall).is_some(),
                    "missing number for syscall '{}'",
                    syscall
                );
            }
        }
    }

    #[test]
    fn test_load_rejects_unknown_syscalls() {
        let mut filter = SeccompFilter::minimal();
        filter.allow_syscall("syscall_que_nao_existe_xyz_123");
        let result = SeccompBpf::compile(&filter);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Unknown syscall"));
    }
}
