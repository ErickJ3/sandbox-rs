//! sandbox-seccomp: Seccomp BPF syscall filtering (no root required)
//!
//! This crate provides seccomp-based syscall filtering using BPF programs.
//! Seccomp does NOT require root - it only needs `PR_SET_NO_NEW_PRIVS`.

pub mod bpf;
pub mod profile;
pub mod syscall_table;

pub use bpf::SeccompBpf;
pub use profile::{SeccompFilter, SeccompProfile};
