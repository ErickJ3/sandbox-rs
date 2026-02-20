//! Execution layer: Process management and initialization
//!
//! This module handles process execution within sandboxes,
//! including namespace cloning, initialization, and lifecycle management.

pub mod init;
pub mod process;
pub mod stream;

pub use init::SandboxInit;
pub use process::{ProcessConfig, ProcessExecutor, ProcessResult};
pub use stream::{ProcessStream, StreamChunk};
