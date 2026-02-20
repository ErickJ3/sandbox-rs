//! sandbox-landlock: Unprivileged filesystem sandboxing via Landlock LSM (Linux 5.13+)
//!
//! Landlock provides filesystem access control without root.
//! It is the unprivileged replacement for chroot.

mod ruleset;

pub use ruleset::LandlockConfig;
