//! Seccomp profiles example

use sandbox_rs::SeccompProfile;

fn main() {
    println!("=== Sandbox RS - Seccomp Profiles ===\n");

    println!("Available seccomp profiles:\n");

    for profile in SeccompProfile::all() {
        println!("Profile: {:?}", profile);
        println!("  Description: {}", profile.description());

        // Note: Actual syscall filtering would require kernel-level seccomp
        // For now, we just demonstrate the API
        println!("  Note: Syscall filtering requires root and proper seccomp setup\n");
    }

    println!("\nProfile Usage Example:");
    println!("  let sandbox = SandboxBuilder::new(\"my-box\")");
    println!("    .seccomp_profile(SeccompProfile::IoHeavy)");
    println!("    .build()?;");
}
