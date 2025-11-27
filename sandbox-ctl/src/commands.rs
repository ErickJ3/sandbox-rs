use log::info;

use crate::profiles::SecurityProfile;

pub fn list_security_profiles() {
    info!("Listing available security profiles");
    println!("Available security profiles:\n");

    for profile in SecurityProfile::all() {
        println!(
            "  {:12} - {}",
            format!("{:?}", profile).to_lowercase(),
            profile.description()
        );
        println!("               {}", profile.details());
        println!();
    }

    println!("Use --profile <PROFILE> to select a profile");
    println!("Individual settings can be overridden with specific flags");
}

pub fn list_seccomp_profiles() {
    info!("Listing available seccomp profiles");
    println!("Available seccomp profiles:\n");
    println!("  minimal        - Minimal syscalls only (most secure)");
    println!("  io-heavy       - With file I/O operations");
    println!("  compute        - With memory operations");
    println!("  network        - With socket operations");
    println!("  unrestricted   - Allow most syscalls (least secure)");
    println!();
    println!("Use --seccomp <PROFILE> to override the profile's default seccomp setting");
}

pub fn check_requirements() {
    use sandbox_rs::utils;

    info!("Checking sandbox requirements");
    println!("Checking sandbox requirements...\n");

    if utils::is_root() {
        println!("[✓] Running as root");
    } else {
        println!("[✗] NOT running as root (required)");
    }

    if utils::has_cgroup_v2() {
        println!("[✓] Cgroup v2 available");
    } else {
        println!("[✗] Cgroup v2 NOT available");
    }

    println!("\nSystem info:");
    println!("  UID: {}", utils::get_uid());
    println!("  GID: {}", utils::get_gid());
}
