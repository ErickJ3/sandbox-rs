use console::style;
use log::info;

use crate::profiles::SecurityProfile;

pub fn list_security_profiles() {
    info!("Listing available security profiles");
    println!("{}\n", style("Available security profiles:").cyan().bold());

    for profile in SecurityProfile::all() {
        let name = format!("{:?}", profile).to_lowercase();
        println!(
            "  {:12} - {}",
            style(name).green().bold(),
            profile.description()
        );
        println!("               {}", style(profile.details()).dim());
        println!();
    }

    println!(
        "Use {} to select a profile",
        style("--profile <PROFILE>").cyan()
    );
    println!("Individual settings can be overridden with specific flags");
}

pub fn list_seccomp_profiles() {
    info!("Listing available seccomp profiles");
    println!("{}\n", style("Available seccomp profiles:").cyan().bold());

    let profiles: &[(&str, &str, Option<&str>)] = &[
        ("minimal", "Minimal syscalls only", Some("(most secure)")),
        ("io-heavy", "With file I/O operations", None),
        ("compute", "With memory operations", None),
        ("network", "With socket operations", None),
        (
            "unrestricted",
            "Allow most syscalls",
            Some("(least secure)"),
        ),
    ];

    for &(name, desc, annotation) in profiles {
        let styled_name = if name == "unrestricted" {
            format!("{}", style(format!("{:<16}", name)).yellow().bold())
        } else {
            format!("{}", style(format!("{:<16}", name)).green().bold())
        };

        let suffix = match annotation {
            Some("(most secure)") => format!(" {}", style("(most secure)").green()),
            Some("(least secure)") => format!(" {}", style("(least secure)").yellow()),
            Some(other) => format!(" {other}"),
            None => String::new(),
        };

        println!("  {styled_name} - {desc}{suffix}");
    }

    println!();
    println!(
        "Use {} to override the profile's default seccomp setting",
        style("--seccomp <PROFILE>").cyan()
    );
}

pub fn check_requirements() {
    use sandbox_rs::PrivilegeMode;
    use sandbox_rs::SystemCapabilities;

    info!("Checking sandbox capabilities");
    let caps = SystemCapabilities::detect();

    println!("{}\n", style("Sandbox capabilities:").cyan().bold());

    // Colorize [ok] / [--] in summary lines
    for line in caps.summary().lines() {
        if line.starts_with("[ok]") {
            let rest = &line[4..];
            println!("{}{}", style("[ok]").green().bold(), rest);
        } else if line.starts_with("[--]") {
            let rest = &line[4..];
            println!("{}{}", style("[--]").red().bold(), rest);
        } else {
            println!("{line}");
        }
    }
    println!();

    // Show resolved mode
    let mode = PrivilegeMode::Auto.resolve(&caps);
    println!(
        "{} {}",
        style("Resolved mode:").bold(),
        style(format!("{:?}", mode)).cyan().bold()
    );

    if mode.is_privileged() {
        println!(
            "  {}",
            style("All isolation features available (namespaces + cgroups + chroot + seccomp)")
                .green()
        );
    } else {
        println!(
            "  {}",
            style("Using unprivileged sandbox (user namespaces + seccomp + landlock + rlimits)")
                .yellow()
        );
    }

    // Show what's active vs missing
    println!("\n{}", style("Security layers:").cyan().bold());

    if caps.has_seccomp {
        println!(
            "  {}  Seccomp BPF - syscall filtering",
            style("[active]").green().bold()
        );
    } else {
        println!(
            "  {} Seccomp BPF - kernel too old or disabled",
            style("[missing]").red().bold()
        );
    }

    if caps.has_user_namespaces {
        println!(
            "  {}  User namespaces - unprivileged isolation",
            style("[active]").green().bold()
        );
    } else {
        println!(
            "  {} User namespaces - check kernel.unprivileged_userns_clone",
            style("[missing]").red().bold()
        );
    }

    if caps.has_landlock {
        println!(
            "  {}  Landlock LSM - filesystem restrictions (no root needed)",
            style("[active]").green().bold()
        );
    } else {
        println!(
            "  {} Landlock LSM - requires Linux 5.13+",
            style("[missing]").red().bold()
        );
    }

    if caps.has_root && caps.has_cgroup_v2 {
        println!(
            "  {}  Cgroups v2 - precise resource limits",
            style("[active]").green().bold()
        );
    } else if !caps.has_root {
        println!(
            "  {} Resource limits via setrlimit (no cgroups without root)",
            style("[fallback]").yellow().bold()
        );
    } else {
        println!(
            "  {} Cgroups v2 - mount unified hierarchy",
            style("[missing]").red().bold()
        );
    }

    println!("\n{}", style("System info:").cyan().bold());
    println!("  UID: {}", style(sandbox_rs::utils::get_uid()).bold());
    println!("  GID: {}", style(sandbox_rs::utils::get_gid()).bold());
}
