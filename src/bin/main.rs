#!/usr/bin/env rust-script
//! Sandbox controller CLI

use clap::{Parser, Subcommand};
use sandbox_rs::{SandboxBuilder, SeccompProfile};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "sandbox-ctl")]
#[command(about = "Sandbox controller - a comprehensive Rust sandbox implementation", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Run {
        /// Sandbox ID
        #[arg(short, long)]
        id: String,

        /// Program to run
        program: String,

        /// Program arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,

        /// Memory limit (e.g., 100M, 1G)
        #[arg(short, long)]
        memory: Option<String>,

        /// CPU limit percentage (0-100)
        #[arg(short, long)]
        cpu: Option<u32>,

        /// Timeout in seconds
        #[arg(short, long)]
        timeout: Option<u64>,

        /// Seccomp profile (minimal, io-heavy, compute, network, unrestricted)
        #[arg(short = 'p', long)]
        seccomp: Option<String>,

        /// Sandbox root directory
        #[arg(short, long)]
        root: Option<PathBuf>,
    },

    /// List available seccomp profiles
    Profiles,

    /// Check sandbox requirements
    Check,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            id,
            program,
            args,
            memory,
            cpu,
            timeout,
            seccomp,
            root,
        } => {
            if let Err(e) = run_sandbox(&id, &program, &args, memory, cpu, timeout, seccomp, root) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Profiles => list_profiles(),
        Commands::Check => check_requirements(),
    }
}

fn run_sandbox(
    id: &str,
    program: &str,
    args: &[String],
    memory: Option<String>,
    cpu: Option<u32>,
    timeout: Option<u64>,
    seccomp: Option<String>,
    root: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = SandboxBuilder::new(id);

    if let Some(m) = memory {
        builder = builder.memory_limit_str(&m)?;
    }

    if let Some(c) = cpu {
        builder = builder.cpu_limit_percent(c);
    }

    if let Some(t) = timeout {
        builder = builder.timeout(Duration::from_secs(t));
    }

    if let Some(s) = seccomp {
        builder = builder.seccomp_profile(match s.to_lowercase().as_str() {
            "minimal" => SeccompProfile::Minimal,
            "io-heavy" => SeccompProfile::IoHeavy,
            "compute" => SeccompProfile::Compute,
            "network" => SeccompProfile::Network,
            "unrestricted" => SeccompProfile::Unrestricted,
            _ => {
                return Err(format!("Unknown seccomp profile: {}", s).into());
            }
        });
    }

    if let Some(r) = root {
        builder = builder.root(&r);
    }

    let mut sandbox = builder.build()?;

    let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    let result = sandbox.run(program, &args_refs)?;

    println!(
        "exit_code={} | wall_time_ms={} | memory_peak_bytes={} | cpu_time_us={}{}",
        result.exit_code,
        result.wall_time_ms,
        result.memory_peak,
        result.cpu_time_us,
        if result.timed_out {
            " | timed_out=true"
        } else {
            ""
        }
    );

    std::process::exit(result.exit_code);
}

fn list_profiles() {
    println!("Available seccomp profiles:");
    println!("  minimal        - Minimal syscalls only (default)");
    println!("  io-heavy       - With file I/O operations");
    println!("  compute        - With memory operations");
    println!("  network        - With socket operations");
    println!("  unrestricted   - Allow most syscalls");
}

fn check_requirements() {
    use sandbox_rs::utils;

    println!("[*] Checking sandbox requirements...");
    println!();

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

    println!("    UID: {}", utils::get_uid());
    println!("    GID: {}", utils::get_gid());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_profiles_runs() {
        list_profiles();
    }

    #[test]
    fn check_requirements_runs() {
        check_requirements();
    }

    #[test]
    fn run_sandbox_without_root_fails() {
        let args: Vec<String> = Vec::new();
        let result = run_sandbox(
            "test",
            "/bin/echo",
            &args,
            Some("64M".to_string()),
            Some(50),
            Some(1),
            Some("minimal".to_string()),
            None,
        );
        assert!(result.is_err());
    }
}
