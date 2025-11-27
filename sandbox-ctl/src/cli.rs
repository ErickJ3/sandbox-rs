use clap::{Parser, Subcommand};
use std::path::PathBuf;

use crate::profiles::SecurityProfile;

#[derive(Parser)]
#[command(name = "sandbox-ctl")]
#[command(version, about = "Run applications in secure isolated environments", long_about = None)]
#[command(after_help = "EXAMPLES:
    # Direct execution with default security (strict)
    sandbox-ctl firefox
    sandbox-ctl --profile moderate bash
    sandbox-ctl --memory 512M --cpu 50 python script.py

    # Using subcommands
    sandbox-ctl run --id test --memory 100M /bin/ls
    sandbox-ctl profiles
    sandbox-ctl check

    # List available profiles
    sandbox-ctl --list-profiles
    sandbox-ctl --list-seccomp
")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Program to run in sandbox (direct mode, yep :)
    #[arg(value_name = "PROGRAM", global = true)]
    pub program: Option<String>,

    /// Program arguments
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,

    /// Security profile preset
    #[arg(short = 'P', long, value_name = "PROFILE", global = true)]
    pub profile: Option<SecurityProfile>,

    /// Memory limit (100M, 1G, 2G)
    #[arg(short, long, value_name = "SIZE", global = true)]
    pub memory: Option<String>,

    /// CPU limit percentage (0-100)
    #[arg(short, long, value_name = "PERCENT", global = true)]
    pub cpu: Option<u32>,

    /// Timeout in seconds
    #[arg(short, long, value_name = "SECONDS", global = true)]
    pub timeout: Option<u64>,

    /// Seccomp profile
    #[arg(short = 's', long, value_name = "SECCOMP", global = true)]
    pub seccomp: Option<String>,

    /// Sandbox root directory
    #[arg(short, long, value_name = "PATH", global = true)]
    pub root: Option<PathBuf>,

    /// Sandbox ID (auto-generated if not provided)
    #[arg(short, long, value_name = "ID", global = true)]
    pub id: Option<String>,

    /// Show verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// List available security profiles
    #[arg(long)]
    pub list_profiles: bool,

    /// Check sandbox requirements
    #[arg(long)]
    pub check: bool,

    /// List available seccomp profiles
    #[arg(long)]
    pub list_seccomp: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run a program in sandbox
    Run {
        /// Program to run
        program: String,

        /// Program arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// List available security profiles
    Profiles,

    /// Check sandbox requirements
    Check,

    /// List available seccomp profiles
    Seccomp,
}
