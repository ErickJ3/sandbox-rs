//! Sandbox controller CLI - Run applications in secure isolated environments

mod cli;
mod commands;
mod logging;
mod profiles;
mod runner;

use clap::Parser;
use cli::{Cli, Commands};
use commands::{check_requirements, list_seccomp_profiles, list_security_profiles};
use console::style;
use runner::{RunConfig, run_sandbox};

fn main() {
    let cli = Cli::parse();

    logging::init_logger(cli.verbose);

    if cli.check {
        check_requirements();
        return;
    }

    if cli.list_profiles {
        list_security_profiles();
        return;
    }

    if cli.list_seccomp {
        list_seccomp_profiles();
        return;
    }

    if let Some(command) = cli.command {
        match command {
            Commands::Run { program, args } => {
                let config = RunConfig {
                    id: cli.id,
                    program,
                    args,
                    profile: cli.profile,
                    memory: cli.memory,
                    cpu: cli.cpu,
                    timeout: cli.timeout,
                    seccomp: cli.seccomp,
                    root: cli.root,
                };
                if let Err(e) = run_sandbox(config) {
                    eprintln!("{} {}", style("error:").red().bold(), e);
                    std::process::exit(1);
                }
            }
            Commands::Profiles => list_security_profiles(),
            Commands::Check => check_requirements(),
            Commands::Seccomp => list_seccomp_profiles(),
        }
        return;
    }

    let Some(program) = cli.program else {
        eprintln!("{} No program specified", style("error:").red().bold());
        eprintln!(
            "Try {} for more information",
            style("sandbox-ctl --help").cyan()
        );
        std::process::exit(1);
    };

    let config = RunConfig {
        id: cli.id,
        program,
        args: cli.args,
        profile: cli.profile,
        memory: cli.memory,
        cpu: cli.cpu,
        timeout: cli.timeout,
        seccomp: cli.seccomp,
        root: cli.root,
    };
    if let Err(e) = run_sandbox(config) {
        eprintln!("{} {}", style("error:").red().bold(), e);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_profiles_runs() {
        list_security_profiles();
    }

    #[test]
    fn list_seccomp_runs() {
        list_seccomp_profiles();
    }

    #[test]
    fn check_requirements_runs() {
        check_requirements();
    }
}
