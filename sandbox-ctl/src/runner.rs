use console::style;
use log::{debug, info};
use sandbox_rs::{SandboxBuilder, SeccompProfile};
use std::path::PathBuf;
use std::time::Duration;

use crate::profiles::SecurityProfile;

/// Configuration for sandbox execution
pub struct RunConfig {
    pub id: Option<String>,
    pub program: String,
    pub args: Vec<String>,
    pub profile: Option<SecurityProfile>,
    pub memory: Option<String>,
    pub cpu: Option<u32>,
    pub timeout: Option<u64>,
    pub seccomp: Option<String>,
    pub root: Option<PathBuf>,
}

pub fn run_sandbox(config: RunConfig) -> Result<(), Box<dyn std::error::Error>> {
    let sandbox_id = config
        .id
        .unwrap_or_else(|| format!("sandbox-{}", std::process::id()));

    let mut builder = SandboxBuilder::new(&sandbox_id);

    let selected_profile = config.profile.unwrap_or(SecurityProfile::Strict);
    builder = selected_profile.apply(builder);

    debug!("Using profile: {:?}", selected_profile);
    debug!("{}", selected_profile.details());

    if let Some(m) = config.memory {
        debug!("Overriding memory limit: {}", m);
        builder = builder.memory_limit_str(&m)?;
    }

    if let Some(c) = config.cpu {
        debug!("Overriding CPU limit: {}%", c);
        builder = builder.cpu_limit_percent(c);
    }

    if let Some(t) = config.timeout {
        debug!("Overriding timeout: {}s", t);
        builder = builder.timeout(Duration::from_secs(t));
    }

    if let Some(s) = config.seccomp {
        debug!("Overriding seccomp profile: {}", s);
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

    if let Some(r) = config.root {
        debug!("Using custom root: {:?}", r);
        builder = builder.root(&r);
    }

    info!("Building sandbox '{}'", sandbox_id);

    let mut sandbox = builder.build()?;

    info!("Executing: {} {:?}", config.program, config.args);

    let args_refs: Vec<&str> = config.args.iter().map(|s| s.as_str()).collect();
    let result = sandbox.run(&config.program, &args_refs)?;

    info!("Execution completed in {}ms", result.wall_time_ms);

    let exit_code_styled = if result.exit_code == 0 {
        style(result.exit_code).green().bold()
    } else {
        style(result.exit_code).red().bold()
    };

    print!(
        "{}={} | {}={} | {}={} | {}={}",
        style("exit_code").dim(),
        exit_code_styled,
        style("wall_time_ms").dim(),
        style(result.wall_time_ms).bold(),
        style("memory_peak_bytes").dim(),
        style(result.memory_peak).bold(),
        style("cpu_time_us").dim(),
        style(result.cpu_time_us).bold(),
    );

    if result.timed_out {
        print!(
            " | {}={}",
            style("timed_out").red(),
            style("true").red().bold()
        );
    }

    println!();

    std::process::exit(result.exit_code);
}
