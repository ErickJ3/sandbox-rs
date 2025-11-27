use log::{debug, info};
use sandbox_rs::{SandboxBuilder, SeccompProfile};
use std::path::PathBuf;
use std::time::Duration;

use crate::profiles::SecurityProfile;

pub fn run_sandbox(
    id: Option<String>,
    program: &str,
    args: &[String],
    profile: Option<SecurityProfile>,
    memory: Option<String>,
    cpu: Option<u32>,
    timeout: Option<u64>,
    seccomp: Option<String>,
    root: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let sandbox_id = id.unwrap_or_else(|| format!("sandbox-{}", std::process::id()));

    let mut builder = SandboxBuilder::new(&sandbox_id);

    let selected_profile = profile.unwrap_or(SecurityProfile::Strict);
    builder = selected_profile.apply(builder);

    debug!("Using profile: {:?}", selected_profile);
    debug!("{}", selected_profile.details());

    if let Some(m) = memory {
        debug!("Overriding memory limit: {}", m);
        builder = builder.memory_limit_str(&m)?;
    }

    if let Some(c) = cpu {
        debug!("Overriding CPU limit: {}%", c);
        builder = builder.cpu_limit_percent(c);
    }

    if let Some(t) = timeout {
        debug!("Overriding timeout: {}s", t);
        builder = builder.timeout(Duration::from_secs(t));
    }

    if let Some(s) = seccomp {
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

    if let Some(r) = root {
        debug!("Using custom root: {:?}", r);
        builder = builder.root(&r);
    }

    info!("Building sandbox '{}'", sandbox_id);

    let mut sandbox = builder.build()?;

    info!("Executing: {} {:?}", program, args);

    let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = sandbox.run(program, &args_refs)?;

    info!("Execution completed in {}ms", result.wall_time_ms);

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
