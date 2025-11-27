use clap::ValueEnum;
use sandbox_rs::{SandboxBuilder, SeccompProfile};
use std::time::Duration;

struct SecurityConfig {
    memory: u64,
    cpu: u32,
    timeout: Duration,
    seccomp: SeccompProfile,
}

const STRICT: SecurityConfig = SecurityConfig {
    memory: 128 * 1024 * 1024,
    cpu: 50,
    timeout: Duration::from_secs(30),
    seccomp: SeccompProfile::Minimal,
};

const MODERATE: SecurityConfig = SecurityConfig {
    memory: 512 * 1024 * 1024,
    cpu: 75,
    timeout: Duration::from_secs(300),
    seccomp: SeccompProfile::IoHeavy,
};

const PERMISSIVE: SecurityConfig = SecurityConfig {
    memory: 2 * 1024 * 1024 * 1024,
    cpu: 90,
    timeout: Duration::from_secs(3600),
    seccomp: SeccompProfile::Unrestricted,
};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum SecurityProfile {
    /// Maximum security: strict limits and minimal syscalls
    Strict,
    /// Balanced security: reasonable limits and common syscalls
    Moderate,
    /// Minimal restrictions: good for development
    Permissive,
}

impl SecurityProfile {
    fn config(&self) -> &'static SecurityConfig {
        match self {
            SecurityProfile::Strict => &STRICT,
            SecurityProfile::Moderate => &MODERATE,
            SecurityProfile::Permissive => &PERMISSIVE,
        }
    }

    pub fn apply(&self, builder: SandboxBuilder) -> SandboxBuilder {
        let cfg = self.config();
        builder
            .memory_limit(cfg.memory)
            .cpu_limit_percent(cfg.cpu)
            .timeout(cfg.timeout)
            .seccomp_profile(cfg.seccomp.clone())
    }

    pub fn description(&self) -> &str {
        match self {
            SecurityProfile::Strict => "Maximum security with strict resource limits",
            SecurityProfile::Moderate => "Balanced security for general applications",
            SecurityProfile::Permissive => "Minimal restrictions for development work",
        }
    }

    pub fn details(&self) -> String {
        match self {
            SecurityProfile::Strict => {
                "Memory: 128MB | CPU: 50% | Timeout: 30s | Seccomp: Minimal".to_string()
            }
            SecurityProfile::Moderate => {
                "Memory: 512MB | CPU: 75% | Timeout: 5m | Seccomp: IO-Heavy".to_string()
            }
            SecurityProfile::Permissive => {
                "Memory: 2GB | CPU: 90% | Timeout: 1h | Seccomp: Unrestricted".to_string()
            }
        }
    }

    pub fn all() -> [SecurityProfile; 3] {
        [
            SecurityProfile::Strict,
            SecurityProfile::Moderate,
            SecurityProfile::Permissive,
        ]
    }
}
