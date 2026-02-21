use console::style;
use env_logger::{Builder, Env};
use log::{Level, LevelFilter};
use std::io::Write;

/// Initialize logger based on verbose flag
pub fn init_logger(verbose: bool) {
    let env = Env::default().filter_or("RUST_LOG", if verbose { "debug" } else { "warn" });

    Builder::from_env(env)
        .format(|buf, record| {
            let level = match record.level() {
                Level::Error => format!("{}", style("ERROR").red().bold()),
                Level::Warn => format!("{}", style("WARN ").yellow().bold()),
                Level::Info => format!("{}", style("INFO ").green()),
                Level::Debug => format!("{}", style("DEBUG").cyan()),
                Level::Trace => format!("{}", style("TRACE").dim()),
            };
            writeln!(buf, "{} {}", level, record.args())
        })
        .filter_level(if verbose {
            LevelFilter::Debug
        } else {
            LevelFilter::Warn
        })
        .init();
}
