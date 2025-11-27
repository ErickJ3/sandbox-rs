use env_logger::{Builder, Env};
use log::LevelFilter;
use std::io::Write;

/// Initialize logger based on verbose flag
pub fn init_logger(verbose: bool) {
    let env = Env::default().filter_or("RUST_LOG", if verbose { "debug" } else { "info" });

    Builder::from_env(env)
        .format(|buf, record| writeln!(buf, "{:5} {}", record.level(), record.args()))
        .filter_level(if verbose {
            LevelFilter::Debug
        } else {
            LevelFilter::Info
        })
        .init();
}
