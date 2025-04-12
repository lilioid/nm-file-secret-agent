//! NetworkManager secret agent that responds with the content of preconfigured files
use std::path::PathBuf;

use anyhow::Context;
use clap::{ArgAction, Parser};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::prelude::*;

mod dbus_server;
#[allow(unused, clippy::all)]
mod generated;
mod mapping;

/// Small NetworkManager secret agent that responds with the content of preconfigured files
#[derive(Parser, Debug, Eq, PartialEq, Hash)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Path to a config file
    #[arg(short = 'c', long = "conf")]
    config: PathBuf,

    /// Increase program verbosity
    ///
    /// The default verbosity level is INFO.
    #[arg(short = 'v', long = "verbose", action = ArgAction::Count, default_value = "0")]
    pub verbose: u8,

    /// Decrease program verbosity
    ///
    /// The default verbosity level is INFO.
    #[arg(short = 'q', long = "quiet", action = ArgAction::Count, default_value = "0")]
    pub quiet: u8,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_logger(&cli);
    let config = mapping::MappingConfig::from_file(&cli.config)?;
    config.validate().context("Config validation failed")?;
    dbus_server::run(config)
}

fn init_logger(args: &Cli) {
    // determine combined log level from cli arguments
    const DEFAULT_LEVEL: u8 = 3;
    let log_level = match DEFAULT_LEVEL
        .saturating_add(args.verbose)
        .saturating_sub(args.quiet)
    {
        0 => LevelFilter::OFF,
        1 => LevelFilter::ERROR,
        2 => LevelFilter::WARN,
        3 => LevelFilter::INFO,
        4 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    };

    // configure appropriate level filter
    // tokio is very spammy on higher log levels which is usually not interesting so we filter it out
    let filter = tracing_subscriber::filter::Targets::new().with_default(log_level);
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().without_time())
        .with(filter)
        .init();
}
