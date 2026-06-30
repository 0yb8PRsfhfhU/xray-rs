//! `xray-saas` — XrayR-compatible SaaS server entry point.

use anyhow::{Context, Result};
use clap::Parser;
use saas::config::Config;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "xray-saas",
    version,
    about = "XrayR-compatible SaaS server entry point"
)]
struct Cli {
    /// Path to the config file.
    #[arg(short, long, value_name = "PATH")]
    config: Option<String>,

    /// Backward-compatible positional config path.
    #[arg(value_name = "CONFIG")]
    positional_config: Option<String>,

    /// Validate the config file and exit without starting the server.
    #[arg(long)]
    check: bool,

    /// Override log level, e.g. trace, debug, info, warn, or error.
    #[arg(long, value_name = "LEVEL")]
    log_level: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let path = cli
        .config
        .or(cli.positional_config)
        .unwrap_or_else(|| "config.toml".to_string());

    let text = std::fs::read_to_string(&path).with_context(|| format!("reading config {path}"))?;
    let config = Config::parse(&text)?;

    if cli.check {
        println!("config ok: {path}");
        return Ok(());
    }

    let level = cli.log_level.unwrap_or_else(|| {
        if config.log.level.is_empty() || config.log.level == "none" {
            "info".to_string()
        } else {
            config.log.level.clone()
        }
    });
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&level));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let shutdown = CancellationToken::new();
    let sig = shutdown.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            tracing::info!("shutdown signal received");
            sig.cancel();
        }
    });

    saas::panel::run(config, shutdown).await
}
