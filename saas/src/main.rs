//! `xray-saas` — XrayR-compatible SaaS server entry point.

use anyhow::{Context, Result};
use saas::config::Config;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string());
    let text = std::fs::read_to_string(&path).with_context(|| format!("reading config {path}"))?;
    let config = Config::parse(&text)?;

    let level = if config.log.level.is_empty() || config.log.level == "none" {
        "info".to_string()
    } else {
        config.log.level.clone()
    };
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
