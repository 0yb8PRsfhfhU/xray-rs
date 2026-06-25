//! xray-rs server entry point.

mod config;
mod instance;

use anyhow::{Context, Result};
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::instance::Instance;

#[tokio::main]
async fn main() -> Result<()> {
    let path = std::env::args().nth(1).unwrap_or_else(|| "config.toml".to_string());
    let text = std::fs::read_to_string(&path).with_context(|| format!("reading config {path}"))?;
    let config = Config::parse(&text)?;

    let level = config.log.level.clone().unwrap_or_else(|| "info".to_string());
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&level));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let built = config.build()?;
    tracing::info!("xray-rs starting with {} inbound(s)", built.inbounds.len());
    Instance::new(built).run().await
}
