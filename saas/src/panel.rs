//! Panel orchestration — the xray-rs analogue of XrayR's `panel.Panel`: build
//! the shared data plane (dispatcher + freedom outbound + per-user stats), then
//! start one [`Controller`] per SSPanel node and drive their polling loops.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use compact_str::CompactString;
use kernel::{CachedResolver, Dispatcher, Outbound, Policy, Stats, SystemDialer};
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::controller::Controller;
use crate::inbound_manager::InboundManager;
use crate::sspanel::SspanelClient;

/// Build the data plane and run every configured SSPanel node until `shutdown`.
pub async fn run(config: Config, shutdown: CancellationToken) -> Result<()> {
    // Shared per-user traffic stats, read by controllers and written by the
    // data plane via the dispatcher.
    let stats = Arc::new(Stats::new());

    let resolver = Arc::new(CachedResolver::system().context("DNS resolver")?);
    let dialer = SystemDialer::new(resolver);
    let mut outbounds: HashMap<CompactString, Outbound> = HashMap::new();
    outbounds.insert(CompactString::new("freedom"), Outbound::Freedom);
    let dispatcher =
        Arc::new(Dispatcher::new(dialer, outbounds, "freedom", None).with_stats(stats.clone()));

    let policy = Policy {
        handshake: Duration::from_secs(u64::from(config.connection.handshake.max(1))),
        idle: Duration::from_secs(u64::from(config.connection.conn_idle.max(1))),
    };
    let ibm = Arc::new(InboundManager::new(dispatcher, policy));

    let mut controllers = Vec::new();
    for node in &config.nodes {
        if node.panel_type != "SSpanel" {
            tracing::warn!(panel = %node.panel_type, "unsupported panel type, skipping node");
            continue;
        }
        let api_cfg = node.api_config()?;
        let client = SspanelClient::new(&api_cfg);
        let mut controller =
            Controller::new(client, node.controller.clone(), ibm.clone(), stats.clone());
        controller
            .start()
            .await
            .with_context(|| format!("starting node {}", node.api.node_id))?;
        controllers.push(controller);
    }

    if controllers.is_empty() {
        bail!("no SSpanel nodes configured");
    }
    tracing::info!(nodes = controllers.len(), "panel started");

    let mut handles = Vec::new();
    for controller in controllers {
        handles.push(tokio::spawn(controller.run(shutdown.clone())));
    }
    for h in handles {
        let _ = h.await;
    }
    Ok(())
}
