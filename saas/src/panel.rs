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
    tracing::debug!(
        handshake_secs = policy.handshake.as_secs(),
        idle_secs = policy.idle.as_secs(),
        "data plane policy configured"
    );
    let ibm = Arc::new(InboundManager::new(dispatcher, policy));

    let mut controllers = Vec::new();
    for node in &config.nodes {
        if node.panel_type != "SSpanel" {
            tracing::warn!(panel = %node.panel_type, "unsupported panel type, skipping node");
            continue;
        }
        warn_unsupported_config(node);
        let api_cfg = node.api_config()?;
        tracing::debug!(
            api_host = %node.api.api_host,
            node_id = node.api.node_id,
            node_type = %api_cfg.node_type.as_str(),
            listen_ip = %node.controller.listen_ip,
            update_periodic = node.controller.update_periodic,
            "starting SSpanel controller"
        );
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

/// Emit one-time startup warnings for configured-but-unsupported features, so an
/// operator migrating an XrayR `config.yml` is not surprised by silently-ignored
/// keys. These keys are parsed for config compatibility but never acted on.
fn warn_unsupported_config(node: &crate::config::NodeConfig) {
    let api = &node.api;
    let ctl = &node.controller;

    if api.speed_limit > 0.0 {
        tracing::warn!(
            node_id = api.node_id,
            speed_limit = api.speed_limit,
            "SpeedLimit is set but speed limiting is not implemented; the limit is ignored"
        );
    }
    if api.device_limit > 0 {
        tracing::warn!(
            node_id = api.node_id,
            device_limit = api.device_limit,
            "DeviceLimit is set but device / online-IP limiting is not implemented; \
             online-user reporting is also inactive, so the limit is ignored"
        );
    }
    if !api.vless_flow.is_empty() {
        tracing::warn!(
            node_id = api.node_id,
            vless_flow = %api.vless_flow,
            "VlessFlow (XTLS/Vision) is not supported; only flow=none works, and a node will \
             fail to build if the panel reports a flow"
        );
    }
    if !api.rule_list_path.is_empty() {
        tracing::warn!(
            node_id = api.node_id,
            rule_list_path = %api.rule_list_path,
            "RuleListPath is set but local audit-rule lists are not used (no rule manager)"
        );
    }
    if !ctl.disable_get_rule {
        tracing::warn!(
            node_id = api.node_id,
            "audit-rule matching is not active (no rule manager + sniffer): the panel's audit \
             rules are neither fetched nor enforced, and violations are not reported. Set \
             DisableGetRule=true to silence this"
        );
    }
    if ctl.dns_type != "AsIs" {
        tracing::warn!(
            node_id = api.node_id,
            dns_type = %ctl.dns_type,
            "DNSType is set but custom DNS is not implemented; resolution always uses the system \
             resolver"
        );
    }
    let mode = ctl.cert.cert_mode.as_str();
    if mode != "none" && mode != "file" {
        tracing::warn!(
            node_id = api.node_id,
            cert_mode = %mode,
            "CertMode requests ACME / auto-issued certificates, which are not supported; only \
             file-provided certs (CertFile + KeyFile) work, and there is no auto-renewal"
        );
    }

    // Any XrayR key under ControllerConfig that this core doesn't model lands in
    // `unknown` (captured via #[serde(flatten)]); surface each one instead of
    // dropping it silently. Catches fallback / custom DNS / REALITY / routing and
    // also plain typos.
    for key in ctl.unknown.keys() {
        tracing::warn!(
            node_id = api.node_id,
            key = ?key,
            "unrecognized ControllerConfig key is ignored (unsupported XrayR feature or a typo)"
        );
    }
}
