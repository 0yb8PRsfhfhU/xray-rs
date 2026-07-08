//! Per-node controller: fetch node config + users from the panel, build and
//! bind the inbound, sync users into the live handler, and report per-user
//! traffic — the xray-rs analogue of XrayR's `service/controller`, trimmed to
//! what this core supports (no speed limiter, device limiter, or audit rules).
//!
//! Polling preserves XrayR's behaviour: a single periodic tick (every
//! `UpdatePeriodic` seconds, default 60) runs the node/user monitor followed by
//! the traffic-report monitor, exactly as XrayR's two same-interval periodics do.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use compact_str::CompactString;
use kernel::Stats;
use proxy::ProxyContext;
use tokio_util::sync::CancellationToken;

use crate::api::{ApiError, NodeInfo, UserInfo, UserTraffic};
use crate::builder::{apply_users, build_inbound, build_user_tag};
use crate::config::ControllerConfig;
use crate::inbound_manager::InboundManager;
use crate::serverstatus;
use crate::sspanel::SspanelClient;

/// Drives one panel node end to end.
pub struct Controller {
    api: SspanelClient,
    cfg: ControllerConfig,
    ibm: Arc<InboundManager>,
    stats: Arc<Stats>,
    cx: ProxyContext,
    node_info: Option<NodeInfo>,
    node_tag: CompactString,
    user_list: Vec<UserInfo>,
}

impl Controller {
    pub fn new(
        api: SspanelClient,
        cfg: ControllerConfig,
        ibm: Arc<InboundManager>,
        stats: Arc<Stats>,
        cx: ProxyContext,
    ) -> Controller {
        Controller {
            api,
            cfg,
            ibm,
            stats,
            cx,
            node_info: None,
            node_tag: CompactString::default(),
            user_list: Vec::new(),
        }
    }

    /// The current node tag (test/inspection helper).
    pub fn node_tag(&self) -> &str {
        &self.node_tag
    }

    /// Initial fetch + bind, mirroring XrayR's `Controller.Start`.
    pub async fn start(&mut self) -> Result<()> {
        let node = self
            .api
            .get_node_info()
            .await
            .context("initial GetNodeInfo")?;
        if node.port == 0 {
            bail!("server port must be > 0");
        }
        let users = match self.api.get_user_list().await {
            Ok(u) => u,
            Err(ApiError::NotModified) => Vec::new(),
            Err(e) => return Err(e).context("initial GetUserList"),
        };

        let built = build_inbound(&node, &users, &self.cfg.listen_ip, &self.cfg.cert, &self.cx)?;
        let tag = built.tag.clone();
        tracing::debug!(
            tag = %tag,
            port = node.port,
            transport = %node.transport_protocol,
            tls = node.enable_tls,
            users = users.len(),
            "initial node and user list fetched"
        );
        self.ibm.add(built)?;
        self.node_tag = tag;
        self.node_info = Some(node);
        self.user_list = users;
        tracing::info!(tag = %self.node_tag, users = self.user_list.len(), "controller started");
        Ok(())
    }

    /// Run the periodic loop until `shutdown` fires. `start` must have succeeded.
    pub async fn run(mut self, shutdown: CancellationToken) {
        let interval = Duration::from_secs(u64::from(self.cfg.update_periodic.max(1)));
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = tokio::time::sleep(interval) => {}
            }
            let started = Instant::now();
            tracing::debug!(
                tag = %self.node_tag,
                interval_secs = interval.as_secs(),
                "controller periodic tick started"
            );
            self.node_info_monitor().await;
            self.user_info_monitor().await;
            tracing::debug!(
                tag = %self.node_tag,
                elapsed_ms = started.elapsed().as_millis(),
                "controller periodic tick finished"
            );
        }
        self.ibm.remove(&self.node_tag);
        tracing::info!(tag = %self.node_tag, "controller stopped");
    }

    /// Poll node info + user list; rebuild the inbound on node change, swap the
    /// user table on user change. Mirrors XrayR's `nodeInfoMonitor`.
    pub async fn node_info_monitor(&mut self) {
        let new_node = match self.api.get_node_info().await {
            Ok(n) => Some(n),
            Err(ApiError::NotModified) => {
                tracing::debug!(tag = %self.node_tag, "node info not modified");
                None
            }
            Err(e) => {
                tracing::warn!(error = %e, "GetNodeInfo failed");
                return;
            }
        };
        let new_users = match self.api.get_user_list().await {
            Ok(u) => Some(u),
            Err(ApiError::NotModified) => None,
            Err(e) => {
                tracing::warn!(error = %e, "GetUserList failed");
                return;
            }
        };

        let node_changed = matches!(&new_node, Some(n) if Some(n) != self.node_info.as_ref());

        if node_changed {
            let Some(node) = new_node else { return };
            if node.port == 0 {
                tracing::warn!("new node port is 0, ignoring");
                return;
            }
            let old_tag = self.node_tag.clone();
            tracing::debug!(
                old = %old_tag,
                port = node.port,
                transport = %node.transport_protocol,
                tls = node.enable_tls,
                "node info changed; rebuilding inbound"
            );
            let users = match new_users {
                Some(users) => users,
                None => {
                    tracing::debug!(
                        tag = %old_tag,
                        count = self.user_list.len(),
                        "node changed; reusing cached user list"
                    );
                    self.user_list.clone()
                }
            };
            self.ibm.remove(&old_tag);
            self.prune_all_stats(&old_tag).await;

            let built =
                match build_inbound(&node, &users, &self.cfg.listen_ip, &self.cfg.cert, &self.cx) {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::error!(error = %e, "rebuilding inbound failed");
                        return;
                    }
                };
            let tag = built.tag.clone();
            if let Err(e) = self.ibm.add(built) {
                tracing::error!(error = %e, "rebinding inbound failed");
                return;
            }
            tracing::info!(old = %old_tag, new = %tag, "node info changed, inbound rebuilt");
            self.node_tag = tag;
            self.node_info = Some(node);
            self.user_list = users;
        } else {
            if new_node.is_some() {
                tracing::debug!(tag = %self.node_tag, "node info unchanged");
            }
            let Some(users) = new_users else {
                tracing::debug!(tag = %self.node_tag, "user list not modified");
                return;
            };
            if !users_differ(&self.user_list, &users) {
                tracing::debug!(
                    tag = %self.node_tag,
                    count = users.len(),
                    "user list unchanged"
                );
                return;
            }
            let Some(node) = self.node_info.clone() else {
                tracing::debug!(
                    tag = %self.node_tag,
                    count = users.len(),
                    "user list fetched but node info is unavailable"
                );
                return;
            };
            let Some(handler) = self.ibm.handler(&self.node_tag) else {
                tracing::debug!(
                    tag = %self.node_tag,
                    count = users.len(),
                    "user list fetched but inbound handler is unavailable"
                );
                return;
            };

            if let Err(e) = apply_users(&handler, &node, &users, &self.node_tag) {
                tracing::error!(error = %e, "syncing users failed");
                return;
            }
            self.prune_removed_stats(&users).await;
            tracing::info!(tag = %self.node_tag, count = users.len(), "user list synced");
            self.user_list = users;
        }
    }

    /// Report node status and per-user traffic. Mirrors XrayR's
    /// `userInfoMonitor` (online-IP and audit reporting are omitted: the xray-rs
    /// core has no device limiter or rule manager to source them).
    pub async fn user_info_monitor(&mut self) {
        let status = serverstatus::get_system_info().await;
        tracing::debug!(
            tag = %self.node_tag,
            cpu = status.cpu,
            mem = status.mem,
            disk = status.disk,
            uptime = status.uptime,
            "node status sampled"
        );

        // Per-user speed/device limits arrive from the panel in UserInfo but this
        // core cannot enforce them. Surfaced at debug (once per poll is harmless).
        if tracing::enabled!(tracing::Level::DEBUG) {
            let speed = self.user_list.iter().filter(|u| u.speed_limit > 0).count();
            let device = self.user_list.iter().filter(|u| u.device_limit > 0).count();
            if speed > 0 || device > 0 {
                tracing::debug!(
                    tag = %self.node_tag,
                    users_with_speed_limit = speed,
                    users_with_device_limit = device,
                    "panel reports per-user speed/device limits; this core does not enforce them"
                );
            }
        }

        if let Err(e) = self.api.report_node_status(&status).await {
            tracing::warn!(error = %e, "ReportNodeStatus failed");
        }

        let mut traffic: Vec<UserTraffic> = Vec::new();
        // Keep the taken counts so we can restore on report failure.
        let mut taken: Vec<(Arc<kernel::Counter>, u64, u64)> = Vec::new();
        for (tag, counter) in self.stats.active_counters().await {
            let (up, down) = counter.take();
            if up == 0 && down == 0 {
                continue;
            }
            let Some((uid, email)) = parse_user_tag(&self.node_tag, &tag) else {
                counter.restore(up, down);
                tracing::debug!(tag = %tag, "active traffic counter does not match node tag");
                continue;
            };
            traffic.push(UserTraffic {
                uid,
                email,
                upload: i64::try_from(up).unwrap_or(i64::MAX),
                download: i64::try_from(down).unwrap_or(i64::MAX),
            });
            taken.push((counter, up, down));
        }

        if traffic.is_empty() {
            tracing::debug!(tag = %self.node_tag, "no user traffic to report");
            return;
        }

        if self.cfg.disable_upload_traffic {
            // Counted but discarded (XrayR resets without reporting in this mode).
            tracing::debug!(
                tag = %self.node_tag,
                count = traffic.len(),
                "user traffic upload disabled; counters discarded"
            );
            return;
        }

        tracing::info!(count = traffic.len(), "reporting user traffic");
        if let Err(e) = self.api.report_user_traffic(&traffic).await {
            tracing::warn!(error = %e, "ReportUserTraffic failed; preserving counts");
            for (counter, up, down) in taken {
                counter.restore(up, down);
            }
        }
    }

    /// Drop stats counters for users removed since the last sync.
    async fn prune_removed_stats(&self, new_users: &[UserInfo]) {
        let keep: HashSet<CompactString> = new_users
            .iter()
            .map(|u| build_user_tag(&self.node_tag, u))
            .collect();
        for u in &self.user_list {
            let tag = build_user_tag(&self.node_tag, u);
            if !keep.contains(&tag) {
                self.stats.remove(&tag).await;
            }
        }
    }

    /// Drop all stats counters for the current user set under `tag` (node change).
    async fn prune_all_stats(&self, tag: &str) {
        for u in &self.user_list {
            self.stats.remove(&build_user_tag(tag, u)).await;
        }
    }
}

/// Order-independent set comparison of two user lists.
fn users_differ(old: &[UserInfo], new: &[UserInfo]) -> bool {
    if old.len() != new.len() {
        return true;
    }
    let set: HashSet<&UserInfo> = old.iter().collect();
    new.iter().any(|u| !set.contains(u))
}

fn parse_user_tag(node_tag: &str, tag: &str) -> Option<(i32, CompactString)> {
    let prefix = format!("{node_tag}|");
    let rest = tag.strip_prefix(&prefix)?;
    let (email, uid) = rest.rsplit_once('|')?;
    let uid = uid.parse::<i32>().ok()?;
    Some((uid, CompactString::new(email)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::UserInfo;

    fn u(uid: i32, uuid: &str) -> UserInfo {
        UserInfo {
            uid,
            email: CompactString::default(),
            uuid: CompactString::from(uuid),
            passwd: CompactString::default(),
            port: 0,
            alter_id: 0,
            method: CompactString::default(),
            speed_limit: 0,
            device_limit: 0,
        }
    }

    #[test]
    fn users_differ_detects_changes() {
        let a = vec![u(1, "x"), u(2, "y")];
        // Same set, reversed order → not different.
        let b = vec![u(2, "y"), u(1, "x")];
        assert!(!users_differ(&a, &b));
        // Added user.
        let c = vec![u(1, "x"), u(2, "y"), u(3, "z")];
        assert!(users_differ(&a, &c));
        // Removed user.
        let d = vec![u(1, "x")];
        assert!(users_differ(&a, &d));
        // Same count, different member.
        let e = vec![u(1, "x"), u(9, "y")];
        assert!(users_differ(&a, &e));
    }
}
