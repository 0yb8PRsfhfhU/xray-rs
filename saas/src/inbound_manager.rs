//! Runtime inbound manager: bind/unbind listeners on demand so the controller
//! can add a node's inbound at start and rebuild it when the node config
//! changes — the xray-rs analogue of XrayR's `inbound.Manager` add/remove.
//!
//! Each node's inbound is a per-node tower service tree (transport → proxy →
//! shared route + outbound children). Live user changes never rebuild the tree:
//! the handler's internal `ArcSwap` user table is swapped in place (see
//! [`handler`](InboundManager::handler) + `builder::apply_users`). Each inbound
//! owns a [`CancellationToken`]; `remove` cancels it, stopping the accept loop
//! and dropping the listener. In-flight connections run to completion.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use compact_str::CompactString;
use kernel::{
    CachedResolver, Ctx, Incoming, NoGeo, OutboundDispatch, ProxyService, RouteService,
    SystemDialer, TransportService,
};
use parking_lot::{Mutex, MutexGuard};
use proxy::Inbound;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
use transport::{SocketOpts, StreamTransport, bind_tcp};

use crate::builder::BuiltInbound;

/// Concrete outbound sum (freedom / blackhole / ss / socks).
type Ob = proxy::Outbound;
type Dial = SystemDialer<CachedResolver>;
/// Shared route child (first-match table over the configured egress).
pub type RouteChild = RouteService<NoGeo>;
/// Shared outbound-dispatch child (tag-keyed egress + freedom default).
pub type ObChild = OutboundDispatch<Ob, Dial>;
type ProxySvc = ProxyService<Inbound, RouteChild, ObChild>;
type InboundTree = TransportService<StreamTransport, ProxySvc>;

struct Running {
    token: CancellationToken,
    handler: Arc<Inbound>,
    tasks: Vec<JoinHandle<()>>,
}

/// Owns the set of live inbound listeners, keyed by node tag. Every inbound
/// shares the route + outbound children built once from the egress config.
pub struct InboundManager {
    route_svc: RouteChild,
    ob_dispatch: ObChild,
    running: Mutex<HashMap<CompactString, Running>>,
}

impl InboundManager {
    pub fn new(route_svc: RouteChild, ob_dispatch: ObChild) -> InboundManager {
        InboundManager {
            route_svc,
            ob_dispatch,
            running: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<CompactString, Running>> {
        self.running.lock()
    }

    /// The live handler for `tag`, used to push user-table updates.
    pub fn handler(&self, tag: &str) -> Option<Arc<Inbound>> {
        self.lock().get(tag).map(|r| r.handler.clone())
    }

    /// Whether an inbound with `tag` is currently bound.
    pub fn contains(&self, tag: &str) -> bool {
        self.lock().contains_key(tag)
    }

    /// Bind a new inbound and start serving it. Errors if the address is in use
    /// or a same-tagged inbound already exists.
    pub fn add(&self, built: BuiltInbound) -> Result<()> {
        if self.contains(&built.tag) {
            anyhow::bail!("inbound {} already running", built.tag);
        }
        let addr: SocketAddr = format!("{}:{}", built.listen, built.port)
            .parse()
            .with_context(|| format!("invalid listen address {}:{}", built.listen, built.port))?;

        let BuiltInbound {
            tag,
            stream,
            handler,
            ..
        } = built;

        let listener =
            bind_tcp(addr, &SocketOpts::default()).with_context(|| format!("binding {addr}"))?;

        let token = CancellationToken::new();
        let mut tasks: Vec<JoinHandle<()>> = Vec::new();

        // UDP listener (Shadowsocks) — bound alongside, driven outside the tree.
        if handler.binds_udp() {
            match std::net::UdpSocket::bind(addr).and_then(|s| {
                s.set_nonblocking(true)?;
                tokio::net::UdpSocket::from_std(s)
            }) {
                Ok(sock) => {
                    let sock = Arc::new(sock);
                    let uh = handler.clone();
                    let utag = tag.clone();
                    let utk = token.clone();
                    tracing::info!(tag = %utag, %addr, "listening (udp)");
                    tasks.push(tokio::spawn(async move {
                        let ctx = Ctx::new(utag, None);
                        tokio::select! {
                            _ = utk.cancelled() => {}
                            r = uh.serve_udp(sock, ctx) => {
                                if let Err(e) = r {
                                    tracing::debug!(error = %e, "udp listener ended");
                                }
                            }
                        }
                    }));
                }
                Err(e) => tracing::warn!(%addr, error = %e, "udp bind failed"),
            }
        }

        // Per-node tower service tree.
        let stream_transport = StreamTransport::new(stream, addr);
        let proxy_svc = ProxyService::new(
            handler.clone(),
            self.route_svc.clone(),
            self.ob_dispatch.clone(),
        );
        let tree: InboundTree =
            TransportService::new(Arc::new(stream_transport), proxy_svc, tag.clone());

        // TCP accept loop.
        let acc_tag = tag.clone();
        let acc_token = token.clone();
        tracing::info!(tag = %acc_tag, %addr, "listening");
        tasks.push(tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    _ = acc_token.cancelled() => {
                        tracing::debug!(tag = %acc_tag, "accept loop stopped");
                        break;
                    }
                    res = listener.accept() => res,
                };
                let (tcp, peer) = match accepted {
                    Ok(v) => v,
                    Err(e) => {
                        // EMFILE (24) / ENFILE (23): fd exhaustion — back off to let
                        // connections close rather than spinning and flooding logs.
                        if matches!(e.raw_os_error(), Some(23) | Some(24)) {
                            tracing::warn!(error = %e, "accept failed");
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        } else if e.kind() != std::io::ErrorKind::ConnectionAborted {
                            tracing::warn!(error = %e, "accept failed");
                        }
                        continue;
                    }
                };
                let _ = tcp.set_nodelay(true);
                let tree = tree.clone();
                tokio::spawn(async move {
                    if let Err(e) = tree
                        .oneshot(Incoming {
                            conn: tcp,
                            source: Some(peer),
                        })
                        .await
                    {
                        tracing::debug!(error = %e, "connection ended");
                    }
                });
            }
        }));

        self.lock().insert(
            tag,
            Running {
                token,
                handler,
                tasks,
            },
        );
        Ok(())
    }

    /// Stop and unbind the inbound with `tag` (no-op if absent).
    pub fn remove(&self, tag: &str) {
        if let Some(running) = self.lock().remove(tag) {
            running.token.cancel();
            for t in running.tasks {
                t.abort();
            }
            tracing::info!(tag = %tag, "inbound removed");
        }
    }

    /// Number of bound inbounds (test/inspection helper).
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether no inbounds are bound.
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }
}
