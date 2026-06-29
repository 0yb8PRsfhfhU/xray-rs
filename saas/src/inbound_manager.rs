//! Runtime inbound manager: bind/unbind listeners on demand so the controller
//! can add a node's inbound at start and rebuild it when the node config
//! changes — the xray-rs analogue of XrayR's `inbound.Manager` add/remove.
//!
//! Each inbound owns a [`CancellationToken`]; `remove` cancels it, which stops
//! the accept loop and drops the listener. In-flight connections, already
//! spawned, run to completion on their own.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use compact_str::CompactString;
use kernel::{Ctx, Dispatcher, Policy};
use parking_lot::{Mutex, MutexGuard};
use proxy::{Inbound, ProxyInbound};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use transport::{Accepted, SocketOpts, accept_conn, bind_tcp};

use crate::builder::BuiltInbound;

struct Running {
    token: CancellationToken,
    handler: Arc<Inbound>,
    tasks: Vec<JoinHandle<()>>,
}

/// Owns the set of live inbound listeners, keyed by node tag.
pub struct InboundManager {
    disp: Arc<Dispatcher>,
    policy: Policy,
    running: Mutex<HashMap<CompactString, Running>>,
}

impl InboundManager {
    pub fn new(disp: Arc<Dispatcher>, policy: Policy) -> InboundManager {
        InboundManager {
            disp,
            policy,
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

        // UDP listener (Shadowsocks).
        if handler.binds_udp() {
            match std::net::UdpSocket::bind(addr).and_then(|s| {
                s.set_nonblocking(true)?;
                tokio::net::UdpSocket::from_std(s)
            }) {
                Ok(sock) => {
                    let sock = Arc::new(sock);
                    let uh = handler.clone();
                    let ud = self.disp.clone();
                    let policy = self.policy;
                    let utag = tag.clone();
                    let utk = token.clone();
                    tracing::info!(tag = %utag, %addr, "listening (udp)");
                    tasks.push(tokio::spawn(async move {
                        let ctx = Ctx::new(utag.clone(), None);
                        tokio::select! {
                            _ = utk.cancelled() => {
                                tracing::debug!(tag = %utag, "udp listener stopped");
                            }
                            r = uh.serve_udp(sock, &ctx, &ud, &policy) => {
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

        // TCP accept loop.
        let acc_handler = handler.clone();
        let disp = self.disp.clone();
        let policy = self.policy;
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
                        tracing::warn!(error = %e, "accept failed");
                        continue;
                    }
                };
                let _ = tcp.set_nodelay(true);
                let handler = acc_handler.clone();
                let disp = disp.clone();
                let stream_cfg = stream.clone();
                let tag = acc_tag.clone();
                tokio::spawn(async move {
                    match accept_conn(tcp, &stream_cfg).await {
                        Ok(Accepted::Single(stream)) => {
                            let ctx = Ctx::new(tag, Some(peer));
                            if let Err(e) = handler.serve(&ctx, stream, &disp, &policy).await {
                                tracing::debug!(session = ctx.id, error = %e, "connection ended");
                            }
                        }
                        Ok(Accepted::Multiplexed(mut rx)) => {
                            while let Some(stream) = rx.recv().await {
                                let handler = handler.clone();
                                let disp = disp.clone();
                                let tag = tag.clone();
                                tokio::spawn(async move {
                                    let ctx = Ctx::new(tag, Some(peer));
                                    if let Err(e) = handler.serve(&ctx, stream, &disp, &policy).await {
                                        tracing::debug!(session = ctx.id, error = %e, "connection ended");
                                    }
                                });
                            }
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "stream setup failed");
                        }
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
