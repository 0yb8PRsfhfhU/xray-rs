//! Runtime instance: bind each inbound's TCP listener (and UDP socket where the
//! protocol needs one), then drive the per-inbound tower service tree.

use std::sync::Arc;

use anyhow::{Context, Result};
use kernel::{Ctx, Incoming};
use tower::ServiceExt;
use transport::{SocketOpts, bind_tcp};

use crate::config::{Built, InboundInstance};

pub struct Instance {
    built: Built,
}

impl Instance {
    pub fn new(built: Built) -> Instance {
        Instance { built }
    }

    /// Run all inbound listeners until the process exits.
    pub async fn run(self) -> Result<()> {
        if self.built.inbounds.is_empty() {
            anyhow::bail!("no inbounds configured");
        }
        let mut handles = Vec::new();
        for ib in self.built.inbounds {
            handles.push(tokio::spawn(serve(ib)));
        }
        for h in handles {
            let _ = h.await;
        }
        Ok(())
    }
}

async fn serve(ib: InboundInstance) -> Result<()> {
    let listener = bind_tcp(ib.listen, &SocketOpts::default())
        .with_context(|| format!("binding {}", ib.listen))?;
    tracing::info!(tag = %ib.tag, addr = %ib.listen, "listening");

    // Protocols with a standalone UDP listener (Shadowsocks) bind a UDP socket
    // alongside the TCP one; it is driven outside the tower tree.
    if ib.handler.binds_udp() {
        match tokio::net::UdpSocket::bind(ib.listen).await {
            Ok(sock) => {
                let sock = Arc::new(sock);
                let handler = ib.handler.clone();
                let tag = ib.tag.clone();
                tracing::info!(tag = %tag, addr = %ib.listen, "listening (udp)");
                tokio::spawn(async move {
                    let ctx = Ctx::new(tag, None);
                    if let Err(e) = handler.serve_udp(sock, ctx).await {
                        tracing::debug!(error = %e, "udp listener ended");
                    }
                });
            }
            Err(e) => tracing::warn!(addr = %ib.listen, error = %e, "udp bind failed"),
        }
    }

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                continue;
            }
        };
        let _ = tcp.set_nodelay(true);
        tracing::debug!(tag = %ib.tag, %peer, "tcp accepted");
        let tree = ib.tree.clone();
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
}
