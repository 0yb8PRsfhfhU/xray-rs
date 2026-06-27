//! Runtime instance: bind listeners and drive inbound handlers (SPEC §2f).

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use kernel::{Ctx, Dispatcher, Policy};
use proxy::ProxyInbound;
use transport::{SocketOpts, accept_stream, bind_tcp};

use crate::config::{Built, InboundInstance};

pub struct Instance {
    built: Built,
    policy: Policy,
}

impl Instance {
    pub fn new(built: Built) -> Instance {
        Instance {
            built,
            policy: Policy::default(),
        }
    }

    /// Run all inbound listeners until the process exits.
    pub async fn run(self) -> Result<()> {
        let disp = self.built.dispatcher;
        let policy = self.policy;
        if self.built.inbounds.is_empty() {
            anyhow::bail!("no inbounds configured");
        }
        let mut handles = Vec::new();
        for ib in self.built.inbounds {
            let disp = disp.clone();
            handles.push(tokio::spawn(serve(ib, disp, policy)));
        }
        for h in handles {
            let _ = h.await;
        }
        Ok(())
    }
}

async fn serve(ib: InboundInstance, disp: Arc<Dispatcher>, policy: Policy) -> Result<()> {
    let addr: SocketAddr = format!("{}:{}", ib.listen, ib.port)
        .parse()
        .with_context(|| format!("invalid listen address {}:{}", ib.listen, ib.port))?;
    let listener =
        bind_tcp(addr, &SocketOpts::default()).with_context(|| format!("binding {addr}"))?;
    tracing::info!(tag = %ib.tag, %addr, "listening");

    let handler = ib.handler;
    let stream_cfg = ib.stream;
    let tag = ib.tag;

    if handler.binds_udp() {
        match tokio::net::UdpSocket::bind(addr).await {
            Ok(sock) => {
                let sock = Arc::new(sock);
                let uh = handler.clone();
                let ud = disp.clone();
                let utag = tag.clone();
                tracing::info!(tag = %utag, %addr, "listening (udp)");
                tokio::spawn(async move {
                    let ctx = Ctx::new(utag, None);
                    if let Err(e) = uh.serve_udp(sock, &ctx, &ud, &policy).await {
                        tracing::debug!(error = %e, "udp listener ended");
                    }
                });
            }
            Err(e) => tracing::warn!(%addr, error = %e, "udp bind failed"),
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
        tracing::debug!(tag = %tag, %peer, "tcp accepted");
        let handler = handler.clone();
        let disp = disp.clone();
        let stream_cfg = stream_cfg.clone();
        let tag = tag.clone();
        tokio::spawn(async move {
            let stream = match accept_stream(tcp, &stream_cfg).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(error = %e, "stream setup failed");
                    return;
                }
            };
            let ctx = Ctx::new(tag, Some(peer));
            if let Err(e) = handler.serve(&ctx, stream, &disp, &policy).await {
                tracing::debug!(session = ctx.id, error = %e, "connection ended");
            }
        });
    }
}
