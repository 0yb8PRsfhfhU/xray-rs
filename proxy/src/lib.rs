//! `proxy` — inbound protocol handlers and the `Inbound` sum (SPEC §2e).
//! Held to SPEC §P7 (parses attacker-controlled bytes).

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

pub mod crypto;
pub mod dokodemo;
pub mod http;
pub mod io;
pub mod mux;
pub mod outbound;
pub mod shadowsocks;
pub mod socks;
pub mod trojan;
pub mod udp;
pub mod vless;
pub mod vmess;

use std::io as stdio;
use std::sync::Arc;

use kernel::{
    CachedResolver, ConnectionPolicy, Ctx, Network, Proxy, ProxyDecision, Stats, SystemDialer,
};
use tokio::net::UdpSocket;

pub use dokodemo::Dokodemo;
pub use http::{Http, HttpAccount};
pub use outbound::{Outbound, SocksOutbound, SsOutbound};
pub use shadowsocks::Shadowsocks;
pub use socks::{Socks, SocksAccount};
pub use trojan::{Trojan, TrojanUsers};
pub use vless::{Vless, VlessUsers};
pub use vmess::{Vmess, VmessUsers};

/// The shared direct dialer handed to proxy decoders for self-servicing the
/// flows the kernel tree cannot express (UDP-associated + mux sub-flows): those
/// egress DIRECT through this dialer, while ordinary TCP flows route through the
/// tower tree's outbound child.
pub type SharedDialer = Arc<SystemDialer<CachedResolver>>;

/// Runtime handle every inbound handler carries: the direct dialer (for UDP/mux
/// self-service), the optional per-user traffic [`Stats`] registry, and the
/// connection [`ConnectionPolicy`] (handshake + idle timeouts). Cheap to clone.
#[derive(Clone)]
pub struct ProxyContext {
    pub dialer: SharedDialer,
    pub stats: Option<Arc<Stats>>,
    pub policy: ConnectionPolicy,
}

impl ProxyContext {
    pub fn new(dialer: SharedDialer, stats: Option<Arc<Stats>>, policy: ConnectionPolicy) -> Self {
        ProxyContext {
            dialer,
            stats,
            policy,
        }
    }
}

/// Closed sum of inbound handlers (SPEC §P1). Implements [`kernel::Proxy`] by
/// delegating `decode` to the active variant; the tower `ProxyService` drives
/// it and routes the resulting flow.
pub enum Inbound {
    Trojan(Trojan),
    Vless(Vless),
    Shadowsocks(Shadowsocks),
    Socks(Socks),
    Http(Http),
    Dokodemo(Dokodemo),
    Vmess(Vmess),
}

impl Proxy for Inbound {
    type Auth = ();

    fn networks(&self) -> &[Network] {
        match self {
            Inbound::Trojan(h) => h.networks(),
            Inbound::Vless(h) => h.networks(),
            Inbound::Shadowsocks(h) => h.networks(),
            Inbound::Socks(h) => h.networks(),
            Inbound::Http(h) => h.networks(),
            Inbound::Dokodemo(h) => h.networks(),
            Inbound::Vmess(h) => h.networks(),
        }
    }

    async fn decode<S>(&self, ctx: Ctx, stream: S) -> stdio::Result<ProxyDecision>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        match self {
            Inbound::Trojan(h) => h.decode(ctx, stream).await,
            Inbound::Vless(h) => h.decode(ctx, stream).await,
            Inbound::Shadowsocks(h) => h.decode(ctx, stream).await,
            Inbound::Socks(h) => h.decode(ctx, stream).await,
            Inbound::Http(h) => h.decode(ctx, stream).await,
            Inbound::Dokodemo(h) => h.decode(ctx, stream).await,
            Inbound::Vmess(h) => h.decode(ctx, stream).await,
        }
    }
}

impl Inbound {
    /// Whether this inbound needs a standalone UDP listener socket bound on its
    /// port (only Shadowsocks; SOCKS/Trojan/VLESS carry UDP over the stream).
    pub fn binds_udp(&self) -> bool {
        matches!(self, Inbound::Shadowsocks(_))
    }

    /// Drive the inbound's standalone UDP socket (no-op unless it binds one).
    pub async fn serve_udp(&self, socket: Arc<UdpSocket>, ctx: Ctx) -> stdio::Result<()> {
        match self {
            Inbound::Shadowsocks(h) => h.serve_udp(socket, ctx).await,
            _ => Ok(()),
        }
    }
}
