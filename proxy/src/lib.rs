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
pub mod shadowsocks;
pub mod socks;
pub mod trojan;
pub mod udp;
pub mod vless;
pub mod vmess;

use std::future::Future;
use std::io as stdio;
use std::sync::Arc;

use kernel::{Ctx, Dispatcher, Policy};
use tokio::net::UdpSocket;
use transport::Stream;

pub use dokodemo::Dokodemo;
pub use http::{Http, HttpAccount};
pub use shadowsocks::Shadowsocks;
pub use socks::{Socks, SocksAccount};
pub use trojan::{Trojan, TrojanUsers};
pub use vless::{Vless, VlessUsers};
pub use vmess::{Vmess, VmessUsers};

/// Closed sum of inbound handlers (SPEC §P1).
pub enum Inbound {
    Trojan(Trojan),
    Vless(Vless),
    Shadowsocks(Shadowsocks),
    Socks(Socks),
    Http(Http),
    Dokodemo(Dokodemo),
    Vmess(Vmess),
}

pub trait ProxyInbound {
    /// Decode the proxy header, authenticate, and run the flow to completion.
    fn serve(
        &self,
        ctx: &Ctx,
        conn: Stream,
        disp: &Dispatcher,
        policy: &Policy,
    ) -> impl Future<Output = stdio::Result<()>> + Send;
}

pub trait UdpProxyInbound {
    fn serve_udp(
        &self,
        socket: Arc<UdpSocket>,
        ctx: &Ctx,
        disp: &Dispatcher,
        policy: &Policy,
    ) -> impl Future<Output = stdio::Result<()>> + Send;
}

impl ProxyInbound for Inbound {
    async fn serve(
        &self,
        ctx: &Ctx,
        conn: Stream,
        disp: &Dispatcher,
        policy: &Policy,
    ) -> stdio::Result<()> {
        match self {
            Inbound::Trojan(h) => h.serve(ctx, conn, disp, policy).await,
            Inbound::Vless(h) => h.serve(ctx, conn, disp, policy).await,
            Inbound::Shadowsocks(h) => h.serve(ctx, conn, disp, policy).await,
            Inbound::Socks(h) => h.serve(ctx, conn, disp, policy).await,
            Inbound::Http(h) => h.serve(ctx, conn, disp, policy).await,
            Inbound::Dokodemo(h) => h.serve(ctx, conn, disp, policy).await,
            Inbound::Vmess(h) => h.serve(ctx, conn, disp, policy).await,
        }
    }
}

impl Inbound {
    /// Whether this inbound also binds a UDP socket on its port.
    pub fn binds_udp(&self) -> bool {
        matches!(self, Inbound::Shadowsocks(_))
    }

    /// Serve the inbound's UDP socket (only protocols with a UDP listener).
    pub async fn serve_udp(
        &self,
        socket: Arc<UdpSocket>,
        ctx: &Ctx,
        disp: &Dispatcher,
        policy: &Policy,
    ) -> stdio::Result<()> {
        match self {
            Inbound::Shadowsocks(h) => h.serve_udp(socket, ctx, disp, policy).await,
            _ => Ok(()),
        }
    }
}
