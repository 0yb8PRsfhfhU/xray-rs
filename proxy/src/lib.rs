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

impl Inbound {
    /// Decode the proxy header, authenticate, and run the flow to completion.
    pub async fn process(
        &self,
        ctx: &Ctx,
        conn: Stream,
        disp: &Dispatcher,
        policy: &Policy,
    ) -> stdio::Result<()> {
        match self {
            Inbound::Trojan(h) => h.process(ctx, conn, disp, policy).await,
            Inbound::Vless(h) => h.process(ctx, conn, disp, policy).await,
            Inbound::Shadowsocks(h) => h.process(ctx, conn, disp, policy).await,
            Inbound::Socks(h) => h.process(ctx, conn, disp, policy).await,
            Inbound::Http(h) => h.process(ctx, conn, disp, policy).await,
            Inbound::Dokodemo(h) => h.process(ctx, conn, disp, policy).await,
            Inbound::Vmess(h) => h.process(ctx, conn, disp, policy).await,
        }
    }

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
