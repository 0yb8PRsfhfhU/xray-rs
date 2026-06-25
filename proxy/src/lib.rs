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

pub mod io;
pub mod trojan;
pub mod udp;
pub mod vless;

use std::io as stdio;

use kernel::{Ctx, Dispatcher, Policy};
use transport::Stream;

pub use trojan::{Trojan, TrojanUsers};
pub use vless::{Vless, VlessUsers};

/// Closed sum of inbound handlers (SPEC §P1).
pub enum Inbound {
    Trojan(Trojan),
    Vless(Vless),
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
        }
    }
}
