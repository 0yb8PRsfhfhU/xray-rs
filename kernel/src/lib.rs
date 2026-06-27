//! `kernel` — the xray-rs data plane and shared value types.
//!
//! Connection-path code parses attacker-controlled bytes, so this crate is held
//! to SPEC §P7: no panics, no unchecked indexing, no unchecked arithmetic.

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

pub mod types;
pub mod pipe_asm;
pub mod egress;
pub mod controller;

pub use egress::dialer::SystemDialer;
pub use controller::dispatcher::Dispatcher;
pub use egress::dns::Resolver;
pub use types::error::{Error, Result};
pub use types::net::{AddrCodec, Address, Destination, Family, Network, PortOrder};
pub use egress::outbound::Outbound;
pub use pipe_asm::pipe::{Link, UdpLink, UdpPacket};
pub use controller::policy::Policy;
pub use controller::router::{Cidr, DomainMatcher, RouteCtx, Router, Rule};
pub use controller::session::Ctx;
pub use controller::sniff::{sniff, sniff_http, sniff_tls, SniffedProtocol};
pub use pipe_asm::timer::Timer;
pub use types::uuid::Uuid;
