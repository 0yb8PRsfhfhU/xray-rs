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

pub mod copy;
pub mod dialer;
pub mod dispatcher;
pub mod dns;
pub mod error;
pub mod net;
pub mod outbound;
pub mod pipe;
pub mod policy;
pub mod router;
pub mod session;
pub mod sniff;
pub mod timer;
pub mod uuid;

pub use dialer::SystemDialer;
pub use dispatcher::Dispatcher;
pub use dns::Resolver;
pub use error::{Error, Result};
pub use net::{AddrCodec, Address, Destination, Family, Network, PortOrder};
pub use outbound::Outbound;
pub use pipe::{Link, UdpLink, UdpPacket};
pub use policy::Policy;
pub use router::{Cidr, DomainMatcher, RouteCtx, Router, Rule};
pub use session::Ctx;
pub use sniff::{SniffedProtocol, sniff, sniff_http, sniff_tls};
pub use timer::Timer;
pub use uuid::Uuid;
