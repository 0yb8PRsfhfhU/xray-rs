//! `kernel` — the xray-rs runtime framework.
//!
//! This crate is the *framework*, not the protocols: it provides the abstract
//! traits every proxy plugs into ([`Transport`], [`Proxy`], [`Outbound`],
//! [`DnsResolver`], [`Dialer`]), the RCU-published config machinery, the
//! `tower::Service` config↔service tree (diff-and-swap on reload, React-style
//! `useContext` via `watch`), the routing engine, and the data plane
//! (`Link`/copy/timer). Concrete protocol/transport implementations live in
//! sibling crates and are intentionally absent here (objective requirement 1).
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

pub mod config;
pub mod error;
pub mod net;
pub mod pipe;
pub mod rcu;
pub mod route;
pub mod runtime;
pub mod stats;
pub mod uuid;

pub use config::{ConnectionPolicy, KernelConfig};
pub use error::{Error, Result};
pub use net::{AddrCodec, Address, Destination, Family, Network, PortOrder};
pub use pipe::copy::{BytesSink, splice, splice_sink};
pub use pipe::outbound::{Outbound, OutboundList};
pub use pipe::pipe::{LINK_CAPACITY, Link, UdpLink, UdpPacket, pipe, udp_pipe};
pub use pipe::proxy_protocol::{Proxy, ProxyDecision};
pub use pipe::timer::Timer;
pub use pipe::translation::{ChunkRead, ChunkWrite, read_header};
pub use pipe::transport::{Accepted, Transport, TransportList};
pub use rcu::RcuCell;
pub use route::balance::{BalanceMode, LoadBalancer};
pub use route::rule::{
    Condition, GeoMatcher, MatchRule, NoGeo, RouteDecision, RouteQuery, RouteTable,
};
pub use route::sniff::{SniffedProtocol, sniff, sniff_http, sniff_tls};
pub use runtime::context::ContextHandle;
pub use runtime::dialer::{Dialer, SystemDialer, TcpDialer, UdpDialer};
pub use runtime::dns::{CachedResolver, DnsResolver};
pub use runtime::service::{
    KeyedTree, Node, Reconcile, Slot, SwapHandle, SwappableService, UpdatePolicy,
};
pub use runtime::session::Ctx;
pub use runtime::tree::{
    Incoming, OutboundDispatch, OutboundRequest, ProxyRequest, ProxyService, RouteRequest,
    RouteService, TransportService,
};
pub use runtime::user::{
    Authentication, ByteCounter, User, UserAuthorization, UserContext, UserList, UserListInner,
};
pub use stats::{Counter, Stats};
pub use uuid::Uuid;
