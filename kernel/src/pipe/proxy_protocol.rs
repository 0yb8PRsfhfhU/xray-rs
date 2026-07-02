//! The [`Proxy`] seam: decode a transport stream, authenticate the user, and
//! learn the target (objective requirement 1).
//!
//! A proxy reads its protocol header off the decoded transport stream, looks
//! the user up in its [`UserList`](crate::runtime::user::UserList) (abstract
//! authentication data `Auth`, closed [`UserAuthorization`](crate::runtime::user::UserAuthorization) identity), and
//! yields a [`ProxyDecision`]: the target [`Destination`], the (possibly
//! user-attributed) [`Ctx`], and the outbound-facing half of a [`Link`] whose
//! inbound half the proxy is now pumping the connection into. This trait is
//! **not** implemented in `kernel`; concrete decoders live downstream.

use std::io;

use crate::net::Destination;
use crate::pipe::pipe::Link;
use crate::runtime::session::Ctx;

/// What a proxy learned from one connection: where to route it, the context to
/// route it *with*, and the outbound-facing pipe half to hand to the outbound.
pub struct ProxyDecision {
    /// The target the client asked to reach.
    pub target: Destination,
    /// The session context, updated with the authenticated user (SPEC §2f).
    pub ctx: Ctx,
    /// The outbound end of the in-process [`Link`]; the proxy owns and drives
    /// the inbound end (uplink `conn→link`, downlink `link→conn`).
    pub link: Link,
}

/// The proxy (decode + auth) seam. `Auth` is the abstract per-user
/// authentication data (objective requirement 1); the proxy authenticates
/// against an `Arc<UserListInner<Self::Auth>>` snapshot (SPEC §P2).
///
/// Not dyn-compatible by construction (async fn + generic stream) — proxies are
/// summed into an `enum` or driven by generic bound (SPEC §P1).
pub trait Proxy: Send + Sync + 'static {
    /// Abstract per-user authentication data this proxy verifies against.
    type Auth: Send + Sync + 'static;

    /// Networks this proxy binds (TCP, UDP, or both).
    fn networks(&self) -> &[crate::net::Network];

    /// Decode `stream`: read the header, authenticate, learn the target, and
    /// start pumping the connection into the returned [`ProxyDecision::link`].
    fn decode<S>(
        &self,
        ctx: Ctx,
        stream: S,
    ) -> impl Future<Output = io::Result<ProxyDecision>> + Send
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static;
}
