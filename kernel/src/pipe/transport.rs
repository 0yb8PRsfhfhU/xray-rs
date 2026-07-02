//! The [`Transport`] seam: the listener layer (objective requirement 1).
//!
//! A transport owns its listening socket address (objective requirement 3's
//! worked example: the listen setting lives in transport, not the proxy) and
//! turns a raw accepted connection into a decoded [`Transport::Stream`] — raw
//! TCP passthrough, a TLS handshake, a WebSocket upgrade, or a multiplexed
//! carrier that yields many streams. This trait is intentionally **not**
//! implemented in `kernel`; concrete transports live downstream.

use std::io;
use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

/// The result of accepting one raw connection: either a single decoded stream,
/// or a multiplexed carrier delivering streams as they open (gRPC/HTTP2, mux).
pub enum Accepted<S> {
    /// One stream, 1:1 with the accepted connection (TCP, TLS, WebSocket).
    Single(S),
    /// A carrier that demultiplexes into many streams (h2, mux). The receiver
    /// closes when the carrier ends.
    Multiplexed(mpsc::Receiver<S>),
}

/// The transport (listener) seam. Owns its bind address; frames raw bytes into
/// a proxy-ready [`Stream`](Transport::Stream).
///
/// Generic methods + async-fn-in-trait make this deliberately **not**
/// dyn-compatible: transports are summed into an `enum` or driven by generic
/// bound, never a trait object (SPEC §P1).
pub trait Transport: Send + Sync + 'static {
    /// The raw connection type handed in by the accept loop (e.g. `TcpStream`).
    type Conn: AsyncRead + AsyncWrite + Unpin + Send + 'static;
    /// The decoded stream handed up to the proxy after transport framing.
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// The address this transport listens on (objective requirement 3).
    fn listen_addr(&self) -> SocketAddr;

    /// Frame one accepted connection into a proxy-ready stream (or a mux).
    fn accept(
        &self,
        conn: Self::Conn,
    ) -> impl Future<Output = io::Result<Accepted<Self::Stream>>> + Send;
}

/// An RCU-published set of transports (one per listener), swapped wholesale on
/// reload (SPEC §P2). Unsized-`[T]` backed so the snapshot is a single `Arc`.
#[derive(Debug)]
pub struct TransportList<T>(crate::rcu::RcuCell<[T]>);

impl<T> TransportList<T> {
    pub fn new(items: impl IntoIterator<Item = T>) -> Self {
        let arc: std::sync::Arc<[T]> = items.into_iter().collect();
        Self(crate::rcu::RcuCell::from_arc(arc))
    }

    /// Cheap snapshot of the current transport set.
    pub fn load(&self) -> std::sync::Arc<[T]> {
        self.0.load()
    }

    /// Publish a new transport set atomically.
    pub fn replace(&self, items: impl IntoIterator<Item = T>) {
        let arc: std::sync::Arc<[T]> = items.into_iter().collect();
        self.0.swap(arc);
    }
}
