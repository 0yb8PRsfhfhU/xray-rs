//! `transport` — listeners, the `Stream` sum, transport security (OpenSSL TLS)
//! and stream transports (raw / websocket / httpupgrade). Held to SPEC §P7.

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

pub mod grpc;
pub mod httpupgrade;
pub mod listener;
pub mod stream;
pub mod tls;
pub mod ws;

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;

use kernel::{Accepted, Transport};

pub use grpc::GrpcConfig;
pub use httpupgrade::HttpUpgradeConfig;
pub use listener::{SocketOpts, bind_tcp};
pub use stream::{Stream, StreamReadHalf, StreamWriteHalf};
pub use tls::TlsServer;
pub use ws::{WsConfig, WsStream};

/// Transport-security layer for an inbound listener.
#[derive(Clone)]
pub enum Security {
    None,
    Tls(Arc<TlsServer>),
}

/// Stream transport layered on top of the security layer.
#[derive(Clone)]
pub enum TransportKind {
    Raw,
    Ws(Arc<WsConfig>),
    HttpUpgrade(Arc<HttpUpgradeConfig>),
    Grpc(Arc<GrpcConfig>),
}

/// Full inbound stream configuration: security + transport.
#[derive(Clone)]
pub struct StreamConfig {
    pub security: Security,
    pub transport: TransportKind,
}

impl StreamConfig {
    pub fn raw() -> StreamConfig {
        StreamConfig {
            security: Security::None,
            transport: TransportKind::Raw,
        }
    }
}

/// Apply security then transport to an accepted TCP connection. Raw / websocket
/// / httpupgrade yield a single composed [`Stream`]; gRPC yields a receiver of
/// streams multiplexed over one HTTP/2 connection.
pub async fn accept_conn(tcp: TcpStream, cfg: &StreamConfig) -> std::io::Result<Accepted<Stream>> {
    let raw = match &cfg.security {
        Security::None => stream::RawNetworkStream::Tcp(tcp),
        Security::Tls(server) => stream::RawNetworkStream::Tls(Box::new(server.accept(tcp).await?)),
    };
    Ok(match &cfg.transport {
        TransportKind::Raw => Accepted::Single(Stream::Raw(raw)),
        TransportKind::Ws(c) => Accepted::Single(Stream::Ws(Box::new(ws::accept(raw, c).await?))),
        TransportKind::HttpUpgrade(c) => {
            Accepted::Single(httpupgrade::accept(raw, c).await?.into())
        }
        TransportKind::Grpc(c) => Accepted::Multiplexed(grpc::serve(raw, c).await?),
    })
}

/// A concrete [`kernel::Transport`]: owns its listen address (objective req. 3)
/// and frames one accepted raw TCP connection into a proxy-ready [`Stream`] by
/// applying the configured security + transport layers via [`accept_conn`].
pub struct StreamTransport {
    cfg: StreamConfig,
    listen: SocketAddr,
}

impl StreamTransport {
    pub fn new(cfg: StreamConfig, listen: SocketAddr) -> StreamTransport {
        StreamTransport { cfg, listen }
    }
}

impl Transport for StreamTransport {
    type Conn = TcpStream;
    type Stream = Stream;

    fn listen_addr(&self) -> SocketAddr {
        self.listen
    }

    fn accept(
        &self,
        conn: TcpStream,
    ) -> impl Future<Output = std::io::Result<Accepted<Stream>>> + Send {
        accept_conn(conn, &self.cfg)
    }
}
