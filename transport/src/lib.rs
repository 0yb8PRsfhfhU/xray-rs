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

use std::sync::Arc;
use tokio::net::TcpStream;

pub use httpupgrade::HttpUpgradeConfig;
pub use listener::{SocketOpts, bind_tcp};
pub use stream::Stream;
pub use tls::TlsServer;
pub use ws::{WsConfig, WsStream};
pub use grpc::GrpcConfig;

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

pub trait Transport {
    type Stream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static;
    fn accept(
        &self,
        stream: stream::RawNetworkStream,
    ) -> impl Future<Output = std::io::Result<Self::Stream>> + Send;
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

impl Transport for TransportKind {
    type Stream = Stream;
    async fn accept(&self, raw: stream::RawNetworkStream) -> std::io::Result<Stream> {
        match self {
            TransportKind::Raw => Ok(Stream::Raw(raw)),
            TransportKind::Ws(cfg) => {
                let ws = ws::accept(raw, cfg).await?;
                Ok(Stream::Ws(Box::new(ws)))
            }
            TransportKind::HttpUpgrade(cfg) => {
                let raw = httpupgrade::accept(raw, cfg).await?;
                Ok(Stream::Raw(raw))
            }
            TransportKind::Grpc(cfg) => {
                let grpc = grpc::accept(raw, cfg).await?;
                Ok(Stream::Grpc(Box::new(grpc)))
            }
        }
    }
}

/// Apply security then transport to an accepted TCP connection, producing the
/// composed [`Stream`] handed to an inbound handler.
pub async fn accept_stream(tcp: TcpStream, cfg: &StreamConfig) -> std::io::Result<Stream> {
    let raw = match &cfg.security {
        Security::None => stream::RawNetworkStream::Tcp(tcp),
        Security::Tls(server) => stream::RawNetworkStream::Tls(Box::new(server.accept(tcp).await?)),
    };
    cfg.transport.accept(raw).await
}
