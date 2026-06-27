//! The `Stream` sum type for accepted connections (SPEC §P1).
//!
//! `Raw` is the security layer (plain TCP or OpenSSL TLS). `Stream` wraps a
//! `Raw` with any higher transport (websocket / grpc). Large variants are boxed
//! so the enum stays pointer-sized. `AsyncRead`/`AsyncWrite` delegate per arm.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

use crate::grpc::GrpcStream;
use crate::ws::WsStream;

/// The transport-security layer.
pub enum RawNetworkStream {
    Tcp(TcpStream),
    Tls(Box<SslStream<TcpStream>>),
}

impl AsyncRead for RawNetworkStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            RawNetworkStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            RawNetworkStream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for RawNetworkStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            RawNetworkStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            RawNetworkStream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            RawNetworkStream::Tcp(s) => Pin::new(s).poll_flush(cx),
            RawNetworkStream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            RawNetworkStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            RawNetworkStream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// A fully composed inbound connection.
pub enum Stream {
    Raw(RawNetworkStream),
    Ws(Box<WsStream<RawNetworkStream>>),
    Grpc(Box<GrpcStream<RawNetworkStream>>),
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Raw(s) => Pin::new(s).poll_read(cx, buf),
            Stream::Ws(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
            Stream::Grpc(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Stream::Raw(s) => Pin::new(s).poll_write(cx, buf),
            Stream::Ws(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
            Stream::Grpc(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Raw(s) => Pin::new(s).poll_flush(cx),
            Stream::Ws(s) => Pin::new(s.as_mut()).poll_flush(cx),
            Stream::Grpc(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Raw(s) => Pin::new(s).poll_shutdown(cx),
            Stream::Ws(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
            Stream::Grpc(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

impl From<RawNetworkStream> for Stream {
    fn from(r: RawNetworkStream) -> Stream {
        Stream::Raw(r)
    }
}

impl From<TcpStream> for Stream {
    fn from(t: TcpStream) -> Stream {
        Stream::Raw(RawNetworkStream::Tcp(t))
    }
}

impl From<SslStream<TcpStream>> for Stream {
    fn from(s: SslStream<TcpStream>) -> Stream {
        Stream::Raw(RawNetworkStream::Tls(Box::new(s)))
    }
}
