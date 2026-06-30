use crate::function_util::SimpleService;
use std::pin::Pin;
use std::sync::mpsc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};

pub struct InboundConnection<T: AsyncRead + AsyncWrite + Unpin>(T);

impl<T: AsyncRead + AsyncWrite + Unpin> InboundConnection<T> {
    pub fn new(inner: T) -> Self {
        Self(inner)
    }

    pub fn split(self) -> TransportStreamSplit<T> {
        let (read_half, write_half) = tokio::io::split(self.0);
        TransportStreamSplit {
            read_half,
            write_half,
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for InboundConnection<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let inner = &mut self.get_mut().0;
        Pin::new(inner).poll_read(cx, buf)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for InboundConnection<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let inner = &mut self.get_mut().0;
        Pin::new(inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let inner = &mut self.get_mut().0;
        Pin::new(inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let inner = &mut self.get_mut().0;
        Pin::new(inner).poll_shutdown(cx)
    }
}

pub struct TransportStream<T: AsyncRead + AsyncWrite + Unpin>(T);

impl<T: AsyncRead + AsyncWrite + Unpin> TransportStream<T> {
    pub fn split(self) -> TransportStreamSplit<T> {
        let (read_half, write_half) = tokio::io::split(self.0);
        TransportStreamSplit {
            read_half,
            write_half,
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for TransportStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let inner = &mut self.get_mut().0;
        Pin::new(inner).poll_read(cx, buf)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TransportStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let inner = &mut self.get_mut().0;
        Pin::new(inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let inner = &mut self.get_mut().0;
        Pin::new(inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let inner = &mut self.get_mut().0;
        Pin::new(inner).poll_shutdown(cx)
    }
}

pub struct TransportStreamSplit<T: AsyncRead + AsyncWrite> {
    pub read_half: ReadHalf<T>,
    pub write_half: WriteHalf<T>,
}

pub enum Accepted<T: AsyncRead + AsyncWrite + Unpin> {
    Single(TransportStream<T>),
    Multiplexed(mpsc::Receiver<TransportStream<T>>),
}

pub trait InboundTransport<T: AsyncRead + AsyncWrite + Unpin + Send>:
    SimpleService<
        InboundConnection<T>,
        Output = TransportStream<Self::StreamTy>,
        Error = std::io::Error,
    >
{
    type StreamTy: AsyncRead + AsyncWrite + Unpin;
}
