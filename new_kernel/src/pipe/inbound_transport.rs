use crate::rcu_helper::RcuCell;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::{Arc, mpsc};
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

pub trait InboundTransport<T: AsyncRead + AsyncWrite + Unpin + Send> {
    type StreamTy: AsyncRead + AsyncWrite + Unpin;
    fn call(
        &self,
        conn: InboundConnection<T>,
    ) -> impl Future<Output = std::io::Result<Accepted<Self::StreamTy>>> + Send;
}

pub struct InboundList<T: InboundTransport<Str>, Str>(RcuCell<[T]>, PhantomData<fn(Str)>)
where
    Str: AsyncRead + AsyncWrite + Unpin + Send;

impl<T, Str> InboundList<T, Str>
where
    T: InboundTransport<Str>,
    Str: AsyncRead + AsyncWrite + Unpin + Send,
{
    pub fn new(inner: impl IntoIterator<Item = T>) -> Self {
        Self(
            RcuCell::from_arc(inner.into_iter().collect::<Arc<[T]>>()),
            PhantomData,
        )
    }
    pub fn new_with_arc(inner: Arc<[T]>) -> Self {
        Self(RcuCell::from_arc(inner), PhantomData)
    }
    pub fn read(&self) -> Arc<[T]> {
        self.0.read_owned()
    }
    pub fn update(&self, new: impl IntoIterator<Item = T>) {
        self.0.swap_arc(new.into_iter().collect::<Arc<[T]>>());
    }
}

#[derive(Debug, Clone)]
pub struct InboundContext<T, Str>
where
    T: InboundTransport<Str>,
    Str: AsyncRead + AsyncWrite + Unpin + Send,
{
    pub list: Arc<[T]>,
    pub index: usize,
    pub _phantom: PhantomData<InboundList<T, Str>>,
}
