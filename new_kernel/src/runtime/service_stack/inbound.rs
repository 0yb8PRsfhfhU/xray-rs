use crate::pipe::inbound_transport::{InboundList, InboundTransport};
use crate::runtime::dialer::{TcpDialer, UdpDialer};
use crate::runtime::service_stack::system::SystemContext;
use std::marker::PhantomData;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;

#[derive(Debug, Clone)]
pub struct InboundTransportService<SysDial, InB, Stream>
where
    SysDial: TcpDialer + UdpDialer + Send + Sync,
    InB: InboundTransport<Stream>,
    Stream: AsyncRead + AsyncWrite + Unpin + Send,
{
    system_context: SystemContext<SysDial>,
    inbound_context: InboundContext<InB, Stream>,
    context_update: watch::Receiver<Option<InboundContext<InB, Stream>>>,
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
