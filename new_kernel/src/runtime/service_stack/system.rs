use std::marker::PhantomData;
use std::sync::Arc;
use parking_lot::RwLock;
use tokio::io::{AsyncRead, AsyncWrite};
use crate::config::KernelConfig;
use crate::pipe::inbound_transport::{InboundList, InboundTransport};
use crate::runtime::dialer::{TcpDialer, UdpDialer};

pub struct SystemService<Dial, InB, Str>
where
    Dial: TcpDialer + UdpDialer,
    InB: InboundTransport<Str>,
    Str: AsyncRead + AsyncWrite + Unpin + Send + Sync
{
    dialer: Dial,
    inbound: InboundList<InB, Str>,
    config: RwLock<Arc<KernelConfig>>,
    _phantom_stream: PhantomData<fn(Str)>
}
