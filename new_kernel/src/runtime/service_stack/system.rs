use crate::config::KernelConfig;
use crate::pipe::inbound_transport::{InboundList, InboundTransport};
use crate::runtime::dialer::{TcpDialer, UdpDialer};
use crate::runtime::service_stack::ReactiveServiceStack;
use std::marker::PhantomData;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;

pub struct SystemService<Dial, InB, Str>
where
    Dial: TcpDialer + UdpDialer,
    InB: InboundTransport<Str>,
    Str: AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
    dialer: Arc<Dial>,
    inbound: InboundList<InB, Str>,
    config: KernelConfig,
    context_update: watch::Receiver<Option<SystemServiceDep<Dial, InB, Str>>>,
    _phantom_stream: PhantomData<fn(Str)>,
}

#[derive(Debug)]
pub struct SystemServiceDep<Dial, InB, Str>
where
    Dial: TcpDialer + UdpDialer,
    InB: InboundTransport<Str>,
    Str: AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
    pub dialer: Arc<Dial>,
    pub config: KernelConfig,
    pub inbound: Arc<[InB]>,
    pub _phantom: PhantomData<fn(Str)>,
}

impl<Dial, InB, Str> ReactiveServiceStack for SystemService<Dial, InB, Str>
where
    Dial: TcpDialer + UdpDialer + Send + Sync,
    InB: InboundTransport<Str> + Send + Sync,
    Str: AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
    type BottomContext = ();
    type TopContext = SystemServiceDep<Dial, InB, Str>;
    fn new(
        _bottom: (),
        top: watch::Receiver<Option<Self::TopContext>>,
    ) -> Result<Self, crate::Error> {
        let update_ref = top.borrow();
        let top_dep = update_ref.as_ref().ok_or(crate::Error::ServiceStack)?;
        Ok(Self {
            dialer: top_dep.dialer.clone(),
            config: top_dep.config.clone(),
            inbound: InboundList::new_with_arc(top_dep.inbound.clone()),
            context_update: top.clone(),
            _phantom_stream: PhantomData,
        })
    }
}

#[derive(Debug, Clone)]
pub struct SystemContext<Dial: TcpDialer + UdpDialer> {
    pub dialer: Arc<Dial>,
    pub config: KernelConfig,
}
