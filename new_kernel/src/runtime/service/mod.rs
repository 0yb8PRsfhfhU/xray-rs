use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use futures::future::BoxFuture;
use tokio_stream::Stream;
use tokio_stream::wrappers::WatchStream;

pub struct ConfigNode<T, C> {
    pub config: Arc<T>,
    pub children: Vec<Arc<C>>
}

pub struct Frame<T, U> {
    pub config: Arc<T>,
    pub parent: Option<Arc<U>>
}

pub enum Slot<S, Req>
    where S: tower::Service<Req>
{
    Updating,
    Ready(S, PhantomData<fn(Req)>)
}

pub struct ChildHandle<S, Req, CS, CReq>
    where
        S: tower::Service<Req>,
        CS: tower::Service<CReq>
{
    stream: WatchStream<Slot<S, Req>>,
    current: Option<CS>,
    _phantom: PhantomData<fn(CReq)>
}
