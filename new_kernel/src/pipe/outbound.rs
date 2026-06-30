use crate::rcu_helper::RcuCell;
use bytes::Bytes;
use std::sync::Arc;
use tokio_stream::Stream;
use tokio_stream::wrappers::UnboundedReceiverStream;

pub trait OutboundLink {
    fn handle_connection(
        &self,
        inc: impl Stream<Item = Bytes>,
    ) -> impl Future<Output = UnboundedReceiverStream<Bytes>>;
}

pub struct OutboundList<T>(RcuCell<[T]>)
where
    T: OutboundLink;

impl<T> OutboundList<T>
where
    T: OutboundLink,
{
    pub fn new(items: impl IntoIterator<Item = T>) -> Self {
        let items = items.into_iter().collect();
        Self(RcuCell::from_arc(items))
    }
    pub fn read(&self) -> Arc<[T]> {
        self.0.read_owned()
    }
    pub fn update(&self, items: impl IntoIterator<Item = T>) {
        self.0.swap_arc(items.into_iter().collect());
    }
}
