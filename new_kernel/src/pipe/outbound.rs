use bytes::Bytes;
use tokio_stream::Stream;
use tokio_stream::wrappers::UnboundedReceiverStream;

pub trait OutboundLink {
    fn handle_connection(
        &self,
        inc: impl Stream<Item = Bytes>,
    ) -> impl Future<Output = UnboundedReceiverStream<Bytes>>;
}
