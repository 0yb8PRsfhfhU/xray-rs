use std::convert::Infallible;
use std::marker::PhantomData;
use std::sync::Arc;
use tokio::task::JoinSet;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::{Stream, StreamExt};

pub trait SimpleService<T: Send> {
    type Output;
    type Error;
    fn call(&self, input: T) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send;
}

#[derive(Debug, Clone)]
pub struct IdenticalFunctor<T>(PhantomData<T>);

impl<T: Send> IdenticalFunctor<T> {
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<I: Send + Sync> SimpleService<I> for IdenticalFunctor<I> {
    type Output = I;
    type Error = Infallible;

    async fn call(&self, input: I) -> Result<Self::Output, Self::Error> {
        Ok(input)
    }
}

#[derive(Debug, Clone)]
pub struct PipedFunction<A, B>(A, B);

impl<A, B> PipedFunction<A, B> {
    pub fn pipe<C>(self, c: C) -> PipedFunction<PipedFunction<A, B>, C> {
        PipedFunction(self, c)
    }
}

impl<I, A> PipedFunction<IdenticalFunctor<I>, A>
where
    A: SimpleService<I> + Sync,
    A::Output: Send,
    A::Error: Send,
    I: Send,
{
    pub fn single(service: A) -> Self {
        Self(IdenticalFunctor::new(), service)
    }
}

impl<I, A, B> SimpleService<I> for PipedFunction<A, B>
where
    A: SimpleService<I> + Sync,
    A::Output: Send,
    A::Error: Send,
    B: SimpleService<A::Output> + Sync,
    B::Error: From<A::Error> + Send,
    B::Output: Send,
    I: Send,
{
    type Output = B::Output;
    type Error = B::Error;

    async fn call(&self, input: I) -> Result<Self::Output, Self::Error> {
        self.1.call(self.0.call(input).await?).await
    }
}

pub struct StreamService<I, One>
where
    One: SimpleService<I> + Sync + 'static,
    One::Output: Send,
    One::Error: Send,
    I: Send,
{
    inner: Arc<One>,
    tasks: JoinSet<Result<One::Output, One::Error>>,
}

impl<I, One> StreamService<I, One>
where
    One: SimpleService<I> + Sync + Send + 'static,
    One::Output: Send,
    One::Error: Send,
    I: Send,
{
    pub fn new(inner: Arc<One>) -> Self {
        Self {
            inner,
            tasks: JoinSet::new(),
        }
    }
    /// Consumes an input stream and produces a stream of results.
    ///
    /// Each input item is dispatched to `inner` on its own task, and results
    /// are yielded in completion order (not input order) as the tasks finish.
    /// New inputs keep being spawned while earlier results are still pending,
    /// so work runs concurrently; the bounded result channel applies
    /// backpressure when the consumer falls behind.
    pub fn serve<S>(self, mut stream: S) -> ReceiverStream<Result<One::Output, One::Error>>
    where
        S: Stream<Item = I> + Unpin + Send + 'static,
        One::Output: 'static,
        One::Error: 'static,
        I: 'static,
    {
        const CHANNEL_BUFFER: usize = 256;
        let Self { inner, mut tasks } = self;
        let (tx, rx) = tokio::sync::mpsc::channel(CHANNEL_BUFFER);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    // Input still open: pull the next item and spawn its task.
                    next = stream.next() => match next {
                        Some(item) => {
                            let inner = Arc::clone(&inner);
                            tasks.spawn(async move { inner.call(item).await });
                        }
                        // Input exhausted: drain remaining tasks, then stop.
                        None => break,
                    },
                    // A task finished: forward its result downstream.
                    Some(joined) = tasks.join_next() => {
                        // Join error (panic/cancel): skip it.
                        if let Ok(result) = joined {
                            // Consumer dropped the stream: nothing left to do.
                            if tx.send(result).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            }
            while let Some(joined) = tasks.join_next().await {
                if let Ok(result) = joined {
                    if tx.send(result).await.is_err() {
                        return;
                    }
                }
            }
        });
        ReceiverStream::new(rx)
    }
}
