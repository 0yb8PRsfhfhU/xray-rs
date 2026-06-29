use std::convert::Infallible;
use std::marker::PhantomData;
use tokio::task::JoinSet;

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
    inner: One,
    tasks: JoinSet<Result<One::Output, One::Error>>,
}

impl<I, One> StreamService<I, One>
where
    One: SimpleService<I> + Sync + Send + 'static,
    One::Output: Send,
    One::Error: Send,
    I: Send,
{
    pub fn new(inner: One) -> Self {
        Self {
            inner,
            tasks: JoinSet::new(),
        }
    }
}
