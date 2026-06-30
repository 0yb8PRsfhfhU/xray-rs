use tokio::sync::watch;

pub mod inbound;
pub mod outbound;
pub mod proxy;
pub mod system;

pub trait ReactiveServiceStack: Send + Sync + Sized {
    type BottomContext;
    type TopContext;
    fn new(
        bottom: Self::BottomContext,
        top: watch::Receiver<Option<Self::TopContext>>,
    ) -> Result<Self, crate::Error>;
}

pub trait ParentService<SubService: ReactiveServiceStack>:
    Send + Sync + ReactiveServiceStack
{
    type Requirement;
    fn everything_lower(&self) -> SubService::BottomContext;
    fn provide_layer(
        &self,
        req: Self::Requirement,
    ) -> (
        SubService::TopContext,
        watch::Receiver<Option<SubService::TopContext>>,
    );
}
