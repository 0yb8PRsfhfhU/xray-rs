//! React-`useContext`-style context propagation (objective requirement 4).
//!
//! A parent service owns the sender and publishes a context value `T`; every
//! descendant holds a [`ContextHandle`] (a wrapped [`watch::Receiver`]) and
//! reads the latest value or awaits the next change. This is how a parent node
//! stays *transparent* to its children while still handing them cross-cutting
//! state (a SaaS layer's tenant info, a rate limiter, a shared clock) — the
//! child depends only on `ContextHandle<T>`, not on which parent supplied it.

use tokio::sync::watch;

/// The context provider: owned by the service that supplies context `T`.
///
/// Dropping the provider is fine — outstanding [`ContextHandle`]s keep serving
/// the last published value (`watch` semantics), so a mid-reload parent swap
/// never strands a child.
#[derive(Debug)]
pub struct ContextProvider<T> {
    tx: watch::Sender<T>,
}

impl<T> ContextProvider<T> {
    /// Create a provider seeded with `initial`.
    pub fn new(initial: T) -> Self {
        Self {
            tx: watch::channel(initial).0,
        }
    }

    /// Publish a new context value to every descendant handle.
    pub fn publish(&self, value: T) {
        // Ignore the "no receivers" error: a provider with no current children
        // still holds the value for handles created later via `handle()`.
        let _ = self.tx.send(value);
    }

    /// Mutate the context in place and notify descendants.
    pub fn update(&self, f: impl FnOnce(&mut T)) {
        self.tx.send_modify(f);
    }

    /// Hand a fresh [`ContextHandle`] to a child.
    pub fn handle(&self) -> ContextHandle<T> {
        ContextHandle {
            rx: self.tx.subscribe(),
        }
    }

    /// Number of live descendant handles (diagnostics/tests).
    pub fn handle_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

/// A child's view of a context value published by an ancestor.
#[derive(Debug, Clone)]
pub struct ContextHandle<T> {
    rx: watch::Receiver<T>,
}

impl<T: Clone> ContextHandle<T> {
    /// Read the current context value (`useContext`). Clones the latest value.
    pub fn use_context(&self) -> T {
        self.rx.borrow().clone()
    }
}

impl<T> ContextHandle<T> {
    /// Read the current value under a borrow guard, without cloning.
    pub fn borrow(&self) -> watch::Ref<'_, T> {
        self.rx.borrow()
    }

    /// Await the next change to the context, then return a borrow of the new
    /// value. Errors only if every provider has been dropped.
    pub async fn changed(&mut self) -> Result<watch::Ref<'_, T>, watch::error::RecvError> {
        self.rx.changed().await?;
        Ok(self.rx.borrow_and_update())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn use_context_reads_latest_published_value() {
        let provider = ContextProvider::new(1u32);
        let child = provider.handle();
        assert_eq!(child.use_context(), 1);
        provider.publish(42);
        assert_eq!(child.use_context(), 42, "child sees the published value");
    }

    #[test]
    fn update_mutates_in_place() {
        let provider = ContextProvider::new(vec![1, 2, 3]);
        let child = provider.handle();
        provider.update(|v| v.push(4));
        assert_eq!(child.use_context(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn handle_survives_provider_drop() {
        let provider = ContextProvider::new("hello");
        let child = provider.handle();
        drop(provider);
        // watch keeps the last value alive for outstanding handles.
        assert_eq!(child.use_context(), "hello");
    }

    #[tokio::test]
    async fn changed_awaits_next_publish() {
        let provider = ContextProvider::new(0u32);
        let mut child = provider.handle();
        provider.publish(7);
        let v = child.changed().await.unwrap();
        assert_eq!(*v, 7);
    }

    #[test]
    fn multiple_children_all_observe() {
        let provider = ContextProvider::new(0u8);
        let a = provider.handle();
        let b = provider.handle();
        assert_eq!(provider.handle_count(), 2);
        provider.publish(9);
        assert_eq!(a.use_context(), 9);
        assert_eq!(b.use_context(), 9);
    }
}
