//! The `tower::Service` config↔service tree (objective requirement 4).
//!
//! Every node in the runtime is a [`tower::Service`]. A node's config is an
//! `Arc<C>`; the isomorphic service subtree is wrapped in a [`SwappableService`]
//! fed by a [`watch`] channel, and its controller is a [`SwapHandle`]. On a
//! config-tree update the owner diffs each [`Node`] against the new config and
//! calls [`SwapHandle::update`] **only** where the config actually changed
//! (diff-and-swap); unchanged subtrees keep serving without interruption.
//!
//! During a swap the node publishes [`Slot::Updating`], so its `poll_ready`
//! reports `Pending` — this is the accepted "not ready after update" window
//! (objective requirement 4). The [`UpdatePolicy`] chooses whether in-flight
//! work is [`aborted`](UpdatePolicy::Abort) (the generation's
//! [`CancellationToken`] is cancelled) or [`drained`](UpdatePolicy::Drain)
//! (left to finish against the old snapshot).
//!
//! Parents are *transparent* to children: a child depends only on its own
//! request/response and on a [`ContextHandle`](crate::runtime::context) it is
//! handed, never on which parent supplied it — so a SaaS deployment can splice
//! extra layers between two nodes without the child noticing.

use std::sync::Arc;
use std::task::{Context, Poll};

use compact_str::CompactString;
use futures::StreamExt;
use futures::future::{Either, Ready, ready};
use tokio::sync::watch;
use tokio_stream::wrappers::WatchStream;
use tokio_util::sync::CancellationToken;
use tower::Service;

/// A service slot published over the node's [`watch`] channel.
#[derive(Debug, Clone)]
pub enum Slot<S> {
    /// A swap is in progress; the node is deliberately not ready.
    Updating,
    /// The current live service.
    Ready(S),
}

/// How in-flight work is treated when a node is swapped (objective req. 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdatePolicy {
    /// Cancel the outgoing generation's [`CancellationToken`], interrupting
    /// tasks that race it.
    Abort,
    /// Leave in-flight tasks running against their old snapshot; only new work
    /// picks up the new service.
    Drain,
}

/// An error that can represent "the service is mid-swap and not ready". Lets
/// [`SwappableService::call`] stay panic-free (SPEC §P7) if it is ever called
/// during the not-ready window instead of fabricating an inner future.
pub trait NotReady {
    fn not_ready() -> Self;
}

impl NotReady for crate::Error {
    fn not_ready() -> Self {
        crate::Error::ServiceStack
    }
}

impl NotReady for std::io::Error {
    fn not_ready() -> Self {
        std::io::Error::new(std::io::ErrorKind::WouldBlock, "service updating")
    }
}

/// A `tower::Service` whose inner service can be atomically hot-swapped.
///
/// Wraps a [`watch`] receiver of [`Slot`]s. `poll_ready` drains the channel to
/// the latest slot: [`Slot::Ready`] caches the service and polls it; while
/// [`Slot::Updating`] (or after the sender is dropped) it reports `Pending`,
/// re-armed by the receiver so a later publish wakes it.
pub struct SwappableService<S: Clone + Send + Sync + 'static> {
    rx: watch::Receiver<Slot<S>>,
    stream: WatchStream<Slot<S>>,
    ready: Option<S>,
}

impl<S: Clone + Send + Sync + 'static> SwappableService<S> {
    fn from_receiver(rx: watch::Receiver<Slot<S>>) -> Self {
        let stream = WatchStream::new(rx.clone());
        SwappableService {
            rx,
            stream,
            ready: None,
        }
    }
}

impl<S: Clone + Send + Sync + 'static> Clone for SwappableService<S> {
    fn clone(&self) -> Self {
        // Re-subscribe so the clone gets its own change notifications, seeded
        // with the current value.
        SwappableService::from_receiver(self.rx.clone())
    }
}

impl<S, Req> Service<Req> for SwappableService<S>
where
    S: Service<Req> + Clone + Send + Sync + 'static,
    S::Error: NotReady,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Either<S::Future, Ready<Result<S::Response, S::Error>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Drain to the newest published slot; the last Pending re-arms the waker.
        loop {
            match self.stream.poll_next_unpin(cx) {
                Poll::Ready(Some(Slot::Ready(s))) => self.ready = Some(s),
                Poll::Ready(Some(Slot::Updating)) => self.ready = None,
                Poll::Ready(None) => {
                    // Sender dropped: no further updates. Keep serving the last
                    // ready service if we have one; otherwise stay not-ready.
                    break;
                }
                Poll::Pending => break,
            }
        }
        match &mut self.ready {
            Some(inner) => inner.poll_ready(cx),
            None => Poll::Pending,
        }
    }

    fn call(&mut self, req: Req) -> Self::Future {
        match self.ready.clone() {
            Some(mut inner) => Either::Left(inner.call(req)),
            // Contract: `call` follows a `Ready(Ok)` from `poll_ready`, so this
            // arm is unreachable in correct use. Stay panic-free regardless.
            None => Either::Right(ready(Err(S::Error::not_ready()))),
        }
    }
}

/// The controller side of a [`SwappableService`]: publishes new services and
/// owns the current generation's [`CancellationToken`].
pub struct SwapHandle<S> {
    tx: watch::Sender<Slot<S>>,
    policy: UpdatePolicy,
    token: CancellationToken,
}

impl<S: Clone + Send + Sync + 'static> SwapHandle<S> {
    /// Create a handle seeded with `initial`, plus a fresh [`SwappableService`]
    /// already serving it.
    pub fn new(initial: S, policy: UpdatePolicy) -> (SwapHandle<S>, SwappableService<S>) {
        let (tx, rx) = watch::channel(Slot::Ready(initial));
        let handle = SwapHandle {
            tx,
            policy,
            token: CancellationToken::new(),
        };
        let service = SwappableService::from_receiver(rx);
        (handle, service)
    }

    /// The current generation's cancellation token. Children spawn their
    /// per-connection tasks under a clone (or [`child_token`](CancellationToken::child_token))
    /// so an [`UpdatePolicy::Abort`] swap interrupts them.
    pub fn token(&self) -> CancellationToken {
        self.token.clone()
    }

    /// Hot-swap the live service to `new`.
    ///
    /// Opens the not-ready window ([`Slot::Updating`]), applies the
    /// [`UpdatePolicy`] to the outgoing generation (abort → cancel its token;
    /// drain → leave it running), rolls a new generation token, then publishes
    /// the new service. Returns `false` if every consumer has been dropped.
    pub fn update(&mut self, new: S) -> bool {
        if self.tx.send(Slot::Updating).is_err() {
            return false;
        }
        if self.policy == UpdatePolicy::Abort {
            self.token.cancel();
        }
        // New generation gets a fresh token regardless of policy.
        self.token = CancellationToken::new();
        self.tx.send(Slot::Ready(new)).is_ok()
    }

    /// Number of live [`SwappableService`] consumers (diagnostics/tests).
    pub fn consumer_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

/// One node of the config↔service tree: an `Arc<C>` config paired with the
/// [`SwapHandle`] that publishes the service built from it, plus the builder.
///
/// [`reconfigure`](Node::reconfigure) is the per-node diff step: it rebuilds and
/// swaps **only** when the new config differs from the current one (objective
/// requirement 4's "update only the sub-services that need updating"). Applied
/// across the isomorphic tree, the diff naturally touches only changed subtrees.
pub struct Node<C, S, F>
where
    C: PartialEq,
    S: Clone + Send + Sync + 'static,
    F: Fn(&C) -> S,
{
    config: Arc<C>,
    handle: SwapHandle<S>,
    build: F,
}

impl<C, S, F> Node<C, S, F>
where
    C: PartialEq,
    S: Clone + Send + Sync + 'static,
    F: Fn(&C) -> S,
{
    /// Build a node from an initial config and a builder, returning the node and
    /// the live [`SwappableService`] the parent delegates to.
    pub fn new(
        config: Arc<C>,
        policy: UpdatePolicy,
        build: F,
    ) -> (Node<C, S, F>, SwappableService<S>) {
        let service = build(&config);
        let (handle, swappable) = SwapHandle::new(service, policy);
        (
            Node {
                config,
                handle,
                build,
            },
            swappable,
        )
    }

    /// The current config snapshot.
    pub fn config(&self) -> &Arc<C> {
        &self.config
    }

    /// This node's cancellation token (see [`SwapHandle::token`]).
    pub fn token(&self) -> CancellationToken {
        self.handle.token()
    }

    /// Diff `new` against the current config; if it changed, rebuild the service
    /// and hot-swap it in. Returns `true` iff a swap happened.
    pub fn reconfigure(&mut self, new: Arc<C>) -> bool {
        if *self.config == *new {
            return false; // no change: leave the subtree untouched
        }
        let service = (self.build)(&new);
        self.config = new;
        self.handle.update(service)
    }
}

/// The outcome of reconciling a [`KeyedTree`] against a new config set: which
/// keyed children were added, swapped, dropped, or left untouched.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Reconcile {
    pub added: Vec<CompactString>,
    pub updated: Vec<CompactString>,
    pub removed: Vec<CompactString>,
    pub unchanged: Vec<CompactString>,
}

/// A keyed set of [`Node`]s — the *set* analogue of a single [`Node`], for a
/// dynamic collection of same-shaped children (e.g. one per inbound tag, or one
/// per outbound tag). [`reconcile`](KeyedTree::reconcile) diffs a new config map
/// against the live set and touches only what changed (objective requirement 4:
/// "update only the sub-services that need updating"): unchanged keys keep
/// serving uninterrupted, changed keys hot-swap, new keys are built, and removed
/// keys are dropped (which ends their `watch`, letting their service drain).
pub struct KeyedTree<C, S, F>
where
    C: PartialEq,
    S: Clone + Send + Sync + 'static,
    F: Fn(&str, &C) -> S,
{
    nodes: std::collections::HashMap<CompactString, Node<C, S, BuildFor<C, S>>>,
    services: std::collections::HashMap<CompactString, SwappableService<S>>,
    build: F,
    policy: UpdatePolicy,
}

/// Per-node builder stored inside a [`KeyedTree`] node: closes over the key so
/// each node rebuilds with its own key on reconfigure.
type BuildFor<C, S> = Box<dyn Fn(&C) -> S + Send + Sync>;

impl<C, S, F> KeyedTree<C, S, F>
where
    C: PartialEq + Send + Sync + 'static,
    S: Clone + Send + Sync + 'static,
    F: Fn(&str, &C) -> S + Clone + Send + Sync + 'static,
{
    /// An empty tree; `build(key, config) -> service` constructs each child.
    pub fn new(policy: UpdatePolicy, build: F) -> Self {
        KeyedTree {
            nodes: std::collections::HashMap::new(),
            services: std::collections::HashMap::new(),
            build,
            policy,
        }
    }

    /// The live service for `key`, if present. Clone it to delegate to.
    pub fn service(&self, key: &str) -> Option<SwappableService<S>> {
        self.services.get(key).cloned()
    }

    /// Reconcile the live set against `new_configs`. Returns the [`Reconcile`]
    /// classification. Keys absent from `new_configs` are removed; new keys are
    /// built; shared keys diff-and-swap only when their config changed.
    pub fn reconcile(
        &mut self,
        new_configs: impl IntoIterator<Item = (CompactString, Arc<C>)>,
    ) -> Reconcile {
        let mut report = Reconcile::default();
        let mut seen: std::collections::HashSet<CompactString> = std::collections::HashSet::new();

        for (key, cfg) in new_configs {
            seen.insert(key.clone());
            match self.nodes.get_mut(key.as_str()) {
                Some(node) => {
                    if node.reconfigure(cfg) {
                        report.updated.push(key);
                    } else {
                        report.unchanged.push(key);
                    }
                }
                None => {
                    let build = self.build.clone();
                    let k = key.clone();
                    let per_node: BuildFor<C, S> = Box::new(move |c: &C| build(k.as_str(), c));
                    let (node, svc) = Node::new(cfg, self.policy, per_node);
                    self.nodes.insert(key.clone(), node);
                    self.services.insert(key.clone(), svc);
                    report.added.push(key);
                }
            }
        }

        // Drop keys no longer present (their watch ends -> consumers see EOF).
        let stale: Vec<CompactString> = self
            .nodes
            .keys()
            .filter(|k| !seen.contains(k.as_str()))
            .cloned()
            .collect();
        for key in stale {
            self.nodes.remove(key.as_str());
            self.services.remove(key.as_str());
            report.removed.push(key);
        }
        report
    }

    /// Number of live keyed children.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    /// A trivial tower service: adds `delta` to its input.
    #[derive(Clone)]
    struct Adder {
        delta: i64,
    }

    impl Service<i64> for Adder {
        type Response = i64;
        type Error = crate::Error;
        type Future = Ready<Result<i64, crate::Error>>;
        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: i64) -> Self::Future {
            ready(Ok(req + self.delta))
        }
    }

    async fn call<S: Service<i64>>(svc: &mut S) -> Result<S::Response, S::Error> {
        futures::future::poll_fn(|cx| svc.poll_ready(cx)).await?;
        svc.call(7).await
    }

    #[tokio::test]
    async fn swappable_serves_then_updates() {
        let (mut handle, mut svc) = SwapHandle::new(Adder { delta: 1 }, UpdatePolicy::Drain);
        assert_eq!(call(&mut svc).await.unwrap(), 8);

        assert!(handle.update(Adder { delta: 100 }));
        // Give the watch a moment to propagate to the stream.
        tokio::task::yield_now().await;
        assert_eq!(call(&mut svc).await.unwrap(), 107);
    }

    #[tokio::test]
    async fn node_reconfigure_only_swaps_on_change() {
        let builds = Arc::new(AtomicU32::new(0));
        let b = builds.clone();
        let (mut node, mut svc) = Node::new(Arc::new(5i64), UpdatePolicy::Drain, move |c| {
            b.fetch_add(1, Ordering::SeqCst);
            Adder { delta: *c }
        });
        assert_eq!(builds.load(Ordering::SeqCst), 1); // initial build
        assert_eq!(call(&mut svc).await.unwrap(), 12);

        // Same config -> no rebuild, no swap.
        assert!(!node.reconfigure(Arc::new(5i64)));
        assert_eq!(builds.load(Ordering::SeqCst), 1);

        // Changed config -> rebuild + swap.
        assert!(node.reconfigure(Arc::new(50i64)));
        assert_eq!(builds.load(Ordering::SeqCst), 2);
        tokio::task::yield_now().await;
        assert_eq!(call(&mut svc).await.unwrap(), 57);
    }

    #[tokio::test]
    async fn abort_policy_cancels_inflight() {
        let (mut handle, _svc) = SwapHandle::new(Adder { delta: 0 }, UpdatePolicy::Abort);
        let token = handle.token();
        // A task spawned under the current generation's token.
        let jh = tokio::spawn(async move {
            token.cancelled().await;
            "aborted"
        });
        assert!(handle.update(Adder { delta: 1 }));
        // The Abort swap cancelled the old generation token -> task wakes.
        let out = tokio::time::timeout(Duration::from_secs(1), jh)
            .await
            .expect("task should finish after abort")
            .unwrap();
        assert_eq!(out, "aborted");
    }

    #[tokio::test]
    async fn drain_policy_leaves_inflight_running() {
        let (mut handle, _svc) = SwapHandle::new(Adder { delta: 0 }, UpdatePolicy::Drain);
        let token = handle.token();
        assert!(handle.update(Adder { delta: 1 }));
        // Drain did NOT cancel the old token.
        assert!(!token.is_cancelled());
    }

    #[tokio::test]
    async fn keyed_tree_reconcile_diffs_add_update_remove_unchanged() {
        let builds = Arc::new(AtomicU32::new(0));
        let b = builds.clone();
        let mut tree: KeyedTree<i64, Adder, _> =
            KeyedTree::new(UpdatePolicy::Drain, move |_key, c: &i64| {
                b.fetch_add(1, Ordering::SeqCst);
                Adder { delta: *c }
            });

        // Initial set: a=1, b=2.
        let r = tree.reconcile([
            (CompactString::from("a"), Arc::new(1i64)),
            (CompactString::from("b"), Arc::new(2i64)),
        ]);
        assert_eq!(r.added.len(), 2);
        assert_eq!(tree.len(), 2);
        assert_eq!(builds.load(Ordering::SeqCst), 2);

        // "a" service works.
        let mut svc_a = tree.service("a").unwrap();
        assert_eq!(call(&mut svc_a).await.unwrap(), 8); // 7 + 1

        // Reconcile: a unchanged (1), b changed (2->20), c added (3), (b removed? no).
        let r = tree.reconcile([
            (CompactString::from("a"), Arc::new(1i64)),  // unchanged
            (CompactString::from("b"), Arc::new(20i64)), // updated
            (CompactString::from("c"), Arc::new(3i64)),  // added
        ]);
        assert_eq!(r.unchanged, vec![CompactString::from("a")]);
        assert_eq!(r.updated, vec![CompactString::from("b")]);
        assert_eq!(r.added, vec![CompactString::from("c")]);
        assert!(r.removed.is_empty());

        // "b" was rebuilt with delta 20; its live service reflects the swap.
        let mut svc_b = tree.service("b").unwrap();
        tokio::task::yield_now().await;
        assert_eq!(call(&mut svc_b).await.unwrap(), 27); // 7 + 20

        // Reconcile down to just "c": a and b removed.
        let r = tree.reconcile([(CompactString::from("c"), Arc::new(3i64))]);
        assert_eq!(r.removed.len(), 2);
        assert_eq!(tree.len(), 1);
        assert!(tree.service("a").is_none());
    }
}
