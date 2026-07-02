//! The [`Outbound`] seam: dial the target and pump the [`Link`] (objective
//! requirement 1; SPEC §1 `OutboundHandler`).
//!
//! An outbound receives the outbound-facing half of the proxy's [`Link`] plus a
//! target [`Destination`], dials through a generic [`Dialer`] (never a trait
//! object, SPEC §P1), and copies bytes both ways. `kernel` provides the trait
//! and the tag-keyed set, not the concrete `freedom`/`blackhole` bodies.

use std::io;
use std::sync::Arc;

use compact_str::CompactString;

use crate::net::Destination;
use crate::pipe::pipe::Link;
use crate::rcu::RcuCell;
use crate::runtime::dialer::Dialer;
use crate::runtime::session::Ctx;

/// The outbound (egress) seam. Generic over the [`Dialer`] so a TLS/WS/mux
/// dialer can be substituted without changing the outbound (SPEC §P1).
pub trait Outbound: Send + Sync + 'static {
    /// Dial `target` and relay the [`Link`] to it until either side closes.
    fn process<D: Dialer>(
        &self,
        ctx: &Ctx,
        target: Destination,
        link: Link,
        dialer: &D,
    ) -> impl Future<Output = io::Result<()>> + Send;
}

/// A tag-keyed, RCU-published set of outbounds (objective requirement 5: every
/// outbound has a readable tag). Reload rebuilds the map and swaps the pointer
/// (SPEC §P2); the router resolves a tag to an `Arc<O>` with an `O(1)` lookup.
#[derive(Debug)]
pub struct OutboundList<O>(RcuCell<OutboundMap<O>>);

#[derive(Debug)]
pub struct OutboundMap<O> {
    by_tag: std::collections::HashMap<CompactString, Arc<O>>,
}

impl<O> OutboundMap<O> {
    pub fn get(&self, tag: &str) -> Option<Arc<O>> {
        self.by_tag.get(tag).cloned()
    }
    pub fn contains(&self, tag: &str) -> bool {
        self.by_tag.contains_key(tag)
    }
    pub fn len(&self) -> usize {
        self.by_tag.len()
    }
    pub fn is_empty(&self) -> bool {
        self.by_tag.is_empty()
    }
}

impl<O> OutboundList<O> {
    fn build(items: impl IntoIterator<Item = (CompactString, O)>) -> OutboundMap<O> {
        OutboundMap {
            by_tag: items
                .into_iter()
                .map(|(tag, o)| (tag, Arc::new(o)))
                .collect(),
        }
    }

    pub fn new(items: impl IntoIterator<Item = (CompactString, O)>) -> Self {
        Self(RcuCell::new(Self::build(items)))
    }

    /// Cheap snapshot of the current outbound map.
    pub fn load(&self) -> Arc<OutboundMap<O>> {
        self.0.load()
    }

    /// Resolve a tag to an outbound in the current snapshot.
    pub fn get(&self, tag: &str) -> Option<Arc<O>> {
        self.0.load().get(tag)
    }

    /// Publish a new outbound set atomically.
    pub fn replace(&self, items: impl IntoIterator<Item = (CompactString, O)>) {
        self.0.store(Self::build(items));
    }
}
