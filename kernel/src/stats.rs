//! Per-user traffic accounting for the SaaS panel integration.
//!
//! The hot per-byte path uses lock-free [`Counter`] atomics resolved once at
//! connection setup. The [`Stats`] registry (tag → counter) is guarded by a
//! plain mutex, taken only at connection setup and at reporting time — never on
//! the per-byte data path (SPEC §P2: no locks on the data path).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use compact_str::CompactString;
use tokio::sync::RwLock;

/// Lock-free upload/download byte counter for a single user.
#[derive(Debug, Default)]
pub struct Counter {
    up: AtomicU64,
    down: AtomicU64,
    dirty: AtomicU64,
    tag: CompactString,
    active: Option<Arc<Mutex<HashSet<CompactString>>>>,
}

impl Counter {
    fn new(tag: CompactString, active: Arc<Mutex<HashSet<CompactString>>>) -> Counter {
        Counter {
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
            dirty: AtomicU64::new(0),
            tag,
            active: Some(active),
        }
    }

    fn mark_active(&self) {
        if self
            .dirty
            .compare_exchange(0, 1, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
            && let Some(active) = &self.active
            && let Ok(mut guard) = active.lock()
        {
            guard.insert(self.tag.clone());
        }
    }

    /// Add `n` bytes to the upload (client → target) total.
    pub fn add_up(&self, n: u64) {
        if n > 0 {
            self.mark_active();
        }
        self.up.fetch_add(n, Ordering::Relaxed);
    }

    /// Add `n` bytes to the download (target → client) total.
    pub fn add_down(&self, n: u64) {
        if n > 0 {
            self.mark_active();
        }
        self.down.fetch_add(n, Ordering::Relaxed);
    }

    /// Current upload total.
    pub fn up(&self) -> u64 {
        self.up.load(Ordering::Relaxed)
    }

    /// Current download total.
    pub fn down(&self) -> u64 {
        self.down.load(Ordering::Relaxed)
    }

    /// Atomically read and zero both directions for a reporting cycle.
    pub fn take(&self) -> (u64, u64) {
        self.dirty.store(0, Ordering::Relaxed);
        (
            self.up.swap(0, Ordering::Relaxed),
            self.down.swap(0, Ordering::Relaxed),
        )
    }

    /// Add counts back after a failed report so traffic is not lost.
    pub fn restore(&self, up: u64, down: u64) {
        if up > 0 || down > 0 {
            self.mark_active();
        }
        self.up.fetch_add(up, Ordering::Relaxed);
        self.down.fetch_add(down, Ordering::Relaxed);
    }
}

/// Registry of per-user [`Counter`]s, keyed by the full user tag
/// (`{inbound_tag}|{email}|{uid}`, matching XrayR's traffic counter names).
#[derive(Debug, Default)]
pub struct Stats {
    users: RwLock<HashMap<CompactString, Arc<Counter>>>,
    active: Arc<Mutex<HashSet<CompactString>>>,
}

impl Stats {
    pub fn new() -> Stats {
        Stats::default()
    }

    /// Get (or create) the counter for `tag`.
    pub async fn counter(&self, tag: &str) -> Arc<Counter> {
        let mut guard = self.users.write().await;
        if let Some(c) = guard.get(tag) {
            return c.clone();
        }
        let tag = CompactString::new(tag);
        let c = Arc::new(Counter::new(tag.clone(), self.active.clone()));
        guard.insert(tag, c.clone());
        c
    }

    /// Look up an existing counter without creating one.
    pub async fn get(&self, tag: &str) -> Option<Arc<Counter>> {
        self.users.read().await.get(tag).cloned()
    }

    /// Drop a user's counter (on user removal).
    pub async fn remove(&self, tag: &str) {
        self.users.write().await.remove(tag);
        if let Ok(mut active) = self.active.lock() {
            active.remove(tag);
        }
    }

    /// Drain counters that have seen traffic since the previous reporting cycle.
    pub async fn active_counters(&self) -> Vec<(CompactString, Arc<Counter>)> {
        let tags = match self.active.lock() {
            Ok(mut active) => active.drain().collect::<Vec<_>>(),
            Err(_) => Vec::new(),
        };
        let guard = self.users.read().await;
        let mut out = Vec::with_capacity(tags.len());
        for tag in tags {
            if let Some(counter) = guard.get(&tag) {
                out.push((tag, counter.clone()));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::Stats;

    #[tokio::test]
    async fn active_counters_only_returns_dirty_counters_once() {
        let stats = Stats::new();
        let active = stats.counter("node|active|1").await;
        let _inactive = stats.counter("node|inactive|2").await;

        assert!(stats.active_counters().await.is_empty());

        active.add_up(42);
        let first = stats.active_counters().await;
        assert_eq!(first.len(), 1);
        assert!(first.iter().any(|(tag, _)| tag == "node|active|1"));
        assert!(stats.active_counters().await.is_empty());
    }

    #[tokio::test]
    async fn restored_counter_becomes_active_again() {
        let stats = Stats::new();
        let counter = stats.counter("node|alice|1").await;
        counter.restore(7, 11);

        let active = stats.active_counters().await;
        assert_eq!(active.len(), 1);
        assert!(active.iter().any(|(tag, _)| tag == "node|alice|1"));
    }
}
