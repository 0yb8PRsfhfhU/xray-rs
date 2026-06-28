//! Per-user traffic accounting for the SaaS panel integration.
//!
//! The hot per-byte path uses lock-free [`Counter`] atomics resolved once at
//! connection setup. The [`Stats`] registry (tag → counter) is guarded by a
//! plain mutex, taken only at connection setup and at reporting time — never on
//! the per-byte data path (SPEC §P2: no locks on the data path).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use compact_str::CompactString;
use parking_lot::Mutex;

/// Lock-free upload/download byte counter for a single user.
#[derive(Debug, Default)]
pub struct Counter {
    up: AtomicU64,
    down: AtomicU64,
}

impl Counter {
    /// Add `n` bytes to the upload (client → target) total.
    pub fn add_up(&self, n: u64) {
        self.up.fetch_add(n, Ordering::Relaxed);
    }

    /// Add `n` bytes to the download (target → client) total.
    pub fn add_down(&self, n: u64) {
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
        (
            self.up.swap(0, Ordering::Relaxed),
            self.down.swap(0, Ordering::Relaxed),
        )
    }

    /// Add counts back after a failed report so traffic is not lost.
    pub fn restore(&self, up: u64, down: u64) {
        self.up.fetch_add(up, Ordering::Relaxed);
        self.down.fetch_add(down, Ordering::Relaxed);
    }
}

/// Registry of per-user [`Counter`]s, keyed by the full user tag
/// (`{inbound_tag}|{email}|{uid}`, matching XrayR's traffic counter names).
#[derive(Debug, Default)]
pub struct Stats {
    users: Mutex<HashMap<CompactString, Arc<Counter>>>,
}

impl Stats {
    pub fn new() -> Stats {
        Stats::default()
    }

    /// Get (or create) the counter for `tag`.
    pub fn counter(&self, tag: &str) -> Arc<Counter> {
        let mut guard = self.users.lock();
        if let Some(c) = guard.get(tag) {
            return c.clone();
        }
        let c = Arc::new(Counter::default());
        guard.insert(CompactString::new(tag), c.clone());
        c
    }

    /// Look up an existing counter without creating one.
    pub fn get(&self, tag: &str) -> Option<Arc<Counter>> {
        self.users.lock().get(tag).cloned()
    }

    /// Drop a user's counter (on user removal).
    pub fn remove(&self, tag: &str) {
        self.users.lock().remove(tag);
    }
}
