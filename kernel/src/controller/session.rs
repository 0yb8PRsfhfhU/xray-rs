//! Per-connection session context (SPEC §2f), carried immutably by reference.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use compact_str::CompactString;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Immutable context for one accepted connection.
#[derive(Debug, Clone)]
pub struct Ctx {
    /// Monotonic session id (for logging/correlation).
    pub id: u64,
    /// Tag of the inbound that accepted this connection.
    pub inbound_tag: CompactString,
    /// Client source address.
    pub source: Option<SocketAddr>,
    /// Local address the connection landed on.
    pub local: Option<SocketAddr>,
}

impl Ctx {
    pub fn new(inbound_tag: impl Into<CompactString>, source: Option<SocketAddr>) -> Ctx {
        Ctx {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            inbound_tag: inbound_tag.into(),
            source,
            local: None,
        }
    }
}
