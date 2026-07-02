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
    /// Tag of the inbound (transport) that accepted this connection.
    pub inbound_tag: CompactString,
    /// Client source address.
    pub source: Option<SocketAddr>,
    /// Local address the connection landed on.
    pub local: Option<SocketAddr>,
    /// Authenticated user tag (`{inbound_tag}|{email}|{uid}`), set by the proxy
    /// after auth so the relay/router can attribute traffic. `None` until auth.
    pub user_email: Option<CompactString>,
    /// Stable authorization hash of the authenticated user, when known — feeds
    /// the `user_auth_hash` load-balancer (objective requirement 5).
    pub user_auth_hash: Option<u64>,
}

impl Ctx {
    pub fn new(inbound_tag: impl Into<CompactString>, source: Option<SocketAddr>) -> Ctx {
        Ctx {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            inbound_tag: inbound_tag.into(),
            source,
            local: None,
            user_email: None,
            user_auth_hash: None,
        }
    }

    /// The authenticated user tag, if set.
    pub fn user_email(&self) -> Option<&str> {
        self.user_email.as_deref()
    }

    /// Clone the context with the authenticated user's email + auth hash set,
    /// attributing the session after the proxy decodes its header (SPEC §2f).
    pub fn with_user(&self, email: impl Into<CompactString>, auth_hash: u64) -> Ctx {
        Ctx {
            user_email: Some(email.into()),
            user_auth_hash: Some(auth_hash),
            ..self.clone()
        }
    }
}
