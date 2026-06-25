//! Connection policy defaults (SPEC §2f).

use std::time::Duration;

/// Timeouts and buffer sizing for a connection.
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    /// Deadline for reading the proxy handshake header.
    pub handshake: Duration,
    /// Idle timeout after the handshake completes.
    pub idle: Duration,
}

impl Default for Policy {
    fn default() -> Policy {
        Policy {
            handshake: Duration::from_secs(60),
            idle: Duration::from_secs(300),
        }
    }
}
