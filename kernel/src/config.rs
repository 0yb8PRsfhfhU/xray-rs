//! Kernel-level connection policy (SPEC §2f defaults).

use std::time::Duration;

/// Timeouts for one connection: the handshake read-deadline and the
/// post-handshake idle timeout.
#[derive(Debug, Clone, Copy)]
pub struct ConnectionPolicy {
    /// Deadline for reading the proxy handshake header (default 60s).
    pub handshake_timeout: Duration,
    /// Idle timeout after the handshake completes (default 300s).
    pub idle_timeout: Duration,
}

impl Default for ConnectionPolicy {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(300),
        }
    }
}

/// Top-level kernel config carried by the runtime instance.
#[derive(Debug, Clone, Default)]
pub struct KernelConfig {
    pub connection_policy: ConnectionPolicy,
}
