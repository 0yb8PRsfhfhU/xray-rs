use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub struct ConnectionPolicy {
    pub handshake_timeout: Duration,
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

#[derive(Debug, Clone)]
pub struct KernelConfig {
    pub connection_policy: ConnectionPolicy,
}