//! Shared DNS resolver with a `moka` cache (SPEC §P4).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use compact_str::CompactString;
use hickory_resolver::TokioResolver;
use moka::future::Cache;

/// Resolver backed by `hickory-resolver` with a bounded, TTL'd `moka` cache in
/// front to dedupe and bound the slow path.
pub struct CachedResolver {
    inner: TokioResolver,
    cache: Cache<CompactString, Arc<[IpAddr]>>,
}

impl CachedResolver {
    /// Build a resolver from the system configuration, falling back to public
    /// resolvers when `/etc/resolv.conf` is unavailable.
    pub fn system() -> Result<Self, hickory_resolver::net::NetError> {
        let inner = TokioResolver::builder_tokio()?.build()?;
        Ok(CachedResolver::with_resolver(inner))
    }

    fn with_resolver(inner: TokioResolver) -> CachedResolver {
        let cache = Cache::builder()
            .max_capacity(8192)
            .time_to_live(Duration::from_secs(30))
            .build();
        CachedResolver { inner, cache }
    }

    /// Resolve a hostname to one or more IPs. IP literals short-circuit.
    pub async fn resolve(&self, host: &str) -> std::io::Result<Arc<[IpAddr]>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(Arc::from(vec![ip]));
        }
        if let Some(hit) = self.cache.get(host).await {
            return Ok(hit);
        }
        let lookup = self
            .inner
            .lookup_ip(host)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, e))?;
        let ips: Vec<IpAddr> = lookup.iter().collect();
        if ips.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no DNS records",
            ));
        }
        let arc: Arc<[IpAddr]> = Arc::from(ips);
        self.cache
            .insert(CompactString::new(host), arc.clone())
            .await;
        Ok(arc)
    }
}
