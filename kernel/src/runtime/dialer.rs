//! Outbound dialing: abstract [`TcpDialer`] / [`UdpDialer`] traits (objective
//! requirement 1) plus a concrete [`SystemDialer`] that dials real targets,
//! resolving domains through any [`DnsResolver`] (SPEC §2a).

use crate::net::{Address, Destination};
use crate::runtime::dns::DnsResolver;
use smallvec::SmallVec;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpStream, UdpSocket};

/// Connect a TCP stream to a destination. Abstract so a transport wrapper
/// (TLS/WS dialer, a mux client) can present the same interface (SPEC §P1).
pub trait TcpDialer: Send + Sync {
    fn dial_tcp(&self, dest: &Destination) -> impl Future<Output = io::Result<TcpStream>> + Send;
}

/// Bind a UDP socket for outbound datagrams.
pub trait UdpDialer: Send + Sync {
    fn bind_udp(&self, dest: &Destination) -> impl Future<Output = io::Result<UdpSocket>> + Send;
}

/// Convenience super-trait: a full dialer speaks both TCP and UDP.
pub trait Dialer: TcpDialer + UdpDialer {}
impl<T: TcpDialer + UdpDialer> Dialer for T {}

/// Dials real destinations directly, resolving domains through a shared
/// [`DnsResolver`] (SPEC §P4). Generic over the resolver so tests inject a mock.
#[derive(Clone)]
pub struct SystemDialer<DR: DnsResolver> {
    resolver: Arc<DR>,
}

impl<DR: DnsResolver> SystemDialer<DR> {
    pub fn new(resolver: Arc<DR>) -> SystemDialer<DR> {
        SystemDialer { resolver }
    }

    pub fn resolver(&self) -> Arc<DR> {
        Arc::clone(&self.resolver)
    }

    /// Resolve `dest` to concrete socket addresses (all resolved IPs).
    async fn resolve_addr(&self, dest: &Destination) -> io::Result<SmallVec<[SocketAddr; 3]>> {
        match &dest.address {
            Address::Ip(ip) => Ok(smallvec::smallvec![SocketAddr::new(*ip, dest.port)]),
            Address::Domain(d) => {
                let ips = self.resolver.resolve(d).await?;
                let socket_addrs = ips
                    .iter()
                    .map(|ip| SocketAddr::new(*ip, dest.port))
                    .collect();
                Ok(socket_addrs)
            }
        }
    }
}

impl<DR: DnsResolver> TcpDialer for SystemDialer<DR> {
    async fn dial_tcp(&self, dest: &Destination) -> io::Result<TcpStream> {
        let resolved = self.resolve_addr(dest).await?;
        for addr in resolved {
            let Ok(stream) = TcpStream::connect(addr).await else {
                continue;
            };
            let _ = stream.set_nodelay(true);
            return Ok(stream);
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no addresses for domain",
        ))
    }
}

impl<DR: DnsResolver> UdpDialer for SystemDialer<DR> {
    async fn bind_udp(&self, _dest: &Destination) -> io::Result<UdpSocket> {
        UdpSocket::bind(("0.0.0.0", 0)).await
    }
}
