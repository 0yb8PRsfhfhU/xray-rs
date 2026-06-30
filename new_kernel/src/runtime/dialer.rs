//! The system dialer: direct `connect`/`bind` to real targets (SPEC §2a).

use crate::runtime::dns::DnsResolver;
use crate::runtime::{Address, Destination};
use smallvec::SmallVec;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpStream, UdpSocket};

pub trait TcpDialer {
    /// Connect a TCP stream to `dest`, trying each resolved IP in turn.
    fn dial_tcp(&self, dest: &Destination) -> impl Future<Output = io::Result<TcpStream>> + Send;
}

pub trait UdpDialer {
    /// Bind a UDP socket for outbound datagrams.
    fn bind_udp(&self, dest: &Destination) -> impl Future<Output = io::Result<UdpSocket>> + Send;
}

/// Dials real destinations directly, resolving domains through the shared
/// cached [`CachedResolver`] (SPEC §P4).
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

    /// Resolve `dest` to a single socket address (first IP).
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

impl<DR: DnsResolver + Send + Sync> TcpDialer for SystemDialer<DR> {
    async fn dial_tcp(&self, dest: &Destination) -> io::Result<TcpStream> {
        let resolve = self.resolve_addr(dest).await?;
        for dest in resolve {
            let Ok(stream) = TcpStream::connect(dest).await else {
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

impl<DR: DnsResolver + Send + Sync> UdpDialer for SystemDialer<DR> {
    async fn bind_udp(&self, _dest: &Destination) -> io::Result<UdpSocket> {
        UdpSocket::bind(("0.0.0.0", 0)).await
    }
}
