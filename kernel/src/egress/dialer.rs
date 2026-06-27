//! The system dialer: direct `connect`/`bind` to real targets (SPEC §2a).

use smallvec::SmallVec;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpStream, UdpSocket};

use crate::egress::dns::CachedResolver;
use crate::types::net::{Address, Destination};

/// Dials real destinations directly, resolving domains through the shared
/// cached [`CachedResolver`] (SPEC §P4).
#[derive(Clone)]
pub struct SystemDialer {
    resolver: Arc<CachedResolver>,
}

impl SystemDialer {
    pub fn new(resolver: Arc<CachedResolver>) -> SystemDialer {
        SystemDialer { resolver }
    }

    pub fn resolver(&self) -> &Arc<CachedResolver> {
        &self.resolver
    }

    /// Connect a TCP stream to `dest`, trying each resolved IP in turn.
    pub async fn dial_tcp(&self, dest: &Destination) -> io::Result<TcpStream> {
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

    /// Resolve `dest` to a single socket address (first IP).
    pub async fn resolve_addr(&self, dest: &Destination) -> io::Result<SmallVec<[SocketAddr; 3]>> {
        match &dest.address {
            Address::Ip(ip) => Ok(smallvec::smallvec![SocketAddr::new(*ip, dest.port)]),
            Address::Domain(d) => {
                let ips = self.resolver.resolve(d).await?;
                let socket_addrs = ips
                    .into_iter()
                    .map(|ip| SocketAddr::new(*ip, dest.port))
                    .collect();
                Ok(socket_addrs)
            }
        }
    }

    /// Bind a UDP socket for outbound datagrams.
    pub async fn bind_udp(&self) -> io::Result<UdpSocket> {
        UdpSocket::bind(("0.0.0.0", 0)).await
    }
}
