//! The system dialer: direct `connect`/`bind` to real targets (SPEC §2a).

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpStream, UdpSocket};

use crate::dns::Resolver;
use crate::net::{Address, Destination};

/// Dials real destinations directly, resolving domains through the shared
/// cached [`Resolver`] (SPEC §P4).
#[derive(Clone)]
pub struct SystemDialer {
    resolver: Arc<Resolver>,
}

impl SystemDialer {
    pub fn new(resolver: Arc<Resolver>) -> SystemDialer {
        SystemDialer { resolver }
    }

    pub fn resolver(&self) -> &Arc<Resolver> {
        &self.resolver
    }

    /// Connect a TCP stream to `dest`, trying each resolved IP in turn.
    pub async fn dial_tcp(&self, dest: &Destination) -> io::Result<TcpStream> {
        match &dest.address {
            Address::Ip(ip) => {
                let stream = TcpStream::connect(SocketAddr::new(*ip, dest.port)).await?;
                let _ = stream.set_nodelay(true);
                Ok(stream)
            }
            Address::Domain(d) => {
                let ips = self.resolver.resolve(d).await?;
                let mut last = io::Error::new(io::ErrorKind::NotFound, "no addresses for domain");
                for ip in ips.iter() {
                    match TcpStream::connect(SocketAddr::new(*ip, dest.port)).await {
                        Ok(s) => {
                            let _ = s.set_nodelay(true);
                            return Ok(s);
                        }
                        Err(e) => last = e,
                    }
                }
                Err(last)
            }
        }
    }

    /// Resolve `dest` to a single socket address (first IP).
    pub async fn resolve_addr(&self, dest: &Destination) -> io::Result<SocketAddr> {
        match &dest.address {
            Address::Ip(ip) => Ok(SocketAddr::new(*ip, dest.port)),
            Address::Domain(d) => {
                let ips = self.resolver.resolve(d).await?;
                let ip = ips
                    .iter()
                    .next()
                    .copied()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "empty resolve"))?;
                Ok(SocketAddr::new(ip, dest.port))
            }
        }
    }

    /// Bind a UDP socket for outbound datagrams.
    pub async fn bind_udp(&self) -> io::Result<UdpSocket> {
        UdpSocket::bind(("0.0.0.0", 0)).await
    }
}
