//! Framed UDP relays for stream-carried datagrams (Trojan / VLESS).
//!
//! The kernel tower tree models only single-target stream flows, so a
//! UDP-associated flow is self-serviced here: a shared [`Framed`] reader decodes
//! datagrams off the stream, and this relay binds one direct UDP socket through
//! the [`SystemDialer`] and pumps datagrams both ways (freedom/direct egress).

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use kernel::net::{self, AddrCodec};
use kernel::{
    Address, CachedResolver, Counter, Destination, DnsResolver, Error, SystemDialer, Timer,
    UdpDialer, UdpLink, UdpPacket,
};

/// Direct (freedom) UDP egress driving one [`UdpLink`] half: bind a socket, send
/// each outbound packet to its (resolved) target, and deliver replies tagged
/// with their source. Used by mux UDP sub-sessions, which own their own link.
pub async fn freedom_udp(
    dialer: Arc<SystemDialer<CachedResolver>>,
    link: UdpLink,
    timer: Timer,
) -> io::Result<()> {
    let bind = Destination::udp(Address::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), 0);
    let sock = Arc::new(dialer.bind_udp(&bind).await?);
    let UdpLink { mut reader, writer } = link;
    let token = timer.token();
    let send_sock = sock.clone();
    let send_dialer = dialer.clone();
    let send_timer = timer.clone();
    let send = async move {
        while let Some(pkt) = reader.recv().await {
            send_timer.update();
            let addr = resolve_first(&send_dialer, &pkt.target).await?;
            send_sock.send_to(&pkt.data, addr).await?;
        }
        io::Result::Ok(())
    };
    let recv = async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, from) = sock.recv_from(&mut buf).await?;
            timer.update();
            let data = Bytes::copy_from_slice(buf.get(..n).unwrap_or(&[]));
            let target = Destination::udp(Address::Ip(from.ip()), from.port());
            if writer.send(UdpPacket { data, target }).await.is_err() {
                return io::Result::Ok(());
            }
        }
    };
    tokio::select! {
        _ = token.cancelled() => Ok(()),
        r = send => r,
        r = recv => r,
    }
}

/// A buffered framed reader over a stream half, seeded with header leftover.
struct Framed<R> {
    r: R,
    buf: BytesMut,
}

impl<R: AsyncRead + Unpin> Framed<R> {
    fn new(r: R, init: Bytes) -> Framed<R> {
        let mut buf = BytesMut::with_capacity(2048);
        buf.extend_from_slice(&init);
        Framed { r, buf }
    }

    /// Read and decode one frame, growing the buffer as needed.
    async fn frame<T>(
        &mut self,
        mut parse: impl FnMut(&mut Bytes) -> Result<T, Error>,
    ) -> io::Result<T> {
        let mut chunk = [0u8; 4096];
        loop {
            let snap = Bytes::copy_from_slice(&self.buf);
            let mut view = snap.clone();
            match parse(&mut view) {
                Ok(t) => {
                    let consumed = snap.len().saturating_sub(view.remaining());
                    self.buf.advance(consumed);
                    return Ok(t);
                }
                Err(Error::Truncated { .. }) => {}
                Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
            }
            let n = self.r.read(&mut chunk).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "eof in udp frame",
                ));
            }
            self.buf.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
        }
    }
}

/// Resolve a destination to its first socket address, going through the shared
/// cached resolver for domains (SPEC §P4).
async fn resolve_first(
    dialer: &SystemDialer<CachedResolver>,
    dest: &Destination,
) -> io::Result<SocketAddr> {
    match &dest.address {
        Address::Ip(ip) => Ok(SocketAddr::new(*ip, dest.port)),
        Address::Domain(d) => {
            let ips = dialer.resolver().resolve(d).await?;
            ips.first()
                .copied()
                .map(|ip| SocketAddr::new(ip, dest.port))
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addresses for domain"))
        }
    }
}

fn parse_trojan_packet(buf: &mut Bytes) -> Result<(Destination, Bytes), Error> {
    let (address, port) = AddrCodec::TROJAN.read(buf)?;
    let len = net::read_port(buf)? as usize;
    let _crlf = net::take(buf, 2)?;
    let payload = net::take(buf, len)?;
    Ok((Destination::udp(address, port), payload))
}

/// Trojan UDP: per-packet `addr+port + len(2) + CRLF + payload` framing.
/// Self-serviced through a direct UDP socket (freedom egress).
pub async fn relay_trojan_udp<S>(
    conn: S,
    _hdr: Destination,
    leftover: Bytes,
    dialer: &SystemDialer<CachedResolver>,
    timer: Timer,
    counter: Option<Arc<Counter>>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let bind = Destination::udp(Address::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), 0);
    let sock = dialer.bind_udp(&bind).await?;
    let (r, mut w) = tokio::io::split(conn);
    let mut framed = Framed::new(r, leftover);
    let token = timer.token();
    let c = counter.as_ref();

    let up = async {
        loop {
            let (target, payload) = framed.frame(parse_trojan_packet).await?;
            timer.update();
            if let Some(c) = c {
                c.add_up(payload.len() as u64);
            }
            let addr = resolve_first(dialer, &target).await?;
            sock.send_to(&payload, addr).await?;
        }
    };

    let down = async {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, from) = sock.recv_from(&mut buf).await?;
            timer.update();
            let payload = buf.get(..n).unwrap_or(&[]);
            if let Some(c) = c {
                c.add_down(payload.len() as u64);
            }
            let len = match u16::try_from(payload.len()) {
                Ok(l) => l,
                Err(_) => continue,
            };
            let target = Destination::udp(Address::Ip(from.ip()), from.port());
            let mut out = BytesMut::with_capacity(payload.len().saturating_add(24));
            AddrCodec::TROJAN
                .write(&mut out, &target.address, target.port)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(b"\r\n");
            out.extend_from_slice(payload);
            w.write_all(&out).await?;
        }
    };

    tokio::select! {
        _ = token.cancelled() => Ok(()),
        r = up => r,
        r = down => r,
    }
}

fn parse_vless_packet(buf: &mut Bytes) -> Result<Bytes, Error> {
    let len = net::read_port(buf)? as usize;
    let payload = net::take(buf, len)?;
    Ok(payload)
}

/// VLESS UDP: `len(2) + payload` framing, all to the header's fixed target.
/// Self-serviced through a direct UDP socket (freedom egress).
pub async fn relay_vless_udp<S>(
    conn: S,
    hdr: Destination,
    leftover: Bytes,
    dialer: &SystemDialer<CachedResolver>,
    timer: Timer,
    counter: Option<Arc<Counter>>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let bind = Destination::udp(Address::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), 0);
    let sock = dialer.bind_udp(&bind).await?;
    let (r, mut w) = tokio::io::split(conn);
    let mut framed = Framed::new(r, leftover);
    let token = timer.token();
    let c = counter.as_ref();
    let target = Destination::udp(hdr.address, hdr.port);
    let addr = resolve_first(dialer, &target).await?;

    let up = async {
        loop {
            let payload = framed.frame(parse_vless_packet).await?;
            timer.update();
            if let Some(c) = c {
                c.add_up(payload.len() as u64);
            }
            sock.send_to(&payload, addr).await?;
        }
    };

    let down = async {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, _from) = sock.recv_from(&mut buf).await?;
            timer.update();
            let payload = buf.get(..n).unwrap_or(&[]);
            if let Some(c) = c {
                c.add_down(payload.len() as u64);
            }
            let len = match u16::try_from(payload.len()) {
                Ok(l) => l,
                Err(_) => continue,
            };
            let mut out = BytesMut::with_capacity(payload.len().saturating_add(2));
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(payload);
            w.write_all(&out).await?;
        }
    };

    tokio::select! {
        _ = token.cancelled() => Ok(()),
        r = up => r,
        r = down => r,
    }
}
