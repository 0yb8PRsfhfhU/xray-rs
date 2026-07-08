//! SOCKS5 inbound (SPEC §2e): RFC 1928 greeting + optional RFC 1929 user/pass
//! auth, then a CONNECT relayed through the tower tree or a UDP ASSOCIATE
//! self-serviced through a direct (freedom) UDP socket.
//!
//! Reference: `Xray-core/proxy/socks/{protocol.go,server.go}`. Only SOCKS5 is
//! handled (SOCKS4/4a are not offered). BIND is rejected. UDP ASSOCIATE binds an
//! ephemeral relay socket and egresses datagrams DIRECT via the shared dialer;
//! the association lives exactly as long as the TCP control connection.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use kernel::net::AddrCodec;
use kernel::{
    Address, CachedResolver, Counter, Ctx, Destination, DnsResolver, LINK_CAPACITY, Network, Proxy,
    ProxyDecision, SystemDialer, Timer, UdpDialer, pipe,
};

use crate::ProxyContext;
use crate::io::{noop_decision, relay_stream, sniff_override, user_counter};

const VERSION5: u8 = 0x05;
/// RFC 1929 user/password subnegotiation version.
const AUTH_VERSION: u8 = 0x01;

const AUTH_NONE: u8 = 0x00;
const AUTH_PASSWORD: u8 = 0x02;
const AUTH_NO_MATCH: u8 = 0xFF;

const CMD_CONNECT: u8 = 0x01;
const CMD_UDP: u8 = 0x03;

const REP_SUCCESS: u8 = 0x00;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

const NETWORKS: &[Network] = &[Network::Tcp, Network::Udp];

/// A single SOCKS5 user/password account.
#[derive(Debug, Clone)]
pub struct SocksAccount {
    pub username: String,
    pub password: String,
}

/// SOCKS5 inbound handler. Empty `accounts` means no authentication.
pub struct Socks {
    accounts: Vec<SocksAccount>,
    cx: ProxyContext,
}

impl Socks {
    pub fn new(accounts: Vec<SocksAccount>, cx: ProxyContext) -> Socks {
        Socks { accounts, cx }
    }

    /// Constant-time-ish account lookup by raw username/password bytes.
    fn account_for(&self, user: &[u8], pass: &[u8]) -> Option<&SocksAccount> {
        self.accounts
            .iter()
            .find(|a| a.username.as_bytes() == user && a.password.as_bytes() == pass)
    }

    pub fn networks(&self) -> &'static [Network] {
        NETWORKS
    }

    /// Run the SOCKS5 greeting, optional auth, and request parse, returning the
    /// command byte and the requested destination.
    async fn handshake<S>(&self, conn: &mut S) -> io::Result<(u8, Address, u16)>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // Greeting: VER, NMETHODS, METHODS.
        let ver = conn.read_u8().await?;
        if ver != VERSION5 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "socks: unsupported version",
            ));
        }
        let nmethods = conn.read_u8().await?;
        let mut methods = vec![0u8; usize::from(nmethods)];
        conn.read_exact(&mut methods).await?;

        // Pick the method we require and tell the client.
        let expected = if self.accounts.is_empty() {
            AUTH_NONE
        } else {
            AUTH_PASSWORD
        };
        if !methods.contains(&expected) {
            conn.write_all(&[VERSION5, AUTH_NO_MATCH]).await?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "socks: no acceptable auth method",
            ));
        }
        conn.write_all(&[VERSION5, expected]).await?;

        // RFC 1929 user/password subnegotiation when auth is required.
        if expected == AUTH_PASSWORD {
            let uver = conn.read_u8().await?;
            if uver != AUTH_VERSION {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "socks: bad auth version",
                ));
            }
            let ulen = conn.read_u8().await?;
            let mut uname = vec![0u8; usize::from(ulen)];
            conn.read_exact(&mut uname).await?;
            let plen = conn.read_u8().await?;
            let mut passwd = vec![0u8; usize::from(plen)];
            conn.read_exact(&mut passwd).await?;

            if self.account_for(&uname, &passwd).is_none() {
                conn.write_all(&[AUTH_VERSION, 0x01]).await?; // status != 0 -> failure
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "socks: auth failed",
                ));
            }
            conn.write_all(&[AUTH_VERSION, 0x00]).await?; // success
        }

        // Request: VER, CMD, RSV, then the SOCKS address (ATYP + addr + port).
        let rver = conn.read_u8().await?;
        if rver != VERSION5 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "socks: bad request version",
            ));
        }
        let cmd = conn.read_u8().await?;
        let _rsv = conn.read_u8().await?;
        let (address, port) = read_addr(conn).await?;
        Ok((cmd, address, port))
    }
}

impl Proxy for Socks {
    type Auth = ();

    fn networks(&self) -> &[Network] {
        NETWORKS
    }

    async fn decode<S>(&self, ctx: Ctx, mut stream: S) -> io::Result<ProxyDecision>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (cmd, address, port) = timeout(
            self.cx.policy.handshake_timeout,
            self.handshake(&mut stream),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "socks handshake timeout"))??;

        // SOCKS auth (when present) only gates access; it carries no stable user
        // identity to attribute the flow, so `ctx` is passed through unattributed.
        let timer = Timer::new(self.cx.policy.idle_timeout);
        let counter = user_counter(&ctx, self.cx.stats.as_ref()).await;

        match cmd {
            CMD_CONNECT => {
                // Success reply: BND.ADDR/PORT are unused for CONNECT, so report
                // 0.0.0.0:0 (Go's net.AnyIP + port 0).
                write_reply(&mut stream, REP_SUCCESS).await?;
                let dest = Destination::tcp(address, port);
                let leftover = Bytes::new();
                let target = sniff_override(dest, &leftover);
                let (inbound, outbound) = pipe(LINK_CAPACITY);
                tokio::spawn(relay_stream(stream, inbound, timer, counter, leftover));
                Ok(ProxyDecision {
                    target,
                    ctx,
                    link: outbound,
                })
            }
            CMD_UDP => {
                let sock = match UdpSocket::bind(("0.0.0.0", 0)).await {
                    Ok(s) => Arc::new(s),
                    Err(e) => {
                        write_reply(&mut stream, REP_CMD_NOT_SUPPORTED).await?;
                        return Err(e);
                    }
                };
                let bnd_port = sock.local_addr().map(|a| a.port()).unwrap_or(0);
                write_reply_port(&mut stream, REP_SUCCESS, bnd_port).await?;
                socks_udp_associate(stream, sock, self.cx.dialer.as_ref(), timer, counter).await?;
                Ok(noop_decision(ctx))
            }
            _ => {
                // BIND (0x02) and anything else are unsupported.
                write_reply(&mut stream, REP_CMD_NOT_SUPPORTED).await?;
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "socks: unsupported command",
                ))
            }
        }
    }
}

/// Write a SOCKS5 reply with a zeroed IPv4 BND.ADDR / BND.PORT.
async fn write_reply<W: AsyncWrite + Unpin>(w: &mut W, rep: u8) -> io::Result<()> {
    // VER, REP, RSV, ATYP=IPv4, BND.ADDR=0.0.0.0, BND.PORT=0.
    let resp = [VERSION5, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
    w.write_all(&resp).await
}

/// Read a SOCKS address (ATYP + addr + port) off the stream and decode it via
/// the shared [`AddrCodec::SOCKS`] codec.
async fn read_addr<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<(Address, u16)> {
    let atyp = r.read_u8().await?;
    let mut raw = BytesMut::with_capacity(260);
    raw.put_u8(atyp);
    match atyp {
        ATYP_IPV4 => {
            let mut b = [0u8; 6]; // 4 addr + 2 port
            r.read_exact(&mut b).await?;
            raw.put_slice(&b);
        }
        ATYP_IPV6 => {
            let mut b = [0u8; 18]; // 16 addr + 2 port
            r.read_exact(&mut b).await?;
            raw.put_slice(&b);
        }
        ATYP_DOMAIN => {
            let len = r.read_u8().await?;
            raw.put_u8(len);
            let total = usize::from(len).saturating_add(2); // name + 2 port
            let mut b = vec![0u8; total];
            r.read_exact(&mut b).await?;
            raw.put_slice(&b);
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "socks: bad address type",
            ));
        }
    }
    let mut buf = raw.freeze();
    AddrCodec::SOCKS
        .read(&mut buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Write a SOCKS5 reply with BND.ADDR=0.0.0.0 and the given BND.PORT.
async fn write_reply_port<W: AsyncWrite + Unpin>(w: &mut W, rep: u8, port: u16) -> io::Result<()> {
    let p = port.to_be_bytes();
    let resp = [VERSION5, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, p[0], p[1]];
    w.write_all(&resp).await
}

/// Decode a SOCKS5 UDP request datagram: `RSV(2) FRAG(1) ATYP addr port DATA`.
fn decode_socks_udp(d: &[u8]) -> Option<(Destination, Bytes)> {
    if d.len() < 3 {
        return None;
    }
    if *d.get(2)? != 0 {
        return None; // fragmentation unsupported
    }
    let mut b = Bytes::copy_from_slice(d.get(3..)?);
    let (address, port) = AddrCodec::SOCKS.read(&mut b).ok()?;
    Some((Destination::udp(address, port), b))
}

/// Encode a SOCKS5 UDP reply datagram for `target` + `payload`.
fn encode_socks_udp(target: &Destination, payload: &[u8]) -> Option<Bytes> {
    let mut out = BytesMut::with_capacity(payload.len().saturating_add(16));
    out.put_slice(&[0, 0, 0]); // RSV(2) + FRAG(1)
    AddrCodec::SOCKS
        .write(&mut out, &target.address, target.port)
        .ok()?;
    out.extend_from_slice(payload);
    Some(out.freeze())
}

/// Resolve a destination to its first socket address, going through the shared
/// cached resolver for domains (SPEC §P4). Mirrors the private helper in
/// `crate::udp` (not re-exported) for SOCKS UDP's per-packet targets.
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

/// Relay SOCKS5 UDP traffic until the control TCP connection closes or idles.
///
/// Self-serviced (freedom/direct egress): the client-facing `sock` carries
/// SOCKS-framed datagrams while a second socket bound through the shared
/// [`SystemDialer`] carries the raw payloads to their per-packet targets
/// (resolved through the cached resolver). Replies are tagged with the egress
/// source address and re-framed for the client. The association lives exactly as
/// long as the TCP control connection: EOF or error on it ends the relay.
async fn socks_udp_associate<S>(
    mut conn: S,
    sock: Arc<UdpSocket>,
    dialer: &SystemDialer<CachedResolver>,
    timer: Timer,
    counter: Option<Arc<Counter>>,
) -> io::Result<()>
where
    S: AsyncRead + Unpin,
{
    let bind = Destination::udp(Address::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), 0);
    let egress = dialer.bind_udp(&bind).await?;
    let token = timer.token();
    let c = counter.as_ref();
    let mut cbuf = vec![0u8; 65535];
    let mut ebuf = vec![0u8; 65535];
    let mut ctl = [0u8; 512];
    let mut client: Option<SocketAddr> = None;
    loop {
        tokio::select! {
            _ = token.cancelled() => return Ok(()),
            r = sock.recv_from(&mut cbuf) => {
                let (n, from) = r?;
                client = Some(from);
                timer.update();
                if let Some((target, payload)) = decode_socks_udp(cbuf.get(..n).unwrap_or(&[])) {
                    let addr = match resolve_first(dialer, &target).await {
                        Ok(a) => a,
                        Err(_) => continue,
                    };
                    if let Some(c) = c {
                        c.add_up(payload.len() as u64);
                    }
                    let _ = egress.send_to(&payload, addr).await;
                }
            }
            r = egress.recv_from(&mut ebuf) => {
                let (n, from) = r?;
                timer.update();
                if let Some(addr) = client {
                    let payload = ebuf.get(..n).unwrap_or(&[]);
                    let target = Destination::udp(Address::Ip(from.ip()), from.port());
                    if let Some(d) = encode_socks_udp(&target, payload) {
                        if let Some(c) = c {
                            c.add_down(payload.len() as u64);
                        }
                        let _ = sock.send_to(&d, addr).await;
                    }
                }
            }
            r = conn.read(&mut ctl) => {
                // The control connection closing (or erroring) ends the association.
                match r {
                    Ok(0) | Err(_) => return Ok(()),
                    Ok(_) => {}
                }
            }
        }
    }
}
