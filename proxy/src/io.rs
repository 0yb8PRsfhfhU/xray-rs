//! Shared inbound I/O helpers on the new kernel data plane (SPEC §1, §2e).
//!
//! A protocol `decode` reads its header, authenticates, learns the target, then
//! builds a [`Link`] and spawns one of these copy loops pumping the client
//! stream into the inbound half; the outbound half rides out on the returned
//! [`ProxyDecision`](kernel::ProxyDecision) for the tower tree to route + dial.

use std::io;
use std::sync::Arc;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use kernel::pipe::copy::{conn_to_link, link_to_conn};
use kernel::{
    Address, Counter, Ctx, Destination, Link, Network, ProxyDecision, Stats, Timer, pipe,
};

/// Re-exported from the kernel: header framing + framed-body chunk codecs, so
/// the per-protocol decoders keep a single import surface.
pub use kernel::{ChunkRead, ChunkWrite, read_header};

/// Stable 64-bit hash of a user's identity bytes (FNV-1a), used to seed
/// [`Ctx::with_user`] so the `user_auth_hash` load balancer can pin a user to
/// one outbound (objective req. 5). Deterministic across runs.
pub fn user_hash(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    let mut h = OFFSET;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(PRIME);
    }
    h
}

/// A no-op [`ProxyDecision`] for a flow the decoder already serviced itself
/// (UDP-associated / mux, which the kernel tree cannot express): a sentinel
/// target (`Network::Unknown`, so `is_valid()` is false) plus an already-EOF
/// link, so routing sends it to freedom, which drops an invalid destination.
pub fn noop_decision(ctx: Ctx) -> ProxyDecision {
    let (_inbound, outbound) = pipe(1);
    ProxyDecision {
        target: Destination {
            network: Network::Unknown,
            address: Address::Ip(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            port: 0,
        },
        ctx,
        link: outbound,
    }
}

/// If `target` is a bare IP and `leftover` sniffs to a domain (TLS SNI / HTTP
/// Host), override the target address with that domain so the router — which
/// only sees the target — can apply domain rules (xray's sniffing destOverride,
/// SPEC §2f). A target the client already gave as a domain is left untouched.
pub fn sniff_override(mut target: Destination, leftover: &[u8]) -> Destination {
    if target.address.is_ip()
        && !leftover.is_empty()
        && let Some((_, domain)) = kernel::sniff(leftover)
    {
        target.address = Address::Domain(domain);
    }
    target
}

/// Resolve the per-user traffic [`Counter`] for this session, if both an
/// authenticated user and a stats registry are present (SPEC §2f).
pub async fn user_counter(ctx: &Ctx, stats: Option<&Arc<Stats>>) -> Option<Arc<Counter>> {
    if let Some(email) = ctx.user_email()
        && let Some(stats) = stats
    {
        Some(stats.counter(email).await)
    } else {
        None
    }
}

/// Pump a decoded client stream against the inbound half of a [`Link`]: forward
/// any already-read `leftover` uplink payload, then run both copy directions to
/// completion (first error — or the idle `timer` firing inside the copy loops —
/// wins). Spawned by `decode`; the outbound half rides the `ProxyDecision`.
pub async fn relay_stream<S>(
    conn: S,
    link: Link,
    timer: Timer,
    counter: Option<Arc<Counter>>,
    leftover: Bytes,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (r, w) = tokio::io::split(conn);
    let Link { reader, writer } = link;
    if !leftover.is_empty() {
        timer.update();
        if let Some(c) = &counter {
            c.add_up(leftover.len() as u64);
        }
        if writer.send(leftover).await.is_err() {
            // Outbound already gone: nothing to forward; still drain downlink.
            return link_to_conn(reader, w, &timer, counter.as_deref()).await;
        }
    }
    let c = counter.as_deref();
    tokio::try_join!(
        conn_to_link(r, writer, &timer, c),
        link_to_conn(reader, w, &timer, c),
    )?;
    Ok(())
}

/// Relay a framed (per-chunk encrypted) flow: the framed counterpart to
/// [`relay_stream`], shared by Shadowsocks and VMess. `dec`/`enc` carry the
/// per-direction codec state; `leftover` is the already-decoded head of the
/// uplink payload (empty for codecs that consume nothing past the header).
///
/// Each chunk resets the idle `timer`; empty chunks are dropped. First error on
/// either direction — or the idle token firing — wins.
pub async fn relay_framed<S, D, E>(
    conn: S,
    mut dec: D,
    mut enc: E,
    link: Link,
    timer: Timer,
    counter: Option<Arc<Counter>>,
    leftover: Bytes,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    D: ChunkRead,
    E: ChunkWrite,
{
    let (mut r, mut w) = tokio::io::split(conn);
    let Link { mut reader, writer } = link;
    let token = timer.token();

    let up_counter = counter.clone();
    let up_timer = timer.clone();
    let up = async move {
        if !leftover.is_empty() && writer.send(leftover).await.is_err() {
            return io::Result::Ok(());
        }
        loop {
            match dec.read_chunk(&mut r).await? {
                Some(chunk) if chunk.is_empty() => continue,
                Some(chunk) => {
                    up_timer.update();
                    if let Some(c) = &up_counter {
                        c.add_up(chunk.len() as u64);
                    }
                    if writer.send(chunk).await.is_err() {
                        return io::Result::Ok(());
                    }
                }
                None => return io::Result::Ok(()),
            }
        }
    };
    let down = async move {
        while let Some(data) = reader.recv().await {
            timer.update();
            if let Some(c) = &counter {
                c.add_down(data.len() as u64);
            }
            enc.write_chunk(&mut w, &data).await?;
        }
        enc.finish(&mut w).await?;
        let _ = w.flush().await;
        io::Result::Ok(())
    };

    tokio::select! {
        _ = token.cancelled() => Err(io::Error::new(io::ErrorKind::TimedOut, "idle")),
        r = up => r,
        r = down => r,
    }
}
