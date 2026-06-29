//! Shared inbound I/O helpers: read a header off a [`Stream`] keeping leftover
//! payload, and relay a TCP flow through the dispatcher (SPEC §1, §2e).

use std::io;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use kernel::types::error::Error;
use kernel::{Counter, Ctx, Destination, Dispatcher, Link, Timer};
use transport::Stream;

/// Read and parse a protocol header off `conn` under a handshake deadline.
///
/// `parse` is a pure codec over the accumulated [`Bytes`]; it returns
/// [`Error::Truncated`] to request more bytes. On success the consumed bytes are
/// dropped and the unparsed remainder (start of the uplink payload) is returned.
pub async fn read_header<S, T>(
    conn: &mut S,
    handshake: Duration,
    max: usize,
    mut parse: impl FnMut(&mut Bytes) -> Result<T, Error>,
) -> io::Result<(T, Bytes)>
where
    S: AsyncRead + Unpin,
{
    let fut = async {
        let mut acc = BytesMut::with_capacity(512);
        let mut chunk = [0u8; 4096];
        loop {
            let snapshot = Bytes::copy_from_slice(&acc);
            let mut view = snapshot.clone();
            match parse(&mut view) {
                Ok(t) => {
                    let consumed = snapshot.len().saturating_sub(view.remaining());
                    acc.advance(consumed);
                    return Ok((t, acc.freeze()));
                }
                Err(Error::Truncated { .. }) => {}
                Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
            }
            if acc.len() >= max {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "header too large",
                ));
            }
            let n = conn.read(&mut chunk).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "eof during header",
                ));
            }
            acc.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
        }
    };
    match timeout(handshake, fut).await {
        Ok(r) => r,
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "handshake timeout")),
    }
}

/// Dispatch a TCP flow and pump bytes, forwarding any already-read `leftover`
/// payload first.
pub async fn relay_tcp(
    conn: Stream,
    dest: Destination,
    leftover: Bytes,
    ctx: &Ctx,
    disp: &Dispatcher,
    timer: Timer,
) -> io::Result<()> {
    let sniff_result = if leftover.is_empty() {
        None
    } else {
        kernel::controller::sniff::sniff(&leftover)
    };
    let sniffed_domain = sniff_result.as_ref().map(|(_, domain)| domain.as_str());
    let sniffed_proto = sniff_result.as_ref().map(|(proto, _)| proto.as_str());
    let link = disp.dispatch_tcp_sniffed(ctx, dest, sniffed_domain, sniffed_proto, timer.clone());
    if !leftover.is_empty() {
        link.writer
            .send(leftover)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "outbound closed"))?;
    }
    let counter_maybe = user_counter(ctx, disp).await;
    let (r, w) = conn.into_split();
    kernel::splice_sink(r, w, link, &timer, counter_maybe.as_deref()).await
}

/// Resolve the per-user traffic [`Counter`] for this session, if both an
/// authenticated user and a stats registry are present. Shared by every inbound
/// that attributes traffic (SPEC §2f).
pub async fn user_counter(ctx: &Ctx, disp: &Dispatcher) -> Option<Arc<Counter>> {
    if let Some(user_email) = ctx.user_email()
        && let Some(stats) = disp.stats()
    {
        Some(stats.counter(user_email).await)
    } else {
        None
    }
}

/// Uplink decoder for a framed (per-chunk) inbound body: decrypt/deframe one
/// chunk off `r`, returning `Ok(None)` at clean end-of-stream.
pub trait ChunkRead {
    fn read_chunk<R>(&mut self, r: &mut R) -> impl Future<Output = io::Result<Option<Bytes>>> + Send
    where
        R: AsyncRead + Unpin + Send;
}

/// Downlink encoder for a framed inbound body: frame/encrypt `data` onto `w`,
/// then `finish` writes any terminal marker before the final flush.
pub trait ChunkWrite {
    fn write_chunk<W>(&mut self, w: &mut W, data: &[u8]) -> impl Future<Output = io::Result<()>> + Send
    where
        W: AsyncWrite + Unpin + Send;

    /// Write a terminal frame at end-of-stream. Defaults to a no-op for codecs
    /// (e.g. Shadowsocks) that signal EOF by closing the connection.
    fn finish<W>(&mut self, _w: &mut W) -> impl Future<Output = io::Result<()>> + Send
    where
        W: AsyncWrite + Unpin + Send,
    {
        async { Ok(()) }
    }
}

/// Relay a framed (per-chunk encrypted) flow: the framed counterpart to
/// [`relay_tcp`], shared by Shadowsocks and VMess. `dec`/`enc` carry the
/// per-direction codec state; `leftover` is the already-decoded head of the
/// uplink payload (empty for codecs that consume nothing past the header).
///
/// Uplink resets the idle `timer` on each chunk; empty chunks are dropped (they
/// carry no payload). First error on either direction — or the idle token firing
/// — wins.
pub async fn relay_framed<D, E>(
    conn: Stream,
    mut dec: D,
    mut enc: E,
    link: Link,
    timer: Timer,
    counter: Option<Arc<Counter>>,
    leftover: Bytes,
) -> io::Result<()>
where
    D: ChunkRead,
    E: ChunkWrite,
{
    let (mut r, mut w) = tokio::io::split(conn);
    let Link { mut reader, writer } = link;
    let token = timer.token();

    let up_counter = counter.clone();
    let up = async move {
        if !leftover.is_empty() && writer.send(leftover).await.is_err() {
            return io::Result::Ok(());
        }
        loop {
            match dec.read_chunk(&mut r).await? {
                Some(chunk) if chunk.is_empty() => continue,
                Some(chunk) => {
                    timer.update();
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
