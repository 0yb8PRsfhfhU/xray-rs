//! Shared inbound I/O helpers: read a header off a [`Stream`] keeping leftover
//! payload, and relay a TCP flow through the dispatcher (SPEC §1, §2e).

use std::io;
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::timeout;

use kernel::types::error::Error;
use kernel::{Ctx, Destination, Dispatcher, Timer};
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
    let counter_maybe = if let Some(ref user_email) = ctx.user_email
        && let Some(stats) = disp.stats()
    {
        Some(stats.counter(user_email).await)
    } else {
        None
    };
    let (r, w) = conn.into_split();
    kernel::splice_sink(r, w, link, &timer, counter_maybe.as_deref()).await
}
