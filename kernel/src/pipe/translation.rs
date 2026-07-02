//! Header/chunk translation seam: read a protocol header off an `AsyncRead`
//! under a handshake deadline, and per-chunk uplink/downlink codec traits.

use bytes::{Buf, Bytes, BytesMut};
use std::io;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::time::timeout;

/// Uplink decoder for a framed (per-chunk) inbound body: decrypt/deframe one
/// chunk off `r`, returning `Ok(None)` at clean end-of-stream.
pub trait ChunkRead {
    fn read_chunk<R>(
        &mut self,
        r: &mut R,
    ) -> impl Future<Output = io::Result<Option<Bytes>>> + Send
    where
        R: AsyncRead + Unpin + Send;
}

/// Downlink encoder for a framed inbound body: frame/encrypt `data` onto `w`,
/// then `finish` writes any terminal marker before the final flush.
pub trait ChunkWrite {
    fn write_chunk<W>(
        &mut self,
        w: &mut W,
        data: &[u8],
    ) -> impl Future<Output = io::Result<()>> + Send
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

async fn read_header_inner<S: AsyncRead + Unpin, T>(
    conn: &mut S,
    max: usize,
    mut parse: impl FnMut(&mut Bytes) -> Result<T, crate::Error>,
) -> Result<(T, Bytes), io::Error> {
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
            Err(crate::Error::Truncated { .. }) => {}
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
}

/// Read and parse a protocol header off `conn` under a handshake deadline.
///
/// `parse` is a pure codec over the accumulated [`Bytes`]; it returns
/// [`crate::Error::Truncated`] to request more bytes. On success the consumed
/// bytes are dropped and the unparsed remainder (start of the uplink payload)
/// is returned.
pub async fn read_header<S: AsyncRead + Unpin, T>(
    conn: &mut S,
    handshake: Duration,
    max: usize,
    parse: impl FnMut(&mut Bytes) -> Result<T, crate::Error>,
) -> Result<(T, Bytes), io::Error> {
    timeout(handshake, read_header_inner(conn, max, parse))
        .await
        .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "handshake timeout")))
}
