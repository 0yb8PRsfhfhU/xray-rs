//! gRPC inbound stream transport (SPEC §2c).
//!
//! Server side of xray's gRPC tunnel. A client opens an HTTP/2 `POST` to
//! `/<serviceName>/Tun` with `content-type: application/grpc`; the request body
//! is a stream of length-prefixed gRPC messages, each wrapping a `Hunk`
//! protobuf (`bytes data = 1`) whose payload is tunnelled verbatim. The server
//! answers with `200`/`application/grpc` headers (not end-of-stream) and frames
//! the reply identically, closing with a `grpc-status: 0` trailer.
//!
//! See `Xray-core/transport/internet/grpc/` (`hub.go`, `config.go`,
//! `encoding/hunkconn.go`, `encoding/stream.proto`).
//!
//! Because the kernel's data plane splits the [`crate::stream::Stream`] into
//! independent read / write halves driven on separate tasks, the underlying
//! `h2` connection (which owns the socket and a single I/O waker) is driven by a
//! dedicated background task; the [`GrpcStream`] adapter only operates the
//! per-stream send / receive halves, each of which carries its own waker.

use std::io;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use h2::{RecvStream, SendStream, server};
use http::{HeaderMap, HeaderValue, Method, Response};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use crate::stream::{RawNetworkStream, Stream};

/// Reject any single gRPC message claiming more than this many bytes. Real
/// xray peers frame small buffers (bounded by the HTTP/2 flow-control window);
/// this caps memory against a malicious length prefix.
const MAX_FRAME: usize = 16_777_216;

/// Server gRPC transport settings.
#[derive(Debug, Clone, Default)]
pub struct GrpcConfig {
    /// gRPC service name, matched exactly as Xray-core constructs the request
    /// path (`Config.getServiceName`/`getTunStreamName`): the accepted path is
    /// `/<service_name>/Tun` for an ordinary name, or the custom path encoded by
    /// a value beginning with `/` (see [`grpc_path_parts`]).
    pub service_name: String,
}

/// Channel depth for streams handed off to the listener. The listener drains
/// each immediately (spawns a serve task), so this only absorbs short bursts of
/// concurrent new streams; it never gates steady-state I/O.
const STREAM_CHANNEL_CAP: usize = 256;

/// Perform the server-side gRPC (HTTP/2) handshake over `raw`, then accept every
/// `Tun` stream multiplexed on the connection, delivering each as a [`Stream`].
/// The spawned task drives the whole HTTP/2 connection (polling `accept`
/// advances all in-flight streams) and lives until the client closes it; a
/// rejected request resets only its own stream, never the shared connection.
pub async fn serve(raw: RawNetworkStream, cfg: &GrpcConfig) -> io::Result<mpsc::Receiver<Stream>> {
    let mut conn = server::handshake(raw).await.map_err(io::Error::other)?;
    let (tx, rx) = mpsc::channel::<Stream>(STREAM_CHANNEL_CAP);
    let service = cfg.service_name.clone();
    tokio::spawn(async move {
        loop {
            let (request, mut respond) = match conn.accept().await {
                Some(Ok(pair)) => pair,
                Some(Err(_)) => break,
                None => break,
            };
            match accept_request(request, &mut respond, &service) {
                Ok(grpc) => {
                    if tx.send(Stream::Grpc(Box::new(grpc))).await.is_err() {
                        break; // listener dropped the receiver
                    }
                }
                Err(_) => respond.send_reset(h2::Reason::REFUSED_STREAM),
            }
        }
    });
    Ok(rx)
}

/// Validate one inbound `Tun` request and send the `200 application/grpc` head,
/// returning a byte-stream adapter over the tunnel. Free of `.await`, so the
/// accept loop re-parks in `conn.accept()` promptly, keeping the connection
/// driven for sibling streams.
fn accept_request(
    request: http::Request<RecvStream>,
    respond: &mut server::SendResponse<Bytes>,
    service: &str,
) -> io::Result<GrpcStream<RawNetworkStream>> {
    if request.method() != Method::POST {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "grpc: expected POST",
        ));
    }
    if !path_matches(request.uri().path(), service) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "grpc: unexpected path",
        ));
    }
    if let Some(ct) = request.headers().get(http::header::CONTENT_TYPE) {
        let ok = ct
            .to_str()
            .map(|s| s.starts_with("application/grpc"))
            .unwrap_or(false);
        if !ok {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "grpc: unexpected content-type",
            ));
        }
    }

    let response = Response::builder()
        .status(http::StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .body(())
        .map_err(io::Error::other)?;
    let send = respond
        .send_response(response, false)
        .map_err(io::Error::other)?;
    let recv = request.into_body();

    tracing::debug!("grpc: accepted Tun stream");

    Ok(GrpcStream::new(send, recv))
}

/// Percent-escape one path segment the way Go's `url.PathEscape` does
/// (`encodePathSegment`): keep alphanumerics, the unreserved marks `-_.~`, and
/// the reserved characters allowed unescaped in a path segment (`$&+:=@`);
/// escape everything else (notably `/`, space, `!`, `|`, …). Xray-core runs the
/// configured service name through this before placing it on the wire, so the
/// server must escape identically to compare.
const PATH_SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~')
    .remove(b'$')
    .remove(b'&')
    .remove(b'+')
    .remove(b':')
    .remove(b'=')
    .remove(b'@');

fn path_escape(s: &str) -> String {
    utf8_percent_encode(s, PATH_SEGMENT).to_string()
}

/// Split a configured service name into the `(service, tunStream)` path
/// segments a gRPC client addresses, reproducing Xray-core's
/// `Config.getServiceName` + `getTunStreamName`
/// (`transport/internet/grpc/config.go`).
///
/// - An ordinary name (no leading `/`) escapes whole and uses the `Tun` method:
///   `"GunService"` → `("GunService", "Tun")`.
/// - A value beginning with `/` is a custom path `"/<svc…>/<tun>[|<tunMulti>]"`:
///   each `/`-separated service part is escaped and rejoined, and the trailing
///   segment (before any `|`) is the Tun method —
///   `"/my/path/a|b"` → `("my/path", "a")`.
fn grpc_path_parts(service: &str) -> (String, String) {
    let Some(after) = service.strip_prefix('/') else {
        return (path_escape(service), String::from("Tun"));
    };
    let (raw_svc, ending) = after.rsplit_once('/').unwrap_or(("", after));
    let svc = raw_svc
        .split('/')
        .map(path_escape)
        .collect::<Vec<_>>()
        .join("/");
    let tun = path_escape(ending.split('|').next().unwrap_or(ending));
    (svc, tun)
}

/// Accept an inbound request path iff it is exactly the `/<service>/<tunStream>`
/// path the configured service name produces — the same equality grpc-go
/// enforces against its registered service descriptor.
fn path_matches(path: &str, service: &str) -> bool {
    let (svc, tun) = grpc_path_parts(service);
    path == format!("/{svc}/{tun}")
}

/// A byte stream tunnelled over a gRPC `Tun` bidirectional stream.
///
/// Inbound HTTP/2 `DATA` is decoded from `Hunk` frames (reassembling frames
/// split across `DATA` frames); outbound bytes are wrapped one `Hunk` per
/// write. `S` tags the underlying transport; the socket itself is owned by the
/// connection-driver task spawned in [`serve`].
pub struct GrpcStream<S> {
    send: SendStream<Bytes>,
    recv: RecvStream,
    /// Raw inbound framing bytes received but not yet parsed into a full frame.
    recv_buf: BytesMut,
    /// Decoded `Hunk` payload bytes not yet handed to the reader.
    pending: Bytes,
    /// Encoded outbound frame bytes not yet accepted by flow control.
    write_buf: Bytes,
    /// Inbound stream reached end-of-stream.
    eof: bool,
    /// Closing trailer already queued.
    trailers_sent: bool,
    _marker: PhantomData<fn() -> S>,
}

impl<S> GrpcStream<S> {
    fn new(send: SendStream<Bytes>, recv: RecvStream) -> GrpcStream<S> {
        GrpcStream {
            send,
            recv,
            recv_buf: BytesMut::new(),
            pending: Bytes::new(),
            write_buf: Bytes::new(),
            eof: false,
            trailers_sent: false,
            _marker: PhantomData,
        }
    }

    /// Flush buffered outbound frame bytes into the send stream as flow-control
    /// capacity allows. `Ready(Ok(()))` once `write_buf` is fully drained.
    fn flush_write_buf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.write_buf.is_empty() {
            self.send.reserve_capacity(self.write_buf.len());
            let cap = match self.send.capacity() {
                0 => match ready!(self.send.poll_capacity(cx)) {
                    Some(Ok(c)) => c,
                    Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
                    None => return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe))),
                },
                c => c,
            };
            if cap == 0 {
                return Poll::Pending;
            }
            let n = cap.min(self.write_buf.len());
            let chunk = self.write_buf.split_to(n);
            if let Err(e) = self.send.send_data(chunk, false) {
                return Poll::Ready(Err(io::Error::other(e)));
            }
        }
        Poll::Ready(Ok(()))
    }
}

/// Read half of a split [`GrpcStream`]: decodes inbound `Hunk` frames, draining
/// any residual / partially-buffered bytes first.
pub struct GrpcReadHalf {
    recv: RecvStream,
    recv_buf: BytesMut,
    pending: Bytes,
    eof: bool,
}

/// Write half of a split [`GrpcStream`]: frames each owned [`Bytes`] payload as
/// a `Hunk`, splitting (not copying) it across flow-control windows (SPEC §P3).
pub struct GrpcWriteHalf {
    send: SendStream<Bytes>,
}

impl<S> GrpcStream<S> {
    /// Split into independent read / write halves, carrying buffered inbound
    /// state into the read half.
    pub fn into_split(self) -> (GrpcReadHalf, GrpcWriteHalf) {
        (
            GrpcReadHalf {
                recv: self.recv,
                recv_buf: self.recv_buf,
                pending: self.pending,
                eof: self.eof,
            },
            GrpcWriteHalf { send: self.send },
        )
    }
}

impl<S> AsyncRead for GrpcStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            if !me.pending.is_empty() {
                let n = me.pending.len().min(buf.remaining());
                let chunk = me.pending.split_to(n);
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }
            if let Some(payload) = try_decode(&mut me.recv_buf)? {
                me.pending = payload;
                continue;
            }
            if me.eof {
                return Poll::Ready(Ok(()));
            }
            match ready!(me.recv.poll_data(cx)) {
                Some(Ok(data)) => {
                    let len = data.len();
                    me.recv_buf.extend_from_slice(&data);
                    // Release inbound flow-control window for the bytes we took
                    // ownership of, letting the peer send more.
                    let _ = me.recv.flow_control().release_capacity(len);
                }
                Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
                None => me.eof = true,
            }
        }
    }
}

impl<S> AsyncWrite for GrpcStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        // A previously framed write must drain before we accept more bytes.
        ready!(me.flush_write_buf(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        me.write_buf = encode_hunk(buf)?;
        // Best-effort flush; any remainder stays buffered and is drained on the
        // next poll. The bytes are owned regardless, so report them consumed.
        match me.flush_write_buf(cx) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) | Poll::Pending => {}
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().flush_write_buf(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        ready!(me.flush_write_buf(cx))?;
        if !me.trailers_sent {
            let mut trailers = HeaderMap::new();
            trailers.insert("grpc-status", HeaderValue::from_static("0"));
            // Closes the send half; ignore errors if the peer already reset it.
            let _ = me.send.send_trailers(trailers);
            me.trailers_sent = true;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for GrpcReadHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            if !me.pending.is_empty() {
                let n = me.pending.len().min(buf.remaining());
                let chunk = me.pending.split_to(n);
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }
            if let Some(payload) = try_decode(&mut me.recv_buf)? {
                me.pending = payload;
                continue;
            }
            if me.eof {
                return Poll::Ready(Ok(()));
            }
            match ready!(me.recv.poll_data(cx)) {
                Some(Ok(data)) => {
                    let len = data.len();
                    me.recv_buf.extend_from_slice(&data);
                    let _ = me.recv.flow_control().release_capacity(len);
                }
                Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
                None => me.eof = true,
            }
        }
    }
}

impl GrpcWriteHalf {
    /// Frame and send one `Hunk` payload: the small header then the payload as
    /// separate `send_data` calls (byte-identical to [`encode_hunk`] on the
    /// wire), splitting the owned payload across flow-control windows.
    pub async fn send(&mut self, payload: Bytes) -> io::Result<()> {
        if payload.is_empty() {
            return Ok(());
        }
        let header = grpc_header(payload.len())?;
        Self::send_all(&mut self.send, header).await?;
        Self::send_all(&mut self.send, payload).await
    }

    /// No-op: the connection-driver task writes queued `DATA` frames; there is
    /// no adapter-side buffer to flush.
    pub async fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    /// Send all of `data`, awaiting flow-control capacity (async mirror of
    /// [`GrpcStream::flush_write_buf`]); splits `data` in place, never copies.
    async fn send_all(s: &mut SendStream<Bytes>, mut data: Bytes) -> io::Result<()> {
        while !data.is_empty() {
            s.reserve_capacity(data.len());
            let cap = match s.capacity() {
                0 => match std::future::poll_fn(|cx| s.poll_capacity(cx)).await {
                    Some(Ok(c)) => c,
                    Some(Err(e)) => return Err(io::Error::other(e)),
                    None => return Err(io::Error::from(io::ErrorKind::BrokenPipe)),
                },
                c => c,
            };
            if cap == 0 {
                continue;
            }
            let n = cap.min(data.len());
            s.send_data(data.split_to(n), false)
                .map_err(io::Error::other)?;
        }
        Ok(())
    }
}

/// Build the gRPC frame + `Hunk` header for a payload of `payload_len` bytes:
/// `0x00 | u32be(proto_len) | 0x0A | varint(payload_len)`. The payload follows.
fn grpc_header(payload_len: usize) -> io::Result<Bytes> {
    let overflow = || io::Error::new(io::ErrorKind::InvalidData, "grpc: frame length overflow");
    let vlen = varint_len(payload_len as u64);
    // protobuf message length = tag(1) + varint(len) + payload
    let proto_len = 1usize
        .checked_add(vlen)
        .and_then(|x| x.checked_add(payload_len))
        .ok_or_else(overflow)?;
    let proto_len_u32: u32 = proto_len.try_into().map_err(|_| overflow())?;
    let mut h = BytesMut::with_capacity(5usize.saturating_add(vlen));
    h.put_u8(0); // compression flag: uncompressed
    h.put_u32(proto_len_u32); // gRPC message length, big-endian
    h.put_u8(0x0A); // Hunk field #1, wire type 2 (length-delimited)
    put_varint(&mut h, payload_len as u64);
    Ok(h.freeze())
}

/// Encode `payload` as one gRPC-framed `Hunk` message:
/// `0x00 | u32be(len) | 0x0A | varint(payload.len) | payload`.
fn encode_hunk(payload: &[u8]) -> io::Result<Bytes> {
    let header = grpc_header(payload.len())?;
    let mut out = BytesMut::with_capacity(header.len().saturating_add(payload.len()));
    out.put_slice(&header);
    out.put_slice(payload);
    Ok(out.freeze())
}

/// Try to decode one complete gRPC-framed `Hunk` from the front of `buf`,
/// advancing past it. `Ok(None)` means more bytes are needed.
fn try_decode(buf: &mut BytesMut) -> io::Result<Option<Bytes>> {
    let total;
    let payload;
    {
        let src: &[u8] = buf.as_ref();
        let [flag, a, b, c, d, ..] = src else {
            return Ok(None);
        };
        if *flag != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "grpc: compressed frames unsupported",
            ));
        }
        let msg_len = u32::from_be_bytes([*a, *b, *c, *d]) as usize;
        if msg_len > MAX_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "grpc: frame too large",
            ));
        }
        let t = msg_len
            .checked_add(5)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "grpc: length overflow"))?;
        let Some(message) = src.get(5..t) else {
            return Ok(None);
        };
        payload = parse_hunk(message)?;
        total = t;
    }
    buf.advance(total);
    Ok(Some(payload))
}

/// Parse a `Hunk` protobuf, returning the bytes of field #1 (`data`). Unknown
/// fields are skipped; an absent field yields empty payload.
fn parse_hunk(mut m: &[u8]) -> io::Result<Bytes> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "grpc: malformed hunk");
    while let Some((&tag, rest)) = m.split_first() {
        m = rest;
        let wire = tag & 0x07;
        let field = tag.wrapping_shr(3);
        match wire {
            0 => {
                // varint
                let (_, r) = read_varint(m).ok_or_else(invalid)?;
                m = r;
            }
            2 => {
                // length-delimited
                let (len, r) = read_varint(m).ok_or_else(invalid)?;
                let len = usize::try_from(len).map_err(|_| invalid())?;
                let Some(bytes) = r.get(0..len) else {
                    return Err(invalid());
                };
                if field == 1 {
                    return Ok(Bytes::copy_from_slice(bytes));
                }
                m = r.get(len..).unwrap_or(&[]);
            }
            5 => {
                // 32-bit
                let Some(r) = m.get(4..) else {
                    return Err(invalid());
                };
                m = r;
            }
            1 => {
                // 64-bit
                let Some(r) = m.get(8..) else {
                    return Err(invalid());
                };
                m = r;
            }
            _ => return Err(invalid()),
        }
    }
    Ok(Bytes::new())
}

/// Decode a protobuf base-128 varint, returning the value and the remaining
/// bytes. `None` on truncation or overflow.
fn read_varint(src: &[u8]) -> Option<(u64, &[u8])> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in src.iter().enumerate() {
        if shift >= 64 {
            return None;
        }
        result |= u64::from(byte & 0x7f).wrapping_shl(shift);
        if byte & 0x80 == 0 {
            let next = i.checked_add(1)?;
            return Some((result, src.get(next..).unwrap_or(&[])));
        }
        shift = shift.checked_add(7)?;
    }
    None
}

/// Number of bytes a base-128 varint encoding of `v` occupies.
fn varint_len(mut v: u64) -> usize {
    let mut n = 1usize;
    while v >= 0x80 {
        v = v.wrapping_shr(7);
        n = n.saturating_add(1);
    }
    n
}

/// Append the base-128 varint encoding of `v` to `out`.
fn put_varint(out: &mut BytesMut, mut v: u64) {
    while v >= 0x80 {
        out.put_u8((v as u8) | 0x80);
        v = v.wrapping_shr(7);
    }
    out.put_u8(v as u8);
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::unreachable
)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;

    #[test]
    fn assert_send_unpin() {
        fn check<T: Send + Unpin>() {}
        check::<GrpcStream<RawNetworkStream>>();
    }

    #[test]
    fn varint_roundtrip() {
        for v in [0u64, 1, 127, 128, 300, 16384, 1 << 20, u32::MAX as u64] {
            let mut buf = BytesMut::new();
            put_varint(&mut buf, v);
            assert_eq!(buf.len(), varint_len(v));
            let (got, rest) = read_varint(&buf).unwrap();
            assert_eq!(got, v);
            assert!(rest.is_empty());
        }
    }

    #[test]
    fn frame_roundtrip() {
        let payload = b"hello grpc tunnel".to_vec();
        let frame = encode_hunk(&payload).unwrap();
        // 5-byte gRPC prefix + 0x0A + 1-byte varint(17) + payload
        assert_eq!(frame[0], 0);
        assert_eq!(frame[5], 0x0A);
        let mut buf = BytesMut::from(&frame[..]);
        let decoded = try_decode(&mut buf).unwrap().unwrap();
        assert_eq!(&decoded[..], &payload[..]);
        assert!(buf.is_empty());
    }

    #[test]
    fn decode_needs_more_bytes() {
        let frame = encode_hunk(b"abcd").unwrap();
        // Feed everything but the final byte: must report "need more".
        let mut buf = BytesMut::from(&frame[..frame.len() - 1]);
        assert!(try_decode(&mut buf).unwrap().is_none());
        // Append the missing byte and decode succeeds.
        buf.extend_from_slice(&frame[frame.len() - 1..]);
        let decoded = try_decode(&mut buf).unwrap().unwrap();
        assert_eq!(&decoded[..], b"abcd");
    }

    #[test]
    fn decode_two_frames_in_one_buffer() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&encode_hunk(b"one").unwrap());
        buf.extend_from_slice(&encode_hunk(b"two").unwrap());
        assert_eq!(&try_decode(&mut buf).unwrap().unwrap()[..], b"one");
        assert_eq!(&try_decode(&mut buf).unwrap().unwrap()[..], b"two");
        assert!(try_decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn empty_hunk_yields_empty_payload() {
        // gRPC frame with a zero-length protobuf message = empty Hunk.
        let mut buf = BytesMut::new();
        buf.put_u8(0);
        buf.put_u32(0);
        let decoded = try_decode(&mut buf).unwrap().unwrap();
        assert!(decoded.is_empty());
        assert!(buf.is_empty());
    }

    #[test]
    fn rejects_oversized_frame() {
        let mut buf = BytesMut::new();
        buf.put_u8(0);
        buf.put_u32(MAX_FRAME as u32 + 1);
        assert!(try_decode(&mut buf).is_err());
    }

    #[test]
    fn path_matching() {
        // Ordinary service name: "/<serviceName>/Tun".
        assert!(path_matches("/GunService/Tun", "GunService"));
        assert!(!path_matches("/GunService/Tun", "Other"));
        assert!(!path_matches("/GunService", "GunService")); // missing method
        assert!(!path_matches("/GunService/TunMulti", "GunService")); // multi unsupported

        // Empty name maps to "//Tun" exactly (matching Xray-core), not a wildcard.
        assert!(path_matches("//Tun", ""));
        assert!(!path_matches("/anything/Tun", ""));

        // url.PathEscape of special characters (Xray-core config_test.go vectors).
        assert!(path_matches("/hello%2Fworld%21/Tun", "hello/world!"));

        // Custom absolute path "/<svc…>/<tun>[|<tunMulti>]".
        assert!(path_matches("/my/sample/path/a", "/my/sample/path/a|b"));
        assert!(path_matches("//foo", "/foo")); // single '/': empty service segment
        assert!(path_matches("/hello%20/world%21/a", "/hello /world!/a|b"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn end_to_end_echo_with_real_h2_client() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Server: accept the gRPC Tun stream and echo one message back, then
        // close (sending the grpc-status trailer) and drain to EOF.
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let cfg = GrpcConfig {
                service_name: "GunService".into(),
            };
            let mut rx = serve(RawNetworkStream::Tcp(sock), &cfg).await.unwrap();
            let Stream::Grpc(g) = rx.recv().await.unwrap() else {
                unreachable!()
            };
            let mut stream = *g;
            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).await.unwrap();
            stream.write_all(&buf[..n]).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut rest = Vec::new();
            let _ = stream.read_to_end(&mut rest).await;
        });

        // Client: a real h2 client speaking the gRPC framing manually.
        let tcp = TcpStream::connect(addr).await.unwrap();
        let (mut send_req, conn) = h2::client::handshake(tcp).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let request = http::Request::builder()
            .method(Method::POST)
            .uri("http://localhost/GunService/Tun")
            .header(http::header::CONTENT_TYPE, "application/grpc")
            .body(())
            .unwrap();
        let (resp, mut body_out) = send_req.send_request(request, false).unwrap();

        let payload = b"ping-through-the-tunnel";
        body_out
            .send_data(encode_hunk(payload).unwrap(), false)
            .unwrap();

        let response = resp.await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(
            response.headers().get(http::header::CONTENT_TYPE).unwrap(),
            "application/grpc"
        );

        let mut body_in = response.into_body();
        let mut acc = BytesMut::new();
        let mut got = Vec::new();
        while let Some(data) = body_in.data().await {
            let data = data.unwrap();
            let _ = body_in.flow_control().release_capacity(data.len());
            acc.extend_from_slice(&data);
            while let Some(p) = try_decode(&mut acc).unwrap() {
                got.extend_from_slice(&p);
            }
        }
        assert_eq!(&got[..], payload);

        // Closing trailer must carry grpc-status: 0.
        let trailers = body_in.trailers().await.unwrap().unwrap();
        assert_eq!(trailers.get("grpc-status").unwrap(), "0");

        // End the client's send half so the server's drain completes.
        body_out.send_data(Bytes::new(), true).unwrap();
        server.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn write_half_frames_chunks_decodable_by_h2_client() {
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Chunks pushed through the split write half. The empty one must produce
        // no frame; the 32 KiB one must survive flow-control chunking. Expected
        // decoded output = concatenation of the non-empty chunks.
        let chunks: Vec<Bytes> = vec![
            Bytes::from_static(b"alpha"),
            Bytes::new(),
            Bytes::from(vec![0xABu8; 32 * 1024]),
        ];
        let mut expected = Vec::new();
        expected.extend_from_slice(b"alpha");
        expected.extend_from_slice(&[0xABu8; 32 * 1024]);

        let (done_tx, done_rx) = oneshot::channel::<()>();

        let server = tokio::spawn({
            let chunks = chunks.clone();
            async move {
                let (sock, _) = listener.accept().await.unwrap();
                let cfg = GrpcConfig {
                    service_name: "GunService".into(),
                };
                let mut rx = serve(RawNetworkStream::Tcp(sock), &cfg).await.unwrap();
                let Stream::Grpc(g) = rx.recv().await.unwrap() else {
                    unreachable!()
                };
                let stream = *g;
                let (read, mut write) = stream.into_split();
                for chunk in chunks {
                    write.send(chunk).await.unwrap();
                }
                // Hold both halves (keeping the driver and send stream alive)
                // until the client confirms it has received everything.
                let _ = done_rx.await;
                drop(write);
                drop(read);
            }
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let (mut send_req, conn) = h2::client::handshake(tcp).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let request = http::Request::builder()
            .method(Method::POST)
            .uri("http://localhost/GunService/Tun")
            .header(http::header::CONTENT_TYPE, "application/grpc")
            .body(())
            .unwrap();
        let (resp, _body_out) = send_req.send_request(request, false).unwrap();

        let response = resp.await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);

        let mut body_in = response.into_body();
        let mut acc = BytesMut::new();
        let mut got = Vec::new();
        while got.len() < expected.len() {
            let Some(data) = body_in.data().await else {
                break;
            };
            let data = data.unwrap();
            let _ = body_in.flow_control().release_capacity(data.len());
            acc.extend_from_slice(&data);
            while let Some(p) = try_decode(&mut acc).unwrap() {
                got.extend_from_slice(&p);
            }
        }
        assert_eq!(
            got, expected,
            "split header+payload frames must decode identically"
        );

        let _ = done_tx.send(());
        server.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_concurrent_streams_each_served() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Server: accept the gRPC connection and spawn one echo task per Tun
        // stream. Serving the second stream (not just the first) is what proves
        // the multiplexing fix; the serve task keeps driving both in-flight
        // streams while parked in `accept()`.
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let cfg = GrpcConfig {
                service_name: "GunService".into(),
            };
            let mut rx = serve(RawNetworkStream::Tcp(sock), &cfg).await.unwrap();
            let mut tasks = Vec::new();
            while let Some(stream) = rx.recv().await {
                let Stream::Grpc(g) = stream else {
                    unreachable!()
                };
                tasks.push(tokio::spawn(async move {
                    let mut s = *g;
                    let mut buf = [0u8; 64];
                    let n = s.read(&mut buf).await.unwrap();
                    s.write_all(&buf[..n]).await.unwrap();
                    s.shutdown().await.unwrap();
                    let mut rest = Vec::new();
                    let _ = s.read_to_end(&mut rest).await;
                }));
                if tasks.len() == 2 {
                    break;
                }
            }
            for t in tasks {
                t.await.unwrap();
            }
        });

        // Client: one h2 connection multiplexing two Tun streams, each carrying
        // a distinct payload.
        let tcp = TcpStream::connect(addr).await.unwrap();
        let (mut send_req, conn) = h2::client::handshake(tcp).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let p1 = b"first-stream-payload";
        let p2 = b"second-stream-payload";

        let req1 = http::Request::builder()
            .method(Method::POST)
            .uri("http://localhost/GunService/Tun")
            .header(http::header::CONTENT_TYPE, "application/grpc")
            .body(())
            .unwrap();
        let (resp1, mut out1) = send_req.send_request(req1, false).unwrap();
        out1.send_data(encode_hunk(p1).unwrap(), false).unwrap();

        let req2 = http::Request::builder()
            .method(Method::POST)
            .uri("http://localhost/GunService/Tun")
            .header(http::header::CONTENT_TYPE, "application/grpc")
            .body(())
            .unwrap();
        let (resp2, mut out2) = send_req.send_request(req2, false).unwrap();
        out2.send_data(encode_hunk(p2).unwrap(), false).unwrap();

        async fn read_echo(mut body_in: RecvStream) -> Vec<u8> {
            let mut acc = BytesMut::new();
            let mut got = Vec::new();
            while let Some(data) = body_in.data().await {
                let data = data.unwrap();
                let _ = body_in.flow_control().release_capacity(data.len());
                acc.extend_from_slice(&data);
                while let Some(p) = try_decode(&mut acc).unwrap() {
                    got.extend_from_slice(&p);
                }
            }
            got
        }

        let response1 = resp1.await.unwrap();
        assert_eq!(response1.status(), http::StatusCode::OK);
        let response2 = resp2.await.unwrap();
        assert_eq!(response2.status(), http::StatusCode::OK);

        let g1 = read_echo(response1.into_body()).await;
        let g2 = read_echo(response2.into_body()).await;
        assert_eq!(&g1[..], p1, "first stream must echo its own payload");
        assert_eq!(&g2[..], p2, "second multiplexed stream must also be served");

        // End both client send halves so each server echo task's drain
        // completes, then drop the client to close the connection.
        out1.send_data(Bytes::new(), true).unwrap();
        out2.send_data(Bytes::new(), true).unwrap();
        drop(send_req);
        server.await.unwrap();
    }
}
