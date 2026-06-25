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
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::oneshot;

use crate::stream::Raw;

/// Reject any single gRPC message claiming more than this many bytes. Real
/// xray peers frame small buffers (bounded by the HTTP/2 flow-control window);
/// this caps memory against a malicious length prefix.
const MAX_FRAME: usize = 16_777_216;

/// Server gRPC transport settings.
#[derive(Debug, Clone, Default)]
pub struct GrpcConfig {
    /// gRPC service name. The accepted path is `/<service_name>/Tun`. When
    /// empty, any service name is accepted (the path need only address `/Tun`).
    pub service_name: String,
}

/// Perform the server-side gRPC (HTTP/2) handshake over `raw`, accept the
/// `Tun` stream, send the `200 application/grpc` response head, and return a
/// byte-stream adapter over the tunnel.
pub async fn accept(raw: Raw, cfg: &GrpcConfig) -> io::Result<GrpcStream<Raw>> {
    let mut conn = server::handshake(raw).await.map_err(io::Error::other)?;

    let (request, mut respond) = match conn.accept().await {
        Some(Ok(pair)) => pair,
        Some(Err(e)) => return Err(io::Error::other(e)),
        None => {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "grpc: no request",
            ));
        }
    };

    if request.method() != Method::POST {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "grpc: expected POST",
        ));
    }
    if !path_matches(request.uri().path(), &cfg.service_name) {
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

    // Drive the HTTP/2 connection from a dedicated task. `signal` lets the
    // adapter request a graceful shutdown when it is dropped, bounding the
    // task's lifetime instead of waiting for the client to close.
    let (signal, mut shutdown) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let mut requested = false;
        let _ = std::future::poll_fn(move |cx| {
            if !requested && Pin::new(&mut shutdown).poll(cx).is_ready() {
                requested = true;
                conn.graceful_shutdown();
            }
            conn.poll_closed(cx).map(drop)
        })
        .await;
    });

    Ok(GrpcStream::new(send, recv, signal))
}

/// Match an inbound request path against the configured service name. The path
/// must address the `Tun` method (end with `/Tun`); when `service` is set, the
/// preceding segment must name that service.
fn path_matches(path: &str, service: &str) -> bool {
    let Some(prefix) = path.strip_suffix("/Tun") else {
        return false;
    };
    if service.is_empty() {
        return true;
    }
    let svc = prefix.strip_prefix('/').unwrap_or(prefix);
    svc == service || prefix.ends_with(service)
}

/// A byte stream tunnelled over a gRPC `Tun` bidirectional stream.
///
/// Inbound HTTP/2 `DATA` is decoded from `Hunk` frames (reassembling frames
/// split across `DATA` frames); outbound bytes are wrapped one `Hunk` per
/// write. `S` tags the underlying transport; the socket itself is owned by the
/// connection-driver task spawned in [`accept`].
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
    /// Dropped on teardown to signal the driver task to shut down.
    _signal: oneshot::Sender<()>,
    _marker: PhantomData<fn() -> S>,
}

impl<S> GrpcStream<S> {
    fn new(
        send: SendStream<Bytes>,
        recv: RecvStream,
        signal: oneshot::Sender<()>,
    ) -> GrpcStream<S> {
        GrpcStream {
            send,
            recv,
            recv_buf: BytesMut::new(),
            pending: Bytes::new(),
            write_buf: Bytes::new(),
            eof: false,
            trailers_sent: false,
            _signal: signal,
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

/// Encode `payload` as one gRPC-framed `Hunk` message:
/// `0x00 | u32be(len) | 0x0A | varint(payload.len) | payload`.
fn encode_hunk(payload: &[u8]) -> io::Result<Bytes> {
    let payload_len = payload.len();
    let vlen = varint_len(payload_len as u64);
    let overflow = || io::Error::new(io::ErrorKind::InvalidData, "grpc: frame length overflow");
    // protobuf message length = tag(1) + varint(len) + payload
    let proto_len = 1usize
        .checked_add(vlen)
        .and_then(|x| x.checked_add(payload_len))
        .ok_or_else(overflow)?;
    let proto_len_u32: u32 = proto_len.try_into().map_err(|_| overflow())?;
    let total = proto_len.checked_add(5).ok_or_else(overflow)?;

    let mut out = BytesMut::with_capacity(total);
    out.put_u8(0); // compression flag: uncompressed
    out.put_u32(proto_len_u32); // gRPC message length, big-endian
    out.put_u8(0x0A); // Hunk field #1, wire type 2 (length-delimited)
    put_varint(&mut out, payload_len as u64);
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
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    #[test]
    fn assert_send_unpin() {
        fn check<T: Send + Unpin>() {}
        check::<GrpcStream<Raw>>();
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
        assert!(path_matches("/GunService/Tun", "GunService"));
        assert!(path_matches("/anything/Tun", ""));
        assert!(!path_matches("/GunService/Tun", "Other"));
        assert!(!path_matches("/GunService/TunMulti", "GunService"));
        assert!(!path_matches("/GunService", "GunService"));
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
            let mut stream = accept(Raw::Tcp(sock), &cfg).await.unwrap();
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
}
