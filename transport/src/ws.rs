//! WebSocket transport: a byte-stream adapter over a `tokio_tungstenite` server
//! stream (one binary message per write) plus the server handshake (SPEC §2c).

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};

use crate::{Transport, stream::RawNetworkStream};
use base64::Engine;
use bytes::Bytes;
use futures::sink::Sink;
use futures::stream::Stream as FutStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::accept_hdr_async;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};

/// Server websocket transport settings.
#[derive(Debug, Clone, Default)]
pub struct WsConfig {
    pub path: String,
    pub host: Option<String>,
}

impl Transport for WsConfig {
    type Stream = WsStream<RawNetworkStream>;
    async fn accept(&self, stream: RawNetworkStream) -> io::Result<WsStream<RawNetworkStream>> {
        accept(stream, self).await
    }
}

/// Adapter exposing a WebSocket stream as a byte stream.
pub struct WsStream<S> {
    inner: WebSocketStream<S>,
    read_buf: Bytes,
    eof: bool,
}

impl<S> WsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Wrap an already-handshaked server websocket stream, seeding any decoded
    /// early-data into the read buffer.
    pub fn new(inner: WebSocketStream<S>, early_data: Bytes) -> WsStream<S> {
        WsStream {
            inner,
            read_buf: early_data,
            eof: false,
        }
    }
}

/// Read half of a split [`WsStream`]: pulls inbound WebSocket frames while
/// draining any residual / early-data bytes first.
pub struct WsReadHalf<S> {
    stream: futures::stream::SplitStream<WebSocketStream<S>>,
    read_buf: Bytes,
    eof: bool,
}

/// Write half of a split [`WsStream`]: moves each owned [`Bytes`] chunk into one
/// binary frame (zero-copy downlink, SPEC §P3).
pub struct WsWriteHalf<S> {
    sink: futures::stream::SplitSink<WebSocketStream<S>, Message>,
}

impl<S> WsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Split into independent read / write halves, carrying any buffered inbound
    /// bytes (early-data + residual) into the read half.
    pub fn into_split(self) -> (WsReadHalf<S>, WsWriteHalf<S>) {
        use futures::StreamExt;
        let (sink, stream) = self.inner.split();
        (
            WsReadHalf {
                stream,
                read_buf: self.read_buf,
                eof: self.eof,
            },
            WsWriteHalf { sink },
        )
    }
}

/// Perform the server-side WebSocket upgrade, validating path/host and decoding
/// `Sec-WebSocket-Protocol` early-data (xray-compatible).
#[allow(clippy::result_large_err)]
pub async fn accept<S>(stream: S, cfg: &WsConfig) -> io::Result<WsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let early: Arc<Mutex<Bytes>> = Arc::new(Mutex::new(Bytes::new()));
    let early_cb = early.clone();
    let want_path = cfg.path.clone();
    let want_host = cfg.host.clone();

    let callback = move |req: &Request, mut resp: Response| -> Result<Response, ErrorResponse> {
        if !want_path.is_empty() && req.uri().path() != want_path {
            return Err(reject(404, "bad path"));
        }
        if let Some(h) = &want_host {
            let host_ok = req
                .headers()
                .get("host")
                .and_then(|v| v.to_str().ok())
                .map(|got| got.split(':').next().unwrap_or(got).eq_ignore_ascii_case(h))
                .unwrap_or(false);
            if !host_ok {
                return Err(reject(404, "bad host"));
            }
        }
        if let Some(proto) = req.headers().get("sec-websocket-protocol")
            && let Ok(s) = proto.to_str()
            && let Some(ed) = decode_early_data(s)
            && !ed.is_empty()
        {
            if let Ok(mut g) = early_cb.lock() {
                *g = ed;
            }
            resp.headers_mut()
                .insert("sec-websocket-protocol", proto.clone());
        }
        Ok(resp)
    };

    let ws = accept_hdr_async(stream, callback)
        .await
        .map_err(io::Error::other)?;
    let early_data = early.lock().map(|g| g.clone()).unwrap_or_default();
    Ok(WsStream::new(ws, early_data))
}

fn reject(code: u16, msg: &str) -> ErrorResponse {
    let mut r = ErrorResponse::new(Some(msg.to_string()));
    *r.status_mut() = http::StatusCode::from_u16(code).unwrap_or(http::StatusCode::BAD_REQUEST);
    r
}

/// Decode xray ws early-data: normalize to URL-safe base64, strip padding.
fn decode_early_data(s: &str) -> Option<Bytes> {
    let norm: String = s
        .chars()
        .filter_map(|c| match c {
            '+' => Some('-'),
            '/' => Some('_'),
            '=' => None,
            other => Some(other),
        })
        .collect();
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(norm.as_bytes())
        .ok()
        .map(Bytes::from)
}

impl<S> AsyncRead for WsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            if !me.read_buf.is_empty() {
                let n = me.read_buf.len().min(buf.remaining());
                let chunk = me.read_buf.split_to(n);
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }
            if me.eof {
                return Poll::Ready(Ok(()));
            }
            match ready!(Pin::new(&mut me.inner).poll_next(cx)) {
                Some(Ok(Message::Binary(d))) => me.read_buf = d,
                Some(Ok(Message::Text(t))) => me.read_buf = Bytes::from(t.as_bytes().to_vec()),
                Some(Ok(Message::Close(_))) | None => {
                    me.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
            }
        }
    }
}

impl<S> AsyncWrite for WsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        ready!(Pin::new(&mut me.inner).poll_ready(cx)).map_err(io::Error::other)?;
        let msg = Message::Binary(Bytes::copy_from_slice(buf));
        Pin::new(&mut me.inner)
            .start_send(msg)
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        Pin::new(&mut me.inner)
            .poll_flush(cx)
            .map_err(io::Error::other)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        Pin::new(&mut me.inner)
            .poll_close(cx)
            .map_err(io::Error::other)
    }
}

impl<S> AsyncRead for WsReadHalf<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            if !me.read_buf.is_empty() {
                let n = me.read_buf.len().min(buf.remaining());
                let chunk = me.read_buf.split_to(n);
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }
            if me.eof {
                return Poll::Ready(Ok(()));
            }
            match ready!(Pin::new(&mut me.stream).poll_next(cx)) {
                Some(Ok(Message::Binary(d))) => me.read_buf = d,
                Some(Ok(Message::Text(t))) => me.read_buf = Bytes::from(t.as_bytes().to_vec()),
                Some(Ok(Message::Close(_))) | None => {
                    me.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
            }
        }
    }
}

impl<S> WsWriteHalf<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Send one chunk as a single binary frame, moving the owned [`Bytes`] into
    /// the message (no copy).
    pub async fn send(&mut self, buf: Bytes) -> io::Result<()> {
        use futures::SinkExt;
        self.sink
            .send(Message::Binary(buf))
            .await
            .map_err(io::Error::other)
    }

    /// Flush queued frames (including any control frames) to the peer.
    pub async fn flush(&mut self) -> io::Result<()> {
        use futures::SinkExt;
        self.sink.flush().await.map_err(io::Error::other)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use futures::{SinkExt, StreamExt};
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn write_half_emits_one_binary_frame_per_chunk() {
        let (server_end, client_end) = tokio::io::duplex(64 * 1024);

        let server = tokio::spawn(async move {
            let ws = tokio_tungstenite::accept_async(server_end).await.unwrap();
            let (_read, mut write) = WsStream::new(ws, Bytes::new()).into_split();
            write.send(Bytes::from_static(b"alpha")).await.unwrap();
            write.send(Bytes::from(vec![0xCDu8; 20_000])).await.unwrap();
            write.flush().await.unwrap();
            // Keep the underlying stream alive until the client has read.
            write
        });

        let (mut client, _resp) = tokio_tungstenite::client_async("ws://localhost/", client_end)
            .await
            .unwrap();

        let m1 = client.next().await.unwrap().unwrap();
        assert_eq!(m1, Message::Binary(Bytes::from_static(b"alpha")));
        let m2 = client.next().await.unwrap().unwrap();
        assert_eq!(m2, Message::Binary(Bytes::from(vec![0xCDu8; 20_000])));

        let _w = server.await.unwrap();
    }

    #[tokio::test]
    async fn read_half_drains_early_data_before_messages() {
        let (server_end, client_end) = tokio::io::duplex(64 * 1024);

        let server = tokio::spawn(async move {
            let ws = tokio_tungstenite::accept_async(server_end).await.unwrap();
            // Seed early-data into the read buffer, as the ws handshake would.
            let (mut read, _write) = WsStream::new(ws, Bytes::from_static(b"EARLY")).into_split();
            let mut buf = [0u8; 64];
            let n1 = read.read(&mut buf).await.unwrap();
            let first = buf[..n1].to_vec();
            let n2 = read.read(&mut buf).await.unwrap();
            let second = buf[..n2].to_vec();
            (first, second, _write)
        });

        let (mut client, _resp) = tokio_tungstenite::client_async("ws://localhost/", client_end)
            .await
            .unwrap();
        client
            .send(Message::Binary(Bytes::from_static(b"LATE")))
            .await
            .unwrap();
        client.flush().await.unwrap();

        let (first, second, _w) = server.await.unwrap();
        assert_eq!(&first, b"EARLY", "early-data must be drained first");
        assert_eq!(&second, b"LATE", "then inbound messages, in order");
    }
}
