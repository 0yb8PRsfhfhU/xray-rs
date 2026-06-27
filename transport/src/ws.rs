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
                Some(Ok(Message::Binary(d))) => me.read_buf = Bytes::from(d),
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
        let msg = Message::Binary(buf.to_vec());
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
