//! Framed UDP relays for stream-carried datagrams (Trojan / VLESS).
//!
//! Each protocol frames datagrams differently; a shared [`Framed`] reader
//! accumulates bytes off the stream and re-parses until a whole frame is ready.

use std::io;

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use kernel::types::error::Error;
use kernel::types::net::{self, AddrCodec};
use kernel::{Ctx, Destination, Dispatcher, Timer, UdpPacket};
use transport::Stream;

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

fn parse_trojan_packet(buf: &mut Bytes) -> Result<(Destination, Bytes), Error> {
    let (address, port) = AddrCodec::TROJAN.read(buf)?;
    let len = net::read_port(buf)? as usize;
    let _crlf = net::take(buf, 2)?;
    let payload = net::take(buf, len)?;
    Ok((Destination::udp(address, port), payload))
}

/// Trojan UDP: per-packet `addr+port + len(2) + CRLF + payload` framing.
pub async fn relay_trojan_udp(
    conn: Stream,
    _hdr: Destination,
    leftover: Bytes,
    ctx: &Ctx,
    disp: &Dispatcher,
    timer: Timer,
) -> io::Result<()> {
    let link = disp.dispatch_udp(ctx, timer.clone());
    let (r, mut w) = tokio::io::split(conn);
    let mut framed = Framed::new(r, leftover);
    let kernel::UdpLink { mut reader, writer } = link;
    let token = timer.token();

    let up = async {
        loop {
            let (target, payload) = framed.frame(parse_trojan_packet).await?;
            timer.update();
            if writer
                .send(UdpPacket {
                    data: payload,
                    target,
                })
                .await
                .is_err()
            {
                return io::Result::Ok(());
            }
        }
    };

    let down = async {
        while let Some(pkt) = reader.recv().await {
            timer.update();
            let len = match u16::try_from(pkt.data.len()) {
                Ok(l) => l,
                Err(_) => continue,
            };
            let mut out = BytesMut::with_capacity(pkt.data.len().saturating_add(24));
            AddrCodec::TROJAN
                .write(&mut out, &pkt.target.address, pkt.target.port)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(b"\r\n");
            out.extend_from_slice(&pkt.data);
            w.write_all(&out).await?;
        }
        io::Result::Ok(())
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
pub async fn relay_vless_udp(
    conn: Stream,
    hdr: Destination,
    leftover: Bytes,
    ctx: &Ctx,
    disp: &Dispatcher,
    timer: Timer,
) -> io::Result<()> {
    let link = disp.dispatch_udp(ctx, timer.clone());
    let (r, mut w) = tokio::io::split(conn);
    let mut framed = Framed::new(r, leftover);
    let kernel::UdpLink { mut reader, writer } = link;
    let token = timer.token();
    let target = Destination::udp(hdr.address, hdr.port);

    let up = async {
        loop {
            let payload = framed.frame(parse_vless_packet).await?;
            timer.update();
            if writer
                .send(UdpPacket {
                    data: payload,
                    target: target.clone(),
                })
                .await
                .is_err()
            {
                return io::Result::Ok(());
            }
        }
    };

    let down = async {
        while let Some(pkt) = reader.recv().await {
            timer.update();
            let len = match u16::try_from(pkt.data.len()) {
                Ok(l) => l,
                Err(_) => continue,
            };
            let mut out = BytesMut::with_capacity(pkt.data.len().saturating_add(2));
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(&pkt.data);
            w.write_all(&out).await?;
        }
        io::Result::Ok(())
    };

    tokio::select! {
        _ = token.cancelled() => Ok(()),
        r = up => r,
        r = down => r,
    }
}
