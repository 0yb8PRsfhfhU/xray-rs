//! mux.cool server demuxer + XUDP (SPEC M6 — needed for default VLESS/VMess
//! UDP, which modern xray carries over mux). Operates on a plaintext duplex:
//! VLESS hands its post-header stream directly; the byte stream carries frames
//! `[metalen(2)][meta][datalen(2)][data?]`.
//!
//! The XUDP global-ID connection-migration optimisation is intentionally not
//! implemented; every `New` UDP sub-session dispatches a fresh relay, which is
//! functionally correct for normal clients.

use std::collections::HashMap;
use std::io;

use bytes::{Bytes, BytesMut};
use kernel::types::net::AddrCodec;
use kernel::{Ctx, Destination, Dispatcher, Network, Policy, Timer, UdpLink, UdpPacket};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const ST_NEW: u8 = 0x01;
const ST_KEEP: u8 = 0x02;
const ST_END: u8 = 0x03;
const ST_KEEPALIVE: u8 = 0x04;
const OPT_DATA: u8 = 0x01;
const NET_TCP: u8 = 0x01;
const NET_UDP: u8 = 0x02;
const MAX_META: usize = 512;
const MAX_DATA: usize = 8192;

struct Meta {
    sid: u16,
    status: u8,
    option: u8,
    target: Option<Destination>,
}

fn parse_meta(meta: &[u8]) -> Option<Meta> {
    let sid = u16::from_be_bytes([*meta.first()?, *meta.get(1)?]);
    let status = *meta.get(2)?;
    let option = *meta.get(3)?;
    let mut target = None;
    let rest = meta.get(4..).unwrap_or(&[]);
    let keep_udp = status == ST_KEEP && rest.first() == Some(&NET_UDP);
    if status == ST_NEW || keep_udp {
        let network = *rest.first()?;
        let mut b = Bytes::copy_from_slice(rest.get(1..)?);
        let (address, port) = AddrCodec::VLESS.read(&mut b).ok()?;
        let net = match network {
            NET_TCP => Network::Tcp,
            NET_UDP => Network::Udp,
            _ => return None,
        };
        target = Some(Destination {
            network: net,
            address,
            port,
        });
    }
    Some(Meta {
        sid,
        status,
        option,
        target,
    })
}

// ---- frame builders (server -> client) ----

fn frame_keep_tcp(sid: u16, data: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(data.len().saturating_add(8));
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&sid.to_be_bytes());
    out.extend_from_slice(&[ST_KEEP, OPT_DATA]);
    let len = u16::try_from(data.len()).unwrap_or(0);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    out.freeze()
}

fn frame_keep_udp(sid: u16, target: &Destination, data: &[u8]) -> Option<Bytes> {
    let mut meta = BytesMut::new();
    meta.extend_from_slice(&sid.to_be_bytes());
    meta.extend_from_slice(&[ST_KEEP, OPT_DATA, NET_UDP]);
    AddrCodec::VLESS
        .write(&mut meta, &target.address, target.port)
        .ok()?;
    let metalen = u16::try_from(meta.len()).ok()?;
    let len = u16::try_from(data.len()).ok()?;
    let mut out = BytesMut::with_capacity(meta.len().saturating_add(data.len()).saturating_add(4));
    out.extend_from_slice(&metalen.to_be_bytes());
    out.extend_from_slice(&meta);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    Some(out.freeze())
}

fn frame_end(sid: u16) -> Bytes {
    let mut out = BytesMut::with_capacity(6);
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&sid.to_be_bytes());
    out.extend_from_slice(&[ST_END, 0]);
    out.freeze()
}

enum Sub {
    Tcp(mpsc::Sender<Bytes>),
    Udp(mpsc::Sender<UdpPacket>),
}

struct Reader<R> {
    r: R,
    buf: BytesMut,
}

impl<R: AsyncRead + Unpin> Reader<R> {
    fn new(r: R, init: Bytes) -> Reader<R> {
        let mut buf = BytesMut::with_capacity(4096);
        buf.extend_from_slice(&init);
        Reader { r, buf }
    }

    async fn take(&mut self, n: usize) -> io::Result<Bytes> {
        let mut chunk = [0u8; 4096];
        while self.buf.len() < n {
            let m = self.r.read(&mut chunk).await?;
            if m == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "mux eof"));
            }
            self.buf.extend_from_slice(chunk.get(..m).unwrap_or(&[]));
        }
        Ok(self.buf.split_to(n).freeze())
    }

    async fn u16(&mut self) -> io::Result<usize> {
        let b = self.take(2).await?;
        Ok(usize::from(u16::from_be_bytes([
            *b.first().unwrap_or(&0),
            *b.get(1).unwrap_or(&0),
        ])))
    }
}

/// Demultiplex a mux.cool plaintext stream until it closes or idles.
pub async fn serve<S>(
    io: S,
    leftover: Bytes,
    ctx: &Ctx,
    disp: &Dispatcher,
    policy: &Policy,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (rh, mut wh) = tokio::io::split(io);
    let mut reader = Reader::new(rh, leftover);
    let token = CancellationToken::new();
    let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(64);
    let timer = Timer::new(policy.idle);

    // Single writer task serialises muxed frames back to the client.
    let writer = tokio::spawn(async move {
        while let Some(frame) = out_rx.recv().await {
            if wh.write_all(&frame).await.is_err() {
                break;
            }
        }
        let _ = wh.flush().await;
    });

    let mut sessions: HashMap<u16, Sub> = HashMap::new();
    let result = demux(
        &mut reader,
        ctx,
        disp,
        policy,
        &timer,
        &token,
        &out_tx,
        &mut sessions,
    )
    .await;

    token.cancel();
    drop(out_tx);
    drop(sessions);
    let _ = writer.await;
    result
}

#[allow(clippy::too_many_arguments)]
async fn demux<R>(
    reader: &mut Reader<R>,
    ctx: &Ctx,
    disp: &Dispatcher,
    policy: &Policy,
    timer: &Timer,
    token: &CancellationToken,
    out_tx: &mpsc::Sender<Bytes>,
    sessions: &mut HashMap<u16, Sub>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    loop {
        let metalen = tokio::select! {
            _ = token.cancelled() => return Ok(()),
            r = reader.u16() => match r {
                Ok(v) => v,
                Err(_) => return Ok(()),
            },
        };
        if metalen == 0 || metalen > MAX_META {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "mux metalen"));
        }
        let meta_bytes = reader.take(metalen).await?;
        let meta = parse_meta(&meta_bytes)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "mux meta"))?;

        let data = if meta.option & OPT_DATA != 0 {
            let dlen = reader.u16().await?;
            if dlen > MAX_DATA {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "mux datalen"));
            }
            Some(reader.take(dlen).await?)
        } else {
            None
        };

        timer.update();
        match meta.status {
            ST_NEW => {
                handle_new(
                    ctx, disp, policy, timer, token, out_tx, sessions, &meta, data,
                )
                .await;
            }
            ST_KEEP => {
                if let Some(d) = data {
                    handle_keep(sessions, &meta, d).await;
                }
            }
            ST_END => {
                sessions.remove(&meta.sid);
            }
            ST_KEEPALIVE => {}
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "mux status")),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_new(
    ctx: &Ctx,
    disp: &Dispatcher,
    _policy: &Policy,
    timer: &Timer,
    token: &CancellationToken,
    out_tx: &mpsc::Sender<Bytes>,
    sessions: &mut HashMap<u16, Sub>,
    meta: &Meta,
    data: Option<Bytes>,
) {
    let target = match &meta.target {
        Some(t) => t.clone(),
        None => return,
    };
    let sid = meta.sid;
    if target.network == Network::Udp {
        let UdpLink { mut reader, writer } = disp.dispatch_udp(ctx, timer.clone());
        if let Some(d) = data {
            let _ = writer
                .send(UdpPacket {
                    data: d,
                    target: target.clone(),
                })
                .await;
        }
        sessions.insert(sid, Sub::Udp(writer));
        let out = out_tx.clone();
        let tok = token.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tok.cancelled() => break,
                    pkt = reader.recv() => match pkt {
                        Some(pkt) => {
                            for piece in pkt.data.chunks(MAX_DATA) {
                                if let Some(f) = frame_keep_udp(sid, &pkt.target, piece)
                                    && out.send(f).await.is_err() { return; }
                            }
                        }
                        None => break,
                    },
                }
            }
            let _ = out.send(frame_end(sid)).await;
        });
    } else {
        let link = disp.dispatch_tcp(ctx, target, timer.clone());
        let kernel::Link { mut reader, writer } = link;
        if let Some(d) = data
            && !d.is_empty()
        {
            let _ = writer.send(d).await;
        }
        sessions.insert(sid, Sub::Tcp(writer));
        let out = out_tx.clone();
        let tok = token.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tok.cancelled() => break,
                    chunk = reader.recv() => match chunk {
                        Some(chunk) => {
                            for piece in chunk.chunks(MAX_DATA) {
                                if out.send(frame_keep_tcp(sid, piece)).await.is_err() { return; }
                            }
                        }
                        None => break,
                    },
                }
            }
            let _ = out.send(frame_end(sid)).await;
        });
    }
}

async fn handle_keep(sessions: &mut HashMap<u16, Sub>, meta: &Meta, data: Bytes) {
    match sessions.get(&meta.sid) {
        Some(Sub::Tcp(tx)) => {
            let _ = tx.send(data).await;
        }
        Some(Sub::Udp(tx)) => {
            let target = match &meta.target {
                Some(t) => t.clone(),
                None => return,
            };
            let _ = tx.send(UdpPacket { data, target }).await;
        }
        None => {}
    }
}
