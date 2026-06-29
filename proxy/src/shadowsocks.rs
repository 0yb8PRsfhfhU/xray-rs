//! Shadowsocks AEAD inbound (SPEC §2e): `salt` then an AEAD chunk stream
//! `[len(2)+tag][payload+tag]`, subkey = HKDF-SHA1(EVP_BytesToKey(pw), salt).
//! Multi-user is trial-decrypt of the first length chunk.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use compact_str::CompactString;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::timeout;

use kernel::types::net::AddrCodec;
use kernel::{Ctx, Destination, Dispatcher, Policy, Timer, UdpLink, UdpPacket};
use transport::Stream;

use crate::crypto::{Aead, AeadKind, NonceCtr, evp_bytes_to_key, hkdf_sha1};
use crate::{ProxyInbound, UdpProxyInbound};

const TAG: usize = AeadKind::TAG;
const SUBKEY_INFO: &[u8] = b"ss-subkey";
const MAX_CHUNK: usize = 0x3fff;

/// Parse a Shadowsocks method name into an [`AeadKind`].
pub fn method_kind(name: &str) -> Option<AeadKind> {
    match name {
        "aes-128-gcm" | "AEAD_AES_128_GCM" => Some(AeadKind::Aes128Gcm),
        "aes-256-gcm" | "AEAD_AES_256_GCM" => Some(AeadKind::Aes256Gcm),
        "chacha20-ietf-poly1305" | "chacha20-poly1305" | "AEAD_CHACHA20_POLY1305" => {
            Some(AeadKind::ChaCha20Poly1305)
        }
        "xchacha20-ietf-poly1305" | "xchacha20-poly1305" => Some(AeadKind::XChaCha20Poly1305),
        _ => None,
    }
}

/// A Shadowsocks user: the master key derived from its password.
#[derive(Clone)]
pub struct SsUser {
    pub master: Arc<[u8]>,
    pub email: CompactString,
    pub level: u32,
}

/// Shadowsocks inbound handler.
pub struct Shadowsocks {
    kind: AeadKind,
    users: arc_swap::ArcSwap<Vec<SsUser>>,
}

/// Derive the per-user master keys for a method.
fn build_ss_users<I>(kind: AeadKind, users: I) -> Vec<SsUser>
where
    I: IntoIterator<Item = (String, CompactString, u32)>,
{
    let ksize = kind.key_size();
    users
        .into_iter()
        .map(|(pw, email, level)| SsUser {
            master: Arc::from(evp_bytes_to_key(pw.as_bytes(), ksize)),
            email,
            level,
        })
        .collect()
}

impl Shadowsocks {
    /// Build from a method and `(password, email, level)` users.
    pub fn new<I>(kind: AeadKind, users: I) -> Shadowsocks
    where
        I: IntoIterator<Item = (String, CompactString, u32)>,
    {
        Shadowsocks {
            kind,
            users: arc_swap::ArcSwap::from(Arc::new(build_ss_users(kind, users))),
        }
    }

    /// Swap in a new user table (live user sync, SPEC §P2).
    pub fn set_users<I>(&self, users: I)
    where
        I: IntoIterator<Item = (String, CompactString, u32)>,
    {
        self.users.store(Arc::new(build_ss_users(self.kind, users)));
    }

    pub async fn process(
        &self,
        ctx: &Ctx,
        mut conn: Stream,
        disp: &Dispatcher,
        policy: &Policy,
    ) -> io::Result<()> {
        let kind = self.kind;
        let ksize = kind.key_size();
        let nsize = kind.nonce_size();

        // Salt + first length chunk under the handshake deadline.
        let mut salt = vec![0u8; ksize];
        let mut lenct = vec![0u8; 2 + TAG];
        timeout(policy.handshake, async {
            conn.read_exact(&mut salt).await?;
            conn.read_exact(&mut lenct).await
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake timeout"))??;

        // Trial-decrypt the first length chunk to find the user.
        let mut matched = None;
        let users = self.users.load_full();
        for user in users.iter() {
            let mut subkey = vec![0u8; ksize];
            if hkdf_sha1(&user.master, &salt, SUBKEY_INFO, &mut subkey).is_err() {
                continue;
            }
            let aead = match Aead::new(kind, &subkey) {
                Ok(a) => a,
                Err(_) => continue,
            };
            let mut nonce = NonceCtr::new(nsize);
            if let Ok(lenpt) = aead.open(nonce.bytes(), &lenct) {
                nonce.inc();
                matched = Some((user.clone(), aead, nonce, lenpt));
                break;
            }
        }
        let (user, aead, mut nonce, lenpt) =
            matched.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ss auth failed"))?;
        let mut ctx = ctx.clone();
        ctx.user_email = Some(user.email.clone());
        let ctx = &ctx;
        let maybe_counter = if let Some(ref user_email) = ctx.user_email
            && let Some(stats) = disp.stats()
        {
            Some(stats.counter(user_email).await)
        } else {
            None
        };

        let length = chunk_len(&lenpt)?;
        let mut payct = vec![0u8; length.checked_add(TAG).unwrap_or(length)];
        conn.read_exact(&mut payct).await?;
        let plain = aead
            .open(nonce.bytes(), &payct)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        nonce.inc();

        // First plaintext = target address + start of payload.
        let mut pb = Bytes::from(plain);
        let (address, port) = AddrCodec::SHADOWSOCKS
            .read(&mut pb)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let dest = Destination::tcp(address, port);
        let leftover = pb;

        // Server response salt + downlink cipher.
        let mut ssalt = vec![0u8; ksize];
        rand::fill(&mut ssalt);
        conn.write_all(&ssalt).await?;
        let mut dsub = vec![0u8; ksize];
        hkdf_sha1(&user.master, &ssalt, SUBKEY_INFO, &mut dsub).map_err(io::Error::other)?;
        let daead = Aead::new(kind, &dsub).map_err(io::Error::other)?;
        let dnonce = NonceCtr::new(nsize);

        let timer = Timer::new(policy.idle);
        let link = disp.dispatch_tcp(ctx, dest, timer.clone());
        let kernel::Link { mut reader, writer } = link;
        let (mut r, mut w) = tokio::io::split(conn);
        let token = timer.token();

        if !leftover.is_empty() {
            let _ = writer.send(leftover).await;
        }

        let up_counter = maybe_counter.clone();
        let up = async move {
            loop {
                match ss_read_chunk(&mut r, &aead, &mut nonce).await? {
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
        let down_counter = maybe_counter.clone();
        let down = async move {
            let daead = daead;
            let mut dnonce = dnonce;
            while let Some(data) = reader.recv().await {
                if let Some(c) = &down_counter {
                    c.add_down(data.len() as u64);
                }
                ss_write_chunks(&mut w, &daead, &mut dnonce, &data).await?;
            }
            let _ = w.flush().await;
            io::Result::Ok(())
        };

        tokio::select! {
            _ = token.cancelled() => Err(io::Error::new(io::ErrorKind::TimedOut, "idle")),
            r = up => r,
            r = down => r,
        }
    }
}

fn chunk_len(lenpt: &[u8]) -> io::Result<usize> {
    let hi = *lenpt
        .first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "len"))?;
    let lo = *lenpt
        .get(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "len"))?;
    Ok(((hi as usize) << 8) | (lo as usize))
}

async fn ss_read_chunk<R>(r: &mut R, aead: &Aead, nonce: &mut NonceCtr) -> io::Result<Option<Bytes>>
where
    R: AsyncRead + Unpin,
{
    let mut lenct = vec![0u8; 2 + TAG];
    match r.read_exact(&mut lenct).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let lenpt = aead
        .open(nonce.bytes(), &lenct)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    nonce.inc();
    let length = chunk_len(&lenpt)?;
    let mut payct = vec![0u8; length.checked_add(TAG).unwrap_or(length)];
    r.read_exact(&mut payct).await?;
    let pay = aead
        .open(nonce.bytes(), &payct)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    nonce.inc();
    Ok(Some(Bytes::from(pay)))
}

async fn ss_write_chunks<W>(
    w: &mut W,
    aead: &Aead,
    nonce: &mut NonceCtr,
    data: &[u8],
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    for piece in data.chunks(MAX_CHUNK) {
        let len = u16::try_from(piece.len()).unwrap_or(0);
        let lenct = aead
            .seal(nonce.bytes(), &len.to_be_bytes())
            .map_err(io::Error::other)?;
        nonce.inc();
        let payct = aead.seal(nonce.bytes(), piece).map_err(io::Error::other)?;
        nonce.inc();
        let mut out = BytesMut::with_capacity(lenct.len().saturating_add(payct.len()));
        out.extend_from_slice(&lenct);
        out.extend_from_slice(&payct);
        w.write_all(&out).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// UDP (per-packet salt + zero-nonce AEAD over addr+port+payload)
// ---------------------------------------------------------------------------

fn ss_udp_encode(
    kind: AeadKind,
    master: &[u8],
    target: &Destination,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let ksize = kind.key_size();
    let nsize = kind.nonce_size();
    let mut salt = vec![0u8; ksize];
    rand::fill(&mut salt);
    let mut subkey = vec![0u8; ksize];
    hkdf_sha1(master, &salt, SUBKEY_INFO, &mut subkey).ok()?;
    let aead = Aead::new(kind, &subkey).ok()?;
    let mut plain = BytesMut::new();
    AddrCodec::SHADOWSOCKS
        .write(&mut plain, &target.address, target.port)
        .ok()?;
    plain.extend_from_slice(payload);
    let zero = [0u8; 24];
    let ct = aead.seal(zero.get(..nsize)?, &plain).ok()?;
    let mut out = salt;
    out.extend_from_slice(&ct);
    Some(out)
}

impl Shadowsocks {
    /// Decode one SS UDP datagram: trial-decrypt with zero nonce, parse target.
    fn udp_decode(&self, dgram: &[u8]) -> Option<(Arc<[u8]>, CompactString, Destination, Bytes)> {
        let ksize = self.kind.key_size();
        let nsize = self.kind.nonce_size();
        let (salt, ct) = dgram.split_at_checked(ksize)?;
        let zero = [0u8; 24];
        let nonce = zero.get(..nsize)?;
        let users = self.users.load();
        for user in users.iter() {
            let mut subkey = vec![0u8; ksize];
            if hkdf_sha1(&user.master, salt, SUBKEY_INFO, &mut subkey).is_err() {
                continue;
            }
            let aead = match Aead::new(self.kind, &subkey) {
                Ok(a) => a,
                Err(_) => continue,
            };
            if let Ok(plain) = aead.open(nonce, ct) {
                let mut pb = Bytes::from(plain);
                if let Ok((address, port)) = AddrCodec::SHADOWSOCKS.read(&mut pb) {
                    return Some((
                        user.master.clone(),
                        user.email.clone(),
                        Destination::udp(address, port),
                        pb,
                    ));
                }
            }
        }
        None
    }

    /// Serve the SS UDP socket: one dispatcher session per client source addr.
    pub async fn serve_udp(
        &self,
        socket: Arc<UdpSocket>,
        ctx: &Ctx,
        disp: &Dispatcher,
        policy: &Policy,
    ) -> io::Result<()> {
        let mut sessions: HashMap<
            SocketAddr,
            (mpsc::Sender<UdpPacket>, Option<Arc<kernel::Counter>>),
        > = HashMap::new();
        let (reap_tx, mut reap_rx) = mpsc::channel::<SocketAddr>(64);
        let mut buf = vec![0u8; 65535];
        loop {
            tokio::select! {
                r = socket.recv_from(&mut buf) => {
                    let (n, from) = r?;
                    let dgram = buf.get(..n).unwrap_or(&[]);
                    let (master, email, target, payload) = match self.udp_decode(dgram) {
                        Some(v) => v,
                        None => continue,
                    };
                    let (tx, counter) = if let Some((tx, c)) = sessions.get(&from) {
                        (tx.clone(), c.clone())
                    } else {
                        let maybe_counter =
                            if let Some(stats) = disp.stats() {
                                Some(stats.counter(&email).await)
                            } else {
                                None
                            };
                        let timer = Timer::new(policy.idle);
                        let UdpLink { mut reader, writer } = disp.dispatch_udp(ctx, timer);
                        let sock = socket.clone();
                        let kind = self.kind;
                        let reap = reap_tx.clone();
                        let down_counter = maybe_counter.clone();
                        tokio::spawn(async move {
                            while let Some(pkt) = reader.recv().await {
                                if let Some(c) = &down_counter {
                                    c.add_down(pkt.data.len() as u64);
                                }
                                if let Some(d) = ss_udp_encode(kind, &master, &pkt.target, &pkt.data) {
                                    let _ = sock.send_to(&d, from).await;
                                }
                            }
                            let _ = reap.send(from).await;
                        });
                        sessions.insert(from, (writer.clone(), maybe_counter.clone()));
                        (writer, maybe_counter)
                    };
                    if let Some(c) = &counter {
                        c.add_up(payload.len() as u64);
                    }
                    let _ = tx.send(UdpPacket { data: payload, target }).await;
                }
                Some(dead) = reap_rx.recv() => {
                    sessions.remove(&dead);
                }
            }
        }
    }
}

impl ProxyInbound for Shadowsocks {
    async fn serve(
        &self,
        ctx: &Ctx,
        conn: Stream,
        disp: &Dispatcher,
        policy: &Policy,
    ) -> io::Result<()> {
        Shadowsocks::process(self, ctx, conn, disp, policy).await
    }
}

impl UdpProxyInbound for Shadowsocks {
    async fn serve_udp(
        &self,
        socket: Arc<UdpSocket>,
        ctx: &Ctx,
        disp: &Dispatcher,
        policy: &Policy,
    ) -> io::Result<()> {
        Shadowsocks::serve_udp(self, socket, ctx, disp, policy).await
    }
}
