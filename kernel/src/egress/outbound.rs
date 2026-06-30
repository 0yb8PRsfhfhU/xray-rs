//! Outbound handlers: direct, block, SOCKS5 and Shadowsocks AEAD. Summed into a
//! closed `enum` per SPEC §P1, so route selection stays static and explicit.

use aes_gcm::aead::Aead as _;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Nonce};
use bytes::{BufMut, Bytes, BytesMut};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use hkdf::Hkdf;
use md5::Md5;
use sha1::Sha1;
use sha2::Digest;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::egress::dialer::SystemDialer;
use crate::pipe_asm::copy::splice;
use crate::pipe_asm::pipe::{Link, UdpLink, UdpPacket};
use crate::pipe_asm::timer::Timer;
use crate::types::net::{AddrCodec, Address, Destination};

const SOCKS_VERSION: u8 = 0x05;
const SOCKS_AUTH_NONE: u8 = 0x00;
const SOCKS_AUTH_PASSWORD: u8 = 0x02;
const SOCKS_CMD_CONNECT: u8 = 0x01;
const SOCKS_ATYP_IPV4: u8 = 0x01;
const SOCKS_ATYP_DOMAIN: u8 = 0x03;
const SOCKS_ATYP_IPV6: u8 = 0x04;

const SS_TAG: usize = 16;
const SS_SUBKEY_INFO: &[u8] = b"ss-subkey";
const SS_MAX_CHUNK: usize = 0x3fff;

/// Closed sum of server outbounds.
#[derive(Debug, Clone)]
pub enum Outbound {
    /// Direct outbound: dial the real target and forward bytes.
    Freedom,
    /// Drop everything (used to block routed traffic).
    Blackhole,
    /// Relay TCP through a Shadowsocks AEAD server.
    Shadowsocks(Arc<SsOutbound>),
    /// Relay TCP through a SOCKS5 server.
    Socks(Arc<SocksOutbound>),
}

impl Outbound {
    /// Handle a TCP flow to `dest`, pumping bytes between the link and target.
    pub async fn handle_tcp(
        &self,
        dialer: &SystemDialer,
        dest: Destination,
        link: Link,
        timer: &Timer,
    ) -> io::Result<()> {
        match self {
            Outbound::Freedom => {
                let stream = dialer.dial_tcp(&dest).await?;
                splice(stream, link, timer).await
            }
            Outbound::Blackhole => {
                drop(link);
                Ok(())
            }
            Outbound::Shadowsocks(ob) => ob.handle_tcp(dialer, dest, link, timer).await,
            Outbound::Socks(ob) => ob.handle_tcp(dialer, dest, link, timer).await,
        }
    }

    /// Handle a UDP-associated flow: relay datagrams to their per-packet targets.
    pub async fn handle_udp(
        &self,
        dialer: &SystemDialer,
        link: UdpLink,
        timer: &Timer,
    ) -> io::Result<()> {
        match self {
            Outbound::Freedom => freedom_udp(dialer, link, timer).await,
            Outbound::Blackhole => {
                drop(link);
                Ok(())
            }
            Outbound::Shadowsocks(_) | Outbound::Socks(_) => {
                drop(link);
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "udp is not implemented for this outbound",
                ))
            }
        }
    }
}

/// A TCP Shadowsocks AEAD outbound.
#[derive(Debug, Clone)]
pub struct SsOutbound {
    server: Destination,
    kind: SsAeadKind,
    master: Arc<[u8]>,
}

impl SsOutbound {
    pub fn new(
        server: Address,
        port: u16,
        password: &str,
        cipher: &str,
    ) -> Result<SsOutbound, &'static str> {
        let kind = SsAeadKind::parse(cipher).ok_or("unsupported shadowsocks cipher")?;
        let master = Arc::from(evp_bytes_to_key(password.as_bytes(), kind.key_size()));
        Ok(SsOutbound {
            server: Destination::tcp(server, port),
            kind,
            master,
        })
    }

    async fn handle_tcp(
        &self,
        dialer: &SystemDialer,
        dest: Destination,
        link: Link,
        timer: &Timer,
    ) -> io::Result<()> {
        let mut stream = dialer.dial_tcp(&self.server).await?;
        let ksize = self.kind.key_size();
        let nsize = self.kind.nonce_size();

        let mut salt = vec![0u8; ksize];
        rand::fill(salt.as_mut_slice());
        stream.write_all(&salt).await?;
        let mut subkey = vec![0u8; ksize];
        hkdf_sha1(&self.master, &salt, SS_SUBKEY_INFO, &mut subkey)?;
        let aead = SsAead::new(self.kind, &subkey)?;
        let mut nonce = NonceCtr::new(nsize);

        let mut first = BytesMut::with_capacity(260);
        AddrCodec::SHADOWSOCKS
            .write(&mut first, &dest.address, dest.port)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        ss_write_chunks(&mut stream, &aead, &mut nonce, &first).await?;

        let Link { mut reader, writer } = link;
        let (mut r, mut w) = tokio::io::split(stream);
        let token = timer.token();
        let up_timer = timer.clone();
        let up = async move {
            while let Some(data) = reader.recv().await {
                up_timer.update();
                ss_write_chunks(&mut w, &aead, &mut nonce, &data).await?;
            }
            let _ = w.shutdown().await;
            io::Result::Ok(())
        };

        let down_kind = self.kind;
        let down_master = self.master.clone();
        let down_timer = timer.clone();
        let down = async move {
            let mut salt = vec![0u8; down_kind.key_size()];
            r.read_exact(&mut salt).await?;
            let mut subkey = vec![0u8; down_kind.key_size()];
            hkdf_sha1(&down_master, &salt, SS_SUBKEY_INFO, &mut subkey)?;
            let aead = SsAead::new(down_kind, &subkey)?;
            let mut nonce = NonceCtr::new(down_kind.nonce_size());
            while let Some(data) = ss_read_chunk(&mut r, &aead, &mut nonce).await? {
                down_timer.update();
                if writer.send(data).await.is_err() {
                    return io::Result::Ok(());
                }
            }
            io::Result::Ok(())
        };

        tokio::select! {
            _ = token.cancelled() => Err(io::Error::new(io::ErrorKind::TimedOut, "idle")),
            r = up => r,
            r = down => r,
        }
    }
}

/// A TCP SOCKS5 outbound.
#[derive(Debug, Clone)]
pub struct SocksOutbound {
    server: Destination,
    username: String,
    password: String,
}

impl SocksOutbound {
    pub fn new(
        server: Address,
        port: u16,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> SocksOutbound {
        SocksOutbound {
            server: Destination::tcp(server, port),
            username: username.into(),
            password: password.into(),
        }
    }

    async fn handle_tcp(
        &self,
        dialer: &SystemDialer,
        dest: Destination,
        link: Link,
        timer: &Timer,
    ) -> io::Result<()> {
        let mut stream = dialer.dial_tcp(&self.server).await?;
        socks5_handshake(
            &mut stream,
            &dest,
            self.username.as_bytes(),
            self.password.as_bytes(),
        )
        .await?;
        splice(stream, link, timer).await
    }
}

async fn socks5_handshake<S>(
    stream: &mut S,
    dest: &Destination,
    username: &[u8],
    password: &[u8],
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let auth = if username.is_empty() && password.is_empty() {
        SOCKS_AUTH_NONE
    } else {
        SOCKS_AUTH_PASSWORD
    };
    stream.write_all(&[SOCKS_VERSION, 1, auth]).await?;
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp.first() != Some(&SOCKS_VERSION) || resp.get(1) != Some(&auth) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socks outbound auth method rejected",
        ));
    }

    if auth == SOCKS_AUTH_PASSWORD {
        let ulen = u8::try_from(username.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "socks outbound username is too long",
            )
        })?;
        let plen = u8::try_from(password.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "socks outbound password is too long",
            )
        })?;
        let cap = 3usize
            .checked_add(username.len())
            .and_then(|v| v.checked_add(password.len()))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "socks auth too large"))?;
        let mut req = Vec::with_capacity(cap);
        req.push(0x01);
        req.push(ulen);
        req.extend_from_slice(username);
        req.push(plen);
        req.extend_from_slice(password);
        stream.write_all(&req).await?;
        let mut auth_resp = [0u8; 2];
        stream.read_exact(&mut auth_resp).await?;
        if auth_resp.first() != Some(&0x01) || auth_resp.get(1) != Some(&0x00) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "socks outbound username/password rejected",
            ));
        }
    }

    let mut req = BytesMut::with_capacity(270);
    req.put_slice(&[SOCKS_VERSION, SOCKS_CMD_CONNECT, 0x00]);
    AddrCodec::SOCKS
        .write(&mut req, &dest.address, dest.port)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    stream.write_all(&req).await?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head.first() != Some(&SOCKS_VERSION) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "socks outbound bad reply version",
        ));
    }
    if head.get(1) != Some(&0x00) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socks outbound connect rejected",
        ));
    }
    let atyp = *head
        .get(3)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "socks reply"))?;
    discard_socks_bound_addr(stream, atyp).await
}

async fn discard_socks_bound_addr<S>(stream: &mut S, atyp: u8) -> io::Result<()>
where
    S: AsyncRead + Unpin,
{
    match atyp {
        SOCKS_ATYP_IPV4 => {
            let mut buf = [0u8; 6];
            stream.read_exact(&mut buf).await.map(|_| ())
        }
        SOCKS_ATYP_IPV6 => {
            let mut buf = [0u8; 18];
            stream.read_exact(&mut buf).await.map(|_| ())
        }
        SOCKS_ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let n = usize::from(*len.first().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "socks domain length")
            })?);
            let total = n
                .checked_add(2)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "socks reply"))?;
            let mut buf = vec![0u8; total];
            stream.read_exact(&mut buf).await.map(|_| ())
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "socks outbound bad reply address type",
        )),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SsAeadKind {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

impl SsAeadKind {
    fn parse(name: &str) -> Option<SsAeadKind> {
        match name {
            "aes-128-gcm" | "AEAD_AES_128_GCM" => Some(SsAeadKind::Aes128Gcm),
            "aes-256-gcm" | "AEAD_AES_256_GCM" => Some(SsAeadKind::Aes256Gcm),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" | "AEAD_CHACHA20_POLY1305" => {
                Some(SsAeadKind::ChaCha20Poly1305)
            }
            "xchacha20-ietf-poly1305" | "xchacha20-poly1305" => Some(SsAeadKind::XChaCha20Poly1305),
            _ => None,
        }
    }

    fn key_size(self) -> usize {
        match self {
            SsAeadKind::Aes128Gcm => 16,
            SsAeadKind::Aes256Gcm
            | SsAeadKind::ChaCha20Poly1305
            | SsAeadKind::XChaCha20Poly1305 => 32,
        }
    }

    fn nonce_size(self) -> usize {
        match self {
            SsAeadKind::XChaCha20Poly1305 => 24,
            _ => 12,
        }
    }
}

enum SsAead {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
    Cha(Box<ChaCha20Poly1305>),
    XCha(Box<XChaCha20Poly1305>),
}

impl SsAead {
    fn new(kind: SsAeadKind, key: &[u8]) -> io::Result<SsAead> {
        let err = |_| io::Error::new(io::ErrorKind::InvalidInput, "shadowsocks aead key");
        Ok(match kind {
            SsAeadKind::Aes128Gcm => {
                SsAead::Aes128(Box::new(Aes128Gcm::new_from_slice(key).map_err(err)?))
            }
            SsAeadKind::Aes256Gcm => {
                SsAead::Aes256(Box::new(Aes256Gcm::new_from_slice(key).map_err(err)?))
            }
            SsAeadKind::ChaCha20Poly1305 => SsAead::Cha(Box::new(
                ChaCha20Poly1305::new_from_slice(key).map_err(err)?,
            )),
            SsAeadKind::XChaCha20Poly1305 => SsAead::XCha(Box::new(
                XChaCha20Poly1305::new_from_slice(key).map_err(err)?,
            )),
        })
    }

    fn seal(&self, nonce: &[u8], plain: &[u8]) -> io::Result<Vec<u8>> {
        let err = |_| io::Error::new(io::ErrorKind::InvalidData, "shadowsocks aead seal");
        match self {
            SsAead::Aes128(c) => c.encrypt(Nonce::from_slice(nonce), plain).map_err(err),
            SsAead::Aes256(c) => c.encrypt(Nonce::from_slice(nonce), plain).map_err(err),
            SsAead::Cha(c) => c
                .encrypt(chacha20poly1305::Nonce::from_slice(nonce), plain)
                .map_err(err),
            SsAead::XCha(c) => c
                .encrypt(chacha20poly1305::XNonce::from_slice(nonce), plain)
                .map_err(err),
        }
    }

    fn open(&self, nonce: &[u8], ct: &[u8]) -> io::Result<Vec<u8>> {
        let err = |_| io::Error::new(io::ErrorKind::InvalidData, "shadowsocks aead open");
        match self {
            SsAead::Aes128(c) => c.decrypt(Nonce::from_slice(nonce), ct).map_err(err),
            SsAead::Aes256(c) => c.decrypt(Nonce::from_slice(nonce), ct).map_err(err),
            SsAead::Cha(c) => c
                .decrypt(chacha20poly1305::Nonce::from_slice(nonce), ct)
                .map_err(err),
            SsAead::XCha(c) => c
                .decrypt(chacha20poly1305::XNonce::from_slice(nonce), ct)
                .map_err(err),
        }
    }
}

struct NonceCtr {
    buf: [u8; 24],
    size: usize,
}

impl NonceCtr {
    fn new(size: usize) -> NonceCtr {
        NonceCtr {
            buf: [0u8; 24],
            size: size.min(24),
        }
    }

    fn bytes(&self) -> &[u8] {
        self.buf.get(..self.size).unwrap_or(&[])
    }

    fn inc(&mut self) {
        for b in self.buf.iter_mut().take(self.size) {
            let (v, carry) = b.overflowing_add(1);
            *b = v;
            if !carry {
                break;
            }
        }
    }
}

fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len);
    let mut prev: Vec<u8> = Vec::new();
    while key.len() < key_len {
        let mut h = Md5::new();
        h.update(&prev);
        h.update(password);
        let digest = h.finalize();
        key.extend_from_slice(&digest);
        prev = digest.to_vec();
    }
    key.truncate(key_len);
    key
}

fn hkdf_sha1(secret: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> io::Result<()> {
    let hk = Hkdf::<Sha1>::new(Some(salt), secret);
    hk.expand(info, out)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "shadowsocks hkdf expand"))
}

fn ss_chunk_len(lenpt: &[u8]) -> io::Result<usize> {
    let hi = *lenpt
        .first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "shadowsocks chunk length"))?;
    let lo = *lenpt
        .get(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "shadowsocks chunk length"))?;
    let len = (usize::from(hi) << 8) | usize::from(lo);
    if len > SS_MAX_CHUNK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "shadowsocks chunk too large",
        ));
    }
    Ok(len)
}

async fn ss_read_chunk<R>(
    r: &mut R,
    aead: &SsAead,
    nonce: &mut NonceCtr,
) -> io::Result<Option<Bytes>>
where
    R: AsyncRead + Unpin,
{
    let mut lenct = vec![0u8; 2usize.saturating_add(SS_TAG)];
    match r.read_exact(&mut lenct).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let lenpt = aead.open(nonce.bytes(), &lenct)?;
    nonce.inc();
    let length = ss_chunk_len(&lenpt)?;
    let mut payct = vec![0u8; length.saturating_add(SS_TAG)];
    r.read_exact(&mut payct).await?;
    let pay = aead.open(nonce.bytes(), &payct)?;
    nonce.inc();
    Ok(Some(Bytes::from(pay)))
}

async fn ss_write_chunks<W>(
    w: &mut W,
    aead: &SsAead,
    nonce: &mut NonceCtr,
    data: &[u8],
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    for piece in data.chunks(SS_MAX_CHUNK) {
        let len = u16::try_from(piece.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "shadowsocks chunk too large")
        })?;
        let lenct = aead.seal(nonce.bytes(), &len.to_be_bytes())?;
        nonce.inc();
        let payct = aead.seal(nonce.bytes(), piece)?;
        nonce.inc();
        let cap = lenct.len().saturating_add(payct.len());
        let mut out = BytesMut::with_capacity(cap);
        out.extend_from_slice(&lenct);
        out.extend_from_slice(&payct);
        w.write_all(&out).await?;
    }
    Ok(())
}

async fn freedom_udp(dialer: &SystemDialer, link: UdpLink, timer: &Timer) -> io::Result<()> {
    use std::sync::Arc;
    let UdpLink { mut reader, writer } = link;
    let sock = Arc::new(dialer.bind_udp().await?);
    let token = timer.token();

    let send_sock = sock.clone();
    let send = async move {
        while let Some(pkt) = reader.recv().await {
            timer.update();
            let addr = dialer.resolve_addr(&pkt.target).await?;
            let first_addr = addr.first().ok_or(io::Error::new(
                io::ErrorKind::NotFound,
                "no addresses for domain",
            ))?;
            send_sock.send_to(&pkt.data, first_addr).await?;
        }
        Ok(())
    };

    let recv = async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, from) = sock.recv_from(&mut buf).await?;
            timer.update();
            let slice = buf.get(..n).unwrap_or(&[]);
            let data = Bytes::copy_from_slice(slice);
            let target = Destination::udp(Address::Ip(from.ip()), from.port());
            if writer.send(UdpPacket { data, target }).await.is_err() {
                return Ok(());
            }
        }
    };

    tokio::select! {
        _ = token.cancelled() => Ok(()),
        r = send => r,
        r = recv => r,
    }
}
