//! Concrete server outbounds implementing [`kernel::Outbound`] (the egress seam,
//! SPEC §1). A closed `enum` summed over the known egress kinds (SPEC §P1) so
//! `OutboundList<Outbound>` keys one type by tag. The kernel deliberately ships
//! no concrete outbound bodies; these live downstream.
//!
//! The [`kernel::Outbound`] trait is TCP/stream-only (`process(ctx, target,
//! link, dialer)`); UDP-associated egress is self-serviced inside the proxy
//! decoders, not routed through this list.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use kernel::{
    AddrCodec, Address, Ctx, Destination, Dialer, Link, Outbound as OutboundTrait, Timer, splice,
};

use crate::crypto::{Aead, AeadKind, NonceCtr, evp_bytes_to_key, hkdf_sha1};
use crate::shadowsocks::method_kind;

/// Idle timeout for an outbound copy loop (kernel default, SPEC §2f). The
/// inbound side carries the configured idle; the tighter of the two governs.
const DEFAULT_IDLE: Duration = Duration::from_secs(300);

const SS_TAG: usize = AeadKind::TAG;
const SS_SUBKEY_INFO: &[u8] = b"ss-subkey";
const SS_MAX_CHUNK: usize = 0x3fff;

const SOCKS_VERSION: u8 = 0x05;
const SOCKS_AUTH_NONE: u8 = 0x00;
const SOCKS_AUTH_PASSWORD: u8 = 0x02;
const SOCKS_CMD_CONNECT: u8 = 0x01;
const SOCKS_ATYP_IPV4: u8 = 0x01;
const SOCKS_ATYP_DOMAIN: u8 = 0x03;
const SOCKS_ATYP_IPV6: u8 = 0x04;

/// Closed sum of server outbounds. `Shadowsocks`/`Socks` relay through an
/// upstream proxy server; `Freedom` dials the target directly; `Blackhole`
/// drops the flow.
#[derive(Debug, Clone)]
pub enum Outbound {
    /// Direct outbound: dial the real target and forward bytes.
    Freedom,
    /// Drop everything (blocks routed traffic).
    Blackhole,
    /// Relay TCP through a Shadowsocks AEAD server.
    Shadowsocks(Arc<SsOutbound>),
    /// Relay TCP through a SOCKS5 server.
    Socks(Arc<SocksOutbound>),
}

impl OutboundTrait for Outbound {
    async fn process<D: Dialer>(
        &self,
        _ctx: &Ctx,
        target: Destination,
        link: Link,
        dialer: &D,
    ) -> io::Result<()> {
        match self {
            Outbound::Freedom => {
                // A sentinel/invalid destination (e.g. a self-serviced UDP or
                // mux flow routed here as a no-op) is dropped, not dialed.
                if !target.is_valid() {
                    drop(link);
                    return Ok(());
                }
                let stream = dialer.dial_tcp(&target).await?;
                let timer = Timer::new(DEFAULT_IDLE);
                splice(stream, link, &timer).await
            }
            Outbound::Blackhole => {
                drop(link);
                Ok(())
            }
            Outbound::Shadowsocks(ob) => ob.relay(dialer, target, link).await,
            Outbound::Socks(ob) => ob.relay(dialer, target, link).await,
        }
    }
}

/// A TCP Shadowsocks AEAD outbound.
#[derive(Debug, Clone)]
pub struct SsOutbound {
    server: Destination,
    kind: AeadKind,
    master: Arc<[u8]>,
}

impl SsOutbound {
    pub fn new(
        server: Address,
        port: u16,
        password: &str,
        cipher: &str,
    ) -> Result<SsOutbound, &'static str> {
        let kind = method_kind(cipher).ok_or("unsupported shadowsocks cipher")?;
        let master = Arc::from(evp_bytes_to_key(password.as_bytes(), kind.key_size()));
        Ok(SsOutbound {
            server: Destination::tcp(server, port),
            kind,
            master,
        })
    }

    async fn relay<D: Dialer>(
        &self,
        dialer: &D,
        target: Destination,
        link: Link,
    ) -> io::Result<()> {
        let mut stream = dialer.dial_tcp(&self.server).await?;
        let ksize = self.kind.key_size();
        let nsize = self.kind.nonce_size();

        let mut salt = vec![0u8; ksize];
        rand::fill(salt.as_mut_slice());
        stream.write_all(&salt).await?;
        let mut subkey = vec![0u8; ksize];
        hkdf_sha1(&self.master, &salt, SS_SUBKEY_INFO, &mut subkey)?;
        let aead = Aead::new(self.kind, &subkey)?;
        let mut nonce = NonceCtr::new(nsize);

        let mut first = BytesMut::with_capacity(260);
        AddrCodec::SHADOWSOCKS.write(&mut first, &target.address, target.port)?;
        ss_write_chunks(&mut stream, &aead, &mut nonce, &first).await?;

        let timer = Timer::new(DEFAULT_IDLE);
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
        let down = async move {
            let mut salt = vec![0u8; down_kind.key_size()];
            r.read_exact(&mut salt).await?;
            let mut subkey = vec![0u8; down_kind.key_size()];
            hkdf_sha1(&down_master, &salt, SS_SUBKEY_INFO, &mut subkey)?;
            let aead = Aead::new(down_kind, &subkey)?;
            let mut nonce = NonceCtr::new(down_kind.nonce_size());
            while let Some(data) = ss_read_chunk(&mut r, &aead, &mut nonce).await? {
                timer.update();
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

    async fn relay<D: Dialer>(
        &self,
        dialer: &D,
        target: Destination,
        link: Link,
    ) -> io::Result<()> {
        let mut stream = dialer.dial_tcp(&self.server).await?;
        socks5_handshake(
            &mut stream,
            &target,
            self.username.as_bytes(),
            self.password.as_bytes(),
        )
        .await?;
        let timer = Timer::new(DEFAULT_IDLE);
        splice(stream, link, &timer).await
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
    AddrCodec::SOCKS.write(&mut req, &dest.address, dest.port)?;
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

async fn ss_read_chunk<R>(r: &mut R, aead: &Aead, nonce: &mut NonceCtr) -> io::Result<Option<Bytes>>
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
    aead: &Aead,
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
