//! VMess inbound (SPEC §2e) — the AEAD-header variant used by modern xray.
//!
//! Flow: 16B authID (AES-ECB trial-match → user/cmdKey + ±120s time window) →
//! AEAD header (nested-HMAC KDF) → 38B fixed header + addr + padding + FNV1a →
//! per-security AEAD chunk body with optional SHAKE128 length masking + padding.
//! `flow=none` equivalent; Mux (cmd 3) is out of scope (deferred with XUDP/mux).

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use aes::Aes128;
use aes::cipher::BlockCipherDecrypt;
use bytes::Bytes;
use compact_str::CompactString;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio::time::timeout;

use kernel::types::error::Error;
use kernel::types::net::{self, AddrCodec};
use kernel::{Ctx, Destination, Dispatcher, Network, Policy, Timer, Uuid};
use transport::Stream;

use crate::ProxyInbound;
use crate::crypto::{Aead, AeadKind};
use crate::io::{relay_framed, user_counter};

mod crypto;

use crypto::*;

const OPT_CHUNK_MASKING: u8 = 0x04;
const OPT_GLOBAL_PADDING: u8 = 0x08;

const SEC_AES128_GCM: u8 = 3;
const SEC_CHACHA20: u8 = 4;
const SEC_NONE: u8 = 5;

const CMD_TCP: u8 = 1;
const CMD_UDP: u8 = 2;
const CMD_MUX: u8 = 3;

const VMESS_AUTH_CACHE_MAX: usize = 8192;
const VMESS_ACTIVE_AUTH_MAX: usize = 4096;

static VMESS_AUTH_LIMITER: OnceLock<Arc<Semaphore>> = OnceLock::new();

fn vmess_auth_limiter() -> Arc<Semaphore> {
    VMESS_AUTH_LIMITER
        .get_or_init(|| {
            let cpus = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4);
            let permits = cpus.saturating_mul(2).clamp(4, 128);
            Arc::new(Semaphore::new(permits))
        })
        .clone()
}


// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

/// A VMess user with precomputed cmdKey + authID cipher.
pub struct VmessUser {
    pub cmd_key: [u8; 16],
    authid_cipher: Aes128,
    pub email: CompactString,
    pub level: u32,
}

struct VmessAuth {
    index: usize,
    cmd_key: [u8; 16],
    email: CompactString,
    kind: VmessAuthKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VmessAuthKind {
    Preferred,
    Active,
    Fallback,
}

/// Immutable VMess user table.
pub struct VmessUsers {
    users: Vec<VmessUser>,
}

impl VmessUsers {
    pub fn new<I>(users: I) -> Result<VmessUsers, Error>
    where
        I: IntoIterator<Item = (Uuid, CompactString, u32)>,
    {
        let mut out = Vec::new();
        for (id, email, level) in users {
            let ck = cmd_key(&id);
            let authid_key = kdf16(&ck, &[SALT_AUTHID]);
            let cipher = <Aes128 as aes::cipher::KeyInit>::new_from_slice(&authid_key)
                .map_err(|_| Error::Crypto("aes key"))?;
            out.push(VmessUser {
                cmd_key: ck,
                authid_cipher: cipher,
                email,
                level,
            });
        }
        Ok(VmessUsers { users: out })
    }

    fn match_one(
        index: usize,
        user: &VmessUser,
        authid: &[u8; 16],
        now: i64,
        kind: VmessAuthKind,
    ) -> Option<VmessAuth> {
        let mut block = aes::cipher::Block::<Aes128>::from(*authid);
        user.authid_cipher.decrypt_block(&mut block);
        let plain: &[u8] = block.as_ref();
        let (ts_bytes, rest) = plain.split_at_checked(8)?;
        let crc_field = rest.get(4..8).and_then(|b| <[u8; 4]>::try_from(b).ok())?;
        let crc_field = u32::from_be_bytes(crc_field);
        let check = crc32fast::hash(plain.get(..12)?);
        if crc_field != check {
            return None;
        }
        let ts = ts_bytes.try_into().ok()?;
        let t = i64::from_be_bytes(ts);
        if (now.saturating_sub(t)).abs() > 120 {
            return None;
        }
        Some(VmessAuth {
            index,
            cmd_key: user.cmd_key,
            email: user.email.clone(),
            kind,
        })
    }

    /// Trial-match a 16-byte authID against users (AES-ECB + CRC + time).
    fn match_user(
        &self,
        authid: &[u8; 16],
        preferred: Option<usize>,
        active: &[usize],
    ) -> Option<VmessAuth> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_secs()).ok())
            .unwrap_or(0);
        let mut tried =
            TriedSet::new(preferred.is_some() || !active.is_empty(), self.users.len());
        if let Some(index) = preferred
            && let Some(user) = self.users.get(index)
        {
            tried.mark(index);
            if let Some(matched) =
                Self::match_one(index, user, authid, now, VmessAuthKind::Preferred)
            {
                return Some(matched);
            }
        }
        for index in active {
            let index = *index;
            if tried.contains(index) {
                continue;
            }
            let Some(user) = self.users.get(index) else {
                continue;
            };
            tried.mark(index);
            if let Some(matched) = Self::match_one(index, user, authid, now, VmessAuthKind::Active)
            {
                return Some(matched);
            }
        }
        for (index, user) in self.users.iter().enumerate() {
            if tried.contains(index) {
                continue;
            }
            if let Some(matched) =
                Self::match_one(index, user, authid, now, VmessAuthKind::Fallback)
            {
                return Some(matched);
            }
        }
        None
    }
}

/// Tracks which user indices have already been trial-decrypted, so the
/// preferred/active passes never re-test a user that the fallback scan repeats.
/// `None` means "track nothing": the fallback-only path visits each index once.
struct TriedSet(Option<Vec<bool>>);

impl TriedSet {
    fn new(track: bool, len: usize) -> TriedSet {
        TriedSet(track.then(|| vec![false; len]))
    }

    fn mark(&mut self, index: usize) {
        if let Some(slots) = self.0.as_mut()
            && let Some(slot) = slots.get_mut(index)
        {
            *slot = true;
        }
    }

    fn contains(&self, index: usize) -> bool {
        self.0
            .as_ref()
            .and_then(|s| s.get(index))
            .copied()
            .unwrap_or(false)
    }
}

mod body;
use body::*;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Decoded VMess request header.
struct Request {
    dest: Destination,
    req_key: [u8; 16],
    req_iv: [u8; 16],
    resp_header: u8,
    option: u8,
    security: u8,
    mux: bool,
    email: CompactString,
}

/// VMess inbound handler.
pub struct Vmess {
    users: arc_swap::ArcSwap<VmessUsers>,
    recent_users: Arc<Mutex<HashMap<IpAddr, usize>>>,
    active_users: Arc<Mutex<VecDeque<usize>>>,
    auth_preferred_hits: AtomicU64,
    auth_active_hits: AtomicU64,
    auth_fallback_hits: AtomicU64,
    auth_failures: AtomicU64,
}

impl Vmess {
    pub fn new(users: Arc<VmessUsers>) -> Vmess {
        Vmess {
            users: arc_swap::ArcSwap::from(users),
            recent_users: Arc::new(Mutex::new(HashMap::new())),
            active_users: Arc::new(Mutex::new(VecDeque::new())),
            auth_preferred_hits: AtomicU64::new(0),
            auth_active_hits: AtomicU64::new(0),
            auth_fallback_hits: AtomicU64::new(0),
            auth_failures: AtomicU64::new(0),
        }
    }

    /// Swap in a new user table (live user sync, SPEC §P2).
    pub fn set_users(&self, users: Arc<VmessUsers>) {
        self.users.store(users);
        if let Ok(mut cache) = self.recent_users.lock() {
            cache.clear();
        }
        if let Ok(mut active) = self.active_users.lock() {
            active.clear();
        }
    }

    pub fn auth_preferred_hits(&self) -> u64 {
        self.auth_preferred_hits.load(Ordering::Relaxed)
    }

    pub fn auth_active_hits(&self) -> u64 {
        self.auth_active_hits.load(Ordering::Relaxed)
    }

    pub fn auth_fallback_hits(&self) -> u64 {
        self.auth_fallback_hits.load(Ordering::Relaxed)
    }

    pub fn auth_failures(&self) -> u64 {
        self.auth_failures.load(Ordering::Relaxed)
    }

    fn active_user_snapshot(&self) -> Vec<usize> {
        self.active_users
            .lock()
            .map(|active| active.iter().copied().collect())
            .unwrap_or_default()
    }

    fn remember_active_user(&self, index: usize) {
        let Ok(mut active) = self.active_users.lock() else {
            return;
        };
        if let Some(pos) = active.iter().position(|i| *i == index) {
            let _ = active.remove(pos);
        }
        active.push_front(index);
        if active.len() > VMESS_ACTIVE_AUTH_MAX {
            let _ = active.pop_back();
        }
    }

    fn record_auth_hit(&self, kind: VmessAuthKind) {
        match kind {
            VmessAuthKind::Preferred => {
                self.auth_preferred_hits.fetch_add(1, Ordering::Relaxed);
            }
            VmessAuthKind::Active => {
                self.auth_active_hits.fetch_add(1, Ordering::Relaxed);
            }
            VmessAuthKind::Fallback => {
                self.auth_fallback_hits.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub async fn process(
        &self,
        ctx: &Ctx,
        mut conn: Stream,
        disp: &Dispatcher,
        policy: &Policy,
    ) -> io::Result<()> {
        let req = timeout(policy.handshake, self.read_header(ctx, &mut conn))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake timeout"))??;
        let ctx = ctx.with_user(req.email.clone());
        let ctx = &ctx;

        let (resp_key, resp_iv) = response_keys(&req);
        write_response_header(&mut conn, &resp_key, &resp_iv, req.resp_header).await?;
        let (up, down) = body_codecs(&req, &resp_key, &resp_iv)?;

        // Mux (XUDP / mux.cool) carries no address and is demuxed separately.
        if req.mux {
            return serve_mux(conn, up, down, ctx, disp, policy).await;
        }

        if req.dest.network == Network::Udp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "vmess udp-direct not supported",
            ));
        }

        let timer = Timer::new(policy.idle);
        let counter = user_counter(ctx, disp).await;
        let link = disp.dispatch_tcp(ctx, req.dest, timer.clone());
        relay_framed(conn, up, down, link, timer, counter, Bytes::new()).await
    }

    async fn read_header<R>(&self, ctx: &Ctx, conn: &mut R) -> io::Result<Request>
    where
        R: AsyncRead + Unpin,
    {
        let mut authid = [0u8; 16];
        conn.read_exact(&mut authid).await?;
        let users = self.users.load_full();
        let peer = ctx.source.map(|s| s.ip());
        let preferred = peer.and_then(|ip| {
            self.recent_users
                .lock()
                .ok()
                .and_then(|c| c.get(&ip).copied())
        });
        let active = self.active_user_snapshot();
        let failures = &self.auth_failures;
        let permit = vmess_auth_limiter()
            .acquire_owned()
            .await
            .map_err(|_| io::Error::other("vmess auth limiter closed"))?;
        let matched = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            users.match_user(&authid, preferred, &active)
        })
        .await
        .map_err(io::Error::other)?;
        let matched = match matched {
            Some(m) => m,
            None => {
                failures.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    session = ctx.id,
                    failures = failures.load(Ordering::Relaxed),
                    "vmess auth failed"
                );
                return Err(io::Error::new(io::ErrorKind::InvalidData, "vmess auth"));
            }
        };
        self.record_auth_hit(matched.kind);
        self.remember_active_user(matched.index);
        if let Some(ip) = peer
            && let Ok(mut cache) = self.recent_users.lock()
        {
            if cache.len() >= VMESS_AUTH_CACHE_MAX && !cache.contains_key(&ip) {
                cache.clear();
            }
            cache.insert(ip, matched.index);
        }
        let (cmd_key, email) = (matched.cmd_key, matched.email);

        // [sealed length 18][connection nonce 8]
        let mut lenct = [0u8; 18];
        let mut nonce = [0u8; 8];
        conn.read_exact(&mut lenct).await?;
        conn.read_exact(&mut nonce).await?;

        let len_key = kdf16(&cmd_key, &[SALT_HDR_LEN_KEY, &authid, &nonce]);
        let len_iv = kdf(&cmd_key, &[SALT_HDR_LEN_IV, &authid, &nonce]);
        let len_plain = aes128gcm_open(&len_key, len_iv.get(..12).unwrap_or(&[]), &lenct, &authid)?;
        let hlen = match len_plain.get(..2).and_then(|b| <[u8; 2]>::try_from(b).ok()) {
            Some(b) => usize::from(u16::from_be_bytes(b)),
            None => return Err(io::Error::new(io::ErrorKind::InvalidData, "vmess hdr len")),
        };

        let mut payct = vec![0u8; hlen.saturating_add(16)];
        conn.read_exact(&mut payct).await?;
        let pay_key = kdf16(&cmd_key, &[SALT_HDR_KEY, &authid, &nonce]);
        let pay_iv = kdf(&cmd_key, &[SALT_HDR_IV, &authid, &nonce]);
        let header = aes128gcm_open(&pay_key, pay_iv.get(..12).unwrap_or(&[]), &payct, &authid)?;

        let mut req =
            parse_header(&header).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        req.email = email;
        Ok(req)
    }
}

impl ProxyInbound for Vmess {
    async fn serve(
        &self,
        ctx: &Ctx,
        conn: Stream,
        disp: &Dispatcher,
        policy: &Policy,
    ) -> io::Result<()> {
        Vmess::process(self, ctx, conn, disp, policy).await
    }
}

/// Derive the response key/iv from the request key/iv: SHA-256, truncated to 16.
fn response_keys(req: &Request) -> ([u8; 16], [u8; 16]) {
    let resp_key_full = Sha256::digest(req.req_key);
    let resp_iv_full = Sha256::digest(req.req_iv);
    let mut resp_key = [0u8; 16];
    let mut resp_iv = [0u8; 16];
    resp_key.copy_from_slice(resp_key_full.get(..16).unwrap_or(&[0u8; 16]));
    resp_iv.copy_from_slice(resp_iv_full.get(..16).unwrap_or(&[0u8; 16]));
    (resp_key, resp_iv)
}

/// Seal and write the 38-byte AEAD response header: [sealed len(18)][sealed payload(20)].
async fn write_response_header<W>(
    conn: &mut W,
    resp_key: &[u8; 16],
    resp_iv: &[u8; 16],
    resp_header: u8,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let resp_payload = [resp_header, 0u8, 0u8, 0u8];
    let len_key = kdf16(resp_key, &[SALT_RESP_LEN_KEY]);
    let len_iv = kdf(resp_iv, &[SALT_RESP_LEN_IV]);
    let pay_key = kdf16(resp_key, &[SALT_RESP_KEY]);
    let pay_iv = kdf(resp_iv, &[SALT_RESP_IV]);
    let len_field = u16::try_from(resp_payload.len()).unwrap_or(0).to_be_bytes();
    let sealed_len = aes128gcm_seal(&len_key, len_iv.get(..12).unwrap_or(&[]), &len_field, &[])?;
    let sealed_pay = aes128gcm_seal(
        &pay_key,
        pay_iv.get(..12).unwrap_or(&[]),
        &resp_payload,
        &[],
    )?;
    conn.write_all(&sealed_len).await?;
    conn.write_all(&sealed_pay).await?;
    Ok(())
}

/// Build the up (client->server) and down (server->client) chunk codecs for the
/// negotiated security and chunk options.
fn body_codecs(req: &Request, resp_key: &[u8; 16], resp_iv: &[u8; 16]) -> io::Result<(Body, Body)> {
    let masking = req.option & OPT_CHUNK_MASKING != 0;
    let padding = req.option & OPT_GLOBAL_PADDING != 0;
    let up = Body::new(body_aead(req.security, &req.req_key)?, req.req_iv, masking, padding);
    let down = Body::new(body_aead(req.security, resp_key)?, *resp_iv, masking, padding);
    Ok((up, down))
}

/// Bridge the AEAD chunk body to a plaintext duplex and run the mux demuxer
/// (XUDP / mux.cool) over it, aborting the bridge when the session ends.
async fn serve_mux(
    conn: Stream,
    mut up: Body,
    mut down: Body,
    ctx: &Ctx,
    disp: &Dispatcher,
    policy: &Policy,
) -> io::Result<()> {
    let (mine, theirs) = tokio::io::duplex(65536);
    let (mut r, mut w) = tokio::io::split(conn);
    let (mut mr, mut mw) = tokio::io::split(mine);
    let bridge = tokio::spawn(async move {
        let up_dir = async move {
            while let Ok(Some(c)) = read_chunk(&mut r, &mut up).await {
                if !c.is_empty() && mw.write_all(&c).await.is_err() {
                    break;
                }
            }
        };
        let down_dir = async move {
            let mut buf = vec![0u8; 16384];
            loop {
                match mr.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if write_chunk(&mut w, &mut down, buf.get(..n).unwrap_or(&[]))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
            let _ = write_terminal(&mut w, &mut down).await;
        };
        tokio::join!(up_dir, down_dir);
    });
    let res = crate::mux::serve(theirs, bytes::Bytes::new(), ctx, disp, policy).await;
    bridge.abort();
    res
}

fn body_aead(security: u8, key: &[u8; 16]) -> io::Result<Option<Aead>> {
    let mk = |kind, k: &[u8]| Aead::new(kind, k).map_err(io::Error::other);
    match security {
        SEC_AES128_GCM => Ok(Some(mk(AeadKind::Aes128Gcm, key)?)),
        SEC_CHACHA20 => {
            let ck = chacha_key(key);
            Ok(Some(mk(AeadKind::ChaCha20Poly1305, &ck)?))
        }
        SEC_NONE => Ok(None),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "vmess security")),
    }
}

fn parse_header(header: &[u8]) -> Result<Request, Error> {
    // version(1) iv(16) key(16) respHeader(1) option(1) padsec(1) reserved(1) cmd(1) = 38
    if header.len() < 38 {
        return Err(Error::Protocol("vmess header short"));
    }
    let fixed = header.get(..38).ok_or(Error::Protocol("vmess header"))?;
    let mut b = Bytes::copy_from_slice(header);
    // verify FNV1a over header[..len-4]
    let body_len = header
        .len()
        .checked_sub(4)
        .ok_or(Error::Protocol("vmess fnv"))?;
    let signed = header.get(..body_len).ok_or(Error::Protocol("vmess fnv"))?;
    let expect = header.get(body_len..).ok_or(Error::Protocol("vmess fnv"))?;
    let expect = u32::from_be_bytes([
        *expect.first().ok_or(Error::Protocol("fnv"))?,
        *expect.get(1).ok_or(Error::Protocol("fnv"))?,
        *expect.get(2).ok_or(Error::Protocol("fnv"))?,
        *expect.get(3).ok_or(Error::Protocol("fnv"))?,
    ]);
    if fnv1a(signed) != expect {
        return Err(Error::Auth);
    }

    let version = *fixed.first().ok_or(Error::Protocol("ver"))?;
    if version != 1 {
        return Err(Error::Protocol("vmess version"));
    }
    let mut req_iv = [0u8; 16];
    let mut req_key = [0u8; 16];
    req_iv.copy_from_slice(fixed.get(1..17).ok_or(Error::Protocol("iv"))?);
    req_key.copy_from_slice(fixed.get(17..33).ok_or(Error::Protocol("key"))?);
    let resp_header = *fixed.get(33).ok_or(Error::Protocol("resp"))?;
    let option = *fixed.get(34).ok_or(Error::Protocol("opt"))?;
    let padsec = *fixed.get(35).ok_or(Error::Protocol("padsec"))?;
    // padsec high nibble is the address-padding length; the decrypted header
    // already includes those bytes and the FNV1a check covers them, so the
    // address codec reads what it needs and the trailing padding is just left.
    let security = padsec & 0x0f;
    let cmd = *fixed.get(37).ok_or(Error::Protocol("cmd"))?;

    // Consume the 38 fixed bytes, then addr (unless Mux, which carries no addr).
    b.advance_fixed(38)?;
    if cmd == CMD_MUX {
        return Ok(Request {
            dest: Destination::tcp(kernel::Address::Ip(std::net::Ipv4Addr::LOCALHOST.into()), 0),
            req_key,
            req_iv,
            resp_header,
            option,
            security,
            mux: true,
            email: CompactString::default(),
        });
    }
    let network = match cmd {
        CMD_TCP => Network::Tcp,
        CMD_UDP => Network::Udp,
        _ => return Err(Error::Protocol("vmess command")),
    };
    let (address, port) = AddrCodec::VMESS.read(&mut b)?;

    Ok(Request {
        dest: Destination {
            network,
            address,
            port,
        },
        req_key,
        req_iv,
        resp_header,
        option,
        security,
        mux: false,
        email: CompactString::default(),
    })
}

trait AdvanceFixed {
    fn advance_fixed(&mut self, n: usize) -> Result<(), Error>;
}

impl AdvanceFixed for Bytes {
    fn advance_fixed(&mut self, n: usize) -> Result<(), Error> {
        let _ = net::take(self, n)?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use aes::cipher::BlockCipherEncrypt;
    use std::time::Instant;

    fn auth_id(uuid: &Uuid, ts: i64, nonce: [u8; 4]) -> [u8; 16] {
        let ck = cmd_key(uuid);
        let authid_key = kdf16(&ck, &[SALT_AUTHID]);
        let cipher = <Aes128 as aes::cipher::KeyInit>::new_from_slice(&authid_key).expect("aes");
        let mut plain = [0u8; 16];
        plain[..8].copy_from_slice(&ts.to_be_bytes());
        plain[8..12].copy_from_slice(&nonce);
        let crc = crc32fast::hash(&plain[..12]);
        plain[12..16].copy_from_slice(&crc.to_be_bytes());
        let mut block = aes::cipher::Block::<Aes128>::from(plain);
        cipher.encrypt_block(&mut block);
        block.into()
    }

    fn uuid(text: &str) -> Uuid {
        Uuid::parse_str(text).expect("uuid")
    }

    fn uuid_from_index(index: u64) -> Uuid {
        let mut b = [0u8; 16];
        b[8..16].copy_from_slice(&index.to_be_bytes());
        Uuid(b)
    }

    #[test]
    fn vmess_auth_uses_preferred_user_fast_path() {
        let a = uuid("b831381d-6324-4d53-ad4f-8cda48b30811");
        let b = uuid("7cd0a7b7-7b3a-4d61-ae0b-5f0f77f2f04f");
        let table = VmessUsers::new([
            (a, CompactString::new("a@example.test"), 0),
            (b, CompactString::new("b@example.test"), 0),
        ])
        .expect("users");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_secs();
        let authid = auth_id(&b, i64::try_from(now).expect("time range"), [1, 2, 3, 4]);
        let matched = table.match_user(&authid, Some(1), &[]).expect("match");
        assert_eq!(matched.index, 1);
        assert_eq!(matched.email, "b@example.test");
        assert_eq!(matched.kind, VmessAuthKind::Preferred);
    }

    #[test]
    fn vmess_auth_uses_active_hotset_before_fallback() {
        let a = uuid("b831381d-6324-4d53-ad4f-8cda48b30811");
        let b = uuid("7cd0a7b7-7b3a-4d61-ae0b-5f0f77f2f04f");
        let table = VmessUsers::new([
            (a, CompactString::new("a@example.test"), 0),
            (b, CompactString::new("b@example.test"), 0),
        ])
        .expect("users");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_secs();
        let authid = auth_id(&b, i64::try_from(now).expect("time range"), [2, 3, 4, 5]);
        let matched = table.match_user(&authid, Some(0), &[1]).expect("match");
        assert_eq!(matched.index, 1);
        assert_eq!(matched.email, "b@example.test");
        assert_eq!(matched.kind, VmessAuthKind::Active);
    }

    #[test]
    fn vmess_auth_falls_back_after_wrong_preferred_user() {
        let a = uuid("b831381d-6324-4d53-ad4f-8cda48b30811");
        let b = uuid("7cd0a7b7-7b3a-4d61-ae0b-5f0f77f2f04f");
        let table = VmessUsers::new([
            (a, CompactString::new("a@example.test"), 0),
            (b, CompactString::new("b@example.test"), 0),
        ])
        .expect("users");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_secs();
        let authid = auth_id(&b, i64::try_from(now).expect("time range"), [5, 6, 7, 8]);
        let matched = table.match_user(&authid, Some(0), &[]).expect("match");
        assert_eq!(matched.index, 1);
        assert_eq!(matched.email, "b@example.test");
        assert_eq!(matched.kind, VmessAuthKind::Fallback);
    }

    #[test]
    fn vmess_auth_falls_back_after_bad_active_hotset() {
        let a = uuid("b831381d-6324-4d53-ad4f-8cda48b30811");
        let b = uuid("7cd0a7b7-7b3a-4d61-ae0b-5f0f77f2f04f");
        let table = VmessUsers::new([
            (a, CompactString::new("a@example.test"), 0),
            (b, CompactString::new("b@example.test"), 0),
        ])
        .expect("users");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_secs();
        let authid = auth_id(&b, i64::try_from(now).expect("time range"), [6, 7, 8, 9]);
        let matched = table
            .match_user(&authid, None, &[usize::MAX, 0])
            .expect("match");
        assert_eq!(matched.index, 1);
        assert_eq!(matched.email, "b@example.test");
        assert_eq!(matched.kind, VmessAuthKind::Fallback);
    }

    #[test]
    fn vmess_set_users_clears_auth_caches() {
        let a = uuid("b831381d-6324-4d53-ad4f-8cda48b30811");
        let b = uuid("7cd0a7b7-7b3a-4d61-ae0b-5f0f77f2f04f");
        let handler = Vmess::new(Arc::new(
            VmessUsers::new([(a, CompactString::new("a@example.test"), 0)]).expect("users"),
        ));
        handler
            .recent_users
            .lock()
            .expect("recent lock")
            .insert(std::net::Ipv4Addr::LOCALHOST.into(), 0);
        handler
            .active_users
            .lock()
            .expect("active lock")
            .push_front(0);

        handler.set_users(Arc::new(
            VmessUsers::new([(b, CompactString::new("b@example.test"), 0)]).expect("users"),
        ));

        assert!(handler.recent_users.lock().expect("recent lock").is_empty());
        assert!(handler.active_users.lock().expect("active lock").is_empty());
    }

    #[test]
    #[ignore = "manual VMess auth table timing baseline"]
    fn vmess_auth_table_size_baseline() {
        for size in [1_000usize, 10_000, 50_000] {
            let mut users = Vec::with_capacity(size);
            for i in 0..size {
                let id = uuid_from_index(u64::try_from(i).expect("index range"));
                users.push((id, CompactString::new(format!("u{i}@example.test")), 0));
            }
            let target_index = size - 1;
            let target = uuid_from_index(u64::try_from(target_index).expect("index range"));
            let table = VmessUsers::new(users).expect("users");
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_secs();
            let authid = auth_id(
                &target,
                i64::try_from(now).expect("time range"),
                [9, 8, 7, 6],
            );

            let fallback_start = Instant::now();
            let fallback = table
                .match_user(&authid, None, &[])
                .expect("fallback match");
            let fallback_elapsed = fallback_start.elapsed();
            assert_eq!(fallback.index, target_index);

            let preferred_start = Instant::now();
            let preferred = table
                .match_user(&authid, Some(target_index), &[])
                .expect("preferred match");
            let preferred_elapsed = preferred_start.elapsed();
            assert_eq!(preferred.index, target_index);

            let active_start = Instant::now();
            let active = table
                .match_user(&authid, None, &[target_index])
                .expect("active match");
            let active_elapsed = active_start.elapsed();
            assert_eq!(active.index, target_index);

            eprintln!(
                "vmess auth users={size} fallback={fallback_elapsed:?} preferred={preferred_elapsed:?} active={active_elapsed:?}"
            );
        }
    }


}
