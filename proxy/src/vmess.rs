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
use aes_gcm::aead::{Aead as _, Payload};
use aes_gcm::{Aes128Gcm, KeyInit as _GcmInit, Nonce};
use bytes::{Bytes, BytesMut};
use compact_str::CompactString;
use md5::Md5;
use sha2::{Digest, Sha256};
use shake::digest::{ExtendableOutput, Update as _, XofReader};
use shake::{Shake128, Shake128Reader};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio::time::timeout;

use kernel::types::error::Error;
use kernel::types::net::{self, AddrCodec};
use kernel::{Ctx, Destination, Dispatcher, Network, Policy, Timer, Uuid};
use transport::Stream;

use crate::ProxyInbound;
use crate::crypto::{Aead, AeadKind};
use crate::io::{ChunkRead, ChunkWrite, relay_framed, user_counter};

const MAGIC: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
const KDF_SALT: &[u8] = b"VMess AEAD KDF";
const SALT_AUTHID: &[u8] = b"AES Auth ID Encryption";
const SALT_HDR_LEN_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const SALT_HDR_LEN_IV: &[u8] = b"VMess Header AEAD Nonce_Length";
const SALT_HDR_KEY: &[u8] = b"VMess Header AEAD Key";
const SALT_HDR_IV: &[u8] = b"VMess Header AEAD Nonce";
const SALT_RESP_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
const SALT_RESP_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
const SALT_RESP_KEY: &[u8] = b"AEAD Resp Header Key";
const SALT_RESP_IV: &[u8] = b"AEAD Resp Header IV";

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
// Primitives
// ---------------------------------------------------------------------------

fn md5_16(data: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    md5::Digest::update(&mut h, data);
    h.finalize().into()
}

fn fnv1a(data: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in data {
        h ^= u32::from(*b);
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

/// cmdKey = MD5(uuid ‖ magic).
fn cmd_key(uuid: &Uuid) -> [u8; 16] {
    let mut buf = Vec::with_capacity(16usize.saturating_add(MAGIC.len()));
    buf.extend_from_slice(uuid.as_bytes());
    buf.extend_from_slice(MAGIC);
    md5_16(&buf)
}

/// VMess body ChaCha20 key: md5(k) ‖ md5(md5(k)).
fn chacha_key(k: &[u8]) -> [u8; 32] {
    let a = md5_16(k);
    let b = md5_16(&a);
    let mut out = [0u8; 32];
    if let Some(s) = out.get_mut(..16) {
        s.copy_from_slice(&a);
    }
    if let Some(s) = out.get_mut(16..) {
        s.copy_from_slice(&b);
    }
    out
}

// ---- nested-HMAC VMess KDF ----

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let h = sha256(key);
        if let Some(s) = k.get_mut(..32) {
            s.copy_from_slice(&h);
        }
    } else if let Some(s) = k.get_mut(..key.len()) {
        s.copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for (p, kk) in ipad.iter_mut().zip(k.iter()) {
        *p ^= *kk;
    }
    for (p, kk) in opad.iter_mut().zip(k.iter()) {
        *p ^= *kk;
    }
    let mut inner = Vec::with_capacity(64usize.saturating_add(msg.len()));
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(msg);
    let ih = sha256(&inner);
    let mut outer = Vec::with_capacity(96);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&ih);
    sha256(&outer)
}

fn kdf_level(keys: &[&[u8]], level: usize, msg: &[u8]) -> [u8; 32] {
    let key = match keys.get(level) {
        Some(k) => *k,
        None => return sha256(msg),
    };
    if level == 0 {
        return hmac_sha256(key, msg);
    }
    let mut k = [0u8; 64];
    if key.len() <= 64 {
        if let Some(s) = k.get_mut(..key.len()) {
            s.copy_from_slice(key);
        }
    } else {
        let h = sha256(key);
        if let Some(s) = k.get_mut(..32) {
            s.copy_from_slice(&h);
        }
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for (p, kk) in ipad.iter_mut().zip(k.iter()) {
        *p ^= *kk;
    }
    for (p, kk) in opad.iter_mut().zip(k.iter()) {
        *p ^= *kk;
    }
    let prev = level.saturating_sub(1);
    let mut inner = Vec::with_capacity(64usize.saturating_add(msg.len()));
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(msg);
    let ih = kdf_level(keys, prev, &inner);
    let mut outer = Vec::with_capacity(96);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&ih);
    kdf_level(keys, prev, &outer)
}

/// VMess KDF: nested HMAC-SHA256 keyed by the salt then each path component.
fn kdf(key: &[u8], paths: &[&[u8]]) -> [u8; 32] {
    let mut keys: Vec<&[u8]> = Vec::with_capacity(paths.len().saturating_add(1));
    keys.push(KDF_SALT);
    keys.extend_from_slice(paths);
    kdf_level(&keys, paths.len(), key)
}

fn kdf16(key: &[u8], paths: &[&[u8]]) -> [u8; 16] {
    let full = kdf(key, paths);
    let mut out = [0u8; 16];
    if let Some(s) = full.get(..16) {
        out.copy_from_slice(s);
    }
    out
}

fn aes128gcm_open(key: &[u8], nonce: &[u8], ct: &[u8], aad: &[u8]) -> io::Result<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| io::Error::other("gcm key"))?;
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "vmess header open"))
}

fn aes128gcm_seal(key: &[u8], nonce: &[u8], pt: &[u8], aad: &[u8]) -> io::Result<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| io::Error::other("gcm key"))?;
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: pt, aad })
        .map_err(|_| io::Error::other("vmess header seal"))
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
        let mut tried = if preferred.is_some() || !active.is_empty() {
            Some(vec![false; self.users.len()])
        } else {
            None
        };
        if let Some(index) = preferred
            && let Some(user) = self.users.get(index)
        {
            mark_tried(&mut tried, index);
            if let Some(matched) =
                Self::match_one(index, user, authid, now, VmessAuthKind::Preferred)
            {
                return Some(matched);
            }
        }
        for index in active {
            let index = *index;
            if was_tried(&tried, index) {
                continue;
            }
            let Some(user) = self.users.get(index) else {
                continue;
            };
            mark_tried(&mut tried, index);
            if let Some(matched) = Self::match_one(index, user, authid, now, VmessAuthKind::Active)
            {
                return Some(matched);
            }
        }
        for (index, user) in self.users.iter().enumerate() {
            if was_tried(&tried, index) {
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

fn mark_tried(tried: &mut Option<Vec<bool>>, index: usize) {
    if let Some(tried) = tried
        && let Some(slot) = tried.get_mut(index)
    {
        *slot = true;
    }
}

fn was_tried(tried: &Option<Vec<bool>>, index: usize) -> bool {
    tried
        .as_ref()
        .and_then(|t| t.get(index))
        .copied()
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Body chunk codec
// ---------------------------------------------------------------------------

struct ShakeParser {
    reader: Shake128Reader,
}

impl ShakeParser {
    fn new(iv: &[u8]) -> ShakeParser {
        let mut shake = Shake128::default();
        shake.update(iv);
        ShakeParser {
            reader: shake.finalize_xof(),
        }
    }
    fn next_u16(&mut self) -> u16 {
        let mut b = [0u8; 2];
        self.reader.read(&mut b);
        u16::from_be_bytes(b)
    }
}

/// AEAD chunk body state for one direction.
struct Body {
    aead: Option<Aead>,
    iv: [u8; 16],
    count: u16,
    shake: Option<ShakeParser>,
    global_padding: bool,
}

impl Body {
    fn overhead(&self) -> usize {
        if self.aead.is_some() {
            AeadKind::TAG
        } else {
            0
        }
    }

    fn chunk_nonce(&self) -> [u8; 12] {
        let mut n = [0u8; 12];
        let cb = self.count.to_be_bytes();
        if let Some(dst) = n.get_mut(..2) {
            dst.copy_from_slice(&cb);
        }
        if let (Some(dst), Some(src)) = (n.get_mut(2..12), self.iv.get(2..12)) {
            dst.copy_from_slice(src);
        }
        n
    }
}

async fn read_chunk<R>(r: &mut R, body: &mut Body) -> io::Result<Option<Bytes>>
where
    R: AsyncRead + Unpin,
{
    let mut size_buf = [0u8; 2];
    match r.read_exact(&mut size_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let padding = if body.global_padding {
        body.shake
            .as_mut()
            .map_or(0, |s| usize::from(s.next_u16() % 64))
    } else {
        0
    };
    let raw = u16::from_be_bytes(size_buf);
    let size = match body.shake.as_mut() {
        Some(s) => (s.next_u16() ^ raw) as usize,
        None => raw as usize,
    };
    let overhead = body.overhead();
    if size == overhead.saturating_add(padding) {
        return Ok(None); // terminal empty chunk
    }
    if size < overhead.saturating_add(padding) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "vmess chunk size",
        ));
    }
    let mut chunk = vec![0u8; size];
    r.read_exact(&mut chunk).await?;
    let ct_len = size.saturating_sub(padding);
    let ct = chunk.get(..ct_len).unwrap_or(&[]);
    let plain = match &body.aead {
        Some(aead) => {
            let nonce = body.chunk_nonce();
            aead.open(&nonce, ct)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        }
        None => ct.to_vec(),
    };
    body.count = body.count.wrapping_add(1);
    Ok(Some(Bytes::from(plain)))
}

async fn write_chunk<W>(w: &mut W, body: &mut Body, data: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let overhead = body.overhead();
    let max = 8192usize.saturating_sub(overhead).saturating_sub(64);
    for piece in data.chunks(max.max(1)) {
        let padding = if body.global_padding {
            body.shake
                .as_mut()
                .map_or(0, |s| usize::from(s.next_u16() % 64))
        } else {
            0
        };
        let ct = match &body.aead {
            Some(aead) => {
                let nonce = body.chunk_nonce();
                aead.seal(&nonce, piece).map_err(io::Error::other)?
            }
            None => piece.to_vec(),
        };
        body.count = body.count.wrapping_add(1);
        let size = ct.len().saturating_add(padding);
        let size16 = u16::try_from(size).unwrap_or(u16::MAX);
        let enc = match body.shake.as_mut() {
            Some(s) => s.next_u16() ^ size16,
            None => size16,
        };
        let mut out = BytesMut::with_capacity(size.saturating_add(2));
        out.extend_from_slice(&enc.to_be_bytes());
        out.extend_from_slice(&ct);
        if padding > 0 {
            let mut pad = vec![0u8; padding];
            rand::fill(&mut pad);
            out.extend_from_slice(&pad);
        }
        w.write_all(&out).await?;
    }
    Ok(())
}

async fn write_terminal<W>(w: &mut W, body: &mut Body) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let overhead = body.overhead();
    let padding = if body.global_padding {
        body.shake
            .as_mut()
            .map_or(0, |s| usize::from(s.next_u16() % 64))
    } else {
        0
    };
    let ct = match &body.aead {
        Some(aead) => {
            let nonce = body.chunk_nonce();
            aead.seal(&nonce, &[]).map_err(io::Error::other)?
        }
        None => Vec::new(),
    };
    body.count = body.count.wrapping_add(1);
    let _ = overhead;
    let size = ct.len().saturating_add(padding);
    let size16 = u16::try_from(size).unwrap_or(u16::MAX);
    let enc = match body.shake.as_mut() {
        Some(s) => s.next_u16() ^ size16,
        None => size16,
    };
    let mut out = BytesMut::new();
    out.extend_from_slice(&enc.to_be_bytes());
    out.extend_from_slice(&ct);
    if padding > 0 {
        let mut pad = vec![0u8; padding];
        rand::fill(&mut pad);
        out.extend_from_slice(&pad);
    }
    w.write_all(&out).await?;
    Ok(())
}

impl ChunkRead for Body {
    async fn read_chunk<R>(&mut self, r: &mut R) -> io::Result<Option<Bytes>>
    where
        R: AsyncRead + Unpin + Send,
    {
        read_chunk(r, self).await
    }
}

impl ChunkWrite for Body {
    async fn write_chunk<W>(&mut self, w: &mut W, data: &[u8]) -> io::Result<()>
    where
        W: AsyncWrite + Unpin + Send,
    {
        write_chunk(w, self, data).await
    }

    async fn finish<W>(&mut self, w: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin + Send,
    {
        write_terminal(w, self).await
    }
}

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

        // Response key/iv derived from request key/iv.
        let resp_key_full = Sha256::digest(req.req_key);
        let resp_iv_full = Sha256::digest(req.req_iv);
        let mut resp_key = [0u8; 16];
        let mut resp_iv = [0u8; 16];
        resp_key.copy_from_slice(resp_key_full.get(..16).unwrap_or(&[0u8; 16]));
        resp_iv.copy_from_slice(resp_iv_full.get(..16).unwrap_or(&[0u8; 16]));

        // AEAD response header (38 bytes): [sealed len(18)][sealed payload(20)].
        let resp_payload = [req.resp_header, 0u8, 0u8, 0u8];
        let len_key = kdf16(&resp_key, &[SALT_RESP_LEN_KEY]);
        let len_iv = kdf(&resp_iv, &[SALT_RESP_LEN_IV]);
        let pay_key = kdf16(&resp_key, &[SALT_RESP_KEY]);
        let pay_iv = kdf(&resp_iv, &[SALT_RESP_IV]);
        let len_field = u16::try_from(resp_payload.len()).unwrap_or(0).to_be_bytes();
        let sealed_len =
            aes128gcm_seal(&len_key, len_iv.get(..12).unwrap_or(&[]), &len_field, &[])?;
        let sealed_pay = aes128gcm_seal(
            &pay_key,
            pay_iv.get(..12).unwrap_or(&[]),
            &resp_payload,
            &[],
        )?;
        conn.write_all(&sealed_len).await?;
        conn.write_all(&sealed_pay).await?;

        // Body ciphers.
        let masking = req.option & OPT_CHUNK_MASKING != 0;
        let padding = req.option & OPT_GLOBAL_PADDING != 0;
        let up_aead = body_aead(req.security, &req.req_key)?;
        let down_aead = body_aead(req.security, &resp_key)?;
        let mut up = Body {
            aead: up_aead,
            iv: req.req_iv,
            count: 0,
            shake: masking.then(|| ShakeParser::new(&req.req_iv)),
            global_padding: padding,
        };
        let mut down = Body {
            aead: down_aead,
            iv: resp_iv,
            count: 0,
            shake: masking.then(|| ShakeParser::new(&resp_iv)),
            global_padding: padding,
        };

        // Mux (XUDP / mux.cool): bridge the AEAD chunk body to a plaintext
        // duplex and run the mux demuxer over it.
        if req.mux {
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
            return res;
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
    let padding_len = usize::from(padsec >> 4);
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
    let _ = padding_len;

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
