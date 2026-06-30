//! VMess inbound (SPEC §2e) — the AEAD-header variant used by modern xray.
//!
//! Flow: 16B authID (AES-ECB trial-match → user/cmdKey + ±120s time window) →
//! AEAD header (nested-HMAC KDF) → 38B fixed header + addr + padding + FNV1a →
//! per-security AEAD chunk body with optional SHAKE128 length masking + padding.
//! `flow=none` equivalent; Mux (cmd 3) is out of scope (deferred with XUDP/mux).

use std::collections::{HashSet, VecDeque};
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio::time::timeout;

use kernel::{Ctx, Dispatcher, Network, Policy, Timer};
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

const VMESS_ACTIVE_AUTH_MAX: usize = 1024;
const VMESS_AUTH_REPLAY_WINDOW_SECS: u64 = 120;
const VMESS_AUTH_REPLAY_MAX: usize = 65_536;

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

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

struct ReplayEntry {
    authid: [u8; 16],
    expires_at: u64,
}

#[derive(Default)]
struct ReplayFilter {
    seen: HashSet<[u8; 16]>,
    order: VecDeque<ReplayEntry>,
}

impl ReplayFilter {
    fn check_insert(&mut self, authid: [u8; 16], now: u64) -> bool {
        self.prune(now);
        if self.seen.contains(&authid) || self.seen.len() >= VMESS_AUTH_REPLAY_MAX {
            return false;
        }
        let expires_at = now.saturating_add(VMESS_AUTH_REPLAY_WINDOW_SECS);
        let _ = self.seen.insert(authid);
        self.order.push_back(ReplayEntry { authid, expires_at });
        true
    }

    fn prune(&mut self, now: u64) {
        while let Some(entry) = self.order.front() {
            if entry.expires_at > now {
                break;
            }
            let Some(entry) = self.order.pop_front() else {
                break;
            };
            self.seen.remove(&entry.authid);
        }
    }
}

mod body;
mod header;
mod user;

use body::*;
use header::{Request, parse_header};
use user::VmessAuthKind;
pub use user::VmessUsers;

/// VMess inbound handler.
pub struct Vmess {
    users: arc_swap::ArcSwap<VmessUsers>,
    active_users: Arc<Mutex<VecDeque<usize>>>,
    replay_filter: Arc<Mutex<ReplayFilter>>,
    auth_active_hits: AtomicU64,
    auth_fallback_hits: AtomicU64,
    auth_failures: AtomicU64,
}

impl Vmess {
    pub fn new(users: Arc<VmessUsers>) -> Vmess {
        Vmess {
            users: arc_swap::ArcSwap::from(users),
            active_users: Arc::new(Mutex::new(VecDeque::new())),
            replay_filter: Arc::new(Mutex::new(ReplayFilter::default())),
            auth_active_hits: AtomicU64::new(0),
            auth_fallback_hits: AtomicU64::new(0),
            auth_failures: AtomicU64::new(0),
        }
    }

    /// Swap in a new user table (live user sync, SPEC §P2).
    pub fn set_users(&self, users: Arc<VmessUsers>) {
        self.users.store(users);
        if let Ok(mut active) = self.active_users.lock() {
            active.clear();
        }
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
            VmessAuthKind::Active => {
                self.auth_active_hits.fetch_add(1, Ordering::Relaxed);
            }
            VmessAuthKind::Fallback => {
                self.auth_fallback_hits.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn remember_authid_once(&self, authid: [u8; 16]) -> io::Result<bool> {
        self.replay_filter
            .lock()
            .map(|mut replay| replay.check_insert(authid, unix_now_secs()))
            .map_err(|_| io::Error::other("vmess replay filter poisoned"))
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
        let active = self.active_user_snapshot();
        let failures = &self.auth_failures;
        let permit = vmess_auth_limiter()
            .acquire_owned()
            .await
            .map_err(|_| io::Error::other("vmess auth limiter closed"))?;
        let matched = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            users.match_user(&authid, &active)
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
        if !self.remember_authid_once(authid)? {
            failures.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                session = ctx.id,
                failures = failures.load(Ordering::Relaxed),
                "vmess auth replay"
            );
            return Err(io::Error::new(io::ErrorKind::InvalidData, "vmess replay"));
        }
        self.record_auth_hit(matched.kind);
        self.remember_active_user(matched.index);
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
    let up = Body::new(
        body_aead(req.security, &req.req_key)?,
        req.req_iv,
        masking,
        padding,
    );
    let down = Body::new(
        body_aead(req.security, resp_key)?,
        *resp_iv,
        masking,
        padding,
    );
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
    use compact_str::CompactString;
    use kernel::Uuid;

    fn uuid(text: &str) -> Uuid {
        Uuid::parse_str(text).expect("uuid")
    }

    #[test]
    fn vmess_set_users_clears_active_auth_hotset() {
        let a = uuid("b831381d-6324-4d53-ad4f-8cda48b30811");
        let b = uuid("7cd0a7b7-7b3a-4d61-ae0b-5f0f77f2f04f");
        let handler = Vmess::new(Arc::new(
            VmessUsers::new([(a, CompactString::new("a@example.test"), 0)]).expect("users"),
        ));
        handler
            .active_users
            .lock()
            .expect("active lock")
            .push_front(0);

        handler.set_users(Arc::new(
            VmessUsers::new([(b, CompactString::new("b@example.test"), 0)]).expect("users"),
        ));

        assert!(handler.active_users.lock().expect("active lock").is_empty());
    }

    #[test]
    fn vmess_replay_filter_accepts_once_and_rejects_replay() {
        let mut filter = ReplayFilter::default();
        let authid = [7u8; 16];

        assert!(filter.check_insert(authid, 1000));
        assert!(!filter.check_insert(authid, 1001));
    }

    #[test]
    fn vmess_replay_filter_allows_authid_after_expiry() {
        let mut filter = ReplayFilter::default();
        let authid = [8u8; 16];

        assert!(filter.check_insert(authid, 1000));
        assert!(filter.check_insert(
            authid,
            1000u64.saturating_add(VMESS_AUTH_REPLAY_WINDOW_SECS)
        ));
    }

    #[test]
    fn vmess_auth_stats_record_active_and_fallback_hits() {
        let id = uuid("b831381d-6324-4d53-ad4f-8cda48b30811");
        let handler = Vmess::new(Arc::new(
            VmessUsers::new([(id, CompactString::new("a@example.test"), 0)]).expect("users"),
        ));

        handler.record_auth_hit(VmessAuthKind::Active);
        handler.record_auth_hit(VmessAuthKind::Fallback);
        handler.remember_active_user(0);

        assert_eq!(handler.auth_active_hits(), 1);
        assert_eq!(handler.auth_fallback_hits(), 1);
        assert_eq!(
            handler
                .active_users
                .lock()
                .expect("active lock")
                .front()
                .copied(),
            Some(0)
        );
    }
}
