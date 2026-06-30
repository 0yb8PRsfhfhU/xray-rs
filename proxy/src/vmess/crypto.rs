//! VMess crypto primitives: MD5/FNV1a/SHA-256, the nested-HMAC VMess KDF, the
//! cmdKey/ChaCha20 key derivations, and AES-128-GCM header sealing. Pure and
//! I/O-free, so the handler never has to reason about the AEAD-header math.

use std::io;

use aes_gcm::aead::{Aead as _, Payload};
use aes_gcm::{Aes128Gcm, KeyInit as _GcmInit, Nonce};
use md5::Md5;
use sha2::{Digest, Sha256};

use kernel::Uuid;

const MAGIC: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
const KDF_SALT: &[u8] = b"VMess AEAD KDF";
pub(crate) const SALT_AUTHID: &[u8] = b"AES Auth ID Encryption";
pub(crate) const SALT_HDR_LEN_KEY: &[u8] = b"VMess Header AEAD Key_Length";
pub(crate) const SALT_HDR_LEN_IV: &[u8] = b"VMess Header AEAD Nonce_Length";
pub(crate) const SALT_HDR_KEY: &[u8] = b"VMess Header AEAD Key";
pub(crate) const SALT_HDR_IV: &[u8] = b"VMess Header AEAD Nonce";
pub(crate) const SALT_RESP_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
pub(crate) const SALT_RESP_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
pub(crate) const SALT_RESP_KEY: &[u8] = b"AEAD Resp Header Key";
pub(crate) const SALT_RESP_IV: &[u8] = b"AEAD Resp Header IV";

fn md5_16(data: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    md5::Digest::update(&mut h, data);
    h.finalize().into()
}

pub(crate) fn fnv1a(data: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in data {
        h ^= u32::from(*b);
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

/// cmdKey = MD5(uuid ‖ magic).
pub(crate) fn cmd_key(uuid: &Uuid) -> [u8; 16] {
    let mut buf = Vec::with_capacity(16usize.saturating_add(MAGIC.len()));
    buf.extend_from_slice(uuid.as_bytes());
    buf.extend_from_slice(MAGIC);
    md5_16(&buf)
}

/// VMess body ChaCha20 key: md5(k) ‖ md5(md5(k)).
pub(crate) fn chacha_key(k: &[u8]) -> [u8; 32] {
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
    hmac_with(key, msg, sha256)
}

/// Generic HMAC, parameterized over the inner/outer hash. Single source of truth
/// for the ipad/opad block: plain HMAC-SHA256 passes `sha256`, while the nested
/// VMess KDF passes a recursion into the previous level's hash.
fn hmac_with<H: Fn(&[u8]) -> [u8; 32]>(key: &[u8], msg: &[u8], hash: H) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        if let Some(s) = k.get_mut(..32) {
            s.copy_from_slice(&sha256(key));
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
    let ih = hash(&inner);
    let mut outer = Vec::with_capacity(96);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&ih);
    hash(&outer)
}

/// One nested-HMAC level: HMAC the message under `keys[level]`, where the inner
/// and outer hashes recurse into level-1 (level 0 bottoms out at HMAC-SHA256).
fn kdf_level(keys: &[&[u8]], level: usize, msg: &[u8]) -> [u8; 32] {
    match keys.get(level) {
        None => sha256(msg),
        Some(key) if level == 0 => hmac_sha256(key, msg),
        Some(key) => hmac_with(key, msg, |m| kdf_level(keys, level.saturating_sub(1), m)),
    }
}

/// VMess KDF: nested HMAC-SHA256 keyed by the salt then each path component.
pub(crate) fn kdf(key: &[u8], paths: &[&[u8]]) -> [u8; 32] {
    let mut keys: Vec<&[u8]> = Vec::with_capacity(paths.len().saturating_add(1));
    keys.push(KDF_SALT);
    keys.extend_from_slice(paths);
    kdf_level(&keys, paths.len(), key)
}

pub(crate) fn kdf16(key: &[u8], paths: &[&[u8]]) -> [u8; 16] {
    let full = kdf(key, paths);
    let mut out = [0u8; 16];
    if let Some(s) = full.get(..16) {
        out.copy_from_slice(s);
    }
    out
}

pub(crate) fn aes128gcm_open(key: &[u8], nonce: &[u8], ct: &[u8], aad: &[u8]) -> io::Result<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| io::Error::other("gcm key"))?;
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "vmess header open"))
}

pub(crate) fn aes128gcm_seal(key: &[u8], nonce: &[u8], pt: &[u8], aad: &[u8]) -> io::Result<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| io::Error::other("gcm key"))?;
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: pt, aad })
        .map_err(|_| io::Error::other("vmess header seal"))
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

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn vmess_hmac_matches_rfc4231() {
        // RFC 4231, Test Case 1: implementation-independent HMAC-SHA256 vector.
        let mac = hmac_sha256(&[0x0b; 20], b"Hi There");
        assert_eq!(
            hex(&mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn vmess_kdf_snapshot() {
        // Golden snapshot of the nested-HMAC VMess KDF; pins byte-for-byte
        // behavior so refactors of the HMAC/KDF internals cannot drift.
        let paths: &[&[u8]] = &[SALT_HDR_KEY, b"authid", b"nonce"];
        assert_eq!(
            hex(&kdf(b"snapshot-key", paths)),
            "9edde34d519902232165aa38e91126b343487cb13158dcf479f64dc25eb2e09c"
        );
        assert_eq!(
            hex(&kdf16(b"snapshot-key", paths)),
            "9edde34d519902232165aa38e91126b3"
        );
    }
}
