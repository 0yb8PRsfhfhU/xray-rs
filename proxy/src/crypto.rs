//! Shared protocol crypto: AEAD ciphers, key schedules, nonce counters
//! (SPEC §2e). Reused by Shadowsocks (and VMess body crypto).

use aes_gcm::aead::Aead as _;
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use aes_gcm::{KeyInit, Nonce};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use hkdf::Hkdf;
use md5::Md5;
use sha1::Sha1;
use sha2::Digest;

use kernel::types::error::{Error, Result};

/// Supported AEAD ciphers (Shadowsocks + VMess body).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadKind {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

impl AeadKind {
    pub fn key_size(self) -> usize {
        match self {
            AeadKind::Aes128Gcm => 16,
            AeadKind::Aes256Gcm | AeadKind::ChaCha20Poly1305 | AeadKind::XChaCha20Poly1305 => 32,
        }
    }

    pub fn nonce_size(self) -> usize {
        match self {
            AeadKind::XChaCha20Poly1305 => 24,
            _ => 12,
        }
    }

    pub const TAG: usize = 16;
}

/// A keyed AEAD instance.
pub enum Aead {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
    Cha(Box<ChaCha20Poly1305>),
    XCha(Box<XChaCha20Poly1305>),
}

impl Aead {
    /// Build a keyed AEAD. `key` length must equal `kind.key_size()`.
    pub fn new(kind: AeadKind, key: &[u8]) -> Result<Aead> {
        let bad = |_| Error::Crypto("aead key");
        Ok(match kind {
            AeadKind::Aes128Gcm => {
                Aead::Aes128(Box::new(Aes128Gcm::new_from_slice(key).map_err(bad)?))
            }
            AeadKind::Aes256Gcm => {
                Aead::Aes256(Box::new(Aes256Gcm::new_from_slice(key).map_err(bad)?))
            }
            AeadKind::ChaCha20Poly1305 => Aead::Cha(Box::new(
                ChaCha20Poly1305::new_from_slice(key).map_err(bad)?,
            )),
            AeadKind::XChaCha20Poly1305 => Aead::XCha(Box::new(
                XChaCha20Poly1305::new_from_slice(key).map_err(bad)?,
            )),
        })
    }

    /// Encrypt `plain` with `nonce` (empty AAD), returning ciphertext+tag.
    pub fn seal(&self, nonce: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
        let err = |_| Error::Crypto("aead seal");
        match self {
            Aead::Aes128(c) => c.encrypt(Nonce::from_slice(nonce), plain).map_err(err),
            Aead::Aes256(c) => c.encrypt(Nonce::from_slice(nonce), plain).map_err(err),
            Aead::Cha(c) => c
                .encrypt(chacha20poly1305::Nonce::from_slice(nonce), plain)
                .map_err(err),
            Aead::XCha(c) => c
                .encrypt(chacha20poly1305::XNonce::from_slice(nonce), plain)
                .map_err(err),
        }
    }

    /// Decrypt `ct` (ciphertext+tag) with `nonce` (empty AAD).
    pub fn open(&self, nonce: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        let err = |_| Error::Crypto("aead open");
        match self {
            Aead::Aes128(c) => c.decrypt(Nonce::from_slice(nonce), ct).map_err(err),
            Aead::Aes256(c) => c.decrypt(Nonce::from_slice(nonce), ct).map_err(err),
            Aead::Cha(c) => c
                .decrypt(chacha20poly1305::Nonce::from_slice(nonce), ct)
                .map_err(err),
            Aead::XCha(c) => c
                .decrypt(chacha20poly1305::XNonce::from_slice(nonce), ct)
                .map_err(err),
        }
    }
}

/// A little-endian counter nonce of fixed size (Shadowsocks / VMess).
pub struct NonceCtr {
    buf: [u8; 24],
    size: usize,
}

impl NonceCtr {
    pub fn new(size: usize) -> NonceCtr {
        NonceCtr {
            buf: [0u8; 24],
            size: size.min(24),
        }
    }

    /// Current nonce bytes.
    pub fn bytes(&self) -> &[u8] {
        self.buf.get(..self.size).unwrap_or(&self.buf)
    }

    /// Increment the little-endian counter by one.
    pub fn inc(&mut self) {
        for b in self.buf.iter_mut().take(self.size) {
            let (v, carry) = b.overflowing_add(1);
            *b = v;
            if !carry {
                break;
            }
        }
    }
}

/// OpenSSL `EVP_BytesToKey` (single MD5 chain, no salt) — Shadowsocks master key.
pub fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
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

/// `HKDF-SHA1(secret, salt, info)` filling `out` — Shadowsocks subkey schedule.
pub fn hkdf_sha1(secret: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    let hk = Hkdf::<Sha1>::new(Some(salt), secret);
    hk.expand(info, out)
        .map_err(|_| Error::Crypto("hkdf expand"))
}
