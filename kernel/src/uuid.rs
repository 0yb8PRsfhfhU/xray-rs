//! 16-byte UUID with xray's short-string SHA1 derivation (SPEC §2b).

use std::fmt;

use sha1::{Digest, Sha1};

use crate::error::{Error, Result};

/// A 128-bit UUID used by VLESS / VMess user identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Uuid(pub [u8; 16]);

const GROUPS: [usize; 5] = [8, 4, 4, 4, 12];

impl Uuid {
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn from_bytes(b: &[u8]) -> Result<Uuid> {
        let arr: [u8; 16] = b.try_into().map_err(|_| Error::Protocol("invalid UUID length"))?;
        Ok(Uuid(arr))
    }

    /// Parse a UUID string. Canonical 32/36-char hex forms decode directly;
    /// any other 1..=30 char string is mapped to a deterministic v5-style UUID
    /// (SHA1 over a zero namespace), matching Go's `uuid.ParseString`.
    pub fn parse_str(s: &str) -> Result<Uuid> {
        let text = s.as_bytes();
        let l = text.len();
        if l < 32 || l > 36 {
            if l == 0 || l > 30 {
                return Err(Error::Protocol("invalid UUID"));
            }
            let mut hasher = Sha1::new();
            hasher.update([0u8; 16]);
            hasher.update(text);
            let digest = hasher.finalize();
            let mut u = [0u8; 16];
            u.copy_from_slice(digest.get(..16).ok_or(Error::Crypto("sha1 short"))?);
            u[6] = (u[6] & 0x0f) | (5 << 4);
            u[8] = (u[8] & 0x3f) | 0x80;
            return Ok(Uuid(u));
        }

        let mut out = [0u8; 16];
        let mut text = text;
        let mut out_off = 0usize;
        for group in GROUPS {
            if text.first() == Some(&b'-') {
                text = text.get(1..).unwrap_or(&[]);
            }
            let hex = text.get(..group).ok_or(Error::Protocol("invalid UUID"))?;
            let nbytes = group / 2;
            let end = out_off.checked_add(nbytes).ok_or(Error::Overflow)?;
            let dst = out.get_mut(out_off..end).ok_or(Error::Protocol("invalid UUID"))?;
            decode_hex(hex, dst)?;
            text = text.get(group..).unwrap_or(&[]);
            out_off = end;
        }
        Ok(Uuid(out))
    }
}

fn decode_hex(hex: &[u8], dst: &mut [u8]) -> Result<()> {
    for (i, byte) in dst.iter_mut().enumerate() {
        let hi_idx = i.checked_mul(2).ok_or(Error::Overflow)?;
        let lo_idx = hi_idx.checked_add(1).ok_or(Error::Overflow)?;
        let hi = hex.get(hi_idx).copied().ok_or(Error::Protocol("invalid UUID"))?;
        let lo = hex.get(lo_idx).copied().ok_or(Error::Protocol("invalid UUID"))?;
        *byte = hex_val(hi)?.wrapping_shl(4) | hex_val(lo)?;
    }
    Ok(())
}

fn hex_val(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Ok(c.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Ok(c.wrapping_sub(b'A').wrapping_add(10)),
        _ => Err(Error::Protocol("invalid UUID hex")),
    }
}

impl fmt::Display for Uuid {
    #[allow(clippy::indexing_slicing)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
        )
    }
}
