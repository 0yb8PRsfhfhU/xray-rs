//! VMess user table and authID trial matching. The hot path first tries the
//! active-user hotset, then falls back to a full scan without retrying indices
//! already tested in the hotset pass.

use std::time::{SystemTime, UNIX_EPOCH};

use aes::Aes128;
use aes::cipher::BlockCipherDecrypt;
use compact_str::CompactString;

use kernel::Uuid;
use kernel::types::error::Error;

use super::crypto::{SALT_AUTHID, cmd_key, kdf16};

/// A VMess user with precomputed cmdKey + authID cipher.
pub(crate) struct VmessUser {
    cmd_key: [u8; 16],
    authid_cipher: Aes128,
    email: CompactString,
    _level: u32,
}

pub(crate) struct VmessAuth {
    pub(crate) index: usize,
    pub(crate) cmd_key: [u8; 16],
    pub(crate) email: CompactString,
    pub(crate) kind: VmessAuthKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VmessAuthKind {
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
                _level: level,
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
        if t < 0 || now.abs_diff(t) > 120 {
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
    pub(crate) fn match_user(&self, authid: &[u8; 16], active: &[usize]) -> Option<VmessAuth> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_secs()).ok())
            .unwrap_or(0);
        let mut tried = TriedSet::new(!active.is_empty(), self.users.len());
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
/// active pass never re-tests a user that the fallback scan repeats.
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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use std::time::Instant;

    use aes::cipher::BlockCipherEncrypt;

    use super::*;

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
        let matched = table.match_user(&authid, &[1]).expect("match");
        assert_eq!(matched.index, 1);
        assert_eq!(matched.email, "b@example.test");
        assert_eq!(matched.kind, VmessAuthKind::Active);
    }

    #[test]
    fn vmess_auth_falls_back_without_active_hit() {
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
        let matched = table.match_user(&authid, &[]).expect("match");
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
        let matched = table.match_user(&authid, &[usize::MAX, 0]).expect("match");
        assert_eq!(matched.index, 1);
        assert_eq!(matched.email, "b@example.test");
        assert_eq!(matched.kind, VmessAuthKind::Fallback);
    }

    #[test]
    fn vmess_auth_rejects_expired_timestamp() {
        let id = uuid("b831381d-6324-4d53-ad4f-8cda48b30811");
        let table =
            VmessUsers::new([(id, CompactString::new("a@example.test"), 0)]).expect("users");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_secs();
        let ts = i64::try_from(now.saturating_sub(121)).expect("time range");
        let authid = auth_id(&id, ts, [1, 1, 1, 1]);
        assert!(table.match_user(&authid, &[]).is_none());
    }

    #[test]
    fn vmess_auth_rejects_future_timestamp_outside_window() {
        let id = uuid("b831381d-6324-4d53-ad4f-8cda48b30811");
        let table =
            VmessUsers::new([(id, CompactString::new("a@example.test"), 0)]).expect("users");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_secs();
        let ts = i64::try_from(now.saturating_add(121)).expect("time range");
        let authid = auth_id(&id, ts, [2, 2, 2, 2]);
        assert!(table.match_user(&authid, &[]).is_none());
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
            let fallback = table.match_user(&authid, &[]).expect("fallback match");
            let fallback_elapsed = fallback_start.elapsed();
            assert_eq!(fallback.index, target_index);

            let active_start = Instant::now();
            let active = table
                .match_user(&authid, &[target_index])
                .expect("active match");
            let active_elapsed = active_start.elapsed();
            assert_eq!(active.index, target_index);

            eprintln!(
                "vmess auth users={size} fallback={fallback_elapsed:?} active={active_elapsed:?}"
            );
        }
    }
}
