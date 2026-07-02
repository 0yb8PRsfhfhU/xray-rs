//! Users: abstract authentication data + an authorization enum, plus an
//! RCU-published user table (objective requirement 1; SPEC §P2).
//!
//! `authentication` is intentionally a free type parameter `P`: a proxy stores
//! whatever secret it authenticates against (a trojan password hash, a VMess
//! cmd-key, a SOCKS credential set) without the kernel knowing its shape. The
//! *authorization* — the stable identity the router and stats key on — is the
//! closed [`UserAuthorization`] enum.

use crate::rcu::RcuCell;
use compact_str::CompactString;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Marker for a type usable as abstract per-user authentication data. Blanket
/// implemented; exists so bounds read as `P: Authentication`.
pub trait Authentication: Send + Sync + 'static {}
impl<T: Send + Sync + 'static> Authentication for T {}

/// One user: opaque authentication data `P` plus a stable authorization key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User<P> {
    /// Protocol-specific secret used to authenticate the handshake.
    pub authentication: P,
    /// Stable identity used for routing (`user_auth_hash` balancing) and stats.
    pub authorization: UserAuthorization,
}

/// The closed set of authorization identities a proxy can present.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UserAuthorization {
    /// UUID identity (VLESS / VMess).
    Uuid(uuid::Uuid),
    /// Username/password account (SOCKS / HTTP / trojan-by-name).
    Account {
        username: CompactString,
        password: CompactString,
    },
}

impl UserAuthorization {
    /// A stable 64-bit hash of the identity, used by the `user_auth_hash`
    /// load-balancer to pin a user to one outbound (objective requirement 5).
    pub fn stable_hash(&self) -> u64 {
        // FNV-1a over a discriminant-tagged encoding: deterministic across runs
        // (unlike `DefaultHasher`, whose seed can change).
        const OFFSET: u64 = 0xcbf29ce484222325;
        const PRIME: u64 = 0x100000001b3;
        let mut h = OFFSET;
        let mut mix = |bytes: &[u8]| {
            for &b in bytes {
                h ^= u64::from(b);
                h = h.wrapping_mul(PRIME);
            }
        };
        match self {
            UserAuthorization::Uuid(u) => {
                mix(&[0u8]);
                mix(u.as_bytes());
            }
            UserAuthorization::Account { username, password } => {
                mix(&[1u8]);
                mix(username.as_bytes());
                mix(&[0u8]);
                mix(password.as_bytes());
            }
        }
        h
    }
}

/// The immutable inner state of a [`UserList`]: the users plus an index from
/// authorization identity to slot, so auth is an `O(1)` map lookup (SPEC §P2).
#[derive(Debug)]
pub struct UserListInner<P> {
    pub users: Vec<(User<P>, ByteCounter)>,
    pub authorization_index: HashMap<UserAuthorization, usize>,
}

impl<P> UserListInner<P> {
    /// Look up a user slot by its authorization identity.
    pub fn find(&self, authz: &UserAuthorization) -> Option<usize> {
        self.authorization_index.get(authz).copied()
    }
}

/// An RCU-published table of users. AddUser/RemoveUser rebuild the inner state
/// and atomically swap the pointer — the auth path never blocks on a writer
/// and never locks a shared mutable map (SPEC §P2).
#[derive(Debug)]
pub struct UserList<P>(RcuCell<UserListInner<P>>);

impl<P> UserList<P> {
    fn build_inner(users: impl IntoIterator<Item = User<P>>) -> UserListInner<P> {
        let users: Vec<_> = users
            .into_iter()
            .map(|user| (user, ByteCounter::default()))
            .collect();
        let authorization_index: HashMap<_, _> = users
            .iter()
            .enumerate()
            .map(|(i, (user, _))| (user.authorization.clone(), i))
            .collect();
        UserListInner {
            users,
            authorization_index,
        }
    }

    pub fn new(users: impl IntoIterator<Item = User<P>>) -> Self {
        Self(RcuCell::new(Self::build_inner(users)))
    }

    pub fn from_inner(inner: Arc<UserListInner<P>>) -> Self {
        Self(RcuCell::from_arc(inner))
    }

    /// Take a cheap snapshot of the current table (SPEC §P2).
    pub fn load(&self) -> Arc<UserListInner<P>> {
        self.0.load()
    }

    /// Rebuild the table from a new user set and publish it atomically.
    pub fn replace(&self, users: impl IntoIterator<Item = User<P>>) {
        self.0.store(Self::build_inner(users));
    }
}

/// Lock-free per-user upload/download byte counter carried alongside each user.
#[derive(Debug, Default)]
pub struct ByteCounter {
    pub up: AtomicU64,
    pub down: AtomicU64,
}

impl ByteCounter {
    pub fn add_up(&self, n: u64) {
        self.up.fetch_add(n, Ordering::Relaxed);
    }
    pub fn add_down(&self, n: u64) {
        self.down.fetch_add(n, Ordering::Relaxed);
    }
}

/// A resolved reference to one authenticated user: the table snapshot it lives
/// in plus its slot. Carried on the session so the relay can attribute traffic.
#[derive(Debug, Clone)]
pub struct UserContext<P> {
    pub list: Arc<UserListInner<P>>,
    pub index: usize,
}

impl<P> UserContext<P> {
    /// The authenticated user, if the slot is still valid.
    pub fn user(&self) -> Option<&User<P>> {
        self.list.users.get(self.index).map(|(u, _)| u)
    }
}
