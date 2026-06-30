use compact_str::CompactString;
use parking_lot::lock_api::RwLockReadGuard;
use parking_lot::{RawRwLock, RwLock};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User<P> {
    pub authentication: P,
    pub authorization: UserAuthorization,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UserAuthorization {
    Uuid(uuid::Uuid),
    Account {
        username: CompactString,
        password: CompactString,
    },
}

#[derive(Debug)]
pub struct UserListInner<P> {
    pub user_array: Vec<(User<P>, ByteCounter)>,
    pub authorization_index: HashMap<UserAuthorization, usize>,
}

#[derive(Debug)]
pub struct UserList<P>(RwLock<Arc<UserListInner<P>>>);

impl<P> UserList<P> {
    fn build_inner(user_array: impl IntoIterator<Item = User<P>>) -> Arc<UserListInner<P>> {
        let user_array: Vec<_> = user_array
            .into_iter()
            .map(|user| (user, ByteCounter::default()))
            .collect();

        let authorization_index: HashMap<_, _> = user_array
            .iter()
            .enumerate()
            .map(|(i, (user, _))| (user.authorization.clone(), i))
            .collect();

        Arc::new(UserListInner {
            user_array,
            authorization_index,
        })
    }
    pub fn new(user_array: impl IntoIterator<Item = User<P>>) -> Self {
        Self(RwLock::new(Self::build_inner(user_array)))
    }
    pub fn new_with_arc(inner: Arc<UserListInner<P>>) -> Self {
        Self(RwLock::new(inner))
    }
    pub fn read(&self) -> RwLockReadGuard<'_, RawRwLock, Arc<UserListInner<P>>> {
        self.0.read()
    }
    pub fn update(&self, new: impl IntoIterator<Item = User<P>>) {
        let new_inner = Self::build_inner(new);
        let mut guard = self.0.write();
        *guard = new_inner;
    }
}

#[derive(Debug, Default)]
pub struct ByteCounter {
    pub up: AtomicU64,
    pub down: AtomicU64,
}

#[derive(Debug, Clone)]
pub struct UserContext<P> {
    pub list: Arc<UserListInner<P>>,
    pub index: usize,
}