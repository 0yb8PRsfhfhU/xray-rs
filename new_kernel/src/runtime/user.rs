use arc_swap::ArcSwap;
use compact_str::CompactString;
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
pub struct UserList<P>(pub ArcSwap<UserListInner<P>>);

impl<P> UserList<P> {
    pub fn new(user_array: impl IntoIterator<Item = User<P>>) -> Self {
        let user_array: Vec<_> = user_array
            .into_iter()
            .map(|user| (user, ByteCounter::default()))
            .collect();

        let authorization_index: HashMap<_, _> = user_array
            .iter()
            .enumerate()
            .map(|(i, (user, _))| (user.authorization.clone(), i))
            .collect();

        let inner = UserListInner {
            user_array,
            authorization_index,
        };
        Self(ArcSwap::new(Arc::new(inner)))
    }
}

#[derive(Debug, Default)]
pub struct ByteCounter {
    pub up: AtomicU64,
    pub down: AtomicU64,
}
