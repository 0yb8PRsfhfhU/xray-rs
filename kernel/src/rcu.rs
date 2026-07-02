//! RCU-style config cell (objective requirement 2, SPEC §P2).
//!
//! Live config is a deeply-immutable `Arc<T>` published behind an [`RcuCell`].
//! Readers take a cheap snapshot (`Arc` clone) and hold it for the whole
//! operation — no reader ever blocks on a writer past the pointer read, and an
//! in-flight reader keeps its consistent snapshot after a writer swaps in a new
//! value. Update = build the new value, then atomically swap the pointer; the
//! old `Arc` drops when its last reader releases it (read-copy-update).

use parking_lot::RwLock;
use std::sync::Arc;

/// A read-copy-update cell holding an `Arc<T>`.
///
/// The `RwLock` guards only the *pointer*, never `T`; the read guard is dropped
/// as soon as the `Arc` is cloned out, so the critical section is a single
/// pointer copy. Reads never observe a torn value.
#[derive(Debug)]
pub struct RcuCell<T: ?Sized>(RwLock<Arc<T>>);

impl<T: ?Sized> RcuCell<T> {
    /// Wrap an existing `Arc<T>` (works for unsized `T`, e.g. `[U]`).
    pub fn from_arc(arc: Arc<T>) -> Self {
        RcuCell(RwLock::new(arc))
    }

    /// Clone out the current snapshot. `O(1)` refcount bump.
    pub fn load(&self) -> Arc<T> {
        self.0.read().clone()
    }

    /// Atomically publish `new`, returning the previous snapshot so the caller
    /// can drain/inspect it (swap-and-drain reload, SPEC §P2).
    pub fn swap(&self, new: Arc<T>) -> Arc<T> {
        let mut guard = self.0.write();
        std::mem::replace(&mut *guard, new)
    }
}

impl<T: Sized> RcuCell<T> {
    /// Create a cell from an owned value.
    pub fn new(value: T) -> Self {
        RcuCell(RwLock::new(Arc::new(value)))
    }

    /// Replace the value, dropping the returned old snapshot.
    pub fn store(&self, value: T) {
        self.swap(Arc::new(value));
    }
}

impl<T: Default> Default for RcuCell<T> {
    fn default() -> Self {
        RcuCell::new(T::default())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn in_flight_reader_keeps_snapshot_across_swap() {
        let cell = RcuCell::new(1u32);
        let snap = cell.load(); // reader holds v1
        cell.store(2); // writer publishes v2
        assert_eq!(*snap, 1, "in-flight snapshot is stable");
        assert_eq!(*cell.load(), 2, "new readers see v2");
    }

    #[test]
    fn swap_returns_old() {
        let cell = RcuCell::new(10u32);
        let old = cell.swap(Arc::new(20));
        assert_eq!(*old, 10);
        assert_eq!(*cell.load(), 20);
    }

    #[test]
    fn unsized_slice() {
        let cell: RcuCell<[u32]> = RcuCell::from_arc(Arc::from(vec![1, 2, 3]));
        assert_eq!(&*cell.load(), &[1, 2, 3]);
        cell.swap(Arc::from(vec![9]));
        assert_eq!(&*cell.load(), &[9]);
    }
}
