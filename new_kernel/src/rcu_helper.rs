use parking_lot::{RwLock, RwLockReadGuard};
use std::sync::Arc;

#[derive(Debug)]
pub struct RcuCell<T: ?Sized>(RwLock<Arc<T>>);

impl<T: ?Sized> RcuCell<T> {
    pub fn from_arc(arc: Arc<T>) -> Self {
        RcuCell(RwLock::new(arc))
    }
    pub fn read(&self) -> RwLockReadGuard<'_, Arc<T>> {
        self.0.read()
    }
    pub fn read_owned(&self) -> Arc<T> {
        self.0.read().clone()
    }
    pub fn swap_arc(&self, new_value: Arc<T>) -> Arc<T> {
        let old_value = self.0.write().clone();
        *self.0.write() = new_value;
        old_value
    }
}

impl<T: Sized> RcuCell<T> {
    pub fn new(value: T) -> Self {
        RcuCell(RwLock::new(Arc::new(value)))
    }
    pub fn update(&self, new_value: T) {
        *self.0.write() = Arc::new(new_value);
    }
}
