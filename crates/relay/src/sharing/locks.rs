//! The one way sharing and the directory take their locks: a lock a panic poisoned is taken
//! anyway, with what it holds. Every value behind these locks is a cache of what the network
//! keeps sending (members, offers, records within the horizon, parity being reassembled), so a
//! half-made change costs at most what the next tick or the next message rebuilds, while a
//! poisoned lock refused for good would end sharing (or the directory) until the relay restarts.
//! No code in either takes a `std::sync` lock any other way.

use std::sync::{Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

pub fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

pub fn read<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(PoisonError::into_inner)
}

pub fn write<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(PoisonError::into_inner)
}
