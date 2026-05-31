//! Locking primitives.
//!
//! `Mutex` is a preempt-safe wrapper over `spin::Mutex` (see `spinlock`): while
//! a lock is held it disables scheduler preemption, so a task holding a
//! spinlock is never switched out on this single hart (which would deadlock the
//! next task spinning on it).

pub mod futex;
mod spinlock;

pub use spinlock::{preempt_disable, preempt_enable, preempt_enabled, preempt_reset};
pub use spinlock::{Mutex, MutexGuard};

pub use spin::RwLock;
