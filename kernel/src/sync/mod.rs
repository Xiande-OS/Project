//! Locking primitives.
//!
//! M1 wraps `spin::Mutex` for now. SpinLock-with-IRQ disable lives here
//! later (M2 when secondaries come online).

pub mod futex;

pub use spin::Mutex;
pub use spin::RwLock;
