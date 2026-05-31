//! Preempt-safe mutex for the single-hart preemptive scheduler.
//!
//! `Mutex` is a thin wrapper over `spin::Mutex` with the same surface, but
//! holding a guard bumps a per-hart preemption-disable count. The timer-driven
//! scheduler refuses to switch tasks while that count is non-zero: on a single
//! hart, preempting a task that holds a spinlock would let the next task spin
//! on it forever (the holder can't run to release it). Re-enabling preemption
//! happens *after* the lock is released, so there is never a window where we
//! are preemptible while still holding the lock.

use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicUsize, Ordering};

/// Per-hart preemption-disable nesting count (the kernel runs on one hart).
static PREEMPT_DISABLE: AtomicUsize = AtomicUsize::new(0);

/// Disable preemption (nestable). The scheduler will not switch tasks until
/// the matching `preempt_enable`.
#[inline]
pub fn preempt_disable() {
    PREEMPT_DISABLE.fetch_add(1, Ordering::Acquire);
}

/// Re-enable preemption (undoes one `preempt_disable`).
#[inline]
pub fn preempt_enable() {
    PREEMPT_DISABLE.fetch_sub(1, Ordering::Release);
}

/// True when no lock is held and the scheduler may preempt the current task.
#[inline]
pub fn preempt_enabled() -> bool {
    PREEMPT_DISABLE.load(Ordering::Acquire) == 0
}

/// Force the count back to zero. The fault/watchdog recovery path abandons a
/// task's kernel stack without running its outstanding guards' destructors, so
/// their `preempt_enable`s never fire; without this reset the count would leak
/// upward and disable preemption forever. Safe because that path also
/// force-releases the underlying locks and switches to a fresh task.
#[inline]
pub fn preempt_reset() {
    PREEMPT_DISABLE.store(0, Ordering::Release);
}

/// Preempt-safe mutex. Same API as `spin::Mutex`; holding the guard disables
/// preemption.
pub struct Mutex<T: ?Sized> {
    inner: spin::Mutex<T>,
}

unsafe impl<T: ?Sized + Send> Send for Mutex<T> {}
unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    #[inline]
    pub const fn new(val: T) -> Self {
        Self { inner: spin::Mutex::new(val) }
    }

    #[inline]
    pub fn into_inner(self) -> T {
        self.inner.into_inner()
    }
}

impl<T: ?Sized> Mutex<T> {
    #[inline]
    pub fn lock(&self) -> MutexGuard<'_, T> {
        preempt_disable();
        MutexGuard { inner: Some(self.inner.lock()) }
    }

    #[inline]
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        preempt_disable();
        match self.inner.try_lock() {
            Some(g) => Some(MutexGuard { inner: Some(g) }),
            None => {
                preempt_enable();
                None
            }
        }
    }

    #[inline]
    pub fn is_locked(&self) -> bool {
        self.inner.is_locked()
    }

    /// # Safety
    /// As `spin::Mutex::force_unlock`: the caller guarantees the lock is held
    /// and no live guard will keep using it. This does NOT undo the abandoned
    /// guard's `preempt_disable` — the recovery paths that call it also call
    /// [`preempt_reset`].
    #[inline]
    pub unsafe fn force_unlock(&self) {
        self.inner.force_unlock();
    }

    #[inline]
    pub fn get_mut(&mut self) -> &mut T {
        self.inner.get_mut()
    }
}

pub struct MutexGuard<'a, T: ?Sized + 'a> {
    inner: Option<spin::MutexGuard<'a, T>>,
}

impl<'a, T: ?Sized> Deref for MutexGuard<'a, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        // Always Some between construction and Drop.
        self.inner.as_ref().unwrap()
    }
}

impl<'a, T: ?Sized> DerefMut for MutexGuard<'a, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        self.inner.as_mut().unwrap()
    }
}

impl<'a, T: ?Sized> Drop for MutexGuard<'a, T> {
    #[inline]
    fn drop(&mut self) {
        // Drop the spin guard first (releases the lock), then re-enable
        // preemption — never preemptible while the lock is still held.
        self.inner = None;
        preempt_enable();
    }
}
