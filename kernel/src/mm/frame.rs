//! Physical frame allocator.
//!
//! Wraps `buddy_system_allocator::FrameAllocator` so callers see a typed
//! `PhysPageNum`. `FrameTracker` is an RAII guard that frees on drop —
//! exactly what `MemorySet` wants when a process exits.

use core::fmt;

use buddy_system_allocator::LockedFrameAllocator;
use spin::Lazy;

use super::address::{PhysAddr, PhysPageNum, PAGE_SIZE};

static FRAME_ALLOC: Lazy<LockedFrameAllocator<32>> = Lazy::new(LockedFrameAllocator::new);

/// Register the [start, end) physical range as the kernel's free frame pool.
/// Pass `[__kernel_end .. MEMORY_END)` from boot.
pub fn init(pa_start: PhysAddr, pa_end: PhysAddr) {
    let start = pa_start.0.div_ceil(PAGE_SIZE);
    let end = pa_end.0 / PAGE_SIZE;
    assert!(end > start, "frame range empty");
    FRAME_ALLOC.lock().add_frame(start, end);
}

pub fn alloc() -> Option<FrameTracker> {
    FRAME_ALLOC
        .lock()
        .alloc(1)
        .map(|ppn_usize| FrameTracker::new_zeroed(PhysPageNum(ppn_usize)))
}

pub fn dealloc(ppn: PhysPageNum) {
    FRAME_ALLOC.lock().dealloc(ppn.0, 1);
}

/// Owns one physical frame; frees on drop.
pub struct FrameTracker {
    pub ppn: PhysPageNum,
}

impl FrameTracker {
    fn new_zeroed(ppn: PhysPageNum) -> Self {
        for b in ppn.as_byte_slice().iter_mut() {
            *b = 0;
        }
        Self { ppn }
    }
}

impl Drop for FrameTracker {
    fn drop(&mut self) {
        dealloc(self.ppn);
    }
}

impl fmt::Debug for FrameTracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FrameTracker({:?})", self.ppn)
    }
}
