//! Physical frame allocator.
//!
//! Wraps `buddy_system_allocator::FrameAllocator` so callers see a typed
//! `PhysPageNum`. `FrameTracker` is an RAII guard that frees on drop —
//! exactly what `MemorySet` wants when a process exits.

use core::fmt;
use core::sync::atomic::{AtomicUsize, Ordering};

use buddy_system_allocator::LockedFrameAllocator;
use spin::Lazy;

use super::address::{PhysAddr, PhysPageNum, PAGE_SIZE};

static FRAME_ALLOC: Lazy<LockedFrameAllocator<32>> = Lazy::new(LockedFrameAllocator::new);

/// Total pages put into the frame pool at boot (constant after `init`).
static TOTAL_PAGES: AtomicUsize = AtomicUsize::new(0);
/// Pages currently handed out (in-use). Decremented on dealloc.
static ALLOCATED_PAGES: AtomicUsize = AtomicUsize::new(0);

/// Register the [start, end) physical range as the kernel's free frame pool.
/// Pass `[__kernel_end .. MEMORY_END)` from boot.
pub fn init(pa_start: PhysAddr, pa_end: PhysAddr) {
    let start = pa_start.0.div_ceil(PAGE_SIZE);
    let end = pa_end.0 / PAGE_SIZE;
    assert!(end > start, "frame range empty");
    FRAME_ALLOC.lock().add_frame(start, end);
    TOTAL_PAGES.store(end - start, Ordering::Relaxed);
}

pub fn alloc() -> Option<FrameTracker> {
    if let Some(f) = try_alloc_zeroed() {
        return Some(f);
    }
    // Out of frames: reclaim a finished fork/thread-storm's dead leftovers
    // (their user frames are freed as the tasks are reaped) and retry once.
    crate::task::emergency_reclaim();
    try_alloc_zeroed()
}

fn try_alloc_zeroed() -> Option<FrameTracker> {
    // The frame pool is guarded by a plain spin::Mutex (inside
    // LockedFrameAllocator) that the preemption count can't see; disable
    // preemption around it so a preempted holder can't deadlock the next
    // allocator on this single hart.
    crate::sync::preempt_disable();
    let res = FRAME_ALLOC
        .lock()
        .alloc(1)
        .map(|ppn_usize| FrameTracker::new_zeroed(PhysPageNum(ppn_usize)));
    crate::sync::preempt_enable();
    if res.is_some() {
        ALLOCATED_PAGES.fetch_add(1, Ordering::Relaxed);
    }
    res
}

/// Allocate a frame WITHOUT zeroing it. Only sound when the caller
/// immediately overwrites the entire page; otherwise stale physical
/// contents would leak to user space. The fork copy path qualifies — it
/// does a full-page `copy_from_slice` straight after — and skipping the
/// zero there removes a redundant 4 KiB write per copied page (the page is
/// zeroed and then overwritten), which matters when a busybox `fork`
/// duplicates a multi-thousand-page address space on every shell command.
pub fn alloc_uninit() -> Option<FrameTracker> {
    if let Some(f) = try_alloc_uninit() {
        return Some(f);
    }
    crate::task::emergency_reclaim();
    try_alloc_uninit()
}

fn try_alloc_uninit() -> Option<FrameTracker> {
    crate::sync::preempt_disable();
    let res = FRAME_ALLOC
        .lock()
        .alloc(1)
        .map(|ppn_usize| FrameTracker { ppn: PhysPageNum(ppn_usize) });
    crate::sync::preempt_enable();
    if res.is_some() {
        ALLOCATED_PAGES.fetch_add(1, Ordering::Relaxed);
    }
    res
}

pub fn dealloc(ppn: PhysPageNum) {
    crate::sync::preempt_disable();
    FRAME_ALLOC.lock().dealloc(ppn.0, 1);
    crate::sync::preempt_enable();
    ALLOCATED_PAGES.fetch_sub(1, Ordering::Relaxed);
}

/// (total_pages, free_pages) snapshot of the frame allocator. Used by procfs
/// to fill in /proc/meminfo.
pub fn frame_stats() -> (usize, usize) {
    let total = TOTAL_PAGES.load(Ordering::Relaxed);
    let used = ALLOCATED_PAGES.load(Ordering::Relaxed);
    (total, total.saturating_sub(used))
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
