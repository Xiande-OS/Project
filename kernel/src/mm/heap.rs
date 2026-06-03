//! Kernel heap.
//!
//! Lives in a static `.bss` buffer; the buddy allocator manages it as a
//! linked free list. M1 keeps this simple — once frame allocation is up
//! we could move to a slab on top, but a single LockedHeap covers all
//! kmalloc needs through M5 easily.

use buddy_system_allocator::LockedHeap;
use core::alloc::{GlobalAlloc, Layout};

/// Preempt-safe global allocator. The buddy `LockedHeap` guards its free lists
/// with a plain `spin::Mutex` that the preemption count cannot see, so a task
/// preempted mid-allocation would strand that lock and deadlock the next task's
/// allocation on this single hart. Bracket every alloc/dealloc with
/// preempt_disable/enable so the scheduler never switches away while the heap
/// lock is held. (realloc/alloc_zeroed use the default impls, which route
/// through these.)
struct PreemptHeap(LockedHeap<32>);

unsafe impl GlobalAlloc for PreemptHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        crate::sync::preempt_disable();
        let p = self.0.alloc(layout);
        crate::sync::preempt_enable();
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        crate::sync::preempt_disable();
        self.0.dealloc(ptr, layout);
        crate::sync::preempt_enable();
    }
}

// libc-bench's b_stdio_putcgetc et al. allocate ~8 MB scratch buffers
// per bench. The contest harness also forks many short-lived ELFs whose
// images we slurp into Vec<u8> in sys_execve. 32 MB was hitting alloc
// failures mid-libcbench. 128 MB still fits inside QEMU virt's -m 1G.
const KERNEL_HEAP_SIZE: usize = 256 * 1024 * 1024;

#[link_section = ".bss.heap"]
static mut KERNEL_HEAP: [u8; KERNEL_HEAP_SIZE] = [0; KERNEL_HEAP_SIZE];

#[global_allocator]
static HEAP_ALLOCATOR: PreemptHeap = PreemptHeap(LockedHeap::empty());

pub fn init() {
    unsafe {
        HEAP_ALLOCATOR
            .0
            .lock()
            .init(KERNEL_HEAP.as_mut_ptr() as usize, KERNEL_HEAP_SIZE);
    }
}

/// Force-release the buddy heap's internal spinlock. The preempt_disable bracket
/// in alloc/dealloc keeps the scheduler from switching mid-allocation, but it
/// can't help the watchdog/fault recovery path, which *abandons* the wedged
/// stack without unwinding. If that stack was inside `alloc` (an LTP case that
/// loops allocating until the 8 s watchdog fires is frequently mid-alloc when
/// the timer lands), the heap lock stays held forever and EVERY later
/// allocation — including pid 1's — spins, cascading the whole run to death.
/// `force_release_locks_after_fault` calls this so a single wedged case can't
/// strand the allocator.
///
/// # Safety
/// Call only from the single-hart fault/watchdog recovery, where the abandoned
/// stack is the only possible holder of the lock.
pub unsafe fn force_unlock() {
    unsafe { HEAP_ALLOCATOR.0.force_unlock() };
}
