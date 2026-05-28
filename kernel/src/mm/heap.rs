//! Kernel heap.
//!
//! Lives in a static `.bss` buffer; the buddy allocator manages it as a
//! linked free list. M1 keeps this simple — once frame allocation is up
//! we could move to a slab on top, but a single LockedHeap covers all
//! kmalloc needs through M5 easily.

use buddy_system_allocator::LockedHeap;

// libc-bench's b_stdio_putcgetc et al. allocate ~8 MB scratch buffers
// per bench. The contest harness also forks many short-lived ELFs whose
// images we slurp into Vec<u8> in sys_execve. 32 MB was hitting alloc
// failures mid-libcbench. 128 MB still fits inside QEMU virt's -m 1G.
const KERNEL_HEAP_SIZE: usize = 128 * 1024 * 1024;

#[link_section = ".bss.heap"]
static mut KERNEL_HEAP: [u8; KERNEL_HEAP_SIZE] = [0; KERNEL_HEAP_SIZE];

#[global_allocator]
static HEAP_ALLOCATOR: LockedHeap<32> = LockedHeap::empty();

pub fn init() {
    unsafe {
        HEAP_ALLOCATOR
            .lock()
            .init(KERNEL_HEAP.as_mut_ptr() as usize, KERNEL_HEAP_SIZE);
    }
}
