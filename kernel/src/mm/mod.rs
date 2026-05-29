//! Memory management.

pub mod address;
pub mod frame;
pub mod heap;
pub mod memory_set;
pub mod page_table;

pub use address::{PhysAddr, PhysPageNum, VirtAddr, VirtPageNum, PAGE_SIZE};
pub use frame::{alloc as alloc_frame, frame_stats, FrameTracker};
pub use page_table::{PageTable, Pte, PteFlags};

/// Physical memory end. QEMU virt's default RAM ends at 0x80000000 + 1 GiB.
/// QEMU virt RAM starts at 0x8000_0000. The contest evaluator boots us
/// with `-m 1G`, extending RAM through 0xC000_0000 — claim it all so
/// heavy malloc workloads (libc-bench, lmbench) don't OOM on brk.
pub const MEMORY_END: usize = 0xC000_0000;

pub const fn mm_end() -> usize {
    MEMORY_END
}

/// Symbols exported by linker.ld.
extern "C" {
    fn __kernel_end();
}

pub fn init() {
    heap::init();
    // `__kernel_end` is a linked (virtual) address; on loongarch64 that is
    // a DMW0 window address, so strip the window offset to get the physical
    // end of the kernel image. On riscv64 the offset is 0 (identity map).
    let kend = PhysAddr(__kernel_end as usize - address::KERNEL_PHYS_OFFSET);
    frame::init(kend, PhysAddr(MEMORY_END));
}
