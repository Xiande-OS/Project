//! Memory management.

pub mod address;
pub mod frame;
pub mod heap;
pub mod page_table;

pub use address::{PhysAddr, PhysPageNum, VirtAddr, VirtPageNum, PAGE_SIZE};
pub use frame::{alloc as alloc_frame, FrameTracker};
pub use page_table::{PageTable, Pte, PteFlags};

/// Physical memory end. QEMU virt's default RAM ends at 0x80000000 + 1 GiB.
/// We pick 0x88000000 as a conservative cap (128 MiB beyond kernel base);
/// good enough for now and avoids walking the DTB at this stage.
pub const MEMORY_END: usize = 0x8800_0000;

/// Symbols exported by linker.ld.
extern "C" {
    fn __kernel_end();
}

pub fn init() {
    heap::init();
    let kend = PhysAddr(__kernel_end as usize);
    frame::init(kend, PhysAddr(MEMORY_END));
}
