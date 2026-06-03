//! Memory management.

pub mod address;
pub mod frame;
pub mod heap;
pub mod memory_set;
pub mod page_table;

pub use address::{PhysAddr, PhysPageNum, VirtAddr, VirtPageNum, PAGE_SIZE};
pub use frame::{alloc as alloc_frame, frame_stats, FrameTracker};
pub use page_table::{PageTable, Pte, PteFlags};

/// Default physical memory end when the device tree can't be read: the 1 GiB
/// the contest historically used (RAM `0x8000_0000..0xC000_0000`).
pub const MEMORY_END_DEFAULT: usize = 0xC000_0000;
const RAM_START: usize = 0x8000_0000;

/// Detected physical end of RAM, set by [`init`] from the device tree.
static MEMORY_END: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(MEMORY_END_DEFAULT);

pub fn mm_end() -> usize {
    MEMORY_END.load(core::sync::atomic::Ordering::Relaxed)
}

/// Symbols exported by linker.ld.
extern "C" {
    fn __kernel_end();
}

/// Read the physical end of RAM from the device tree the bootloader passed in.
/// The old hardcoded 1 GiB end made the frame allocator hand out frames past
/// real memory on any smaller machine — zeroing such a frame faults, which
/// killed init at `-m 512M`. Falls back to the 1 GiB default if the DTB is
/// missing/unparseable or its memory node lies outside the early-accessible
/// window. riscv64 reaches here with paging off (identity), so the DTB pointer
/// is directly readable.
fn detect_memory_end(dtb_pa: usize) -> usize {
    #[cfg(target_arch = "riscv64")]
    {
        // Only trust a pointer inside the historically-assumed RAM window, so a
        // bogus value can't fault us by reading non-existent physical memory.
        if dtb_pa >= RAM_START && dtb_pa < MEMORY_END_DEFAULT {
            if let Ok(fdt) = unsafe { fdt::Fdt::from_ptr(dtb_pa as *const u8) } {
                // Learn the real mtime frequency so the timer layer can rescale
                // it to the kernel's assumed 10 MHz. A non-10 MHz board would
                // otherwise make every timeout and the in-kernel watchdog run
                // at the wrong rate (the contest-machine execl01 cascade).
                if let Some(hz) = fdt
                    .find_node("/cpus")
                    .and_then(|n| n.property("timebase-frequency"))
                    .and_then(|p| p.as_usize())
                {
                    crate::arch::set_timer_raw_hz(hz as u64);
                }
                let mut end = 0usize;
                for region in fdt.memory().regions() {
                    if let Some(size) = region.size {
                        let start = region.starting_address as usize;
                        end = end.max(start.saturating_add(size));
                    }
                }
                if end > RAM_START {
                    return end;
                }
            }
        }
    }
    let _ = dtb_pa;
    MEMORY_END_DEFAULT
}

pub fn init(dtb_pa: usize) {
    heap::init();
    let mem_end = detect_memory_end(dtb_pa);
    MEMORY_END.store(mem_end, core::sync::atomic::Ordering::Relaxed);
    // `__kernel_end` is a linked (virtual) address; on loongarch64 that is
    // a DMW0 window address, so strip the window offset to get the physical
    // end of the kernel image. On riscv64 the offset is 0 (identity map).
    let kend = PhysAddr(__kernel_end as usize - address::KERNEL_PHYS_OFFSET);
    frame::init(kend, PhysAddr(mem_end));
}
