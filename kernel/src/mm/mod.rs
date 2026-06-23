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
    fn __kernel_start();
    fn __kernel_end();
}

/// Read the physical end of RAM from the device tree the bootloader passed in.
/// The old hardcoded 1 GiB end made the frame allocator hand out frames past
/// real memory on any smaller machine — zeroing (or fork-copying into) such a
/// frame faults, which killed init at `-m 512M`. Falls back to the 1 GiB
/// default only if no parseable DTB is found.
///
/// riscv64 reaches here with paging off (identity), so the DTB pointer the
/// bootloader put in a1 is directly readable. loongarch64 is direct-booted by
/// QEMU with no DTB pointer in a register (a0..a3 carry efi-style scalars), but
/// QEMU still loads the flattened tree into low RAM — so we scan the
/// always-backed low window for the FDT magic and parse that.
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
                    crate::println!("[timer] dtb timebase-frequency = {} Hz", hz);
                    crate::arch::set_timer_raw_hz(hz as u64);
                } else {
                    crate::println!("[timer] no timebase-frequency in dtb — assuming 10 MHz");
                }
                let end = fdt_ram_end(&fdt);
                if end > RAM_START {
                    return end;
                }
            }
        }
    }
    #[cfg(target_arch = "loongarch64")]
    {
        let _ = dtb_pa;
        // QEMU >= 9 moved the `virt` high-RAM base from 0x9000_0000 down to
        // 0x8000_0000, so with `-m 1G` real RAM ends at 0xB000_0000, not the
        // historical 0xC000_0000. Trusting the old default makes the frame
        // allocator hand out frames in the unbacked [0xB000_0000, 0xC000_0000)
        // gap; the first fork to copy a page into one dies with a kernel-mode
        // ADE deep in the run — exactly the crash the contest judge (newer
        // QEMU) hits while CI (QEMU 8.2, RAM to 0xC000_0000) does not.
        //
        // QEMU direct-boot doesn't hand loongarch a DTB pointer, but it loads
        // the flattened tree into low RAM. The FDT is reachable through the
        // cached direct-map window; scanning [0, 16 MiB) is safe because the
        // low memory node is present on every QEMU version, so those physical
        // pages are always backed.
        //
        // We take the end of the memory region that *contains the kernel's
        // fixed load address*, not the global max: QEMU 8.2's loongarch DTB is
        // buggy (it sets the high 32 bits of every memory `reg` cell to 0x2, so
        // the nodes claim RAM at ~0x2_9000_0000). Those bogus regions don't
        // span the kernel, so on 8.2 no region matches and we fall through to
        // the (correct-for-8.2) 0xC000_0000 default; on a sane DTB the kernel's
        // region gives the true end.
        let kphys = __kernel_start as usize - address::KERNEL_PHYS_OFFSET;
        const DMW: usize = address::KERNEL_PHYS_OFFSET;
        let mut pa = 0usize;
        while pa < 0x0100_0000 {
            // FDT magic 0xd00dfeed is stored big-endian; a little-endian load
            // of the first word therefore reads 0xedfe0dd0.
            let magic = unsafe { core::ptr::read_volatile((pa | DMW) as *const u32) };
            if magic == 0xedfe0dd0 {
                if let Ok(fdt) = unsafe { fdt::Fdt::from_ptr((pa | DMW) as *const u8) } {
                    if let Some(end) = fdt_region_end_containing(&fdt, kphys) {
                        return end;
                    }
                }
            }
            pa += 0x1000;
        }
    }
    let _ = dtb_pa;
    MEMORY_END_DEFAULT
}

/// Highest physical end-of-RAM described by any `device_type = "memory"` node.
/// Used on riscv64, whose firmware emits a well-formed memory map.
#[cfg(target_arch = "riscv64")]
fn fdt_ram_end(fdt: &fdt::Fdt) -> usize {
    let mut end = 0usize;
    for node in memory_nodes(fdt) {
        if let Some(regions) = node.reg() {
            for region in regions {
                if let Some(size) = region.size {
                    let start = region.starting_address as usize;
                    end = end.max(start.saturating_add(size));
                }
            }
        }
    }
    end
}

/// End of the `device_type = "memory"` region whose `reg` range contains the
/// physical address `addr` (the kernel image), or `None` if no sane region
/// does. The upper sanity bound rejects a DTB with corrupt size cells while
/// still allowing any realistic amount of RAM.
#[cfg(target_arch = "loongarch64")]
fn fdt_region_end_containing(fdt: &fdt::Fdt, addr: usize) -> Option<usize> {
    const SANE_MAX: usize = 0x40_0000_0000; // 256 GiB
    for node in memory_nodes(fdt) {
        if let Some(regions) = node.reg() {
            for region in regions {
                if let Some(size) = region.size {
                    let start = region.starting_address as usize;
                    let end = start.saturating_add(size);
                    if start <= addr && addr < end && end <= SANE_MAX {
                        return Some(end);
                    }
                }
            }
        }
    }
    None
}

/// Iterate every `device_type = "memory"` node. QEMU's `virt` splits RAM across
/// `/memory@0` and a high `/memory@…` node, so the convenience `Fdt::memory()`
/// (which resolves a single `/memory` path) is not enough.
fn memory_nodes<'b, 'a>(
    fdt: &'b fdt::Fdt<'a>,
) -> impl Iterator<Item = fdt::node::FdtNode<'b, 'a>> {
    fdt.all_nodes().filter(|node| {
        node.property("device_type")
            .map(|p| p.value.starts_with(b"memory"))
            .unwrap_or(false)
    })
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
    // loongarch64 `virt` splits RAM into a low bank at PA 0 and a high bank at
    // 0x8000_0000. `detect_memory_end` only pools the high bank (the one holding
    // the kernel), so the entire low bank — 256 MiB with `-m 1G` on QEMU >= 9 —
    // was wasted, leaving LA with ~280 MiB less than RV. That gap is exactly why
    // the LA contest run OOM-wedged mid-glibc (libcbench) on the judge's QEMU
    // while RV completed. Fold the low bank in so LA has RV-comparable headroom.
    #[cfg(target_arch = "loongarch64")]
    add_low_ram_banks();
}

/// loongarch64: pool the low RAM bank(s) the kernel doesn't load into.
///
/// QEMU direct-boot leaves the flattened device tree in the low bank, and we
/// read the memory map from it (the same FDT scan `detect_memory_end` uses).
/// For every `device_type = "memory"` region that lies entirely below the high
/// RAM base (RAM_START) we add it to the frame pool, skipping a generous 16 MiB
/// prefix that holds the FDT (it sits in [0, 16 MiB) — that scan is what found
/// it) and any early-boot scratch. Regions are validated against RAM_START so
/// QEMU 8.2's buggy DTB (which mislabels RAM at ~0x2_9000_0000) contributes
/// nothing — there it simply no-ops, which is correct (8.2 already maps the high
/// bank to 0xC000_0000).
#[cfg(target_arch = "loongarch64")]
fn add_low_ram_banks() {
    const DMW: usize = address::KERNEL_PHYS_OFFSET;
    const LOW_RESERVE: usize = 0x100_0000; // 16 MiB FDT/boot prefix to skip
    let mut pa = 0usize;
    let fdt = loop {
        if pa >= 0x0100_0000 {
            return; // no FDT found in the low window — leave the pool as-is
        }
        let magic = unsafe { core::ptr::read_volatile((pa | DMW) as *const u32) };
        if magic == 0xedfe0dd0 {
            if let Ok(f) = unsafe { fdt::Fdt::from_ptr((pa | DMW) as *const u8) } {
                break f;
            }
        }
        pa += 0x1000;
    };
    for node in memory_nodes(&fdt) {
        let Some(regions) = node.reg() else { continue };
        for region in regions {
            let Some(size) = region.size else { continue };
            let start = region.starting_address as usize;
            let end = start.saturating_add(size);
            // A low bank: ends at or below the high RAM base, and is big enough
            // to be worth pooling past the reserved prefix.
            if end <= RAM_START && size >= LOW_RESERVE * 2 {
                let lo = start.saturating_add(LOW_RESERVE);
                if lo < end {
                    frame::add_region(PhysAddr(lo), PhysAddr(end));
                }
            }
        }
    }
}
