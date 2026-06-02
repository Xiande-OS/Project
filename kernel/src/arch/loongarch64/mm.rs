//! loongarch64 MMU control: address-space activation + TLB maintenance.
//!
//! LoongArch has no hardware page-table walker for the general case; the
//! TLB-refill exception (see `trap.S`) fills entries from the page tables
//! rooted at PGDL/PGDH. Switching address space therefore means pointing
//! PGDL at the new user root and flushing the TLB.

/// Point the low-half (user) page-directory base at `pgd_pa` and flush the
/// local TLB. `pgd_pa` is the value produced by `PageTable::satp()` on
/// loongarch64 (the physical address of the root directory frame).
#[inline]
pub fn activate(pgd_pa: usize) {
    unsafe {
        // PGDL (CSR 0x19) backs translation for low-half (user) addresses;
        // the high-half kernel mappings live in DMW windows and need no
        // page table. csrwr returns the old value into the source reg,
        // which we discard.
        core::arch::asm!("csrwr {0}, 0x19", inout(reg) pgd_pa => _);
        // invtlb op 0: invalidate all TLB entries.
        core::arch::asm!("invtlb 0x0, $zero, $zero");
    }
}

/// Invalidate the local TLB entry covering `va` — single page, not the whole
/// TLB.
///
/// `invtlb 0x5` clears entries with `G==0 AND ASID==rj AND VA==rk`. User space
/// runs at ASID 0 (activate never reprograms CSR.ASID) and user PTEs are
/// non-global, so `rj=$zero, rk=va` targets exactly this page. `activate()`
/// still whole-flushes on every address-space switch, which is what keeps the
/// shared-ASID-0 design correct against sibling shadows — `flush_va` only has
/// to drop the one intra-process page being unmapped/remapped, so it no longer
/// nukes the whole TLB on each munmap/mprotect (the fork-heavy refill storm).
///
/// NB: the earlier attempt used `invtlb 0x6` (`G==1 OR ASID==rj`), which on this
/// QEMU did NOT invalidate the live entry — leaving stale translations that
/// crashed every fork-heavy LA test (badv=0x0 faults). op 0x5 is validated on
/// the glibc LA image: ltp runs hundreds of cases with 0 systemic faults.
#[inline]
pub fn flush_va(va: usize) {
    unsafe {
        core::arch::asm!("invtlb 0x5, $zero, {0}", in(reg) va);
    }
}

/// Flush the entire local TLB.
#[inline]
pub fn flush_all() {
    unsafe {
        core::arch::asm!("invtlb 0x0, $zero, $zero");
    }
}
