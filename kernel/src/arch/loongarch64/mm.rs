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

/// Invalidate the local TLB entry covering `va`. We flush the whole TLB
/// (op 0) rather than a single ASID/VA pair to stay correct regardless of
/// the ASID currently programmed.
#[inline]
pub fn flush_va(va: usize) {
    let _ = va;
    unsafe {
        core::arch::asm!("invtlb 0x0, $zero, $zero");
    }
}

/// Flush the entire local TLB.
#[inline]
pub fn flush_all() {
    unsafe {
        core::arch::asm!("invtlb 0x0, $zero, $zero");
    }
}
