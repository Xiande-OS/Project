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

/// Invalidate the local TLB entry covering `va`.
///
/// Was flushing the WHOLE TLB (`invtlb 0x0`) on every single-page invalidation
/// — so each munmap/mprotect/exit-time page teardown nuked the entire TLB and
/// forced the next process to refill its whole working set. On a fork-heavy
/// LTP case (access01/getpid01/waitpid01 fork 100–199× → as many address-space
/// teardowns) that refill storm made the case overrun the contest's 5s/3s
/// per-case `timeout` on loongarch64 and score 0, even though it ran correctly.
///
/// We run user space at ASID 0 (no ASID recycling) and the kernel lives in DMW
/// windows (never in the TLB), so `invtlb 0x6, $zero, va` — invalidate entries
/// matching VA `va` that are global OR carry ASID 0 — flushes exactly the one
/// page instead of the whole TLB.
#[inline]
pub fn flush_va(va: usize) {
    unsafe {
        core::arch::asm!("invtlb 0x6, $zero, {0}", in(reg) va);
    }
}

/// Flush the entire local TLB.
#[inline]
pub fn flush_all() {
    unsafe {
        core::arch::asm!("invtlb 0x0, $zero, $zero");
    }
}
