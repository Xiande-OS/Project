//! riscv64 MMU control: address-space activation + TLB maintenance.
//!
//! The architecture-neutral MM layer (`mm::page_table`, `task`) drives
//! address-space switches and TLB shootdowns through `crate::arch::*`;
//! this is the riscv64 backing. The LoongArch port supplies the same
//! three functions over its own CSRs (PGDL + `invtlb`).

/// Install `satp` as the active translation and flush stale TLB entries.
/// `satp` is the value produced by `PageTable::satp()` (mode | root PPN).
#[inline]
pub fn activate(satp: usize) {
    unsafe {
        core::arch::asm!(
            "csrw satp, {satp}",
            "sfence.vma",
            satp = in(reg) satp,
        );
    }
}

/// Invalidate the local-hart TLB entry covering virtual address `va`.
#[inline]
pub fn flush_va(va: usize) {
    unsafe {
        core::arch::asm!("sfence.vma {0}, zero", in(reg) va);
    }
}

/// Flush the entire local-hart TLB.
#[inline]
pub fn flush_all() {
    unsafe {
        core::arch::asm!("sfence.vma");
    }
}
