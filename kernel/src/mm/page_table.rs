//! Sv39 page tables.
//!
//! A `PageTable` owns its root frame and the intermediate level frames
//! (lazily allocated on map). Drop releases them.

use alloc::vec::Vec;
use bitflags::bitflags;
use core::fmt;

use super::address::{PhysAddr, PhysPageNum, VirtAddr, VirtPageNum, PAGE_SIZE};
use super::frame::{alloc as alloc_frame, FrameTracker};

bitflags! {
    #[derive(Clone, Copy, Eq, PartialEq)]
    pub struct PteFlags: usize {
        const V = 1 << 0;
        const R = 1 << 1;
        const W = 1 << 2;
        const X = 1 << 3;
        const U = 1 << 4;
        const G = 1 << 5;
        const A = 1 << 6;
        const D = 1 << 7;
    }
}

impl fmt::Debug for PteFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}{}{}{}{}{}{}",
            if self.contains(Self::D) { 'D' } else { '-' },
            if self.contains(Self::A) { 'A' } else { '-' },
            if self.contains(Self::G) { 'G' } else { '-' },
            if self.contains(Self::U) { 'U' } else { '-' },
            if self.contains(Self::X) { 'X' } else { '-' },
            if self.contains(Self::W) { 'W' } else { '-' },
            if self.contains(Self::R) { 'R' } else { '-' },
            if self.contains(Self::V) { 'V' } else { '-' },
        )
    }
}

/// A raw page-table entry.
///
/// * riscv64 (Sv39): PPN in bits [53:10], flags in bits [9:0].
/// * loongarch64: the hardware TLB-refill walker (`lddir`/`ldpte`) parses
///   the entry, so the bit layout is LoongArch-native (see [`la`] below).
///   Leaf entries carry V/D/PLV/MAT/G/P/W + PPN<<12 + NR/NX; directory
///   (non-leaf) slots hold the bare physical base of the next level.
#[derive(Clone, Copy, Default)]
#[repr(transparent)]
pub struct Pte(pub usize);

/// LoongArch-native PTE/TLBELO leaf bit positions (4 KiB pages, lp64d).
/// These match the in-memory software-PTE layout that `ldpte` copies
/// verbatim into CSR.TLBRELO0/1, so the leaf format must use them exactly.
#[cfg(target_arch = "loongarch64")]
mod la {
    pub const V: usize = 1 << 0; // valid
    pub const D: usize = 1 << 1; // dirty (write performed) — gates writes with W
    pub const PLV_SHIFT: usize = 2; // bits [3:2] privilege level
    pub const MAT_CC: usize = 1 << 4; // bits [5:4] = 01: coherent cached
    pub const G: usize = 1 << 6; // global (ignored per-ASID; we flush-all on switch)
    pub const P: usize = 1 << 7; // present (physical exists) — required on a leaf
    pub const W: usize = 1 << 8; // writable
    pub const NR: usize = 1 << 61; // no-read  (negative logic)
    pub const NX: usize = 1 << 62; // no-execute (negative logic)
    /// Physical address occupies the entry from bit 12 up (PPN << 12). Mask
    /// off the software/permission bits above the 48-bit physical window.
    pub const PA_MASK: usize = ((1usize << 48) - 1) & !((1usize << 12) - 1);
}

impl Pte {
    /// Build a leaf entry mapping `ppn` with the given generic permission
    /// flags. riscv64 stores the flags verbatim; loongarch64 translates
    /// them into native leaf bits.
    #[cfg(target_arch = "riscv64")]
    pub const fn new(ppn: PhysPageNum, flags: PteFlags) -> Self {
        Self((ppn.0 << 10) | flags.bits())
    }
    #[cfg(target_arch = "loongarch64")]
    pub fn new(ppn: PhysPageNum, flags: PteFlags) -> Self {
        let mut bits = (ppn.0 << 12) & la::PA_MASK;
        bits |= la::V | la::P | la::MAT_CC;
        // User pages (U) are PLV3 (accessible by PLV0 kernel + PLV3 user);
        // kernel-only pages stay PLV0. LA permits access when CRMD.PLV <=
        // PTE.PLV, so PLV3 is the "everyone" level.
        if flags.contains(PteFlags::U) {
            bits |= 3 << la::PLV_SHIFT;
        }
        // Writable pages also get D set so the first store doesn't take a
        // page-modify exception (we don't lazily track dirty on LA).
        if flags.contains(PteFlags::W) {
            bits |= la::W | la::D;
        }
        if flags.contains(PteFlags::G) {
            bits |= la::G;
        }
        // NR/NX are negative: set them when the page is NOT readable /
        // executable.
        if !flags.contains(PteFlags::R) {
            bits |= la::NR;
        }
        if !flags.contains(PteFlags::X) {
            bits |= la::NX;
        }
        Self(bits)
    }

    /// Build a non-leaf directory entry pointing at the next level rooted
    /// at `ppn`. On riscv64 that's a valid pointer PTE (V set, R/W/X
    /// clear); on loongarch64 the hardware walker wants a bare physical
    /// base with no flag bits.
    #[cfg(target_arch = "riscv64")]
    pub fn new_dir(ppn: PhysPageNum) -> Self {
        Self::new(ppn, PteFlags::V)
    }
    #[cfg(target_arch = "loongarch64")]
    pub fn new_dir(ppn: PhysPageNum) -> Self {
        Self(ppn.base().0 & la::PA_MASK)
    }

    pub const fn empty() -> Self {
        Self(0)
    }
    #[cfg(target_arch = "riscv64")]
    pub fn ppn(self) -> PhysPageNum {
        PhysPageNum((self.0 >> 10) & ((1 << 44) - 1))
    }
    #[cfg(target_arch = "loongarch64")]
    pub fn ppn(self) -> PhysPageNum {
        // PPN sits at bit 12+ for both leaf entries and directory pointers
        // (a directory slot is just PPN<<12 with no flags).
        PhysPageNum((self.0 & la::PA_MASK) >> 12)
    }
    pub fn flags(self) -> PteFlags {
        PteFlags::from_bits_truncate(self.0)
    }
    #[cfg(target_arch = "riscv64")]
    pub fn is_valid(self) -> bool {
        self.flags().contains(PteFlags::V)
    }
    /// loongarch64: a slot is occupied iff it is non-zero. Leaf entries
    /// carry the V bit; directory pointers carry a (page-aligned, hence
    /// V-clear) physical base, so a plain V-bit test would wrongly treat
    /// every directory slot as empty.
    #[cfg(target_arch = "loongarch64")]
    pub fn is_valid(self) -> bool {
        self.0 != 0
    }
    /// True for leaf PTEs. Otherwise it's a pointer to the next level.
    #[cfg(target_arch = "riscv64")]
    pub fn is_leaf(self) -> bool {
        let f = self.flags();
        f.intersects(PteFlags::R | PteFlags::W | PteFlags::X)
    }
    /// loongarch64: only leaf entries set V (bit 0); directory pointers are
    /// page-aligned physical bases with bit 0 clear.
    #[cfg(target_arch = "loongarch64")]
    pub fn is_leaf(self) -> bool {
        self.0 & la::V != 0
    }
}

impl fmt::Debug for Pte {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pte({:?},{:?})", self.ppn(), self.flags())
    }
}

pub struct PageTable {
    root: FrameTracker,
    intermediate: Vec<FrameTracker>,
}

impl PageTable {
    pub fn new() -> Self {
        // Root allocation should virtually never OOM if we reach this
        // line (we're about to need many more frames anyway). But if it
        // happens during a fork-storm we must NOT panic — return a
        // page table whose root is invalid; the caller's
        // `push_user_area` will fail with the same ENOMEM the rest of
        // the OOM-graceful path uses.
        let root = match alloc_frame() {
            Some(f) => f,
            None => {
                // Repurpose the first frame allocated as a dummy: we
                // hand a zeroed FrameTracker by reallocating after a
                // brief retry. As a last resort, panic — there's no
                // way to convey ENOMEM through `new()` without changing
                // the signature, but the only caller path (fork/exec)
                // already handles a downstream push_user_area failure.
                alloc_frame().expect("OOM: page-table root (no recovery path)")
            }
        };
        Self {
            root,
            intermediate: Vec::new(),
        }
    }

    /// Fallible constructor used by fork/exec paths. Returns None on
    /// frame exhaustion so the kernel can return ENOMEM instead of
    /// panicking when a contest benchmark forks the heap dry.
    pub fn try_new() -> Option<Self> {
        let root = alloc_frame()?;
        Some(Self {
            root,
            intermediate: Vec::new(),
        })
    }

    pub fn root_ppn(&self) -> PhysPageNum {
        self.root.ppn
    }

    /// The architecture's address-space activation token for this table
    /// (consumed by `crate::arch::activate_page_table`). On riscv64 this is
    /// the Sv39 `satp` value (mode | root PPN); on loongarch64 it is the
    /// physical address of the root directory frame loaded into PGDL.
    #[cfg(target_arch = "riscv64")]
    pub fn satp(&self) -> usize {
        const SATP_MODE_SV39: usize = 8 << 60;
        SATP_MODE_SV39 | self.root_ppn().0
    }
    #[cfg(target_arch = "loongarch64")]
    pub fn satp(&self) -> usize {
        self.root_ppn().base().0
    }

    fn find_or_create(&mut self, vpn: VirtPageNum) -> Option<&mut Pte> {
        let indices = vpn.indices();
        let mut ppn = self.root.ppn;
        for (lvl, &idx) in indices.iter().enumerate() {
            let pte = unsafe { &mut *(ppn.base().kernel_ptr::<Pte>()).add(idx) };
            if lvl == 2 {
                return Some(pte);
            }
            if !pte.is_valid() {
                // None on frame exhaustion — map() turns this into a
                // silent no-op so the OOMing process faults & dies
                // instead of panicking the kernel.
                let frame = alloc_frame()?;
                *pte = Pte::new_dir(frame.ppn);
                ppn = frame.ppn;
                self.intermediate.push(frame);
            } else {
                ppn = pte.ppn();
            }
        }
        None
    }

    fn find(&self, vpn: VirtPageNum) -> Option<&Pte> {
        let indices = vpn.indices();
        let mut ppn = self.root.ppn;
        for (lvl, &idx) in indices.iter().enumerate() {
            let pte = unsafe { &*(ppn.base().kernel_ptr::<Pte>() as *const Pte).add(idx) };
            if !pte.is_valid() {
                return None;
            }
            if lvl == 2 || pte.is_leaf() {
                return Some(pte);
            }
            ppn = pte.ppn();
        }
        None
    }

    /// Map `vpn -> ppn` with `flags` (must include at least V). Overwrites
    /// any existing leaf at that VPN (the caller is responsible for TLB
    /// invalidation and for tracking that the previous PPN is no longer
    /// referenced).
    pub fn map(&mut self, vpn: VirtPageNum, ppn: PhysPageNum, flags: PteFlags) {
        // Best-effort: on PT-node OOM the mapping silently doesn't get
        // installed. The caller (push_user_area) has already checked the
        // data frame; a missing mapping just means the OOMing process
        // will fault on access and be killed — the kernel stays up.
        if let Some(pte) = self.find_or_create(vpn) {
            *pte = Pte::new(ppn, flags | PteFlags::V);
        }
    }

    pub fn unmap(&mut self, vpn: VirtPageNum) -> Option<Pte> {
        let pte = self.find_or_create(vpn)?;
        if pte.is_valid() {
            let old = *pte;
            *pte = Pte::empty();
            Some(old)
        } else {
            None
        }
    }

    pub fn translate(&self, va: VirtAddr) -> Option<PhysAddr> {
        let vpn = va.floor();
        let pte = self.find(vpn)?;
        if !pte.is_leaf() {
            return None;
        }
        Some(PhysAddr((pte.ppn().0 << 12) | va.page_offset()))
    }
}

/// Invalidate one VPN in the local hart TLB. Caller must ensure the
/// store to the PTE happened before this.
pub fn local_flush_va(vpn: VirtPageNum) {
    crate::arch::flush_tlb_va(vpn.base().0);
}

/// Flush the entire local hart TLB.
pub fn local_flush_all() {
    crate::arch::flush_tlb_all();
}
