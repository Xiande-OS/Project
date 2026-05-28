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

/// A raw Sv39 page-table entry. The PPN occupies bits [53:10], flags
/// occupy bits [9:0]. Bits [63:54] are reserved.
#[derive(Clone, Copy, Default)]
#[repr(transparent)]
pub struct Pte(pub usize);

impl Pte {
    pub const fn new(ppn: PhysPageNum, flags: PteFlags) -> Self {
        Self((ppn.0 << 10) | flags.bits())
    }
    pub const fn empty() -> Self {
        Self(0)
    }
    pub fn ppn(self) -> PhysPageNum {
        PhysPageNum((self.0 >> 10) & ((1 << 44) - 1))
    }
    pub fn flags(self) -> PteFlags {
        PteFlags::from_bits_truncate(self.0)
    }
    pub fn is_valid(self) -> bool {
        self.flags().contains(PteFlags::V)
    }
    /// True for leaf PTEs (any of R/W/X is set). Otherwise it's a
    /// pointer to the next page-table level.
    pub fn is_leaf(self) -> bool {
        let f = self.flags();
        f.intersects(PteFlags::R | PteFlags::W | PteFlags::X)
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
        let root = alloc_frame().expect("OOM: page-table root");
        Self {
            root,
            intermediate: Vec::new(),
        }
    }

    pub fn root_ppn(&self) -> PhysPageNum {
        self.root.ppn
    }

    /// satp value for Sv39 with this table as the active translation.
    pub fn satp(&self) -> usize {
        const SATP_MODE_SV39: usize = 8 << 60;
        SATP_MODE_SV39 | self.root_ppn().0
    }

    fn find_or_create(&mut self, vpn: VirtPageNum) -> Option<&mut Pte> {
        let indices = vpn.indices();
        let mut ppn = self.root.ppn;
        for (lvl, &idx) in indices.iter().enumerate() {
            let pte = unsafe { &mut *(ppn.base().0 as *mut Pte).add(idx) };
            if lvl == 2 {
                return Some(pte);
            }
            if !pte.is_valid() {
                // None on frame exhaustion — map() turns this into a
                // silent no-op so the OOMing process faults & dies
                // instead of panicking the kernel.
                let frame = alloc_frame()?;
                *pte = Pte::new(frame.ppn, PteFlags::V);
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
            let pte = unsafe { &*(ppn.base().0 as *const Pte).add(idx) };
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
    unsafe {
        core::arch::asm!("sfence.vma {0}, zero", in(reg) vpn.base().0);
    }
}

/// Flush the entire local hart TLB.
pub fn local_flush_all() {
    unsafe { core::arch::asm!("sfence.vma") };
}
