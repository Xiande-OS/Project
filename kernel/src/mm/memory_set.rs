//! Per-process / per-kernel memory map.
//!
//! `MemorySet` = one Sv39 page table plus the list of mapped regions
//! (`VmArea`) and their owned physical frames. Drop frees the frames.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use bitflags::bitflags;

use super::address::{PhysPageNum, VirtAddr, VirtPageNum, PAGE_SIZE};
use super::frame::{alloc as alloc_frame, FrameTracker};
use super::page_table::{PageTable, PteFlags};

bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct VmPerm: u8 {
        const R = 1 << 0;
        const W = 1 << 1;
        const X = 1 << 2;
        const U = 1 << 3;   // user-accessible
    }
}

impl VmPerm {
    pub fn to_pte(self) -> PteFlags {
        let mut f = PteFlags::V;
        if self.contains(Self::R) {
            f |= PteFlags::R;
        }
        if self.contains(Self::W) {
            f |= PteFlags::W;
        }
        if self.contains(Self::X) {
            f |= PteFlags::X;
        }
        if self.contains(Self::U) {
            f |= PteFlags::U;
        }
        f
    }
}

pub struct VmArea {
    pub vpn_start: VirtPageNum,
    pub vpn_end: VirtPageNum, // exclusive
    pub perm: VmPerm,
    /// VPN -> backing frame. Empty for pages that haven't been faulted in
    /// yet (we always eager-map in M3, so this is fully populated).
    pub frames: BTreeMap<VirtPageNum, FrameTracker>,
}

impl VmArea {
    pub fn new(va_start: VirtAddr, va_end: VirtAddr, perm: VmPerm) -> Self {
        Self {
            vpn_start: va_start.floor(),
            vpn_end: va_end.ceil(),
            perm,
            frames: BTreeMap::new(),
        }
    }

    pub fn contains(&self, vpn: VirtPageNum) -> bool {
        vpn >= self.vpn_start && vpn < self.vpn_end
    }
}

pub struct MemorySet {
    pub page_table: PageTable,
    areas: Vec<VmArea>,
    /// Heap (brk) state.
    pub brk_base: VirtAddr,
    pub brk_cur: VirtAddr,
}

impl MemorySet {
    pub fn new() -> Self {
        Self {
            page_table: PageTable::new(),
            areas: Vec::new(),
            brk_base: VirtAddr(0),
            brk_cur: VirtAddr(0),
        }
    }

    pub fn satp(&self) -> usize {
        self.page_table.satp()
    }

    /// Identity-map the kernel image + heap + frame pool into this address
    /// space, with R|W|X permissions and no U bit. Required so that the
    /// CPU keeps executing the kernel after we switch satp to this table.
    pub fn map_kernel_identity(&mut self, k_start: usize, k_end: usize) {
        let start_vpn = VirtAddr(k_start).floor();
        let end_vpn = VirtAddr(k_end).ceil();
        let perm = PteFlags::V | PteFlags::R | PteFlags::W | PteFlags::X;
        for vpn_raw in start_vpn.0..end_vpn.0 {
            self.page_table
                .map(VirtPageNum(vpn_raw), PhysPageNum(vpn_raw), perm);
        }
    }

    /// Map an MMIO region identity (R|W, no U).
    pub fn map_mmio(&mut self, pa_start: usize, pa_end: usize) {
        let start_vpn = VirtAddr(pa_start).floor();
        let end_vpn = VirtAddr(pa_end).ceil();
        let perm = PteFlags::V | PteFlags::R | PteFlags::W;
        for vpn_raw in start_vpn.0..end_vpn.0 {
            self.page_table
                .map(VirtPageNum(vpn_raw), PhysPageNum(vpn_raw), perm);
        }
    }

    /// Push a user-mode area into this address space and (eagerly) back
    /// every page with a freshly allocated frame. If `init_data` is Some,
    /// the bytes are copied to the start of the area (zero padded).
    pub fn push_user_area(&mut self, mut area: VmArea, init_data: Option<&[u8]>) {
        let pte_flags = area.perm.to_pte();
        // Walk page by page.
        let mut copied = 0usize;
        for vpn_raw in area.vpn_start.0..area.vpn_end.0 {
            let vpn = VirtPageNum(vpn_raw);
            let frame = alloc_frame().expect("OOM: user area");
            let ppn = frame.ppn;
            // Copy initial bytes (if any) into the frame.
            if let Some(data) = init_data {
                if copied < data.len() {
                    let dst = ppn.as_byte_slice();
                    let n = core::cmp::min(PAGE_SIZE, data.len() - copied);
                    dst[..n].copy_from_slice(&data[copied..copied + n]);
                    copied += n;
                }
            }
            self.page_table.map(vpn, ppn, pte_flags);
            area.frames.insert(vpn, frame);
        }
        self.areas.push(area);
    }

    pub fn translate(&self, va: VirtAddr) -> Option<super::address::PhysAddr> {
        self.page_table.translate(va)
    }

    /// Find the area that contains `vpn` (for fault handlers, brk).
    pub fn find_area_mut(&mut self, vpn: VirtPageNum) -> Option<&mut VmArea> {
        self.areas.iter_mut().find(|a| a.contains(vpn))
    }

    /// Grow the brk segment to `new_brk`. Returns the new program-break.
    /// Lazy: allocates frames as needed; never shrinks (just returns
    /// the previous brk_cur if new_brk < brk_base or if shrinking).
    pub fn brk_set(&mut self, new_brk: VirtAddr) -> VirtAddr {
        if new_brk.0 == 0 {
            return self.brk_cur;
        }
        if new_brk.0 < self.brk_base.0 {
            return self.brk_cur;
        }
        if new_brk.0 <= self.brk_cur.0 {
            // Allow shrink in tracking only, don't actually free pages
            // (musl rarely shrinks). Real impl: unmap pages.
            self.brk_cur = new_brk;
            return self.brk_cur;
        }
        // Grow.
        let old_top_vpn = self.brk_cur.ceil();
        let new_top_vpn = new_brk.ceil();
        // Locate or extend the heap area.
        let heap_perm = VmPerm::R | VmPerm::W | VmPerm::U;
        // Find an existing heap area starting at brk_base.
        let idx = self
            .areas
            .iter()
            .position(|a| a.vpn_start == self.brk_base.floor());
        if let Some(i) = idx {
            // Append frames.
            let area = &mut self.areas[i];
            let pte_flags = heap_perm.to_pte();
            for vpn_raw in old_top_vpn.0..new_top_vpn.0 {
                let vpn = VirtPageNum(vpn_raw);
                if area.frames.contains_key(&vpn) {
                    continue;
                }
                let frame = alloc_frame().expect("OOM: brk grow");
                self.page_table.map(vpn, frame.ppn, pte_flags);
                area.frames.insert(vpn, frame);
            }
            area.vpn_end = new_top_vpn;
        } else {
            // Create a new heap area.
            let area = VmArea::new(self.brk_base, new_brk, heap_perm);
            self.push_user_area(area, None);
        }
        self.brk_cur = new_brk;
        self.brk_cur
    }
}
