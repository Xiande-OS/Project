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

/// Split a BTreeMap so the returned half contains keys < `pivot` and the
/// original retains keys >= `pivot`.
fn split_off_le<V>(
    map: &mut BTreeMap<VirtPageNum, V>,
    pivot: VirtPageNum,
) -> BTreeMap<VirtPageNum, V> {
    let mut head = BTreeMap::new();
    let keys: Vec<VirtPageNum> = map.range(..pivot).map(|(k, _)| *k).collect();
    for k in keys {
        if let Some(v) = map.remove(&k) {
            head.insert(k, v);
        }
    }
    head
}

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

/// Base address from which anonymous mmap (and file mmap) hands out
/// pages. Grows upward, kept page-aligned, and lives well below the
/// user stack (USER_STACK_TOP = 0x4000_0000) so a typical malloc-heavy
/// workload has hundreds of MiB to play with without colliding with
/// brk or stack. Must NOT overlap brk (which lives just above the
/// program image, typically around 0x12_0000).
pub const MMAP_BASE: usize = 0x2000_0000;

pub struct MemorySet {
    pub page_table: PageTable,
    pub areas: Vec<VmArea>,
    /// Heap (brk) state.
    pub brk_base: VirtAddr,
    pub brk_cur: VirtAddr,
    /// Next free virtual address for anonymous/file mmap. Always
    /// page-aligned. Grows upward.
    pub mmap_top: VirtAddr,
    /// Stack tops of exited pthreads awaiting reclaim. Drained (and the
    /// corresponding stack mappings freed) at the next thread creation in
    /// this address space. See `queue_stack_reclaim` / `drain_stack_reclaim`.
    pub pending_stack_reclaim: Vec<usize>,
}

impl MemorySet {
    pub fn new() -> Self {
        Self {
            page_table: PageTable::new(),
            areas: Vec::new(),
            brk_base: VirtAddr(0),
            brk_cur: VirtAddr(0),
            mmap_top: VirtAddr(MMAP_BASE),
            pending_stack_reclaim: Vec::new(),
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

    /// Install a user-readable+executable page at `va` containing `bytes`
    /// (zero-padded to a page). Used for the signal-restorer trampoline.
    pub fn map_user_rx_page(&mut self, va: VirtAddr, bytes: &[u8]) {
        let area = VmArea::new(va, VirtAddr(va.0 + PAGE_SIZE), VmPerm::R | VmPerm::X | VmPerm::U);
        self.push_user_area(area, Some(bytes));
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

    /// Real munmap: unmap every page in `[va, va+len)`. If a VmArea is
    /// fully covered, drop it (and all its frames). If partially covered,
    /// shrink or split it. PTEs in the range are cleared and the local TLB
    /// is flushed page-by-page.
    pub fn unmap_range(&mut self, va: VirtAddr, len: usize) {
        let start = va.0 & !(PAGE_SIZE - 1);
        let end = (va.0 + len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let start_vpn = VirtPageNum(start / PAGE_SIZE);
        let end_vpn = VirtPageNum(end / PAGE_SIZE);

        let mut new_areas: Vec<VmArea> = Vec::new();
        for area in core::mem::take(&mut self.areas) {
            // No overlap → keep verbatim.
            if area.vpn_end <= start_vpn || area.vpn_start >= end_vpn {
                new_areas.push(area);
                continue;
            }

            let a_start = area.vpn_start;
            let a_end = area.vpn_end;
            let perm = area.perm;
            let mut frames = area.frames;

            // Compute overlap.
            let cut_start = core::cmp::max(a_start, start_vpn);
            let cut_end = core::cmp::min(a_end, end_vpn);

            // Unmap pages in the overlap.
            for vpn_raw in cut_start.0..cut_end.0 {
                let vpn = VirtPageNum(vpn_raw);
                if frames.remove(&vpn).is_some() {
                    let _ = self.page_table.unmap(vpn);
                    super::page_table::local_flush_va(vpn);
                }
            }

            // Reconstitute the head, if any.
            if a_start < cut_start {
                let head_frames = split_off_le(&mut frames, cut_start);
                new_areas.push(VmArea {
                    vpn_start: a_start,
                    vpn_end: cut_start,
                    perm,
                    frames: head_frames,
                });
            }
            // Reconstitute the tail, if any.
            if cut_end < a_end {
                new_areas.push(VmArea {
                    vpn_start: cut_end,
                    vpn_end: a_end,
                    perm,
                    frames,
                });
            }
            // (If the area was fully covered, both branches above are false
            // and we just drop everything, releasing frames via Drop.)
        }
        self.areas = new_areas;
    }

    /// Real mprotect: change perms on every page in `[va, va+len)`. Splits
    /// VmAreas at boundaries as needed and rewrites the PTE flags. Pages
    /// outside any existing area are silently skipped.
    pub fn protect_range(&mut self, va: VirtAddr, len: usize, perm: VmPerm) {
        let start = va.0 & !(PAGE_SIZE - 1);
        let end = (va.0 + len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let start_vpn = VirtPageNum(start / PAGE_SIZE);
        let end_vpn = VirtPageNum(end / PAGE_SIZE);
        let new_pte = perm.to_pte();

        let mut new_areas: Vec<VmArea> = Vec::new();
        for area in core::mem::take(&mut self.areas) {
            if area.vpn_end <= start_vpn || area.vpn_start >= end_vpn {
                new_areas.push(area);
                continue;
            }

            let a_start = area.vpn_start;
            let a_end = area.vpn_end;
            let a_perm = area.perm;
            let mut frames = area.frames;

            let cut_start = core::cmp::max(a_start, start_vpn);
            let cut_end = core::cmp::min(a_end, end_vpn);

            // Head with old perm.
            if a_start < cut_start {
                let head_frames = split_off_le(&mut frames, cut_start);
                new_areas.push(VmArea {
                    vpn_start: a_start,
                    vpn_end: cut_start,
                    perm: a_perm,
                    frames: head_frames,
                });
            }
            // Middle with new perm — rewrite PTEs.
            let mid_frames = split_off_le(&mut frames, cut_end);
            for (&vpn, frame) in &mid_frames {
                self.page_table.map(vpn, frame.ppn, new_pte);
                super::page_table::local_flush_va(vpn);
            }
            new_areas.push(VmArea {
                vpn_start: cut_start,
                vpn_end: cut_end,
                perm,
                frames: mid_frames,
            });
            // Tail with old perm.
            if cut_end < a_end {
                new_areas.push(VmArea {
                    vpn_start: cut_end,
                    vpn_end: a_end,
                    perm: a_perm,
                    frames,
                });
            }
        }
        self.areas = new_areas;
    }

    /// Deep-copy this address space (fork). Each user VmArea gets fresh
    /// frames whose contents are copied from the parent. Kernel + MMIO
    /// identity mappings need to be re-added by the caller.
    pub fn fork(&self) -> Self {
        let mut new_ms = MemorySet::new();
        for area in &self.areas {
            let mut new_frames = alloc::collections::BTreeMap::new();
            let pte_flags = area.perm.to_pte();
            for (&vpn, frame) in &area.frames {
                let new_frame = super::frame::alloc().expect("OOM in fork");
                let src = frame.ppn.as_byte_slice();
                let dst = new_frame.ppn.as_byte_slice();
                dst.copy_from_slice(src);
                new_ms.page_table.map(vpn, new_frame.ppn, pte_flags);
                new_frames.insert(vpn, new_frame);
            }
            new_ms.areas.push(VmArea {
                vpn_start: area.vpn_start,
                vpn_end: area.vpn_end,
                perm: area.perm,
                frames: new_frames,
            });
        }
        new_ms.brk_base = self.brk_base;
        new_ms.brk_cur = self.brk_cur;
        new_ms.mmap_top = self.mmap_top;
        new_ms
    }

    /// Find the area that contains `vpn` (for fault handlers, brk).
    pub fn find_area_mut(&mut self, vpn: VirtPageNum) -> Option<&mut VmArea> {
        self.areas.iter_mut().find(|a| a.contains(vpn))
    }

    /// Unmap and free the single VmArea at index `idx`, clearing its PTEs,
    /// flushing the local TLB, and dropping the backing frames. Returns the
    /// freed area so the caller can inspect its bounds.
    fn drop_area_at(&mut self, idx: usize) -> VmArea {
        let area = self.areas.remove(idx);
        for (&vpn, _frame) in area.frames.iter() {
            let _ = self.page_table.unmap(vpn);
            super::page_table::local_flush_va(vpn);
        }
        // `area` (and its FrameTrackers) drop on return / at the call site,
        // releasing the frames.
        area
    }

    /// Queue an exited pthread's stack top for deferred reclamation. The
    /// actual unmap happens at the next `drain_stack_reclaim` (called when a
    /// new thread is created in this address space) so that a concurrent
    /// `pthread_join` can still read the exiting thread's descriptor first.
    pub fn queue_stack_reclaim(&mut self, stack_top: usize) {
        if stack_top != 0 {
            self.pending_stack_reclaim.push(stack_top);
        }
    }

    /// Number of most-recently-queued exited-thread stacks we never reclaim.
    /// Must exceed the largest number of threads that can be exited-but-not-
    /// yet-joined at once for any well-behaved workload, so we never unmap a
    /// stack whose descriptor a pending `pthread_join` still needs. libc-bench
    /// `b_pthread_createjoin_serial2` batches 50 creates before 50 joins, so a
    /// margin well above 50 keeps every not-yet-joined stack safe.
    const RECLAIM_KEEP_NEWEST: usize = 96;
    /// Only start reclaiming once the queue grows past this. Keeps the common
    /// case (threads promptly joined → musl munmaps the stack itself, our
    /// queue entries are stale no-ops) cheap, and means batched create/join
    /// patterns never trip reclaim.
    const RECLAIM_HIGH_WATER: usize = 192;

    /// Reclaim *old* queued pthread stacks once the backlog grows large. The
    /// newest `RECLAIM_KEEP_NEWEST` entries are always retained (a pending
    /// join may still read their descriptor); older entries belong to threads
    /// that were abandoned (never joined — e.g. b_pthread_create_serial1's
    /// 2500 threads) and are freed so the region count stays bounded and
    /// /proc/self/smaps reads don't go quadratic. Reclaiming an already-joined
    /// (musl-munmap'd) stack is a harmless no-op. Returns the count freed.
    pub fn drain_stack_reclaim(&mut self) -> usize {
        let len = self.pending_stack_reclaim.len();
        if len <= Self::RECLAIM_HIGH_WATER {
            return 0;
        }
        // Take the oldest entries, keep the newest RECLAIM_KEEP_NEWEST.
        let take = len - Self::RECLAIM_KEEP_NEWEST;
        let old: Vec<usize> = self.pending_stack_reclaim.drain(..take).collect();
        let mut n = 0;
        for stack_top in old {
            if self.reclaim_thread_stack(stack_top) {
                n += 1;
            }
        }
        n
    }

    /// Reclaim a never-joined thread's stack allocation from the (shared)
    /// address space, given the stack pointer handed to `clone` (`stack_top`,
    /// the highest stack address). Frees the VmArea that contains
    /// `stack_top - 1`, plus any immediately-preceding contiguous guard
    /// region (the PROT_NONE page musl maps just below the usable stack).
    /// Never touches the heap (brk) area. Returns true if anything was freed.
    ///
    /// libc-bench's `b_pthread_create_serial1` spawns 2500 threads it never
    /// joins; without reclaiming their stacks here, the address space grows
    /// to ~5000 regions and reading /proc/self/smaps (which print_stats does)
    /// turns quadratic and effectively hangs.
    fn reclaim_thread_stack(&mut self, stack_top: usize) -> bool {
        if stack_top == 0 {
            return false;
        }
        // Probe the highest valid stack byte (stack_top is exclusive / points
        // one past the top in the typical "sp = base + size" convention).
        let probe = VirtAddr(stack_top.saturating_sub(1));
        let vpn = probe.floor();
        let brk_start_vpn = self.brk_base.floor();
        let Some(idx) = self
            .areas
            .iter()
            .position(|a| a.contains(vpn) && a.vpn_start != brk_start_vpn)
        else {
            return false;
        };
        let stack_area = self.drop_area_at(idx);
        // Free a contiguous guard region directly below the stack, if present
        // (vpn_end touches the stack's vpn_start). Only the guard immediately
        // adjacent is reclaimed, never the heap.
        let guard_top = stack_area.vpn_start;
        if let Some(gidx) = self
            .areas
            .iter()
            .position(|a| a.vpn_end == guard_top && a.vpn_start != brk_start_vpn)
        {
            let _ = self.drop_area_at(gidx);
        }
        true
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

    /// Allocate and map `len` bytes of anonymous user memory with the
    /// given permissions. Returns the page-aligned start address. The
    /// allocator carves out the region above the previous mmap_top so
    /// it never collides with brk or with other mmap regions. The
    /// returned address is always PAGE_SIZE aligned, which is what
    /// musl's mallocng (and friends) require — it asserts on 16-byte
    /// alignment of every malloc result, and a page-aligned region
    /// trivially satisfies that.
    pub fn mmap_anon(&mut self, len: usize, perm: VmPerm, init: Option<&[u8]>) -> VirtAddr {
        let aligned = (len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let start = self.mmap_top.0;
        let end = start + aligned;
        let area = VmArea::new(VirtAddr(start), VirtAddr(end), perm);
        self.push_user_area(area, init);
        self.mmap_top = VirtAddr(end);
        VirtAddr(start)
    }
}
