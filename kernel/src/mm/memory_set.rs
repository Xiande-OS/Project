//! Per-process / per-kernel memory map.
//!
//! `MemorySet` = one Sv39 page table plus the list of mapped regions
//! (`VmArea`) and their owned physical frames. Drop frees the frames.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use bitflags::bitflags;

use super::address::{PhysPageNum, VirtAddr, VirtPageNum, PAGE_SIZE};
use super::frame::{alloc as alloc_frame, alloc_uninit as alloc_uninit_frame, FrameTracker};
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
        // A user region with no R/W/X is a PROT_NONE reservation. RISC-V has
        // no valid leaf with all of R/W/X clear (that encoding is a non-leaf
        // pointer), and we have no demand-fault handler, so back it with a
        // real R|W leaf: the owning process can reserve-then-write it (musl
        // mallocng arenas, busybox heap). The *logical* VmPerm stays U-only,
        // so the kernel copy path (perm_at) still refuses a syscall handed a
        // pointer into it — EFAULT, which LTP's tst_get_bad_addr relies on.
        if self.contains(Self::U) && !self.intersects(Self::R | Self::W | Self::X) {
            f |= PteFlags::R | PteFlags::W;
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
    /// Arc-wrapped so a MAP_SHARED area can hand the *same* physical frame
    /// to a forked child (refcount > 1); private areas keep refcount 1 and
    /// behave exactly like the old owned FrameTracker.
    pub frames: BTreeMap<VirtPageNum, Arc<FrameTracker>>,
    /// MAP_SHARED|MAP_ANONYMOUS region: on fork() the child maps the same
    /// physical frames instead of private copies, so writes are mutually
    /// visible. LTP's tst_test framework passes results parent<->child
    /// through exactly such a region.
    pub shared: bool,
    /// True for private anonymous memory (MAP_ANONYMOUS without a file backing,
    /// plus the brk heap). False for file-backed mappings and kernel-provided
    /// pages. madvise(2) uses this to honor Linux's rule that MADV_FREE and
    /// MADV_WIPEONFORK apply only to private anonymous pages (EINVAL otherwise).
    pub anon: bool,
    /// MADV_WIPEONFORK was requested on this area: on fork() the child receives
    /// freshly zeroed pages for this range instead of a copy of the parent's
    /// contents. MADV_KEEPONFORK clears it again. Only ever set on private
    /// anonymous areas (see `anon`).
    pub wipe_on_fork: bool,
}

impl VmArea {
    pub fn new(va_start: VirtAddr, va_end: VirtAddr, perm: VmPerm) -> Self {
        Self {
            vpn_start: va_start.floor(),
            vpn_end: va_end.ceil(),
            perm,
            frames: BTreeMap::new(),
            shared: false,
            anon: false,
            wipe_on_fork: false,
        }
    }

    pub fn contains(&self, vpn: VirtPageNum) -> bool {
        vpn >= self.vpn_start && vpn < self.vpn_end
    }
}

/// Outcome of `MemorySet::madvise_anon_check` for an advice (MADV_FREE /
/// MADV_WIPEONFORK) that Linux restricts to private anonymous memory.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MadviseRange {
    /// Every covered page is private anonymous and the range is fully mapped.
    Ok,
    /// A mapped page in the range is not private anonymous → EINVAL.
    WrongType,
    /// The range is private-anon where mapped but has an unmapped hole → ENOMEM.
    Hole,
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

    /// Fallible constructor. fork/exec paths call this so a frame-pool
    /// exhaustion returns ENOMEM (the failing syscall fails cleanly)
    /// instead of panicking the whole kernel mid-contest.
    pub fn try_new() -> Option<Self> {
        Some(Self {
            page_table: PageTable::try_new()?,
            areas: Vec::new(),
            brk_base: VirtAddr(0),
            brk_cur: VirtAddr(0),
            mmap_top: VirtAddr(MMAP_BASE),
            pending_stack_reclaim: Vec::new(),
        })
    }

    pub fn satp(&self) -> usize {
        self.page_table.satp()
    }

    /// Identity-map the kernel image + heap + frame pool into this address
    /// space, with R|W|X permissions and no U bit. Required so that the
    /// CPU keeps executing the kernel after we switch satp to this table.
    pub fn map_kernel_identity(&mut self, k_start: usize, k_end: usize) {
        let perm = PteFlags::V | PteFlags::R | PteFlags::W | PteFlags::X;
        self.map_identity_range(k_start, k_end, perm);
    }

    /// Map an MMIO region identity (R|W, no U).
    pub fn map_mmio(&mut self, pa_start: usize, pa_end: usize) {
        let perm = PteFlags::V | PteFlags::R | PteFlags::W;
        self.map_identity_range(pa_start, pa_end, perm);
    }

    /// Identity-map `[pa_start, pa_end)` using 2 MiB megapages wherever the
    /// span is 2 MiB-aligned, falling back to 4 KiB pages for any ragged
    /// ends. The kernel image (≈1 GiB up to MEMORY_END) and the PLIC window
    /// (64 MiB) are 2 MiB-aligned, so this turns the ~261 k per-spawn PTE
    /// writes of the old page-at-a-time loop into a few hundred — fork and
    /// execve rebuild the kernel half of every address space, so this was
    /// ~40 ms of pure overhead on each shell command. These ranges are
    /// identity-mapped, never unmapped per-process, and live in page-table
    /// slots disjoint from every user region, so a coarser leaf is safe.
    fn map_identity_range(&mut self, pa_start: usize, pa_end: usize, perm: PteFlags) {
        const MEGA: usize = 2 * 1024 * 1024;
        let mut addr = pa_start & !(PAGE_SIZE - 1);
        let end = (pa_end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        while addr < end {
            let vpn = VirtPageNum(addr / PAGE_SIZE);
            if addr % MEGA == 0 && addr + MEGA <= end {
                self.page_table.map_megapage(vpn, PhysPageNum(vpn.0), perm);
                addr += MEGA;
            } else {
                self.page_table.map(vpn, PhysPageNum(vpn.0), perm);
                addr += PAGE_SIZE;
            }
        }
    }

    /// Install a user-readable+executable page at `va` containing `bytes`
    /// (zero-padded to a page). Used for the signal-restorer trampoline.
    pub fn map_user_rx_page(&mut self, va: VirtAddr, bytes: &[u8]) {
        let area = VmArea::new(va, VirtAddr(va.0 + PAGE_SIZE), VmPerm::R | VmPerm::X | VmPerm::U);
        // One page at exec time; if this OOMs the restorer just won't be
        // mapped (signals would fault) but the kernel survives.
        let _ = self.push_user_area(area, Some(bytes));
    }

    /// Push a user-mode area into this address space and (eagerly) back
    /// every page with a freshly allocated frame. If `init_data` is Some,
    /// the bytes are copied to the start of the area (zero padded).
    /// Returns Err(()) on frame exhaustion. Frames mapped so far in this
    /// area are freed when `area` drops, so a partial failure leaves no
    /// leak. Callers in the execve / brk / mmap paths must turn Err into
    /// ENOMEM rather than panicking — a fork-storm benchmark must not
    /// take down the kernel.
    pub fn push_user_area(&mut self, mut area: VmArea, init_data: Option<&[u8]>) -> Result<(), ()> {
        let pte_flags = area.perm.to_pte();
        // Walk page by page.
        let mut copied = 0usize;
        for vpn_raw in area.vpn_start.0..area.vpn_end.0 {
            let vpn = VirtPageNum(vpn_raw);
            // Grab an *unzeroed* frame and initialise it exactly once: copy
            // the init bytes that land on this page, then zero only the
            // remainder. The old path zero-filled every frame in `alloc`
            // and then immediately overwrote most of it with the copy — a
            // second full-page write per page. For a 1.4 MiB busybox image
            // (~350 text pages) that doubled the bytes touched on every
            // execve, and execve runs ~100×/fs_bind case. Zeroing the tail
            // here preserves the .bss / page-padding guarantee callers rely
            // on (uninitialised user memory must read as 0).
            let Some(frame) = alloc_uninit_frame() else { return Err(()); };
            let ppn = frame.ppn;
            let dst = ppn.as_byte_slice();
            let n = match init_data {
                Some(data) if copied < data.len() => {
                    let n = core::cmp::min(PAGE_SIZE, data.len() - copied);
                    dst[..n].copy_from_slice(&data[copied..copied + n]);
                    copied += n;
                    n
                }
                _ => 0,
            };
            if n < PAGE_SIZE {
                dst[n..].fill(0);
            }
            self.page_table.map(vpn, ppn, pte_flags);
            area.frames.insert(vpn, Arc::new(frame));
        }
        self.areas.push(area);
        Ok(())
    }

    pub fn translate(&self, va: VirtAddr) -> Option<super::address::PhysAddr> {
        self.page_table.translate(va)
    }

    /// The declared VmArea permission covering `va`, if any. Used by the
    /// kernel's copy_in/copy_out to honor a region's *declared* protection
    /// even when the hardware page is mapped more permissively. In
    /// particular a mmap(PROT_NONE) guard page (perm == U only, no R/W) is
    /// mapped R|W at the PTE level so the owning process's reserve-then-write
    /// pattern works — but a syscall handed such an address must still fail
    /// with EFAULT, which LTP's tst_get_bad_addr relies on. Returns None if
    /// no area covers the address (also a fault).
    pub fn perm_at(&self, va: VirtAddr) -> Option<VmPerm> {
        let vpn = va.floor();
        self.areas
            .iter()
            .find(|a| a.contains(vpn))
            .map(|a| a.perm)
    }

    /// Is every page in `[start_vpn, end_vpn)` covered by some VmArea? Used by
    /// madvise(2)/msync(2) to return ENOMEM when a hole (or an address outside
    /// the address space) falls inside the requested range. A PROT_NONE guard
    /// page still counts as mapped — it lives in a VmArea — which matches Linux
    /// (madvise on a PROT_NONE region is not ENOMEM).
    pub fn range_fully_mapped(&self, start_vpn: VirtPageNum, end_vpn: VirtPageNum) -> bool {
        let mut vpn = start_vpn.0;
        while vpn < end_vpn.0 {
            let cur = VirtPageNum(vpn);
            match self.areas.iter().find(|a| a.contains(cur)) {
                // Skip to the end of the covering area so this is O(areas), not
                // O(pages) — a multi-hundred-MiB range would otherwise be slow.
                Some(a) => vpn = a.vpn_end.0,
                None => return false,
            }
        }
        true
    }

    /// Check `[start_vpn, end_vpn)` for MADV_FREE / MADV_WIPEONFORK, which Linux
    /// allows only on private anonymous memory. This reproduces the precedence
    /// of Linux's `madvise_walk_vmas`: it scans VMAs left-to-right and returns
    /// EINVAL the moment it visits a non-(private-anon) area, *before* it would
    /// report a later hole as ENOMEM. So a range that starts in a too-short
    /// MAP_SHARED anonymous mapping (madvise02's shared_anon, where the madvise
    /// length runs past the one mapped page) yields EINVAL, not ENOMEM — the
    /// wrong-type area at the start wins over the trailing gap.
    pub fn madvise_anon_check(&self, start_vpn: VirtPageNum, end_vpn: VirtPageNum) -> MadviseRange {
        let mut vpn = start_vpn.0;
        let mut saw_hole = false;
        while vpn < end_vpn.0 {
            let cur = VirtPageNum(vpn);
            match self.areas.iter().find(|a| a.contains(cur)) {
                Some(a) => {
                    // A mapped area that is not private anonymous → EINVAL now,
                    // exactly as the per-VMA behaviour check would fire.
                    if !(a.anon && !a.shared) {
                        return MadviseRange::WrongType;
                    }
                    vpn = a.vpn_end.0;
                }
                // Unmapped page: remember it as a candidate ENOMEM but keep
                // scanning — a wrong-type area later still takes precedence.
                // Jump straight to the next area that starts beyond here (or to
                // the end of the range) so a large hole stays O(areas).
                None => {
                    saw_hole = true;
                    let next = self
                        .areas
                        .iter()
                        .map(|a| a.vpn_start.0)
                        .filter(|&s| s > vpn)
                        .min()
                        .unwrap_or(end_vpn.0);
                    vpn = next;
                }
            }
        }
        if saw_hole {
            MadviseRange::Hole
        } else {
            MadviseRange::Ok
        }
    }

    /// Set (or clear) the MADV_WIPEONFORK flag on every page in `[va, va+len)`,
    /// splitting VmAreas at the range boundaries so the flag applies exactly to
    /// the requested span. Mirrors `protect_range`'s split logic but only flips
    /// the per-area `wipe_on_fork` bit (no PTE rewrite). The caller has already
    /// validated that the whole range is private anonymous.
    pub fn set_wipe_on_fork(&mut self, va: VirtAddr, len: usize, wipe: bool) {
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
            let a_shared = area.shared;
            let a_anon = area.anon;
            let a_wipe = area.wipe_on_fork;
            let mut frames = area.frames;

            let cut_start = core::cmp::max(a_start, start_vpn);
            let cut_end = core::cmp::min(a_end, end_vpn);

            // Head outside the range — keep its old flag.
            if a_start < cut_start {
                let head_frames = split_off_le(&mut frames, cut_start);
                new_areas.push(VmArea {
                    vpn_start: a_start,
                    vpn_end: cut_start,
                    perm,
                    shared: a_shared,
                    anon: a_anon,
                    wipe_on_fork: a_wipe,
                    frames: head_frames,
                });
            }
            // Middle inside the range — set the new flag.
            let mid_frames = split_off_le(&mut frames, cut_end);
            new_areas.push(VmArea {
                vpn_start: cut_start,
                vpn_end: cut_end,
                perm,
                shared: a_shared,
                anon: a_anon,
                wipe_on_fork: wipe,
                frames: mid_frames,
            });
            // Tail outside the range — keep its old flag.
            if cut_end < a_end {
                new_areas.push(VmArea {
                    vpn_start: cut_end,
                    vpn_end: a_end,
                    perm,
                    shared: a_shared,
                    anon: a_anon,
                    wipe_on_fork: a_wipe,
                    frames,
                });
            }
        }
        self.areas = new_areas;
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
            let a_shared = area.shared;
            let a_anon = area.anon;
            let a_wipe = area.wipe_on_fork;
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
                    shared: a_shared,
                    anon: a_anon,
                    wipe_on_fork: a_wipe,
                    frames: head_frames,
                });
            }
            // Reconstitute the tail, if any.
            if cut_end < a_end {
                new_areas.push(VmArea {
                    vpn_start: cut_end,
                    vpn_end: a_end,
                    perm,
                    shared: a_shared,
                    anon: a_anon,
                    wipe_on_fork: a_wipe,
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
            let a_shared = area.shared;
            let a_anon = area.anon;
            let a_wipe = area.wipe_on_fork;
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
                    shared: a_shared,
                    anon: a_anon,
                    wipe_on_fork: a_wipe,
                    frames: head_frames,
                });
            }
            // Middle with new perm — rewrite PTEs. If this makes pages
            // writable, break any cross-address-space sharing first: fork()
            // hands a read-only page to the child as the *same* physical
            // frame (Arc refcount > 1), so turning it writable here would let
            // writes leak across the fork boundary. Copy such an aliased
            // frame to a private one before remapping it writable. MAP_SHARED
            // areas (a_shared) are deliberately exempt — their writes are
            // meant to be mutually visible. There is no COW fault path, so
            // mprotect is the only place an RO-shared page can become
            // writable; guarding it here keeps fork's RO-sharing sound.
            let mut mid_frames = split_off_le(&mut frames, cut_end);
            let make_writable = perm.contains(VmPerm::W);
            for (vpn, frame) in mid_frames.iter_mut() {
                if make_writable && !a_shared && Arc::strong_count(frame) > 1 {
                    if let Some(copy) = super::frame::alloc_uninit() {
                        copy.ppn
                            .as_byte_slice()
                            .copy_from_slice(frame.ppn.as_byte_slice());
                        *frame = Arc::new(copy);
                    }
                    // On OOM we fall through and reuse the shared frame: the
                    // mprotect still succeeds, and the (rare) aliased write is
                    // a lesser evil than failing the syscall or panicking.
                }
                self.page_table.map(*vpn, frame.ppn, new_pte);
                super::page_table::local_flush_va(*vpn);
            }
            new_areas.push(VmArea {
                vpn_start: cut_start,
                vpn_end: cut_end,
                perm,
                shared: a_shared,
                anon: a_anon,
                wipe_on_fork: a_wipe,
                frames: mid_frames,
            });
            // Tail with old perm.
            if cut_end < a_end {
                new_areas.push(VmArea {
                    vpn_start: cut_end,
                    vpn_end: a_end,
                    perm: a_perm,
                    shared: a_shared,
                    anon: a_anon,
                    wipe_on_fork: a_wipe,
                    frames,
                });
            }
        }
        self.areas = new_areas;
    }

    /// Deep-copy this address space (fork). Each user VmArea gets fresh
    /// frames whose contents are copied from the parent. Kernel + MMIO
    /// identity mappings need to be re-added by the caller.
    ///
    /// Returns None if any frame allocation fails (out of physical
    /// memory). The caller must turn that into an ENOMEM for the fork
    /// syscall instead of crashing — a fork-storm benchmark
    /// (unixbench SHELL16) must not panic the whole kernel and lose
    /// every test group sequenced after it. On None, all frames
    /// allocated so far are freed when `new_ms` drops.
    pub fn fork(&self) -> Option<Self> {
        let mut new_ms = MemorySet::try_new()?;
        for area in &self.areas {
            let mut new_frames = alloc::collections::BTreeMap::new();
            let pte_flags = area.perm.to_pte();
            // Read-only areas (program text, rodata) can never diverge
            // between parent and child: a write faults to SIGSEGV in both,
            // exactly as it would against a private copy. So the child maps
            // the SAME physical frames (Arc refcount bump) instead of
            // allocating and memcpying a byte-identical duplicate — the
            // observable behaviour is unchanged but a busybox-sized text
            // segment (~260 pages) is no longer copied on every fork. The
            // common shell pattern fork()+execve() then drops the shared
            // refs at exec teardown, so nothing is pinned.
            // MADV_WIPEONFORK: the child must see this private-anonymous range
            // as freshly zeroed rather than a copy of the parent (Linux zaps
            // the child's pages at fork). The setting itself is inherited, so a
            // grand-child forked from this child is wiped too.
            let wipe = area.wipe_on_fork;
            let share = !wipe && (area.shared || !area.perm.contains(VmPerm::W));
            for (&vpn, frame) in &area.frames {
                if wipe {
                    // Hand the child a zeroed frame instead of the parent's
                    // contents. alloc_frame() returns a zero-filled page.
                    let new_frame = alloc_frame()?; // None -> ENOMEM
                    new_ms.page_table.map(vpn, new_frame.ppn, pte_flags);
                    new_frames.insert(vpn, Arc::new(new_frame));
                } else if share {
                    // MAP_SHARED anon (mutually-visible writes) OR a
                    // read-only page: map the same frame in the child.
                    new_ms.page_table.map(vpn, frame.ppn, pte_flags);
                    new_frames.insert(vpn, Arc::clone(frame));
                } else {
                    // Writable private page: a real copy is required (there
                    // is no copy-on-write fault path). `alloc_uninit` skips
                    // the zero-fill since the very next line overwrites the
                    // whole page.
                    let new_frame = super::frame::alloc_uninit()?; // None -> ENOMEM
                    let src = frame.ppn.as_byte_slice();
                    let dst = new_frame.ppn.as_byte_slice();
                    dst.copy_from_slice(src);
                    new_ms.page_table.map(vpn, new_frame.ppn, pte_flags);
                    new_frames.insert(vpn, Arc::new(new_frame));
                }
            }
            new_ms.areas.push(VmArea {
                vpn_start: area.vpn_start,
                vpn_end: area.vpn_end,
                perm: area.perm,
                shared: area.shared,
                anon: area.anon,
                wipe_on_fork: area.wipe_on_fork,
                frames: new_frames,
            });
        }
        new_ms.brk_base = self.brk_base;
        new_ms.brk_cur = self.brk_cur;
        new_ms.mmap_top = self.mmap_top;
        Some(new_ms)
    }

    /// Release every user frame (areas) back to the physical allocator,
    /// keeping the page-table root intact. Called when a task exits so a
    /// zombie no longer pins ~hundreds of frames until it's wait4'd.
    /// Without this, a fork-storm (unixbench SHELL16) piles up zombies
    /// faster than the parent reaps them and the frame pool is exhausted,
    /// panicking some later alloc_frame().expect(). The page table root
    /// stays allocated (satp may still point here until the scheduler
    /// switches away); its stale PTEs are harmless because the dead task
    /// never re-enters user mode.
    pub fn free_user_frames(&mut self) {
        // Dropping the Frame values returns them to the allocator.
        self.areas.clear();
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
        // Bound the heap. We eagerly back every brk page (no demand paging),
        // so an unbounded grow — e.g. LTP sbrk02, which probes the limit by
        // doubling the break until it fails — would allocate the entire frame
        // pool one page at a time in the loop below, and with no signal check
        // do so uninterruptibly (the per-case test timeout's SIGKILL can't
        // land mid-loop, so the whole run wedges). Linux bounds brk by
        // RLIMIT_DATA + the mmap gap and never backs a page until it faults;
        // we approximate that with a fixed ceiling so an oversized request
        // fails fast (userland gets the old break back = ENOMEM) instead of
        // draining RAM. 128 MiB is far above any contest program's real heap
        // (malloc routes large requests through mmap, not brk), yet well below
        // the point where eagerly backing the grow would itself take long
        // enough to look like a hang.
        const BRK_MAX_HEAP: usize = 128 * 1024 * 1024;
        if new_brk.0 > self.brk_base.0.saturating_add(BRK_MAX_HEAP) {
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
            let killing = crate::task::current_task();
            for vpn_raw in old_top_vpn.0..new_top_vpn.0 {
                // Stay killable on a large grow: a pending SIGKILL (the
                // per-case test timeout) must end us instead of being
                // deferred until this loop finishes draining memory. Check
                // cheaply, every 1024 pages, and commit the partial break.
                if vpn_raw & 1023 == 0 && crate::signal::has_pending_sigkill(&killing) {
                    area.vpn_end = VirtPageNum(vpn_raw);
                    self.brk_cur = VirtAddr(vpn_raw << crate::mm::address::PAGE_SIZE_BITS);
                    return self.brk_cur;
                }
                let vpn = VirtPageNum(vpn_raw);
                if area.frames.contains_key(&vpn) {
                    continue;
                }
                let Some(frame) = alloc_frame() else {
                    // OOM: stop growing. Commit the brk we managed to
                    // back so far; userland sees a short brk and its
                    // allocator returns NULL instead of the kernel dying.
                    area.vpn_end = vpn;
                    self.brk_cur = VirtAddr(vpn.0 << crate::mm::address::PAGE_SIZE_BITS);
                    return self.brk_cur;
                };
                self.page_table.map(vpn, frame.ppn, pte_flags);
                area.frames.insert(vpn, Arc::new(frame));
            }
            area.vpn_end = new_top_vpn;
        } else {
            // Create a new heap area.
            let mut area = VmArea::new(self.brk_base, new_brk, heap_perm);
            area.anon = true; // the program break heap is private anonymous memory
            if self.push_user_area(area, None).is_err() {
                // OOM — leave brk where it was.
                return self.brk_cur;
            }
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
    pub fn mmap_anon(&mut self, len: usize, perm: VmPerm, init: Option<&[u8]>, shared: bool) -> VirtAddr {
        let aligned = (len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let mut start = self.mmap_top.0;
        // Never hand back a region overlapping the program break heap.
        // `mmap_top` can be dragged into [brk_base, brk_cur) by a MAP_FIXED
        // overlay placed near the brk (e.g. a libc heap guard); allocating
        // there would alias the heap and silently corrupt it (musl mallocng
        // metadata, in practice). Skip past the heap when that happens.
        let brk_hi = (self.brk_cur.0 + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        if start < brk_hi && start + aligned > self.brk_base.0 {
            start = brk_hi;
        }
        let end = start + aligned;
        let mut area = VmArea::new(VirtAddr(start), VirtAddr(end), perm);
        area.shared = shared;
        // A mapping with no file-backed initialiser is anonymous memory (a
        // plain MAP_ANONYMOUS mmap, or the brk heap which calls in with
        // init=None). File mmaps pass the file contents as `init`. madvise(2)
        // restricts MADV_FREE/MADV_WIPEONFORK to private anonymous pages.
        area.anon = init.is_none();
        if self.push_user_area(area, init).is_err() {
            // OOM — return the conventional MAP_FAILED sentinel. The
            // mmap syscall translates this to -ENOMEM. Don't advance
            // mmap_top so the address space stays consistent.
            return VirtAddr(usize::MAX);
        }
        self.mmap_top = VirtAddr(end);
        VirtAddr(start)
    }

    /// SysV `shmat`: map a set of already-allocated, shared physical frames
    /// into this address space. The frames are owned by the IPC segment (in
    /// `sysv_ipc::SHM`); we clone each `Arc` so they stay live while *either*
    /// the segment or this attachment references them — exactly SysV semantics
    /// (memory persists past the creator's exit until IPC_RMID *and* the last
    /// detach). With `at` == None we place the region at the mmap arena top;
    /// otherwise we honor the caller's address (shmat with a non-NULL shmaddr),
    /// replacing whatever was there. Returns the start VA, or usize::MAX on a
    /// page-table-node OOM.
    pub fn map_shared_frames(
        &mut self,
        frames: &[Arc<FrameTracker>],
        perm: VmPerm,
        at: Option<usize>,
    ) -> VirtAddr {
        let aligned = frames.len() * PAGE_SIZE;
        if aligned == 0 {
            return VirtAddr(usize::MAX);
        }
        let start = match at {
            Some(a) => {
                let s = a & !(PAGE_SIZE - 1);
                // Replace any existing mapping in the target span (shmat at a
                // fixed address overlays it, like MAP_FIXED).
                self.unmap_range(VirtAddr(s), aligned);
                s
            }
            None => {
                let mut s = self.mmap_top.0;
                let brk_hi = (self.brk_cur.0 + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
                if s < brk_hi && s + aligned > self.brk_base.0 {
                    s = brk_hi;
                }
                s
            }
        };
        let end = start + aligned;
        let mut area = VmArea::new(VirtAddr(start), VirtAddr(end), perm);
        area.shared = true;
        let pte_flags = perm.to_pte();
        for (i, fr) in frames.iter().enumerate() {
            let vpn = VirtPageNum(start / PAGE_SIZE + i);
            self.page_table.map(vpn, fr.ppn, pte_flags);
            area.frames.insert(vpn, fr.clone());
        }
        self.areas.push(area);
        if start >= self.mmap_top.0 {
            self.mmap_top = VirtAddr(end);
        }
        VirtAddr(start)
    }

    /// `mmap(... MAP_FIXED ...)`: map exactly at `va`, replacing whatever
    /// was mapped in `[va, va+len)`. This is mandatory for the glibc
    /// dynamic loader: it reserves a span with one file mmap, then
    /// overlays each subsequent PT_LOAD segment with a MAP_FIXED mmap at
    /// base+vaddr. If we placed those at mmap_top instead, the loader's
    /// relocations would write to the gap and StorePageFault. Returns
    /// `va` on success, usize::MAX (MAP_FAILED) on OOM.
    pub fn mmap_fixed(
        &mut self,
        va: usize,
        len: usize,
        perm: VmPerm,
        init: Option<&[u8]>,
    ) -> VirtAddr {
        let start = va & !(PAGE_SIZE - 1);
        let aligned = (len + (va - start) + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let end = start + aligned;
        // Drop any existing mappings (and their frames) in the range so
        // the overlay is clean — MAP_FIXED semantics replace, not error.
        self.unmap_range(VirtAddr(start), aligned);
        let area = VmArea::new(VirtAddr(start), VirtAddr(end), perm);
        if self.push_user_area(area, init).is_err() {
            return VirtAddr(usize::MAX);
        }
        // Keep mmap_top above a fixed mapping that *extends the mmap arena*
        // — e.g. the dynamic loader overlaying PT_LOAD segments onto a span
        // it just reserved with an anonymous mmap (so `start <= mmap_top`).
        // Do NOT drag mmap_top up to a far fixed mapping in unrelated
        // territory (a libc heap-guard placed near brk, or the interpreter
        // base): that pulls subsequent anonymous mmaps out of the arena and
        // straight on top of the brk heap, aliasing it.
        if start <= self.mmap_top.0 && end > self.mmap_top.0 {
            self.mmap_top = VirtAddr(end);
        }
        VirtAddr(va)
    }
}
