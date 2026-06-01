//! virtio-blk on top of the `virtio-drivers` crate.
//!
//! Two transports are supported, selected per architecture:
//!   * riscv64 — the virtio-mmio bank scanned at fixed addresses.
//!   * loongarch64 — virtio-pci, discovered via ECAM enumeration
//!     (`crate::drivers::pci`).
//! The block logic itself is transport-agnostic; only `init()` and the
//! `BlockDevice` enum wrapper differ.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};
use crate::sync::Mutex; use spin::Once;
use virtio_drivers::device::blk::VirtIOBlk;
use virtio_drivers::transport::mmio::MmioTransport;
#[cfg(not(target_arch = "loongarch64"))]
use virtio_drivers::transport::mmio::VirtIOHeader;
use virtio_drivers::transport::DeviceType;
#[cfg(not(target_arch = "loongarch64"))]
use virtio_drivers::transport::Transport;
use virtio_drivers::{BufferDirection, Hal, PhysAddr};

use crate::mm::address::KERNEL_PHYS_OFFSET;
use crate::mm::{alloc_frame, PAGE_SIZE};

/// Uncached DMW1 window base on loongarch64. Device MMIO (BAR regions)
/// must be reached through this window so accesses bypass the cache.
#[cfg(target_arch = "loongarch64")]
const DMW1_UNCACHED: usize = 0x8000_0000_0000_0000;

/// HAL backing the `virtio-drivers` crate.
///
/// The frame allocator hands out real physical frames; the kernel reaches
/// them (and the heap) through the direct-map window described by
/// `KERNEL_PHYS_OFFSET` (0 on riscv64 — identity-mapped; the cached DMW0
/// window on loongarch64). Devices always see physical addresses, so the
/// VA<->PA conversions below add/strip that offset. Because the offset is
/// 0 on riscv64 these are exact no-ops there, leaving the RV path
/// byte-for-byte unchanged.
pub struct KernelHal;

unsafe impl Hal for KernelHal {
    fn dma_alloc(
        pages: usize,
        _direction: BufferDirection,
    ) -> (PhysAddr, NonNull<u8>) {
        // Allocate `pages` contiguous frames. The buddy allocator returns
        // 2^k-aligned runs; for our small ring needs the frames come back
        // contiguous. Leak them — the device lives for the whole kernel
        // lifetime.
        let mut first_pa = 0usize;
        for i in 0..pages {
            let frame = alloc_frame().expect("dma_alloc OOM");
            let pa = frame.ppn.0 * PAGE_SIZE;
            if i == 0 {
                first_pa = pa;
            } else if pa != first_pa + i * PAGE_SIZE {
                panic!("dma_alloc: non-contiguous frames");
            }
            core::mem::forget(frame); // intentional leak; persistent ring buffer
        }
        // Device sees the physical address; the kernel writes descriptors
        // through the direct-map window.
        let va = first_pa + KERNEL_PHYS_OFFSET;
        (first_pa, NonNull::new(va as *mut u8).unwrap())
    }

    unsafe fn dma_dealloc(_paddr: PhysAddr, _vaddr: NonNull<u8>, _pages: usize) -> i32 {
        // We leaked the frames; nothing to do.
        0
    }

    unsafe fn mmio_phys_to_virt(paddr: PhysAddr, _size: usize) -> NonNull<u8> {
        // BAR regions read from PCI config space. riscv64 is identity
        // mapped; loongarch64 must use the uncached DMW1 window.
        #[cfg(target_arch = "loongarch64")]
        {
            return NonNull::new((paddr | DMW1_UNCACHED) as *mut u8).unwrap();
        }
        #[cfg(not(target_arch = "loongarch64"))]
        {
            NonNull::new(paddr as *mut u8).unwrap()
        }
    }

    unsafe fn share(buffer: NonNull<[u8]>, _direction: BufferDirection) -> PhysAddr {
        // `buffer` is a kernel pointer (heap or direct-map). Convert back
        // to the physical address the device needs. On riscv64 the offset
        // is 0, so this is the identity the old code used.
        (buffer.as_ptr() as *mut u8 as usize) - KERNEL_PHYS_OFFSET
    }

    unsafe fn unshare(_paddr: PhysAddr, _buffer: NonNull<[u8]>, _direction: BufferDirection) {}
}

/// Transport-erased virtio-blk handle. The PCI variant only exists on
/// loongarch64; riscv64 always uses the MMIO variant.
enum BlkInner {
    Mmio(VirtIOBlk<KernelHal, MmioTransport>),
    #[cfg(target_arch = "loongarch64")]
    Pci(VirtIOBlk<KernelHal, virtio_drivers::transport::pci::PciTransport>),
}

impl BlkInner {
    fn capacity(&mut self) -> u64 {
        match self {
            BlkInner::Mmio(b) => b.capacity(),
            #[cfg(target_arch = "loongarch64")]
            BlkInner::Pci(b) => b.capacity(),
        }
    }
    fn read_blocks(&mut self, sector: usize, buf: &mut [u8]) -> Result<(), ()> {
        match self {
            BlkInner::Mmio(b) => b.read_blocks(sector, buf).map_err(|_| ()),
            #[cfg(target_arch = "loongarch64")]
            BlkInner::Pci(b) => b.read_blocks(sector, buf).map_err(|_| ()),
        }
    }
    fn write_blocks(&mut self, sector: usize, buf: &[u8]) -> Result<(), ()> {
        match self {
            BlkInner::Mmio(b) => b.write_blocks(sector, buf).map_err(|_| ()),
            #[cfg(target_arch = "loongarch64")]
            BlkInner::Pci(b) => b.write_blocks(sector, buf).map_err(|_| ()),
        }
    }
}

/// Sector size in bytes (virtio-blk / ext4-on-512).
const SECTOR_BYTES: usize = 512;
/// Read-cache ceiling: 32768 sectors = 16 MiB of cached blocks. The hot
/// reuse set on an LTP run — the musl loader + libc.so re-read on *every*
/// dynamically-linked exec, plus the ext4 superblock / group-descriptor /
/// inode-table / directory blocks re-read for every lookup — comfortably
/// fits, so cache hits turn what used to be thousands of redundant
/// virtio-blk round-trips into memcpys. That is the single biggest LTP
/// throughput lever (more cases clear the 600s budget).
const CACHE_MAX_SECTORS: usize = 32768;

/// Bounded read cache, sector-granular. Correctness model: the contest
/// test disk is read-mostly (LTP/libctest write their scratch to the
/// tmpfs /tmp and /dev/shm, not to the ext4 image), so on the rare write
/// we simply drop the whole cache — trivially coherent, no per-sector
/// invalidation logic to get subtly wrong. On overflow we also clear and
/// let the hot set re-populate; with a 16 MiB ceiling that's infrequent.
struct BlockCache {
    map: BTreeMap<usize, [u8; SECTOR_BYTES]>,
}

impl BlockCache {
    fn new() -> Self {
        Self { map: BTreeMap::new() }
    }
    fn get(&self, sector: usize, out: &mut [u8]) -> bool {
        if out.len() != SECTOR_BYTES {
            return false;
        }
        if let Some(d) = self.map.get(&sector) {
            out.copy_from_slice(d);
            true
        } else {
            false
        }
    }
    fn put(&mut self, sector: usize, data: &[u8]) {
        if data.len() != SECTOR_BYTES {
            return;
        }
        if self.map.len() >= CACHE_MAX_SECTORS && !self.map.contains_key(&sector) {
            self.map.clear();
        }
        let mut a = [0u8; SECTOR_BYTES];
        a.copy_from_slice(data);
        self.map.insert(sector, a);
    }
    fn clear(&mut self) {
        self.map.clear();
    }
}

pub struct BlockDevice {
    inner: Mutex<BlkInner>,
    cache: Mutex<BlockCache>,
}

/// All block devices found at probe time, in scan order. The contest
/// attaches the read-only on-disk test image on x0 and our writable
/// scratch (disk.img / disk-la.img) on x1; we register BOTH and pin which
/// is which at boot via TEST_IMAGE_IDX / SCRATCH_IDX.
static BLKS: Once<Vec<Arc<BlockDevice>>> = Once::new();
/// Index into BLKS of the read-only test image — the device whose
/// superblock carries an ext magic (0xEF53) at probe time. `get()` returns
/// it, so callers that mount the test image are robust to MMIO/PCI slot
/// order regardless of how many disks are attached.
static TEST_IMAGE_IDX: AtomicUsize = AtomicUsize::new(usize::MAX);
/// Index into BLKS of our writable scratch — the device WITHOUT an ext
/// magic at probe time (zeroed by the Makefile, formatted to ext2 at boot).
/// Pinned BEFORE any format runs, so a freshly written magic can't make it
/// indistinguishable from the ext4 test image (they share magic 0xEF53).
static SCRATCH_IDX: AtomicUsize = AtomicUsize::new(usize::MAX);

/// Probe for virtio-blk devices and register them. On riscv64 this scans
/// the virtio-mmio bank; on loongarch64 it enumerates PCI. Returns the
/// test-image device (for the existing single-disk callers).
pub fn init() -> Option<Arc<BlockDevice>> {
    #[cfg(target_arch = "loongarch64")]
    let devs = probe_pci();
    #[cfg(not(target_arch = "loongarch64"))]
    let devs = probe_mmio();
    if devs.is_empty() {
        return None;
    }
    // The contest pins the read-only test image on x0 (bus.0 = the first slot
    // scanned / first PCI function) and our writable scratch on x1 (bus.1 =
    // the second). Identify by that fixed slot order, which is deterministic
    // regardless of on-disk content — once the scratch is formatted it shares
    // ext4's 0xEF53 magic, so content cannot distinguish the two. Device 0 is
    // always the test image; a second device, if present, is the scratch.
    TEST_IMAGE_IDX.store(0, Ordering::Relaxed);
    if devs.len() >= 2 {
        SCRATCH_IDX.store(1, Ordering::Relaxed);
    }
    BLKS.call_once(|| devs);
    crate::println!(
        "[virtio-blk] {} device(s): test-image=#{} scratch=#{}",
        device_count(),
        TEST_IMAGE_IDX.load(Ordering::Relaxed) as isize,
        SCRATCH_IDX.load(Ordering::Relaxed) as isize,
    );
    get()
}

/// riscv64 virtio-mmio bank scan. QEMU virt's bank lives at
/// 0x1000_1000 .. 0x1000_9000 with 0x1000-spaced slots.
#[cfg(not(target_arch = "loongarch64"))]
fn probe_mmio() -> Vec<Arc<BlockDevice>> {
    const BASES: &[usize] = &[
        0x1000_1000,
        0x1000_2000,
        0x1000_3000,
        0x1000_4000,
        0x1000_5000,
        0x1000_6000,
        0x1000_7000,
        0x1000_8000,
    ];
    let mut out = Vec::new();
    for &base in BASES {
        // Peek DeviceID before opening — MmioTransport::new resets the
        // device on drop, so probing a non-block device with it would
        // disturb whatever else is sitting there.
        if probe_device_id(base) != 2 {
            // 2 = Block.
            continue;
        }
        let Some(header) = (unsafe { NonNull::new(base as *mut VirtIOHeader) }) else {
            continue;
        };
        let transport = match unsafe { MmioTransport::new(header) } {
            Ok(t) => t,
            Err(_) => continue,
        };
        if transport.device_type() != DeviceType::Block {
            continue;
        }
        let blk = match VirtIOBlk::<KernelHal, _>::new(transport) {
            Ok(b) => b,
            Err(e) => {
                crate::println!("[virtio-blk] init failed at {:#x}: {:?}", base, e);
                continue;
            }
        };
        let dev = Arc::new(BlockDevice {
            inner: Mutex::new(BlkInner::Mmio(blk)),
            cache: Mutex::new(BlockCache::new()),
        });
        crate::println!("[virtio-blk] online at {:#x}, capacity={} sectors", base, dev.capacity());
        out.push(dev);
    }
    out
}

/// loongarch64 virtio-pci path: enumerate the ECAM, find the first block
/// device, build a `PciTransport`, and wrap it.
#[cfg(target_arch = "loongarch64")]
fn probe_pci() -> Vec<Arc<BlockDevice>> {
    use virtio_drivers::transport::pci::PciTransport;

    let mut out = Vec::new();
    let Some((mut root, devices)) = crate::drivers::pci::enumerate() else {
        return out;
    };
    for d in devices {
        if d.dev_type != DeviceType::Block {
            continue;
        }
        let transport = match PciTransport::new::<KernelHal>(&mut root, d.func) {
            Ok(t) => t,
            Err(e) => {
                crate::println!("[virtio-blk] PciTransport {} failed: {:?}", d.func, e);
                continue;
            }
        };
        let blk = match VirtIOBlk::<KernelHal, _>::new(transport) {
            Ok(b) => b,
            Err(e) => {
                crate::println!("[virtio-blk] init failed on {}: {:?}", d.func, e);
                continue;
            }
        };
        let dev = Arc::new(BlockDevice {
            inner: Mutex::new(BlkInner::Pci(blk)),
            cache: Mutex::new(BlockCache::new()),
        });
        crate::println!(
            "[virtio-blk] online on PCI {}, capacity={} sectors",
            d.func, dev.capacity()
        );
        out.push(dev);
    }
    out
}

/// The read-only on-disk test image (x0). Robust to slot order: returns the
/// device pinned as the ext-filesystem image at probe time.
pub fn get() -> Option<Arc<BlockDevice>> {
    let devs = BLKS.get()?;
    let idx = TEST_IMAGE_IDX.load(Ordering::Relaxed);
    devs.get(idx).or_else(|| devs.first()).cloned()
}

/// Our writable scratch disk (x1 = disk.img / disk-la.img), if one was
/// attached. This is the device the writable on-disk filesystems live on;
/// the test image (`get()`) is never written.
pub fn get_scratch() -> Option<Arc<BlockDevice>> {
    let devs = BLKS.get()?;
    let idx = SCRATCH_IDX.load(Ordering::Relaxed);
    if idx == usize::MAX {
        return None;
    }
    devs.get(idx).cloned()
}

/// Number of block devices registered at boot.
pub fn device_count() -> usize {
    BLKS.get().map_or(0, |v| v.len())
}

#[cfg(not(target_arch = "loongarch64"))]
fn probe_device_id(base: usize) -> u32 {
    let magic = unsafe { core::ptr::read_volatile(base as *const u32) };
    if magic != 0x7472_6976 {
        return 0;
    }
    unsafe { core::ptr::read_volatile((base + 0x08) as *const u32) }
}

impl BlockDevice {
    pub fn capacity(&self) -> u64 {
        self.inner.lock().capacity()
    }

    pub fn read_block(&self, sector: usize, buf: &mut [u8]) -> Result<(), ()> {
        // Fast path: serve a full sector from the cache without touching the
        // device. The lock guard drops at the end of the `&&` so we never
        // hold the cache lock across the device read below.
        if buf.len() == SECTOR_BYTES && self.cache.lock().get(sector, buf) {
            return Ok(());
        }
        self.inner.lock().read_blocks(sector, buf)?;
        if buf.len() == SECTOR_BYTES {
            self.cache.lock().put(sector, buf);
        }
        Ok(())
    }

    pub fn write_block(&self, sector: usize, buf: &[u8]) -> Result<(), ()> {
        let r = self.inner.lock().write_blocks(sector, buf);
        // Drop the entire read cache on any write: coherent without
        // per-sector bookkeeping (writes to the ext4 image are rare in the
        // contest — scratch goes to tmpfs).
        self.cache.lock().clear();
        r
    }
}
