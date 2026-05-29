//! virtio-blk on top of the `virtio-drivers` crate.
//!
//! Two transports are supported, selected per architecture:
//!   * riscv64 — the virtio-mmio bank scanned at fixed addresses.
//!   * loongarch64 — virtio-pci, discovered via ECAM enumeration
//!     (`crate::drivers::pci`).
//! The block logic itself is transport-agnostic; only `init()` and the
//! `BlockDevice` enum wrapper differ.

use alloc::sync::Arc;
use core::ptr::NonNull;
use spin::{Mutex, Once};
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

pub struct BlockDevice {
    inner: Mutex<BlkInner>,
}

static BLK: Once<Arc<BlockDevice>> = Once::new();

/// Probe for a virtio-blk device and register it. On riscv64 this scans
/// the virtio-mmio bank; on loongarch64 it enumerates PCI.
pub fn init() -> Option<Arc<BlockDevice>> {
    #[cfg(target_arch = "loongarch64")]
    {
        return init_pci();
    }
    #[cfg(not(target_arch = "loongarch64"))]
    {
        init_mmio()
    }
}

/// riscv64 virtio-mmio bank scan. QEMU virt's bank lives at
/// 0x1000_1000 .. 0x1000_9000 with 0x1000-spaced slots.
#[cfg(not(target_arch = "loongarch64"))]
fn init_mmio() -> Option<Arc<BlockDevice>> {
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
    for &base in BASES {
        // Peek DeviceID before opening — MmioTransport::new resets the
        // device on drop, so probing a non-block device with it would
        // disturb whatever else is sitting there.
        if probe_device_id(base) != 2 {
            // 2 = Block.
            continue;
        }
        let header = unsafe { NonNull::new(base as *mut VirtIOHeader)? };
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
        });
        BLK.call_once(|| dev.clone());
        crate::println!("[virtio-blk] online at {:#x}, capacity={} sectors", base, dev.capacity());
        return Some(dev);
    }
    None
}

/// loongarch64 virtio-pci path: enumerate the ECAM, find the first block
/// device, build a `PciTransport`, and wrap it.
#[cfg(target_arch = "loongarch64")]
fn init_pci() -> Option<Arc<BlockDevice>> {
    use virtio_drivers::transport::pci::PciTransport;

    let (mut root, devices) = crate::drivers::pci::enumerate()?;
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
        });
        BLK.call_once(|| dev.clone());
        crate::println!(
            "[virtio-blk] online on PCI {}, capacity={} sectors",
            d.func, dev.capacity()
        );
        return Some(dev);
    }
    None
}

pub fn get() -> Option<Arc<BlockDevice>> {
    BLK.get().cloned()
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
        self.inner.lock().read_blocks(sector, buf)
    }

    pub fn write_block(&self, sector: usize, buf: &[u8]) -> Result<(), ()> {
        self.inner.lock().write_blocks(sector, buf)
    }
}
