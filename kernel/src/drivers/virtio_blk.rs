//! virtio-blk (MMIO transport) on top of the `virtio-drivers` crate.

use alloc::sync::Arc;
use core::ptr::NonNull;
use spin::{Mutex, Once};
use virtio_drivers::device::blk::VirtIOBlk;
use virtio_drivers::transport::mmio::{MmioTransport, VirtIOHeader};
use virtio_drivers::transport::{DeviceType, Transport};
use virtio_drivers::{BufferDirection, Hal, PhysAddr};

use crate::mm::{alloc_frame, FrameTracker, PAGE_SIZE};

/// Hal impl. We don't have a real DMA pool — the kernel heap + frame
/// allocator give us identity-mapped pages, which the device can DMA
/// from/to since our identity map gives PA==VA.
pub struct KernelHal;

unsafe impl Hal for KernelHal {
    fn dma_alloc(
        pages: usize,
        _direction: BufferDirection,
    ) -> (PhysAddr, NonNull<u8>) {
        // Allocate consecutive frames. The frame allocator's buddy
        // gives 2^k-aligned runs.
        let order = pages.next_power_of_two().trailing_zeros() as usize;
        let _ = order;

        // Use a Vec of FrameTrackers — for our small needs (rings),
        // one or two pages are sufficient. Persist trackers in a Once.
        // For simplicity here, just leak frames (the device lives for
        // the whole kernel lifetime).
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
        let va = first_pa; // identity-mapped
        (first_pa, NonNull::new(va as *mut u8).unwrap())
    }

    unsafe fn dma_dealloc(_paddr: PhysAddr, _vaddr: NonNull<u8>, _pages: usize) -> i32 {
        // We leaked the frames; nothing to do.
        0
    }

    unsafe fn mmio_phys_to_virt(paddr: PhysAddr, _size: usize) -> NonNull<u8> {
        NonNull::new(paddr as *mut u8).unwrap()
    }

    unsafe fn share(buffer: NonNull<[u8]>, _direction: BufferDirection) -> PhysAddr {
        buffer.as_ptr() as *mut u8 as usize
    }

    unsafe fn unshare(_paddr: PhysAddr, _buffer: NonNull<[u8]>, _direction: BufferDirection) {}
}

pub struct BlockDevice {
    inner: Mutex<VirtIOBlk<KernelHal, MmioTransport>>,
}

static BLK: Once<Arc<BlockDevice>> = Once::new();

/// QEMU virt's virtio-mmio bank lives at 0x1000_1000 .. 0x1000_9000 with
/// 0x1000-spaced slots. We scan them and grab the first block device.
pub fn init() -> Option<Arc<BlockDevice>> {
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
            inner: Mutex::new(blk),
        });
        BLK.call_once(|| dev.clone());
        crate::println!("[virtio-blk] online at {:#x}, capacity={} sectors", base, dev.capacity());
        return Some(dev);
    }
    None
}

pub fn get() -> Option<Arc<BlockDevice>> {
    BLK.get().cloned()
}

impl BlockDevice {
    pub fn capacity(&self) -> u64 {
        self.inner.lock().capacity()
    }

    pub fn read_block(&self, sector: usize, buf: &mut [u8]) -> Result<(), ()> {
        let mut blk = self.inner.lock();
        blk.read_blocks(sector, buf).map_err(|_| ())
    }

    pub fn write_block(&self, sector: usize, buf: &[u8]) -> Result<(), ()> {
        let mut blk = self.inner.lock();
        blk.write_blocks(sector, buf).map_err(|_| ())
    }
}
