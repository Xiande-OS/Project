//! virtio-net on top of the `virtio-drivers` crate.
//!
//! Mirrors the structure of `virtio_blk.rs`: the virtio-mmio transport on
//! riscv64, virtio-pci on loongarch64. The smoltcp `Device` adapter lives
//! in `crate::net` and uses `transmit()` / `receive()` here.

use alloc::sync::Arc;
use alloc::vec::Vec;
#[cfg(not(target_arch = "loongarch64"))]
use core::ptr::NonNull;
use crate::sync::Mutex; use spin::Once;
use virtio_drivers::device::net::VirtIONet;
#[cfg(not(target_arch = "loongarch64"))]
use virtio_drivers::transport::mmio::{MmioTransport, VirtIOHeader};
#[cfg(not(target_arch = "loongarch64"))]
use virtio_drivers::transport::{DeviceType, Transport};

use crate::drivers::virtio_blk::KernelHal;

/// Queue depth + maximum frame buffer used by the underlying VirtIONet.
/// QEMU's virtio-net comfortably handles full Ethernet MTU (1514 bytes).
const QUEUE_SIZE: usize = 16;
const BUF_LEN: usize = 2048;

/// Transport-erased virtio-net handle. The PCI variant only exists on
/// loongarch64; riscv64 always uses the MMIO variant.
enum NetInner {
    #[cfg(not(target_arch = "loongarch64"))]
    Mmio(VirtIONet<KernelHal, MmioTransport, QUEUE_SIZE>),
    #[cfg(target_arch = "loongarch64")]
    Pci(VirtIONet<KernelHal, virtio_drivers::transport::pci::PciTransport, QUEUE_SIZE>),
}

pub struct NetDev {
    inner: Mutex<NetInner>,
    mac: [u8; 6],
}

static NET: Once<Arc<NetDev>> = Once::new();

/// Probe for a virtio-net device and register it. On riscv64 this scans
/// the virtio-mmio bank; on loongarch64 it enumerates PCI.
pub fn init() -> Option<Arc<NetDev>> {
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
fn init_mmio() -> Option<Arc<NetDev>> {
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
        // Peek the virtio-mmio header's DeviceID *without* constructing
        // a transport. MmioTransport::new resets the device on drop,
        // so probing every base would wipe state on the virtio-blk
        // we already initialised.
        if probe_device_id(base) != 1 {
            // 1 = Network. Everything else (block=2, console=3, ...)
            // belongs to someone else.
            continue;
        }
        let header = unsafe { NonNull::new(base as *mut VirtIOHeader)? };
        let transport = match unsafe { MmioTransport::new(header) } {
            Ok(t) => t,
            Err(_) => continue,
        };
        if transport.device_type() != DeviceType::Network {
            continue;
        }
        let net = match VirtIONet::<KernelHal, _, QUEUE_SIZE>::new(transport, BUF_LEN) {
            Ok(n) => n,
            Err(e) => {
                crate::println!("[virtio-net] init failed at {:#x}: {:?}", base, e);
                continue;
            }
        };
        let mac = net.mac_address();
        let dev = Arc::new(NetDev {
            inner: Mutex::new(NetInner::Mmio(net)),
            mac,
        });
        NET.call_once(|| dev.clone());
        crate::println!(
            "[virtio-net] online at {:#x}, mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            base, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
        );
        return Some(dev);
    }
    None
}

/// loongarch64 virtio-pci path: enumerate the ECAM, find the first network
/// device, build a `PciTransport`, and wrap it.
#[cfg(target_arch = "loongarch64")]
fn init_pci() -> Option<Arc<NetDev>> {
    use virtio_drivers::transport::pci::PciTransport;
    use virtio_drivers::transport::DeviceType;

    let (mut root, devices) = crate::drivers::pci::enumerate()?;
    for d in devices {
        if d.dev_type != DeviceType::Network {
            continue;
        }
        let transport = match PciTransport::new::<KernelHal>(&mut root, d.func) {
            Ok(t) => t,
            Err(e) => {
                crate::println!("[virtio-net] PciTransport {} failed: {:?}", d.func, e);
                continue;
            }
        };
        let net = match VirtIONet::<KernelHal, _, QUEUE_SIZE>::new(transport, BUF_LEN) {
            Ok(n) => n,
            Err(e) => {
                crate::println!("[virtio-net] init failed on {}: {:?}", d.func, e);
                continue;
            }
        };
        let mac = net.mac_address();
        let dev = Arc::new(NetDev {
            inner: Mutex::new(NetInner::Pci(net)),
            mac,
        });
        NET.call_once(|| dev.clone());
        crate::println!(
            "[virtio-net] online on PCI {}, mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            d.func, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
        );
        return Some(dev);
    }
    None
}

pub fn get() -> Option<Arc<NetDev>> {
    NET.get().cloned()
}

/// Read the virtio-mmio header's DeviceID field at `base + 0x08` without
/// constructing an MmioTransport (which would reset the device on
/// drop). Returns 0 if the magic doesn't match.
#[cfg(not(target_arch = "loongarch64"))]
fn probe_device_id(base: usize) -> u32 {
    let magic = unsafe { core::ptr::read_volatile(base as *const u32) };
    if magic != 0x7472_6976 {
        // "virt"
        return 0;
    }
    unsafe { core::ptr::read_volatile((base + 0x08) as *const u32) }
}

impl NetInner {
    fn can_recv(&mut self) -> bool {
        match self {
            #[cfg(not(target_arch = "loongarch64"))]
            NetInner::Mmio(n) => n.can_recv(),
            #[cfg(target_arch = "loongarch64")]
            NetInner::Pci(n) => n.can_recv(),
        }
    }

    fn transmit(&mut self, frame: &[u8]) -> Result<(), ()> {
        match self {
            #[cfg(not(target_arch = "loongarch64"))]
            NetInner::Mmio(net) => {
                let mut buf = net.new_tx_buffer(frame.len());
                buf.packet_mut().copy_from_slice(frame);
                net.send(buf).map_err(|_| ())
            }
            #[cfg(target_arch = "loongarch64")]
            NetInner::Pci(net) => {
                let mut buf = net.new_tx_buffer(frame.len());
                buf.packet_mut().copy_from_slice(frame);
                net.send(buf).map_err(|_| ())
            }
        }
    }

    fn receive(&mut self) -> Option<Vec<u8>> {
        match self {
            #[cfg(not(target_arch = "loongarch64"))]
            NetInner::Mmio(net) => {
                if !net.can_recv() {
                    return None;
                }
                let rx_buf = net.receive().ok()?;
                let packet = rx_buf.packet().to_vec();
                let _ = net.recycle_rx_buffer(rx_buf);
                Some(packet)
            }
            #[cfg(target_arch = "loongarch64")]
            NetInner::Pci(net) => {
                if !net.can_recv() {
                    return None;
                }
                let rx_buf = net.receive().ok()?;
                let packet = rx_buf.packet().to_vec();
                let _ = net.recycle_rx_buffer(rx_buf);
                Some(packet)
            }
        }
    }
}

impl NetDev {
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Transmit a raw Ethernet frame. Synchronously blocks until the
    /// device acknowledges (the `virtio-drivers` `send()` polls the used
    /// ring inline).
    pub fn transmit(&self, frame: &[u8]) -> Result<(), ()> {
        self.inner.lock().transmit(frame)
    }

    /// Pop one Ethernet frame off the receive queue if available. Returns
    /// `None` if the queue is empty.
    pub fn receive(&self) -> Option<Vec<u8>> {
        self.inner.lock().receive()
    }

    /// True iff the device has a frame ready to dequeue.
    pub fn can_recv(&self) -> bool {
        self.inner.lock().can_recv()
    }
}
