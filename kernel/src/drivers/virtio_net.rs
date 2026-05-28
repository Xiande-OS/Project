//! virtio-net (MMIO transport) on top of the `virtio-drivers` crate.
//!
//! Mirrors the structure of `virtio_blk.rs`. The smoltcp `Device` adapter
//! lives in `crate::net` and uses `transmit()` / `receive()` here.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ptr::NonNull;
use spin::{Mutex, Once};
use virtio_drivers::device::net::VirtIONet;
use virtio_drivers::transport::mmio::{MmioTransport, VirtIOHeader};
use virtio_drivers::transport::{DeviceType, Transport};

use crate::drivers::virtio_blk::KernelHal;

/// Queue depth + maximum frame buffer used by the underlying VirtIONet.
/// QEMU's virtio-net comfortably handles full Ethernet MTU (1514 bytes).
const QUEUE_SIZE: usize = 16;
const BUF_LEN: usize = 2048;

pub struct NetDev {
    inner: Mutex<VirtIONet<KernelHal, MmioTransport, QUEUE_SIZE>>,
    mac: [u8; 6],
}

static NET: Once<Arc<NetDev>> = Once::new();

/// Scan the virtio-mmio bank for a Network device. Returns the wrapper or
/// None if no virtio-net is present.
pub fn init() -> Option<Arc<NetDev>> {
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
            inner: Mutex::new(net),
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

pub fn get() -> Option<Arc<NetDev>> {
    NET.get().cloned()
}

impl NetDev {
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Transmit a raw Ethernet frame. Synchronously blocks until the
    /// device acknowledges (the `virtio-drivers` `send()` polls the used
    /// ring inline).
    pub fn transmit(&self, frame: &[u8]) -> Result<(), ()> {
        let mut net = self.inner.lock();
        let mut buf = net.new_tx_buffer(frame.len());
        buf.packet_mut().copy_from_slice(frame);
        net.send(buf).map_err(|_| ())
    }

    /// Pop one Ethernet frame off the receive queue if available. Returns
    /// `None` if the queue is empty.
    pub fn receive(&self) -> Option<Vec<u8>> {
        let mut net = self.inner.lock();
        if !net.can_recv() {
            return None;
        }
        let rx_buf = match net.receive() {
            Ok(b) => b,
            Err(_) => return None,
        };
        let packet = rx_buf.packet().to_vec();
        let _ = net.recycle_rx_buffer(rx_buf);
        Some(packet)
    }

    /// True iff the device has a frame ready to dequeue.
    pub fn can_recv(&self) -> bool {
        self.inner.lock().can_recv()
    }
}
