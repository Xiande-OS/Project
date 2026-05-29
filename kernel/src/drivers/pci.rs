//! Minimal PCI ECAM bring-up for the loongarch64 `virt` machine.
//!
//! On loongarch64 the QEMU `virt` board exposes virtio devices over
//! virtio-pci (a `pci-host-ecam-generic` bridge), not the RISC-V
//! virtio-mmio bank. This module enumerates the ECAM, assigns BARs out of
//! the board's 32-bit MMIO window, enables memory decoding + bus
//! mastering, and hands back a `PciRoot` plus the virtio device functions
//! it found so the higher-level drivers can build a `PciTransport`.
//!
//! The whole module is loongarch64-only; the riscv64 build never compiles
//! or references it.

use spin::Once;
use virtio_drivers::transport::pci::bus::{
    BarInfo, Cam, Command, DeviceFunction, MemoryBarType, PciRoot,
};
use virtio_drivers::transport::pci::virtio_device_type;
use virtio_drivers::transport::DeviceType;

/// Physical base of the ECAM region (`pcie@20000000` `reg` in the DTB).
const ECAM_PHYS_BASE: usize = 0x2000_0000;
/// Uncached DMW1 window base. Reaching MMIO/config space through this
/// window keeps device accesses uncached, as required.
const DMW1_UNCACHED: usize = 0x8000_0000_0000_0000;

/// 32-bit MMIO window the host bridge forwards to PCI (`ranges` entry with
/// space code 0x2000000). PCI bus addresses are identity-mapped to CPU
/// physical addresses across this window, so a BAR programmed with
/// physical `X` is reachable by the CPU at `X | DMW1_UNCACHED`.
const MMIO32_BASE: u32 = 0x4000_0000;
const MMIO32_SIZE: u32 = 0x4000_0000;

/// A virtio device discovered during enumeration, with its BARs already
/// assigned and memory decoding enabled.
#[derive(Copy, Clone)]
pub struct PciVirtioDevice {
    pub func: DeviceFunction,
    pub dev_type: DeviceType,
}

/// The set of virtio functions found on the bus. Populated exactly once;
/// BAR assignment + command-register setup happen during that single scan.
static DEVICES: Once<alloc::vec::Vec<PciVirtioDevice>> = Once::new();

/// Returns a fresh `PciRoot` wrapping the ECAM through the uncached DMW1
/// window. `PciRoot` only holds the base pointer + CAM kind (no device
/// state), so handing out a new one per call is cheap and safe.
fn root() -> PciRoot {
    // SAFETY: the ECAM physical region is mapped (for the whole address
    // space) through the uncached DMW1 window set up in boot.S. The base
    // is 4 KiB aligned, satisfying `PciRoot::new`'s alignment requirement,
    // and the region is `'static` (firmware/SoC fixed).
    let ecam_va = (ECAM_PHYS_BASE | DMW1_UNCACHED) as *mut u8;
    unsafe { PciRoot::new(ecam_va, Cam::Ecam) }
}

/// Enumerate bus 0, assign BARs and enable decoding for every virtio
/// device (only on the first call), then return a configured `PciRoot`
/// together with the virtio functions found. Returns `None` only if no
/// virtio device is present.
pub fn enumerate() -> Option<(PciRoot, alloc::vec::Vec<PciVirtioDevice>)> {
    let devices = DEVICES.call_once(scan);
    let mut root = root();
    // Ensure decoding + bus-mastering are enabled (idempotent — cheap to
    // re-assert if a second driver enumerates after the first).
    for d in devices.iter() {
        let (_status, command) = root.get_status_command(d.func);
        root.set_command(d.func, command | Command::MEMORY_SPACE | Command::BUS_MASTER);
    }
    if devices.is_empty() {
        return None;
    }
    Some((root, devices.clone()))
}

/// One-time bus scan: discover virtio functions and assign their BARs.
fn scan() -> alloc::vec::Vec<PciVirtioDevice> {
    let mut root = root();

    // Bump allocator over the 32-bit MMIO window for BAR assignment.
    let mut next_mmio: u32 = MMIO32_BASE;
    let mmio_end: u32 = MMIO32_BASE + MMIO32_SIZE;

    let mut out = alloc::vec::Vec::new();

    // The board only populates bus 0 (no PCI-PCI bridges on `virt`), so a
    // single-bus scan suffices.
    let devices: alloc::vec::Vec<_> = root.enumerate_bus(0).collect();
    for (func, info) in devices {
        let dev_type = match virtio_device_type(&info) {
            Some(t) => t,
            None => continue,
        };

        assign_bars(&mut root, func, &mut next_mmio, mmio_end);

        crate::println!(
            "[pci] {} virtio {:?} (id {:04x}:{:04x})",
            func, dev_type, info.vendor_id, info.device_id
        );
        out.push(PciVirtioDevice { func, dev_type });
    }
    out
}

/// Walk a device function's six BAR slots and assign a physical address
/// (out of the 32-bit MMIO window) to every memory BAR that needs one.
/// I/O BARs are left untouched — virtio-pci uses memory BARs for the
/// capability regions we care about.
fn assign_bars(
    root: &mut PciRoot,
    func: DeviceFunction,
    next_mmio: &mut u32,
    mmio_end: u32,
) {
    let mut bar_index = 0u8;
    while bar_index < 6 {
        let info = match root.bar_info(func, bar_index) {
            Ok(i) => i,
            Err(_) => {
                bar_index += 1;
                continue;
            }
        };
        let takes_two = info.takes_two_entries();
        match info {
            BarInfo::Memory {
                address_type, size, ..
            } => {
                if size > 0 {
                    // PCI BARs are naturally aligned; align the cursor up
                    // to the BAR size before assigning.
                    let aligned = align_up(*next_mmio, size);
                    if aligned.checked_add(size).map_or(true, |e| e > mmio_end) {
                        crate::println!(
                            "[pci] {} BAR{} ({} bytes) does not fit MMIO window",
                            func, bar_index, size
                        );
                    } else {
                        match address_type {
                            MemoryBarType::Width64 => {
                                // High dword is 0: the window lives below 4 GiB.
                                root.set_bar_64(func, bar_index, aligned as u64);
                            }
                            _ => {
                                root.set_bar_32(func, bar_index, aligned);
                            }
                        }
                        *next_mmio = aligned + size;
                    }
                }
            }
            BarInfo::IO { .. } => {}
        }
        bar_index += if takes_two { 2 } else { 1 };
    }
}

#[inline]
fn align_up(value: u32, align: u32) -> u32 {
    debug_assert!(align.is_power_of_two());
    (value + align - 1) & !(align - 1)
}
