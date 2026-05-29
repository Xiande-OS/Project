//! Device drivers (M7).

/// PCI ECAM enumeration for the loongarch64 `virt` board (virtio-pci).
/// riscv64 uses the virtio-mmio bank and never compiles this.
#[cfg(target_arch = "loongarch64")]
pub mod pci;
pub mod virtio_blk;
pub mod virtio_net;
