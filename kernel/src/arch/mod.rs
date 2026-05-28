//! Arch dispatcher.
//!
//! M0 targets riscv64gc only. The cfg gate keeps the door open for
//! other architectures later (e.g. an aarch64 port for QEMU `virt`).

#[cfg(target_arch = "riscv64")]
pub mod riscv64;
