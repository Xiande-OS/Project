//! riscv64 timer / cycle counter access.
//!
//! The kernel-wide "tick" unit is the RISC-V `time` CSR (mtime on QEMU
//! virt, 10 MHz). Architecture-independent code reads it through
//! `crate::arch::now_ticks()`; this is the riscv64 backing.

/// Raw monotonic tick counter. On QEMU virt this is the 10 MHz mtime.
#[inline]
pub fn now_ticks() -> u64 {
    riscv::register::time::read64()
}

/// Ticks per second of `now_ticks()`. QEMU virt's mtime runs at 10 MHz.
pub const TICKS_PER_SEC: u64 = 10_000_000;
