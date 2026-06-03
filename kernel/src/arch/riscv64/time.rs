//! riscv64 timer / cycle counter access.
//!
//! The kernel-wide "tick" unit is a *normalised* 10 MHz clock. The raw RISC-V
//! `time` CSR (mtime) runs at whatever rate the platform advertises in the
//! device tree's `timebase-frequency` — 10 MHz on QEMU virt, but other values
//! on different QEMU builds / real boards. Every timeout, `clock_gettime`
//! conversion, and the 8 s in-kernel watchdog is written against 10 MHz, so we
//! rescale the raw counter to it. Without this, a machine whose mtime ran at,
//! say, 100 MHz made the watchdog's "8 s" elapse in 0.8 s of real time and it
//! SIGKILLed perfectly healthy syscalls (init, the shell, every exec child) —
//! the contest-machine execl01 watchdog cascade that never reproduced on the
//! 10 MHz CI QEMU.

use core::sync::atomic::{AtomicU64, Ordering};

/// The tick rate the rest of the kernel assumes `now_ticks()` runs at.
const NORMALISED_HZ: u64 = 10_000_000;

/// The raw `time` CSR frequency, learned from the DTB at boot. Defaults to the
/// normalised rate so that until `set_raw_hz` runs (very early, in `mm::init`)
/// the counter passes through unscaled.
static RAW_HZ: AtomicU64 = AtomicU64::new(NORMALISED_HZ);

/// Monotonic tick counter, rescaled to a fixed 10 MHz so all time math is
/// platform-independent. The common case (raw rate already 10 MHz) takes the
/// identity fast path; otherwise a 128-bit mul/div avoids overflow and keeps
/// full precision.
#[inline]
pub fn now_ticks() -> u64 {
    let raw = riscv::register::time::read64();
    let hz = RAW_HZ.load(Ordering::Relaxed);
    if hz == NORMALISED_HZ {
        raw
    } else {
        ((raw as u128 * NORMALISED_HZ as u128) / hz as u128) as u64
    }
}

/// Ticks per second of `now_ticks()`. Fixed by construction — we rescale the
/// raw counter to this rate.
pub const TICKS_PER_SEC: u64 = NORMALISED_HZ;

/// Record the raw `time` CSR frequency read from the device tree's
/// `timebase-frequency`. Called once at boot before any task runs, so the
/// one-time discontinuity it introduces (raw → rescaled) is unobservable.
pub fn set_raw_hz(hz: u64) {
    if hz != 0 {
        RAW_HZ.store(hz, Ordering::Relaxed);
    }
}

/// The raw mtime frequency we're rescaling from (for the boot diagnostic).
pub fn raw_hz() -> u64 {
    RAW_HZ.load(Ordering::Relaxed)
}
