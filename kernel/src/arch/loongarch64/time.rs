//! loongarch64 timer / stable-counter access.
//!
//! LoongArch exposes a constant-frequency stable counter read with the
//! `rdtime.d` instruction (`rd` = counter value, `rj` = counter id, which
//! we discard). On QEMU `virt` it runs at 100 MHz (the DTB advertises a
//! 100 MHz reference clock). Architecture-independent code reads it via
//! `crate::arch::now_ticks()`.

/// Raw monotonic tick counter.
#[inline]
pub fn now_ticks() -> u64 {
    let val: u64;
    let _id: u64;
    unsafe {
        core::arch::asm!("rdtime.d {0}, {1}", out(reg) val, out(reg) _id);
    }
    val
}

/// Ticks per second of `now_ticks()`. QEMU `virt`'s stable counter is
/// 100 MHz; if a real board reports otherwise via CPUCFG this is where
/// it would be derived.
pub const TICKS_PER_SEC: u64 = 100_000_000;
