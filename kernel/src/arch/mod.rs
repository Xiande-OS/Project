//! Arch dispatcher.
//!
//! Architecture differences are confined to `arch/<arch>/`. The rest of
//! the kernel calls the architecture-neutral functions re-exported here
//! (`now_ticks`, `shutdown`, `console_put`, ...) and never references a
//! specific ISA. Each backend module supplies the same set of names; the
//! `#[cfg(target_arch)]` gate selects which one is linked.
//!
//! This mirrors Linux's `arch/` model: a naming contract that every
//! architecture must satisfy, with no `#[cfg]` leaking into the common
//! layers above.

#[cfg(target_arch = "riscv64")]
pub mod riscv64;

#[cfg(target_arch = "riscv64")]
use riscv64 as imp;

// ---- Time -------------------------------------------------------------

/// Raw monotonic tick counter. Unit is architecture-defined; convert via
/// [`TICKS_PER_SEC`]. On riscv64 QEMU virt this is the 10 MHz mtime CSR.
#[inline]
pub fn now_ticks() -> u64 {
    imp::time::now_ticks()
}

/// Ticks of [`now_ticks`] per wall-clock second.
pub const TICKS_PER_SEC: u64 = imp::time::TICKS_PER_SEC;

// ---- Power ------------------------------------------------------------

/// Power the machine off cleanly (normal completion).
pub fn shutdown() -> ! {
    imp::power::shutdown()
}

/// Power the machine off signalling failure (panic path).
pub fn shutdown_failure() -> ! {
    imp::power::shutdown_failure()
}

// ---- Console ----------------------------------------------------------

/// Write one byte to the platform console.
#[inline]
pub fn console_put(b: u8) {
    imp::console::console_put(b)
}

/// Read one byte from the platform console, or `None` if none is ready.
#[inline]
pub fn console_get() -> Option<u8> {
    imp::console::console_get()
}
