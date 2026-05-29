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

#[cfg(target_arch = "loongarch64")]
pub mod loongarch64;

#[cfg(target_arch = "loongarch64")]
use loongarch64 as imp;

/// The architecture's trap frame. Common code (`signal`, `syscall`,
/// `task`) names it through this re-export and only ever touches it via
/// its inherent methods, so it is portable across backends.
pub use imp::trap::TrapFrame;

// ---- Traps ------------------------------------------------------------

/// Install the trap vector(s) and start the preemption timer. Call once
/// during early boot, after the console is up.
pub fn trap_init() {
    imp::trap::init();
}

// ---- MMU --------------------------------------------------------------

/// Make the address space identified by `token` (the value returned by
/// `mm::PageTable::satp()`) the active translation and flush stale TLB
/// entries.
#[inline]
pub fn activate_page_table(token: usize) {
    imp::mm::activate(token);
}

/// Invalidate the local-hart TLB entry covering virtual address `va`.
#[inline]
pub fn flush_tlb_va(va: usize) {
    imp::mm::flush_va(va);
}

/// Flush the entire local-hart TLB.
#[inline]
pub fn flush_tlb_all() {
    imp::mm::flush_all();
}

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
