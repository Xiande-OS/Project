//! loongarch64 power control (shutdown / reset).
//!
//! QEMU `virt` wires an ACPI GED whose sleep-control register lives at
//! physical `0x100e_001c` (the GED is ACPI-only, not described in the
//! DTB). Writing `SLP_EN | (S5 << 2)` == `0x34` powers the machine off,
//! which the contest evaluator detects as the QEMU process exiting. The
//! register is reached through the DMW1 uncached window.

const GED_SLEEP_CTL: usize = 0x8000_0000_0000_0000 | 0x100e_001c;
/// ACPI S5 (soft-off): SLP_EN (bit 5) | (slp_typ=5 << 2).
const S5_POWEROFF: u8 = (1 << 5) | (5 << 2);

fn poweroff() -> ! {
    unsafe {
        core::ptr::write_volatile(GED_SLEEP_CTL as *mut u8, S5_POWEROFF);
    }
    loop {
        unsafe { core::arch::asm!("idle 0") };
    }
}

/// Shut the machine down cleanly (normal completion).
pub fn shutdown() -> ! {
    poweroff()
}

/// Shut down signalling failure (used from the panic handler). QEMU has
/// no separate failure code path, so this is the same soft-off.
pub fn shutdown_failure() -> ! {
    poweroff()
}
