//! riscv64 power control (shutdown / reset) via SBI.

/// Shut the machine down cleanly. The contest evaluator detects the QEMU
/// process exit to score the run, so this must actually power off.
pub fn shutdown() -> ! {
    sbi_rt::system_reset(sbi_rt::Shutdown, sbi_rt::NoReason);
    loop {
        unsafe { core::arch::asm!("wfi") };
    }
}

/// Shut down signalling a failure (used from the panic handler).
pub fn shutdown_failure() -> ! {
    sbi_rt::system_reset(sbi_rt::Shutdown, sbi_rt::SystemFailure);
    loop {
        unsafe { core::arch::asm!("wfi") };
    }
}
