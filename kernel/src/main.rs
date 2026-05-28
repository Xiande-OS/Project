#![no_std]
#![no_main]

mod arch;
#[macro_use]
mod console;

use core::panic::PanicInfo;

/// Kernel entry, called from `boot.S` after the boot stack is set up
/// and `.bss` is zeroed.
///
/// # Safety
/// Invoked exactly once by the boot trampoline with the OpenSBI handoff
/// registers preserved (a0 = hartid, a1 = DTB physical address).
#[no_mangle]
pub extern "C" fn kmain(hartid: usize, dtb_pa: usize) -> ! {
    println!("xiande-os booting on hart {}", hartid);
    println!("  dtb @ {:#x}", dtb_pa);
    println!("M0: SBI console up. Halting.");

    shutdown_success()
}

fn shutdown_success() -> ! {
    sbi_rt::system_reset(sbi_rt::Shutdown, sbi_rt::NoReason);
    loop {
        unsafe { core::arch::asm!("wfi") };
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("[kernel panic] {}", info);
    sbi_rt::system_reset(sbi_rt::Shutdown, sbi_rt::SystemFailure);
    loop {
        unsafe { core::arch::asm!("wfi") };
    }
}
