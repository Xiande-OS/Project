#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

mod arch;
#[macro_use]
mod console;
mod mm;
mod sync;

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

    mm::init();
    arch::riscv64::trap::init();
    println!("[ok] heap + frame allocator + trap vector");

    // Smoke-test allocation.
    {
        use alloc::vec::Vec;
        let mut v = Vec::with_capacity(8);
        for i in 0..8 {
            v.push(i * i);
        }
        println!("[ok] heap alloc: {:?}", v);
    }

    // Smoke-test frame allocator.
    {
        let f1 = mm::alloc_frame().expect("frame alloc 1");
        let f2 = mm::alloc_frame().expect("frame alloc 2");
        println!("[ok] frames: {:?} {:?}", f1.ppn, f2.ppn);
        // Dropped here.
    }

    // Smoke-test page table walk: identity-map two pages and translate.
    {
        use mm::page_table::{PageTable, PteFlags};
        use mm::{PhysPageNum, VirtAddr, VirtPageNum};
        let mut pt = PageTable::new();
        pt.map(
            VirtPageNum(0x10000),
            PhysPageNum(0x80000),
            PteFlags::R | PteFlags::W,
        );
        let tr = pt.translate(VirtAddr(0x10000_123)).unwrap();
        println!("[ok] page-table translate -> {:?}", tr);
    }

    // Smoke-test trap path with ebreak; the handler skips past it.
    unsafe {
        core::arch::asm!("ebreak");
    }
    println!("[ok] ebreak round-trip via trap handler");

    println!("M1: trap + mm + heap up. Halting.");
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

#[alloc_error_handler]
fn alloc_error(layout: core::alloc::Layout) -> ! {
    panic!("alloc error: {:?}", layout);
}
