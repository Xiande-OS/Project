#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

mod arch;
#[macro_use]
mod console;
mod loader;
mod mm;
mod sync;
mod syscall;
mod task;

use core::panic::PanicInfo;

#[repr(C, align(8))]
struct AlignedElf<T: ?Sized>(T);

static HELLO_ALIGNED: &AlignedElf<[u8]> =
    &AlignedElf(*include_bytes!(env!("HELLO_ELF_PATH")));
static MUSL_HELLO_ALIGNED: &AlignedElf<[u8]> =
    &AlignedElf(*include_bytes!(env!("MUSL_HELLO_ELF_PATH")));

fn hello_elf() -> &'static [u8] {
    &HELLO_ALIGNED.0
}
fn musl_hello_elf() -> &'static [u8] {
    &MUSL_HELLO_ALIGNED.0
}

#[no_mangle]
pub extern "C" fn kmain(hartid: usize, dtb_pa: usize) -> ! {
    println!("xiande-os booting on hart {}", hartid);
    println!("  dtb @ {:#x}", dtb_pa);

    mm::init();
    arch::riscv64::trap::init();
    println!("[ok] heap + frame allocator + trap vector");

    // Pick which user binary to run.  Bare-metal `hello` is the M3 smoke
    // test; switch to musl_hello for M4.
    let (name, elf) = if cfg!(feature = "bare_hello") {
        ("hello", hello_elf())
    } else {
        ("musl_hello", musl_hello_elf())
    };
    println!("[user] loading {} ({} bytes)", name, elf.len());
    let task = task::create_task_from_elf(elf, &[name], &["PATH=/bin", "HOME=/"]);
    println!("[user] task installed, entering user mode...");
    task::run_user_loop(&task);
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
