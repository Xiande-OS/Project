#![no_std]
#![no_main]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_WRITE: usize = 64;
const SYS_EXIT_GROUP: usize = 94;

#[inline(always)]
unsafe fn syscall3(nr: usize, a0: usize, a1: usize, a2: usize) -> isize {
    let mut ret: isize;
    asm!(
        "ecall",
        in("a7") nr,
        inlateout("a0") a0 => ret,
        in("a1") a1,
        in("a2") a2,
        options(nostack),
    );
    ret
}

#[inline(always)]
unsafe fn write_str(fd: usize, s: &str) -> isize {
    syscall3(SYS_WRITE, fd, s.as_ptr() as usize, s.len())
}

#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    let _ = write_str(1, "hello from xiande-os user mode (M3)\n");
    let _ = write_str(1, "exit_group(0) ->\n");
    syscall3(SYS_EXIT_GROUP, 0, 0, 0);
    loop {
        asm!("wfi");
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        unsafe { asm!("wfi") };
    }
}
