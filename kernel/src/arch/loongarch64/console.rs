//! loongarch64 console byte I/O via the platform 16550 UART.
//!
//! QEMU `virt` exposes an `ns16550a` at physical `0x1fe0_01e0` (confirmed
//! from the machine DTB). The kernel reaches MMIO through the uncached
//! direct-map window DMW1 (`0x8000_0000_0000_0000` + PA). Architecture-
//! independent code routes raw byte I/O through `crate::arch::console_*`;
//! this is the loongarch64 backing, mirroring the riscv64 SBI console.

/// 16550 UART base in the DMW1 (uncached) window.
const UART_BASE: usize = 0x8000_0000_0000_0000 | 0x1fe0_01e0;

/// Register offsets (8-bit registers, no shift on this part).
const RBR_THR: usize = 0; // read: RBR, write: THR
const LSR: usize = 5; // line status

const LSR_THRE: u8 = 1 << 5; // transmit-holding-register empty
const LSR_DR: u8 = 1 << 0; // data ready

#[inline]
fn reg(off: usize) -> *mut u8 {
    (UART_BASE + off) as *mut u8
}

/// Write one byte to the console, busy-waiting for the THR to drain.
#[inline]
pub fn console_put(b: u8) {
    unsafe {
        while core::ptr::read_volatile(reg(LSR)) & LSR_THRE == 0 {}
        core::ptr::write_volatile(reg(RBR_THR), b);
    }
}

/// Read one byte without blocking; `None` when the RX FIFO is empty.
#[inline]
pub fn console_get() -> Option<u8> {
    unsafe {
        if core::ptr::read_volatile(reg(LSR)) & LSR_DR != 0 {
            Some(core::ptr::read_volatile(reg(RBR_THR)))
        } else {
            None
        }
    }
}
