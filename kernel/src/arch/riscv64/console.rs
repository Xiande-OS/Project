//! riscv64 console byte I/O via the SBI legacy console calls.
//!
//! Architecture-independent code (the `print!` macro, the VFS console
//! file, devfs) routes raw byte I/O through `crate::arch::console_*`;
//! this is the riscv64 backing. A future LoongArch port supplies a
//! 16550 UART implementation behind the same three functions.

/// Write one byte to the console.
#[inline]
pub fn console_put(b: u8) {
    #[allow(deprecated)]
    sbi_rt::legacy::console_putchar(b as usize);
}

/// Read one byte from the console without blocking. Returns `None` when
/// no byte is currently available.
#[inline]
pub fn console_get() -> Option<u8> {
    let c = sbi_rt::legacy::console_getchar();
    if c == usize::MAX || c == !0_usize {
        None
    } else {
        Some(c as u8)
    }
}
