//! Kernel console output.
//!
//! Byte I/O is delegated to the active architecture backend
//! (`crate::arch::console_put`); on riscv64 that's the SBI legacy
//! console, on LoongArch a 16550 UART.

use core::fmt::{self, Write};

struct Console;

impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            crate::arch::console_put(b);
        }
        Ok(())
    }
}

pub fn _print(args: fmt::Arguments<'_>) {
    let _ = Console.write_fmt(args);
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::console::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}
