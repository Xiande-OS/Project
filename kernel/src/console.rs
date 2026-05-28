//! SBI console output.
//!
//! M0 uses the SBI legacy `console_putchar` for simplicity. Once we have
//! a 16550 driver (M1+) we'll route through that instead.

use core::fmt::{self, Write};

struct SbiConsole;

impl Write for SbiConsole {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            #[allow(deprecated)]
            sbi_rt::legacy::console_putchar(b as usize);
        }
        Ok(())
    }
}

pub fn _print(args: fmt::Arguments<'_>) {
    let _ = SbiConsole.write_fmt(args);
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
