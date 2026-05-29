//! riscv64 architecture support.

use core::arch::global_asm;

pub mod console;
pub mod power;
pub mod time;
pub mod trap;

global_asm!(include_str!("boot.S"));
