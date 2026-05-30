//! loongarch64 architecture support.
//!
//! Backend for the `crate::arch` naming contract. Supplies the same set
//! of names the riscv64 backend does (`time`, `console`, `power`, `mm`,
//! `trap`) so the architecture-neutral kernel links unchanged.

use core::arch::global_asm;

pub mod console;
pub mod fpu;
pub mod mm;
pub mod power;
pub mod time;
pub mod trap;

global_asm!(include_str!("boot.S"));
