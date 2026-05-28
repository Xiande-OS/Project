//! riscv64 architecture support.
//!
//! M0 keeps this minimal: just the boot entry symbol. Later milestones
//! grow `trap.rs`, `cpu.rs`, etc. — the module is split out now so the
//! shape doesn't have to change later.

use core::arch::global_asm;

global_asm!(include_str!("boot.S"));
