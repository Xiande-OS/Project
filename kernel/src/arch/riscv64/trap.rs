//! S-mode trap dispatch.
//!
//! M1 handles kernel-mode exceptions (panic with details) and ignores
//! the few interrupts we won't get yet. M3 will branch to syscall /
//! user-fault paths.

use core::arch::global_asm;

use riscv::register::{
    scause::{self, Exception, Interrupt, Trap},
    sstatus, stval, stvec,
};

global_asm!(include_str!("trap.S"));

extern "C" {
    fn __trap_entry();
}

/// Layout matches `trap.S` above.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct TrapFrame {
    /// x1 (ra), x2 (sp), x3..x31. Index = register number - 1.
    pub x: [usize; 31],
    pub sstatus: usize,
    pub sepc: usize,
    pub _reserved: usize,
}

/// Install the trap vector. Call once during early boot, before any
/// instruction that might fault.
pub fn init() {
    unsafe {
        stvec::write(__trap_entry as usize, stvec::TrapMode::Direct);
    }
}

#[no_mangle]
pub extern "C" fn rust_trap_handler(tf: &mut TrapFrame) {
    let cause = scause::read();
    let stval = stval::read();
    match cause.cause() {
        Trap::Exception(Exception::Breakpoint) => {
            // Skip the `ebreak` instruction (2 or 4 bytes).
            tf.sepc += instr_len_at(tf.sepc);
        }
        Trap::Interrupt(Interrupt::SupervisorTimer) => {
            // Disarm; M1 has no scheduler yet.
            unsafe {
                sbi_rt::set_timer(u64::MAX);
            }
        }
        Trap::Exception(e) => {
            panic!(
                "kernel exception {:?}\n  sepc  = {:#x}\n  stval = {:#x}\n  sstatus = {:#x}\n  ra = {:#x}",
                e, tf.sepc, stval, tf.sstatus, tf.x[0],
            );
        }
        Trap::Interrupt(i) => {
            crate::println!("[trap] unhandled interrupt {:?}; masking", i);
            // For safety, disable interrupts in sstatus.
            unsafe {
                sstatus::clear_sie();
            }
        }
    }
}

/// Length of the instruction at `pc` in bytes (2 for compressed, 4 otherwise).
fn instr_len_at(pc: usize) -> usize {
    let first = unsafe { core::ptr::read_volatile(pc as *const u16) };
    if first & 0b11 == 0b11 {
        4
    } else {
        2
    }
}
