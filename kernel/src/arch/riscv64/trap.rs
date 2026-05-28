//! S-mode trap dispatch (both kernel and user traps).

use core::arch::global_asm;

use riscv::register::{
    scause::{self, Exception, Interrupt, Trap},
    sstatus, stval, stvec,
};

global_asm!(include_str!("trap.S"));

extern "C" {
    fn __trap_entry();
}

/// Layout matches `trap.S`.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct TrapFrame {
    /// x1 (ra), x2 (sp), x3..x31. Index = register number - 1.
    pub x: [usize; 31],
    pub sstatus: usize,
    pub sepc: usize,
    pub _reserved: usize,
}

/// Install the trap vector. Call once during early boot.
pub fn init() {
    unsafe {
        stvec::write(__trap_entry as usize, stvec::TrapMode::Direct);
        // sscratch == 0 means "we're in S-mode now". Trap entry uses this.
        riscv::register::sscratch::write(0);
    }
}

#[no_mangle]
pub extern "C" fn rust_trap_handler(tf: &mut TrapFrame) {
    let cause = scause::read();
    let stval = stval::read();
    let from_user = (tf.sstatus & (1 << 8)) == 0;

    match cause.cause() {
        Trap::Exception(Exception::UserEnvCall) => {
            // Advance past the ecall instruction (4 bytes).
            tf.sepc += 4;
            crate::syscall::dispatch(tf);
        }
        Trap::Exception(Exception::Breakpoint) => {
            tf.sepc += instr_len_at(tf.sepc);
        }
        Trap::Interrupt(Interrupt::SupervisorTimer) => {
            unsafe {
                sbi_rt::set_timer(u64::MAX);
            }
        }
        Trap::Exception(e) if from_user => {
            crate::println!(
                "[user fault] {:?}\n  sepc  = {:#x}\n  stval = {:#x}\n  killing task",
                e, tf.sepc, stval,
            );
            crate::syscall::request_exit(139);
        }
        Trap::Exception(e) => {
            panic!(
                "kernel exception {:?}\n  sepc  = {:#x}\n  stval = {:#x}\n  sstatus = {:#x}",
                e, tf.sepc, stval, tf.sstatus,
            );
        }
        Trap::Interrupt(i) => {
            crate::println!("[trap] unhandled interrupt {:?}; masking", i);
            unsafe {
                sstatus::clear_sie();
            }
        }
    }
}

fn instr_len_at(pc: usize) -> usize {
    let first = unsafe { core::ptr::read_volatile(pc as *const u16) };
    if first & 0b11 == 0b11 {
        4
    } else {
        2
    }
}
