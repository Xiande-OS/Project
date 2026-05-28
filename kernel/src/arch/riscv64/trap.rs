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
                "[user fault] {:?}\n  sepc  = {:#x}\n  stval = {:#x}\n  sstatus = {:#x}",
                e, tf.sepc, stval, tf.sstatus
            );
            for i in 0..31 {
                let reg = i + 1;
                let name = match reg {
                    1 => "ra ", 2 => "sp ", 3 => "gp ", 4 => "tp ",
                    5 => "t0 ", 6 => "t1 ", 7 => "t2 ",
                    8 => "s0 ", 9 => "s1 ",
                    10 => "a0 ", 11 => "a1 ", 12 => "a2 ", 13 => "a3 ",
                    14 => "a4 ", 15 => "a5 ", 16 => "a6 ", 17 => "a7 ",
                    18 => "s2 ", 19 => "s3 ", 20 => "s4 ", 21 => "s5 ",
                    22 => "s6 ", 23 => "s7 ", 24 => "s8 ", 25 => "s9 ",
                    26 => "s10", 27 => "s11",
                    28 => "t3 ", 29 => "t4 ", 30 => "t5 ", 31 => "t6 ",
                    _ => "???",
                };
                crate::println!("  x{:2}({}) = {:#018x}", reg, name, tf.x[i]);
            }
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
