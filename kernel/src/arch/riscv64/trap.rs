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
pub extern "C" fn rust_trap_handler(tf: &mut TrapFrame) -> *mut TrapFrame {
    let cause = scause::read();
    let stval = stval::read();
    let from_user = (tf.sstatus & (1 << 8)) == 0;

    match cause.cause() {
        Trap::Exception(Exception::UserEnvCall) => {
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
                "[user fault pid={}] {:?}\n  sepc  = {:#x}\n  stval = {:#x}\n  sstatus = {:#x}",
                crate::task::current_pid(),
                e, tf.sepc, stval, tf.sstatus
            );
            // Dump a few key registers, not all of them.
            crate::println!(
                "  ra={:#x} sp={:#x} a0={:#x} a1={:#x} a7={:#x}",
                tf.x[0], tf.x[1], tf.x[9], tf.x[10], tf.x[16]
            );
            // Translate the fault into a signal targeting the current task.
            let signo = match e {
                Exception::IllegalInstruction => crate::signal::SIGILL,
                Exception::LoadMisaligned
                | Exception::StoreMisaligned
                | Exception::InstructionMisaligned => crate::signal::SIGBUS,
                Exception::LoadPageFault
                | Exception::StorePageFault
                | Exception::InstructionPageFault
                | Exception::LoadFault
                | Exception::StoreFault
                | Exception::InstructionFault => crate::signal::SIGSEGV,
                _ => crate::signal::SIGSEGV,
            };
            let task = crate::task::current_task();
            // If the default action is SIG_DFL and would terminate, calling
            // raise + letting check_signals do its thing also clears the
            // PC so we don't loop. But if the user installed a handler we
            // must not re-execute the faulting instruction after the
            // handler returns; signals run at trap boundary which means we
            // re-enter user mode after the handler -> sret -> faulting
            // PC. So for unhandled / DFL faults this is fine; for handler-
            // returns, the handler still runs but then user faults again.
            // For now we just deliver and let the natural flow proceed.
            let _ = crate::signal::raise_signal(&task, signo);
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

    // After handling, possibly switch to another task.
    crate::task::schedule_next_after_trap(tf as *mut _)
}

fn instr_len_at(pc: usize) -> usize {
    let first = unsafe { core::ptr::read_volatile(pc as *const u16) };
    if first & 0b11 == 0b11 {
        4
    } else {
        2
    }
}
