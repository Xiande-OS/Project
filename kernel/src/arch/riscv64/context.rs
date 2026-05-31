//! riscv64 kernel-side context switch for preemptive scheduling.
//!
//! A task that is not currently running has its kernel callee-saved state
//! (`ra`, `sp`, `s0..s11`) parked in a [`TaskContext`]. [`__switch`] saves the
//! running task's state into `prev` and loads `next`'s, so execution resumes
//! wherever the target last called `__switch` — or, for a brand-new task, at
//! the trampoline its context was primed with.
//!
//! Caller-saved registers and the rest of the kernel call stack live on the
//! task's own kstack, which is left untouched across the switch, so from the
//! Rust caller's view `__switch` is just a function call that returns once this
//! task is scheduled again.

use core::arch::global_asm;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TaskContext {
    pub ra: usize,
    pub sp: usize,
    /// s0..s11 (x8, x9, x18..x27).
    pub s: [usize; 12],
}

impl TaskContext {
    pub const fn new() -> Self {
        Self { ra: 0, sp: 0, s: [0; 12] }
    }

    /// Prime a fresh context so the first `__switch` into it begins executing
    /// at `entry` on stack `sp`, callee-saved registers zeroed.
    pub fn init(&mut self, entry: usize, sp: usize) {
        self.ra = entry;
        self.sp = sp;
        self.s = [0; 12];
    }
}

global_asm!(
    r#"
    .section .text
    .globl __switch
    .balign 4
__switch:
    # a0 = *mut prev, a1 = *const next  (offsets match TaskContext)
    sd   ra,  0*8(a0)
    sd   sp,  1*8(a0)
    sd   s0,  2*8(a0)
    sd   s1,  3*8(a0)
    sd   s2,  4*8(a0)
    sd   s3,  5*8(a0)
    sd   s4,  6*8(a0)
    sd   s5,  7*8(a0)
    sd   s6,  8*8(a0)
    sd   s7,  9*8(a0)
    sd   s8, 10*8(a0)
    sd   s9, 11*8(a0)
    sd   s10,12*8(a0)
    sd   s11,13*8(a0)

    ld   ra,  0*8(a1)
    ld   sp,  1*8(a1)
    ld   s0,  2*8(a1)
    ld   s1,  3*8(a1)
    ld   s2,  4*8(a1)
    ld   s3,  5*8(a1)
    ld   s4,  6*8(a1)
    ld   s5,  7*8(a1)
    ld   s6,  8*8(a1)
    ld   s7,  9*8(a1)
    ld   s8, 10*8(a1)
    ld   s9, 11*8(a1)
    ld   s10,12*8(a1)
    ld   s11,13*8(a1)
    ret
"#
);

extern "C" {
    pub fn __switch(prev: *mut TaskContext, next: *const TaskContext);
}
