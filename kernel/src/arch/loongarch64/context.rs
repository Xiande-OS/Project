//! loongarch64 kernel-side context switch for preemptive scheduling.
//! See the riscv64 backend (`arch/riscv64/context.rs`) for the model; this
//! parks the LoongArch callee-saved GPRs (`ra`, `sp`, `tp`, `fp`, `s0..s8`).
//! Live FP/LSX/LASX vector state is parked separately by the scheduler via
//! `fpu::save`/`restore` around the switch (the kernel is soft-float).

use core::arch::global_asm;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TaskContext {
    pub ra: usize,
    pub sp: usize,
    pub tp: usize,
    pub fp: usize,
    /// s0..s8 ($r23..$r31).
    pub s: [usize; 9],
}

impl TaskContext {
    pub const fn new() -> Self {
        Self { ra: 0, sp: 0, tp: 0, fp: 0, s: [0; 9] }
    }

    /// Prime a fresh context so the first `__switch` into it begins executing
    /// at `entry` on stack `sp`, callee-saved registers zeroed.
    pub fn init(&mut self, entry: usize, sp: usize) {
        self.ra = entry;
        self.sp = sp;
        self.tp = 0;
        self.fp = 0;
        self.s = [0; 9];
    }
}

global_asm!(
    r#"
    .section .text
    .globl __switch
    .balign 4
__switch:
    # $r4 = a0 = *mut prev, $r5 = a1 = *const next  (offsets match TaskContext)
    st.d  $r1,  $r4, 0       # ra
    st.d  $r3,  $r4, 8       # sp
    st.d  $r2,  $r4, 16      # tp
    st.d  $r22, $r4, 24      # fp
    st.d  $r23, $r4, 32      # s0
    st.d  $r24, $r4, 40      # s1
    st.d  $r25, $r4, 48      # s2
    st.d  $r26, $r4, 56      # s3
    st.d  $r27, $r4, 64      # s4
    st.d  $r28, $r4, 72      # s5
    st.d  $r29, $r4, 80      # s6
    st.d  $r30, $r4, 88      # s7
    st.d  $r31, $r4, 96      # s8

    ld.d  $r1,  $r5, 0
    ld.d  $r3,  $r5, 8
    ld.d  $r2,  $r5, 16
    ld.d  $r22, $r5, 24
    ld.d  $r23, $r5, 32
    ld.d  $r24, $r5, 40
    ld.d  $r25, $r5, 48
    ld.d  $r26, $r5, 56
    ld.d  $r27, $r5, 64
    ld.d  $r28, $r5, 72
    ld.d  $r29, $r5, 80
    ld.d  $r30, $r5, 88
    ld.d  $r31, $r5, 96
    jr    $r1
"#
);

extern "C" {
    pub fn __switch(prev: *mut TaskContext, next: *const TaskContext);
}
