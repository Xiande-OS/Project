/* xiande-os minimal vDSO for riscv64.
 * Exports __vdso_rt_sigreturn with .eh_frame CFI marking it a signal
 * frame, so glibc's _Unwind_ForcedUnwind (pthread_cancel) can step
 * across the kernel-pushed rt_sigframe.
 *
 * Our rt_sigframe (see kernel/src/signal.rs): when the kernel enters the
 * signal handler, sp = frame base = &siginfo. Layout:
 *   sp+0    : siginfo_t (128 bytes)
 *   sp+128  : ucontext; uc_mcontext (== struct sigcontext) at +176
 *   => sc_regs (gregs[32]) starts at sp + 128 + 176 = sp + 304.
 * gregs order: pc, ra, sp, gp, tp, t0..t2, s0,s1, a0..a7, s2..s11, t3..t6
 * => greg[N] lives at (sp+304) + 8*N.
 *
 * For the signal-frame FDE we set CFA = sp + 304 (address of gregs), and
 * each saved x-register N is at CFA + 8*(its greg index). The interrupted
 * PC is gregs[0] = CFA+0; we make that the return-address column.
 */
	.text
	.balign 16
	.globl __vdso_rt_sigreturn
	.type __vdso_rt_sigreturn, @function
__vdso_rt_sigreturn:
	.cfi_startproc
	.cfi_signal_frame
	/* CFA = sp + 304 (start of sc_regs/gregs in the sigframe) */
	.cfi_def_cfa 2, 304
	/* return address column -> saved pc = gregs[0] = CFA+0 */
	.cfi_offset 64, 0
	.cfi_offset 1, 8       /* ra  gregs[1] */
	.cfi_offset 2, 16      /* sp  gregs[2] */
	.cfi_offset 3, 24      /* gp  gregs[3] */
	.cfi_offset 4, 32      /* tp  gregs[4] */
	.cfi_offset 5, 40      /* t0  gregs[5] */
	.cfi_offset 6, 48      /* t1  gregs[6] */
	.cfi_offset 7, 56      /* t2  gregs[7] */
	.cfi_offset 8, 64      /* s0  gregs[8] */
	.cfi_offset 9, 72      /* s1  gregs[9] */
	.cfi_offset 10, 80     /* a0  gregs[10] */
	.cfi_offset 11, 88     /* a1  gregs[11] */
	.cfi_offset 12, 96     /* a2  gregs[12] */
	.cfi_offset 13, 104    /* a3  gregs[13] */
	.cfi_offset 14, 112    /* a4  gregs[14] */
	.cfi_offset 15, 120    /* a5  gregs[15] */
	.cfi_offset 16, 128    /* a6  gregs[16] */
	.cfi_offset 17, 136    /* a7  gregs[17] */
	.cfi_offset 18, 144    /* s2  gregs[18] */
	.cfi_offset 19, 152    /* s3  gregs[19] */
	.cfi_offset 20, 160    /* s4  gregs[20] */
	.cfi_offset 21, 168    /* s5  gregs[21] */
	.cfi_offset 22, 176    /* s6  gregs[22] */
	.cfi_offset 23, 184    /* s7  gregs[23] */
	.cfi_offset 24, 192    /* s8  gregs[24] */
	.cfi_offset 25, 200    /* s9  gregs[25] */
	.cfi_offset 26, 208    /* s10 gregs[26] */
	.cfi_offset 27, 216    /* s11 gregs[27] */
	.cfi_offset 28, 224    /* t3  gregs[28] */
	.cfi_offset 29, 232    /* t4  gregs[29] */
	.cfi_offset 30, 240    /* t5  gregs[30] */
	.cfi_offset 31, 248    /* t6  gregs[31] */
	li a7, 139             /* __NR_rt_sigreturn */
	ecall
	.cfi_endproc
	.size __vdso_rt_sigreturn, . - __vdso_rt_sigreturn
