//! loongarch64 trap dispatch (general exceptions, interrupts, syscalls).

use core::arch::global_asm;

global_asm!(include_str!("trap.S"));

extern "C" {
    fn __trap_entry();
    fn __tlb_refill_entry();
}

/// Layout matches `trap.S`. `r[i]` is general register `$r{i}`:
///   r1=ra, r2=tp, r3=sp, r4..r11=a0..a7, r12..r20=t0..t8,
///   r21=reserved, r22=fp, r23..r31=s0..s8. r0 is hardwired zero.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct TrapFrame {
    pub r: [usize; 32],
    pub era: usize,
    pub prmd: usize,
}

/// Architecture-independent accessors — the same contract the riscv64
/// `TrapFrame` implements, so signal/syscall/task code stays portable.
impl TrapFrame {
    // --- Program counter -----------------------------------------------

    #[inline]
    pub fn user_pc(&self) -> usize {
        self.era
    }
    #[inline]
    pub fn set_user_pc(&mut self, pc: usize) {
        self.era = pc;
    }
    /// Rewind PC by one `syscall` instruction so it re-executes on next
    /// entry. The dispatcher advances ERA past `syscall` before running
    /// the handler (mirroring riscv64's pre-increment), so the rewind /
    /// advance polarity matches riscv64 exactly.
    #[inline]
    pub fn rewind_syscall(&mut self) {
        self.era -= 4;
    }
    #[inline]
    pub fn advance_past_syscall(&mut self) {
        self.era += 4;
    }

    // --- User stack pointer / return address ---------------------------

    #[inline]
    pub fn user_sp(&self) -> usize {
        self.r[3]
    }
    #[inline]
    pub fn set_user_sp(&mut self, sp: usize) {
        self.r[3] = sp;
    }
    #[inline]
    pub fn set_user_ra(&mut self, ra: usize) {
        self.r[1] = ra;
    }
    /// Thread pointer (TLS base). loongarch64: `$tp` = r2.
    #[inline]
    pub fn set_user_tp(&mut self, tp: usize) {
        self.r[2] = tp;
    }

    /// Configure privilege/mode bits so `__trap_return` drops this frame
    /// into user mode with interrupts enabled. loongarch64 restores
    /// CRMD.{PLV,IE} from PRMD.{PPLV,PIE} on `ertn`, so we set
    /// PPLV=3 (PLV3 / user) and PIE=1.
    #[inline]
    pub fn init_user_state(&mut self) {
        self.prmd = 0b111; // PPLV=3 | PIE=1
    }

    // --- Syscall ABI (loongarch64 Linux) -------------------------------

    /// Syscall number: `$a7` = r11.
    #[inline]
    pub fn syscall_no(&self) -> usize {
        self.r[11]
    }
    /// Syscall argument n (0..=5 → a0..a5 = r4..r9).
    #[inline]
    pub fn syscall_arg(&self, n: usize) -> usize {
        debug_assert!(n < 6);
        self.r[4 + n]
    }
    /// Return value: `$a0` = r4.
    #[inline]
    pub fn set_syscall_ret(&mut self, v: usize) {
        self.r[4] = v;
    }
    #[inline]
    pub fn syscall_ret(&self) -> usize {
        self.r[4]
    }

    // --- Signal handler entry ------------------------------------------

    #[inline]
    pub fn enter_signal_handler(
        &mut self,
        handler: usize,
        restorer: usize,
        sp: usize,
        signo: u32,
        siginfo: usize,
        ucontext: usize,
    ) {
        self.r[3] = sp; // sp
        self.set_user_pc(handler);
        self.r[4] = signo as usize; // a0
        self.r[5] = siginfo; // a1
        self.r[6] = ucontext; // a2
        self.r[1] = restorer; // ra
    }

    // --- Signal frame mcontext save / restore --------------------------
    //
    // First-pass mapping (handoff option A): populate the riscv-named
    // KGRegs slots with their loongarch equivalents where they overlap.
    // gp/r21/t7/t8/s10/s11 have no slot and are not round-tripped; this
    // is symmetric (save/restore are inverse) which is all the RV-shaped
    // sigreturn path needs until the musl-LA sigcontext layer is forked.

    pub fn save_to_sigcontext(&self, g: &mut crate::signal::KGRegs) {
        let r = &self.r;
        g.pc = self.era as u64;
        g.ra = r[1] as u64;
        g.sp = r[3] as u64;
        g.gp = 0;
        g.tp = r[2] as u64;
        g.a0 = r[4] as u64;
        g.a1 = r[5] as u64;
        g.a2 = r[6] as u64;
        g.a3 = r[7] as u64;
        g.a4 = r[8] as u64;
        g.a5 = r[9] as u64;
        g.a6 = r[10] as u64;
        g.a7 = r[11] as u64;
        g.t0 = r[12] as u64;
        g.t1 = r[13] as u64;
        g.t2 = r[14] as u64;
        g.t3 = r[15] as u64;
        g.t4 = r[16] as u64;
        g.t5 = r[17] as u64;
        g.t6 = r[18] as u64;
        g.s0 = r[23] as u64;
        g.s1 = r[24] as u64;
        g.s2 = r[25] as u64;
        g.s3 = r[26] as u64;
        g.s4 = r[27] as u64;
        g.s5 = r[28] as u64;
        g.s6 = r[29] as u64;
        g.s7 = r[30] as u64;
        g.s8 = r[31] as u64;
        g.s9 = r[22] as u64; // fp
        g.s10 = 0;
        g.s11 = 0;
    }

    pub fn restore_from_sigcontext(&mut self, g: &crate::signal::KGRegs) {
        self.era = g.pc as usize;
        self.r[1] = g.ra as usize;
        self.r[3] = g.sp as usize;
        self.r[2] = g.tp as usize;
        self.r[4] = g.a0 as usize;
        self.r[5] = g.a1 as usize;
        self.r[6] = g.a2 as usize;
        self.r[7] = g.a3 as usize;
        self.r[8] = g.a4 as usize;
        self.r[9] = g.a5 as usize;
        self.r[10] = g.a6 as usize;
        self.r[11] = g.a7 as usize;
        self.r[12] = g.t0 as usize;
        self.r[13] = g.t1 as usize;
        self.r[14] = g.t2 as usize;
        self.r[15] = g.t3 as usize;
        self.r[16] = g.t4 as usize;
        self.r[17] = g.t5 as usize;
        self.r[18] = g.t6 as usize;
        self.r[23] = g.s0 as usize;
        self.r[24] = g.s1 as usize;
        self.r[25] = g.s2 as usize;
        self.r[26] = g.s3 as usize;
        self.r[27] = g.s4 as usize;
        self.r[28] = g.s5 as usize;
        self.r[29] = g.s6 as usize;
        self.r[30] = g.s7 as usize;
        self.r[31] = g.s8 as usize;
        self.r[22] = g.s9 as usize; // fp
    }
}

// ---- CSR helpers ------------------------------------------------------

#[inline]
fn csrrd(csr: u32) -> usize {
    // The csr index is an instruction immediate, so it must be known at
    // compile time; we dispatch the handful we read.
    let v: usize;
    unsafe {
        match csr {
            0x0 => core::arch::asm!("csrrd {0}, 0x0", out(reg) v),
            0x5 => core::arch::asm!("csrrd {0}, 0x5", out(reg) v),
            0x7 => core::arch::asm!("csrrd {0}, 0x7", out(reg) v),
            _ => unreachable!(),
        }
    }
    v
}

const TIMER_QUANTUM: usize = 100_000; // ~1 ms at 100 MHz

fn arm_timer() {
    // Periodic timer: En(bit0) | Periodic(bit1) | InitVal (bits [N:2]).
    let tcfg = (TIMER_QUANTUM & !0x3) | 0b11;
    unsafe {
        core::arch::asm!("csrwr {0}, 0x41", inout(reg) tcfg => _);
    }
}

/// Install the trap vectors and start the periodic timer. Call once during
/// early boot (after the console works).
pub fn init() {
    unsafe {
        // EENTRY (general exceptions) and TLBRENTRY (TLB refill).
        core::arch::asm!("csrwr {0}, 0xc", inout(reg) (__trap_entry as usize) => _);
        core::arch::asm!("csrwr {0}, 0x88", inout(reg) (__tlb_refill_entry as usize) => _);

        // Page-walk controls for 4 KiB pages, 3 levels of 9 bits — the
        // Sv39-shaped tree the common mm layer builds.
        let pwcl: usize =
            12 | (9 << 5) | (21 << 10) | (9 << 15) | (30 << 20) | (9 << 25);
        core::arch::asm!("csrwr {0}, 0x1c", inout(reg) pwcl => _);
        let pwch: usize = 0;
        core::arch::asm!("csrwr {0}, 0x1d", inout(reg) pwch => _);
        let stlbps: usize = 12; // 4 KiB
        core::arch::asm!("csrwr {0}, 0x1e", inout(reg) stlbps => _);

        // ECFG.LIE: enable the timer interrupt line (bit 11). Global
        // delivery is gated by CRMD.IE, which stays 0 in kernel mode and
        // is set on return to user via PRMD.PIE (init_user_state) — so
        // ticks preempt user mode without re-entering the kernel handler.
        let ecfg: usize = 1 << 11;
        core::arch::asm!("csrwr {0}, 0x4", inout(reg) ecfg => _);
    }
    arm_timer();
}

#[no_mangle]
pub extern "C" fn rust_trap_handler(tf: &mut TrapFrame) -> *mut TrapFrame {
    let estat = csrrd(0x5);
    let ecode = (estat >> 16) & 0x3f;
    let is = estat & 0x1fff;
    let from_user = (tf.prmd & 0x3) != 0;

    if ecode == 0 {
        // Interrupt. Timer == IS bit 11.
        if is & (1 << 11) != 0 {
            // Clear the timer interrupt; the periodic timer re-arms itself.
            unsafe {
                core::arch::asm!("csrwr {0}, 0x44", inout(reg) 1usize => _);
            }
            if !from_user {
                // Nested tick during in-kernel syscall handling. See riscv64
                // trap.rs: kill a wedged (overrun) syscall, else preempt — if no
                // lock is held and another task is Ready, suspend this syscall
                // and switch (it resumes here later); otherwise carry on.
                if crate::task::watchdog_overrun() {
                    return unsafe { crate::task::watchdog_kill_current(tf as *mut _) };
                }
                return unsafe { crate::task::preempt_current(tf as *mut _) };
            }
        } else {
            crate::println!("[trap] unhandled interrupt, IS={:#x}; masking", is);
            // Mask further interrupts by clearing ECFG.LIE.
            unsafe {
                core::arch::asm!("csrwr {0}, 0x4", inout(reg) 0usize => _);
            }
        }
    } else {
        match ecode {
            0x0B => {
                // syscall: step past the `syscall` instruction, then run.
                tf.era += 4;
                // Run with CRMD.IE set so the periodic timer can fire as a
                // nested trap and drive the in-kernel watchdog if this call
                // wedges (see task::watchdog_*). Restore IE=0 before the
                // scheduler runs so it is never itself interrupted.
                crate::task::watchdog_arm();
                let set = csrrd(0x0) | (1usize << 2);
                unsafe { core::arch::asm!("csrwr {0}, 0x0", inout(reg) set => _); }
                crate::syscall::dispatch(tf);
                let clr = csrrd(0x0) & !(1usize << 2);
                unsafe { core::arch::asm!("csrwr {0}, 0x0", inout(reg) clr => _); }
                crate::task::watchdog_disarm();
            }
            0x0C => {
                // breakpoint
                tf.era += 4;
            }
            _ if from_user => {
                let badv = csrrd(0x7);
                let task = crate::task::current_task();
                // PIL/PIS/PIF (load/store/fetch page faults) on a VA that is
                // actually mapped in the page table are spurious: the general
                // exception fired against a stale TLB entry (a single ASID
                // space is shared, so a sibling's entry can shadow ours).
                // Drop the stale entry and re-run the instruction; the retry
                // misses the TLB and the refill walker reloads the live PTE.
                if matches!(ecode, 0x01 | 0x02 | 0x03)
                    && task
                        .memory_set
                        .lock()
                        .translate(crate::mm::VirtAddr(badv))
                        .is_some()
                {
                    crate::arch::flush_tlb_all();
                    return crate::task::schedule_next_after_trap(tf as *mut _);
                }
                crate::println!(
                    "[user fault pid={}] ecode={:#x} era={:#x} badv={:#x} prmd={:#x}",
                    crate::task::current_pid(),
                    ecode,
                    tf.era,
                    badv,
                    tf.prmd
                );
                let signo = match ecode {
                    0x0D | 0x0E => crate::signal::SIGILL, // INE / IPE
                    0x09 => crate::signal::SIGBUS,        // ALE (alignment)
                    _ => crate::signal::SIGSEGV,          // PIL/PIS/PIF/PME/PNR/PNX/PPI/ADE
                };
                // force_sig semantics: a synchronous fault signal must not be
                // lost to a blocked mask / SIG_IGN, else we return to the
                // faulting `era` and loop forever. See riscv64 trap.rs.
                crate::signal::force_fault_signal(&task, signo);
            }
            _ => {
                let badv = csrrd(0x7);
                panic!(
                    "kernel exception ecode={:#x}\n  era  = {:#x}\n  badv = {:#x}\n  prmd = {:#x}",
                    ecode, tf.era, badv, tf.prmd,
                );
            }
        }
    }

    crate::task::schedule_next_after_trap(tf as *mut _)
}
