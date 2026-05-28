//! POSIX signal delivery for riscv64 (musl userspace).
//!
//! Restorer trampoline: musl on riscv64 doesn't fill SA_RESTORER. The
//! kernel must therefore plant a tiny piece of user-executable code
//! whose only job is to issue rt_sigreturn. We do this by mapping a
//! dedicated page at SIG_RESTORER_VA into every user address space.
//!
//! Per-task signal state lives on `Task` (sig_actions, sig_mask,
//! sig_pending, sig_altstack, saved_sig_mask). This module is the
//! delivery + sigreturn engine.
//!
//! The rt_sigframe layout we push on the user stack matches what musl's
//! `__restore_rt` expects to find when it issues `rt_sigreturn`:
//!
//!   sp_low  ──────────────────────────────────
//!           siginfo_t   (128 bytes, set fully)
//!           ucontext {
//!             uc_flags    : u64
//!             uc_link     : *ucontext (we leave 0)
//!             uc_stack    : stack_t (24 bytes)
//!             uc_mcontext : sigcontext  { gregs[32] (u64), fpregs (528 bytes, zeroed) }
//!             uc_sigmask  : sigset_t (128 bytes -- we use 8 + 120 pad)
//!           }
//!   sp_high ──────────────────────────────────
//!
//! On rt_sigreturn we restore tf from `gregs` and sig_mask from uc_sigmask.

use alloc::sync::Arc;
use core::mem::size_of;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

pub type SigActions = [KSigAction; (NSIG + 1) as usize];

use crate::arch::riscv64::trap::TrapFrame;
use crate::mm::memory_set::MemorySet;
use crate::mm::VirtAddr;
use crate::task::{Task, TaskState};

/// Virtual address at which we install the per-process signal-restorer
/// page. Lives above the 8 MiB user stack (top = 0x4000_0000) and well
/// below the dynamic-linker base (0x10_0000_0000).
pub const SIG_RESTORER_VA: usize = 0x5000_0000;

/// Build a 4 KiB page whose first 8 bytes are `li a7, 139 ; ecall`.
/// Repeating the instructions across the page is unnecessary but
/// harmless.
fn restorer_page_bytes() -> [u8; 4096] {
    let mut buf = [0u8; 4096];
    // li a7, 139   -> 0x08b00893
    let insns: [u32; 2] = [0x08b00893, 0x00000073];
    let bytes = unsafe {
        core::slice::from_raw_parts(insns.as_ptr() as *const u8, 8)
    };
    buf[..8].copy_from_slice(bytes);
    buf
}

/// Map the restorer page into the given MemorySet. Idempotent: if a
/// page already exists at that VA the caller is responsible for not
/// remapping.
pub fn install_restorer_page(ms: &mut MemorySet) {
    let bytes = restorer_page_bytes();
    ms.map_user_rx_page(VirtAddr(SIG_RESTORER_VA), &bytes);
}

// ----- Signal numbers (matching Linux/musl) -----

pub const SIGHUP: u32 = 1;
pub const SIGINT: u32 = 2;
pub const SIGQUIT: u32 = 3;
pub const SIGILL: u32 = 4;
pub const SIGTRAP: u32 = 5;
pub const SIGABRT: u32 = 6;
pub const SIGBUS: u32 = 7;
pub const SIGFPE: u32 = 8;
pub const SIGKILL: u32 = 9;
pub const SIGUSR1: u32 = 10;
pub const SIGSEGV: u32 = 11;
pub const SIGUSR2: u32 = 12;
pub const SIGPIPE: u32 = 13;
pub const SIGALRM: u32 = 14;
pub const SIGTERM: u32 = 15;
pub const SIGCHLD: u32 = 17;
pub const SIGCONT: u32 = 18;
pub const SIGSTOP: u32 = 19;
pub const SIGTSTP: u32 = 20;
pub const SIGTTIN: u32 = 21;
pub const SIGTTOU: u32 = 22;
pub const SIGURG: u32 = 23;
pub const SIGXCPU: u32 = 24;
pub const SIGXFSZ: u32 = 25;
pub const SIGVTALRM: u32 = 26;
pub const SIGPROF: u32 = 27;
pub const SIGWINCH: u32 = 28;
pub const SIGIO: u32 = 29;
pub const SIGPWR: u32 = 30;
pub const SIGSYS: u32 = 31;

pub const NSIG: u32 = 64;

// ----- sigaction flags (matching musl bits/signal.h riscv) -----

pub const SA_NOCLDSTOP: u64 = 1;
pub const SA_NOCLDWAIT: u64 = 2;
pub const SA_SIGINFO: u64 = 4;
pub const SA_ONSTACK: u64 = 0x08000000;
pub const SA_RESTART: u64 = 0x10000000;
pub const SA_NODEFER: u64 = 0x40000000;
pub const SA_RESETHAND: u64 = 0x80000000;

pub const SIG_DFL: usize = 0;
pub const SIG_IGN: usize = 1;

// sigprocmask `how` values
pub const SIG_BLOCK: i32 = 0;
pub const SIG_UNBLOCK: i32 = 1;
pub const SIG_SETMASK: i32 = 2;

// sigaltstack flags
pub const SS_ONSTACK: i32 = 1;
pub const SS_DISABLE: i32 = 2;
pub const MINSIGSTKSZ: usize = 2048;

// siginfo si_code (small subset)
pub const SI_USER: i32 = 0;
pub const SI_KERNEL: i32 = 0x80;

#[derive(Clone, Copy, Debug)]
pub struct KSigAction {
    pub handler: usize,
    pub flags: u64,
    pub restorer: usize,
    /// Blocked-while-handler mask. Excludes SIGKILL/SIGSTOP.
    pub mask: u64,
}

impl Default for KSigAction {
    fn default() -> Self {
        Self {
            handler: SIG_DFL,
            flags: 0,
            restorer: 0,
            mask: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SigAltStack {
    pub ss_sp: usize,
    pub ss_flags: i32,
    pub ss_size: usize,
}

/// Per-task signal state container. Stored on `Task`.
///
/// `actions` is wrapped in `Arc<Mutex<>>` so CLONE_SIGHAND threads share the
/// disposition table while each thread keeps its own mask + pending bits.
pub struct SignalState {
    pub actions: Arc<Mutex<SigActions>>,
    pub mask: AtomicU64,
    pub pending: AtomicU64,
    pub altstack: Mutex<Option<SigAltStack>>,
    pub saved_mask: Mutex<Option<u64>>,
}

impl SignalState {
    pub fn new() -> Self {
        Self {
            actions: Arc::new(Mutex::new([KSigAction::default(); (NSIG + 1) as usize])),
            mask: AtomicU64::new(0),
            pending: AtomicU64::new(0),
            altstack: Mutex::new(None),
            saved_mask: Mutex::new(None),
        }
    }

    /// Inherited copy for fork(): same actions (fresh deep copy), same
    /// mask, pending cleared.
    pub fn fork_inherit(&self) -> Self {
        let actions = *self.actions.lock();
        Self {
            actions: Arc::new(Mutex::new(actions)),
            mask: AtomicU64::new(self.mask.load(Ordering::Relaxed)),
            pending: AtomicU64::new(0),
            altstack: Mutex::new(*self.altstack.lock()),
            saved_mask: Mutex::new(None),
        }
    }

    /// Inherited copy for CLONE_THREAD/CLONE_SIGHAND: **same** Arc backing
    /// the actions table (so a sigaction in one thread is visible to all).
    /// Mask and pending are still per-thread.
    pub fn share_actions_inherit(&self) -> Self {
        Self {
            actions: self.actions.clone(),
            mask: AtomicU64::new(self.mask.load(Ordering::Relaxed)),
            pending: AtomicU64::new(0),
            altstack: Mutex::new(*self.altstack.lock()),
            saved_mask: Mutex::new(None),
        }
    }

    /// On execve: keep mask, reset every non-IGN handler to DFL.
    pub fn reset_for_exec(&self) {
        let mut actions = self.actions.lock();
        for slot in actions.iter_mut() {
            // SIG_IGN stays as IGN. Anything else (incl. user handler) -> DFL.
            if slot.handler != SIG_IGN {
                *slot = KSigAction::default();
            } else {
                slot.flags = 0;
                slot.restorer = 0;
                slot.mask = 0;
            }
        }
        self.pending.store(0, Ordering::Relaxed);
        *self.altstack.lock() = None;
        *self.saved_mask.lock() = None;
    }
}

fn sigbit(signo: u32) -> u64 {
    1u64 << (signo - 1)
}

pub fn is_valid_signo(signo: u32) -> bool {
    signo >= 1 && signo <= NSIG
}

/// Forbidden-to-mask signals (POSIX).
pub fn unblockable_mask() -> u64 {
    sigbit(SIGKILL) | sigbit(SIGSTOP)
}

// ----- post-trap dispatch -----

/// Default-action category for a signal (when handler == SIG_DFL).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DefaultAction {
    /// Terminate the process with `signo` as exit status.
    Term,
    /// Terminate + dump core. We just set status with the WIFSIGNALED|core bit.
    Core,
    /// Stop the process (we treat as Ignore for now -- no job control state).
    Stop,
    /// Continue the process (no-op when not stopped).
    Cont,
    /// Ignore.
    Ignore,
}

pub fn default_action(signo: u32) -> DefaultAction {
    match signo {
        SIGABRT | SIGSEGV | SIGFPE | SIGILL | SIGBUS | SIGSYS | SIGTRAP
            | SIGXCPU | SIGXFSZ | SIGQUIT => DefaultAction::Core,
        SIGINT | SIGTERM | SIGHUP | SIGALRM | SIGUSR1 | SIGUSR2 | SIGPIPE
            | SIGKILL | SIGVTALRM | SIGPROF | SIGIO | SIGPWR => DefaultAction::Term,
        SIGCHLD | SIGURG | SIGWINCH => DefaultAction::Ignore,
        SIGCONT => DefaultAction::Cont,
        SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU => DefaultAction::Stop,
        _ => DefaultAction::Term,
    }
}

/// Add `signo` to `target`'s pending set; wake if the task was Waiting.
/// Returns true if a deliverable signal was posted (false if signo invalid).
pub fn raise_signal(target: &Arc<Task>, signo: u32) -> bool {
    if !is_valid_signo(signo) {
        return false;
    }
    // Check current disposition: SIG_IGN with default sense -> drop entirely.
    {
        let act = target.signals.actions.lock()[signo as usize];
        if act.handler == SIG_IGN
            && signo != SIGKILL
            && signo != SIGSTOP
        {
            return true;
        }
    }
    target.signals.pending.fetch_or(sigbit(signo), Ordering::SeqCst);
    // Wake from blocking syscalls.
    let was_waiting = {
        let mut s = target.state.lock();
        if *s == TaskState::Waiting {
            *s = TaskState::Ready;
            true
        } else {
            false
        }
    };
    if was_waiting {
        // If the task was parked in a futex queue, remove it and mark
        // EINTR so the syscall resumes with -EINTR instead of "blocked
        // again, no wake_result". Harmless if not in a futex queue.
        crate::sync::futex::interrupt_wait(target.pid);
    }
    true
}

/// Pop the lowest pending non-blocked signal. None if none deliverable.
fn pick_signal(task: &Arc<Task>) -> Option<u32> {
    let pending = task.signals.pending.load(Ordering::SeqCst);
    let mask = task.signals.mask.load(Ordering::SeqCst);
    // SIGKILL/SIGSTOP can never be blocked.
    let deliverable = pending & !(mask & !unblockable_mask());
    if deliverable == 0 {
        return None;
    }
    Some((deliverable.trailing_zeros() + 1) as u32)
}

fn clear_pending(task: &Arc<Task>, signo: u32) {
    task.signals.pending.fetch_and(!sigbit(signo), Ordering::SeqCst);
}

// ----- Signal frame layout written on user stack -----

/// 32 general-purpose registers as the kernel-side mcontext expects them.
/// Field order matches Linux's `struct user_regs_struct` (which is also
/// `__gregs[0..32]` in musl's mcontext_t).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct KGRegs {
    pub pc: u64,
    pub ra: u64,
    pub sp: u64,
    pub gp: u64,
    pub tp: u64,
    pub t0: u64, pub t1: u64, pub t2: u64,
    pub s0: u64, pub s1: u64,
    pub a0: u64, pub a1: u64, pub a2: u64, pub a3: u64,
    pub a4: u64, pub a5: u64, pub a6: u64, pub a7: u64,
    pub s2: u64, pub s3: u64, pub s4: u64, pub s5: u64,
    pub s6: u64, pub s7: u64, pub s8: u64, pub s9: u64,
    pub s10: u64, pub s11: u64,
    pub t3: u64, pub t4: u64, pub t5: u64, pub t6: u64,
}

/// Linux generic mcontext = struct sigcontext = { gregs[32], fpregs }.
/// fpregs is a 528-byte tail (union of __riscv_{f,d,q}_ext_state). We zero
/// it; user code that doesn't touch FP through getcontext is unaffected.
const FPREGS_LEN: usize = 528;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KMContext {
    pub regs: KGRegs,
    pub fpregs: [u8; FPREGS_LEN],
}

impl Default for KMContext {
    fn default() -> Self {
        Self {
            regs: KGRegs::default(),
            fpregs: [0u8; FPREGS_LEN],
        }
    }
}

/// stack_t (musl/Linux) -- ss_sp, ss_flags, ss_size.
/// 8 + 4 + 4(pad) + 8 = 24 bytes.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct KStackT {
    pub ss_sp: u64,
    pub ss_flags: i32,
    pub _pad: u32,
    pub ss_size: u64,
}

/// 1024-bit sigset, padded to 128 bytes to match Linux kernel layout.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KSigSet {
    pub bits: u64,
    pub _pad: [u8; 120],
}
impl Default for KSigSet {
    fn default() -> Self { Self { bits: 0, _pad: [0u8; 120] } }
}

/// What the kernel writes for `struct ucontext` on the rt_sigframe.
/// Matches Linux generic ucontext (asm-generic/ucontext.h) field order.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct KUContext {
    pub uc_flags: u64,
    pub uc_link: u64,
    pub uc_stack: KStackT,
    pub uc_mcontext: KMContext,
    pub uc_sigmask: KSigSet,
}

/// siginfo_t (128 bytes). We populate si_signo, si_errno, si_code,
/// _pad's si_pid/si_uid for SI_USER signals. Everything else stays zero.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KSigInfo {
    pub si_signo: i32,
    pub si_errno: i32,
    pub si_code: i32,
    pub _pad: [u8; 116],
}
impl Default for KSigInfo {
    fn default() -> Self {
        Self { si_signo: 0, si_errno: 0, si_code: 0, _pad: [0u8; 116] }
    }
}

/// The full frame on the user stack. siginfo first (low address), then
/// ucontext, then... that's all we write. The frame base address we put
/// in user sp.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RtSigFrame {
    pub info: KSigInfo,
    pub uc: KUContext,
}

impl Default for RtSigFrame {
    fn default() -> Self {
        Self {
            info: KSigInfo::default(),
            uc: KUContext::default(),
        }
    }
}

pub const SIGFRAME_SIZE: usize = size_of::<RtSigFrame>();

// ----- Building a sigframe + entering the user handler -----

fn copy_tf_to_gregs(tf: &TrapFrame) -> KGRegs {
    let x = &tf.x;
    KGRegs {
        pc: tf.sepc as u64,
        ra: x[0] as u64,  // x1
        sp: x[1] as u64,  // x2
        gp: x[2] as u64,  // x3
        tp: x[3] as u64,  // x4
        t0: x[4] as u64,  t1: x[5] as u64,  t2: x[6] as u64,
        s0: x[7] as u64,  s1: x[8] as u64,
        a0: x[9] as u64,  a1: x[10] as u64, a2: x[11] as u64, a3: x[12] as u64,
        a4: x[13] as u64, a5: x[14] as u64, a6: x[15] as u64, a7: x[16] as u64,
        s2: x[17] as u64, s3: x[18] as u64, s4: x[19] as u64, s5: x[20] as u64,
        s6: x[21] as u64, s7: x[22] as u64, s8: x[23] as u64, s9: x[24] as u64,
        s10: x[25] as u64, s11: x[26] as u64,
        t3: x[27] as u64, t4: x[28] as u64, t5: x[29] as u64, t6: x[30] as u64,
    }
}

fn restore_tf_from_gregs(tf: &mut TrapFrame, g: &KGRegs) {
    tf.sepc = g.pc as usize;
    tf.x[0] = g.ra as usize;
    tf.x[1] = g.sp as usize;
    tf.x[2] = g.gp as usize;
    tf.x[3] = g.tp as usize;
    tf.x[4] = g.t0 as usize;
    tf.x[5] = g.t1 as usize;
    tf.x[6] = g.t2 as usize;
    tf.x[7] = g.s0 as usize;
    tf.x[8] = g.s1 as usize;
    tf.x[9] = g.a0 as usize;
    tf.x[10] = g.a1 as usize;
    tf.x[11] = g.a2 as usize;
    tf.x[12] = g.a3 as usize;
    tf.x[13] = g.a4 as usize;
    tf.x[14] = g.a5 as usize;
    tf.x[15] = g.a6 as usize;
    tf.x[16] = g.a7 as usize;
    tf.x[17] = g.s2 as usize;
    tf.x[18] = g.s3 as usize;
    tf.x[19] = g.s4 as usize;
    tf.x[20] = g.s5 as usize;
    tf.x[21] = g.s6 as usize;
    tf.x[22] = g.s7 as usize;
    tf.x[23] = g.s8 as usize;
    tf.x[24] = g.s9 as usize;
    tf.x[25] = g.s10 as usize;
    tf.x[26] = g.s11 as usize;
    tf.x[27] = g.t3 as usize;
    tf.x[28] = g.t4 as usize;
    tf.x[29] = g.t5 as usize;
    tf.x[30] = g.t6 as usize;
}

/// Inspect signals and possibly start delivering one. Returns true when
/// the task is now Zombie because of a terminating default-action signal
/// (caller should pick another task).
///
/// Must be called only when `tf` belongs to the currently running task
/// and we're about to sret back to user mode.
pub fn check_signals(task: &Arc<Task>, tf: &mut TrapFrame) -> bool {
    loop {
        let Some(signo) = pick_signal(task) else { return false; };

        // Snapshot the action under the lock; if user handler we'll hold
        // info beyond the lock.
        let act = {
            let acts = task.signals.actions.lock();
            acts[signo as usize]
        };

        // Always clear pending bit early; if delivery fails we still
        // shouldn't loop forever.
        clear_pending(task, signo);

        // SIG_IGN handling (in case the disposition changed since we
        // posted): drop and continue scanning.
        if act.handler == SIG_IGN {
            continue;
        }

        // SIG_DFL handling.
        if act.handler == SIG_DFL {
            let action = default_action(signo);
            match action {
                DefaultAction::Ignore | DefaultAction::Cont => {
                    continue;
                }
                DefaultAction::Stop => {
                    // No job-control stop state yet -- ignore.
                    continue;
                }
                DefaultAction::Term => {
                    deliver_default_terminate(task, signo as i32, false);
                    return true;
                }
                DefaultAction::Core => {
                    deliver_default_terminate(task, signo as i32, true);
                    return true;
                }
            }
        }

        // Custom user handler.
        if let Err(()) = deliver_user_handler(task, tf, signo, &act) {
            // Fall back to default terminate if frame setup failed.
            deliver_default_terminate(task, signo as i32, false);
            return true;
        }
        return false;
    }
}

fn deliver_default_terminate(task: &Arc<Task>, signo: i32, core: bool) {
    // wait4-encoded status: WIFSIGNALED bits in the low 7 of byte0, optional
    // WCOREDUMP at 0x80.
    let status = (signo & 0x7f) | if core { 0x80 } else { 0 };
    task.exit_code.store(status, Ordering::Relaxed);
    *task.state.lock() = TaskState::Zombie;
    crate::println!(
        "[exit] pid={} killed by signal {}{}",
        task.pid, signo, if core { " (core)" } else { "" },
    );
    // Notify parent (SIGCHLD + wake from wait4).
    let ppid = task.ppid.load(Ordering::Relaxed);
    if let Some(parent) = crate::task::task_by_pid(ppid) {
        // Wake first; SIGCHLD as well so sigwait/handlers see it.
        let mut s = parent.state.lock();
        if *s == TaskState::Waiting {
            *s = TaskState::Ready;
        }
        drop(s);
        let _ = raise_signal(&parent, SIGCHLD);
    }
}

fn deliver_user_handler(
    task: &Arc<Task>,
    tf: &mut TrapFrame,
    signo: u32,
    act: &KSigAction,
) -> Result<(), ()> {
    // If user didn't set a restorer (the riscv musl path), fall back to
    // the kernel-installed restorer page.
    let restorer = if act.restorer == 0 { SIG_RESTORER_VA } else { act.restorer };

    // Compute the sp for the handler. If SA_ONSTACK and an enabled
    // altstack exists and we're not already on it, switch.
    let mut new_sp = tf.x[1]; // current user sp
    {
        if (act.flags & SA_ONSTACK) != 0 {
            if let Some(ast) = *task.signals.altstack.lock() {
                if (ast.ss_flags & SS_DISABLE) == 0
                    && ast.ss_size >= MINSIGSTKSZ
                {
                    let stack_top = ast.ss_sp + ast.ss_size;
                    let on_it = new_sp >= ast.ss_sp && new_sp <= stack_top;
                    if !on_it {
                        new_sp = stack_top;
                    }
                }
            }
        }
    }

    // Reserve a 128-byte "red zone" gap (riscv64 psABI doesn't require one
    // but musl tolerates it; ensures local-variable use in a frame
    // immediately above sp is safe to clobber).
    new_sp = new_sp.saturating_sub(128);
    // Frame is allocated DOWN from new_sp.
    let frame_addr = (new_sp.saturating_sub(SIGFRAME_SIZE)) & !0xfusize;
    if frame_addr == 0 || frame_addr.checked_add(SIGFRAME_SIZE).is_none() {
        return Err(());
    }

    // Build the frame in kernel memory then copy out.
    let mut frame = RtSigFrame::default();

    // siginfo
    frame.info.si_signo = signo as i32;
    frame.info.si_errno = 0;
    frame.info.si_code = SI_USER;
    // si_pid/si_uid follow at offset 16 (after si_signo,si_errno,si_code).
    // The C kernel layout is: int signo; int errno; int code; int pid; int uid; ...
    // pad starts at byte 12; pid at byte 16, uid at byte 20.
    let sender_pid: i32 = crate::task::current_pid();
    let pad = &mut frame.info._pad;
    pad[16 - 12..16 - 12 + 4].copy_from_slice(&sender_pid.to_le_bytes());
    pad[20 - 12..20 - 12 + 4].copy_from_slice(&0i32.to_le_bytes()); // uid

    // ucontext
    frame.uc.uc_flags = 0;
    frame.uc.uc_link = 0;
    // Fill uc_stack from current altstack (best-effort).
    if let Some(ast) = *task.signals.altstack.lock() {
        frame.uc.uc_stack.ss_sp = ast.ss_sp as u64;
        frame.uc.uc_stack.ss_flags = ast.ss_flags;
        frame.uc.uc_stack.ss_size = ast.ss_size as u64;
    }
    frame.uc.uc_mcontext.regs = copy_tf_to_gregs(tf);
    // fpregs already zeroed.
    let old_mask = task.signals.mask.load(Ordering::SeqCst);
    frame.uc.uc_sigmask.bits = old_mask;

    // Copy out the frame.
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &frame as *const _ as *const u8,
            SIGFRAME_SIZE,
        )
    };
    if task.copy_out_bytes(frame_addr, bytes).is_none() {
        return Err(());
    }

    // If rt_sigsuspend installed a temporary mask, the frame should
    // remember the *pre-sigsuspend* mask so sigreturn restores that.
    {
        let mut saved = task.signals.saved_mask.lock();
        if let Some(prev) = saved.take() {
            // Overwrite uc_sigmask in the frame we just wrote, with the
            // pre-sigsuspend mask.
            let sigmask_off =
                size_of::<KSigInfo>() // siginfo
                + 8                   // uc_flags
                + 8                   // uc_link
                + size_of::<KStackT>() // uc_stack
                + size_of::<KMContext>(); // uc_mcontext
            let _ = task.copy_out_bytes(
                frame_addr + sigmask_off,
                &prev.to_le_bytes(),
            );
            // saved was take()'d -- after sigreturn handler we're back to prev.
        } else {
            *saved = Some(old_mask);
        }
    }

    // Update the blocked-signal mask: add (act.mask | {signo unless SA_NODEFER}).
    let mut new_mask = old_mask | (act.mask & !unblockable_mask());
    if (act.flags & SA_NODEFER) == 0 {
        new_mask |= sigbit(signo);
    }
    task.signals.mask.store(new_mask & !unblockable_mask(), Ordering::SeqCst);

    // SA_RESETHAND: revert this signal's action to DFL after delivery.
    if (act.flags & SA_RESETHAND) != 0 {
        let mut acts = task.signals.actions.lock();
        acts[signo as usize] = KSigAction::default();
    }

    // Patch TF: sp, sepc, a0/a1/a2, ra.
    tf.x[1] = frame_addr;                 // sp
    tf.sepc = act.handler;
    tf.x[9] = signo as usize;             // a0
    tf.x[10] = frame_addr;                // a1 (siginfo*) — same as frame base
    tf.x[11] = frame_addr + size_of::<KSigInfo>(); // a2 (ucontext*)
    tf.x[0] = restorer;                   // ra

    // We don't try to roll back / restart the in-flight syscall. POSIX
    // SA_RESTART would re-issue ecall by sepc -= 4 if the kernel had
    // returned -EINTR; we don't have EINTR plumbing yet, so handlers
    // returning into a blocking syscall just won't be interrupted.

    Ok(())
}

// ----- rt_sigreturn -----

/// Pop the rt_sigframe from `tf.sp` and restore tf + sig_mask. Returns
/// the value to leave in `a0` (which is `tf.x[9]`); per Linux ABI this
/// is the saved `a0` from before the signal, restored from the frame.
pub fn do_sigreturn(task: &Arc<Task>, tf: &mut TrapFrame) -> isize {
    let frame_addr = tf.x[1];

    // Read the frame back.
    let Some(bytes) = task.copy_in_bytes(frame_addr, SIGFRAME_SIZE) else {
        crate::println!(
            "[sigreturn] pid={} EFAULT reading frame at {:#x}",
            task.pid, frame_addr
        );
        // Can't recover -- terminate.
        deliver_default_terminate(task, SIGSEGV as i32, true);
        return -14;
    };

    let frame = unsafe { core::ptr::read(bytes.as_ptr() as *const RtSigFrame) };

    // Restore TF GPRs + pc.
    restore_tf_from_gregs(tf, &frame.uc.uc_mcontext.regs);

    // Restore sig_mask.
    let mask = frame.uc.uc_sigmask.bits & !unblockable_mask();
    task.signals.mask.store(mask, Ordering::SeqCst);
    *task.signals.saved_mask.lock() = None;

    // The a0 in `tf` was just restored from gregs (a0 == saved). Return
    // that as the syscall result (caller will skip the usual `tf.x[9] = ret`
    // path).
    tf.x[9] as isize
}
