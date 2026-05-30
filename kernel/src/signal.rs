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
//!             uc_flags    : u64                         @ 0
//!             uc_link     : *ucontext (we leave 0)      @ 8
//!             uc_stack    : stack_t (24 bytes)          @ 16
//!             uc_sigmask  : sigset_t (8 + 128 pad)      @ 40
//!             uc_mcontext : sigcontext { gregs[32], fpregs(528) } @ 176
//!           }
//!   sp_high ──────────────────────────────────
//!
//! uc_mcontext MUST start at byte 176 — musl/glibc SA_SIGINFO handlers
//! (notably pthread_cancel's) read+write the saved PC there. A const
//! offset_of assert below enforces it. On rt_sigreturn we restore tf
//! from `gregs` and sig_mask from uc_sigmask.

use alloc::sync::Arc;
use core::mem::size_of;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

pub type SigActions = [KSigAction; (NSIG + 1) as usize];

use crate::arch::TrapFrame;
use crate::mm::memory_set::MemorySet;
use crate::mm::VirtAddr;
use crate::task::{Task, TaskState};

/// Virtual address at which we install the per-process signal-restorer
/// page. Lives above the 8 MiB user stack (top = 0x4000_0000) and well
/// below the dynamic-linker base (0x10_0000_0000).
pub const SIG_RESTORER_VA: usize = 0x5000_0000;

/// Build a 4 KiB page whose first 8 bytes are the `rt_sigreturn` (139)
/// trampoline for the target ISA. The kernel points a returning signal
/// handler's `ra` here; on return it issues rt_sigreturn. The two
/// instructions are architecture-specific machine code.
fn restorer_page_bytes() -> [u8; 4096] {
    let mut buf = [0u8; 4096];
    // riscv64: `li a7, 139` (0x08b00893) ; `ecall` (0x00000073)
    #[cfg(target_arch = "riscv64")]
    let insns: [u32; 2] = [0x08b00893, 0x00000073];
    // loongarch64: `li.w $a7, 139` (0x03822c0b) ; `syscall 0` (0x002b0000)
    #[cfg(target_arch = "loongarch64")]
    let insns: [u32; 2] = [0x03822c0b, 0x002b0000];
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
/// Sent by tkill(2)/tgkill(2). glibc's pthread_cancel / setxid handlers
/// require this in `si_code`.
pub const SI_TKILL: i32 = -6;

/// First realtime signal number. glibc reserves SIGRTMIN (32) = SIGCANCEL
/// and 33 = SIGSETXID for its internal pthread machinery, both delivered
/// via tgkill (hence SI_TKILL).
pub const SIGRTMIN: u32 = 32;

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
    /// Per-signal siginfo source captured at `raise_signal` time: the
    /// `(si_code, si_pid)` the SA_SIGINFO handler will observe. Indexed by
    /// signo (0 unused). Defaults to (SI_USER, 0). glibc's pthread_cancel /
    /// __nptl_setxid SIGCANCEL/SIGSETXID handlers reject the signal unless
    /// `si_code == SI_TKILL` and `si_pid == getpid()`, so the kill-family
    /// syscalls must hand the *sender's* identity through to delivery.
    pub siginfo: Mutex<[SigSource; (NSIG + 1) as usize]>,
}

/// `(si_code, si_pid)` captured when a signal is raised.
#[derive(Clone, Copy)]
pub struct SigSource {
    pub code: i32,
    pub pid: i32,
}
impl Default for SigSource {
    fn default() -> Self {
        Self { code: SI_USER, pid: 0 }
    }
}

impl SignalState {
    pub fn new() -> Self {
        Self {
            actions: Arc::new(Mutex::new([KSigAction::default(); (NSIG + 1) as usize])),
            mask: AtomicU64::new(0),
            pending: AtomicU64::new(0),
            altstack: Mutex::new(None),
            saved_mask: Mutex::new(None),
            siginfo: Mutex::new([SigSource::default(); (NSIG + 1) as usize]),
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
            siginfo: Mutex::new([SigSource::default(); (NSIG + 1) as usize]),
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
            siginfo: Mutex::new([SigSource::default(); (NSIG + 1) as usize]),
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
        *self.siginfo.lock() = [SigSource::default(); (NSIG + 1) as usize];
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

    // Record the siginfo source the handler will see. The realtime signals
    // (>= SIGRTMIN = 32) are glibc's internal pthread machinery, always
    // delivered via tgkill, whose handlers (sigcancel_handler /
    // __nptl_setxid_sighandler) demand `si_code == SI_TKILL` and
    // `si_pid == getpid()`. We supply SI_TKILL + the process TGID for
    // those; standard signals keep the existing SI_USER/0 behaviour (no
    // current consumer reads their si_code). Self-directed signals — which
    // is every case glibc's cancel handler accepts — have sender TGID ==
    // target TGID, so the target's tgid is the right si_pid.
    {
        let code = if signo >= SIGRTMIN { SI_TKILL } else { SI_USER };
        let pid = target.tgid.load(Ordering::Relaxed);
        target.signals.siginfo.lock()[signo as usize] = SigSource { code, pid };
    }

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
    // SIGKILL cascades to the entire descendant tree. POSIX-strict it
    // doesn't, but for the contest harness a wedged child outliving
    // its sh wrapper (iperf3 daemons that never reap, runtest.exe
    // forks that block on unimplemented syscalls) just sits in the
    // task table forever and the wall-clock budget evaporates against
    // it. Cascading SIGKILL collapses the orphan tree at the same
    // moment busybox-timeout fires its outer SIGKILL on sh.
    if signo == SIGKILL {
        // Fan SIGKILL out to every thread in the target's group. Threads are
        // siblings (they share the tgid) — NOT descendants — so the cascade
        // below misses them. A multithreaded case like ebizzy parks its
        // leader in pthread_join while worker threads spin in a tight
        // mmap/munmap loop; the leader re-blocks before it can ever deliver
        // the kill, and the running siblings otherwise never receive it, so
        // the process outlives the per-case timeout (and the loop eventually
        // exhausts memory). Posting SIGKILL to each sibling lets whichever
        // thread runs next terminate the whole group via check_signals ->
        // deliver_default_terminate.
        let tgid = target.tgid.load(Ordering::Relaxed);
        for t in crate::task::all_tasks() {
            if t.pid != target.pid && t.tgid.load(Ordering::Relaxed) == tgid {
                t.signals.pending.fetch_or(sigbit(SIGKILL), Ordering::SeqCst);
                {
                    let mut s = t.state.lock();
                    if *s == TaskState::Waiting {
                        *s = TaskState::Ready;
                    }
                }
                crate::sync::futex::interrupt_wait(t.pid);
            }
        }
        let target_pid = target.pid;
        let descendants = collect_descendants(target_pid);
        for d in descendants {
            d.signals.pending.fetch_or(sigbit(SIGKILL), Ordering::SeqCst);
            let mut s = d.state.lock();
            if *s == TaskState::Waiting {
                *s = TaskState::Ready;
            }
            drop(s);
            crate::sync::futex::interrupt_wait(d.pid);
        }
    }
    true
}

/// Linux `force_sig` semantics for a **synchronous, CPU-generated** fault
/// signal (SIGSEGV/SIGBUS/SIGILL raised from the trap handler). Such a
/// signal must never be silently lost: if the task has it blocked, or set
/// to SIG_IGN, a plain `raise_signal` leaves it undeliverable and the trap
/// handler sret's back to the faulting instruction, which faults again —
/// forever (an unbounded InstructionPageFault storm). So:
///   * if the signal is currently blocked, or its disposition is SIG_IGN,
///     reset the disposition to SIG_DFL (forcing the default terminate/core
///     action — a process cannot mask away or ignore a fault it just took);
///   * unblock it so `pick_signal` will select it on the trap-return scan;
///   * post it.
/// An installed, *unblocked* handler is left intact and delivered once. If
/// that handler returns to the faulting PC and re-faults, the signal is by
/// then blocked (masked during its own handler), so this routine forces the
/// default on the second fault — the process always terminates instead of
/// looping. Mirrors how Linux refuses to let a task evade a synchronous
/// fault via SIG_IGN / a blocked mask.
pub fn force_fault_signal(task: &Arc<Task>, signo: u32) {
    if !is_valid_signo(signo) {
        return;
    }
    let bit = sigbit(signo);
    let blocked = (task.signals.mask.load(Ordering::SeqCst) & bit) != 0;
    {
        let mut acts = task.signals.actions.lock();
        let slot = &mut acts[signo as usize];
        if blocked || slot.handler == SIG_IGN {
            *slot = KSigAction::default(); // -> SIG_DFL (terminate/core)
        }
    }
    // Unblock so the pending signal is deliverable on the next pick_signal.
    task.signals.mask.fetch_and(!bit, Ordering::SeqCst);
    let _ = raise_signal(task, signo);
}

fn collect_descendants(root_pid: i32) -> alloc::vec::Vec<Arc<crate::task::Task>> {
    let all = crate::task::all_tasks();
    let mut included: alloc::collections::BTreeSet<i32> =
        alloc::collections::BTreeSet::new();
    included.insert(root_pid);
    // Fixed-point: include any task whose ppid is already in the set.
    // Linear passes are fine — task counts are tiny.
    loop {
        let before = included.len();
        for t in &all {
            let ppid = t.ppid.load(Ordering::Relaxed);
            if included.contains(&ppid) {
                included.insert(t.pid);
            }
        }
        if included.len() == before { break; }
    }
    included.remove(&root_pid);
    all.into_iter().filter(|t| included.contains(&t.pid)).collect()
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

/// sigset region of the ucontext. The active mask is `bits` (offset 0 of
/// this struct). On riscv64 Linux the ucontext is laid out so that
/// `uc_mcontext` begins at byte 176: uc_flags(8) + uc_link(8) +
/// uc_stack(24) = 40, then this sigset region occupies 136 bytes
/// (40 + 136 = 176). musl/glibc read+write the live mask at offset 40
/// and the saved mcontext (incl. PC) at offset 176, so this padding is
/// load-bearing — the pthread_cancel handler reads the interrupted PC
/// from 176(ucontext) and writes the redirect target back there.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KSigSet {
    pub bits: u64,
    pub _pad: [u8; 128],
}
impl Default for KSigSet {
    fn default() -> Self { Self { bits: 0, _pad: [0u8; 128] } }
}

/// What the kernel writes for `struct ucontext` on the rt_sigframe.
/// Matches Linux generic ucontext (asm-generic/ucontext.h) field order:
/// uc_sigmask comes BEFORE uc_mcontext, and the sigset padding places
/// uc_mcontext at offset 176 (the offset musl's SA_SIGINFO handlers
/// hardcode for the saved register file).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct KUContext {
    pub uc_flags: u64,
    pub uc_link: u64,
    pub uc_stack: KStackT,
    pub uc_sigmask: KSigSet,
    pub uc_mcontext: KMContext,
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

// Lock the ABI: musl/glibc SA_SIGINFO handlers read the saved register
// file (and PC) from offset 176 of the ucontext. If this ever drifts,
// pthread_cancel / swapcontext silently break, so fail the build instead.
const _: () = {
    assert!(core::mem::offset_of!(KUContext, uc_mcontext) == 176);
    assert!(core::mem::offset_of!(KUContext, uc_sigmask) == 40);
};

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

// Sigcontext save / restore is the riscv64 register-name dance, so it
// lives on TrapFrame itself (in arch/riscv64/trap.rs). These two thin
// wrappers preserve the old call sites.

fn copy_tf_to_gregs(tf: &TrapFrame) -> KGRegs {
    let mut g = KGRegs::default();
    tf.save_to_sigcontext(&mut g);
    g
}

fn restore_tf_from_gregs(tf: &mut TrapFrame, g: &KGRegs) {
    tf.restore_from_sigcontext(g);
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
                    // PID 1 (init) is immune to signals left at their default
                    // action, exactly as Linux protects init. A test that
                    // broadcasts to its process group via kill(0)/kill(-1) (the
                    // cpu-controller cases fire SIGUSR1 at their workers) must
                    // never be able to terminate the reaper of last resort —
                    // a dead init leaves unreapable zombies and wedges the run.
                    if task.pid == 1 {
                        continue;
                    }
                    deliver_default_terminate(task, signo as i32, false);
                    return true;
                }
                DefaultAction::Core => {
                    if task.pid == 1 {
                        continue;
                    }
                    deliver_default_terminate(task, signo as i32, true);
                    return true;
                }
            }
        }

        // EINTR plumbing: if the task is parked in an interruptible
        // blocking syscall (sepc rewound to the ecall) and this handler is
        // NOT SA_RESTART, un-rewind past the ecall and make the syscall
        // return -EINTR. After the handler's sigreturn, userspace observes
        // the interrupted syscall instead of silently re-blocking. With
        // SA_RESTART, leave sepc rewound so the syscall restarts.
        if task
            .in_blocking_syscall
            .swap(false, Ordering::Relaxed)
            && (act.flags & SA_RESTART) == 0
        {
            tf.advance_past_syscall();
            tf.set_syscall_ret((-4isize) as usize); // -EINTR
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
    if crate::syscall::syscall_trace_enabled() {
        crate::println!(
            "[exit] pid={} killed by signal {}{}",
            task.pid, signo, if core { " (core)" } else { "" },
        );
    }

    // POSIX: a fatal unhandled signal terminates the *whole* thread
    // group, not just one thread. Walk the tgid and zombie-fy any
    // siblings, and wake any pthread_join that was futex-waiting on
    // their ctid.
    let tgid = task.tgid.load(Ordering::Relaxed);
    for sib in crate::task::all_tasks() {
        if sib.tgid.load(Ordering::Relaxed) != tgid || sib.pid == task.pid {
            continue;
        }
        if *sib.state.lock() == TaskState::Zombie {
            continue;
        }
        sib.exit_code.store(status, Ordering::Relaxed);
        *sib.state.lock() = TaskState::Zombie;
        // CLONE_CHILD_CLEARTID: zero the ctid and wake one waiter so
        // pthread_join unblocks.
        let ctid = *sib.clear_child_tid.lock();
        if ctid != 0 {
            let _ = sib.copy_out_bytes(ctid, &[0u8; 4]);
            let _ = crate::sync::futex::wake_for_task(&sib, ctid, 1);
        }
        crate::sync::futex::forget_task(sib.pid);
    }

    // Notify parent (SIGCHLD + wake from wait4). Use the group leader
    // as the SIGCHLD target since a thread dying isn't normally
    // observable, but the leader's death is.
    let leader_pid = tgid;
    let notify_from = if leader_pid != task.pid {
        crate::task::task_by_pid(leader_pid).unwrap_or_else(|| task.clone())
    } else {
        task.clone()
    };
    let ppid = notify_from.ppid.load(Ordering::Relaxed);
    if let Some(parent) = crate::task::task_by_pid(ppid) {
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
    // Restorer (the `ra` the handler returns to). riscv musl/glibc both
    // leave SA_RESTORER unset, so we supply one. We use the vDSO's
    // `__vdso_rt_sigreturn` rather than the bare SIG_RESTORER_VA page: its
    // body is identical (`li a7,139; ecall`), but its PC carries
    // `.cfi_signal_frame` CFI, which is what glibc's pthread_cancel forced
    // unwind needs to step across this signal frame. musl is unaffected
    // (it just rt_sigreturns from there as before). If the app explicitly
    // installed its own restorer, honour it.
    let restorer = if act.restorer != 0 {
        act.restorer
    } else {
        // riscv64: the vDSO's __vdso_rt_sigreturn (same `li a7,139; ecall`
        // body but with .cfi_signal_frame CFI for glibc's forced unwind).
        #[cfg(target_arch = "riscv64")]
        {
            crate::vdso::sigreturn_entry()
        }
        // loongarch64: the embedded vDSO is a RISC-V image, so use the
        // per-process LA restorer page (`li.w $a7,139; syscall 0`).
        #[cfg(target_arch = "loongarch64")]
        {
            SIG_RESTORER_VA
        }
    };

    // Compute the sp for the handler. If SA_ONSTACK and an enabled
    // altstack exists and we're not already on it, switch.
    let mut new_sp = tf.user_sp();
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

    // siginfo. si_code + si_pid come from the source recorded when the
    // signal was raised (see raise_signal). For glibc's SIGCANCEL the
    // handler insists on si_code == SI_TKILL && si_pid == getpid(); a
    // hardcoded SI_USER here made it ignore the cancel and the canceled
    // thread spun forever (pthread_join hang).
    let src = task.signals.siginfo.lock()[signo as usize];
    frame.info.si_signo = signo as i32;
    frame.info.si_errno = 0;
    frame.info.si_code = src.code;
    // si_pid/si_uid follow at offset 16 (after si_signo,si_errno,si_code).
    // The C kernel layout is: int signo; int errno; int code; int pid; int uid; ...
    // pad starts at byte 12; pid at byte 16, uid at byte 20.
    let pad = &mut frame.info._pad;
    pad[16 - 12..16 - 12 + 4].copy_from_slice(&src.pid.to_le_bytes());
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
                + size_of::<KStackT>(); // uc_stack (uc_sigmask now precedes uc_mcontext)
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

    // Patch TF: sp, PC, a0/a1/a2, ra in one architecture-agnostic call.
    tf.enter_signal_handler(
        act.handler,
        restorer,
        frame_addr,
        signo,
        frame_addr,                                // siginfo* = frame base
        frame_addr + size_of::<KSigInfo>(),        // ucontext* = right after siginfo
    );

    // EINTR / SA_RESTART for an interrupted blocking syscall is handled by
    // the caller (`check_signals`, via `in_blocking_syscall`): without
    // SA_RESTART it steps the syscall PC past the ecall and sets the
    // return slot to -EINTR before we get here, so the handler's
    // sigreturn lands on the post-ecall instruction with the interrupted
    // return value.

    Ok(())
}

// ----- rt_sigreturn -----

/// Pop the rt_sigframe from the user sp and restore tf + sig_mask.
/// Returns the value to place in the syscall return slot — per Linux ABI
/// this is the saved a0 from before the signal, restored from the frame.
pub fn do_sigreturn(task: &Arc<Task>, tf: &mut TrapFrame) -> isize {
    let frame_addr = tf.user_sp();

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

    // The syscall ret slot was just restored from gregs (== saved a0).
    // Return it so the caller can short-circuit the usual ret-write path.
    tf.syscall_ret() as isize
}
