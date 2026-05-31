//! Tasks + cooperative scheduler (M5 part 2).
//!
//! Layout: each Task owns a kstack buffer with the per-task TrapFrame
//! at the top. The trap handler swaps `sscratch` with the current
//! task's `kstack_top`, so all kernel work for that task happens on
//! the kstack just below the TF.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering};
use crate::sync::Mutex; use spin::Lazy;

use crate::arch::TrapFrame;
use crate::loader::LoadedElf;
use crate::mm::memory_set::{MemorySet, VmArea, VmPerm};
use crate::mm::{VirtAddr, PAGE_SIZE};

const KSTACK_SIZE: usize = 64 * 1024;

#[repr(C, align(16))]
struct TaskStorage {
    buf: [u8; KSTACK_SIZE],
    /// Parked kernel context (callee-saved regs + kernel sp) for the preemptive
    /// scheduler. Holds where this task last `__switch`ed out — empty/`init`ed
    /// to a first-run trampoline for a task that has never run.
    kctx: crate::arch::TaskContext,
    /// loongarch64 vector-unit (FP/LSX/LASX) save slot. The kernel is
    /// soft-float, so a preempted task's live vector registers must be
    /// parked here while another task runs (see `context_switch_to`).
    #[cfg(target_arch = "loongarch64")]
    fp: crate::arch::loongarch64::fpu::FpContext,
}

impl TaskStorage {
    fn boxed() -> Box<Self> {
        Box::new(Self {
            buf: [0u8; KSTACK_SIZE],
            kctx: crate::arch::TaskContext::new(),
            #[cfg(target_arch = "loongarch64")]
            fp: crate::arch::loongarch64::fpu::FpContext::new(),
        })
    }

    /// Fallible kstack allocation. A fork/thread storm deep into the LTP run
    /// can exhaust the kernel heap; clone must then fail with EAGAIN, never
    /// trip the infallible `Box::new` and panic the whole kernel.
    fn try_boxed() -> Option<Box<Self>> {
        let layout = core::alloc::Layout::new::<Self>();
        // SAFETY: layout has non-zero size (KSTACK_SIZE > 0). alloc_zeroed
        // returns null on failure, which we surface as None.
        unsafe {
            let ptr = alloc::alloc::alloc_zeroed(layout) as *mut Self;
            if ptr.is_null() {
                None
            } else {
                Some(Box::from_raw(ptr))
            }
        }
    }

    fn kstack_top(&self) -> usize {
        self.buf.as_ptr() as usize + KSTACK_SIZE
    }

    fn tf_ptr(&self) -> *mut TrapFrame {
        (self.kstack_top() - size_of::<TrapFrame>()) as *mut TrapFrame
    }

    fn kctx_ptr(&self) -> *mut crate::arch::TaskContext {
        &self.kctx as *const _ as *mut _
    }

    #[cfg(target_arch = "loongarch64")]
    fn fp_ptr(&self) -> *mut crate::arch::loongarch64::fpu::FpContext {
        &self.fp as *const _ as *mut _
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskState {
    Ready,
    Running,
    /// Blocked waiting for any child to exit.
    Waiting,
    Zombie,
}

pub struct Task {
    pub pid: i32,
    /// Thread-group leader pid. Equals `pid` for process leaders; for threads
    /// (CLONE_THREAD), this is the creator's tgid. `getpid()` returns this.
    pub tgid: AtomicI32,
    pub ppid: AtomicI32,
    pub pgid: AtomicI32,
    pub sid: AtomicI32,
    storage: UnsafeCell<Box<TaskStorage>>,
    /// Address space. Wrapped in Arc so CLONE_VM threads share the same one.
    pub memory_set: Arc<Mutex<MemorySet>>,
    /// File-descriptor table. Wrapped in Arc so CLONE_FILES threads share it.
    pub fd_table: Arc<Mutex<crate::fs::FdTable>>,
    /// Working directory. Wrapped in Arc so CLONE_FS threads share it.
    pub cwd: Arc<Mutex<String>>,
    pub state: Mutex<TaskState>,
    pub exit_code: AtomicI32,
    /// Signal delivered to the parent when this task (a process leader) exits.
    /// SIGCHLD for fork; a clone/clone3 may request another (clone301 uses
    /// SIGUSR2); 0 means none (a CLONE_THREAD member).
    pub exit_signal: AtomicI32,
    pub children: Mutex<Vec<i32>>,
    /// argv joined with NUL separators, NUL terminated. Used by /proc/<pid>/cmdline.
    pub cmdline: Mutex<Vec<u8>>,
    /// Absolute path to the executable image. Used by /proc/<pid>/exe and /comm.
    pub exe_path: Mutex<String>,
    pub signals: crate::signal::SignalState,
    /// `clone(..., CLONE_CHILD_CLEARTID, ...)` — when this task exits we
    /// write 0 to *addr and `futex_wake(addr, 1)`. Set by `set_tid_address`
    /// and by CLONE_CHILD_CLEARTID. 0 = disabled.
    pub clear_child_tid: Mutex<usize>,
    /// `clone(CLONE_VFORK)` parent suspension. POSIX vfork blocks the parent
    /// until the child either calls execve (gets its own address space) or
    /// exits. Without this, parent + child race on the shared stack and
    /// parent reads back garbage values for variables it held there (e.g.
    /// busybox `timeout`'s saved child pid).
    /// Holds Some(child_pid) while waiting; cleared when child exec's/exits.
    pub vfork_child: Mutex<Option<i32>>,
    /// For genuine pthreads (CLONE_VM|CLONE_THREAD): the user stack pointer
    /// handed to `clone` (top of the thread's mmap'd stack). When such a
    /// thread exits, the exit path queues this address for *deferred* reclaim
    /// on the shared address space (freed at the next thread creation, after
    /// any pending join has read the descriptor). This stops never-joined
    /// thread stacks from piling up (e.g. libc-bench's
    /// `b_pthread_create_serial1` spawns 2500 — without reclaim,
    /// /proc/self/smaps balloons to thousands of regions and reading it in
    /// print_stats becomes quadratic). 0 = not a reclaimable thread stack.
    pub thread_stack_top: AtomicUsize,
    /// Set while the task is parked in an *interruptible* blocking syscall
    /// (recv/accept/poll/... via `block_and_retry`, nanosleep, etc.) with
    /// sepc rewound to the ecall. If a signal handler is then delivered,
    /// the delivery path turns the in-flight syscall into -EINTR (unless
    /// the handler is SA_RESTART) so userspace can observe the
    /// interruption — netperf's CRR loop, for one, only checks its
    /// times-up flag after its blocking recv returns. Cleared at the
    /// start of every syscall.
    pub in_blocking_syscall: AtomicBool,
}

unsafe impl Send for Task {}
unsafe impl Sync for Task {}

impl Task {
    pub fn tf_ptr(&self) -> *mut TrapFrame {
        unsafe { (*self.storage.get()).tf_ptr() }
    }

    pub fn kstack_top(&self) -> usize {
        unsafe { (*self.storage.get()).kstack_top() }
    }

    /// Pointer to this task's parked kernel context (for `__switch`).
    pub fn kctx_ptr(&self) -> *mut crate::arch::TaskContext {
        unsafe { (*self.storage.get()).kctx_ptr() }
    }

    /// Prime this task's kernel context so the scheduler's first `__switch`
    /// into it lands in the first-run trampoline (then enters user mode via
    /// the normal trap-return path). Stack is the task's kstack just below its
    /// TrapFrame — the same region a syscall handler would use.
    pub fn init_kctx_for_first_run(&self) {
        let sp = self.tf_ptr() as usize;
        unsafe { (*self.storage.get()).kctx.init(task_first_run as usize, sp); }
    }

    /// loongarch64: pointer to this task's parked vector-unit state.
    #[cfg(target_arch = "loongarch64")]
    pub fn fp_ptr(&self) -> *mut crate::arch::loongarch64::fpu::FpContext {
        unsafe { (*self.storage.get()).fp_ptr() }
    }

    pub fn copy_in_bytes(&self, va: usize, len: usize) -> Option<Vec<u8>> {
        let ms = self.memory_set.lock();
        copy_in_via(&ms, va, len)
    }

    pub fn copy_out_bytes(&self, va: usize, bytes: &[u8]) -> Option<()> {
        let ms = self.memory_set.lock();
        copy_out_via(&ms, va, bytes)
    }

    pub fn memory_set_mut(&self) -> crate::sync::MutexGuard<'_, MemorySet> {
        self.memory_set.lock()
    }

    /// True if this task shares its address space with at least one other
    /// task (via CLONE_VM). Used by `schedule_next_after_trap` to skip the
    /// satp write + sfence on intra-tgid context switches.
    pub fn vm_shared(&self) -> bool {
        Arc::strong_count(&self.memory_set) > 1
    }
}

pub fn copy_in_via(ms: &MemorySet, va: usize, len: usize) -> Option<Vec<u8>> {
    // Fallible reserve: a user can pass a gigantic count to write()/writev()
    // etc.; allocating it unconditionally panics the kernel via the alloc
    // error handler. Fail the copy (caller maps None -> EFAULT) instead.
    let mut out = Vec::new();
    out.try_reserve_exact(len).ok()?;
    let mut cursor = va;
    let end = va.checked_add(len)?;
    while cursor < end {
        let page_va = cursor & !(PAGE_SIZE - 1);
        let page_off = cursor & (PAGE_SIZE - 1);
        let chunk = core::cmp::min(PAGE_SIZE - page_off, end - cursor);
        // Honor the declared region protection: a read from a PROT_NONE
        // guard page (covered by an area with no R bit) is EFAULT, even
        // though the page is mapped R|W at the PTE level. If a VmArea
        // covers the page it must grant R; if none covers it we fall through
        // to translate() (kernel-internal mappings have no VmArea).
        if let Some(p) = ms.perm_at(VirtAddr(page_va)) {
            if !p.contains(VmPerm::R) {
                return None;
            }
        }
        let pa = ms.translate(VirtAddr(page_va))?;
        let src = unsafe {
            let ptr = crate::mm::PhysAddr(pa.0 + page_off).kernel_ptr::<u8>();
            core::slice::from_raw_parts(ptr as *const u8, chunk)
        };
        out.extend_from_slice(src);
        cursor += chunk;
    }
    Some(out)
}

pub fn copy_out_via(ms: &MemorySet, va: usize, bytes: &[u8]) -> Option<()> {
    let mut written = 0usize;
    let end = va.checked_add(bytes.len())?;
    let mut cursor = va;
    while cursor < end {
        let page_va = cursor & !(PAGE_SIZE - 1);
        let page_off = cursor & (PAGE_SIZE - 1);
        let chunk = core::cmp::min(PAGE_SIZE - page_off, end - cursor);
        // Honor the declared region protection: a write to a PROT_NONE
        // (or read-only) area is EFAULT, which is what LTP's tst_get_bad_addr
        // (a 1-byte PROT_NONE mmap) relies on for clock_gettime02, capget02,
        // and the many other "bad pointer => EFAULT" subtests. The page may
        // be mapped R|W at the PTE level (so the owning process's own
        // reserve-then-write still works); we reject based on the *declared*
        // VmArea perm. No covering area -> fall through to translate().
        if let Some(p) = ms.perm_at(VirtAddr(page_va)) {
            if !p.contains(VmPerm::W) {
                return None;
            }
        }
        let pa = ms.translate(VirtAddr(page_va))?;
        let dst = unsafe {
            let ptr = crate::mm::PhysAddr(pa.0 + page_off).kernel_ptr::<u8>();
            core::slice::from_raw_parts_mut(ptr, chunk)
        };
        dst.copy_from_slice(&bytes[written..written + chunk]);
        written += chunk;
        cursor += chunk;
    }
    Some(())
}

// ----- Task table + scheduler -----

static NEXT_PID: AtomicI32 = AtomicI32::new(1);
fn alloc_pid() -> i32 {
    NEXT_PID.fetch_add(1, Ordering::Relaxed)
}

pub struct TaskTable {
    pub tasks: BTreeMap<i32, Arc<Task>>,
}

static TABLE: Lazy<Mutex<TaskTable>> = Lazy::new(|| {
    Mutex::new(TaskTable {
        tasks: BTreeMap::new(),
    })
});

static CURRENT_PID: AtomicI32 = AtomicI32::new(0);

pub fn current_pid() -> i32 {
    CURRENT_PID.load(Ordering::Relaxed)
}

/// True when there is a live current task that `current_task()` can return
/// without panicking. Used by the trap handler to decide whether a kernel-mode
/// fault is recoverable (kill the task) or fatal (no task to blame -> panic).
pub fn has_current_task() -> bool {
    let pid = CURRENT_PID.load(Ordering::Relaxed);
    pid != 0 && TABLE.lock().tasks.contains_key(&pid)
}

/// Recovery prep for a kernel-mode fault: the faulting operation is abandoned
/// without unwinding (no_std has no unwinding), so any spin-lock it held is
/// stuck locked forever. On this single-hart kernel the only possible holder
/// of these locks is the faulting stack itself, so force-releasing them is
/// safe and is the only way the recovery path (which re-locks TABLE etc.) can
/// proceed instead of deadlocking. Call this BEFORE any other task API in the
/// trap handler's recover-by-kill path.
///
/// # Safety
/// Must only be called from the trap handler when abandoning a faulted
/// kernel operation on a single hart.
pub unsafe fn force_release_locks_after_fault() {
    // The abandoned stack's lock guards will never run their destructors, so
    // the preemption-disable count they bumped would otherwise leak upward and
    // wedge preemption off forever. Zero it — we are force-releasing the locks
    // and switching to a fresh task anyway.
    crate::sync::preempt_reset();
    TABLE.force_unlock();
    // The abandoned operation may also be holding the *current task's own*
    // per-process locks — e.g. a syscall that wedged or faulted mid fd-table
    // walk (LTP pipe07 opens ~1020 pipes and wedges inside fd allocation) or
    // mid page-table edit. The recovery path that follows (kill_now ->
    // release_user_resources) re-locks exactly fd_table and memory_set to
    // close fds and free frames; if the dead stack still holds either, that
    // re-lock self-deadlocks — in the trap handler, not an armed syscall, so
    // even the watchdog can't recover and the machine hangs. On this single
    // hart the abandoned stack is the only possible holder, so force-release
    // them (and state, which kill_now flips to Zombie) before re-locking.
    let pid = CURRENT_PID.load(Ordering::Relaxed);
    if let Some(task) = TABLE.lock().tasks.get(&pid).cloned() {
        task.memory_set.force_unlock();
        task.fd_table.force_unlock();
        task.state.force_unlock();
    }
}

// ---- In-kernel watchdog -------------------------------------------------
//
// This single-hart kernel historically ran syscalls with interrupts disabled,
// so a syscall that loops or blocks in-kernel without yielding could never be
// preempted: the periodic timer never fired, no other task ran (not even the
// busybox `timeout` daemon meant to kill the case), and the machine wedged
// until the grader's global cap — throwing away every case after the wedge.
// The reference kernel keeps interrupts ENABLED during syscall handling and
// reschedules preemptively; we keep the cooperative scheduler but enable the
// timer for the duration of `dispatch` (see each arch's trap handler) so this
// watchdog can observe wall-clock progress from a nested timer tick. If a
// syscall holds the hart in-kernel past WATCHDOG_BUDGET_SECS it is presumed
// wedged and abandoned via the same recovery path a kernel fault uses
// (force-release the table lock the dead stack may hold, kill the task, let
// the scheduler pick another) — so one bad case can never block the whole run.

/// Continuous in-kernel time after which a syscall is presumed wedged. Far
/// above any legitimate syscall (even a heavy fork/exec or fs sync finishes in
/// well under a second) yet far below the grader's per-run cap, so it fires
/// only on a genuine uninterruptible wedge, never on a slow-but-correct call.
const WATCHDOG_BUDGET_SECS: u64 = 8;

/// `now_ticks()` captured when the current task entered its current syscall.
static WATCHDOG_ANCHOR: AtomicU64 = AtomicU64::new(0);
/// Whether a syscall is currently being timed (set between arm and disarm).
static WATCHDOG_ARMED: AtomicBool = AtomicBool::new(false);

/// Start timing the current syscall. Called at syscall entry, just before the
/// timer is enabled for the dispatch window.
#[inline]
pub fn watchdog_arm() {
    WATCHDOG_ANCHOR.store(crate::arch::now_ticks(), Ordering::Relaxed);
    WATCHDOG_ARMED.store(true, Ordering::Relaxed);
}

/// Stop timing (the syscall returned). Idempotent.
#[inline]
pub fn watchdog_disarm() {
    WATCHDOG_ARMED.store(false, Ordering::Relaxed);
}

/// True once the in-flight syscall has held the hart longer than the budget.
/// Lock-free by construction: it touches only atomics and `now_ticks()`, never
/// a kernel lock, so it is safe to call from a nested timer trap that may have
/// interrupted code holding the task-table (or any other) lock.
#[inline]
pub fn watchdog_overrun() -> bool {
    if !WATCHDOG_ARMED.load(Ordering::Relaxed) {
        return false;
    }
    let elapsed =
        crate::arch::now_ticks().wrapping_sub(WATCHDOG_ANCHOR.load(Ordering::Relaxed));
    elapsed > WATCHDOG_BUDGET_SECS.saturating_mul(crate::arch::TICKS_PER_SEC)
}

/// Abandon the wedged current syscall and schedule another task. Mirrors the
/// kernel-fault recovery in the trap handlers: the looping kernel operation is
/// dropped without unwinding, so force-release the one global lock its dead
/// stack could be holding (TABLE) before re-locking it to kill the task. The
/// task's per-process resources are freed by `kill_now`; its abandoned kernel
/// stack is never resumed (it is now a Zombie). Returns the next task's frame.
///
/// # Safety
/// Call only from the trap handler's nested-timer watchdog path, on this
/// single hart, when `watchdog_overrun()` has just returned true.
pub unsafe fn watchdog_kill_current(current_tf: *mut TrapFrame) -> *mut TrapFrame {
    watchdog_disarm();
    unsafe { force_release_locks_after_fault(); }
    let pid = current_pid();
    if let Some(task) = task_by_pid(pid) {
        // Only act on a still-live task. If dispatch already zombified it
        // (e.g. a slow exit), re-killing would double-free its resources.
        let live = matches!(*task.state.lock(), TaskState::Ready | TaskState::Running);
        if live {
            crate::println!(
                "[watchdog] pid={} wedged in-kernel >{}s — killing the case so the run continues",
                pid, WATCHDOG_BUDGET_SECS,
            );
            crate::signal::kill_now(&task);
        }
    }
    schedule_next_after_trap(current_tf)
}

pub fn current_task() -> Arc<Task> {
    let pid = current_pid();
    TABLE
        .lock()
        .tasks
        .get(&pid)
        .expect("no current task")
        .clone()
}

pub fn install_task(task: Arc<Task>) {
    let pid = task.pid;
    TABLE.lock().tasks.insert(pid, task);
    CURRENT_PID.store(pid, Ordering::Relaxed);
}

pub fn task_by_pid(pid: i32) -> Option<Arc<Task>> {
    TABLE.lock().tasks.get(&pid).cloned()
}

/// Snapshot list of live pids. Used by procfs to list /proc.
pub fn all_pids() -> Vec<i32> {
    TABLE.lock().tasks.keys().copied().collect()
}

/// Snapshot of the next pid the allocator would hand out — a stand-in for
/// "processes ever created" used by /proc/stat.
pub fn next_pid_snapshot() -> i32 {
    NEXT_PID.load(Ordering::Relaxed)
}

/// Pick any task in Ready state (other than `exclude`) and mark it Running.
pub fn pick_ready(exclude: i32) -> Option<Arc<Task>> {
    let table = TABLE.lock();
    for (&pid, task) in table.tasks.iter() {
        if pid == exclude {
            continue;
        }
        let mut state = task.state.lock();
        if *state == TaskState::Ready {
            *state = TaskState::Running;
            return Some(task.clone());
        }
    }
    None
}

/// Mark a task Ready (e.g. after wake-from-wait).
pub fn make_ready(pid: i32) {
    if let Some(t) = task_by_pid(pid) {
        let mut s = t.state.lock();
        if *s != TaskState::Zombie {
            *s = TaskState::Ready;
        }
    }
}

pub fn reap(pid: i32) {
    TABLE.lock().tasks.remove(&pid);
    crate::sync::futex::forget_task(pid);
    forget_itimer(pid);
    crate::syscall::forget_creds(pid);
    crate::syscall::forget_sched(pid);
    crate::syscall::forget_timers(pid);
    crate::syscall::forget_personality(pid);
}

/// Reap orphan zombies — Zombie tasks whose parent is no longer in the table
/// (dead), so nobody will ever wait4() them. A killed fork-storm test (the
/// LTP cgroup `fork_processes`/`cgroup_regression_*` cases each fork or
/// mount in a tight infinite loop) leaves behind the children that were
/// in-flight when its `timeout` SIGKILL landed; those orphans pin kstack /
/// task slots forever. After ~the cgroup cluster the table is bloated enough
/// that later fork()s fail (ENOMEM) and every subsequent LTP case breaks
/// ("$(basename ...)" returns empty, tests can't spawn). On a normal init
/// these are reaped by pid 1; our contest `sh` loop only wait4()s its own
/// direct children, so reap them here. Capped per call so the sweep stays
/// cheap; the caller only invokes it when the table has grown large.
/// Trap counter to rate-limit the orphan-zombie sweep (see scheduler).
static REAP_SWEEP_TICK: AtomicU64 = AtomicU64::new(0);

/// Reparent an exiting task's still-live children to pid 1 (init), the way a
/// real kernel's `find_new_reaper` does. Without this, a test that is
/// SIGKILLed mid-run (timeout) leaves grandchildren whose parent pointer
/// dangles: nobody adds them to a living wait4'er's child list, so when they
/// become zombies no one reaps them and they pin frames/kstack until the pool
/// drains (the cumulative fork07 ENOMEM + scheduler livelock). Moving them to
/// pid 1 — the contest init, a proper reaper — lets them be collected
/// normally. This only rewrites ppid + child lists; it never kills a task.
pub fn reparent_children_to_init(dead_pid: i32) {
    const INIT_PID: i32 = 1;
    if dead_pid == INIT_PID {
        return;
    }
    let dead = match task_by_pid(dead_pid) {
        Some(t) => t,
        None => return,
    };
    // Take the dying task's child list.
    let kids: Vec<i32> = {
        let mut c = dead.children.lock();
        core::mem::take(&mut *c)
    };
    if kids.is_empty() {
        return;
    }
    let Some(init) = task_by_pid(INIT_PID) else { return };
    let mut init_kids = init.children.lock();
    for kid in kids {
        if let Some(k) = task_by_pid(kid) {
            k.ppid.store(INIT_PID, Ordering::Relaxed);
            init_kids.push(kid);
        }
    }
}

pub fn reap_orphan_zombies(except: i32) {
    // Snapshot (pid, ppid) and the live-pid set under the table lock, then
    // release it before touching per-task state locks (TABLE-then-state would
    // invert the scheduler's state-then-TABLE order).
    let (pairs, live): (Vec<(i32, i32)>, alloc::collections::BTreeSet<i32>) = {
        let t = TABLE.lock();
        let live = t.tasks.keys().copied().collect();
        let pairs = t
            .tasks
            .values()
            .map(|task| (task.pid, task.ppid.load(Ordering::Relaxed)))
            .collect();
        (pairs, live)
    };
    const INIT_PID: i32 = 1;
    let mut n = 0;
    for (pid, ppid) in pairs {
        if pid == except {
            continue; // never reap the caller
        }
        // Reap a Zombie if nobody will wait4 it: either its parent is gone
        // (true orphan), or its parent is init (pid 1) — orphans we reparented
        // to init are fire-and-forget; init never explicitly wait4()s the
        // grandchildren of a SIGKILLed test, so collect them here. A Zombie
        // whose parent is a *normal* live task is left alone (that parent's
        // own wait4 will reap it and read its status).
        let reapable_parent = ppid == INIT_PID || !live.contains(&ppid);
        if !reapable_parent {
            continue;
        }
        if let Some(task) = task_by_pid(pid) {
            let is_zombie = *task.state.lock() == TaskState::Zombie;
            drop(task);
            if is_zombie {
                reap(pid);
                n += 1;
                if n >= 64 {
                    break;
                }
            }
        }
    }
}

/// Last-resort livelock breaker: terminate ONE task that is blocked
/// (Waiting) with no living parent and which is NOT the caller. Used only by
/// the scheduler's wedged spin-loop after it has spun a long time making no
/// progress. A parentless Waiting task left by a SIGKILLed fork-storm can
/// never be woken (no init to reap it, its waiter is gone), so it pins
/// frames/kstack and keeps any_waiting() true forever. Killing it (SIGKILL
/// semantics → Zombie, frees user frames) lets the genuinely-blocked waiter
/// that depends on the freed memory proceed. Returns true if it terminated
/// something. Deliberately conservative: only Waiting (parked, not doing
/// work) tasks with a dead parent — never Ready/Running ones.
pub fn kill_one_stuck_orphan(except: i32) -> bool {
    let (cand, live): (Vec<(i32, i32)>, alloc::collections::BTreeSet<i32>) = {
        let t = TABLE.lock();
        let live = t.tasks.keys().copied().collect();
        let cand = t
            .tasks
            .values()
            .map(|task| (task.pid, task.ppid.load(Ordering::Relaxed)))
            .collect();
        (cand, live)
    };
    for (pid, ppid) in cand {
        if pid == except || pid == 1 {
            continue;
        }
        // Parent must be gone (true orphan); pid 1 (init) is never "gone".
        if ppid == 1 || live.contains(&ppid) {
            continue;
        }
        if let Some(task) = task_by_pid(pid) {
            let waiting = *task.state.lock() == TaskState::Waiting;
            if waiting {
                crate::signal::kill_now(&task);
                drop(task);
                reap(pid);
                return true;
            }
        }
    }
    false
}

pub fn set_current_pid(pid: i32) {
    CURRENT_PID.store(pid, Ordering::Relaxed);
}

pub fn any_runnable_except(pid: i32) -> bool {
    let t = TABLE.lock();
    t.tasks.values().any(|task| {
        task.pid != pid
            && matches!(
                *task.state.lock(),
                TaskState::Ready | TaskState::Running
            )
    })
}

pub fn any_waiting() -> bool {
    let t = TABLE.lock();
    t.tasks.values().any(|task| *task.state.lock() == TaskState::Waiting)
}

/// Diagnostic: dump why the scheduler can't make progress. Counts tasks by
/// state and lists the Waiting/Running ones (with parent liveness) so a
/// resource leak (hundreds of tasks) is distinguishable from a deadlock (a few
/// stuck waiters). Retained for scheduler bring-up debugging.
#[allow(dead_code)]
pub fn dump_stuck_state(cur_pid: i32) {
    let t = TABLE.lock();
    let (mut ready, mut running, mut waiting, mut zombie) = (0u32, 0u32, 0u32, 0u32);
    for task in t.tasks.values() {
        match *task.state.lock() {
            TaskState::Ready => ready += 1,
            TaskState::Running => running += 1,
            TaskState::Waiting => waiting += 1,
            TaskState::Zombie => zombie += 1,
        }
    }
    crate::println!(
        "[stuck] cur={} total={} ready={} running={} waiting={} zombie={}",
        cur_pid, t.tasks.len(), ready, running, waiting, zombie,
    );
    let mut n = 0;
    for (&pid, task) in t.tasks.iter() {
        if n >= 14 { break; }
        let st = *task.state.lock();
        if matches!(st, TaskState::Waiting | TaskState::Running) {
            let ppid = task.ppid.load(Ordering::Relaxed);
            crate::println!(
                "[stuck]   pid={} {:?} ppid={} parent_alive={}",
                pid, st, ppid, t.tasks.contains_key(&ppid),
            );
            n += 1;
        }
    }
}

/// Snapshot of every task in the table. Cloning Arcs keeps it cheap
/// and avoids holding the table lock while callers iterate.
pub fn all_tasks() -> Vec<Arc<Task>> {
    let t = TABLE.lock();
    t.tasks.values().cloned().collect()
}

/// Tasks parked by sys_nanosleep / clock_nanosleep. The scheduler
/// flips them back to Ready once their deadline (in mtime ticks) is
/// reached. Before this, sys_nanosleep busy-spun until the deadline,
/// pinning the CPU and starving any other Ready task — busybox
/// `timeout` (a polling daemon doing `nanosleep + kill(self_parent,0)`)
/// would hold the CPU forever and the actual wrapped command never got
/// scheduled.
static SLEEPING_UNTIL: crate::sync::Mutex<alloc::collections::BTreeMap<i32, u64>> =
    crate::sync::Mutex::new(alloc::collections::BTreeMap::new());

pub fn sleep_until(pid: i32, deadline_ticks: u64) {
    SLEEPING_UNTIL.lock().insert(pid, deadline_ticks);
}

pub fn forget_sleeper(pid: i32) {
    SLEEPING_UNTIL.lock().remove(&pid);
}

/// Returns the current sleep deadline for `pid` if it is parked, else None.
/// Used by sys_rt_sigtimedwait re-entry to avoid extending the deadline on
/// every wake by an out-of-set signal.
pub fn sleeper_deadline(pid: i32) -> Option<u64> {
    SLEEPING_UNTIL.lock().get(&pid).copied()
}

/// Returns true if any task is parked on a sleep / futex deadline
/// that hasn't expired yet. Used by the scheduler's deadlock check —
/// a stalled kernel where nobody is ever going to wake should panic
/// rather than spin forever pretending to make progress.
pub fn any_pending_deadline(now: u64) -> bool {
    if SLEEPING_UNTIL.lock().values().any(|&d| d > now) {
        return true;
    }
    crate::sync::futex::has_pending_deadline(now)
}

#[cold]
fn panic_dead_locked(cur_pid: i32, reason: &str) -> ! {
    crate::println!("\n=== KERNEL DEADLOCK DETECTED ===");
    crate::println!("reason: {}", reason);
    crate::println!("current pid: {}", cur_pid);
    let now = crate::arch::now_ticks();
    crate::println!("mtime: {}", now);
    crate::println!("task table:");
    let snapshot: Vec<(i32, TaskState, i32, i32)> = {
        let t = TABLE.lock();
        t.tasks.values().map(|task| (
            task.pid,
            *task.state.lock(),
            task.tgid.load(Ordering::Relaxed),
            task.ppid.load(Ordering::Relaxed),
        )).collect()
    };
    for (pid, st, tgid, ppid) in snapshot {
        crate::println!("  pid={} tgid={} ppid={} state={:?}", pid, tgid, ppid, st);
    }
    let sleepers: Vec<(i32, u64)> = SLEEPING_UNTIL.lock().iter().map(|(&p,&d)|(p,d)).collect();
    if !sleepers.is_empty() {
        crate::println!("sleepers (pid -> deadline_ticks):");
        for (p, d) in sleepers {
            let dt = if d > now { d - now } else { 0 };
            crate::println!("  pid={} deadline={} ({} ticks away = {}ms)",
                p, d, dt, dt / 10_000);
        }
    }
    panic!("kernel deadlock — no path to forward progress");
}

/// Wake any nanosleep'd tasks whose deadline has been reached. Called
/// from the scheduler hook on every trap exit; cheap when the map is
/// empty.
///
/// We deliberately do NOT remove the entry from SLEEPING_UNTIL on
/// expiry — only flip the state Waiting->Ready. This is required for
/// the rewind-sepc syscalls (sys_rt_sigtimedwait) to detect expiry on
/// re-entry by re-checking the still-present deadline; otherwise the
/// re-entry installs a FRESH deadline `now + timeout` and the call
/// never times out (libctest's runtest.exe loses its 5s watchdog for
/// pthread_cancel and similar pthread tests, taking the whole group
/// down). Stale entries get cleared by `forget_sleeper` on the success
/// path, the next `sleep_until` (which overwrites), or `exit_one_thread`.
pub fn wake_expired_sleepers(now: u64) {
    let expired: Vec<i32> = {
        let m = SLEEPING_UNTIL.lock();
        m.iter().filter_map(|(&pid, &d)| if now >= d { Some(pid) } else { None }).collect()
    };
    if expired.is_empty() {
        return;
    }
    for pid in expired {
        if let Some(t) = TABLE.lock().tasks.get(&pid).cloned() {
            let mut s = t.state.lock();
            if *s == TaskState::Waiting {
                *s = TaskState::Ready;
            }
        }
    }
}

/// ITIMER_REAL deadlines: per-pid (next_deadline_ticks, interval_ticks).
/// `interval_ticks == 0` means single-shot (don't rearm).
static IT_REAL_DEADLINES: crate::sync::Mutex<alloc::collections::BTreeMap<i32, (u64, u64)>> =
    crate::sync::Mutex::new(alloc::collections::BTreeMap::new());

/// Install / replace this pid's ITIMER_REAL. `next == 0` disarms it.
pub fn itimer_real_set(pid: i32, next_deadline_ticks: u64, interval_ticks: u64) {
    let mut m = IT_REAL_DEADLINES.lock();
    if next_deadline_ticks == 0 {
        m.remove(&pid);
    } else {
        m.insert(pid, (next_deadline_ticks, interval_ticks));
    }
}

/// Query current ITIMER_REAL (next_deadline_ticks, interval_ticks).
pub fn itimer_real_get(pid: i32) -> Option<(u64, u64)> {
    IT_REAL_DEADLINES.lock().get(&pid).copied()
}

/// Drop any timer state owned by `pid`. Called from reap.
pub fn forget_itimer(pid: i32) {
    IT_REAL_DEADLINES.lock().remove(&pid);
}

/// Raise SIGALRM on any task whose ITIMER_REAL deadline has elapsed.
pub fn wake_expired_itimers(now: u64) {
    let fired: Vec<(i32, u64, u64)> = {
        let m = IT_REAL_DEADLINES.lock();
        m.iter()
            .filter_map(|(&pid, &(next, interval))| {
                if now >= next { Some((pid, next, interval)) } else { None }
            })
            .collect()
    };
    if fired.is_empty() {
        return;
    }
    {
        let mut m = IT_REAL_DEADLINES.lock();
        for (pid, _next, interval) in &fired {
            if *interval > 0 {
                m.insert(*pid, (now + *interval, *interval));
            } else {
                m.remove(pid);
            }
        }
    }
    for (pid, _next, _interval) in fired {
        if let Some(t) = task_by_pid(pid) {
            let _ = crate::signal::raise_signal(&t, crate::signal::SIGALRM);
        }
    }
}

/// CLONE_VFORK wakeup: the child has reached execve or exit. Any task whose
/// `vfork_child` matches this pid is unblocked. Called from sys_execve (on
/// success) and exit_one_thread.
pub fn wake_vfork_parent_of(child_pid: i32) {
    for t in all_tasks() {
        let mut slot = t.vfork_child.lock();
        if *slot == Some(child_pid) {
            *slot = None;
            drop(slot);
            let mut s = t.state.lock();
            if *s == TaskState::Waiting {
                *s = TaskState::Ready;
            }
        }
    }
}

/// Mark this task as blocked on socket activity rather than wait4/futex.
/// `wake_socket_waiters` only wakes tasks in this set, so a wait4 caller
/// doesn't get spuriously bounced back to Ready every trap.
static SOCKET_WAITERS: crate::sync::Mutex<alloc::collections::BTreeSet<i32>> =
    crate::sync::Mutex::new(alloc::collections::BTreeSet::new());

pub fn mark_socket_waiter(pid: i32) {
    SOCKET_WAITERS.lock().insert(pid);
}

pub fn unmark_socket_waiter(pid: i32) {
    SOCKET_WAITERS.lock().remove(&pid);
}

/// Promote every task that's blocked on a socket back to Ready so it
/// can re-attempt its syscall. Does NOT touch tasks blocked on wait4
/// (children-pending) or futex.
pub fn wake_socket_waiters() {
    let pending: Vec<i32> = SOCKET_WAITERS.lock().iter().copied().collect();
    if pending.is_empty() { return; }
    let t = TABLE.lock();
    for pid in pending {
        if let Some(task) = t.tasks.get(&pid) {
            let mut s = task.state.lock();
            if *s == TaskState::Waiting {
                *s = TaskState::Ready;
            }
        }
    }
    // The actual syscall handler is responsible for unmark when it
    // finishes (success or error). Leaving them marked is fine: they
    // just get promoted again on a subsequent trap.
}

// ----- Initial task creation -----

pub fn create_task_from_elf(
    elf_image: &[u8],
    argv: &[&str],
    envp: &[&str],
) -> Arc<Task> {
    create_task_from_elf_with_path(elf_image, argv, envp, "")
}

pub fn create_task_from_elf_with_path(
    elf_image: &[u8],
    argv: &[&str],
    envp: &[&str],
    exe_path: &str,
) -> Arc<Task> {
    let mut ms = MemorySet::new();
    map_kernel_into(&mut ms);
    let elf = crate::loader::load_elf(elf_image, &mut ms).expect("ELF load");
    let user_sp_top = setup_initial_stack(&elf, &mut ms, argv, envp);
    crate::signal::install_restorer_page(&mut ms);
    crate::vdso::install(&mut ms);

    let mut tf = TrapFrame::default();
    tf.set_user_pc(elf.entry);
    tf.set_user_sp(user_sp_top);
    tf.init_user_state();

    let task = make_task_with_ms(ms, tf, 0);
    *task.cmdline.lock() = build_cmdline(argv);
    *task.exe_path.lock() = exe_path.into();
    install_task(task.clone());
    task
}

fn build_cmdline(argv: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for s in argv {
        out.extend_from_slice(s.as_bytes());
        out.push(0);
    }
    out
}

#[cfg(target_arch = "riscv64")]
fn map_kernel_into(ms: &mut MemorySet) {
    extern "C" {
        fn __kernel_start();
    }
    let k_start = __kernel_start as usize;
    ms.map_kernel_identity(k_start, crate::mm::mm_end());
    ms.map_mmio(0x0c00_0000, 0x1000_0000); // PLIC
    ms.map_mmio(0x1000_0000, 0x1000_1000); // UART
    ms.map_mmio(0x1000_1000, 0x1000_9000); // virtio-mmio
}

/// loongarch64 reaches the whole kernel image + all MMIO through the DMW0
/// (cached) and DMW1 (uncached) direct-map windows, which bypass the TLB
/// entirely. The per-process page table therefore needs no kernel or MMIO
/// identity mappings — only the user (low-half) regions installed by
/// `push_user_area`. Mapping the high-half kernel VA here would also be
/// actively wrong: the 3×9-bit walk only sees the low 27 VPN bits, so a
/// DMW kernel address would alias an unrelated low user VPN.
#[cfg(target_arch = "loongarch64")]
fn map_kernel_into(_ms: &mut MemorySet) {}

fn make_task_with_ms(ms: MemorySet, tf: TrapFrame, ppid: i32) -> Arc<Task> {
    let pid = alloc_pid();
    // Inherit parent's process group + session if there is one; else
    // become our own pgid+sid leader (this is the case for the very
    // first task and for explicit setsid).
    let (pgid, sid) = if ppid > 0 {
        if let Some(p) = TABLE.lock().tasks.get(&ppid) {
            (
                p.pgid.load(Ordering::Relaxed),
                p.sid.load(Ordering::Relaxed),
            )
        } else {
            (pid, pid)
        }
    } else {
        (pid, pid)
    };
    let task = Arc::new(Task {
        pid,
        tgid: AtomicI32::new(pid),
        ppid: AtomicI32::new(ppid),
        pgid: AtomicI32::new(pgid),
        sid: AtomicI32::new(sid),
        storage: UnsafeCell::new(TaskStorage::boxed()),
        memory_set: Arc::new(Mutex::new(ms)),
        fd_table: Arc::new(Mutex::new(crate::fs::FdTable::new())),
        cwd: Arc::new(Mutex::new(String::from("/"))),
        state: Mutex::new(TaskState::Running),
        exit_code: AtomicI32::new(0),
        exit_signal: AtomicI32::new(crate::signal::SIGCHLD as i32),
        children: Mutex::new(Vec::new()),
        cmdline: Mutex::new(Vec::new()),
        exe_path: Mutex::new(String::new()),
        signals: crate::signal::SignalState::new(),
        clear_child_tid: Mutex::new(0),
        vfork_child: Mutex::new(None),
        thread_stack_top: AtomicUsize::new(0),
        in_blocking_syscall: AtomicBool::new(false),
    });
    unsafe {
        core::ptr::write(task.tf_ptr(), tf);
    }
    // Prime the kernel context for a first `__switch` into this task. (The
    // initial task enters via run_user_loop instead and overwrites this on its
    // first park, but ELF-spawned tasks reached only through the scheduler
    // need it.)
    task.init_kctx_for_first_run();
    task
}

// ----- Initial argv/envp/auxv stack -----

fn setup_initial_stack(
    elf: &LoadedElf,
    ms: &mut MemorySet,
    argv: &[&str],
    envp: &[&str],
) -> usize {
    let mut sp = elf.user_sp_top;

    sp -= 16;
    let random_va = sp;
    let random_bytes = [0x42u8; 16];
    copy_out_via(ms, random_va, &random_bytes).expect("write AT_RANDOM");

    // AT_PLATFORM: the ISA string the C library may use to expand
    // $PLATFORM in library search paths. Match the running architecture.
    #[cfg(target_arch = "riscv64")]
    let platform = b"riscv64\0".as_slice();
    #[cfg(target_arch = "loongarch64")]
    let platform = b"loongarch\0".as_slice();
    sp -= platform.len();
    let platform_va = sp;
    copy_out_via(ms, platform_va, platform).expect("write platform");

    let mut env_addrs = Vec::with_capacity(envp.len());
    for s in envp.iter().rev() {
        sp -= s.len() + 1;
        let mut bytes = Vec::with_capacity(s.len() + 1);
        bytes.extend_from_slice(s.as_bytes());
        bytes.push(0);
        copy_out_via(ms, sp, &bytes).expect("write envp");
        env_addrs.push(sp);
    }
    env_addrs.reverse();

    let mut arg_addrs = Vec::with_capacity(argv.len());
    for s in argv.iter().rev() {
        sp -= s.len() + 1;
        let mut bytes = Vec::with_capacity(s.len() + 1);
        bytes.extend_from_slice(s.as_bytes());
        bytes.push(0);
        copy_out_via(ms, sp, &bytes).expect("write argv");
        arg_addrs.push(sp);
    }
    arg_addrs.reverse();

    sp &= !0xfusize;

    // AT_HWCAP: CPU feature bitmap the C library reads to pick ifunc
    // variants of its hot routines (memcpy/memset/str*). loongarch64 la464
    // (what QEMU's `virt` emulates) carries CPUCFG|LAM|UAL|FPU|LSX|LASX, so
    // glibc resolves to the vector implementations — which the kernel now
    // permits in userspace (EUEN.SXE/ASXE, see boot.S). riscv64 advertises
    // nothing here, matching the prior behaviour.
    #[cfg(target_arch = "riscv64")]
    const AT_HWCAP: usize = 0;
    #[cfg(target_arch = "loongarch64")]
    const AT_HWCAP: usize = 0x3f; // CPUCFG|LAM|UAL|FPU|LSX|LASX

    let mut auxv: alloc::vec::Vec<(usize, usize)> = alloc::vec::Vec::new();
    // AT_SYSINFO_EHDR: base of the vDSO ELF. glibc parses its program
    // headers + .eh_frame from here so pthread_cancel's forced unwind can
    // step across the signal frame (see kernel/src/vdso.rs). The embedded
    // vDSO is a RISC-V image, so only advertise it on riscv64 — handing a
    // foreign vDSO to a loongarch64 libc makes it parse a bogus ELF and
    // chase near-null symbol pointers. LA libc just uses direct syscalls.
    #[cfg(target_arch = "riscv64")]
    auxv.push((33, crate::vdso::VDSO_BASE));
    auxv.extend_from_slice(&[
        (3, elf.phdr_va),
        (4, elf.phent),
        (5, elf.phnum),
        (6, PAGE_SIZE),
        (7, elf.interp_base),
        (8, 0),
        (9, elf.program_entry),
        (11, 0),
        (12, 0),
        (13, 0),
        (14, 0),
        (16, AT_HWCAP),
        (17, 100),
        (23, 0),
        (25, random_va),
        (15, platform_va),
        (31, arg_addrs.first().copied().unwrap_or(0)),
        (0, 0),
    ]);

    let ptrs_bytes = 8
        + 8 * (arg_addrs.len() + 1 + env_addrs.len() + 1)
        + 16 * auxv.len();
    if (sp - ptrs_bytes) & 0xf != 0 {
        sp -= 8;
    }
    let start_va = sp - ptrs_bytes;

    let mut cursor = start_va;
    write_usize(ms, cursor, argv.len());
    cursor += 8;
    for &a in &arg_addrs {
        write_usize(ms, cursor, a);
        cursor += 8;
    }
    write_usize(ms, cursor, 0);
    cursor += 8;
    for &a in &env_addrs {
        write_usize(ms, cursor, a);
        cursor += 8;
    }
    write_usize(ms, cursor, 0);
    cursor += 8;
    for &(k, v) in &auxv {
        write_usize(ms, cursor, k);
        cursor += 8;
        write_usize(ms, cursor, v);
        cursor += 8;
    }

    start_va
}

fn write_usize(ms: &mut MemorySet, va: usize, v: usize) {
    let bytes = v.to_le_bytes();
    copy_out_via(ms, va, &bytes).expect("write usize");
}

// ----- fork / execve -----

pub fn fork_current() -> Option<Arc<Task>> {
    clone_current(0, 0, 0, 0, 0)
}

// CLONE_* flag bits (Linux generic).
pub const CLONE_VM: usize = 0x100;
pub const CLONE_FS: usize = 0x200;
pub const CLONE_FILES: usize = 0x400;
pub const CLONE_SIGHAND: usize = 0x800;
pub const CLONE_PIDFD: usize = 0x1000;
pub const CLONE_PTRACE: usize = 0x2000;
pub const CLONE_VFORK: usize = 0x4000;
pub const CLONE_PARENT: usize = 0x8000;
pub const CLONE_THREAD: usize = 0x10000;
pub const CLONE_NEWNS: usize = 0x20000;
pub const CLONE_SYSVSEM: usize = 0x40000;
pub const CLONE_SETTLS: usize = 0x80000;
pub const CLONE_PARENT_SETTID: usize = 0x100000;
pub const CLONE_CHILD_CLEARTID: usize = 0x200000;
pub const CLONE_DETACHED: usize = 0x400000;
pub const CLONE_UNTRACED: usize = 0x800000;
pub const CLONE_CHILD_SETTID: usize = 0x1000000;

/// General clone primitive used by both `fork()` and `pthread_create()`.
///
/// * If `CLONE_VM` is set, the new task shares its caller's address space
///   (same `Arc<Mutex<MemorySet>>`, same satp). Otherwise we deep-copy.
/// * If `CLONE_FS` is set, the new task shares the cwd. Otherwise cloned.
/// * If `CLONE_FILES` is set, fd_table is shared. Otherwise cloned.
/// * If `CLONE_SIGHAND` is set, the new task shares sig_actions. Otherwise
///   a fresh inheriting copy.
/// * If `CLONE_THREAD` is set, the new task gets caller's `tgid` and is NOT
///   placed in the caller's `children` list; SIGCHLD on its exit is suppressed.
///
/// Returns the new task (already inserted into the table). The new task's TF
/// has `a0 = 0` (so it returns 0 from clone), `sp = child_sp` if non-zero, and
/// `tp = newtls` if `CLONE_SETTLS` is set.
pub fn clone_current(
    flags: usize,
    child_sp: usize,
    ptid: usize,
    ctid: usize,
    newtls: usize,
) -> Option<Arc<Task>> {
    let parent = current_task();

    // ---- Address space ----
    // Share the page table only for a genuine thread (CLONE_VM *without*
    // CLONE_VFORK). A CLONE_VM|CLONE_VFORK child is glibc's posix_spawn /
    // fork-then-exec helper: it shares briefly then immediately execve()s.
    // If we let it share the Arc, its execve would replace the *shared*
    // MemorySet contents and yank the still-mapped vfork parent's code out
    // from under it — the parent then faults at a glibc PC the instant the
    // child execs (clock_gettime04 / creat07 SIGSEGV'd exactly this way).
    // Give the vfork child its own private (forked) copy instead: correct
    // per POSIX (the child must not durably modify the parent's memory
    // other than by exec/exit) and it makes execve's in-place swap safe.
    let share_vm = (flags & CLONE_VM != 0) && (flags & CLONE_VFORK == 0);
    let memory_set: Arc<Mutex<MemorySet>> = if share_vm {
        // Share: same Arc, same satp, same page table.
        // Before spawning a new thread, reclaim the stacks of any threads
        // that have since exited and were never joined. Doing this here (and
        // not at thread exit) guarantees any join already read the exiting
        // thread's descriptor. Keeps the region count bounded for workloads
        // that spawn thousands of unjoined threads (b_pthread_create_serial1).
        parent.memory_set.lock().drain_stack_reclaim();
        parent.memory_set.clone()
    } else {
        // Deep-copy parent's user areas; remap the kernel/MMIO identity into
        // the new page table so the trap handler keeps working after a
        // future satp switch. fork() returns None on physical-memory
        // exhaustion — propagate as None so sys_clone returns ENOMEM
        // instead of panicking the kernel.
        let mut new_ms = parent.memory_set.lock().fork()?;
        map_kernel_into(&mut new_ms);
        Arc::new(Mutex::new(new_ms))
    };

    // ---- Working dir ----
    let cwd: Arc<Mutex<String>> = if flags & CLONE_FS != 0 {
        parent.cwd.clone()
    } else {
        Arc::new(Mutex::new(parent.cwd.lock().clone()))
    };

    // ---- fd table ----
    let fd_table: Arc<Mutex<crate::fs::FdTable>> = if flags & CLONE_FILES != 0 {
        parent.fd_table.clone()
    } else {
        let new_fdt = parent.fd_table.lock().clone_for_fork();
        Arc::new(Mutex::new(new_fdt))
    };

    // ---- TF: clone parent's, override sp/tp/a0 ----
    let mut new_tf = unsafe { (*parent.tf_ptr()).clone() };
    new_tf.set_syscall_ret(0); // child sees 0 from clone
    if child_sp != 0 {
        new_tf.set_user_sp(child_sp);
    }
    if flags & CLONE_SETTLS != 0 {
        new_tf.set_user_tp(newtls);
    }

    // ---- Allocate the task with a fresh kstack/TF, then patch shared fields ----
    let pid = alloc_pid();

    // Inherit parent's process group + session. For CLONE_THREAD the ppid
    // stays as the *parent's* parent (matches Linux behaviour with CLONE_PARENT
    // implied) — actually Linux: with CLONE_THREAD, child's ppid = parent's
    // ppid. With plain fork: child's ppid = parent.pid. We follow that.
    let ppid = if flags & CLONE_THREAD != 0 {
        parent.ppid.load(Ordering::Relaxed)
    } else {
        parent.pid
    };
    let tgid = if flags & CLONE_THREAD != 0 {
        parent.tgid.load(Ordering::Relaxed)
    } else {
        pid
    };
    let pgid = parent.pgid.load(Ordering::Relaxed);
    let sid = parent.sid.load(Ordering::Relaxed);

    // Allocate the 64 KiB kstack fallibly: a thread/fork storm (ebizzy spawns
    // workers in a tight loop) can drain the kernel heap, and clone must then
    // return EAGAIN to userspace rather than panic the kernel via Box::new.
    let kstack = TaskStorage::try_boxed()?;
    let task = Arc::new(Task {
        pid,
        tgid: AtomicI32::new(tgid),
        ppid: AtomicI32::new(ppid),
        pgid: AtomicI32::new(pgid),
        sid: AtomicI32::new(sid),
        storage: UnsafeCell::new(kstack),
        memory_set,
        fd_table,
        cwd,
        state: Mutex::new(TaskState::Ready),
        exit_code: AtomicI32::new(0),
        // The exit signal lives in the low byte of the clone flags (SIGCHLD
        // for fork). A CLONE_THREAD member reports 0 (no parent signal).
        exit_signal: AtomicI32::new(
            if flags & CLONE_THREAD != 0 { 0 } else { (flags & 0xff) as i32 },
        ),
        children: Mutex::new(Vec::new()),
        cmdline: Mutex::new(parent.cmdline.lock().clone()),
        exe_path: Mutex::new(parent.exe_path.lock().clone()),
        signals: if flags & CLONE_SIGHAND != 0 {
            parent.signals.share_actions_inherit()
        } else {
            parent.signals.fork_inherit()
        },
        clear_child_tid: Mutex::new(0),
        vfork_child: Mutex::new(None),
        // Record the thread stack only for genuine pthreads: CLONE_VM AND
        // CLONE_THREAD with an explicit, distinct stack, and NOT vfork.
        // vfork() also sets CLONE_VM and may pass a stack but *shares* the
        // parent's stack — reclaiming it on the vfork child's exit would
        // unmap the parent's live stack. Requiring CLONE_THREAD (which vfork
        // never sets) excludes that case. Used by the exit path to reclaim a
        // never-joined thread's stack from the shared address space.
        thread_stack_top: AtomicUsize::new(
            if flags & CLONE_VM != 0
                && flags & CLONE_THREAD != 0
                && flags & CLONE_VFORK == 0
                && child_sp != 0
            {
                child_sp
            } else {
                0
            },
        ),
        in_blocking_syscall: AtomicBool::new(false),
    });
    // Write the TF onto the new kstack.
    unsafe {
        core::ptr::write(task.tf_ptr(), new_tf);
    }
    // Prime the kernel context: the child has never run, so the scheduler's
    // first `__switch` into it must land in the first-run trampoline, which
    // sret's to the TrapFrame just written (the child returns 0 from fork).
    task.init_kctx_for_first_run();

    // A fork starts a new thread group and so needs its own copy of the
    // parent's credentials; thread members share the parent's tgid (and thus
    // its creds) already.
    let parent_tgid = parent.tgid.load(Ordering::Relaxed);
    if tgid != parent_tgid {
        crate::syscall::inherit_creds(parent_tgid, tgid);
    }

    // loongarch64: the child inherits the parent's vector-unit state. We're
    // running in the parent's clone syscall and the kernel is soft-float, so
    // the live registers still hold the parent's values — snapshot them into
    // the child's slot so it resumes with the same FP/LSX/LASX context.
    #[cfg(target_arch = "loongarch64")]
    unsafe {
        crate::arch::loongarch64::fpu::save(task.fp_ptr());
    }

    // CLONE_CHILD_CLEARTID — remember addr so exit clears it + futex_wakes.
    if flags & CLONE_CHILD_CLEARTID != 0 {
        *task.clear_child_tid.lock() = ctid;
    }

    // CLONE_PARENT_SETTID — write the new tid into the parent's address
    // space at `ptid`. We're still on the parent's page table, so the
    // parent's copy_out works directly.
    if flags & CLONE_PARENT_SETTID != 0 && ptid != 0 {
        let tid_bytes = (task.pid as i32).to_le_bytes();
        let _ = parent.copy_out_bytes(ptid, &tid_bytes);
    }

    // CLONE_CHILD_SETTID — write the new tid into the child's address
    // space at `ctid`. With CLONE_VM the address spaces are the same, so
    // copying via the *parent* (current task) works. Without CLONE_VM, the
    // child's MS was deep-copied from parent's, so the same VA maps to a
    // different PA but is still set up; we can write via the child's MS.
    if flags & CLONE_CHILD_SETTID != 0 && ctid != 0 {
        let tid_bytes = (task.pid as i32).to_le_bytes();
        if flags & CLONE_VM != 0 {
            let _ = parent.copy_out_bytes(ctid, &tid_bytes);
        } else {
            let _ = task.copy_out_bytes(ctid, &tid_bytes);
        }
    }

    // children-tracking + waiter semantics: only the non-CLONE_THREAD case
    // adds the new task as a child of the caller (so wait4 finds it).
    if flags & CLONE_THREAD == 0 {
        parent.children.lock().push(task.pid);
    }

    TABLE.lock().tasks.insert(task.pid, task.clone());

    // CLONE_VFORK: block the parent until child execs or exits. With
    // CLONE_VM (always the case for real vfork()), parent + child share
    // stack — running them concurrently corrupts whatever the parent had
    // on its stack across the vfork call. We pre-write the parent's a0
    // here because the syscall dispatch loop skips the tf write when the
    // task is Waiting (otherwise it would clobber retried-syscall args).
    if flags & CLONE_VFORK != 0 {
        *parent.vfork_child.lock() = Some(task.pid);
        unsafe {
            (*parent.tf_ptr()).set_syscall_ret(task.pid as usize);
        }
        *parent.state.lock() = TaskState::Waiting;
    }

    Some(task)
}

/// Replace the current task's image with `elf_image`, argv, envp.
pub fn execve_current(elf_image: &[u8], argv: &[&str], envp: &[&str]) -> Result<(), i32> {
    execve_current_with_path(elf_image, argv, envp, "")
}

pub fn execve_current_with_path(
    elf_image: &[u8],
    argv: &[&str],
    envp: &[&str],
    exe_path: &str,
) -> Result<(), i32> {
    let task = current_task();
    let mut ms = MemorySet::try_new().ok_or(-12i32)?; // ENOMEM
    map_kernel_into(&mut ms);
    let elf = crate::loader::load_elf(elf_image, &mut ms).map_err(|e| {
        // Frame-pool exhaustion must surface as ENOMEM, not EINVAL. Returning
        // EINVAL made execve("./busybox") look like "Invalid argument" once a
        // memory-hog case (data_space, etc.) drained the pool, and busybox
        // failing to start collapsed the whole LTP loop (every later case
        // 126 with an empty name). ENOMEM is correct and recoverable.
        if e.starts_with("OOM") { -12i32 } else { -22i32 }
    })?;
    let user_sp_top = setup_initial_stack(&elf, &mut ms, argv, envp);
    crate::signal::install_restorer_page(&mut ms);
    crate::vdso::install(&mut ms);

    // execve detaches the caller from any shared address space (POSIX
    // semantics): we replace the contents of the Arc<Mutex<MemorySet>>.
    // A CLONE_VM child that reaches execve does NOT share this Arc (see
    // clone_current: a CLONE_VFORK/spawn child is given its own private
    // address space precisely so this in-place swap can't clobber the
    // vfork parent's still-live memory). Pure CLONE_THREAD pthreads that
    // exec are undefined behaviour, so swapping in place is safe here.
    let new_satp;
    {
        let mut slot = task.memory_set.lock();
        *slot = ms;
        new_satp = slot.satp();
    }
    crate::arch::activate_page_table(new_satp);

    // Replace trap frame with fresh entry state.
    let mut tf = TrapFrame::default();
    tf.set_user_pc(elf.entry);
    tf.set_user_sp(user_sp_top);
    tf.init_user_state();
    unsafe {
        core::ptr::write(task.tf_ptr(), tf);
    }

    // close-on-exec
    task.fd_table.lock().close_cloexec();

    // Record cmdline + exe_path for procfs. /proc/self/exe is read by
    // glibc's _dl_get_origin which assert()s the linkval starts with
    // '/'; resolve any relative path against the caller's cwd here so
    // the recorded exe_path is absolute. Without this the entire
    // glibc-dynamic test variant (lua-glibc, libctest-glibc, ...)
    // aborts on _dl_get_origin.
    *task.cmdline.lock() = build_cmdline(argv);
    if !exe_path.is_empty() {
        let s: String = exe_path.into();
        let abs = if s.starts_with('/') {
            s
        } else {
            let cwd = task.cwd.lock().clone();
            let cwd = cwd.trim_end_matches('/');
            let rel = s.strip_prefix("./").unwrap_or(&s);
            alloc::format!("{}/{}", cwd, rel)
        };
        *task.exe_path.lock() = abs;
    }
    // POSIX: keep mask, reset every user-installed handler to SIG_DFL
    // (SIG_IGN survives), clear pending, clear altstack.
    task.signals.reset_for_exec();
    // execve also clears any pending CLONE_CHILD_CLEARTID address.
    *task.clear_child_tid.lock() = 0;

    // CLONE_VFORK parent has been waiting for us to call execve. Now that
    // we have our own address space, the parent's stack is no longer at
    // risk of being trashed by us — let it resume.
    wake_vfork_parent_of(task.pid);

    Ok(())
}

/// First-time entry to user mode for the initial task.
pub fn run_user_loop(task: &Arc<Task>) -> ! {
    extern "C" {
        fn __trap_return(tf: *const TrapFrame) -> !;
    }

    let satp = task.memory_set.lock().satp();
    let tf_ptr = task.tf_ptr();

    crate::arch::activate_page_table(satp);
    unsafe {
        __trap_return(tf_ptr as *const _);
    }
}

/// Called by the trap handler. Decides which task to return through and
/// switches satp + current_pid accordingly. Returns the TF to load.
///
/// On loongarch64 this wraps the scheduler proper so the vector register
/// file (FP/LSX/LASX) follows the task switch. The kernel is soft-float and
/// leaves the file untouched, so when `pick_*` hands the CPU to a different
/// task we park the outgoing task's live registers and load the incoming
/// one's — without this, two vector workloads silently corrupt each other.
#[cfg(target_arch = "loongarch64")]
pub fn schedule_next_after_trap(current_tf: *mut TrapFrame) -> *mut TrapFrame {
    // The actual task change — and, on loongarch64, the FP/vector save+restore
    // that goes with it — now happens inside the inner scheduler via
    // `context_switch_to`, so this is a thin wrapper.
    schedule_next_after_trap_inner(current_tf)
}

#[cfg(not(target_arch = "loongarch64"))]
pub fn schedule_next_after_trap(current_tf: *mut TrapFrame) -> *mut TrapFrame {
    schedule_next_after_trap_inner(current_tf)
}

extern "C" {
    /// Restore a TrapFrame and return to its task's user mode (defined in
    /// trap.S). Used by the first-run trampoline.
    fn __trap_return(tf: *const TrapFrame) -> !;
}

/// First-run entry for a task that has never executed. The scheduler primes a
/// fresh task's kernel context (see [`Task::init_kctx_for_first_run`]) so the
/// first `__switch` into it lands here. CURRENT_PID is already this task, so
/// restore its user TrapFrame and enter user mode via the normal trap return.
extern "C" fn task_first_run() -> ! {
    let tf = current_task().tf_ptr();
    unsafe { __trap_return(tf) }
}

/// Park the currently-running task (`prev_pid`) and resume `next_pid` by
/// switching kernel contexts. `next_pid` must already be published as
/// CURRENT_PID, with its page table active and its pending signals delivered.
/// `prev_tf` is the trap frame to resume `prev_pid` through when it next runs
/// — its user TrapFrame at a trap-exit boundary, or the nested timer frame if
/// `prev_pid` is being preempted mid-syscall. It is returned (on `prev_pid`'s
/// timeline) once `prev_pid` is scheduled again, so the trap handler sret's to
/// the right place (back to user, or back into the interrupted syscall).
///
/// # Safety
/// Call only from the scheduler at a point where no kernel lock is held; both
/// pids must name live tasks with intact kernel stacks.
unsafe fn context_switch_to(
    prev_pid: i32,
    next_pid: i32,
    prev_tf: *mut TrapFrame,
) -> *mut TrapFrame {
    let prev_kctx = task_by_pid(prev_pid).map(|t| t.kctx_ptr());
    let next_kctx = task_by_pid(next_pid).map(|t| t.kctx_ptr());
    if let (Some(p), Some(n)) = (prev_kctx, next_kctx) {
        // loongarch64: the kernel is soft-float, so the outgoing task's live
        // FP/LSX/LASX state lives only in the hardware regs until parked. Save
        // it and load the incoming task's before the GPR switch.
        #[cfg(target_arch = "loongarch64")]
        {
            if let Some(prev) = task_by_pid(prev_pid) {
                unsafe { crate::arch::loongarch64::fpu::save(prev.fp_ptr()) };
            }
            if let Some(next) = task_by_pid(next_pid) {
                unsafe { crate::arch::loongarch64::fpu::restore(next.fp_ptr()) };
            }
        }
        unsafe { crate::arch::switch_context(p, n) };
    }
    // Resumed: continue `prev_pid` through the frame it parked on.
    prev_tf
}

fn schedule_next_after_trap_inner(current_tf: *mut TrapFrame) -> *mut TrapFrame {
    // Push/pull whatever the network stack has been doing while user-mode
    // ran. Only wake socket-blocked tasks if poll actually made progress;
    // otherwise the same task (e.g. iperf3 -s on accept) re-Ready'd itself
    // every trap and starved every other scheduler candidate, including
    // the busybox-`timeout` daemon that was meant to kill it after N
    // seconds.
    if crate::net::poll_with_progress() {
        wake_socket_waiters();
    }

    let cur_pid = current_pid();

    // Sweep futex timeouts every trap exit; cheap on an empty queue.
    crate::sync::futex::poll_timeouts();

    // Wake any nanosleep'd tasks whose deadline has elapsed. Without
    // this a polling sleeper (busybox `timeout`) holds the CPU forever.
    {
        let now = crate::arch::now_ticks();
        wake_expired_sleepers(now);
        wake_expired_itimers(now);
    }

    // Reap any detached threads (CLONE_THREAD) that died last round.
    // We can't reap the current pid even if dead — kstack still in use.
    crate::syscall::drain_self_reap_list(cur_pid);

    // Sweep orphan zombies (parent dead, nobody will wait4 them) when the
    // table has bloated past a normal working set. A killed LTP fork-storm
    // (cgroup `fork_processes`/`cgroup_regression_*`) leaves orphans that
    // pin kstacks and make every table scan O(n); left alone they exhaust
    // task slots and later fork()s fail, breaking the rest of the suite.
    // Rate-limited (every 32 traps) and size-gated so steady-state cost is
    // nil — it only fires while a backlog exists, and stops once drained.
    {
        let n = REAP_SWEEP_TICK.fetch_add(1, Ordering::Relaxed);
        if n % 32 == 0 && TABLE.lock().tasks.len() > 128 {
            reap_orphan_zombies(cur_pid);
        }
    }

    // Run signal delivery for the current task before considering a switch.
    // Doing this before scheduling means terminating-by-signal flows through
    // the same Zombie path as sys_exit. We must call this only if the cur
    // task is still active (not already Zombie/Waiting).
    if let Some(cur) = task_by_pid(cur_pid) {
        let st = *cur.state.lock();
        if matches!(st, TaskState::Ready | TaskState::Running) {
            // SAFETY: current_tf is the kernel-side TF for the current task.
            // No other CPU runs concurrently on this kernel.
            let became_zombie = unsafe {
                crate::signal::check_signals(&cur, &mut *current_tf)
            };
            if became_zombie {
                // Fall through to scheduler -- it'll pick another task.
            }
        } else if st == TaskState::Waiting && crate::signal::has_pending_sigkill(&cur) {
            // A task parked in a blocking syscall (read/futex/wait4) re-blocks
            // before check_signals — which only runs for Ready/Running — can
            // deliver a pending SIGKILL. Left alone it outlives the per-case
            // timeout and pins its frames/kstack; a killed fork-storm
            // (cgroup_regression_fork_processes) thus leaks ~200 stacks until
            // the heap drains and later fork()s fail (the loop breaks with an
            // empty `$(basename)`). SIGKILL is unblockable: end it now.
            crate::signal::kill_now(&cur);
        }
    }

    let cur_state = task_by_pid(cur_pid).map(|t| *t.state.lock());

    // If the current task is Zombie OR Waiting and nothing else is
    // Ready, we can't return its trap frame: Zombie would re-enter
    // dead-process user code; Waiting would silently flip the task
    // back to Running and userland would observe a successful return
    // from nanosleep/wait4/... that didn't actually block. Spin
    // sweeping the sleep / futex queues until SOMETHING becomes
    // runnable. Cheap; same shape as a wfi loop without needing
    // timer interrupts enabled.
    if matches!(cur_state, Some(TaskState::Zombie) | Some(TaskState::Waiting))
        && !any_runnable_except(cur_pid)
    {
        // No wall-clock deadline here — that's the busybox-`timeout`
        // wrapper's job and the kernel can't know what counts as "too
        // long" for an arbitrary userspace workload. Spin until either
        //   - someone becomes Ready,
        //   - this task itself becomes Ready (its own deadline matures),
        //   - or there is provably nobody who could ever wake us, in
        //     which case panic with a state dump so the failure is
        //     visible instead of a silent hang.
        let mut spins: u64 = 0;
        loop {
            {
        let now = crate::arch::now_ticks();
        wake_expired_sleepers(now);
        wake_expired_itimers(now);
    }
            crate::sync::futex::poll_timeouts();
            if any_runnable_except(cur_pid) { break; }
            if let Some(t) = task_by_pid(cur_pid) {
                if *t.state.lock() == TaskState::Ready { break; }
            }
            // Periodic orphan drain. A SIGKILLed fork-storm (fork_exec_loop,
            // fork07, the cgroup cases) leaves orphans behind: zombies whose
            // parent is gone, and — the case that wedges us here — tasks
            // blocked in wait4() on children that will never be reaped. With
            // no real init nobody collects them, so any_waiting() stays true
            // and this loop spins forever. Reap zombie orphans (always safe),
            // then, only once we've spun a while with no progress, terminate a
            // *Waiting* orphan whose parent is dead. We never touch a Ready/
            // Running orphan (it is doing real work — killing those is what
            // broke the busybox group in an earlier attempt); a Waiting task
            // is parked and, being parentless, unwakeable, so ending it frees
            // its frames/kstack and lets the wedged waiter make progress.
            spins = spins.wrapping_add(1);
            if spins % 2048 == 0 {
                reap_orphan_zombies(cur_pid);
                if any_runnable_except(cur_pid) { break; }
                if spins >= 16384 {
                    if kill_one_stuck_orphan(cur_pid) {
                        // Made progress (freed/woke something) — re-evaluate.
                        if let Some(t) = task_by_pid(cur_pid) {
                            if *t.state.lock() == TaskState::Ready { break; }
                        }
                        if any_runnable_except(cur_pid) { break; }
                    }
                }
            }
            // No-progress check: are there any other live tasks at
            // all, and do any of them have a deadline that could
            // eventually wake us? If neither, this is a real deadlock.
            let now = crate::arch::now_ticks();
            let alive_others = any_runnable_except(cur_pid) || any_waiting();
            if !alive_others {
                // End the run ONLY when the contest init (pid 1) has exited.
                // A transient empty runnable+waiting set during a test's
                // teardown (e.g. pidns04's PID-namespace collapse racing its
                // parent's wait4) must NOT halt the machine — the old code
                // shut down here and killed every group after it. pid 1 is
                // the reaper and will be runnable again; fall through and keep
                // spinning (the orphan drain above + wakeups below resolve it).
                let init_done = task_by_pid(1)
                    .map_or(false, |t| matches!(*t.state.lock(), TaskState::Zombie));
                if init_done {
                    crate::arch::shutdown();
                }
            }
            if !any_pending_deadline(now) {
                // Everyone is parked on something with no timeout —
                // futex without deadline, socket wait, pipe wait, etc.
                // Those CAN still be woken (by I/O events, by another
                // task's write), so keep spinning. Network poll runs
                // at the top of schedule_next_after_trap on the next
                // round; getting back there requires a syscall, but
                // we're not in user code. Drive net::poll here too.
                crate::net::poll();
                wake_socket_waiters();
                if any_runnable_except(cur_pid) { break; }
            }
            core::hint::spin_loop();
        }
    }

    if matches!(cur_state, Some(TaskState::Zombie) | Some(TaskState::Waiting)) {
        // Outer loop: if we picked a task that died in its own signal
        // delivery (SIGKILL queued while it was Waiting), pick another.
        // If no Ready task remains AND cur is Zombie, we cannot return
        // cur_tf — that would re-enter dead user code. Wait instead.
        let cur_satp = task_by_pid(cur_pid).map(|t| t.memory_set.lock().satp());
        loop {
            // Try to pick a Ready task, skipping any that get killed by
            // their own signals on arrival.
            let mut found: Option<i32> = None;
            while let Some(next) = pick_ready(cur_pid) {
                CURRENT_PID.store(next.pid, Ordering::Relaxed);
                let next_satp = next.memory_set.lock().satp();
                if cur_satp != Some(next_satp) {
                    crate::arch::activate_page_table(next_satp);
                }
                let next_tf = next.tf_ptr();
                unsafe { crate::signal::check_signals(&next, &mut *next_tf); }
                if !matches!(*next.state.lock(), TaskState::Zombie) {
                    found = Some(next.pid);
                    break;
                }
            }
            if let Some(next_pid) = found {
                // Switch kernel context to the chosen task. If `cur` is a
                // Zombie its parked context is simply never resumed; if it is
                // Waiting it resumes when later woken and re-runs its syscall
                // through `current_tf`.
                return unsafe { context_switch_to(cur_pid, next_pid, current_tf) };
            }
            // No live Ready task. If cur is Zombie we must NOT return
            // its tf. Wait for either a sleeper to mature, an I/O event
            // to wake a socket waiter, or a futex deadline. If literally
            // nobody can ever wake us, shut down (Zombie) or panic
            // (Waiting).
            if cur_state == Some(TaskState::Waiting) {
                if let Some(t) = task_by_pid(cur_pid) {
                    *t.state.lock() = TaskState::Running;
                }
                return current_tf;
            }
            // Zombie path: spin until something Ready appears.
            loop {
                {
        let now = crate::arch::now_ticks();
        wake_expired_sleepers(now);
        wake_expired_itimers(now);
    }
                crate::sync::futex::poll_timeouts();
                if crate::net::poll_with_progress() {
                    wake_socket_waiters();
                }
                if any_runnable_except(cur_pid) { break; }
                if !any_waiting()
                    && task_by_pid(1).map_or(false, |t| matches!(*t.state.lock(), TaskState::Zombie))
                {
                    // Only halt once the contest init (pid 1) itself is gone;
                    // a transient lull during a test's teardown keeps spinning.
                    crate::arch::shutdown();
                }
                core::hint::spin_loop();
            }
            // Loop back and try pick_ready again.
        }
    }

    // Round-robin nudge for the Ready/Running case. If the current
    // task is still runnable but another Ready task exists, yield to
    // them this trap. Without this, a userspace tight loop that does
    // a syscall per iteration (e.g. libctest's pthread_cancel_points
    // hammering tkill+sigreturn 36k times) monopolises the hart and
    // the busybox `timeout` daemon never gets scheduled to fire its
    // wall-clock SIGKILL. Cooperative-with-a-nudge: at every trap
    // boundary, if anyone else is Ready, switch to the
    // lowest-pid one.
    //
    // Important: pick_ready may return a task that becomes Zombie the
    // moment check_signals delivers SIGKILL to it. In that case we
    // must NOT have already switched satp/CURRENT_PID, because we'd
    // fall through to `current_tf` and re-enter the *current* task's
    // user code against a different task's page tables — instant
    // segfault for the wrapping sh when its child got cascade-killed.
    // Loop until we find a non-Zombie pick (or run out), then commit.
    let cur_satp = task_by_pid(cur_pid).map(|t| t.memory_set.lock().satp());
    while let Some(next) = pick_ready(cur_pid) {
        let next_satp = next.memory_set.lock().satp();
        // Speculatively switch satp so check_signals' copy_out for a
        // user signal frame writes to the right page table. If next
        // becomes Zombie below, restore cur_satp before falling back.
        if cur_satp != Some(next_satp) {
            crate::arch::activate_page_table(next_satp);
        }
        let next_tf = next.tf_ptr();
        unsafe { crate::signal::check_signals(&next, &mut *next_tf); }
        if matches!(*next.state.lock(), TaskState::Zombie) {
            // Restore the previous satp and try the next candidate.
            if let Some(s) = cur_satp {
                if Some(next_satp) != cur_satp {
                    crate::arch::activate_page_table(s);
                }
            }
            continue;
        }
        // Commit the switch: demote current to Ready, publish CURRENT_PID.
        if let Some(cur) = task_by_pid(cur_pid) {
            let mut s = cur.state.lock();
            if *s == TaskState::Running {
                *s = TaskState::Ready;
            }
        }
        CURRENT_PID.store(next.pid, Ordering::Relaxed);
        // Switch kernel contexts instead of just returning next's TrapFrame:
        // `cur` (demoted to Ready above) parks here and resumes through
        // `current_tf` the next time the scheduler picks it; `next` resumes
        // wherever it last parked.
        return unsafe { context_switch_to(cur_pid, next.pid, current_tf) };
    }

    current_tf
}

/// Preempt the current task mid-syscall: if preemption is currently enabled (no
/// lock held) and another task is Ready, switch to it so a long-running
/// in-kernel syscall cannot monopolise the hart. Called from the nested timer
/// trap (see each arch's handler). `cur_tf` is that nested frame — the current
/// task resumes its syscall through it when later rescheduled. Unlike the
/// trap-exit scheduler this does NOT deliver the current task's own signals
/// (it is mid-syscall; its signals are handled when it returns to user), but
/// it does deliver the incoming task's, exactly like the round-robin path.
/// Returns the frame the trap handler should return through.
///
/// # Safety
/// Call only from the nested-timer trap path; `cur_tf` must be that frame.
pub unsafe fn preempt_current(cur_tf: *mut TrapFrame) -> *mut TrapFrame {
    // A held lock means switching away could deadlock the next task on it.
    if !crate::sync::preempt_enabled() {
        return cur_tf;
    }
    let cur_pid = current_pid();
    let cur_satp = task_by_pid(cur_pid).map(|t| t.memory_set.lock().satp());
    while let Some(next) = pick_ready(cur_pid) {
        let next_satp = next.memory_set.lock().satp();
        if cur_satp != Some(next_satp) {
            crate::arch::activate_page_table(next_satp);
        }
        let next_tf = next.tf_ptr();
        crate::signal::check_signals(&next, &mut *next_tf);
        if matches!(*next.state.lock(), TaskState::Zombie) {
            // Killed by its own signal on arrival — restore satp, try another.
            if let Some(s) = cur_satp {
                if Some(next_satp) != cur_satp {
                    crate::arch::activate_page_table(s);
                }
            }
            continue;
        }
        // Demote the (mid-syscall) current task to Ready so it is re-picked
        // later, publish the new current, and switch. `cur` parks in the
        // nested timer frame and resumes its syscall there when rescheduled.
        if let Some(cur) = task_by_pid(cur_pid) {
            let mut s = cur.state.lock();
            if *s == TaskState::Running {
                *s = TaskState::Ready;
            }
        }
        CURRENT_PID.store(next.pid, Ordering::Relaxed);
        return context_switch_to(cur_pid, next.pid, cur_tf);
    }
    // Nobody else is Ready: resume the current syscall.
    cur_tf
}
