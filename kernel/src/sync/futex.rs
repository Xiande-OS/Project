//! Blocking futex implementation.
//!
//! We key the waiter queue by the *physical* address of the futex word so
//! that two threads sharing a MemorySet (CLONE_VM) automatically agree
//! on the same queue regardless of how the userspace pointers were
//! materialised. PRIVATE futexes work too, since within a single process
//! PA == PA.
//!
//! Supported ops (musl-only enough to make pthread_mutex/cond + join work):
//!   FUTEX_WAIT, FUTEX_WAKE, FUTEX_WAIT_BITSET, FUTEX_WAKE_BITSET,
//!   FUTEX_REQUEUE, FUTEX_CMP_REQUEUE.
//!
//! Blocking model: the calling task is marked Waiting + sepc is rewound
//! by 4 so the syscall re-runs on wake. On wake, we set Ready and clear
//! the per-task `WaitResult` (Wake/Timedout/Intr) — the syscall checks
//! this on the re-entry path.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicI32, Ordering};
use spin::{Lazy, Mutex};

use crate::task::{current_task, task_by_pid, Task, TaskState};

// ---- musl/Linux futex op codes ----
pub const FUTEX_WAIT: i32 = 0;
pub const FUTEX_WAKE: i32 = 1;
pub const FUTEX_REQUEUE: i32 = 3;
pub const FUTEX_CMP_REQUEUE: i32 = 4;
pub const FUTEX_WAKE_OP: i32 = 5;
pub const FUTEX_WAIT_BITSET: i32 = 9;
pub const FUTEX_WAKE_BITSET: i32 = 10;
pub const FUTEX_PRIVATE_FLAG: i32 = 128;
pub const FUTEX_CLOCK_REALTIME: i32 = 256;
pub const FUTEX_CMD_MASK: i32 = !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);

// ---- errno ----
pub const EAGAIN: isize = -11;
pub const EINTR: isize = -4;
pub const ETIMEDOUT: isize = -110;
pub const EINVAL: isize = -22;
pub const EFAULT: isize = -14;

/// Why a futex wait ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitResult {
    /// Still blocked (or never blocked). Default state.
    None = 0,
    /// FUTEX_WAKE delivered us.
    Woken = 1,
    /// Timed out waiting.
    Timedout = 2,
    /// A signal arrived.
    Intr = 3,
}

impl From<i32> for WaitResult {
    fn from(v: i32) -> Self {
        match v {
            1 => WaitResult::Woken,
            2 => WaitResult::Timedout,
            3 => WaitResult::Intr,
            _ => WaitResult::None,
        }
    }
}

/// Per-task wake-state, stored as an atomic so wake/timeout/signal can poke
/// it without taking the futex queue lock. Keyed by pid.
static WAIT_RESULT: Lazy<Mutex<BTreeMap<i32, Arc<AtomicI32>>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

pub fn wait_result(pid: i32) -> Arc<AtomicI32> {
    let mut t = WAIT_RESULT.lock();
    if let Some(slot) = t.get(&pid) {
        return slot.clone();
    }
    let slot = Arc::new(AtomicI32::new(0));
    t.insert(pid, slot.clone());
    slot
}

pub fn take_wait_result(pid: i32) -> WaitResult {
    let r = wait_result(pid).swap(0, Ordering::SeqCst);
    WaitResult::from(r)
}

pub fn set_wait_result(pid: i32, res: WaitResult) {
    wait_result(pid).store(res as i32, Ordering::SeqCst);
}

/// One queued waiter.
#[derive(Clone, Copy)]
struct Waiter {
    pid: i32,
    bitset: u32,
    /// Absolute deadline in monotonic mtime ticks (10MHz). 0 = no timeout.
    deadline_ticks: u64,
}

/// Global futex queue: PA -> waiter list. PA is a `u64` (we don't expect to
/// store more than usize but i64-keyed BTreeMap is fine on riscv64).
static FUTEXES: Lazy<Mutex<BTreeMap<u64, VecDeque<Waiter>>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

/// Translate a user VA to a PA so we have a stable key independent of the
/// thread's PT mapping (CLONE_VM threads still hit the same key; non-VM
/// threads use a different PA, which is what we want).
fn futex_key(task: &Arc<Task>, uaddr: usize) -> Option<u64> {
    if uaddr == 0 || uaddr & 0x3 != 0 {
        return None;
    }
    let ms = task.memory_set.lock();
    let pa = ms.translate(crate::mm::VirtAddr(uaddr))?;
    Some(pa.0 as u64)
}

fn read_u32(task: &Arc<Task>, uaddr: usize) -> Option<u32> {
    let b = task.copy_in_bytes(uaddr, 4)?;
    let arr: [u8; 4] = b.as_slice().try_into().ok()?;
    Some(u32::from_le_bytes(arr))
}

fn parse_timespec(task: &Arc<Task>, ts_ptr: usize) -> Option<(u64, u64)> {
    if ts_ptr == 0 {
        return None;
    }
    let b = task.copy_in_bytes(ts_ptr, 16)?;
    let sec = u64::from_le_bytes(b[0..8].try_into().ok()?);
    let nsec = u64::from_le_bytes(b[8..16].try_into().ok()?);
    Some((sec, nsec))
}

fn ts_to_ticks(sec: u64, nsec: u64) -> u64 {
    sec.saturating_mul(10_000_000).saturating_add(nsec / 100)
}

/// Main dispatcher; returns the syscall return value (in isize/errno form).
pub fn do_futex(
    uaddr: usize,
    op: i32,
    val: u32,
    val2_or_timeout: usize,
    uaddr2: usize,
    val3: u32,
) -> isize {
    let cmd = op & FUTEX_CMD_MASK;
    let task = current_task();

    match cmd {
        // FUTEX_WAIT: timeout is RELATIVE.
        FUTEX_WAIT => futex_wait(&task, uaddr, val, val2_or_timeout, u32::MAX, false),
        // FUTEX_WAIT_BITSET: timeout is ABSOLUTE (in the clock selected by
        // FUTEX_CLOCK_REALTIME; our CLOCK_REALTIME and CLOCK_MONOTONIC are
        // both the boot-relative mtime, so either way the deadline is an
        // absolute mtime value). glibc's pthread_cond_timedwait uses this.
        FUTEX_WAIT_BITSET => {
            if val3 == 0 {
                return EINVAL;
            }
            futex_wait(&task, uaddr, val, val2_or_timeout, val3, true)
        }
        FUTEX_WAKE => futex_wake(&task, uaddr, val as i32, u32::MAX),
        FUTEX_WAKE_BITSET => {
            if val3 == 0 {
                return EINVAL;
            }
            futex_wake(&task, uaddr, val as i32, val3)
        }
        FUTEX_REQUEUE => futex_requeue(&task, uaddr, val as i32, uaddr2, val2_or_timeout as i32, None),
        FUTEX_CMP_REQUEUE => futex_requeue(
            &task,
            uaddr,
            val as i32,
            uaddr2,
            val2_or_timeout as i32,
            Some(val3),
        ),
        _ => EINVAL,
    }
}

/// `FUTEX_WAIT(uaddr, val, timeout)` —
///
/// (1) Load `*uaddr` atomically. If it doesn't equal `val`, return EAGAIN.
/// (2) Enqueue ourselves, mark Waiting, rewind sepc by 4 so the same ecall
///     re-runs on wake. The trampoline at the bottom (`finish_wait`) on the
///     resumption path inspects WAIT_RESULT and returns 0 / -EINTR /
///     -ETIMEDOUT accordingly.
fn futex_wait(task: &Arc<Task>, uaddr: usize, val: u32, timeout_ptr: usize, bitset: u32, absolute: bool) -> isize {
    // First check if we're resuming after a wake: WAIT_RESULT non-zero means
    // we already blocked once and are re-running this syscall.
    let prior = take_wait_result(task.pid);
    if prior != WaitResult::None {
        return match prior {
            WaitResult::Woken => 0,
            WaitResult::Timedout => ETIMEDOUT,
            WaitResult::Intr => EINTR,
            WaitResult::None => 0,
        };
    }

    // Resolve the key. If translate fails, fault.
    let Some(key) = futex_key(task, uaddr) else {
        return EFAULT;
    };

    // Atomic compare. We don't have atomic R-M-W to user memory; rely on
    // single-hart cooperative scheduling guaranteeing nobody else runs.
    let cur = match read_u32(task, uaddr) {
        Some(v) => v,
        None => return EFAULT,
    };
    if cur != val {
        return EAGAIN;
    }

    // Compute the absolute deadline in mtime ticks. FUTEX_WAIT passes a
    // *relative* timeout (deadline = now + ticks); FUTEX_WAIT_BITSET passes
    // an *absolute* deadline already in our (boot-relative mtime) timebase,
    // so the timespec converts straight to the deadline. Treating the
    // absolute BITSET deadline as relative made `now + (now+10ms)` ≈ 2·now,
    // so glibc's pthread_cond_timedwait(10ms) only "timed out" after another
    // `now` worth of uptime — fine early in a run, but past the per-test
    // watchdog once uptime grew (the flaky pthread_condattr_setclock hang).
    let now = crate::arch::now_ticks();
    let deadline_ticks = if let Some((s, ns)) = parse_timespec(task, timeout_ptr) {
        let ticks = ts_to_ticks(s, ns);
        if absolute {
            // Absolute deadline already passed → immediate timeout.
            if ticks <= now {
                return ETIMEDOUT;
            }
            ticks
        } else {
            if ticks == 0 {
                return ETIMEDOUT; // 0 relative timespec → immediate timeout
            }
            now.saturating_add(ticks)
        }
    } else {
        0
    };

    // Enqueue.
    FUTEXES.lock().entry(key).or_default().push_back(Waiter {
        pid: task.pid,
        bitset,
        deadline_ticks,
    });

    // Mark Waiting + rewind sepc by 4 so we re-enter the syscall on wake.
    {
        let mut s = task.state.lock();
        *s = TaskState::Waiting;
    }
    unsafe {
        (*task.tf_ptr()).sepc -= 4;
    }
    0
}

/// Public helper: same as futex_wake(FUTEX_WAKE) but addressable by an
/// arbitrary `Task` (not necessarily current). Used by exit/cleartid
/// paths. Returns count woken.
pub fn wake_for_task(task: &Arc<Task>, uaddr: usize, n: i32) -> isize {
    futex_wake(task, uaddr, n, u32::MAX)
}

/// FUTEX_WAKE — wake up to `n` waiters on `uaddr` whose `bitset` overlaps
/// `mask`. Returns the count woken.
fn futex_wake(task: &Arc<Task>, uaddr: usize, n: i32, mask: u32) -> isize {
    let Some(key) = futex_key(task, uaddr) else { return EFAULT; };
    let mut woken = 0i32;
    let mut tab = FUTEXES.lock();
    if let Some(q) = tab.get_mut(&key) {
        let mut i = 0;
        while i < q.len() && woken < n {
            let entry = q[i];
            if entry.bitset & mask != 0 {
                q.remove(i);
                drop_and_wake(entry.pid);
                woken += 1;
            } else {
                i += 1;
            }
        }
        if q.is_empty() {
            tab.remove(&key);
        }
    }
    woken as isize
}

/// FUTEX_REQUEUE / FUTEX_CMP_REQUEUE — wake `wake_n` on key1, move up to
/// `req_n` from key1 → key2. For CMP variant, first check *uaddr == cmpval.
fn futex_requeue(
    task: &Arc<Task>,
    uaddr: usize,
    wake_n: i32,
    uaddr2: usize,
    req_n: i32,
    cmpval: Option<u32>,
) -> isize {
    let Some(key1) = futex_key(task, uaddr) else { return EFAULT; };
    let Some(key2) = futex_key(task, uaddr2) else { return EFAULT; };

    if let Some(cmp) = cmpval {
        let cur = match read_u32(task, uaddr) {
            Some(v) => v,
            None => return EFAULT,
        };
        if cur != cmp {
            return EAGAIN;
        }
    }

    let mut moved = 0i32;
    let mut woken = 0i32;
    let mut tab = FUTEXES.lock();

    // Step 1: wake up to wake_n from key1.
    if let Some(q) = tab.get_mut(&key1) {
        while woken < wake_n {
            let Some(w) = q.pop_front() else { break };
            drop_and_wake(w.pid);
            woken += 1;
        }
    }
    // Step 2: requeue up to req_n more from key1 to key2.
    if wake_n >= 0 && req_n > 0 {
        let mut moved_entries: alloc::vec::Vec<Waiter> = alloc::vec::Vec::new();
        if let Some(q) = tab.get_mut(&key1) {
            while moved < req_n {
                let Some(w) = q.pop_front() else { break };
                moved_entries.push(w);
                moved += 1;
            }
            if q.is_empty() {
                tab.remove(&key1);
            }
        }
        if !moved_entries.is_empty() {
            let q2 = tab.entry(key2).or_default();
            for w in moved_entries {
                q2.push_back(w);
            }
        }
    }
    // Cleanup if key1 is now empty.
    if let Some(q) = tab.get(&key1) {
        if q.is_empty() {
            tab.remove(&key1);
        }
    }

    (woken + moved) as isize
}

/// Mark `pid` Ready and set its WAIT_RESULT to Woken.
fn drop_and_wake(pid: i32) {
    set_wait_result(pid, WaitResult::Woken);
    if let Some(t) = task_by_pid(pid) {
        let mut s = t.state.lock();
        if *s == TaskState::Waiting {
            *s = TaskState::Ready;
        }
    }
}

/// True if any waiter in any queue has a finite deadline still in
/// the future. Used by the scheduler's deadlock check.
pub fn has_pending_deadline(now: u64) -> bool {
    let tab = FUTEXES.lock();
    for q in tab.values() {
        for w in q {
            if w.deadline_ticks != 0 && w.deadline_ticks > now {
                return true;
            }
        }
    }
    false
}

/// Poll-driven timeout sweep. Called from the scheduler between trap exits.
/// Walks every queue; for each Waiter whose deadline has passed, removes it
/// from the queue and marks Ready with WaitResult::Timedout.
pub fn poll_timeouts() {
    let now = crate::arch::now_ticks();
    let mut tab = FUTEXES.lock();
    let mut empty_keys: alloc::vec::Vec<u64> = alloc::vec::Vec::new();
    for (key, q) in tab.iter_mut() {
        let mut i = 0;
        while i < q.len() {
            let w = q[i];
            if w.deadline_ticks != 0 && now >= w.deadline_ticks {
                q.remove(i);
                set_wait_result(w.pid, WaitResult::Timedout);
                if let Some(t) = task_by_pid(w.pid) {
                    let mut s = t.state.lock();
                    if *s == TaskState::Waiting {
                        *s = TaskState::Ready;
                    }
                }
            } else {
                i += 1;
            }
        }
        if q.is_empty() {
            empty_keys.push(*key);
        }
    }
    for k in empty_keys {
        tab.remove(&k);
    }
}

/// Called from signal raise: if `pid` is parked in a futex queue, remove
/// it from there and mark WaitResult::Intr so the re-entered syscall
/// returns EINTR. Cooperatively wakes the task; if not in any queue, no-op.
pub fn interrupt_wait(pid: i32) -> bool {
    let mut tab = FUTEXES.lock();
    let mut empty_keys: alloc::vec::Vec<u64> = alloc::vec::Vec::new();
    let mut hit = false;
    for (key, q) in tab.iter_mut() {
        let mut i = 0;
        while i < q.len() {
            if q[i].pid == pid {
                q.remove(i);
                hit = true;
            } else {
                i += 1;
            }
        }
        if q.is_empty() {
            empty_keys.push(*key);
        }
    }
    for k in empty_keys {
        tab.remove(&k);
    }
    if hit {
        set_wait_result(pid, WaitResult::Intr);
    }
    hit
}

/// Called from task exit: clean up the futex/wait-result entries so they
/// don't leak.
pub fn forget_task(pid: i32) {
    interrupt_wait(pid); // remove from any queue
    WAIT_RESULT.lock().remove(&pid);
}
