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
use core::sync::atomic::{AtomicI32, Ordering};
use spin::{Lazy, Mutex};

use crate::arch::riscv64::trap::TrapFrame;
use crate::loader::LoadedElf;
use crate::mm::memory_set::{MemorySet, VmArea, VmPerm};
use crate::mm::{VirtAddr, PAGE_SIZE};

const KSTACK_SIZE: usize = 64 * 1024;

#[repr(C, align(16))]
struct TaskStorage {
    buf: [u8; KSTACK_SIZE],
}

impl TaskStorage {
    fn boxed() -> Box<Self> {
        Box::new(Self {
            buf: [0u8; KSTACK_SIZE],
        })
    }

    fn kstack_top(&self) -> usize {
        self.buf.as_ptr() as usize + KSTACK_SIZE
    }

    fn tf_ptr(&self) -> *mut TrapFrame {
        (self.kstack_top() - size_of::<TrapFrame>()) as *mut TrapFrame
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

    pub fn copy_in_bytes(&self, va: usize, len: usize) -> Option<Vec<u8>> {
        let ms = self.memory_set.lock();
        copy_in_via(&ms, va, len)
    }

    pub fn copy_out_bytes(&self, va: usize, bytes: &[u8]) -> Option<()> {
        let ms = self.memory_set.lock();
        copy_out_via(&ms, va, bytes)
    }

    pub fn memory_set_mut(&self) -> spin::MutexGuard<'_, MemorySet> {
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
    let mut out = Vec::with_capacity(len);
    let mut cursor = va;
    let end = va.checked_add(len)?;
    while cursor < end {
        let page_va = cursor & !(PAGE_SIZE - 1);
        let page_off = cursor & (PAGE_SIZE - 1);
        let chunk = core::cmp::min(PAGE_SIZE - page_off, end - cursor);
        let pa = ms.translate(VirtAddr(page_va))?;
        let src = unsafe {
            core::slice::from_raw_parts((pa.0 + page_off) as *const u8, chunk)
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
        let pa = ms.translate(VirtAddr(page_va))?;
        let dst = unsafe {
            core::slice::from_raw_parts_mut((pa.0 + page_off) as *mut u8, chunk)
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

/// Snapshot of every task in the table. Cloning Arcs keeps it cheap
/// and avoids holding the table lock while callers iterate.
pub fn all_tasks() -> Vec<Arc<Task>> {
    let t = TABLE.lock();
    t.tasks.values().cloned().collect()
}

/// Mark this task as blocked on socket activity rather than wait4/futex.
/// `wake_socket_waiters` only wakes tasks in this set, so a wait4 caller
/// doesn't get spuriously bounced back to Ready every trap.
static SOCKET_WAITERS: spin::Mutex<alloc::collections::BTreeSet<i32>> =
    spin::Mutex::new(alloc::collections::BTreeSet::new());

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

    let mut tf = TrapFrame::default();
    tf.sepc = elf.entry;
    tf.x[1] = user_sp_top;
    // SPIE | SUM | FS=Initial (1<<13) so user-mode FP doesn't trap on first
    // touch. busybox' setjmp saves fs0..fs11.
    let sstatus: usize = (1 << 5) | (1 << 18) | (1 << 13);
    tf.sstatus = sstatus;

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
        children: Mutex::new(Vec::new()),
        cmdline: Mutex::new(Vec::new()),
        exe_path: Mutex::new(String::new()),
        signals: crate::signal::SignalState::new(),
        clear_child_tid: Mutex::new(0),
    });
    unsafe {
        core::ptr::write(task.tf_ptr(), tf);
    }
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

    let platform = b"riscv64\0";
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

    let auxv: alloc::vec::Vec<(usize, usize)> = alloc::vec![
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
        (16, 0),
        (17, 100),
        (23, 0),
        (25, random_va),
        (15, platform_va),
        (31, arg_addrs.first().copied().unwrap_or(0)),
        (0, 0),
    ];

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

pub fn fork_current() -> Arc<Task> {
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
) -> Arc<Task> {
    let parent = current_task();

    // ---- Address space ----
    let memory_set: Arc<Mutex<MemorySet>> = if flags & CLONE_VM != 0 {
        // Share: same Arc, same satp, same page table.
        parent.memory_set.clone()
    } else {
        // Deep-copy parent's user areas; remap the kernel/MMIO identity into
        // the new page table so the trap handler keeps working after a
        // future satp switch.
        let mut new_ms = parent.memory_set.lock().fork();
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
    new_tf.x[9] = 0; // child sees 0 from clone
    if child_sp != 0 {
        new_tf.x[1] = child_sp;
    }
    if flags & CLONE_SETTLS != 0 {
        new_tf.x[3] = newtls; // x4 = tp (index 3 because x[0] is x1)
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

    let task = Arc::new(Task {
        pid,
        tgid: AtomicI32::new(tgid),
        ppid: AtomicI32::new(ppid),
        pgid: AtomicI32::new(pgid),
        sid: AtomicI32::new(sid),
        storage: UnsafeCell::new(TaskStorage::boxed()),
        memory_set,
        fd_table,
        cwd,
        state: Mutex::new(TaskState::Ready),
        exit_code: AtomicI32::new(0),
        children: Mutex::new(Vec::new()),
        cmdline: Mutex::new(parent.cmdline.lock().clone()),
        exe_path: Mutex::new(parent.exe_path.lock().clone()),
        signals: if flags & CLONE_SIGHAND != 0 {
            parent.signals.share_actions_inherit()
        } else {
            parent.signals.fork_inherit()
        },
        clear_child_tid: Mutex::new(0),
    });
    // Write the TF onto the new kstack.
    unsafe {
        core::ptr::write(task.tf_ptr(), new_tf);
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
    task
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
    let mut ms = MemorySet::new();
    map_kernel_into(&mut ms);
    let elf = crate::loader::load_elf(elf_image, &mut ms).map_err(|_| -22i32)?;
    let user_sp_top = setup_initial_stack(&elf, &mut ms, argv, envp);
    crate::signal::install_restorer_page(&mut ms);

    // execve detaches the caller from any shared address space (POSIX
    // semantics): we replace the contents of the Arc<Mutex<MemorySet>>.
    // If it was shared (e.g. by a CLONE_VM thread that lived past exec),
    // the other thread keeps the *old* shared Arc — but in practice
    // pthread_create + execve is undefined, so this is safe for our test
    // matrix. We just swap the lock's contents.
    let new_satp;
    {
        let mut slot = task.memory_set.lock();
        *slot = ms;
        new_satp = slot.satp();
    }
    unsafe {
        core::arch::asm!(
            "csrw satp, {satp}",
            "sfence.vma",
            satp = in(reg) new_satp,
        );
    }

    // Replace trap frame with fresh entry state.
    let mut tf = TrapFrame::default();
    tf.sepc = elf.entry;
    tf.x[1] = user_sp_top;
    tf.sstatus = (1 << 5) | (1 << 18) | (1 << 13); // SPIE | SUM | FS=Initial
    unsafe {
        core::ptr::write(task.tf_ptr(), tf);
    }

    // close-on-exec
    task.fd_table.lock().close_cloexec();

    // Record cmdline + exe_path for procfs.
    *task.cmdline.lock() = build_cmdline(argv);
    if !exe_path.is_empty() {
        *task.exe_path.lock() = exe_path.into();
    }
    // POSIX: keep mask, reset every user-installed handler to SIG_DFL
    // (SIG_IGN survives), clear pending, clear altstack.
    task.signals.reset_for_exec();
    // execve also clears any pending CLONE_CHILD_CLEARTID address.
    *task.clear_child_tid.lock() = 0;
    Ok(())
}

/// First-time entry to user mode for the initial task.
pub fn run_user_loop(task: &Arc<Task>) -> ! {
    extern "C" {
        fn __trap_return(tf: *const TrapFrame) -> !;
    }

    let satp = task.memory_set.lock().satp();
    let tf_ptr = task.tf_ptr();

    unsafe {
        core::arch::asm!(
            "csrw satp, {satp}",
            "sfence.vma",
            satp = in(reg) satp,
        );
        __trap_return(tf_ptr as *const _);
    }
}

/// Called by the trap handler. Decides which task to return through and
/// switches satp + current_pid accordingly. Returns the TF to load.
pub fn schedule_next_after_trap(current_tf: *mut TrapFrame) -> *mut TrapFrame {
    // Push/pull whatever the network stack has been doing while user-mode
    // ran. Cheap no-op if the stack isn't up.
    crate::net::poll();
    // Wake any tasks that were blocked on sockets and now have progress.
    wake_socket_waiters();

    let cur_pid = current_pid();

    // Sweep futex timeouts every trap exit; cheap on an empty queue.
    crate::sync::futex::poll_timeouts();

    // Reap any detached threads (CLONE_THREAD) that died last round.
    // We can't reap the current pid even if dead — kstack still in use.
    crate::syscall::drain_self_reap_list(cur_pid);

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
        }
    }

    let cur_state = task_by_pid(cur_pid).map(|t| *t.state.lock());

    if matches!(cur_state, Some(TaskState::Zombie) | Some(TaskState::Waiting)) {
        if let Some(next) = pick_ready(cur_pid) {
            let next_satp = next.memory_set.lock().satp();
            // Fast path: same address space (CLONE_VM threads) — skip the
            // csrw+sfence; satp is already correct for the new task.
            let cur_satp = task_by_pid(cur_pid).map(|t| t.memory_set.lock().satp());
            CURRENT_PID.store(next.pid, Ordering::Relaxed);
            if cur_satp != Some(next_satp) {
                unsafe {
                    core::arch::asm!(
                        "csrw satp, {satp}",
                        "sfence.vma",
                        satp = in(reg) next_satp,
                    );
                }
            }
            // Also deliver signals to the new current task.
            let next_tf = next.tf_ptr();
            unsafe {
                crate::signal::check_signals(&next, &mut *next_tf);
            }
            return next_tf;
        }
        if cur_state == Some(TaskState::Waiting) {
            if let Some(t) = task_by_pid(cur_pid) {
                *t.state.lock() = TaskState::Running;
            }
        }
        if cur_state == Some(TaskState::Zombie) {
            // No other runnable task -- shutdown.
            if !any_runnable_except(cur_pid) && !any_waiting() {
                sbi_rt::system_reset(sbi_rt::Shutdown, sbi_rt::NoReason);
                loop {
                    unsafe { core::arch::asm!("wfi") };
                }
            }
        }
    }

    current_tf
}
