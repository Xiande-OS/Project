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
    pub ppid: AtomicI32,
    pub pgid: AtomicI32,
    pub sid: AtomicI32,
    storage: UnsafeCell<Box<TaskStorage>>,
    pub memory_set: Mutex<MemorySet>,
    pub fd_table: Mutex<crate::fs::FdTable>,
    pub cwd: Mutex<String>,
    pub state: Mutex<TaskState>,
    pub exit_code: AtomicI32,
    pub children: Mutex<Vec<i32>>,
    /// argv joined with NUL separators, NUL terminated. Used by /proc/<pid>/cmdline.
    pub cmdline: Mutex<Vec<u8>>,
    /// Absolute path to the executable image. Used by /proc/<pid>/exe and /comm.
    pub exe_path: Mutex<String>,
    pub signals: crate::signal::SignalState,
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
        ppid: AtomicI32::new(ppid),
        pgid: AtomicI32::new(pgid),
        sid: AtomicI32::new(sid),
        storage: UnsafeCell::new(TaskStorage::boxed()),
        memory_set: Mutex::new(ms),
        fd_table: Mutex::new(crate::fs::FdTable::new()),
        cwd: Mutex::new(String::from("/")),
        state: Mutex::new(TaskState::Running),
        exit_code: AtomicI32::new(0),
        children: Mutex::new(Vec::new()),
        cmdline: Mutex::new(Vec::new()),
        exe_path: Mutex::new(String::new()),
        signals: crate::signal::SignalState::new(),
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
    let parent = current_task();
    let mut new_ms = parent.memory_set.lock().fork();
    // fork() only copies user areas; the kernel identity map and MMIO
    // mappings need to be re-added so the trap handler keeps working
    // after we switch satp to the child's table.
    map_kernel_into(&mut new_ms);
    let mut new_tf = unsafe { (*parent.tf_ptr()).clone() };
    new_tf.x[9] = 0; // child sees 0 from clone
    let task = make_task_with_ms(new_ms, new_tf, parent.pid);
    *task.state.lock() = TaskState::Ready;
    {
        let new_fdt = parent.fd_table.lock().clone_for_fork();
        *task.fd_table.lock() = new_fdt;
        *task.cwd.lock() = parent.cwd.lock().clone();
        parent.children.lock().push(task.pid);
        // Inherit signal dispositions and mask, but child starts with no
        // pending signals.
        let inherited = parent.signals.fork_inherit();
        *task.signals.actions.lock() = *inherited.actions.lock();
        task.signals.mask.store(
            inherited.mask.load(core::sync::atomic::Ordering::Relaxed),
            core::sync::atomic::Ordering::Relaxed,
        );
        *task.signals.altstack.lock() = *inherited.altstack.lock();
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

    // Replace memory_set and activate its satp immediately.
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
            let satp = next.memory_set.lock().satp();
            CURRENT_PID.store(next.pid, Ordering::Relaxed);
            unsafe {
                core::arch::asm!(
                    "csrw satp, {satp}",
                    "sfence.vma",
                    satp = in(reg) satp,
                );
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
