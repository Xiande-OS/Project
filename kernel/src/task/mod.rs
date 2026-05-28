//! Per-process task and run loop.
//!
//! Layout invariants we depend on:
//!
//!   ```text
//!   TaskStorage buffer  [..kstack_usable..][TrapFrame]
//!                       ^low                ^tf_ptr   ^top = sscratch on trap entry
//!   ```
//!
//! The TrapFrame lives at the top of the per-task kernel stack so that
//! after `__trap_entry` saves the frame, `sp` lands at `tf_ptr` with the
//! usable kstack just below for the Rust handler's own frame.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::mem::size_of;
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

pub struct Task {
    storage: UnsafeCell<Box<TaskStorage>>,
    pub memory_set: Mutex<MemorySet>,
    pub fd_table: crate::fs::FdTable,
    pub cwd: Mutex<alloc::string::String>,
}

// SAFETY: M3 has a single task running on a single hart. The trap handler
// writes the TrapFrame area between syscalls; Rust code only accesses it
// in known-safe windows.
unsafe impl Send for Task {}
unsafe impl Sync for Task {}

impl Task {
    pub fn tf_ptr(&self) -> *mut TrapFrame {
        unsafe { (*self.storage.get()).tf_ptr() }
    }

    pub fn kstack_top(&self) -> usize {
        unsafe { (*self.storage.get()).kstack_top() }
    }

    /// Get a mut reference to the trap frame. Caller must ensure no
    /// concurrent access (trap.S does not run while this is held).
    pub unsafe fn trap_frame_mut(&self) -> &mut TrapFrame {
        &mut *self.tf_ptr()
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

static TASK: Lazy<Mutex<Option<Arc<Task>>>> = Lazy::new(|| Mutex::new(None));

pub fn current_task() -> Arc<Task> {
    TASK.lock().as_ref().expect("no current task").clone()
}

pub fn install_task(task: Arc<Task>) {
    *TASK.lock() = Some(task);
}

/// Build a Task from an ELF image, install it as current, and return it.
pub fn create_task_from_elf(
    elf_image: &[u8],
    argv: &[&str],
    envp: &[&str],
) -> Arc<Task> {
    let mut ms = MemorySet::new();

    extern "C" {
        fn __kernel_start();
    }
    let k_start = __kernel_start as usize;
    ms.map_kernel_identity(k_start, crate::mm::mm_end());
    ms.map_mmio(0x0c00_0000, 0x1000_0000); // PLIC
    ms.map_mmio(0x1000_0000, 0x1000_1000); // UART
    ms.map_mmio(0x1000_1000, 0x1000_9000); // virtio-mmio

    let elf = crate::loader::load_elf(elf_image, &mut ms).expect("ELF load");
    let user_sp_top = setup_initial_stack(&elf, &mut ms, argv, envp);

    let mut tf = TrapFrame::default();
    tf.sepc = elf.entry;
    tf.x[1] = user_sp_top;
    // sstatus: SPP=0 (return to U-mode), SPIE=1, SUM=1 (kernel can poke user mem).
    let sstatus: usize = (1 << 5) | (1 << 18);
    tf.sstatus = sstatus;

    let task = Arc::new(Task {
        storage: UnsafeCell::new(TaskStorage::boxed()),
        memory_set: Mutex::new(ms),
        fd_table: crate::fs::FdTable::new(),
        cwd: Mutex::new(alloc::string::String::from("/")),
    });

    // Copy TF into the storage.
    unsafe {
        core::ptr::write(task.tf_ptr(), tf);
    }

    install_task(task.clone());
    task
}

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
        (3, elf.phdr_va),                              // AT_PHDR
        (4, elf.phent),                                // AT_PHENT
        (5, elf.phnum),                                // AT_PHNUM
        (6, PAGE_SIZE),                                // AT_PAGESZ
        (7, 0),                                        // AT_BASE
        (8, 0),                                        // AT_FLAGS
        (9, elf.entry),                                // AT_ENTRY
        (11, 0),                                       // AT_UID
        (12, 0),                                       // AT_EUID
        (13, 0),                                       // AT_GID
        (14, 0),                                       // AT_EGID
        (16, 0),                                       // AT_HWCAP
        (17, 100),                                     // AT_CLKTCK
        (23, 0),                                       // AT_SECURE
        (25, random_va),                               // AT_RANDOM
        (15, platform_va),                             // AT_PLATFORM
        (31, arg_addrs.first().copied().unwrap_or(0)), // AT_EXECFN
        (0, 0),                                        // AT_NULL
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

/// Enter user-mode for the first time, and never return. Activates the
/// task's satp, then tail-calls into the trap-return asm to restore the
/// initial register set and `sret`.
pub fn run_user_loop(task: &Arc<Task>) -> ! {
    extern "C" {
        fn __trap_return(tf: *const TrapFrame) -> !;
    }

    let satp = task.memory_set.lock().satp();
    let tf_ptr = task.tf_ptr();

    unsafe {
        // Set kernel sp for the very first trap: we want it equal to
        // (tf_ptr + size_of::<TrapFrame>()), which __trap_return will
        // load into sscratch on return-to-user.
        core::arch::asm!(
            "csrw satp, {satp}",
            "sfence.vma",
            satp = in(reg) satp,
        );
        __trap_return(tf_ptr as *const _);
    }
}
