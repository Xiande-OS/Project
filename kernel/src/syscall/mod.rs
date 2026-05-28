//! Syscall dispatch.

pub mod nr;

use crate::arch::riscv64::trap::TrapFrame;
use crate::println;
use crate::task::current_task;

const ENOSYS: isize = -38;
const EBADF: isize = -9;
const EFAULT: isize = -14;
const EINVAL: isize = -22;
const ERANGE: isize = -34;
const ENOENT: isize = -2;

/// Called by the trap handler when scause is U-mode ecall. The TrapFrame
/// argument is mutable so the return value can be written into a0.
pub fn dispatch(tf: &mut TrapFrame) {
    let id = tf.x[16]; // a7
    let a0 = tf.x[9];
    let a1 = tf.x[10];
    let a2 = tf.x[11];
    let a3 = tf.x[12];
    let a4 = tf.x[13];
    let a5 = tf.x[14];

    if syscall_trace_enabled() {
        crate::println!(
            "[sys] #{} sp={:#x} a0={:#x} a1={:#x} a2={:#x}",
            id, tf.x[1], a0, a1, a2
        );
    }

    let ret = match id {
        nr::SYS_WRITE => sys_write(a0, a1, a2),
        nr::SYS_WRITEV => sys_writev(a0, a1, a2),
        nr::SYS_READ => sys_read(a0, a1, a2),
        nr::SYS_READV => sys_readv(a0, a1, a2),
        nr::SYS_EXIT | nr::SYS_EXIT_GROUP => sys_exit(a0 as i32),
        nr::SYS_BRK => sys_brk(a0),
        nr::SYS_SET_TID_ADDRESS => sys_set_tid_address(a0),
        nr::SYS_SET_ROBUST_LIST => 0,
        nr::SYS_RT_SIGACTION => 0,
        nr::SYS_RT_SIGPROCMASK => 0,
        nr::SYS_IOCTL => sys_ioctl(a0, a1, a2),
        nr::SYS_GETUID | nr::SYS_GETEUID | nr::SYS_GETGID | nr::SYS_GETEGID => 0,
        nr::SYS_GETPID => 1,
        nr::SYS_GETTID => 1,
        nr::SYS_UNAME => sys_uname(a0),
        nr::SYS_GETRANDOM => sys_getrandom(a0, a1, a2),
        nr::SYS_MMAP => sys_mmap(a0, a1, a2 as i32, a3 as i32, a4 as i32, a5),
        nr::SYS_MUNMAP => 0,
        nr::SYS_MPROTECT => 0,
        nr::SYS_MADVISE => 0,
        nr::SYS_PRLIMIT64 => 0,
        nr::SYS_CLOCK_GETTIME => sys_clock_gettime(a0, a1),
        nr::SYS_SCHED_YIELD => 0,
        nr::SYS_TGKILL => 0,
        nr::SYS_TKILL => 0,
        nr::SYS_FUTEX => 0,
        nr::SYS_PPOLL => 0, // 0 fds ready (timeout)
        nr::SYS_FCNTL => 0,
        nr::SYS_SIGALTSTACK => 0,
        nr::SYS_RT_SIGTIMEDWAIT => 0,
        nr::SYS_RT_SIGSUSPEND => 0,
        nr::SYS_GETTIMEOFDAY => sys_gettimeofday(a0),
        nr::SYS_SYSINFO => 0,
        nr::SYS_GETRUSAGE => 0,
        nr::SYS_MEMBARRIER => 0,
        nr::SYS_TIMES => 0,
        nr::SYS_READLINKAT => sys_readlinkat(a0 as i32, a1, a2, a3),
        nr::SYS_OPENAT => sys_openat(a0 as i32, a1, a2 as i32, a3 as i32),
        nr::SYS_CLOSE => sys_close(a0 as i32),
        nr::SYS_NEWFSTATAT | nr::SYS_FSTAT | nr::SYS_STATX => 0,
        nr::SYS_FACCESSAT | nr::SYS_FACCESSAT2 => 0,
        nr::SYS_GETCWD => sys_getcwd(a0, a1),
        _ => {
            println!("[syscall] unimplemented #{} a0={:#x} a1={:#x}", id, a0, a1);
            ENOSYS
        }
    };

    if syscall_trace_enabled() {
        crate::println!("[sys] #{} -> {:#x}", id, ret as usize);
    }
    tf.x[9] = ret as usize;
}

use core::sync::atomic::{AtomicBool, Ordering};
static SYSCALL_TRACE: AtomicBool = AtomicBool::new(false);

fn syscall_trace_enabled() -> bool {
    SYSCALL_TRACE.load(Ordering::Relaxed)
}

pub fn set_syscall_trace(on: bool) {
    SYSCALL_TRACE.store(on, Ordering::Relaxed);
}

fn sys_write(fd: usize, buf: usize, len: usize) -> isize {
    if fd != 1 && fd != 2 {
        return EBADF;
    }
    let task = current_task();
    let Some(bytes) = task.copy_in_bytes(buf, len) else {
        return EFAULT;
    };
    for b in &bytes {
        #[allow(deprecated)]
        sbi_rt::legacy::console_putchar(*b as usize);
    }
    bytes.len() as isize
}

#[repr(C)]
struct IoVec {
    base: usize,
    len: usize,
}

fn sys_writev(fd: usize, iov: usize, count: usize) -> isize {
    if fd != 1 && fd != 2 {
        return EBADF;
    }
    if count == 0 {
        return 0;
    }
    let task = current_task();
    let Some(iovs_bytes) = task.copy_in_bytes(iov, count * core::mem::size_of::<IoVec>()) else {
        return EFAULT;
    };
    let iovs = unsafe {
        core::slice::from_raw_parts(iovs_bytes.as_ptr() as *const IoVec, count)
    };
    let mut total = 0isize;
    for v in iovs {
        if v.len == 0 {
            continue;
        }
        let Some(bytes) = task.copy_in_bytes(v.base, v.len) else {
            return EFAULT;
        };
        for b in &bytes {
            #[allow(deprecated)]
            sbi_rt::legacy::console_putchar(*b as usize);
        }
        total += bytes.len() as isize;
    }
    total
}

fn sys_read(fd: usize, _buf: usize, _len: usize) -> isize {
    if fd == 0 {
        0
    } else {
        EBADF
    }
}

fn sys_readv(_fd: usize, _iov: usize, _count: usize) -> isize {
    0
}

fn sys_exit(status: i32) -> isize {
    println!("[syscall] task exit({})", status);
    sbi_rt::system_reset(sbi_rt::Shutdown, sbi_rt::NoReason);
    loop {
        unsafe { core::arch::asm!("wfi") };
    }
}

fn sys_brk(new_brk: usize) -> isize {
    let task = current_task();
    let mut ms = task.memory_set_mut();
    let cur = ms.brk_set(crate::mm::VirtAddr(new_brk));
    cur.0 as isize
}

fn sys_set_tid_address(_addr: usize) -> isize {
    1
}

fn sys_ioctl(_fd: usize, _req: usize, _arg: usize) -> isize {
    0
}

#[repr(C)]
struct Utsname {
    sysname: [u8; 65],
    nodename: [u8; 65],
    release: [u8; 65],
    version: [u8; 65],
    machine: [u8; 65],
    domainname: [u8; 65],
}

fn write_field(dst: &mut [u8; 65], s: &str) {
    let n = core::cmp::min(64, s.len());
    dst[..n].copy_from_slice(&s.as_bytes()[..n]);
    dst[n] = 0;
}

fn sys_uname(addr: usize) -> isize {
    let mut uts = Utsname {
        sysname: [0; 65],
        nodename: [0; 65],
        release: [0; 65],
        version: [0; 65],
        machine: [0; 65],
        domainname: [0; 65],
    };
    write_field(&mut uts.sysname, "Linux");
    write_field(&mut uts.nodename, "xiande");
    write_field(&mut uts.release, "6.6.0-xiande");
    write_field(&mut uts.version, "#1 SMP xiande-os");
    write_field(&mut uts.machine, "riscv64");
    write_field(&mut uts.domainname, "(none)");
    let task = current_task();
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &uts as *const _ as *const u8,
            core::mem::size_of::<Utsname>(),
        )
    };
    if task.copy_out_bytes(addr, bytes).is_none() {
        return EFAULT;
    }
    0
}

fn sys_getrandom(buf: usize, len: usize, _flags: usize) -> isize {
    let task = current_task();
    let mut out = alloc::vec![0u8; len];
    let mut x: u64 = 0xdeadbeef_cafebabe;
    for b in out.iter_mut() {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        *b = (x >> 33) as u8;
    }
    if task.copy_out_bytes(buf, &out).is_none() {
        return EFAULT;
    }
    len as isize
}

#[repr(C)]
struct Timespec {
    sec: i64,
    nsec: i64,
}

#[repr(C)]
struct Timeval {
    sec: i64,
    usec: i64,
}

fn sys_gettimeofday(tv: usize) -> isize {
    let mtime = riscv::register::time::read64();
    let tv_val = Timeval {
        sec: (mtime / 10_000_000) as i64,
        usec: ((mtime % 10_000_000) / 10) as i64,
    };
    let task = current_task();
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &tv_val as *const _ as *const u8,
            core::mem::size_of::<Timeval>(),
        )
    };
    if task.copy_out_bytes(tv, bytes).is_none() {
        return EFAULT;
    }
    0
}

fn sys_clock_gettime(_clk: usize, ts: usize) -> isize {
    let mtime = riscv::register::time::read64();
    let ts_val = Timespec {
        sec: (mtime / 10_000_000) as i64,
        nsec: ((mtime % 10_000_000) * 100) as i64,
    };
    let task = current_task();
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &ts_val as *const _ as *const u8,
            core::mem::size_of::<Timespec>(),
        )
    };
    if task.copy_out_bytes(ts, bytes).is_none() {
        return EFAULT;
    }
    0
}

fn sys_mmap(
    _addr: usize,
    len: usize,
    _prot: i32,
    _flags: i32,
    _fd: i32,
    _off: usize,
) -> isize {
    if len == 0 {
        return EINVAL;
    }
    let task = current_task();
    let mut ms = task.memory_set_mut();
    let aligned = (len + crate::mm::PAGE_SIZE - 1) & !(crate::mm::PAGE_SIZE - 1);
    let start = ms.brk_cur.0;
    let area = crate::mm::memory_set::VmArea::new(
        crate::mm::VirtAddr(start),
        crate::mm::VirtAddr(start + aligned),
        crate::mm::memory_set::VmPerm::R
            | crate::mm::memory_set::VmPerm::W
            | crate::mm::memory_set::VmPerm::U,
    );
    ms.push_user_area(area, None);
    ms.brk_cur = crate::mm::VirtAddr(start + aligned);
    start as isize
}

fn sys_readlinkat(_dfd: i32, path: usize, buf: usize, len: usize) -> isize {
    let task = current_task();
    let Some(path_bytes) = task.copy_in_bytes(path, 256) else {
        return EFAULT;
    };
    let path_str = match cstr_to_str(&path_bytes) {
        Some(s) => s,
        None => return EINVAL,
    };
    let resolved: &str = match path_str {
        "/proc/self/exe" => "/app",
        _ => return ENOENT,
    };
    let n = core::cmp::min(len, resolved.len());
    if task.copy_out_bytes(buf, &resolved.as_bytes()[..n]).is_none() {
        return EFAULT;
    }
    n as isize
}

fn cstr_to_str(bytes: &[u8]) -> Option<&str> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    core::str::from_utf8(&bytes[..end]).ok()
}

fn sys_openat(_dfd: i32, _path: usize, _flags: i32, _mode: i32) -> isize {
    ENOENT
}

fn sys_close(_fd: i32) -> isize {
    0
}

fn sys_getcwd(buf: usize, len: usize) -> isize {
    let task = current_task();
    let cwd = b"/\0";
    if len < cwd.len() {
        return ERANGE;
    }
    if task.copy_out_bytes(buf, cwd).is_none() {
        return EFAULT;
    }
    buf as isize
}

// Trap handler entry point for user-induced kills (page faults, etc.).
pub fn request_exit(status: i32) -> ! {
    println!("[kernel] killing task with status {}", status);
    sbi_rt::system_reset(sbi_rt::Shutdown, sbi_rt::SystemFailure);
    loop {
        unsafe { core::arch::asm!("wfi") };
    }
}
