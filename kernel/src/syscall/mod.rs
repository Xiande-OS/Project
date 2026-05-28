//! Syscall dispatch.

pub mod nr;

use alloc::string::String;
use alloc::sync::Arc;

use crate::arch::riscv64::trap::TrapFrame;
use crate::fs::{self, File, FileType, Inode};
use crate::println;
use crate::task::current_task;

const ENOSYS: isize = -38;
const EBADF: isize = -9;
const EFAULT: isize = -14;
const EINVAL: isize = -22;
const ERANGE: isize = -34;
const ENOENT: isize = -2;

const AT_FDCWD: i32 = -100;

// O_* flags (Linux generic).
const O_RDONLY: i32 = 0o0;
const O_WRONLY: i32 = 0o1;
const O_RDWR: i32 = 0o2;
const O_CREAT: i32 = 0o100;
const O_EXCL: i32 = 0o200;
const O_TRUNC: i32 = 0o1000;
const O_APPEND: i32 = 0o2000;
const O_NONBLOCK: i32 = 0o4000;
const O_DIRECTORY: i32 = 0o200000;
const O_CLOEXEC: i32 = 0o2000000;

pub fn dispatch(tf: &mut TrapFrame) {
    let id = tf.x[16];
    let a0 = tf.x[9];
    let a1 = tf.x[10];
    let a2 = tf.x[11];
    let a3 = tf.x[12];
    let a4 = tf.x[13];
    let a5 = tf.x[14];

    if syscall_trace_enabled() {
        crate::println!(
            "[sys pid={}] #{} sp={:#x} a0={:#x} a1={:#x} a2={:#x}",
            crate::task::current_pid(), id, tf.x[1], a0, a1, a2
        );
    }

    let ret = match id {
        nr::SYS_WRITE => sys_write(a0 as i32, a1, a2),
        nr::SYS_WRITEV => sys_writev(a0 as i32, a1, a2),
        nr::SYS_READ => sys_read(a0 as i32, a1, a2),
        nr::SYS_READV => sys_readv(a0 as i32, a1, a2),
        nr::SYS_PREAD64 => sys_pread(a0 as i32, a1, a2, a3 as u64),
        nr::SYS_PWRITE64 => sys_pwrite(a0 as i32, a1, a2, a3 as u64),
        nr::SYS_LSEEK => sys_lseek(a0 as i32, a1 as i64, a2 as i32),
        nr::SYS_OPENAT => sys_openat(a0 as i32, a1, a2 as i32, a3 as i32),
        nr::SYS_CLOSE => sys_close(a0 as i32),
        nr::SYS_DUP => sys_dup(a0 as i32),
        nr::SYS_DUP3 => sys_dup3(a0 as i32, a1 as i32, a2 as i32),
        nr::SYS_PIPE2 => sys_pipe2(a0, a1 as i32),
        nr::SYS_MKDIRAT => sys_mkdirat(a0 as i32, a1, a2 as u32),
        nr::SYS_UNLINKAT => sys_unlinkat(a0 as i32, a1, a2 as i32),
        nr::SYS_GETDENTS64 => sys_getdents64(a0 as i32, a1, a2),
        nr::SYS_FSTAT => sys_fstat(a0 as i32, a1),
        nr::SYS_NEWFSTATAT => sys_newfstatat(a0 as i32, a1, a2, a3 as i32),
        nr::SYS_STATX => sys_statx(a0 as i32, a1, a2 as i32, a3 as u32, a4),
        nr::SYS_GETCWD => sys_getcwd(a0, a1),
        nr::SYS_CHDIR => sys_chdir(a0),
        nr::SYS_FACCESSAT | nr::SYS_FACCESSAT2 => sys_faccessat(a0 as i32, a1, a2 as i32),
        nr::SYS_FCHMOD | nr::SYS_FCHMODAT | nr::SYS_FCHOWN | nr::SYS_FCHOWNAT => 0,
        nr::SYS_UMASK => 0o022,
        nr::SYS_FCNTL => sys_fcntl(a0 as i32, a1 as i32, a2 as i32),
        nr::SYS_FSYNC => 0,
        nr::SYS_UTIMENSAT => 0,
        nr::SYS_EXIT | nr::SYS_EXIT_GROUP => sys_exit(a0 as i32),
        nr::SYS_BRK => sys_brk(a0),
        nr::SYS_SET_TID_ADDRESS => 1,
        nr::SYS_SET_ROBUST_LIST => 0,
        nr::SYS_RT_SIGACTION => sys_rt_sigaction(a0 as i32, a1, a2, a3),
        nr::SYS_RT_SIGPROCMASK => sys_rt_sigprocmask(a0 as i32, a1, a2, a3),
        nr::SYS_RT_SIGRETURN => {
            // Restore tf (incl. a0) from the rt_sigframe. Return the
            // restored a0 so the trailing `tf.x[9] = ret` is a no-op.
            let task = current_task();
            crate::signal::do_sigreturn(&task, tf)
        }
        nr::SYS_IOCTL => sys_ioctl(a0 as i32, a1 as u32, a2),
        nr::SYS_GETUID | nr::SYS_GETEUID | nr::SYS_GETGID | nr::SYS_GETEGID => 0,
        nr::SYS_GETPID | nr::SYS_GETTID => current_task().pid as isize,
        nr::SYS_GETPPID => {
            current_task().ppid.load(core::sync::atomic::Ordering::Relaxed) as isize
        }
        nr::SYS_GETPGID => sys_getpgid(a0 as i32),
        nr::SYS_GETSID => sys_getsid(a0 as i32),
        nr::SYS_GETPGRP => sys_getpgid(0),
        nr::SYS_SETPGID => sys_setpgid(a0 as i32, a1 as i32),
        nr::SYS_SETSID => sys_setsid(),
        nr::SYS_UNAME => sys_uname(a0),
        nr::SYS_GETRANDOM => sys_getrandom(a0, a1, a2),
        nr::SYS_MMAP => sys_mmap(a0, a1, a2 as i32, a3 as i32, a4 as i32, a5),
        nr::SYS_MUNMAP => 0,
        nr::SYS_MPROTECT => 0,
        nr::SYS_MADVISE => 0,
        nr::SYS_PRLIMIT64 => 0,
        nr::SYS_CLOCK_GETTIME => sys_clock_gettime(a0, a1),
        nr::SYS_GETTIMEOFDAY => sys_gettimeofday(a0),
        nr::SYS_SCHED_YIELD => 0,
        nr::SYS_TGKILL => sys_tgkill(a0 as i32, a1 as i32, a2 as i32),
        nr::SYS_TKILL => sys_tkill(a0 as i32, a1 as i32),
        nr::SYS_KILL => sys_kill(a0 as i32, a1 as i32),
        nr::SYS_FUTEX => 0,
        nr::SYS_PPOLL => sys_ppoll(a0, a1, a2),
        nr::SYS_SIGALTSTACK => sys_sigaltstack(a0, a1),
        nr::SYS_RT_SIGTIMEDWAIT => sys_rt_sigtimedwait(a0, a1, a2),
        nr::SYS_RT_SIGSUSPEND => sys_rt_sigsuspend(a0, a1),
        nr::SYS_SYSINFO => 0,
        nr::SYS_GETRUSAGE => 0,
        nr::SYS_MEMBARRIER => 0,
        nr::SYS_TIMES => 0,
        nr::SYS_READLINKAT => sys_readlinkat(a0 as i32, a1, a2, a3),
        nr::SYS_RENAMEAT2 => sys_renameat2(a0 as i32, a1, a2 as i32, a3, a4 as u32),
        nr::SYS_LINKAT => sys_linkat(a0 as i32, a1, a2 as i32, a3, a4 as i32),
        nr::SYS_SYMLINKAT => 0, // best-effort stub
        nr::SYS_CLONE => sys_clone(a0, a1, a2, a3, a4),
        nr::SYS_EXECVE => sys_execve(a0, a1, a2),
        nr::SYS_WAIT4 => sys_wait4(a0 as i32, a1, a2 as i32),
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

static SYSCALL_TRACE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

fn syscall_trace_enabled() -> bool {
    SYSCALL_TRACE.load(core::sync::atomic::Ordering::Relaxed)
}

pub fn set_syscall_trace(on: bool) {
    SYSCALL_TRACE.store(on, core::sync::atomic::Ordering::Relaxed);
}

fn copy_path(addr: usize) -> Option<String> {
    if addr == 0 {
        return None;
    }
    let task = current_task();
    // Read in page-sized chunks, stopping at the first NUL. Avoids
    // failing copy_in_bytes when the string is near end-of-mapping.
    let mut out = alloc::vec::Vec::new();
    let mut cursor = addr;
    loop {
        let page_end = (cursor & !4095) + 4096;
        let chunk = page_end - cursor;
        let bytes = task.copy_in_bytes(cursor, chunk)?;
        if let Some(pos) = bytes.iter().position(|&b| b == 0) {
            out.extend_from_slice(&bytes[..pos]);
            break;
        }
        out.extend_from_slice(&bytes);
        cursor = page_end;
        if out.len() > 4096 {
            return None;
        }
    }
    core::str::from_utf8(&out).ok().map(String::from)
}

fn cwd_inode() -> Arc<dyn Inode> {
    let task = current_task();
    let cwd = task.cwd.lock().clone();
    fs::lookup_path(fs::root(), &cwd).unwrap_or_else(|_| fs::root())
}

fn err_to_isize(e: i32) -> isize {
    e as isize
}

// ---------- File I/O ----------

fn sys_write(fd: i32, buf: usize, len: usize) -> isize {
    let task = current_task();
    let Some(bytes) = task.copy_in_bytes(buf, len) else {
        return EFAULT;
    };
    let Some(file) = task.fd_table.lock().get(fd) else {
        return EBADF;
    };
    match file.write(&bytes) {
        Ok(n) => n as isize,
        Err(e) => err_to_isize(e),
    }
}

#[repr(C)]
struct IoVec {
    base: usize,
    len: usize,
}

fn sys_writev(fd: i32, iov: usize, count: usize) -> isize {
    if count == 0 {
        return 0;
    }
    let task = current_task();
    let Some(file) = task.fd_table.lock().get(fd) else {
        return EBADF;
    };
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
        match file.write(&bytes) {
            Ok(n) => total += n as isize,
            Err(e) => {
                if total == 0 {
                    return err_to_isize(e);
                }
                return total;
            }
        }
    }
    total
}

fn sys_read(fd: i32, buf: usize, len: usize) -> isize {
    let task = current_task();
    let Some(file) = task.fd_table.lock().get(fd) else {
        return EBADF;
    };
    let mut tmp = alloc::vec![0u8; len];
    let n = match file.read(&mut tmp) {
        Ok(n) => n,
        Err(e) => return err_to_isize(e),
    };
    if task.copy_out_bytes(buf, &tmp[..n]).is_none() {
        return EFAULT;
    }
    n as isize
}

fn sys_readv(fd: i32, iov: usize, count: usize) -> isize {
    if count == 0 {
        return 0;
    }
    let task = current_task();
    let Some(file) = task.fd_table.lock().get(fd) else {
        return EBADF;
    };
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
        let mut tmp = alloc::vec![0u8; v.len];
        match file.read(&mut tmp) {
            Ok(n) => {
                if n == 0 {
                    break;
                }
                if task.copy_out_bytes(v.base, &tmp[..n]).is_none() {
                    return EFAULT;
                }
                total += n as isize;
                if n < v.len {
                    break;
                }
            }
            Err(e) => {
                if total == 0 {
                    return err_to_isize(e);
                }
                break;
            }
        }
    }
    total
}

fn sys_pread(fd: i32, buf: usize, len: usize, off: u64) -> isize {
    let task = current_task();
    let Some(file) = task.fd_table.lock().get(fd) else {
        return EBADF;
    };
    let mut tmp = alloc::vec![0u8; len];
    match file.inode.read_at(off, &mut tmp) {
        Ok(n) => {
            if task.copy_out_bytes(buf, &tmp[..n]).is_none() {
                return EFAULT;
            }
            n as isize
        }
        Err(e) => err_to_isize(e),
    }
}

fn sys_pwrite(fd: i32, buf: usize, len: usize, off: u64) -> isize {
    let task = current_task();
    let Some(file) = task.fd_table.lock().get(fd) else {
        return EBADF;
    };
    let Some(bytes) = task.copy_in_bytes(buf, len) else {
        return EFAULT;
    };
    match file.inode.write_at(off, &bytes) {
        Ok(n) => n as isize,
        Err(e) => err_to_isize(e),
    }
}

fn sys_lseek(fd: i32, offset: i64, whence: i32) -> isize {
    let task = current_task();
    let Some(file) = task.fd_table.lock().get(fd) else {
        return EBADF;
    };
    match file.seek(offset, whence) {
        Ok(o) => o as isize,
        Err(e) => err_to_isize(e),
    }
}

fn resolve_at(dfd: i32, path: &str) -> Option<Arc<dyn Inode>> {
    let task = current_task();
    let start = if dfd == AT_FDCWD || path.starts_with('/') {
        let cwd = task.cwd.lock().clone();
        fs::lookup_path(fs::root(), &cwd).ok()?
    } else {
        task.fd_table.lock().get(dfd)?.inode.clone()
    };
    fs::lookup_path(start, path).ok()
}

fn resolve_at_parent(dfd: i32, path: &str) -> Option<(Arc<dyn Inode>, String)> {
    let task = current_task();
    let start = if dfd == AT_FDCWD || path.starts_with('/') {
        let cwd = task.cwd.lock().clone();
        fs::lookup_path(fs::root(), &cwd).ok()?
    } else {
        task.fd_table.lock().get(dfd)?.inode.clone()
    };
    fs::split_parent(start, path).ok()
}

fn sys_openat(dfd: i32, path: usize, flags: i32, _mode: i32) -> isize {
    let Some(path_str) = copy_path(path) else {
        return EFAULT;
    };

    let cloexec = (flags & O_CLOEXEC) != 0;
    let create = (flags & O_CREAT) != 0;
    let excl = (flags & O_EXCL) != 0;
    let trunc = (flags & O_TRUNC) != 0;
    let append = (flags & O_APPEND) != 0;
    let access = flags & 0o3;
    let readable = access == O_RDONLY || access == O_RDWR;
    let writable = access == O_WRONLY || access == O_RDWR;

    let inode = match resolve_at(dfd, &path_str) {
        Some(i) => {
            if excl && create {
                return -17; // EEXIST
            }
            if trunc {
                let _ = i.truncate(0);
            }
            i
        }
        None => {
            if !create {
                return ENOENT;
            }
            let Some((parent, name)) = resolve_at_parent(dfd, &path_str) else {
                return ENOENT;
            };
            match parent.create(&name, FileType::Regular) {
                Ok(i) => i,
                Err(e) => return err_to_isize(e),
            }
        }
    };

    let file = Arc::new(File::from_inode(inode, readable, writable, append));
    match current_task().fd_table.lock().alloc(file, cloexec) {
        Ok(fd) => fd as isize,
        Err(e) => err_to_isize(e),
    }
}

fn sys_close(fd: i32) -> isize {
    match current_task().fd_table.lock().close(fd) {
        Ok(()) => 0,
        Err(e) => err_to_isize(e),
    }
}

fn sys_dup(fd: i32) -> isize {
    let task = current_task();
    let f = match task.fd_table.lock().get(fd) {
        Some(f) => f,
        None => return EBADF,
    };
    let res = task.fd_table.lock().alloc(f, false);
    match res {
        Ok(nfd) => nfd as isize,
        Err(e) => err_to_isize(e),
    }
}

fn sys_dup3(oldfd: i32, newfd: i32, flags: i32) -> isize {
    let cloexec = (flags & O_CLOEXEC) != 0;
    match current_task().fd_table.lock().dup3(oldfd, newfd, cloexec) {
        Ok(fd) => fd as isize,
        Err(e) => err_to_isize(e),
    }
}

fn sys_pipe2(pipefd_ptr: usize, flags: i32) -> isize {
    let task = current_task();
    let (r, w) = fs::pipe::make_pipe();
    let rf = Arc::new(File::from_inode(r, true, false, false));
    let wf = Arc::new(File::from_inode(w, false, true, false));
    let cloexec = (flags & O_CLOEXEC) != 0;
    let r_fd = match task.fd_table.lock().alloc(rf, cloexec) {
        Ok(fd) => fd,
        Err(e) => return err_to_isize(e),
    };
    let w_fd = match task.fd_table.lock().alloc(wf, cloexec) {
        Ok(fd) => fd,
        Err(e) => {
            let _ = task.fd_table.lock().close(r_fd);
            return err_to_isize(e);
        }
    };
    let pair = [r_fd, w_fd];
    let bytes = unsafe {
        core::slice::from_raw_parts(pair.as_ptr() as *const u8, 8)
    };
    if task.copy_out_bytes(pipefd_ptr, bytes).is_none() {
        return EFAULT;
    }
    0
}

fn sys_mkdirat(dfd: i32, path: usize, _mode: u32) -> isize {
    let Some(path_str) = copy_path(path) else {
        return EFAULT;
    };
    let Some((parent, name)) = resolve_at_parent(dfd, &path_str) else {
        return ENOENT;
    };
    match parent.create(&name, FileType::Directory) {
        Ok(_) => 0,
        Err(e) => err_to_isize(e),
    }
}

/// Linux `struct termios` on RISC-V (60 bytes). Just enough that
/// `isatty(stdin)` returns true and the shell treats us as a terminal.
#[repr(C)]
#[derive(Default)]
struct Termios {
    c_iflag: u32,
    c_oflag: u32,
    c_cflag: u32,
    c_lflag: u32,
    c_line: u8,
    c_cc: [u8; 19],
    c_ispeed: u32,
    c_ospeed: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

fn sys_ppoll(fds: usize, nfds: usize, timeout: usize) -> isize {
    if nfds == 0 || fds == 0 {
        return 0;
    }
    let task = current_task();
    let size = nfds * core::mem::size_of::<PollFd>();
    let Some(raw) = task.copy_in_bytes(fds, size) else {
        return EFAULT;
    };
    let mut polls: alloc::vec::Vec<PollFd> = alloc::vec![PollFd::default(); nfds];
    for i in 0..nfds {
        let off = i * core::mem::size_of::<PollFd>();
        polls[i] = unsafe {
            core::ptr::read(raw[off..].as_ptr() as *const PollFd)
        };
        polls[i].revents = 0;
    }

    // Identify any console-backed fd in the set.
    let mut console_indices: alloc::vec::Vec<usize> = alloc::vec::Vec::new();
    for (i, p) in polls.iter().enumerate() {
        if let Some(f) = task.fd_table.lock().get(p.fd) {
            if f.is_console && p.events & 0x1 != 0 {
                console_indices.push(i);
            }
        }
    }

    let mut ready = 0;
    if !console_indices.is_empty() {
        if timeout == 0 {
            // NULL timeout = block until something readable.
            crate::fs::console_wait_readable();
            for &i in &console_indices {
                polls[i].revents = 0x1; // POLLIN
            }
            ready = console_indices.len() as isize;
        } else if crate::fs::console_has_readable() {
            for &i in &console_indices {
                polls[i].revents = 0x1;
            }
            ready = console_indices.len() as isize;
        }
    }

    // Write revents back.
    let mut out = alloc::vec::Vec::with_capacity(size);
    for p in &polls {
        out.extend_from_slice(unsafe {
            core::slice::from_raw_parts(
                p as *const _ as *const u8,
                core::mem::size_of::<PollFd>(),
            )
        });
    }
    if task.copy_out_bytes(fds, &out).is_none() {
        return EFAULT;
    }
    ready
}

/// Controlling terminal's foreground process group. Updated by
/// TIOCSPGRP (when busybox sh installs itself as the foreground
/// pgrp). Returned by TIOCGPGRP.
static TTY_FG_PGID: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(1);

fn sys_ioctl(fd: i32, req: u32, arg: usize) -> isize {
    const TCGETS: u32 = 0x5401;
    const TCSETS: u32 = 0x5402;
    const TCSETSW: u32 = 0x5403;
    const TCSETSF: u32 = 0x5404;
    const TIOCGWINSZ: u32 = 0x5413;
    const TIOCGPGRP: u32 = 0x540f;
    const TIOCSPGRP: u32 = 0x5410;

    let task = current_task();
    let is_console = task
        .fd_table
        .lock()
        .get(fd)
        .map(|f| f.is_console)
        .unwrap_or(false);

    match req {
        TCGETS if is_console => {
            // The host's TTY is already in cooked mode echoing the user's
            // typing, and our `printf | qemu` pipeline doesn't echo either
            // way. Tell the shell ECHO is *off* so it doesn't expect a
            // kernel-side echo (busybox would otherwise read the first
            // char and decide the input device dropped a byte).
            let mut t = Termios::default();
            t.c_iflag = 0o0000400 | 0o0000004; // ICRNL | IGNBRK
            t.c_oflag = 0o0000001 | 0o0000004; // OPOST | ONLCR
            t.c_cflag = 0o0000060 | 0o0000200; // CS8 | CREAD
            t.c_lflag = 0o0000002 | 0o0000100 | 0o0000020; // ICANON | ISIG | ECHOE  (ECHO cleared)
            t.c_cc[0] = 3;   // VINTR  ^C
            t.c_cc[1] = 28;  // VQUIT  ^\
            t.c_cc[2] = 127; // VERASE DEL
            t.c_cc[3] = 21;  // VKILL  ^U
            t.c_cc[4] = 4;   // VEOF   ^D
            t.c_cc[8] = 17;  // VSTART ^Q
            t.c_cc[9] = 19;  // VSTOP  ^S
            t.c_cc[10] = 26; // VSUSP  ^Z
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    &t as *const _ as *const u8,
                    core::mem::size_of::<Termios>(),
                )
            };
            if task.copy_out_bytes(arg, bytes).is_none() {
                return EFAULT;
            }
            0
        }
        TCSETS | TCSETSW | TCSETSF => 0,
        TIOCGWINSZ if is_console => {
            let ws: [u16; 4] = [24, 80, 0, 0];
            let bytes = unsafe { core::slice::from_raw_parts(ws.as_ptr() as *const u8, 8) };
            if task.copy_out_bytes(arg, bytes).is_none() {
                return EFAULT;
            }
            0
        }
        TIOCGPGRP => {
            let pg = TTY_FG_PGID.load(core::sync::atomic::Ordering::Relaxed);
            if task.copy_out_bytes(arg, &pg.to_le_bytes()).is_none() {
                return EFAULT;
            }
            0
        }
        TIOCSPGRP => {
            let Some(bytes) = task.copy_in_bytes(arg, 4) else {
                return EFAULT;
            };
            let pg = i32::from_le_bytes(bytes.as_slice().try_into().unwrap_or([0; 4]));
            TTY_FG_PGID.store(pg, core::sync::atomic::Ordering::Relaxed);
            0
        }
        _ => 0,
    }
}

fn sys_fcntl(fd: i32, cmd: i32, arg: i32) -> isize {
    const F_DUPFD: i32 = 0;
    const F_GETFD: i32 = 1;
    const F_SETFD: i32 = 2;
    const F_GETFL: i32 = 3;
    const F_SETFL: i32 = 4;
    const F_DUPFD_CLOEXEC: i32 = 1030;

    let task = current_task();
    match cmd {
        F_DUPFD | F_DUPFD_CLOEXEC => {
            let file = match task.fd_table.lock().get(fd) {
                Some(f) => f,
                None => return EBADF,
            };
            let cloexec = cmd == F_DUPFD_CLOEXEC;
            let min_fd = arg as usize;
            // Find the smallest free fd >= min_fd and place the file there.
            let mut t = task.fd_table.lock();
            let mut tab = t.table.lock();
            let mut c = t.cloexec.lock();
            while tab.len() <= min_fd {
                tab.push(None);
                c.push(false);
            }
            let mut chosen = None;
            for i in min_fd..tab.len() {
                if tab[i].is_none() {
                    chosen = Some(i);
                    break;
                }
            }
            let chosen = chosen.unwrap_or_else(|| {
                let i = tab.len();
                tab.push(None);
                c.push(false);
                i
            });
            tab[chosen] = Some(file);
            if c.len() <= chosen {
                c.resize(chosen + 1, false);
            }
            c[chosen] = cloexec;
            chosen as isize
        }
        F_GETFD => {
            let t = task.fd_table.lock();
            let c = t.cloexec.lock();
            if c.get(fd as usize).copied().unwrap_or(false) {
                1
            } else {
                0
            }
        }
        F_SETFD => {
            let t = task.fd_table.lock();
            let mut c = t.cloexec.lock();
            while c.len() <= fd as usize {
                c.push(false);
            }
            c[fd as usize] = arg & 1 != 0;
            0
        }
        F_GETFL => 0,
        F_SETFL => 0,
        _ => 0,
    }
}

fn sys_faccessat(dfd: i32, path: usize, _mode: i32) -> isize {
    let Some(path_str) = copy_path(path) else {
        return EFAULT;
    };
    match resolve_at(dfd, &path_str) {
        Some(_) => 0,
        None => ENOENT,
    }
}

fn sys_unlinkat(dfd: i32, path: usize, _flag: i32) -> isize {
    let Some(path_str) = copy_path(path) else {
        return EFAULT;
    };
    let Some((parent, name)) = resolve_at_parent(dfd, &path_str) else {
        return ENOENT;
    };
    match parent.unlink(&name) {
        Ok(()) => 0,
        Err(e) => err_to_isize(e),
    }
}

#[repr(C)]
struct Linux64Dirent {
    d_ino: u64,
    d_off: i64,
    d_reclen: u16,
    d_type: u8,
    // followed by name[]
}

fn sys_getdents64(fd: i32, buf: usize, len: usize) -> isize {
    let task = current_task();
    let Some(file) = task.fd_table.lock().get(fd) else {
        return EBADF;
    };
    let entries = match file.inode.list() {
        Ok(e) => e,
        Err(e) => return err_to_isize(e),
    };

    // Track read progress with `offset`.
    let mut offset = file.offset.lock();
    let start_idx = *offset as usize;
    if start_idx >= entries.len() {
        return 0;
    }

    let mut out = alloc::vec::Vec::new();
    let mut idx = start_idx;
    while idx < entries.len() {
        let (name, kind) = &entries[idx];
        let name_bytes = name.as_bytes();
        let reclen = ((19 + name_bytes.len() + 1) + 7) & !7;
        if out.len() + reclen > len {
            break;
        }
        let d_type = match kind {
            FileType::Regular => 8u8,
            FileType::Directory => 4u8,
            FileType::CharDevice => 2u8,
            FileType::Pipe => 1u8,
        };
        let mut dent = alloc::vec![0u8; reclen];
        dent[0..8].copy_from_slice(&(idx as u64 + 1).to_le_bytes());
        dent[8..16].copy_from_slice(&((idx + 1) as i64).to_le_bytes());
        dent[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
        dent[18] = d_type;
        let name_end = 19 + name_bytes.len();
        dent[19..name_end].copy_from_slice(name_bytes);
        dent[name_end] = 0;
        out.extend_from_slice(&dent);
        idx += 1;
    }

    if out.is_empty() {
        return EINVAL;
    }
    if task.copy_out_bytes(buf, &out).is_none() {
        return EFAULT;
    }
    *offset = idx as u64;
    out.len() as isize
}

#[repr(C)]
#[derive(Default)]
struct LinuxStat {
    st_dev: u64,
    st_ino: u64,
    st_mode: u32,
    st_nlink: u32,
    st_uid: u32,
    st_gid: u32,
    st_rdev: u64,
    __pad: u64,
    st_size: i64,
    st_blksize: i32,
    __pad2: i32,
    st_blocks: i64,
    st_atime: i64,
    st_atime_nsec: u64,
    st_mtime: i64,
    st_mtime_nsec: u64,
    st_ctime: i64,
    st_ctime_nsec: u64,
    __unused: [u32; 2],
}

fn fill_stat(inode: &Arc<dyn Inode>) -> LinuxStat {
    let mut s = LinuxStat::default();
    s.st_mode = match inode.kind() {
        FileType::Regular => 0o100644,
        FileType::Directory => 0o040755,
        FileType::CharDevice => 0o020666,
        FileType::Pipe => 0o010600,
    };
    s.st_nlink = 1;
    s.st_size = inode.size() as i64;
    s.st_blksize = 4096;
    s.st_blocks = (s.st_size + 511) / 512;
    s.st_ino = (Arc::as_ptr(inode) as *const () as usize) as u64;
    s
}

fn write_struct<T>(addr: usize, value: &T) -> isize {
    let task = current_task();
    let bytes = unsafe {
        core::slice::from_raw_parts(value as *const T as *const u8, core::mem::size_of::<T>())
    };
    if task.copy_out_bytes(addr, bytes).is_none() {
        return EFAULT;
    }
    0
}

fn sys_fstat(fd: i32, buf: usize) -> isize {
    let task = current_task();
    let Some(file) = task.fd_table.lock().get(fd) else {
        return EBADF;
    };
    let st = fill_stat(&file.inode);
    write_struct(buf, &st)
}

fn sys_newfstatat(dfd: i32, path: usize, buf: usize, _flags: i32) -> isize {
    let Some(path_str) = copy_path(path) else {
        return EFAULT;
    };
    let inode = if path_str.is_empty() {
        // AT_EMPTY_PATH semantics: use dfd directly.
        let Some(file) = current_task().fd_table.lock().get(dfd) else {
            return EBADF;
        };
        file.inode.clone()
    } else {
        let Some(i) = resolve_at(dfd, &path_str) else {
            return ENOENT;
        };
        i
    };
    let st = fill_stat(&inode);
    write_struct(buf, &st)
}

#[repr(C)]
#[derive(Default)]
struct Statx {
    stx_mask: u32,
    stx_blksize: u32,
    stx_attributes: u64,
    stx_nlink: u32,
    stx_uid: u32,
    stx_gid: u32,
    stx_mode: u16,
    __pad1: u16,
    stx_ino: u64,
    stx_size: u64,
    stx_blocks: u64,
    stx_attributes_mask: u64,
    stx_atime: [u64; 2],
    stx_btime: [u64; 2],
    stx_ctime: [u64; 2],
    stx_mtime: [u64; 2],
    stx_rdev_major: u32,
    stx_rdev_minor: u32,
    stx_dev_major: u32,
    stx_dev_minor: u32,
    stx_mnt_id: u64,
    stx_dio_mem_align: u32,
    stx_dio_offset_align: u32,
    __reserved: [u64; 12],
}

fn sys_statx(dfd: i32, path: usize, _flags: i32, _mask: u32, buf: usize) -> isize {
    let Some(path_str) = copy_path(path) else {
        return EFAULT;
    };
    let inode = if path_str.is_empty() {
        let Some(file) = current_task().fd_table.lock().get(dfd) else {
            return EBADF;
        };
        file.inode.clone()
    } else {
        let Some(i) = resolve_at(dfd, &path_str) else {
            return ENOENT;
        };
        i
    };
    let mut st = Statx::default();
    st.stx_mask = 0x7ff;
    st.stx_blksize = 4096;
    st.stx_nlink = 1;
    st.stx_mode = match inode.kind() {
        FileType::Regular => 0o100644,
        FileType::Directory => 0o040755,
        FileType::CharDevice => 0o020666,
        FileType::Pipe => 0o010600,
    };
    st.stx_size = inode.size();
    st.stx_blocks = (inode.size() + 511) / 512;
    st.stx_ino = (Arc::as_ptr(&inode) as *const () as usize) as u64;
    write_struct(buf, &st)
}

fn sys_getcwd(buf: usize, len: usize) -> isize {
    let task = current_task();
    let cwd = task.cwd.lock().clone();
    let mut bytes = cwd.into_bytes();
    bytes.push(0);
    if len < bytes.len() {
        return ERANGE;
    }
    if task.copy_out_bytes(buf, &bytes).is_none() {
        return EFAULT;
    }
    buf as isize
}

fn sys_chdir(path: usize) -> isize {
    let Some(path_str) = copy_path(path) else {
        return EFAULT;
    };
    let inode = match fs::lookup_path(fs::root(), &path_str) {
        Ok(i) => i,
        Err(e) => return err_to_isize(e),
    };
    if inode.kind() != FileType::Directory {
        return -20; // ENOTDIR
    }
    let new_cwd = if path_str.starts_with('/') {
        normalize_path(&path_str)
    } else {
        let task = current_task();
        let cur = task.cwd.lock().clone();
        normalize_path(&alloc::format!("{}/{}", cur, path_str))
    };
    *current_task().cwd.lock() = new_cwd;
    0
}

fn normalize_path(p: &str) -> String {
    let mut out = String::from("/");
    for part in p.split('/').filter(|s| !s.is_empty() && *s != ".") {
        if part == ".." {
            if let Some(idx) = out[..out.len().saturating_sub(1)].rfind('/') {
                out.truncate(idx + 1);
            }
            continue;
        }
        if !out.ends_with('/') {
            out.push('/');
        }
        out.push_str(part);
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

// ---------- Misc ----------

fn sys_getpgid(pid: i32) -> isize {
    let task = if pid == 0 {
        current_task()
    } else {
        match crate::task::task_by_pid(pid) {
            Some(t) => t,
            None => return -3, // ESRCH
        }
    };
    task.pgid.load(core::sync::atomic::Ordering::Relaxed) as isize
}

fn sys_getsid(pid: i32) -> isize {
    let task = if pid == 0 {
        current_task()
    } else {
        match crate::task::task_by_pid(pid) {
            Some(t) => t,
            None => return -3, // ESRCH
        }
    };
    task.sid.load(core::sync::atomic::Ordering::Relaxed) as isize
}

fn sys_setpgid(pid: i32, pgid: i32) -> isize {
    let me = current_task();
    let target = if pid == 0 {
        me.clone()
    } else {
        match crate::task::task_by_pid(pid) {
            Some(t) => t,
            None => return -3, // ESRCH
        }
    };
    // POSIX: target must be the caller or one of its children, must not
    // be a session leader, and must be in the same session as the caller.
    // We only enforce the basics; everything else is permissive.
    if target.sid.load(core::sync::atomic::Ordering::Relaxed)
        != me.sid.load(core::sync::atomic::Ordering::Relaxed)
    {
        return -1; // EPERM
    }
    let new_pgid = if pgid == 0 { target.pid } else { pgid };
    target
        .pgid
        .store(new_pgid, core::sync::atomic::Ordering::Relaxed);
    0
}

fn sys_setsid() -> isize {
    let me = current_task();
    // Only a non-session-leader can create a new session.
    let cur_sid = me.sid.load(core::sync::atomic::Ordering::Relaxed);
    if cur_sid == me.pid {
        return -1; // EPERM (already session leader)
    }
    me.sid
        .store(me.pid, core::sync::atomic::Ordering::Relaxed);
    me.pgid
        .store(me.pid, core::sync::atomic::Ordering::Relaxed);
    me.pid as isize
}

fn sys_exit(status: i32) -> isize {
    let task = current_task();
    // Pre-encode the wait4 status as Linux expects: normal exit puts the
    // low byte of `status` in bits 8..15. wait4 returns it verbatim.
    task.exit_code
        .store((status & 0xff) << 8, core::sync::atomic::Ordering::Relaxed);
    *task.state.lock() = crate::task::TaskState::Zombie;
    println!("[exit] pid={} status={}", task.pid, status);

    // Wake any parent in wait4 and send SIGCHLD.
    let ppid = task.ppid.load(core::sync::atomic::Ordering::Relaxed);
    if let Some(parent) = crate::task::task_by_pid(ppid) {
        {
            let mut s = parent.state.lock();
            if *s == crate::task::TaskState::Waiting {
                *s = crate::task::TaskState::Ready;
            }
        }
        let _ = crate::signal::raise_signal(&parent, crate::signal::SIGCHLD);
    }

    // If no other runnable/waiting/zombie task exists, halt.
    let pid = task.pid;
    if !crate::task::any_runnable_except(pid) && !crate::task::any_waiting() {
        sbi_rt::system_reset(sbi_rt::Shutdown, sbi_rt::NoReason);
        loop {
            unsafe { core::arch::asm!("wfi") };
        }
    }
    0
}

pub fn sys_kill_current(status: i32) -> isize {
    sys_exit(status)
}

fn sys_clone(flags: usize, child_sp: usize, _ptid: usize, _ctid: usize, _newtls: usize) -> isize {
    let _ = flags;
    let new_task = crate::task::fork_current();
    if child_sp != 0 {
        unsafe {
            (*new_task.tf_ptr()).x[1] = child_sp;
        }
    }
    new_task.pid as isize
}

fn sys_execve(path_addr: usize, argv_addr: usize, envp_addr: usize) -> isize {
    let Some(path) = copy_path(path_addr) else {
        return EFAULT;
    };
    let argv = read_string_array(argv_addr).unwrap_or_default();
    let envp = read_string_array(envp_addr).unwrap_or_default();

    // Look up the binary in the VFS.
    let inode = match fs::lookup_path(fs::root(), &path) {
        Ok(i) => i,
        Err(_) => return ENOENT,
    };
    if inode.kind() != FileType::Regular {
        return -13; // EACCES
    }
    let size = inode.size() as usize;
    let mut elf_image = alloc::vec![0u8; size];
    if let Err(e) = inode.read_at(0, &mut elf_image) {
        return err_to_isize(e);
    }
    // Ensure aligned (xmas-elf requires 8-byte alignment).
    let elf_aligned: alloc::vec::Vec<u8> = aligned_clone(&elf_image);

    let argv_refs: alloc::vec::Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
    let envp_refs: alloc::vec::Vec<&str> = envp.iter().map(|s| s.as_str()).collect();
    match crate::task::execve_current(&elf_aligned, &argv_refs, &envp_refs) {
        Ok(()) => 0,
        Err(e) => err_to_isize(e),
    }
}

fn aligned_clone(src: &[u8]) -> alloc::vec::Vec<u8> {
    // Vec data has 8-byte (or stricter) alignment by default — alloc gives
    // pointer aligned to mem::align_of::<u8>() == 1, but in practice the
    // allocator returns >=8 byte aligned blocks. Re-allocate via a u64
    // buffer to be safe.
    let nwords = (src.len() + 7) / 8;
    let mut words = alloc::vec![0u64; nwords];
    unsafe {
        core::ptr::copy_nonoverlapping(src.as_ptr(), words.as_mut_ptr() as *mut u8, src.len());
    }
    // Re-interpret as Vec<u8>. Easier: just copy into a Vec<u8> created from words.
    let mut bytes = alloc::vec::Vec::with_capacity(src.len());
    unsafe {
        core::ptr::copy_nonoverlapping(words.as_ptr() as *const u8, bytes.as_mut_ptr(), src.len());
        bytes.set_len(src.len());
    }
    drop(words);
    bytes
}

fn read_string_array(addr: usize) -> Option<alloc::vec::Vec<String>> {
    if addr == 0 {
        return Some(alloc::vec::Vec::new());
    }
    let task = current_task();
    let mut out = alloc::vec::Vec::new();
    let mut cursor = addr;
    loop {
        let bytes = task.copy_in_bytes(cursor, 8)?;
        let ptr = u64::from_le_bytes(bytes.as_slice().try_into().ok()?);
        if ptr == 0 {
            break;
        }
        let s = copy_path(ptr as usize)?;
        out.push(s);
        cursor += 8;
        if out.len() > 1024 {
            return None;
        }
    }
    Some(out)
}

fn sys_wait4(pid: i32, status_addr: usize, _options: i32) -> isize {
    let me = current_task();
    let zombie = {
        let children = me.children.lock();
        children
            .iter()
            .filter_map(|&cpid| crate::task::task_by_pid(cpid))
            .find(|c| {
                // pid < 0  -> any child (we ignore pgid distinctions)
                // pid == 0 -> any child in caller's pgid (treat as any)
                // pid > 0  -> specific pid
                (pid <= 0 || c.pid == pid)
                    && *c.state.lock() == crate::task::TaskState::Zombie
            })
    };
    if let Some(z) = zombie {
        let code = z.exit_code.load(core::sync::atomic::Ordering::Relaxed);
        if status_addr != 0 {
            // exit_code is already pre-encoded by sys_exit / signal-death.
            let _ = me.copy_out_bytes(status_addr, &code.to_le_bytes());
        }
        me.children.lock().retain(|&cpid| cpid != z.pid);
        crate::task::reap(z.pid);
        return z.pid as isize;
    }

    // No matching zombie. Mark Waiting and rewind sepc so the ecall is
    // re-executed when we get rescheduled. The scheduler will switch
    // to a child.
    if me.children.lock().is_empty() {
        return -10; // ECHILD
    }
    *me.state.lock() = crate::task::TaskState::Waiting;
    unsafe {
        (*me.tf_ptr()).sepc -= 4;
    }
    0
}

fn sys_brk(new_brk: usize) -> isize {
    let task = current_task();
    let mut ms = task.memory_set_mut();
    let cur = ms.brk_set(crate::mm::VirtAddr(new_brk));
    cur.0 as isize
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
    write_struct(addr, &uts)
}

fn sys_getrandom(buf: usize, len: usize, _flags: usize) -> isize {
    let task = current_task();
    let mut out = alloc::vec![0u8; len];
    let mut x: u64 = riscv::register::time::read64()
        .wrapping_mul(2862933555777941757);
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
    write_struct(tv, &tv_val)
}

fn sys_clock_gettime(_clk: usize, ts: usize) -> isize {
    let mtime = riscv::register::time::read64();
    let ts_val = Timespec {
        sec: (mtime / 10_000_000) as i64,
        nsec: ((mtime % 10_000_000) * 100) as i64,
    };
    write_struct(ts, &ts_val)
}

fn sys_mmap(_addr: usize, len: usize, _prot: i32, flags: i32, fd: i32, off: usize) -> isize {
    const MAP_ANONYMOUS: i32 = 0x20;
    if len == 0 {
        return EINVAL;
    }
    let task = current_task();
    let aligned = (len + crate::mm::PAGE_SIZE - 1) & !(crate::mm::PAGE_SIZE - 1);

    // If file-backed, read file content into a buffer first.
    let init = if (flags & MAP_ANONYMOUS) == 0 && fd >= 0 {
        let Some(file) = task.fd_table.lock().get(fd) else {
            return EBADF;
        };
        let mut buf = alloc::vec![0u8; aligned];
        match file.inode.read_at(off as u64, &mut buf) {
            Ok(_) => Some(buf),
            Err(e) => return err_to_isize(e),
        }
    } else {
        None
    };

    let mut ms = task.memory_set_mut();
    let start = ms.brk_cur.0;
    let area = crate::mm::memory_set::VmArea::new(
        crate::mm::VirtAddr(start),
        crate::mm::VirtAddr(start + aligned),
        crate::mm::memory_set::VmPerm::R
            | crate::mm::memory_set::VmPerm::W
            | crate::mm::memory_set::VmPerm::U,
    );
    ms.push_user_area(area, init.as_deref());
    ms.brk_cur = crate::mm::VirtAddr(start + aligned);
    start as isize
}

fn sys_renameat2(old_dfd: i32, old_path: usize, new_dfd: i32, new_path: usize, _flags: u32) -> isize {
    let Some(old_str) = copy_path(old_path) else {
        return EFAULT;
    };
    let Some(new_str) = copy_path(new_path) else {
        return EFAULT;
    };
    let Some((old_parent, old_name)) = resolve_at_parent(old_dfd, &old_str) else {
        return ENOENT;
    };
    let Some((new_parent, new_name)) = resolve_at_parent(new_dfd, &new_str) else {
        return ENOENT;
    };

    // Pull the inode out, then re-insert under the new name + parent.
    let inode = match old_parent.lookup(&old_name) {
        Ok(i) => i,
        Err(e) => return err_to_isize(e),
    };
    // Unlink from old location.
    if let Err(e) = old_parent.unlink(&old_name) {
        return err_to_isize(e);
    }
    // Re-place under new location; works only on TmpfsDir.
    if let Some(td) = crate::fs::tmpfs::downcast_dir(&new_parent) {
        // If new name already exists, replace it.
        let _ = td.place_inode(&new_name, inode);
        0
    } else {
        ENOENT
    }
}

fn sys_linkat(old_dfd: i32, old_path: usize, new_dfd: i32, new_path: usize, _flags: i32) -> isize {
    let Some(old_str) = copy_path(old_path) else {
        return EFAULT;
    };
    let Some(new_str) = copy_path(new_path) else {
        return EFAULT;
    };
    let Some(src_inode) = resolve_at(old_dfd, &old_str) else {
        return ENOENT;
    };
    let Some((new_parent, new_name)) = resolve_at_parent(new_dfd, &new_str) else {
        return ENOENT;
    };
    if let Some(td) = crate::fs::tmpfs::downcast_dir(&new_parent) {
        match td.place_inode(&new_name, src_inode) {
            Ok(()) => 0,
            Err(e) => err_to_isize(e),
        }
    } else {
        ENOENT
    }
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
        "/proc/self/exe" => "/bin/git",
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

pub fn request_exit(status: i32) -> ! {
    println!("[kernel] killing task with status {}", status);
    sbi_rt::system_reset(sbi_rt::Shutdown, sbi_rt::SystemFailure);
    loop {
        unsafe { core::arch::asm!("wfi") };
    }
}

// =========================================================================
//   Signal syscalls
// =========================================================================

const ESRCH: isize = -3;
const EPERM: isize = -1;

/// Kernel-side `struct sigaction` layout that musl's __libc_sigaction
/// passes to the kernel on riscv64. On riscv64, musl does NOT use
/// SA_RESTORER -- it relies on the kernel to set the return PC to a
/// VDSO/fixed restorer. Layout:
///     sa_handler : 8
///     sa_flags   : 8
///     sa_mask    : 8 (1024-bit sigset, but sigsetsize=8 so just low 64)
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UserSigAction {
    handler: usize,
    flags: u64,
    mask: u64,
}

fn sys_rt_sigaction(signo: i32, new_ptr: usize, old_ptr: usize, sigsetsize: usize) -> isize {
    use crate::signal::*;
    if sigsetsize != 8 {
        return EINVAL;
    }
    let signo_u = signo as u32;
    if !is_valid_signo(signo_u) {
        return EINVAL;
    }
    // SIGKILL/SIGSTOP cannot have their dispositions changed.
    if signo_u == SIGKILL || signo_u == SIGSTOP {
        // POSIX: writing returns EINVAL; reading old value is allowed.
        if new_ptr != 0 {
            return EINVAL;
        }
    }
    let task = current_task();

    let prev = task.signals.actions.lock()[signo_u as usize];

    if new_ptr != 0 {
        let Some(bytes) = task.copy_in_bytes(new_ptr, core::mem::size_of::<UserSigAction>()) else {
            return EFAULT;
        };
        let usa: UserSigAction = unsafe { core::ptr::read(bytes.as_ptr() as *const _) };
        let new_act = KSigAction {
            handler: usa.handler,
            flags: usa.flags,
            restorer: 0, // riscv64: kernel-provided restorer (set at delivery)
            mask: usa.mask & !unblockable_mask(),
        };
        task.signals.actions.lock()[signo_u as usize] = new_act;
    }

    if old_ptr != 0 {
        let old_usa = UserSigAction {
            handler: prev.handler,
            flags: prev.flags,
            mask: prev.mask,
        };
        let bytes = unsafe {
            core::slice::from_raw_parts(
                &old_usa as *const _ as *const u8,
                core::mem::size_of::<UserSigAction>(),
            )
        };
        if task.copy_out_bytes(old_ptr, bytes).is_none() {
            return EFAULT;
        }
    }

    0
}

fn sys_rt_sigprocmask(how: i32, new_ptr: usize, old_ptr: usize, sigsetsize: usize) -> isize {
    use crate::signal::*;
    if sigsetsize != 8 {
        return EINVAL;
    }
    let task = current_task();

    let cur = task.signals.mask.load(core::sync::atomic::Ordering::SeqCst);
    if old_ptr != 0 {
        if task.copy_out_bytes(old_ptr, &cur.to_le_bytes()).is_none() {
            return EFAULT;
        }
    }
    if new_ptr != 0 {
        let Some(bytes) = task.copy_in_bytes(new_ptr, 8) else {
            return EFAULT;
        };
        let new_set =
            u64::from_le_bytes(bytes.as_slice().try_into().unwrap_or([0u8; 8]));
        let next = match how {
            SIG_BLOCK => cur | new_set,
            SIG_UNBLOCK => cur & !new_set,
            SIG_SETMASK => new_set,
            _ => return EINVAL,
        };
        task.signals
            .mask
            .store(next & !unblockable_mask(), core::sync::atomic::Ordering::SeqCst);
    }
    0
}

fn sys_kill(pid: i32, sig: i32) -> isize {
    use crate::signal::*;
    let signo = sig as u32;
    if sig != 0 && !is_valid_signo(signo) {
        return EINVAL;
    }
    let me = current_task();

    let targets: alloc::vec::Vec<Arc<crate::task::Task>> = if pid > 0 {
        match crate::task::task_by_pid(pid) {
            Some(t) => alloc::vec![t],
            None => return ESRCH,
        }
    } else if pid == 0 {
        // own pgrp
        let pg = me.pgid.load(core::sync::atomic::Ordering::Relaxed);
        tasks_in_pgrp(pg)
    } else if pid == -1 {
        // every task in our session, excluding init/self per POSIX (we
        // include self -- nothing has more privilege here)
        let sid = me.sid.load(core::sync::atomic::Ordering::Relaxed);
        tasks_in_session(sid)
    } else {
        // pid < -1 → pgid = -pid
        tasks_in_pgrp(-pid)
    };

    if targets.is_empty() {
        return ESRCH;
    }
    if sig == 0 {
        // signal 0: probe only
        return 0;
    }

    let mut delivered = false;
    for t in &targets {
        if raise_signal(t, signo) {
            delivered = true;
        }
    }
    if delivered { 0 } else { EINVAL }
}

fn sys_tkill(tid: i32, sig: i32) -> isize {
    use crate::signal::*;
    let signo = sig as u32;
    if sig != 0 && !is_valid_signo(signo) {
        return EINVAL;
    }
    let Some(t) = crate::task::task_by_pid(tid) else {
        return ESRCH;
    };
    if sig == 0 {
        return 0;
    }
    if raise_signal(&t, signo) { 0 } else { EINVAL }
}

fn sys_tgkill(tgid: i32, tid: i32, sig: i32) -> isize {
    // We don't model threads-per-process distinctly; tgid is the same as tid.
    use crate::signal::*;
    let signo = sig as u32;
    if sig != 0 && !is_valid_signo(signo) {
        return EINVAL;
    }
    let Some(t) = crate::task::task_by_pid(tid) else {
        return ESRCH;
    };
    if tgid > 0 && t.pid != tgid {
        return ESRCH;
    }
    if sig == 0 {
        return 0;
    }
    if raise_signal(&t, signo) { 0 } else { EINVAL }
}

fn tasks_in_pgrp(pgid: i32) -> alloc::vec::Vec<Arc<crate::task::Task>> {
    crate::task::all_tasks()
        .into_iter()
        .filter(|t| t.pgid.load(core::sync::atomic::Ordering::Relaxed) == pgid)
        .collect()
}

fn tasks_in_session(sid: i32) -> alloc::vec::Vec<Arc<crate::task::Task>> {
    crate::task::all_tasks()
        .into_iter()
        .filter(|t| t.sid.load(core::sync::atomic::Ordering::Relaxed) == sid)
        .collect()
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UserSigAltStack {
    ss_sp: usize,
    ss_flags: i32,
    _pad: u32,
    ss_size: usize,
}

fn sys_sigaltstack(new_ptr: usize, old_ptr: usize) -> isize {
    use crate::signal::*;
    let task = current_task();
    let cur = *task.signals.altstack.lock();

    if old_ptr != 0 {
        let old_uss = match cur {
            Some(s) => UserSigAltStack {
                ss_sp: s.ss_sp,
                ss_flags: s.ss_flags,
                _pad: 0,
                ss_size: s.ss_size,
            },
            None => UserSigAltStack {
                ss_sp: 0,
                ss_flags: SS_DISABLE,
                _pad: 0,
                ss_size: 0,
            },
        };
        let bytes = unsafe {
            core::slice::from_raw_parts(
                &old_uss as *const _ as *const u8,
                core::mem::size_of::<UserSigAltStack>(),
            )
        };
        if task.copy_out_bytes(old_ptr, bytes).is_none() {
            return EFAULT;
        }
    }

    if new_ptr != 0 {
        let Some(bytes) = task.copy_in_bytes(new_ptr, core::mem::size_of::<UserSigAltStack>()) else {
            return EFAULT;
        };
        let uss: UserSigAltStack = unsafe { core::ptr::read(bytes.as_ptr() as *const _) };
        if (uss.ss_flags & SS_DISABLE) != 0 {
            *task.signals.altstack.lock() = None;
            return 0;
        }
        if uss.ss_size < MINSIGSTKSZ {
            return EINVAL;
        }
        *task.signals.altstack.lock() = Some(SigAltStack {
            ss_sp: uss.ss_sp,
            ss_flags: uss.ss_flags,
            ss_size: uss.ss_size,
        });
    }
    0
}

fn sys_rt_sigtimedwait(set_ptr: usize, info_ptr: usize, timeout_ptr: usize) -> isize {
    use crate::signal::*;
    let task = current_task();
    let Some(bytes) = task.copy_in_bytes(set_ptr, 8) else {
        return EFAULT;
    };
    let set = u64::from_le_bytes(bytes.as_slice().try_into().unwrap_or([0u8; 8]));
    let set = set & !unblockable_mask();
    let _ = timeout_ptr; // we don't sleep; polling once is what musl tolerates

    // Check immediately: if any pending bit overlaps set, dequeue + return signo.
    let pending = task.signals.pending.load(core::sync::atomic::Ordering::SeqCst);
    let hit = pending & set;
    if hit == 0 {
        return -11; // EAGAIN -- no signal currently pending in set
    }
    let signo = (hit.trailing_zeros() + 1) as i32;
    task.signals
        .pending
        .fetch_and(!(1u64 << (signo - 1)), core::sync::atomic::Ordering::SeqCst);
    if info_ptr != 0 {
        let mut info = crate::signal::KSigInfo::default();
        info.si_signo = signo;
        info.si_code = SI_USER;
        let bs = unsafe {
            core::slice::from_raw_parts(
                &info as *const _ as *const u8,
                core::mem::size_of::<crate::signal::KSigInfo>(),
            )
        };
        if task.copy_out_bytes(info_ptr, bs).is_none() {
            return EFAULT;
        }
    }
    signo as isize
}

fn sys_rt_sigsuspend(mask_ptr: usize, sigsetsize: usize) -> isize {
    use crate::signal::*;
    if sigsetsize != 8 {
        return EINVAL;
    }
    let task = current_task();
    let Some(bytes) = task.copy_in_bytes(mask_ptr, 8) else {
        return EFAULT;
    };
    let temp =
        u64::from_le_bytes(bytes.as_slice().try_into().unwrap_or([0u8; 8])) & !unblockable_mask();
    let saved = task.signals.mask.load(core::sync::atomic::Ordering::SeqCst);
    task.signals.mask.store(temp, core::sync::atomic::Ordering::SeqCst);
    *task.signals.saved_mask.lock() = Some(saved);

    // Block until any signal arrives. We can't truly block without a
    // signal-driven wakeup of waiting tasks; in this kernel any pending
    // signal arrival is followed by check_signals at the next trap
    // boundary. So we mark Waiting and rewind sepc so the syscall re-runs
    // and we re-check pending.
    let pending = task.signals.pending.load(core::sync::atomic::Ordering::SeqCst);
    let deliverable = pending & !temp;
    if deliverable != 0 {
        // A signal is already pending and unblocked under temp mask --
        // check_signals will deliver it on trap exit. Restore mask after.
        task.signals.mask.store(saved, core::sync::atomic::Ordering::SeqCst);
        *task.signals.saved_mask.lock() = None;
        return -4; // EINTR
    }
    // No deliverable signal; mark Waiting and rewind so we get rescheduled.
    *task.state.lock() = crate::task::TaskState::Waiting;
    unsafe {
        (*task.tf_ptr()).sepc -= 4;
    }
    0
}

/// Called by the console when ^C / ^\ / ^Z is observed on the foreground
/// tty. Posts the appropriate signal to every task in the foreground
/// process group.
pub fn deliver_tty_signal(signo: u32) {
    let pg = TTY_FG_PGID.load(core::sync::atomic::Ordering::Relaxed);
    if pg <= 0 {
        return;
    }
    let targets = tasks_in_pgrp(pg);
    for t in &targets {
        let _ = crate::signal::raise_signal(t, signo);
    }
}
