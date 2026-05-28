//! Syscall dispatch.

pub mod nr;
pub mod socket;

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
        nr::SYS_FCHMOD => sys_fchmod(a0 as i32, a1 as u32),
        nr::SYS_FCHMODAT => sys_fchmodat(a0 as i32, a1, a2 as u32),
        nr::SYS_FCHOWN => sys_fchown(a0 as i32, a1 as u32, a2 as u32),
        nr::SYS_FCHOWNAT => sys_fchownat(a0 as i32, a1, a2 as u32, a3 as u32),
        nr::SYS_UMASK => 0o022,
        nr::SYS_FCNTL => sys_fcntl(a0 as i32, a1 as i32, a2 as i32),
        nr::SYS_FLOCK => sys_flock(a0 as i32, a1 as i32),
        nr::SYS_FSYNC => 0,
        nr::SYS_UTIMENSAT => sys_utimensat(a0 as i32, a1, a2, a3 as i32),
        nr::SYS_NANOSLEEP => sys_nanosleep(a0, a1),
        nr::SYS_EXIT => sys_exit(a0 as i32),
        nr::SYS_EXIT_GROUP => sys_exit_group(a0 as i32),
        nr::SYS_BRK => sys_brk(a0),
        nr::SYS_SET_TID_ADDRESS => sys_set_tid_address(a0),
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
        nr::SYS_GETPID => current_task().tgid.load(core::sync::atomic::Ordering::Relaxed) as isize,
        nr::SYS_GETTID => current_task().pid as isize,
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
        nr::SYS_MUNMAP => sys_munmap(a0, a1),
        nr::SYS_MPROTECT => sys_mprotect(a0, a1, a2 as i32),
        nr::SYS_MADVISE => 0,
        nr::SYS_PRLIMIT64 => sys_prlimit64(a0 as i32, a1 as u32, a2, a3),
        nr::SYS_GETRLIMIT => sys_getrlimit(a0 as u32, a1),
        nr::SYS_SETRLIMIT => sys_setrlimit(a0 as u32, a1),
        nr::SYS_TRUNCATE => sys_truncate(a0, a1 as u64),
        nr::SYS_FTRUNCATE => sys_ftruncate(a0 as i32, a1 as u64),
        nr::SYS_PSELECT6 => sys_pselect6(a0, a1, a2, a3, a4, a5),
        nr::SYS_EVENTFD2 => sys_eventfd2(a0 as u32, a1 as i32),
        nr::SYS_SENDFILE => sys_sendfile(a0 as i32, a1 as i32, a2, a3),
        nr::SYS_COPY_FILE_RANGE => sys_copy_file_range(a0 as i32, a1, a2 as i32, a3, a4, a5 as u32),
        nr::SYS_MEMFD_CREATE => sys_memfd_create(a0, a1 as u32),
        nr::SYS_SYNC | nr::SYS_FDATASYNC | nr::SYS_SYNCFS => 0,
        nr::SYS_MLOCK | nr::SYS_MUNLOCK | nr::SYS_MLOCKALL | nr::SYS_MUNLOCKALL => 0,
        nr::SYS_MREMAP => sys_mremap(a0, a1, a2, a3 as i32, a4),
        nr::SYS_CLOSE_RANGE => sys_close_range(a0 as u32, a1 as u32, a2 as u32),
        nr::SYS_STATFS => sys_statfs(a0, a1),
        nr::SYS_FSTATFS => sys_fstatfs(a0 as i32, a1),
        nr::SYS_PREADV => sys_preadv(a0 as i32, a1, a2, a3 as u64),
        nr::SYS_PWRITEV => sys_pwritev(a0 as i32, a1, a2, a3 as u64),
        nr::SYS_TIMERFD_CREATE => sys_timerfd_create(a0 as i32, a1 as i32),
        nr::SYS_TIMERFD_SETTIME => sys_timerfd_settime(a0 as i32, a1 as i32, a2, a3),
        nr::SYS_TIMERFD_GETTIME => sys_timerfd_gettime(a0 as i32, a1),
        nr::SYS_PRCTL => sys_prctl(a0 as i32, a1, a2, a3, a4),
        nr::SYS_CAPGET | nr::SYS_CAPSET => 0,
        nr::SYS_SCHED_GETAFFINITY => sys_sched_getaffinity(a0 as i32, a1, a2),
        nr::SYS_SCHED_SETAFFINITY => 0,
        nr::SYS_SCHED_GETPARAM | nr::SYS_SCHED_GETSCHEDULER => 0,
        nr::SYS_SCHED_SETSCHEDULER => 0,
        nr::SYS_CLOCK_GETTIME => sys_clock_gettime(a0, a1),
        nr::SYS_GETTIMEOFDAY => sys_gettimeofday(a0),
        nr::SYS_SCHED_YIELD => 0,
        nr::SYS_TGKILL => sys_tgkill(a0 as i32, a1 as i32, a2 as i32),
        nr::SYS_TKILL => sys_tkill(a0 as i32, a1 as i32),
        nr::SYS_KILL => sys_kill(a0 as i32, a1 as i32),
        nr::SYS_FUTEX => sys_futex(a0, a1 as i32, a2 as u32, a3, a4, a5 as u32),
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
        nr::SYS_SYMLINKAT => sys_symlinkat(a0, a1 as i32, a2),
        nr::SYS_CLONE => sys_clone(a0, a1, a2, a3, a4),
        nr::SYS_EXECVE => sys_execve(a0, a1, a2),
        nr::SYS_WAIT4 => sys_wait4(a0 as i32, a1, a2 as i32),
        nr::SYS_WAITID => sys_waitid(a0 as i32, a1 as i32, a2, a3 as i32),
        nr::SYS_MQ_OPEN => sys_mq_open(a0, a1 as i32, a2 as u32, a3),
        nr::SYS_MQ_UNLINK => sys_mq_unlink(a0),
        nr::SYS_MQ_TIMEDSEND => sys_mq_timedsend(a0 as i32, a1, a2, a3 as u32, a4),
        nr::SYS_MQ_TIMEDRECEIVE => sys_mq_timedreceive(a0 as i32, a1, a2, a3, a4),
        nr::SYS_MQ_GETSETATTR => 0,
        nr::SYS_PIDFD_OPEN => sys_pidfd_open(a0 as i32, a1 as u32),
        nr::SYS_PIDFD_SEND_SIGNAL => sys_pidfd_send_signal(a0 as i32, a1 as i32, a2, a3 as u32),
        nr::SYS_PIDFD_GETFD => EBADF,
        nr::SYS_INOTIFY_INIT1 => sys_inotify_init1(a0 as i32),
        nr::SYS_INOTIFY_ADD_WATCH => 1,
        nr::SYS_INOTIFY_RM_WATCH => 0,
        nr::SYS_SIGNALFD4 => sys_signalfd4(a0 as i32, a1, a2 as usize, a3 as i32),
        nr::SYS_SOCKET => { crate::net::poll(); socket::sys_socket(a0 as i32, a1 as i32, a2 as i32) }
        nr::SYS_BIND => { crate::net::poll(); socket::sys_bind(a0 as i32, a1, a2) }
        nr::SYS_LISTEN => { crate::net::poll(); socket::sys_listen(a0 as i32, a1 as i32) }
        nr::SYS_ACCEPT4 => { crate::net::poll(); socket::sys_accept4(a0 as i32, a1, a2, a3 as i32) }
        nr::SYS_CONNECT => { crate::net::poll(); socket::sys_connect(a0 as i32, a1, a2) }
        nr::SYS_GETSOCKNAME => socket::sys_getsockname(a0 as i32, a1, a2),
        nr::SYS_GETPEERNAME => socket::sys_getpeername(a0 as i32, a1, a2),
        nr::SYS_SENDTO => { crate::net::poll(); socket::sys_sendto(a0 as i32, a1, a2, a3 as i32, a4, a5) }
        nr::SYS_RECVFROM => { crate::net::poll(); socket::sys_recvfrom(a0 as i32, a1, a2, a3 as i32, a4, a5) }
        nr::SYS_SETSOCKOPT => socket::sys_setsockopt(a0 as i32, a1 as i32, a2 as i32, a3, a4 as i32),
        nr::SYS_GETSOCKOPT => socket::sys_getsockopt(a0 as i32, a1 as i32, a2 as i32, a3, a4),
        nr::SYS_SHUTDOWN => { crate::net::poll(); socket::sys_shutdown(a0 as i32, a1 as i32) }
        nr::SYS_SENDMSG => { crate::net::poll(); socket::sys_sendmsg(a0 as i32, a1, a2 as i32) }
        nr::SYS_RECVMSG => { crate::net::poll(); socket::sys_recvmsg(a0 as i32, a1, a2 as i32) }
        _ => {
            println!("[syscall] unimplemented #{} a0={:#x} a1={:#x}", id, a0, a1);
            ENOSYS
        }
    };

    if syscall_trace_enabled() {
        crate::println!("[sys] #{} -> {:#x}", id, ret as usize);
    }
    // If the syscall handler put the task into Waiting + rewound sepc to
    // retry on wakeup, the user's a0 must NOT be clobbered by our
    // intermediate return value — otherwise the retry sees a different
    // first argument (e.g. fd=-11 instead of fd=3). Detect by checking
    // task state.
    let is_blocked = matches!(
        *current_task().state.lock(),
        crate::task::TaskState::Waiting
    );
    if !is_blocked {
        tf.x[9] = ret as usize;
    }
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
    // Drive the network stack so RX queue is current before we attempt the
    // read. Cheap when there's nothing to do.
    crate::net::poll();
    let n = match file.read(&mut tmp) {
        Ok(n) => n,
        Err(e) => return err_to_isize(e),
    };
    // TCP socket returning 0 may mean "no data yet" rather than EOF. Block
    // until either data arrives or the peer closes.
    if n == 0 {
        if let Some(sock) = file.inode.as_any().downcast_ref::<crate::fs::socket::Socket>() {
            if sock.kind == crate::fs::socket::SocketKind::Tcp {
                let nonblock = sock.state.lock().nonblock;
                if crate::net::tcp_may_recv(sock.handle) {
                    if nonblock {
                        return -11; // EAGAIN
                    }
                    // Rewind sepc and park; we'll be re-run after a packet.
                    crate::task::mark_socket_waiter(task.pid);
                    *task.state.lock() = crate::task::TaskState::Waiting;
                    unsafe {
                        let tf = task.tf_ptr();
                        (*tf).sepc -= 4;
                    }
                    return -11;
                }
            }
        }
    }
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
    crate::net::poll();
    let mut total = 0isize;
    for v in iovs {
        if v.len == 0 {
            continue;
        }
        let mut tmp = alloc::vec![0u8; v.len];
        match file.read(&mut tmp) {
            Ok(n) => {
                if n == 0 {
                    // Same socket-block treatment as sys_read when we've
                    // gotten nothing so far.
                    if total == 0 {
                        if let Some(sock) = file.inode.as_any()
                            .downcast_ref::<crate::fs::socket::Socket>()
                        {
                            if sock.kind == crate::fs::socket::SocketKind::Tcp {
                                let nonblock = sock.state.lock().nonblock;
                                if crate::net::tcp_may_recv(sock.handle) {
                                    if nonblock { return -11; }
                                    crate::task::mark_socket_waiter(task.pid);
                                    *task.state.lock() =
                                        crate::task::TaskState::Waiting;
                                    unsafe {
                                        let tf = task.tf_ptr();
                                        (*tf).sepc -= 4;
                                    }
                                    return -11;
                                }
                            }
                        }
                    }
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

// ---------- POSIX message queues ----------

use alloc::collections::VecDeque as MqVecDeque;

struct PosixMsg {
    prio: u32,
    data: alloc::vec::Vec<u8>,
}

struct PosixMq {
    queue: SpinMutex<MqVecDeque<PosixMsg>>,
    max_msgs: usize,
    max_msg_size: usize,
}

impl crate::fs::Inode for PosixMq {
    fn as_any(&self) -> &dyn core::any::Any { self }
    fn kind(&self) -> crate::fs::FileType { crate::fs::FileType::Pipe }
    fn size(&self) -> u64 { self.queue.lock().len() as u64 }
}

static MQ_TABLE: SpinMutex<alloc::collections::BTreeMap<alloc::string::String, Arc<PosixMq>>> =
    SpinMutex::new(alloc::collections::BTreeMap::new());

fn sys_mq_open(name: usize, oflag: i32, _mode: u32, attr: usize) -> isize {
    const O_CREAT: i32 = 0o100;
    const O_EXCL: i32 = 0o200;
    let task = current_task();
    let Some(name_s) = copy_path(name) else { return EFAULT };
    let key = alloc::string::String::from(name_s.trim_start_matches('/'));

    let mut table = MQ_TABLE.lock();
    let mq = if let Some(existing) = table.get(&key) {
        if (oflag & O_EXCL) != 0 && (oflag & O_CREAT) != 0 { return -17; }
        existing.clone()
    } else {
        if (oflag & O_CREAT) == 0 { return ENOENT; }
        let (max_msgs, max_size) = if attr != 0 {
            let Some(b) = task.copy_in_bytes(attr, 32) else { return EFAULT };
            let m = i64::from_le_bytes(b[8..16].try_into().unwrap_or([0; 8])) as usize;
            let s = i64::from_le_bytes(b[16..24].try_into().unwrap_or([0; 8])) as usize;
            (if m == 0 { 10 } else { m }, if s == 0 { 8192 } else { s })
        } else { (10, 8192) };
        let mq = Arc::new(PosixMq {
            queue: SpinMutex::new(MqVecDeque::new()),
            max_msgs, max_msg_size: max_size,
        });
        table.insert(key, mq.clone());
        mq
    };
    drop(table);
    let inode: Arc<dyn Inode> = mq;
    let file = Arc::new(crate::fs::File::from_inode(inode, true, true, false));
    let res = task.fd_table.lock().alloc(file, false);
    match res {
        Ok(fd) => fd as isize,
        Err(e) => err_to_isize(e),
    }
}

fn sys_mq_unlink(name: usize) -> isize {
    let Some(name_s) = copy_path(name) else { return EFAULT };
    let key = alloc::string::String::from(name_s.trim_start_matches('/'));
    let mut table = MQ_TABLE.lock();
    if table.remove(&key).is_some() { 0 } else { ENOENT }
}

fn sys_mq_timedsend(fd: i32, msg: usize, len: usize, prio: u32, _abs: usize) -> isize {
    let task = current_task();
    let Some(file) = task.fd_table.lock().get(fd) else { return EBADF };
    let mq = match file.inode.as_any().downcast_ref::<PosixMq>() { Some(q) => q, None => return EBADF };
    if len > mq.max_msg_size { return -90; }
    let Some(data) = task.copy_in_bytes(msg, len) else { return EFAULT };
    let mut q = mq.queue.lock();
    if q.len() >= mq.max_msgs { return -11; }
    q.push_back(PosixMsg { prio, data });
    0
}

fn sys_mq_timedreceive(fd: i32, msg: usize, len: usize, prio_ptr: usize, _abs: usize) -> isize {
    let task = current_task();
    let Some(file) = task.fd_table.lock().get(fd) else { return EBADF };
    let mq = match file.inode.as_any().downcast_ref::<PosixMq>() { Some(q) => q, None => return EBADF };
    let m = { let mut q = mq.queue.lock(); q.pop_front() };
    let Some(m) = m else { return -11; };
    let n = core::cmp::min(len, m.data.len());
    if task.copy_out_bytes(msg, &m.data[..n]).is_none() { return EFAULT; }
    if prio_ptr != 0 { let _ = task.copy_out_bytes(prio_ptr, &m.prio.to_le_bytes()); }
    n as isize
}

// ---------- pidfd / inotify / signalfd ----------

struct PidFd { pid: i32 }
impl crate::fs::Inode for PidFd {
    fn as_any(&self) -> &dyn core::any::Any { self }
    fn kind(&self) -> crate::fs::FileType { crate::fs::FileType::Pipe }
    fn size(&self) -> u64 { 0 }
}

fn sys_pidfd_open(pid: i32, _flags: u32) -> isize {
    if crate::task::task_by_pid(pid).is_none() { return -3; }
    let pfd: Arc<dyn Inode> = Arc::new(PidFd { pid });
    let file = Arc::new(crate::fs::File::from_inode(pfd, true, false, false));
    match current_task().fd_table.lock().alloc(file, true) {
        Ok(fd) => fd as isize, Err(e) => err_to_isize(e),
    }
}

fn sys_pidfd_send_signal(pidfd: i32, sig: i32, _siginfo: usize, _flags: u32) -> isize {
    let task = current_task();
    let Some(file) = task.fd_table.lock().get(pidfd) else { return EBADF };
    let pfd = match file.inode.as_any().downcast_ref::<PidFd>() { Some(p) => p, None => return EBADF };
    let Some(target) = crate::task::task_by_pid(pfd.pid) else { return -3; };
    crate::signal::raise_signal(&target, sig as u32);
    0
}

struct InotifyFd;
impl crate::fs::Inode for InotifyFd {
    fn as_any(&self) -> &dyn core::any::Any { self }
    fn kind(&self) -> crate::fs::FileType { crate::fs::FileType::Pipe }
    fn size(&self) -> u64 { 0 }
    fn read_at(&self, _o: u64, _b: &mut [u8]) -> crate::fs::Result<usize> { Ok(0) }
}

fn sys_inotify_init1(flags: i32) -> isize {
    const IN_CLOEXEC: i32 = 0o2000000;
    let n: Arc<dyn Inode> = Arc::new(InotifyFd);
    let file = Arc::new(crate::fs::File::from_inode(n, true, false, false));
    match current_task().fd_table.lock().alloc(file, flags & IN_CLOEXEC != 0) {
        Ok(fd) => fd as isize, Err(e) => err_to_isize(e),
    }
}

struct SignalFd { _mask: u64 }
impl crate::fs::Inode for SignalFd {
    fn as_any(&self) -> &dyn core::any::Any { self }
    fn kind(&self) -> crate::fs::FileType { crate::fs::FileType::Pipe }
    fn size(&self) -> u64 { 0 }
    fn read_at(&self, _o: u64, _b: &mut [u8]) -> crate::fs::Result<usize> { Ok(0) }
}

fn sys_signalfd4(fd: i32, mask_addr: usize, _sizemask: usize, flags: i32) -> isize {
    const SFD_CLOEXEC: i32 = 0o2000000;
    let task = current_task();
    let mask = if mask_addr != 0 {
        let b = task.copy_in_bytes(mask_addr, 8).unwrap_or(alloc::vec![0u8; 8]);
        u64::from_le_bytes(b.as_slice().try_into().unwrap_or([0; 8]))
    } else { 0 };
    if fd >= 0 { return fd as isize; }
    let s: Arc<dyn Inode> = Arc::new(SignalFd { _mask: mask });
    let file = Arc::new(crate::fs::File::from_inode(s, true, false, false));
    let res = task.fd_table.lock().alloc(file, flags & SFD_CLOEXEC != 0);
    match res {
        Ok(fd) => fd as isize,
        Err(e) => err_to_isize(e),
    }
}

// ---------- waitid ----------

fn sys_waitid(idtype: i32, id: i32, infop: usize, _options: i32) -> isize {
    let pid_filter = match idtype {
        0 => -1,
        1 => id,
        2 => -id,
        _ => return EINVAL,
    };
    let r = sys_wait4(pid_filter, 0, 0);
    if r < 0 { return r; }
    if r == 0 { return 0; }
    if infop != 0 {
        let pid = r as i32;
        let task = current_task();
        let mut buf = [0u8; 128];
        buf[0..4].copy_from_slice(&17i32.to_le_bytes());
        buf[8..12].copy_from_slice(&1i32.to_le_bytes());
        buf[16..20].copy_from_slice(&pid.to_le_bytes());
        let _ = task.copy_out_bytes(infop, &buf);
    }
    0
}

// ---------- POSIX record locks (fcntl F_SETLK / F_GETLK) ----------

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
struct Flock {
    l_type: i16,
    l_whence: i16,
    l_start: i64,
    l_len: i64,
    l_pid: i32,
    _pad: i32,
}

#[derive(Clone, Copy, Debug)]
struct LockRange {
    start: u64,
    end: u64,
    excl: bool,
    pid: i32,
}

static FLOCK_RANGES: SpinMutex<alloc::collections::BTreeMap<usize, alloc::vec::Vec<LockRange>>> =
    SpinMutex::new(alloc::collections::BTreeMap::new());

fn resolve_lock_range(l: &Flock, size: u64) -> (u64, u64) {
    let base = match l.l_whence {
        0 => 0,
        1 => 0,
        2 => size as i64,
        _ => 0,
    };
    let start = (base + l.l_start).max(0) as u64;
    let end = if l.l_len == 0 {
        u64::MAX
    } else if l.l_len > 0 {
        start + l.l_len as u64
    } else {
        let s = (start as i64 + l.l_len).max(0) as u64;
        let e = start;
        return (s, e);
    };
    (start, end)
}

fn ranges_overlap(a: (u64, u64), b: (u64, u64)) -> bool {
    a.0 < b.1 && b.0 < a.1
}

fn fcntl_setlk(file: &Arc<crate::fs::File>, flock: &Flock, wait: bool) -> isize {
    let key = Arc::as_ptr(&file.inode) as *const () as usize;
    let size = file.inode.size();
    let (start, end) = resolve_lock_range(flock, size);
    let me = current_task();
    let pid = me.pid;

    let mut table = FLOCK_RANGES.lock();
    let v = table.entry(key).or_default();

    if flock.l_type == 2 {
        v.retain(|r| !(r.pid == pid && ranges_overlap((r.start, r.end), (start, end))));
        if v.is_empty() { table.remove(&key); }
        return 0;
    }

    let excl = flock.l_type == 1;
    for r in v.iter() {
        if r.pid == pid { continue; }
        if !ranges_overlap((r.start, r.end), (start, end)) { continue; }
        if excl || r.excl {
            if wait { return -4; }
            return -11;
        }
    }
    v.push(LockRange { start, end, excl, pid });
    0
}

fn fcntl_getlk(file: &Arc<crate::fs::File>, flock_in: &Flock) -> Flock {
    let key = Arc::as_ptr(&file.inode) as *const () as usize;
    let size = file.inode.size();
    let (start, end) = resolve_lock_range(flock_in, size);
    let me_pid = current_task().pid;
    let mut out = *flock_in;
    let table = FLOCK_RANGES.lock();
    let want_excl = flock_in.l_type == 1;
    if let Some(v) = table.get(&key) {
        for r in v {
            if r.pid == me_pid { continue; }
            if !ranges_overlap((r.start, r.end), (start, end)) { continue; }
            if want_excl || r.excl {
                out.l_type = if r.excl { 1 } else { 0 };
                out.l_whence = 0;
                out.l_start = r.start as i64;
                out.l_len = if r.end == u64::MAX { 0 } else { (r.end - r.start) as i64 };
                out.l_pid = r.pid;
                return out;
            }
        }
    }
    out.l_type = 2;
    out
}

// ---------- flock (advisory, per-inode) ----------

use spin::Mutex as SpinMutex;

#[derive(Default)]
struct LockState {
    /// 0 = unlocked, >0 = shared count, -1 = exclusive
    count: i32,
}

static FLOCK_TABLE: SpinMutex<alloc::collections::BTreeMap<usize, LockState>> =
    SpinMutex::new(alloc::collections::BTreeMap::new());

fn sys_flock(fd: i32, op: i32) -> isize {
    const LOCK_SH: i32 = 1;
    const LOCK_EX: i32 = 2;
    const LOCK_NB: i32 = 4;
    const LOCK_UN: i32 = 8;

    let task = current_task();
    let Some(file) = task.fd_table.lock().get(fd) else { return EBADF; };
    let key = Arc::as_ptr(&file.inode) as *const () as usize;
    let mode = op & !LOCK_NB;
    let mut table = FLOCK_TABLE.lock();
    let entry = table.entry(key).or_default();

    match mode {
        LOCK_SH => {
            if entry.count < 0 {
                // exclusive held; would block
                return -11; // EWOULDBLOCK
            }
            entry.count += 1;
            0
        }
        LOCK_EX => {
            if entry.count != 0 {
                return -11; // EWOULDBLOCK
            }
            entry.count = -1;
            0
        }
        LOCK_UN => {
            if entry.count > 0 {
                entry.count -= 1;
            } else if entry.count < 0 {
                entry.count = 0;
            }
            if entry.count == 0 {
                table.remove(&key);
            }
            0
        }
        _ => EINVAL,
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
        // F_GETLK=5, F_SETLK=6, F_SETLKW=7. arg is `struct flock *`.
        5 | 6 | 7 => {
            let task = current_task();
            let Some(file) = task.fd_table.lock().get(fd) else { return EBADF };
            let Some(buf) = task.copy_in_bytes(arg as usize, core::mem::size_of::<Flock>()) else { return EFAULT };
            let mut flock = Flock::default();
            unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), &mut flock as *mut _ as *mut u8, core::mem::size_of::<Flock>()); }
            match cmd {
                5 => {
                    let out = fcntl_getlk(&file, &flock);
                    let bytes = unsafe { core::slice::from_raw_parts(&out as *const _ as *const u8, core::mem::size_of::<Flock>()) };
                    let _ = task.copy_out_bytes(arg as usize, bytes);
                    0
                }
                6 => fcntl_setlk(&file, &flock, false),
                7 => fcntl_setlk(&file, &flock, true),
                _ => unreachable!(),
            }
        }
        _ => 0,
    }
}

// ---------- statfs / preadv-pwritev / timerfd / prctl / sched_getaffinity ----------

#[repr(C)]
#[derive(Default)]
struct Statfs {
    f_type: u64,
    f_bsize: u64,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_fsid: [i32; 2],
    f_namelen: u64,
    f_frsize: u64,
    f_flags: u64,
    f_spare: [u64; 4],
}

fn statfs_for(_inode: &Arc<dyn Inode>) -> Statfs {
    let mut s = Statfs::default();
    s.f_type = 0x01021994; // TMPFS_MAGIC
    s.f_bsize = 4096;
    let (total, free) = crate::mm::frame_stats();
    s.f_blocks = total as u64;
    s.f_bfree = free as u64;
    s.f_bavail = free as u64;
    s.f_files = 1_000_000;
    s.f_ffree = 1_000_000;
    s.f_namelen = 255;
    s.f_frsize = 4096;
    s
}

fn sys_statfs(path: usize, buf: usize) -> isize {
    let Some(p) = copy_path(path) else { return EFAULT };
    let Some(i) = resolve_at(AT_FDCWD, &p) else { return ENOENT };
    let s = statfs_for(&i);
    write_struct(buf, &s)
}

fn sys_fstatfs(fd: i32, buf: usize) -> isize {
    let task = current_task();
    let Some(f) = task.fd_table.lock().get(fd) else { return EBADF };
    let s = statfs_for(&f.inode);
    write_struct(buf, &s)
}

fn sys_preadv(fd: i32, iov: usize, count: usize, off: u64) -> isize {
    if count == 0 { return 0; }
    let task = current_task();
    let Some(file) = task.fd_table.lock().get(fd) else { return EBADF };
    let Some(iovs_bytes) = task.copy_in_bytes(iov, count * core::mem::size_of::<IoVec>()) else { return EFAULT };
    let iovs = unsafe { core::slice::from_raw_parts(iovs_bytes.as_ptr() as *const IoVec, count) };
    let mut total = 0isize;
    let mut cur_off = off;
    for v in iovs {
        if v.len == 0 { continue; }
        let mut tmp = alloc::vec![0u8; v.len];
        match file.inode.read_at(cur_off, &mut tmp) {
            Ok(n) => {
                if n == 0 { break; }
                if task.copy_out_bytes(v.base, &tmp[..n]).is_none() { return EFAULT; }
                total += n as isize;
                cur_off += n as u64;
                if n < v.len { break; }
            }
            Err(e) => { if total == 0 { return err_to_isize(e); } else { break; } }
        }
    }
    total
}

fn sys_pwritev(fd: i32, iov: usize, count: usize, off: u64) -> isize {
    if count == 0 { return 0; }
    let task = current_task();
    let Some(file) = task.fd_table.lock().get(fd) else { return EBADF };
    let Some(iovs_bytes) = task.copy_in_bytes(iov, count * core::mem::size_of::<IoVec>()) else { return EFAULT };
    let iovs = unsafe { core::slice::from_raw_parts(iovs_bytes.as_ptr() as *const IoVec, count) };
    let mut total = 0isize;
    let mut cur_off = off;
    for v in iovs {
        if v.len == 0 { continue; }
        let Some(bytes) = task.copy_in_bytes(v.base, v.len) else { return EFAULT };
        match file.inode.write_at(cur_off, &bytes) {
            Ok(n) => { total += n as isize; cur_off += n as u64; if n < v.len { break; } }
            Err(e) => { if total == 0 { return err_to_isize(e); } else { break; } }
        }
    }
    total
}

struct TimerFd {
    expiry: SpinMutex<u64>,
    interval_ticks: SpinMutex<u64>,
}

impl crate::fs::Inode for TimerFd {
    fn as_any(&self) -> &dyn core::any::Any { self }
    fn kind(&self) -> crate::fs::FileType { crate::fs::FileType::Pipe }
    fn size(&self) -> u64 { 8 }
    fn read_at(&self, _off: u64, buf: &mut [u8]) -> crate::fs::Result<usize> {
        if buf.len() < 8 { return Err(crate::fs::EINVAL); }
        let exp_at = *self.expiry.lock();
        if exp_at == 0 { return Ok(0); }
        while riscv::register::time::read64() < exp_at {
            core::hint::spin_loop();
        }
        let interval = *self.interval_ticks.lock();
        let count: u64 = if interval == 0 {
            *self.expiry.lock() = 0;
            1
        } else {
            let now = riscv::register::time::read64();
            let n = ((now - exp_at) / interval) + 1;
            *self.expiry.lock() = exp_at + n * interval;
            n
        };
        buf[..8].copy_from_slice(&count.to_le_bytes());
        Ok(8)
    }
}

fn sys_timerfd_create(_clockid: i32, flags: i32) -> isize {
    const TFD_CLOEXEC: i32 = 0o2000000;
    let tf = Arc::new(TimerFd {
        expiry: SpinMutex::new(0),
        interval_ticks: SpinMutex::new(0),
    });
    let file = Arc::new(crate::fs::File::from_inode(tf, true, false, false));
    match current_task().fd_table.lock().alloc(file, flags & TFD_CLOEXEC != 0) {
        Ok(fd) => fd as isize,
        Err(e) => err_to_isize(e),
    }
}

fn parse_timespec(buf: &[u8]) -> (u64, u64) {
    let sec = i64::from_le_bytes(buf[0..8].try_into().unwrap_or([0; 8])) as u64;
    let ns = i64::from_le_bytes(buf[8..16].try_into().unwrap_or([0; 8])) as u64;
    (sec, ns)
}

fn ts_to_ticks(sec: u64, ns: u64) -> u64 {
    sec.saturating_mul(10_000_000) + ns / 100
}

fn sys_timerfd_settime(fd: i32, _flags: i32, new_value: usize, old_value: usize) -> isize {
    let task = current_task();
    let Some(file) = task.fd_table.lock().get(fd) else { return EBADF };
    let tf = match file.inode.as_any().downcast_ref::<TimerFd>() { Some(t) => t, None => return EINVAL };
    let Some(buf) = task.copy_in_bytes(new_value, 32) else { return EFAULT };
    let (interval_s, interval_ns) = parse_timespec(&buf[0..16]);
    let (value_s, value_ns) = parse_timespec(&buf[16..32]);

    if old_value != 0 {
        let zero = [0u8; 32];
        let _ = task.copy_out_bytes(old_value, &zero);
    }

    let interval = ts_to_ticks(interval_s, interval_ns);
    let value = ts_to_ticks(value_s, value_ns);
    let now = riscv::register::time::read64();
    *tf.expiry.lock() = if value == 0 { 0 } else { now + value };
    *tf.interval_ticks.lock() = interval;
    0
}

fn sys_timerfd_gettime(fd: i32, cur: usize) -> isize {
    let task = current_task();
    let Some(file) = task.fd_table.lock().get(fd) else { return EBADF };
    let Some(_) = file.inode.as_any().downcast_ref::<TimerFd>() else { return EINVAL };
    let zero = [0u8; 32];
    if task.copy_out_bytes(cur, &zero).is_none() { return EFAULT; }
    0
}

fn sys_prctl(option: i32, a2: usize, _a3: usize, _a4: usize, _a5: usize) -> isize {
    const PR_SET_NAME: i32 = 15;
    const PR_GET_NAME: i32 = 16;
    let task = current_task();
    match option {
        PR_SET_NAME => {
            if let Some(bytes) = task.copy_in_bytes(a2, 16) {
                let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                let mut cmd = task.cmdline.lock();
                let mut parts: alloc::vec::Vec<alloc::vec::Vec<u8>> =
                    cmd.split(|&b| b == 0).map(|s| s.to_vec()).collect();
                if parts.is_empty() { parts.push(alloc::vec::Vec::new()); }
                parts[0] = bytes[..end].to_vec();
                let mut new = alloc::vec::Vec::new();
                for (i, p) in parts.iter().enumerate() {
                    if i > 0 { new.push(0); }
                    new.extend_from_slice(p);
                }
                *cmd = new;
            }
            0
        }
        PR_GET_NAME => {
            let cmd = task.cmdline.lock();
            let name: alloc::vec::Vec<u8> = cmd.iter().take_while(|&&b| b != 0).cloned().collect();
            let mut buf = [0u8; 16];
            let n = core::cmp::min(15, name.len());
            buf[..n].copy_from_slice(&name[..n]);
            if task.copy_out_bytes(a2, &buf).is_none() { return EFAULT; }
            0
        }
        _ => 0,
    }
}

fn sys_sched_getaffinity(_pid: i32, _cpusetsize: usize, mask: usize) -> isize {
    let task = current_task();
    let mut buf = alloc::vec![0u8; 128];
    buf[0] = 0x1;
    if task.copy_out_bytes(mask, &buf).is_none() { return EFAULT; }
    128
}

// ---------- sendfile / copy_file_range / memfd_create / close_range / mremap ----------

fn sys_sendfile(out_fd: i32, in_fd: i32, offset_ptr: usize, count: usize) -> isize {
    let task = current_task();
    let in_file = match task.fd_table.lock().get(in_fd) { Some(f) => f, None => return EBADF };
    let out_file = match task.fd_table.lock().get(out_fd) { Some(f) => f, None => return EBADF };

    let mut off = if offset_ptr != 0 {
        let bytes = task.copy_in_bytes(offset_ptr, 8).unwrap_or(alloc::vec![0u8; 8]);
        u64::from_le_bytes(bytes.as_slice().try_into().unwrap_or([0; 8]))
    } else {
        *in_file.offset.lock()
    };

    let mut copied = 0usize;
    let chunk = 8192;
    while copied < count {
        let want = core::cmp::min(chunk, count - copied);
        let mut buf = alloc::vec![0u8; want];
        let n = match in_file.inode.read_at(off, &mut buf) {
            Ok(n) => n,
            Err(e) => { if copied == 0 { return err_to_isize(e); } else { break; } }
        };
        if n == 0 { break; }
        match out_file.write(&buf[..n]) {
            Ok(w) => { copied += w; off += w as u64; if w < n { break; } }
            Err(e) => { if copied == 0 { return err_to_isize(e); } else { break; } }
        }
    }
    if offset_ptr != 0 {
        let _ = task.copy_out_bytes(offset_ptr, &off.to_le_bytes());
    } else {
        *in_file.offset.lock() = off;
    }
    copied as isize
}

fn sys_copy_file_range(fd_in: i32, off_in: usize, fd_out: i32, off_out: usize, len: usize, _flags: u32) -> isize {
    let task = current_task();
    let in_file = match task.fd_table.lock().get(fd_in) { Some(f) => f, None => return EBADF };
    let out_file = match task.fd_table.lock().get(fd_out) { Some(f) => f, None => return EBADF };

    let mut in_off = if off_in != 0 {
        let bytes = task.copy_in_bytes(off_in, 8).unwrap_or(alloc::vec![0u8; 8]);
        u64::from_le_bytes(bytes.as_slice().try_into().unwrap_or([0; 8]))
    } else { *in_file.offset.lock() };
    let mut out_off = if off_out != 0 {
        let bytes = task.copy_in_bytes(off_out, 8).unwrap_or(alloc::vec![0u8; 8]);
        u64::from_le_bytes(bytes.as_slice().try_into().unwrap_or([0; 8]))
    } else { *out_file.offset.lock() };

    let mut copied = 0usize;
    let chunk = 8192;
    while copied < len {
        let want = core::cmp::min(chunk, len - copied);
        let mut buf = alloc::vec![0u8; want];
        let n = match in_file.inode.read_at(in_off, &mut buf) {
            Ok(n) => n, Err(e) => { if copied == 0 { return err_to_isize(e); } else { break; } }
        };
        if n == 0 { break; }
        match out_file.inode.write_at(out_off, &buf[..n]) {
            Ok(w) => { copied += w; in_off += w as u64; out_off += w as u64; if w < n { break; } }
            Err(e) => { if copied == 0 { return err_to_isize(e); } else { break; } }
        }
    }
    if off_in != 0 { let _ = task.copy_out_bytes(off_in, &in_off.to_le_bytes()); }
    else { *in_file.offset.lock() = in_off; }
    if off_out != 0 { let _ = task.copy_out_bytes(off_out, &out_off.to_le_bytes()); }
    else { *out_file.offset.lock() = out_off; }
    copied as isize
}

/// memfd_create(name, flags) — anonymous in-memory file.
fn sys_memfd_create(_name: usize, flags: u32) -> isize {
    const MFD_CLOEXEC: u32 = 1;
    let file_inode: Arc<dyn Inode> = Arc::new(crate::fs::tmpfs::TmpfsFile::new());
    let f = Arc::new(crate::fs::File::from_inode(file_inode, true, true, false));
    match current_task().fd_table.lock().alloc(f, flags & MFD_CLOEXEC != 0) {
        Ok(fd) => fd as isize,
        Err(e) => err_to_isize(e),
    }
}

fn sys_close_range(first: u32, last: u32, _flags: u32) -> isize {
    let task = current_task();
    let t = task.fd_table.lock();
    let max = t.table.lock().len() as u32;
    let end = core::cmp::min(last, max.saturating_sub(1));
    for fd in first..=end {
        let _ = t.close(fd as i32);
    }
    0
}

/// mremap(old, old_sz, new_sz, flags, new_addr) — alloc new range,
/// copy old contents, unmap old.
fn sys_mremap(old: usize, old_sz: usize, new_sz: usize, _flags: i32, _new_addr: usize) -> isize {
    if old == 0 || old_sz == 0 || new_sz == 0 { return EINVAL; }
    let task = current_task();
    let copy_n = core::cmp::min(old_sz, new_sz);
    let buf = task.copy_in_bytes(old, copy_n).unwrap_or_default();
    let new_va = sys_mmap(0, new_sz, 0x3, 0x22, -1, 0);
    if new_va < 0 { return new_va; }
    let _ = task.copy_out_bytes(new_va as usize, &buf);
    task.memory_set_mut().unmap_range(crate::mm::VirtAddr(old), old_sz);
    new_va
}

// ---------- rlimit / truncate / pselect / eventfd ----------

#[repr(C)]
#[derive(Clone, Copy)]
struct Rlimit {
    cur: u64,
    max: u64,
}

const RLIMIT_CPU: u32 = 0;
const RLIMIT_FSIZE: u32 = 1;
const RLIMIT_DATA: u32 = 2;
const RLIMIT_STACK: u32 = 3;
const RLIMIT_CORE: u32 = 4;
const RLIMIT_RSS: u32 = 5;
const RLIMIT_NPROC: u32 = 6;
const RLIMIT_NOFILE: u32 = 7;
const RLIMIT_MEMLOCK: u32 = 8;
const RLIMIT_AS: u32 = 9;
const RLIM_INFINITY: u64 = u64::MAX;

fn default_rlimit(resource: u32) -> Rlimit {
    match resource {
        RLIMIT_STACK => Rlimit { cur: 8 * 1024 * 1024, max: 8 * 1024 * 1024 },
        RLIMIT_NOFILE => Rlimit { cur: 1024, max: 4096 },
        RLIMIT_NPROC => Rlimit { cur: 64, max: 64 },
        RLIMIT_CORE => Rlimit { cur: 0, max: RLIM_INFINITY },
        RLIMIT_DATA | RLIMIT_RSS | RLIMIT_AS => {
            Rlimit { cur: RLIM_INFINITY, max: RLIM_INFINITY }
        }
        RLIMIT_FSIZE => Rlimit { cur: RLIM_INFINITY, max: RLIM_INFINITY },
        RLIMIT_CPU => Rlimit { cur: RLIM_INFINITY, max: RLIM_INFINITY },
        RLIMIT_MEMLOCK => Rlimit { cur: 65536, max: 65536 },
        _ => Rlimit { cur: RLIM_INFINITY, max: RLIM_INFINITY },
    }
}

fn sys_prlimit64(_pid: i32, resource: u32, new_lim: usize, old_lim: usize) -> isize {
    let task = current_task();
    let cur = default_rlimit(resource);
    if old_lim != 0 {
        let bytes = unsafe {
            core::slice::from_raw_parts(&cur as *const _ as *const u8, 16)
        };
        if task.copy_out_bytes(old_lim, bytes).is_none() {
            return EFAULT;
        }
    }
    // Pretend the new limit succeeded; we don't actually enforce.
    let _ = new_lim;
    0
}

fn sys_getrlimit(resource: u32, buf: usize) -> isize {
    sys_prlimit64(0, resource, 0, buf)
}

fn sys_setrlimit(_resource: u32, _buf: usize) -> isize {
    0
}

fn sys_truncate(path: usize, length: u64) -> isize {
    let Some(p) = copy_path(path) else { return EFAULT };
    let Some(i) = resolve_at(AT_FDCWD, &p) else { return ENOENT };
    match i.truncate(length) {
        Ok(()) => 0,
        Err(e) => err_to_isize(e),
    }
}

fn sys_ftruncate(fd: i32, length: u64) -> isize {
    let task = current_task();
    let Some(file) = task.fd_table.lock().get(fd) else { return EBADF; };
    match file.inode.truncate(length) {
        Ok(()) => 0,
        Err(e) => err_to_isize(e),
    }
}

/// pselect6(nfds, rfds, wfds, efds, timeout, sigmask_arg).
/// We translate to ppoll by walking the fd bitmaps and building a
/// pollfd[] for the union, then waiting via the console-aware ppoll
/// path. Good enough for the common select+stdin idiom.
fn sys_pselect6(
    nfds: usize,
    rfds: usize,
    wfds: usize,
    efds: usize,
    _timeout: usize,
    _sigmask: usize,
) -> isize {
    if nfds == 0 {
        return 0;
    }
    let task = current_task();
    let bytes = (nfds + 7) / 8;
    let read_set = |addr: usize| -> alloc::vec::Vec<u8> {
        if addr == 0 { alloc::vec![0u8; bytes] }
        else { task.copy_in_bytes(addr, bytes).unwrap_or_else(|| alloc::vec![0u8; bytes]) }
    };
    let r = read_set(rfds);
    let w = read_set(wfds);
    let _e = read_set(efds);
    let mut ready = 0isize;
    let mut zero = alloc::vec![0u8; bytes];

    // Trivial case: any read-fd is the console -> block on it; mark
    // ready when it becomes readable. Non-console reads we say "ready
    // now" (so unblocking sockets work cooperatively). Writes always
    // ready.
    let mut blocking_console = false;
    for fd in 0..nfds {
        if r[fd / 8] & (1 << (fd % 8)) != 0 {
            if let Some(f) = task.fd_table.lock().get(fd as i32) {
                if f.is_console {
                    blocking_console = true;
                    break;
                }
            }
        }
    }
    if blocking_console {
        crate::fs::console_wait_readable();
    }

    // Build result: keep r/w bits set as input said (everything ready).
    if rfds != 0 {
        let _ = task.copy_out_bytes(rfds, &r);
        for fd in 0..nfds {
            if r[fd / 8] & (1 << (fd % 8)) != 0 { ready += 1; }
        }
    }
    if wfds != 0 {
        let _ = task.copy_out_bytes(wfds, &w);
        for fd in 0..nfds {
            if w[fd / 8] & (1 << (fd % 8)) != 0 { ready += 1; }
        }
    }
    if efds != 0 {
        zero.fill(0);
        let _ = task.copy_out_bytes(efds, &zero);
    }
    ready
}

/// Eventfd: tiny semaphore-ish counter file. Read takes (and zeros or
/// decrements), write adds. We implement it as a regular Inode so it
/// fits the fd table.
struct EventFd {
    counter: SpinMutex<u64>,
    semaphore: bool,
}

impl crate::fs::Inode for EventFd {
    fn as_any(&self) -> &dyn core::any::Any { self }
    fn kind(&self) -> crate::fs::FileType { crate::fs::FileType::Pipe }
    fn size(&self) -> u64 { 8 }
    fn read_at(&self, _off: u64, buf: &mut [u8]) -> crate::fs::Result<usize> {
        if buf.len() < 8 { return Err(crate::fs::EINVAL); }
        let mut c = self.counter.lock();
        if *c == 0 { return Ok(0); }
        let val = if self.semaphore { 1 } else { *c };
        buf[..8].copy_from_slice(&val.to_le_bytes());
        if self.semaphore { *c -= 1; } else { *c = 0; }
        Ok(8)
    }
    fn write_at(&self, _off: u64, buf: &[u8]) -> crate::fs::Result<usize> {
        if buf.len() < 8 { return Err(crate::fs::EINVAL); }
        let add = u64::from_le_bytes(buf[..8].try_into().unwrap());
        if add == u64::MAX { return Err(crate::fs::EINVAL); }
        let mut c = self.counter.lock();
        *c = c.saturating_add(add);
        Ok(8)
    }
}

fn sys_eventfd2(initval: u32, flags: i32) -> isize {
    const EFD_SEMAPHORE: i32 = 1;
    const EFD_CLOEXEC: i32 = 0o2000000;
    let ef = Arc::new(EventFd {
        counter: SpinMutex::new(initval as u64),
        semaphore: flags & EFD_SEMAPHORE != 0,
    });
    let file = Arc::new(crate::fs::File::from_inode(ef, true, true, false));
    let cloexec = flags & EFD_CLOEXEC != 0;
    match current_task().fd_table.lock().alloc(file, cloexec) {
        Ok(fd) => fd as isize,
        Err(e) => err_to_isize(e),
    }
}

// ---------- mmap / munmap / mprotect ----------

fn sys_munmap(addr: usize, len: usize) -> isize {
    if len == 0 {
        return EINVAL;
    }
    let task = current_task();
    task.memory_set_mut().unmap_range(crate::mm::VirtAddr(addr), len);
    0
}

fn sys_mprotect(addr: usize, len: usize, prot: i32) -> isize {
    if len == 0 {
        return EINVAL;
    }
    let mut perm = crate::mm::memory_set::VmPerm::U;
    if prot & 0x1 != 0 { perm |= crate::mm::memory_set::VmPerm::R; }
    if prot & 0x2 != 0 { perm |= crate::mm::memory_set::VmPerm::W; }
    if prot & 0x4 != 0 { perm |= crate::mm::memory_set::VmPerm::X; }
    let task = current_task();
    task.memory_set_mut().protect_range(crate::mm::VirtAddr(addr), len, perm);
    0
}

// ---------- chmod / chown / utimensat ----------

fn meta_of_inode(inode: &Arc<dyn Inode>) -> Option<&Arc<dyn Inode>> {
    Some(inode)
}

fn apply_mode(inode: &Arc<dyn Inode>, mode: u32) {
    if let Some(f) = inode.as_any().downcast_ref::<crate::fs::tmpfs::TmpfsFile>() {
        f.meta.lock().mode = mode & 0o7777;
    } else if let Some(d) = inode.as_any().downcast_ref::<crate::fs::tmpfs::TmpfsDir>() {
        d.meta.lock().mode = mode & 0o7777;
    }
}

fn apply_owner(inode: &Arc<dyn Inode>, uid: u32, gid: u32) {
    if let Some(f) = inode.as_any().downcast_ref::<crate::fs::tmpfs::TmpfsFile>() {
        let mut m = f.meta.lock();
        if uid != u32::MAX { m.uid = uid; }
        if gid != u32::MAX { m.gid = gid; }
    } else if let Some(d) = inode.as_any().downcast_ref::<crate::fs::tmpfs::TmpfsDir>() {
        let mut m = d.meta.lock();
        if uid != u32::MAX { m.uid = uid; }
        if gid != u32::MAX { m.gid = gid; }
    }
}

fn apply_times(inode: &Arc<dyn Inode>, atime: Option<(i64, i64)>, mtime: Option<(i64, i64)>) {
    if let Some(f) = inode.as_any().downcast_ref::<crate::fs::tmpfs::TmpfsFile>() {
        let mut m = f.meta.lock();
        if let Some((s, ns)) = atime { m.atime_sec = s; m.atime_nsec = ns; }
        if let Some((s, ns)) = mtime { m.mtime_sec = s; m.mtime_nsec = ns; }
    } else if let Some(d) = inode.as_any().downcast_ref::<crate::fs::tmpfs::TmpfsDir>() {
        let mut m = d.meta.lock();
        if let Some((s, ns)) = atime { m.atime_sec = s; m.atime_nsec = ns; }
        if let Some((s, ns)) = mtime { m.mtime_sec = s; m.mtime_nsec = ns; }
    }
}

fn sys_fchmod(fd: i32, mode: u32) -> isize {
    let task = current_task();
    let Some(file) = task.fd_table.lock().get(fd) else { return EBADF; };
    apply_mode(&file.inode, mode);
    0
}

fn sys_fchmodat(dfd: i32, path: usize, mode: u32) -> isize {
    let Some(p) = copy_path(path) else { return EFAULT };
    let Some(i) = resolve_at(dfd, &p) else { return ENOENT };
    apply_mode(&i, mode);
    0
}

fn sys_fchown(fd: i32, uid: u32, gid: u32) -> isize {
    let task = current_task();
    let Some(file) = task.fd_table.lock().get(fd) else { return EBADF; };
    apply_owner(&file.inode, uid, gid);
    0
}

fn sys_fchownat(dfd: i32, path: usize, uid: u32, gid: u32) -> isize {
    let Some(p) = copy_path(path) else { return EFAULT };
    let Some(i) = resolve_at(dfd, &p) else { return ENOENT };
    apply_owner(&i, uid, gid);
    0
}

const UTIME_NOW: i64 = (1i64 << 30) - 1;
const UTIME_OMIT: i64 = (1i64 << 30) - 2;

fn sys_utimensat(dfd: i32, path: usize, times: usize, _flags: i32) -> isize {
    let inode = if path == 0 {
        // AT_EMPTY_PATH or operating on dfd directly.
        let task = current_task();
        let Some(file) = task.fd_table.lock().get(dfd) else { return EBADF; };
        file.inode.clone()
    } else {
        let Some(p) = copy_path(path) else { return EFAULT };
        let Some(i) = resolve_at(dfd, &p) else { return ENOENT };
        i
    };

    let now_mtime = riscv::register::time::read64();
    let now_sec = (now_mtime / 10_000_000) as i64;
    let now_ns = ((now_mtime % 10_000_000) * 100) as i64;

    let (atime, mtime) = if times == 0 {
        // NULL → both = now.
        (Some((now_sec, now_ns)), Some((now_sec, now_ns)))
    } else {
        let task = current_task();
        let Some(buf) = task.copy_in_bytes(times, 32) else { return EFAULT };
        let parse = |o: usize| -> (i64, i64) {
            let s = i64::from_le_bytes(buf[o..o + 8].try_into().unwrap_or([0; 8]));
            let ns = i64::from_le_bytes(buf[o + 8..o + 16].try_into().unwrap_or([0; 8]));
            (s, ns)
        };
        let (as_, ans) = parse(0);
        let (ms_, mns) = parse(16);
        let atime = if ans == UTIME_OMIT { None } else if ans == UTIME_NOW { Some((now_sec, now_ns)) } else { Some((as_, ans)) };
        let mtime = if mns == UTIME_OMIT { None } else if mns == UTIME_NOW { Some((now_sec, now_ns)) } else { Some((ms_, mns)) };
        (atime, mtime)
    };

    apply_times(&inode, atime, mtime);
    0
}

// ---------- nanosleep (busy-wait on SBI timer) ----------

fn sys_nanosleep(req: usize, _rem: usize) -> isize {
    if req == 0 {
        return EFAULT;
    }
    let task = current_task();
    let Some(b) = task.copy_in_bytes(req, 16) else { return EFAULT };
    let sec = i64::from_le_bytes(b[0..8].try_into().unwrap_or([0; 8]));
    let nsec = i64::from_le_bytes(b[8..16].try_into().unwrap_or([0; 8]));
    if sec < 0 || nsec < 0 || nsec >= 1_000_000_000 {
        return EINVAL;
    }
    // QEMU virt mtime ticks at 10 MHz: 1 tick = 100 ns.
    let total_ticks = (sec as u64).saturating_mul(10_000_000)
        + (nsec as u64) / 100;
    let target = riscv::register::time::read64().saturating_add(total_ticks);
    while riscv::register::time::read64() < target {
        core::hint::spin_loop();
    }
    0
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
            FileType::Symlink => 10u8,
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
    let type_bits = match inode.kind() {
        FileType::Regular => 0o100000,
        FileType::Directory => 0o040000,
        FileType::CharDevice => 0o020000,
        FileType::Pipe => 0o010000,
        FileType::Symlink => 0o120000,
    };
    let (mode_bits, uid, gid, atime, mtime, ctime) = if let Some(f) = inode.as_any().downcast_ref::<crate::fs::tmpfs::TmpfsFile>() {
        let m = *f.meta.lock();
        (m.mode, m.uid, m.gid, (m.atime_sec, m.atime_nsec), (m.mtime_sec, m.mtime_nsec), (m.ctime_sec, m.ctime_nsec))
    } else if let Some(d) = inode.as_any().downcast_ref::<crate::fs::tmpfs::TmpfsDir>() {
        let m = *d.meta.lock();
        (m.mode, m.uid, m.gid, (m.atime_sec, m.atime_nsec), (m.mtime_sec, m.mtime_nsec), (m.ctime_sec, m.ctime_nsec))
    } else {
        let mode_default = match inode.kind() {
            FileType::Regular => 0o644,
            FileType::Directory => 0o755,
            FileType::CharDevice => 0o666,
            FileType::Pipe => 0o600,
            FileType::Symlink => 0o777,
        };
        (mode_default, 0, 0, (0, 0), (0, 0), (0, 0))
    };
    s.st_mode = (type_bits | (mode_bits & 0o7777)) as u32;
    s.st_uid = uid;
    s.st_gid = gid;
    s.st_atime = atime.0;
    s.st_atime_nsec = atime.1 as u64;
    s.st_mtime = mtime.0;
    s.st_mtime_nsec = mtime.1 as u64;
    s.st_ctime = ctime.0;
    s.st_ctime_nsec = ctime.1 as u64;
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

fn sys_newfstatat(dfd: i32, path: usize, buf: usize, flags: i32) -> isize {
    const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
    let Some(path_str) = copy_path(path) else { return EFAULT; };
    let inode = if path_str.is_empty() {
        let Some(file) = current_task().fd_table.lock().get(dfd) else { return EBADF; };
        file.inode.clone()
    } else if flags & AT_SYMLINK_NOFOLLOW != 0 {
        let Some(i) = resolve_at_nofollow(dfd, &path_str) else { return ENOENT; };
        i
    } else {
        let Some(i) = resolve_at(dfd, &path_str) else { return ENOENT; };
        i
    };
    let st = fill_stat(&inode);
    write_struct(buf, &st)
}

fn resolve_at_nofollow(dfd: i32, path: &str) -> Option<Arc<dyn Inode>> {
    let task = current_task();
    let start = if dfd == AT_FDCWD || path.starts_with('/') {
        let cwd = task.cwd.lock().clone();
        fs::lookup_path(fs::root(), &cwd).ok()?
    } else {
        task.fd_table.lock().get(dfd)?.inode.clone()
    };
    fs::lookup_path_nofollow(start, path).ok()
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
        FileType::Symlink => 0o120777,
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

/// Per-POSIX, exit_thread (sys_exit) terminates only the calling thread.
/// The process (tgid) survives until the *last* thread exits, at which
/// point we send SIGCHLD to the parent.
fn sys_exit(status: i32) -> isize {
    exit_one_thread(&current_task(), status, /* group_exit = */ false);
    0
}

/// exit_group: terminate every thread in this tgid with `status`. Used
/// by `_exit`, `abort`, signal-default-terminate paths.
fn sys_exit_group(status: i32) -> isize {
    let me = current_task();
    let my_tgid = me.tgid.load(core::sync::atomic::Ordering::Relaxed);

    // Snapshot the list of sibling threads (other tasks with same tgid).
    let mut siblings: alloc::vec::Vec<alloc::sync::Arc<crate::task::Task>> =
        crate::task::all_tasks()
            .into_iter()
            .filter(|t| {
                t.tgid.load(core::sync::atomic::Ordering::Relaxed) == my_tgid
                    && t.pid != me.pid
            })
            .collect();
    // Mark each sibling Zombie + drop them from any futex queue.
    for s in siblings.drain(..) {
        s.exit_code
            .store((status & 0xff) << 8, core::sync::atomic::Ordering::Relaxed);
        crate::sync::futex::forget_task(s.pid);
        clear_child_tid(&s);
        *s.state.lock() = crate::task::TaskState::Zombie;
        println!("[exit_group] pid={} status={}", s.pid, status);
    }
    // Now exit ourselves (group-exit: this is the leader's exit so the
    // parent gets SIGCHLD).
    exit_one_thread(&me, status, /* group_exit = */ true);
    0
}

/// Common exit path for one thread. If this is the last thread in the
/// tgid (or `group_exit`), notify the parent via SIGCHLD + wake.
fn exit_one_thread(task: &alloc::sync::Arc<crate::task::Task>, status: i32, group_exit: bool) {
    // Pre-encode the wait4 status as Linux expects: normal exit puts the
    // low byte of `status` in bits 8..15. wait4 returns it verbatim.
    task.exit_code
        .store((status & 0xff) << 8, core::sync::atomic::Ordering::Relaxed);

    // CLONE_CHILD_CLEARTID handling: store 0 to ctid, wake one futex.
    clear_child_tid(task);

    // Drop ourselves from any futex queue.
    crate::sync::futex::forget_task(task.pid);

    *task.state.lock() = crate::task::TaskState::Zombie;
    println!("[exit] pid={} status={}", task.pid, status);

    // Is this the last thread alive in this tgid?
    let my_tgid = task.tgid.load(core::sync::atomic::Ordering::Relaxed);
    let any_alive = crate::task::all_tasks().into_iter().any(|t| {
        t.tgid.load(core::sync::atomic::Ordering::Relaxed) == my_tgid
            && t.pid != task.pid
            && *t.state.lock() != crate::task::TaskState::Zombie
    });

    // For non-leader threads (tgid != pid), there is no parent that
    // will wait4 for us — POSIX says SIGCHLD is sent only when the
    // *process* (last thread) exits. We're detached, so self-reap.
    let is_thread = task.tgid.load(core::sync::atomic::Ordering::Relaxed) != task.pid;
    let leader_exit = group_exit || !any_alive;
    if leader_exit {
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
    }

    if is_thread {
        // Non-leader thread: no one will ever wait4 for this pid. Self-reap
        // *after* scheduler picks the next task. We can't reap now (the
        // scheduler still needs to read our state == Zombie to skip us);
        // instead, mark a "needs_reap" flag and reap on the next schedule.
        // Simpler: defer to a lazy sweep via a side channel.
        mark_for_self_reap(task.pid);
    }

    // If no other runnable/waiting/zombie task exists, halt.
    let pid = task.pid;
    if !crate::task::any_runnable_except(pid) && !crate::task::any_waiting() {
        sbi_rt::system_reset(sbi_rt::Shutdown, sbi_rt::NoReason);
        loop {
            unsafe { core::arch::asm!("wfi") };
        }
    }
}

/// PIDs of detached threads that should be reaped (deleted from the
/// task table + kstack freed) on the next scheduling boundary. We can't
/// reap inline because the scheduler still needs to observe our Zombie
/// state to switch off us.
static SELF_REAP_LIST: spin::Mutex<alloc::vec::Vec<i32>> = spin::Mutex::new(alloc::vec::Vec::new());

fn mark_for_self_reap(pid: i32) {
    SELF_REAP_LIST.lock().push(pid);
}

/// Called by the scheduler each trap exit. Reap pids queued for self-reap
/// (CLONE_THREAD detached threads whose memory is no longer needed). We
/// skip the *current* pid; it gets reaped next round.
pub fn drain_self_reap_list(except: i32) {
    let pids: alloc::vec::Vec<i32> = {
        let mut l = SELF_REAP_LIST.lock();
        let kept: alloc::vec::Vec<i32> = l.iter().copied().filter(|&p| p == except).collect();
        let to_take: alloc::vec::Vec<i32> = l.iter().copied().filter(|&p| p != except).collect();
        *l = kept;
        to_take
    };
    for pid in pids {
        crate::task::reap(pid);
    }
}

/// If a CLONE_CHILD_CLEARTID address was registered for `task`, store 0
/// to it and futex_wake(addr, 1). This is what unblocks pthread_join().
fn clear_child_tid(task: &alloc::sync::Arc<crate::task::Task>) {
    let addr = *task.clear_child_tid.lock();
    if addr == 0 {
        return;
    }
    *task.clear_child_tid.lock() = 0;
    let _ = task.copy_out_bytes(addr, &0i32.to_le_bytes());
    // Wake one waiter on this futex. Use the global futex machinery, but
    // we must perform the wake AS the exiting task (so the futex key is
    // computed via this task's MS — necessary in the no-CLONE_VM case).
    // crate::sync::futex::do_futex with a borrowed task isn't there yet;
    // do it directly by translating + waking.
    futex_wake_via_task(task, addr, 1);
}

fn futex_wake_via_task(task: &alloc::sync::Arc<crate::task::Task>, uaddr: usize, n: i32) {
    // Resolve PA via this task's MS (so the key matches what FUTEX_WAIT
    // used). We can't reach private helpers in sync::futex from outside
    // easily, so use the global op via a temporary current_task swap?
    // Simpler: temporarily set CURRENT_PID to this task. But we're called
    // from sys_exit_group iterating siblings — we ARE the current task
    // executing.
    //
    // Instead just call do_futex with the appropriate args, but use this
    // task's MS to compute the PA — implement a small public helper.
    crate::sync::futex::wake_for_task(task, uaddr, n);
}

pub fn sys_kill_current(status: i32) -> isize {
    sys_exit(status)
}

/// RISC-V (and most "generic") clone calling convention:
///   a0 = clone_flags | (exit_signal & 0xff)
///   a1 = child_sp
///   a2 = parent_tid_ptr
///   a3 = tls
///   a4 = child_tid_ptr
///
/// Note the swap of a3/a4 vs the standard musl prototype — RISC-V uses
/// the same order as ARM/x86_64. Musl's pthread_create passes:
///   flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD
///         |CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID
///   a1=child_sp, a2=&tid (==ptid), a3=tls, a4=&tid (==ctid)
fn sys_clone(flags: usize, child_sp: usize, ptid: usize, tls: usize, ctid: usize) -> isize {
    let new_task = crate::task::clone_current(flags, child_sp, ptid, ctid, tls);
    new_task.pid as isize
}

fn sys_set_tid_address(addr: usize) -> isize {
    let task = current_task();
    *task.clear_child_tid.lock() = addr;
    task.pid as isize
}

fn sys_futex(uaddr: usize, op: i32, val: u32, val2: usize, uaddr2: usize, val3: u32) -> isize {
    crate::sync::futex::do_futex(uaddr, op, val, val2, uaddr2, val3)
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
    match crate::task::execve_current_with_path(&elf_aligned, &argv_refs, &envp_refs, &path) {
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

fn sys_symlinkat(target: usize, new_dfd: i32, linkpath: usize) -> isize {
    let Some(target_s) = copy_path(target) else { return EFAULT };
    let Some(link_s) = copy_path(linkpath) else { return EFAULT };
    let Some((parent, name)) = resolve_at_parent(new_dfd, &link_s) else { return ENOENT };
    match parent.symlink(&name, &target_s) {
        Ok(()) => 0,
        Err(e) => err_to_isize(e),
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
    let resolved: alloc::string::String = if path_str == "/proc/self/exe" {
        task.exe_path.lock().clone()
    } else if path_str == "/proc/self/cwd" {
        task.cwd.lock().clone()
    } else if let Some(rest) = path_str.strip_prefix("/proc/") {
        if let Some((pid_str, leaf)) = rest.split_once('/') {
            if let Ok(pid) = pid_str.parse::<i32>() {
                if let Some(t) = crate::task::task_by_pid(pid) {
                    match leaf {
                        "exe" => t.exe_path.lock().clone(),
                        "cwd" => t.cwd.lock().clone(),
                        _ => return ENOENT,
                    }
                } else { return ENOENT; }
            } else { return ENOENT; }
        } else { return ENOENT; }
    } else {
        // General symlink: look up without following the final hop.
        match crate::fs::lookup_path_nofollow(crate::fs::root(), path_str) {
            Ok(i) if i.kind() == crate::fs::FileType::Symlink => match i.readlink() {
                Ok(t) => t,
                Err(_) => return EINVAL,
            },
            Ok(_) => return EINVAL,
            Err(_) => return ENOENT,
        }
    };
    if resolved.is_empty() {
        return ENOENT;
    }
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
