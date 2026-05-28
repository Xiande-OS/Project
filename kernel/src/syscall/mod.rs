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
            "[sys] #{} sp={:#x} a0={:#x} a1={:#x} a2={:#x}",
            id, tf.x[1], a0, a1, a2
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
        nr::SYS_FCNTL => 0,
        nr::SYS_FSYNC => 0,
        nr::SYS_UTIMENSAT => 0,
        nr::SYS_EXIT | nr::SYS_EXIT_GROUP => sys_exit(a0 as i32),
        nr::SYS_BRK => sys_brk(a0),
        nr::SYS_SET_TID_ADDRESS => 1,
        nr::SYS_SET_ROBUST_LIST => 0,
        nr::SYS_RT_SIGACTION => 0,
        nr::SYS_RT_SIGPROCMASK => 0,
        nr::SYS_IOCTL => 0,
        nr::SYS_GETUID | nr::SYS_GETEUID | nr::SYS_GETGID | nr::SYS_GETEGID => 0,
        nr::SYS_GETPID | nr::SYS_GETTID => 1,
        nr::SYS_GETPPID => 0,
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
        nr::SYS_TGKILL => 0,
        nr::SYS_TKILL => 0,
        nr::SYS_KILL => 0,
        nr::SYS_FUTEX => 0,
        nr::SYS_PPOLL => 0,
        nr::SYS_SIGALTSTACK => 0,
        nr::SYS_RT_SIGTIMEDWAIT => 0,
        nr::SYS_RT_SIGSUSPEND => 0,
        nr::SYS_SYSINFO => 0,
        nr::SYS_GETRUSAGE => 0,
        nr::SYS_MEMBARRIER => 0,
        nr::SYS_TIMES => 0,
        nr::SYS_READLINKAT => sys_readlinkat(a0 as i32, a1, a2, a3),
        nr::SYS_RENAMEAT2 => sys_renameat2(a0 as i32, a1, a2 as i32, a3, a4 as u32),
        nr::SYS_LINKAT => sys_linkat(a0 as i32, a1, a2 as i32, a3, a4 as i32),
        nr::SYS_SYMLINKAT => 0, // best-effort stub
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
    let Some(file) = task.fd_table.get(fd) else {
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
    let Some(file) = task.fd_table.get(fd) else {
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
    let Some(file) = task.fd_table.get(fd) else {
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
    let Some(file) = task.fd_table.get(fd) else {
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
    let Some(file) = task.fd_table.get(fd) else {
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
    let Some(file) = task.fd_table.get(fd) else {
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
    let Some(file) = task.fd_table.get(fd) else {
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
        task.fd_table.get(dfd)?.inode.clone()
    };
    fs::lookup_path(start, path).ok()
}

fn resolve_at_parent(dfd: i32, path: &str) -> Option<(Arc<dyn Inode>, String)> {
    let task = current_task();
    let start = if dfd == AT_FDCWD || path.starts_with('/') {
        let cwd = task.cwd.lock().clone();
        fs::lookup_path(fs::root(), &cwd).ok()?
    } else {
        task.fd_table.get(dfd)?.inode.clone()
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
    match current_task().fd_table.alloc(file, cloexec) {
        Ok(fd) => fd as isize,
        Err(e) => err_to_isize(e),
    }
}

fn sys_close(fd: i32) -> isize {
    match current_task().fd_table.close(fd) {
        Ok(()) => 0,
        Err(e) => err_to_isize(e),
    }
}

fn sys_dup(fd: i32) -> isize {
    let task = current_task();
    let Some(f) = task.fd_table.get(fd) else {
        return EBADF;
    };
    match task.fd_table.alloc(f, false) {
        Ok(nfd) => nfd as isize,
        Err(e) => err_to_isize(e),
    }
}

fn sys_dup3(oldfd: i32, newfd: i32, flags: i32) -> isize {
    let cloexec = (flags & O_CLOEXEC) != 0;
    match current_task().fd_table.dup3(oldfd, newfd, cloexec) {
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
    let r_fd = match task.fd_table.alloc(rf, cloexec) {
        Ok(fd) => fd,
        Err(e) => return err_to_isize(e),
    };
    let w_fd = match task.fd_table.alloc(wf, cloexec) {
        Ok(fd) => fd,
        Err(e) => {
            let _ = task.fd_table.close(r_fd);
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
    let Some(file) = task.fd_table.get(fd) else {
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
    let Some(file) = task.fd_table.get(fd) else {
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
        let Some(file) = current_task().fd_table.get(dfd) else {
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
        let Some(file) = current_task().fd_table.get(dfd) else {
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
        let Some(file) = task.fd_table.get(fd) else {
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
