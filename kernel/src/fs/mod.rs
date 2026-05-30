//! VFS skeleton. Minimal Inode/File/FdTable, in-memory only (M5).

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::{Mutex, Once};

pub mod devfs;
pub mod ext4;
pub mod fat32;
pub mod pipe;
pub mod procfs;
pub mod socket;
pub mod tmpfs;
pub use tmpfs::TmpfsDir;

/// One-byte ring of pushback: if `ppoll` peeked a char, the next
/// `console_read` returns it first before going back to SBI.
static CONSOLE_PEEK: Mutex<Option<u8>> = Mutex::new(None);

/// Translate raw tty control chars to signals (sent to the foreground pgrp).
/// Returns `Some(b)` if the char should still be delivered as input, or
/// `None` if it was a signal-trigger and should be swallowed.
fn handle_tty_input(b: u8) -> Option<u8> {
    use crate::signal::{SIGINT, SIGQUIT, SIGTSTP};
    match b {
        0x03 => {
            crate::syscall::deliver_tty_signal(SIGINT);
            None
        }
        0x1c => {
            crate::syscall::deliver_tty_signal(SIGQUIT);
            None
        }
        0x1a => {
            crate::syscall::deliver_tty_signal(SIGTSTP);
            None
        }
        _ => Some(b),
    }
}

fn get_console_byte_blocking() -> u8 {
    loop {
        let Some(b) = crate::arch::console_get() else {
            core::hint::spin_loop();
            continue;
        };
        let b = if b == b'\r' { b'\n' } else { b };
        if let Some(b) = handle_tty_input(b) {
            return b;
        }
        // Was a signal-trigger -- loop and read the next byte (or block).
    }
}

fn get_console_byte_nonblock() -> Option<u8> {
    let b = crate::arch::console_get()?;
    let b = if b == b'\r' { b'\n' } else { b };
    handle_tty_input(b)
}

/// Block until at least one byte is available on stdin, then drain the
/// rest of what's queued without further blocking.
fn console_read(buf: &mut [u8]) -> usize {
    if buf.is_empty() {
        return 0;
    }
    let mut n = 0;
    if let Some(b) = CONSOLE_PEEK.lock().take() {
        buf[n] = b;
        n += 1;
        if n == buf.len() {
            return n;
        }
    } else {
        buf[n] = get_console_byte_blocking();
        n += 1;
        if n == buf.len() {
            return n;
        }
    }
    while n < buf.len() {
        match get_console_byte_nonblock() {
            Some(b) => {
                buf[n] = b;
                n += 1;
            }
            None => break,
        }
    }
    n
}

/// Block until the SBI console has a readable byte (which we stash into
/// the peek buffer for the next read). Used to back ppoll(stdin).
pub fn console_wait_readable() {
    let mut peek = CONSOLE_PEEK.lock();
    if peek.is_some() {
        return;
    }
    drop(peek);
    let b = get_console_byte_blocking();
    *CONSOLE_PEEK.lock() = Some(b);
}

pub fn console_has_readable() -> bool {
    if CONSOLE_PEEK.lock().is_some() {
        return true;
    }
    if let Some(b) = get_console_byte_nonblock() {
        *CONSOLE_PEEK.lock() = Some(b);
        true
    } else {
        false
    }
}

pub type Result<T> = core::result::Result<T, i32>;

pub const ENOENT: i32 = -2;
pub const EBADF: i32 = -9;
pub const EAGAIN: i32 = -11;
pub const ENOMEM: i32 = -12;
pub const EFAULT: i32 = -14;
pub const EEXIST: i32 = -17;
pub const ENOTDIR: i32 = -20;
pub const ENAMETOOLONG: i32 = -36;
pub const EISDIR: i32 = -21;
pub const EINVAL: i32 = -22;
pub const ENOSPC: i32 = -28;
pub const EMFILE: i32 = -24;
pub const ESPIPE: i32 = -29;
pub const ENOSYS: i32 = -38;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileType {
    Regular,
    Directory,
    CharDevice,
    Pipe,
    Symlink,
}

pub trait Inode: Send + Sync + core::any::Any {
    fn as_any(&self) -> &dyn core::any::Any;
    fn kind(&self) -> FileType;
    fn size(&self) -> u64 {
        0
    }
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> Result<usize> {
        Err(EINVAL)
    }
    fn write_at(&self, _offset: u64, _buf: &[u8]) -> Result<usize> {
        Err(EINVAL)
    }
    fn truncate(&self, _len: u64) -> Result<()> {
        Err(EINVAL)
    }
    fn lookup(&self, _name: &str) -> Result<Arc<dyn Inode>> {
        Err(ENOTDIR)
    }
    fn create(&self, _name: &str, _kind: FileType) -> Result<Arc<dyn Inode>> {
        Err(ENOTDIR)
    }
    /// Create a symlink named `name` pointing at `target`. Default: not
    /// supported.
    fn symlink(&self, _name: &str, _target: &str) -> Result<()> {
        Err(EINVAL)
    }
    fn unlink(&self, _name: &str) -> Result<()> {
        Err(ENOTDIR)
    }
    fn list(&self) -> Result<Vec<(String, FileType)>> {
        Err(ENOTDIR)
    }
    /// If this Inode is a symlink, return its target path.
    fn readlink(&self) -> Result<String> {
        Err(EINVAL)
    }
}

/// In-memory symlink: just stores the target path.
pub struct Symlink {
    pub target: String,
}

impl Inode for Symlink {
    fn as_any(&self) -> &dyn core::any::Any { self }
    fn kind(&self) -> FileType { FileType::Symlink }
    fn size(&self) -> u64 { self.target.len() as u64 }
    fn readlink(&self) -> Result<String> { Ok(self.target.clone()) }
}

pub struct File {
    pub inode: Arc<dyn Inode>,
    pub offset: Mutex<u64>,
    pub readable: bool,
    pub writable: bool,
    pub append: bool,
    /// For stdio fds 0/1/2 backed by the SBI console.
    pub is_console: bool,
}

impl File {
    pub fn from_inode(inode: Arc<dyn Inode>, readable: bool, writable: bool, append: bool) -> Self {
        Self {
            inode,
            offset: Mutex::new(0),
            readable,
            writable,
            append,
            is_console: false,
        }
    }

    pub fn console() -> Self {
        Self {
            inode: Arc::new(tmpfs::TmpfsFile::new()),
            offset: Mutex::new(0),
            readable: true,
            writable: true,
            append: false,
            is_console: true,
        }
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize> {
        if !self.readable {
            return Err(EBADF);
        }
        if self.is_console {
            return Ok(console_read(buf));
        }
        let mut offset = self.offset.lock();
        let n = self.inode.read_at(*offset, buf)?;
        *offset += n as u64;
        Ok(n)
    }

    pub fn write(&self, buf: &[u8]) -> Result<usize> {
        if !self.writable {
            return Err(EBADF);
        }
        if self.is_console {
            for &b in buf {
                crate::arch::console_put(b);
            }
            return Ok(buf.len());
        }
        let mut offset = self.offset.lock();
        let pos = if self.append { self.inode.size() } else { *offset };
        let n = self.inode.write_at(pos, buf)?;
        *offset = pos + n as u64;
        Ok(n)
    }

    pub fn seek(&self, offset: i64, whence: i32) -> Result<u64> {
        if self.is_console {
            return Err(ESPIPE);
        }
        let mut off = self.offset.lock();
        let new_off = match whence {
            0 => offset as u64,
            1 => (*off as i64 + offset) as u64,
            2 => (self.inode.size() as i64 + offset) as u64,
            _ => return Err(EINVAL),
        };
        *off = new_off;
        Ok(new_off)
    }
}

pub struct FdTable {
    pub table: Mutex<Vec<Option<Arc<File>>>>,
    pub cloexec: Mutex<Vec<bool>>,
    /// Soft cap on the number of open fds (RLIMIT_NOFILE). alloc() returns
    /// EMFILE once we'd cross this many live fds. setrlimit updates this so
    /// libc-test/rlimit_open_files terminates instead of opening fds
    /// forever. Default mirrors `default_rlimit(NOFILE).cur = 1024`.
    pub soft_max: core::sync::atomic::AtomicUsize,
}

impl FdTable {
    pub fn new() -> Self {
        let stdin = Arc::new(File::console());
        let stdout = Arc::new(File::console());
        let stderr = Arc::new(File::console());
        Self {
            table: Mutex::new(alloc::vec![Some(stdin), Some(stdout), Some(stderr)]),
            cloexec: Mutex::new(alloc::vec![false, false, false]),
            soft_max: core::sync::atomic::AtomicUsize::new(1024),
        }
    }

    pub fn clone_for_fork(&self) -> Self {
        let t = self.table.lock();
        let c = self.cloexec.lock();
        Self {
            table: Mutex::new(t.clone()),
            cloexec: Mutex::new(c.clone()),
            soft_max: core::sync::atomic::AtomicUsize::new(
                self.soft_max.load(core::sync::atomic::Ordering::Relaxed),
            ),
        }
    }

    pub fn close_cloexec(&self) {
        let mut t = self.table.lock();
        let c = self.cloexec.lock();
        for i in 0..t.len() {
            if c.get(i).copied().unwrap_or(false) {
                t[i] = None;
            }
        }
    }

    /// Close every fd, dropping the File Arcs. Called on process exit so
    /// pipe write-ends are released and downstream readers observe EOF.
    /// Without this, a zombie's fd_table keeps the pipe writer alive until
    /// reap(), so `cmd | grep ...` hangs forever (the grep never sees EOF).
    pub fn close_all(&self) {
        let mut t = self.table.lock();
        for slot in t.iter_mut() {
            *slot = None;
        }
    }

    pub fn alloc(&self, file: Arc<File>, cloexec: bool) -> Result<i32> {
        let mut t = self.table.lock();
        let mut c = self.cloexec.lock();
        let cap = self.soft_max.load(core::sync::atomic::Ordering::Relaxed);
        for i in 0..t.len() {
            if t[i].is_none() {
                if i >= cap {
                    return Err(EMFILE);
                }
                t[i] = Some(file);
                if c.len() <= i {
                    c.resize(i + 1, false);
                }
                c[i] = cloexec;
                return Ok(i as i32);
            }
        }
        let fd = t.len();
        if fd >= cap {
            return Err(EMFILE);
        }
        t.push(Some(file));
        c.push(cloexec);
        Ok(fd as i32)
    }

    pub fn get(&self, fd: i32) -> Option<Arc<File>> {
        let t = self.table.lock();
        if fd < 0 || fd as usize >= t.len() {
            return None;
        }
        t[fd as usize].clone()
    }

    pub fn close(&self, fd: i32) -> Result<()> {
        let mut t = self.table.lock();
        if fd < 0 || fd as usize >= t.len() {
            return Err(EBADF);
        }
        if t[fd as usize].is_none() {
            return Err(EBADF);
        }
        t[fd as usize] = None;
        Ok(())
    }

    pub fn dup3(&self, oldfd: i32, newfd: i32, cloexec: bool) -> Result<i32> {
        if oldfd == newfd {
            return Err(EINVAL);
        }
        let mut t = self.table.lock();
        let mut c = self.cloexec.lock();
        if oldfd < 0 || oldfd as usize >= t.len() {
            return Err(EBADF);
        }
        let f = t[oldfd as usize].clone().ok_or(EBADF)?;
        // Reject an out-of-range target the way Linux does: newfd must be a
        // non-negative descriptor below RLIMIT_NOFILE. Without this, dup201's
        // dup2(fd, huge) grows the fd-table Vec to `newfd` entries — a
        // multi-hundred-MB infallible allocation that panics the whole kernel.
        let cap = self.soft_max.load(core::sync::atomic::Ordering::Relaxed);
        if newfd < 0 || newfd as usize >= cap {
            return Err(EBADF);
        }
        let nf = newfd as usize;
        while t.len() <= nf {
            t.push(None);
            c.push(false);
        }
        t[nf] = Some(f);
        c[nf] = cloexec;
        Ok(newfd)
    }
}

static ROOT_INODE: Once<Arc<dyn Inode>> = Once::new();

pub fn init() {
    let root = tmpfs::TmpfsDir::new_root();

    let dev = tmpfs::TmpfsDir::new_root();
    dev.create_special("null", devfs::DevKind::Null).unwrap();
    dev.create_special("zero", devfs::DevKind::Zero).unwrap();
    dev.create_special("full", devfs::DevKind::Full).unwrap();
    dev.create_special("tty", devfs::DevKind::Tty).unwrap();
    dev.create_special("console", devfs::DevKind::Tty).unwrap();
    dev.create_special("urandom", devfs::DevKind::Random).unwrap();
    dev.create_special("random", devfs::DevKind::Random).unwrap();
    root.place_inode("dev", dev as Arc<dyn Inode>).unwrap();

    let etc = tmpfs::TmpfsDir::new_root();
    write_file(etc.as_ref(), "passwd", b"root::0:0:root:/:/bin/sh\n");
    write_file(etc.as_ref(), "group", b"root:x:0:\n");
    write_file(etc.as_ref(), "hostname", b"xiande\n");
    write_file(etc.as_ref(), "hosts", b"127.0.0.1 localhost\n");
    root.place_inode("etc", etc as Arc<dyn Inode>).unwrap();

    for name in ["tmp", "bin", "sys", "root", "usr", "var", "home"] {
        let d = tmpfs::TmpfsDir::new_root();
        root.place_inode(name, d as Arc<dyn Inode>).unwrap();
    }

    ROOT_INODE.call_once(|| root as Arc<dyn Inode>);

    // Mount procfs at /proc with a real dynamic inode tree.
    procfs::mount("/proc").expect("procfs mount");
}

fn write_file(dir: &dyn Inode, name: &str, data: &[u8]) {
    let f = dir.create(name, FileType::Regular).unwrap();
    let _ = f.write_at(0, data);
}

/// Drop a regular file into a directory inode and return its inode so
/// the caller can hardlink it under additional names.
pub fn install_file(parent: &str, name: &str, content: &[u8]) -> Result<Arc<dyn Inode>> {
    let dir = lookup_path(root(), parent)?;
    let f = dir.create(name, FileType::Regular)?;
    f.write_at(0, content)?;
    Ok(f)
}

pub fn link_into(parent: &str, name: &str, inode: Arc<dyn Inode>) -> Result<()> {
    let dir = lookup_path(root(), parent)?;
    if let Some(td) = tmpfs::downcast_dir(&dir) {
        td.place_inode(name, inode)?;
    }
    Ok(())
}

pub fn root() -> Arc<dyn Inode> {
    ROOT_INODE.get().unwrap().clone()
}

/// Resolve an absolute or CWD-relative path. Returns the inode or an error.
/// Follows symlinks (up to 8 nestings to avoid loops).
pub fn lookup_path(cwd: Arc<dyn Inode>, path: &str) -> Result<Arc<dyn Inode>> {
    lookup_path_inner(cwd, path, true, 0)
}

/// Like `lookup_path` but does not follow the final-component symlink.
pub fn lookup_path_nofollow(cwd: Arc<dyn Inode>, path: &str) -> Result<Arc<dyn Inode>> {
    lookup_path_inner(cwd, path, false, 0)
}

fn lookup_path_inner(
    cwd: Arc<dyn Inode>,
    path: &str,
    follow_last: bool,
    depth: usize,
) -> Result<Arc<dyn Inode>> {
    if depth > 8 {
        return Err(-40); // ELOOP
    }
    let mut cur = if path.starts_with('/') { root() } else { cwd.clone() };
    let parts: alloc::vec::Vec<&str> = path
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
    let last_idx = parts.len().wrapping_sub(1);
    for (idx, part) in parts.iter().enumerate() {
        // A component longer than NAME_MAX (255) is ENAMETOOLONG.
        if part.len() > 255 {
            return Err(ENAMETOOLONG);
        }
        if *part == ".." {
            // Single-level VFS doesn't track parents.
            continue;
        }
        // Descending *through* a component requires it to be a directory. If
        // `cur` is a regular file (or other non-dir), the path tries to use it
        // as a directory — that is ENOTDIR, not ENOENT. access04/chmod06/
        // chown04/creat06 build "<file>/sub" paths and require ENOTDIR.
        if cur.kind() != FileType::Directory {
            return Err(ENOTDIR);
        }
        let next = cur.lookup(part)?;
        // Follow symlinks for all but the final component when follow_last==false.
        let is_last = idx == last_idx;
        if next.kind() == FileType::Symlink && (!is_last || follow_last) {
            let target = next.readlink()?;
            // Resolve target relative to the current dir (not next's parent).
            let resolved = lookup_path_inner(cur.clone(), &target, true, depth + 1)?;
            cur = resolved;
        } else {
            cur = next;
        }
    }
    Ok(cur)
}

/// Resolve the parent directory of `path` plus the final component name.
pub fn split_parent(cwd: Arc<dyn Inode>, path: &str) -> Result<(Arc<dyn Inode>, String)> {
    let path = path.trim_end_matches('/');
    let (parent_path, name) = match path.rfind('/') {
        Some(0) => ("/", &path[1..]),
        Some(i) => (&path[..i], &path[i + 1..]),
        None => ("", path),
    };
    let parent = if parent_path.is_empty() {
        cwd
    } else {
        lookup_path(cwd, parent_path)?
    };
    Ok((parent, name.to_string()))
}
