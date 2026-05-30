//! Anonymous pipes (M5).
//!
//! Each pipe has a fixed-size ring buffer and two `Inode` ends.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::any::Any;
use spin::Mutex;

use super::{FileType, Inode, Result, EBADF, EINVAL};

const EPIPE: i32 = -32;

pub const PIPE_CAP: usize = 64 * 1024;

struct PipeBuffer {
    buf: VecDeque<u8>,
    closed_read: bool,
    closed_write: bool,
    /// pids of tasks parked in sys_read on the read end, waiting for
    /// data to arrive (or the writer to close). Woken by the writer's
    /// write_at and by Drop on the writer end.
    read_waiters: alloc::vec::Vec<i32>,
    /// Capacity (in bytes) reported by fcntl(F_GETPIPE_SZ) and the high-water
    /// mark a writer may buffer. fcntl(F_SETPIPE_SZ) adjusts it.
    capacity: usize,
    /// Async-I/O target for fcntl(F_SETFL,O_ASYNC)+F_SETOWN+F_SETSIG, mirrored
    /// here from the read end's `File` so a writer can signal data readiness.
    /// `owner`: pid (>0) / negated pgid (<0); `signal`: 0 = default SIGIO.
    async_owner: i32,
    async_signal: i32,
    async_armed: bool,
}

pub struct PipeEnd {
    inner: Arc<Mutex<PipeBuffer>>,
    is_writer: bool,
}

impl PipeEnd {
    pub fn is_writer(&self) -> bool { self.is_writer }
    pub fn writer_alive(&self) -> bool {
        let p = self.inner.lock();
        !p.closed_write
    }
    pub fn buffered(&self) -> usize {
        self.inner.lock().buf.len()
    }
    /// Current pipe capacity in bytes (fcntl F_GETPIPE_SZ).
    pub fn capacity(&self) -> usize {
        self.inner.lock().capacity
    }
    /// Set the pipe capacity in bytes (fcntl F_SETPIPE_SZ, already validated).
    pub fn set_capacity(&self, cap: usize) {
        self.inner.lock().capacity = cap;
    }
    /// Mirror the read end's async-I/O settings into the shared buffer so the
    /// peer writer can raise the configured signal when data arrives.
    pub fn set_async(&self, owner: i32, signal: i32, armed: bool) {
        let mut p = self.inner.lock();
        p.async_owner = owner;
        p.async_signal = signal;
        p.async_armed = armed;
    }
    pub fn add_read_waiter(&self, pid: i32) {
        let mut p = self.inner.lock();
        if !p.read_waiters.contains(&pid) {
            p.read_waiters.push(pid);
        }
    }
}

/// Deliver the async-I/O signal to a fcntl(F_SETOWN) target: a pid when
/// `owner > 0`, or every member of process group `-owner` when `owner < 0`.
/// `signal == 0` selects the POSIX default, SIGIO.
fn deliver_io_signal(owner: i32, signal: i32) {
    let signo = if signal == 0 {
        crate::signal::SIGIO
    } else {
        signal as u32
    };
    if owner > 0 {
        if let Some(t) = crate::task::task_by_pid(owner) {
            crate::signal::raise_signal(&t, signo);
        }
    } else if owner < 0 {
        let pgid = -owner;
        for pid in crate::task::all_pids() {
            if let Some(t) = crate::task::task_by_pid(pid) {
                if t.pgid.load(core::sync::atomic::Ordering::Relaxed) == pgid {
                    crate::signal::raise_signal(&t, signo);
                }
            }
        }
    }
}

fn wake_pipe_readers(waiters: &[i32]) {
    for &pid in waiters {
        if let Some(t) = crate::task::task_by_pid(pid) {
            let mut s = t.state.lock();
            if *s == crate::task::TaskState::Waiting {
                *s = crate::task::TaskState::Ready;
            }
        }
    }
}

impl PipeEnd {
    fn new_pair() -> (Arc<Self>, Arc<Self>) {
        let inner = Arc::new(Mutex::new(PipeBuffer {
            buf: VecDeque::with_capacity(PIPE_CAP),
            closed_read: false,
            closed_write: false,
            read_waiters: alloc::vec::Vec::new(),
            capacity: PIPE_CAP,
            async_owner: 0,
            async_signal: 0,
            async_armed: false,
        }));
        let r = Arc::new(Self {
            inner: inner.clone(),
            is_writer: false,
        });
        let w = Arc::new(Self {
            inner,
            is_writer: true,
        });
        (r, w)
    }
}

impl Inode for PipeEnd {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn kind(&self) -> FileType {
        FileType::Pipe
    }
    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> Result<usize> {
        if self.is_writer {
            return Err(EBADF);
        }
        let mut pipe = self.inner.lock();
        let mut n = 0;
        while n < buf.len() {
            if let Some(b) = pipe.buf.pop_front() {
                buf[n] = b;
                n += 1;
            } else {
                break;
            }
        }
        // Without blocking, return whatever we have (including 0 if writer
        // hasn't closed — busybox/git handle EAGAIN-like polling, but
        // for M5 we just return Ok(0) which means EOF if writer is gone).
        Ok(n)
    }
    fn write_at(&self, _offset: u64, buf: &[u8]) -> Result<usize> {
        if !self.is_writer {
            return Err(EBADF);
        }
        let mut pipe = self.inner.lock();
        // Read end closed: deliver SIGPIPE to the writer and return EPIPE.
        if pipe.closed_read {
            drop(pipe);
            let task = crate::task::current_task();
            let _ = crate::signal::raise_signal(&task, crate::signal::SIGPIPE);
            return Err(EPIPE);
        }
        let cap = pipe.capacity;
        let mut n = 0;
        while n < buf.len() && pipe.buf.len() < cap {
            pipe.buf.push_back(buf[n]);
            n += 1;
        }
        if n == 0 && !buf.is_empty() {
            return Err(EINVAL); // full
        }
        // Wake any reader that parked on an empty pipe, then fire the async-I/O
        // signal if the read end armed one (fcntl O_ASYNC + F_SETOWN/F_SETSIG).
        let waiters = core::mem::take(&mut pipe.read_waiters);
        let async_target = if pipe.async_armed && pipe.async_owner != 0 {
            Some((pipe.async_owner, pipe.async_signal))
        } else {
            None
        };
        drop(pipe);
        wake_pipe_readers(&waiters);
        if let Some((owner, signal)) = async_target {
            deliver_io_signal(owner, signal);
        }
        Ok(n)
    }
}

impl Drop for PipeEnd {
    fn drop(&mut self) {
        let mut pipe = self.inner.lock();
        if self.is_writer {
            pipe.closed_write = true;
            // Wake parked readers so they observe EOF instead of
            // blocking forever.
            let waiters = core::mem::take(&mut pipe.read_waiters);
            drop(pipe);
            wake_pipe_readers(&waiters);
        } else {
            pipe.closed_read = true;
        }
    }
}

pub fn make_pipe() -> (Arc<dyn Inode>, Arc<dyn Inode>) {
    let (r, w) = PipeEnd::new_pair();
    (r as Arc<dyn Inode>, w as Arc<dyn Inode>)
}
