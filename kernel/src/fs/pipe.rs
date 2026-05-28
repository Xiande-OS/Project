//! Anonymous pipes (M5).
//!
//! Each pipe has a fixed-size ring buffer and two `Inode` ends.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::any::Any;
use spin::Mutex;

use super::{FileType, Inode, Result, EBADF, EINVAL};

const EPIPE: i32 = -32;

const PIPE_CAP: usize = 64 * 1024;

struct PipeBuffer {
    buf: VecDeque<u8>,
    closed_read: bool,
    closed_write: bool,
    /// pids of tasks parked in sys_read on the read end, waiting for
    /// data to arrive (or the writer to close). Woken by the writer's
    /// write_at and by Drop on the writer end.
    read_waiters: alloc::vec::Vec<i32>,
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
    pub fn add_read_waiter(&self, pid: i32) {
        let mut p = self.inner.lock();
        if !p.read_waiters.contains(&pid) {
            p.read_waiters.push(pid);
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
        let mut n = 0;
        while n < buf.len() && pipe.buf.len() < PIPE_CAP {
            pipe.buf.push_back(buf[n]);
            n += 1;
        }
        if n == 0 && !buf.is_empty() {
            return Err(EINVAL); // full
        }
        // Wake any reader that parked on an empty pipe.
        let waiters = core::mem::take(&mut pipe.read_waiters);
        drop(pipe);
        wake_pipe_readers(&waiters);
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
