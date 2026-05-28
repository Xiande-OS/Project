//! Anonymous pipes (M5).
//!
//! Each pipe has a fixed-size ring buffer and two `Inode` ends.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::any::Any;
use spin::Mutex;

use super::{FileType, Inode, Result, EBADF, EINVAL};

const PIPE_CAP: usize = 64 * 1024;

struct PipeBuffer {
    buf: VecDeque<u8>,
    closed_read: bool,
    closed_write: bool,
}

pub struct PipeEnd {
    inner: Arc<Mutex<PipeBuffer>>,
    is_writer: bool,
}

impl PipeEnd {
    fn new_pair() -> (Arc<Self>, Arc<Self>) {
        let inner = Arc::new(Mutex::new(PipeBuffer {
            buf: VecDeque::with_capacity(PIPE_CAP),
            closed_read: false,
            closed_write: false,
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
        let mut n = 0;
        while n < buf.len() && pipe.buf.len() < PIPE_CAP {
            pipe.buf.push_back(buf[n]);
            n += 1;
        }
        if n == 0 && !buf.is_empty() {
            return Err(EINVAL); // full
        }
        Ok(n)
    }
}

pub fn make_pipe() -> (Arc<dyn Inode>, Arc<dyn Inode>) {
    let (r, w) = PipeEnd::new_pair();
    (r as Arc<dyn Inode>, w as Arc<dyn Inode>)
}
