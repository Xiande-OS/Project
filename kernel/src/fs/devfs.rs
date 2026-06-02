//! /dev nodes.

use core::any::Any;

use super::{FileType, Inode, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DevKind {
    Null,
    Zero,
    Full,
    Tty,
    Random,
}

impl DevKind {
    /// Linux device number (major<<8 | minor) reported via st_rdev. glibc's
    /// daemon() verifies /dev/null is `makedev(1,3)` (== 259) — not just a
    /// char device — so a zero rdev makes daemon() fail with ENODEV and
    /// `iperf3 -s -D` never starts. Use the canonical Linux numbers.
    pub fn rdev(self) -> u64 {
        match self {
            DevKind::Null => (1 << 8) | 3,   // /dev/null  1:3  = 259
            DevKind::Zero => (1 << 8) | 5,   // /dev/zero  1:5
            DevKind::Full => (1 << 8) | 7,   // /dev/full  1:7
            DevKind::Random => (1 << 8) | 8, // /dev/random 1:8 (urandom is 1:9; close enough)
            DevKind::Tty => (5 << 8) | 0,    // /dev/tty   5:0
        }
    }
}

pub struct DevNode {
    pub kind: DevKind,
}

impl Inode for DevNode {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn kind(&self) -> FileType {
        FileType::CharDevice
    }
    fn size(&self) -> u64 {
        0
    }
    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> Result<usize> {
        match self.kind {
            DevKind::Null => Ok(0),
            DevKind::Zero => {
                for b in buf.iter_mut() {
                    *b = 0;
                }
                Ok(buf.len())
            }
            DevKind::Full => {
                for b in buf.iter_mut() {
                    *b = 0;
                }
                Ok(buf.len())
            }
            DevKind::Tty => Ok(0),
            DevKind::Random => {
                let mut x: u64 = crate::arch::now_ticks()
                    .wrapping_mul(2862933555777941757);
                for b in buf.iter_mut() {
                    x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    *b = (x >> 33) as u8;
                }
                Ok(buf.len())
            }
        }
    }
    fn write_at(&self, _offset: u64, buf: &[u8]) -> Result<usize> {
        match self.kind {
            DevKind::Null | DevKind::Zero | DevKind::Random => Ok(buf.len()),
            DevKind::Full => Err(super::ENOSPC),
            DevKind::Tty => {
                for &b in buf {
                    crate::arch::console_put(b);
                }
                Ok(buf.len())
            }
        }
    }
}

/// A raw block-device node (e.g. /dev/sdb) over a virtio-blk device. Byte
/// reads/writes are translated to 512-byte sector I/O, so `dd`, `mkfs`, and
/// LTP's tst_device (which requires an S_ISBLK device) all work against it.
pub struct BlockDevNode {
    pub dev: alloc::sync::Arc<crate::drivers::virtio_blk::BlockDevice>,
    pub rdev: u64,
}

const SEC: usize = 512;

impl Inode for BlockDevNode {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn kind(&self) -> FileType {
        FileType::BlockDevice
    }
    fn size(&self) -> u64 {
        self.dev.capacity() * SEC as u64
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let total = self.dev.capacity() * SEC as u64;
        if offset >= total {
            return Ok(0);
        }
        let end = core::cmp::min(offset + buf.len() as u64, total);
        let mut done = 0usize;
        let mut pos = offset;
        let mut sec = [0u8; SEC];
        while pos < end {
            let s = (pos / SEC as u64) as usize;
            let within = (pos % SEC as u64) as usize;
            let n = core::cmp::min(SEC - within, (end - pos) as usize);
            self.dev.read_block(s, &mut sec).map_err(|_| super::EINVAL)?;
            buf[done..done + n].copy_from_slice(&sec[within..within + n]);
            done += n;
            pos += n as u64;
        }
        Ok(done)
    }
    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<usize> {
        let total = self.dev.capacity() * SEC as u64;
        if offset >= total {
            return Err(super::ENOSPC);
        }
        let end = core::cmp::min(offset + buf.len() as u64, total);
        let mut done = 0usize;
        let mut pos = offset;
        let mut sec = [0u8; SEC];
        while pos < end {
            let s = (pos / SEC as u64) as usize;
            let within = (pos % SEC as u64) as usize;
            let n = core::cmp::min(SEC - within, (end - pos) as usize);
            if within != 0 || n != SEC {
                self.dev.read_block(s, &mut sec).map_err(|_| super::EINVAL)?;
            }
            sec[within..within + n].copy_from_slice(&buf[done..done + n]);
            self.dev.write_block(s, &sec).map_err(|_| super::EINVAL)?;
            done += n;
            pos += n as u64;
        }
        Ok(done)
    }
}
