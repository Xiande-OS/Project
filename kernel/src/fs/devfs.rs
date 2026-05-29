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
                let mut x: u64 = riscv::register::time::read64()
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
                    #[allow(deprecated)]
                    sbi_rt::legacy::console_putchar(b as usize);
                }
                Ok(buf.len())
            }
        }
    }
}
