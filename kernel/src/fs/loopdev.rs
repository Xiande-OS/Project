//! Loop block devices (/dev/loop-control + /dev/loopN).
//!
//! LTP's whole device-needing suite (~90 cases: fallocate, fanotify, copy_
//! file_range, mkdir09, the fs tests, …) does, via its tst_device helper:
//!   1. open("/dev/loop-control"), ioctl(LOOP_CTL_GET_FREE)  -> a free N
//!   2. open("/dev/loopN"), ioctl(LOOP_SET_FD, backing_fd)   -> attach
//!   3. mkfs.<fs> /dev/loopN ; mount("/dev/loopN", mntpoint, fs, …)
//! Without loop devices step 1 already fails with "Failed to acquire device"
//! and the case is TBROK before doing anything.
//!
//! We model up to 8 loop devices. A loop device's reads/writes pass through to
//! the attached backing file (a tmpfs file, since LTP's image lives in tmpfs);
//! that makes mkfs write a real filesystem image into the backing file and a
//! subsequent loop-aware mount see it. The actual filesystem mounting is
//! handled in syscall::sys_mount (it overlays a fresh in-memory dir at the
//! mountpoint); here we only provide the block device plumbing.

use alloc::sync::Arc;
use core::any::Any;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::sync::Mutex;

use super::{FileType, Inode, Result};

// errno values as isize for the ioctl() return path (super's are i32, used by
// the Inode read/write Result paths below).
const E_BADF: isize = -9;
const E_INVAL: isize = -22;

pub const NLOOP: usize = 8;

/// ioctl request numbers (uapi/linux/loop.h).
pub const LOOP_SET_FD: u32 = 0x4C00;
pub const LOOP_CLR_FD: u32 = 0x4C01;
pub const LOOP_SET_STATUS: u32 = 0x4C02;
pub const LOOP_GET_STATUS: u32 = 0x4C03;
pub const LOOP_SET_STATUS64: u32 = 0x4C04;
pub const LOOP_GET_STATUS64: u32 = 0x4C05;
pub const LOOP_SET_CAPACITY: u32 = 0x4C07;
pub const LOOP_CTL_GET_FREE: u32 = 0x4C82;
pub const LOOP_CTL_ADD: u32 = 0x4C80;
pub const LOOP_CTL_REMOVE: u32 = 0x4C81;
/// BLKGETSIZE64 — mount/mkfs query the device size.
pub const BLKGETSIZE64: u32 = 0x80081272;
pub const BLKGETSIZE: u32 = 0x1260;
pub const BLKSSZGET: u32 = 0x1268;

struct LoopState {
    /// The backing file (the image the test created and attached). None = free.
    backing: Option<Arc<dyn Inode>>,
}

static LOOPS: [Mutex<LoopState>; NLOOP] = [
    Mutex::new(LoopState { backing: None }),
    Mutex::new(LoopState { backing: None }),
    Mutex::new(LoopState { backing: None }),
    Mutex::new(LoopState { backing: None }),
    Mutex::new(LoopState { backing: None }),
    Mutex::new(LoopState { backing: None }),
    Mutex::new(LoopState { backing: None }),
    Mutex::new(LoopState { backing: None }),
];

/// Whether each /dev/loopN node currently exists (LOOP_CTL_ADD/REMOVE just
/// flip this; the nodes are all created at boot so "exists" is informational).
static PRESENT: [AtomicBool; NLOOP] = [
    AtomicBool::new(true),
    AtomicBool::new(true),
    AtomicBool::new(true),
    AtomicBool::new(true),
    AtomicBool::new(true),
    AtomicBool::new(true),
    AtomicBool::new(true),
    AtomicBool::new(true),
];

/// Find a free loop device index (LOOP_CTL_GET_FREE). Returns the number, or
/// -1 if all are in use.
pub fn get_free() -> i32 {
    for i in 0..NLOOP {
        let g = LOOPS[i].lock();
        if g.backing.is_none() {
            return i as i32;
        }
    }
    -1
}

/// Attach a backing inode to loop `idx` (LOOP_SET_FD). Returns false if idx
/// out of range.
pub fn set_fd(idx: usize, backing: Arc<dyn Inode>) -> bool {
    if idx >= NLOOP {
        return false;
    }
    LOOPS[idx].lock().backing = Some(backing);
    PRESENT[idx].store(true, Ordering::Relaxed);
    true
}

/// Detach loop `idx` (LOOP_CLR_FD).
pub fn clr_fd(idx: usize) -> bool {
    if idx >= NLOOP {
        return false;
    }
    LOOPS[idx].lock().backing = None;
    true
}

/// The attached backing inode of loop `idx`, if any. Used by mount to find the
/// image a loop device carries.
pub fn backing_of(idx: usize) -> Option<Arc<dyn Inode>> {
    if idx >= NLOOP {
        return None;
    }
    LOOPS[idx].lock().backing.clone()
}

/// /dev/loop-control — a char device whose only purpose is the LOOP_CTL_*
/// ioctls. Reads/writes are not meaningful.
pub struct LoopControl;

impl Inode for LoopControl {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn kind(&self) -> FileType {
        FileType::CharDevice
    }
    fn read_at(&self, _o: u64, _b: &mut [u8]) -> Result<usize> {
        Ok(0)
    }
    fn write_at(&self, _o: u64, b: &[u8]) -> Result<usize> {
        Ok(b.len())
    }
}

/// /dev/loopN — a block device backed by whatever file is attached via
/// LOOP_SET_FD. Reads/writes route to the backing inode (offset-addressed);
/// with nothing attached they behave like an empty device.
pub struct LoopDevice {
    pub idx: usize,
}

impl Inode for LoopDevice {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn kind(&self) -> FileType {
        // A real block device so stat() reports S_ISBLK — tst_device's
        // set_dev_loop_path requires it before it'll use /dev/loopN.
        FileType::BlockDevice
    }
    fn size(&self) -> u64 {
        backing_of(self.idx).map(|b| b.size()).unwrap_or(0)
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        match backing_of(self.idx) {
            Some(b) => b.read_at(offset, buf),
            None => Ok(0),
        }
    }
    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<usize> {
        match backing_of(self.idx) {
            Some(b) => b.write_at(offset, buf),
            None => Err(super::EBADF),
        }
    }
}

/// Handle a LOOP_*/BLK* ioctl on a loop or loop-control fd. `loop_idx` is
/// Some(n) for /dev/loopN, None for /dev/loop-control. Returns the syscall
/// result, or None if `req` isn't a loop/block ioctl (caller continues).
pub fn ioctl(
    loop_idx: Option<usize>,
    req: u32,
    arg: usize,
    task: &Arc<crate::task::Task>,
) -> Option<isize> {
    match req {
        LOOP_CTL_GET_FREE => Some(get_free() as isize),
        LOOP_CTL_ADD => {
            // arg = desired loop number; mark present (all already exist).
            if (arg as usize) < NLOOP {
                PRESENT[arg].store(true, Ordering::Relaxed);
                Some(arg as isize)
            } else {
                Some(E_INVAL)
            }
        }
        LOOP_CTL_REMOVE => Some(0),
        LOOP_SET_FD => {
            // arg = a backing fd in the calling process. Attach its inode.
            let Some(idx) = loop_idx else { return Some(E_INVAL) };
            let Some(file) = task.fd_table.lock().get(arg as i32) else {
                return Some(E_BADF);
            };
            set_fd(idx, file.inode.clone());
            Some(0)
        }
        LOOP_CLR_FD => {
            let Some(idx) = loop_idx else { return Some(E_INVAL) };
            clr_fd(idx);
            Some(0)
        }
        // Status get/set: accept (mkfs/losetup probe these). We don't model the
        // full loop_info struct; returning success is enough for the tools.
        LOOP_SET_STATUS | LOOP_SET_STATUS64 | LOOP_SET_CAPACITY => Some(0),
        LOOP_GET_STATUS | LOOP_GET_STATUS64 => Some(0),
        BLKGETSIZE64 => {
            // Write the device size in bytes (u64) to *arg.
            let sz = loop_idx.and_then(backing_of).map(|b| b.size()).unwrap_or(0);
            if task.copy_out_bytes(arg, &sz.to_le_bytes()).is_none() {
                return Some(E_INVAL);
            }
            Some(0)
        }
        BLKGETSIZE => {
            // Size in 512-byte sectors (unsigned long).
            let sz = loop_idx.and_then(backing_of).map(|b| b.size()).unwrap_or(0);
            let sectors = (sz / 512) as usize;
            if task.copy_out_bytes(arg, &sectors.to_le_bytes()).is_none() {
                return Some(E_INVAL);
            }
            Some(0)
        }
        BLKSSZGET => {
            // Logical block (sector) size.
            if task.copy_out_bytes(arg, &512u32.to_le_bytes()).is_none() {
                return Some(E_INVAL);
            }
            Some(0)
        }
        _ => None,
    }
}
