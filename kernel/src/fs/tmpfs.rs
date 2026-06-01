//! In-memory tmpfs.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use crate::sync::Mutex;

use core::any::Any;
use core::sync::atomic::{AtomicUsize, Ordering};

use super::{
    devfs, xattr_store_get, xattr_store_list, xattr_store_remove, xattr_store_set, FileType,
    Inode, Result, XattrStore, EEXIST, EINVAL, ENOENT, ENOSPC,
};

/// Global ceiling on the kernel heap consumed by tmpfs file data, summed
/// across every in-memory mount (root /, /tmp, /dev/shm). tmpfs files live in
/// the 256 MiB kernel heap as `Vec<u8>`; that same heap also backs every task
/// struct and kernel stack. Without a cap, one LTP test that writes a
/// multi-hundred-MB temp file (mmap2/mmap3/the growfiles family) fills the
/// heap, and — because a SIGKILLed test never runs its own cleanup — those
/// files leak. Once the heap is full, every `fork()` (task-struct alloc) fails
/// with ENOMEM and the run drowns in `sh: busybox: Out of memory`, never
/// recovering. A real Linux tmpfs defaults to half of RAM and enforces it,
/// returning ENOSPC so the *rest* of memory stays usable for processes. Mirror
/// that: cap tmpfs at half the heap so a runaway file gets ENOSPC (a localized,
/// recoverable error) instead of wedging the whole kernel. The contest runner
/// also wipes /tmp between cases, so this is only ever the per-case ceiling.
const TMPFS_CAP: usize = 128 * 1024 * 1024;
static TMPFS_USED: AtomicUsize = AtomicUsize::new(0);

/// Reserve `bytes` of the global tmpfs budget. Returns false (caller surfaces
/// ENOSPC) if that would exceed the cap.
fn tmpfs_charge(bytes: usize) -> bool {
    loop {
        let cur = TMPFS_USED.load(Ordering::Relaxed);
        let next = cur.saturating_add(bytes);
        if next > TMPFS_CAP {
            return false;
        }
        if TMPFS_USED
            .compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return true;
        }
    }
}

/// Return `bytes` to the global tmpfs budget (file shrunk or freed).
fn tmpfs_uncharge(bytes: usize) {
    if bytes == 0 {
        return;
    }
    let mut cur = TMPFS_USED.load(Ordering::Relaxed);
    loop {
        let next = cur.saturating_sub(bytes);
        match TMPFS_USED.compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(actual) => cur = actual,
        }
    }
}

pub struct TmpfsFile {
    data: Mutex<Vec<u8>>,
    /// Logical file length. May exceed `data.len()` for a sparse file: a
    /// `truncate`/`fallocate` that grows the file only bumps this (no heap is
    /// charged) and the unbacked tail reads as zeros. LTP's tst_device
    /// preallocates a 300 MiB backing image this way, then writes only a small
    /// filesystem into it — without sparseness that 300 MiB blew past the
    /// tmpfs cap (ENOSPC → "Failed to acquire device" → ~93 cases TBROK).
    logical_len: core::sync::atomic::AtomicU64,
    pub meta: Mutex<Meta>,
    xattrs: XattrStore,
    /// F_SEAL_* bits set via fcntl(F_ADD_SEALS) — used by memfd_create. Stored
    /// so F_GET_SEALS reads them back (memfd_create01 adds seals then checks).
    seals: core::sync::atomic::AtomicU32,
}

impl TmpfsFile {
    /// Current memfd seal bitmask (fcntl F_GET_SEALS).
    pub fn seals(&self) -> u32 {
        self.seals.load(Ordering::Relaxed)
    }
    /// Add seal bits (fcntl F_ADD_SEALS). Returns false if F_SEAL_SEAL is
    /// already set (further sealing forbidden) — what memfd_create rejects.
    pub fn add_seals(&self, add: u32) -> bool {
        const F_SEAL_SEAL: u32 = 0x0001;
        let cur = self.seals.load(Ordering::Relaxed);
        if cur & F_SEAL_SEAL != 0 {
            return false;
        }
        self.seals.fetch_or(add, Ordering::Relaxed);
        true
    }
}

impl Drop for TmpfsFile {
    fn drop(&mut self) {
        // Credit back the heap this file's data was holding so a deleted (or
        // GC'd) tmpfs file frees its slice of the global budget.
        let cap = self.data.get_mut().capacity();
        tmpfs_uncharge(cap);
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Meta {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub atime_sec: i64,
    pub atime_nsec: i64,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
}

impl Default for Meta {
    fn default() -> Self {
        Self {
            mode: 0o644,
            uid: 0,
            gid: 0,
            atime_sec: 0,
            atime_nsec: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
            ctime_sec: 0,
            ctime_nsec: 0,
        }
    }
}

impl TmpfsFile {
    pub fn new() -> Self {
        Self {
            data: Mutex::new(Vec::new()),
            logical_len: core::sync::atomic::AtomicU64::new(0),
            meta: Mutex::new(Meta::default()),
            xattrs: Mutex::new(BTreeMap::new()),
            seals: core::sync::atomic::AtomicU32::new(0),
        }
    }
}

impl Inode for TmpfsFile {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn kind(&self) -> FileType {
        FileType::Regular
    }
    fn size(&self) -> u64 {
        // Logical length wins for a sparse file (grown by truncate/fallocate
        // past the materialised bytes).
        let backed = self.data.lock().len() as u64;
        core::cmp::max(backed, self.logical_len.load(Ordering::Relaxed))
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let data = self.data.lock();
        let logical = core::cmp::max(
            data.len() as u64,
            self.logical_len.load(Ordering::Relaxed),
        ) as usize;
        let off = offset as usize;
        if off >= logical {
            return Ok(0);
        }
        // Read may span materialised bytes then the sparse (zero) tail.
        let n = core::cmp::min(buf.len(), logical - off);
        for (i, b) in buf[..n].iter_mut().enumerate() {
            let p = off + i;
            *b = if p < data.len() { data[p] } else { 0 };
        }
        Ok(n)
    }
    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<usize> {
        let mut data = self.data.lock();
        let off = offset as usize;
        let end = off.checked_add(buf.len()).ok_or(EINVAL)?;
        if end > data.len() {
            // Grow the heap-backed file FALLIBLY. A tmpfs file lives in the
            // kernel heap; the Vec's amortized doubling means a 64 MiB file
            // tries to grow to a 128 MiB block, and an infallible resize trips
            // the alloc-error handler and panics the whole kernel when that
            // block isn't available (LTP fills a multi-hundred-MB temp file).
            // Reserve fallibly and surface ENOSPC instead — the in-memory fs
            // is simply full.
            if data.capacity() < end {
                let need = end - data.len();
                // Refuse before allocating if the global tmpfs budget is spent,
                // so one test's runaway file can't eat the heap that fork()/exec
                // need (the `sh: busybox: Out of memory` storm). Charge the real
                // heap growth (capacity delta), not just the logical length, so
                // amortized doubling can't slip past the cap.
                if !tmpfs_charge(need) {
                    return Err(ENOSPC);
                }
                let before = data.capacity();
                if let Err(e) = data.try_reserve(need) {
                    tmpfs_uncharge(need);
                    let _ = e;
                    return Err(ENOSPC);
                }
                // Reconcile the estimate (`need`) against the allocator's actual
                // capacity growth so the budget tracks true heap use.
                let grew = data.capacity() - before;
                if grew >= need {
                    tmpfs_charge(grew - need);
                } else {
                    tmpfs_uncharge(need - grew);
                }
            }
            data.resize(end, 0);
        }
        data[off..end].copy_from_slice(buf);
        // Keep the logical length at least as large as the written extent (a
        // write into the middle of a sparse file mustn't shrink it).
        let cur = self.logical_len.load(Ordering::Relaxed);
        if (end as u64) > cur {
            self.logical_len.store(end as u64, Ordering::Relaxed);
        }
        Ok(buf.len())
    }
    fn truncate(&self, len: u64) -> Result<()> {
        let mut data = self.data.lock();
        let new_len = len as usize;
        if new_len > data.len() {
            // Grow SPARSELY: record the logical length but allocate nothing.
            // The unbacked tail reads as zeros (see read_at) and is materialised
            // only where a later write lands. This is what lets LTP preallocate
            // a 300 MiB device image (fallocate/ftruncate) without consuming
            // 300 MiB of the kernel heap — it then writes only a small fs into
            // it. Charging the full size here was the "Failed to acquire
            // device" ENOSPC that broke ~93 fs/mount cases.
            self.logical_len.store(new_len as u64, Ordering::Relaxed);
        } else {
            // Shrinking (new_len <= data.len()): drop the materialised bytes
            // past new_len and hand the freed heap back to the budget. resize()
            // alone keeps the old capacity, so a test that truncates a huge temp
            // file to 0 (a common teardown) would otherwise keep pinning it.
            let before = data.capacity();
            data.truncate(new_len);
            data.shrink_to_fit();
            tmpfs_uncharge(before.saturating_sub(data.capacity()));
            self.logical_len.store(new_len as u64, Ordering::Relaxed);
        }
        Ok(())
    }
    fn xattr_get(&self, name: &str) -> Result<Vec<u8>> {
        xattr_store_get(&self.xattrs, name)
    }
    fn xattr_set(&self, name: &str, value: &[u8], flags: i32) -> Result<()> {
        xattr_store_set(&self.xattrs, name, value, flags)
    }
    fn xattr_list(&self) -> Vec<String> {
        xattr_store_list(&self.xattrs)
    }
    fn xattr_remove(&self, name: &str) -> Result<()> {
        xattr_store_remove(&self.xattrs, name)
    }
}

pub struct TmpfsDir {
    entries: Mutex<BTreeMap<String, Arc<dyn Inode>>>,
    pub meta: Mutex<Meta>,
    xattrs: XattrStore,
}

impl TmpfsDir {
    pub fn new_root() -> Arc<Self> {
        Arc::new(Self {
            entries: Mutex::new(BTreeMap::new()),
            meta: Mutex::new(Meta { mode: 0o755, ..Meta::default() }),
            xattrs: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn create_special(self: &Arc<Self>, name: &str, kind: devfs::DevKind) -> Result<()> {
        let mut entries = self.entries.lock();
        if entries.contains_key(name) {
            return Err(EEXIST);
        }
        let dev: Arc<dyn Inode> = Arc::new(devfs::DevNode { kind });
        entries.insert(name.to_string(), dev);
        Ok(())
    }

    pub fn place_inode(&self, name: &str, inode: Arc<dyn Inode>) -> Result<()> {
        let mut entries = self.entries.lock();
        if entries.contains_key(name) {
            entries.remove(name);
        }
        entries.insert(name.to_string(), inode);
        Ok(())
    }
}

/// Downcast `Arc<dyn Inode>` to `Arc<TmpfsDir>` if applicable.
pub fn downcast_dir(inode: &Arc<dyn Inode>) -> Option<Arc<TmpfsDir>> {
    let any: &dyn Any = inode.as_any();
    if any.is::<TmpfsDir>() {
        // SAFETY: we just type-checked.
        let raw = Arc::into_raw(inode.clone());
        unsafe {
            let typed = Arc::from_raw(raw as *const TmpfsDir);
            Some(typed)
        }
    } else {
        None
    }
}

impl Inode for TmpfsDir {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn kind(&self) -> FileType {
        FileType::Directory
    }
    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>> {
        self.entries
            .lock()
            .get(name)
            .cloned()
            .ok_or(ENOENT)
    }
    fn create(&self, name: &str, kind: FileType) -> Result<Arc<dyn Inode>> {
        let mut entries = self.entries.lock();
        if entries.contains_key(name) {
            return Err(EEXIST);
        }
        let node: Arc<dyn Inode> = match kind {
            FileType::Regular => Arc::new(TmpfsFile::new()),
            FileType::Directory => Arc::new(TmpfsDir {
                entries: Mutex::new(BTreeMap::new()),
                meta: Mutex::new(Meta { mode: 0o755, ..Meta::default() }),
                xattrs: Mutex::new(BTreeMap::new()),
            }),
            _ => return Err(EINVAL),
        };
        entries.insert(name.to_string(), node.clone());
        Ok(node)
    }
    fn symlink(&self, name: &str, target: &str) -> Result<()> {
        let mut entries = self.entries.lock();
        if entries.contains_key(name) {
            return Err(EEXIST);
        }
        let link: Arc<dyn Inode> = Arc::new(super::Symlink::new(target.to_string()));
        entries.insert(name.to_string(), link);
        Ok(())
    }
    fn unlink(&self, name: &str) -> Result<()> {
        let mut entries = self.entries.lock();
        if entries.remove(name).is_some() {
            Ok(())
        } else {
            Err(ENOENT)
        }
    }
    fn list(&self) -> Result<Vec<(String, FileType)>> {
        Ok(self
            .entries
            .lock()
            .iter()
            .map(|(k, v)| (k.clone(), v.kind()))
            .collect())
    }
    fn xattr_get(&self, name: &str) -> Result<Vec<u8>> {
        xattr_store_get(&self.xattrs, name)
    }
    fn xattr_set(&self, name: &str, value: &[u8], flags: i32) -> Result<()> {
        xattr_store_set(&self.xattrs, name, value, flags)
    }
    fn xattr_list(&self) -> Vec<String> {
        xattr_store_list(&self.xattrs)
    }
    fn xattr_remove(&self, name: &str) -> Result<()> {
        xattr_store_remove(&self.xattrs, name)
    }
}
