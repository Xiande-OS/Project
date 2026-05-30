//! In-memory tmpfs.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

use core::any::Any;

use super::{
    devfs, xattr_store_get, xattr_store_list, xattr_store_remove, xattr_store_set, FileType,
    Inode, Result, XattrStore, EEXIST, EINVAL, ENOENT, ENOSPC,
};

pub struct TmpfsFile {
    data: Mutex<Vec<u8>>,
    pub meta: Mutex<Meta>,
    xattrs: XattrStore,
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
            meta: Mutex::new(Meta::default()),
            xattrs: Mutex::new(BTreeMap::new()),
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
        self.data.lock().len() as u64
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let data = self.data.lock();
        let off = offset as usize;
        if off >= data.len() {
            return Ok(0);
        }
        let n = core::cmp::min(buf.len(), data.len() - off);
        buf[..n].copy_from_slice(&data[off..off + n]);
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
            let need = end - data.len();
            data.try_reserve(need).map_err(|_| ENOSPC)?;
            data.resize(end, 0);
        }
        data[off..end].copy_from_slice(buf);
        Ok(buf.len())
    }
    fn truncate(&self, len: u64) -> Result<()> {
        let mut data = self.data.lock();
        let new_len = len as usize;
        if new_len > data.len() {
            let need = new_len - data.len();
            data.try_reserve(need).map_err(|_| ENOSPC)?;
        }
        data.resize(new_len, 0);
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
