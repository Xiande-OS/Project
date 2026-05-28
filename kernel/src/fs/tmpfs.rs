//! In-memory tmpfs.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

use core::any::Any;

use super::{devfs, FileType, Inode, Result, EEXIST, EINVAL, ENOENT};

pub struct TmpfsFile {
    data: Mutex<Vec<u8>>,
    pub meta: Mutex<Meta>,
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
        if off + buf.len() > data.len() {
            data.resize(off + buf.len(), 0);
        }
        data[off..off + buf.len()].copy_from_slice(buf);
        Ok(buf.len())
    }
    fn truncate(&self, len: u64) -> Result<()> {
        self.data.lock().resize(len as usize, 0);
        Ok(())
    }
}

pub struct TmpfsDir {
    entries: Mutex<BTreeMap<String, Arc<dyn Inode>>>,
    pub meta: Mutex<Meta>,
}

impl TmpfsDir {
    pub fn new_root() -> Arc<Self> {
        Arc::new(Self {
            entries: Mutex::new(BTreeMap::new()),
            meta: Mutex::new(Meta { mode: 0o755, ..Meta::default() }),
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
        let link: Arc<dyn Inode> = Arc::new(super::Symlink {
            target: target.to_string(),
        });
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
}
