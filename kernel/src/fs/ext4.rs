//! Read-only ext2/ext3/ext4 driver.
//!
//! Targets the 2026 OS-Kernel contest's testsuite disk: the evaluator
//! attaches an EXT4 image at `virtio-mmio-bus.0`, and we need to walk
//! its root, locate each `xxxx_testcode.sh`, and feed it to the shell.
//!
//! Supported on-disk features:
//!  - blocks 1KiB / 2KiB / 4KiB (s_log_block_size 0/1/2)
//!  - 64-bit group descriptors (s_desc_size >= 64 + INCOMPAT_64BIT)
//!  - inline extents (i_block holds the extent header), depth-1
//!    extent indices (one level of indirection through a leaf block)
//!  - linear dirs (`ext4_dir_entry_2`); HTREE dirs degrade to linear
//!    walk since DX_DIR just hides directory blocks behind a hash
//!    index — the underlying blocks are still real dir entries.
//!
//! Out of scope on purpose: writes, journal replay, encryption,
//! verity, inline_data, bigalloc, ea_inode.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use crate::sync::Mutex;

use super::tmpfs::{TmpfsDir, TmpfsFile};
use super::{FileType, Inode, Result, EEXIST, EINVAL, ENOENT};
use crate::drivers::virtio_blk::BlockDevice;

const SECTOR_SIZE: usize = 512;
const EXT4_SUPER_MAGIC: u16 = 0xEF53;
const EXT4_EXTENT_MAGIC: u16 = 0xF30A;
const ROOT_INO: u32 = 2;

const INCOMPAT_64BIT: u32 = 0x80;

const S_IFMT: u16 = 0xF000;
const S_IFREG: u16 = 0x8000;
const S_IFDIR: u16 = 0x4000;
const S_IFLNK: u16 = 0xA000;

#[derive(Clone, Copy, Debug)]
struct SuperBlock {
    inodes_per_group: u32,
    blocks_per_group: u32,
    block_size: u32,
    inode_size: u16,
    desc_size: u16,
    features_incompat: u32,
    total_blocks: u64,
}

#[derive(Clone, Copy, Debug)]
struct GroupDesc {
    inode_table_block: u64,
}

#[derive(Clone, Debug)]
struct Inode4 {
    mode: u16,
    size: u64,
    i_block: [u8; 60],
    flags: u32,
}

struct Fs {
    blk: Arc<BlockDevice>,
    sb: SuperBlock,
    group_descs: Vec<GroupDesc>,
}

impl Fs {
    fn parse(blk: Arc<BlockDevice>) -> core::result::Result<Self, &'static str> {
        let mut sb_bytes = vec![0u8; 1024];
        let mut tmp = vec![0u8; SECTOR_SIZE];
        blk.read_block(2, &mut tmp).map_err(|_| "read sb s2")?;
        sb_bytes[..SECTOR_SIZE].copy_from_slice(&tmp);
        blk.read_block(3, &mut tmp).map_err(|_| "read sb s3")?;
        sb_bytes[SECTOR_SIZE..].copy_from_slice(&tmp);
        let magic = u16::from_le_bytes([sb_bytes[56], sb_bytes[57]]);
        if magic != EXT4_SUPER_MAGIC {
            return Err("bad ext4 magic");
        }
        let s_log_block_size = u32_at(&sb_bytes, 24);
        let block_size = 1024u32 << s_log_block_size;
        let inodes_per_group = u32_at(&sb_bytes, 40);
        let blocks_per_group = u32_at(&sb_bytes, 32);
        let inode_size = u16::from_le_bytes([sb_bytes[88], sb_bytes[89]]);
        let inode_size = if inode_size == 0 { 128 } else { inode_size };
        let desc_size = u16::from_le_bytes([sb_bytes[0xfe], sb_bytes[0xff]]);
        let desc_size = if desc_size == 0 { 32 } else { desc_size };
        let features_incompat = u32_at(&sb_bytes, 96);
        let blocks_lo = u32_at(&sb_bytes, 4) as u64;
        let blocks_hi = u32_at(&sb_bytes, 0x150) as u64;
        let total_blocks = (blocks_hi << 32) | blocks_lo;

        let sb = SuperBlock {
            inodes_per_group,
            blocks_per_group,
            block_size,
            inode_size,
            desc_size,
            features_incompat,
            total_blocks,
        };

        // Group descriptors live in the block right after the superblock.
        // With 1KiB blocks the SB occupies block 1 and GDT starts at 2;
        // with 4KiB blocks SB is inside block 0 and GDT starts at block 1.
        let gdt_start_block = if block_size == 1024 { 2 } else { 1 };
        let n_groups = ((sb.total_blocks + sb.blocks_per_group as u64 - 1)
            / sb.blocks_per_group as u64) as usize;
        let bytes_needed = n_groups * sb.desc_size as usize;
        let mut gdt_buf = vec![0u8; ((bytes_needed + block_size as usize - 1) / block_size as usize) * block_size as usize];
        Self::read_blocks_raw(&blk, &sb, gdt_start_block, &mut gdt_buf)?;
        let mut group_descs = Vec::with_capacity(n_groups);
        for i in 0..n_groups {
            let off = i * sb.desc_size as usize;
            let inode_lo = u32_at(&gdt_buf, off + 8) as u64;
            let inode_hi = if sb.desc_size >= 64
                && (sb.features_incompat & INCOMPAT_64BIT) != 0
            {
                u32_at(&gdt_buf, off + 0x28) as u64
            } else {
                0
            };
            group_descs.push(GroupDesc {
                inode_table_block: (inode_hi << 32) | inode_lo,
            });
        }

        Ok(Self { blk, sb, group_descs })
    }

    fn read_blocks_raw(
        blk: &BlockDevice,
        sb: &SuperBlock,
        block_no: u64,
        out: &mut [u8],
    ) -> core::result::Result<(), &'static str> {
        let bs = sb.block_size as usize;
        if out.len() % bs != 0 {
            return Err("read_blocks_raw: length not block-aligned");
        }
        let count = out.len() / bs;
        let sectors_per_block = bs / SECTOR_SIZE;
        let mut buf = vec![0u8; SECTOR_SIZE];
        for i in 0..count {
            let blk_no = block_no + i as u64;
            let sec_base = blk_no * sectors_per_block as u64;
            for s in 0..sectors_per_block {
                blk.read_block((sec_base + s as u64) as usize, &mut buf)
                    .map_err(|_| "blk read")?;
                let dst_off = i * bs + s * SECTOR_SIZE;
                out[dst_off..dst_off + SECTOR_SIZE].copy_from_slice(&buf);
            }
        }
        Ok(())
    }

    fn read_block(&self, block_no: u64) -> core::result::Result<Vec<u8>, &'static str> {
        let mut out = vec![0u8; self.sb.block_size as usize];
        Self::read_blocks_raw(&self.blk, &self.sb, block_no, &mut out)?;
        Ok(out)
    }

    fn read_inode(&self, ino: u32) -> core::result::Result<Inode4, &'static str> {
        if ino == 0 {
            return Err("inode 0");
        }
        let group = (ino - 1) / self.sb.inodes_per_group;
        let idx = (ino - 1) % self.sb.inodes_per_group;
        let gd = self.group_descs.get(group as usize).ok_or("group oob")?;
        let isz = self.sb.inode_size as u32;
        let byte_off_in_table = idx as u64 * isz as u64;
        let block_in_table = byte_off_in_table / self.sb.block_size as u64;
        let off_in_block = (byte_off_in_table % self.sb.block_size as u64) as usize;
        let block = self.read_block(gd.inode_table_block + block_in_table)?;
        let inode_bytes = &block[off_in_block..off_in_block + isz as usize];
        let mode = u16::from_le_bytes([inode_bytes[0], inode_bytes[1]]);
        let size_lo = u32_at(inode_bytes, 4) as u64;
        let size_hi = u32_at(inode_bytes, 0x6c) as u64;
        let size = (size_hi << 32) | size_lo;
        let flags = u32_at(inode_bytes, 32);
        let mut i_block = [0u8; 60];
        i_block.copy_from_slice(&inode_bytes[40..100]);
        Ok(Inode4 { mode, size, i_block, flags })
    }

    /// Walk the extent tree rooted in `i_block` and produce a Vec of
    /// `(file_block_start, phys_block_start, len)` tuples sorted by
    /// file_block_start.
    fn extent_map(&self, ino: &Inode4) -> core::result::Result<Vec<(u32, u64, u32)>, &'static str> {
        let mut out = Vec::new();
        self.walk_extent(&ino.i_block, &mut out)?;
        out.sort_by_key(|e| e.0);
        Ok(out)
    }

    fn walk_extent(
        &self,
        node_bytes: &[u8],
        out: &mut Vec<(u32, u64, u32)>,
    ) -> core::result::Result<(), &'static str> {
        if node_bytes.len() < 12 {
            return Err("extent node too small");
        }
        let magic = u16::from_le_bytes([node_bytes[0], node_bytes[1]]);
        if magic != EXT4_EXTENT_MAGIC {
            return Err("not an extent header");
        }
        let entries = u16::from_le_bytes([node_bytes[2], node_bytes[3]]) as usize;
        let depth = u16::from_le_bytes([node_bytes[6], node_bytes[7]]);
        for i in 0..entries {
            let off = 12 + i * 12;
            if off + 12 > node_bytes.len() {
                break;
            }
            if depth == 0 {
                // leaf: ext4_extent
                let ee_block = u32_at(node_bytes, off);
                let mut ee_len = u16::from_le_bytes([node_bytes[off + 4], node_bytes[off + 5]]);
                if ee_len > 0x8000 {
                    ee_len -= 0x8000; // uninitialized — still readable
                }
                let ee_start_hi = u16::from_le_bytes([node_bytes[off + 6], node_bytes[off + 7]]) as u64;
                let ee_start_lo = u32_at(node_bytes, off + 8) as u64;
                let phys = (ee_start_hi << 32) | ee_start_lo;
                out.push((ee_block, phys, ee_len as u32));
            } else {
                // internal: ext4_extent_idx
                let ei_leaf_lo = u32_at(node_bytes, off + 4) as u64;
                let ei_leaf_hi = u16::from_le_bytes([node_bytes[off + 8], node_bytes[off + 9]]) as u64;
                let leaf_block = (ei_leaf_hi << 32) | ei_leaf_lo;
                let leaf = self.read_block(leaf_block)?;
                self.walk_extent(&leaf, out)?;
            }
        }
        Ok(())
    }

    /// Read the file contents of an inode into a Vec.
    fn read_file(&self, ino: &Inode4) -> core::result::Result<Vec<u8>, &'static str> {
        // Fallible: a huge file (or an exhausted heap after many cached reads)
        // must surface an error to the read/exec syscall, never trip the Rust
        // alloc-error handler and panic the whole kernel (which would zero
        // every test sequenced after it).
        let size = ino.size as usize;
        let mut out: Vec<u8> = Vec::new();
        if out.try_reserve_exact(size).is_err() {
            return Err("ENOMEM: file does not fit in heap");
        }
        out.resize(size, 0);
        let bs = self.sb.block_size as u64;
        let map = self.extent_map(ino)?;
        for (file_blk, phys_blk, len) in map {
            for i in 0..len as u64 {
                let dst_off = ((file_blk as u64 + i) * bs) as usize;
                if dst_off >= out.len() {
                    break;
                }
                let take = core::cmp::min(bs as usize, out.len() - dst_off);
                let block = self.read_block(phys_blk + i)?;
                out[dst_off..dst_off + take].copy_from_slice(&block[..take]);
            }
        }
        Ok(out)
    }

    /// Read up to `buf.len()` bytes at byte offset `off`, touching only the
    /// blocks that overlap the request (each fetched through the bounded
    /// block cache). Unlike read_file this never allocates the whole file,
    /// so reading thousands of large test binaries can't pin hundreds of MB
    /// of per-inode cache and exhaust the heap. Returns bytes read (clamped
    /// to the file size); sparse holes read as zero.
    fn read_range(
        &self,
        ino: &Inode4,
        off: usize,
        buf: &mut [u8],
    ) -> core::result::Result<usize, &'static str> {
        let size = ino.size as usize;
        if off >= size {
            return Ok(0);
        }
        let want = core::cmp::min(buf.len(), size - off);
        if want == 0 {
            return Ok(0);
        }
        let bs = self.sb.block_size as usize;
        let map = self.extent_map(ino)?;
        let mut done = 0usize;
        while done < want {
            let cur = off + done;
            let fblk = (cur / bs) as u64;
            let blk_off = cur % bs;
            let take = core::cmp::min(bs - blk_off, want - done);
            let phys = map.iter().find_map(|&(start, phys, len)| {
                let s = start as u64;
                if fblk >= s && fblk < s + len as u64 {
                    Some(phys + (fblk - s))
                } else {
                    None
                }
            });
            match phys {
                Some(pblk) => {
                    let block = self.read_block(pblk)?;
                    buf[done..done + take].copy_from_slice(&block[blk_off..blk_off + take]);
                }
                None => {
                    for b in buf[done..done + take].iter_mut() {
                        *b = 0;
                    }
                }
            }
            done += take;
        }
        Ok(done)
    }

    /// Enumerate directory entries (name -> inode#, file_type).
    fn read_dir(&self, ino: &Inode4) -> core::result::Result<Vec<(String, u32, u8)>, &'static str> {
        if (ino.mode & S_IFMT) != S_IFDIR {
            return Err("not a dir");
        }
        let data = self.read_file(ino)?;
        let mut out = Vec::new();
        let mut off = 0usize;
        while off + 8 <= data.len() {
            let inode = u32_at(&data, off);
            let rec_len = u16::from_le_bytes([data[off + 4], data[off + 5]]) as usize;
            if rec_len == 0 {
                break;
            }
            let name_len = data[off + 6] as usize;
            let file_type = data[off + 7];
            if inode != 0 && name_len > 0 && off + 8 + name_len <= data.len() {
                let name = core::str::from_utf8(&data[off + 8..off + 8 + name_len])
                    .unwrap_or("")
                    .to_string();
                if !name.is_empty() {
                    out.push((name, inode, file_type));
                }
            }
            off += rec_len;
            if rec_len < 8 {
                break;
            }
        }
        Ok(out)
    }
}

fn u32_at(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

// ---------- Inode wrappers exposing the VFS Inode trait ----------

pub struct Ext4Dir {
    fs: Arc<Fs>,
    ino: u32,
    children: Mutex<Option<BTreeMap<String, Arc<dyn Inode>>>>,
    overlay_added: Mutex<BTreeMap<String, Arc<dyn Inode>>>,
    overlay_deleted: Mutex<BTreeSet<String>>,
    /// chmod/chown override (mode_perm_bits, uid, gid). None = read from disk.
    perm: Mutex<Option<(u32, u32, u32)>>,
    /// utimensat() times override (atime, mtime) as (sec, nsec) pairs; None
    /// until set. ext4 doesn't track on-disk times here, so utimes/stat
    /// round-trip through this (utimensat01).
    times: Mutex<Option<((i64, i64), (i64, i64))>>,
}

pub struct Ext4File {
    fs: Arc<Fs>,
    ino: u32,
    cached: Mutex<Option<Arc<[u8]>>>,
    mutated: Mutex<Option<Vec<u8>>>,
    /// chmod/chown override (mode_perm_bits, uid, gid). None = read from disk.
    perm: Mutex<Option<(u32, u32, u32)>>,
    /// utimensat() times override (atime, mtime) as (sec, nsec) pairs; None
    /// until set. ext4 doesn't track on-disk times here, so utimes/stat
    /// round-trip through this (utimensat01).
    times: Mutex<Option<((i64, i64), (i64, i64))>>,
}

impl Ext4Dir {
    /// Insert (or replace) an inode under `name` in this directory's overlay.
    /// Used by rename/link to attach an existing inode to a new parent that
    /// lives in the ext4 overlay (rather than a tmpfs dir).
    pub fn place_inode(&self, name: &str, inode: Arc<dyn Inode>) -> Result<()> {
        let mut added = self.overlay_added.lock();
        let mut deleted = self.overlay_deleted.lock();
        deleted.remove(name);
        added.insert(name.to_string(), inode);
        Ok(())
    }

    fn build_children(&self) -> Result<()> {
        let mut slot = self.children.lock();
        if slot.is_some() {
            return Ok(());
        }
        let raw = self.fs.read_inode(self.ino).map_err(|_| EINVAL)?;
        let entries = self.fs.read_dir(&raw).map_err(|_| EINVAL)?;
        let mut map: BTreeMap<String, Arc<dyn Inode>> = BTreeMap::new();
        for (name, child_ino, file_type) in entries {
            if name == "." || name == ".." {
                continue;
            }
            let child: Arc<dyn Inode> = match file_type {
                2 => Arc::new(Ext4Dir {
                    fs: self.fs.clone(),
                    ino: child_ino,
                    children: Mutex::new(None),
                    overlay_added: Mutex::new(BTreeMap::new()),
                    overlay_deleted: Mutex::new(BTreeSet::new()),
                    perm: Mutex::new(None),
                    times: Mutex::new(None),
                }),
                7 => {
                    // Symlink — present as a regular file holding the target.
                    Arc::new(Ext4File {
                        fs: self.fs.clone(),
                        ino: child_ino,
                        cached: Mutex::new(None),
                        mutated: Mutex::new(None),
                    perm: Mutex::new(None),
                    times: Mutex::new(None),
                    })
                }
                _ => Arc::new(Ext4File {
                    fs: self.fs.clone(),
                    ino: child_ino,
                    cached: Mutex::new(None),
                    mutated: Mutex::new(None),
                    perm: Mutex::new(None),
                    times: Mutex::new(None),
                }),
            };
            map.insert(name, child);
        }
        *slot = Some(map);
        Ok(())
    }
}

impl Inode for Ext4Dir {
    fn as_any(&self) -> &dyn Any { self }
    fn meta_perm(&self) -> Option<(u32, u32, u32)> {
        if let Some(p) = *self.perm.lock() {
            return Some(p);
        }
        let mode = self.fs.read_inode(self.ino).map(|i| (i.mode & 0o7777) as u32).unwrap_or(0o755);
        Some((mode, 0, 0))
    }
    fn set_mode(&self, mode: u32) -> bool {
        let mut p = self.perm.lock();
        let cur = p.unwrap_or((0o755, 0, 0));
        *p = Some((mode & 0o7777, cur.1, cur.2));
        true
    }
    fn set_owner(&self, uid: u32, gid: u32) -> bool {
        let mut p = self.perm.lock();
        let cur = p.unwrap_or((0o755, 0, 0));
        let nu = if uid != u32::MAX { uid } else { cur.1 };
        let ng = if gid != u32::MAX { gid } else { cur.2 };
        *p = Some((cur.0, nu, ng));
        true
    }
    fn meta_times(&self) -> Option<((i64, i64), (i64, i64), (i64, i64))> {
        let ((as_, an), (ms, mn)) = self.times.lock().unwrap_or(((0, 0), (0, 0)));
        Some(((as_, an), (ms, mn), (ms, mn)))
    }
    fn set_times(&self, atime: Option<(i64, i64)>, mtime: Option<(i64, i64)>) -> bool {
        let mut t = self.times.lock();
        let cur = t.unwrap_or(((0, 0), (0, 0)));
        *t = Some((atime.unwrap_or(cur.0), mtime.unwrap_or(cur.1)));
        true
    }
    fn kind(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>> {
        if self.overlay_deleted.lock().contains(name) {
            return Err(ENOENT);
        }
        if let Some(node) = self.overlay_added.lock().get(name).cloned() {
            return Ok(node);
        }
        self.build_children()?;
        let map = self.children.lock();
        map.as_ref()
            .and_then(|m| m.get(name).cloned())
            .ok_or(ENOENT)
    }
    fn list(&self) -> Result<Vec<(String, FileType)>> {
        self.build_children()?;
        let deleted = self.overlay_deleted.lock();
        let added = self.overlay_added.lock();
        let map = self.children.lock();
        let mut out: BTreeMap<String, FileType> = BTreeMap::new();
        if let Some(m) = map.as_ref() {
            for (k, v) in m.iter() {
                if !deleted.contains(k) {
                    out.insert(k.clone(), v.kind());
                }
            }
        }
        for (k, v) in added.iter() {
            out.insert(k.clone(), v.kind());
        }
        Ok(out.into_iter().collect())
    }
    fn create(&self, name: &str, kind: FileType) -> Result<Arc<dyn Inode>> {
        let mut deleted = self.overlay_deleted.lock();
        let mut added = self.overlay_added.lock();
        if !deleted.contains(name) {
            if added.contains_key(name) {
                return Err(EEXIST);
            }
            self.build_children()?;
            if let Some(m) = self.children.lock().as_ref() {
                if m.contains_key(name) {
                    return Err(EEXIST);
                }
            }
        }
        let node: Arc<dyn Inode> = match kind {
            FileType::Regular | FileType::Symlink => Arc::new(TmpfsFile::new()),
            FileType::Directory => TmpfsDir::new_root() as Arc<dyn Inode>,
            _ => return Err(EINVAL),
        };
        deleted.remove(name);
        added.insert(name.to_string(), node.clone());
        Ok(node)
    }
    fn unlink(&self, name: &str) -> Result<()> {
        let mut added = self.overlay_added.lock();
        if added.remove(name).is_some() {
            return Ok(());
        }
        if self.overlay_deleted.lock().contains(name) {
            return Err(ENOENT);
        }
        self.build_children()?;
        let on_disk = self
            .children
            .lock()
            .as_ref()
            .map(|m| m.contains_key(name))
            .unwrap_or(false);
        if !on_disk {
            return Err(ENOENT);
        }
        self.overlay_deleted.lock().insert(name.to_string());
        Ok(())
    }
    fn read_at(&self, _off: u64, _buf: &mut [u8]) -> Result<usize> { Err(EINVAL) }
    fn write_at(&self, _off: u64, _buf: &[u8]) -> Result<usize> { Err(EINVAL) }
}

impl Ext4File {
    fn data(&self) -> Result<Arc<[u8]>> {
        let mut slot = self.cached.lock();
        if let Some(d) = &*slot {
            return Ok(d.clone());
        }
        let raw = self.fs.read_inode(self.ino).map_err(|_| EINVAL)?;
        let bytes = self.fs.read_file(&raw).map_err(|_| EINVAL)?;
        let arc: Arc<[u8]> = bytes.into();
        *slot = Some(arc.clone());
        Ok(arc)
    }
}

impl Inode for Ext4File {
    fn as_any(&self) -> &dyn Any { self }
    fn meta_perm(&self) -> Option<(u32, u32, u32)> {
        if let Some(p) = *self.perm.lock() {
            return Some(p);
        }
        let mode = self.fs.read_inode(self.ino).map(|i| (i.mode & 0o7777) as u32).unwrap_or(0o644);
        Some((mode, 0, 0))
    }
    fn set_mode(&self, mode: u32) -> bool {
        let mut p = self.perm.lock();
        let cur = p.unwrap_or((0o644, 0, 0));
        *p = Some((mode & 0o7777, cur.1, cur.2));
        true
    }
    fn set_owner(&self, uid: u32, gid: u32) -> bool {
        let mut p = self.perm.lock();
        let cur = p.unwrap_or_else(|| {
            let m = self.fs.read_inode(self.ino).map(|i| (i.mode & 0o7777) as u32).unwrap_or(0o644);
            (m, 0, 0)
        });
        let nu = if uid != u32::MAX { uid } else { cur.1 };
        let ng = if gid != u32::MAX { gid } else { cur.2 };
        *p = Some((cur.0, nu, ng));
        true
    }
    fn meta_times(&self) -> Option<((i64, i64), (i64, i64), (i64, i64))> {
        let ((as_, an), (ms, mn)) = self.times.lock().unwrap_or(((0, 0), (0, 0)));
        Some(((as_, an), (ms, mn), (ms, mn)))
    }
    fn set_times(&self, atime: Option<(i64, i64)>, mtime: Option<(i64, i64)>) -> bool {
        let mut t = self.times.lock();
        let cur = t.unwrap_or(((0, 0), (0, 0)));
        *t = Some((atime.unwrap_or(cur.0), mtime.unwrap_or(cur.1)));
        true
    }
    fn kind(&self) -> FileType {
        let raw = match self.fs.read_inode(self.ino) {
            Ok(r) => r,
            Err(_) => return FileType::Regular,
        };
        match raw.mode & S_IFMT {
            S_IFDIR => FileType::Directory,
            S_IFLNK => FileType::Symlink,
            _ => FileType::Regular,
        }
    }
    fn size(&self) -> u64 {
        if let Some(v) = self.mutated.lock().as_ref() {
            return v.len() as u64;
        }
        self.fs.read_inode(self.ino).map(|i| i.size).unwrap_or(0)
    }
    fn lookup(&self, _name: &str) -> Result<Arc<dyn Inode>> { Err(EINVAL) }
    fn list(&self) -> Result<Vec<(String, FileType)>> { Err(EINVAL) }
    fn create(&self, _name: &str, _kind: FileType) -> Result<Arc<dyn Inode>> {
        Err(EINVAL)
    }
    fn unlink(&self, _name: &str) -> Result<()> { Err(EINVAL) }
    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<usize> {
        let start = off as usize;
        if let Some(v) = self.mutated.lock().as_ref() {
            if start >= v.len() {
                return Ok(0);
            }
            let end = core::cmp::min(start + buf.len(), v.len());
            let n = end - start;
            buf[..n].copy_from_slice(&v[start..end]);
            return Ok(n);
        }
        // Ranged read straight from the block cache — no whole-file cache,
        // so exec/read of many large binaries doesn't pin per-inode memory.
        let raw = self.fs.read_inode(self.ino).map_err(|_| EINVAL)?;
        self.fs.read_range(&raw, start, buf).map_err(|_| EINVAL)
    }
    fn write_at(&self, off: u64, buf: &[u8]) -> Result<usize> {
        let mut slot = self.mutated.lock();
        if slot.is_none() {
            let data = self.data()?;
            *slot = Some(data.to_vec());
        }
        let v = slot.as_mut().unwrap();
        let start = off as usize;
        if start + buf.len() > v.len() {
            v.resize(start + buf.len(), 0);
        }
        v[start..start + buf.len()].copy_from_slice(buf);
        Ok(buf.len())
    }
    fn truncate(&self, len: u64) -> Result<()> {
        let mut slot = self.mutated.lock();
        if slot.is_none() {
            let data = self.data()?;
            *slot = Some(data.to_vec());
        }
        slot.as_mut().unwrap().resize(len as usize, 0);
        Ok(())
    }
}

/// Downcast `Arc<dyn Inode>` to `Arc<Ext4Dir>` if applicable. Used by
/// rename/link to detect that the new parent is an ext4 overlay dir.
pub fn downcast_dir(inode: &Arc<dyn Inode>) -> Option<Arc<Ext4Dir>> {
    let any: &dyn Any = inode.as_any();
    if any.is::<Ext4Dir>() {
        // SAFETY: we just type-checked.
        let raw = Arc::into_raw(inode.clone());
        unsafe {
            let typed = Arc::from_raw(raw as *const Ext4Dir);
            Some(typed)
        }
    } else {
        None
    }
}

/// Mount the first virtio-blk device as EXT4 and return the root dir
/// inode (or an error string if the disk isn't a recognisable EXT4
/// image).
pub fn mount() -> core::result::Result<Arc<dyn Inode>, &'static str> {
    let blk = crate::drivers::virtio_blk::get().ok_or("no block dev")?;
    let fs = Arc::new(Fs::parse(blk).map_err(|e| {
        crate::println!("[ext4] mount failed: {}", e);
        e
    })?);
    crate::println!(
        "[ext4] online: block={} inode_size={} groups={} total_blocks={}",
        fs.sb.block_size, fs.sb.inode_size, fs.group_descs.len(),
        fs.sb.total_blocks
    );
    let root: Arc<dyn Inode> = Arc::new(Ext4Dir {
        fs,
        ino: ROOT_INO,
        children: Mutex::new(None),
        overlay_added: Mutex::new(BTreeMap::new()),
        overlay_deleted: Mutex::new(BTreeSet::new()),
                    perm: Mutex::new(None),
                    times: Mutex::new(None),
    });
    Ok(root)
}

/// Bolt the ext4 root inode in under `name` at `/`. After the call
/// `lookup_path(/<name>)` reaches the disk's contents. The mount point
/// must be a single name under the tmpfs root (the only one with
/// `place_inode` support).
pub fn mount_at(name: &str) -> core::result::Result<(), &'static str> {
    let root = mount()?;
    let host_root = super::root();
    let td = super::tmpfs::downcast_dir(&host_root)
        .ok_or("root is not tmpfs")?;
    td.place_inode(name, root).map_err(|_| "place_inode failed")?;
    Ok(())
}
