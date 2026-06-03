//! ext2 read/write filesystem on a block device (our writable scratch, x1).
//!
//! A real on-disk filesystem: superblock, block/inode bitmaps, on-disk
//! inodes with direct + single/double indirect block maps, and linear
//! directories — the same layout `mke2fs`/Linux produce, so the data
//! genuinely lives on the device (not in RAM). This backs the writable
//! scratch the `.needs_device` LTP cases mkfs+mount, and gives real inode
//! semantics for fanotify et al.
//!
//! Scope: a SINGLE block group (4 KiB blocks → up to 32768 blocks = 128 MiB,
//! plenty for the LTP scratch). rev 1 (dynamic), 128-byte inodes, FILETYPE
//! dir entries. No journal (that's ext3/4), no extents, no htree — a plain
//! ext2, which Linux mounts as ext2/ext3/ext4.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use crate::drivers::virtio_blk::BlockDevice;
use crate::sync::Mutex;
use super::{FileType, Inode, Result};
use super::{EEXIST, EINVAL, EISDIR, ENOENT, ENOSPC, ENOTDIR};

const EIO: i32 = -5;
const ENOTEMPTY: i32 = -39;

pub const BLOCK_SIZE: usize = 4096;
const SECTORS_PER_BLOCK: u64 = (BLOCK_SIZE / 512) as u64;
const EXT2_MAGIC: u16 = 0xEF53;
const ROOT_INO: u32 = 2;
const FIRST_INO: u32 = 11; // inodes 1..=10 reserved; 11 = lost+found
const INODE_SIZE: usize = 128;
const INODES_PER_BLOCK: usize = BLOCK_SIZE / INODE_SIZE; // 32
const PTRS_PER_BLOCK: usize = BLOCK_SIZE / 4; // 1024
const N_DIRECT: usize = 12;
const IND: usize = 12; // i_block[12] = single indirect
const DIND: usize = 13; // i_block[13] = double indirect
const N_BLOCKS: usize = 15;

// inode mode type bits (high nibble)
const S_IFMT: u16 = 0xF000;
const S_IFREG: u16 = 0x8000;
const S_IFDIR: u16 = 0x4000;
const S_IFLNK: u16 = 0xA000;

// dir entry file_type values (FILETYPE feature)
const FT_REG: u8 = 1;
const FT_DIR: u8 = 2;
const FT_LNK: u8 = 7;

#[inline]
fn rd16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
#[inline]
fn rd32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
#[inline]
fn wr16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
#[inline]
fn wr32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// Cached superblock + group-descriptor fields for the single group.
#[derive(Clone, Copy)]
struct SuperBlock {
    inodes_count: u32,
    blocks_count: u32,
    free_blocks: u32,
    free_inodes: u32,
    first_data_block: u32,
    blocks_per_group: u32,
    inodes_per_group: u32,
    // group 0 descriptor:
    block_bitmap: u32,
    inode_bitmap: u32,
    inode_table: u32,
}

/// One mounted ext2 instance.
pub struct Ext2Fs {
    dev: Arc<BlockDevice>,
    sb: Mutex<SuperBlock>,
}

/// Read fs-block `blk` (BLOCK_SIZE bytes) into `buf`.
fn read_blk(dev: &BlockDevice, blk: u32, buf: &mut [u8; BLOCK_SIZE]) -> Result<()> {
    dev.read_block((blk as u64 * SECTORS_PER_BLOCK) as usize, buf)
        .map_err(|_| EIO)
}
/// Write fs-block `blk` (BLOCK_SIZE bytes) from `buf`.
fn write_blk(dev: &BlockDevice, blk: u32, buf: &[u8; BLOCK_SIZE]) -> Result<()> {
    dev.write_block((blk as u64 * SECTORS_PER_BLOCK) as usize, buf)
        .map_err(|_| EIO)
}

/// On-disk inode fields we care about, decoded from the 128-byte record.
#[derive(Clone)]
struct DiskInode {
    mode: u16,
    uid: u16,
    gid: u16,
    size: u64,
    links: u16,
    blocks512: u32, // i_blocks, in 512-byte units
    atime: u32,
    ctime: u32,
    mtime: u32,
    block: [u32; N_BLOCKS],
}

impl DiskInode {
    fn empty() -> Self {
        Self {
            mode: 0,
            uid: 0,
            gid: 0,
            size: 0,
            links: 0,
            blocks512: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            block: [0; N_BLOCKS],
        }
    }
    fn kind(&self) -> FileType {
        match self.mode & S_IFMT {
            S_IFDIR => FileType::Directory,
            S_IFLNK => FileType::Symlink,
            _ => FileType::Regular,
        }
    }
    fn decode(raw: &[u8]) -> Self {
        let mut block = [0u32; N_BLOCKS];
        for (i, b) in block.iter_mut().enumerate() {
            *b = rd32(raw, 40 + i * 4);
        }
        Self {
            mode: rd16(raw, 0),
            uid: rd16(raw, 2),
            size: rd32(raw, 4) as u64 | ((rd32(raw, 108) as u64) << 32),
            atime: rd32(raw, 8),
            ctime: rd32(raw, 12),
            mtime: rd32(raw, 16),
            gid: rd16(raw, 24),
            links: rd16(raw, 26),
            blocks512: rd32(raw, 28),
            block,
        }
    }
    fn encode(&self, raw: &mut [u8]) {
        for b in raw.iter_mut().take(INODE_SIZE) {
            *b = 0;
        }
        wr16(raw, 0, self.mode);
        wr16(raw, 2, self.uid);
        wr32(raw, 4, (self.size & 0xFFFF_FFFF) as u32);
        wr32(raw, 8, self.atime);
        wr32(raw, 12, self.ctime);
        wr32(raw, 16, self.mtime);
        wr16(raw, 24, self.gid);
        wr16(raw, 26, self.links);
        wr32(raw, 28, self.blocks512);
        for (i, b) in self.block.iter().enumerate() {
            wr32(raw, 40 + i * 4, *b);
        }
        wr32(raw, 108, (self.size >> 32) as u32); // i_size_high (dir_acl)
    }
}

impl Ext2Fs {
    /// Read raw bytes of inode `ino` (1-based) from the inode table.
    fn read_inode(&self, ino: u32) -> Result<DiskInode> {
        if ino == 0 {
            return Err(EINVAL);
        }
        let sb = *self.sb.lock();
        let index = (ino - 1) as usize; // single group
        let blk = sb.inode_table + (index / INODES_PER_BLOCK) as u32;
        let off = (index % INODES_PER_BLOCK) * INODE_SIZE;
        let mut buf = [0u8; BLOCK_SIZE];
        read_blk(&self.dev, blk, &mut buf)?;
        Ok(DiskInode::decode(&buf[off..off + INODE_SIZE]))
    }
    fn write_inode(&self, ino: u32, di: &DiskInode) -> Result<()> {
        let sb = *self.sb.lock();
        let index = (ino - 1) as usize;
        let blk = sb.inode_table + (index / INODES_PER_BLOCK) as u32;
        let off = (index % INODES_PER_BLOCK) * INODE_SIZE;
        let mut buf = [0u8; BLOCK_SIZE];
        read_blk(&self.dev, blk, &mut buf)?;
        di.encode(&mut buf[off..off + INODE_SIZE]);
        write_blk(&self.dev, blk, &buf)
    }

    /// Persist the cached superblock counters into the on-disk superblock
    /// (block-0 offset 1024) and the group-0 descriptor (block 1).
    fn sync_super(&self) -> Result<()> {
        let sb = *self.sb.lock();
        let mut b0 = [0u8; BLOCK_SIZE];
        read_blk(&self.dev, 0, &mut b0)?;
        wr32(&mut b0, 1024 + 12, sb.free_blocks);
        wr32(&mut b0, 1024 + 16, sb.free_inodes);
        write_blk(&self.dev, 0, &b0)?;
        let mut gd = [0u8; BLOCK_SIZE];
        let gd_blk = sb.first_data_block + 1;
        read_blk(&self.dev, gd_blk, &mut gd)?;
        wr16(&mut gd, 12, sb.free_blocks as u16);
        wr16(&mut gd, 14, sb.free_inodes as u16);
        write_blk(&self.dev, gd_blk, &gd)
    }

    /// Allocate a free data block (returns the block number, zeroed on disk).
    fn alloc_block(&self) -> Result<u32> {
        let (bitmap_blk, total) = {
            let sb = self.sb.lock();
            (sb.block_bitmap, sb.blocks_count)
        };
        let mut bm = [0u8; BLOCK_SIZE];
        read_blk(&self.dev, bitmap_blk, &mut bm)?;
        // first_data_block .. blocks_count are the valid block numbers; bit i
        // of the bitmap tracks block (first_data_block + i).
        let first = self.sb.lock().first_data_block;
        let nbits = (total - first) as usize;
        for i in 0..nbits {
            if bm[i / 8] & (1 << (i % 8)) == 0 {
                bm[i / 8] |= 1 << (i % 8);
                write_blk(&self.dev, bitmap_blk, &bm)?;
                let blk = first + i as u32;
                {
                    let mut sb = self.sb.lock();
                    sb.free_blocks = sb.free_blocks.saturating_sub(1);
                }
                let zero = [0u8; BLOCK_SIZE];
                write_blk(&self.dev, blk, &zero)?;
                self.sync_super()?;
                return Ok(blk);
            }
        }
        Err(ENOSPC)
    }
    fn free_block(&self, blk: u32) -> Result<()> {
        let (bitmap_blk, first) = {
            let sb = self.sb.lock();
            (sb.block_bitmap, sb.first_data_block)
        };
        if blk < first {
            return Ok(());
        }
        let i = (blk - first) as usize;
        let mut bm = [0u8; BLOCK_SIZE];
        read_blk(&self.dev, bitmap_blk, &mut bm)?;
        if bm[i / 8] & (1 << (i % 8)) != 0 {
            bm[i / 8] &= !(1 << (i % 8));
            write_blk(&self.dev, bitmap_blk, &bm)?;
            let mut sb = self.sb.lock();
            sb.free_blocks += 1;
        }
        self.sync_super()
    }
    /// Allocate a free inode number (>= FIRST_INO for user inodes).
    fn alloc_inode(&self, is_dir: bool) -> Result<u32> {
        let _ = is_dir;
        let (bitmap_blk, count) = {
            let sb = self.sb.lock();
            (sb.inode_bitmap, sb.inodes_count)
        };
        let mut bm = [0u8; BLOCK_SIZE];
        read_blk(&self.dev, bitmap_blk, &mut bm)?;
        for ino in FIRST_INO..=count {
            let i = (ino - 1) as usize; // bit index
            if bm[i / 8] & (1 << (i % 8)) == 0 {
                bm[i / 8] |= 1 << (i % 8);
                write_blk(&self.dev, bitmap_blk, &bm)?;
                {
                    let mut sb = self.sb.lock();
                    sb.free_inodes = sb.free_inodes.saturating_sub(1);
                }
                self.sync_super()?;
                return Ok(ino);
            }
        }
        Err(ENOSPC)
    }
    fn free_inode(&self, ino: u32) -> Result<()> {
        let bitmap_blk = self.sb.lock().inode_bitmap;
        let i = (ino - 1) as usize;
        let mut bm = [0u8; BLOCK_SIZE];
        read_blk(&self.dev, bitmap_blk, &mut bm)?;
        if bm[i / 8] & (1 << (i % 8)) != 0 {
            bm[i / 8] &= !(1 << (i % 8));
            write_blk(&self.dev, bitmap_blk, &bm)?;
            let mut sb = self.sb.lock();
            sb.free_inodes += 1;
        }
        self.sync_super()
    }

    /// Map logical block `lbn` of inode `di` to a physical block. If
    /// `alloc`, allocate (and link) any missing blocks along the path.
    /// Returns 0 (a hole) when not present and not allocating.
    fn bmap(&self, di: &mut DiskInode, lbn: usize, alloc: bool) -> Result<u32> {
        // Direct.
        if lbn < N_DIRECT {
            if di.block[lbn] == 0 && alloc {
                di.block[lbn] = self.alloc_block()?;
                di.blocks512 += (BLOCK_SIZE / 512) as u32;
            }
            return Ok(di.block[lbn]);
        }
        // Single indirect.
        let l = lbn - N_DIRECT;
        if l < PTRS_PER_BLOCK {
            return self.bmap_indirect(&mut di.block[IND], l, alloc, &mut di.blocks512);
        }
        // Double indirect.
        let l = l - PTRS_PER_BLOCK;
        if l < PTRS_PER_BLOCK * PTRS_PER_BLOCK {
            let d_idx = l / PTRS_PER_BLOCK;
            let s_idx = l % PTRS_PER_BLOCK;
            // Top-level double-indirect block.
            if di.block[DIND] == 0 {
                if !alloc {
                    return Ok(0);
                }
                di.block[DIND] = self.alloc_block()?;
                di.blocks512 += (BLOCK_SIZE / 512) as u32;
            }
            let mut top = di.block[DIND];
            let mid = self.idx_ptr(top, d_idx, alloc, &mut di.blocks512)?;
            let _ = &mut top;
            if mid == 0 {
                return Ok(0);
            }
            let mut mid_mut = mid;
            return self.bmap_indirect(&mut mid_mut, s_idx, alloc, &mut di.blocks512);
        }
        Err(EINVAL) // file too large for this driver
    }

    /// Resolve `idx` within the single-indirect block pointed at by `*slot`,
    /// allocating the indirect block and/or the data block as requested.
    fn bmap_indirect(
        &self,
        slot: &mut u32,
        idx: usize,
        alloc: bool,
        blocks512: &mut u32,
    ) -> Result<u32> {
        if *slot == 0 {
            if !alloc {
                return Ok(0);
            }
            *slot = self.alloc_block()?;
            *blocks512 += (BLOCK_SIZE / 512) as u32;
        }
        self.idx_ptr(*slot, idx, alloc, blocks512)
    }

    /// Read/allocate the data-block pointer at slot `idx` of indirect block
    /// `ind_blk`, allocating the target data block when `alloc`.
    fn idx_ptr(&self, ind_blk: u32, idx: usize, alloc: bool, blocks512: &mut u32) -> Result<u32> {
        let mut buf = [0u8; BLOCK_SIZE];
        read_blk(&self.dev, ind_blk, &mut buf)?;
        let cur = rd32(&buf, idx * 4);
        if cur != 0 {
            return Ok(cur);
        }
        if !alloc {
            return Ok(0);
        }
        let nb = self.alloc_block()?;
        *blocks512 += (BLOCK_SIZE / 512) as u32;
        wr32(&mut buf, idx * 4, nb);
        write_blk(&self.dev, ind_blk, &buf)?;
        Ok(nb)
    }

    /// Read `buf.len()` bytes from inode `di` at byte `offset`.
    fn read_data(&self, di: &DiskInode, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if offset >= di.size {
            return Ok(0);
        }
        let end = core::cmp::min(offset + buf.len() as u64, di.size);
        let mut done = 0usize;
        let mut pos = offset;
        let mut di2 = di.clone();
        while pos < end {
            let lbn = (pos / BLOCK_SIZE as u64) as usize;
            let within = (pos % BLOCK_SIZE as u64) as usize;
            let n = core::cmp::min(BLOCK_SIZE - within, (end - pos) as usize);
            let pbn = self.bmap(&mut di2, lbn, false)?;
            if pbn == 0 {
                // Hole: reads as zeros.
                for b in &mut buf[done..done + n] {
                    *b = 0;
                }
            } else {
                let mut blk = [0u8; BLOCK_SIZE];
                read_blk(&self.dev, pbn, &mut blk)?;
                buf[done..done + n].copy_from_slice(&blk[within..within + n]);
            }
            done += n;
            pos += n as u64;
        }
        Ok(done)
    }

    /// Write `buf` into inode `ino` at byte `offset`, growing the file as
    /// needed. Updates and persists the inode.
    fn write_data(&self, ino: u32, offset: u64, buf: &[u8]) -> Result<usize> {
        let mut di = self.read_inode(ino)?;
        let mut done = 0usize;
        let mut pos = offset;
        let end = offset + buf.len() as u64;
        while pos < end {
            let lbn = (pos / BLOCK_SIZE as u64) as usize;
            let within = (pos % BLOCK_SIZE as u64) as usize;
            let n = core::cmp::min(BLOCK_SIZE - within, (end - pos) as usize);
            let pbn = self.bmap(&mut di, lbn, true)?;
            if pbn == 0 {
                return Err(ENOSPC);
            }
            let mut blk = [0u8; BLOCK_SIZE];
            if within != 0 || n != BLOCK_SIZE {
                read_blk(&self.dev, pbn, &mut blk)?;
            }
            blk[within..within + n].copy_from_slice(&buf[done..done + n]);
            write_blk(&self.dev, pbn, &blk)?;
            done += n;
            pos += n as u64;
        }
        if end > di.size {
            di.size = end;
        }
        di.mtime = now();
        self.write_inode(ino, &di)?;
        Ok(done)
    }
}

fn now() -> u32 {
    // Seconds since boot (monotonic). LTP fs tests check that mtime/ctime
    // *advance* after a write, not the absolute date, so a monotonic value
    // is sufficient and avoids depending on the settable wall offset.
    ((crate::arch::now_ticks() / 10_000_000) as u32).max(1)
}

// ---- mount / format -------------------------------------------------------

/// Read the superblock + group descriptor off `dev` and build an Ext2Fs.
pub fn mount(dev: Arc<BlockDevice>) -> Result<Arc<Ext2Fs>> {
    let mut b0 = [0u8; BLOCK_SIZE];
    read_blk(&dev, 0, &mut b0)?;
    let sb_off = 1024;
    if rd16(&b0, sb_off + 56) != EXT2_MAGIC {
        return Err(EINVAL);
    }
    let log_bs = rd32(&b0, sb_off + 24);
    if (1024usize << log_bs) != BLOCK_SIZE {
        // We only handle 4 KiB blocks.
        return Err(EINVAL);
    }
    let first_data_block = rd32(&b0, sb_off + 20);
    let inodes_count = rd32(&b0, sb_off + 0);
    let blocks_count = rd32(&b0, sb_off + 4);
    let free_blocks = rd32(&b0, sb_off + 12);
    let free_inodes = rd32(&b0, sb_off + 16);
    let blocks_per_group = rd32(&b0, sb_off + 32);
    let inodes_per_group = rd32(&b0, sb_off + 40);
    // Group descriptor 0 lives in the block right after the superblock block.
    let gd_blk = first_data_block + 1;
    let mut gd = [0u8; BLOCK_SIZE];
    read_blk(&dev, gd_blk, &mut gd)?;
    let sb = SuperBlock {
        inodes_count,
        blocks_count,
        free_blocks,
        free_inodes,
        first_data_block,
        blocks_per_group,
        inodes_per_group,
        block_bitmap: rd32(&gd, 0),
        inode_bitmap: rd32(&gd, 4),
        inode_table: rd32(&gd, 8),
    };
    Ok(Arc::new(Ext2Fs { dev, sb: Mutex::new(sb) }))
}

/// Lay down a fresh single-group ext2 filesystem on `dev`, sized to the
/// device capacity (capped at one block group). Wipes prior contents.
pub fn format(dev: &BlockDevice) -> Result<()> {
    let dev_blocks = (dev.capacity() / SECTORS_PER_BLOCK) as u32;
    if dev_blocks < 64 {
        return Err(EINVAL);
    }
    let first_data_block: u32 = 0; // block size > 1024
    // One group: cap at the single-group block-bitmap reach (8 * BLOCK_SIZE).
    let max_group = (8 * BLOCK_SIZE) as u32; // 32768
    let blocks_count = core::cmp::min(dev_blocks, max_group);
    let inodes_count: u32 = 2048;
    let itb_blocks = (inodes_count as usize * INODE_SIZE).div_ceil(BLOCK_SIZE) as u32;

    // Fixed layout: 0=sb, 1=gdt, 2=block bitmap, 3=inode bitmap,
    // 4..4+itb=inode table, then root dir, lost+found, free data.
    let block_bitmap = first_data_block + 2;
    let inode_bitmap = first_data_block + 3;
    let inode_table = first_data_block + 4;
    let first_data = inode_table + itb_blocks;
    let root_data = first_data;
    let lpf_data = first_data + 1;
    let meta_blocks = lpf_data + 1; // blocks 0..meta_blocks are in use

    let zero = [0u8; BLOCK_SIZE];
    // Wipe metadata region (bitmaps, inode table, the two dir blocks).
    for b in 0..meta_blocks {
        write_blk(dev, b, &zero)?;
    }

    // --- superblock (in block 0 at offset 1024) ---
    let mut b0 = [0u8; BLOCK_SIZE];
    let used_inodes = FIRST_INO; // inodes 1..=11 reserved/used
    let free_inodes = inodes_count - used_inodes;
    let free_blocks = blocks_count - meta_blocks;
    {
        let s = &mut b0[1024..];
        wr32(s, 0, inodes_count);
        wr32(s, 4, blocks_count);
        wr32(s, 8, 0); // r_blocks
        wr32(s, 12, free_blocks);
        wr32(s, 16, free_inodes);
        wr32(s, 20, first_data_block);
        wr32(s, 24, 2); // log_block_size: 1024<<2 = 4096
        wr32(s, 28, 2); // log_frag_size
        wr32(s, 32, blocks_count); // blocks_per_group (single group)
        wr32(s, 36, blocks_count); // frags_per_group
        wr32(s, 40, inodes_count); // inodes_per_group
        wr16(s, 56, EXT2_MAGIC);
        wr16(s, 58, 1); // state: clean
        wr16(s, 60, 1); // errors: continue
        wr32(s, 76, 1); // rev_level: dynamic
        wr32(s, 84, FIRST_INO); // first_ino
        wr16(s, 88, INODE_SIZE as u16);
        // feature_incompat: FILETYPE (0x2) so dir entries carry d_type.
        wr32(s, 96, 0x0002);
    }
    write_blk(dev, 0, &b0)?;

    // --- group descriptor 0 (block 1) ---
    let mut gd = [0u8; BLOCK_SIZE];
    wr32(&mut gd, 0, block_bitmap);
    wr32(&mut gd, 4, inode_bitmap);
    wr32(&mut gd, 8, inode_table);
    wr16(&mut gd, 12, free_blocks as u16);
    wr16(&mut gd, 14, free_inodes as u16);
    wr16(&mut gd, 16, 1); // used_dirs_count (root)
    write_blk(dev, first_data_block + 1, &gd)?;

    // --- block bitmap: mark blocks 0..meta_blocks used ---
    let mut bbm = [0u8; BLOCK_SIZE];
    for i in 0..meta_blocks as usize {
        bbm[i / 8] |= 1 << (i % 8);
    }
    // Mark blocks beyond blocks_count (padding bits) as used so they're never
    // allocated.
    for i in blocks_count as usize..(8 * BLOCK_SIZE) {
        bbm[i / 8] |= 1 << (i % 8);
    }
    write_blk(dev, block_bitmap, &bbm)?;

    // --- inode bitmap: mark inodes 1..=FIRST_INO used ---
    let mut ibm = [0u8; BLOCK_SIZE];
    for i in 0..FIRST_INO as usize {
        ibm[i / 8] |= 1 << (i % 8);
    }
    for i in inodes_count as usize..(8 * BLOCK_SIZE) {
        ibm[i / 8] |= 1 << (i % 8);
    }
    write_blk(dev, inode_bitmap, &ibm)?;

    // --- root inode (2) and lost+found (11) ---
    let t = now();
    let mut root = DiskInode::empty();
    root.mode = S_IFDIR | 0o755;
    root.links = 3; // ., .., and lost+found's ..
    root.size = BLOCK_SIZE as u64;
    root.blocks512 = (BLOCK_SIZE / 512) as u32;
    root.block[0] = root_data;
    root.atime = t;
    root.ctime = t;
    root.mtime = t;

    let mut lpf = DiskInode::empty();
    lpf.mode = S_IFDIR | 0o700;
    lpf.links = 2;
    lpf.size = BLOCK_SIZE as u64;
    lpf.blocks512 = (BLOCK_SIZE / 512) as u32;
    lpf.block[0] = lpf_data;
    lpf.atime = t;
    lpf.ctime = t;
    lpf.mtime = t;

    // Write inodes into the inode table.
    write_raw_inode(dev, inode_table, ROOT_INO, &root)?;
    write_raw_inode(dev, inode_table, FIRST_INO, &lpf)?;

    // Root directory block: ".", "..", "lost+found".
    let mut rd = [0u8; BLOCK_SIZE];
    let mut o = 0usize;
    o = put_dirent(&mut rd, o, ROOT_INO, ".", FT_DIR, false);
    o = put_dirent(&mut rd, o, ROOT_INO, "..", FT_DIR, false);
    let _ = put_dirent(&mut rd, o, FIRST_INO, "lost+found", FT_DIR, true);
    write_blk(dev, root_data, &rd)?;

    // lost+found block: ".", "..".
    let mut lb = [0u8; BLOCK_SIZE];
    let o2 = put_dirent(&mut lb, 0, FIRST_INO, ".", FT_DIR, false);
    let _ = put_dirent(&mut lb, o2, ROOT_INO, "..", FT_DIR, true);
    write_blk(dev, lpf_data, &lb)?;

    Ok(())
}

fn write_raw_inode(dev: &BlockDevice, inode_table: u32, ino: u32, di: &DiskInode) -> Result<()> {
    let index = (ino - 1) as usize;
    let blk = inode_table + (index / INODES_PER_BLOCK) as u32;
    let off = (index % INODES_PER_BLOCK) * INODE_SIZE;
    let mut buf = [0u8; BLOCK_SIZE];
    read_blk(dev, blk, &mut buf)?;
    di.encode(&mut buf[off..off + INODE_SIZE]);
    write_blk(dev, blk, &buf)
}

/// Write a directory entry at byte offset `o`. If `last`, the record spans
/// the rest of the block (rec_len to block end). Returns the next offset.
fn put_dirent(buf: &mut [u8], o: usize, ino: u32, name: &str, ftype: u8, last: bool) -> usize {
    let nl = name.len();
    let need = (8 + nl + 3) & !3; // 4-byte aligned
    let rec_len = if last { BLOCK_SIZE - o } else { need };
    wr32(buf, o, ino);
    wr16(buf, o + 4, rec_len as u16);
    buf[o + 6] = nl as u8;
    buf[o + 7] = ftype;
    buf[o + 8..o + 8 + nl].copy_from_slice(name.as_bytes());
    o + rec_len
}

// ---- directory operations -------------------------------------------------

impl Ext2Fs {
    /// Walk active dir entries (ino != 0), calling `f(ino, ftype, name)`;
    /// returns the first `Some(v)` `f` produces, else None.
    fn dir_walk<T>(
        &self,
        dir: &DiskInode,
        mut f: impl FnMut(u32, u8, &str) -> Option<T>,
    ) -> Result<Option<T>> {
        let nblocks = (dir.size as usize).div_ceil(BLOCK_SIZE);
        let mut di = dir.clone();
        for lbn in 0..nblocks {
            let pbn = self.bmap(&mut di, lbn, false)?;
            if pbn == 0 {
                continue;
            }
            let mut buf = [0u8; BLOCK_SIZE];
            read_blk(&self.dev, pbn, &mut buf)?;
            let mut o = 0usize;
            while o + 8 <= BLOCK_SIZE {
                let ino = rd32(&buf, o);
                let rec_len = rd16(&buf, o + 4) as usize;
                if rec_len < 8 || o + rec_len > BLOCK_SIZE {
                    break;
                }
                let name_len = buf[o + 6] as usize;
                if ino != 0 && name_len > 0 && o + 8 + name_len <= BLOCK_SIZE {
                    if let Ok(name) = core::str::from_utf8(&buf[o + 8..o + 8 + name_len]) {
                        if let Some(v) = f(ino, buf[o + 7], name) {
                            return Ok(Some(v));
                        }
                    }
                }
                o += rec_len;
            }
        }
        Ok(None)
    }

    fn dir_lookup(&self, dir_ino: u32, name: &str) -> Result<Option<u32>> {
        let dir = self.read_inode(dir_ino)?;
        self.dir_walk(&dir, |ino, _ft, n| if n == name { Some(ino) } else { None })
    }

    fn dir_list(&self, dir_ino: u32) -> Result<Vec<(String, FileType)>> {
        let dir = self.read_inode(dir_ino)?;
        let mut out = Vec::new();
        self.dir_walk(&dir, |_ino, ft, n| {
            if n != "." && n != ".." {
                let k = match ft {
                    FT_DIR => FileType::Directory,
                    FT_LNK => FileType::Symlink,
                    _ => FileType::Regular,
                };
                out.push((String::from(n), k));
            }
            None::<()>
        })?;
        Ok(out)
    }

    /// Add (child_ino, name, ftype) to directory `dir_ino`.
    fn dir_add(&self, dir_ino: u32, name: &str, child_ino: u32, ftype: u8) -> Result<()> {
        let nl = name.len();
        if nl == 0 || nl > 255 {
            return Err(EINVAL);
        }
        let need = (8 + nl + 3) & !3;
        let mut dir = self.read_inode(dir_ino)?;
        let nblocks = (dir.size as usize).div_ceil(BLOCK_SIZE).max(1);
        for lbn in 0..nblocks {
            let pbn = self.bmap(&mut dir, lbn, false)?;
            if pbn == 0 {
                continue;
            }
            let mut buf = [0u8; BLOCK_SIZE];
            read_blk(&self.dev, pbn, &mut buf)?;
            let mut o = 0usize;
            while o + 8 <= BLOCK_SIZE {
                let ino = rd32(&buf, o);
                let rec_len = rd16(&buf, o + 4) as usize;
                if rec_len < 8 || o + rec_len > BLOCK_SIZE {
                    break;
                }
                let name_len = buf[o + 6] as usize;
                let used = if ino == 0 { 0 } else { (8 + name_len + 3) & !3 };
                if rec_len - used >= need {
                    let new_off = o + used;
                    let new_rec = rec_len - used;
                    if ino != 0 {
                        wr16(&mut buf, o + 4, used as u16);
                    }
                    wr32(&mut buf, new_off, child_ino);
                    wr16(&mut buf, new_off + 4, new_rec as u16);
                    buf[new_off + 6] = nl as u8;
                    buf[new_off + 7] = ftype;
                    buf[new_off + 8..new_off + 8 + nl].copy_from_slice(name.as_bytes());
                    write_blk(&self.dev, pbn, &buf)?;
                    return Ok(());
                }
                o += rec_len;
            }
        }
        // No room in existing blocks — append a fresh one.
        let lbn = nblocks;
        let pbn = self.bmap(&mut dir, lbn, true)?;
        let mut buf = [0u8; BLOCK_SIZE];
        let _ = put_dirent(&mut buf, 0, child_ino, name, ftype, true);
        write_blk(&self.dev, pbn, &buf)?;
        dir.size = ((lbn + 1) * BLOCK_SIZE) as u64;
        self.write_inode(dir_ino, &dir)
    }

    /// Remove `name` from `dir_ino`: merge its slot into the previous entry,
    /// or zero its inode if first in the block.
    fn dir_remove(&self, dir_ino: u32, name: &str) -> Result<()> {
        let dir = self.read_inode(dir_ino)?;
        let nblocks = (dir.size as usize).div_ceil(BLOCK_SIZE);
        let mut di = dir.clone();
        for lbn in 0..nblocks {
            let pbn = self.bmap(&mut di, lbn, false)?;
            if pbn == 0 {
                continue;
            }
            let mut buf = [0u8; BLOCK_SIZE];
            read_blk(&self.dev, pbn, &mut buf)?;
            let mut o = 0usize;
            let mut prev: Option<usize> = None;
            while o + 8 <= BLOCK_SIZE {
                let ino = rd32(&buf, o);
                let rec_len = rd16(&buf, o + 4) as usize;
                if rec_len < 8 || o + rec_len > BLOCK_SIZE {
                    break;
                }
                let name_len = buf[o + 6] as usize;
                if ino != 0
                    && name_len == name.len()
                    && o + 8 + name_len <= BLOCK_SIZE
                    && &buf[o + 8..o + 8 + name_len] == name.as_bytes()
                {
                    if let Some(p) = prev {
                        let plen = rd16(&buf, p + 4) as usize;
                        wr16(&mut buf, p + 4, (plen + rec_len) as u16);
                    } else {
                        wr32(&mut buf, o, 0);
                    }
                    write_blk(&self.dev, pbn, &buf)?;
                    return Ok(());
                }
                prev = Some(o);
                o += rec_len;
            }
        }
        Err(ENOENT)
    }

    /// Free every data block of an inode (direct + single/double indirect).
    fn free_inode_blocks(&self, di: &DiskInode) -> Result<()> {
        for i in 0..N_DIRECT {
            if di.block[i] != 0 {
                self.free_block(di.block[i])?;
            }
        }
        if di.block[IND] != 0 {
            self.free_indirect(di.block[IND], 1)?;
        }
        if di.block[DIND] != 0 {
            self.free_indirect(di.block[DIND], 2)?;
        }
        Ok(())
    }
    fn free_indirect(&self, blk: u32, level: u8) -> Result<()> {
        let mut buf = [0u8; BLOCK_SIZE];
        read_blk(&self.dev, blk, &mut buf)?;
        for i in 0..PTRS_PER_BLOCK {
            let p = rd32(&buf, i * 4);
            if p == 0 {
                continue;
            }
            if level == 1 {
                self.free_block(p)?;
            } else {
                self.free_indirect(p, level - 1)?;
            }
        }
        self.free_block(blk)
    }

    pub fn get_inode(self: &Arc<Self>, ino: u32) -> Arc<Ext2Inode> {
        Arc::new(Ext2Inode { fs: self.clone(), ino })
    }
    /// The filesystem root inode, for grafting into the VFS at a mount point.
    pub fn root_inode(self: &Arc<Self>) -> Arc<dyn Inode> {
        self.get_inode(ROOT_INO)
    }
}

// ---- VFS inode ------------------------------------------------------------

pub struct Ext2Inode {
    fs: Arc<Ext2Fs>,
    ino: u32,
}

impl Ext2Inode {
    fn di(&self) -> Result<DiskInode> {
        self.fs.read_inode(self.ino)
    }
}

impl Inode for Ext2Inode {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn kind(&self) -> FileType {
        self.di().map(|d| d.kind()).unwrap_or(FileType::Regular)
    }
    fn size(&self) -> u64 {
        self.di().map(|d| d.size).unwrap_or(0)
    }
    fn meta_times(&self) -> Option<((i64, i64), (i64, i64), (i64, i64))> {
        let d = self.di().ok()?;
        Some(((d.atime as i64, 0), (d.mtime as i64, 0), (d.ctime as i64, 0)))
    }
    fn set_times(&self, atime: Option<(i64, i64)>, mtime: Option<(i64, i64)>) -> bool {
        let Ok(mut d) = self.di() else { return false };
        if let Some((s, _)) = atime { d.atime = s as u32; }
        if let Some((s, _)) = mtime { d.mtime = s as u32; }
        d.ctime = now();
        self.fs.write_inode(self.ino, &d).is_ok()
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let di = self.di()?;
        if di.kind() == FileType::Directory {
            return Err(EISDIR);
        }
        self.fs.read_data(&di, offset, buf)
    }
    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<usize> {
        let di = self.di()?;
        if di.kind() == FileType::Directory {
            return Err(EISDIR);
        }
        self.fs.write_data(self.ino, offset, buf)
    }
    fn truncate(&self, len: u64) -> Result<()> {
        let mut di = self.di()?;
        if di.kind() == FileType::Directory {
            return Err(EISDIR);
        }
        if len < di.size {
            // Free whole blocks past the new end. (Indirect bookkeeping is
            // left intact for the partial tail; a future write re-maps it.)
            let keep = (len as usize).div_ceil(BLOCK_SIZE);
            let had = (di.size as usize).div_ceil(BLOCK_SIZE);
            for lbn in keep..had {
                if lbn < N_DIRECT && di.block[lbn] != 0 {
                    let _ = self.fs.free_block(di.block[lbn]);
                    di.block[lbn] = 0;
                }
            }
        }
        di.size = len;
        di.mtime = now();
        self.fs.write_inode(self.ino, &di)
    }
    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>> {
        let di = self.di()?;
        if di.kind() != FileType::Directory {
            return Err(ENOTDIR);
        }
        match self.fs.dir_lookup(self.ino, name)? {
            Some(ino) => Ok(self.fs.get_inode(ino) as Arc<dyn Inode>),
            None => Err(ENOENT),
        }
    }
    fn create(&self, name: &str, kind: FileType) -> Result<Arc<dyn Inode>> {
        let parent = self.di()?;
        if parent.kind() != FileType::Directory {
            return Err(ENOTDIR);
        }
        if self.fs.dir_lookup(self.ino, name)?.is_some() {
            return Err(EEXIST);
        }
        let t = now();
        let ino = self.fs.alloc_inode(kind == FileType::Directory)?;
        let mut di = DiskInode::empty();
        di.atime = t;
        di.ctime = t;
        di.mtime = t;
        match kind {
            FileType::Directory => {
                di.mode = S_IFDIR | 0o755;
                di.links = 2;
                let dblk = self.fs.alloc_block()?;
                di.block[0] = dblk;
                di.blocks512 = (BLOCK_SIZE / 512) as u32;
                di.size = BLOCK_SIZE as u64;
                let mut buf = [0u8; BLOCK_SIZE];
                let o = put_dirent(&mut buf, 0, ino, ".", FT_DIR, false);
                let _ = put_dirent(&mut buf, o, self.ino, "..", FT_DIR, true);
                write_blk(&self.fs.dev, dblk, &buf)?;
                self.fs.write_inode(ino, &di)?;
                self.fs.dir_add(self.ino, name, ino, FT_DIR)?;
                // Parent gains a link from the child's "..".
                let mut p = self.fs.read_inode(self.ino)?;
                p.links += 1;
                self.fs.write_inode(self.ino, &p)?;
            }
            _ => {
                di.mode = S_IFREG | 0o644;
                di.links = 1;
                self.fs.write_inode(ino, &di)?;
                self.fs.dir_add(self.ino, name, ino, FT_REG)?;
            }
        }
        Ok(self.fs.get_inode(ino) as Arc<dyn Inode>)
    }
    fn symlink(&self, name: &str, target: &str) -> Result<()> {
        if self.di()?.kind() != FileType::Directory {
            return Err(ENOTDIR);
        }
        if self.fs.dir_lookup(self.ino, name)?.is_some() {
            return Err(EEXIST);
        }
        let t = now();
        let ino = self.fs.alloc_inode(false)?;
        let mut di = DiskInode::empty();
        di.mode = S_IFLNK | 0o777;
        di.links = 1;
        di.size = target.len() as u64;
        di.atime = t;
        di.ctime = t;
        di.mtime = t;
        if target.len() < 60 {
            // Fast symlink: target stored inline in the i_block area.
            let mut raw = [0u8; 60];
            raw[..target.len()].copy_from_slice(target.as_bytes());
            for i in 0..N_BLOCKS {
                di.block[i] = u32::from_le_bytes([
                    raw[i * 4],
                    raw[i * 4 + 1],
                    raw[i * 4 + 2],
                    raw[i * 4 + 3],
                ]);
            }
            self.fs.write_inode(ino, &di)?;
        } else {
            let dblk = self.fs.alloc_block()?;
            di.block[0] = dblk;
            di.blocks512 = (BLOCK_SIZE / 512) as u32;
            let mut buf = [0u8; BLOCK_SIZE];
            buf[..target.len()].copy_from_slice(target.as_bytes());
            write_blk(&self.fs.dev, dblk, &buf)?;
            self.fs.write_inode(ino, &di)?;
        }
        self.fs.dir_add(self.ino, name, ino, FT_LNK)
    }
    fn readlink(&self) -> Result<String> {
        let di = self.di()?;
        if di.kind() != FileType::Symlink {
            return Err(EINVAL);
        }
        if di.size < 60 && di.block[0] != 0 && (di.block[0] & 0xff) >= 0x20 {
            // Heuristic ambiguity avoided below: fast symlinks have no real
            // block ptr. Fall through to inline decode regardless of size<60.
        }
        if di.size < 60 {
            // Fast symlink: target inline in i_block bytes.
            let mut raw = [0u8; 60];
            for i in 0..N_BLOCKS {
                raw[i * 4..i * 4 + 4].copy_from_slice(&di.block[i].to_le_bytes());
            }
            let n = di.size as usize;
            return Ok(String::from_utf8_lossy(&raw[..n]).into_owned());
        }
        let mut buf = [0u8; BLOCK_SIZE];
        read_blk(&self.fs.dev, di.block[0], &mut buf)?;
        let n = di.size as usize;
        Ok(String::from_utf8_lossy(&buf[..n.min(BLOCK_SIZE)]).into_owned())
    }
    fn unlink(&self, name: &str) -> Result<()> {
        if self.di()?.kind() != FileType::Directory {
            return Err(ENOTDIR);
        }
        let child_ino = match self.fs.dir_lookup(self.ino, name)? {
            Some(i) => i,
            None => return Err(ENOENT),
        };
        let child = self.fs.read_inode(child_ino)?;
        self.fs.dir_remove(self.ino, name)?;
        if child.kind() == FileType::Directory {
            // rmdir: the syscall already verified it's empty. Free it and
            // drop the parent's link (its "..").
            self.fs.free_inode_blocks(&child)?;
            self.fs.free_inode(child_ino)?;
            let mut p = self.fs.read_inode(self.ino)?;
            if p.links > 0 {
                p.links -= 1;
            }
            self.fs.write_inode(self.ino, &p)?;
        }
        // For files, the link-count decrement + free-on-zero happens in
        // adjust_nlink(-1), which sys_unlinkat calls on the victim next.
        Ok(())
    }
    fn list(&self) -> Result<Vec<(String, FileType)>> {
        if self.di()?.kind() != FileType::Directory {
            return Err(ENOTDIR);
        }
        self.fs.dir_list(self.ino)
    }
    fn meta_perm(&self) -> Option<(u32, u32, u32)> {
        let di = self.di().ok()?;
        Some(((di.mode & 0o7777) as u32, di.uid as u32, di.gid as u32))
    }
    fn set_mode(&self, mode: u32) -> bool {
        let Ok(mut di) = self.di() else { return false };
        di.mode = (di.mode & S_IFMT) | (mode as u16 & 0o7777);
        di.ctime = now();
        self.fs.write_inode(self.ino, &di).is_ok()
    }
    fn set_owner(&self, uid: u32, gid: u32) -> bool {
        let Ok(mut di) = self.di() else { return false };
        if uid != u32::MAX {
            di.uid = uid as u16;
        }
        if gid != u32::MAX {
            di.gid = gid as u16;
        }
        di.ctime = now();
        self.fs.write_inode(self.ino, &di).is_ok()
    }
    fn nlink(&self) -> u32 {
        self.di().map(|d| d.links as u32).unwrap_or(1)
    }
    fn adjust_nlink(&self, delta: i32) -> u32 {
        let Ok(mut di) = self.di() else { return 1 };
        let new = (di.links as i32 + delta).max(0) as u16;
        di.links = new;
        if new == 0 {
            // Last name gone: free the file's blocks and inode.
            let _ = self.fs.free_inode_blocks(&di);
            let _ = self.fs.free_inode(self.ino);
        } else {
            let _ = self.fs.write_inode(self.ino, &di);
        }
        new as u32
    }
}

/// Boot-time smoke test: format the scratch device, then exercise the core
/// paths (create/write/read, mkdir/list, a multi-block + single-indirect
/// write, unlink). Prints a one-line PASS summary. Dev/bring-up only.
pub fn smoke_test() {
    let Some(dev) = crate::drivers::virtio_blk::get_scratch() else {
        crate::println!("[ext2-smoke] no scratch device");
        return;
    };
    if let Err(e) = format(&dev) {
        crate::println!("[ext2-smoke] format failed: {}", e);
        return;
    }
    let fs = match mount(dev) {
        Ok(f) => f,
        Err(e) => {
            crate::println!("[ext2-smoke] mount failed: {}", e);
            return;
        }
    };
    let root = fs.root_inode();
    let f = match root.create("hello.txt", FileType::Regular) {
        Ok(f) => f,
        Err(e) => {
            crate::println!("[ext2-smoke] create failed: {}", e);
            return;
        }
    };
    let data = b"hello ext2 on disk!";
    let _ = f.write_at(0, data);
    let mut buf = [0u8; 64];
    let n = f.read_at(0, &mut buf).unwrap_or(0);
    let ok_rw = &buf[..n] == data;

    let _ = root.create("subdir", FileType::Directory);
    let listing = root.list().unwrap_or_default();
    let has_sub = listing.iter().any(|(nm, _)| nm == "subdir");

    // Multi-block write crossing the 12 direct blocks into single-indirect.
    let big_ok = match root.create("big.bin", FileType::Regular) {
        Ok(big) => {
            let chunk = [0xABu8; BLOCK_SIZE];
            let mut wrote = 0usize;
            for i in 0..30usize {
                if big.write_at((i * BLOCK_SIZE) as u64, &chunk).unwrap_or(0) != BLOCK_SIZE {
                    break;
                }
                wrote += BLOCK_SIZE;
            }
            let mut rb = [0u8; BLOCK_SIZE];
            let rn = big.read_at((29 * BLOCK_SIZE) as u64, &mut rb).unwrap_or(0);
            wrote == 30 * BLOCK_SIZE && rn == BLOCK_SIZE && rb.iter().all(|&b| b == 0xAB)
        }
        Err(_) => false,
    };

    let _ = root.unlink("hello.txt");
    let after = root.list().unwrap_or_default();
    let gone = !after.iter().any(|(nm, _)| nm == "hello.txt");

    // VFS mount test: graft this ext2 root at /tmp/m and round-trip a file
    // through full-path resolution (proves mount_at + cross-mount lookup).
    let mut vfs_ok = false;
    if let Ok(tmp) = crate::fs::lookup_path(crate::fs::root(), "/tmp") {
        let _ = tmp.create("m", FileType::Directory);
        if crate::fs::mount_at(tmp.clone(), "m", fs.root_inode()).is_ok() {
            if let Ok(md) = crate::fs::lookup_path(crate::fs::root(), "/tmp/m") {
                if let Ok(file) = md.create("vfs.txt", FileType::Regular) {
                    let _ = file.write_at(0, b"via-vfs");
                }
            }
            if let Ok(f2) = crate::fs::lookup_path(crate::fs::root(), "/tmp/m/vfs.txt") {
                let mut b = [0u8; 16];
                let n = f2.read_at(0, &mut b).unwrap_or(0);
                vfs_ok = &b[..n] == b"via-vfs";
            }
            let _ = crate::fs::umount_at(&tmp, "m");
        }
    }

    crate::println!(
        "[ext2-smoke] rw={} mkdir={} big_indirect={} unlink={} vfs_mount={} entries_now={}",
        ok_rw, has_sub, big_ok, gone, vfs_ok, after.len()
    );
}
