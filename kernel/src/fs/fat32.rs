//! Minimal FAT32 read-only driver hooked up as an Inode tree.
//!
//! We parse the BPB, walk the FAT (32-bit entries, top 4 bits reserved),
//! and expose each cluster chain as an in-memory snapshot. Read-only is
//! enough for the M7 acceptance criterion (`mount /dev/vda /mnt` + ls/cat).

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use core::convert::TryInto;
use spin::Mutex;

use super::{FileType, Inode, Result, EINVAL, ENOENT};
use crate::drivers::virtio_blk::{self, BlockDevice};

const SECTOR_SIZE: usize = 512;
const DIR_ENTRY_SIZE: usize = 32;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_VOLUME_ID: u8 = 0x08;
const ATTR_LFN: u8 = 0x0f;
const FAT_EOC: u32 = 0x0fff_fff8;

struct Bpb {
    bytes_per_sector: u32,
    sectors_per_cluster: u32,
    reserved_sectors: u32,
    num_fats: u32,
    sectors_per_fat: u32,
    root_cluster: u32,
}

struct Fs {
    blk: Arc<BlockDevice>,
    bpb: Bpb,
    fat_start_sector: u32,
    data_start_sector: u32,
}

impl Fs {
    fn parse(blk: Arc<BlockDevice>) -> core::result::Result<Self, &'static str> {
        let mut sector = vec![0u8; SECTOR_SIZE];
        blk.read_block(0, &mut sector)
            .map_err(|_| "read boot sector")?;
        if sector[510] != 0x55 || sector[511] != 0xaa {
            return Err("bad boot sector signature");
        }
        let bytes_per_sector = u16::from_le_bytes([sector[11], sector[12]]) as u32;
        let sectors_per_cluster = sector[13] as u32;
        let reserved_sectors = u16::from_le_bytes([sector[14], sector[15]]) as u32;
        let num_fats = sector[16] as u32;
        let sectors_per_fat = u32::from_le_bytes([
            sector[36], sector[37], sector[38], sector[39],
        ]);
        let root_cluster = u32::from_le_bytes([
            sector[44], sector[45], sector[46], sector[47],
        ]);
        if bytes_per_sector as usize != SECTOR_SIZE {
            return Err("non-512 sector unsupported");
        }
        let bpb = Bpb {
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sectors,
            num_fats,
            sectors_per_fat,
            root_cluster,
        };
        let fat_start_sector = bpb.reserved_sectors;
        let data_start_sector = fat_start_sector + bpb.num_fats * bpb.sectors_per_fat;
        Ok(Self {
            blk,
            bpb,
            fat_start_sector,
            data_start_sector,
        })
    }

    fn cluster_first_sector(&self, cluster: u32) -> u32 {
        self.data_start_sector + (cluster - 2) * self.bpb.sectors_per_cluster
    }

    fn cluster_byte_size(&self) -> usize {
        self.bpb.sectors_per_cluster as usize * SECTOR_SIZE
    }

    fn next_cluster(&self, cluster: u32) -> core::result::Result<u32, ()> {
        let fat_offset = cluster as usize * 4;
        let sector = self.fat_start_sector + (fat_offset / SECTOR_SIZE) as u32;
        let off = fat_offset % SECTOR_SIZE;
        let mut buf = vec![0u8; SECTOR_SIZE];
        self.blk.read_block(sector as usize, &mut buf)?;
        let entry = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) & 0x0fff_ffff;
        Ok(entry)
    }

    fn read_cluster_chain(&self, first: u32, max: Option<usize>) -> Vec<u8> {
        let mut out = Vec::new();
        let mut cur = first;
        let cluster_bytes = self.cluster_byte_size();
        while cur >= 2 && cur < FAT_EOC {
            let first_sector = self.cluster_first_sector(cur) as usize;
            for s in 0..self.bpb.sectors_per_cluster as usize {
                let mut buf = vec![0u8; SECTOR_SIZE];
                if self.blk.read_block(first_sector + s, &mut buf).is_err() {
                    return out;
                }
                out.extend_from_slice(&buf);
            }
            if let Some(m) = max {
                if out.len() >= m {
                    out.truncate(m);
                    break;
                }
            }
            cur = match self.next_cluster(cur) {
                Ok(n) => n,
                Err(_) => break,
            };
            let _ = cluster_bytes;
        }
        out
    }
}

#[derive(Clone)]
struct DirEntry {
    name: String,
    is_dir: bool,
    first_cluster: u32,
    size: u32,
}

fn parse_dir(blob: &[u8]) -> Vec<DirEntry> {
    let mut entries = Vec::new();
    let mut lfn_chunks: Vec<String> = Vec::new();
    for i in (0..blob.len()).step_by(DIR_ENTRY_SIZE) {
        if i + DIR_ENTRY_SIZE > blob.len() {
            break;
        }
        let e = &blob[i..i + DIR_ENTRY_SIZE];
        if e[0] == 0 {
            break;
        }
        if e[0] == 0xe5 {
            lfn_chunks.clear();
            continue;
        }
        let attr = e[11];
        if attr == ATTR_LFN {
            lfn_chunks.push(parse_lfn_chunk(e));
            continue;
        }
        if attr & ATTR_VOLUME_ID != 0 && attr & ATTR_DIRECTORY == 0 {
            lfn_chunks.clear();
            continue;
        }
        let name = if !lfn_chunks.is_empty() {
            let mut s = String::new();
            for chunk in lfn_chunks.iter().rev() {
                s.push_str(chunk);
            }
            lfn_chunks.clear();
            s.trim_end_matches('\0').to_string()
        } else {
            parse_8_3_name(e)
        };
        if name.is_empty() || name == "." || name == ".." {
            continue;
        }
        let cluster_high = u16::from_le_bytes([e[20], e[21]]) as u32;
        let cluster_low = u16::from_le_bytes([e[26], e[27]]) as u32;
        let first_cluster = (cluster_high << 16) | cluster_low;
        let size = u32::from_le_bytes([e[28], e[29], e[30], e[31]]);
        entries.push(DirEntry {
            name,
            is_dir: attr & ATTR_DIRECTORY != 0,
            first_cluster,
            size,
        });
    }
    entries
}

fn parse_lfn_chunk(e: &[u8]) -> String {
    let mut out = String::new();
    let positions = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
    for &p in &positions {
        let lo = e[p];
        let hi = e[p + 1];
        let c = u16::from_le_bytes([lo, hi]);
        if c == 0 || c == 0xffff {
            break;
        }
        if let Some(ch) = char::from_u32(c as u32) {
            out.push(ch);
        }
    }
    out
}

fn parse_8_3_name(e: &[u8]) -> String {
    let base: String = e[0..8]
        .iter()
        .map(|&b| b as char)
        .collect::<String>()
        .trim_end()
        .to_string();
    let ext: String = e[8..11]
        .iter()
        .map(|&b| b as char)
        .collect::<String>()
        .trim_end()
        .to_string();
    if ext.is_empty() {
        base
    } else {
        format!("{}.{}", base, ext)
    }
}

struct FatFile {
    fs: Arc<Fs>,
    first_cluster: u32,
    size: u32,
    cached: Mutex<Option<Vec<u8>>>,
}

impl FatFile {
    fn data(&self) -> Vec<u8> {
        let mut c = self.cached.lock();
        if let Some(d) = &*c {
            return d.clone();
        }
        let blob = self
            .fs
            .read_cluster_chain(self.first_cluster, Some(self.size as usize));
        *c = Some(blob.clone());
        blob
    }
}

impl Inode for FatFile {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn kind(&self) -> FileType {
        FileType::Regular
    }
    fn size(&self) -> u64 {
        self.size as u64
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let data = self.data();
        let off = offset as usize;
        if off >= data.len() {
            return Ok(0);
        }
        let n = core::cmp::min(buf.len(), data.len() - off);
        buf[..n].copy_from_slice(&data[off..off + n]);
        Ok(n)
    }
}

struct FatDir {
    fs: Arc<Fs>,
    first_cluster: u32,
    entries: Mutex<Option<BTreeMap<String, Arc<dyn Inode>>>>,
}

impl FatDir {
    fn populate(&self) {
        let mut cache = self.entries.lock();
        if cache.is_some() {
            return;
        }
        let blob = self.fs.read_cluster_chain(self.first_cluster, None);
        let parsed = parse_dir(&blob);
        let mut map: BTreeMap<String, Arc<dyn Inode>> = BTreeMap::new();
        for e in parsed {
            let node: Arc<dyn Inode> = if e.is_dir {
                Arc::new(FatDir {
                    fs: self.fs.clone(),
                    first_cluster: e.first_cluster,
                    entries: Mutex::new(None),
                })
            } else {
                Arc::new(FatFile {
                    fs: self.fs.clone(),
                    first_cluster: e.first_cluster,
                    size: e.size,
                    cached: Mutex::new(None),
                })
            };
            map.insert(e.name.clone(), node);
        }
        *cache = Some(map);
    }
}

impl Inode for FatDir {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn kind(&self) -> FileType {
        FileType::Directory
    }
    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>> {
        self.populate();
        let cache = self.entries.lock();
        cache
            .as_ref()
            .and_then(|m| m.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone()))
            .ok_or(ENOENT)
    }
    fn list(&self) -> Result<Vec<(String, FileType)>> {
        self.populate();
        let cache = self.entries.lock();
        Ok(cache
            .as_ref()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.kind()))
            .collect())
    }
}

pub fn mount(mount_point: &str) -> core::result::Result<(), &'static str> {
    let blk = virtio_blk::get().ok_or("no block device")?;
    let fs = Arc::new(Fs::parse(blk)?);
    let root_cluster = fs.bpb.root_cluster;
    let root = Arc::new(FatDir {
        fs,
        first_cluster: root_cluster,
        entries: Mutex::new(None),
    });

    let vfs_root = super::root();
    // Drop our entry under `mount_point` (single path component for now).
    let name = mount_point.trim_start_matches('/');
    if let Some(td) = super::tmpfs::downcast_dir(&vfs_root) {
        td.place_inode(name, root as Arc<dyn Inode>)
            .map_err(|_| "place_inode")?;
    } else {
        return Err("root isn't tmpfs");
    }
    Ok(())
}
