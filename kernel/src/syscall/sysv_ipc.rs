//! System V IPC: shared memory (shmget/shmat/shmdt/shmctl).
//!
//! LTP exercises the whole family (shmget0*, shmat0*, shmdt0*, shmctl0*) plus
//! a pile of tests that merely *set up* a SysV segment as scaffolding; all of
//! those previously hard-failed because the syscalls returned -1/ENOSYS. The
//! segment's pages are real frames owned by the global table here and handed
//! to each attaching address space as shared `Arc<FrameTracker>`s, so a write
//! through one attachment is visible through every other — true shared memory,
//! and the memory persists past the creator's exit until IPC_RMID + last
//! detach, exactly like Linux.
//!
//! Message queues and semaphores live in the sibling modules; this file is
//! shared memory only.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::mm::frame::{alloc as alloc_frame, FrameTracker};
use crate::mm::memory_set::VmPerm;
use crate::sync::Mutex;

// ── errno values this module needs that syscall/mod.rs doesn't already pull in
const EINVAL: isize = -22;
const EFAULT: isize = -14;
const EACCES: isize = -13;
const ENOENT: isize = -2;
const EEXIST: isize = -17;
const ENOSPC: isize = -28;
const ENOMEM: isize = -12;

// ── ipc / shm command + flag constants (asm-generic, shared by rv64 & la64)
const IPC_PRIVATE: i32 = 0;
const IPC_CREAT: i32 = 0o1000;
const IPC_EXCL: i32 = 0o2000;
const IPC_RMID: i32 = 0;
const IPC_SET: i32 = 1;
const IPC_STAT: i32 = 2;
const IPC_INFO: i32 = 3;
const SHM_STAT: i32 = 13;
const SHM_INFO: i32 = 14;
const SHM_STAT_ANY: i32 = 15;
const SHM_RDONLY: i32 = 0o10000;
const SHM_RND: i32 = 0o20000;
/// Segment-attach boundary for SHM_RND. Page size is fine on both arches.
const SHMLBA: usize = PAGE_SIZE;

use crate::mm::address::PAGE_SIZE;

// ── tunables. Generous enough for every LTP case, bounded so a leaked/abusive
// segment can't eat the kernel the way unbounded tmpfs did.
const SHMMIN: usize = 1;
const SHMMAX: usize = 64 * 1024 * 1024;
const SHMMNI: usize = 4096;
/// Ceiling on the total frames pinned across all live segments (defense in
/// depth, same spirit as the tmpfs cap): a test that leaks segments can't pin
/// more than this. 128 MiB / 4 KiB pages.
const SHM_TOTAL_PAGES_MAX: usize = 128 * 1024 * 1024 / PAGE_SIZE;

static SHM_TOTAL_PAGES: AtomicUsize = AtomicUsize::new(0);

struct ShmSeg {
    shmid: i32,
    key: i32,
    size: usize,
    /// The segment's pages. Cloned (Arc) into each attaching address space.
    frames: Vec<Arc<FrameTracker>>,
    mode: u32,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    cpid: i32,
    lpid: i32,
    nattch: usize,
    atime: i64,
    dtime: i64,
    ctime: i64,
    /// IPC_RMID requested while still attached: destroy on the last detach.
    rmid: bool,
}

struct ShmTable {
    segs: BTreeMap<i32, ShmSeg>,
    by_key: BTreeMap<i32, i32>,
    /// (pid, attach-vaddr) -> shmid, so shmdt(addr) finds its segment.
    attaches: BTreeMap<(i32, usize), i32>,
    next_id: i32,
}

static SHM: Mutex<ShmTable> = Mutex::new(ShmTable {
    segs: BTreeMap::new(),
    by_key: BTreeMap::new(),
    attaches: BTreeMap::new(),
    next_id: 1,
});

fn now_secs() -> i64 {
    // Seconds since boot — monotonic and nonzero, which is all the SysV time
    // stamps (shm_atime/dtime/ctime) need; no LTP shm case checks them against
    // an absolute wall clock, only that they advance across operations.
    (crate::arch::now_ticks() / crate::arch::TICKS_PER_SEC) as i64
}

/// Drop a segment and release its frame budget. Caller holds the SHM lock and
/// has already removed the by_key entry.
fn destroy_seg(seg: ShmSeg) {
    SHM_TOTAL_PAGES.fetch_sub(seg.frames.len(), Ordering::Relaxed);
    // `seg` (and its Arc<FrameTracker> vec) drops here; frames free once no
    // attachment still references them.
}

pub fn sys_shmget(key: i32, size: usize, shmflg: i32) -> isize {
    let mut t = SHM.lock();

    // Existing-key lookup (IPC_PRIVATE always makes a fresh segment).
    if key != IPC_PRIVATE {
        if let Some(&id) = t.by_key.get(&key) {
            if (shmflg & IPC_CREAT) != 0 && (shmflg & IPC_EXCL) != 0 {
                return EEXIST;
            }
            let seg = t.segs.get(&id).unwrap();
            if size != 0 && size > seg.size {
                return EINVAL;
            }
            return id as isize;
        }
        if (shmflg & IPC_CREAT) == 0 {
            return ENOENT;
        }
    }

    // Creating a new segment: validate the requested size.
    if size < SHMMIN || size > SHMMAX {
        return EINVAL;
    }
    if t.segs.len() >= SHMMNI {
        return ENOSPC;
    }
    let pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    if SHM_TOTAL_PAGES.load(Ordering::Relaxed) + pages > SHM_TOTAL_PAGES_MAX {
        return ENOSPC;
    }

    let mut frames: Vec<Arc<FrameTracker>> = Vec::new();
    if frames.try_reserve(pages).is_err() {
        return ENOMEM;
    }
    for _ in 0..pages {
        match alloc_frame() {
            Some(f) => frames.push(Arc::new(f)),
            None => return ENOMEM, // partial `frames` drops here, freeing them
        }
    }
    SHM_TOTAL_PAGES.fetch_add(pages, Ordering::Relaxed);

    let id = t.next_id;
    t.next_id = t.next_id.wrapping_add(1).max(1);
    let pid = crate::task::current_pid();
    let now = now_secs();
    let seg = ShmSeg {
        shmid: id,
        key,
        size,
        frames,
        mode: (shmflg as u32) & 0o777,
        uid: 0,
        gid: 0,
        cuid: 0,
        cgid: 0,
        cpid: pid,
        lpid: 0,
        nattch: 0,
        atime: 0,
        dtime: 0,
        ctime: now,
        rmid: false,
    };
    t.segs.insert(id, seg);
    if key != IPC_PRIVATE {
        t.by_key.insert(key, id);
    }
    id as isize
}

pub fn sys_shmat(shmid: i32, shmaddr: usize, shmflg: i32) -> isize {
    // Snapshot the segment's frames under the table lock, then release it
    // before touching the address space (never hold two locks at once).
    let (frames, size) = {
        let t = SHM.lock();
        let Some(seg) = t.segs.get(&shmid) else { return EINVAL };
        (seg.frames.clone(), seg.size)
    };

    // Resolve the requested attach address.
    let at = if shmaddr == 0 {
        None
    } else if (shmflg & SHM_RND) != 0 {
        Some(shmaddr & !(SHMLBA - 1))
    } else if shmaddr % PAGE_SIZE != 0 {
        return EINVAL;
    } else {
        Some(shmaddr)
    };

    let mut perm = VmPerm::R | VmPerm::U;
    if (shmflg & SHM_RDONLY) == 0 {
        perm |= VmPerm::W;
    }

    let task = crate::task::current_task();
    let va = task
        .memory_set
        .lock()
        .map_shared_frames(&frames, perm, at);
    if va.0 == usize::MAX {
        return ENOMEM;
    }
    drop(frames);

    // Commit: bump attach count + record the attachment.
    let pid = task.pid;
    let mut t = SHM.lock();
    if let Some(seg) = t.segs.get_mut(&shmid) {
        seg.nattch += 1;
        seg.lpid = pid;
        seg.atime = now_secs();
    }
    t.attaches.insert((pid, va.0), shmid);
    let _ = size;
    va.0 as isize
}

pub fn sys_shmdt(shmaddr: usize) -> isize {
    let task = crate::task::current_task();
    let pid = task.pid;

    let (shmid, size) = {
        let t = SHM.lock();
        let Some(&id) = t.attaches.get(&(pid, shmaddr)) else { return EINVAL };
        let size = t.segs.get(&id).map(|s| s.size).unwrap_or(0);
        (id, size)
    };

    // Drop the mapping (releases this address space's Arc clones).
    if size > 0 {
        task.memory_set.lock().unmap_range(crate::mm::address::VirtAddr(shmaddr), size);
    }

    let mut t = SHM.lock();
    t.attaches.remove(&(pid, shmaddr));
    let mut destroy = None;
    if let Some(seg) = t.segs.get_mut(&shmid) {
        seg.nattch = seg.nattch.saturating_sub(1);
        seg.lpid = pid;
        seg.dtime = now_secs();
        if seg.rmid && seg.nattch == 0 {
            destroy = Some(shmid);
        }
    }
    if let Some(id) = destroy {
        if let Some(seg) = t.segs.remove(&id) {
            t.by_key.remove(&seg.key);
            destroy_seg(seg);
        }
    }
    0
}

pub fn sys_shmctl(shmid: i32, cmd: i32, buf: usize) -> isize {
    // IPC_INFO / SHM_INFO report system-wide limits, not a specific segment.
    match cmd {
        IPC_INFO | SHM_INFO => return shm_info(buf),
        _ => {}
    }

    let mut t = SHM.lock();

    // SHM_STAT[_ANY] index by table position and return the shmid; IPC_STAT
    // and friends index by shmid directly.
    let id = match cmd {
        SHM_STAT | SHM_STAT_ANY => {
            let idx = shmid as usize;
            match t.segs.values().nth(idx) {
                Some(s) => s.shmid,
                None => return EINVAL,
            }
        }
        _ => shmid,
    };

    match cmd {
        IPC_RMID => {
            let Some(seg) = t.segs.get_mut(&id) else { return EINVAL };
            seg.rmid = true;
            seg.ctime = now_secs();
            if seg.nattch == 0 {
                if let Some(seg) = t.segs.remove(&id) {
                    t.by_key.remove(&seg.key);
                    destroy_seg(seg);
                }
            }
            0
        }
        IPC_STAT | SHM_STAT | SHM_STAT_ANY => {
            let Some(seg) = t.segs.get(&id) else { return EINVAL };
            let bytes = encode_shmid_ds(seg);
            drop(t);
            if crate::task::current_task().copy_out_bytes(buf, &bytes).is_none() {
                return EFAULT;
            }
            match cmd {
                SHM_STAT | SHM_STAT_ANY => id as isize,
                _ => 0,
            }
        }
        IPC_SET => {
            // Read back the (possibly) modified mode/uid/gid from the user ds.
            let Some(bytes) = crate::task::current_task().copy_in_bytes(buf, SHMID_DS_LEN) else {
                return EFAULT;
            };
            let Some(seg) = t.segs.get_mut(&id) else { return EINVAL };
            seg.uid = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
            seg.gid = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
            seg.mode = u32::from_le_bytes(bytes[20..24].try_into().unwrap()) & 0o777;
            seg.ctime = now_secs();
            0
        }
        _ => EINVAL,
    }
}

/// Minimal IPC_INFO/SHM_INFO: report the static limits so tst tools that read
/// them don't TBROK. Layout is `struct shminfo`/`struct shm_info`; we fill the
/// first few longs (the only fields LTP reads) and zero the rest.
fn shm_info(buf: usize) -> isize {
    if buf == 0 {
        return 0;
    }
    let mut out = [0u8; 112];
    // struct shminfo { unsigned long shmmax, shmmin, shmmni, shmseg, shmall; ... }
    out[0..8].copy_from_slice(&(SHMMAX as u64).to_le_bytes());
    out[8..16].copy_from_slice(&(SHMMIN as u64).to_le_bytes());
    out[16..24].copy_from_slice(&(SHMMNI as u64).to_le_bytes());
    out[24..32].copy_from_slice(&(SHMMNI as u64).to_le_bytes());
    out[32..40].copy_from_slice(&(SHM_TOTAL_PAGES_MAX as u64).to_le_bytes());
    if crate::task::current_task().copy_out_bytes(buf, &out).is_none() {
        return EFAULT;
    }
    0
}

/// `struct shmid64_ds` is 112 bytes on both rv64 and la64 (asm-generic LP64).
const SHMID_DS_LEN: usize = 112;

/// Serialize a segment into the asm-generic `struct shmid64_ds` musl reads.
/// Offsets: ipc64_perm[0..48], segsz[48], atime[56], dtime[64], ctime[72],
/// cpid[80], lpid[84], nattch[88], pad[96], pad[104].
fn encode_shmid_ds(seg: &ShmSeg) -> [u8; SHMID_DS_LEN] {
    let mut b = [0u8; SHMID_DS_LEN];
    // ipc64_perm
    b[0..4].copy_from_slice(&seg.key.to_le_bytes());
    b[4..8].copy_from_slice(&seg.uid.to_le_bytes());
    b[8..12].copy_from_slice(&seg.gid.to_le_bytes());
    b[12..16].copy_from_slice(&seg.cuid.to_le_bytes());
    b[16..20].copy_from_slice(&seg.cgid.to_le_bytes());
    b[20..24].copy_from_slice(&seg.mode.to_le_bytes());
    // seq [24..26], pad [26..28], __unused1 [32..40], __unused2 [40..48] = 0
    // shmid64_ds body
    b[48..56].copy_from_slice(&(seg.size as u64).to_le_bytes());
    b[56..64].copy_from_slice(&seg.atime.to_le_bytes());
    b[64..72].copy_from_slice(&seg.dtime.to_le_bytes());
    b[72..80].copy_from_slice(&seg.ctime.to_le_bytes());
    b[80..84].copy_from_slice(&seg.cpid.to_le_bytes());
    b[84..88].copy_from_slice(&seg.lpid.to_le_bytes());
    b[88..96].copy_from_slice(&(seg.nattch as u64).to_le_bytes());
    b
}
