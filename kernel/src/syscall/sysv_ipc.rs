//! System V IPC: shared memory, message queues, semaphores.
//!
//! LTP exercises the whole family (shmget/shmat/shmdt/shmctl, msgget/msgsnd/
//! msgrcv/msgctl, semget/semop/semctl/semtimedop) plus a pile of tests that
//! merely *set up* a SysV object as scaffolding; all of those previously
//! hard-failed because the syscalls returned -1/ENOSYS.
//!
//! Shared memory: the segment's pages are real frames owned by the global
//! table here and handed to each attaching address space as shared
//! `Arc<FrameTracker>`s, so a write through one attachment is visible through
//! every other — true shared memory, persisting past the creator's exit until
//! IPC_RMID + last detach, exactly like Linux.
//!
//! Message queues / semaphores: blocking msgrcv/msgsnd/semop use the same
//! park-and-retry shape as wait4/futex — mark the task Waiting, rewind the
//! ecall, and have the waking operation (msgsnd / semop increment / IPC_RMID)
//! flip the parked waiters back to Ready so the rewound syscall re-checks. No
//! lost wakeups: mid-syscall preemption is disabled, so check→park is atomic
//! w.r.t. other tasks.

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

/// Linux encodes a SysV IPC id as `seq * IPCMNI + index`, where the slot index
/// AND the sequence counter BOTH advance on every allocation. The crucial
/// consequence: `id - k*IPCMNI` (for k != 0) decodes to a slot whose live seq
/// no longer matches, so it is never itself a valid id. {msg,shm,sem}ctl04
/// derive their "bad id" exactly this way — `msg_id - IPCMNI`, `msg_id - 1`, a
/// created-then-removed id — and expect EINVAL. We assign ids `n * (IPCMNI+1)`
/// (a monotonic n standing in for both index and seq, never reused), which
/// reproduces that invariant: ids are spaced IPCMNI+1 apart, so neither an
/// arithmetic neighbour nor `id - k*IPCMNI` ever collides with a live object.
/// Densely packed ids (1, 2, 3, …) failed because the bad id hit a queue a
/// different test left live earlier in the boot (SysV objects persist past
/// process exit); a plain IPCMNI stride still let `msg_id - IPCMNI` hit the
/// previous live id.
const IPCMNI: i32 = 32768;

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
    t.next_id = t.next_id.wrapping_add(IPCMNI + 1).max(1);
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

// ───────────────────────────── shared helpers ──────────────────────────────

const EAGAIN: isize = -11;
const ENOMSG: isize = -42;
const E2BIG: isize = -7;
const EIDRM: isize = -43;
const ERANGE: isize = -34;
const EINTR: isize = -4;

const IPC_NOWAIT: i32 = 0o4000;

/// Write the 48-byte asm-generic `struct ipc64_perm` prefix shared by every
/// `*id64_ds`. Offsets: key[0], uid[4], gid[8], cuid[12], cgid[16], mode[20],
/// seq[24], then padding through 48.
fn write_ipc_perm(b: &mut [u8], key: i32, uid: u32, gid: u32, cuid: u32, cgid: u32, mode: u32) {
    b[0..4].copy_from_slice(&key.to_le_bytes());
    b[4..8].copy_from_slice(&uid.to_le_bytes());
    b[8..12].copy_from_slice(&gid.to_le_bytes());
    b[12..16].copy_from_slice(&cuid.to_le_bytes());
    b[16..20].copy_from_slice(&cgid.to_le_bytes());
    b[20..24].copy_from_slice(&mode.to_le_bytes());
}

/// Flip every parked waiter back to Ready so its rewound syscall re-checks.
fn wake_pids(pids: &[i32]) {
    for &pid in pids {
        if let Some(t) = crate::task::task_by_pid(pid) {
            let mut s = t.state.lock();
            if *s == crate::task::TaskState::Waiting {
                *s = crate::task::TaskState::Ready;
            }
        }
    }
}

/// Park the current task and rewind its ecall so the syscall re-runs (and
/// re-checks its condition) when something flips it back to Ready. Returns 0,
/// the value the dispatcher ignores for a parked task.
fn park_current() -> isize {
    let task = crate::task::current_task();
    *task.state.lock() = crate::task::TaskState::Waiting;
    unsafe {
        (*task.tf_ptr()).rewind_syscall();
    }
    0
}

// ════════════════════════════ message queues ═══════════════════════════════

const MSGMAX: usize = 8192; // max bytes in one message
const MSGMNB: usize = 16384; // default max bytes in a queue
const MSGMNI: usize = 1024; // max queues
/// MSG_EXCEPT / MSG_NOERROR live in msgflg / the receive type selector.
const MSG_NOERROR: i32 = 0o10000;
const MSG_EXCEPT: i32 = 0o20000;

struct MsgItem {
    mtype: i64,
    data: Vec<u8>,
}

struct MsgQueue {
    msqid: i32,
    key: i32,
    msgs: alloc::collections::VecDeque<MsgItem>,
    cbytes: usize,
    qbytes: usize,
    mode: u32,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    lspid: i32,
    lrpid: i32,
    stime: i64,
    rtime: i64,
    ctime: i64,
    /// pids parked in msgrcv (queue empty) or msgsnd (queue full).
    waiters: Vec<i32>,
    rmid: bool,
}

struct MsgTable {
    qs: BTreeMap<i32, MsgQueue>,
    by_key: BTreeMap<i32, i32>,
    next_id: i32,
}

static MSG: Mutex<MsgTable> = Mutex::new(MsgTable {
    qs: BTreeMap::new(),
    by_key: BTreeMap::new(),
    next_id: 1,
});

pub fn sys_msgget(key: i32, msgflg: i32) -> isize {
    let mut t = MSG.lock();
    if key != IPC_PRIVATE {
        if let Some(&id) = t.by_key.get(&key) {
            if (msgflg & IPC_CREAT) != 0 && (msgflg & IPC_EXCL) != 0 {
                return EEXIST;
            }
            return id as isize;
        }
        if (msgflg & IPC_CREAT) == 0 {
            return ENOENT;
        }
    }
    if t.qs.len() >= MSGMNI {
        return ENOSPC;
    }
    let id = t.next_id;
    t.next_id = t.next_id.wrapping_add(IPCMNI + 1).max(1);
    let now = now_secs();
    let q = MsgQueue {
        msqid: id,
        key,
        msgs: alloc::collections::VecDeque::new(),
        cbytes: 0,
        qbytes: MSGMNB,
        mode: (msgflg as u32) & 0o777,
        uid: 0,
        gid: 0,
        cuid: 0,
        cgid: 0,
        lspid: 0,
        lrpid: 0,
        stime: 0,
        rtime: 0,
        ctime: now,
        waiters: Vec::new(),
        rmid: false,
    };
    t.qs.insert(id, q);
    if key != IPC_PRIVATE {
        t.by_key.insert(key, id);
    }
    id as isize
}

pub fn sys_msgsnd(msqid: i32, msgp: usize, msgsz: usize, msgflg: i32) -> isize {
    if msgsz > MSGMAX {
        return EINVAL;
    }
    // msgbuf = { long mtype; char mtext[msgsz]; }
    let task = crate::task::current_task();
    let Some(buf) = task.copy_in_bytes(msgp, 8 + msgsz) else { return EFAULT };
    let mtype = i64::from_le_bytes(buf[0..8].try_into().unwrap());
    if mtype < 1 {
        return EINVAL;
    }
    let pid = task.pid;

    let mut t = MSG.lock();
    // Drop our stale waiter entry from a previous park (re-entry after wake).
    if let Some(q) = t.qs.get_mut(&msqid) {
        q.waiters.retain(|&p| p != pid);
    }
    let Some(q) = t.qs.get_mut(&msqid) else { return EINVAL };
    if q.rmid {
        return EIDRM;
    }
    // Block (or EAGAIN) while the queue can't hold the new message.
    if q.cbytes + msgsz > q.qbytes && !q.msgs.is_empty() {
        if (msgflg & IPC_NOWAIT) != 0 {
            return EAGAIN;
        }
        q.waiters.push(pid);
        return park_current();
    }
    q.msgs.push_back(MsgItem { mtype, data: buf[8..].to_vec() });
    q.cbytes += msgsz;
    q.lspid = pid;
    q.stime = now_secs();
    let wake: Vec<i32> = core::mem::take(&mut q.waiters);
    drop(t);
    wake_pids(&wake); // wake parked receivers
    0
}

pub fn sys_msgrcv(msqid: i32, msgp: usize, msgsz: usize, msgtyp: i64, msgflg: i32) -> isize {
    let task = crate::task::current_task();
    let pid = task.pid;

    let mut t = MSG.lock();
    if let Some(q) = t.qs.get_mut(&msqid) {
        q.waiters.retain(|&p| p != pid); // clear stale park entry on re-entry
    }
    let Some(q) = t.qs.get_mut(&msqid) else { return EINVAL };
    if q.rmid {
        return EIDRM;
    }

    // Pick the message matching msgtyp.
    let idx = select_msg(&q.msgs, msgtyp, msgflg);
    let Some(i) = idx else {
        // Nothing matched: block or report.
        if (msgflg & IPC_NOWAIT) != 0 {
            return ENOMSG;
        }
        q.waiters.push(pid);
        return park_current();
    };

    let item = &q.msgs[i];
    if item.data.len() > msgsz && (msgflg & MSG_NOERROR) == 0 {
        return E2BIG;
    }
    let n = core::cmp::min(item.data.len(), msgsz);
    let mtype = item.mtype;
    // Build mtype + truncated data, then hand back to the user.
    let mut out = Vec::with_capacity(8 + n);
    out.extend_from_slice(&mtype.to_le_bytes());
    out.extend_from_slice(&item.data[..n]);
    let removed = q.msgs.remove(i).unwrap();
    q.cbytes = q.cbytes.saturating_sub(removed.data.len());
    q.lrpid = pid;
    q.rtime = now_secs();
    let wake: Vec<i32> = core::mem::take(&mut q.waiters);
    drop(t);
    if task.copy_out_bytes(msgp, &out).is_none() {
        return EFAULT;
    }
    wake_pids(&wake); // wake parked senders (space freed)
    n as isize
}

/// Index of the first message in `msgs` matching the SysV `msgtyp` rule.
fn select_msg(
    msgs: &alloc::collections::VecDeque<MsgItem>,
    msgtyp: i64,
    msgflg: i32,
) -> Option<usize> {
    if msgtyp == 0 {
        return if msgs.is_empty() { None } else { Some(0) };
    }
    if msgtyp > 0 {
        if (msgflg & MSG_EXCEPT) != 0 {
            return msgs.iter().position(|m| m.mtype != msgtyp);
        }
        return msgs.iter().position(|m| m.mtype == msgtyp);
    }
    // msgtyp < 0: lowest mtype that is <= |msgtyp|.
    let lim = (-msgtyp) as i64;
    let mut best: Option<(usize, i64)> = None;
    for (i, m) in msgs.iter().enumerate() {
        if m.mtype <= lim {
            match best {
                Some((_, bt)) if m.mtype >= bt => {}
                _ => best = Some((i, m.mtype)),
            }
        }
    }
    best.map(|(i, _)| i)
}

pub fn sys_msgctl(msqid: i32, cmd: i32, buf: usize) -> isize {
    let mut t = MSG.lock();
    let id = match cmd {
        13 /* MSG_STAT */ | 15 /* MSG_STAT_ANY */ => {
            match t.qs.values().nth(msqid as usize) {
                Some(q) => q.msqid,
                None => return EINVAL,
            }
        }
        _ => msqid,
    };
    match cmd {
        IPC_RMID => {
            let Some(mut q) = t.qs.remove(&id) else { return EINVAL };
            t.by_key.remove(&q.key);
            let wake = core::mem::take(&mut q.waiters);
            drop(t);
            wake_pids(&wake); // parked ops re-run and see the queue gone (EIDRM/EINVAL)
            0
        }
        IPC_STAT | 13 | 15 => {
            let Some(q) = t.qs.get(&id) else { return EINVAL };
            let bytes = encode_msqid_ds(q);
            drop(t);
            if crate::task::current_task().copy_out_bytes(buf, &bytes).is_none() {
                return EFAULT;
            }
            if cmd == 13 || cmd == 15 { id as isize } else { 0 }
        }
        IPC_SET => {
            let Some(bytes) = crate::task::current_task().copy_in_bytes(buf, MSQID_DS_LEN) else {
                return EFAULT;
            };
            let Some(q) = t.qs.get_mut(&id) else { return EINVAL };
            q.uid = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
            q.gid = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
            q.mode = u32::from_le_bytes(bytes[20..24].try_into().unwrap()) & 0o777;
            // msg_qbytes is settable (offset 88 in msqid64_ds).
            let qb = u64::from_le_bytes(bytes[88..96].try_into().unwrap()) as usize;
            if qb > 0 {
                q.qbytes = qb;
            }
            q.ctime = now_secs();
            0
        }
        _ => EINVAL,
    }
}

const MSQID_DS_LEN: usize = 120;

/// asm-generic `struct msqid64_ds` (120 bytes): perm[0..48], stime[48],
/// rtime[56], ctime[64], cbytes[72], qnum[80], qbytes[88], lspid[96],
/// lrpid[100], pad[104], pad[112].
fn encode_msqid_ds(q: &MsgQueue) -> [u8; MSQID_DS_LEN] {
    let mut b = [0u8; MSQID_DS_LEN];
    write_ipc_perm(&mut b, q.key, q.uid, q.gid, q.cuid, q.cgid, q.mode);
    b[48..56].copy_from_slice(&q.stime.to_le_bytes());
    b[56..64].copy_from_slice(&q.rtime.to_le_bytes());
    b[64..72].copy_from_slice(&q.ctime.to_le_bytes());
    b[72..80].copy_from_slice(&(q.cbytes as u64).to_le_bytes());
    b[80..88].copy_from_slice(&(q.msgs.len() as u64).to_le_bytes());
    b[88..96].copy_from_slice(&(q.qbytes as u64).to_le_bytes());
    b[96..100].copy_from_slice(&q.lspid.to_le_bytes());
    b[100..104].copy_from_slice(&q.lrpid.to_le_bytes());
    b
}

// ═══════════════════════════════ semaphores ════════════════════════════════

const SEMVMX: i32 = 32767;
const SEMMSL: usize = 250; // max semaphores per set
const SEMOPM: usize = 500; // max ops per semop
const SEMMNI: usize = 1024;

// semctl commands beyond the IPC_* shared ones.
const GETPID: i32 = 11;
const GETVAL: i32 = 12;
const GETALL: i32 = 13;
const GETNCNT: i32 = 14;
const GETZCNT: i32 = 15;
const SETVAL: i32 = 16;
const SETALL: i32 = 17;
const SEM_STAT: i32 = 18;
const SEM_STAT_ANY: i32 = 20;

struct SemSet {
    semid: i32,
    key: i32,
    vals: Vec<i32>,
    pids: Vec<i32>, // sempid per semaphore (last op)
    mode: u32,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    otime: i64,
    ctime: i64,
    waiters: Vec<i32>,
    rmid: bool,
}

struct SemTable {
    sets: BTreeMap<i32, SemSet>,
    by_key: BTreeMap<i32, i32>,
    next_id: i32,
}

static SEM: Mutex<SemTable> = Mutex::new(SemTable {
    sets: BTreeMap::new(),
    by_key: BTreeMap::new(),
    next_id: 1,
});

pub fn sys_semget(key: i32, nsems: usize, semflg: i32) -> isize {
    let mut t = SEM.lock();
    if key != IPC_PRIVATE {
        if let Some(&id) = t.by_key.get(&key) {
            if (semflg & IPC_CREAT) != 0 && (semflg & IPC_EXCL) != 0 {
                return EEXIST;
            }
            let s = t.sets.get(&id).unwrap();
            if nsems != 0 && nsems > s.vals.len() {
                return EINVAL;
            }
            return id as isize;
        }
        if (semflg & IPC_CREAT) == 0 {
            return ENOENT;
        }
    }
    if nsems == 0 || nsems > SEMMSL {
        return EINVAL;
    }
    if t.sets.len() >= SEMMNI {
        return ENOSPC;
    }
    let id = t.next_id;
    t.next_id = t.next_id.wrapping_add(IPCMNI + 1).max(1);
    let now = now_secs();
    let set = SemSet {
        semid: id,
        key,
        vals: alloc::vec![0i32; nsems],
        pids: alloc::vec![0i32; nsems],
        mode: (semflg as u32) & 0o777,
        uid: 0,
        gid: 0,
        cuid: 0,
        cgid: 0,
        otime: 0,
        ctime: now,
        waiters: Vec::new(),
        rmid: false,
    };
    t.sets.insert(id, set);
    if key != IPC_PRIVATE {
        t.by_key.insert(key, id);
    }
    id as isize
}

/// `struct sembuf { unsigned short sem_num; short sem_op; short sem_flg; }`.
struct SemBuf {
    num: u16,
    op: i16,
    flg: i16,
}

pub fn sys_semop(semid: i32, sops: usize, nsops: usize) -> isize {
    sys_semtimedop(semid, sops, nsops, 0)
}

pub fn sys_semtimedop(semid: i32, sops: usize, nsops: usize, _timeout: usize) -> isize {
    if nsops == 0 || nsops > SEMOPM {
        return EINVAL;
    }
    let task = crate::task::current_task();
    let pid = task.pid;
    let Some(raw) = task.copy_in_bytes(sops, nsops * 6) else { return EFAULT };
    let ops: Vec<SemBuf> = (0..nsops)
        .map(|i| {
            let o = i * 6;
            SemBuf {
                num: u16::from_le_bytes(raw[o..o + 2].try_into().unwrap()),
                op: i16::from_le_bytes(raw[o + 2..o + 4].try_into().unwrap()),
                flg: i16::from_le_bytes(raw[o + 4..o + 6].try_into().unwrap()),
            }
        })
        .collect();

    let mut t = SEM.lock();
    if let Some(s) = t.sets.get_mut(&semid) {
        s.waiters.retain(|&p| p != pid);
    }
    let Some(s) = t.sets.get_mut(&semid) else { return EINVAL };
    if s.rmid {
        return EIDRM;
    }
    for op in &ops {
        if op.num as usize >= s.vals.len() {
            return -27; // EFBIG: sem_num out of range
        }
    }

    // Find the first op that can't proceed right now.
    let mut block_idx = None;
    for (i, op) in ops.iter().enumerate() {
        let v = s.vals[op.num as usize];
        let ok = if op.op > 0 {
            true
        } else if op.op < 0 {
            v + (op.op as i32) >= 0
        } else {
            v == 0
        };
        if !ok {
            block_idx = Some(i);
            break;
        }
    }
    if let Some(bi) = block_idx {
        // IPC_NOWAIT is honored per the operation that would block.
        if ops[bi].flg as i32 & IPC_NOWAIT != 0 {
            return EAGAIN;
        }
        s.waiters.push(pid);
        return park_current();
    }

    // Apply all ops atomically.
    for op in &ops {
        let idx = op.num as usize;
        s.vals[idx] += op.op as i32;
        if s.vals[idx] > SEMVMX {
            s.vals[idx] = SEMVMX;
        }
        s.pids[idx] = pid;
    }
    s.otime = now_secs();
    // An increment may unblock other waiters; wake them to re-check.
    let raised = ops.iter().any(|o| o.op > 0);
    let wake: Vec<i32> = if raised {
        core::mem::take(&mut s.waiters)
    } else {
        Vec::new()
    };
    drop(t);
    wake_pids(&wake);
    0
}

pub fn sys_semctl(semid: i32, semnum: i32, cmd: i32, arg: usize) -> isize {
    let mut t = SEM.lock();
    let id = match cmd {
        SEM_STAT | SEM_STAT_ANY => match t.sets.values().nth(semid as usize) {
            Some(s) => s.semid,
            None => return EINVAL,
        },
        _ => semid,
    };
    match cmd {
        IPC_RMID => {
            let Some(mut s) = t.sets.remove(&id) else { return EINVAL };
            t.by_key.remove(&s.key);
            let wake = core::mem::take(&mut s.waiters);
            drop(t);
            wake_pids(&wake);
            0
        }
        GETVAL => {
            let Some(s) = t.sets.get(&id) else { return EINVAL };
            match s.vals.get(semnum as usize) {
                Some(&v) => v as isize,
                None => EINVAL,
            }
        }
        SETVAL => {
            let val = arg as i32;
            if val < 0 || val > SEMVMX {
                return ERANGE;
            }
            let Some(s) = t.sets.get_mut(&id) else { return EINVAL };
            let Some(slot) = s.vals.get_mut(semnum as usize) else { return EINVAL };
            *slot = val;
            s.pids[semnum as usize] = crate::task::current_pid();
            s.ctime = now_secs();
            let wake = core::mem::take(&mut s.waiters);
            drop(t);
            wake_pids(&wake);
            0
        }
        GETPID => {
            let Some(s) = t.sets.get(&id) else { return EINVAL };
            s.pids.get(semnum as usize).map(|&p| p as isize).unwrap_or(EINVAL)
        }
        GETNCNT | GETZCNT => {
            // We don't track per-semaphore wait counts precisely; report 0.
            if t.sets.contains_key(&id) { 0 } else { EINVAL }
        }
        GETALL => {
            let Some(s) = t.sets.get(&id) else { return EINVAL };
            let mut out = Vec::with_capacity(s.vals.len() * 2);
            for &v in &s.vals {
                out.extend_from_slice(&(v as u16).to_le_bytes());
            }
            drop(t);
            if crate::task::current_task().copy_out_bytes(arg, &out).is_none() {
                return EFAULT;
            }
            0
        }
        SETALL => {
            let n = match t.sets.get(&id) {
                Some(s) => s.vals.len(),
                None => return EINVAL,
            };
            let Some(raw) = crate::task::current_task().copy_in_bytes(arg, n * 2) else {
                return EFAULT;
            };
            let s = t.sets.get_mut(&id).unwrap();
            for i in 0..n {
                s.vals[i] = u16::from_le_bytes(raw[i * 2..i * 2 + 2].try_into().unwrap()) as i32;
            }
            s.ctime = now_secs();
            let wake = core::mem::take(&mut s.waiters);
            drop(t);
            wake_pids(&wake);
            0
        }
        IPC_STAT | SEM_STAT | SEM_STAT_ANY => {
            let Some(s) = t.sets.get(&id) else { return EINVAL };
            let bytes = encode_semid_ds(s);
            drop(t);
            if crate::task::current_task().copy_out_bytes(arg, &bytes).is_none() {
                return EFAULT;
            }
            if cmd == IPC_STAT { 0 } else { id as isize }
        }
        IPC_SET => {
            let Some(bytes) = crate::task::current_task().copy_in_bytes(arg, SEMID_DS_LEN) else {
                return EFAULT;
            };
            let Some(s) = t.sets.get_mut(&id) else { return EINVAL };
            s.uid = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
            s.gid = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
            s.mode = u32::from_le_bytes(bytes[20..24].try_into().unwrap()) & 0o777;
            s.ctime = now_secs();
            0
        }
        _ => EINVAL,
    }
}

const SEMID_DS_LEN: usize = 88;

/// asm-generic `struct semid64_ds` (88 bytes): perm[0..48], otime[48],
/// ctime[56], nsems[64], pad[72], pad[80].
fn encode_semid_ds(s: &SemSet) -> [u8; SEMID_DS_LEN] {
    let mut b = [0u8; SEMID_DS_LEN];
    write_ipc_perm(&mut b, s.key, s.uid, s.gid, s.cuid, s.cgid, s.mode);
    b[48..56].copy_from_slice(&s.otime.to_le_bytes());
    b[56..64].copy_from_slice(&s.ctime.to_le_bytes());
    b[64..72].copy_from_slice(&(s.vals.len() as u64).to_le_bytes());
    b
}
