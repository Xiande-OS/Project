//! fsnotify backend shared by inotify (and later fanotify).
//!
//! A global list of watch groups. Each group holds watches (an inode +
//! interest mask, keyed by a watch descriptor) and a queue of pending
//! events. Filesystem operations in the syscall layer call [`report`] after
//! they succeed; it fans the event out to every group watching the affected
//! object (the object itself, and/or its parent directory with the child's
//! name). `read(2)` on the inotify fd drains the queue as packed
//! `struct inotify_event` records, blocking until an event arrives.
//!
//! Inode identity is the `Arc<dyn Inode>` pointer. tmpfs (where LTP's
//! inotify cases run, under the tmpfs tmpdir) hands out a stable cached Arc
//! per name, so a watch added on a path matches the same Arc seen at the
//! operation site.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering};

use crate::sync::Mutex;
use super::{Inode, Result};

/// Total active watches across all groups. The fs-op hooks call [`report`]
/// on every read/write/open/…; when nothing is being watched (the common
/// case) this lets report() bail out before taking any lock.
static WATCH_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Fast check for the op hooks: is anything being watched at all?
#[inline]
pub fn active() -> bool {
    WATCH_COUNT.load(Ordering::Relaxed) > 0
}

/// Max queued events per group (Linux's default max_queued_events). Bounds
/// per-group memory so a reader that stops draining can't leak the kernel.
const EVENT_QUEUE_CAP: usize = 16384;

/// A fresh nonzero cookie tying an IN_MOVED_FROM to its IN_MOVED_TO.
static MOVE_COOKIE: AtomicU32 = AtomicU32::new(1);
pub fn next_cookie() -> u32 {
    MOVE_COOKIE.fetch_add(1, Ordering::Relaxed).max(1)
}

// inotify / fanotify shared event bits (the inotify ABI values).
pub const IN_ACCESS: u32 = 0x0000_0001;
pub const IN_MODIFY: u32 = 0x0000_0002;
pub const IN_ATTRIB: u32 = 0x0000_0004;
pub const IN_CLOSE_WRITE: u32 = 0x0000_0008;
pub const IN_CLOSE_NOWRITE: u32 = 0x0000_0010;
pub const IN_OPEN: u32 = 0x0000_0020;
pub const IN_MOVED_FROM: u32 = 0x0000_0040;
pub const IN_MOVED_TO: u32 = 0x0000_0080;
pub const IN_CREATE: u32 = 0x0000_0100;
pub const IN_DELETE: u32 = 0x0000_0200;
pub const IN_DELETE_SELF: u32 = 0x0000_0400;
pub const IN_MOVE_SELF: u32 = 0x0000_0800;
pub const IN_UNMOUNT: u32 = 0x0000_2000;
pub const IN_Q_OVERFLOW: u32 = 0x0000_4000;
pub const IN_IGNORED: u32 = 0x0000_8000;
pub const IN_ISDIR: u32 = 0x4000_0000;

// add_watch flags (high bits of the mask argument).
pub const IN_ONLYDIR: u32 = 0x0100_0000;
pub const IN_DONT_FOLLOW: u32 = 0x0200_0000;
pub const IN_MASK_ADD: u32 = 0x2000_0000;
pub const IN_ONESHOT: u32 = 0x8000_0000;
pub const IN_MASK_CREATE: u32 = 0x1000_0000;

/// Events that are valid to report/store (the bits the watch mask selects on).
const IN_ALL_EVENTS: u32 = IN_ACCESS
    | IN_MODIFY
    | IN_ATTRIB
    | IN_CLOSE_WRITE
    | IN_CLOSE_NOWRITE
    | IN_OPEN
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_CREATE
    | IN_DELETE
    | IN_DELETE_SELF
    | IN_MOVE_SELF;

struct Watch {
    wd: i32,
    inode: Arc<dyn Inode>,
    mask: u32,
}

struct InEvent {
    wd: i32,
    mask: u32,
    cookie: u32,
    name: Option<String>,
}

pub struct InotifyGroup {
    watches: Mutex<Vec<Watch>>,
    next_wd: AtomicI32,
    events: Mutex<VecDeque<InEvent>>,
    read_waiters: Mutex<Vec<i32>>,
    pub nonblock: bool,
}

static GROUPS: Mutex<Vec<Weak<InotifyGroup>>> = Mutex::new(Vec::new());

impl InotifyGroup {
    pub fn new(nonblock: bool) -> Arc<Self> {
        let g = Arc::new(Self {
            watches: Mutex::new(Vec::new()),
            next_wd: AtomicI32::new(1),
            events: Mutex::new(VecDeque::new()),
            read_waiters: Mutex::new(Vec::new()),
            nonblock,
        });
        GROUPS.lock().push(Arc::downgrade(&g));
        // Drop dead group slots opportunistically so the registry can't grow
        // without bound over a long run that opens many inotify fds.
        GROUPS.lock().retain(|w| w.strong_count() > 0);
        g
    }

    /// inotify_add_watch: add or update a watch on `inode`. Returns the wd.
    pub fn add_watch(&self, inode: Arc<dyn Inode>, mask: u32) -> i32 {
        let eff = mask & (IN_ALL_EVENTS | IN_ISDIR);
        let mut w = self.watches.lock();
        for watch in w.iter_mut() {
            if Arc::ptr_eq(&watch.inode, &inode) {
                watch.mask = if mask & IN_MASK_ADD != 0 {
                    watch.mask | eff
                } else {
                    eff
                };
                return watch.wd;
            }
        }
        let wd = self.next_wd.fetch_add(1, Ordering::Relaxed);
        w.push(Watch { wd, inode, mask: eff });
        WATCH_COUNT.fetch_add(1, Ordering::Relaxed);
        wd
    }

    /// inotify_rm_watch: drop a watch and queue its IN_IGNORED.
    pub fn rm_watch(&self, wd: i32) -> bool {
        let mut w = self.watches.lock();
        let before = w.len();
        w.retain(|x| x.wd != wd);
        let removed = w.len() != before;
        drop(w);
        if removed {
            WATCH_COUNT.fetch_sub(1, Ordering::Relaxed);
            self.push_event(InEvent { wd, mask: IN_IGNORED, cookie: 0, name: None });
        }
        removed
    }

    fn push_event(&self, e: InEvent) {
        {
            let mut q = self.events.lock();
            // Coalesce an identical consecutive event (inotify does this for
            // back-to-back duplicates with no intervening read).
            if let Some(last) = q.back() {
                if last.wd == e.wd && last.mask == e.mask && last.name == e.name {
                    return;
                }
            }
            // Bounded queue (Linux's max_queued_events): on overflow, keep a
            // single IN_Q_OVERFLOW marker instead of growing without bound — a
            // reader that stops draining must not be able to leak the kernel.
            if q.len() >= EVENT_QUEUE_CAP {
                if let Some(last) = q.back() {
                    if last.mask == IN_Q_OVERFLOW {
                        return;
                    }
                }
                q.push_back(InEvent { wd: -1, mask: IN_Q_OVERFLOW, cookie: 0, name: None });
                return;
            }
            q.push_back(e);
        }
        self.wake_readers();
    }

    fn wake_readers(&self) {
        let waiters: Vec<i32> = core::mem::take(&mut self.read_waiters.lock());
        for pid in waiters {
            if let Some(t) = crate::task::task_by_pid(pid) {
                let mut s = t.state.lock();
                if *s == crate::task::TaskState::Waiting {
                    *s = crate::task::TaskState::Ready;
                }
            }
        }
    }

    pub fn add_read_waiter(&self, pid: i32) {
        let mut w = self.read_waiters.lock();
        if !w.contains(&pid) {
            w.push(pid);
        }
    }

    pub fn has_events(&self) -> bool {
        !self.events.lock().is_empty()
    }

    /// Serialize as many queued events as fit into `buf` as packed
    /// `struct inotify_event { i32 wd; u32 mask; u32 cookie; u32 len; char name[len]; }`.
    /// Returns bytes written (0 if the queue is empty).
    pub fn read_events(&self, buf: &mut [u8]) -> usize {
        let mut q = self.events.lock();
        let mut off = 0usize;
        while let Some(e) = q.front() {
            let name_len = e.name.as_ref().map_or(0, |n| n.len());
            let padded = if name_len == 0 { 0 } else { (name_len + 1 + 3) & !3 };
            let rec = 16 + padded;
            if off + rec > buf.len() {
                break;
            }
            let e = q.pop_front().unwrap();
            buf[off..off + 4].copy_from_slice(&e.wd.to_le_bytes());
            buf[off + 4..off + 8].copy_from_slice(&e.mask.to_le_bytes());
            buf[off + 8..off + 12].copy_from_slice(&e.cookie.to_le_bytes());
            buf[off + 12..off + 16].copy_from_slice(&(padded as u32).to_le_bytes());
            if let Some(n) = &e.name {
                buf[off + 16..off + 16 + n.len()].copy_from_slice(n.as_bytes());
                for b in &mut buf[off + 16 + n.len()..off + rec] {
                    *b = 0;
                }
            }
            off += rec;
        }
        off
    }
}

impl Drop for InotifyGroup {
    fn drop(&mut self) {
        // Account for any watches still live when the fd is closed.
        let n = self.watches.lock().len();
        if n > 0 {
            WATCH_COUNT.fetch_sub(n, Ordering::Relaxed);
        }
    }
}

/// Report a filesystem event. `target` is the affected object (for self
/// events like IN_MODIFY/IN_ATTRIB/IN_DELETE_SELF); `parent` is its
/// directory (for child events, reported with `name`). Either may be None.
/// `is_dir` sets IN_ISDIR. Called from the syscall layer after the op
/// succeeds — defensive (brief locks, never panics) so it can't disturb the
/// operation it observes.
pub fn report(
    target: Option<&Arc<dyn Inode>>,
    parent: Option<&Arc<dyn Inode>>,
    name: &str,
    mask: u32,
    cookie: u32,
    is_dir: bool,
) {
    if !active() {
        return;
    }
    // Fan to fanotify groups too (basic event bits share inotify's values).
    report_fanotify(target, parent, name, mask as u64, is_dir);
    // Snapshot live inotify groups, then release the registry lock before
    // touching any group (avoids holding two locks across the fan-out).
    let groups: Vec<Arc<InotifyGroup>> = {
        let g = GROUPS.lock();
        g.iter().filter_map(|w| w.upgrade()).collect()
    };
    if groups.is_empty() {
        return;
    }
    // IN_ISDIR is added for directory events EXCEPT the self/meta events
    // (IN_DELETE_SELF / IN_MOVE_SELF / IN_IGNORED carry no IN_ISDIR).
    let self_ev = mask & (IN_DELETE_SELF | IN_MOVE_SELF) != 0;
    let dirbit = if is_dir && !self_ev { IN_ISDIR } else { 0 };
    for g in groups {
        // Decide what to queue without holding the watches lock across push.
        let mut to_queue: Vec<InEvent> = Vec::new();
        {
            let watches = g.watches.lock();
            for w in watches.iter() {
                if w.mask & mask == 0 {
                    continue;
                }
                if let Some(t) = target {
                    if Arc::ptr_eq(&w.inode, t) {
                        to_queue.push(InEvent {
                            wd: w.wd,
                            mask: mask | dirbit,
                            cookie,
                            name: None,
                        });
                    }
                }
                if let Some(p) = parent {
                    if Arc::ptr_eq(&w.inode, p) {
                        to_queue.push(InEvent {
                            wd: w.wd,
                            mask: mask | dirbit,
                            cookie,
                            name: if name.is_empty() {
                                None
                            } else {
                                Some(String::from(name))
                            },
                        });
                    }
                }
            }
        }
        for e in to_queue {
            g.push_event(e);
        }
    }
}

/// The watched object was deleted (or unmounted). After the caller has
/// reported IN_DELETE_SELF, auto-remove every watch on it and fire the
/// terminating IN_IGNORED — Linux drops a watch when its object goes away.
pub fn inode_gone(inode: &Arc<dyn Inode>) {
    if !active() {
        return;
    }
    let groups: Vec<Arc<InotifyGroup>> = {
        let g = GROUPS.lock();
        g.iter().filter_map(|w| w.upgrade()).collect()
    };
    for g in groups {
        let mut gone_wds: Vec<i32> = Vec::new();
        {
            let mut watches = g.watches.lock();
            watches.retain(|w| {
                if Arc::ptr_eq(&w.inode, inode) {
                    gone_wds.push(w.wd);
                    false
                } else {
                    true
                }
            });
        }
        for wd in gone_wds {
            WATCH_COUNT.fetch_sub(1, Ordering::Relaxed);
            g.push_event(InEvent { wd, mask: IN_IGNORED, cookie: 0, name: None });
        }
    }
}

/// The fd returned by inotify_init: reading it drains the group's events.
pub struct InotifyFd {
    pub group: Arc<InotifyGroup>,
}

impl Inode for InotifyFd {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn kind(&self) -> super::FileType {
        super::FileType::Pipe
    }
    fn size(&self) -> u64 {
        0
    }
    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> Result<usize> {
        // Non-blocking at the inode level: return what's queued (0 if empty).
        // sys_read parks the caller on an empty queue for the blocking case.
        Ok(self.group.read_events(buf))
    }
}

// ===================== fanotify =====================
//
// Built on the same op hooks: report() also fans events to fanotify groups.
// The basic notification mask bits share inotify's values (FAN_ACCESS=0x1,
// FAN_MODIFY=0x2, FAN_CLOSE_WRITE=0x8, FAN_CLOSE_NOWRITE=0x10, FAN_OPEN=0x20),
// so the hooks need no new plumbing. A fanotify event carries an *open fd* to
// the affected object (allocated in the reader at read time), not a name.

pub const FAN_ACCESS: u64 = 0x0000_0001;
pub const FAN_MODIFY: u64 = 0x0000_0002;
pub const FAN_CLOSE_WRITE: u64 = 0x0000_0008;
pub const FAN_CLOSE_NOWRITE: u64 = 0x0000_0010;
pub const FAN_OPEN: u64 = 0x0000_0020;
pub const FAN_ONDIR: u64 = 0x4000_0000;
pub const FAN_EVENT_ON_CHILD: u64 = 0x0800_0000;

// fanotify_mark flags
pub const FAN_MARK_ADD: u32 = 0x0000_0001;
pub const FAN_MARK_REMOVE: u32 = 0x0000_0002;
pub const FAN_MARK_FLUSH: u32 = 0x0000_0080;
pub const FAN_MARK_MOUNT: u32 = 0x0000_0010;
pub const FAN_MARK_FILESYSTEM: u32 = 0x0000_0100;

const FANOTIFY_METADATA_VERSION: u8 = 3;

struct FanMark {
    inode: Arc<dyn Inode>,
    mask: u64,
    /// Ignore mask: events in this set are suppressed for this object
    /// (FAN_MARK_IGNORED_MASK). fanotify10 checks that inode + mount ignore
    /// masks merge correctly.
    ignore_mask: u64,
    mount: bool, // a mount/filesystem-wide mark: matches any object
}

struct FanEvent {
    mask: u64,
    // The object whose file handle this event reports. In FID mode that's the
    // affected object; in DFID/DFID_NAME mode it's the parent directory.
    // Weak so a queued event never keeps it (or a tmpfs file's data) alive
    // after deletion — a stale event is dropped at read time.
    inode: Weak<dyn Inode>,
    // Entry name for DFID_NAME events (None for FID/DFID self events).
    name: Option<String>,
}

pub struct FanotifyGroup {
    marks: Mutex<Vec<FanMark>>,
    events: Mutex<VecDeque<FanEvent>>,
    read_waiters: Mutex<Vec<i32>>,
    pub nonblock: bool,
    /// FAN_REPORT_FID: events carry the affected object's file handle.
    pub report_fid: bool,
    /// FAN_REPORT_DIR_FID: events carry the PARENT directory's file handle.
    pub report_dir_fid: bool,
    /// FAN_REPORT_NAME (with DIR_FID = FAN_REPORT_DFID_NAME): also the name.
    pub report_name: bool,
}

static FAN_GROUPS: Mutex<Vec<Weak<FanotifyGroup>>> = Mutex::new(Vec::new());

impl FanotifyGroup {
    pub fn new(nonblock: bool, report_fid: bool, report_dir_fid: bool, report_name: bool) -> Arc<Self> {
        let g = Arc::new(Self {
            marks: Mutex::new(Vec::new()),
            events: Mutex::new(VecDeque::new()),
            read_waiters: Mutex::new(Vec::new()),
            nonblock,
            report_fid,
            report_dir_fid,
            report_name,
        });
        let mut reg = FAN_GROUPS.lock();
        reg.retain(|w| w.strong_count() > 0);
        reg.push(Arc::downgrade(&g));
        g
    }
    /// Any FID-family reporting (FID, DFID, or DFID_NAME).
    pub fn any_fid(&self) -> bool {
        self.report_fid || self.report_dir_fid
    }

    /// Snapshot of marks for /proc/<pid>/fdinfo/<fd>: (mask, ignore_mask,
    /// mount, ino). fanotify10's show_fanotify_ignore_marks() opens fdinfo and
    /// counts the inode marks whose ignored_mask is non-zero.
    pub fn fdinfo_marks(&self) -> Vec<(u64, u64, bool, u64)> {
        self.marks
            .lock()
            .iter()
            .map(|m| {
                let ino = Arc::as_ptr(&m.inode) as *const () as u64;
                (m.mask, m.ignore_mask, m.mount, ino)
            })
            .collect()
    }

    pub fn add_mark(&self, inode: Arc<dyn Inode>, mask: u64, mount: bool, ignore: bool) {
        let mut m = self.marks.lock();
        for mk in m.iter_mut() {
            if Arc::ptr_eq(&mk.inode, &inode) && mk.mount == mount {
                if ignore {
                    mk.ignore_mask |= mask;
                } else {
                    mk.mask |= mask;
                }
                return;
            }
        }
        let (mask, ignore_mask) = if ignore { (0, mask) } else { (mask, 0) };
        m.push(FanMark { inode, mask, ignore_mask, mount });
        WATCH_COUNT.fetch_add(1, Ordering::Relaxed);
    }

    pub fn remove_mark(&self, inode: &Arc<dyn Inode>, mask: u64, mount: bool) {
        let mut m = self.marks.lock();
        let mut removed = 0;
        m.retain_mut(|mk| {
            if Arc::ptr_eq(&mk.inode, inode) && mk.mount == mount {
                mk.mask &= !mask;
                if mk.mask == 0 {
                    removed += 1;
                    return false;
                }
            }
            true
        });
        if removed > 0 {
            WATCH_COUNT.fetch_sub(removed, Ordering::Relaxed);
        }
    }

    pub fn flush(&self, mount: bool) {
        let mut m = self.marks.lock();
        let before = m.len();
        m.retain(|mk| mk.mount != mount);
        let removed = before - m.len();
        if removed > 0 {
            WATCH_COUNT.fetch_sub(removed, Ordering::Relaxed);
        }
    }

    fn push_event(&self, e: FanEvent) {
        {
            let mut q = self.events.lock();
            // Coalesce with the most-recent unread event on the SAME object by
            // OR-ing the masks — fanotify merges e.g. FAN_OPEN then
            // FAN_CLOSE_NOWRITE on one object into a single mask=0x30 event
            // (fanotify13 checks this). Distinct objects stay separate.
            if let Some(last) = q.back_mut() {
                if Weak::ptr_eq(&last.inode, &e.inode) && last.name == e.name {
                    last.mask |= e.mask;
                    return;
                }
            }
            // Bounded queue: drop new events past the cap (a stalled reader
            // must not grow the queue without bound).
            if q.len() >= EVENT_QUEUE_CAP {
                return;
            }
            q.push_back(e);
        }
        let waiters: Vec<i32> = core::mem::take(&mut self.read_waiters.lock());
        for pid in waiters {
            if let Some(t) = crate::task::task_by_pid(pid) {
                let mut s = t.state.lock();
                if *s == crate::task::TaskState::Waiting {
                    *s = crate::task::TaskState::Ready;
                }
            }
        }
    }

    pub fn add_read_waiter(&self, pid: i32) {
        let mut w = self.read_waiters.lock();
        if !w.contains(&pid) {
            w.push(pid);
        }
    }
    pub fn has_events(&self) -> bool {
        !self.events.lock().is_empty()
    }

    /// Pack as many queued events as fit, allocating an fd to each object in
    /// the calling process. Returns bytes written.
    pub fn read_events(&self, buf: &mut [u8]) -> usize {
        const META: usize = 24;
        let task = crate::task::current_task();
        let mut off = 0usize;
        loop {
            if off + META > buf.len() {
                break;
            }
            let ev = {
                let mut q = self.events.lock();
                q.pop_front()
            };
            let Some(ev) = ev else { break };
            // Upgrade the weak target; a stale event (object already freed)
            // is dropped — an fd/handle to a deleted file is useless anyway.
            let Some(inode) = ev.inode.upgrade() else { continue };
            if self.any_fid() {
                // FID family: metadata (fd = FAN_NOFD) + a
                // fanotify_event_info_fid record. info_type is DFID_NAME(2)
                // when a name is reported, DFID(3) for dir-fid only, else
                // FID(1). The handle bytes are the reported object's st_ino
                // (== Arc pointer == name_to_handle_at(2)'s handle). Layout:
                //   hdr(4): info_type(u8), pad(u8), len(u16)
                //   fsid(8) = 0 (matches our statfs f_fsid)
                //   file_handle: handle_bytes(u32)=8, handle_type(i32)=1,
                //                f_handle[8] = st_ino
                //   name[]: for DFID_NAME, NUL-terminated, right after f_handle
                let st_ino = Arc::as_ptr(&inode) as *const () as u64;
                let with_name = self.report_name && ev.name.is_some();
                let info_type: u8 = if with_name {
                    2 // FAN_EVENT_INFO_TYPE_DFID_NAME
                } else if self.report_dir_fid {
                    3 // FAN_EVENT_INFO_TYPE_DFID
                } else {
                    1 // FAN_EVENT_INFO_TYPE_FID
                };
                let nm: &[u8] = if with_name {
                    ev.name.as_deref().unwrap().as_bytes()
                } else {
                    &[]
                };
                let name_field = if with_name { nm.len() + 1 } else { 0 };
                let info_len = (4 + 8 + 16 + name_field + 3) & !3; // 4-byte aligned
                let total = META + info_len;
                if off + total > buf.len() {
                    self.events.lock().push_front(ev);
                    break;
                }
                const FAN_NOFD: i32 = -1;
                buf[off..off + 4].copy_from_slice(&(total as u32).to_le_bytes());
                buf[off + 4] = FANOTIFY_METADATA_VERSION;
                buf[off + 5] = 0;
                buf[off + 6..off + 8].copy_from_slice(&(META as u16).to_le_bytes());
                buf[off + 8..off + 16].copy_from_slice(&ev.mask.to_le_bytes());
                buf[off + 16..off + 20].copy_from_slice(&FAN_NOFD.to_le_bytes());
                buf[off + 20..off + 24].copy_from_slice(&(task.pid).to_le_bytes());
                let i = off + META;
                for b in &mut buf[i..off + total] {
                    *b = 0; // zero hdr pad + fsid + name padding
                }
                buf[i] = info_type;
                buf[i + 2..i + 4].copy_from_slice(&(info_len as u16).to_le_bytes());
                // fsid at i+4..i+12 stays 0
                buf[i + 12..i + 16].copy_from_slice(&8u32.to_le_bytes());
                buf[i + 16..i + 20].copy_from_slice(&1i32.to_le_bytes());
                buf[i + 20..i + 28].copy_from_slice(&st_ino.to_le_bytes());
                if with_name {
                    buf[i + 28..i + 28 + nm.len()].copy_from_slice(nm);
                }
                off += total;
                continue;
            }
            // Default (notification) mode: open an fd to the object.
            let file = Arc::new(crate::fs::File::from_inode(inode, true, false, false));
            let fd = match task.fd_table.lock().alloc(file, false) {
                Ok(fd) => fd as i32,
                Err(_) => -1,
            };
            buf[off..off + 4].copy_from_slice(&(META as u32).to_le_bytes());
            buf[off + 4] = FANOTIFY_METADATA_VERSION;
            buf[off + 5] = 0;
            buf[off + 6..off + 8].copy_from_slice(&(META as u16).to_le_bytes());
            buf[off + 8..off + 16].copy_from_slice(&ev.mask.to_le_bytes());
            buf[off + 16..off + 20].copy_from_slice(&fd.to_le_bytes());
            buf[off + 20..off + 24].copy_from_slice(&(task.pid).to_le_bytes());
            off += META;
        }
        off
    }
}

impl Drop for FanotifyGroup {
    fn drop(&mut self) {
        let n = self.marks.lock().len();
        if n > 0 {
            WATCH_COUNT.fetch_sub(n, Ordering::Relaxed);
        }
    }
}

/// Fan a filesystem event to fanotify groups. Called from [`report`].
fn report_fanotify(
    target: Option<&Arc<dyn Inode>>,
    parent: Option<&Arc<dyn Inode>>,
    name: &str,
    mask: u64,
    is_dir: bool,
) {
    let groups: Vec<Arc<FanotifyGroup>> = {
        let g = FAN_GROUPS.lock();
        g.iter().filter_map(|w| w.upgrade()).collect()
    };
    if groups.is_empty() {
        return;
    }
    for g in groups {
        let mut report_bits = 0u64;
        let mut ignore_bits = 0u64;
        {
            let marks = g.marks.lock();
            for mk in marks.iter() {
                // A mount/fs mark matches any object; an inode mark matches its
                // own inode whether it's the target or the parent dir.
                let matches_obj = mk.mount
                    || target.map_or(false, |t| Arc::ptr_eq(&mk.inode, t))
                    || parent.map_or(false, |p| Arc::ptr_eq(&mk.inode, p));
                if !matches_obj {
                    continue;
                }
                // For a directory event, a mark participates only if it asked
                // for FAN_ONDIR (in its report or ignore set).
                if is_dir && (mk.mask | mk.ignore_mask) & FAN_ONDIR == 0 {
                    continue;
                }
                report_bits |= mk.mask & mask;
                ignore_bits |= mk.ignore_mask & mask;
            }
        }
        // fanotify reports the bits a mark requested minus the bits an
        // (merged inode + mount) ignore mask suppresses — fanotify10's check.
        let m = report_bits & !ignore_bits;
        if m == 0 {
            continue;
        }
        // Which object's handle the event reports, and whether to attach the
        // name: DFID/DFID_NAME report the parent directory; FID (and the
        // legacy fd mode) report the affected object itself.
        let (fid_obj, ev_name) = if g.report_dir_fid {
            let p = parent.or(target);
            let nm = if g.report_name && !name.is_empty() {
                Some(String::from(name))
            } else {
                None
            };
            (p, nm)
        } else {
            (target.or(parent), None)
        };
        if let Some(fo) = fid_obj {
            // FAN_ONDIR (== IN_ISDIR bit) when the affected entry is a
            // directory — fanotify16 checks e.g. 0x40000100 for creating a dir.
            let em = if is_dir { m | FAN_ONDIR } else { m };
            g.push_event(FanEvent {
                mask: em,
                inode: Arc::downgrade(fo),
                name: ev_name,
            });
        }
    }
}

/// The fd returned by fanotify_init.
pub struct FanotifyFd {
    pub group: Arc<FanotifyGroup>,
}

impl Inode for FanotifyFd {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn kind(&self) -> super::FileType {
        super::FileType::Pipe
    }
    fn size(&self) -> u64 {
        0
    }
    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> Result<usize> {
        Ok(self.group.read_events(buf))
    }
}
