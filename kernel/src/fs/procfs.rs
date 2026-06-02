//! /proc: dynamic per-process and system-wide pseudo-filesystem.
//!
//! Every file is generated on demand by the closure stored in `ProcGenFile`,
//! so the data you `cat` is always fresh (no caching, no stale state).
//! Directories list their children dynamically: `/proc` enumerates live
//! pids on each list/lookup, and each `/proc/<pid>` exposes the standard
//! Linux per-process set (cmdline, exe, maps, status, stat, comm, cwd, fd/).
//!
//! Mount at boot time with `procfs::mount("/proc")` after `fs::init()`.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Once;

use super::{FileType, Inode, Result, EINVAL, ENOENT};

/// Boot mtime (CSR `time` units, 10 MHz on QEMU virt). Captured the first
/// time procfs is asked. Used by /proc/uptime and /proc/stat:btime.
static BOOT_MTIME: AtomicU64 = AtomicU64::new(0);

fn now_mtime() -> u64 {
    crate::arch::now_ticks()
}

fn boot_mtime() -> u64 {
    BOOT_MTIME.load(Ordering::Relaxed)
}

fn seconds_since_boot() -> u64 {
    let now = now_mtime();
    let base = boot_mtime();
    now.saturating_sub(base) / 10_000_000
}

fn centiseconds_since_boot() -> u64 {
    let now = now_mtime();
    let base = boot_mtime();
    (now.saturating_sub(base) / 100_000) % 100
}

/// Generic dynamic file: every `read_at` regenerates the contents.
pub struct ProcGenFile {
    gen: Box<dyn Fn() -> Vec<u8> + Send + Sync>,
}

impl ProcGenFile {
    fn new<F>(f: F) -> Arc<Self>
    where
        F: Fn() -> Vec<u8> + Send + Sync + 'static,
    {
        Arc::new(Self { gen: Box::new(f) })
    }
}

impl Inode for ProcGenFile {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn kind(&self) -> FileType {
        FileType::Regular
    }
    fn size(&self) -> u64 {
        (self.gen)().len() as u64
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let data = (self.gen)();
        let off = offset as usize;
        if off >= data.len() {
            return Ok(0);
        }
        let n = core::cmp::min(buf.len(), data.len() - off);
        buf[..n].copy_from_slice(&data[off..off + n]);
        Ok(n)
    }
    // NB: deliberately no write_at. The default (EINVAL) is what tst_memutils
    // and tst_sys_conf expect when a tunable can't be set — they fall back
    // gracefully. Accepting-and-ignoring writes instead made the framework's
    // oom_score_adj write "succeed" then fail its -1000 readback → TBROK in
    // every memory-protected test. A tunable that needs real write semantics
    // (e.g. oom_score_adj) must store per-process state, not blanket-accept.
}

/// A small procfs file that reports fixed content but ACCEPTS writes (the
/// bytes are discarded). Unlike the blanket writable ProcGenFile that
/// regressed oom_score_adj, this is opted into ONLY for the userns setup files
/// (setgroups / uid_map / gid_map) whose tests merely need the write to
/// succeed — they never read the value back expecting their own input.
pub struct ProcWritableFile {
    content: alloc::vec::Vec<u8>,
}
impl ProcWritableFile {
    fn new(content: &[u8]) -> Arc<Self> {
        Arc::new(Self { content: content.to_vec() })
    }
}
impl Inode for ProcWritableFile {
    fn as_any(&self) -> &dyn Any { self }
    fn kind(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { self.content.len() as u64 }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let off = offset as usize;
        if off >= self.content.len() { return Ok(0); }
        let n = core::cmp::min(buf.len(), self.content.len() - off);
        buf[..n].copy_from_slice(&self.content[off..off + n]);
        Ok(n)
    }
    fn write_at(&self, _offset: u64, buf: &[u8]) -> Result<usize> {
        Ok(buf.len()) // accept and discard — the userns setup just needs success
    }
    fn truncate(&self, _len: u64) -> Result<()> { Ok(()) }
}

/// /proc/<pid>/ns — one pseudo-file per namespace type. The ioctl_ns0* cases
/// and the setns/unshare/clock_gettime03 setups open these just to obtain an
/// fd referring to "the namespace"; we have a single global namespace, so each
/// is a tiny readable file (its bytes are never interpreted — only the open
/// and subsequent ioctl/setns matter, which we accept).
pub struct ProcNsDir {
    pid: i32,
}
impl Inode for ProcNsDir {
    fn as_any(&self) -> &dyn Any { self }
    fn kind(&self) -> FileType { FileType::Directory }
    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>> {
        match name {
            "mnt" | "pid" | "pid_for_children" | "net" | "ipc" | "uts" | "user"
            | "cgroup" | "time" | "time_for_children" => {
                let id = self.pid as u64;
                Ok(ProcGenFile::new(move || alloc::format!("ns:[{}]\n", 4026531840u64 + id).into_bytes()))
            }
            _ => Err(ENOENT),
        }
    }
    fn list(&self) -> Result<Vec<(String, FileType)>> {
        Ok(["mnt","pid","net","ipc","uts","user","cgroup","time"]
            .iter().map(|n| ((*n).into(), FileType::Regular)).collect())
    }
}

/// Per-pid directory. Children are resolved on demand against the current
/// state of `task::task_by_pid(pid)`; if the task has exited we return
/// ENOENT just like real Linux.
pub struct ProcPidDir {
    pid: i32,
}

impl ProcPidDir {
    fn new(pid: i32) -> Arc<Self> {
        Arc::new(Self { pid })
    }

    fn task_exists(&self) -> bool {
        crate::task::task_by_pid(self.pid).is_some()
    }
}

impl Inode for ProcPidDir {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn kind(&self) -> FileType {
        FileType::Directory
    }
    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>> {
        if !self.task_exists() {
            return Err(ENOENT);
        }
        let pid = self.pid;
        match name {
            "cmdline" => Ok(ProcGenFile::new(move || gen_cmdline(pid))),
            "exe" => Ok(ProcGenFile::new(move || gen_exe(pid))),
            "maps" => Ok(ProcGenFile::new(move || gen_maps(pid))),
            "smaps" => Ok(ProcGenFile::new(move || gen_smaps(pid))),
            "status" => Ok(ProcGenFile::new(move || gen_status(pid))),
            "stat" => Ok(ProcGenFile::new(move || gen_stat(pid))),
            "cwd" => Ok(ProcGenFile::new(move || gen_cwd(pid))),
            "comm" => Ok(ProcGenFile::new(move || gen_comm(pid))),
            "fd" => Ok(Arc::new(ProcFdDir { pid }) as Arc<dyn Inode>),
            // LTP's cgroup/taint/kconfig probes open /proc/self/mounts,
            // /proc/self/cmdline, etc. The "self" path resolves to here, so
            // mirror the global proc files that some cases happen to read
            // through /proc/<pid>/... instead of /proc/<name>.
            "mounts" => Ok(ProcGenFile::new(gen_mounts)),
            "cgroup" => Ok(ProcGenFile::new(|| b"0::/\n".to_vec())),
            "limits" => Ok(ProcGenFile::new(gen_limits)),
            "oom_score" => Ok(ProcGenFile::new(|| b"0\n".to_vec())),
            "oom_score_adj" => Ok(ProcGenFile::new(|| b"0\n".to_vec())),
            // User-namespace setup files. tst_net.c (every cve-*/net case that
            // unshares a netns) writes "deny" to setgroups then maps uid/gid;
            // without these it TBROKs at setup ("Failed to open
            // /proc/self/setgroups"). We have no real userns, but a writable
            // file that accepts the write lets the test proceed.
            "setgroups" => Ok(ProcWritableFile::new(b"allow\n")),
            "uid_map" => Ok(ProcWritableFile::new(b"0 0 4294967295\n")),
            "gid_map" => Ok(ProcWritableFile::new(b"0 0 4294967295\n")),
            // /proc/self/ns/<type> — opened by ioctl_ns0*, clock_gettime03,
            // and the setns/unshare cases just to get an fd to the namespace.
            "ns" => Ok(Arc::new(ProcNsDir { pid }) as Arc<dyn Inode>),
            _ => Err(ENOENT),
        }
    }
    fn list(&self) -> Result<Vec<(String, FileType)>> {
        if !self.task_exists() {
            return Err(ENOENT);
        }
        Ok(alloc::vec![
            ("cmdline".into(), FileType::Regular),
            ("exe".into(), FileType::Regular),
            ("maps".into(), FileType::Regular),
            ("smaps".into(), FileType::Regular),
            ("status".into(), FileType::Regular),
            ("stat".into(), FileType::Regular),
            ("cwd".into(), FileType::Regular),
            ("comm".into(), FileType::Regular),
            ("fd".into(), FileType::Directory),
            ("mounts".into(), FileType::Regular),
            ("cgroup".into(), FileType::Regular),
            ("limits".into(), FileType::Regular),
            ("setgroups".into(), FileType::Regular),
            ("uid_map".into(), FileType::Regular),
            ("gid_map".into(), FileType::Regular),
            ("ns".into(), FileType::Directory),
            ("oom_score".into(), FileType::Regular),
            ("oom_score_adj".into(), FileType::Regular),
        ])
    }
}

fn gen_limits() -> Vec<u8> {
    // Plausible defaults; LTP cases use this to discover RLIMIT_NOFILE etc.
    b"Limit                     Soft Limit           Hard Limit           Units\n\
      Max open files            1024                 4096                 files\n\
      Max processes             4096                 4096                 processes\n\
      Max stack size            8388608              16777216             bytes\n"
        .to_vec()
}

/// /proc/<pid>/fd directory: lookup "<n>" gives a regular file whose contents
/// describe what that fd points at (best-effort target path).
pub struct ProcFdDir {
    pid: i32,
}

impl Inode for ProcFdDir {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn kind(&self) -> FileType {
        FileType::Directory
    }
    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>> {
        let fd: i32 = name.parse().map_err(|_| ENOENT)?;
        let task = crate::task::task_by_pid(self.pid).ok_or(ENOENT)?;
        // Verify the fd is open.
        if task.fd_table.lock().get(fd).is_none() {
            return Err(ENOENT);
        }
        let pid = self.pid;
        Ok(ProcGenFile::new(move || gen_fd_target(pid, fd)))
    }
    fn list(&self) -> Result<Vec<(String, FileType)>> {
        let task = crate::task::task_by_pid(self.pid).ok_or(ENOENT)?;
        let table = task.fd_table.lock();
        let t = table.table.lock();
        let mut out = Vec::new();
        for (i, slot) in t.iter().enumerate() {
            if slot.is_some() {
                out.push((alloc::format!("{}", i), FileType::Regular));
            }
        }
        Ok(out)
    }
}

/// Resolves at lookup time to the current task's pid directory.
pub struct ProcSelfLink;

impl Inode for ProcSelfLink {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn kind(&self) -> FileType {
        FileType::Directory
    }
    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>> {
        let pid = crate::task::current_pid();
        let dir = ProcPidDir::new(pid);
        dir.lookup(name)
    }
    fn list(&self) -> Result<Vec<(String, FileType)>> {
        let pid = crate::task::current_pid();
        ProcPidDir::new(pid).list()
    }
}

/// `/proc` root inode.
pub struct ProcRoot;

impl Inode for ProcRoot {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn kind(&self) -> FileType {
        FileType::Directory
    }
    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>> {
        if name == "self" {
            return Ok(Arc::new(ProcSelfLink) as Arc<dyn Inode>);
        }
        if let Ok(pid) = name.parse::<i32>() {
            if crate::task::task_by_pid(pid).is_some() {
                return Ok(ProcPidDir::new(pid) as Arc<dyn Inode>);
            }
            return Err(ENOENT);
        }
        match name {
            "cpuinfo" => Ok(ProcGenFile::new(gen_cpuinfo)),
            "meminfo" => Ok(ProcGenFile::new(gen_meminfo)),
            "mounts" => Ok(ProcGenFile::new(gen_mounts)),
            "version" => Ok(ProcGenFile::new(gen_version)),
            "uptime" => Ok(ProcGenFile::new(gen_uptime)),
            "filesystems" => Ok(ProcGenFile::new(gen_filesystems)),
            "stat" => Ok(ProcGenFile::new(gen_proc_stat)),
            "loadavg" => Ok(ProcGenFile::new(gen_loadavg)),
            "cmdline" => Ok(ProcGenFile::new(|| b"console=ttyS0\n".to_vec())),
            // /proc/sys/kernel/{tainted,pid_max,...} — LTP cgroup/taint/kconfig
            // probes need these or they TBROK before doing any real work.
            "sys" => Ok(Arc::new(ProcSysDir) as Arc<dyn Inode>),
            _ => Err(ENOENT),
        }
    }
    fn list(&self) -> Result<Vec<(String, FileType)>> {
        let mut out: Vec<(String, FileType)> = alloc::vec![
            ("self".into(), FileType::Directory),
            ("sys".into(), FileType::Directory),
            ("cpuinfo".into(), FileType::Regular),
            ("meminfo".into(), FileType::Regular),
            ("mounts".into(), FileType::Regular),
            ("version".into(), FileType::Regular),
            ("uptime".into(), FileType::Regular),
            ("filesystems".into(), FileType::Regular),
            ("stat".into(), FileType::Regular),
            ("loadavg".into(), FileType::Regular),
            ("cmdline".into(), FileType::Regular),
        ];
        for pid in crate::task::all_pids() {
            out.push((alloc::format!("{}", pid), FileType::Directory));
        }
        Ok(out)
    }
}

// ----- Per-pid content generators -----

fn gen_cmdline(pid: i32) -> Vec<u8> {
    if let Some(task) = crate::task::task_by_pid(pid) {
        task.cmdline.lock().clone()
    } else {
        Vec::new()
    }
}

fn gen_exe(pid: i32) -> Vec<u8> {
    if let Some(task) = crate::task::task_by_pid(pid) {
        task.exe_path.lock().clone().into_bytes()
    } else {
        Vec::new()
    }
}

fn gen_cwd(pid: i32) -> Vec<u8> {
    if let Some(task) = crate::task::task_by_pid(pid) {
        task.cwd.lock().clone().into_bytes()
    } else {
        Vec::new()
    }
}

fn gen_comm(pid: i32) -> Vec<u8> {
    if let Some(task) = crate::task::task_by_pid(pid) {
        let exe = task.exe_path.lock().clone();
        let base = exe.rsplit('/').next().unwrap_or(&exe).to_string();
        let base = if base.is_empty() { "kthread".into() } else { base };
        let mut out = base.into_bytes();
        out.push(b'\n');
        out
    } else {
        Vec::new()
    }
}

fn task_state_letter(state: crate::task::TaskState) -> char {
    use crate::task::TaskState::*;
    match state {
        Running => 'R',
        Ready => 'R',
        Waiting => 'S',
        Zombie => 'Z',
    }
}

fn gen_maps(pid: i32) -> Vec<u8> {
    let Some(task) = crate::task::task_by_pid(pid) else {
        return Vec::new();
    };
    let ms = task.memory_set.lock();
    let brk_base_vpn = ms.brk_base.0 >> crate::mm::address::PAGE_SIZE_BITS;
    // Sort areas by start VPN.
    let mut areas: Vec<(usize, usize, crate::mm::memory_set::VmPerm, bool)> = ms
        .areas
        .iter()
        .filter(|a| a.perm.contains(crate::mm::memory_set::VmPerm::U))
        .map(|a| (a.vpn_start.0, a.vpn_end.0, a.perm, a.shared))
        .collect();
    areas.sort_by_key(|&(s, _, _, _)| s);

    // Heuristic: the highest-address user area is the stack.
    let stack_start = areas.iter().map(|&(s, _, _, _)| s).max().unwrap_or(0);

    let mut out = String::new();
    for (s, e, p, shared) in &areas {
        let start = s << crate::mm::address::PAGE_SIZE_BITS;
        let end = e << crate::mm::address::PAGE_SIZE_BITS;
        let r = if p.contains(crate::mm::memory_set::VmPerm::R) { 'r' } else { '-' };
        let w = if p.contains(crate::mm::memory_set::VmPerm::W) { 'w' } else { '-' };
        let x = if p.contains(crate::mm::memory_set::VmPerm::X) { 'x' } else { '-' };
        // 4th flag: 's' for a MAP_SHARED area, 'p' (private/copy-on-write) else.
        // mmap04 maps with MAP_SHARED and greps /proc/self/maps for the 's'.
        let sh = if *shared { 's' } else { 'p' };
        let name = if *s == brk_base_vpn {
            "[heap]"
        } else if *s == stack_start {
            "[stack]"
        } else {
            ""
        };
        out.push_str(&format!(
            "{:08x}-{:08x} {}{}{}{} 00000000 00:00 0          {}\n",
            start, end, r, w, x, sh, name
        ));
    }
    out.into_bytes()
}

fn gen_smaps(pid: i32) -> Vec<u8> {
    let Some(task) = crate::task::task_by_pid(pid) else {
        return Vec::new();
    };
    let ms = task.memory_set.lock();
    let brk_base_vpn = ms.brk_base.0 >> crate::mm::address::PAGE_SIZE_BITS;
    let mut areas: Vec<(usize, usize, crate::mm::memory_set::VmPerm, usize)> = ms
        .areas
        .iter()
        .filter(|a| a.perm.contains(crate::mm::memory_set::VmPerm::U))
        .map(|a| (a.vpn_start.0, a.vpn_end.0, a.perm, a.frames.len()))
        .collect();
    areas.sort_by_key(|&(s, _, _, _)| s);
    let stack_start = areas.iter().map(|&(s, _, _, _)| s).max().unwrap_or(0);

    let mut out = String::new();
    for (s, e, p, frames) in &areas {
        let start = s << crate::mm::address::PAGE_SIZE_BITS;
        let end = e << crate::mm::address::PAGE_SIZE_BITS;
        let r = if p.contains(crate::mm::memory_set::VmPerm::R) { 'r' } else { '-' };
        let w = if p.contains(crate::mm::memory_set::VmPerm::W) { 'w' } else { '-' };
        let x = if p.contains(crate::mm::memory_set::VmPerm::X) { 'x' } else { '-' };
        let name = if *s == brk_base_vpn {
            "[heap]"
        } else if *s == stack_start {
            "[stack]"
        } else {
            ""
        };
        let size_kb = ((e - s) << crate::mm::address::PAGE_SIZE_BITS) / 1024;
        let rss_kb = (frames << crate::mm::address::PAGE_SIZE_BITS) / 1024;
        out.push_str(&format!(
            "{:08x}-{:08x} {}{}{}p 00000000 00:00 0          {}\n",
            start, end, r, w, x, name
        ));
        out.push_str(&format!("Size:           {:>8} kB\n", size_kb));
        out.push_str(&format!("Rss:            {:>8} kB\n", rss_kb));
        out.push_str(&format!("Pss:            {:>8} kB\n", rss_kb));
        out.push_str(&format!("Shared_Clean:   {:>8} kB\n", 0));
        out.push_str(&format!("Shared_Dirty:   {:>8} kB\n", 0));
        out.push_str(&format!("Private_Clean:  {:>8} kB\n", 0));
        out.push_str(&format!("Private_Dirty:  {:>8} kB\n", rss_kb));
        out.push_str(&format!("Referenced:     {:>8} kB\n", rss_kb));
        out.push_str(&format!("Anonymous:      {:>8} kB\n", rss_kb));
        out.push_str(&format!("AnonHugePages:  {:>8} kB\n", 0));
        out.push_str(&format!("Swap:           {:>8} kB\n", 0));
        out.push_str(&format!("KernelPageSize: {:>8} kB\n", 4));
        out.push_str(&format!("MMUPageSize:    {:>8} kB\n", 4));
        out.push_str(&format!("Locked:         {:>8} kB\n", 0));
        out.push_str("VmFlags: rd wr mr mw me ac \n");
    }
    out.into_bytes()
}

fn vm_size_kb(pid: i32) -> u64 {
    let Some(task) = crate::task::task_by_pid(pid) else {
        return 0;
    };
    let ms = task.memory_set.lock();
    let bytes: u64 = ms
        .areas
        .iter()
        .filter(|a| a.perm.contains(crate::mm::memory_set::VmPerm::U))
        .map(|a| ((a.vpn_end.0 - a.vpn_start.0) << crate::mm::address::PAGE_SIZE_BITS) as u64)
        .sum();
    bytes / 1024
}

fn gen_status(pid: i32) -> Vec<u8> {
    let Some(task) = crate::task::task_by_pid(pid) else {
        return Vec::new();
    };
    let exe = task.exe_path.lock().clone();
    let comm = exe.rsplit('/').next().unwrap_or(&exe).to_string();
    let state = *task.state.lock();
    let st_char = task_state_letter(state);
    let st_word = match state {
        crate::task::TaskState::Running | crate::task::TaskState::Ready => "running",
        crate::task::TaskState::Waiting => "sleeping",
        crate::task::TaskState::Zombie => "zombie",
    };
    let ppid = task.ppid.load(Ordering::Relaxed);
    let vm = vm_size_kb(pid);
    let s = format!(
        "Name:\t{}\n\
         Umask:\t0022\n\
         State:\t{} ({})\n\
         Tgid:\t{}\n\
         Ngid:\t0\n\
         Pid:\t{}\n\
         PPid:\t{}\n\
         TracerPid:\t0\n\
         Uid:\t0\t0\t0\t0\n\
         Gid:\t0\t0\t0\t0\n\
         FDSize:\t256\n\
         Groups:\t\n\
         VmSize:\t{} kB\n\
         VmRSS:\t{} kB\n\
         VmData:\t{} kB\n\
         VmStk:\t{} kB\n\
         VmExe:\t{} kB\n\
         VmLck:\t0 kB\n\
         VmPin:\t0 kB\n\
         VmHWM:\t{} kB\n\
         VmLib:\t0 kB\n\
         VmPTE:\t0 kB\n\
         VmSwap:\t0 kB\n\
         Threads:\t1\n\
         SigQ:\t0/0\n\
         SigPnd:\t0000000000000000\n\
         ShdPnd:\t0000000000000000\n\
         SigBlk:\t0000000000000000\n\
         SigIgn:\t0000000000000000\n\
         SigCgt:\t0000000000000000\n\
         CapInh:\t0000000000000000\n\
         CapPrm:\t0000000000000000\n\
         CapEff:\t0000000000000000\n\
         CapBnd:\t0000000000000000\n\
         Seccomp:\t0\n\
         Cpus_allowed:\t1\n\
         Cpus_allowed_list:\t0\n\
         voluntary_ctxt_switches:\t0\n\
         nonvoluntary_ctxt_switches:\t0\n",
        comm, st_char, st_word, pid, pid, ppid, vm, vm, vm, 64, 64, vm,
    );
    s.into_bytes()
}

fn gen_stat(pid: i32) -> Vec<u8> {
    let Some(task) = crate::task::task_by_pid(pid) else {
        return Vec::new();
    };
    let exe = task.exe_path.lock().clone();
    let comm = exe.rsplit('/').next().unwrap_or(&exe).to_string();
    let state = task_state_letter(*task.state.lock());
    let ppid = task.ppid.load(Ordering::Relaxed);
    let pgid = task.pgid.load(Ordering::Relaxed);
    let sid = task.sid.load(Ordering::Relaxed);
    let vsize_bytes = vm_size_kb(pid) * 1024;
    let rss_pages = vsize_bytes / 4096;
    // pid (comm) state ppid pgid sid tty_nr tpgid flags minflt cminflt majflt
    // cmajflt utime stime cutime cstime priority nice num_threads itrealvalue
    // starttime vsize rss rsslim startcode endcode startstack kstkesp kstkeip
    // signal blocked sigignore sigcatch wchan nswap cnswap exit_signal
    // processor rt_priority policy delayacct_blkio_ticks guest_time
    // cguest_time start_data end_data start_brk arg_start arg_end env_start
    // env_end exit_code
    let s = format!(
        "{} ({}) {} {} {} {} -1 0 0 0 0 0 0 0 0 0 20 0 1 0 0 {} {} 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
        pid, comm, state, ppid, pgid, sid, vsize_bytes, rss_pages
    );
    s.into_bytes()
}

fn gen_fd_target(pid: i32, fd: i32) -> Vec<u8> {
    let Some(task) = crate::task::task_by_pid(pid) else {
        return Vec::new();
    };
    let file = match task.fd_table.lock().get(fd) {
        Some(f) => f,
        None => return Vec::new(),
    };
    if file.is_console {
        return b"/dev/tty".to_vec();
    }
    let kind = file.inode.kind();
    let label = match kind {
        FileType::Pipe => format!("pipe:[{}]", fd),
        FileType::CharDevice | FileType::BlockDevice => alloc::string::String::from("/dev/null"),
        FileType::Directory => alloc::string::String::from("anon_inode:dir"),
        FileType::Regular => alloc::string::String::from("anon_inode:file"),
        FileType::Symlink => alloc::string::String::from("anon_inode:symlink"),
    };
    label.into_bytes()
}

// ----- System-wide content generators -----

fn gen_cpuinfo() -> Vec<u8> {
    b"processor\t: 0\n\
      hart\t\t: 0\n\
      isa\t\t: rv64imafdc\n\
      mmu\t\t: sv39\n\
      uarch\t\t: generic\n\
      mvendorid\t: 0x0\n\
      marchid\t\t: 0x0\n\
      mimpid\t\t: 0x0\n\
      \n"
        .to_vec()
}

fn gen_meminfo() -> Vec<u8> {
    let (total_pages, free_pages) = crate::mm::frame_stats();
    let total_kb = (total_pages * 4096) / 1024;
    let free_kb = (free_pages * 4096) / 1024;
    let avail_kb = free_kb;
    let s = format!(
        "MemTotal:       {:>8} kB\n\
         MemFree:        {:>8} kB\n\
         MemAvailable:   {:>8} kB\n\
         Buffers:        {:>8} kB\n\
         Cached:         {:>8} kB\n\
         SwapTotal:      {:>8} kB\n\
         SwapFree:       {:>8} kB\n",
        total_kb, free_kb, avail_kb, 0, 0, 0, 0
    );
    s.into_bytes()
}

fn gen_mounts() -> Vec<u8> {
    let mut s = String::new();
    s.push_str("tmpfs / tmpfs rw,relatime 0 0\n");
    s.push_str("proc /proc proc rw,relatime 0 0\n");
    s.push_str("devtmpfs /dev devtmpfs rw,relatime 0 0\n");
    // /mnt is FAT32 if a block device was found at boot. Test it cheaply by
    // checking whether /mnt is currently a non-tmpfs directory whose root
    // can be downcast — but simpler: if a block device was registered we
    // mounted vfat there, so try lookup_path("/mnt") and inspect.
    if let Ok(mnt) = super::lookup_path(super::root(), "/mnt") {
        let any: &dyn Any = mnt.as_any();
        if any.is::<super::tmpfs::TmpfsDir>() {
            // it's a placeholder tmpfs, leave it out
        } else {
            s.push_str("/dev/vda /mnt vfat ro,relatime 0 0\n");
        }
    }
    s.into_bytes()
}

fn gen_version() -> Vec<u8> {
    b"xiande-os version 0.1 (rust nightly riscv64gc-unknown-none-elf) #1 SMP\n".to_vec()
}

fn gen_uptime() -> Vec<u8> {
    let secs = seconds_since_boot();
    let cs = centiseconds_since_boot();
    format!("{}.{:02} {}.{:02}\n", secs, cs, secs, cs).into_bytes()
}

fn gen_filesystems() -> Vec<u8> {
    b"nodev\ttmpfs\nnodev\tproc\nnodev\tdevtmpfs\n\tvfat\n".to_vec()
}

fn gen_proc_stat() -> Vec<u8> {
    let secs = seconds_since_boot();
    let cs = centiseconds_since_boot();
    // user nice system idle iowait irq softirq steal guest guest_nice
    // values are in USER_HZ (100/s); fudge with seconds_since_boot.
    let user_ticks = secs * 100 + cs;
    let s = format!(
        "cpu  {ut} 0 0 0 0 0 0 0 0 0\n\
         cpu0 {ut} 0 0 0 0 0 0 0 0 0\n\
         intr 0\n\
         ctxt 0\n\
         btime 0\n\
         processes {np}\n\
         procs_running 1\n\
         procs_blocked 0\n",
        ut = user_ticks,
        np = crate::task::next_pid_snapshot()
    );
    s.into_bytes()
}

fn gen_loadavg() -> Vec<u8> {
    b"0.00 0.00 0.00 1/1 1\n".to_vec()
}

// ----- /proc/sys/kernel/<file> -----

pub struct ProcSysDir;
impl Inode for ProcSysDir {
    fn as_any(&self) -> &dyn Any { self }
    fn kind(&self) -> FileType { FileType::Directory }
    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>> {
        match name {
            "kernel" => Ok(Arc::new(ProcSysKernelDir) as Arc<dyn Inode>),
            "fs" => Ok(Arc::new(ProcSysFsDir) as Arc<dyn Inode>),
            "vm" => Ok(Arc::new(ProcSysVmDir) as Arc<dyn Inode>),
            _ => Err(ENOENT),
        }
    }
    fn list(&self) -> Result<Vec<(String, FileType)>> {
        Ok(alloc::vec![
            ("kernel".into(), FileType::Directory),
            ("fs".into(), FileType::Directory),
            ("vm".into(), FileType::Directory),
        ])
    }
}

/// /proc/sys/vm/<file>. LTP's tst_sys_conf saves/restores several of these and
/// TBROKs if they're absent (min_free_kbytes, mmap stress, the mtest cases all
/// poke overcommit_memory; oom tests read the rest). Static defaults are fine —
/// we don't act on them, but their presence lets the tests run.
pub struct ProcSysVmDir;
impl Inode for ProcSysVmDir {
    fn as_any(&self) -> &dyn Any { self }
    fn kind(&self) -> FileType { FileType::Directory }
    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>> {
        match name {
            "overcommit_memory" => Ok(ProcGenFile::new(|| b"0\n".to_vec())),
            "overcommit_ratio" => Ok(ProcGenFile::new(|| b"50\n".to_vec())),
            "overcommit_kbytes" => Ok(ProcGenFile::new(|| b"0\n".to_vec())),
            "max_map_count" => Ok(ProcGenFile::new(|| b"65530\n".to_vec())),
            "min_free_kbytes" => Ok(ProcGenFile::new(|| b"4096\n".to_vec())),
            "nr_hugepages" => Ok(ProcGenFile::new(|| b"0\n".to_vec())),
            "nr_overcommit_hugepages" => Ok(ProcGenFile::new(|| b"0\n".to_vec())),
            // Writable: tests poke these (fanotify10 evicts inodes via
            // drop_caches and saves/sets vfs_cache_pressure in setup). They
            // only need the write to succeed and never read their own value
            // back, so accept-and-discard is correct. Missing vfs_cache_pressure
            // was a hard TBROK in fanotify10's setup (SAFE_FILE_SCANF ENOENT),
            // aborting the whole test before any fanotify case ran.
            "drop_caches" => Ok(ProcWritableFile::new(b"0\n")),
            "vfs_cache_pressure" => Ok(ProcWritableFile::new(b"100\n")),
            "swappiness" => Ok(ProcGenFile::new(|| b"60\n".to_vec())),
            "dirty_ratio" => Ok(ProcGenFile::new(|| b"20\n".to_vec())),
            "panic_on_oom" => Ok(ProcGenFile::new(|| b"0\n".to_vec())),
            "mmap_min_addr" => Ok(ProcGenFile::new(|| b"65536\n".to_vec())),
            "legacy_va_layout" => Ok(ProcGenFile::new(|| b"0\n".to_vec())),
            _ => Err(ENOENT),
        }
    }
    fn list(&self) -> Result<Vec<(String, FileType)>> {
        Ok(alloc::vec![
            ("overcommit_memory".into(), FileType::Regular),
            ("overcommit_ratio".into(), FileType::Regular),
            ("max_map_count".into(), FileType::Regular),
            ("min_free_kbytes".into(), FileType::Regular),
            ("nr_hugepages".into(), FileType::Regular),
            ("mmap_min_addr".into(), FileType::Regular),
            ("swappiness".into(), FileType::Regular),
            ("drop_caches".into(), FileType::Regular),
            ("vfs_cache_pressure".into(), FileType::Regular),
        ])
    }
}

pub struct ProcSysKernelDir;
impl Inode for ProcSysKernelDir {
    fn as_any(&self) -> &dyn Any { self }
    fn kind(&self) -> FileType { FileType::Directory }
    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>> {
        match name {
            // LTP's tst_taint.c reads this — TBROK without it.
            "tainted" => Ok(ProcGenFile::new(|| b"0\n".to_vec())),
            // tst_pid.c reads pid_max — TBROK without it (capget02, etc).
            "pid_max" => Ok(ProcGenFile::new(|| b"32768\n".to_vec())),
            "osrelease" => Ok(ProcGenFile::new(|| b"6.6.0-xiande\n".to_vec())),
            "ostype" => Ok(ProcGenFile::new(|| b"Linux\n".to_vec())),
            "hostname" => Ok(ProcGenFile::new(|| b"xiande\n".to_vec())),
            "domainname" => Ok(ProcGenFile::new(|| b"(none)\n".to_vec())),
            "random" => Ok(Arc::new(ProcSysKernelRandomDir) as Arc<dyn Inode>),
            "sem" => Ok(ProcGenFile::new(|| b"32000\t1024000000\t500\t32000\n".to_vec())),
            "shmall" => Ok(ProcGenFile::new(|| b"18446744073692774399\n".to_vec())),
            "shmmax" => Ok(ProcGenFile::new(|| b"18446744073692774399\n".to_vec())),
            "shmmni" => Ok(ProcGenFile::new(|| b"4096\n".to_vec())),
            "msgmax" => Ok(ProcGenFile::new(|| b"8192\n".to_vec())),
            "msgmnb" => Ok(ProcGenFile::new(|| b"16384\n".to_vec())),
            "msgmni" => Ok(ProcGenFile::new(|| b"32000\n".to_vec())),
            "ngroups_max" => Ok(ProcGenFile::new(|| b"65536\n".to_vec())),
            "threads-max" => Ok(ProcGenFile::new(|| b"63095\n".to_vec())),
            "cap_last_cap" => Ok(ProcGenFile::new(|| b"40\n".to_vec())),
            "yama" => Ok(Arc::new(ProcSysKernelYamaDir) as Arc<dyn Inode>),
            _ => Err(ENOENT),
        }
    }
    fn list(&self) -> Result<Vec<(String, FileType)>> {
        Ok(alloc::vec![
            ("tainted".into(), FileType::Regular),
            ("pid_max".into(), FileType::Regular),
            ("osrelease".into(), FileType::Regular),
            ("ostype".into(), FileType::Regular),
            ("hostname".into(), FileType::Regular),
            ("domainname".into(), FileType::Regular),
            ("random".into(), FileType::Directory),
            ("sem".into(), FileType::Regular),
            ("shmall".into(), FileType::Regular),
            ("shmmax".into(), FileType::Regular),
            ("shmmni".into(), FileType::Regular),
            ("msgmax".into(), FileType::Regular),
            ("msgmnb".into(), FileType::Regular),
            ("msgmni".into(), FileType::Regular),
            ("ngroups_max".into(), FileType::Regular),
            ("threads-max".into(), FileType::Regular),
            ("cap_last_cap".into(), FileType::Regular),
            ("yama".into(), FileType::Directory),
        ])
    }
}

pub struct ProcSysKernelRandomDir;
impl Inode for ProcSysKernelRandomDir {
    fn as_any(&self) -> &dyn Any { self }
    fn kind(&self) -> FileType { FileType::Directory }
    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>> {
        match name {
            "uuid" => Ok(ProcGenFile::new(|| b"00000000-0000-0000-0000-000000000000\n".to_vec())),
            "boot_id" => Ok(ProcGenFile::new(|| b"00000000-0000-0000-0000-000000000000\n".to_vec())),
            "entropy_avail" => Ok(ProcGenFile::new(|| b"256\n".to_vec())),
            "poolsize" => Ok(ProcGenFile::new(|| b"256\n".to_vec())),
            _ => Err(ENOENT),
        }
    }
    fn list(&self) -> Result<Vec<(String, FileType)>> {
        Ok(alloc::vec![
            ("uuid".into(), FileType::Regular),
            ("boot_id".into(), FileType::Regular),
            ("entropy_avail".into(), FileType::Regular),
            ("poolsize".into(), FileType::Regular),
        ])
    }
}

pub struct ProcSysKernelYamaDir;
impl Inode for ProcSysKernelYamaDir {
    fn as_any(&self) -> &dyn Any { self }
    fn kind(&self) -> FileType { FileType::Directory }
    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>> {
        match name {
            "ptrace_scope" => Ok(ProcGenFile::new(|| b"0\n".to_vec())),
            _ => Err(ENOENT),
        }
    }
    fn list(&self) -> Result<Vec<(String, FileType)>> {
        Ok(alloc::vec![("ptrace_scope".into(), FileType::Regular)])
    }
}

pub struct ProcSysFsDir;
impl Inode for ProcSysFsDir {
    fn as_any(&self) -> &dyn Any { self }
    fn kind(&self) -> FileType { FileType::Directory }
    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>> {
        match name {
            "file-max" => Ok(ProcGenFile::new(|| b"9223372036854775807\n".to_vec())),
            "file-nr" => Ok(ProcGenFile::new(|| b"0\t0\t9223372036854775807\n".to_vec())),
            "nr_open" => Ok(ProcGenFile::new(|| b"1073741816\n".to_vec())),
            "pipe-max-size" => Ok(ProcGenFile::new(|| b"1048576\n".to_vec())),
            "inotify" => Ok(Arc::new(ProcSysFsInotifyDir) as Arc<dyn Inode>),
            _ => Err(ENOENT),
        }
    }
    fn list(&self) -> Result<Vec<(String, FileType)>> {
        Ok(alloc::vec![
            ("file-max".into(), FileType::Regular),
            ("file-nr".into(), FileType::Regular),
            ("nr_open".into(), FileType::Regular),
            ("pipe-max-size".into(), FileType::Regular),
            ("inotify".into(), FileType::Directory),
        ])
    }
}

/// /proc/sys/fs/inotify/* — the tunables LTP's inotify cases read.
pub struct ProcSysFsInotifyDir;
impl Inode for ProcSysFsInotifyDir {
    fn as_any(&self) -> &dyn Any { self }
    fn kind(&self) -> FileType { FileType::Directory }
    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>> {
        match name {
            "max_queued_events" => Ok(ProcGenFile::new(|| b"16384\n".to_vec())),
            "max_user_instances" => Ok(ProcGenFile::new(|| b"128\n".to_vec())),
            "max_user_watches" => Ok(ProcGenFile::new(|| b"65536\n".to_vec())),
            _ => Err(ENOENT),
        }
    }
    fn list(&self) -> Result<Vec<(String, FileType)>> {
        Ok(alloc::vec![
            ("max_queued_events".into(), FileType::Regular),
            ("max_user_instances".into(), FileType::Regular),
            ("max_user_watches".into(), FileType::Regular),
        ])
    }
}

// ----- Mount -----

static MOUNTED: Once<()> = Once::new();

/// Mount procfs at the given path (must be a single component under "/",
/// i.e. "/proc"). Replaces whatever was there.
pub fn mount(mount_point: &str) -> Result<()> {
    BOOT_MTIME.store(now_mtime(), Ordering::Relaxed);
    let name = mount_point.trim_start_matches('/');
    let root = super::root();
    let td = super::tmpfs::downcast_dir(&root).ok_or(EINVAL)?;
    let proc_inode: Arc<dyn Inode> = Arc::new(ProcRoot);
    td.place_inode(name, proc_inode)?;
    MOUNTED.call_once(|| ());
    Ok(())
}
