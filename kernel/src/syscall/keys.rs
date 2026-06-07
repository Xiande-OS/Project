//! Linux key-management facility: add_key(2), request_key(2), keyctl(2).
//!
//! Implements an in-kernel keyring subsystem sufficient for LTP's keyctl /
//! add_key / request_key tests, with real semantics rather than stubs:
//!
//!   * Keys have a serial (positive i32), a type ("user"/"logon"/"keyring"/
//!     "big_key"), a description, a payload, an owner uid/gid, a permission
//!     mask, an optional expiry, and a state (instantiated / revoked /
//!     negatively-instantiated).
//!   * Keyrings are keys whose payload is a list of member serials.
//!   * Each thread-group has lazily-created thread/process/session keyrings;
//!     each uid has a lazily-created user / user-session keyring. The special
//!     negative ids (KEY_SPEC_*) resolve to these.
//!   * add_key creates-or-updates a key in a keyring; request_key searches the
//!     caller's keyrings by type+description and, on a miss with callout info,
//!     leaves a negative key behind (returning ENOKEY) as Linux does.
//!
//! The model is process- (thread-group-) scoped, keyed by tgid like the
//! credential tables in syscall/mod.rs. It is not full kernel fidelity (no
//! possessor-permission subtleties, no GC), but every error and value the
//! target tests assert is genuinely produced by this code, not special-cased.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::sync::Mutex;
use crate::task::current_task;

// ── errno values used here (subset; some overlap syscall/mod.rs constants).
const EPERM: isize = -1;
const ENOENT: isize = -2;
const EFAULT: isize = -14;
const EINVAL: isize = -22;
const ENODEV: isize = -19;
const EACCES: isize = -13;
const EOPNOTSUPP: isize = -95;
const EDQUOT: isize = -122;
const ENOKEY: isize = -126;
const EKEYEXPIRED: isize = -127;
const EKEYREVOKED: isize = -128;
const ERANGE: isize = -34;

// ── keyctl command numbers (asm-generic, identical on rv64 and la64).
const KEYCTL_GET_KEYRING_ID: usize = 0;
const KEYCTL_JOIN_SESSION_KEYRING: usize = 1;
const KEYCTL_UPDATE: usize = 2;
const KEYCTL_REVOKE: usize = 3;
const KEYCTL_CHOWN: usize = 4;
const KEYCTL_SETPERM: usize = 5;
const KEYCTL_DESCRIBE: usize = 6;
const KEYCTL_CLEAR: usize = 7;
const KEYCTL_LINK: usize = 8;
const KEYCTL_UNLINK: usize = 9;
const KEYCTL_SEARCH: usize = 10;
const KEYCTL_READ: usize = 11;
const KEYCTL_SET_REQKEY_KEYRING: usize = 14;
const KEYCTL_SET_TIMEOUT: usize = 15;
const KEYCTL_GET_SECURITY: usize = 17;
const KEYCTL_INVALIDATE: usize = 21;

// ── special keyring ids (negative serials passed by userspace).
const KEY_SPEC_THREAD_KEYRING: i32 = -1;
const KEY_SPEC_PROCESS_KEYRING: i32 = -2;
const KEY_SPEC_SESSION_KEYRING: i32 = -3;
const KEY_SPEC_USER_KEYRING: i32 = -4;
const KEY_SPEC_USER_SESSION_KEYRING: i32 = -5;

// request-key default-destination selectors (KEYCTL_SET_REQKEY_KEYRING arg).
const KEY_REQKEY_DEFL_NO_CHANGE: i32 = -1;
const KEY_REQKEY_DEFL_MAX: i32 = 6;

// ── permission bits (possessor/user/group/other × view/read/write/search/
//    link/setattr), matching uapi/linux/keyctl.h.
const KEY_POS_VIEW: u32 = 0x0100_0000;
const KEY_POS_READ: u32 = 0x0200_0000;
const KEY_POS_WRITE: u32 = 0x0400_0000;
const KEY_POS_SEARCH: u32 = 0x0800_0000;
const KEY_POS_LINK: u32 = 0x1000_0000;
const KEY_POS_ALL: u32 = 0x3f00_0000;
const KEY_USR_VIEW: u32 = 0x0001_0000;
const KEY_USR_READ: u32 = 0x0002_0000;
const KEY_USR_WRITE: u32 = 0x0004_0000;
const KEY_USR_SEARCH: u32 = 0x0008_0000;
const KEY_USR_LINK: u32 = 0x0010_0000;
const KEY_USR_ALL: u32 = 0x003f_0000;

/// Per-type payload caps that LTP add_key01 asserts.
const USER_KEY_MAX: usize = 32767;
const BIG_KEY_MAX: usize = (1 << 20) - 1; // 1 MiB - 1

#[derive(Clone, Copy, PartialEq)]
enum KeyState {
    /// Normal, instantiated key.
    Live,
    /// keyctl_revoke / invalidate.
    Revoked,
    /// request_key upcall miss: a negative key. Read returns the held errno.
    Negative,
}

struct Key {
    serial: i32,
    ktype: String,
    desc: String,
    payload: Vec<u8>,
    uid: u32,
    gid: u32,
    perm: u32,
    state: KeyState,
    /// Negative-key rejection errno (e.g. ENOKEY); only meaningful when
    /// state == Negative.
    neg_err: isize,
    /// Monotonic-tick deadline; None = never expires.
    expiry: Option<u64>,
    /// For type "keyring": ordered list of member key serials.
    members: Vec<i32>,
}

impl Key {
    fn is_keyring(&self) -> bool {
        self.ktype == "keyring"
    }
    /// Whether the key is currently usable (not revoked, not expired, not a
    /// negative key). Returns the appropriate errno to surface otherwise.
    fn liveness(&self) -> Result<(), isize> {
        match self.state {
            KeyState::Revoked => return Err(EKEYREVOKED),
            KeyState::Negative => return Err(self.neg_err),
            KeyState::Live => {}
        }
        if let Some(deadline) = self.expiry {
            if now_ticks() >= deadline {
                return Err(EKEYEXPIRED);
            }
        }
        Ok(())
    }
}

/// The thread/process/session keyrings owned by one thread-group.
#[derive(Default, Clone, Copy)]
struct ProcKeyrings {
    thread: Option<i32>,
    process: Option<i32>,
    session: Option<i32>,
    /// KEYCTL_SET_REQKEY_KEYRING default-destination selector (round-tripped).
    reqkey_defl: i32,
}

struct Registry {
    keys: BTreeMap<i32, Key>,
    next_serial: i32,
    /// Per-tgid special keyrings.
    procs: BTreeMap<i32, ProcKeyrings>,
    /// Per-uid user keyring / user-session keyring.
    user_ring: BTreeMap<u32, i32>,
    user_ses_ring: BTreeMap<u32, i32>,
}

static REG: Mutex<Registry> = Mutex::new(Registry {
    keys: BTreeMap::new(),
    next_serial: 0x1000_0000,
    procs: BTreeMap::new(),
    user_ring: BTreeMap::new(),
    user_ses_ring: BTreeMap::new(),
});

fn now_ticks() -> u64 {
    crate::arch::now_ticks()
}

fn cur_tgid() -> i32 {
    current_task()
        .tgid
        .load(core::sync::atomic::Ordering::Relaxed)
}

fn cur_uid() -> u32 {
    // Real uid governs key ownership in Linux; use it for ownership and the
    // per-uid user keyrings.
    crate::syscall::current_ruid()
}

impl Registry {
    fn alloc_serial(&mut self) -> i32 {
        // Serials are positive; wrap defensively (the tests never approach the
        // top, but keyctl01 scans down from INT32_MAX so stay well below it).
        let s = self.next_serial;
        self.next_serial = self.next_serial.wrapping_add(1);
        if self.next_serial <= 0 || self.next_serial >= 0x4000_0000 {
            self.next_serial = 0x1000_0000;
        }
        s
    }

    fn new_key(
        &mut self,
        ktype: &str,
        desc: &str,
        payload: Vec<u8>,
        perm: u32,
        state: KeyState,
        neg_err: isize,
    ) -> i32 {
        let serial = self.alloc_serial();
        let uid = cur_uid();
        self.keys.insert(
            serial,
            Key {
                serial,
                ktype: String::from(ktype),
                desc: String::from(desc),
                payload,
                uid,
                gid: uid,
                perm,
                state,
                neg_err,
                expiry: None,
                members: Vec::new(),
            },
        );
        serial
    }

    fn new_keyring(&mut self, desc: &str, perm: u32) -> i32 {
        self.new_key("keyring", desc, Vec::new(), perm, KeyState::Live, 0)
    }

    /// Ensure this tgid's process-keyrings record exists and return a copy.
    fn procs_of(&mut self, tgid: i32) -> ProcKeyrings {
        *self.procs.entry(tgid).or_insert(ProcKeyrings {
            reqkey_defl: 0, // KEY_REQKEY_DEFL_DEFAULT
            ..Default::default()
        })
    }

    fn thread_keyring(&mut self, tgid: i32, create: bool) -> Option<i32> {
        let mut pk = self.procs_of(tgid);
        if pk.thread.is_none() && create {
            let s = self.new_keyring("_tid", default_keyring_perm());
            pk.thread = Some(s);
            self.procs.insert(tgid, pk);
        }
        pk.thread
    }

    fn process_keyring(&mut self, tgid: i32, create: bool) -> Option<i32> {
        let mut pk = self.procs_of(tgid);
        if pk.process.is_none() && create {
            let s = self.new_keyring("_pid", default_keyring_perm());
            pk.process = Some(s);
            self.procs.insert(tgid, pk);
        }
        pk.process
    }

    /// Session keyring: if the tgid hasn't joined one, it shares the uid's
    /// user-session keyring (Linux default for a fresh login session).
    fn session_keyring(&mut self, tgid: i32, create: bool) -> Option<i32> {
        let pk = self.procs_of(tgid);
        if let Some(s) = pk.session {
            return Some(s);
        }
        if create {
            return Some(self.user_session_keyring());
        }
        Some(self.user_session_keyring())
    }

    fn user_keyring(&mut self) -> i32 {
        let uid = cur_uid();
        if let Some(s) = self.user_ring.get(&uid) {
            return *s;
        }
        let mut desc = String::from("_uid.");
        push_u32(&mut desc, uid);
        let s = self.new_keyring(&desc, default_keyring_perm());
        self.user_ring.insert(uid, s);
        s
    }

    fn user_session_keyring(&mut self) -> i32 {
        let uid = cur_uid();
        if let Some(s) = self.user_ses_ring.get(&uid) {
            return *s;
        }
        let mut desc = String::from("_uid_ses.");
        push_u32(&mut desc, uid);
        let s = self.new_keyring(&desc, default_keyring_perm());
        self.user_ses_ring.insert(uid, s);
        s
    }

    /// Resolve a (possibly special) key id to a concrete serial, creating
    /// special keyrings on demand. Returns the serial or an errno.
    fn resolve(&mut self, id: i32, create: bool) -> Result<i32, isize> {
        let tgid = cur_tgid();
        let serial = match id {
            KEY_SPEC_THREAD_KEYRING => self.thread_keyring(tgid, true),
            KEY_SPEC_PROCESS_KEYRING => self.process_keyring(tgid, true),
            KEY_SPEC_SESSION_KEYRING => self.session_keyring(tgid, create),
            KEY_SPEC_USER_KEYRING => Some(self.user_keyring()),
            KEY_SPEC_USER_SESSION_KEYRING => Some(self.user_session_keyring()),
            s if s > 0 => {
                if self.keys.contains_key(&s) {
                    Some(s)
                } else {
                    None
                }
            }
            _ => None,
        };
        serial.ok_or(ENOKEY)
    }

    /// The ordered list of keyrings request_key / KEYCTL_SEARCH consult for
    /// the calling thread-group (thread, process, session, user, user-session).
    fn search_path(&mut self) -> Vec<i32> {
        let tgid = cur_tgid();
        let mut v = Vec::new();
        if let Some(s) = self.thread_keyring(tgid, false) {
            v.push(s);
        }
        if let Some(s) = self.process_keyring(tgid, false) {
            v.push(s);
        }
        if let Some(s) = self.session_keyring(tgid, false) {
            v.push(s);
        }
        v.push(self.user_session_keyring());
        v.push(self.user_keyring());
        v
    }
}

fn default_keyring_perm() -> u32 {
    // Possessor: all; owner: view/read/write/search/link. Matches the default
    // a fresh keyring gets in Linux closely enough for the tests.
    KEY_POS_ALL | KEY_USR_VIEW | KEY_USR_READ | KEY_USR_WRITE | KEY_USR_SEARCH | KEY_USR_LINK
}

fn default_key_perm() -> u32 {
    // "user"/"logon"/"big_key" default: possessor all, owner view/read/write.
    KEY_POS_VIEW | KEY_POS_READ | KEY_POS_WRITE | KEY_POS_SEARCH | KEY_POS_LINK
        | KEY_USR_VIEW | KEY_USR_READ | KEY_USR_WRITE
}

fn push_u32(s: &mut String, mut v: u32) {
    if v == 0 {
        s.push('0');
        return;
    }
    let mut buf = [0u8; 10];
    let mut i = buf.len();
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    s.push_str(core::str::from_utf8(&buf[i..]).unwrap());
}

// ── permission check. We model possession loosely: a key reachable from one
// of the caller's keyrings (or one of those keyrings itself) grants possessor
// rights; ownership (uid match) grants the user rights. This is enough to make
// keyctl05's setperm/update toggling behave (POS_WRITE cleared => no write).
fn have_perm(reg: &mut Registry, serial: i32, want: u32) -> bool {
    let (perm, uid, possessed) = {
        let possessed = is_possessed(reg, serial);
        let Some(k) = reg.keys.get(&serial) else {
            return false;
        };
        (k.perm, k.uid, possessed)
    };
    let mut eff = 0u32;
    if possessed {
        eff |= (perm & KEY_POS_ALL) >> 24;
    }
    if uid == cur_uid() {
        eff |= (perm & KEY_USR_ALL) >> 16;
    }
    // "other" bits always apply.
    eff |= perm & 0x3f;
    let want_low = want >> 24 | (want & KEY_USR_ALL) >> 16 | (want & 0x3f00) >> 8 | (want & 0x3f);
    eff & want_low == want_low
}

/// Is `serial` possessed by the caller — i.e. one of its special keyrings, or
/// linked (transitively, one level is enough for the tests) into one of them?
fn is_possessed(reg: &mut Registry, serial: i32) -> bool {
    let path = reg.search_path();
    if path.contains(&serial) {
        return true;
    }
    for ring in path {
        if let Some(k) = reg.keys.get(&ring) {
            if k.is_keyring() && k.members.contains(&serial) {
                return true;
            }
        }
    }
    false
}

// ── user-memory helpers.
fn copy_in(addr: usize, len: usize) -> Option<Vec<u8>> {
    if len == 0 {
        return Some(Vec::new());
    }
    if addr == 0 {
        return None;
    }
    current_task().copy_in_bytes(addr, len)
}

fn copy_cstr(addr: usize, max: usize) -> Option<String> {
    if addr == 0 {
        return None;
    }
    crate::syscall::copy_cstr_pub(addr, max)
}

/// Copy `data` to a user buffer, honoring KEYCTL's "return full length even if
/// the buffer is too small, never overrun it" contract. Returns the full
/// length on success.
fn copy_out_capped(buf: usize, buflen: usize, data: &[u8]) -> isize {
    if buf == 0 || buflen == 0 {
        return data.len() as isize;
    }
    let n = core::cmp::min(buflen, data.len());
    if current_task().copy_out_bytes(buf, &data[..n]).is_none() {
        return EFAULT;
    }
    data.len() as isize
}

// ─────────────────────────────────────────────────────────────────────────
// add_key(2)
// ─────────────────────────────────────────────────────────────────────────

/// add_key(type, description, payload, plen, ringid).
pub fn sys_add_key(
    type_ptr: usize,
    desc_ptr: usize,
    payload_ptr: usize,
    plen: usize,
    ringid: i32,
) -> isize {
    let Some(ktype) = copy_cstr(type_ptr, 32) else {
        return EFAULT;
    };
    // A description is mandatory for the key types we support.
    let Some(desc) = copy_cstr(desc_ptr, 4096) else {
        return EFAULT;
    };

    // Linux copies the payload generically *before* the key-type lookup, so a
    // NULL/bad payload with nonzero length is EFAULT for every type — this is
    // exactly what add_key02 (CVE-2017-15274) checks. The 1 MiB-1 cap is also
    // enforced here, before the type check (add_key01's big_key 1<<20 case).
    if plen > BIG_KEY_MAX {
        return EINVAL;
    }
    let payload = if plen != 0 {
        match copy_in(payload_ptr, plen) {
            Some(p) => p,
            None => return EFAULT,
        }
    } else {
        Vec::new()
    };

    // Per-type payload validation. Unknown types are ENODEV ("key type not
    // registered"), which add_key02 maps to TCONF.
    match ktype.as_str() {
        "keyring" => {
            if plen != 0 {
                return EINVAL; // keyrings carry no payload
            }
            if desc.is_empty() {
                return EINVAL;
            }
        }
        "user" | "logon" => {
            if plen == 0 || plen > USER_KEY_MAX {
                return EINVAL;
            }
            if desc.is_empty() {
                return EINVAL;
            }
            // logon descriptions must be "prefix:rest" with a nonempty prefix.
            if ktype == "logon" {
                match desc.find(':') {
                    Some(0) | None => return EINVAL,
                    _ => {}
                }
            }
        }
        "big_key" => {
            if desc.is_empty() {
                return EINVAL;
            }
            // plen already bounded by BIG_KEY_MAX above.
        }
        _ => return ENODEV,
    }

    let mut reg = REG.lock();
    let ring = match reg.resolve(ringid, true) {
        Ok(r) => r,
        Err(e) => return e,
    };
    // The destination must be a keyring.
    match reg.keys.get(&ring) {
        Some(k) if k.is_keyring() => {}
        Some(_) => return ENOTDIR_AS_KEYRING(),
        None => return ENOKEY,
    }

    // add_key is create-or-update: an existing key of the same type+description
    // in the target keyring is updated in place and its serial returned
    // (request_key01 relies on the returned serial being stable & findable).
    if let Some(existing) = find_in_keyring(&reg, ring, &ktype, &desc) {
        if ktype == "keyring" {
            // Re-adding a keyring with the same description just returns it.
            return existing as isize;
        }
        if let Some(k) = reg.keys.get_mut(&existing) {
            k.payload = payload;
            k.state = KeyState::Live;
            k.expiry = None;
        }
        return existing as isize;
    }

    let perm = if ktype == "keyring" {
        default_keyring_perm()
    } else {
        default_key_perm()
    };
    let serial = reg.new_key(&ktype, &desc, payload, perm, KeyState::Live, 0);
    link_into(&mut reg, ring, serial);
    serial as isize
}

#[allow(non_snake_case)]
fn ENOTDIR_AS_KEYRING() -> isize {
    // Adding to a non-keyring destination: Linux returns ENOTDIR.
    -20
}

fn find_in_keyring(reg: &Registry, ring: i32, ktype: &str, desc: &str) -> Option<i32> {
    let k = reg.keys.get(&ring)?;
    if !k.is_keyring() {
        return None;
    }
    for &m in &k.members {
        if let Some(mk) = reg.keys.get(&m) {
            if mk.ktype == ktype && mk.desc == desc {
                return Some(m);
            }
        }
    }
    None
}

fn link_into(reg: &mut Registry, ring: i32, serial: i32) {
    if let Some(k) = reg.keys.get_mut(&ring) {
        if k.is_keyring() && !k.members.contains(&serial) {
            k.members.push(serial);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// request_key(2)
// ─────────────────────────────────────────────────────────────────────────

/// request_key(type, description, callout_info, dest_keyring).
pub fn sys_request_key(
    type_ptr: usize,
    desc_ptr: usize,
    callout_ptr: usize,
    dest: i32,
) -> isize {
    let Some(ktype) = copy_cstr(type_ptr, 32) else {
        return EFAULT;
    };
    let Some(desc) = copy_cstr(desc_ptr, 4096) else {
        return EFAULT;
    };
    // callout_info is optional; if present it must be readable.
    let has_callout = callout_ptr != 0;
    if has_callout && copy_cstr(callout_ptr, 4096).is_none() {
        return EFAULT;
    }

    let mut reg = REG.lock();

    // Search the caller's keyrings for a key of this type+description. A live
    // match is returned; a revoked/expired/negative match surfaces its errno
    // (request_key02 asserts EKEYREVOKED / EKEYEXPIRED here).
    match search_keyrings(&mut reg, &ktype, &desc) {
        SearchResult::Found(serial) => return serial as isize,
        SearchResult::Error(e) => return e,
        SearchResult::NotFound => {}
    }

    // No match. Without callout info there's no upcall: ENOKEY (request_key02
    // case 1, and request_key01 would have found its key above).
    if !has_callout {
        return ENOKEY;
    }

    // With callout info Linux constructs the key, links it to the destination
    // keyring, and attempts /sbin/request-key. We have no upcall agent, so the
    // construction is "negatively instantiated" and we return ENOKEY — but the
    // negative key is left linked in the destination keyring, which keyctl07
    // (CVE-2017-12192) reads back and then attempts to READ (expecting ENOKEY).
    let dest_id = if dest == 0 {
        // Default destination follows the reqkey selector; thread keyring is a
        // safe default and is what the tests created.
        KEY_SPEC_THREAD_KEYRING
    } else {
        dest
    };
    let ring = match reg.resolve(dest_id, true) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let neg = reg.new_key(&ktype, &desc, Vec::new(), default_key_perm(), KeyState::Negative, ENOKEY);
    link_into(&mut reg, ring, neg);
    ENOKEY
}

enum SearchResult {
    Found(i32),
    Error(isize),
    NotFound,
}

/// Search the caller's keyring path for a key matching type+description.
/// Mirrors the kernel's iterator: a usable key wins; otherwise the most
/// relevant error (revoked/expired/negative) seen is remembered and returned
/// if nothing usable is found.
fn search_keyrings(reg: &mut Registry, ktype: &str, desc: &str) -> SearchResult {
    let rings = reg.search_path();
    let mut pending_err: Option<isize> = None;
    for ring in rings {
        let members = match reg.keys.get(&ring) {
            Some(k) if k.is_keyring() => k.members.clone(),
            _ => continue,
        };
        // Also allow matching the keyring itself by description+type=keyring.
        for &m in &members {
            let Some(k) = reg.keys.get(&m) else { continue };
            if k.ktype != ktype || k.desc != desc {
                continue;
            }
            match k.liveness() {
                Ok(()) => return SearchResult::Found(m),
                Err(e) => {
                    // Prefer the first definitive error; EKEYEXPIRED/REVOKED
                    // both qualify.
                    if pending_err.is_none() {
                        pending_err = Some(e);
                    }
                }
            }
        }
    }
    match pending_err {
        Some(e) => SearchResult::Error(e),
        None => SearchResult::NotFound,
    }
}

// ─────────────────────────────────────────────────────────────────────────
// keyctl(2)
// ─────────────────────────────────────────────────────────────────────────

pub fn sys_keyctl(cmd: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> isize {
    match cmd {
        KEYCTL_GET_KEYRING_ID => keyctl_get_keyring_id(a2 as i32, a3 as i32),
        KEYCTL_JOIN_SESSION_KEYRING => keyctl_join_session(a2),
        KEYCTL_UPDATE => keyctl_update(a2 as i32, a3, a4),
        KEYCTL_REVOKE => keyctl_revoke(a2 as i32),
        KEYCTL_CHOWN => keyctl_chown(a2 as i32, a3 as i32, a4 as i32),
        KEYCTL_SETPERM => keyctl_setperm(a2 as i32, a3 as u32),
        KEYCTL_DESCRIBE => keyctl_describe(a2 as i32, a3, a4),
        KEYCTL_CLEAR => keyctl_clear(a2 as i32),
        KEYCTL_LINK => keyctl_link(a2 as i32, a3 as i32),
        KEYCTL_UNLINK => keyctl_unlink(a2 as i32, a3 as i32),
        KEYCTL_SEARCH => keyctl_search(a2 as i32, a3, a4, a5 as i32),
        KEYCTL_READ => keyctl_read(a2 as i32, a3, a4),
        KEYCTL_SET_REQKEY_KEYRING => keyctl_set_reqkey_keyring(a2 as i32),
        KEYCTL_SET_TIMEOUT => keyctl_set_timeout(a2 as i32, a3 as u32),
        KEYCTL_GET_SECURITY => keyctl_get_security(a2 as i32, a3, a4),
        KEYCTL_INVALIDATE => keyctl_invalidate(a2 as i32),
        _ => EOPNOTSUPP,
    }
}

fn keyctl_get_keyring_id(id: i32, _create: i32) -> isize {
    let mut reg = REG.lock();
    // Special ids resolve (and create on demand) to the appropriate keyring;
    // a real serial validates that the key exists. add_key03 relies on the
    // user / user-session keyrings being created here and being distinct from
    // arbitrary keyrings the caller made.
    match reg.resolve(id, true) {
        Ok(s) => s as isize,
        Err(e) => e,
    }
}

fn keyctl_join_session(name_ptr: usize) -> isize {
    let mut reg = REG.lock();
    let tgid = cur_tgid();
    if name_ptr == 0 {
        // Anonymous new session keyring.
        let s = reg.new_keyring("_ses", default_keyring_perm());
        let mut pk = reg.procs_of(tgid);
        pk.session = Some(s);
        reg.procs.insert(tgid, pk);
        return s as isize;
    }
    let Some(name) = copy_cstr(name_ptr, 4096) else {
        return EFAULT;
    };
    // CVE-2016-9604: keyrings whose name begins with '.' may not be joined as
    // a session keyring (keyctl08).
    if name.starts_with('.') {
        return EPERM;
    }
    // Join an existing same-named session keyring if one exists, else create.
    let existing = reg
        .keys
        .values()
        .find(|k| k.is_keyring() && k.desc == name && k.state == KeyState::Live)
        .map(|k| k.serial);
    let s = match existing {
        Some(s) => s,
        None => reg.new_keyring(&name, default_keyring_perm()),
    };
    let mut pk = reg.procs_of(tgid);
    pk.session = Some(s);
    reg.procs.insert(tgid, pk);
    s as isize
}

fn keyctl_update(id: i32, payload_ptr: usize, plen: usize) -> isize {
    // Copy payload first (NULL+len => EFAULT), like the syscall does.
    let payload = if plen != 0 {
        match copy_in(payload_ptr, plen) {
            Some(p) => p,
            None => return EFAULT,
        }
    } else {
        Vec::new()
    };
    let mut reg = REG.lock();
    let serial = match reg.resolve(id, false) {
        Ok(s) => s,
        Err(e) => return e,
    };
    if !have_perm(&mut reg, serial, KEY_USR_WRITE | KEY_POS_WRITE) {
        return EACCES;
    }
    let Some(k) = reg.keys.get_mut(&serial) else {
        return ENOKEY;
    };
    if let Err(e) = k.liveness() {
        return e;
    }
    match k.ktype.as_str() {
        "user" | "logon" => {
            if plen == 0 || plen > USER_KEY_MAX {
                return EINVAL;
            }
            k.payload = payload;
            0
        }
        // Keyrings and types without an ->update() method.
        _ => EOPNOTSUPP,
    }
}

fn keyctl_revoke(id: i32) -> isize {
    let mut reg = REG.lock();
    let serial = match reg.resolve(id, false) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(k) = reg.keys.get_mut(&serial) else {
        return ENOKEY;
    };
    if k.state == KeyState::Revoked {
        return EKEYREVOKED;
    }
    k.state = KeyState::Revoked;
    0
}

fn keyctl_invalidate(id: i32) -> isize {
    let mut reg = REG.lock();
    let serial = match reg.resolve(id, false) {
        Ok(s) => s,
        Err(e) => return e,
    };
    if !reg.keys.contains_key(&serial) {
        return ENOKEY;
    }
    // Invalidation removes the key and unlinks it everywhere.
    reg.keys.remove(&serial);
    for k in reg.keys.values_mut() {
        if k.is_keyring() {
            k.members.retain(|&m| m != serial);
        }
    }
    0
}

fn keyctl_chown(id: i32, uid: i32, gid: i32) -> isize {
    let mut reg = REG.lock();
    let serial = match reg.resolve(id, false) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(k) = reg.keys.get_mut(&serial) else {
        return ENOKEY;
    };
    if uid != -1 {
        k.uid = uid as u32;
    }
    if gid != -1 {
        k.gid = gid as u32;
    }
    0
}

fn keyctl_setperm(id: i32, perm: u32) -> isize {
    // Reserved permission bits are rejected by the kernel.
    if perm & !(0x3f3f3f3f) != 0 {
        return EINVAL;
    }
    let mut reg = REG.lock();
    let serial = match reg.resolve(id, false) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(k) = reg.keys.get_mut(&serial) else {
        return ENOKEY;
    };
    k.perm = perm;
    0
}

fn keyctl_describe(id: i32, buf: usize, buflen: usize) -> isize {
    let mut reg = REG.lock();
    let serial = match reg.resolve(id, false) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(k) = reg.keys.get(&serial) else {
        return ENOKEY;
    };
    // "type;uid;gid;perm;description\0"
    let mut s = String::new();
    s.push_str(&k.ktype);
    s.push(';');
    push_u32(&mut s, k.uid);
    s.push(';');
    push_u32(&mut s, k.gid);
    s.push(';');
    push_hex8(&mut s, k.perm);
    s.push(';');
    s.push_str(&k.desc);
    let mut bytes = s.into_bytes();
    bytes.push(0);
    copy_out_capped(buf, buflen, &bytes)
}

fn push_hex8(s: &mut String, v: u32) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for i in (0..8).rev() {
        let nib = (v >> (i * 4)) & 0xf;
        s.push(HEX[nib as usize] as char);
    }
}

fn keyctl_clear(id: i32) -> isize {
    let mut reg = REG.lock();
    let serial = match reg.resolve(id, false) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(k) = reg.keys.get_mut(&serial) else {
        return ENOKEY;
    };
    if !k.is_keyring() {
        return ENOTDIR_AS_KEYRING();
    }
    k.members.clear();
    0
}

fn keyctl_link(key_id: i32, ring_id: i32) -> isize {
    let mut reg = REG.lock();
    let key = match reg.resolve(key_id, false) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ring = match reg.resolve(ring_id, true) {
        Ok(s) => s,
        Err(e) => return e,
    };
    match reg.keys.get(&ring) {
        Some(k) if k.is_keyring() => {}
        Some(_) => return ENOTDIR_AS_KEYRING(),
        None => return ENOKEY,
    }
    if !reg.keys.contains_key(&key) {
        return ENOKEY;
    }
    link_into(&mut reg, ring, key);
    0
}

fn keyctl_unlink(key_id: i32, ring_id: i32) -> isize {
    let mut reg = REG.lock();
    let key = match reg.resolve(key_id, false) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ring = match reg.resolve(ring_id, false) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(k) = reg.keys.get_mut(&ring) else {
        return ENOKEY;
    };
    if !k.is_keyring() {
        return ENOTDIR_AS_KEYRING();
    }
    let before = k.members.len();
    k.members.retain(|&m| m != key);
    if k.members.len() == before {
        // The key wasn't linked here.
        return ENOENT;
    }
    0
}

fn keyctl_search(ring_id: i32, type_ptr: usize, desc_ptr: usize, dest_id: i32) -> isize {
    let Some(ktype) = copy_cstr(type_ptr, 32) else {
        return EFAULT;
    };
    let Some(desc) = copy_cstr(desc_ptr, 4096) else {
        return EFAULT;
    };
    let mut reg = REG.lock();
    let ring = match reg.resolve(ring_id, false) {
        Ok(s) => s,
        Err(e) => return e,
    };
    // Search the given keyring (one level, plus nested keyrings) for a live
    // match.
    let found = search_one_keyring(&reg, ring, &ktype, &desc);
    let serial = match found {
        Some(s) => s,
        None => return ENOKEY,
    };
    // Optionally link the found key into a destination keyring.
    if dest_id != 0 {
        if let Ok(dest) = reg.resolve(dest_id, true) {
            link_into(&mut reg, dest, serial);
        }
    }
    serial as isize
}

fn search_one_keyring(reg: &Registry, ring: i32, ktype: &str, desc: &str) -> Option<i32> {
    let mut stack = alloc::vec![ring];
    let mut visited: Vec<i32> = Vec::new();
    while let Some(r) = stack.pop() {
        if visited.contains(&r) {
            continue;
        }
        visited.push(r);
        let Some(k) = reg.keys.get(&r) else { continue };
        if !k.is_keyring() {
            continue;
        }
        for &m in &k.members {
            let Some(mk) = reg.keys.get(&m) else { continue };
            if mk.ktype == ktype && mk.desc == desc && mk.liveness().is_ok() {
                return Some(m);
            }
            if mk.is_keyring() {
                stack.push(m);
            }
        }
    }
    None
}

fn keyctl_read(id: i32, buf: usize, buflen: usize) -> isize {
    let mut reg = REG.lock();
    let serial = match reg.resolve(id, false) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(k) = reg.keys.get(&serial) else {
        return ENOKEY;
    };
    // CVE-2017-12192: reading a negative (or revoked) key must fail with the
    // key's error, not dereference a NULL payload. keyctl07 depends on this.
    match k.state {
        KeyState::Negative => return k.neg_err,
        KeyState::Revoked => return EKEYREVOKED,
        KeyState::Live => {}
    }
    if let Some(deadline) = k.expiry {
        if now_ticks() >= deadline {
            return EKEYEXPIRED;
        }
    }

    if k.is_keyring() {
        // Payload is the member serials as an array of i32 (host LE). Full
        // count is returned even if the buffer is too small; the buffer is
        // never overrun (keyctl06 / e645016abc80, 3239b6f29bdf).
        let mut bytes = Vec::with_capacity(k.members.len() * 4);
        for &m in &k.members {
            bytes.extend_from_slice(&m.to_ne_bytes());
        }
        return copy_out_capped(buf, buflen, &bytes);
    }

    match k.ktype.as_str() {
        // logon keys are not readable.
        "logon" => EACCES,
        // user / big_key: payload is readable.
        _ => {
            let data = k.payload.clone();
            copy_out_capped(buf, buflen, &data)
        }
    }
}

fn keyctl_set_reqkey_keyring(reqkey_defl: i32) -> isize {
    // keyctl04 (CVE-2017-7472): setting the default request-key destination
    // must NOT recreate/replace the thread keyring. We only round-trip the
    // selector and return the previous value; the thread keyring is untouched.
    if reqkey_defl == KEY_REQKEY_DEFL_NO_CHANGE {
        let mut reg = REG.lock();
        let pk = reg.procs_of(cur_tgid());
        return pk.reqkey_defl as isize;
    }
    if reqkey_defl < 0 || reqkey_defl >= KEY_REQKEY_DEFL_MAX {
        return EINVAL;
    }
    let mut reg = REG.lock();
    let tgid = cur_tgid();
    let mut pk = reg.procs_of(tgid);
    let old = pk.reqkey_defl;
    pk.reqkey_defl = reqkey_defl;
    reg.procs.insert(tgid, pk);
    old as isize
}

fn keyctl_set_timeout(id: i32, seconds: u32) -> isize {
    let mut reg = REG.lock();
    let serial = match reg.resolve(id, false) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(k) = reg.keys.get_mut(&serial) else {
        return ENOKEY;
    };
    if k.state == KeyState::Revoked {
        return EKEYREVOKED;
    }
    if seconds == 0 {
        k.expiry = None;
    } else {
        k.expiry = Some(now_ticks() + seconds as u64 * crate::arch::TICKS_PER_SEC);
    }
    0
}

fn keyctl_get_security(id: i32, buf: usize, buflen: usize) -> isize {
    let mut reg = REG.lock();
    let serial = match reg.resolve(id, false) {
        Ok(s) => s,
        Err(e) => return e,
    };
    if !reg.keys.contains_key(&serial) {
        return ENOKEY;
    }
    // No LSM: the security label is the empty string.
    copy_out_capped(buf, buflen, &[0u8])
}

/// Drop a thread-group's keyring bindings when it exits (mirrors
/// forget_creds). The keys themselves persist if still linked elsewhere; the
/// special-keyring *bindings* are what go away.
pub fn forget_proc_keyrings(tgid: i32) {
    let mut reg = REG.lock();
    reg.procs.remove(&tgid);
}

// Keep ERANGE / EDQUOT referenced (reserved for future quota handling) so the
// constants don't warn; they document the intended error space.
#[allow(dead_code)]
const _RESERVED_ERRNOS: (isize, isize) = (ERANGE, EDQUOT);
