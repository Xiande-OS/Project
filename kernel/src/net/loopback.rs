//! In-kernel TCP/UDP loopback for 127.0.0.1.
//!
//! smoltcp's `Interface` is single-IP (10.0.2.15) and doesn't route
//! 127.0.0.1, so user-space loopback workloads (iperf3 -c 127.0.0.1,
//! netperf -H 127.0.0.1) hit "Connection refused" before any packet
//! ever reaches the wire. We side-step smoltcp entirely for those
//! flows: a per-port registry of listeners, plus per-connection
//! VecDeque pipes for the two directions.
//!
//! Lifecycle of a TCP loopback connection:
//!
//!   server:                          client:
//!     socket()                         socket()
//!     bind(127.0.0.1:P) ───┐
//!     listen()             │
//!                          │
//!                          │           connect(127.0.0.1:P)
//!                          │             → register accept in queue,
//!                          │               build LoopbackPair
//!     accept() ◀───────────┘             → wait for accept
//!       takes pair.server side,            takes pair.client side
//!       returns new fd                    returns 0
//!
//! Once both ends have an `Arc<LoopbackEnd>`, send writes into the
//! peer's incoming queue and recv reads from our own.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use spin::Mutex;

/// One direction's byte pipe. ~64 KiB cap matches a typical TCP window;
/// when full the writer returns short / EAGAIN.
const BUF_CAP: usize = 65536;

pub struct Pipe {
    pub buf: Mutex<VecDeque<u8>>,
    /// Set when the *writer* shuts down its side. Reader then returns
    /// EOF once the buffer drains.
    pub closed: AtomicBool,
}

impl Pipe {
    pub fn new() -> Self {
        Self {
            buf: Mutex::new(VecDeque::with_capacity(BUF_CAP)),
            closed: AtomicBool::new(false),
        }
    }
}

/// One end of a TCP loopback connection. The two ends of the same
/// connection share `incoming`/`outgoing` swapped: A.outgoing == B.incoming.
pub struct LoopbackEnd {
    /// Bytes the peer has sent us, waiting to be read.
    pub incoming: Arc<Pipe>,
    /// Bytes we've sent, waiting for the peer to read.
    pub outgoing: Arc<Pipe>,
    /// Local (us) and remote (peer) endpoints.
    pub local_port: u16,
    pub remote_port: u16,
}

impl LoopbackEnd {
    /// Build the two ends of a fresh connection. `(client, server)`.
    pub fn pair(client_port: u16, server_port: u16) -> (Arc<Self>, Arc<Self>) {
        let c2s = Arc::new(Pipe::new());
        let s2c = Arc::new(Pipe::new());
        let client = Arc::new(LoopbackEnd {
            incoming: s2c.clone(),
            outgoing: c2s.clone(),
            local_port: client_port,
            remote_port: server_port,
        });
        let server = Arc::new(LoopbackEnd {
            incoming: c2s,
            outgoing: s2c,
            local_port: server_port,
            remote_port: client_port,
        });
        (client, server)
    }

    pub fn send(&self, data: &[u8]) -> usize {
        if self.outgoing.closed.load(Ordering::Acquire) {
            return 0;
        }
        let mut q = self.outgoing.buf.lock();
        let cap = BUF_CAP.saturating_sub(q.len());
        let n = core::cmp::min(cap, data.len());
        q.extend(data[..n].iter().copied());
        drop(q);
        // Wake the peer if it's blocked in a recv/select.
        if n > 0 {
            crate::task::wake_socket_waiters();
        }
        n
    }

    pub fn recv(&self, buf: &mut [u8]) -> usize {
        let mut q = self.incoming.buf.lock();
        let n = core::cmp::min(buf.len(), q.len());
        for slot in buf.iter_mut().take(n) {
            *slot = q.pop_front().unwrap();
        }
        let drained = !q.is_empty() || n > 0;
        drop(q);
        // Draining our incoming queue frees space in the peer's outgoing
        // queue; a peer blocked in send() on a full pipe must be woken.
        if drained && n > 0 {
            crate::task::wake_socket_waiters();
        }
        n
    }

    pub fn can_recv(&self) -> bool {
        !self.incoming.buf.lock().is_empty()
    }

    pub fn can_send(&self) -> bool {
        !self.outgoing.closed.load(Ordering::Acquire)
            && self.outgoing.buf.lock().len() < BUF_CAP
    }

    /// True if the peer has both stopped sending and drained our outgoing
    /// queue (i.e. nothing more will ever arrive).
    pub fn peer_eof(&self) -> bool {
        self.incoming.closed.load(Ordering::Acquire)
            && self.incoming.buf.lock().is_empty()
    }

    /// Half-close (we won't send any more).
    pub fn shutdown_write(&self) {
        self.outgoing.closed.store(true, Ordering::Release);
    }

    /// Full close (both directions).
    pub fn close(&self) {
        self.incoming.closed.store(true, Ordering::Release);
        self.outgoing.closed.store(true, Ordering::Release);
    }
}

impl Drop for LoopbackEnd {
    fn drop(&mut self) {
        // When the last fd holding this end goes away, signal EOF to the
        // peer so they get a proper recv()==0 rather than blocking forever.
        self.outgoing.closed.store(true, Ordering::Release);
    }
}

/// A listening TCP port. `pending` is the accept backlog; each entry is
/// the server-side `LoopbackEnd` that `connect()` has freshly built.
pub struct TcpListener {
    pub port: u16,
    pub pending: Mutex<VecDeque<Arc<LoopbackEnd>>>,
}

/// A bound UDP socket. Datagrams sent to this port land in `incoming`.
///
/// When `peer_port` is `None` the socket is wildcard-bound and accepts any
/// source. Once the application calls `connect(2)` the kernel pins the
/// expected source (see `set_udp_peer`) so we don't fan out per-flow
/// datagrams to sibling sockets that happen to share the listen port —
/// iperf3's `-P 5` UDP test keeps five data sockets plus one listener all
/// bound to `:5001`, and without filtering each datagram lands in *all*
/// six queues, blowing up the sequence-number bookkeeping (huge "lost"
/// counts) and burning CPU re-reading dupes.
pub struct UdpEnd {
    pub port: u16,
    pub incoming: Mutex<VecDeque<UdpDatagram>>,
    pub peer_port: Mutex<Option<u16>>,
}

pub struct UdpDatagram {
    pub src_port: u16,
    pub data: Vec<u8>,
}

/// Global registries. A single mutex per kind keeps the bookkeeping
/// simple — the critical sections are short.
static TCP_LISTENERS: Mutex<BTreeMap<u16, Weak<TcpListener>>> = Mutex::new(BTreeMap::new());
/// Multiple UDP sockets can bind the same port (iperf3's UDP server keeps a
/// wildcard listener *and* a per-flow socket on the test port). We deliver a
/// datagram to every live end on that port so whichever socket the app reads
/// from receives it — keeping only the last would silently drop data into the
/// wrong queue.
static UDP_BINDS: Mutex<BTreeMap<u16, Vec<Weak<UdpEnd>>>> = Mutex::new(BTreeMap::new());

/// Source-port allocator for connect/sendto when the socket isn't bound.
static NEXT_PORT: AtomicU16 = AtomicU16::new(40000);

pub fn alloc_ephemeral() -> u16 {
    let p = NEXT_PORT.fetch_add(1, Ordering::Relaxed);
    if p < 40000 {
        NEXT_PORT.store(40000, Ordering::Relaxed);
        return 40000;
    }
    p
}

/// Register a listener on `port`. Replaces any prior (dead) entry.
pub fn register_listener(port: u16) -> Arc<TcpListener> {
    let l = Arc::new(TcpListener {
        port,
        pending: Mutex::new(VecDeque::new()),
    });
    TCP_LISTENERS.lock().insert(port, Arc::downgrade(&l));
    l
}

/// Look up a live listener on `port`.
pub fn find_listener(port: u16) -> Option<Arc<TcpListener>> {
    let mut m = TCP_LISTENERS.lock();
    let entry = m.get(&port)?.upgrade();
    if entry.is_none() {
        m.remove(&port);
    }
    entry
}

pub fn unregister_listener(port: u16) {
    TCP_LISTENERS.lock().remove(&port);
}

/// Try to connect: if a listener is running on `dst_port`, build a pair,
/// enqueue the server side on its backlog, return the client side. If no
/// listener: return None (caller returns ECONNREFUSED).
pub fn try_connect(dst_port: u16, src_port_hint: u16) -> Option<Arc<LoopbackEnd>> {
    let listener = find_listener(dst_port)?;
    let local = if src_port_hint != 0 {
        src_port_hint
    } else {
        alloc_ephemeral()
    };
    let (client, server) = LoopbackEnd::pair(local, dst_port);
    listener.pending.lock().push_back(server);
    // A server parked in accept()/select() on this listener needs to wake
    // so it can pick up the freshly-queued connection.
    crate::task::wake_socket_waiters();
    Some(client)
}

// --- UDP -----------------------------------------------------------------

pub fn register_udp(port: u16) -> Arc<UdpEnd> {
    let e = Arc::new(UdpEnd {
        port,
        incoming: Mutex::new(VecDeque::new()),
        peer_port: Mutex::new(None),
    });
    let mut m = UDP_BINDS.lock();
    let v = m.entry(port).or_default();
    // Drop any dead weak refs while we're here.
    v.retain(|w| w.strong_count() > 0);
    v.push(Arc::downgrade(&e));
    e
}

/// Pin this socket's expected source port. Subsequent `udp_deliver` calls
/// only push into this end when the datagram's `src_port` matches. Pass
/// `None` to clear (treated as wildcard). Called from `sys_connect` on UDP.
pub fn set_udp_peer(end: &Arc<UdpEnd>, peer_port: Option<u16>) {
    *end.peer_port.lock() = peer_port;
}

/// Any one live end bound to `port` (used for getsockname-style lookups).
pub fn find_udp(port: u16) -> Option<Arc<UdpEnd>> {
    let mut m = UDP_BINDS.lock();
    let v = m.get_mut(&port)?;
    v.retain(|w| w.strong_count() > 0);
    if v.is_empty() {
        m.remove(&port);
        return None;
    }
    v.iter().find_map(|w| w.upgrade())
}

pub fn unregister_udp(port: u16) {
    let mut m = UDP_BINDS.lock();
    if let Some(v) = m.get_mut(&port) {
        v.retain(|w| w.strong_count() > 0);
        if v.is_empty() {
            m.remove(&port);
        }
    }
}

/// Deliver a datagram from `src_port` to `dst_port`. Returns true if at
/// least one receiver was picked.
///
/// Routing: prefer the connected end whose `peer_port == src_port`. If no
/// such end exists, fall back to a single wildcard (`peer_port == None`)
/// end. We never deliver to a connected end whose peer doesn't match —
/// otherwise iperf3's `-P N` UDP test (N data sockets all bound to the
/// same listen port) sees every datagram in every queue and the sequence
/// bookkeeping disintegrates.
///
/// If there is exactly one bound end and it's wildcard, we deliver
/// (covers single-stream UDP where the server's per-flow socket hasn't
/// been `connect()`ed yet at the moment the first packet arrives).
pub fn udp_deliver(dst_port: u16, src_port: u16, data: &[u8]) -> bool {
    let ends: Vec<Arc<UdpEnd>> = {
        let mut m = UDP_BINDS.lock();
        let Some(v) = m.get_mut(&dst_port) else {
            // No receiver bound. We treat 127.0.0.1 as a single host where
            // unbound ports silently sink datagrams (UDP is best-effort).
            return false;
        };
        v.retain(|w| w.strong_count() > 0);
        if v.is_empty() {
            m.remove(&dst_port);
            return false;
        }
        v.iter().filter_map(|w| w.upgrade()).collect()
    };
    if ends.is_empty() {
        return false;
    }
    // Pass 1: connected end matching src_port.
    let mut matched = false;
    for dst in &ends {
        if dst.peer_port.lock().map(|p| p == src_port).unwrap_or(false) {
            dst.incoming.lock().push_back(UdpDatagram {
                src_port,
                data: data.to_vec(),
            });
            matched = true;
            break;
        }
    }
    if !matched {
        // Pass 2: first wildcard end. iperf3's UDP server reads the initial
        // UDP_CONNECT_MSG off the wildcard prot_listener, then `connect()`s
        // a fresh peer-port-pinned socket and spawns a new wildcard
        // listener; both are bound to the same port at once. Without a
        // wildcard fallback the second client (in parallel mode) would
        // arrive at the FIRST stream's pinned socket and get dropped.
        for dst in &ends {
            if dst.peer_port.lock().is_none() {
                dst.incoming.lock().push_back(UdpDatagram {
                    src_port,
                    data: data.to_vec(),
                });
                matched = true;
                break;
            }
        }
    }
    // Wake any task blocked in recv/select on this UDP socket so the
    // scheduler can promote it back to Ready before the next time slice
    // expires.
    if matched {
        crate::task::wake_socket_waiters();
    }
    matched
}
