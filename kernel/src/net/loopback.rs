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
        n
    }

    pub fn recv(&self, buf: &mut [u8]) -> usize {
        let mut q = self.incoming.buf.lock();
        let n = core::cmp::min(buf.len(), q.len());
        for slot in buf.iter_mut().take(n) {
            *slot = q.pop_front().unwrap();
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
pub struct UdpEnd {
    pub port: u16,
    pub incoming: Mutex<VecDeque<UdpDatagram>>,
}

pub struct UdpDatagram {
    pub src_port: u16,
    pub data: Vec<u8>,
}

/// Global registries. A single mutex per kind keeps the bookkeeping
/// simple — the critical sections are short.
static TCP_LISTENERS: Mutex<BTreeMap<u16, Weak<TcpListener>>> = Mutex::new(BTreeMap::new());
static UDP_BINDS: Mutex<BTreeMap<u16, Weak<UdpEnd>>> = Mutex::new(BTreeMap::new());

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
    Some(client)
}

// --- UDP -----------------------------------------------------------------

pub fn register_udp(port: u16) -> Arc<UdpEnd> {
    let e = Arc::new(UdpEnd {
        port,
        incoming: Mutex::new(VecDeque::new()),
    });
    UDP_BINDS.lock().insert(port, Arc::downgrade(&e));
    e
}

pub fn find_udp(port: u16) -> Option<Arc<UdpEnd>> {
    let mut m = UDP_BINDS.lock();
    let entry = m.get(&port)?.upgrade();
    if entry.is_none() {
        m.remove(&port);
    }
    entry
}

pub fn unregister_udp(port: u16) {
    UDP_BINDS.lock().remove(&port);
}

/// Deliver a datagram from `src_port` to `dst_port`. Returns true if a
/// receiver existed (so the sender can decide whether to error).
pub fn udp_deliver(dst_port: u16, src_port: u16, data: &[u8]) -> bool {
    let Some(dst) = find_udp(dst_port) else {
        // Auto-bind on first deliver: we treat 127.0.0.1 like a single host
        // where any port can sink datagrams (matches the way iperf3 -u runs
        // its server on a fixed port). Returning false would make sendto
        // fail and break unbound `iperf3 -c -u`.
        return false;
    };
    dst.incoming.lock().push_back(UdpDatagram {
        src_port,
        data: data.to_vec(),
    });
    true
}
