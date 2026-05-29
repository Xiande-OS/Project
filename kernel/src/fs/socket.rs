//! POSIX socket inode glue.
//!
//! Each `Socket` wraps one smoltcp socket handle. We expose it through the
//! VFS `Inode` trait so the per-task `FdTable` can store sockets the same
//! way it stores files and pipes. `read_at`/`write_at` perform non-blocking
//! send/recv; the syscall layer drives blocking when needed.

use alloc::sync::Arc;
use core::any::Any;
use core::sync::atomic::{AtomicU16, Ordering};
use spin::Mutex;

use smoltcp::iface::SocketHandle;
use smoltcp::wire::Ipv4Address;

use crate::net;
use crate::net::loopback::{LoopbackEnd, TcpListener, UdpEnd};

use super::{FileType, Inode, Result, EINVAL};

pub const AF_INET: i32 = 2;
pub const SOCK_STREAM: i32 = 1;
pub const SOCK_DGRAM: i32 = 2;
/// SOCK_NONBLOCK / SOCK_CLOEXEC may be ORed into the `type` argument.
pub const SOCK_NONBLOCK: i32 = 0o4000;
pub const SOCK_CLOEXEC: i32 = 0o2000000;

/// "How" values for `shutdown(2)`.
pub const SHUT_RD: i32 = 0;
pub const SHUT_WR: i32 = 1;
pub const SHUT_RDWR: i32 = 2;

#[derive(Debug, Clone, Copy)]
pub struct SockAddrIn {
    pub addr: Ipv4Address,
    pub port: u16,
}

impl SockAddrIn {
    pub const ANY: Self = Self {
        addr: Ipv4Address::new(0, 0, 0, 0),
        port: 0,
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketKind {
    Tcp,
    Udp,
}

pub struct SocketState {
    pub bound: Option<SockAddrIn>,
    pub peer: Option<SockAddrIn>,
    pub listening: bool,
    pub nonblock: bool,
    /// Set when this socket has been wired through the in-kernel loopback
    /// shim (sys_connect to 127.0.0.1 with a matching listener, or
    /// sys_accept handing back a server end). All TCP I/O bypasses smoltcp
    /// once this is `Some`.
    pub loopback: Option<Arc<LoopbackEnd>>,
    /// Set on the listening side. Accept pulls pending server-ends from
    /// the listener's backlog.
    pub listener: Option<Arc<TcpListener>>,
    /// Set on UDP sockets bound to 127.0.0.1 / 0.0.0.0 so datagram delivery
    /// works without going through smoltcp.
    pub udp_end: Option<Arc<UdpEnd>>,
    /// SO_RCVTIMEO value in mtime ticks (0 = no timeout). iperf3 sets a
    /// 30-second SO_RCVTIMEO on its UDP data socket so a blocking recvfrom
    /// that never sees a packet eventually times out instead of hanging
    /// forever. The recv path uses this with sleep_until to block up to
    /// `recv_timeout_ticks` and then surface EAGAIN. Treating it as a
    /// nonblock flag (return EAGAIN on the first empty queue check) breaks
    /// iperf3's UDP_CONNECT handshake, where the client writes a probe and
    /// then expects the server's reply to arrive shortly.
    pub recv_timeout_ticks: u64,
}

pub struct Socket {
    pub handle: SocketHandle,
    pub family: i32,
    pub kind: SocketKind,
    pub state: Mutex<SocketState>,
}

impl Socket {
    pub fn new_tcp(handle: SocketHandle) -> Arc<Self> {
        Arc::new(Self {
            handle,
            family: AF_INET,
            kind: SocketKind::Tcp,
            state: Mutex::new(SocketState {
                bound: None,
                peer: None,
                listening: false,
                nonblock: false,
                loopback: None,
                listener: None,
                udp_end: None,
                recv_timeout_ticks: 0,
            }),
        })
    }

    pub fn new_udp(handle: SocketHandle) -> Arc<Self> {
        Arc::new(Self {
            handle,
            family: AF_INET,
            kind: SocketKind::Udp,
            state: Mutex::new(SocketState {
                bound: None,
                peer: None,
                listening: false,
                nonblock: false,
                loopback: None,
                listener: None,
                udp_end: None,
                recv_timeout_ticks: 0,
            }),
        })
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        // If this was a loopback listener/binding, unregister so a later
        // socket can rebind the same port (iperf3 starts a fresh server
        // for each sub-test).
        let st = self.state.lock();
        if let Some(l) = st.listener.as_ref() {
            crate::net::loopback::unregister_listener(l.port);
        }
        if let Some(u) = st.udp_end.as_ref() {
            crate::net::loopback::unregister_udp(u.port);
        }
        if let Some(lb) = st.loopback.as_ref() {
            // Mark our outgoing pipe closed so the peer's recv returns EOF.
            lb.close();
        }
        drop(st);
        // Close + remove from smoltcp.
        match self.kind {
            SocketKind::Tcp => {
                net::tcp_abort(self.handle);
            }
            SocketKind::Udp => {
                net::udp_close(self.handle);
            }
        }
        net::remove_socket(self.handle);
    }
}

impl Inode for Socket {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn kind(&self) -> FileType {
        // Linux reports sockets with S_IFSOCK; we don't have that variant.
        // Pipe is the closest in spirit (FIFO). The shell only uses kind()
        // for stat() decoration; busybox doesn't care about S_IFSOCK here.
        FileType::Pipe
    }
    fn read_at(&self, _off: u64, buf: &mut [u8]) -> Result<usize> {
        // Best-effort non-blocking read. The syscall layer (recvfrom) is
        // responsible for the blocking dance — direct file `read()` is
        // for the SYS_READ shim path.
        // Loopback TCP fast path (set by sys_connect / sys_accept).
        if let Some(lb) = self.state.lock().loopback.clone() {
            let n = lb.recv(buf);
            if n == 0 && lb.peer_eof() {
                return Ok(0);
            }
            return Ok(n);
        }
        // Loopback UDP fast path: pop from our incoming queue.
        if let Some(ue) = self.state.lock().udp_end.clone() {
            let dg = ue.incoming.lock().pop_front();
            if let Some(dg) = dg {
                let n = core::cmp::min(buf.len(), dg.data.len());
                buf[..n].copy_from_slice(&dg.data[..n]);
                return Ok(n);
            }
            // No datagram available; return EAGAIN-equivalent through the
            // VFS error path the same way smoltcp would.
            return Err(super::EAGAIN);
        }
        net::poll();
        match self.kind {
            SocketKind::Tcp => net::tcp_recv(self.handle, buf),
            SocketKind::Udp => {
                let (n, _addr, _port) = net::udp_recv(self.handle, buf)?;
                Ok(n)
            }
        }
    }
    fn write_at(&self, _off: u64, buf: &[u8]) -> Result<usize> {
        // Loopback TCP fast path.
        if let Some(lb) = self.state.lock().loopback.clone() {
            let n = lb.send(buf);
            // A full pipe must surface as EAGAIN, not a 0-byte write:
            // iperf3's Nwrite treats write()==0 as a hard error / spins,
            // whereas EAGAIN sends it back to select to wait for room.
            if n == 0 && !buf.is_empty() {
                if lb.can_send() {
                    // Peer still alive but momentarily wedged: report EAGAIN.
                    return Err(super::EAGAIN);
                }
                // Peer closed its receive side -> broken pipe.
                return Err(super::EAGAIN);
            }
            return Ok(n);
        }
        match self.kind {
            SocketKind::Tcp => {
                let r = net::tcp_send(self.handle, buf);
                net::poll();
                r
            }
            SocketKind::Udp => {
                let peer = self.state.lock().peer;
                let Some(p) = peer else {
                    return Err(EINVAL);
                };
                // Loopback UDP fast path: deliver into the in-kernel registry
                // instead of letting smoltcp drop the packet (no 127.0.0.1
                // route on the smoltcp interface).
                if p.addr.0[0] == 127 || p.addr.0 == [0, 0, 0, 0] {
                    let mut st = self.state.lock();
                    let src_port = if let Some(ue) = st.udp_end.as_ref() {
                        ue.port
                    } else {
                        let port = st
                            .bound
                            .map(|b| b.port)
                            .filter(|p| *p != 0)
                            .unwrap_or_else(crate::net::loopback::alloc_ephemeral);
                        let ue = crate::net::loopback::register_udp(port);
                        st.udp_end = Some(ue);
                        st.bound = Some(SockAddrIn {
                            addr: Ipv4Address::new(127, 0, 0, 1),
                            port,
                        });
                        port
                    };
                    drop(st);
                    let _ = crate::net::loopback::udp_deliver(p.port, src_port, buf);
                    return Ok(buf.len());
                }
                let r = net::udp_send(self.handle, buf, p.addr, p.port);
                net::poll();
                r
            }
        }
    }
}

// ---- sockaddr_in (Linux) -----------------------------------------------

pub const SOCKADDR_IN_SIZE: usize = 16;

pub fn parse_sockaddr_in(bytes: &[u8]) -> Option<SockAddrIn> {
    if bytes.len() < SOCKADDR_IN_SIZE {
        return None;
    }
    let family = u16::from_le_bytes([bytes[0], bytes[1]]);
    if family != AF_INET as u16 {
        return None;
    }
    let port = u16::from_be_bytes([bytes[2], bytes[3]]);
    let a = [bytes[4], bytes[5], bytes[6], bytes[7]];
    Some(SockAddrIn {
        addr: Ipv4Address::new(a[0], a[1], a[2], a[3]),
        port,
    })
}

pub fn write_sockaddr_in(addr: SockAddrIn) -> [u8; SOCKADDR_IN_SIZE] {
    let mut out = [0u8; SOCKADDR_IN_SIZE];
    out[0..2].copy_from_slice(&(AF_INET as u16).to_le_bytes());
    out[2..4].copy_from_slice(&addr.port.to_be_bytes());
    out[4..8].copy_from_slice(&addr.addr.0);
    // bytes 8..15 are zero (sin_zero).
    out
}

/// Allocator for ephemeral source ports used by TCP `connect()`.
static NEXT_EPHEMERAL: AtomicU16 = AtomicU16::new(49152);

pub fn next_ephemeral_port() -> u16 {
    let mut p = NEXT_EPHEMERAL.fetch_add(1, Ordering::Relaxed);
    if p < 49152 || p == 0 {
        NEXT_EPHEMERAL.store(49152, Ordering::Relaxed);
        p = 49152;
    }
    p
}

pub fn init() {
    net::init();
}
