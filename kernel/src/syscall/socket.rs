//! POSIX socket syscalls.
//!
//! All AF_INET only (smoltcp only does IP). Blocking ops use the same
//! "mark Waiting + rewind sepc" pattern as `sys_wait4` — the scheduler
//! moves to another runnable task, and when we get re-scheduled we redo
//! the syscall and see if the network state has advanced.

use alloc::sync::Arc;
use alloc::vec::Vec;
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use smoltcp::wire::Ipv4Address;

use crate::fs::socket::{
    parse_sockaddr_in, write_sockaddr_in, AF_INET, SHUT_RD, SHUT_RDWR, SHUT_WR, SOCKADDR_IN_SIZE,
    SOCK_CLOEXEC, SOCK_DGRAM, SOCK_NONBLOCK, SOCK_STREAM, SockAddrIn, Socket, SocketKind,
};
use crate::fs::File;
use crate::net;
use crate::task::current_task;

const EBADF: isize = -9;
const EFAULT: isize = -14;
const EINVAL: isize = -22;
const EISCONN: isize = -106;
const ENOTSOCK: isize = -88;
const EAFNOSUPPORT: isize = -97;
const EPROTONOSUPPORT: isize = -93;
const ENETUNREACH: isize = -101;
const ECONNREFUSED: isize = -111;
const ECONNRESET: isize = -104;
const ENOTCONN: isize = -107;
const EAGAIN: isize = -11;
const EOPNOTSUPP: isize = -95;

/// True for 127.x.x.x or 0.0.0.0 — both of which the loopback shim should
/// service. (Most apps connect to 127.0.0.1 but a few bind to ANY and
/// reach themselves via localhost.)
fn is_loopback(a: Ipv4Address) -> bool {
    a.0[0] == 127 || a.0 == [0, 0, 0, 0]
}

/// Run `f` with a borrowed `&Socket` resolved from the fd table. Keeps the
/// `Arc<File>` alive for the duration of the call.
fn with_socket<R>(fd: i32, f: impl FnOnce(&Socket) -> R) -> Result<R, isize> {
    let task = current_task();
    let file = task.fd_table.lock().get(fd).ok_or(EBADF)?;
    let inode = file.inode.clone();
    if let Some(s) = inode.as_any().downcast_ref::<Socket>() {
        Ok(f(s))
    } else {
        Err(ENOTSOCK)
    }
}

/// Mark the current task Waiting and rewind sepc by 4 so the syscall
/// re-executes on wake-up. Caller's `dispatch()` will switch tasks via
/// `schedule_next_after_trap` because the state moved out of Running.
fn block_and_retry() {
    let me = current_task();
    crate::task::mark_socket_waiter(me.pid);
    *me.state.lock() = crate::task::TaskState::Waiting;
    unsafe {
        let tf = me.tf_ptr();
        (*tf).sepc -= 4;
    }
}

/// Wake ourselves (Waiting -> Ready) so on the next scheduler tick we get
/// rerun. The current syscall completes normally first; the rewound sepc
/// + Waiting state takes effect at trap exit.
fn _self_ready() {
    let me = current_task();
    *me.state.lock() = crate::task::TaskState::Ready;
}

// ---------- socket(2) ----------

pub fn sys_socket(family: i32, kind: i32, _proto: i32) -> isize {
    if family != AF_INET {
        return EAFNOSUPPORT;
    }
    let nonblock = (kind & SOCK_NONBLOCK) != 0;
    let cloexec = (kind & SOCK_CLOEXEC) != 0;
    let base = kind & !(SOCK_NONBLOCK | SOCK_CLOEXEC);
    let (sock_arc, _kind) = match base {
        SOCK_STREAM => {
            let h = match net::add_tcp_socket() {
                Some(h) => h,
                None => return ENETUNREACH,
            };
            (Socket::new_tcp(h), SocketKind::Tcp)
        }
        SOCK_DGRAM => {
            let h = match net::add_udp_socket() {
                Some(h) => h,
                None => return ENETUNREACH,
            };
            (Socket::new_udp(h), SocketKind::Udp)
        }
        _ => return EPROTONOSUPPORT,
    };
    if nonblock {
        sock_arc.state.lock().nonblock = true;
    }
    let file = Arc::new(File::from_inode(sock_arc, true, true, false));
    let task = current_task();
    let res = task.fd_table.lock().alloc(file, cloexec);
    match res {
        Ok(fd) => fd as isize,
        Err(e) => e as isize,
    }
}

// ---------- bind(2) ----------

pub fn sys_bind(fd: i32, addr_ptr: usize, addr_len: usize) -> isize {
    if addr_len < SOCKADDR_IN_SIZE {
        return EINVAL;
    }
    let task = current_task();
    let Some(bytes) = task.copy_in_bytes(addr_ptr, SOCKADDR_IN_SIZE) else {
        return EFAULT;
    };
    let Some(sa) = parse_sockaddr_in(&bytes) else {
        return EAFNOSUPPORT;
    };

    let res = with_socket(fd, |s| {
        s.state.lock().bound = Some(sa);
        match s.kind {
            SocketKind::Udp => {
                // Register the in-kernel loopback UDP receiver too — most
                // apps that bind to ANY (0.0.0.0) actually want to receive
                // from 127.0.0.1.
                if is_loopback(sa.addr) || sa.addr.0 == [0, 0, 0, 0] {
                    let ue = crate::net::loopback::register_udp(sa.port);
                    s.state.lock().udp_end = Some(ue);
                }
                net::udp_bind(s.handle, sa.port)
            }
            SocketKind::Tcp => Ok(()), // TCP bind is paired with listen; record only.
        }
    });
    match res {
        Ok(Ok(())) => 0,
        Ok(Err(e)) => e as isize,
        Err(e) => e,
    }
}

// ---------- listen(2) ----------

pub fn sys_listen(fd: i32, _backlog: i32) -> isize {
    let res = with_socket(fd, |s| {
        if s.kind != SocketKind::Tcp {
            return Err(EOPNOTSUPP);
        }
        let port = s.state.lock().bound.map(|a| a.port).unwrap_or(0);
        if port == 0 {
            return Err(EINVAL);
        }
        // Loopback listener — answers connect() to 127.0.0.1:port without
        // smoltcp. Always registered for TCP so 127.0.0.1 / 0.0.0.0 /
        // 10.0.2.15 binds all work.
        let listener = crate::net::loopback::register_listener(port);
        s.state.lock().listener = Some(listener);
        // smoltcp listen too, so external connects on 10.0.2.15 still work.
        let _ = net::tcp_listen(s.handle, port);
        s.state.lock().listening = true;
        Ok(())
    });
    match res {
        Ok(Ok(())) => 0,
        Ok(Err(e)) => e,
        Err(e) => e,
    }
}

// ---------- accept4(2) ----------

pub fn sys_accept4(fd: i32, sa_ptr: usize, sa_len_ptr: usize, flags: i32) -> isize {
    net::poll();
    // Loopback fast path first: if our listener has a pending server-end,
    // build a fresh socket around it and return.
    let listener = match with_socket(fd, |s| s.state.lock().listener.clone()) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if let Some(listener) = listener {
        let pending = listener.pending.lock().pop_front();
        if let Some(server_end) = pending {
            let peer_port = server_end.remote_port;
            // Build the accepted socket. We still need a smoltcp handle for
            // the Socket struct shape; tcp_abort/remove on drop will clean
            // it up (it'll be in `Closed`).
            let new_handle = match net::add_tcp_socket() {
                Some(h) => h,
                None => return ENETUNREACH,
            };
            let new_sock = Socket::new_tcp(new_handle);
            {
                let mut st = new_sock.state.lock();
                st.loopback = Some(server_end);
                st.peer = Some(SockAddrIn {
                    addr: Ipv4Address::new(127, 0, 0, 1),
                    port: peer_port,
                });
                st.bound = Some(SockAddrIn {
                    addr: Ipv4Address::new(127, 0, 0, 1),
                    port: listener.port,
                });
            }
            if sa_ptr != 0 {
                let sa = SockAddrIn { addr: Ipv4Address::new(127, 0, 0, 1), port: peer_port };
                let bytes = write_sockaddr_in(sa);
                let _ = current_task().copy_out_bytes(sa_ptr, &bytes);
                if sa_len_ptr != 0 {
                    let _ = current_task().copy_out_bytes(sa_len_ptr, &(SOCKADDR_IN_SIZE as u32).to_le_bytes());
                }
            }
            let new_file = Arc::new(File::from_inode(new_sock, true, true, false));
            let cloexec = (flags & SOCK_CLOEXEC) != 0;
            let task = current_task();
            return match task.fd_table.lock().alloc(new_file, cloexec) {
                Ok(nfd) => nfd as isize,
                Err(e) => e as isize,
            };
        }
    }
    // Look up the listening socket's handle + port.
    let listen_info = match with_socket(fd, |s| {
        if s.kind != SocketKind::Tcp || !s.state.lock().listening {
            None
        } else {
            Some((s.handle, s.state.lock().bound.map(|a| a.port).unwrap_or(0)))
        }
    }) {
        Ok(Some(v)) => v,
        Ok(None) => return EINVAL,
        Err(e) => return e,
    };
    let (handle, _port) = listen_info;
    // If the listening socket is in Established, an inbound connection
    // has landed in this very handle. Hand it off as a new fd and create
    // a fresh listening socket to replace this one.
    let state = match net::tcp_state(handle) {
        Some(s) => s,
        None => return EBADF,
    };
    match state {
        tcp::State::Established
        | tcp::State::SynReceived
        | tcp::State::CloseWait
        | tcp::State::FinWait1
        | tcp::State::FinWait2 => {
            // Drain peer address.
            let peer = net::tcp_remote_endpoint(handle).unwrap_or((Ipv4Address::new(0, 0, 0, 0), 0));
            if sa_ptr != 0 && sa_len_ptr != 0 {
                let sa = SockAddrIn { addr: peer.0, port: peer.1 };
                let bytes = write_sockaddr_in(sa);
                let _ = current_task().copy_out_bytes(sa_ptr, &bytes);
                let _ = current_task().copy_out_bytes(sa_len_ptr, &(SOCKADDR_IN_SIZE as u32).to_le_bytes());
            }
            // The accepted socket *is* the existing handle. To keep listen
            // behavior we'd want a backlog of multiple sockets; for M8 we
            // hand back the established handle and let the user re-listen
            // by calling listen() again on a fresh socket if they want.
            // Steal the existing handle into a new fd; bury the original
            // listening socket so its drop doesn't abort the connection.
            let task = current_task();
            let old_file = task.fd_table.lock().get(fd).unwrap();
            let new_sock = if let Some(s) = old_file.inode.as_any().downcast_ref::<Socket>() {
                s.state.lock().peer = Some(SockAddrIn { addr: peer.0, port: peer.1 });
                s.state.lock().listening = false;
                old_file.inode.clone()
            } else {
                return ENOTSOCK;
            };
            // Wrap into a NEW File so the caller gets a separate fd. The
            // original `fd` is left pointing at the same socket (so reads
            // from either fd work, which is the expected dup-like semantic
            // for our simplified backlog=1 model).
            let new_file = Arc::new(File::from_inode(new_sock, true, true, false));
            let cloexec = (flags & SOCK_CLOEXEC) != 0;
            return match task.fd_table.lock().alloc(new_file, cloexec) {
                Ok(nfd) => nfd as isize,
                Err(e) => e as isize,
            };
        }
        _ => {}
    }
    // Otherwise block and retry.
    block_and_retry();
    EAGAIN
}

// ---------- connect(2) ----------

pub fn sys_connect(fd: i32, addr_ptr: usize, addr_len: usize) -> isize {
    if addr_len < SOCKADDR_IN_SIZE {
        return EINVAL;
    }
    let task = current_task();
    let Some(bytes) = task.copy_in_bytes(addr_ptr, SOCKADDR_IN_SIZE) else {
        return EFAULT;
    };
    let Some(sa) = parse_sockaddr_in(&bytes) else {
        return EAFNOSUPPORT;
    };

    // Resolve handle + kind without holding fdtable across blocking.
    let info = match with_socket(fd, |s| (s.handle, s.kind, s.state.lock().peer)) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let (handle, kind, peer) = info;
    match kind {
        SocketKind::Udp => {
            // UDP "connect" = just remember the remote endpoint.
            let _ = with_socket(fd, |s| {
                s.state.lock().peer = Some(sa);
            });
            return 0;
        }
        SocketKind::Tcp => {
            // Loopback fast-path: connect to 127.0.0.1 looks up the
            // in-kernel listener registry and pairs us up without
            // touching smoltcp. The agent that added net/loopback.rs
            // forgot to wire this side — bind() already registers via
            // register_listener() but connect() was still going out
            // through smoltcp, which doesn't route 127.0.0.1 and so
            // returned ECONNREFUSED.
            if is_loopback(sa.addr) {
                let task = current_task();
                let lp_end = crate::net::loopback::try_connect(sa.port, 0);
                match lp_end {
                    Some(client_end) => {
                        with_socket(fd, |s| {
                            let mut st = s.state.lock();
                            st.loopback = Some(client_end);
                            st.peer = Some(SockAddrIn { addr: Ipv4Address::new(127, 0, 0, 1), port: sa.port });
                        }).ok();
                        let _ = task;
                        return 0;
                    }
                    None => return ECONNREFUSED,
                }
            }
            // First call: start the connect. Subsequent calls (after
            // block_and_retry) just inspect state.
            if peer.is_none() {
                let local_port = crate::fs::socket::next_ephemeral_port();
                if let Err(e) = net::tcp_connect(handle, sa.addr, sa.port, local_port) {
                    return e as isize;
                }
                let _ = with_socket(fd, |s| s.state.lock().peer = Some(sa));
            }
            // Drive smoltcp a couple of times so SYN goes out & the SYN/ACK
            // can arrive in one syscall whenever the host is fast.
            for _ in 0..4 {
                net::poll();
            }
            let st = net::tcp_state(handle).unwrap_or(tcp::State::Closed);
            match st {
                // Any state past handshake counts as "connected" — even
                // CloseWait can happen if the peer FINs right away.
                tcp::State::Established
                | tcp::State::CloseWait
                | tcp::State::FinWait1
                | tcp::State::FinWait2 => 0,
                tcp::State::SynSent | tcp::State::SynReceived => {
                    block_and_retry();
                    EAGAIN
                }
                tcp::State::Closed | tcp::State::TimeWait => ECONNREFUSED,
                _ => ECONNREFUSED,
            }
        }
    }
}

// ---------- sendto(2) ----------

pub fn sys_sendto(
    fd: i32,
    buf_ptr: usize,
    len: usize,
    _flags: i32,
    sa_ptr: usize,
    sa_len: usize,
) -> isize {
    let task = current_task();
    let Some(data) = task.copy_in_bytes(buf_ptr, len) else {
        return EFAULT;
    };
    let info = match with_socket(fd, |s| (s.handle, s.kind, s.state.lock().peer)) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let (handle, kind, peer) = info;

    match kind {
        SocketKind::Tcp => {
            // TCP ignores sockaddr.
            net::poll();
            match net::tcp_send(handle, &data) {
                Ok(0) => {
                    if !net::tcp_can_send(handle) && net::tcp_is_active(handle) {
                        // Buffer full and connection alive — block.
                        block_and_retry();
                        EAGAIN
                    } else if !net::tcp_is_active(handle) {
                        ECONNRESET
                    } else {
                        0
                    }
                }
                Ok(n) => {
                    net::poll();
                    n as isize
                }
                Err(e) => e as isize,
            }
        }
        SocketKind::Udp => {
            let dst = if sa_ptr != 0 && sa_len >= SOCKADDR_IN_SIZE {
                let Some(b) = task.copy_in_bytes(sa_ptr, SOCKADDR_IN_SIZE) else {
                    return EFAULT;
                };
                match parse_sockaddr_in(&b) {
                    Some(a) => a,
                    None => return EAFNOSUPPORT,
                }
            } else if let Some(p) = peer {
                p
            } else {
                return EINVAL;
            };
            match net::udp_send(handle, &data, dst.addr, dst.port) {
                Ok(n) => {
                    net::poll();
                    n as isize
                }
                Err(e) => e as isize,
            }
        }
    }
}

// ---------- recvfrom(2) ----------

pub fn sys_recvfrom(
    fd: i32,
    buf_ptr: usize,
    len: usize,
    _flags: i32,
    sa_ptr: usize,
    sa_len_ptr: usize,
) -> isize {
    let info = match with_socket(fd, |s| (s.handle, s.kind, s.state.lock().nonblock)) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let (handle, kind, nonblock) = info;
    net::poll();

    let task = current_task();
    let mut buf: Vec<u8> = alloc::vec![0u8; len];

    match kind {
        SocketKind::Tcp => {
            // If we got bytes, return them. If we got 0 and the connection
            // is still alive, block. If the connection is dead, return 0
            // (EOF) per POSIX.
            match net::tcp_recv(handle, &mut buf) {
                Ok(0) => {
                    if !net::tcp_may_recv(handle) {
                        return 0; // EOF
                    }
                    if nonblock {
                        return EAGAIN;
                    }
                    block_and_retry();
                    return EAGAIN;
                }
                Ok(n) => {
                    if task.copy_out_bytes(buf_ptr, &buf[..n]).is_none() {
                        return EFAULT;
                    }
                    if sa_ptr != 0 {
                        let peer = net::tcp_remote_endpoint(handle)
                            .unwrap_or((Ipv4Address::new(0, 0, 0, 0), 0));
                        let sa = SockAddrIn { addr: peer.0, port: peer.1 };
                        let bytes = write_sockaddr_in(sa);
                        let _ = task.copy_out_bytes(sa_ptr, &bytes);
                        if sa_len_ptr != 0 {
                            let _ = task.copy_out_bytes(
                                sa_len_ptr,
                                &(SOCKADDR_IN_SIZE as u32).to_le_bytes(),
                            );
                        }
                    }
                    n as isize
                }
                Err(e) => e as isize,
            }
        }
        SocketKind::Udp => {
            match net::udp_recv(handle, &mut buf) {
                Ok((n, src, port)) => {
                    if task.copy_out_bytes(buf_ptr, &buf[..n]).is_none() {
                        return EFAULT;
                    }
                    if sa_ptr != 0 {
                        let sa = SockAddrIn { addr: src, port };
                        let bytes = write_sockaddr_in(sa);
                        let _ = task.copy_out_bytes(sa_ptr, &bytes);
                        if sa_len_ptr != 0 {
                            let _ = task.copy_out_bytes(
                                sa_len_ptr,
                                &(SOCKADDR_IN_SIZE as u32).to_le_bytes(),
                            );
                        }
                    }
                    n as isize
                }
                Err(-11) => {
                    if nonblock {
                        EAGAIN
                    } else {
                        block_and_retry();
                        EAGAIN
                    }
                }
                Err(e) => e as isize,
            }
        }
    }
}

// ---------- getsockname / getpeername ----------

fn write_endpoint(addr_ptr: usize, len_ptr: usize, sa: SockAddrIn) -> isize {
    let task = current_task();
    let bytes = write_sockaddr_in(sa);
    if task.copy_out_bytes(addr_ptr, &bytes).is_none() {
        return EFAULT;
    }
    if len_ptr != 0 {
        let _ = task.copy_out_bytes(len_ptr, &(SOCKADDR_IN_SIZE as u32).to_le_bytes());
    }
    0
}

pub fn sys_getsockname(fd: i32, addr_ptr: usize, len_ptr: usize) -> isize {
    let res = with_socket(fd, |s| match s.kind {
        SocketKind::Tcp => net::tcp_local_endpoint(s.handle),
        SocketKind::Udp => net::udp_local_endpoint(s.handle),
    });
    match res {
        Ok(Some((a, p))) => write_endpoint(addr_ptr, len_ptr, SockAddrIn { addr: a, port: p }),
        Ok(None) => write_endpoint(addr_ptr, len_ptr, SockAddrIn::ANY),
        Err(e) => e,
    }
}

pub fn sys_getpeername(fd: i32, addr_ptr: usize, len_ptr: usize) -> isize {
    let res = with_socket(fd, |s| match s.kind {
        SocketKind::Tcp => net::tcp_remote_endpoint(s.handle),
        SocketKind::Udp => s.state.lock().peer.map(|p| (p.addr, p.port)),
    });
    match res {
        Ok(Some((a, p))) => write_endpoint(addr_ptr, len_ptr, SockAddrIn { addr: a, port: p }),
        Ok(None) => ENOTCONN,
        Err(e) => e,
    }
}

// ---------- setsockopt / getsockopt ----------

pub fn sys_setsockopt(_fd: i32, _level: i32, _optname: i32, _optval: usize, _optlen: i32) -> isize {
    // Stub OK for SO_REUSEADDR / SO_KEEPALIVE / SO_LINGER / TCP_NODELAY etc.
    0
}

pub fn sys_getsockopt(_fd: i32, level: i32, optname: i32, optval: usize, optlen_ptr: usize) -> isize {
    // Linux setsockopt(2) names (subset). iperf3 / netperf inspect a
    // handful of these and refuse to proceed if any return 0.
    const SOL_SOCKET: i32 = 1;
    const SOL_TCP: i32 = 6;
    const SO_SNDBUF: i32 = 7;
    const SO_RCVBUF: i32 = 8;
    const SO_ERROR: i32 = 4;
    const SO_TYPE: i32 = 3;
    const TCP_MAXSEG: i32 = 2;

    let task = current_task();
    let val: i32 = match (level, optname) {
        // 64 KiB matches our loopback pipe BUF_CAP and smoltcp default.
        (SOL_SOCKET, SO_SNDBUF) | (SOL_SOCKET, SO_RCVBUF) => 65536,
        // iperf3 multiplies SO_RCVBUF / 2 against -w; a non-zero value
        // is what it actually needs.
        (SOL_SOCKET, SO_ERROR) => 0,
        (SOL_SOCKET, SO_TYPE) => 1, // SOCK_STREAM
        (SOL_TCP, TCP_MAXSEG) => 1460,
        _ => 0,
    };
    if optval != 0 {
        let _ = task.copy_out_bytes(optval, &val.to_le_bytes());
    }
    if optlen_ptr != 0 {
        let _ = task.copy_out_bytes(optlen_ptr, &4u32.to_le_bytes());
    }
    0
}

// ---------- shutdown(2) ----------

pub fn sys_shutdown(fd: i32, how: i32) -> isize {
    let res = with_socket(fd, |s| match s.kind {
        SocketKind::Tcp => {
            match how {
                SHUT_WR | SHUT_RDWR => {
                    net::tcp_close(s.handle);
                }
                SHUT_RD => {
                    // smoltcp has no half-close on RX. Just no-op.
                }
                _ => return EINVAL,
            }
            0
        }
        SocketKind::Udp => {
            net::udp_close(s.handle);
            0
        }
    });
    match res {
        Ok(v) => v,
        Err(e) => e,
    }
}

// ---------- sendmsg / recvmsg ----------

#[repr(C)]
struct MsgHdr {
    msg_name: usize,
    msg_namelen: u32,
    _pad0: u32,
    msg_iov: usize,
    msg_iovlen: usize,
    msg_control: usize,
    msg_controllen: usize,
    msg_flags: i32,
    _pad1: u32,
}

#[repr(C)]
struct IoVec {
    base: usize,
    len: usize,
}

pub fn sys_sendmsg(fd: i32, msg_ptr: usize, flags: i32) -> isize {
    let task = current_task();
    let Some(bytes) = task.copy_in_bytes(msg_ptr, core::mem::size_of::<MsgHdr>()) else {
        return EFAULT;
    };
    let msg = unsafe { core::ptr::read(bytes.as_ptr() as *const MsgHdr) };
    if msg.msg_iovlen == 0 {
        return 0;
    }
    let iovs_size = msg.msg_iovlen * core::mem::size_of::<IoVec>();
    let Some(iovs_bytes) = task.copy_in_bytes(msg.msg_iov, iovs_size) else {
        return EFAULT;
    };
    let iovs = unsafe {
        core::slice::from_raw_parts(iovs_bytes.as_ptr() as *const IoVec, msg.msg_iovlen)
    };
    let mut total = 0isize;
    for v in iovs {
        if v.len == 0 {
            continue;
        }
        let n = sys_sendto(
            fd,
            v.base,
            v.len,
            flags,
            msg.msg_name,
            msg.msg_namelen as usize,
        );
        if n < 0 {
            if total == 0 {
                return n;
            }
            break;
        }
        total += n;
        if n as usize != v.len {
            break;
        }
    }
    total
}

pub fn sys_recvmsg(fd: i32, msg_ptr: usize, flags: i32) -> isize {
    let task = current_task();
    let Some(bytes) = task.copy_in_bytes(msg_ptr, core::mem::size_of::<MsgHdr>()) else {
        return EFAULT;
    };
    let msg = unsafe { core::ptr::read(bytes.as_ptr() as *const MsgHdr) };
    if msg.msg_iovlen == 0 {
        return 0;
    }
    let iovs_size = msg.msg_iovlen * core::mem::size_of::<IoVec>();
    let Some(iovs_bytes) = task.copy_in_bytes(msg.msg_iov, iovs_size) else {
        return EFAULT;
    };
    let iovs = unsafe {
        core::slice::from_raw_parts(iovs_bytes.as_ptr() as *const IoVec, msg.msg_iovlen)
    };
    let mut total = 0isize;
    let mut wrote_name = false;
    for v in iovs {
        if v.len == 0 {
            continue;
        }
        // For the first iovec we honor msg_name; subsequent ones use NULL.
        let (sa_ptr, sa_len_ptr) = if !wrote_name {
            wrote_name = true;
            // Pass &msg.msg_namelen back into addr-len for caller. We do
            // a tiny dance: recvfrom expects sa_len_ptr to be a u32* into
            // user memory pointing at the buffer length. msghdr.msg_namelen
            // is u32 inline in struct, so its address is msg_ptr+8.
            (msg.msg_name, msg_ptr + 8)
        } else {
            (0usize, 0usize)
        };
        let n = sys_recvfrom(fd, v.base, v.len, flags, sa_ptr, sa_len_ptr);
        if n < 0 {
            if total == 0 {
                return n;
            }
            break;
        }
        total += n;
        if (n as usize) < v.len {
            break;
        }
    }
    total
}

// Avoid unused-import warning in some builds.
#[allow(dead_code)]
fn _touch_handle(_h: SocketHandle) {}
