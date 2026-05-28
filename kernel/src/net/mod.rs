//! smoltcp glue: per-kernel `Interface` + `SocketSet`, virtio-net
//! `Device` adapter, blocking helpers for the socket syscall layer.
//!
//! QEMU user-mode networking defaults:
//!   - guest IP : 10.0.2.15/24
//!   - gateway  : 10.0.2.2  (the host)
//!   - DNS      : 10.0.2.3

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use spin::{Mutex, Once};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::storage::PacketMetadata;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv4Cidr};

use crate::drivers::virtio_net::{self, NetDev};

/// Number of microseconds since CPU boot. Used to feed smoltcp a
/// monotonic Instant.
fn now_ms() -> i64 {
    // `time` CSR is 10 MHz on QEMU virt → 10_000 ticks per ms.
    (riscv::register::time::read64() / 10_000) as i64
}

fn now() -> Instant {
    Instant::from_millis(now_ms())
}

/// Adapter exposing `NetDev` as smoltcp's `Device` trait.
pub struct VirtioPhy {
    dev: Arc<NetDev>,
    /// Per-call RX queue: we pop frames in `receive()` and hand a token
    /// that owns the frame buffer.
    cap_mtu: usize,
}

impl VirtioPhy {
    pub fn new(dev: Arc<NetDev>) -> Self {
        Self {
            dev,
            cap_mtu: 1514,
        }
    }
}

pub struct VirtioRxToken {
    buf: Vec<u8>,
}

pub struct VirtioTxToken {
    dev: Arc<NetDev>,
}

impl RxToken for VirtioRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.buf)
    }
}

impl TxToken for VirtioTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        // Ignore TX errors — same as a dropped frame on real hardware.
        let _ = self.dev.transmit(&buf);
        r
    }
}

impl Device for VirtioPhy {
    type RxToken<'a>
        = VirtioRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = VirtioTxToken
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let buf = self.dev.receive()?;
        Some((
            VirtioRxToken { buf },
            VirtioTxToken {
                dev: self.dev.clone(),
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(VirtioTxToken {
            dev: self.dev.clone(),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = self.cap_mtu;
        caps.max_burst_size = Some(1);
        caps.medium = Medium::Ethernet;
        caps
    }
}

/// All smoltcp state we own. Single global mutex.
pub struct NetStack {
    pub iface: Interface,
    pub sockets: SocketSet<'static>,
    pub phy: VirtioPhy,
    /// Monotonically-increasing source-port allocator for `connect()`.
    pub next_ephemeral: u16,
}

static STACK: Once<Mutex<NetStack>> = Once::new();

pub fn init() {
    let dev = match virtio_net::get() {
        Some(d) => d,
        None => {
            crate::println!("[net] no virtio-net device — networking disabled");
            return;
        }
    };

    let mut phy = VirtioPhy::new(dev.clone());
    let mac = dev.mac();
    let hw = EthernetAddress(mac);
    let mut cfg = Config::new(HardwareAddress::Ethernet(hw));
    cfg.random_seed = riscv::register::time::read64();

    let mut iface = Interface::new(cfg, &mut phy, now());
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::Ipv4(Ipv4Cidr::new(
            Ipv4Address::new(10, 0, 2, 15),
            24,
        )));
    });
    iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(10, 0, 2, 2))
        .expect("add default route");

    let sockets = SocketSet::new(Vec::with_capacity(8));

    STACK.call_once(|| {
        Mutex::new(NetStack {
            iface,
            sockets,
            phy,
            next_ephemeral: 49152,
        })
    });
    crate::println!("[net] smoltcp online: ip=10.0.2.15/24 gw=10.0.2.2");
}

pub fn is_up() -> bool {
    STACK.get().is_some()
}

pub fn with_stack<R>(f: impl FnOnce(&mut NetStack) -> R) -> Option<R> {
    let s = STACK.get()?;
    let mut guard = s.lock();
    Some(f(&mut *guard))
}

/// Drive the smoltcp poll loop. Safe to call from any syscall entry/exit.
/// No-op if the network stack isn't initialised.
pub fn poll() {
    let _ = poll_with_progress();
}

/// Same as `poll`, but returns true iff smoltcp processed at least one
/// packet or readied a socket. The scheduler uses this to decide
/// whether to wake socket-blocked tasks: waking unconditionally caused
/// a socket-blocked task (e.g. iperf3 server on `accept`) to thrash the
/// CPU, never letting any other task — including the `timeout` daemon
/// that's supposed to kill it — get scheduled.
pub fn poll_with_progress() -> bool {
    let Some(s) = STACK.get() else { return false };
    let mut g = s.lock();
    let t = now();
    let g = &mut *g;
    g.iface.poll(t, &mut g.phy, &mut g.sockets)
}

/// Allocate a fresh ephemeral source port (49152..=65535 wrap).
pub fn alloc_ephemeral() -> u16 {
    let Some(s) = STACK.get() else { return 49152 };
    let mut g = s.lock();
    let p = g.next_ephemeral;
    g.next_ephemeral = if p == 65535 { 49152 } else { p + 1 };
    p
}

// ---------- socket factory ----------

pub fn add_tcp_socket() -> Option<SocketHandle> {
    let s = STACK.get()?;
    let mut g = s.lock();
    let rx = tcp::SocketBuffer::new(vec![0u8; 8192]);
    let tx = tcp::SocketBuffer::new(vec![0u8; 8192]);
    let mut sock = tcp::Socket::new(rx, tx);
    // Match Linux default of TCP_NODELAY off — keep Nagle on so the smoltcp
    // tcp test loop matches what BSD/Linux do.
    sock.set_nagle_enabled(false);
    Some(g.sockets.add(sock))
}

pub fn add_udp_socket() -> Option<SocketHandle> {
    let s = STACK.get()?;
    let mut g = s.lock();
    let rx_meta = vec![PacketMetadata::EMPTY; 16];
    let tx_meta = vec![PacketMetadata::EMPTY; 16];
    let rx_payload = vec![0u8; 8192];
    let tx_payload = vec![0u8; 8192];
    let rx = udp::PacketBuffer::new(rx_meta, rx_payload);
    let tx = udp::PacketBuffer::new(tx_meta, tx_payload);
    let sock = udp::Socket::new(rx, tx);
    Some(g.sockets.add(sock))
}

pub fn remove_socket(handle: SocketHandle) {
    let Some(s) = STACK.get() else { return };
    let mut g = s.lock();
    let _ = g.sockets.remove(handle);
}

// ---------- helpers used by syscalls ----------

pub fn tcp_connect(
    handle: SocketHandle,
    remote_addr: Ipv4Address,
    remote_port: u16,
    local_port: u16,
) -> Result<(), i32> {
    let s = STACK.get().ok_or(-101i32)?; // ENETUNREACH
    let mut g = s.lock();
    let g = &mut *g;
    let sock = g.sockets.get_mut::<tcp::Socket>(handle);
    let cx = g.iface.context();
    sock.connect(cx, (IpAddress::Ipv4(remote_addr), remote_port), local_port)
        .map_err(|_| -22i32) // EINVAL
}

pub fn tcp_listen(handle: SocketHandle, port: u16) -> Result<(), i32> {
    let s = STACK.get().ok_or(-101i32)?;
    let mut g = s.lock();
    let sock = g.sockets.get_mut::<tcp::Socket>(handle);
    sock.listen(port).map_err(|_| -22i32)
}

pub fn tcp_state(handle: SocketHandle) -> Option<tcp::State> {
    let s = STACK.get()?;
    let g = s.lock();
    Some(g.sockets.get::<tcp::Socket>(handle).state())
}

pub fn tcp_may_recv(handle: SocketHandle) -> bool {
    let Some(s) = STACK.get() else { return false };
    let g = s.lock();
    g.sockets.get::<tcp::Socket>(handle).may_recv()
}

pub fn tcp_can_recv(handle: SocketHandle) -> bool {
    let Some(s) = STACK.get() else { return false };
    let g = s.lock();
    g.sockets.get::<tcp::Socket>(handle).can_recv()
}

pub fn tcp_can_send(handle: SocketHandle) -> bool {
    let Some(s) = STACK.get() else { return false };
    let g = s.lock();
    g.sockets.get::<tcp::Socket>(handle).can_send()
}

pub fn tcp_is_active(handle: SocketHandle) -> bool {
    let Some(s) = STACK.get() else { return false };
    let g = s.lock();
    g.sockets.get::<tcp::Socket>(handle).is_active()
}

pub fn tcp_recv(handle: SocketHandle, buf: &mut [u8]) -> Result<usize, i32> {
    let s = STACK.get().ok_or(-9i32)?;
    let mut g = s.lock();
    let sock = g.sockets.get_mut::<tcp::Socket>(handle);
    match sock.recv_slice(buf) {
        Ok(n) => Ok(n),
        Err(tcp::RecvError::Finished) => Ok(0),
        Err(_) => Err(-22),
    }
}

pub fn tcp_send(handle: SocketHandle, data: &[u8]) -> Result<usize, i32> {
    let s = STACK.get().ok_or(-9i32)?;
    let mut g = s.lock();
    let sock = g.sockets.get_mut::<tcp::Socket>(handle);
    sock.send_slice(data).map_err(|_| -32i32) // EPIPE
}

pub fn tcp_close(handle: SocketHandle) {
    let Some(s) = STACK.get() else { return };
    let mut g = s.lock();
    let sock = g.sockets.get_mut::<tcp::Socket>(handle);
    sock.close();
}

pub fn tcp_abort(handle: SocketHandle) {
    let Some(s) = STACK.get() else { return };
    let mut g = s.lock();
    let sock = g.sockets.get_mut::<tcp::Socket>(handle);
    sock.abort();
}

pub fn tcp_local_endpoint(handle: SocketHandle) -> Option<(Ipv4Address, u16)> {
    let s = STACK.get()?;
    let g = s.lock();
    let ep = g.sockets.get::<tcp::Socket>(handle).local_endpoint()?;
    match ep.addr {
        IpAddress::Ipv4(a) => Some((a, ep.port)),
    }
}

pub fn tcp_remote_endpoint(handle: SocketHandle) -> Option<(Ipv4Address, u16)> {
    let s = STACK.get()?;
    let g = s.lock();
    let ep = g.sockets.get::<tcp::Socket>(handle).remote_endpoint()?;
    match ep.addr {
        IpAddress::Ipv4(a) => Some((a, ep.port)),
    }
}

pub fn udp_bind(handle: SocketHandle, port: u16) -> Result<(), i32> {
    let s = STACK.get().ok_or(-101i32)?;
    let mut g = s.lock();
    let sock = g.sockets.get_mut::<udp::Socket>(handle);
    sock.bind(port).map_err(|_| -22i32)
}

pub fn udp_send(
    handle: SocketHandle,
    data: &[u8],
    remote_addr: Ipv4Address,
    remote_port: u16,
) -> Result<usize, i32> {
    let s = STACK.get().ok_or(-9i32)?;
    let mut g = s.lock();
    let sock = g.sockets.get_mut::<udp::Socket>(handle);
    // If the socket isn't bound yet, bind to an ephemeral port first.
    if sock.endpoint().port == 0 {
        let p = {
            let p = g.next_ephemeral;
            g.next_ephemeral = if p == 65535 { 49152 } else { p + 1 };
            p
        };
        let sock = g.sockets.get_mut::<udp::Socket>(handle);
        sock.bind(p).map_err(|_| -22i32)?;
    }
    let sock = g.sockets.get_mut::<udp::Socket>(handle);
    sock.send_slice(data, (IpAddress::Ipv4(remote_addr), remote_port))
        .map(|()| data.len())
        .map_err(|_| -32i32)
}

pub fn udp_recv(handle: SocketHandle, buf: &mut [u8]) -> Result<(usize, Ipv4Address, u16), i32> {
    let s = STACK.get().ok_or(-9i32)?;
    let mut g = s.lock();
    let sock = g.sockets.get_mut::<udp::Socket>(handle);
    match sock.recv_slice(buf) {
        Ok((n, meta)) => match meta.endpoint.addr {
            IpAddress::Ipv4(a) => Ok((n, a, meta.endpoint.port)),
        },
        Err(udp::RecvError::Exhausted) => Err(-11), // EAGAIN
        Err(_) => Err(-22),
    }
}

pub fn udp_can_recv(handle: SocketHandle) -> bool {
    let Some(s) = STACK.get() else { return false };
    let g = s.lock();
    g.sockets.get::<udp::Socket>(handle).can_recv()
}

pub fn udp_local_endpoint(handle: SocketHandle) -> Option<(Ipv4Address, u16)> {
    let s = STACK.get()?;
    let g = s.lock();
    let ep = g.sockets.get::<udp::Socket>(handle).endpoint();
    let port = ep.port;
    let addr = match ep.addr {
        Some(IpAddress::Ipv4(a)) => a,
        _ => Ipv4Address::new(0, 0, 0, 0),
    };
    Some((addr, port))
}

pub fn udp_close(handle: SocketHandle) {
    let Some(s) = STACK.get() else { return };
    let mut g = s.lock();
    let sock = g.sockets.get_mut::<udp::Socket>(handle);
    sock.close();
}
