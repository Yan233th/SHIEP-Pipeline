use crate::error::{EcError, EcResult};
use crate::netstack_device::TunnelDevice;
use crate::output::{self, Scope};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};
use std::collections::{HashMap, VecDeque};
use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::sync::OnceLock;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static CONTROL_TX: OnceLock<mpsc::Sender<ControlMessage>> = OnceLock::new();
const OPEN_CONN_TIMEOUT: Duration = Duration::from_secs(10);
const SOCKET_BUFFER_CAPACITY: usize = 64 * 1024;
const MAX_CONTROL_BATCH: usize = 64;
const NETSTACK_CONTROL_DISCONNECTED: &str = "netstack control channel disconnected";

pub fn validate_netstack_preconditions() -> EcResult<()> {
    Ok(())
}

pub fn start_runtime(assigned_ip: [u8; 4]) -> EcResult<()> {
    if CONTROL_TX.get().is_some() {
        return Ok(());
    }

    let tunnel_rx = crate::protocol::take_tunnel_packet_receiver()?;
    let (control_tx, control_rx) = mpsc::channel::<ControlMessage>();
    let control_tx_for_runtime = control_tx.clone();
    CONTROL_TX
        .set(control_tx)
        .map_err(|_| EcError::Runtime("netstack runtime already initialized".to_string()))?;

    thread::spawn(move || {
        while let Ok(packet) = tunnel_rx.recv() {
            if control_tx_for_runtime
                .send(ControlMessage::TunnelPacket { packet })
                .is_err()
            {
                break;
            }
        }
    });

    thread::spawn(move || {
        if let Err(err) = run_netstack_loop(assigned_ip, control_rx) {
            let detail = format!("netstack closed: {}", crate::error::concise_error(err));
            output::error(Scope::Netstack, &detail);
            crate::protocol::record_runtime_fatal(detail);
        }
    });

    Ok(())
}

pub fn open_tcp_connection(target: &str) -> EcResult<TunnelTcpConnection> {
    let control = CONTROL_TX
        .get()
        .ok_or_else(|| EcError::Runtime("netstack runtime is not started".to_string()))?
        .clone();

    let target_addr = resolve_ipv4_target(target)?;
    let (reply_tx, reply_rx) = mpsc::channel::<EcResult<(u64, mpsc::Receiver<Vec<u8>>)>>();
    control
        .send(ControlMessage::Open {
            target: target_addr,
            reply: reply_tx,
        })
        .map_err(|e| EcError::Runtime(format!("send open connection request failed: {e}")))?;

    match reply_rx.recv_timeout(OPEN_CONN_TIMEOUT) {
        Ok(Ok((id, rx))) => Ok(TunnelTcpConnection {
            id,
            control_tx: control,
            rx,
        }),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(EcError::Runtime(format!(
            "wait open connection response failed for {target}: {e}"
        ))),
    }
}

#[derive(Debug)]
pub struct TunnelTcpConnection {
    id: u64,
    control_tx: mpsc::Sender<ControlMessage>,
    rx: mpsc::Receiver<Vec<u8>>,
}

impl TunnelTcpConnection {
    pub fn sender(&self) -> TunnelTcpSender {
        TunnelTcpSender {
            id: self.id,
            control_tx: self.control_tx.clone(),
        }
    }

    pub fn into_receiver(self) -> mpsc::Receiver<Vec<u8>> {
        self.rx
    }
}

#[derive(Clone, Debug)]
pub struct TunnelTcpSender {
    id: u64,
    control_tx: mpsc::Sender<ControlMessage>,
}

impl TunnelTcpSender {
    pub fn send(&self, data: Vec<u8>) -> EcResult<()> {
        self.control_tx
            .send(ControlMessage::Send { id: self.id, data })
            .map_err(|e| EcError::Runtime(format!("send tcp payload request failed: {e}")))
    }

    pub fn close(&self) -> EcResult<()> {
        self.control_tx
            .send(ControlMessage::Close { id: self.id })
            .map_err(|e| EcError::Runtime(format!("send tcp close request failed: {e}")))
    }
}

enum ControlMessage {
    TunnelPacket {
        packet: Vec<u8>,
    },
    Open {
        target: SocketAddrV4,
        reply: mpsc::Sender<EcResult<(u64, mpsc::Receiver<Vec<u8>>)>>,
    },
    Send {
        id: u64,
        data: Vec<u8>,
    },
    Close {
        id: u64,
    },
}

struct ConnectionState {
    handle: SocketHandle,
    uplink: mpsc::Sender<Vec<u8>>,
    pending_send: VecDeque<Vec<u8>>,
    close_requested: bool,
}

struct ControlDispatch<'a, 'b> {
    device: &'a mut TunnelDevice,
    iface: &'a mut Interface,
    sockets: &'a mut SocketSet<'b>,
    connections: &'a mut HashMap<u64, ConnectionState>,
    next_conn_id: &'a mut u64,
    next_local_port: &'a mut u16,
}

fn run_netstack_loop(
    assigned_ip: [u8; 4],
    control_rx: mpsc::Receiver<ControlMessage>,
) -> EcResult<()> {
    let mut device = TunnelDevice::new();
    let mut cfg = Config::new(HardwareAddress::Ip);
    cfg.random_seed = netstack_random_seed();
    let mut iface = Interface::new(cfg, &mut device, smol_now(Instant::now()));
    let client_ip = Ipv4Address::new(
        assigned_ip[0],
        assigned_ip[1],
        assigned_ip[2],
        assigned_ip[3],
    );
    iface.update_ip_addrs(|ip_addrs| {
        let _ = ip_addrs.push(IpCidr::new(IpAddress::Ipv4(client_ip), 0));
    });

    let mut sockets = SocketSet::new(vec![]);
    let mut connections = HashMap::<u64, ConnectionState>::new();
    let mut next_conn_id: u64 = 1;
    let mut next_local_port: u16 = 40000;
    let start = Instant::now();

    loop {
        let now = smol_now(start);
        let wait = iface
            .poll_delay(now, &sockets)
            .map(|delay| Duration::from_millis(delay.total_millis()));
        if let Some(msg) = wait_control_message(&control_rx, wait)? {
            let mut dispatch = ControlDispatch {
                device: &mut device,
                iface: &mut iface,
                sockets: &mut sockets,
                connections: &mut connections,
                next_conn_id: &mut next_conn_id,
                next_local_port: &mut next_local_port,
            };
            process_control_batch(msg, &control_rx, &mut dispatch)?;
        }

        let now = smol_now(start);
        let _ = iface.poll(now, &mut device, &mut sockets);
        drive_connections(&mut sockets, &mut connections);
    }
}

fn process_control_batch(
    first_msg: ControlMessage,
    control_rx: &mpsc::Receiver<ControlMessage>,
    dispatch: &mut ControlDispatch<'_, '_>,
) -> EcResult<()> {
    handle_control_message(first_msg, dispatch);
    for _ in 1..MAX_CONTROL_BATCH {
        let msg = match control_rx.try_recv() {
            Ok(msg) => msg,
            Err(mpsc::TryRecvError::Empty) => break,
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err(control_channel_disconnected_err());
            }
        };
        handle_control_message(msg, dispatch);
    }
    Ok(())
}

fn handle_control_message(msg: ControlMessage, dispatch: &mut ControlDispatch<'_, '_>) {
    match msg {
        ControlMessage::TunnelPacket { packet } => {
            dispatch.device.push_rx(packet);
        }
        ControlMessage::Open { target, reply } => {
            let result = open_connection(
                target,
                dispatch.iface,
                dispatch.sockets,
                dispatch.connections,
                dispatch.next_conn_id,
                dispatch.next_local_port,
            );
            let _ = reply.send(result);
        }
        ControlMessage::Send { id, data } => {
            if let Some(conn) = dispatch.connections.get_mut(&id) {
                conn.pending_send.push_back(data);
            }
        }
        ControlMessage::Close { id } => {
            if let Some(conn) = dispatch.connections.get_mut(&id) {
                conn.close_requested = true;
            }
        }
    }
}

fn wait_control_message(
    control_rx: &mpsc::Receiver<ControlMessage>,
    timeout: Option<Duration>,
) -> EcResult<Option<ControlMessage>> {
    match timeout {
        Some(delay) => match control_rx.recv_timeout(delay) {
            Ok(msg) => Ok(Some(msg)),
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(control_channel_disconnected_err()),
        },
        None => match control_rx.recv() {
            Ok(msg) => Ok(Some(msg)),
            Err(_) => Err(control_channel_disconnected_err()),
        },
    }
}

fn control_channel_disconnected_err() -> EcError {
    EcError::Runtime(NETSTACK_CONTROL_DISCONNECTED.to_string())
}

fn open_connection(
    target: SocketAddrV4,
    iface: &mut Interface,
    sockets: &mut SocketSet<'_>,
    connections: &mut HashMap<u64, ConnectionState>,
    next_conn_id: &mut u64,
    next_local_port: &mut u16,
) -> EcResult<(u64, mpsc::Receiver<Vec<u8>>)> {
    let socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER_CAPACITY]),
        tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER_CAPACITY]),
    );
    let handle = sockets.add(socket);
    let local_port = alloc_local_port(next_local_port);
    let connect_result = {
        let socket = sockets.get_mut::<tcp::Socket>(handle);
        socket.connect(
            iface.context(),
            (IpAddress::Ipv4(*target.ip()), target.port()),
            local_port,
        )
    };

    match connect_result {
        Ok(()) => {
            let (uplink_tx, uplink_rx) = mpsc::channel::<Vec<u8>>();
            let id = *next_conn_id;
            *next_conn_id = (*next_conn_id).wrapping_add(1);
            connections.insert(
                id,
                ConnectionState {
                    handle,
                    uplink: uplink_tx,
                    pending_send: VecDeque::new(),
                    close_requested: false,
                },
            );
            Ok((id, uplink_rx))
        }
        Err(e) => {
            let _ = sockets.remove(handle);
            Err(EcError::Runtime(format!("tcp connect failed: {e}")))
        }
    }
}

fn drive_connections(sockets: &mut SocketSet<'_>, connections: &mut HashMap<u64, ConnectionState>) {
    let mut remove_ids = Vec::new();
    for (id, conn) in connections.iter_mut() {
        let socket = sockets.get_mut::<tcp::Socket>(conn.handle);

        pump_pending_sends(socket, conn);
        pump_uplink_reads(socket, conn);

        if conn.close_requested && socket.may_send() {
            socket.close();
        }
        if !socket.is_open() {
            remove_ids.push(*id);
        }
    }

    for id in remove_ids {
        if let Some(conn) = connections.remove(&id) {
            let _ = sockets.remove(conn.handle);
        }
    }
}

fn pump_pending_sends(socket: &mut tcp::Socket, conn: &mut ConnectionState) {
    while socket.can_send() {
        let Some(mut chunk) = conn.pending_send.pop_front() else {
            break;
        };
        match socket.send_slice(&chunk) {
            Ok(sent) if sent == chunk.len() => {}
            Ok(sent) => {
                chunk.drain(..sent);
                conn.pending_send.push_front(chunk);
                break;
            }
            Err(_) => {
                conn.close_requested = true;
                break;
            }
        }
    }
}

fn pump_uplink_reads(socket: &mut tcp::Socket, conn: &mut ConnectionState) {
    while socket.can_recv() {
        let mut buf = [0u8; 4096];
        match socket.recv_slice(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if conn.uplink.send(buf[..n].to_vec()).is_err() {
                    conn.close_requested = true;
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

fn resolve_ipv4_target(target: &str) -> EcResult<SocketAddrV4> {
    let mut addrs = target
        .to_socket_addrs()
        .map_err(|e| EcError::Runtime(format!("resolve target failed: {target}: {e}")))?;
    addrs
        .find_map(|addr| match addr {
            SocketAddr::V4(v4) => Some(v4),
            SocketAddr::V6(_) => None,
        })
        .ok_or_else(|| EcError::Runtime(format!("no ipv4 address resolved for {target}")))
}

fn alloc_local_port(next: &mut u16) -> u16 {
    let port = *next;
    *next = if *next >= 60000 { 40000 } else { *next + 1 };
    port
}

fn netstack_random_seed() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x6e6574737461636b)
}

fn smol_now(start: Instant) -> SmolInstant {
    SmolInstant::from_millis(start.elapsed().as_millis() as i64)
}

#[cfg(test)]
mod tests {
    use super::{alloc_local_port, netstack_random_seed};

    #[test]
    fn alloc_local_port_wraps_after_60000() {
        let mut next = 60000;
        let p1 = alloc_local_port(&mut next);
        let p2 = alloc_local_port(&mut next);
        assert_eq!(p1, 60000);
        assert_eq!(p2, 40000);
    }

    #[test]
    fn random_seed_is_non_zero() {
        assert_ne!(netstack_random_seed(), 0);
    }
}
