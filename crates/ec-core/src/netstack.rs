use crate::error::{EcError, EcResult};
use crate::netstack_device::TunnelDevice;
use crate::output::{self, Scope};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::{AnySocket, tcp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};
use std::collections::HashMap;
use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::sync::OnceLock;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static CONTROL_TX: OnceLock<mpsc::Sender<ControlMessage>> = OnceLock::new();
const OPEN_CONN_TIMEOUT: Duration = Duration::from_secs(10);
const SOCKET_BUFFER_CAPACITY: usize = 64 * 1024;
const RECEIVE_CHUNK_SIZE: usize = 4096;
const MAX_CONTROL_BATCH: usize = 64;
const LOCAL_PORT_START: u16 = 40000;
const LOCAL_PORT_END: u16 = 60000;
const LOCAL_PORT_COUNT: usize = (LOCAL_PORT_END - LOCAL_PORT_START) as usize + 1;
const NETSTACK_CONTROL_DISCONNECTED: &str = "netstack control channel disconnected";

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
            crate::runtime_state::record_fatal(detail);
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
    let (reply_tx, reply_rx) = mpsc::channel::<EcResult<OpenedTcpConnection>>();
    control
        .send(ControlMessage::Open {
            target: target_addr,
            reply: reply_tx,
        })
        .map_err(|e| EcError::Runtime(format!("send open connection request failed: {e}")))?;

    match reply_rx.recv() {
        Ok(Ok(opened)) => Ok(TunnelTcpConnection {
            sender: TunnelTcpSender {
                id: opened.id,
                control_tx: control.clone(),
                send_result_rx: opened.send_result_rx,
                closed: false,
            },
            receiver: TunnelTcpReceiver {
                id: opened.id,
                control_tx: control,
                rx: opened.uplink_rx,
                pending: false,
                finished: false,
            },
        }),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(EcError::Runtime(format!(
            "wait open connection response failed for {target}: {e}"
        ))),
    }
}

#[derive(Debug)]
pub struct TunnelTcpConnection {
    sender: TunnelTcpSender,
    receiver: TunnelTcpReceiver,
}

impl TunnelTcpConnection {
    pub fn into_parts(self) -> (TunnelTcpSender, TunnelTcpReceiver) {
        (self.sender, self.receiver)
    }
}

#[derive(Debug)]
pub struct TunnelTcpSender {
    id: u64,
    control_tx: mpsc::Sender<ControlMessage>,
    send_result_rx: mpsc::Receiver<EcResult<()>>,
    closed: bool,
}

impl TunnelTcpSender {
    pub fn send(&self, data: Vec<u8>) -> EcResult<()> {
        self.control_tx
            .send(ControlMessage::Send { id: self.id, data })
            .map_err(|e| EcError::Runtime(format!("send tcp payload request failed: {e}")))?;
        self.send_result_rx
            .recv()
            .map_err(|e| EcError::Runtime(format!("wait tcp payload admission failed: {e}")))?
    }

    pub fn close(mut self) -> EcResult<()> {
        self.closed = true;
        self.control_tx
            .send(ControlMessage::Close { id: self.id })
            .map_err(|e| EcError::Runtime(format!("send tcp close request failed: {e}")))
    }
}

impl Drop for TunnelTcpSender {
    fn drop(&mut self) {
        if !self.closed {
            let _ = self.control_tx.send(ControlMessage::Abort { id: self.id });
        }
    }
}

#[derive(Debug)]
pub struct TunnelTcpReceiver {
    id: u64,
    control_tx: mpsc::Sender<ControlMessage>,
    rx: mpsc::Receiver<EcResult<TunnelTcpRead>>,
    pending: bool,
    finished: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TunnelTcpRead {
    Data(Vec<u8>),
    Eof,
    Closed,
}

impl TunnelTcpReceiver {
    pub fn recv(&mut self) -> EcResult<TunnelTcpRead> {
        // Asking for the next chunk acknowledges consumption of the previous one.
        if self.pending {
            let _ = self
                .control_tx
                .send(ControlMessage::Received { id: self.id });
            self.pending = false;
        }
        let result = self.rx.recv().unwrap_or_else(|_| {
            Err(EcError::Runtime(
                "netstack receive channel disconnected".to_string(),
            ))
        });
        self.pending = matches!(result, Ok(TunnelTcpRead::Data(_)));
        self.finished = matches!(result, Ok(TunnelTcpRead::Closed) | Err(_));
        result
    }
}

impl Drop for TunnelTcpReceiver {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.control_tx.send(ControlMessage::Abort { id: self.id });
        }
    }
}

enum ControlMessage {
    TunnelPacket {
        packet: Vec<u8>,
    },
    Open {
        target: SocketAddrV4,
        reply: mpsc::Sender<EcResult<OpenedTcpConnection>>,
    },
    Send {
        id: u64,
        data: Vec<u8>,
    },
    Close {
        id: u64,
    },
    Received {
        id: u64,
    },
    Abort {
        id: u64,
    },
}

struct OpenedTcpConnection {
    id: u64,
    uplink_rx: mpsc::Receiver<EcResult<TunnelTcpRead>>,
    send_result_rx: mpsc::Receiver<EcResult<()>>,
}

struct ConnectionState {
    handle: SocketHandle,
    uplink: mpsc::Sender<EcResult<TunnelTcpRead>>,
    send_result: mpsc::Sender<EcResult<()>>,
    pending_send: Option<PendingSend>,
    receive_pending: bool,
    remote_fin: bool,
    receive_eof: bool,
    relay_closed: bool,
    aborted: bool,
    close_requested: bool,
    opening: Option<PendingOpen>,
}

struct PendingOpen {
    reply: mpsc::Sender<EcResult<OpenedTcpConnection>>,
    opened: OpenedTcpConnection,
    deadline: SmolInstant,
}

struct PendingSend {
    data: Vec<u8>,
    offset: usize,
}

impl PendingSend {
    fn new(data: Vec<u8>) -> Self {
        Self { data, offset: 0 }
    }

    fn remaining(&self) -> &[u8] {
        &self.data[self.offset..]
    }

    fn advance(&mut self, sent: usize) {
        self.offset += sent;
    }

    fn is_complete(&self) -> bool {
        self.offset == self.data.len()
    }
}

struct ControlDispatch<'a, 'b> {
    device: &'a mut TunnelDevice,
    iface: &'a mut Interface,
    sockets: &'a mut SocketSet<'b>,
    connections: &'a mut HashMap<u64, ConnectionState>,
    next_conn_id: &'a mut u64,
    next_local_port: &'a mut u16,
    now: SmolInstant,
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
    let mut next_local_port = LOCAL_PORT_START;
    let start = Instant::now();

    loop {
        let now = smol_now(start);
        let tcp_wait = iface
            .poll_delay(now, &sockets)
            .map(|delay| Duration::from_millis(delay.total_millis()));
        let wait = connection_wait(tcp_wait, &connections, now);
        if let Some(msg) = wait_control_message(&control_rx, wait)? {
            let mut dispatch = ControlDispatch {
                device: &mut device,
                iface: &mut iface,
                sockets: &mut sockets,
                connections: &mut connections,
                next_conn_id: &mut next_conn_id,
                next_local_port: &mut next_local_port,
                now: smol_now(start),
            };
            process_control_batch(msg, &control_rx, &mut dispatch)?;
        }

        let now = smol_now(start);
        let _ = iface.poll(now, &mut device, &mut sockets);
        drive_connections(&mut sockets, &mut connections, now);
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
            match result {
                Ok(opened) => {
                    let conn = dispatch.connections.get_mut(&opened.id).unwrap();
                    conn.opening = Some(PendingOpen {
                        reply,
                        opened,
                        deadline: dispatch.now
                            + smoltcp::time::Duration::from_millis(
                                OPEN_CONN_TIMEOUT.as_millis() as u64
                            ),
                    });
                }
                Err(err) => {
                    let _ = reply.send(Err(err));
                }
            }
        }
        ControlMessage::Send { id, data } => {
            if let Some(conn) = dispatch.connections.get_mut(&id) {
                if conn.pending_send.is_none() {
                    conn.pending_send = Some(PendingSend::new(data));
                } else {
                    fail_pending_send(
                        conn,
                        EcError::Runtime("multiple tcp payloads pending admission".to_string()),
                    );
                }
            }
        }
        ControlMessage::Close { id } => {
            if let Some(conn) = dispatch.connections.get_mut(&id) {
                conn.close_requested = true;
            }
        }
        ControlMessage::Received { id } => {
            if let Some(conn) = dispatch.connections.get_mut(&id) {
                conn.receive_pending = false;
            }
        }
        ControlMessage::Abort { id } => {
            if let Some(conn) = dispatch.connections.get_mut(&id) {
                conn.aborted = true;
                dispatch.sockets.get_mut::<tcp::Socket>(conn.handle).abort();
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
) -> EcResult<OpenedTcpConnection> {
    let local_port = alloc_local_port(
        next_local_port,
        sockets.iter().filter_map(|(_, socket)| {
            tcp::Socket::downcast(socket)
                .and_then(tcp::Socket::local_endpoint)
                .map(|endpoint| endpoint.port)
        }),
    )?;
    let socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER_CAPACITY]),
        tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER_CAPACITY]),
    );
    let handle = sockets.add(socket);
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
            let (uplink_tx, uplink_rx) = mpsc::channel();
            let (send_result_tx, send_result_rx) = mpsc::channel::<EcResult<()>>();
            let id = *next_conn_id;
            *next_conn_id = (*next_conn_id).wrapping_add(1);
            connections.insert(
                id,
                ConnectionState {
                    handle,
                    uplink: uplink_tx,
                    send_result: send_result_tx,
                    pending_send: None,
                    receive_pending: false,
                    remote_fin: false,
                    receive_eof: false,
                    relay_closed: false,
                    aborted: false,
                    close_requested: false,
                    opening: None,
                },
            );
            Ok(OpenedTcpConnection {
                id,
                uplink_rx,
                send_result_rx,
            })
        }
        Err(e) => {
            let _ = sockets.remove(handle);
            Err(EcError::Runtime(format!("tcp connect failed: {e}")))
        }
    }
}

fn connection_wait(
    tcp_wait: Option<Duration>,
    connections: &HashMap<u64, ConnectionState>,
    now: SmolInstant,
) -> Option<Duration> {
    connections
        .values()
        .filter_map(|conn| {
            // A peer reset may leave no TCP timer. Still finish an outstanding abort.
            if conn.aborted {
                return Some(Duration::ZERO);
            }
            let pending = conn.opening.as_ref()?;
            if now >= pending.deadline {
                Some(Duration::ZERO)
            } else {
                Some(Duration::from_millis(
                    (pending.deadline - now).total_millis(),
                ))
            }
        })
        .chain(tcp_wait)
        .min()
}

fn drive_connections(
    sockets: &mut SocketSet<'_>,
    connections: &mut HashMap<u64, ConnectionState>,
    now: SmolInstant,
) {
    let mut remove_ids = Vec::new();
    for (id, conn) in connections.iter_mut() {
        let socket = sockets.get_mut::<tcp::Socket>(conn.handle);

        // An abort gets one interface poll to dispatch its RST before removal.
        if conn.aborted {
            // The relay that cancelled the connection already owns its error, if any.
            let _ = conn.uplink.send(Ok(TunnelTcpRead::Closed));
            if conn.pending_send.is_some() {
                fail_pending_send(conn, EcError::Runtime("tcp connection aborted".to_string()));
            }
            remove_ids.push(*id);
            continue;
        }

        // Relay completion must not discard smoltcp's TIME_WAIT state and timer.
        if conn.relay_closed {
            if socket.state() == tcp::State::Closed {
                remove_ids.push(*id);
            }
            continue;
        }

        if let Some(pending) = conn.opening.as_ref() {
            let error = if conn.close_requested {
                Some("tcp connect cancelled")
            } else if now >= pending.deadline {
                Some("tcp connect timed out after 10s")
            } else if !socket.is_open() {
                Some("tcp connection refused or reset during handshake")
            } else {
                None
            };
            if let Some(message) = error {
                let pending = conn.opening.take().unwrap();
                let _ = pending
                    .reply
                    .send(Err(EcError::Runtime(message.to_string())));
                socket.abort();
                conn.aborted = true;
                continue;
            }
            if socket.may_send() {
                let pending = conn.opening.take().unwrap();
                if pending.reply.send(Ok(pending.opened)).is_err() {
                    socket.abort();
                    conn.aborted = true;
                    continue;
                }
            } else {
                continue;
            }
        }

        if matches!(
            socket.state(),
            tcp::State::CloseWait
                | tcp::State::LastAck
                | tcp::State::Closing
                | tcp::State::TimeWait
        ) {
            conn.remote_fin = true;
        }
        if socket.state() == tcp::State::Closed && !(conn.close_requested && conn.remote_fin) {
            fail_connection(conn, "tcp connection reset by peer");
            remove_ids.push(*id);
            continue;
        }

        pump_pending_sends(socket, conn);
        pump_uplink_reads(socket, conn);

        if conn.close_requested && conn.pending_send.is_none() {
            socket.close();
        }
        if !socket.is_open() {
            if conn.pending_send.is_some() {
                fail_pending_send(
                    conn,
                    EcError::Runtime(
                        "tcp connection closed before payload admission completed".to_string(),
                    ),
                );
            }
            if !socket.can_recv() && !conn.aborted {
                let _ = conn.uplink.send(Ok(TunnelTcpRead::Closed));
                conn.relay_closed = true;
                if socket.state() == tcp::State::Closed {
                    remove_ids.push(*id);
                }
            }
        }
    }

    for id in remove_ids {
        if let Some(conn) = connections.remove(&id) {
            let _ = sockets.remove(conn.handle);
        }
    }
}

fn fail_connection(conn: &mut ConnectionState, reason: &str) {
    let _ = conn.uplink.send(Err(EcError::Runtime(reason.to_string())));
    if conn.pending_send.is_some() {
        fail_pending_send(conn, EcError::Runtime(reason.to_string()));
    }
}

fn pump_pending_sends(socket: &mut tcp::Socket, conn: &mut ConnectionState) {
    while socket.can_send() {
        let Some(pending) = conn.pending_send.as_mut() else {
            break;
        };

        if pending.is_complete() {
            complete_pending_send(conn);
            break;
        }

        match socket.send_slice(pending.remaining()) {
            Ok(0) => break,
            Ok(sent) => {
                pending.advance(sent);
                if pending.is_complete() {
                    complete_pending_send(conn);
                } else {
                    break;
                }
            }
            Err(err) => {
                fail_pending_send(
                    conn,
                    EcError::Runtime(format!("tcp payload admission failed: {err}")),
                );
                break;
            }
        }
    }
}

fn complete_pending_send(conn: &mut ConnectionState) {
    conn.pending_send = None;
    if conn.send_result.send(Ok(())).is_err() {
        conn.close_requested = true;
    }
}

fn fail_pending_send(conn: &mut ConnectionState, err: EcError) {
    conn.pending_send = None;
    let _ = conn.send_result.send(Err(err));
    conn.close_requested = true;
}

fn pump_uplink_reads(socket: &mut tcp::Socket, conn: &mut ConnectionState) {
    if conn.receive_eof {
        return;
    }
    if !conn.receive_pending && socket.can_recv() {
        let mut buf = [0u8; RECEIVE_CHUNK_SIZE];
        match socket.recv_slice(&mut buf) {
            Ok(0) => {}
            Ok(n) => {
                if conn
                    .uplink
                    .send(Ok(TunnelTcpRead::Data(buf[..n].to_vec())))
                    .is_err()
                {
                    conn.aborted = true;
                    socket.abort();
                    return;
                }
                conn.receive_pending = true;
            }
            Err(_) => {}
        }
    }
    // EOF belongs to the receive half; the peer may still be waiting for our data.
    if !socket.may_recv()
        && !matches!(
            socket.state(),
            tcp::State::SynSent | tcp::State::SynReceived
        )
    {
        conn.receive_eof = true;
        let _ = conn.uplink.send(Ok(TunnelTcpRead::Eof));
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

fn alloc_local_port(next: &mut u16, occupied: impl Iterator<Item = u16>) -> EcResult<u16> {
    // Derive occupancy from live sockets, including TIME_WAIT, without a second registry.
    let mut used = [0u64; LOCAL_PORT_COUNT.div_ceil(64)];
    for port in occupied {
        if (LOCAL_PORT_START..=LOCAL_PORT_END).contains(&port) {
            let index = usize::from(port - LOCAL_PORT_START);
            used[index / 64] |= 1 << (index % 64);
        }
    }
    for _ in 0..LOCAL_PORT_COUNT {
        let port = *next;
        *next = if port == LOCAL_PORT_END {
            LOCAL_PORT_START
        } else {
            port + 1
        };
        let index = usize::from(port - LOCAL_PORT_START);
        if used[index / 64] & (1 << (index % 64)) == 0 {
            return Ok(port);
        }
    }
    Err(EcError::Runtime(
        "tcp local port range exhausted".to_string(),
    ))
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
mod tcp_tests;

#[cfg(test)]
mod tests {
    use super::{
        ControlMessage, LOCAL_PORT_END, LOCAL_PORT_START, PendingSend, TunnelTcpSender,
        alloc_local_port, netstack_random_seed,
    };
    use crate::error::{EcError, EcResult, concise_error};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    const TEST_CONN_ID: u64 = 7;

    fn test_sender() -> (
        TunnelTcpSender,
        mpsc::Receiver<ControlMessage>,
        mpsc::Sender<EcResult<()>>,
    ) {
        let (control_tx, control_rx) = mpsc::channel();
        let (send_result_tx, send_result_rx) = mpsc::channel();
        (
            TunnelTcpSender {
                id: TEST_CONN_ID,
                control_tx,
                send_result_rx,
                closed: false,
            },
            control_rx,
            send_result_tx,
        )
    }

    fn recv_send(control_rx: &mpsc::Receiver<ControlMessage>, expected: &[u8]) {
        match control_rx.recv_timeout(Duration::from_secs(1)).unwrap() {
            ControlMessage::Send { id, data } => {
                assert_eq!(id, TEST_CONN_ID);
                assert_eq!(data, expected);
            }
            _ => panic!("expected tunnel payload"),
        }
    }

    #[test]
    fn alloc_local_port_wraps_after_60000() {
        let mut next = 60000;
        let p1 = alloc_local_port(&mut next, std::iter::empty()).unwrap();
        let p2 = alloc_local_port(&mut next, std::iter::empty()).unwrap();
        assert_eq!(p1, 60000);
        assert_eq!(p2, 40000);
    }

    #[test]
    fn local_port_allocation_skips_occupied_ports_across_wrap() {
        let mut next = LOCAL_PORT_END;
        let occupied = [LOCAL_PORT_END, LOCAL_PORT_START, LOCAL_PORT_START, 80];
        assert_eq!(
            alloc_local_port(&mut next, occupied.into_iter()).unwrap(),
            LOCAL_PORT_START + 1
        );
        assert_eq!(next, LOCAL_PORT_START + 2);
    }

    #[test]
    fn local_port_exhaustion_is_bounded_and_recovers_after_release() {
        let mut next = LOCAL_PORT_START + 17;
        let error = alloc_local_port(&mut next, LOCAL_PORT_START..=LOCAL_PORT_END).unwrap_err();
        assert!(concise_error(error).contains("local port range exhausted"));
        assert_eq!(next, LOCAL_PORT_START + 17);
        let occupied = (LOCAL_PORT_START..=LOCAL_PORT_END).filter(|port| *port != LOCAL_PORT_END);
        assert_eq!(
            alloc_local_port(&mut next, occupied).unwrap(),
            LOCAL_PORT_END
        );
        assert_eq!(next, LOCAL_PORT_START);
    }

    #[test]
    fn random_seed_is_non_zero() {
        assert_ne!(netstack_random_seed(), 0);
    }

    #[test]
    fn sender_waits_for_payload_admission() {
        let (sender, control_rx, send_result_tx) = test_sender();
        let (done_tx, done_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            done_tx.send(sender.send(vec![1, 2, 3])).unwrap();
        });

        recv_send(&control_rx, &[1, 2, 3]);
        assert!(matches!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty)));

        send_result_tx.send(Ok(())).unwrap();
        assert!(
            done_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .is_ok()
        );
        worker.join().unwrap();
    }

    #[test]
    fn sender_serializes_payloads_and_close_after_admission() {
        let (sender, control_rx, send_result_tx) = test_sender();
        let (done_tx, done_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let result = sender
                .send(vec![1])
                .and_then(|()| sender.send(vec![2]))
                .and_then(|()| sender.close());
            done_tx.send(result).unwrap();
        });

        recv_send(&control_rx, &[1]);
        assert!(matches!(
            control_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        send_result_tx.send(Ok(())).unwrap();

        recv_send(&control_rx, &[2]);
        assert!(matches!(
            control_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        send_result_tx.send(Ok(())).unwrap();

        match control_rx.recv_timeout(Duration::from_secs(1)).unwrap() {
            ControlMessage::Close { id } => assert_eq!(id, TEST_CONN_ID),
            _ => panic!("expected tunnel close"),
        }
        assert!(
            done_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .is_ok()
        );
        worker.join().unwrap();
    }

    #[test]
    fn sender_propagates_payload_admission_failure() {
        let (sender, control_rx, send_result_tx) = test_sender();
        let worker = thread::spawn(move || sender.send(vec![1]));

        recv_send(&control_rx, &[1]);
        send_result_tx
            .send(Err(EcError::Runtime("tcp send buffer closed".to_string())))
            .unwrap();

        let err = worker.join().unwrap().unwrap_err();
        assert_eq!(concise_error(err), "tcp send buffer closed");
    }

    #[test]
    fn sender_wakes_when_admission_channel_closes() {
        let (sender, control_rx, send_result_tx) = test_sender();
        let worker = thread::spawn(move || sender.send(vec![1]));

        recv_send(&control_rx, &[1]);
        drop(send_result_tx);

        let err = worker.join().unwrap().unwrap_err();
        assert!(concise_error(err).starts_with("wait tcp payload admission failed:"));
    }

    #[test]
    fn pending_send_tracks_partial_admission() {
        let mut pending = PendingSend::new(vec![1, 2, 3, 4]);

        pending.advance(2);
        assert_eq!(pending.remaining(), &[3, 4]);
        assert!(!pending.is_complete());

        pending.advance(2);
        assert!(pending.remaining().is_empty());
        assert!(pending.is_complete());
    }
}
