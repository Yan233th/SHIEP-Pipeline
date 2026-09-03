use crate::error::{EcError, EcResult};
use crate::netstack_device::TunnelDevice;
use crate::output::{self, Scope};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
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

    match reply_rx.recv_timeout(OPEN_CONN_TIMEOUT) {
        Ok(Ok(opened)) => Ok(TunnelTcpConnection {
            id: opened.id,
            control_tx: control,
            rx: opened.uplink_rx,
            send_result_rx: opened.send_result_rx,
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
    send_result_rx: mpsc::Receiver<EcResult<()>>,
}

impl TunnelTcpConnection {
    pub fn into_parts(self) -> (TunnelTcpSender, mpsc::Receiver<Vec<u8>>) {
        (
            TunnelTcpSender {
                id: self.id,
                control_tx: self.control_tx,
                send_result_rx: self.send_result_rx,
            },
            self.rx,
        )
    }
}

#[derive(Debug)]
pub struct TunnelTcpSender {
    id: u64,
    control_tx: mpsc::Sender<ControlMessage>,
    send_result_rx: mpsc::Receiver<EcResult<()>>,
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
        reply: mpsc::Sender<EcResult<OpenedTcpConnection>>,
    },
    Send {
        id: u64,
        data: Vec<u8>,
    },
    Close {
        id: u64,
    },
}

struct OpenedTcpConnection {
    id: u64,
    uplink_rx: mpsc::Receiver<Vec<u8>>,
    send_result_rx: mpsc::Receiver<EcResult<()>>,
}

struct ConnectionState {
    handle: SocketHandle,
    uplink: mpsc::Sender<Vec<u8>>,
    send_result: mpsc::Sender<EcResult<()>>,
    pending_send: Option<PendingSend>,
    close_requested: bool,
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
                    close_requested: false,
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

fn drive_connections(sockets: &mut SocketSet<'_>, connections: &mut HashMap<u64, ConnectionState>) {
    let mut remove_ids = Vec::new();
    for (id, conn) in connections.iter_mut() {
        let socket = sockets.get_mut::<tcp::Socket>(conn.handle);

        pump_pending_sends(socket, conn);
        pump_uplink_reads(socket, conn);

        if conn.close_requested && conn.pending_send.is_none() && socket.may_send() {
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
    use super::{
        ControlMessage, PendingSend, TunnelTcpSender, alloc_local_port, netstack_random_seed,
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
        let p1 = alloc_local_port(&mut next);
        let p2 = alloc_local_port(&mut next);
        assert_eq!(p1, 60000);
        assert_eq!(p2, 40000);
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
