use super::*;
use smoltcp::phy::{Loopback, Medium};

struct Rig {
    device: Loopback,
    iface: Interface,
    sockets: SocketSet<'static>,
    connections: HashMap<u64, ConnectionState>,
    opened: Option<OpenedTcpConnection>,
    reply: mpsc::Receiver<EcResult<OpenedTcpConnection>>,
    server: SocketHandle,
    clock: i64,
}

impl Rig {
    fn new() -> Self {
        let mut device = Loopback::new(Medium::Ip);
        let mut iface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut device,
            SmolInstant::from_millis(0),
        );
        let local = Ipv4Address::new(192, 0, 2, 1);
        let remote = Ipv4Address::new(192, 0, 2, 2);
        iface.update_ip_addrs(|addrs| {
            addrs.push(IpCidr::new(IpAddress::Ipv4(local), 24)).unwrap();
            addrs
                .push(IpCidr::new(IpAddress::Ipv4(remote), 24))
                .unwrap();
        });
        let mut sockets = SocketSet::new(vec![]);
        let mut server_socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER_CAPACITY]),
            tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER_CAPACITY]),
        );
        server_socket.listen((remote, 80)).unwrap();
        let server = sockets.add(server_socket);
        let mut connections = HashMap::new();
        let (reply_tx, reply) = mpsc::channel();
        handle_control_message(
            ControlMessage::Open {
                target: SocketAddrV4::new(remote, 80),
                reply: reply_tx,
            },
            &mut ControlDispatch {
                device: &mut TunnelDevice::new(),
                iface: &mut iface,
                sockets: &mut sockets,
                connections: &mut connections,
                next_conn_id: &mut 1,
                next_local_port: &mut 40000,
                now: SmolInstant::from_millis(0),
            },
        );
        Self {
            device,
            iface,
            sockets,
            connections,
            opened: None,
            reply,
            server,
            clock: 0,
        }
    }

    fn client(&self) -> &tcp::Socket<'_> {
        self.sockets.get::<tcp::Socket>(self.connections[&1].handle)
    }

    fn steps(&mut self, count: usize) {
        for _ in 0..count {
            self.clock += 10;
            self.iface.poll(
                SmolInstant::from_millis(self.clock),
                &mut self.device,
                &mut self.sockets,
            );
            drive_connections(
                &mut self.sockets,
                &mut self.connections,
                SmolInstant::from_millis(self.clock),
            );
        }
    }

    fn establish(&mut self) {
        self.steps(10);
        assert_eq!(self.client().state(), tcp::State::Established);
        self.opened = Some(self.reply.try_recv().unwrap().unwrap());
    }
}

#[test]
fn remote_fin_delivers_buffered_data_then_eof_without_closing_upload() {
    let mut rig = Rig::new();
    rig.establish();
    let response = vec![0x5a; 8192];
    let server = rig.sockets.get_mut::<tcp::Socket>(rig.server);
    server.send_slice(&response).unwrap();
    server.close();
    rig.steps(10);

    assert_eq!(rig.client().state(), tcp::State::CloseWait);
    let mut received = Vec::new();
    for _ in 0..10 {
        if let Ok(chunk) = rig.opened.as_ref().unwrap().uplink_rx.try_recv() {
            received.extend(chunk);
            rig.connections.get_mut(&1).unwrap().receive_pending = false;
        }
        rig.steps(4);
    }
    assert_eq!(received, response);
    assert!(matches!(
        rig.opened.as_ref().unwrap().uplink_rx.try_recv(),
        Err(mpsc::TryRecvError::Disconnected)
    ));

    let conn = rig.connections.get_mut(&1).unwrap();
    conn.pending_send = Some(PendingSend::new(b"last upload".to_vec()));
    conn.close_requested = true;
    rig.steps(10);
    assert!(
        rig.opened
            .as_ref()
            .unwrap()
            .send_result_rx
            .try_recv()
            .unwrap()
            .is_ok()
    );
    let server = rig.sockets.get_mut::<tcp::Socket>(rig.server);
    let mut bytes = [0; 32];
    let n = server.recv_slice(&mut bytes).unwrap();
    assert_eq!(&bytes[..n], b"last upload");
}

#[test]
fn open_reply_waits_for_the_tcp_handshake() {
    let mut rig = Rig::new();
    drive_connections(
        &mut rig.sockets,
        &mut rig.connections,
        SmolInstant::from_millis(rig.clock),
    );
    assert_eq!(rig.client().state(), tcp::State::SynSent);
    assert!(matches!(
        rig.reply.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    rig.establish();
    assert!(rig.opened.is_some());
}

#[test]
fn slow_reader_bounds_download_buffering_and_resumes_without_loss() {
    let mut rig = Rig::new();
    rig.establish();
    let chunk = vec![0x5a; RECEIVE_CHUNK_SIZE];
    let mut admitted = 0;
    for _ in 0..256 {
        admitted += rig
            .sockets
            .get_mut::<tcp::Socket>(rig.server)
            .send_slice(&chunk)
            .unwrap();
        rig.steps(8);
    }
    // Include the peer's send buffer: it must stop admitting new data as our window closes.
    assert!(admitted <= 2 * SOCKET_BUFFER_CAPACITY + RECEIVE_CHUNK_SIZE);
    let first = rig.opened.as_ref().unwrap().uplink_rx.try_recv().unwrap();
    assert!(first.len() <= RECEIVE_CHUNK_SIZE);
    assert!(matches!(
        rig.opened.as_ref().unwrap().uplink_rx.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));

    let mut received = first;
    for _ in 0..256 {
        rig.connections.get_mut(&1).unwrap().receive_pending = false;
        rig.steps(8);
        received.extend(rig.opened.as_ref().unwrap().uplink_rx.try_iter().flatten());
    }
    assert_eq!(received, vec![0x5a; admitted]);
}

#[test]
fn stalled_download_does_not_block_upload() {
    let mut rig = Rig::new();
    rig.establish();
    rig.sockets
        .get_mut::<tcp::Socket>(rig.server)
        .send_slice(&[1; 8192])
        .unwrap();
    rig.steps(10);
    assert!(rig.connections[&1].receive_pending);
    rig.connections.get_mut(&1).unwrap().pending_send = Some(PendingSend::new(vec![2; 32]));
    rig.steps(10);
    assert!(
        rig.opened
            .as_ref()
            .unwrap()
            .send_result_rx
            .try_recv()
            .unwrap()
            .is_ok()
    );
    let mut bytes = [0; 32];
    assert_eq!(
        rig.sockets
            .get_mut::<tcp::Socket>(rig.server)
            .recv_slice(&mut bytes)
            .unwrap(),
        32
    );
    assert_eq!(bytes, [2; 32]);
}

#[test]
fn receiver_acknowledges_only_on_next_read_and_cancels_on_early_drop() {
    let (control_tx, control_rx) = mpsc::channel();
    let (tx, rx) = mpsc::channel();
    let mut receiver = TunnelTcpReceiver {
        id: 1,
        control_tx,
        rx,
        pending: false,
        eof: false,
    };
    tx.send(vec![1]).unwrap();
    assert_eq!(receiver.recv().unwrap(), [1]);
    assert!(matches!(
        control_rx.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    tx.send(vec![2]).unwrap();
    assert_eq!(receiver.recv().unwrap(), [2]);
    assert!(matches!(
        control_rx.try_recv(),
        Ok(ControlMessage::Received { id: 1 })
    ));
    drop(receiver);
    assert!(matches!(
        control_rx.try_recv(),
        Ok(ControlMessage::Abort { id: 1 })
    ));
}

#[test]
fn receiver_eof_preserves_the_upload_half() {
    let (control_tx, control_rx) = mpsc::channel();
    let (tx, rx) = mpsc::channel();
    let mut receiver = TunnelTcpReceiver {
        id: 1,
        control_tx,
        rx,
        pending: false,
        eof: false,
    };
    drop(tx);
    assert!(receiver.recv().is_err());
    drop(receiver);
    assert!(matches!(
        control_rx.try_recv(),
        Err(mpsc::TryRecvError::Disconnected)
    ));
}

#[test]
fn a_stalled_reader_does_not_block_another_connection() {
    let mut rig = Rig::new();
    rig.establish();
    rig.sockets
        .get_mut::<tcp::Socket>(rig.server)
        .send_slice(&[1; 8192])
        .unwrap();
    rig.steps(10);

    let remote = Ipv4Address::new(192, 0, 2, 2);
    let mut peer = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER_CAPACITY]),
        tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER_CAPACITY]),
    );
    peer.listen((remote, 81)).unwrap();
    let peer = rig.sockets.add(peer);
    let opened = open_connection(
        SocketAddrV4::new(remote, 81),
        &mut rig.iface,
        &mut rig.sockets,
        &mut rig.connections,
        &mut 2,
        &mut 40001,
    )
    .unwrap();
    rig.steps(10);
    rig.sockets
        .get_mut::<tcp::Socket>(peer)
        .send_slice(b"independent")
        .unwrap();
    rig.steps(10);
    assert_eq!(opened.uplink_rx.try_recv().unwrap(), b"independent");
    assert!(rig.connections[&1].receive_pending);
}

#[test]
fn connect_deadline_wakes_the_loop_and_releases_the_socket() {
    let mut rig = Rig::new();
    let deadline = SmolInstant::from_millis(OPEN_CONN_TIMEOUT.as_millis() as i64);
    assert_eq!(
        connection_wait(None, &rig.connections, SmolInstant::from_millis(0)),
        Some(OPEN_CONN_TIMEOUT)
    );
    assert_eq!(
        connection_wait(None, &rig.connections, deadline),
        Some(Duration::ZERO)
    );
    assert_eq!(
        connection_wait(
            None,
            &rig.connections,
            deadline + smoltcp::time::Duration::from_secs(1)
        ),
        Some(Duration::ZERO)
    );
    drive_connections(&mut rig.sockets, &mut rig.connections, deadline);
    let Err(err) = rig.reply.try_recv().unwrap() else {
        panic!("expected timeout")
    };
    assert_eq!(
        crate::error::concise_error(err),
        "tcp connect timed out after 10s"
    );
    rig.clock = deadline.total_millis();
    rig.steps(1);
    assert!(rig.connections.is_empty());
    assert_eq!(rig.sockets.iter().count(), 1);
}

#[test]
fn close_cancels_a_pending_connect() {
    let mut rig = Rig::new();
    rig.connections.get_mut(&1).unwrap().close_requested = true;
    drive_connections(
        &mut rig.sockets,
        &mut rig.connections,
        SmolInstant::from_millis(0),
    );
    assert!(rig.reply.try_recv().unwrap().is_err());
    rig.steps(1);
    assert!(rig.connections.is_empty());
}

#[test]
fn refused_connect_never_reports_success() {
    let mut rig = Rig::new();
    rig.sockets.get_mut::<tcp::Socket>(rig.server).close();
    rig.steps(10);
    let Err(err) = rig.reply.try_recv().unwrap() else {
        panic!("expected refusal")
    };
    assert!(crate::error::concise_error(err).contains("refused or reset"));
    assert!(rig.connections.is_empty());
}

#[test]
fn abandoned_open_reply_does_not_leak_an_established_socket() {
    let mut rig = Rig::new();
    let (_, replacement) = mpsc::channel();
    drop(std::mem::replace(&mut rig.reply, replacement));
    rig.steps(10);
    assert!(rig.connections.is_empty());
    assert_eq!(
        rig.sockets.get::<tcp::Socket>(rig.server).state(),
        tcp::State::Closed
    );
}

#[test]
fn connect_deadline_does_not_apply_after_establishment() {
    let mut rig = Rig::new();
    rig.establish();
    assert_eq!(
        connection_wait(None, &rig.connections, SmolInstant::from_millis(100)),
        None
    );
    drive_connections(
        &mut rig.sockets,
        &mut rig.connections,
        SmolInstant::from_millis(60_000),
    );
    assert_eq!(rig.client().state(), tcp::State::Established);
}

#[test]
fn partial_upload_preserves_bytes_and_fin_order() {
    let mut rig = Rig::new();
    rig.establish();
    let client = rig.connections[&1].handle;
    let filler = vec![0x61; SOCKET_BUFFER_CAPACITY - 2];
    assert_eq!(
        rig.sockets
            .get_mut::<tcp::Socket>(client)
            .send_slice(&filler)
            .unwrap(),
        filler.len()
    );
    let conn = rig.connections.get_mut(&1).unwrap();
    conn.pending_send = Some(PendingSend::new(vec![1, 2, 3, 4]));
    conn.close_requested = true;
    drive_connections(
        &mut rig.sockets,
        &mut rig.connections,
        SmolInstant::from_millis(rig.clock),
    );
    assert_eq!(rig.connections[&1].pending_send.as_ref().unwrap().offset, 2);
    assert!(matches!(
        rig.opened.as_ref().unwrap().send_result_rx.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    assert_eq!(rig.client().state(), tcp::State::Established);
    rig.steps(10);
    assert!(
        rig.opened
            .as_ref()
            .unwrap()
            .send_result_rx
            .try_recv()
            .unwrap()
            .is_ok()
    );
    let mut received = Vec::new();
    for _ in 0..16 {
        let server = rig.sockets.get_mut::<tcp::Socket>(rig.server);
        while server.can_recv() {
            let mut buf = [0; 4096];
            let n = server.recv_slice(&mut buf).unwrap();
            received.extend_from_slice(&buf[..n]);
        }
        rig.steps(8);
    }
    let mut expected = filler;
    expected.extend([1, 2, 3, 4]);
    assert_eq!(received, expected);
    assert_eq!(
        rig.sockets.get::<tcp::Socket>(rig.server).state(),
        tcp::State::CloseWait
    );
}
