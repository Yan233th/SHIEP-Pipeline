use super::*;
use smoltcp::phy::{Loopback, Medium};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

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

    fn tunnel_connection(&mut self) -> (TunnelTcpConnection, mpsc::Receiver<ControlMessage>) {
        let opened = self.opened.take().unwrap();
        let (control_tx, control_rx) = mpsc::channel();
        let conn = TunnelTcpConnection {
            sender: TunnelTcpSender {
                id: opened.id,
                control_tx: control_tx.clone(),
                send_result_rx: opened.send_result_rx,
                closed: false,
            },
            receiver: TunnelTcpReceiver {
                id: opened.id,
                control_tx,
                rx: opened.uplink_rx,
                pending: false,
                finished: false,
            },
        };
        (conn, control_rx)
    }

    fn control(&mut self, message: ControlMessage) {
        handle_control_message(
            message,
            &mut ControlDispatch {
                device: &mut TunnelDevice::new(),
                iface: &mut self.iface,
                sockets: &mut self.sockets,
                connections: &mut self.connections,
                next_conn_id: &mut 2,
                next_local_port: &mut 40001,
                now: SmolInstant::from_millis(self.clock),
            },
        );
        self.steps(10);
    }
}

#[test]
fn remote_reset_ends_the_relay_without_waiting_for_client_eof() {
    for fin_before_reset in [false, true] {
        let mut rig = Rig::new();
        rig.establish();
        let (conn, _control_rx) = rig.tunnel_connection();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (relay_client, _) = listener.accept().unwrap();
        let (done_tx, done_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let _ = done_tx.send(crate::socks::relay_tunnel(relay_client, conn));
        });
        if fin_before_reset {
            rig.sockets.get_mut::<tcp::Socket>(rig.server).close();
            rig.steps(10);
            assert_eq!(client.read(&mut [0]).unwrap(), 0);
            assert!(matches!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
        }
        rig.sockets.get_mut::<tcp::Socket>(rig.server).abort();
        rig.steps(10);
        assert!(rig.connections.is_empty());
        assert_eq!(client.read(&mut [0]).unwrap(), 0);
        let result = done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("remote reset left the relay waiting for client EOF");
        assert_eq!(
            crate::error::concise_error(result.unwrap_err()),
            "tcp connection reset by peer"
        );
        worker.join().unwrap();
    }
}

#[test]
fn tunnel_relay_fin_allows_upload_and_then_exits_cleanly() {
    let mut rig = Rig::new();
    rig.establish();
    let (conn, control_rx) = rig.tunnel_connection();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let (relay_client, _) = listener.accept().unwrap();
    let (done_tx, done_rx) = mpsc::channel();
    let relay = thread::spawn(move || {
        let _ = done_tx.send(crate::socks::relay_tunnel(relay_client, conn));
    });
    let peer = thread::spawn(move || {
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(response, vec![7; 8192]);
        client.write_all(b"after EOF").unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
    });
    rig.sockets
        .get_mut::<tcp::Socket>(rig.server)
        .send_slice(&[7; 8192])
        .unwrap();
    rig.sockets.get_mut::<tcp::Socket>(rig.server).close();
    rig.steps(10);
    for _ in 0..8 {
        let message = control_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let closing = matches!(message, ControlMessage::Close { .. });
        rig.control(message);
        if closing {
            break;
        }
    }
    assert!(
        done_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .is_ok()
    );
    assert!(rig.connections.is_empty());
    let mut upload = [0; 32];
    let n = rig
        .sockets
        .get_mut::<tcp::Socket>(rig.server)
        .recv_slice(&mut upload)
        .unwrap();
    assert_eq!(&upload[..n], b"after EOF");
    peer.join().unwrap();
    relay.join().unwrap();
}

#[test]
fn remote_reset_wakes_a_sender_blocked_on_admission() {
    let mut rig = Rig::new();
    rig.establish();
    let handle = rig.connections[&1].handle;
    rig.sockets
        .get_mut::<tcp::Socket>(handle)
        .send_slice(&[1; SOCKET_BUFFER_CAPACITY])
        .unwrap();
    rig.connections.get_mut(&1).unwrap().pending_send = Some(PendingSend::new(vec![2]));
    rig.sockets.get_mut::<tcp::Socket>(rig.server).abort();
    rig.steps(10);
    let err = rig
        .opened
        .as_ref()
        .unwrap()
        .send_result_rx
        .try_recv()
        .unwrap()
        .unwrap_err();
    assert_eq!(
        crate::error::concise_error(err),
        "tcp connection reset by peer"
    );
    assert!(rig.connections.is_empty());
}

#[test]
fn client_cancellation_does_not_become_an_upstream_failure() {
    let mut rig = Rig::new();
    rig.establish();
    let (conn, control_rx) = rig.tunnel_connection();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (relay_client, _) = listener.accept().unwrap();
    let (done_tx, done_rx) = mpsc::channel();
    let relay = thread::spawn(move || {
        let _ = done_tx.send(crate::socks::relay_tunnel(relay_client, conn));
    });
    socket2::SockRef::from(&client)
        .set_linger(Some(Duration::ZERO))
        .unwrap();
    drop(client);
    let message = control_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(matches!(message, ControlMessage::Abort { .. }));
    rig.control(message);
    assert!(
        done_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .is_ok()
    );
    assert!(rig.connections.is_empty());
    relay.join().unwrap();
}

#[test]
fn complete_close_still_delivers_buffered_response_before_eof() {
    let mut rig = Rig::new();
    rig.establish();
    rig.control(ControlMessage::Close { id: 1 });
    rig.sockets
        .get_mut::<tcp::Socket>(rig.server)
        .send_slice(&[9; 8192])
        .unwrap();
    rig.sockets.get_mut::<tcp::Socket>(rig.server).close();
    rig.steps(10);
    assert_eq!(rig.client().state(), tcp::State::TimeWait);
    let mut received = Vec::new();
    let mut eof = false;
    let mut closed = false;
    for _ in 0..8 {
        while let Ok(event) = rig.opened.as_ref().unwrap().uplink_rx.try_recv() {
            match event.unwrap() {
                TunnelTcpRead::Data(chunk) => {
                    assert!(!eof && !closed);
                    received.extend(chunk);
                    rig.control(ControlMessage::Received { id: 1 });
                }
                TunnelTcpRead::Eof => {
                    assert!(!eof);
                    eof = true;
                }
                TunnelTcpRead::Closed => {
                    assert!(eof);
                    closed = true;
                }
            }
        }
        rig.steps(10);
    }
    assert_eq!(received, [9; 8192]);
    assert!(closed);
    assert!(rig.connections.is_empty());
}

#[test]
fn unexpected_receive_channel_loss_is_an_error() {
    let (control_tx, _control_rx) = mpsc::channel();
    let (tx, rx) = mpsc::channel();
    let mut receiver = TunnelTcpReceiver {
        id: 1,
        control_tx,
        rx,
        pending: false,
        finished: false,
    };
    drop(tx);
    assert_eq!(
        crate::error::concise_error(receiver.recv().unwrap_err()),
        "netstack receive channel disconnected"
    );
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
    let mut eof = false;
    for _ in 0..10 {
        if let Ok(event) = rig.opened.as_ref().unwrap().uplink_rx.try_recv() {
            match event.unwrap() {
                TunnelTcpRead::Data(chunk) => {
                    assert!(!eof);
                    received.extend(chunk);
                    rig.connections.get_mut(&1).unwrap().receive_pending = false;
                }
                TunnelTcpRead::Eof => eof = true,
                TunnelTcpRead::Closed => panic!("upload half closed prematurely"),
            }
        }
        rig.steps(4);
    }
    assert_eq!(received, response);
    assert!(eof);
    assert!(matches!(
        rig.opened.as_ref().unwrap().uplink_rx.try_recv(),
        Err(mpsc::TryRecvError::Empty)
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
    assert_eq!(
        rig.opened
            .as_ref()
            .unwrap()
            .uplink_rx
            .try_recv()
            .unwrap()
            .unwrap(),
        TunnelTcpRead::Closed
    );
}

fn received_data(event: EcResult<TunnelTcpRead>) -> Vec<u8> {
    match event.unwrap() {
        TunnelTcpRead::Data(chunk) => chunk,
        other => panic!("expected data, got {other:?}"),
    }
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
    let first = received_data(rig.opened.as_ref().unwrap().uplink_rx.try_recv().unwrap());
    assert!(first.len() <= RECEIVE_CHUNK_SIZE);
    assert!(matches!(
        rig.opened.as_ref().unwrap().uplink_rx.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));

    let mut received = first;
    for _ in 0..256 {
        rig.connections.get_mut(&1).unwrap().receive_pending = false;
        rig.steps(8);
        received.extend(
            rig.opened
                .as_ref()
                .unwrap()
                .uplink_rx
                .try_iter()
                .flat_map(received_data),
        );
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
        finished: false,
    };
    tx.send(Ok(TunnelTcpRead::Data(vec![1]))).unwrap();
    assert_eq!(received_data(receiver.recv()), [1]);
    assert!(matches!(
        control_rx.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    tx.send(Ok(TunnelTcpRead::Data(vec![2]))).unwrap();
    assert_eq!(received_data(receiver.recv()), [2]);
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
        finished: false,
    };
    tx.send(Ok(TunnelTcpRead::Eof)).unwrap();
    assert_eq!(receiver.recv().unwrap(), TunnelTcpRead::Eof);
    assert!(matches!(
        control_rx.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    tx.send(Ok(TunnelTcpRead::Closed)).unwrap();
    assert_eq!(receiver.recv().unwrap(), TunnelTcpRead::Closed);
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
    assert_eq!(
        received_data(opened.uplink_rx.try_recv().unwrap()),
        b"independent"
    );
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
    assert_eq!(
        connection_wait(None, &rig.connections, deadline),
        Some(Duration::ZERO)
    );
    rig.clock = deadline.total_millis();
    rig.steps(1);
    assert!(rig.connections.is_empty());
    assert_eq!(rig.sockets.iter().count(), 1);
    assert_eq!(connection_wait(None, &rig.connections, deadline), None);
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
fn teardown_is_scheduled_even_after_the_peer_has_reset_its_tuple() {
    let mut rig = Rig::new();
    rig.sockets.get_mut::<tcp::Socket>(rig.server).close();
    // Deliver the refusal before driving the application-level open result.
    for clock in 1..=4 {
        rig.iface.poll(
            SmolInstant::from_millis(clock),
            &mut rig.device,
            &mut rig.sockets,
        );
    }
    assert_eq!(rig.client().state(), tcp::State::Closed);
    drive_connections(
        &mut rig.sockets,
        &mut rig.connections,
        SmolInstant::from_millis(4),
    );
    assert!(rig.reply.try_recv().unwrap().is_err());
    assert_eq!(
        connection_wait(None, &rig.connections, SmolInstant::from_millis(4)),
        Some(Duration::ZERO)
    );
    rig.steps(1);
    assert!(rig.connections.is_empty());
    assert_eq!(
        connection_wait(None, &rig.connections, SmolInstant::from_millis(rig.clock)),
        None
    );
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
