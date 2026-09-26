use super::*;
use smoltcp::phy::{Loopback, Medium};

struct Rig {
    device: Loopback,
    iface: Interface,
    sockets: SocketSet<'static>,
    connections: HashMap<u64, ConnectionState>,
    opened: OpenedTcpConnection,
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
        let opened = open_connection(
            SocketAddrV4::new(remote, 80),
            &mut iface,
            &mut sockets,
            &mut connections,
            &mut 1,
            &mut 40000,
        )
        .unwrap();
        Self {
            device,
            iface,
            sockets,
            connections,
            opened,
            server,
            clock: 0,
        }
    }

    fn client(&self) -> &tcp::Socket<'_> {
        self.sockets
            .get::<tcp::Socket>(self.connections[&self.opened.id].handle)
    }

    fn steps(&mut self, count: usize) {
        for _ in 0..count {
            self.clock += 10;
            self.iface.poll(
                SmolInstant::from_millis(self.clock),
                &mut self.device,
                &mut self.sockets,
            );
            drive_connections(&mut self.sockets, &mut self.connections);
        }
    }

    fn establish(&mut self) {
        self.steps(10);
        assert_eq!(self.client().state(), tcp::State::Established);
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
    let received: Vec<u8> = rig.opened.uplink_rx.try_iter().flatten().collect();
    assert_eq!(received, response);
    assert!(matches!(
        rig.opened.uplink_rx.try_recv(),
        Err(mpsc::TryRecvError::Disconnected)
    ));

    let conn = rig.connections.get_mut(&rig.opened.id).unwrap();
    conn.pending_send = Some(PendingSend::new(b"last upload".to_vec()));
    conn.close_requested = true;
    rig.steps(10);
    assert!(rig.opened.send_result_rx.try_recv().unwrap().is_ok());
    let server = rig.sockets.get_mut::<tcp::Socket>(rig.server);
    let mut bytes = [0; 32];
    let n = server.recv_slice(&mut bytes).unwrap();
    assert_eq!(&bytes[..n], b"last upload");
}

#[test]
fn waiting_for_handshake_is_not_receive_eof() {
    let mut rig = Rig::new();
    drive_connections(&mut rig.sockets, &mut rig.connections);
    assert_eq!(rig.client().state(), tcp::State::SynSent);
    assert!(matches!(
        rig.opened.uplink_rx.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
}
