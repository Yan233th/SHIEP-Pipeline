use crate::error::{EcError, EcResult};
use crate::output::{self, RouteKind, Scope};
use crate::socks_proxy::{FallbackProxy, connect_via_proxy, parse_fallback_proxy};
use crate::socks_wire::{
    ConnectTarget, SOCKS_REP_CMD_NOT_SUPPORTED, SOCKS_REP_SUCCEEDED, SocksCommand,
    format_socket_target, negotiate_method, read_socks_request, write_reply,
};
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, TcpListener, TcpStream};
use std::thread;

const RELAY_BUFFER_SIZE: usize = 4096;

pub fn serve(bind_addr: &str, fallback_proxy: Option<&str>) -> EcResult<()> {
    let normalized = normalize_bind_addr(bind_addr);
    let fallback_proxy = parse_fallback_proxy(fallback_proxy)?;
    let listener = TcpListener::bind(&normalized)
        .map_err(|e| EcError::Runtime(format!("socks bind failed on {bind_addr}: {e}")))?;
    log_socks_startup(normalized.as_str(), fallback_proxy.as_ref());
    spawn_accept_loop(listener, fallback_proxy.clone());

    let _reason = crate::runtime_state::wait_fatal_reason();
    Err(EcError::Runtime("runtime closed".to_string()))
}

fn normalize_bind_addr(bind_addr: &str) -> String {
    if bind_addr.starts_with(':') {
        format!("0.0.0.0{bind_addr}")
    } else {
        bind_addr.to_string()
    }
}

fn log_socks_startup(bind_addr: &str, fallback_proxy: Option<&FallbackProxy>) {
    if let Some(proxy) = fallback_proxy {
        output::info(
            Scope::App,
            format_args!("fallback: proxy to {}", output::value(proxy.url.as_str())),
        );
    } else {
        output::info(Scope::App, "fallback: direct");
    }
    output::info(
        Scope::App,
        format_args!("listening on {}", output::value(bind_addr)),
    );
}

fn spawn_accept_loop(listener: TcpListener, fallback_proxy: Option<FallbackProxy>) {
    thread::spawn(move || {
        loop {
            let (stream, _peer) = match listener.accept() {
                Ok(v) => v,
                Err(err) if is_retryable_accept_error(&err) => continue,
                Err(err) => {
                    let detail = format!("listener closed: {err}");
                    output::error(Scope::App, &detail);
                    crate::runtime_state::record_fatal(detail);
                    return;
                }
            };
            let fallback_proxy = fallback_proxy.clone();
            thread::spawn(move || {
                if let Err(failure) = handle_client(stream, fallback_proxy.as_ref()) {
                    let (scope, err) = failure.into_log_parts();
                    output::error(scope, crate::error::concise_error(err));
                }
            });
        }
    });
}

fn is_retryable_accept_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::Interrupted | ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset
    )
}

fn handle_client(
    mut client: TcpStream,
    fallback_proxy: Option<&FallbackProxy>,
) -> Result<(), ClientFailure> {
    negotiate_method(&mut client).map_err(ClientFailure::Request)?;
    let request = read_socks_request(&mut client).map_err(ClientFailure::Request)?;
    match request.command {
        SocksCommand::Connect => {
            handle_connect(client, request.target, fallback_proxy).map_err(ClientFailure::Upstream)
        }
        SocksCommand::UdpAssociate => {
            reject_udp_associate(&mut client).map_err(ClientFailure::Request)
        }
        SocksCommand::Other(_) => {
            let _ = write_reply(&mut client, SOCKS_REP_CMD_NOT_SUPPORTED);
            Err(ClientFailure::Request(EcError::Runtime(format!(
                "unsupported socks command: {}",
                request.command
            ))))
        }
    }
}

fn handle_connect(
    client: TcpStream,
    target: ConnectTarget,
    fallback_proxy: Option<&FallbackProxy>,
) -> EcResult<()> {
    let target_display = target.to_string();
    let route = decide_route(&target, fallback_proxy);
    output::info(Scope::Req, &route.line);
    execute_route(client, target_display.as_str(), route)
}

fn reject_udp_associate(client: &mut TcpStream) -> EcResult<()> {
    write_reply(client, SOCKS_REP_CMD_NOT_SUPPORTED)?;
    output::warn(
        Scope::Req,
        "UDP ASSOCIATE rejected: listener supports TCP CONNECT only",
    );
    Ok(())
}

fn decide_route(target: &ConnectTarget, fallback_proxy: Option<&FallbackProxy>) -> RouteDecision {
    let target_display = target.to_string();
    let target_is_ip = is_ip_host(target.host());
    match crate::routing::plan_target(target.host(), target.port()) {
        Ok(crate::routing::RoutePlan::Remote {
            dial,
            rc_id: _,
            rc_name,
            source,
            dns_lookup,
        }) => {
            let resolved_ip = dial
                .rsplit_once(':')
                .map(|(ip, _)| ip)
                .unwrap_or(dial.as_str());
            log_resolved_route_source(target.host(), resolved_ip, source, dns_lookup);
            route_decision_remote(
                target_display.as_str(),
                target_is_ip,
                dial,
                rc_name,
                source,
                dns_lookup,
            )
        }
        Ok(crate::routing::RoutePlan::Fallback {
            target: planned_target,
            reason,
        }) => route_decision_fallback(
            target.clone(),
            target_display.as_str(),
            target_addr(&planned_target),
            reason,
            fallback_proxy,
        ),
        Err(err) => route_decision_planner_error(target_display.as_str(), err),
    }
}

fn log_resolved_route_source(
    host: &str,
    resolved_ip: &str,
    source: crate::routing::RouteSource,
    dns_lookup: Option<crate::dns_resolver::ResolveSource>,
) {
    let arrow = output::weak(" -> ");
    if let Some(dns_lookup) = dns_lookup {
        match dns_lookup {
            crate::dns_resolver::ResolveSource::Cache => output::info(
                Scope::Upstream,
                format_args!(
                    "route DNS cache hit {}{}{}",
                    output::value(host),
                    arrow,
                    output::value(resolved_ip)
                ),
            ),
            crate::dns_resolver::ResolveSource::Server(server) => output::info(
                Scope::Upstream,
                format_args!(
                    "route DNS resolved {}{}{} via {}",
                    output::value(host),
                    arrow,
                    output::value(resolved_ip),
                    output::value(server)
                ),
            ),
        }
        return;
    }

    if source == crate::routing::RouteSource::DnsDataIpRule {
        output::info(
            Scope::Upstream,
            format_args!(
                "route dns.data resolved {}{}{}",
                output::value(host),
                arrow,
                output::value(resolved_ip)
            ),
        );
    }
}

fn route_decision_remote(
    target_display: &str,
    target_is_ip: bool,
    dial: String,
    rc_name: String,
    source: crate::routing::RouteSource,
    dns_lookup: Option<crate::dns_resolver::ResolveSource>,
) -> RouteDecision {
    let arrow = output::weak(" -> ");
    let lparen = output::weak("(");
    let rparen = output::weak(")");
    let name = if rc_name.trim().is_empty() {
        "unknown".to_string()
    } else {
        rc_name
    };
    let line = if target_is_ip {
        format!(
            "{target_display}{arrow}{}{arrow}{name}",
            output::route_label(RouteKind::Remote),
        )
    } else {
        format!(
            "{target_display}{arrow}{}{arrow}{name}{lparen}{dial}{rparen}",
            output::route_label(RouteKind::Remote),
        )
    };
    RouteDecision {
        line,
        path: format!(
            "remote -> {name}({dial}); source: {}",
            describe_route_source(source, dns_lookup)
        ),
        transport: RouteTransport::Tunnel(dial),
    }
}

fn describe_route_source(
    source: crate::routing::RouteSource,
    dns_lookup: Option<crate::dns_resolver::ResolveSource>,
) -> String {
    match (source, dns_lookup) {
        (
            crate::routing::RouteSource::DnsServer,
            Some(crate::dns_resolver::ResolveSource::Cache),
        ) => "dns-cache".to_string(),
        (
            crate::routing::RouteSource::CnameDnsServer,
            Some(crate::dns_resolver::ResolveSource::Cache),
        ) => "cname-dns-cache".to_string(),
        (
            crate::routing::RouteSource::DnsServerIpRule,
            Some(crate::dns_resolver::ResolveSource::Cache),
        ) => "dns-server-ip-rule-cache".to_string(),
        (
            crate::routing::RouteSource::DnsServer,
            Some(crate::dns_resolver::ResolveSource::Server(server)),
        ) => {
            format!("dns-server({server})")
        }
        (
            crate::routing::RouteSource::CnameDnsServer,
            Some(crate::dns_resolver::ResolveSource::Server(server)),
        ) => format!("cname-dns-server({server})"),
        (
            crate::routing::RouteSource::DnsServerIpRule,
            Some(crate::dns_resolver::ResolveSource::Server(server)),
        ) => format!("dns-server-ip-rule({server})"),
        (source, Some(crate::dns_resolver::ResolveSource::Cache)) => {
            format!("{} via dns-cache", source.label())
        }
        (source, Some(crate::dns_resolver::ResolveSource::Server(server))) => {
            format!("{} via dns-server({server})", source.label())
        }
        (source, None) => source.label().to_string(),
    }
}

fn route_decision_fallback(
    target: ConnectTarget,
    target_display: &str,
    dial: String,
    reason: String,
    fallback_proxy: Option<&FallbackProxy>,
) -> RouteDecision {
    let arrow = output::weak(" -> ");
    if let Some(proxy) = fallback_proxy {
        return RouteDecision {
            line: format!(
                "{target_display}{arrow}{}{arrow}{}",
                output::route_label(RouteKind::Fallback),
                output::value(proxy.url.as_str()),
            ),
            path: format!("fallback -> {}; reason: {reason}", proxy.url),
            transport: RouteTransport::Proxy(proxy.clone(), target),
        };
    }

    RouteDecision {
        line: format!(
            "{target_display}{arrow}{}{arrow}{}",
            output::route_label(RouteKind::Fallback),
            output::route_label(RouteKind::Direct),
        ),
        path: format!("fallback -> direct; dial: {dial}; reason: {reason}"),
        transport: RouteTransport::Direct(dial),
    }
}

fn route_decision_planner_error(target_display: &str, err: EcError) -> RouteDecision {
    let arrow = output::weak(" -> ");
    let reason = crate::error::concise_error(err);
    RouteDecision {
        line: format!(
            "{target_display}{arrow}{}{arrow}route planner unavailable",
            output::route_label(RouteKind::Fallback),
        ),
        path: format!("fallback -> unavailable; reason: {reason}"),
        transport: RouteTransport::Unsupported("no route transport available".to_string()),
    }
}

fn execute_route(client: TcpStream, target_display: &str, route: RouteDecision) -> EcResult<()> {
    let RouteDecision {
        line: _,
        path,
        transport,
    } = route;
    let route_path = path.as_str();

    match transport {
        RouteTransport::Tunnel(dial_target) => {
            let conn = crate::netstack::open_tcp_connection(&dial_target)
                .map_err(|e| route_runtime_error(target_display, route_path, e))?;
            let mut client = client;
            write_connect_ok_reply(&mut client, target_display, route_path)?;
            relay_tunnel(client, conn)
                .map_err(|e| route_runtime_error(target_display, route_path, e))
        }
        RouteTransport::Direct(dial_target) => {
            let conn = TcpStream::connect(&dial_target)
                .map_err(|e| route_runtime_error(target_display, route_path, e))?;
            relay_direct_with_reply(client, conn, target_display, route_path)
        }
        RouteTransport::Proxy(proxy, target) => {
            let conn = connect_via_proxy(&proxy, target.host(), target.port())
                .map_err(|e| route_runtime_error(target_display, route_path, e))?;
            relay_direct_with_reply(client, conn, target_display, route_path)
        }
        RouteTransport::Unsupported(reason) => Err(route_runtime_error(
            target_display,
            route_path,
            reason.as_str(),
        )),
    }
}

fn route_runtime_error(
    target_display: &str,
    route_path: &str,
    err: impl std::fmt::Display,
) -> EcError {
    let cause = crate::error::concise_error(err);
    EcError::Runtime(format!("{target_display} -> {route_path}; error: {cause}"))
}

fn write_connect_ok_reply(
    client: &mut TcpStream,
    target_display: &str,
    route_path: &str,
) -> EcResult<()> {
    write_reply(client, SOCKS_REP_SUCCEEDED)
        .map_err(|e| route_runtime_error(target_display, route_path, e))
}

fn relay_direct_with_reply(
    mut client: TcpStream,
    conn: TcpStream,
    target_display: &str,
    route_path: &str,
) -> EcResult<()> {
    write_connect_ok_reply(&mut client, target_display, route_path)?;
    relay_direct(client, conn).map_err(|e| route_runtime_error(target_display, route_path, e))
}

fn relay_tunnel(mut client: TcpStream, conn: crate::netstack::TunnelTcpConnection) -> EcResult<()> {
    let sender = conn.sender();
    let rx = conn.into_receiver();
    let c_to_r_src = client
        .try_clone()
        .map_err(|e| EcError::Runtime(format!("clone client stream failed: {e}")))?;

    let uplink = thread::spawn(move || relay_client_to_tunnel(c_to_r_src, sender));
    let downlink = thread::spawn(move || relay_tunnel_to_client(&mut client, rx));

    join_relay_workers(uplink, downlink)
}

fn relay_direct(client: TcpStream, upstream: TcpStream) -> EcResult<()> {
    let client_reader = client
        .try_clone()
        .map_err(|e| EcError::Runtime(format!("clone client stream failed: {e}")))?;
    let upstream_reader = upstream
        .try_clone()
        .map_err(|e| EcError::Runtime(format!("clone upstream stream failed: {e}")))?;

    let uplink = thread::spawn(move || pump_stream(client_reader, upstream, "client to upstream"));
    let downlink =
        thread::spawn(move || pump_stream(upstream_reader, client, "upstream to client"));

    join_relay_workers(uplink, downlink)
}

fn relay_client_to_tunnel(
    mut client: TcpStream,
    sender: crate::netstack::TunnelTcpSender,
) -> EcResult<()> {
    let mut buf = [0u8; RELAY_BUFFER_SIZE];
    let result = loop {
        match client.read(&mut buf) {
            Ok(0) => break Ok(()),
            Ok(n) => {
                sender.send(buf[..n].to_vec())?;
            }
            Err(err) if is_expected_relay_io_error(&err) => break Ok(()),
            Err(err) => {
                break Err(EcError::Runtime(format!(
                    "client to tunnel read failed: {err}"
                )));
            }
        }
    };
    let close_result = sender.close();
    result.and(close_result)
}

fn relay_tunnel_to_client(
    client: &mut TcpStream,
    rx: std::sync::mpsc::Receiver<Vec<u8>>,
) -> EcResult<()> {
    while let Ok(chunk) = rx.recv() {
        if chunk.is_empty() {
            continue;
        }
        if let Err(err) = client.write_all(&chunk) {
            if is_expected_relay_io_error(&err) {
                return Ok(());
            }
            return Err(EcError::Runtime(format!(
                "tunnel to client write failed: {err}"
            )));
        }
    }
    shutdown_write(client, "client")
}

fn pump_stream(mut src: TcpStream, mut dst: TcpStream, direction: &'static str) -> EcResult<()> {
    let mut buf = [0u8; RELAY_BUFFER_SIZE];
    let result = loop {
        match src.read(&mut buf) {
            Ok(0) => break Ok(()),
            Ok(n) => {
                if let Err(err) = dst.write_all(&buf[..n]) {
                    if is_expected_relay_io_error(&err) {
                        break Ok(());
                    }
                    break Err(EcError::Runtime(format!("{direction} write failed: {err}")));
                }
            }
            Err(err) if is_expected_relay_io_error(&err) => break Ok(()),
            Err(err) => {
                break Err(EcError::Runtime(format!("{direction} read failed: {err}")));
            }
        }
    };
    let shutdown_result = shutdown_write(&dst, direction);
    result.and(shutdown_result)
}

fn shutdown_write(stream: &TcpStream, peer: &str) -> EcResult<()> {
    match stream.shutdown(Shutdown::Write) {
        Ok(()) => Ok(()),
        Err(err) if is_expected_relay_io_error(&err) => Ok(()),
        Err(err) => Err(EcError::Runtime(format!(
            "{peer} write shutdown failed: {err}"
        ))),
    }
}

fn join_relay_workers(
    uplink: thread::JoinHandle<EcResult<()>>,
    downlink: thread::JoinHandle<EcResult<()>>,
) -> EcResult<()> {
    let uplink_result = join_relay_worker(uplink, "uplink");
    let downlink_result = join_relay_worker(downlink, "downlink");
    uplink_result.and(downlink_result)
}

fn join_relay_worker(
    worker: thread::JoinHandle<EcResult<()>>,
    direction: &'static str,
) -> EcResult<()> {
    worker
        .join()
        .map_err(|_| EcError::Runtime(format!("{direction} relay worker panicked")))?
}

fn is_expected_relay_io_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::BrokenPipe
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::NotConnected
            | ErrorKind::UnexpectedEof
    )
}

enum RouteTransport {
    Tunnel(String),
    Direct(String),
    Proxy(FallbackProxy, ConnectTarget),
    Unsupported(String),
}

struct RouteDecision {
    line: String,
    path: String,
    transport: RouteTransport,
}

enum ClientFailure {
    Request(EcError),
    Upstream(EcError),
}

impl ClientFailure {
    fn into_log_parts(self) -> (Scope, EcError) {
        match self {
            Self::Request(err) => (Scope::Req, err),
            Self::Upstream(err) => (Scope::Upstream, err),
        }
    }
}

fn target_addr(target: &str) -> String {
    if let Some((host, port)) = target.rsplit_once(':') {
        return format_socket_target(host, port);
    }
    target.to_string()
}

fn is_ip_host(host: &str) -> bool {
    host.trim().parse::<Ipv4Addr>().is_ok() || host.trim().parse::<Ipv6Addr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::{
        ClientFailure, SOCKS_REP_SUCCEEDED, describe_route_source, handle_client,
        is_expected_relay_io_error, is_retryable_accept_error, join_relay_worker,
        normalize_bind_addr, route_decision_planner_error, route_decision_remote, target_addr,
    };
    use crate::error::EcError;
    use crate::route_table::RouteTable;
    use crate::routing::RouteSource;
    use crate::socks_proxy::parse_fallback_proxy;
    use std::io::{Read, Write};
    use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
    use std::sync::Once;
    use std::thread;
    use std::time::Duration;

    static TEST_ROUTER_INIT: Once = Once::new();

    fn install_empty_test_router() {
        TEST_ROUTER_INIT.call_once(|| {
            crate::routing::install_route_table(RouteTable {
                rules: vec![],
                dns_servers: vec![],
                dns_records: vec![],
            })
            .unwrap();
        });
    }

    #[derive(Clone, Copy)]
    enum TestProxyKind {
        Socks5,
        Http,
    }

    impl TestProxyKind {
        fn scheme(self) -> &'static str {
            match self {
                Self::Socks5 => "socks5h",
                Self::Http => "http",
            }
        }
    }

    fn spawn_echo_server() -> (SocketAddr, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 256];
            loop {
                let n = stream.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                stream.write_all(&buf[..n]).unwrap();
            }
            stream.shutdown(Shutdown::Write).unwrap();
        });
        (addr, worker)
    }

    fn relay_test_proxy(client: TcpStream, upstream: TcpStream) {
        let mut client_reader = client.try_clone().unwrap();
        let mut upstream_writer = upstream.try_clone().unwrap();
        let mut upstream_reader = upstream;
        let mut client_writer = client;

        let uplink = thread::spawn(move || {
            std::io::copy(&mut client_reader, &mut upstream_writer).unwrap();
            upstream_writer.shutdown(Shutdown::Write).unwrap();
        });
        std::io::copy(&mut upstream_reader, &mut client_writer).unwrap();
        client_writer.shutdown(Shutdown::Write).unwrap();
        uplink.join().unwrap();
    }

    fn read_http_connect_head(stream: &mut TcpStream) -> String {
        let mut head = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).unwrap();
            head.push(byte[0]);
            assert!(head.len() <= 4096, "HTTP CONNECT head is too large");
            if head.ends_with(b"\r\n\r\n") {
                return String::from_utf8(head).unwrap();
            }
        }
    }

    fn negotiate_test_socks5_proxy(stream: &mut TcpStream, host: &str, port: u16) {
        let mut greeting = [0u8; 3];
        stream.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting, [0x05, 0x01, 0x00]);
        stream.write_all(&[0x05, 0x00]).unwrap();

        let mut request_head = [0u8; 4];
        stream.read_exact(&mut request_head).unwrap();
        assert_eq!(request_head, [0x05, 0x01, 0x00, 0x03]);
        let mut host_len = [0u8; 1];
        stream.read_exact(&mut host_len).unwrap();
        let mut encoded_host = vec![0u8; host_len[0] as usize];
        stream.read_exact(&mut encoded_host).unwrap();
        let mut encoded_port = [0u8; 2];
        stream.read_exact(&mut encoded_port).unwrap();
        assert_eq!(encoded_host, host.as_bytes());
        assert_eq!(u16::from_be_bytes(encoded_port), port);

        stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
            .unwrap();
    }

    fn negotiate_test_http_proxy(stream: &mut TcpStream, host: &str, port: u16) {
        let head = read_http_connect_head(stream);
        let authority = format!("{host}:{port}");
        assert!(head.starts_with(&format!("CONNECT {authority} HTTP/1.1\r\n")));
        assert!(head.contains(&format!("\r\nHost: {authority}\r\n")));
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .unwrap();
    }

    fn spawn_test_proxy(
        kind: TestProxyKind,
        target_addr: SocketAddr,
        expected_host: &'static str,
        expected_port: u16,
    ) -> (SocketAddr, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut client, _) = listener.accept().unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            client
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            match kind {
                TestProxyKind::Socks5 => {
                    negotiate_test_socks5_proxy(&mut client, expected_host, expected_port)
                }
                TestProxyKind::Http => {
                    negotiate_test_http_proxy(&mut client, expected_host, expected_port)
                }
            }

            let target = TcpStream::connect(target_addr).unwrap();
            relay_test_proxy(client, target);
        });
        (addr, worker)
    }

    fn connect_test_socks_client(
        socks_addr: SocketAddr,
        target_host: &str,
        target_port: u16,
    ) -> TcpStream {
        let mut client = TcpStream::connect(socks_addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut method_reply = [0u8; 2];
        client.read_exact(&mut method_reply).unwrap();
        assert_eq!(method_reply, [0x05, 0x00]);

        let host = target_host.as_bytes();
        let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        request.extend_from_slice(host);
        request.extend_from_slice(&target_port.to_be_bytes());
        client.write_all(&request).unwrap();
        let mut connect_reply = [0u8; 10];
        client.read_exact(&mut connect_reply).unwrap();
        assert_eq!(connect_reply[1], SOCKS_REP_SUCCEEDED);
        client
    }

    fn assert_proxy_fallback_relays_bidirectionally(kind: TestProxyKind) {
        const TARGET_HOST: &str = "fallback.test";
        const TARGET_PORT: u16 = 443;

        install_empty_test_router();
        let (target_addr, target_server) = spawn_echo_server();
        let (proxy_addr, proxy_server) =
            spawn_test_proxy(kind, target_addr, TARGET_HOST, TARGET_PORT);
        let proxy_url = format!("{}://{proxy_addr}", kind.scheme());
        let proxy = parse_fallback_proxy(Some(proxy_url.as_str()))
            .unwrap()
            .unwrap();

        let socks_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socks_addr = socks_listener.local_addr().unwrap();
        let socks_server = thread::spawn(move || {
            let (stream, _) = socks_listener.accept().unwrap();
            handle_client(stream, Some(&proxy))
        });

        let mut client = connect_test_socks_client(socks_addr, TARGET_HOST, TARGET_PORT);
        let payload = b"fallback proxy relay test";
        client.write_all(payload).unwrap();
        let mut echoed = vec![0u8; payload.len()];
        client.read_exact(&mut echoed).unwrap();
        assert_eq!(echoed, payload);

        client.shutdown(Shutdown::Write).unwrap();
        let mut trailing = Vec::new();
        client.read_to_end(&mut trailing).unwrap();
        assert!(trailing.is_empty());
        assert!(socks_server.join().unwrap().is_ok());
        proxy_server.join().unwrap();
        target_server.join().unwrap();
    }

    #[test]
    fn normalize_bind_addr_expands_port_only() {
        assert_eq!(normalize_bind_addr(":1080"), "0.0.0.0:1080");
    }

    #[test]
    fn normalize_bind_addr_keeps_explicit_host() {
        assert_eq!(normalize_bind_addr("127.0.0.1:1080"), "127.0.0.1:1080");
    }

    #[test]
    fn listener_retries_only_transient_accept_errors() {
        assert!(is_retryable_accept_error(&std::io::Error::from(
            std::io::ErrorKind::Interrupted
        )));
        assert!(is_retryable_accept_error(&std::io::Error::from(
            std::io::ErrorKind::ConnectionAborted
        )));
        assert!(!is_retryable_accept_error(&std::io::Error::from(
            std::io::ErrorKind::Other
        )));
    }

    #[test]
    fn relay_treats_connection_teardown_as_expected() {
        assert!(is_expected_relay_io_error(&std::io::Error::from(
            std::io::ErrorKind::ConnectionReset
        )));
        assert!(is_expected_relay_io_error(&std::io::Error::from(
            std::io::ErrorKind::BrokenPipe
        )));
        assert!(!is_expected_relay_io_error(&std::io::Error::from(
            std::io::ErrorKind::Other
        )));
    }

    #[test]
    fn relay_worker_panics_are_reported() {
        let worker = thread::spawn(|| -> crate::error::EcResult<()> {
            panic!("relay test panic");
        });

        let err = join_relay_worker(worker, "uplink").unwrap_err();
        assert_eq!(
            crate::error::concise_error(err),
            "uplink relay worker panicked"
        );
    }

    #[test]
    fn direct_fallback_keeps_ipv6_target_bracketed() {
        assert_eq!(target_addr("[2001:db8::1]:443"), "[2001:db8::1]:443");
    }

    #[test]
    fn remote_error_path_uses_consistent_key_separator() {
        let route = route_decision_remote(
            "example.com:443",
            false,
            "192.0.2.1:443".to_string(),
            "Example".to_string(),
            RouteSource::DnsMap,
            None,
        );

        assert_eq!(
            route.path,
            "remote -> Example(192.0.2.1:443); source: dns-map"
        );
    }

    #[test]
    fn cname_dns_map_source_keeps_lookup_provenance() {
        let server = "192.0.2.53:53".parse().unwrap();

        assert_eq!(
            describe_route_source(
                RouteSource::CnameDnsMap,
                Some(crate::dns_resolver::ResolveSource::Server(server))
            ),
            "cname-dns-map via dns-server(192.0.2.53:53)"
        );
    }

    #[test]
    fn planner_error_path_does_not_repeat_planner_unavailable() {
        let route = route_decision_planner_error(
            "example.com:443",
            EcError::Runtime("route matcher is not initialized".to_string()),
        );

        assert_eq!(
            route.path,
            "fallback -> unavailable; reason: route matcher is not initialized"
        );
    }

    #[test]
    fn udp_associate_is_rejected_at_the_socks_boundary() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_client(stream, None)
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut method_reply = [0u8; 2];
        client.read_exact(&mut method_reply).unwrap();
        assert_eq!(method_reply, [0x05, 0x00]);

        client
            .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .unwrap();
        let mut command_reply = [0u8; 10];
        client.read_exact(&mut command_reply).unwrap();
        assert_eq!(command_reply[1], 0x07);
        assert!(server.join().unwrap().is_ok());
    }

    #[test]
    fn invalid_socks_handshake_is_a_request_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_client(stream, None)
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client.write_all(&[0x04, 0x00]).unwrap();

        assert!(matches!(
            server.join().unwrap(),
            Err(ClientFailure::Request(_))
        ));
    }

    #[test]
    fn socks_connect_direct_fallback_relays_bidirectionally() {
        install_empty_test_router();

        let echo_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let echo_addr = match echo_listener.local_addr().unwrap() {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(_) => panic!("expected ipv4 echo listener"),
        };
        let echo_server = thread::spawn(move || {
            let (mut stream, _) = echo_listener.accept().unwrap();
            let mut buf = [0u8; 256];
            loop {
                let n = stream.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                stream.write_all(&buf[..n]).unwrap();
            }
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let socks_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socks_addr = socks_listener.local_addr().unwrap();
        let socks_server = thread::spawn(move || {
            let (stream, _) = socks_listener.accept().unwrap();
            handle_client(stream, None)
        });

        let mut client = TcpStream::connect(socks_addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut method_reply = [0u8; 2];
        client.read_exact(&mut method_reply).unwrap();
        assert_eq!(method_reply, [0x05, 0x00]);

        let mut connect_request = vec![0x05, 0x01, 0x00, 0x01];
        connect_request.extend_from_slice(&echo_addr.ip().octets());
        connect_request.extend_from_slice(&echo_addr.port().to_be_bytes());
        client.write_all(&connect_request).unwrap();
        let mut connect_reply = [0u8; 10];
        client.read_exact(&mut connect_reply).unwrap();
        assert_eq!(connect_reply[1], SOCKS_REP_SUCCEEDED);

        let payload = b"SHIEP-Pipeline relay test";
        client.write_all(payload).unwrap();
        let mut echoed = vec![0u8; payload.len()];
        client.read_exact(&mut echoed).unwrap();
        assert_eq!(echoed, payload);

        client.shutdown(Shutdown::Write).unwrap();
        let mut trailing = Vec::new();
        client.read_to_end(&mut trailing).unwrap();
        assert!(trailing.is_empty());
        assert!(socks_server.join().unwrap().is_ok());
        echo_server.join().unwrap();
    }

    #[test]
    fn socks_connect_socks5_fallback_relays_bidirectionally() {
        assert_proxy_fallback_relays_bidirectionally(TestProxyKind::Socks5);
    }

    #[test]
    fn socks_connect_http_fallback_relays_bidirectionally() {
        assert_proxy_fallback_relays_bidirectionally(TestProxyKind::Http);
    }
}
