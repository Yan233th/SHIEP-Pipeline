use crate::error::{EcError, EcResult};
use crate::output::{self, RouteKind, Scope};
use crate::socks_proxy::{FallbackProxy, connect_via_proxy, parse_fallback_proxy};
use crate::socks_wire::{
    ConnectTarget, SOCKS_REP_CMD_NOT_SUPPORTED, SOCKS_REP_SUCCEEDED, SocksCommand,
    format_socket_target, negotiate_method, read_socks_request, write_reply,
};
use std::io::{Read, Write};
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

    let _reason = crate::protocol::wait_tunnel_fatal_reason();
    Err(EcError::Runtime("tunnel closed".to_string()))
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
                Err(err) => {
                    output::warn(Scope::Req, format_args!("accept failed: {err}"));
                    continue;
                }
            };
            let fallback_proxy = fallback_proxy.clone();
            thread::spawn(move || {
                if let Err(err) = handle_client(stream, fallback_proxy.as_ref()) {
                    output::error(Scope::Upstream, crate::error::concise_error(err));
                }
            });
        }
    });
}

fn handle_client(mut client: TcpStream, fallback_proxy: Option<&FallbackProxy>) -> EcResult<()> {
    negotiate_method(&mut client)?;
    let request = read_socks_request(&mut client)?;
    match request.command {
        SocksCommand::Connect => handle_connect(client, request.target, fallback_proxy),
        SocksCommand::UdpAssociate => reject_udp_associate(&mut client),
        SocksCommand::Other(_) => {
            let _ = write_reply(&mut client, SOCKS_REP_CMD_NOT_SUPPORTED);
            Err(EcError::Runtime(format!(
                "unsupported socks command: {}",
                request.command
            )))
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
        }) => {
            let resolved_ip = dial
                .rsplit_once(':')
                .map(|(ip, _)| ip)
                .unwrap_or(dial.as_str());
            log_resolved_route_source(target.host(), resolved_ip, source);
            route_decision_remote(target_display.as_str(), target_is_ip, dial, rc_name, source)
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

fn log_resolved_route_source(host: &str, resolved_ip: &str, source: crate::routing::RouteSource) {
    let arrow = output::weak(" -> ");
    match source {
        crate::routing::RouteSource::DnsDataIpRule => {
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
        crate::routing::RouteSource::DnsServerQuery(server)
        | crate::routing::RouteSource::CnameDnsServerQuery(server)
        | crate::routing::RouteSource::DnsServerIpRuleQuery(server) => {
            output::info(
                Scope::Upstream,
                format_args!(
                    "route DNS resolved {}{}{} via {}",
                    output::value(host),
                    arrow,
                    output::value(resolved_ip),
                    output::value(server)
                ),
            );
        }
        crate::routing::RouteSource::DnsServerCache
        | crate::routing::RouteSource::CnameDnsServerCache
        | crate::routing::RouteSource::DnsServerIpRuleCache => {
            output::info(
                Scope::Upstream,
                format_args!(
                    "route DNS cache hit {}{}{}",
                    output::value(host),
                    arrow,
                    output::value(resolved_ip)
                ),
            );
        }
        _ => {}
    }
}

fn route_decision_remote(
    target_display: &str,
    target_is_ip: bool,
    dial: String,
    rc_name: String,
    source: crate::routing::RouteSource,
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
        path: format!("remote -> {name}({dial}); source={}", source.describe()),
        transport: RouteTransport::Tunnel(dial),
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
        path: format!("fallback -> unavailable; reason: route planner unavailable: {reason}"),
        transport: RouteTransport::Unsupported("route planner unavailable".to_string()),
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
    let mut c_to_r_src = client
        .try_clone()
        .map_err(|e| EcError::Runtime(format!("clone client stream failed: {e}")))?;

    let t1 = thread::spawn(move || {
        let mut buf = [0u8; RELAY_BUFFER_SIZE];
        loop {
            match c_to_r_src.read(&mut buf) {
                Ok(0) => {
                    let _ = sender.close();
                    break;
                }
                Ok(n) => {
                    if sender.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => {
                    let _ = sender.close();
                    break;
                }
            }
        }
    });
    let t2 = thread::spawn(move || {
        while let Ok(chunk) = rx.recv() {
            if chunk.is_empty() {
                continue;
            }
            if client.write_all(&chunk).is_err() {
                break;
            }
        }
        let _ = client.shutdown(Shutdown::Write);
    });

    let _ = t1.join();
    let _ = t2.join();
    Ok(())
}

fn relay_direct(client: TcpStream, upstream: TcpStream) -> EcResult<()> {
    let client_reader = client
        .try_clone()
        .map_err(|e| EcError::Runtime(format!("clone client stream failed: {e}")))?;
    let upstream_reader = upstream
        .try_clone()
        .map_err(|e| EcError::Runtime(format!("clone upstream stream failed: {e}")))?;

    let t1 = thread::spawn(move || {
        pump_stream(client_reader, upstream);
    });
    let t2 = thread::spawn(move || {
        pump_stream(upstream_reader, client);
    });

    let _ = t1.join();
    let _ = t2.join();
    Ok(())
}

fn pump_stream(mut src: TcpStream, mut dst: TcpStream) {
    let mut buf = [0u8; RELAY_BUFFER_SIZE];
    loop {
        match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if dst.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let _ = dst.shutdown(Shutdown::Write);
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
    use super::{handle_client, normalize_bind_addr, target_addr};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    #[test]
    fn normalize_bind_addr_expands_port_only() {
        assert_eq!(normalize_bind_addr(":1080"), "0.0.0.0:1080");
    }

    #[test]
    fn normalize_bind_addr_keeps_explicit_host() {
        assert_eq!(normalize_bind_addr("127.0.0.1:1080"), "127.0.0.1:1080");
    }

    #[test]
    fn direct_fallback_keeps_ipv6_target_bracketed() {
        assert_eq!(target_addr("[2001:db8::1]:443"), "[2001:db8::1]:443");
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
}
