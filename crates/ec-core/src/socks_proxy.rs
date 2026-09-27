use crate::error::{EcError, EcResult};
use crate::output;
use crate::socks_wire::format_socket_target;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV6, TcpStream};
use std::time::Duration;

const HTTP_PROXY_HEAD_MAX_SIZE: usize = 16 * 1024;
const PROXY_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const SOCKS_VERSION_5: u8 = 0x05;
const SOCKS_METHOD_NO_AUTH: u8 = 0x00;
const SOCKS_CMD_CONNECT: u8 = 0x01;
const SOCKS_RSV: u8 = 0x00;
const SOCKS_ATYP_IPV4: u8 = 0x01;
const SOCKS_ATYP_DOMAIN: u8 = 0x03;
const SOCKS_ATYP_IPV6: u8 = 0x04;
const SOCKS_REP_SUCCEEDED: u8 = 0x00;
const FALLBACK_SCHEME_SOCKS5: &str = "socks5";
const FALLBACK_SCHEME_SOCKS5H: &str = "socks5h";
const FALLBACK_SCHEME_HTTP: &str = "http";
const FALLBACK_SCHEME_ERROR: &str =
    "fallback is invalid: only socks5://, socks5h:// and http:// are supported";

#[derive(Clone)]
pub(crate) struct FallbackProxy {
    pub(crate) url: String,
    addr: String,
    kind: FallbackProxyKind,
}

#[derive(Clone, Copy)]
enum FallbackProxyKind {
    Socks5,
    Http,
}

impl FallbackProxy {
    pub(crate) fn connect(&self, host: &str, port: u16) -> EcResult<TcpStream> {
        match self.kind {
            FallbackProxyKind::Socks5 => connect_via_socks5_proxy(&self.addr, host, port),
            FallbackProxyKind::Http => connect_via_http_connect_proxy(&self.addr, host, port),
        }
    }
}

pub(crate) fn connect_via_proxy(
    proxy: &FallbackProxy,
    host: &str,
    port: u16,
) -> EcResult<TcpStream> {
    proxy.connect(host, port)
}

pub(crate) fn parse_fallback_proxy(raw: Option<&str>) -> EcResult<Option<FallbackProxy>> {
    raw.map(str::trim)
        .filter(|v| !v.is_empty())
        .map(parse_fallback_proxy_value)
        .transpose()
}

fn parse_fallback_proxy_value(raw: &str) -> EcResult<FallbackProxy> {
    let (scheme, addr, kind) = if let Some((scheme, rest)) = raw.split_once("://") {
        (scheme, rest.trim(), parse_fallback_proxy_scheme(scheme)?)
    } else {
        (FALLBACK_SCHEME_SOCKS5H, raw, FallbackProxyKind::Socks5)
    };
    validate_proxy_addr(addr)?;
    Ok(FallbackProxy {
        addr: addr.to_string(),
        url: format!("{scheme}://{addr}"),
        kind,
    })
}

fn validate_proxy_addr(addr: &str) -> EcResult<()> {
    if addr.is_empty() {
        return Err(EcError::InvalidConfig(
            "fallback is invalid: empty proxy address",
        ));
    }
    if addr.contains('@') {
        return Err(EcError::InvalidConfig(
            "fallback is invalid: proxy authentication is not supported",
        ));
    }
    if addr
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '/' | '\\' | '?' | '#'))
    {
        return Err(EcError::InvalidConfig(
            "fallback is invalid: expected host:port with no path, query or fragment",
        ));
    }
    let (host, port) = addr.rsplit_once(':').ok_or(EcError::InvalidConfig(
        "fallback is invalid: proxy port is required",
    ))?;
    if !port.bytes().all(|b| b.is_ascii_digit()) || !matches!(port.parse::<u16>(), Ok(1..=u16::MAX))
    {
        return Err(EcError::InvalidConfig(
            "fallback is invalid: proxy port must be between 1 and 65535",
        ));
    }
    let valid_host = if host.starts_with('[') {
        addr.parse::<SocketAddrV6>().is_ok()
    } else {
        !host.is_empty() && !host.contains([':', '[', ']'])
    };
    if !valid_host {
        return Err(EcError::InvalidConfig(
            "fallback is invalid: expected a hostname, IPv4 address or bracketed IPv6 address",
        ));
    }
    Ok(())
}

fn parse_fallback_proxy_scheme(scheme: &str) -> EcResult<FallbackProxyKind> {
    match scheme {
        FALLBACK_SCHEME_SOCKS5 | FALLBACK_SCHEME_SOCKS5H => Ok(FallbackProxyKind::Socks5),
        FALLBACK_SCHEME_HTTP => Ok(FallbackProxyKind::Http),
        _ => Err(EcError::InvalidConfig(FALLBACK_SCHEME_ERROR)),
    }
}

fn connect_via_socks5_proxy(proxy_addr: &str, host: &str, port: u16) -> EcResult<TcpStream> {
    connect_via_socks5_proxy_with_timeout(proxy_addr, host, port, PROXY_HANDSHAKE_TIMEOUT)
}

fn connect_via_socks5_proxy_with_timeout(
    proxy_addr: &str,
    host: &str,
    port: u16,
    timeout: Duration,
) -> EcResult<TcpStream> {
    let mut stream = connect_tcp_stream(proxy_addr, "fallback proxy")?;
    set_proxy_handshake_timeout(&stream, Some(timeout))?;
    negotiate_socks5_proxy_no_auth(&mut stream)?;
    write_socks5_connect_request(&mut stream, host, port)?;
    read_socks5_connect_reply(&mut stream)?;
    set_proxy_handshake_timeout(&stream, None)?;
    Ok(stream)
}

fn connect_via_http_connect_proxy(proxy_addr: &str, host: &str, port: u16) -> EcResult<TcpStream> {
    connect_via_http_connect_proxy_with_timeout(proxy_addr, host, port, PROXY_HANDSHAKE_TIMEOUT)
}

fn connect_via_http_connect_proxy_with_timeout(
    proxy_addr: &str,
    host: &str,
    port: u16,
    timeout: Duration,
) -> EcResult<TcpStream> {
    let mut stream = connect_tcp_stream(proxy_addr, "fallback http proxy")?;
    set_proxy_handshake_timeout(&stream, Some(timeout))?;
    let request = build_http_connect_request(host, port);
    stream
        .write_all(request.as_bytes())
        .map_err(|e| EcError::Runtime(format!("http proxy connect request write failed: {e}")))?;
    let reply_head = read_http_proxy_head(&mut stream)?;
    ensure_http_connect_success(reply_head.as_str())?;
    set_proxy_handshake_timeout(&stream, None)?;
    Ok(stream)
}

fn build_http_connect_request(host: &str, port: u16) -> String {
    let authority = format_socket_target(host, port);
    format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nConnection: keep-alive\r\nProxy-Connection: keep-alive\r\n\r\n"
    )
}

fn connect_tcp_stream(addr: &str, label: &str) -> EcResult<TcpStream> {
    TcpStream::connect(addr)
        .map_err(|e| EcError::Runtime(format!("connect {label} {addr} failed: {e}")))
}

fn set_proxy_handshake_timeout(stream: &TcpStream, timeout: Option<Duration>) -> EcResult<()> {
    let action = if timeout.is_some() { "set" } else { "clear" };
    stream.set_read_timeout(timeout).map_err(|e| {
        EcError::Runtime(format!(
            "{action} fallback proxy handshake timeout failed: {e}"
        ))
    })
}

fn proxy_read_error(context: &str, err: std::io::Error) -> EcError {
    if matches!(err.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) {
        EcError::Runtime(format!("{context} timed out"))
    } else {
        EcError::Runtime(format!("{context} read failed: {err}"))
    }
}

fn read_proxy_exact(stream: &mut TcpStream, buf: &mut [u8], context: &str) -> EcResult<()> {
    stream
        .read_exact(buf)
        .map_err(|e| proxy_read_error(context, e))
}

fn negotiate_socks5_proxy_no_auth(stream: &mut TcpStream) -> EcResult<()> {
    stream
        .write_all(&[SOCKS_VERSION_5, 0x01, SOCKS_METHOD_NO_AUTH])
        .map_err(|e| EcError::Runtime(format!("proxy greeting write failed: {e}")))?;

    let mut method_resp = [0u8; 2];
    read_proxy_exact(stream, &mut method_resp, "fallback proxy greeting")?;
    if method_resp != [SOCKS_VERSION_5, SOCKS_METHOD_NO_AUTH] {
        return Err(EcError::Runtime(format!(
            "fallback proxy auth method unsupported: version=0x{:02x} method=0x{:02x}",
            method_resp[0], method_resp[1]
        )));
    }
    Ok(())
}

fn write_socks5_connect_request(stream: &mut TcpStream, host: &str, port: u16) -> EcResult<()> {
    let mut req = Vec::with_capacity(300);
    req.push(SOCKS_VERSION_5);
    req.push(SOCKS_CMD_CONNECT);
    req.push(SOCKS_RSV);
    append_socks5_addr(&mut req, host)?;
    req.extend_from_slice(&port.to_be_bytes());
    stream
        .write_all(&req)
        .map_err(|e| EcError::Runtime(format!("proxy connect request write failed: {e}")))
}

fn read_socks5_connect_reply(stream: &mut TcpStream) -> EcResult<()> {
    let mut head = [0u8; 4];
    read_proxy_exact(stream, &mut head, "fallback proxy connect reply")?;
    if head[0] != SOCKS_VERSION_5 {
        return Err(EcError::Runtime(format!(
            "invalid fallback proxy reply version: 0x{:02x}",
            head[0]
        )));
    }
    if head[2] != SOCKS_RSV {
        return Err(EcError::Runtime(format!(
            "invalid fallback proxy reserved byte: 0x{:02x}",
            head[2]
        )));
    }
    if head[1] != SOCKS_REP_SUCCEEDED {
        let code = format!("0x{:02x}", head[1]);
        return Err(EcError::Runtime(format!(
            "fallback proxy connect rejected with code: {} ({})",
            output::value(code),
            socks5_reply_name(head[1])
        )));
    }
    consume_socks5_addr_and_port(stream, head[3])
}

fn read_http_proxy_head(stream: &mut TcpStream) -> EcResult<String> {
    let mut buf = Vec::with_capacity(256);
    let mut chunk = [0u8; 256];
    loop {
        let start = buf.len();
        // Bound peeking by header capacity; consume only through the delimiter.
        buf.reserve(1);
        let remaining = (buf.capacity() - start)
            .min(HTTP_PROXY_HEAD_MAX_SIZE - start)
            .min(chunk.len());
        let n = stream
            .peek(&mut chunk[..remaining])
            .map_err(|e| proxy_read_error("http proxy connect reply", e))?;
        if n == 0 {
            return Err(EcError::Runtime(
                "http proxy connect reply header is incomplete".to_string(),
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        let search_start = start.saturating_sub(3);
        let end = buf[search_start..]
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .map(|offset| search_start + offset + 4);
        let consume_end = end.unwrap_or(buf.len());
        read_proxy_exact(
            stream,
            &mut buf[start..consume_end],
            "http proxy connect reply",
        )?;
        if let Some(end) = end {
            buf.truncate(end);
            break;
        }
        if buf.len() == HTTP_PROXY_HEAD_MAX_SIZE {
            return Err(EcError::Runtime(
                "http proxy connect reply header is too large".to_string(),
            ));
        }
    }
    Ok(String::from_utf8_lossy(&buf).to_string())
}

fn ensure_http_connect_success(reply_head: &str) -> EcResult<()> {
    let status_line = reply_head.lines().next().unwrap_or_default().trim();
    if !status_line.starts_with("HTTP/") {
        return Err(EcError::Runtime(format!(
            "invalid http proxy connect reply: {status_line}"
        )));
    }
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse::<u16>().ok())
        .ok_or_else(|| {
            EcError::Runtime(format!(
                "invalid http proxy connect status line: {status_line}"
            ))
        })?;
    if !(200..300).contains(&code) {
        return Err(EcError::Runtime(format!(
            "http proxy connect rejected: {status_line}"
        )));
    }
    Ok(())
}

fn socks5_reply_name(code: u8) -> &'static str {
    match code {
        0x00 => "succeeded",
        0x01 => "general failure",
        0x02 => "connection not allowed",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "ttl expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown reply code",
    }
}

fn append_socks5_addr(buf: &mut Vec<u8>, host: &str) -> EcResult<()> {
    let host = host.trim();
    if let Ok(ipv4) = host.parse::<Ipv4Addr>() {
        buf.push(SOCKS_ATYP_IPV4);
        buf.extend_from_slice(&ipv4.octets());
        return Ok(());
    }
    if let Ok(ipv6) = host.parse::<Ipv6Addr>() {
        buf.push(SOCKS_ATYP_IPV6);
        buf.extend_from_slice(&ipv6.octets());
        return Ok(());
    }
    if host.is_empty() || host.len() > 255 {
        return Err(EcError::Runtime(
            "fallback proxy target domain is empty or too long".to_string(),
        ));
    }
    buf.push(SOCKS_ATYP_DOMAIN);
    buf.push(host.len() as u8);
    buf.extend_from_slice(host.as_bytes());
    Ok(())
}

fn consume_socks5_addr_and_port(stream: &mut TcpStream, atyp: u8) -> EcResult<()> {
    match atyp {
        SOCKS_ATYP_IPV4 => {
            let mut buf = [0u8; 4];
            read_proxy_exact(stream, &mut buf, "fallback proxy connect reply")?;
        }
        SOCKS_ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            read_proxy_exact(stream, &mut len, "fallback proxy connect reply")?;
            if len[0] == 0 {
                return Err(EcError::Runtime(
                    "fallback proxy reply has an empty bind domain".to_string(),
                ));
            }
            let mut buf = vec![0u8; len[0] as usize];
            read_proxy_exact(stream, &mut buf, "fallback proxy connect reply")?;
        }
        SOCKS_ATYP_IPV6 => {
            let mut buf = [0u8; 16];
            read_proxy_exact(stream, &mut buf, "fallback proxy connect reply")?;
        }
        _ => {
            return Err(EcError::Runtime(format!(
                "unsupported fallback proxy bind atyp: 0x{atyp:02x}"
            )));
        }
    }
    let mut port = [0u8; 2];
    read_proxy_exact(stream, &mut port, "fallback proxy connect reply")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        HTTP_PROXY_HEAD_MAX_SIZE, SOCKS_ATYP_IPV6, append_socks5_addr, build_http_connect_request,
        connect_via_http_connect_proxy_with_timeout, connect_via_socks5_proxy_with_timeout,
        ensure_http_connect_success, parse_fallback_proxy, read_http_proxy_head,
    };
    use std::io::{Read, Write};
    use std::net::{Ipv6Addr, TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    const TEST_PROXY_TIMEOUT: Duration = Duration::from_millis(100);
    const TEST_TARGET_HOST: &str = "fallback.test";
    const TEST_TARGET_PORT: u16 = 443;

    fn spawn_test_proxy<F>(handler: F) -> (String, thread::JoinHandle<()>)
    where
        F: FnOnce(TcpStream) + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handler(stream);
        });
        (addr.to_string(), worker)
    }

    fn wait_for_peer_close(stream: &mut TcpStream) {
        let mut buf = [0u8; 256];
        while stream.read(&mut buf).unwrap() != 0 {}
    }

    fn negotiate_test_socks5_greeting(stream: &mut TcpStream) {
        let mut greeting = [0u8; 3];
        stream.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting, [0x05, 0x01, 0x00]);
        stream.write_all(&[0x05, 0x00]).unwrap();
    }

    fn read_test_socks5_connect_request(stream: &mut TcpStream) {
        let mut head = [0u8; 4];
        stream.read_exact(&mut head).unwrap();
        assert_eq!(head, [0x05, 0x01, 0x00, 0x03]);

        let mut host_len = [0u8; 1];
        stream.read_exact(&mut host_len).unwrap();
        let mut host = vec![0u8; host_len[0] as usize];
        stream.read_exact(&mut host).unwrap();
        let mut port = [0u8; 2];
        stream.read_exact(&mut port).unwrap();
        assert_eq!(host, TEST_TARGET_HOST.as_bytes());
        assert_eq!(u16::from_be_bytes(port), TEST_TARGET_PORT);
    }

    fn read_test_http_connect_request(stream: &mut TcpStream) {
        let mut head = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).unwrap();
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let head = String::from_utf8(head).unwrap();
        assert!(head.starts_with("CONNECT fallback.test:443 HTTP/1.1\r\n"));
    }

    #[test]
    fn parse_fallback_proxy_accepts_socks5_scheme() {
        let parsed = parse_fallback_proxy(Some("socks5://127.0.0.1:1080")).unwrap();
        assert_eq!(parsed.unwrap().addr, "127.0.0.1:1080");
    }

    #[test]
    fn parse_fallback_proxy_accepts_plain_host_port() {
        let parsed = parse_fallback_proxy(Some("127.0.0.1:1080")).unwrap();
        let proxy = parsed.unwrap();
        assert_eq!(proxy.addr, "127.0.0.1:1080");
        assert_eq!(proxy.url, "socks5h://127.0.0.1:1080");
    }

    #[test]
    fn parse_fallback_proxy_accepts_http_scheme() {
        let parsed = parse_fallback_proxy(Some("http://127.0.0.1:8080")).unwrap();
        let proxy = parsed.unwrap();
        assert_eq!(proxy.addr, "127.0.0.1:8080");
        assert_eq!(proxy.url, "http://127.0.0.1:8080");
    }

    #[test]
    fn parse_fallback_proxy_rejects_unsupported_scheme() {
        let err = match parse_fallback_proxy(Some("https://127.0.0.1:8443")) {
            Ok(_) => panic!("expected unsupported fallback scheme to fail"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("only socks5://, socks5h:// and http:// are supported")
        );
    }

    #[test]
    fn parse_fallback_proxy_rejects_invalid_ports() {
        for addr in [
            "proxy.test",
            "proxy.test:",
            "proxy.test:0",
            "proxy.test:114514",
            "proxy.test:-1",
            "proxy.test:+80",
            "proxy.test:http",
            "[::1]",
            "[::1]:65536",
        ] {
            for prefix in ["", "socks5://", "socks5h://", "http://"] {
                let raw = format!("{prefix}{addr}");
                let Err(error) = parse_fallback_proxy(Some(&raw)) else {
                    panic!("invalid proxy port accepted: {raw}");
                };
                assert!(matches!(error, crate::error::EcError::InvalidConfig(_)));
                assert!(error.to_string().contains("port"), "{error}");
            }
        }
    }

    #[test]
    fn parse_fallback_proxy_rejects_invalid_authorities() {
        for addr in [
            ":1080",
            "proxy.test:1080/path",
            "proxy.test/path:1080",
            "proxy.test?query:1080",
            "proxy.test#fragment:1080",
            "proxy.test\\path:1080",
            "user:secret@proxy.test:1080",
            "proxy.test\r\n:1080",
            "proxy test:1080",
            "::1:1080",
            "[::1:1080",
            "[::1]extra:1080",
            "[proxy.test]:1080",
            "[fe80::1%4294967296]:1080",
        ] {
            let raw = format!("socks5h://{addr}");
            let Err(error) = parse_fallback_proxy(Some(&raw)) else {
                panic!("invalid proxy authority accepted: {raw:?}");
            };
            assert!(matches!(error, crate::error::EcError::InvalidConfig(_)));
            assert!(!error.to_string().contains("secret"));
        }
    }

    #[test]
    fn parse_fallback_proxy_accepts_hostnames_and_bracketed_ipv6_without_resolution() {
        for addr in [
            "proxy.invalid:1",
            "localhost:65535",
            "[2001:db8::1]:1080",
            "[fe80::1%1]:1080",
            "[fe80::1%4294967295]:1080",
        ] {
            for prefix in ["socks5://", "socks5h://", "http://"] {
                let url = format!("{prefix}{addr}");
                let proxy = parse_fallback_proxy(Some(&url)).unwrap().unwrap();
                assert_eq!(proxy.addr, addr);
                assert_eq!(proxy.url, url);
            }
        }
    }

    #[test]
    fn http_connect_success_accepts_any_2xx() {
        for code in [200, 201, 204, 299] {
            ensure_http_connect_success(&format!("HTTP/1.1 {code} Connected\r\n\r\n")).unwrap();
        }
    }

    #[test]
    fn http_connect_success_rejects_non_2xx() {
        for code in [199, 300, 407, 503] {
            let err = ensure_http_connect_success(&format!("HTTP/1.1 {code} Rejected\r\n\r\n"))
                .unwrap_err();
            assert!(err.to_string().contains("http proxy connect rejected"));
        }
    }

    #[test]
    fn http_connect_success_rejects_non_http_response() {
        let err = ensure_http_connect_success("HELLO\r\n\r\n").unwrap_err();
        assert!(err.to_string().contains("invalid http proxy connect reply"));
    }

    #[test]
    fn socks5_ipv6_target_uses_ipv6_atyp_and_full_address() {
        let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let mut encoded = Vec::new();

        append_socks5_addr(&mut encoded, &ip.to_string()).unwrap();

        assert_eq!(encoded[0], SOCKS_ATYP_IPV6);
        assert_eq!(&encoded[1..], &ip.octets());
    }

    #[test]
    fn http_connect_ipv6_target_uses_bracketed_authority() {
        let request = build_http_connect_request("2001:db8::1", 443);

        assert!(request.starts_with("CONNECT [2001:db8::1]:443 HTTP/1.1\r\n"));
        assert!(request.contains("Host: [2001:db8::1]:443\r\n"));
    }

    #[test]
    fn malformed_socks5_success_replies_are_rejected() {
        for (reply, expected) in [
            (vec![5, 0, 1, 1, 127, 0, 0, 1, 0, 0], "reserved byte"),
            (vec![5, 0, 0, 3, 0, 0, 0], "empty bind domain"),
        ] {
            let (addr, proxy) = spawn_test_proxy(move |mut stream| {
                negotiate_test_socks5_greeting(&mut stream);
                read_test_socks5_connect_request(&mut stream);
                stream.write_all(&reply).unwrap();
            });
            let result = connect_via_socks5_proxy_with_timeout(
                &addr,
                TEST_TARGET_HOST,
                TEST_TARGET_PORT,
                Duration::from_secs(2),
            );
            proxy.join().unwrap();
            let error = result.unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
        }
    }

    #[test]
    fn successful_http_connect_keeps_the_first_tunnel_payload() {
        for code in [200, 204] {
            let (addr, proxy) = spawn_test_proxy(move |mut stream| {
                read_test_http_connect_request(&mut stream);
                let response = format!(
                    "HTTP/1.1 {code} Connected\r\nContent-Length: 999\r\n\r\nfirst payload"
                );
                stream.write_all(response.as_bytes()).unwrap();
            });
            let result = connect_via_http_connect_proxy_with_timeout(
                &addr,
                TEST_TARGET_HOST,
                TEST_TARGET_PORT,
                Duration::from_secs(2),
            );
            proxy.join().unwrap();
            let mut stream = result.unwrap();
            let mut payload = Vec::new();
            stream.read_to_end(&mut payload).unwrap();
            assert_eq!(payload, b"first payload");
            assert_eq!(stream.read_timeout().unwrap(), None);
        }
    }

    fn padded_http_head(size: usize) -> String {
        let prefix = "HTTP/1.1 200 Connected\r\nX-Padding: ";
        format!("{prefix}{}\r\n\r\n", "a".repeat(size - prefix.len() - 4))
    }

    #[test]
    fn http_head_reader_keeps_payload_across_chunk_boundaries() {
        for size in [255, 256, 257, 258, 511, 512, 513, HTTP_PROXY_HEAD_MAX_SIZE] {
            let head = padded_http_head(size);
            let expected = head.clone();
            let (addr, proxy) = spawn_test_proxy(move |mut stream| {
                let mut response = head.into_bytes();
                response.extend_from_slice(b"\x00\xfftunnel\r\n\r\n");
                stream.write_all(&response).unwrap();
            });
            let mut stream = TcpStream::connect(addr).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            assert_eq!(read_http_proxy_head(&mut stream).unwrap(), expected);
            let mut payload = Vec::new();
            stream.read_to_end(&mut payload).unwrap();
            assert_eq!(payload, b"\x00\xfftunnel\r\n\r\n");
            proxy.join().unwrap();
        }
    }

    #[test]
    fn http_head_reader_accepts_fragmented_input() {
        let head = padded_http_head(513);
        let expected = head.clone();
        let (addr, proxy) = spawn_test_proxy(move |mut stream| {
            stream.set_nodelay(true).unwrap();
            for byte in head.bytes() {
                stream.write_all(&[byte]).unwrap();
            }
            stream.write_all(b"first payload").unwrap();
        });
        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        assert_eq!(read_http_proxy_head(&mut stream).unwrap(), expected);
        let mut payload = Vec::new();
        stream.read_to_end(&mut payload).unwrap();
        assert_eq!(payload, b"first payload");
        proxy.join().unwrap();
    }

    #[test]
    fn http_head_reader_rejects_incomplete_or_oversized_headers() {
        for (response, expected) in [
            (String::new(), "incomplete"),
            ("HTTP/1.1 200 Connected\r\n".to_string(), "incomplete"),
            (padded_http_head(HTTP_PROXY_HEAD_MAX_SIZE + 1), "too large"),
        ] {
            let (addr, proxy) = spawn_test_proxy(move |mut stream| {
                stream.write_all(response.as_bytes()).unwrap();
            });
            let mut stream = TcpStream::connect(addr).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let error = read_http_proxy_head(&mut stream).unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
            proxy.join().unwrap();
        }
    }

    #[test]
    fn socks5_proxy_greeting_times_out_when_proxy_is_silent() {
        let (addr, proxy) = spawn_test_proxy(|mut stream| {
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).unwrap();
            wait_for_peer_close(&mut stream);
        });

        let err = connect_via_socks5_proxy_with_timeout(
            &addr,
            TEST_TARGET_HOST,
            TEST_TARGET_PORT,
            TEST_PROXY_TIMEOUT,
        )
        .unwrap_err();
        assert_eq!(
            crate::error::concise_error(err),
            "fallback proxy greeting timed out"
        );
        proxy.join().unwrap();
    }

    #[test]
    fn socks5_proxy_connect_reply_times_out_when_proxy_is_silent() {
        let (addr, proxy) = spawn_test_proxy(|mut stream| {
            negotiate_test_socks5_greeting(&mut stream);
            read_test_socks5_connect_request(&mut stream);
            wait_for_peer_close(&mut stream);
        });

        let err = connect_via_socks5_proxy_with_timeout(
            &addr,
            TEST_TARGET_HOST,
            TEST_TARGET_PORT,
            TEST_PROXY_TIMEOUT,
        )
        .unwrap_err();
        assert_eq!(
            crate::error::concise_error(err),
            "fallback proxy connect reply timed out"
        );
        proxy.join().unwrap();
    }

    #[test]
    fn http_proxy_connect_reply_times_out_when_proxy_is_silent() {
        let (addr, proxy) = spawn_test_proxy(|mut stream| {
            read_test_http_connect_request(&mut stream);
            wait_for_peer_close(&mut stream);
        });

        let err = connect_via_http_connect_proxy_with_timeout(
            &addr,
            TEST_TARGET_HOST,
            TEST_TARGET_PORT,
            TEST_PROXY_TIMEOUT,
        )
        .unwrap_err();
        assert_eq!(
            crate::error::concise_error(err),
            "http proxy connect reply timed out"
        );
        proxy.join().unwrap();
    }

    #[test]
    fn successful_proxy_handshakes_clear_read_timeout() {
        let (socks_addr, socks_proxy) = spawn_test_proxy(|mut stream| {
            negotiate_test_socks5_greeting(&mut stream);
            read_test_socks5_connect_request(&mut stream);
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .unwrap();
            wait_for_peer_close(&mut stream);
        });
        let socks_stream = connect_via_socks5_proxy_with_timeout(
            &socks_addr,
            TEST_TARGET_HOST,
            TEST_TARGET_PORT,
            TEST_PROXY_TIMEOUT,
        )
        .unwrap();
        assert_eq!(socks_stream.read_timeout().unwrap(), None);
        drop(socks_stream);
        socks_proxy.join().unwrap();

        let (http_addr, http_proxy) = spawn_test_proxy(|mut stream| {
            read_test_http_connect_request(&mut stream);
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .unwrap();
            wait_for_peer_close(&mut stream);
        });
        let http_stream = connect_via_http_connect_proxy_with_timeout(
            &http_addr,
            TEST_TARGET_HOST,
            TEST_TARGET_PORT,
            TEST_PROXY_TIMEOUT,
        )
        .unwrap();
        assert_eq!(http_stream.read_timeout().unwrap(), None);
        drop(http_stream);
        http_proxy.join().unwrap();
    }
}
