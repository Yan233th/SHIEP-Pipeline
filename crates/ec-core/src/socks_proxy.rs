use crate::error::{EcError, EcResult};
use crate::output;
use crate::socks_wire::format_socket_target;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, TcpStream};

const HTTP_PROXY_HEAD_MAX_SIZE: usize = 16 * 1024;
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
    let raw = raw.trim();
    let parsed = if let Some((scheme, rest)) = raw.split_once("://") {
        let kind = parse_fallback_proxy_scheme(scheme)?;
        FallbackProxy {
            addr: rest.trim().to_string(),
            url: raw.to_string(),
            kind,
        }
    } else {
        FallbackProxy {
            addr: raw.to_string(),
            url: format!("{FALLBACK_SCHEME_SOCKS5H}://{raw}"),
            kind: FallbackProxyKind::Socks5,
        }
    };

    if parsed.addr.trim().is_empty() {
        return Err(EcError::InvalidConfig(
            "fallback is invalid: empty proxy address",
        ));
    }

    Ok(parsed)
}

fn parse_fallback_proxy_scheme(scheme: &str) -> EcResult<FallbackProxyKind> {
    match scheme {
        FALLBACK_SCHEME_SOCKS5 | FALLBACK_SCHEME_SOCKS5H => Ok(FallbackProxyKind::Socks5),
        FALLBACK_SCHEME_HTTP => Ok(FallbackProxyKind::Http),
        _ => Err(EcError::InvalidConfig(FALLBACK_SCHEME_ERROR)),
    }
}

fn connect_via_socks5_proxy(proxy_addr: &str, host: &str, port: u16) -> EcResult<TcpStream> {
    let mut stream = connect_tcp_stream(proxy_addr, "fallback proxy")?;
    negotiate_socks5_proxy_no_auth(&mut stream)?;
    write_socks5_connect_request(&mut stream, host, port)?;
    read_socks5_connect_reply(&mut stream)?;
    Ok(stream)
}

fn connect_via_http_connect_proxy(proxy_addr: &str, host: &str, port: u16) -> EcResult<TcpStream> {
    let mut stream = connect_tcp_stream(proxy_addr, "fallback http proxy")?;
    let request = build_http_connect_request(host, port);
    stream
        .write_all(request.as_bytes())
        .map_err(|e| EcError::Runtime(format!("http proxy connect request write failed: {e}")))?;
    let reply_head = read_http_proxy_head(&mut stream)?;
    ensure_http_connect_success(reply_head.as_str())?;
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

fn negotiate_socks5_proxy_no_auth(stream: &mut TcpStream) -> EcResult<()> {
    stream
        .write_all(&[SOCKS_VERSION_5, 0x01, SOCKS_METHOD_NO_AUTH])
        .map_err(|e| EcError::Runtime(format!("proxy greeting write failed: {e}")))?;

    let mut method_resp = [0u8; 2];
    stream
        .read_exact(&mut method_resp)
        .map_err(|e| EcError::Runtime(format!("proxy greeting read failed: {e}")))?;
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
    stream
        .read_exact(&mut head)
        .map_err(|e| EcError::Runtime(format!("proxy connect reply read failed: {e}")))?;
    if head[0] != SOCKS_VERSION_5 {
        return Err(EcError::Runtime(format!(
            "invalid fallback proxy reply version: 0x{:02x}",
            head[0]
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
    loop {
        let mut one = [0u8; 1];
        let n = stream
            .read(&mut one)
            .map_err(|e| EcError::Runtime(format!("http proxy connect reply read failed: {e}")))?;
        if n == 0 {
            return Err(EcError::Runtime(
                "http proxy connect reply is empty".to_string(),
            ));
        }
        buf.push(one[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        if buf.len() > HTTP_PROXY_HEAD_MAX_SIZE {
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
    if code != 200 {
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
            stream
                .read_exact(&mut buf)
                .map_err(|e| EcError::Runtime(format!("read proxy bind ipv4 failed: {e}")))?;
        }
        SOCKS_ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).map_err(|e| {
                EcError::Runtime(format!("read proxy bind domain length failed: {e}"))
            })?;
            let mut buf = vec![0u8; len[0] as usize];
            stream
                .read_exact(&mut buf)
                .map_err(|e| EcError::Runtime(format!("read proxy bind domain failed: {e}")))?;
        }
        SOCKS_ATYP_IPV6 => {
            let mut buf = [0u8; 16];
            stream
                .read_exact(&mut buf)
                .map_err(|e| EcError::Runtime(format!("read proxy bind ipv6 failed: {e}")))?;
        }
        _ => {
            return Err(EcError::Runtime(format!(
                "unsupported fallback proxy bind atyp: 0x{atyp:02x}"
            )));
        }
    }
    let mut port = [0u8; 2];
    stream
        .read_exact(&mut port)
        .map_err(|e| EcError::Runtime(format!("read proxy bind port failed: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        SOCKS_ATYP_IPV6, append_socks5_addr, build_http_connect_request,
        ensure_http_connect_success, parse_fallback_proxy,
    };
    use std::net::Ipv6Addr;

    #[test]
    fn parse_fallback_proxy_accepts_socks5_scheme() {
        let parsed = parse_fallback_proxy(Some("socks5://127.0.0.1:114514")).unwrap();
        assert_eq!(parsed.unwrap().addr, "127.0.0.1:114514");
    }

    #[test]
    fn parse_fallback_proxy_accepts_plain_host_port() {
        let parsed = parse_fallback_proxy(Some("127.0.0.1:114514")).unwrap();
        let proxy = parsed.unwrap();
        assert_eq!(proxy.addr, "127.0.0.1:114514");
        assert_eq!(proxy.url, "socks5h://127.0.0.1:114514");
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
    fn http_connect_success_accepts_200() {
        ensure_http_connect_success("HTTP/1.1 200 Connection Established\r\n\r\n").unwrap();
    }

    #[test]
    fn http_connect_success_rejects_non_200() {
        let err = ensure_http_connect_success("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
            .unwrap_err();
        assert!(err.to_string().contains("http proxy connect rejected"));
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
}
