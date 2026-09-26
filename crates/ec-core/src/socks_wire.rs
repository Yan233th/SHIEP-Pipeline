use crate::error::{EcError, EcResult};
use std::io::{Read, Write};
use std::net::{Ipv6Addr, TcpStream};

const SOCKS_VERSION_5: u8 = 0x05;
const SOCKS_METHOD_NO_AUTH: u8 = 0x00;
const SOCKS_METHOD_NOT_ACCEPTABLE: u8 = 0xff;
const SOCKS_CMD_CONNECT: u8 = 0x01;
const SOCKS_CMD_UDP_ASSOCIATE: u8 = 0x03;
const SOCKS_RSV: u8 = 0x00;
const SOCKS_ATYP_IPV4: u8 = 0x01;
const SOCKS_ATYP_DOMAIN: u8 = 0x03;
const SOCKS_ATYP_IPV6: u8 = 0x04;
pub(crate) const SOCKS_REP_GENERAL_FAILURE: u8 = 0x01;
pub(crate) const SOCKS_REP_SUCCEEDED: u8 = 0x00;
pub(crate) const SOCKS_REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const SOCKS_REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

pub(crate) fn negotiate_method(client: &mut TcpStream) -> EcResult<()> {
    let mut head = [0u8; 2];
    client
        .read_exact(&mut head)
        .map_err(|e| EcError::Runtime(format!("socks hello read failed: {e}")))?;
    if head[0] != SOCKS_VERSION_5 {
        return Err(EcError::Runtime("unsupported socks version".to_string()));
    }

    let n_methods = head[1] as usize;
    let mut methods = vec![0u8; n_methods];
    client
        .read_exact(&mut methods)
        .map_err(|e| EcError::Runtime(format!("socks methods read failed: {e}")))?;

    if methods.contains(&SOCKS_METHOD_NO_AUTH) {
        client
            .write_all(&[SOCKS_VERSION_5, SOCKS_METHOD_NO_AUTH])
            .map_err(|e| EcError::Runtime(format!("socks method reply failed: {e}")))?;
        return Ok(());
    }

    client
        .write_all(&[SOCKS_VERSION_5, SOCKS_METHOD_NOT_ACCEPTABLE])
        .map_err(|e| EcError::Runtime(format!("socks method reject reply failed: {e}")))?;
    Err(EcError::Runtime(
        "client does not support no-auth method".to_string(),
    ))
}

pub(crate) fn read_socks_request(client: &mut TcpStream) -> EcResult<SocksRequest> {
    let mut req = [0u8; 4];
    client
        .read_exact(&mut req)
        .map_err(|e| EcError::Runtime(format!("socks request head read failed: {e}")))?;

    if req[0] != SOCKS_VERSION_5 {
        return Err(EcError::Runtime(
            "invalid socks request version".to_string(),
        ));
    }
    let command = SocksCommand::from_byte(req[1]);
    if matches!(command, SocksCommand::Other(_)) {
        let _ = write_reply(client, SOCKS_REP_CMD_NOT_SUPPORTED);
        return Err(EcError::Runtime(format!(
            "unsupported socks command: {command}"
        )));
    }
    if req[2] != SOCKS_RSV {
        let _ = write_reply(client, SOCKS_REP_GENERAL_FAILURE);
        return Err(EcError::Runtime("invalid socks reserved byte".to_string()));
    }

    let target = read_request_target(client, req[3]).inspect_err(|_| {
        let rep = match req[3] {
            SOCKS_ATYP_IPV4 | SOCKS_ATYP_DOMAIN | SOCKS_ATYP_IPV6 => SOCKS_REP_GENERAL_FAILURE,
            _ => SOCKS_REP_ATYP_NOT_SUPPORTED,
        };
        let _ = write_reply(client, rep);
    })?;
    Ok(SocksRequest { command, target })
}

fn read_request_target(client: &mut TcpStream, atyp: u8) -> EcResult<ConnectTarget> {
    let host = match atyp {
        SOCKS_ATYP_IPV4 => {
            let mut ip = [0u8; 4];
            client
                .read_exact(&mut ip)
                .map_err(|e| EcError::Runtime(format!("read ipv4 failed: {e}")))?;
            Ok(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]))
        }
        SOCKS_ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            client
                .read_exact(&mut len)
                .map_err(|e| EcError::Runtime(format!("read domain length failed: {e}")))?;
            let mut domain = vec![0u8; len[0] as usize];
            client
                .read_exact(&mut domain)
                .map_err(|e| EcError::Runtime(format!("read domain failed: {e}")))?;
            String::from_utf8(domain)
                .map_err(|_| EcError::Runtime("invalid socks domain: expected UTF-8".to_string()))
        }
        SOCKS_ATYP_IPV6 => {
            let mut ip = [0u8; 16];
            client
                .read_exact(&mut ip)
                .map_err(|e| EcError::Runtime(format!("read ipv6 failed: {e}")))?;
            Ok(Ipv6Addr::from(ip).to_string())
        }
        atyp => {
            return Err(EcError::Runtime(format!(
                "unsupported socks atyp: 0x{atyp:02x}"
            )));
        }
    };

    let mut port_buf = [0u8; 2];
    client
        .read_exact(&mut port_buf)
        .map_err(|e| EcError::Runtime(format!("read target port failed: {e}")))?;
    let port = u16::from_be_bytes(port_buf);
    let host = host?;
    // A domain is reused in route logs and HTTP CONNECT authority fields.
    if atyp == SOCKS_ATYP_DOMAIN
        && (host.is_empty()
            || host.chars().any(|c| {
                c.is_control()
                    || c.is_whitespace()
                    || matches!(c, ':' | '/' | '\\' | '?' | '#' | '@' | '[' | ']' | '%')
            }))
    {
        return Err(EcError::Runtime(
            "invalid socks domain: empty name or forbidden character".to_string(),
        ));
    }
    Ok(ConnectTarget { host, port })
}

pub(crate) fn write_reply(client: &mut TcpStream, rep: u8) -> EcResult<()> {
    let reply = [
        SOCKS_VERSION_5,
        rep,
        SOCKS_RSV,
        SOCKS_ATYP_IPV4,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    client
        .write_all(&reply)
        .map_err(|e| EcError::Runtime(format!("socks reply write failed: {e}")))
}

pub(crate) fn format_socket_target(host: &str, port: impl std::fmt::Display) -> String {
    let h = host.trim();
    if h.parse::<Ipv6Addr>().is_ok() {
        format!("[{h}]:{port}")
    } else {
        format!("{h}:{port}")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SocksCommand {
    Connect,
    UdpAssociate,
    Other(u8),
}

impl SocksCommand {
    fn from_byte(value: u8) -> Self {
        match value {
            SOCKS_CMD_CONNECT => Self::Connect,
            SOCKS_CMD_UDP_ASSOCIATE => Self::UdpAssociate,
            other => Self::Other(other),
        }
    }
}

impl std::fmt::Display for SocksCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect => f.write_str("CONNECT"),
            Self::UdpAssociate => f.write_str("UDP ASSOCIATE"),
            Self::Other(value) => write!(f, "0x{value:02x}"),
        }
    }
}

pub(crate) struct SocksRequest {
    pub(crate) command: SocksCommand,
    pub(crate) target: ConnectTarget,
}

#[derive(Clone)]
pub(crate) struct ConnectTarget {
    host: String,
    port: u16,
}

impl ConnectTarget {
    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }
}

impl std::fmt::Display for ConnectTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format_socket_target(&self.host, self.port))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ConnectTarget, SocksCommand, SocksRequest, format_socket_target, read_socks_request,
    };
    use crate::error::{EcResult, concise_error};
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::time::Duration;

    fn parse_request(request: &[u8]) -> (EcResult<SocksRequest>, Vec<u8>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (mut server, _) = listener.accept().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.write_all(request).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let result = read_socks_request(&mut server);
        drop(server);
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        (result, reply)
    }

    fn domain_request(domain: &[u8]) -> Vec<u8> {
        let mut request = vec![5, 1, 0, 3, u8::try_from(domain.len()).unwrap()];
        request.extend_from_slice(domain);
        request.extend_from_slice(&443u16.to_be_bytes());
        request
    }

    #[test]
    fn malformed_domains_are_rejected_before_routing() {
        for domain in [
            b"good.test\r\nX-Injected: yes".as_slice(),
            b"",
            b"good.test\x1b[31m",
            b"good.test\0hidden",
            b" good.test",
            b"good.test\t",
            b"good.test\x7f",
            b"good.test/path",
            b"user@good.test",
            b"good.test:80",
            b"good.test?query",
            b"good.test#fragment",
            b"good.test\\path",
            b"[::1]",
            b"good.test%0d%0a",
            "good.test\u{0085}".as_bytes(),
            "good.test\u{00a0}".as_bytes(),
            &[0xff],
        ] {
            let (result, reply) = parse_request(&domain_request(domain));
            let Err(error) = result else {
                panic!("malformed domain accepted: {domain:?}");
            };
            let error = concise_error(error);
            assert!(error.starts_with("invalid socks domain"), "{error}");
            assert!(!error.chars().any(char::is_control), "{error:?}");
            assert_eq!(reply, [5, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
        }
    }

    #[test]
    fn valid_domain_spelling_is_preserved() {
        for domain in [
            "MiXeD.example.",
            "xn--bcher-kva.example",
            "under_score.test",
            "localhost",
            "127.0.0.1",
            "b\u{00fc}cher.example",
        ] {
            let (result, reply) = parse_request(&domain_request(domain.as_bytes()));
            let request = result.unwrap();
            assert_eq!(request.command, SocksCommand::Connect);
            assert_eq!(request.target.host(), domain);
            assert_eq!(request.target.port(), 443);
            assert!(reply.is_empty());
        }
    }

    #[test]
    fn binary_ip_targets_keep_their_address_family() {
        for (atyp, address, expected) in [
            (1, vec![192, 0, 2, 1], "192.0.2.1:443"),
            (
                4,
                "2001:db8::1"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets()
                    .to_vec(),
                "[2001:db8::1]:443",
            ),
        ] {
            let mut packet = vec![5, 1, 0, atyp];
            packet.extend_from_slice(&address);
            packet.extend_from_slice(&443u16.to_be_bytes());
            let (result, reply) = parse_request(&packet);
            assert_eq!(result.unwrap().target.to_string(), expected);
            assert!(reply.is_empty());
        }
    }

    #[test]
    fn malformed_targets_send_one_failure_reply() {
        for (request, code) in [
            (vec![5, 1, 0, 0xff], 8),
            (vec![5, 1, 0, 1, 192, 0], 1),
            (vec![5, 1, 0, 3, 8, b'a'], 1),
            (vec![5, 1, 0, 4, 0], 1),
            (vec![5, 1, 0, 1, 192, 0, 2, 1, 0], 1),
        ] {
            let (result, reply) = parse_request(&request);
            assert!(result.is_err());
            assert_eq!(reply, [5, code, 0, 1, 0, 0, 0, 0, 0, 0]);
        }
    }

    #[test]
    fn socks_command_maps_known_values() {
        assert_eq!(SocksCommand::from_byte(0x01), SocksCommand::Connect);
        assert_eq!(SocksCommand::from_byte(0x03), SocksCommand::UdpAssociate);
        assert_eq!(SocksCommand::from_byte(0x02), SocksCommand::Other(0x02));
    }

    #[test]
    fn ipv6_targets_use_bracketed_socket_format() {
        let target = ConnectTarget {
            host: "2001:db8::1".to_string(),
            port: 443,
        };

        assert_eq!(target.to_string(), "[2001:db8::1]:443");
        assert_eq!(format_socket_target("example.com", 443), "example.com:443");
    }
}
