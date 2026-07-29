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

    let target = read_request_target(client, req[3])?;
    Ok(SocksRequest { command, target })
}

fn read_request_target(client: &mut TcpStream, atyp: u8) -> EcResult<ConnectTarget> {
    let host = match atyp {
        SOCKS_ATYP_IPV4 => {
            let mut ip = [0u8; 4];
            client
                .read_exact(&mut ip)
                .map_err(|e| EcError::Runtime(format!("read ipv4 failed: {e}")))?;
            format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
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
                .map_err(|e| EcError::Runtime(format!("invalid domain utf8: {e}")))?
        }
        SOCKS_ATYP_IPV6 => {
            let mut ip = [0u8; 16];
            client
                .read_exact(&mut ip)
                .map_err(|e| EcError::Runtime(format!("read ipv6 failed: {e}")))?;
            Ipv6Addr::from(ip).to_string()
        }
        atyp => {
            let _ = write_reply(client, SOCKS_REP_ATYP_NOT_SUPPORTED);
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
    use super::{ConnectTarget, SocksCommand, format_socket_target};

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
