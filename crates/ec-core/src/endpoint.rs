use crate::error::{EcError, EcResult};
use std::fmt::{self, Display};
use std::net::{IpAddr, SocketAddr, TcpStream};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TargetHost {
    Ip(IpAddr),
    Domain(String),
}

impl From<String> for TargetHost {
    fn from(host: String) -> Self {
        match host.trim().parse() {
            Ok(ip) => Self::Ip(ip),
            Err(_) => Self::Domain(host),
        }
    }
}

impl From<&str> for TargetHost {
    fn from(host: &str) -> Self {
        match host.trim().parse() {
            Ok(ip) => Self::Ip(ip),
            Err(_) => Self::Domain(host.to_string()),
        }
    }
}

impl Display for TargetHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(ip) => ip.fmt(f),
            Self::Domain(host) => f.write_str(host),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConnectTarget {
    host: TargetHost,
    port: u16,
}

impl ConnectTarget {
    pub(crate) fn new(host: impl Into<TargetHost>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    pub(crate) fn host(&self) -> &TargetHost {
        &self.host
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    pub(crate) fn connect(&self) -> std::io::Result<TcpStream> {
        match &self.host {
            TargetHost::Ip(ip) => TcpStream::connect(SocketAddr::new(*ip, self.port)),
            TargetHost::Domain(host) => TcpStream::connect((host.as_str(), self.port)),
        }
    }
}

impl Display for ConnectTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            TargetHost::Ip(ip) => SocketAddr::new(*ip, self.port).fmt(f),
            TargetHost::Domain(host) => write!(f, "{}:{}", host.trim(), self.port),
        }
    }
}

const DEFAULT_TLS_PORT: u16 = 443;

pub(crate) fn parse_server(server: &str) -> EcResult<(String, String)> {
    let trimmed = server.trim();
    if trimmed.is_empty() {
        return Err(EcError::InvalidConfig("server is required"));
    }

    let authority_raw = strip_http_scheme(trimmed)
        .split('/')
        .next()
        .ok_or_else(|| EcError::Runtime("invalid server address".to_string()))?;
    if authority_raw.is_empty() {
        return Err(EcError::Runtime("invalid server authority".to_string()));
    }

    let authority = normalize_authority(authority_raw)?;
    let host = extract_host(&authority)?;
    Ok((authority, host))
}

fn strip_http_scheme(server: &str) -> &str {
    server
        .strip_prefix("https://")
        .or_else(|| server.strip_prefix("http://"))
        .unwrap_or(server)
}

fn normalize_authority(authority: &str) -> EcResult<String> {
    if has_explicit_port(authority) {
        return Ok(authority.to_string());
    }

    if looks_like_malformed_port(authority) {
        return Err(EcError::InvalidConfig("invalid server port"));
    }

    Ok(format!("{authority}:{DEFAULT_TLS_PORT}"))
}

fn has_explicit_port(authority: &str) -> bool {
    authority_port_candidate(authority)
        .and_then(|port| port.parse::<u16>().ok())
        .is_some()
}

fn looks_like_malformed_port(authority: &str) -> bool {
    authority_port_candidate(authority)
        .map(|port| !port.is_empty())
        .unwrap_or(false)
}

fn authority_port_candidate(authority: &str) -> Option<&str> {
    if authority.starts_with('[') {
        return authority.rsplit_once("]:").map(|(_, port)| port);
    }
    authority.rsplit_once(':').map(|(_, port)| port)
}

fn extract_host(authority: &str) -> EcResult<String> {
    if authority.starts_with('[') {
        let end = authority
            .find(']')
            .ok_or_else(|| EcError::Runtime("invalid ipv6 authority format".to_string()))?;
        return Ok(authority[1..end].to_string());
    }

    if let Some((host, _)) = authority.rsplit_once(':') {
        if host.is_empty() {
            return Err(EcError::Runtime(
                "invalid host in server authority".to_string(),
            ));
        }
        return Ok(host.to_string());
    }

    Ok(authority.to_string())
}

#[cfg(test)]
mod tests {
    use super::{extract_host, has_explicit_port, parse_server};

    #[test]
    fn parse_server_defaults_to_443() {
        let (authority, host) = parse_server("vpn.example.com").unwrap();
        assert_eq!(authority, "vpn.example.com:443");
        assert_eq!(host, "vpn.example.com");
    }

    #[test]
    fn parse_server_keeps_explicit_port() {
        let (authority, host) = parse_server("https://vpn.example.com:8443").unwrap();
        assert_eq!(authority, "vpn.example.com:8443");
        assert_eq!(host, "vpn.example.com");
    }

    #[test]
    fn parse_server_ipv6_with_port() {
        let (authority, host) = parse_server("https://[2001:db8::1]:443").unwrap();
        assert_eq!(authority, "[2001:db8::1]:443");
        assert_eq!(host, "2001:db8::1");
    }

    #[test]
    fn host_and_port_helpers() {
        assert!(has_explicit_port("vpn.example.com:443"));
        assert!(has_explicit_port("[2001:db8::1]:443"));
        assert!(!has_explicit_port("vpn.example.com"));
        assert!(!has_explicit_port("vpn.example.com:abc"));
        assert_eq!(
            extract_host("vpn.example.com:443").unwrap(),
            "vpn.example.com"
        );
    }

    #[test]
    fn parse_server_rejects_invalid_port() {
        let err = parse_server("vpn.example.com:abc").unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid config: invalid server port")
        );
    }
}
