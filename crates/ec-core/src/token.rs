use crate::endpoint::parse_server;
use crate::error::{EcError, EcResult};
use std::io::{ErrorKind, Read, Write};
use std::time::{Duration, Instant};

const TOKEN_IO_TIMEOUT: Duration = Duration::from_secs(5);
const TOKEN_READ_DEADLINE: Duration = Duration::from_secs(8);
const TOKEN_SESSION_HEX_SLICE_LEN: usize = 31;

pub fn fetch_agent_token(server: &str, twf_id: &str) -> EcResult<String> {
    let (authority, host) = parse_server(server)?;

    let tcp = crate::tls::connect_tcp_with_timeout(&authority, TOKEN_IO_TIMEOUT, "token")?;
    let mut stream = crate::tls::connect_http(tcp, &host, "token")?;

    let request = build_token_request(&authority, twf_id);
    stream
        .write_all(request.as_bytes())
        .map_err(|e| EcError::Runtime(format!("token request write failed: {e}")))?;

    let mut received_response = false;
    let mut buf = [0u8; 4096];
    let deadline = Instant::now() + TOKEN_READ_DEADLINE;
    while Instant::now() < deadline {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => received_response = true,
            Err(e) if e.kind() == ErrorKind::TimedOut || e.kind() == ErrorKind::WouldBlock => {
                break;
            }
            Err(e) => return Err(EcError::Runtime(format!("token response read failed: {e}"))),
        }
    }
    if !received_response {
        return Err(EcError::Runtime(
            "token response is empty or timed out".to_string(),
        ));
    }

    let session_id = stream.session_id();
    if session_id.is_empty() {
        return Err(EcError::Runtime(
            "server tls session id is empty".to_string(),
        ));
    }
    let session_id_hex = hex::encode(session_id);
    if session_id_hex.len() < TOKEN_SESSION_HEX_SLICE_LEN {
        return Err(EcError::Runtime(format!(
            "server session id hex too short: {}",
            session_id_hex.len()
        )));
    }

    let mut token = session_id_hex[..TOKEN_SESSION_HEX_SLICE_LEN].to_string();
    token.push('\0');
    Ok(token)
}

fn build_token_request(authority: &str, twf_id: &str) -> String {
    format!(
        "GET /por/conf.csp HTTP/1.1\r\nHost: {authority}\r\nCookie: TWFID={twf_id}\r\nConnection: keep-alive\r\n\r\n\
         GET /por/rclist.csp HTTP/1.1\r\nHost: {authority}\r\nCookie: TWFID={twf_id}\r\nConnection: close\r\n\r\n"
    )
}

#[cfg(test)]
mod tests {
    use super::build_token_request;

    #[test]
    fn build_token_request_contains_expected_paths_and_cookie() {
        let req = build_token_request("vpn.example.com:443", "ABCDEF");
        assert!(req.contains("GET /por/conf.csp HTTP/1.1"));
        assert!(req.contains("GET /por/rclist.csp HTTP/1.1"));
        assert!(req.contains("Host: vpn.example.com:443"));
        assert!(req.contains("Cookie: TWFID=ABCDEF"));
    }
}
