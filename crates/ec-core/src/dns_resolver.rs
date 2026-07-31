use crate::error::{EcError, EcResult};
use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use std::collections::HashMap;
use std::hash::Hash;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const DNS_IO_TIMEOUT: Duration = Duration::from_millis(1200);
const DNS_CACHE_TTL: Duration = Duration::from_secs(300);
const DNS_CACHE_CAPACITY: usize = 1024;
const DNS_UDP_BUFFER_SIZE: usize = 4096;
const DNS_TCP_MAX_PAYLOAD: usize = 65535;

static DNS_QUERY_ID: AtomicU16 = AtomicU16::new(1);
static DNS_CACHE: OnceLock<Mutex<HashMap<CacheKey, CacheEntry>>> = OnceLock::new();
static DNS_LOOKUP_CACHE: OnceLock<Mutex<HashMap<String, LookupCacheEntry>>> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResolveSource {
    Cache,
    Server(SocketAddr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResolveResult {
    pub ip: Ipv4Addr,
    pub source: ResolveSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LookupResolveResult {
    pub aliases: Vec<String>,
    pub ips: Vec<Ipv4Addr>,
    pub source: ResolveSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    rc_id: i32,
    host: String,
}

#[derive(Debug, Clone, Copy)]
struct CacheEntry {
    ip: Ipv4Addr,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
struct LookupCacheEntry {
    aliases: Vec<String>,
    ips: Vec<Ipv4Addr>,
    expires_at: Instant,
}

enum UdpQueryResult {
    Complete(Message),
    Truncated,
}

pub(crate) fn clear_cache() {
    if let Some(cache) = DNS_CACHE.get()
        && let Ok(mut guard) = cache.lock()
    {
        guard.clear();
    }
    if let Some(cache) = DNS_LOOKUP_CACHE.get()
        && let Ok(mut guard) = cache.lock()
    {
        guard.clear();
    }
}

pub(crate) fn resolve_first_ipv4(
    rc_id: i32,
    host: &str,
    dns_servers: &[SocketAddr],
) -> EcResult<ResolveResult> {
    let key = CacheKey {
        rc_id,
        host: host.to_string(),
    };
    if let Some(ip) = cache_get(&key) {
        return Ok(ResolveResult {
            ip,
            source: ResolveSource::Cache,
        });
    }

    let mut tried = 0usize;
    let mut last_error: Option<String> = None;
    for &server in dns_servers {
        tried += 1;
        match query_server(host, server) {
            Ok(ip) => {
                cache_put(key, ip);
                return Ok(ResolveResult {
                    ip,
                    source: ResolveSource::Server(server),
                });
            }
            Err(err) => {
                last_error = Some(format!("{server}: {}", crate::error::concise_error(err)));
            }
        }
    }

    if tried == 0 {
        return Err(EcError::Runtime(
            "dnsserver lookup has no valid server address".to_string(),
        ));
    }

    Err(EcError::Runtime(format!(
        "dnsserver lookup failed for {host}; {}",
        last_error.unwrap_or_else(|| "no response".to_string())
    )))
}

pub(crate) fn resolve_lookup(
    host: &str,
    dns_servers: &[SocketAddr],
) -> EcResult<LookupResolveResult> {
    let key = normalize_dns_name(host);
    if let Some((aliases, ips)) = lookup_cache_get(&key) {
        return Ok(LookupResolveResult {
            aliases,
            ips,
            source: ResolveSource::Cache,
        });
    }

    let mut tried = 0usize;
    let mut last_error: Option<String> = None;
    for &server in dns_servers {
        tried += 1;
        match query_server_message(host, server) {
            Ok(message) => {
                let aliases = extract_cname_aliases(&message);
                let ips = extract_ipv4s(&message);
                lookup_cache_put(key, aliases.clone(), ips.clone());
                return Ok(LookupResolveResult {
                    aliases,
                    ips,
                    source: ResolveSource::Server(server),
                });
            }
            Err(err) => {
                last_error = Some(format!("{server}: {}", crate::error::concise_error(err)));
            }
        }
    }

    if tried == 0 {
        return Err(EcError::Runtime(
            "dnsserver lookup has no valid server address".to_string(),
        ));
    }

    Err(EcError::Runtime(format!(
        "dnsserver lookup failed for {host}; {}",
        last_error.unwrap_or_else(|| "no response".to_string())
    )))
}

fn query_server(host: &str, server: SocketAddr) -> EcResult<Ipv4Addr> {
    let message = query_server_message(host, server)?;
    extract_first_ipv4(&message, server)
}

fn query_server_message(host: &str, server: SocketAddr) -> EcResult<Message> {
    let (id, request) = build_a_query(host)?;
    match query_udp(id, &request, server)? {
        UdpQueryResult::Complete(message) => Ok(message),
        UdpQueryResult::Truncated => query_tcp(id, &request, server),
    }
}

fn build_a_query(host: &str) -> EcResult<(u16, Vec<u8>)> {
    let mut message = Message::new();
    let id = next_query_id();
    let fqdn = if host.ends_with('.') {
        host.to_string()
    } else {
        format!("{host}.")
    };
    let name = Name::from_ascii(fqdn)
        .map_err(|e| EcError::Runtime(format!("dns query name build failed: {e}")))?;

    message
        .set_id(id)
        .set_recursion_desired(true)
        .add_query(Query::query(name, RecordType::A));

    let payload = message
        .to_vec()
        .map_err(|e| EcError::Runtime(format!("dns query encode failed: {e}")))?;
    Ok((id, payload))
}

fn query_udp(id: u16, request: &[u8], server: SocketAddr) -> EcResult<UdpQueryResult> {
    let socket = bind_udp_socket(server)?;
    socket
        .send_to(request, server)
        .map_err(|e| EcError::Runtime(format!("dns udp send failed: {e}")))?;

    let mut buf = [0u8; DNS_UDP_BUFFER_SIZE];
    // Ignore packets from unexpected peers and only accept responses from the queried server.
    let deadline = Instant::now() + DNS_IO_TIMEOUT;
    while Instant::now() < deadline {
        let (n, peer) = socket
            .recv_from(&mut buf)
            .map_err(|e| EcError::Runtime(format!("dns udp recv failed: {e}")))?;
        if peer != server {
            continue;
        }
        let message = decode_dns_response(&buf[..n], id, server)?;
        if message.truncated() {
            return Ok(UdpQueryResult::Truncated);
        }
        return Ok(UdpQueryResult::Complete(message));
    }
    Err(EcError::Runtime(format!(
        "dns udp recv failed: no valid response from {server}"
    )))
}

fn query_tcp(id: u16, request: &[u8], server: SocketAddr) -> EcResult<Message> {
    let mut stream = TcpStream::connect_timeout(&server, DNS_IO_TIMEOUT)
        .map_err(|e| EcError::Runtime(format!("dns tcp connect failed: {e}")))?;
    stream
        .set_read_timeout(Some(DNS_IO_TIMEOUT))
        .map_err(|e| EcError::Runtime(format!("dns tcp set read timeout failed: {e}")))?;
    stream
        .set_write_timeout(Some(DNS_IO_TIMEOUT))
        .map_err(|e| EcError::Runtime(format!("dns tcp set write timeout failed: {e}")))?;

    let req_len = u16::try_from(request.len())
        .map_err(|_| EcError::Runtime("dns tcp request is too large".to_string()))?;
    stream
        .write_all(&req_len.to_be_bytes())
        .and_then(|_| stream.write_all(request))
        .map_err(|e| EcError::Runtime(format!("dns tcp write failed: {e}")))?;

    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| EcError::Runtime(format!("dns tcp length read failed: {e}")))?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    if resp_len == 0 || resp_len > DNS_TCP_MAX_PAYLOAD {
        return Err(EcError::Runtime(format!(
            "dns tcp response length is invalid: {resp_len}"
        )));
    }

    let mut payload = vec![0u8; resp_len];
    stream
        .read_exact(&mut payload)
        .map_err(|e| EcError::Runtime(format!("dns tcp payload read failed: {e}")))?;
    decode_dns_response(&payload, id, server)
}

fn decode_dns_response(payload: &[u8], expected_id: u16, server: SocketAddr) -> EcResult<Message> {
    let message = Message::from_vec(payload)
        .map_err(|e| EcError::Runtime(format!("dns response decode failed: {e}")))?;
    if message.id() != expected_id {
        return Err(EcError::Runtime(format!(
            "dns response id mismatch from {server}: expected {expected_id}, got {}",
            message.id()
        )));
    }
    if message.message_type() != MessageType::Response {
        return Err(EcError::Runtime(format!(
            "dns response message type is not response from {server}"
        )));
    }
    if message.response_code() != ResponseCode::NoError {
        return Err(EcError::Runtime(format!(
            "dns response code from {server}: {}",
            message.response_code()
        )));
    }
    Ok(message)
}

fn extract_first_ipv4(message: &Message, server: SocketAddr) -> EcResult<Ipv4Addr> {
    if let Some(ip) = extract_ipv4s(message).into_iter().next() {
        return Ok(ip);
    }
    Err(EcError::Runtime(format!("dns no A answer from {server}")))
}

fn extract_ipv4s(message: &Message) -> Vec<Ipv4Addr> {
    let mut ips = Vec::<Ipv4Addr>::new();
    for answer in message.answers() {
        let Some(ip) = answer.data().as_a() else {
            continue;
        };
        let ip = **ip;
        if !ips.contains(&ip) {
            ips.push(ip);
        }
    }
    ips
}

fn extract_cname_aliases(message: &Message) -> Vec<String> {
    let mut aliases = Vec::<String>::new();
    for answer in message.answers() {
        let RData::CNAME(cname) = answer.data() else {
            continue;
        };
        let alias = normalize_dns_name(cname.to_string().as_str());
        if !alias.is_empty() && !aliases.contains(&alias) {
            aliases.push(alias);
        }
    }
    aliases
}

fn normalize_dns_name(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn bind_udp_socket(server: SocketAddr) -> EcResult<UdpSocket> {
    let bind_addr = match server {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let socket = UdpSocket::bind(bind_addr)
        .map_err(|e| EcError::Runtime(format!("dns udp bind failed: {e}")))?;
    socket
        .set_read_timeout(Some(DNS_IO_TIMEOUT))
        .map_err(|e| EcError::Runtime(format!("dns udp set read timeout failed: {e}")))?;
    socket
        .set_write_timeout(Some(DNS_IO_TIMEOUT))
        .map_err(|e| EcError::Runtime(format!("dns udp set write timeout failed: {e}")))?;
    Ok(socket)
}

fn next_query_id() -> u16 {
    DNS_QUERY_ID.fetch_add(1, Ordering::Relaxed)
}

fn cache_get(key: &CacheKey) -> Option<Ipv4Addr> {
    let cache = DNS_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = match cache.lock() {
        Ok(guard) => guard,
        Err(_) => return None,
    };
    let now = Instant::now();
    match guard.get(key).copied() {
        Some(entry) if entry.expires_at > now => Some(entry.ip),
        Some(_) => {
            guard.remove(key);
            None
        }
        None => None,
    }
}

fn cache_put(key: CacheKey, ip: Ipv4Addr) {
    let cache = DNS_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = cache.lock() {
        prepare_cache_insert(&mut guard, &key, DNS_CACHE_CAPACITY, |entry| {
            entry.expires_at
        });
        guard.insert(
            key,
            CacheEntry {
                ip,
                expires_at: Instant::now() + DNS_CACHE_TTL,
            },
        );
    }
}

fn lookup_cache_get(key: &str) -> Option<(Vec<String>, Vec<Ipv4Addr>)> {
    let cache = DNS_LOOKUP_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = match cache.lock() {
        Ok(guard) => guard,
        Err(_) => return None,
    };
    let now = Instant::now();
    match guard.get(key).cloned() {
        Some(entry) if entry.expires_at > now => Some((entry.aliases, entry.ips)),
        Some(_) => {
            guard.remove(key);
            None
        }
        None => None,
    }
}

fn lookup_cache_put(key: String, aliases: Vec<String>, ips: Vec<Ipv4Addr>) {
    let cache = DNS_LOOKUP_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = cache.lock() {
        prepare_cache_insert(&mut guard, &key, DNS_CACHE_CAPACITY, |entry| {
            entry.expires_at
        });
        guard.insert(
            key,
            LookupCacheEntry {
                aliases,
                ips,
                expires_at: Instant::now() + DNS_CACHE_TTL,
            },
        );
    }
}

fn prepare_cache_insert<K, V>(
    cache: &mut HashMap<K, V>,
    key: &K,
    capacity: usize,
    expires_at: impl Fn(&V) -> Instant,
) where
    K: Clone + Eq + Hash,
{
    let now = Instant::now();
    cache.retain(|_, entry| expires_at(entry) > now);

    if capacity == 0 {
        cache.clear();
        return;
    }

    cache.remove(key);
    while cache.len() >= capacity {
        let Some(oldest) = cache
            .iter()
            .min_by_key(|(_, entry)| expires_at(entry))
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        cache.remove(&oldest);
    }
}

#[cfg(test)]
mod tests {
    use super::prepare_cache_insert;
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    #[derive(Clone, Copy)]
    struct TestEntry {
        expires_at: Instant,
    }

    #[test]
    fn cache_insert_prunes_expired_entries() {
        let now = Instant::now();
        let mut cache = HashMap::from([
            (
                "expired",
                TestEntry {
                    expires_at: now - Duration::from_secs(1),
                },
            ),
            (
                "live",
                TestEntry {
                    expires_at: now + Duration::from_secs(30),
                },
            ),
        ]);

        prepare_cache_insert(&mut cache, &"new", 3, |entry| entry.expires_at);

        assert!(!cache.contains_key("expired"));
        assert!(cache.contains_key("live"));
    }

    #[test]
    fn cache_insert_evicts_the_earliest_expiring_entry() {
        let now = Instant::now();
        let mut cache = HashMap::from([
            (
                "oldest",
                TestEntry {
                    expires_at: now + Duration::from_secs(10),
                },
            ),
            (
                "newer",
                TestEntry {
                    expires_at: now + Duration::from_secs(20),
                },
            ),
        ]);

        prepare_cache_insert(&mut cache, &"new", 2, |entry| entry.expires_at);

        assert!(!cache.contains_key("oldest"));
        assert!(cache.contains_key("newer"));
    }
}
