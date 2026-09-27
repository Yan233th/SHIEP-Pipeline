use crate::error::{EcError, EcResult};
use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use rsa::rand_core::{OsRng, RngCore};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const DNS_IO_TIMEOUT: Duration = Duration::from_millis(1200);
const DNS_CACHE_TTL: Duration = Duration::from_secs(300);
const DNS_CACHE_CAPACITY: usize = 1024;
const DNS_UDP_BUFFER_SIZE: usize = 4096;
const DNS_TCP_MAX_PAYLOAD: usize = 65535;

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

#[derive(Debug)]
struct DnsAnswer {
    aliases: Vec<String>,
    ips: Vec<Ipv4Addr>,
    ttl: Duration,
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
            Ok((ip, ttl)) => {
                cache_put(key, ip, ttl);
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
        match query_server_answer(host, server) {
            Ok(DnsAnswer { aliases, ips, ttl }) => {
                lookup_cache_put(key, aliases.clone(), ips.clone(), ttl);
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

fn query_server(host: &str, server: SocketAddr) -> EcResult<(Ipv4Addr, Duration)> {
    let answer = query_server_answer(host, server)?;
    let ip = answer
        .ips
        .first()
        .copied()
        .ok_or_else(|| EcError::Runtime(format!("dns no A answer from {server}")))?;
    Ok((ip, answer.ttl))
}

fn query_server_answer(host: &str, server: SocketAddr) -> EcResult<DnsAnswer> {
    extract_answer(&query_server_message(host, server)?)
}

fn query_server_message(host: &str, server: SocketAddr) -> EcResult<Message> {
    let query = build_a_query(host)?;
    let request = query
        .to_vec()
        .map_err(|e| EcError::Runtime(format!("dns query encode failed: {e}")))?;
    match query_udp(&query, &request, server)? {
        UdpQueryResult::Complete(message) => Ok(message),
        UdpQueryResult::Truncated => query_tcp(&query, &request, server),
    }
}

fn build_a_query(host: &str) -> EcResult<Message> {
    let mut message = Message::new();
    let id = next_query_id()?;
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

    Ok(message)
}

fn query_udp(query: &Message, request: &[u8], server: SocketAddr) -> EcResult<UdpQueryResult> {
    let socket = bind_udp_socket(server)?;
    // Connected UDP lets the OS reject datagrams from other peers.
    socket
        .connect(server)
        .map_err(|e| EcError::Runtime(format!("dns udp connect failed: {e}")))?;
    socket
        .send(request)
        .map_err(|e| EcError::Runtime(format!("dns udp send failed: {e}")))?;

    let mut buf = [0u8; DNS_UDP_BUFFER_SIZE];
    let n = socket
        .recv(&mut buf)
        .map_err(|e| EcError::Runtime(format!("dns udp recv failed: {e}")))?;
    let message = decode_dns_response(&buf[..n], query, server)?;
    if message.truncated() {
        Ok(UdpQueryResult::Truncated)
    } else {
        Ok(UdpQueryResult::Complete(message))
    }
}

fn query_tcp(query: &Message, request: &[u8], server: SocketAddr) -> EcResult<Message> {
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
    let message = decode_dns_response(&payload, query, server)?;
    if message.truncated() {
        return Err(EcError::Runtime(format!(
            "dns tcp response is truncated from {server}"
        )));
    }
    Ok(message)
}

fn decode_dns_response(payload: &[u8], query: &Message, server: SocketAddr) -> EcResult<Message> {
    let message = Message::from_vec(payload)
        .map_err(|e| EcError::Runtime(format!("dns response decode failed: {e}")))?;
    if message.id() != query.id() {
        return Err(EcError::Runtime(format!(
            "dns response id mismatch from {server}: expected {}, got {}",
            query.id(),
            message.id()
        )));
    }
    if message.message_type() != MessageType::Response {
        return Err(EcError::Runtime(format!(
            "dns response message type is not response from {server}"
        )));
    }
    if message.op_code() != query.op_code() || message.queries() != query.queries() {
        return Err(EcError::Runtime(format!(
            "dns response question mismatch from {server}"
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

fn extract_answer(message: &Message) -> EcResult<DnsAnswer> {
    let question = message
        .queries()
        .first()
        .ok_or_else(|| EcError::Runtime("dns response has no question".to_string()))?;
    let mut records = HashMap::new();
    for record in message.answers() {
        if record.dns_class() == question.query_class()
            && matches!(record.data(), RData::A(_) | RData::CNAME(_))
        {
            records
                .entry(record.name())
                .or_insert_with(Vec::new)
                .push(record);
        }
    }

    let mut name = question.name();
    let mut visited = HashSet::new();
    let mut answer = DnsAnswer {
        aliases: Vec::new(),
        ips: Vec::new(),
        ttl: DNS_CACHE_TTL,
    };
    loop {
        if !visited.insert(name) {
            return Err(EcError::Runtime(format!("dns CNAME loop at {name}")));
        }
        let Some(records) = records.get(name) else {
            break;
        };
        let mut alias = None;
        for record in records {
            answer.ttl = answer.ttl.min(Duration::from_secs(u64::from(record.ttl())));
            match record.data() {
                RData::CNAME(cname) => {
                    if alias.is_some_and(|previous| previous != &cname.0) {
                        return Err(EcError::Runtime(format!(
                            "dns conflicting CNAME records for {name}"
                        )));
                    }
                    alias = Some(&cname.0);
                }
                RData::A(ip) => {
                    if !answer.ips.contains(&ip.0) {
                        answer.ips.push(ip.0);
                    }
                }
                _ => unreachable!(),
            }
        }
        let Some(next) = alias else {
            break;
        };
        if !answer.ips.is_empty() {
            return Err(EcError::Runtime(format!(
                "dns CNAME and A records coexist for {name}"
            )));
        }
        answer.aliases.push(normalize_dns_name(&next.to_string()));
        name = next;
    }
    if answer.aliases.is_empty() && answer.ips.is_empty() {
        answer.ttl = Duration::ZERO;
    }
    Ok(answer)
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

fn next_query_id() -> EcResult<u16> {
    let mut id = [0u8; 2];
    OsRng
        .try_fill_bytes(&mut id)
        .map_err(|e| EcError::Runtime(format!("dns query id generation failed: {e}")))?;
    Ok(u16::from_ne_bytes(id))
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

fn cache_put(key: CacheKey, ip: Ipv4Addr, ttl: Duration) {
    let cache = DNS_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = cache.lock() {
        if ttl.is_zero() {
            guard.remove(&key);
            return;
        }
        prepare_cache_insert(&mut guard, &key, DNS_CACHE_CAPACITY, |entry| {
            entry.expires_at
        });
        guard.insert(
            key,
            CacheEntry {
                ip,
                expires_at: Instant::now() + ttl,
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

fn lookup_cache_put(key: String, aliases: Vec<String>, ips: Vec<Ipv4Addr>, ttl: Duration) {
    let cache = DNS_LOOKUP_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = cache.lock() {
        if ttl.is_zero() {
            guard.remove(&key);
            return;
        }
        prepare_cache_insert(&mut guard, &key, DNS_CACHE_CAPACITY, |entry| {
            entry.expires_at
        });
        guard.insert(
            key,
            LookupCacheEntry {
                aliases,
                ips,
                expires_at: Instant::now() + ttl,
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
    use super::*;
    use hickory_proto::op::OpCode;
    use hickory_proto::rr::{
        DNSClass, Record,
        rdata::{A, CNAME},
    };
    use std::collections::HashMap;
    use std::net::TcpListener;
    use std::thread;
    use std::time::{Duration, Instant};

    #[derive(Clone, Copy)]
    struct TestEntry {
        expires_at: Instant,
    }

    fn answer_message(alias_ttl: u32, address_ttl: u32) -> Message {
        let mut message = build_a_query("alias.example.test").unwrap();
        message.add_answer(Record::from_rdata(
            Name::from_ascii("alias.example.test.").unwrap(),
            alias_ttl,
            RData::CNAME(CNAME(Name::from_ascii("origin.example.test.").unwrap())),
        ));
        message.add_answer(Record::from_rdata(
            Name::from_ascii("origin.example.test.").unwrap(),
            address_ttl,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
        ));
        message
    }

    #[test]
    fn cached_answers_expire_with_the_shortest_address_or_alias_ttl() {
        for (alias_ttl, address_ttl, expected) in [
            (20, 60, 20),
            (60, 20, 20),
            (3600, 3600, 300),
            (0, 60, 0),
            (60, 0, 0),
        ] {
            assert_eq!(
                extract_answer(&answer_message(alias_ttl, address_ttl))
                    .unwrap()
                    .ttl,
                Duration::from_secs(expected)
            );
        }
        let empty = build_a_query("empty.example.test").unwrap();
        assert_eq!(extract_answer(&empty).unwrap().ttl, Duration::ZERO);
        let mut message = answer_message(60, 60);
        message.add_answer(Record::from_rdata(
            Name::from_ascii("origin.example.test.").unwrap(),
            10,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 2))),
        ));
        assert_eq!(
            extract_answer(&message).unwrap().ttl,
            Duration::from_secs(10)
        );
    }

    #[test]
    fn answer_ignores_unrelated_names_classes_and_ttls() {
        let mut message = build_a_query("requested.example.test").unwrap();
        message.add_answer(Record::from_rdata(
            Name::from_ascii("unrelated.example.test.").unwrap(),
            0,
            RData::CNAME(CNAME(Name::from_ascii("other.example.test.").unwrap())),
        ));
        message.add_answer(Record::from_rdata(
            Name::from_ascii("other.example.test.").unwrap(),
            0,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 99))),
        ));
        let mut wrong_class = Record::from_rdata(
            Name::from_ascii("requested.example.test.").unwrap(),
            0,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 98))),
        );
        wrong_class.set_dns_class(DNSClass::CH);
        message.add_answer(wrong_class);
        message.add_answer(Record::from_rdata(
            Name::from_ascii("REQUESTED.example.test.").unwrap(),
            60,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
        ));
        let answer = extract_answer(&message).unwrap();
        assert!(answer.aliases.is_empty());
        assert_eq!(answer.ips, [Ipv4Addr::new(192, 0, 2, 1)]);
        assert_eq!(answer.ttl, Duration::from_secs(60));
    }

    #[test]
    fn answer_follows_cname_chain_instead_of_record_order() {
        let mut message = build_a_query("start.example.test").unwrap();
        message.add_answer(Record::from_rdata(
            Name::from_ascii("last.example.test.").unwrap(),
            90,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
        ));
        for (owner, target, ttl) in [
            ("middle.example.test.", "LAST.example.test.", 30),
            ("START.example.test.", "middle.example.test.", 60),
            ("start.example.test.", "MIDDLE.example.test.", 60),
        ] {
            message.add_answer(Record::from_rdata(
                Name::from_ascii(owner).unwrap(),
                ttl,
                RData::CNAME(CNAME(Name::from_ascii(target).unwrap())),
            ));
        }
        let answer = extract_answer(&message).unwrap();
        assert_eq!(answer.aliases, ["middle.example.test", "last.example.test"]);
        assert_eq!(answer.ips, [Ipv4Addr::new(192, 0, 2, 1)]);
        assert_eq!(answer.ttl, Duration::from_secs(30));
    }

    #[test]
    fn answer_rejects_cname_loops_and_conflicting_data() {
        for (owner, data, expected) in [
            (
                "origin.example.test.",
                RData::CNAME(CNAME(Name::from_ascii("ALIAS.example.test.").unwrap())),
                "loop",
            ),
            (
                "origin.example.test.",
                RData::CNAME(CNAME(Name::from_ascii("origin.example.test.").unwrap())),
                "loop",
            ),
            (
                "alias.example.test.",
                RData::CNAME(CNAME(Name::from_ascii("other.example.test.").unwrap())),
                "conflicting",
            ),
            (
                "alias.example.test.",
                RData::A(A(Ipv4Addr::new(192, 0, 2, 2))),
                "coexist",
            ),
        ] {
            let mut message = answer_message(60, 60);
            message.answers_mut().pop();
            message.add_answer(Record::from_rdata(
                Name::from_ascii(owner).unwrap(),
                60,
                data,
            ));
            let error = extract_answer(&message).unwrap_err().to_string();
            assert!(error.contains(expected), "{error}");
        }
    }

    #[test]
    fn incomplete_cname_answer_preserves_only_the_connected_aliases() {
        let mut message = answer_message(60, 60);
        message.answers_mut().pop();
        message.add_answer(Record::from_rdata(
            Name::from_ascii("unrelated.example.test.").unwrap(),
            1,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 99))),
        ));
        let answer = extract_answer(&message).unwrap();
        assert_eq!(answer.aliases, ["origin.example.test"]);
        assert!(answer.ips.is_empty());
        assert_eq!(answer.ttl, Duration::from_secs(60));
    }

    #[test]
    fn zero_ttl_answers_are_queried_again_in_both_caches() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = socket.local_addr().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let worker = thread::spawn(move || {
            for index in 1..=4 {
                let mut buf = [0; 4096];
                let (n, peer) = socket.recv_from(&mut buf).unwrap();
                let query = Message::from_vec(&buf[..n]).unwrap();
                let mut response = Message::new();
                response
                    .set_id(query.id())
                    .set_message_type(MessageType::Response)
                    .add_queries(query.queries().iter().cloned())
                    .add_answer(Record::from_rdata(
                        query.queries()[0].name().clone(),
                        0,
                        RData::A(A(Ipv4Addr::new(192, 0, 2, index))),
                    ));
                socket.send_to(&response.to_vec().unwrap(), peer).unwrap();
            }
        });
        let host = format!("ttl-zero-{}.example.test", server.port());
        for expected in 1..=2 {
            let result = resolve_first_ipv4(i32::MAX, &host, &[server]).unwrap();
            assert_eq!(result.source, ResolveSource::Server(server));
            assert_eq!(result.ip, Ipv4Addr::new(192, 0, 2, expected));
        }
        for expected in 3..=4 {
            let result = resolve_lookup(&host, &[server]).unwrap();
            assert_eq!(result.source, ResolveSource::Server(server));
            assert_eq!(result.ips, [Ipv4Addr::new(192, 0, 2, expected)]);
        }
        worker.join().unwrap();
    }

    #[test]
    fn lookup_rejects_a_reply_for_a_different_question() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = socket.local_addr().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let worker = thread::spawn(move || {
            let mut buf = [0; 4096];
            let (n, peer) = socket.recv_from(&mut buf).unwrap();
            let request = Message::from_vec(&buf[..n]).unwrap();
            let other = Name::from_ascii("other.example.test.").unwrap();
            let mut response = Message::new();
            response
                .set_id(request.id())
                .set_message_type(MessageType::Response)
                .add_query(Query::query(other.clone(), RecordType::A))
                .add_answer(Record::from_rdata(
                    other,
                    60,
                    RData::A(A(Ipv4Addr::new(192, 0, 2, 99))),
                ));
            socket.send_to(&response.to_vec().unwrap(), peer).unwrap();
        });
        let result = query_server_message("expected.example.test", server);
        worker.join().unwrap();
        assert!(
            result.is_err(),
            "accepted an answer to an unrelated DNS question"
        );
    }

    #[test]
    fn response_validation_matches_the_complete_question() {
        let query = build_a_query("Example.TEST").unwrap();
        let server = "192.0.2.53:53".parse().unwrap();
        let mut response = query.clone();
        response.set_message_type(MessageType::Response);
        response.queries_mut()[0].set_name(Name::from_ascii("example.test.").unwrap());
        assert!(decode_dns_response(&response.to_vec().unwrap(), &query, server).is_ok());
        for case in 0..9 {
            let mut invalid = response.clone();
            match case {
                0 => {
                    invalid.set_id(query.id().wrapping_add(1));
                }
                1 => {
                    invalid.set_message_type(MessageType::Query);
                }
                2 => {
                    invalid.set_op_code(OpCode::Update);
                }
                3 => {
                    invalid.queries_mut()[0].set_name(Name::from_ascii("other.test.").unwrap());
                }
                4 => {
                    invalid.queries_mut()[0].set_query_type(RecordType::AAAA);
                }
                5 => {
                    invalid.queries_mut()[0].set_query_class(DNSClass::CH);
                }
                6 => {
                    invalid.queries_mut().clear();
                }
                7 => {
                    invalid.add_query(query.queries()[0].clone());
                }
                8 => {
                    invalid.set_response_code(ResponseCode::NXDomain);
                }
                _ => unreachable!(),
            }
            assert!(
                decode_dns_response(&invalid.to_vec().unwrap(), &query, server).is_err(),
                "accepted mismatch {case}"
            );
        }
        assert!(decode_dns_response(&[0; 3], &query, server).is_err());
    }

    fn response_for(query: &Message, ip: Ipv4Addr) -> Message {
        let mut response = Message::new();
        response
            .set_id(query.id())
            .set_message_type(MessageType::Response)
            .add_queries(query.queries().iter().cloned())
            .add_answer(Record::from_rdata(
                query.queries()[0].name().clone(),
                60,
                RData::A(A(ip)),
            ));
        response
    }

    #[test]
    fn both_resolvers_skip_invalid_chains_and_try_the_next_server() {
        let servers: Vec<_> = [true, false]
            .into_iter()
            .map(|invalid| {
                let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let server = socket.local_addr().unwrap();
                let worker = thread::spawn(move || {
                    for _ in 0..2 {
                        let mut buf = [0; 4096];
                        let (n, peer) = socket.recv_from(&mut buf).unwrap();
                        let query = Message::from_vec(&buf[..n]).unwrap();
                        let mut response = response_for(&query, Ipv4Addr::new(192, 0, 2, 7));
                        if invalid {
                            response.answers_mut().clear();
                            let name = query.queries()[0].name().clone();
                            response.add_answer(Record::from_rdata(
                                name.clone(),
                                60,
                                RData::CNAME(CNAME(name)),
                            ));
                        }
                        socket.send_to(&response.to_vec().unwrap(), peer).unwrap();
                    }
                });
                (server, worker)
            })
            .collect();
        let addresses: Vec<_> = servers.iter().map(|(addr, _)| *addr).collect();
        let host = format!("chain-failover-{}.example.test", addresses[0].port());
        let direct = resolve_first_ipv4(i32::MIN, &host, &addresses).unwrap();
        assert_eq!(direct.ip, Ipv4Addr::new(192, 0, 2, 7));
        assert_eq!(direct.source, ResolveSource::Server(addresses[1]));
        let lookup = resolve_lookup(&host, &addresses).unwrap();
        assert_eq!(lookup.ips, [Ipv4Addr::new(192, 0, 2, 7)]);
        assert!(lookup.aliases.is_empty());
        assert_eq!(lookup.source, ResolveSource::Server(addresses[1]));
        for (_, worker) in servers {
            worker.join().unwrap();
        }
    }

    #[test]
    fn udp_ignores_valid_replies_from_another_peer() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = socket.local_addr().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let worker = thread::spawn(move || {
            let mut buf = [0; 4096];
            let (n, peer) = socket.recv_from(&mut buf).unwrap();
            let query = Message::from_vec(&buf[..n]).unwrap();
            let other = UdpSocket::bind("127.0.0.1:0").unwrap();
            other
                .send_to(
                    &response_for(&query, Ipv4Addr::new(192, 0, 2, 99))
                        .to_vec()
                        .unwrap(),
                    peer,
                )
                .unwrap();
            socket
                .send_to(
                    &response_for(&query, Ipv4Addr::new(192, 0, 2, 7))
                        .to_vec()
                        .unwrap(),
                    peer,
                )
                .unwrap();
        });
        let (ip, _) = query_server("peer.example.test", server).unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 0, 2, 7));
        worker.join().unwrap();
    }

    #[test]
    fn truncated_udp_retries_over_tcp_and_requires_a_complete_response() {
        for truncated_tcp in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let server = listener.local_addr().unwrap();
            let udp = UdpSocket::bind(server).unwrap();
            udp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let worker = thread::spawn(move || {
                let mut buf = [0; 4096];
                let (n, peer) = udp.recv_from(&mut buf).unwrap();
                let query = Message::from_vec(&buf[..n]).unwrap();
                let mut truncated = query.clone();
                truncated
                    .set_message_type(MessageType::Response)
                    .set_truncated(true);
                udp.send_to(&truncated.to_vec().unwrap(), peer).unwrap();
                let (mut tcp, _) = listener.accept().unwrap();
                tcp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                tcp.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut length = [0; 2];
                tcp.read_exact(&mut length).unwrap();
                let mut request = vec![0; usize::from(u16::from_be_bytes(length))];
                tcp.read_exact(&mut request).unwrap();
                assert_eq!(request, query.to_vec().unwrap());
                let mut response = response_for(&query, Ipv4Addr::new(192, 0, 2, 8));
                response.set_truncated(truncated_tcp);
                let response = response.to_vec().unwrap();
                tcp.write_all(&(response.len() as u16).to_be_bytes())
                    .unwrap();
                tcp.write_all(&response).unwrap();
            });
            let result = query_server("truncated.example.test", server);
            if truncated_tcp {
                assert!(
                    crate::error::concise_error(result.unwrap_err())
                        .contains("tcp response is truncated")
                );
            } else {
                assert_eq!(result.unwrap().0, Ipv4Addr::new(192, 0, 2, 8));
            }
            worker.join().unwrap();
        }
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
