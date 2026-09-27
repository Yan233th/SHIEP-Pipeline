use crate::endpoint::parse_server;
use crate::error::{EcError, EcResult};
use quick_xml::Reader;
use quick_xml::events::attributes::Attribute;
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::QName;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

const ROUTE_TABLE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Debug, Clone)]
pub struct RouteTable {
    pub rules: Vec<RouteRule>,
    pub dns_servers: Vec<String>,
    pub dns_records: Vec<DnsRecord>,
}

#[derive(Debug, Clone)]
pub struct RouteRule {
    pub rc_id: i32,
    pub proto: i32,
    pub svc: String,
    pub name: String,
    pub host: String,
    pub port: PortRange,
}

#[derive(Debug, Clone, Copy)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub rc_id: i32,
    pub host: String,
    pub ip: String,
}

pub fn fetch_route_table(server: &str, twf_id: &str) -> EcResult<RouteTable> {
    let (authority, host) = parse_server(server)?;
    let mut stream = connect_tls(&authority, &host)?;
    let request = format!(
        "GET /por/rclist.csp HTTP/1.1\r\nHost: {authority}\r\nCookie: TWFID={twf_id}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| EcError::Runtime(format!("rclist request write failed: {e}")))?;

    let mut buf = [0u8; 4096];
    let mut raw = Vec::new();
    let deadline = Instant::now() + ROUTE_TABLE_RESPONSE_TIMEOUT;
    while Instant::now() < deadline {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
            Err(e) if is_timeout_or_wouldblock(&e) => break,
            Err(e) => {
                return Err(EcError::Runtime(format!(
                    "rclist response read failed: {e}"
                )));
            }
        }
    }
    if raw.is_empty() {
        return Err(EcError::Runtime(
            "rclist response is empty or timed out".to_string(),
        ));
    }

    let text = std::str::from_utf8(&raw)
        .map_err(|e| EcError::Runtime(format!("rclist response is not valid UTF-8: {e}")))?;
    let xml_payload = extract_xml_payload(text)?;
    parse_route_table_xml(xml_payload)
}

fn connect_tls(authority: &str, host: &str) -> EcResult<openssl::ssl::SslStream<TcpStream>> {
    let tcp = crate::tls::connect_tcp_with_timeout(authority, Duration::from_secs(5), "rclist")?;
    let connector = crate::tls::new_insecure_connector("rclist")?;
    let ssl = crate::tls::into_insecure_ssl(&connector, host, "rclist")?;
    crate::tls::handshake(ssl, tcp, "rclist")
}

fn parse_route_table_xml(xml: &str) -> EcResult<RouteTable> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    let mut rules = Vec::<RouteRule>::new();
    let mut dns_servers = Vec::<String>::new();
    let mut dns_records = Vec::<DnsRecord>::new();
    let mut depth = 0usize;
    let mut resource_seen = false;

    loop {
        let event = reader
            .read_event_into(&mut buf)
            .map_err(|e| EcError::Runtime(format!("rclist xml parse failed: {e}")))?;
        match &event {
            Event::Start(e) | Event::Empty(e) => {
                if depth == 0 {
                    if resource_seen || e.name() != QName(b"Resource") {
                        return Err(EcError::Runtime(
                            "rclist XML must contain one Resource root".to_string(),
                        ));
                    }
                    resource_seen = true;
                }
                match e.name() {
                    QName(b"Rc") => parse_rc(e, &reader, &mut rules)?,
                    QName(b"Dns") => parse_dns(e, &reader, &mut dns_servers, &mut dns_records)?,
                    _ => {}
                }
                if matches!(event, Event::Start(_)) {
                    depth += 1;
                }
            }
            Event::End(_) => depth -= 1,
            Event::Text(_) | Event::CData(_) | Event::GeneralRef(_) if depth == 0 => {
                return Err(EcError::Runtime(
                    "rclist XML contains data outside Resource".to_string(),
                ));
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    if !resource_seen || depth != 0 {
        return Err(EcError::Runtime(
            "rclist XML is incomplete: Resource is missing or unclosed".to_string(),
        ));
    }

    Ok(RouteTable {
        rules,
        dns_servers,
        dns_records,
    })
}

fn parse_rc(
    e: &BytesStart<'_>,
    reader: &Reader<&[u8]>,
    rules: &mut Vec<RouteRule>,
) -> EcResult<()> {
    let mut id_raw: Option<String> = None;
    let mut proto_raw: Option<String> = None;
    let mut svc: Option<String> = None;
    let mut host_raw: Option<String> = None;
    let mut port_raw: Option<String> = None;
    let mut name: Option<String> = None;

    for attr in e.attributes().with_checks(false) {
        let attr = attr.map_err(|e| EcError::Runtime(format!("xml attr parse failed: {e}")))?;
        let value = decode_attr_value(&attr, reader)?;
        match attr.key.as_ref() {
            b"id" => id_raw = Some(value),
            b"proto" => proto_raw = Some(value),
            b"svc" => svc = Some(value),
            b"host" => host_raw = Some(value),
            b"port" => port_raw = Some(value),
            b"name" => name = Some(value),
            _ => {}
        }
    }

    let Some(id_raw) = id_raw else {
        return Ok(());
    };
    let Some(host_raw) = host_raw else {
        return Ok(());
    };
    let Some(port_raw) = port_raw else {
        return Ok(());
    };
    let rc_id = id_raw
        .parse::<i32>()
        .map_err(|e| EcError::Runtime(format!("invalid rc id '{id_raw}': {e}")))?;
    let proto = match proto_raw.as_deref().unwrap_or("0").parse::<i32>() {
        Ok(proto) => proto,
        Err(_) => return Ok(()),
    };
    let svc = svc.unwrap_or_default();
    let name = name.unwrap_or_default();
    let hosts = host_raw.split(';');
    let ports = port_raw.split(';');
    if hosts.clone().count() != ports.clone().count() {
        return Ok(());
    }

    // Pair by source position before rejecting malformed entries.
    for (host, port) in hosts.zip(ports) {
        let host = normalize_host_token(host);
        if host.is_empty() {
            continue;
        }
        let Some(port) = parse_port_range(port) else {
            continue;
        };
        rules.push(RouteRule {
            rc_id,
            proto,
            svc: svc.clone(),
            name: name.clone(),
            host,
            port,
        });
    }
    Ok(())
}

fn parse_dns(
    e: &BytesStart<'_>,
    reader: &Reader<&[u8]>,
    dns_servers: &mut Vec<String>,
    dns_records: &mut Vec<DnsRecord>,
) -> EcResult<()> {
    let mut servers: Option<String> = None;
    let mut data: Option<String> = None;
    for attr in e.attributes().with_checks(false) {
        let attr = attr.map_err(|e| EcError::Runtime(format!("xml attr parse failed: {e}")))?;
        let value = decode_attr_value(&attr, reader)?;
        match attr.key.as_ref() {
            b"dnsserver" => servers = Some(value),
            b"data" => data = Some(value),
            _ => {}
        }
    }

    if let Some(servers) = servers {
        push_dns_servers(dns_servers, &servers);
    }
    if let Some(data) = data {
        for token in data.split(';') {
            let item = token.trim();
            if item.is_empty() {
                continue;
            }
            if let Some(record) = parse_dns_record_item(item) {
                dns_records.push(record);
            }
        }
    }
    Ok(())
}

fn is_timeout_or_wouldblock(err: &std::io::Error) -> bool {
    matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

fn extract_xml_payload(response_text: &str) -> EcResult<&str> {
    let (headers, body) = response_text
        .split_once("\r\n\r\n")
        .ok_or_else(|| EcError::Runtime("rclist response headers are incomplete".to_string()))?;
    let mut lines = headers.lines();
    let status = lines.next().unwrap_or_default();
    if status.split_whitespace().nth(1) != Some("200") {
        return Err(EcError::Runtime(format!("rclist request failed: {status}")));
    }
    for line in lines {
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            let expected = value.trim().parse::<usize>().map_err(|_| {
                EcError::Runtime("rclist response has invalid Content-Length".to_string())
            })?;
            if body.len() != expected {
                return Err(EcError::Runtime(format!(
                    "rclist response length mismatch: expected {expected} bytes, got {}",
                    body.len()
                )));
            }
        }
    }
    let xml_start = body
        .find("<?xml")
        .or_else(|| body.find("<Resource"))
        .ok_or_else(|| {
            EcError::Runtime("rclist response does not contain XML payload".to_string())
        })?;
    Ok(&body[xml_start..])
}

fn push_dns_servers(dns_servers: &mut Vec<String>, servers: &str) {
    for token in servers.split(';') {
        let s = token.trim();
        if !s.is_empty() {
            dns_servers.push(s.to_string());
        }
    }
}

fn parse_dns_record_item(item: &str) -> Option<DnsRecord> {
    let (id_raw, rest) = item.split_once(':')?;
    let (host_raw, ip_raw) = rest.rsplit_once(':')?;
    let rc_id = id_raw.parse::<i32>().ok()?;
    let host = normalize_host_token(host_raw);
    let ip = ip_raw.trim().to_string();
    if host.is_empty() || ip.is_empty() {
        return None;
    }
    Some(DnsRecord { rc_id, host, ip })
}

fn decode_attr_value(attr: &Attribute<'_>, reader: &Reader<&[u8]>) -> EcResult<String> {
    attr.decode_and_unescape_value(reader.decoder())
        .map(|v| v.into_owned())
        .map_err(|e| EcError::Runtime(format!("xml attr decode failed: {e}")))
}

fn normalize_host_token(raw: &str) -> String {
    let mut token = raw.trim();
    token = token
        .strip_prefix("http://")
        .or_else(|| token.strip_prefix("https://"))
        .unwrap_or(token);
    token.split('/').next().unwrap_or("").trim().to_string()
}

fn parse_port_range(raw: &str) -> Option<PortRange> {
    let raw = raw.trim();
    if let Some((start, end)) = raw.split_once('~') {
        Some(PortRange {
            start: start.trim().parse().ok()?,
            end: end.trim().parse().ok()?,
        })
    } else {
        let port = raw.parse().ok()?;
        Some(PortRange {
            start: port,
            end: port,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        extract_xml_payload, normalize_host_token, parse_dns_record_item, parse_port_range,
        parse_route_table_xml,
    };

    #[test]
    fn host_tokens_normalize_scheme_and_path() {
        assert_eq!(normalize_host_token("http://a.example/x"), "a.example");
        assert_eq!(normalize_host_token("https://b.example"), "b.example");
        assert_eq!(normalize_host_token("y.example"), "y.example");
    }

    #[test]
    fn port_tokens_parse_ranges() {
        assert_eq!(parse_port_range("80~80").unwrap().start, 80);
        assert_eq!(parse_port_range("443~445").unwrap().end, 445);
        let dns = parse_port_range("53").unwrap();
        assert_eq!((dns.start, dns.end), (53, 53));
        for invalid in ["", "bad", "65536", "80~", "~443", "80~bad", "80~443~445"] {
            assert!(parse_port_range(invalid).is_none());
        }
    }

    #[test]
    fn parse_xml_extracts_rules_and_dns() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<Resource>
  <Rcs>
    <Rc id="205" proto="1" svc="Other" name="IDS" host="ids.shiep.edu.cn;10.1.2.3" port="443~443;80~80" />
  </Rcs>
  <Dns dnsserver="210.35.88.5;114.114.114.114" data="205:ids.shiep.edu.cn:10.166.35.11;" />
</Resource>"#;
        let table = parse_route_table_xml(xml).unwrap();
        assert_eq!(table.rules.len(), 2);
        assert_eq!(table.rules[0].proto, 1);
        assert_eq!(table.rules[1].proto, 1);
        assert_eq!(table.rules[0].svc, "Other");
        assert_eq!(table.rules[1].svc, "Other");
        assert_eq!(table.dns_servers.len(), 2);
        assert_eq!(table.dns_records.len(), 1);
        assert_eq!(table.dns_records[0].host, "ids.shiep.edu.cn");
        assert_eq!(table.dns_records[0].ip, "10.166.35.11");
    }

    #[test]
    fn parse_xml_defaults_missing_svc_to_empty() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<Resource>
  <Rcs>
    <Rc id="-98" proto="1" name="__DNS_HIDE_RC1" host="210.35.88.5" port="53~53" />
  </Rcs>
</Resource>"#;
        let table = parse_route_table_xml(xml).unwrap();
        assert_eq!(table.rules.len(), 1);
        assert_eq!(table.rules[0].svc, "");
    }

    #[test]
    fn parse_xml_skips_rc_with_mismatched_host_port_lists() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<Resource>
  <Rcs>
    <Rc id="205" proto="0" name="bad" host="a.example;b.example" port="443~443" />
    <Rc id="206" proto="0" name="good" host="c.example" port="80~80" />
  </Rcs>
</Resource>"#;
        let table = parse_route_table_xml(xml).unwrap();
        assert_eq!(table.rules.len(), 1);
        assert_eq!(table.rules[0].rc_id, 206);
        assert_eq!(table.rules[0].host, "c.example");
        assert_eq!(table.rules[0].port.start, 80);
    }

    #[test]
    fn invalid_list_entries_never_shift_host_port_pairs() {
        for (hosts, ports, expected) in [
            ("a.test;;c.test", "80;443;bad", vec![("a.test", 80)]),
            (";b.test;c.test", "80;bad;443", vec![("c.test", 443)]),
            (
                "a.test;b.test;c.test",
                "80;bad;443",
                vec![("a.test", 80), ("c.test", 443)],
            ),
            (
                "a.test;;c.test",
                "80;443;8080",
                vec![("a.test", 80), ("c.test", 8080)],
            ),
            ("a.test;b.test", "80;bad;443", vec![]),
        ] {
            let xml =
                format!("<Resource><Rc id=\"1\" host=\"{hosts}\" port=\"{ports}\"/></Resource>");
            let table = parse_route_table_xml(&xml).unwrap();
            let pairs: Vec<_> = table
                .rules
                .iter()
                .map(|rule| (rule.host.as_str(), rule.port.start))
                .collect();
            assert_eq!(pairs, expected, "host={hosts:?}, port={ports:?}");
        }
    }

    #[test]
    fn malformed_protocol_is_not_treated_as_tcp() {
        let table = parse_route_table_xml(
            r#"<Resource>
              <Rc id="1" host="bad.test" port="443" proto="udp"/>
              <Rc id="2" host="empty.test" port="443" proto=""/>
              <Rc id="3" host="default.test" port="443"/>
              <Rc id="4" host="tcp.test" port="443" proto="0"/>
              <Rc id="5" host="any.test" port="443" proto="-1"/>
              <Rc id="6" host="udp.test" port="53" proto="1"/>
            </Resource>"#,
        )
        .unwrap();
        let protocols: Vec<_> = table
            .rules
            .iter()
            .map(|rule| (rule.rc_id, rule.proto))
            .collect();
        assert_eq!(protocols, [(3, 0), (4, 0), (5, -1), (6, 1)]);
    }

    #[test]
    fn parse_dns_record_item_parses_valid_entry() {
        let rec = parse_dns_record_item("205:https://ids.shiep.edu.cn/path:10.166.35.11").unwrap();
        assert_eq!(rec.rc_id, 205);
        assert_eq!(rec.host, "ids.shiep.edu.cn");
        assert_eq!(rec.ip, "10.166.35.11");
    }

    #[test]
    fn parse_dns_record_item_rejects_invalid_entry() {
        assert!(parse_dns_record_item("bad").is_none());
        assert!(parse_dns_record_item("not-int:host:10.0.0.1").is_none());
        assert!(parse_dns_record_item("1::10.0.0.1").is_none());
    }

    #[test]
    fn extract_xml_payload_finds_resource_start() {
        let raw = "HTTP/1.1 200 OK\r\n\r\n<Resource><Rcs/></Resource>";
        let xml = extract_xml_payload(raw).unwrap();
        assert!(xml.starts_with("<Resource>"));
    }

    #[test]
    fn extract_xml_payload_rejects_non_xml_text() {
        let err = extract_xml_payload("HTTP/1.1 200 OK\r\n\r\nhello").unwrap_err();
        assert!(err.to_string().contains("does not contain XML payload"));
    }

    #[test]
    fn xml_rejects_every_truncated_prefix() {
        let xml = r#"<?xml version="1.0"?><Resource><Rcs><Rc id="1" host="example.test" port="80"/></Rcs><Dns dnsserver="192.0.2.53"/></Resource>"#;
        for (end, _) in xml.char_indices() {
            assert!(
                parse_route_table_xml(&xml[..end]).is_err(),
                "accepted prefix ending at {end}"
            );
        }
        let table = parse_route_table_xml(xml).unwrap();
        assert_eq!(table.rules.len(), 1);
        assert_eq!(table.dns_servers, ["192.0.2.53"]);
    }

    #[test]
    fn xml_requires_one_complete_resource_document() {
        for invalid in [
            "<Resource><Rcs></Resource>",
            "<Rcs/>",
            "<Resource/><Resource/>",
            "<Resource/>trailing",
            "<Resource/><![CDATA[trailing]]>",
            "</Resource>",
        ] {
            assert!(
                parse_route_table_xml(invalid).is_err(),
                "accepted {invalid}"
            );
        }
        assert!(parse_route_table_xml(" \n<Resource/>\n ").is_ok());
        assert!(parse_route_table_xml("<!-- routes --><Resource></Resource><!-- end -->").is_ok());
    }

    #[test]
    fn response_checks_http_status_and_declared_body_length() {
        let xml = "<Resource/>";
        let complete = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{xml}",
            xml.len()
        );
        assert_eq!(extract_xml_payload(&complete).unwrap(), xml);
        for invalid in [
            "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n<Resource/>",
            "HTTP/1.1 200 OK\r\nContent-Length: nope\r\n\r\n<Resource/>",
            "HTTP/1.1 403 Forbidden\r\n\r\n<Resource/>",
            "HTTP/1.1 200 OK\r\n",
        ] {
            assert!(extract_xml_payload(invalid).is_err());
        }
    }
}
