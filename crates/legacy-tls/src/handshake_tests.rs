use super::*;
use crate::danger::NoCertificateVerification;
use std::sync::Arc;

fn config() -> ClientConfig {
    ClientConfig::new(Arc::new(NoCertificateVerification))
}

fn hello(extensions: &[u8]) -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend_from_slice(&[0; 32]);
    body.extend_from_slice(&[0, 0, 0x2f, 0]);
    vector16(&mut body, extensions).unwrap();
    body
}

#[test]
fn hello_negotiation_rejects_downgrades_unoffered_and_duplicate_extensions() {
    let cfg = config();
    let mut extensions = Vec::new();
    extension(&mut extensions, 23, &[]).unwrap();
    assert!(server_hello(&cfg, &hello(&extensions)).is_ok());
    assert!(server_hello(&cfg, &hello(&[])).is_err());
    let mut old = hello(&extensions);
    old[1] = 2;
    assert!(server_hello(&cfg, &old).is_err());
    extension(&mut extensions, 23, &[]).unwrap();
    assert!(server_hello(&cfg, &hello(&extensions)).is_err());
    assert!(server_hello(&cfg, &hello(&[0, 35, 0, 0])).is_err());
    for length in 0..hello(&[]).len() {
        assert!(server_hello(&cfg, &hello(&[])[..length]).is_err());
    }
}

#[test]
fn client_hello_preserves_opaque_id_and_does_not_offer_tickets() {
    let mut cfg = config();
    cfg.min_version = Version::Tls11;
    cfg.session_id = vec![0; 32];
    cfg.session_id[..4].copy_from_slice(b"L3IP");
    let hello = client_hello(&cfg, &[0x31; 32]).unwrap();
    let mut cursor = Cursor(&hello[4..]);
    assert_eq!(cursor.u16().unwrap(), 0x0303);
    cursor.take(32).unwrap();
    assert_eq!(cursor.u8().unwrap(), 32);
    assert_eq!(cursor.take(32).unwrap(), &cfg.session_id);
    assert_eq!(cursor.vector16().unwrap(), [0, 0x2f, 0, 0x35]);
    assert_eq!(cursor.take(2).unwrap(), [1, 0]);
    let mut extensions = Cursor(cursor.vector16().unwrap());
    cursor.end().unwrap();
    while !extensions.0.is_empty() {
        let kind = extensions.u16().unwrap();
        assert_ne!(kind, 0);
        assert_ne!(kind, 35);
        extensions.vector16().unwrap();
    }
    cfg.session_id.push(0);
    assert!(cfg.connect(std::io::Cursor::new(Vec::new())).is_err());
}

#[test]
fn malformed_certificate_vectors_fail_without_panics() {
    for input in [
        &b""[..],
        &[0, 0, 0],
        &[0, 0, 3, 0, 0, 0],
        &[0, 0, 4, 0, 0, 2, 9],
    ] {
        assert!(certificates(input).is_err());
    }
}

#[test]
fn sni_rejects_ip_literals_controls_and_invalid_dns_labels() {
    for name in [
        "",
        "127.0.0.1",
        "::1",
        "a..test",
        "-a.test",
        "a-.test",
        "a\n.test",
        "a\0.test",
    ] {
        let mut config = config();
        config.server_name = Some(name.to_string());
        assert!(validate(&config).is_err(), "{name:?}");
    }
    let mut config = config();
    config.server_name = Some(format!("{}.test", "a".repeat(64)));
    assert!(validate(&config).is_err());
    config.server_name = Some("xn--example-9d0b.test".to_string());
    assert!(validate(&config).is_ok());
}

#[test]
fn handshake_record_fragments_reassemble_at_every_boundary() {
    let mut extensions = Vec::new();
    extension(&mut extensions, 23, &[]).unwrap();
    let expected = message(2, &hello(&extensions)).unwrap();
    for boundary in 1..expected.len() {
        let mut wire = Vec::new();
        for fragment in [&expected[..boundary], &expected[boundary..]] {
            record::write(&mut wire, 22, Version::Tls12, fragment).unwrap();
        }
        let mut reader = record::Reader::default();
        let mut messages = Messages::default();
        assert_eq!(
            messages
                .next(&mut reader, &mut wire.as_slice(), None, None)
                .unwrap(),
            expected
        );
        assert!(messages.pending.is_empty());
    }
}

#[test]
fn empty_oversized_and_out_of_order_handshake_records_are_rejected() {
    for (kind, body) in [
        (22, &b""[..]),
        (22, &[11, 255, 255, 255]),
        (20, &[1]),
        (23, b"data"),
    ] {
        let mut wire = Vec::new();
        record::write(&mut wire, kind, Version::Tls12, body).unwrap();
        assert!(
            Messages::default()
                .next(
                    &mut record::Reader::default(),
                    &mut wire.as_slice(),
                    None,
                    None
                )
                .is_err()
        );
    }
}

struct Reply(std::io::Cursor<Vec<u8>>);
impl Read for Reply {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(bytes)
    }
}
impl Write for Reply {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn mutated_and_truncated_server_flights_never_panic_or_establish_a_stream() {
    let mut extensions = Vec::new();
    extension(&mut extensions, 23, &[]).unwrap();
    let mut wire = Vec::new();
    record::write(
        &mut wire,
        22,
        Version::Tls12,
        &message(2, &hello(&extensions)).unwrap(),
    )
    .unwrap();
    record::write(
        &mut wire,
        22,
        Version::Tls12,
        &message(11, &[0, 0, 5, 0, 0, 2, 0x30, 0]).unwrap(),
    )
    .unwrap();
    record::write(&mut wire, 22, Version::Tls12, &message(14, &[]).unwrap()).unwrap();
    let cfg = config();
    for end in 0..=wire.len() {
        assert!(
            cfg.connect(Reply(std::io::Cursor::new(wire[..end].to_vec())))
                .is_err()
        );
    }
    for offset in 0..wire.len() {
        for value in 0..=255 {
            let mut mutated = wire.clone();
            mutated[offset] = value;
            assert!(cfg.connect(Reply(std::io::Cursor::new(mutated))).is_err());
        }
    }
    // Reproducible input mutations; this is not protocol randomness.
    let mut state = 0x78b4_ef2c_3816_9031u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..4096 {
        let mut bytes = vec![0; (next() as usize % 512) + 1];
        for byte in &mut bytes {
            *byte = next() as u8;
        }
        if bytes.len() >= 5 {
            bytes[..3].copy_from_slice(&[22, 3, 3]);
            let len = (bytes.len() - 5) as u16;
            bytes[3..5].copy_from_slice(&len.to_be_bytes());
        }
        assert!(cfg.connect(Reply(std::io::Cursor::new(bytes))).is_err());
    }
}
