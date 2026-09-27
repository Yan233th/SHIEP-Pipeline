use super::{handshake, into_insecure_ssl, new_insecure_connector, new_vpn_ssl};
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::ssl::{HandshakeError, Ssl, SslContext, SslMethod, SslOptions, SslVersion};
use openssl::x509::{X509, X509NameBuilder};
use std::io::{self, Cursor, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

#[derive(Debug, Default)]
struct ClientHelloCapture(Vec<u8>);

impl Read for ClientHelloCapture {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::ErrorKind::WouldBlock.into())
    }
}

impl Write for ClientHelloCapture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn take_u16(input: &mut Cursor<&[u8]>) -> u16 {
    let mut value = [0; 2];
    input.read_exact(&mut value).unwrap();
    u16::from_be_bytes(value)
}

#[test]
fn vpn_client_hello_preserves_l3ip_marker_cbc_ciphers_and_no_sni() {
    assert!(openssl::version::version().contains("AWS-LC"));
    let ssl = new_vpn_ssl("vpn.example.test").unwrap();
    let HandshakeError::WouldBlock(stream) =
        ssl.connect(ClientHelloCapture::default()).unwrap_err()
    else {
        panic!("expected ClientHello followed by a read wait");
    };
    let record = &stream.get_ref().0;
    assert_eq!(record[0], 22); // TLS handshake record.
    assert_eq!(
        u16::from_be_bytes([record[3], record[4]]) as usize,
        record.len() - 5
    );
    let hello = &record[5..];
    assert_eq!(hello[0], 1); // ClientHello.
    assert_eq!(
        u32::from_be_bytes([0, hello[1], hello[2], hello[3]]) as usize,
        hello.len() - 4
    );
    assert_eq!(hello[38], 32);
    assert_eq!(&hello[39..43], b"L3IP");
    assert_eq!(&hello[43..71], &[0; 28]);

    let mut input = Cursor::new(&hello[71..]);
    let cipher_len = take_u16(&mut input) as usize;
    let mut ciphers = vec![0; cipher_len];
    input.read_exact(&mut ciphers).unwrap();
    assert!(ciphers.chunks_exact(2).any(|cipher| cipher == [0, 0x2f]));
    assert!(ciphers.chunks_exact(2).any(|cipher| cipher == [0, 0x35]));
    let mut compression_len = [0];
    input.read_exact(&mut compression_len).unwrap();
    input.set_position(input.position() + u64::from(compression_len[0]));
    let extension_len = take_u16(&mut input);
    let end = input.position() + u64::from(extension_len);
    assert_eq!(end as usize, input.get_ref().len());
    while input.position() < end {
        let kind = take_u16(&mut input);
        let len = take_u16(&mut input);
        assert_ne!(kind, 0, "VPN ClientHello must not send SNI");
        assert_ne!(kind, 35, "VPN ClientHello must not enable session tickets");
        input.set_position(input.position() + u64::from(len));
    }
    assert_eq!(input.position(), end);
}

fn server_context(version: SslVersion, cipher: &str) -> openssl::ssl::SslContext {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "vpn.example.test").unwrap();
    let name = name.build();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    cert.sign(&key, MessageDigest::sha256()).unwrap();

    let mut builder = SslContext::builder(SslMethod::tls_server()).unwrap();
    builder.set_min_proto_version(Some(version)).unwrap();
    builder.set_max_proto_version(Some(version)).unwrap();
    builder.set_cipher_list(cipher).unwrap();
    builder.set_options(SslOptions::NO_TICKET);
    builder.set_session_id_context(b"test").unwrap();
    builder.set_certificate(&cert.build()).unwrap();
    builder.set_private_key(&key).unwrap();
    builder.build()
}

fn exchange(version: SslVersion, cipher: &str, vpn: bool) {
    let context = server_context(version, cipher);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let server = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut stream = Ssl::new(&context).unwrap().accept(tcp).unwrap();
        assert!(!stream.ssl().session_reused());
        let mut message = [0; 4];
        stream.read_exact(&mut message).unwrap();
        assert_eq!(&message, b"ping");
        stream.write_all(b"pong").unwrap();
    });

    let ssl = if vpn {
        new_vpn_ssl("vpn.example.test").unwrap()
    } else {
        let connector = new_insecure_connector("token").unwrap();
        into_insecure_ssl(&connector, "vpn.example.test", "token").unwrap()
    };
    let mut stream = handshake(ssl, tcp, "test").unwrap();
    assert_eq!(stream.ssl().version2(), Some(version));
    assert_eq!(stream.ssl().current_cipher().unwrap().name(), cipher);
    assert!(!stream.ssl().session_reused());
    assert!(!stream.ssl().session().unwrap().id().is_empty());
    assert!(!stream.ssl().session().unwrap().id().starts_with(b"L3IP"));
    stream.write_all(b"ping").unwrap();
    let mut reply = [0; 4];
    stream.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"pong");
    server.join().unwrap();
}

#[test]
fn vpn_negotiates_legacy_tls_and_exchanges_application_data() {
    for version in [SslVersion::TLS1_1, SslVersion::TLS1_2] {
        for cipher in ["AES128-SHA", "AES256-SHA"] {
            exchange(version, cipher, true);
        }
    }
}

#[test]
fn token_handshake_provides_server_session_id() {
    exchange(SslVersion::TLS1_2, "AES128-SHA", false);
}
