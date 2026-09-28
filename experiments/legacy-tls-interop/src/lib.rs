//! Independent native TLS reference, excluded from the application workspace.
#![cfg(test)]

use legacy_tls::{
    CertificateVerifier, ClientConfig, Error, Version, danger::NoCertificateVerification,
};
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::ssl::{NameType, Ssl, SslContext, SslMethod, SslOptions, SslVersion};
use openssl::x509::{X509, X509NameBuilder};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn context(version: SslVersion, cipher: &str) -> SslContext {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "legacy.example.test")
        .unwrap();
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
    #[cfg(not(feature = "aws-lc"))]
    builder.set_security_level(0);
    builder.set_min_proto_version(Some(version)).unwrap();
    builder.set_max_proto_version(Some(version)).unwrap();
    builder.set_cipher_list(cipher).unwrap();
    builder.set_options(SslOptions::NO_TICKET);
    builder
        .set_session_id_context(b"independent-reference")
        .unwrap();
    builder.set_certificate(&cert.build()).unwrap();
    builder.set_private_key(&key).unwrap();
    builder.build()
}

fn sockets() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    for io in [&client, &server] {
        io.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        io.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
    }
    (client, server)
}

struct Fragmented(TcpStream);
impl Read for Fragmented {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = out.len().min(131);
        self.0.read(&mut out[..n])
    }
}
impl Write for Fragmented {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.0.write(&input[..input.len().min(197)])
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

#[test]
fn reference_server_accepts_both_versions_ciphers_and_l3ip_full_handshakes() {
    for (wire, version) in [
        (SslVersion::TLS1_1, Version::Tls11),
        (SslVersion::TLS1_2, Version::Tls12),
    ] {
        for cipher in ["AES128-SHA", "AES256-SHA"] {
            for marker in [false, true] {
                let context = context(wire, cipher);
                let (client, server) = sockets();
                let content: Vec<u8> = (0..65_573).map(|i| i as u8).collect();
                let expected = content.clone();
                let server = thread::spawn(move || {
                    let mut stream = Ssl::new(&context).unwrap().accept(server).unwrap();
                    assert!(!stream.ssl().session_reused());
                    assert_eq!(
                        stream.ssl().servername(NameType::HOST_NAME),
                        Some("legacy.example.test")
                    );
                    let mut received = vec![0; expected.len()];
                    stream.read_exact(&mut received).unwrap();
                    assert_eq!(received, expected);
                    stream.write_all(&received).unwrap();
                    stream.shutdown().unwrap();
                });
                let mut config = ClientConfig::new(Arc::new(NoCertificateVerification));
                config.min_version = version;
                config.max_version = version;
                config.server_name = Some("legacy.example.test".into());
                if marker {
                    config.session_id = [b"L3IP".as_slice(), &[0; 28]].concat();
                }
                let mut stream = config.connect(Fragmented(client)).unwrap();
                assert_eq!(stream.version(), version);
                assert_eq!(stream.cipher_suite().name(), cipher);
                assert!(stream.extended_master_secret());
                assert_eq!(stream.encrypt_then_mac(), !cfg!(feature = "aws-lc"));
                assert!(!stream.session_id().is_empty());
                assert!(!stream.session_id().starts_with(b"L3IP"));
                stream.write_all(&content).unwrap();
                let mut echoed = Vec::new();
                stream.read_to_end(&mut echoed).unwrap();
                assert_eq!(echoed, content);
                server.join().unwrap();
            }
        }
    }
}

struct Reject;
impl CertificateVerifier for Reject {
    fn verify(&self, _: &[Vec<u8>], _: Option<&str>) -> Result<(), Error> {
        Err(Error::Certificate)
    }
}

#[test]
fn rejected_certificate_never_completes_handshake() {
    let context = context(SslVersion::TLS1_2, "AES128-SHA");
    let (client, server) = sockets();
    let server =
        thread::spawn(move || assert!(Ssl::new(&context).unwrap().accept(server).is_err()));
    assert!(matches!(
        ClientConfig::new(Arc::new(Reject)).connect(client),
        Err(Error::Certificate)
    ));
    server.join().unwrap();
}

#[test]
fn raw_eof_is_not_reported_as_clean_tls_shutdown() {
    let context = context(SslVersion::TLS1_2, "AES128-SHA");
    let (client, server) = sockets();
    let server = thread::spawn(move || {
        let _stream = Ssl::new(&context).unwrap().accept(server).unwrap();
    });
    let mut stream = ClientConfig::new(Arc::new(NoCertificateVerification))
        .connect(client)
        .unwrap();
    let error = stream.read(&mut [0; 1]).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    server.join().unwrap();
}

// Alter the native server's first encrypted handshake record, after its CCS.
// The client must authenticate Finished before returning an established stream.
#[derive(Debug)]
struct TamperedFinished {
    io: TcpStream,
    pending: Vec<u8>,
    encrypted: bool,
    altered: bool,
}

impl Read for TamperedFinished {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.io.read(out)
    }
}

impl Write for TamperedFinished {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(bytes);
        while self.pending.len() >= 5 {
            let len = usize::from(u16::from_be_bytes([self.pending[3], self.pending[4]])) + 5;
            if self.pending.len() < len {
                break;
            }
            let mut record: Vec<u8> = self.pending.drain(..len).collect();
            if record[0] == 22 && self.encrypted && !self.altered {
                record[len - 1] ^= 1;
                self.altered = true;
            }
            if record[0] == 20 {
                self.encrypted = true;
            }
            self.io.write_all(&record)?;
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.io.flush()
    }
}

#[test]
fn tampered_server_finished_never_establishes_a_connection() {
    let context = context(SslVersion::TLS1_2, "AES128-SHA");
    let (client, server) = sockets();
    let server = thread::spawn(move || {
        let stream = Ssl::new(&context)
            .unwrap()
            .accept(TamperedFinished {
                io: server,
                pending: Vec::new(),
                encrypted: false,
                altered: false,
            })
            .unwrap();
        assert!(stream.get_ref().altered);
    });
    assert!(matches!(
        ClientConfig::new(Arc::new(NoCertificateVerification)).connect(client),
        Err(Error::BadRecordMac)
    ));
    server.join().unwrap();
}
