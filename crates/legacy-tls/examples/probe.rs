//! Read-only diagnostic for legacy TLS compatibility; deliberately skips PKI.
use legacy_tls::{ClientConfig, Version, danger::NoCertificateVerification};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let authority = std::env::args().nth(1).ok_or("usage: probe server:port")?;
    let endpoint = authority.to_socket_addrs()?.next().ok_or("no address")?;
    for marker in [false, true] {
        let result = (|| -> Result<(), Box<dyn std::error::Error>> {
            let tcp = TcpStream::connect_timeout(&endpoint, Duration::from_secs(5))?;
            tcp.set_read_timeout(Some(Duration::from_secs(5)))?;
            tcp.set_write_timeout(Some(Duration::from_secs(5)))?;
            let mut config = ClientConfig::new(Arc::new(NoCertificateVerification));
            config.min_version = Version::Tls11;
            config.require_extended_master_secret = false;
            if marker {
                config.session_id = vec![0; 32];
                config.session_id[..4].copy_from_slice(b"L3IP");
            }
            let mut stream = config.connect(tcp)?;
            println!(
                "L3IP={marker}: {} / {}; session-id length {}; EMS {}; EtM {}",
                stream.version().name(),
                stream.cipher_suite().name(),
                stream.session_id().len(),
                stream.extended_master_secret(),
                stream.encrypt_then_mac()
            );
            if !marker {
                stream.write_all(
                    format!("GET / HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                )?;
                let mut status = Vec::new();
                let mut byte = [0];
                while status.len() < 1024 {
                    stream.read_exact(&mut byte)?;
                    if byte[0] == b'\n' {
                        break;
                    }
                    status.push(byte[0]);
                }
                println!("{}", String::from_utf8_lossy(&status).trim());
            }
            Ok(())
        })();
        if let Err(err) = result {
            eprintln!("L3IP={marker}: {err}");
        }
    }
    Ok(())
}
