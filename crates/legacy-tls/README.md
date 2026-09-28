# legacy-tls

A focused, pure-Rust blocking TLS client for legacy endpoints that cannot use a
modern TLS stack. It uses RustCrypto primitives and contains no unsafe code or
native cryptographic dependencies.

This is experimental security-sensitive code, not an audited general-purpose
TLS library. Prefer rustls for new applications.

Supported: full TLS 1.1/1.2 handshakes, RSA key transport, AES-128/256-CBC with
HMAC-SHA1, extended master secret, encrypt-then-MAC, SNI, an explicit ClientHello
session identifier, and the server's session identifier. No session resumption,
TLS compression, renegotiation, client certificates, SSL, TLS 1.0, or TLS 1.3.

Certificate policy is explicit: `ClientConfig::new` requires a
`CertificateVerifier`. No authentication policy is chosen implicitly. The
`danger::NoCertificateVerification` policy is available only as a deliberate
opt-out. Keys must be RSA, 2048 to 4096 bits. A verifier using PKI must also
enforce server-authentication and key-encipherment certificate usage.

The crate creates no threads, timers, sockets, or polling loops. Pass a blocking
`Read + Write` transport and configure its timeouts before connecting. Reads
preserve partial TLS records on timeout. Writes apply record-sized backpressure;
a failed write makes the connection unusable to avoid replaying a partial record.
EOF without close_notify is an error. Dropping a stream performs no I/O.

The CBC MAC-then-encrypt receive path computes SHA-1 HMAC with fixed work and
memory accesses for a given public record length, using RustCrypto's compression
function and `subtle` selection. It does not hash a slice selected by decrypted
padding. This design still requires independent timing analysis and security
review; unit tests and interoperability do not establish side-channel safety.

```rust,no_run
use legacy_tls::{CertificateVerifier, ClientConfig, Error};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

struct ApplicationVerifier;
impl CertificateVerifier for ApplicationVerifier {
    fn verify(&self, _chain: &[Vec<u8>], _server: Option<&str>) -> Result<(), Error> {
        // Apply the application's certificate trust and endpoint identity policy.
        Err(Error::Certificate)
    }
}

let socket = TcpStream::connect("legacy.example.com:443")?;
socket.set_read_timeout(Some(Duration::from_secs(5)))?;
socket.set_write_timeout(Some(Duration::from_secs(5)))?;
let mut config = ClientConfig::new(Arc::new(ApplicationVerifier));
config.server_name = Some("legacy.example.com".into());
let mut tls = config.connect(socket)?;
tls.write_all(b"GET / HTTP/1.0\r\n\r\n")?;
let mut response = Vec::new();
tls.read_to_end(&mut response)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

The crate follows the surrounding project's AGPL-3.0 license. It can be packaged
with `cargo package -p legacy-tls`; publishing is a separate action.
