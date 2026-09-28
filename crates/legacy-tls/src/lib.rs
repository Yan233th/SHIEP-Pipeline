#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod crypto;
mod handshake;
mod record;
mod stream;

pub use stream::TlsStream;

use std::io;
use std::sync::Arc;

/// A TLS connection or configuration failure. Secrets are never included.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The underlying transport failed.
    #[error("{0}")]
    Io(#[from] io::Error),
    /// The peer violated the supported protocol or configuration is invalid.
    #[error("{0}")]
    Protocol(&'static str),
    /// Authentication of a record failed, without distinguishing MAC/padding.
    #[error("bad TLS record MAC")]
    BadRecordMac,
    /// The server sent a TLS alert.
    #[error("TLS alert {0}")]
    Alert(u8),
    /// The certificate verifier rejected the server.
    #[error("server certificate rejected")]
    Certificate,
}

/// Supported protocol versions; TLS 1.0 and SSL are deliberately excluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum Version {
    /// TLS 1.1, for endpoints which cannot negotiate TLS 1.2.
    Tls11 = 0x0302,
    /// TLS 1.2, using its SHA-256 PRF.
    Tls12 = 0x0303,
}

impl Version {
    /// Conventional protocol name for diagnostics.
    pub fn name(self) -> &'static str {
        match self {
            Self::Tls11 => "TLSv1.1",
            Self::Tls12 => "TLSv1.2",
        }
    }
}

/// Cipher suites supported by this client. Neither provides forward secrecy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum CipherSuite {
    /// TLS_RSA_WITH_AES_128_CBC_SHA.
    Aes128Sha = 0x002f,
    /// TLS_RSA_WITH_AES_256_CBC_SHA.
    Aes256Sha = 0x0035,
}

impl CipherSuite {
    /// Conventional cipher name for diagnostics.
    pub fn name(self) -> &'static str {
        match self {
            Self::Aes128Sha => "AES128-SHA",
            Self::Aes256Sha => "AES256-SHA",
        }
    }

    pub(crate) fn key_len(self) -> usize {
        match self {
            Self::Aes128Sha => 16,
            Self::Aes256Sha => 32,
        }
    }
}

/// Authenticates the DER certificate chain before key exchange.
///
/// Implementations must check their trust policy, certificate validity and the
/// expected endpoint identity. The chain is leaf-first and nonempty.
pub trait CertificateVerifier: Send + Sync {
    /// Reject a chain that does not authenticate the expected endpoint.
    fn verify(&self, chain: &[Vec<u8>], server_name: Option<&str>) -> Result<(), Error>;
}

/// Explicit opt-out for deployments which already use unauthenticated TLS.
pub mod danger {
    use super::{CertificateVerifier, Error};

    /// Disables certificate authentication. An active attacker can impersonate
    /// the peer. The library never selects this policy implicitly.
    pub struct NoCertificateVerification;

    impl CertificateVerifier for NoCertificateVerification {
        fn verify(&self, _: &[Vec<u8>], _: Option<&str>) -> Result<(), Error> {
            Ok(())
        }
    }
}

/// Configuration for a fresh full handshake; session resumption is unsupported.
#[derive(Clone)]
pub struct ClientConfig {
    /// Minimum accepted version. Defaults to TLS 1.2.
    pub min_version: Version,
    /// Maximum offered version. Defaults to TLS 1.2.
    pub max_version: Version,
    /// Offered cipher suites, in preference order.
    pub cipher_suites: Vec<CipherSuite>,
    /// Optional SNI name, also supplied to the certificate verifier.
    pub server_name: Option<String>,
    /// Optional opaque ClientHello identifier, at most 32 bytes. This is not
    /// a resumable session; a server attempting resumption is rejected.
    pub session_id: Vec<u8>,
    /// Offer RFC 7366 encrypt-then-MAC. Defaults to true.
    pub encrypt_then_mac: bool,
    /// Require RFC 7627 extended master secret. Defaults to true.
    pub require_extended_master_secret: bool,
    pub(crate) verifier: Arc<dyn CertificateVerifier>,
}

impl ClientConfig {
    /// Creates a TLS 1.2 configuration with an explicit certificate policy.
    pub fn new(verifier: Arc<dyn CertificateVerifier>) -> Self {
        Self {
            min_version: Version::Tls12,
            max_version: Version::Tls12,
            cipher_suites: vec![CipherSuite::Aes128Sha, CipherSuite::Aes256Sha],
            server_name: None,
            session_id: Vec::new(),
            encrypt_then_mac: true,
            require_extended_master_secret: true,
            verifier,
        }
    }

    /// Completes a full handshake over a blocking transport. Configure transport
    /// deadlines before calling; the crate creates no threads or timers.
    pub fn connect<S: io::Read + io::Write>(&self, transport: S) -> Result<TlsStream<S>, Error> {
        handshake::connect(self, transport)
    }
}
