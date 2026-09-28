use crate::error::{EcError, EcResult};
use legacy_tls::{ClientConfig, TlsStream, Version, danger::NoCertificateVerification};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use socket2::{SockRef, TcpKeepalive};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

const VPN_TCP_KEEPALIVE_IDLE: Duration = Duration::from_secs(60);
const VPN_TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(1);
const VPN_TCP_KEEPALIVE_RETRIES: u32 = 3;

pub(crate) fn connect_tcp_with_timeout(
    authority: &str,
    timeout: Duration,
    context: &str,
) -> EcResult<TcpStream> {
    let tcp = TcpStream::connect(authority)
        .map_err(|e| EcError::Runtime(format!("{context} tcp connect failed: {e}")))?;
    tcp.set_read_timeout(Some(timeout))
        .map_err(|e| EcError::Runtime(format!("set read timeout failed: {e}")))?;
    tcp.set_write_timeout(Some(timeout))
        .map_err(|e| EcError::Runtime(format!("set write timeout failed: {e}")))?;
    Ok(tcp)
}

pub(crate) fn connect_vpn_tcp(authority: &str, timeout: Duration) -> EcResult<TcpStream> {
    let tcp = connect_tcp_with_timeout(authority, timeout, "vpn")?;
    apply_vpn_tcp_keepalive(&tcp)?;
    Ok(tcp)
}

fn apply_vpn_tcp_keepalive(tcp: &TcpStream) -> EcResult<()> {
    let keepalive = TcpKeepalive::new()
        .with_time(VPN_TCP_KEEPALIVE_IDLE)
        .with_interval(VPN_TCP_KEEPALIVE_INTERVAL)
        .with_retries(VPN_TCP_KEEPALIVE_RETRIES);
    SockRef::from(tcp)
        .set_tcp_keepalive(&keepalive)
        .map_err(|e| EcError::Runtime(format!("set vpn tcp keepalive failed: {e}")))
}

fn legacy_config() -> ClientConfig {
    // Preserve the gateway's existing unauthenticated legacy TLS policy.
    // This server does not negotiate EMS; the reusable crate requires it by default.
    let mut config = ClientConfig::new(Arc::new(NoCertificateVerification));
    config.min_version = Version::Tls11;
    config.require_extended_master_secret = false;
    config
}

pub(crate) fn vpn_config() -> ClientConfig {
    let mut config = legacy_config();
    config.session_id = vec![0; 32];
    config.session_id[..4].copy_from_slice(b"L3IP");
    config
}

pub(crate) fn connect_http(
    tcp: TcpStream,
    host: &str,
    context: &str,
) -> EcResult<TlsStream<TcpStream>> {
    let mut config = legacy_config();
    if host.parse::<std::net::IpAddr>().is_err() {
        config.server_name = Some(host.to_string());
    }
    handshake(&config, tcp, context)
}

pub(crate) fn handshake(
    config: &ClientConfig,
    tcp: TcpStream,
    context: &str,
) -> EcResult<TlsStream<TcpStream>> {
    config
        .connect(tcp)
        .map_err(|e| EcError::Runtime(format!("{context} tls handshake failed: {e}")))
}

pub(crate) fn http_config() -> EcResult<rustls::ClientConfig> {
    let provider = Arc::new(rustls_rustcrypto::provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| EcError::Runtime(format!("http tls configuration failed: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(HttpVerifier(provider)))
        .with_no_client_auth();
    Ok(config)
}

#[derive(Debug)]
struct HttpVerifier(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for HttpVerifier {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            signature,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            signature,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vpn_profile_is_a_full_legacy_handshake_with_only_the_l3ip_identifier() {
        let config = vpn_config();
        assert_eq!(config.min_version, Version::Tls11);
        assert_eq!(config.max_version, Version::Tls12);
        assert_eq!(config.session_id.len(), 32);
        assert_eq!(&config.session_id[..4], b"L3IP");
        assert_eq!(&config.session_id[4..], &[0; 28]);
        assert!(config.server_name.is_none());
        assert!(!config.require_extended_master_secret);
    }
}
