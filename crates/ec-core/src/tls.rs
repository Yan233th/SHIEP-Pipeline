use crate::error::{EcError, EcResult};
use openssl::ssl::{
    ConnectConfiguration, Ssl, SslConnector, SslConnectorBuilder, SslMethod, SslOptions, SslStream,
    SslVerifyMode,
};
use socket2::{SockRef, TcpKeepalive};
use std::net::TcpStream;
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

pub(crate) fn new_insecure_connector_builder(context: &str) -> EcResult<SslConnectorBuilder> {
    let mut builder = SslConnector::builder(SslMethod::tls_client())
        .map_err(|e| EcError::Runtime(format!("{context} tls builder create failed: {e}")))?;
    builder.set_verify(SslVerifyMode::NONE);
    builder.set_options(SslOptions::NO_TICKET);
    Ok(builder)
}

pub(crate) fn new_insecure_connector(context: &str) -> EcResult<SslConnector> {
    Ok(new_insecure_connector_builder(context)?.build())
}

pub(crate) fn new_vpn_ssl(host: &str) -> EcResult<Ssl> {
    let mut builder = new_insecure_connector_builder("vpn")?;
    builder
        .set_cipher_list("RC4-SHA:AES128-SHA:AES256-SHA")
        .map_err(|e| EcError::Runtime(format!("set cipher list failed: {e}")))?;
    let connector = builder.build();
    let mut ssl = into_insecure_ssl_with(&connector, host, "vpn", |config| {
        config.set_use_server_name_indication(false);
    })?;
    crate::protocol_session::apply_l3ip_session_id(&mut ssl, 0x0303)?;
    Ok(ssl)
}

pub(crate) fn into_insecure_ssl(
    connector: &SslConnector,
    host: &str,
    context: &str,
) -> EcResult<Ssl> {
    into_insecure_ssl_with(connector, host, context, |_| {})
}

pub(crate) fn into_insecure_ssl_with<F>(
    connector: &SslConnector,
    host: &str,
    context: &str,
    configure: F,
) -> EcResult<Ssl>
where
    F: FnOnce(&mut ConnectConfiguration),
{
    let mut config = connector
        .configure()
        .map_err(|e| EcError::Runtime(format!("{context} tls configure failed: {e}")))?;
    config.set_verify_hostname(false);
    configure(&mut config);
    config
        .into_ssl(host)
        .map_err(|e| EcError::Runtime(format!("{context} tls prepare failed: {e}")))
}

pub(crate) fn handshake(ssl: Ssl, tcp: TcpStream, context: &str) -> EcResult<SslStream<TcpStream>> {
    ssl.connect(tcp)
        .map_err(|e| EcError::Runtime(format!("{context} tls handshake failed: {e}")))
}

#[cfg(test)]
#[path = "tls_tests.rs"]
mod tests;
