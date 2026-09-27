use crate::config::AppConfig;
use crate::error::EcResult;
use crate::output::{self, Scope};
use std::net::Ipv4Addr;

pub struct EasyConnectApp {
    config: AppConfig,
}

impl EasyConnectApp {
    pub fn new(config: AppConfig) -> Self {
        #[cfg(debug_assertions)]
        output::set_debug_enabled(config.debug_enabled);
        Self { config }
    }

    pub fn run(&self) -> EcResult<()> {
        let fallback_proxy =
            crate::socks_proxy::parse_fallback_proxy(self.config.fallback_proxy.as_deref())?;
        let twf_id = self.login()?;
        self.try_install_route_table(&twf_id)?;
        let token = self.acquire_protocol_token(&twf_id)?;
        let tunnel_ips = self.start_tunnel(&token)?;
        crate::netstack::start_runtime(tunnel_ips.assigned_ip)?;
        crate::socks::serve(&self.config.socks_bind, fallback_proxy)
    }

    fn login(&self) -> EcResult<String> {
        let twf_id = crate::auth::login(&self.config)?;
        output::success(
            Scope::Login,
            format_args!("session id acquired: {}", output::value(twf_id.as_str())),
        );
        Ok(twf_id)
    }

    fn try_install_route_table(&self, twf_id: &str) -> EcResult<()> {
        match crate::route_table::fetch_route_table(&self.config.server, twf_id) {
            Ok(table) => {
                let install = crate::routing::install_route_table(table)?;
                output::info(
                    Scope::App,
                    format_args!(
                        "route table loaded: {} rules, {} dns servers, {} dns records, {} dns scopes",
                        output::value(install.rule_count),
                        output::value(install.dns_server_count),
                        output::value(install.dns_record_count),
                        output::value(install.dns_scope_count)
                    ),
                );
            }
            Err(err) => {
                let reason = crate::error::concise_error(err);
                output::warn(
                    Scope::App,
                    format_args!(
                        "route table unavailable; routing degraded to tunnel: {}",
                        reason
                    ),
                );
                crate::routing::install_tunnel_fallback()?;
            }
        }
        Ok(())
    }

    fn acquire_protocol_token(&self, twf_id: &str) -> EcResult<String> {
        output::info(Scope::Agent, "fetching agent token...");
        let agent_token = crate::token::fetch_agent_token(&self.config.server, twf_id)?;
        output::success(Scope::Agent, "agent token acquired");
        Ok(format!("{agent_token}{twf_id}"))
    }

    fn start_tunnel(&self, token: &str) -> EcResult<crate::protocol::TunnelIps> {
        output::info(Scope::Protocol, "opening command stream...");
        let command = crate::protocol::open_command_stream(&self.config.server, token)?;
        let tunnel_ips = command.ips;
        output::success(
            Scope::Protocol,
            format_args!(
                "assigned IP: {}; heartbeat target: {}",
                output::value(Ipv4Addr::from(tunnel_ips.assigned_ip)),
                output::value(Ipv4Addr::from(tunnel_ips.lan_ip))
            ),
        );
        crate::protocol::start_tunnel_runtime(&self.config.server, token, tunnel_ips)?;
        output::success(Scope::Protocol, "tunnel established");
        Ok(tunnel_ips)
    }
}

#[cfg(test)]
mod tests {
    use super::EasyConnectApp;
    use crate::{AppConfig, EcError};

    #[test]
    fn invalid_fallback_is_rejected_before_login() {
        for fallback in [
            "https://127.0.0.1:8443",
            "socks5h://",
            "socks5h://127.0.0.1:114514",
            "http://proxy.invalid",
            "socks5h://user:secret@proxy.invalid:1080",
            "http://proxy.invalid/path:8080",
        ] {
            let config = AppConfig::new(
                "http://127.0.0.1:0".to_string(),
                "test".to_string(),
                "test".to_string(),
                "127.0.0.1:0".to_string(),
                Some(fallback.to_string()),
            )
            .unwrap();
            let error = EasyConnectApp::new(config).run().unwrap_err();
            assert!(matches!(error, EcError::InvalidConfig(_)), "{error}");
            assert!(error.to_string().contains("fallback is invalid"));
        }
    }
}
