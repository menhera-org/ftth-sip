//! SIP proxy toolkit for NTT East/West Hikari Denwa NGN trunks.
//! This crate exposes a high-level builder that wires ftth-rsipstack transports,
//! media relay helpers, and configuration primitives tailored for a single
//! downstream PBX registration.

mod net;

pub mod config;
pub mod error;
pub mod media;
pub mod sip;

pub use config::ProxyConfig;
pub use error::{Error, Result};
pub use sip::{
    FtthSipProxy, FtthSipProxyBuilder, ProxyHandle, ProxyRuntime, RsipstackBackend, SipContext,
};

#[cfg(test)]
mod tests {
    use super::config::{
        AllowedUserAgent, BindConfig, DownstreamConfig, MediaConfig, PortRange, ProxyConfig,
        TimerConfig, TransportProfile, UpstreamAuth, UpstreamConfig,
    };
    use super::sip::FtthSipProxyBuilder;

    #[tokio::test]
    async fn build_proxy_runtime() {
        let config = ProxyConfig {
            upstream: UpstreamConfig {
                bind: BindConfig {
                    address: "192.0.2.1".parse().unwrap(),
                    port: 5060,
                    interface: Some("ngn0".into()),
                },
                registrar_uri: "sip:example.ngn.jp".into(),
                sip_domain: "example.ngn.jp".into(),
                trunk_addr: "192.0.2.100".parse().unwrap(),
                trunk_port: 5060,
                default_identity: "0298284147".into(),
                allowed_identities: vec!["0298284147".into()],
                auth: Some(UpstreamAuth {
                    username: "upstream".into(),
                    password: "secret".into(),
                }),
                transport: TransportProfile::Udp,
            },
            downstream: DownstreamConfig {
                bind: BindConfig {
                    address: "192.168.1.1".parse().unwrap(),
                    port: 15060,
                    interface: Some("lan0".into()),
                },
                user_agent: AllowedUserAgent {
                    username: "asterisk".into(),
                    realm: Some("asterisk.local".into()),
                    password: "secret".into(),
                },
                transport: TransportProfile::Udp,
            },
            media: MediaConfig {
                upstream: BindConfig {
                    address: "192.0.2.1".parse().unwrap(),
                    port: 0,
                    interface: Some("ngn0".into()),
                },
                downstream: BindConfig {
                    address: "192.168.1.1".parse().unwrap(),
                    port: 0,
                    interface: Some("lan0".into()),
                },
                port_range: PortRange {
                    min: 40000,
                    max: 40100,
                },
                inactivity_timeout_secs: 120,
            },
            timers: TimerConfig {
                registration_refresh_secs: 60,
                invite_timeout_secs: 32,
            },
        };

        let proxy = FtthSipProxyBuilder::new(config)
            .build()
            .await
            .expect("build runtime");

        // We only test that the runtime can be started and shut down cleanly.
        let handle = proxy.start().await.expect("start proxy");
        handle.shutdown().await.expect("shutdown proxy");
    }
}
