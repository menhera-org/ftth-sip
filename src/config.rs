use std::net::{IpAddr, SocketAddr};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

const DEFAULT_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct BindConfig {
    pub address: IpAddr,
    pub port: u16,
    /// Optional Linux interface name for SO_BINDTODEVICE.
    pub interface: Option<String>,
}

impl BindConfig {
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.address, self.port)
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    pub bind: BindConfig,
    pub registrar_uri: String,
    pub sip_domain: String,
    /// IP address used when connecting to the upstream trunk. This can differ from
    /// the SIP domain when DNS for the trunk is unavailable inside the NGN.
    pub trunk_addr: IpAddr,
    /// UDP port used when connecting to the upstream trunk.
    pub trunk_port: u16,
    /// Default caller identity to use when downstream does not present an allowed one.
    pub default_identity: String,
    /// Valid calling line identities (user parts) that may be presented towards NGN.
    pub allowed_identities: Vec<String>,
    pub auth: Option<UpstreamAuth>,
    pub transport: TransportProfile,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct UpstreamAuth {
    pub username: String,
    pub password: String,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct DownstreamConfig {
    pub bind: BindConfig,
    pub user_agent: AllowedUserAgent,
    /// Optional default SIP user part to use when routing inbound requests to the LAN PBX.
    pub default_user: Option<String>,
    pub transport: TransportProfile,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct AllowedUserAgent {
    /// Expected username for REGISTER / INVITE handling.
    pub username: String,
    /// Optional digest realm override for LAN clients.
    pub realm: Option<String>,
    /// Shared secret used for digest authentication challenges (None disables auth).
    pub password: Option<String>,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct MediaConfig {
    pub upstream: BindConfig,
    pub downstream: BindConfig,
    pub port_range: PortRange,
    pub inactivity_timeout_secs: u64,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct PortRange {
    pub min: u16,
    pub max: u16,
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        port >= self.min && port <= self.max
    }
}

impl UpstreamConfig {
    pub fn trunk_socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.trunk_addr, self.trunk_port)
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProfile {
    Udp,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct TimerConfig {
    pub registration_refresh_secs: u64,
    pub invite_timeout_secs: u64,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub upstream: UpstreamConfig,
    pub downstream: DownstreamConfig,
    pub media: MediaConfig,
    pub timers: TimerConfig,
    /// Optional User-Agent header override applied to all outbound SIP messages.
    pub user_agent: Option<String>,
}

impl ProxyConfig {
    pub fn resolved_user_agent(&self) -> String {
        self.user_agent
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(|value| value.to_string())
            .unwrap_or_else(|| DEFAULT_USER_AGENT.to_string())
    }
}
