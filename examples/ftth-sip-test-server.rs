use std::net::{IpAddr, Ipv4Addr};

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use ftth_sip::FtthSipProxyBuilder;
use ftth_sip::config::{
    AllowedUserAgent, BindConfig, DownstreamConfig, MediaConfig, PortRange, ProxyConfig,
    TimerConfig, TransportProfile, UpstreamAuth, UpstreamConfig,
};
use tracing::info;
#[cfg(not(feature = "telemetry"))]
use tracing::warn;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "ftth-sip-test-server",
    about = "Test harness for the FTTH SIP proxy and media relay",
    version
)]
struct Cli {
    /// IP address to bind for upstream (NTT trunk) signalling
    #[arg(long, default_value_t = IpAddr::V4(Ipv4Addr::UNSPECIFIED))]
    upstream_bind_addr: IpAddr,

    /// UDP port to bind for upstream signalling
    #[arg(long, default_value_t = 5060)]
    upstream_bind_port: u16,

    /// Optional network interface name for SO_BINDTODEVICE on upstream socket
    #[arg(long)]
    upstream_interface: Option<String>,

    /// Registrar URI presented to NTT upstream
    #[arg(long)]
    upstream_registrar_uri: String,

    /// SIP domain used for Route/To headers when talking to NTT
    #[arg(long)]
    upstream_domain: String,

    /// IP address used to reach the upstream trunk directly (no DNS lookup).
    #[arg(long)]
    upstream_trunk_ip: IpAddr,

    /// UDP port used when connecting to the upstream trunk
    #[arg(long, default_value_t = 5060)]
    upstream_trunk_port: u16,

    /// Default caller identity when downstream identity is not permitted
    #[arg(long)]
    upstream_default_identity: String,

    /// Allowed calling identities (user part) permitted toward the NGN trunk.
    #[arg(long = "allowed-identity", value_name = "NUMBER", action = clap::ArgAction::Append)]
    upstream_allowed_identity: Vec<String>,

    /// Username for authenticating against upstream registrar
    #[arg(long)]
    upstream_auth_username: Option<String>,

    /// Password for authenticating against upstream registrar
    #[arg(long)]
    upstream_auth_password: Option<String>,

    /// IP address to bind for downstream (LAN PBX) signalling
    #[arg(long, default_value_t = IpAddr::V4(Ipv4Addr::UNSPECIFIED))]
    downstream_bind_addr: IpAddr,

    /// UDP port to bind for downstream signalling
    #[arg(long, default_value_t = 15060)]
    downstream_bind_port: u16,

    /// Optional network interface name for downstream socket
    #[arg(long)]
    downstream_interface: Option<String>,

    /// Expected downstream user agent username (REGISTER / INVITE)
    #[arg(long)]
    downstream_username: String,

    /// Optional password shared with downstream user agent for digest auth
    #[arg(long)]
    downstream_password: Option<String>,

    /// Optional realm override for downstream digest auth
    #[arg(long)]
    downstream_realm: Option<String>,

    /// Media relay upstream bind address (defaults to upstream bind address)
    #[arg(long)]
    media_upstream_addr: Option<IpAddr>,

    /// Media relay upstream bind port (0 for auto)
    #[arg(long, default_value_t = 0)]
    media_upstream_port: u16,

    /// Optional interface for upstream media sockets
    #[arg(long)]
    media_upstream_interface: Option<String>,

    /// Media relay downstream bind address (defaults to downstream bind address)
    #[arg(long)]
    media_downstream_addr: Option<IpAddr>,

    /// Media relay downstream bind port (0 for auto)
    #[arg(long, default_value_t = 0)]
    media_downstream_port: u16,

    /// Optional interface for downstream media sockets
    #[arg(long)]
    media_downstream_interface: Option<String>,

    /// Lower bound (inclusive) for RTP relay port allocation (must be even)
    #[arg(long, default_value_t = 40000)]
    media_port_min: u16,

    /// Upper bound (inclusive) for RTP relay port allocation
    #[arg(long, default_value_t = 40100)]
    media_port_max: u16,

    /// Seconds of inactivity before tearing down a relay session
    #[arg(long, default_value_t = 120)]
    media_inactivity_timeout: u64,

    /// Seconds to request for upstream registration refresh
    #[arg(long, default_value_t = 60)]
    registration_refresh: u64,

    /// Invite transaction timeout in seconds
    #[arg(long, default_value_t = 32)]
    invite_timeout: u64,

    /// Log level when telemetry feature is enabled (default info)
    #[arg(long, default_value = "info")]
    log_level: String,
}

impl Cli {
    fn into_proxy_config(self) -> Result<ProxyConfig> {
        if self.media_port_min % 2 != 0 {
            return Err(anyhow!("media-port-min must be an even port"));
        }
        if self.media_port_max <= self.media_port_min {
            return Err(anyhow!(
                "media-port-max must be greater than media-port-min"
            ));
        }

        let upstream_bind = BindConfig {
            address: self.upstream_bind_addr,
            port: self.upstream_bind_port,
            interface: self.upstream_interface,
        };

        let downstream_bind = BindConfig {
            address: self.downstream_bind_addr,
            port: self.downstream_bind_port,
            interface: self.downstream_interface,
        };

        let upstream_auth = match (self.upstream_auth_username, self.upstream_auth_password) {
            (Some(username), Some(password)) => Some(UpstreamAuth { username, password }),
            (Option::None, Option::None) => None,
            _ => {
                return Err(anyhow!(
                    "both --upstream-auth-username and --upstream-auth-password must be provided"
                ));
            }
        };

        let mut allowed_identities = self.upstream_allowed_identity.clone();
        if allowed_identities.is_empty() {
            allowed_identities.push(self.upstream_default_identity.clone());
        }
        if !allowed_identities
            .iter()
            .any(|id| id.eq_ignore_ascii_case(&self.upstream_default_identity))
        {
            allowed_identities.push(self.upstream_default_identity.clone());
        }

        let media_upstream = BindConfig {
            address: self.media_upstream_addr.unwrap_or(upstream_bind.address),
            port: self.media_upstream_port,
            interface: self.media_upstream_interface,
        };

        let media_downstream = BindConfig {
            address: self
                .media_downstream_addr
                .unwrap_or(downstream_bind.address),
            port: self.media_downstream_port,
            interface: self.media_downstream_interface,
        };

        let media = MediaConfig {
            upstream: media_upstream,
            downstream: media_downstream,
            port_range: PortRange {
                min: self.media_port_min,
                max: self.media_port_max,
            },
            inactivity_timeout_secs: self.media_inactivity_timeout,
        };

        let timers = TimerConfig {
            registration_refresh_secs: self.registration_refresh,
            invite_timeout_secs: self.invite_timeout,
        };

        let downstream = DownstreamConfig {
            bind: downstream_bind,
            user_agent: AllowedUserAgent {
                username: self.downstream_username.clone(),
                realm: self.downstream_realm,
                password: self.downstream_password.clone(),
            },
            transport: TransportProfile::Udp,
        };

        let upstream = UpstreamConfig {
            bind: upstream_bind,
            registrar_uri: self.upstream_registrar_uri,
            sip_domain: self.upstream_domain,
            trunk_addr: self.upstream_trunk_ip,
            trunk_port: self.upstream_trunk_port,
            default_identity: self.upstream_default_identity,
            allowed_identities,
            auth: upstream_auth,
            transport: TransportProfile::Udp,
        };

        Ok(ProxyConfig {
            upstream,
            downstream,
            media,
            timers,
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli.log_level)?;

    let log_level = cli.log_level.clone();
    let config = cli.into_proxy_config().context("build proxy config")?;

    info!(log_level = %log_level, "starting ftth-sip proxy");

    let runtime = FtthSipProxyBuilder::new(config)
        .build()
        .await
        .context("initialise proxy runtime")?;

    let handle = runtime.start().await.context("start proxy runtime")?;

    info!("proxy started; press Ctrl+C to stop");

    tokio::signal::ctrl_c()
        .await
        .context("wait for shutdown signal")?;

    info!("shutdown signal received, stopping proxy");
    handle.shutdown().await.context("proxy shutdown")?;

    info!("proxy stopped");
    Ok(())
}

#[cfg(feature = "telemetry")]
fn init_tracing(level: &str) -> Result<()> {
    use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

    let env_filter = if let Ok(value) = std::env::var(EnvFilter::DEFAULT_ENV) {
        EnvFilter::new(value)
    } else {
        EnvFilter::new(level)
    };

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer())
        .init();
    Ok(())
}

#[cfg(not(feature = "telemetry"))]
fn init_tracing(_level: &str) -> Result<()> {
    if std::env::var("RUST_LOG").is_ok() {
        warn!("telemetry feature disabled; RUST_LOG ignored");
    }
    Ok(())
}
