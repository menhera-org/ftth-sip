use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

use crate::config::{BindConfig, MediaConfig};
use crate::error::{Error, Result};
use crate::net::bind_to_device;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MediaSessionKey {
    pub call_id: String,
    pub dialog_tag: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MediaSessionHandle {
    inner: Arc<MediaSession>,
}

impl MediaSessionHandle {
    pub fn key(&self) -> &MediaSessionKey {
        &self.inner.key
    }

    pub fn upstream_rtp_addr(&self) -> SocketAddr {
        self.inner.upstream.rtp_addr
    }

    pub fn downstream_rtp_addr(&self) -> SocketAddr {
        self.inner.downstream.rtp_addr
    }

    pub fn upstream_rtcp_addr(&self) -> SocketAddr {
        self.inner.upstream.rtcp_addr
    }

    pub fn downstream_rtcp_addr(&self) -> SocketAddr {
        self.inner.downstream.rtcp_addr
    }

    pub fn rewrite_for_upstream(&self, body: &str) -> Result<SdpRewrite> {
        rewrite_sdp(
            body,
            self.inner.upstream.rtp_addr.ip(),
            self.inner.upstream.rtp_addr.port(),
        )
    }

    pub fn rewrite_for_downstream(&self, body: &str) -> Result<SdpRewrite> {
        rewrite_sdp(
            body,
            self.inner.downstream.rtp_addr.ip(),
            self.inner.downstream.rtp_addr.port(),
        )
    }

    pub async fn set_downstream_endpoints(&self, rtp: SocketAddr, rtcp: Option<SocketAddr>) {
        self.inner.downstream_state.rtp.write().await.replace(rtp);
        let rtcp_addr =
            rtcp.unwrap_or_else(|| SocketAddr::new(rtp.ip(), rtp.port().saturating_add(1)));
        self.inner
            .downstream_state
            .rtcp
            .write()
            .await
            .replace(rtcp_addr);
        self.inner.mark_active().await;
    }

    pub async fn set_upstream_endpoints(&self, rtp: SocketAddr, rtcp: Option<SocketAddr>) {
        self.inner.upstream_state.rtp.write().await.replace(rtp);
        let rtcp_addr =
            rtcp.unwrap_or_else(|| SocketAddr::new(rtp.ip(), rtp.port().saturating_add(1)));
        self.inner
            .upstream_state
            .rtcp
            .write()
            .await
            .replace(rtcp_addr);
        self.inner.mark_active().await;
    }

    pub async fn close(&self) {
        self.inner.shutdown.cancel();
        let mut guard = self.inner.tasks.lock().await;
        for task in guard.drain(..) {
            task.abort();
        }
    }
}

#[derive(Debug)]
pub struct MediaRelay {
    upstream: BindConfig,
    downstream: BindConfig,
    port_range: RangeInclusive<u16>,
    next_port: Mutex<u16>,
    inactivity_timeout: Duration,
    sessions: Mutex<HashMap<MediaSessionKey, Arc<MediaSession>>>,
}

#[derive(Debug)]
pub struct MediaRelayBuilder {
    config: MediaConfig,
}

impl MediaRelayBuilder {
    pub fn from_config(config: &MediaConfig) -> Result<Self> {
        if config.port_range.min % 2 != 0 {
            return Err(Error::configuration(
                "media port range must start on an even port",
            ));
        }
        if config.port_range.max <= config.port_range.min {
            return Err(Error::configuration(
                "media port range must span at least two ports",
            ));
        }

        Ok(Self {
            config: config.clone(),
        })
    }

    pub fn build(self) -> MediaRelay {
        let port_range = self.config.port_range.min..=self.config.port_range.max;
        let initial_port = *port_range.start();
        MediaRelay {
            upstream: self.config.upstream,
            downstream: self.config.downstream,
            port_range,
            next_port: Mutex::new(initial_port),
            inactivity_timeout: Duration::from_secs(self.config.inactivity_timeout_secs),
            sessions: Mutex::new(HashMap::new()),
        }
    }
}

impl MediaRelay {
    pub async fn allocate(&self, key: MediaSessionKey) -> Result<MediaSessionHandle> {
        let port = self.reserve_port().await;
        let upstream = SocketPair::bind(&self.upstream, port)?;
        let downstream = SocketPair::bind(&self.downstream, port)?;

        let session = Arc::new(MediaSession::new(
            key.clone(),
            upstream,
            downstream,
            self.inactivity_timeout,
        ));
        session.start().await;

        let mut sessions = self.sessions.lock().await;
        sessions.insert(key, session.clone());

        Ok(MediaSessionHandle { inner: session })
    }

    pub async fn release(&self, key: &MediaSessionKey) {
        if let Some(session) = self.sessions.lock().await.remove(key) {
            session.shutdown.cancel();
            let mut tasks = session.tasks.lock().await;
            for task in tasks.drain(..) {
                task.abort();
            }
        }
    }

    pub async fn lookup(&self, key: &MediaSessionKey) -> Option<MediaSessionHandle> {
        self.sessions
            .lock()
            .await
            .get(key)
            .cloned()
            .map(|session| MediaSessionHandle { inner: session })
    }

    async fn reserve_port(&self) -> u16 {
        let mut next = self.next_port.lock().await;
        let start = *self.port_range.start();
        let end = *self.port_range.end();

        if *next < start || *next > end {
            *next = start;
        }

        let candidate = *next;
        let mut next_port = candidate.saturating_add(2);
        if next_port > end {
            next_port = start;
        }
        *next = next_port;
        candidate
    }
}

#[derive(Debug)]
struct SocketPair {
    rtp: Arc<UdpSocket>,
    rtcp: Arc<UdpSocket>,
    rtp_addr: SocketAddr,
    rtcp_addr: SocketAddr,
}

impl SocketPair {
    fn bind(bind: &BindConfig, port: u16) -> Result<Self> {
        let rtp = bind_udp_socket(bind, port)?;
        let rtcp = bind_udp_socket(bind, port.saturating_add(1))?;

        let rtp_addr = rtp.local_addr()?;
        let rtcp_addr = rtcp.local_addr()?;

        Ok(Self {
            rtp: Arc::new(rtp),
            rtcp: Arc::new(rtcp),
            rtp_addr,
            rtcp_addr,
        })
    }
}

#[derive(Debug)]
struct EndpointState {
    rtp: Arc<RwLock<Option<SocketAddr>>>,
    rtcp: Arc<RwLock<Option<SocketAddr>>>,
}

impl EndpointState {
    fn new() -> Self {
        Self {
            rtp: Arc::new(RwLock::new(None)),
            rtcp: Arc::new(RwLock::new(None)),
        }
    }
}

#[derive(Debug)]
struct MediaSession {
    key: MediaSessionKey,
    upstream: SocketPair,
    downstream: SocketPair,
    upstream_state: EndpointState,
    downstream_state: EndpointState,
    inactivity_timeout: Duration,
    shutdown: CancellationToken,
    activity: Arc<Mutex<Instant>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl MediaSession {
    fn new(
        key: MediaSessionKey,
        upstream: SocketPair,
        downstream: SocketPair,
        inactivity_timeout: Duration,
    ) -> Self {
        Self {
            key,
            upstream,
            downstream,
            upstream_state: EndpointState::new(),
            downstream_state: EndpointState::new(),
            inactivity_timeout,
            shutdown: CancellationToken::new(),
            activity: Arc::new(Mutex::new(Instant::now())),
            tasks: Mutex::new(Vec::new()),
        }
    }

    async fn start(self: &Arc<Self>) {
        let mut tasks = self.tasks.lock().await;
        tasks.push(self.spawn_directional_loop(
            "rtp-up->down",
            self.upstream.rtp.clone(),
            self.upstream_state.rtp.clone(),
            self.downstream.rtp.clone(),
            self.downstream_state.rtp.clone(),
        ));
        tasks.push(self.spawn_directional_loop(
            "rtp-down->up",
            self.downstream.rtp.clone(),
            self.downstream_state.rtp.clone(),
            self.upstream.rtp.clone(),
            self.upstream_state.rtp.clone(),
        ));
        tasks.push(self.spawn_directional_loop(
            "rtcp-up->down",
            self.upstream.rtcp.clone(),
            self.upstream_state.rtcp.clone(),
            self.downstream.rtcp.clone(),
            self.downstream_state.rtcp.clone(),
        ));
        tasks.push(self.spawn_directional_loop(
            "rtcp-down->up",
            self.downstream.rtcp.clone(),
            self.downstream_state.rtcp.clone(),
            self.upstream.rtcp.clone(),
            self.upstream_state.rtcp.clone(),
        ));
        tasks.push(self.spawn_inactivity_watch());
    }

    async fn mark_active(&self) {
        let mut last = self.activity.lock().await;
        *last = Instant::now();
    }

    fn spawn_directional_loop(
        self: &Arc<Self>,
        label: &'static str,
        recv_socket: Arc<UdpSocket>,
        expected_source: Arc<RwLock<Option<SocketAddr>>>,
        send_socket: Arc<UdpSocket>,
        target_addr: Arc<RwLock<Option<SocketAddr>>>,
    ) -> JoinHandle<()> {
        let shutdown = self.shutdown.clone();
        let key = self.key.clone();
        let activity = self.activity.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => {
                        tracing::debug!(?key, label, "media relay loop cancelled");
                        break;
                    }
                    result = recv_socket.recv_from(&mut buf) => {
                        let (len, src) = match result {
                            Ok(res) => res,
                            Err(err) => {
                                tracing::warn!(?key, label, error = %err, "media relay recv error");
                                continue;
                            }
                        };

                        let expected = expected_source.read().await.clone();
                        if let Some(expected_src) = expected {
                            if src != expected_src {
                                tracing::trace!(?key, label, %src, "ignoring packet from unexpected source");
                                continue;
                            }
                        } else {
                            tracing::trace!(?key, label, %src, "source not configured yet");
                            continue;
                        }

                        let destination = target_addr.read().await.clone();
                        let destination = match destination {
                            Some(addr) => addr,
                            None => {
                                tracing::trace!(?key, label, "destination not configured yet");
                                continue;
                            }
                        };

                        if let Err(err) = send_socket.send_to(&buf[..len], destination).await {
                            tracing::debug!(?key, label, %destination, error = %err, "failed to forward media packet");
                        } else {
                            let mut last = activity.lock().await;
                            *last = Instant::now();
                        }
                    }
                }
            }
        })
    }

    fn spawn_inactivity_watch(self: &Arc<Self>) -> JoinHandle<()> {
        let shutdown_wait = self.shutdown.clone();
        let shutdown_trigger = self.shutdown.clone();
        let key = self.key.clone();
        let activity = self.activity.clone();
        let timeout = self.inactivity_timeout;
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_wait.cancelled() => break,
                    _ = sleep(timeout) => {
                        let last = *activity.lock().await;
                        if last.elapsed() >= timeout {
                            tracing::info!(?key, "media session inactive, shutting down");
                            shutdown_trigger.cancel();
                            break;
                        }
                    }
                }
            }
        })
    }
}

#[derive(Debug)]
pub struct SdpRewrite {
    pub sdp: String,
    pub remote_rtp: SocketAddr,
    pub remote_rtcp: SocketAddr,
}

fn rewrite_sdp(body: &str, new_ip: IpAddr, new_port: u16) -> Result<SdpRewrite> {
    let newline = if body.contains("\r\n") { "\r\n" } else { "\n" };
    let mut remote_ip: Option<IpAddr> = None;
    let mut remote_rtp: Option<u16> = None;
    let mut remote_rtcp: Option<u16> = None;
    let mut rewritten = Vec::new();
    let mut has_pcmu_payload = false;
    let mut has_rtpmap_pcmu = false;

    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("c=IN IP4 ") {
            remote_ip = Some(
                rest.trim()
                    .parse::<std::net::Ipv4Addr>()
                    .map(IpAddr::V4)
                    .map_err(|err| Error::Media(err.to_string()))?,
            );
            rewritten.push(format!("c=IN IP4 {}", new_ip));
            continue;
        }
        if let Some(rest) = line.strip_prefix("c=IN IP6 ") {
            remote_ip = Some(
                rest.trim()
                    .parse::<std::net::Ipv6Addr>()
                    .map(IpAddr::V6)
                    .map_err(|err| Error::Media(err.to_string()))?,
            );
            rewritten.push(format!("c=IN IP6 {}", new_ip));
            continue;
        }
        if let Some(rest) = line.strip_prefix("m=audio ") {
            let mut parts = rest.split_whitespace();
            let port_str = parts
                .next()
                .ok_or_else(|| Error::Media("missing port in m=audio".into()))?;
            let port = port_str
                .parse::<u16>()
                .map_err(|err| Error::Media(err.to_string()))?;
            remote_rtp = Some(port);
            let proto = parts
                .next()
                .ok_or_else(|| Error::Media("missing transport protocol in m=audio".into()))?;
            let payloads: Vec<&str> = parts.collect();
            let mut filtered: Vec<&str> = payloads.into_iter().filter(|fmt| *fmt == "0").collect();
            if filtered.is_empty() {
                filtered.push("0");
            }
            has_pcmu_payload = true;
            let payload_section = filtered.join(" ");
            if payload_section.is_empty() {
                rewritten.push(format!("m=audio {} {}", new_port, proto));
            } else {
                rewritten.push(format!(
                    "m=audio {} {} {}",
                    new_port, proto, payload_section
                ));
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("a=rtcp:") {
            let mut parts = rest.split_whitespace();
            let port_str = parts
                .next()
                .ok_or_else(|| Error::Media("missing port in a=rtcp".into()))?;
            let port = port_str
                .parse::<u16>()
                .map_err(|err| Error::Media(err.to_string()))?;
            remote_rtcp = Some(port);
            let remainder: String = parts.collect::<Vec<_>>().join(" ");
            let rewritten_port = new_port.saturating_add(1);
            if remainder.is_empty() {
                rewritten.push(format!("a=rtcp:{}", rewritten_port));
            } else {
                rewritten.push(format!("a=rtcp:{} {}", rewritten_port, remainder));
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("a=rtpmap:") {
            let mut parts = rest.split_whitespace();
            let payload = parts
                .next()
                .ok_or_else(|| Error::Media("invalid a=rtpmap syntax".into()))?;
            if payload == "0" {
                has_rtpmap_pcmu = true;
                rewritten.push("a=rtpmap:0 PCMU/8000".to_string());
            }
            continue;
        }
        if line.starts_with("a=fmtp:") {
            if line.starts_with("a=fmtp:0") {
                rewritten.push(line.to_string());
            }
            continue;
        }
        if line.starts_with("a=rtcp-fb:") {
            if line.starts_with("a=rtcp-fb:0") {
                rewritten.push(line.to_string());
            }
            continue;
        }
        rewritten.push(line.to_string());
    }

    let remote_ip = remote_ip.ok_or_else(|| Error::Media("missing connection address".into()))?;
    let remote_rtp_port =
        remote_rtp.ok_or_else(|| Error::Media("missing audio media port".into()))?;
    let remote_rtcp_port = remote_rtcp.unwrap_or_else(|| remote_rtp_port.saturating_add(1));

    if has_pcmu_payload && !has_rtpmap_pcmu {
        rewritten.push("a=rtpmap:0 PCMU/8000".into());
    }

    let mut sdp = rewritten.join(newline);
    if body.ends_with('\n') {
        sdp.push_str(newline);
    }

    Ok(SdpRewrite {
        sdp,
        remote_rtp: SocketAddr::new(remote_ip, remote_rtp_port),
        remote_rtcp: SocketAddr::new(remote_ip, remote_rtcp_port),
    })
}

fn bind_udp_socket(bind: &BindConfig, port: u16) -> Result<UdpSocket> {
    let domain = Domain::for_address(SocketAddr::new(bind.address, 0));
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;

    if let Some(iface) = &bind.interface {
        bind_to_device(&socket, iface)?;
    }

    let addr = SocketAddr::new(bind.address, port);
    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;

    let udp = UdpSocket::from_std(socket.into())?;
    udp.set_broadcast(true)?;
    Ok(udp)
}
