use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use ftth_rsipstack::transaction::endpoint::MessageInspector;
use ftth_rsipstack::transport::udp::{UdpConnection, UdpInner};
use ftth_rsipstack::transport::{SipAddr, SipConnection, TransportLayer};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::runtime::Builder as RuntimeBuilder;
use tokio::sync::{Mutex, RwLock, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::config::{BindConfig, ProxyConfig};
use crate::error::{Error, Result};
use crate::media::{MediaRelay, MediaRelayBuilder};
use crate::net::bind_to_device;

use super::registration::{DownstreamRegistration, RegistrationCache};

use ftth_rsipstack::EndpointBuilder;
use ftth_rsipstack::transaction::Endpoint;
use ftth_rsipstack::transaction::transaction::Transaction;
use rsip::headers::ToTypedHeader;
use rsip::message::headers_ext::HeadersExt;
use rsip::{self, Method, Param, SipMessage, StatusCode};
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct SipContext {
    pub config: Arc<ProxyConfig>,
    pub media: Arc<MediaRelay>,
    pub registrations: Arc<RwLock<RegistrationCache>>,
    pub sockets: Arc<ListenerSockets>,
}

#[derive(Debug, Default)]
pub struct ListenerSockets {
    pub downstream: Mutex<Option<SocketAddr>>,
    pub upstream: Mutex<Option<SocketAddr>>,
}

#[derive(Debug, Default)]
struct ProxyMessageInspector;

impl ProxyMessageInspector {
    fn strip_rport(via: &mut rsip::headers::Via) {
        if let Ok(mut typed) = via.clone().typed() {
            typed.params.retain(|param| {
                !matches!(param, Param::Other(name, _) if name.value().eq_ignore_ascii_case("rport"))
            });
            *via = typed.into();
        }
    }
}

impl MessageInspector for ProxyMessageInspector {
    fn before_send(&self, msg: SipMessage) -> SipMessage {
        match msg {
            SipMessage::Request(mut req) => {
                if let Ok(via) = req.via_header_mut() {
                    Self::strip_rport(via);
                }
                SipMessage::Request(req)
            }
            other => other,
        }
    }

    fn after_received(&self, msg: SipMessage) -> SipMessage {
        msg
    }
}

pub struct FtthSipProxyBuilder<B = RsipstackBackend> {
    config: ProxyConfig,
    backend: B,
}

impl FtthSipProxyBuilder<RsipstackBackend> {
    pub fn new(config: ProxyConfig) -> Self {
        Self {
            config,
            backend: RsipstackBackend::default(),
        }
    }
}

impl<B> FtthSipProxyBuilder<B>
where
    B: SipBackend,
{
    pub fn with_backend(mut self, backend: B) -> Self {
        self.backend = backend;
        self
    }

    pub async fn build(self) -> Result<ProxyRuntime<B>> {
        let media = MediaRelayBuilder::from_config(&self.config.media)?.build();
        let context = SipContext {
            config: Arc::new(self.config),
            media: Arc::new(media),
            registrations: Arc::new(RwLock::new(RegistrationCache::new())),
            sockets: Arc::new(ListenerSockets::default()),
        };

        Ok(ProxyRuntime {
            backend: Arc::new(self.backend),
            context,
        })
    }
}

pub struct ProxyRuntime<B: SipBackend> {
    backend: Arc<B>,
    context: SipContext,
}

impl<B> ProxyRuntime<B>
where
    B: SipBackend,
{
    pub async fn start(self) -> Result<ProxyHandle> {
        self.backend.initialize(&self.context).await?;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let backend = self.backend.clone();
        let context = self.context.clone();

        let worker: JoinHandle<Result<()>> = tokio::task::spawn_blocking(move || {
            let runtime = RuntimeBuilder::new_current_thread()
                .enable_all()
                .build()
                .map_err(Error::Transport)?;

            let mut shutdown = ShutdownSignal::new(shutdown_rx);
            runtime.block_on(async {
                backend.run(context, &mut shutdown).await?;
                backend.shutdown().await
            })
        });

        Ok(ProxyHandle {
            shutdown_tx,
            worker,
        })
    }
}

pub struct ProxyHandle {
    shutdown_tx: watch::Sender<bool>,
    worker: JoinHandle<Result<()>>,
}

impl ProxyHandle {
    pub fn signal_shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    pub async fn wait(self) -> Result<()> {
        let Self {
            shutdown_tx: _,
            worker,
        } = self;
        match worker.await {
            Ok(result) => result,
            Err(join_error) => Err(Error::Media(format!("proxy task panicked: {join_error}"))),
        }
    }

    pub async fn shutdown(self) -> Result<()> {
        let Self {
            shutdown_tx,
            worker,
        } = self;
        let _ = shutdown_tx.send(true);
        match worker.await {
            Ok(result) => result,
            Err(join_error) => Err(Error::Media(format!("proxy task panicked: {join_error}"))),
        }
    }
}

pub struct ShutdownSignal {
    inner: watch::Receiver<bool>,
}

impl ShutdownSignal {
    fn new(inner: watch::Receiver<bool>) -> Self {
        Self { inner }
    }

    pub async fn recv(&mut self) {
        if *self.inner.borrow() {
            return;
        }

        while self.inner.changed().await.is_ok() {
            if *self.inner.borrow() {
                break;
            }
        }
    }
}

#[async_trait(?Send)]
pub trait SipBackend: Send + Sync + 'static {
    async fn initialize(&self, context: &SipContext) -> Result<()>;

    async fn run(&self, context: SipContext, shutdown: &mut ShutdownSignal) -> Result<()>;

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct RsipstackBackend {
    inner: Arc<BackendInner>,
}

struct BackendInner {
    endpoint: RwLock<Option<Arc<Endpoint>>>,
    transport_cancel: RwLock<CancellationToken>,
}

impl Default for RsipstackBackend {
    fn default() -> Self {
        Self {
            inner: Arc::new(BackendInner {
                endpoint: RwLock::new(None),
                transport_cancel: RwLock::new(CancellationToken::new()),
            }),
        }
    }
}

#[async_trait(?Send)]
impl SipBackend for RsipstackBackend {
    async fn initialize(&self, context: &SipContext) -> Result<()> {
        info!(
            upstream = %context.config.upstream.bind.port,
            downstream = %context.config.downstream.bind.port,
            "initializing ftth-rsipstack backend"
        );

        let cancel = CancellationToken::new();
        let transport_layer = TransportLayer::new(cancel.clone());

        let (downstream_conn, downstream_addr) =
            create_udp_listener(&context.config.downstream.bind, cancel.child_token()).await?;
        transport_layer.add_transport(downstream_conn.into());
        *context.sockets.downstream.lock().await = Some(downstream_addr);

        let (upstream_conn, upstream_addr) =
            create_udp_listener(&context.config.upstream.bind, cancel.child_token()).await?;
        transport_layer.add_transport(upstream_conn.into());
        *context.sockets.upstream.lock().await = Some(upstream_addr);

        let mut endpoint_builder = EndpointBuilder::new();
        endpoint_builder
            .with_cancel_token(cancel.clone())
            .with_transport_layer(transport_layer)
            .with_inspector(Box::new(ProxyMessageInspector::default()));
        let endpoint = Arc::new(endpoint_builder.build());

        {
            let mut guard = self.inner.endpoint.write().await;
            guard.replace(endpoint);
        }

        {
            let mut token_guard = self.inner.transport_cancel.write().await;
            *token_guard = cancel;
        }

        Ok(())
    }

    async fn run(&self, context: SipContext, shutdown: &mut ShutdownSignal) -> Result<()> {
        info!(
            domain = %context.config.upstream.sip_domain,
            "ftth-rsipstack event loop started"
        );

        let endpoint = {
            let guard = self.inner.endpoint.read().await;
            guard
                .as_ref()
                .cloned()
                .ok_or_else(|| Error::configuration("endpoint not initialized"))?
        };

        let downstream_listener = {
            let guard = context.sockets.downstream.lock().await;
            guard
                .clone()
                .ok_or_else(|| Error::configuration("downstream listener not bound"))?
        };

        let upstream_listener = {
            let guard = context.sockets.upstream.lock().await;
            guard
                .clone()
                .ok_or_else(|| Error::configuration("upstream listener not bound"))?
        };

        let mut incoming = endpoint.incoming_transactions().map_err(Error::sip_stack)?;
        let endpoint_task = endpoint.serve();
        tokio::pin!(endpoint_task);

        loop {
            tokio::select! {
                _ = shutdown.recv() => {
                    endpoint.shutdown();
                    break;
                }
                _ = &mut endpoint_task => {
                    warn!("endpoint serve loop exited");
                    break;
                }
                maybe_tx = incoming.recv() => {
                    match maybe_tx {
                        Some(tx) => {
                            if let Err(err) = self
                                .process_transaction(
                                    context.clone(),
                                    tx,
                                    downstream_listener,
                                    upstream_listener,
                                )
                                .await
                            {
                                warn!(error = %err, "failed to process transaction");
                            }
                        }
                        None => break,
                    }
                }
            }
        }

        Ok(())
    }

    async fn shutdown(&self) -> Result<()> {
        info!("ftth-rsipstack backend shutting down");
        if let Some(endpoint) = self.inner.endpoint.write().await.take() {
            endpoint.shutdown();
        }
        self.inner.transport_cancel.write().await.cancel();
        Ok(())
    }
}

pub type FtthSipProxy = ProxyRuntime<RsipstackBackend>;

async fn create_udp_listener(
    bind: &BindConfig,
    cancel_token: CancellationToken,
) -> Result<(UdpConnection, SocketAddr)> {
    let socket = Socket::new(
        Domain::for_address(bind.socket_addr()),
        Type::DGRAM,
        Some(Protocol::UDP),
    )
    .map_err(Error::Transport)?;
    socket.set_reuse_address(true).map_err(Error::Transport)?;

    if let Some(interface) = &bind.interface {
        if let Err(err) = bind_to_device(&socket, interface) {
            return Err(match err {
                Error::Transport(io_err) => Error::Transport(io_err),
                Error::Media(msg) => {
                    Error::Transport(std::io::Error::new(std::io::ErrorKind::Other, msg))
                }
                other => other,
            });
        }
    }

    socket
        .bind(&bind.socket_addr().into())
        .map_err(Error::Transport)?;
    socket.set_nonblocking(true).map_err(Error::Transport)?;

    let std_socket: std::net::UdpSocket = socket.into();
    std_socket.set_nonblocking(true).map_err(Error::Transport)?;

    let udp_socket = UdpSocket::from_std(std_socket).map_err(Error::Transport)?;
    let local_addr = udp_socket.local_addr().map_err(Error::Transport)?;

    let resolved = SipConnection::resolve_bind_address(local_addr);
    let mut sip_addr: SipAddr = resolved.into();
    sip_addr.r#type = Some(rsip::transport::Transport::Udp);

    let connection = UdpConnection::attach(
        UdpInner {
            conn: udp_socket,
            addr: sip_addr,
        },
        None,
        Some(cancel_token),
    )
    .await;

    Ok((connection, local_addr))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransactionDirection {
    Downstream,
    Upstream,
}

impl RsipstackBackend {
    async fn process_transaction(
        &self,
        context: SipContext,
        mut tx: Transaction,
        downstream_listener: SocketAddr,
        upstream_listener: SocketAddr,
    ) -> Result<()> {
        let direction = self.determine_direction(&tx, downstream_listener, upstream_listener)?;

        match tx.original.method {
            Method::Register => self.handle_register(context, &mut tx, direction).await,
            Method::Options => self.handle_options(context, &mut tx, direction).await,
            _ => {
                tx.reply(StatusCode::NotImplemented)
                    .await
                    .map_err(Error::sip_stack)?;
                Ok(())
            }
        }
    }

    fn determine_direction(
        &self,
        tx: &Transaction,
        downstream_listener: SocketAddr,
        upstream_listener: SocketAddr,
    ) -> Result<TransactionDirection> {
        let connection = tx
            .connection
            .as_ref()
            .ok_or_else(|| Error::Media("transaction missing transport connection".into()))?;
        let local_addr = connection
            .get_addr()
            .get_socketaddr()
            .map_err(Error::sip_stack)?;

        if local_addr == downstream_listener {
            Ok(TransactionDirection::Downstream)
        } else if local_addr == upstream_listener {
            Ok(TransactionDirection::Upstream)
        } else {
            Err(Error::Media(format!(
                "transaction arrived on unknown local address {local_addr}"
            )))
        }
    }

    async fn handle_register(
        &self,
        context: SipContext,
        tx: &mut Transaction,
        direction: TransactionDirection,
    ) -> Result<()> {
        if direction != TransactionDirection::Downstream {
            tx.reply(StatusCode::Forbidden)
                .await
                .map_err(Error::sip_stack)?;
            return Ok(());
        }

        let allowed = &context.config.downstream.user_agent;
        let username = tx
            .original
            .to_header()
            .map_err(Error::sip_stack)?
            .typed()
            .map_err(Error::sip_stack)?
            .uri
            .auth
            .as_ref()
            .map(|auth| auth.user.clone())
            .unwrap_or_default();

        if username != allowed.username {
            tx.reply(StatusCode::Forbidden)
                .await
                .map_err(Error::sip_stack)?;
            return Ok(());
        }

        let default_expires = context.config.timers.registration_refresh_secs;
        let expires_secs = match tx.original.expires_header() {
            Some(expires) => expires
                .seconds()
                .map(|value| value as u64)
                .unwrap_or(default_expires),
            None => default_expires,
        };

        if expires_secs == 0 {
            context.registrations.write().await.clear();
            tx.reply(StatusCode::OK).await.map_err(Error::sip_stack)?;
            return Ok(());
        }

        let contact_header = tx
            .original
            .contact_header()
            .map_err(Error::sip_stack)?
            .clone();

        let via_header = tx.original.via_header().map_err(Error::sip_stack)?;
        let remote_addr = resolve_remote_from_via(via_header).map_err(Error::Media)?;

        let registration = DownstreamRegistration {
            contact_uri: contact_header.to_string(),
            registered_at: Instant::now(),
            expires_in: Duration::from_secs(expires_secs),
            source: remote_addr,
        };

        context.registrations.write().await.upsert(registration);

        tx.reply(StatusCode::OK).await.map_err(Error::sip_stack)?;
        Ok(())
    }

    async fn handle_options(
        &self,
        context: SipContext,
        tx: &mut Transaction,
        direction: TransactionDirection,
    ) -> Result<()> {
        // Respond to OPTIONS locally to provide capability and health info.
        let mut headers = Vec::new();
        headers.push(rsip::Header::Other(
            "Allow".into(),
            "INVITE, ACK, CANCEL, BYE, REGISTER, OPTIONS".into(),
        ));
        headers.push(rsip::Header::Other(
            "Accept".into(),
            "application/sdp".into(),
        ));

        if direction == TransactionDirection::Downstream {
            if let Some(registration) = context.registrations.read().await.get() {
                headers.push(rsip::Header::Other(
                    "Contact".into(),
                    registration.contact_uri.clone(),
                ));
            }
        }

        tx.reply_with(StatusCode::OK, headers, None)
            .await
            .map_err(Error::sip_stack)
    }
}

fn resolve_remote_from_via(via: &rsip::headers::Via) -> Result<SocketAddr, String> {
    let via = via
        .typed()
        .map_err(|err| format!("failed to parse Via header: {err}"))?;

    let mut host = via.sent_by().host().clone();
    let mut port = via.sent_by().port().map(|p| *p.value()).unwrap_or(5060);

    match via.received() {
        Ok(Some(received)) => {
            host = rsip::host_with_port::Host::IpAddr(received);
        }
        Ok(None) => {}
        Err(err) => {
            return Err(format!("invalid received parameter: {err}"));
        }
    }

    for param in &via.params {
        if let Param::Other(name, Some(value)) = param {
            if name.value().eq_ignore_ascii_case("rport") {
                if let Ok(parsed) = value.value().parse::<u16>() {
                    port = parsed;
                }
            }
        }
    }

    let ip = match host {
        rsip::host_with_port::Host::IpAddr(addr) => addr,
        rsip::host_with_port::Host::Domain(domain) => {
            let name = domain.to_string();
            name.parse::<IpAddr>()
                .map_err(|err| format!("invalid received host `{name}`: {err}"))?
        }
    };

    Ok(SocketAddr::new(ip, port))
}
