use std::collections::HashMap;
use std::convert::TryFrom;
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
use crate::media::{MediaRelay, MediaRelayBuilder, MediaSessionHandle, MediaSessionKey};
use crate::net::bind_to_device;

use super::registration::{DownstreamRegistration, RegistrationCache};

use ftth_rsipstack::EndpointBuilder;
use ftth_rsipstack::transaction::Endpoint;
use ftth_rsipstack::transaction::key::{TransactionKey, TransactionRole};
use ftth_rsipstack::transaction::transaction::Transaction;
use rsip::headers::{Contact, ToTypedHeader, UntypedHeader};
use rsip::message::headers_ext::HeadersExt;
use rsip::typed;
use rsip::{
    self, Method, Param, Response, SipMessage, StatusCode, StatusCodeKind, Uri,
    host_with_port::HostWithPort, transport::Transport,
};
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct SipContext {
    pub config: Arc<ProxyConfig>,
    pub media: Arc<MediaRelay>,
    pub registrations: Arc<RwLock<RegistrationCache>>,
    pub sockets: Arc<ListenerSockets>,
    pub calls: Arc<RwLock<HashMap<String, CallContext>>>,
    pending: Arc<RwLock<HashMap<String, PendingInvite>>>,
}

#[derive(Debug, Default)]
pub struct ListenerSockets {
    pub downstream: Mutex<Option<SocketAddr>>,
    pub upstream: Mutex<Option<SocketAddr>>,
}

#[derive(Debug, Clone)]
pub struct CallContext {
    pub media: MediaSessionHandle,
    pub media_key: MediaSessionKey,
    pub upstream_target: SipAddr,
    pub upstream_contact: Option<Uri>,
    pub downstream_contact: Option<Uri>,
    pub upstream_to_tag: Option<String>,
    pub downstream_target: SipAddr,
}

#[allow(dead_code)]
#[derive(Clone)]
struct PendingInvite {
    downstream_tx: Arc<Mutex<Transaction>>,
    media: MediaSessionHandle,
    media_key: MediaSessionKey,
    upstream_target: SipAddr,
    downstream_contact: Option<Uri>,
    cancel_token: CancellationToken,
    endpoint: Arc<Endpoint>,
    upstream_request: rsip::Request,
    downstream_target: SipAddr,
}

impl std::fmt::Debug for PendingInvite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingInvite")
            .field("media_key", &self.media_key)
            .field("upstream_target", &self.upstream_target)
            .field("downstream_contact", &self.downstream_contact)
            .field("downstream_target", &self.downstream_target)
            .finish()
    }
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
            calls: Arc::new(RwLock::new(HashMap::new())),
            pending: Arc::new(RwLock::new(HashMap::new())),
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
    fn prepare_upstream_request(
        endpoint: &Endpoint,
        upstream_listener: SocketAddr,
        upstream_config: &crate::config::UpstreamConfig,
        downstream_username: &str,
        original: &rsip::Request,
        body_override: Option<Vec<u8>>,
    ) -> Result<rsip::Request> {
        let mut request = original.clone();

        if let Some(body) = body_override {
            request.body = body;
        }

        let content_length = request.body.len() as u32;
        request.headers.unique_push(rsip::Header::ContentLength(
            rsip::headers::ContentLength::from(content_length),
        ));

        request
            .headers
            .retain(|header| !matches!(header, rsip::Header::Via(_)));
        request
            .headers
            .retain(|header| !matches!(header, rsip::Header::Contact(_)));

        let host_input = if upstream_config.trunk_port == 5060 {
            upstream_config.sip_domain.clone()
        } else {
            format!(
                "{}:{}",
                upstream_config.sip_domain, upstream_config.trunk_port
            )
        };
        let host_with_port =
            HostWithPort::try_from(host_input.as_str()).map_err(Error::sip_stack)?;
        request.uri.host_with_port = host_with_port;

        let mut via_addr: SipAddr = upstream_listener.into();
        via_addr.r#type = Some(Transport::Udp);
        let via = endpoint
            .inner
            .get_via(Some(via_addr.clone()), None)
            .map_err(Error::sip_stack)?;
        request.headers.unique_push(rsip::Header::Via(via.into()));

        let contact_uri_string = format!(
            "sip:{}@{}:{}",
            downstream_username, upstream_config.bind.address, upstream_config.bind.port
        );
        let contact_uri = Uri::try_from(contact_uri_string.as_str()).map_err(Error::sip_stack)?;
        let contact_header = Contact::from(format!("<{}>", contact_uri));
        request
            .headers
            .unique_push(rsip::Header::Contact(contact_header));

        let max_forwards = request
            .max_forwards_header()
            .ok()
            .and_then(|mf| mf.num().ok())
            .and_then(|value| value.checked_sub(1))
            .unwrap_or(69);
        request
            .headers
            .unique_push(rsip::Header::MaxForwards(rsip::headers::MaxForwards::from(
                max_forwards,
            )));

        Ok(request)
    }

    fn build_trunk_target(upstream_config: &crate::config::UpstreamConfig) -> SipAddr {
        let socket = SocketAddr::new(upstream_config.trunk_addr, upstream_config.trunk_port);
        let mut target: SipAddr = socket.into();
        target.r#type = Some(Transport::Udp);
        target
    }

    fn prepare_downstream_request(
        endpoint: &Endpoint,
        downstream_listener: SocketAddr,
        call: &CallContext,
        original: &rsip::Request,
        body_override: Option<Vec<u8>>,
    ) -> Result<rsip::Request> {
        let mut request = original.clone();

        if let Some(body) = body_override {
            request.body = body;
        }

        let content_length = request.body.len() as u32;
        request.headers.unique_push(rsip::Header::ContentLength(
            rsip::headers::ContentLength::from(content_length),
        ));

        request
            .headers
            .retain(|header| !matches!(header, rsip::Header::Via(_)));

        if let Some(contact) = &call.downstream_contact {
            request
                .headers
                .unique_push(rsip::Header::Contact(Contact::from(format!(
                    "<{}>",
                    contact
                ))));
        }

        let mut via_addr: SipAddr = downstream_listener.into();
        via_addr.r#type = Some(Transport::Udp);
        let via = endpoint
            .inner
            .get_via(Some(via_addr.clone()), None)
            .map_err(Error::sip_stack)?;
        request.headers.unique_push(rsip::Header::Via(via.into()));

        let max_forwards = request
            .max_forwards_header()
            .ok()
            .and_then(|mf| mf.num().ok())
            .and_then(|value| value.checked_sub(1))
            .unwrap_or(69);
        request
            .headers
            .unique_push(rsip::Header::MaxForwards(rsip::headers::MaxForwards::from(
                max_forwards,
            )));

        Ok(request)
    }

    fn sip_addr_from_uri(uri: &Uri) -> Result<SipAddr> {
        let port = uri.host_with_port.port.map(|p| *p.value()).unwrap_or(5060);

        let ip = match &uri.host_with_port.host {
            rsip::host_with_port::Host::IpAddr(addr) => *addr,
            rsip::host_with_port::Host::Domain(domain) => domain
                .to_string()
                .parse::<IpAddr>()
                .map_err(|err| Error::Media(err.to_string()))?,
        };

        let mut sip: SipAddr = SocketAddr::new(ip, port).into();
        sip.r#type = Some(Transport::Udp);
        Ok(sip)
    }

    async fn start_client_transaction(
        &self,
        endpoint: Arc<Endpoint>,
        request: rsip::Request,
        target: SipAddr,
    ) -> Result<Transaction> {
        let key = TransactionKey::from_request(&request, TransactionRole::Client)
            .map_err(Error::sip_stack)?;
        let mut tx = Transaction::new_client(key, request, endpoint.inner.clone(), None);
        tx.destination = Some(target);
        tx.send().await.map_err(Error::sip_stack)?;
        Ok(tx)
    }

    async fn forward_upstream_responses(
        &self,
        mut client_tx: Transaction,
        downstream_tx: Arc<Mutex<Transaction>>,
        media_session: MediaSessionHandle,
        cancel_token: CancellationToken,
    ) -> Result<(Option<StatusCode>, Option<Response>)> {
        let mut final_status: Option<StatusCode> = None;
        let mut final_response: Option<Response> = None;

        loop {
            tokio::select! {
                _ = cancel_token.cancelled() => {
                    break;
                }
                maybe_message = client_tx.receive() => {
                    match maybe_message {
                        Some(SipMessage::Response(mut upstream_response)) => {
                            if !upstream_response.body.is_empty() {
                                if let Ok(body) = String::from_utf8(upstream_response.body.clone()) {
                                    let rewrite = media_session.rewrite_for_downstream(&body)?;
                                    media_session
                                        .set_upstream_endpoints(
                                            rewrite.remote_rtp,
                                            Some(rewrite.remote_rtcp),
                                        )
                                        .await;
                                    upstream_response.body = rewrite.sdp.into_bytes();
                                    let len = upstream_response.body.len() as u32;
                                    upstream_response
                                        .headers
                                        .unique_push(rsip::Header::ContentLength(
                                            rsip::headers::ContentLength::from(len),
                                        ));
                                }
                            }

                            {
                                let mut guard = downstream_tx.lock().await;
                                guard
                                    .respond(upstream_response.clone())
                                    .await
                                    .map_err(Error::sip_stack)?;
                            }

                            match upstream_response.status_code.kind() {
                                StatusCodeKind::Provisional => {}
                                _ => {
                                    final_status = Some(upstream_response.status_code.clone());
                                    final_response = Some(upstream_response);
                                    break;
                                }
                            }
                        }
                        Some(SipMessage::Request(_)) => {
                            // Ignore upstream in-dialog requests for now.
                        }
                        None => break,
                    }
                }
            }
        }

        Ok((final_status, final_response))
    }

    async fn finalize_invite_result(
        &self,
        context: SipContext,
        call_id: String,
        result: Result<(Option<StatusCode>, Option<Response>)>,
    ) {
        let pending = context.pending.write().await.remove(&call_id);
        let Some(pending) = pending else {
            return;
        };

        match result {
            Ok((Some(status), Some(response)))
                if matches!(status.kind(), StatusCodeKind::Successful) =>
            {
                let upstream_contact_uri = response
                    .contact_header()
                    .ok()
                    .and_then(|header| header.typed().ok().map(|typed| typed.uri));
                let upstream_to_tag = response
                    .to_header()
                    .ok()
                    .and_then(|to| to.tag().ok().flatten().map(|tag| tag.to_string()));

                context.calls.write().await.insert(
                    call_id,
                    CallContext {
                        media: pending.media,
                        media_key: pending.media_key,
                        upstream_target: pending.upstream_target,
                        upstream_contact: upstream_contact_uri,
                        downstream_contact: pending.downstream_contact,
                        upstream_to_tag,
                        downstream_target: pending.downstream_target,
                    },
                );
            }
            Ok(_) => {
                context.media.release(&pending.media_key).await;
            }
            Err(err) => {
                warn!(error = %err, "invite forwarding task failed");
                let mut guard = pending.downstream_tx.lock().await;
                if let Err(reply_err) = guard.reply(StatusCode::ServerInternalError).await {
                    warn!(error = %reply_err, "failed to notify downstream about INVITE failure");
                }
                context.media.release(&pending.media_key).await;
            }
        }
    }

    async fn process_transaction(
        &self,
        context: SipContext,
        mut tx: Transaction,
        downstream_listener: SocketAddr,
        upstream_listener: SocketAddr,
    ) -> Result<()> {
        let direction = self.determine_direction(&tx, downstream_listener, upstream_listener)?;

        match tx.original.method.clone() {
            Method::Invite => self.handle_invite(context, tx, direction).await,
            Method::Register => self.handle_register(context, &mut tx, direction).await,
            Method::Options => self.handle_options(context, &mut tx, direction).await,
            Method::Ack => self.handle_ack(context, &mut tx, direction).await,
            Method::Cancel => self.handle_cancel(context, &mut tx, direction).await,
            Method::Bye => self.handle_bye(context, &mut tx, direction).await,
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

    async fn handle_invite(
        &self,
        context: SipContext,
        tx: Transaction,
        direction: TransactionDirection,
    ) -> Result<()> {
        if direction != TransactionDirection::Downstream {
            let mut guard = tx;
            guard
                .reply(StatusCode::MethodNotAllowed)
                .await
                .map_err(Error::sip_stack)?;
            return Ok(());
        }

        let call_id = tx
            .original
            .call_id_header()
            .map_err(Error::sip_stack)?
            .value()
            .to_string();
        let from_tag = tx
            .original
            .from_header()
            .map_err(Error::sip_stack)?
            .tag()
            .map_err(Error::sip_stack)?
            .map(|tag| tag.to_string());
        let media_key = MediaSessionKey {
            call_id: call_id.clone(),
            dialog_tag: from_tag.clone(),
        };

        let downstream_contact_uri = tx
            .original
            .contact_header()
            .ok()
            .and_then(|header| header.typed().ok().map(|typed| typed.uri));

        let registration_source = {
            let guard = context.registrations.read().await;
            guard.get().map(|reg| reg.source)
        };

        let downstream_target = downstream_contact_uri
            .as_ref()
            .and_then(|uri| Self::sip_addr_from_uri(uri).ok())
            .or_else(|| {
                registration_source.map(|addr| {
                    let mut sip: SipAddr = addr.into();
                    sip.r#type = Some(Transport::Udp);
                    sip
                })
            })
            .unwrap_or_else(|| {
                let mut sip: SipAddr = context.config.downstream.bind.socket_addr().into();
                sip.r#type = Some(Transport::Udp);
                sip
            });

        let downstream_tx = Arc::new(Mutex::new(tx));
        {
            let mut guard = downstream_tx.lock().await;
            guard.send_trying().await.map_err(Error::sip_stack)?;
        }

        let media_session = context.media.allocate(media_key.clone()).await?;

        let original_request = {
            let guard = downstream_tx.lock().await;
            guard.original.clone()
        };

        let mut rewritten_body: Option<Vec<u8>> = None;
        if !original_request.body.is_empty() {
            let body = String::from_utf8(original_request.body.clone())
                .map_err(|err| Error::Media(err.to_string()))?;
            let rewrite = media_session.rewrite_for_upstream(&body)?;
            media_session
                .set_downstream_endpoints(rewrite.remote_rtp, Some(rewrite.remote_rtcp))
                .await;
            rewritten_body = Some(rewrite.sdp.into_bytes());
        }

        let endpoint = {
            let guard = self.inner.endpoint.read().await;
            guard
                .as_ref()
                .cloned()
                .ok_or_else(|| Error::configuration("endpoint not initialized"))?
        };

        let upstream_listener = {
            let guard = context.sockets.upstream.lock().await;
            guard
                .clone()
                .ok_or_else(|| Error::configuration("upstream listener not bound"))?
        };

        let config = context.config.as_ref();
        let upstream_request = Self::prepare_upstream_request(
            &endpoint,
            upstream_listener,
            &config.upstream,
            &config.downstream.user_agent.username,
            &original_request,
            rewritten_body,
        )?;

        let target = Self::build_trunk_target(&config.upstream);
        let upstream_request_clone = upstream_request.clone();
        let client_tx = self
            .start_client_transaction(endpoint.clone(), upstream_request, target.clone())
            .await?;

        let cancel_token = CancellationToken::new();

        let task_downstream = downstream_tx.clone();
        let task_media = media_session.clone();
        let task_cancel = cancel_token.clone();
        let backend = self.clone();
        let context_clone = context.clone();
        let call_id_clone = call_id.clone();

        context.pending.write().await.insert(
            call_id.clone(),
            PendingInvite {
                downstream_tx,
                media: media_session,
                media_key,
                upstream_target: target,
                downstream_contact: downstream_contact_uri,
                cancel_token,
                endpoint,
                upstream_request: upstream_request_clone,
                downstream_target: downstream_target.clone(),
            },
        );

        tokio::spawn(async move {
            let result = backend
                .forward_upstream_responses(client_tx, task_downstream, task_media, task_cancel)
                .await;
            backend
                .finalize_invite_result(context_clone, call_id_clone, result)
                .await;
        });

        Ok(())
    }

    async fn handle_ack(
        &self,
        context: SipContext,
        tx: &mut Transaction,
        direction: TransactionDirection,
    ) -> Result<()> {
        if direction != TransactionDirection::Downstream {
            return Ok(());
        }

        let call_id = tx
            .original
            .call_id_header()
            .map_err(Error::sip_stack)?
            .value()
            .to_string();

        let call = match context.calls.read().await.get(&call_id).cloned() {
            Some(call) => call,
            None => return Ok(()),
        };

        let endpoint = {
            let guard = self.inner.endpoint.read().await;
            guard
                .as_ref()
                .cloned()
                .ok_or_else(|| Error::configuration("endpoint not initialized"))?
        };

        let upstream_listener = {
            let guard = context.sockets.upstream.lock().await;
            guard
                .clone()
                .ok_or_else(|| Error::configuration("upstream listener not bound"))?
        };

        let config = context.config.as_ref();
        let upstream_request = Self::prepare_upstream_request(
            &endpoint,
            upstream_listener,
            &config.upstream,
            &config.downstream.user_agent.username,
            &tx.original,
            None,
        )?;

        let _ = self
            .start_client_transaction(endpoint, upstream_request, call.upstream_target.clone())
            .await?;

        Ok(())
    }

    async fn handle_bye(
        &self,
        context: SipContext,
        tx: &mut Transaction,
        direction: TransactionDirection,
    ) -> Result<()> {
        let call_id = tx
            .original
            .call_id_header()
            .map_err(Error::sip_stack)?
            .value()
            .to_string();

        let call = match context.calls.read().await.get(&call_id).cloned() {
            Some(call) => call,
            None => {
                tx.reply(StatusCode::CallTransactionDoesNotExist)
                    .await
                    .map_err(Error::sip_stack)?;
                return Ok(());
            }
        };

        match direction {
            TransactionDirection::Downstream => {
                let endpoint = {
                    let guard = self.inner.endpoint.read().await;
                    guard
                        .as_ref()
                        .cloned()
                        .ok_or_else(|| Error::configuration("endpoint not initialized"))?
                };

                let upstream_listener = {
                    let guard = context.sockets.upstream.lock().await;
                    guard
                        .clone()
                        .ok_or_else(|| Error::configuration("upstream listener not bound"))?
                };

                let config = context.config.as_ref();
                let upstream_request = Self::prepare_upstream_request(
                    &endpoint,
                    upstream_listener,
                    &config.upstream,
                    &config.downstream.user_agent.username,
                    &tx.original,
                    None,
                )?;

                let mut client_tx = self
                    .start_client_transaction(
                        endpoint,
                        upstream_request,
                        call.upstream_target.clone(),
                    )
                    .await?;

                let mut responded = false;
                while let Some(message) = client_tx.receive().await {
                    match message {
                        SipMessage::Response(response) => {
                            let status = response.status_code.clone();
                            tx.respond(response).await.map_err(Error::sip_stack)?;
                            responded = true;
                            if matches!(status.kind(), StatusCodeKind::Provisional) {
                                continue;
                            }
                            if matches!(status.kind(), StatusCodeKind::Successful) {
                                context.media.release(&call.media_key).await;
                                context.calls.write().await.remove(&call_id);
                            }
                            break;
                        }
                        SipMessage::Request(_) => {}
                    }
                }

                if !responded {
                    tx.reply(StatusCode::RequestTimeout)
                        .await
                        .map_err(Error::sip_stack)?;
                }

                Ok(())
            }
            TransactionDirection::Upstream => {
                let mut call = call;

                if let Some(contact) = tx
                    .original
                    .contact_header()
                    .ok()
                    .and_then(|header| header.typed().ok().map(|typed| typed.uri))
                {
                    call.upstream_contact = Some(contact);
                }

                let mut body_override: Option<Vec<u8>> = None;
                if !tx.original.body.is_empty() {
                    let body = String::from_utf8(tx.original.body.clone())
                        .map_err(|err| Error::Media(err.to_string()))?;
                    let rewrite = call.media.rewrite_for_downstream(&body)?;
                    call.media
                        .set_upstream_endpoints(rewrite.remote_rtp, Some(rewrite.remote_rtcp))
                        .await;
                    body_override = Some(rewrite.sdp.into_bytes());
                }

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

                let downstream_request = Self::prepare_downstream_request(
                    &endpoint,
                    downstream_listener,
                    &call,
                    &tx.original,
                    body_override,
                )?;

                let mut client_tx = self
                    .start_client_transaction(
                        endpoint,
                        downstream_request,
                        call.downstream_target.clone(),
                    )
                    .await?;

                let mut responded = false;
                let mut new_downstream_contact = call.downstream_contact.clone();
                while let Some(message) = client_tx.receive().await {
                    match message {
                        SipMessage::Response(mut response) => {
                            let status = response.status_code.clone();

                            if !response.body.is_empty() {
                                if let Ok(body) = String::from_utf8(response.body.clone()) {
                                    let rewrite = call.media.rewrite_for_upstream(&body)?;
                                    call.media
                                        .set_downstream_endpoints(
                                            rewrite.remote_rtp,
                                            Some(rewrite.remote_rtcp),
                                        )
                                        .await;
                                    response.body = rewrite.sdp.into_bytes();
                                    let len = response.body.len() as u32;
                                    response.headers.unique_push(rsip::Header::ContentLength(
                                        rsip::headers::ContentLength::from(len),
                                    ));
                                }
                            }

                            if let Some(contact) = response
                                .contact_header()
                                .ok()
                                .and_then(|header| header.typed().ok().map(|typed| typed.uri))
                            {
                                new_downstream_contact = Some(contact);
                            }

                            tx.respond(response.clone())
                                .await
                                .map_err(Error::sip_stack)?;
                            responded = true;
                            if matches!(status.kind(), StatusCodeKind::Provisional) {
                                continue;
                            }

                            if matches!(status.kind(), StatusCodeKind::Successful) {
                                if let Some(contact) = &new_downstream_contact {
                                    call.downstream_contact = Some(contact.clone());
                                    if let Ok(target) = Self::sip_addr_from_uri(contact) {
                                        call.downstream_target = target;
                                    }
                                }
                                context.calls.write().await.insert(call_id.clone(), call);
                            }
                            break;
                        }
                        SipMessage::Request(_) => {}
                    }
                }

                if !responded {
                    tx.reply(StatusCode::RequestTimeout)
                        .await
                        .map_err(Error::sip_stack)?;
                }

                Ok(())
            }
        }
    }

    async fn handle_cancel(
        &self,
        context: SipContext,
        tx: &mut Transaction,
        direction: TransactionDirection,
    ) -> Result<()> {
        let call_id = tx
            .original
            .call_id_header()
            .map_err(Error::sip_stack)?
            .value()
            .to_string();

        let pending_invite = {
            let guard = context.pending.read().await;
            guard.get(&call_id).cloned()
        };

        let Some(pending_invite) = pending_invite else {
            tx.reply(StatusCode::CallTransactionDoesNotExist)
                .await
                .map_err(Error::sip_stack)?;
            return Ok(());
        };

        pending_invite.cancel_token.cancel();

        match direction {
            TransactionDirection::Downstream => {
                tx.reply(StatusCode::OK).await.map_err(Error::sip_stack)?;

                {
                    let mut downstream = pending_invite.downstream_tx.lock().await;
                    if let Err(err) = downstream.reply(StatusCode::RequestTerminated).await {
                        warn!(error = %err, "failed to send 487 to downstream INVITE");
                    }
                }

                context.pending.write().await.remove(&call_id);
                if let Err(err) = self.send_upstream_cancel(&pending_invite).await {
                    warn!(error = %err, "failed to send CANCEL upstream");
                }

                context.media.release(&pending_invite.media_key).await;
                Ok(())
            }
            TransactionDirection::Upstream => {
                tx.reply(StatusCode::OK).await.map_err(Error::sip_stack)?;

                {
                    let mut downstream = pending_invite.downstream_tx.lock().await;
                    if let Err(err) = downstream.reply(StatusCode::RequestTerminated).await {
                        warn!(error = %err, "failed to send 487 to downstream INVITE");
                    }
                }

                context.pending.write().await.remove(&call_id);
                context.media.release(&pending_invite.media_key).await;
                Ok(())
            }
        }
    }

    async fn send_upstream_cancel(&self, pending: &PendingInvite) -> Result<()> {
        let mut cancel = pending.upstream_request.clone();
        cancel.method = Method::Cancel;
        cancel.body.clear();
        cancel.headers.unique_push(rsip::Header::ContentLength(
            rsip::headers::ContentLength::from(0u32),
        ));

        let seq = cancel
            .cseq_header()
            .map_err(Error::sip_stack)?
            .typed()
            .map_err(Error::sip_stack)?
            .seq;
        let cancel_cseq = typed::CSeq {
            seq,
            method: Method::Cancel,
        };
        cancel
            .headers
            .unique_push(rsip::Header::CSeq(cancel_cseq.into()));

        let mut tx = self
            .start_client_transaction(
                pending.endpoint.clone(),
                cancel,
                pending.upstream_target.clone(),
            )
            .await?;

        tokio::spawn(async move { while tx.receive().await.is_some() {} });

        Ok(())
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
