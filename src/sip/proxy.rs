use std::collections::HashMap;
use std::convert::TryFrom;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use ftth_rsipstack::transaction::endpoint::MessageInspector;
use ftth_rsipstack::transport::udp::{UdpConnection, UdpInner};
use ftth_rsipstack::transport::{SipAddr, SipConnection, TransportLayer};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::runtime::Builder as RuntimeBuilder;
use tokio::sync::{Mutex, Notify, RwLock, watch};
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
use rsip::common::uri::param::Tag;
use rsip::headers::auth::{self, AuthQop, Qop};
use rsip::headers::{Contact, ToTypedHeader, UntypedHeader};
use rsip::message::headers_ext::HeadersExt;
use rsip::typed;
use rsip::{
    self, Method, Param, Response, SipMessage, StatusCode, StatusCodeKind, Uri, Version,
    host_with_port::HostWithPort, transport::Transport,
};
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone)]
pub struct SipContext {
    pub config: Arc<ProxyConfig>,
    pub media: Arc<MediaRelay>,
    pub registrations: Arc<RwLock<RegistrationCache>>,
    pub sockets: Arc<ListenerSockets>,
    pub calls: Arc<RwLock<HashMap<String, CallContext>>>,
    auth: Arc<DownstreamAuthState>,
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
    pub identity: String,
}

#[derive(Clone)]
enum PendingInvite {
    Outbound(OutboundPendingInvite),
    Inbound(InboundPendingInvite),
}

const DOWNSTREAM_NONCE_TTL: Duration = Duration::from_secs(300);

#[derive(Debug)]
struct DownstreamAuthState {
    counter: AtomicU64,
    nonces: Mutex<HashMap<String, Instant>>,
}

impl DownstreamAuthState {
    fn new() -> Self {
        Self {
            counter: AtomicU64::new(1),
            nonces: Mutex::new(HashMap::new()),
        }
    }

    async fn issue_nonce(&self) -> String {
        let seq = self.counter.fetch_add(1, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0));
        let raw = format!("{}:{}:{}", seq, now.as_nanos(), std::process::id());
        let nonce = md5_hex(raw.as_bytes());

        let mut guard = self.nonces.lock().await;
        guard.retain(|_, issued| issued.elapsed() < DOWNSTREAM_NONCE_TTL);
        guard.insert(nonce.clone(), Instant::now());
        nonce
    }

    async fn is_valid(&self, nonce: &str) -> bool {
        let mut guard = self.nonces.lock().await;
        guard.retain(|_, issued| issued.elapsed() < DOWNSTREAM_NONCE_TTL);
        guard.contains_key(nonce)
    }

    async fn invalidate(&self, nonce: &str) {
        let mut guard = self.nonces.lock().await;
        guard.remove(nonce);
    }
}

#[derive(Clone)]
struct OutboundPendingInvite {
    downstream_tx: Arc<Mutex<Transaction>>,
    media: MediaSessionHandle,
    media_key: MediaSessionKey,
    upstream_target: SipAddr,
    downstream_contact: Option<Uri>,
    cancel_token: CancellationToken,
    endpoint: Arc<Endpoint>,
    upstream_request: rsip::Request,
    downstream_target: SipAddr,
    identity: String,
}

#[derive(Clone)]
struct InboundPendingInvite {
    upstream_tx: Arc<Mutex<Transaction>>,
    media: MediaSessionHandle,
    media_key: MediaSessionKey,
    downstream_target: SipAddr,
    downstream_contact: Option<Uri>,
    cancel_token: CancellationToken,
    endpoint: Arc<Endpoint>,
    downstream_request: rsip::Request,
    identity: String,
    upstream_request: rsip::Request,
}

impl std::fmt::Debug for PendingInvite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PendingInvite::Outbound(invite) => f
                .debug_struct("PendingInvite::Outbound")
                .field("media_key", &invite.media_key)
                .field("upstream_target", &invite.upstream_target)
                .field("downstream_contact", &invite.downstream_contact)
                .field("downstream_target", &invite.downstream_target)
                .field("identity", &invite.identity)
                .finish(),
            PendingInvite::Inbound(invite) => f
                .debug_struct("PendingInvite::Inbound")
                .field("media_key", &invite.media_key)
                .field("downstream_target", &invite.downstream_target)
                .field("downstream_contact", &invite.downstream_contact)
                .field("identity", &invite.identity)
                .finish(),
        }
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
            auth: Arc::new(DownstreamAuthState::new()),
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
    registrar: RwLock<Option<Arc<UpstreamRegistrar>>>,
}

impl Default for RsipstackBackend {
    fn default() -> Self {
        Self {
            inner: Arc::new(BackendInner {
                endpoint: RwLock::new(None),
                transport_cancel: RwLock::new(CancellationToken::new()),
                registrar: RwLock::new(None),
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

        let registrar_shutdown = CancellationToken::new();
        let registrar = UpstreamRegistrar::new(
            context.clone(),
            endpoint.clone(),
            registrar_shutdown.clone(),
        );
        {
            let mut guard = self.inner.registrar.write().await;
            guard.replace(registrar.clone());
        }
        let registrar_handle = tokio::spawn(registrar.clone().run());

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

        registrar_shutdown.cancel();
        if let Err(join_err) = registrar_handle.await {
            error!(error = %join_err, "upstream registrar task failed");
        }
        self.inner.registrar.write().await.take();

        Ok(())
    }

    async fn shutdown(&self) -> Result<()> {
        info!("ftth-rsipstack backend shutting down");
        if let Some(endpoint) = self.inner.endpoint.write().await.take() {
            endpoint.shutdown();
        }
        self.inner.transport_cancel.write().await.cancel();
        self.inner.registrar.write().await.take();
        Ok(())
    }
}

pub type FtthSipProxy = ProxyRuntime<RsipstackBackend>;

struct UpstreamRegistrar {
    context: SipContext,
    endpoint: Arc<Endpoint>,
    shutdown: CancellationToken,
    call_id: rsip::headers::CallId,
    cseq: AtomicU32,
    nonce_count: AtomicU32,
    challenge: RwLock<Option<DigestChallenge>>,
    wake: Notify,
}

#[derive(Clone, Debug)]
struct DigestChallenge {
    realm: String,
    nonce: String,
    opaque: Option<String>,
    algorithm: Option<auth::Algorithm>,
    qop: Option<Qop>,
}

impl UpstreamRegistrar {
    fn new(context: SipContext, endpoint: Arc<Endpoint>, shutdown: CancellationToken) -> Arc<Self> {
        Arc::new(Self {
            context,
            endpoint,
            shutdown,
            call_id: rsip::headers::CallId::default(),
            cseq: AtomicU32::new(1),
            nonce_count: AtomicU32::new(0),
            challenge: RwLock::new(None),
            wake: Notify::new(),
        })
    }

    async fn run(self: Arc<Self>) {
        info!("starting upstream registrar");
        let mut backoff = Duration::from_secs(1);

        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => {
                    info!("upstream registrar shutdown requested");
                    break;
                }
                _ = self.wake.notified() => {
                    debug!("upstream registrar wake received");
                    continue;
                }
                result = self.register_once() => {
                    match result {
                        Ok(next_refresh) => {
                            backoff = Duration::from_secs(1);
                            tokio::select! {
                                _ = self.shutdown.cancelled() => {
                                    info!("upstream registrar shutdown requested");
                                    break;
                                }
                                _ = self.wake.notified() => {
                                    debug!("upstream registrar refresh triggered early");
                                    continue;
                                }
                                _ = tokio::time::sleep(next_refresh) => {}
                            }
                        }
                        Err(err) => {
                            warn!(error = %err, "upstream REGISTER failed");
                            let wait = backoff;
                            backoff = (backoff * 2).min(Duration::from_secs(300));
                            tokio::select! {
                                _ = self.shutdown.cancelled() => {
                                    info!("upstream registrar shutdown requested");
                                    break;
                                }
                                _ = self.wake.notified() => {
                                    debug!("upstream registrar retry triggered early");
                                    backoff = Duration::from_secs(1);
                                    continue;
                                }
                                _ = tokio::time::sleep(wait) => {}
                            }
                        }
                    }
                }
            }
        }

        info!("upstream registrar stopped");
    }

    fn trigger(&self) {
        self.wake.notify_one();
    }

    async fn register_once(self: &Arc<Self>) -> Result<Duration> {
        let expires_hint = self.context.config.timers.registration_refresh_secs;
        let mut needs_auth_retry = self.challenge.read().await.is_some();
        let mut attempts = 0u8;

        loop {
            let request = self
                .prepare_register_request(expires_hint, needs_auth_retry)
                .await?;

            let target = RsipstackBackend::build_trunk_target(&self.context.config.upstream);
            let mut tx = self
                .start_client_transaction(request.clone(), target)
                .await?;

            while let Some(message) = tx.receive().await {
                if let SipMessage::Response(response) = message {
                    debug!(status = %response.status_code, "received upstream REGISTER response");
                    match response.status_code {
                        StatusCode::OK => {
                            let refresh = self.schedule_from_response(&response, expires_hint)?;
                            self.nonce_count.store(0, Ordering::SeqCst);
                            return Ok(refresh);
                        }
                        StatusCode::Unauthorized | StatusCode::ProxyAuthenticationRequired => {
                            attempts = attempts.saturating_add(1);
                            if attempts > 3 {
                                return Err(Error::sip_stack(
                                    "too many authentication attempts for REGISTER",
                                ));
                            }

                            let challenge_header = match response.status_code {
                                StatusCode::Unauthorized => response
                                    .headers
                                    .iter()
                                    .find_map(|header| match header {
                                        rsip::Header::WwwAuthenticate(value) => Some(value.clone()),
                                        _ => None,
                                    })
                                    .ok_or_else(|| Error::sip_stack("missing WWW-Authenticate"))?,
                                StatusCode::ProxyAuthenticationRequired => response
                                    .headers
                                    .iter()
                                    .find_map(|header| match header {
                                        rsip::Header::ProxyAuthenticate(value) => {
                                            Some(rsip::headers::WwwAuthenticate::new(
                                                value.value().to_string(),
                                            ))
                                        }
                                        _ => None,
                                    })
                                    .ok_or_else(|| {
                                        Error::sip_stack("missing Proxy-Authenticate header")
                                    })?,
                                _ => unreachable!(),
                            };

                            let typed = challenge_header.typed().map_err(Error::sip_stack)?;
                            self.store_challenge(&typed).await?;
                            needs_auth_retry = true;
                            break;
                        }
                        StatusCode::IntervalTooBrief => {
                            let retry_after = response
                                .headers
                                .iter()
                                .find_map(|header| match header {
                                    rsip::Header::MinExpires(value) => {
                                        value.seconds().ok().map(|seconds| seconds as u64)
                                    }
                                    _ => None,
                                })
                                .unwrap_or(expires_hint);
                            warn!(min_expires = retry_after, "upstream registrar received 423");
                            return Ok(Duration::from_secs(retry_after.max(1)));
                        }
                        other => {
                            return Err(Error::sip_stack(format!(
                                "unexpected REGISTER response status {other}"
                            )));
                        }
                    }
                }
            }

            if !needs_auth_retry {
                // No response received; propagate error so caller can back off
                return Err(Error::sip_stack("no valid response to REGISTER"));
            }
        }
    }

    async fn prepare_register_request(
        self: &Arc<Self>,
        expires_hint: u64,
        include_authorization: bool,
    ) -> Result<rsip::Request> {
        let config = &self.context.config.upstream;
        let registrar_uri =
            Uri::try_from(config.registrar_uri.as_str()).map_err(Error::sip_stack)?;

        let local_socket = {
            let guard = self.context.sockets.upstream.lock().await;
            guard
                .to_owned()
                .ok_or_else(|| Error::configuration("upstream listener not bound"))?
        };

        let identity = if config.default_identity.is_empty() {
            return Err(Error::configuration(
                "upstream default identity must be configured",
            ));
        } else {
            config.default_identity.clone()
        };

        let address_literal = format_socket_for_sip(&local_socket);
        let contact_uri = format!("sip:{}@{}", identity, address_literal);

        #[allow(unused_mut)]
        let mut request = rsip::Request {
            method: Method::Register,
            uri: registrar_uri.clone(),
            version: Version::default(),
            headers: rsip::Headers::default(),
            body: Vec::new(),
        };

        let mut via_addr: SipAddr = local_socket.into();
        via_addr.r#type = Some(Transport::Udp);
        let via = self
            .endpoint
            .inner
            .get_via(Some(via_addr), None)
            .map_err(Error::sip_stack)?;
        request.headers.unique_push(rsip::Header::Via(via.into()));
        request
            .headers
            .unique_push(rsip::Header::MaxForwards(rsip::headers::MaxForwards::from(
                70u32,
            )));

        let user_uri = format!("sip:{}@{}", identity, config.sip_domain);
        let user_uri = Uri::try_from(user_uri.as_str()).map_err(Error::sip_stack)?;

        let from_tag = Tag::default();
        let from_header = typed::From {
            display_name: None,
            uri: user_uri.clone(),
            params: vec![Param::Tag(from_tag.clone())],
        };
        request
            .headers
            .unique_push(rsip::Header::From(from_header.into()));

        let to_header = typed::To {
            display_name: None,
            uri: user_uri.clone(),
            params: Vec::new(),
        };
        request
            .headers
            .unique_push(rsip::Header::To(to_header.into()));

        request
            .headers
            .unique_push(rsip::Header::CallId(self.call_id.clone()));

        let seq = self.cseq.fetch_add(1, Ordering::SeqCst);
        let cseq = typed::CSeq {
            seq,
            method: Method::Register,
        };
        request.headers.unique_push(rsip::Header::CSeq(cseq.into()));

        request
            .headers
            .unique_push(rsip::Header::Contact(Contact::from(format!(
                "<{}>",
                contact_uri
            ))));

        request
            .headers
            .unique_push(rsip::Header::Expires(rsip::headers::Expires::from(
                expires_hint as u32,
            )));

        if include_authorization && self.context.config.upstream.auth.is_none() {
            return Err(Error::configuration(
                "upstream authentication required but credentials missing",
            ));
        }

        if include_authorization {
            if let Some(authorization) = self.build_authorization(&request).await? {
                request
                    .headers
                    .unique_push(rsip::Header::Authorization(authorization.into()));
            }
        }

        request.headers.unique_push(rsip::Header::ContentLength(
            rsip::headers::ContentLength::from(0u32),
        ));

        Ok(request)
    }

    fn schedule_from_response(&self, response: &rsip::Response, fallback: u64) -> Result<Duration> {
        let expires = response
            .expires_header()
            .and_then(|header| header.seconds().ok().map(|value| value as u64))
            .unwrap_or(fallback);

        let refresh_secs = if expires > 30 {
            expires - 10
        } else if expires > 5 {
            ((expires as f64) * 0.8).round() as u64
        } else {
            1
        };

        Ok(Duration::from_secs(refresh_secs.max(1)))
    }

    async fn store_challenge(&self, challenge: &rsip::typed::WwwAuthenticate) -> Result<()> {
        let algorithm_value = challenge.algorithm;
        if let Some(algorithm) = algorithm_value {
            if !matches!(algorithm, auth::Algorithm::Md5 | auth::Algorithm::Md5Sess) {
                return Err(Error::configuration(format!(
                    "unsupported digest algorithm {:?}",
                    algorithm
                )));
            }
        }

        let qop_value = challenge.qop.clone();
        if let Some(qop) = qop_value.as_ref() {
            if !matches!(qop, Qop::Auth) {
                return Err(Error::configuration(format!(
                    "unsupported digest qop {:?}",
                    qop
                )));
            }
        }

        let digest = DigestChallenge {
            realm: challenge.realm.clone(),
            nonce: challenge.nonce.clone(),
            opaque: challenge.opaque.clone(),
            algorithm: algorithm_value,
            qop: qop_value,
        };

        let mut guard = self.challenge.write().await;
        *guard = Some(digest);
        Ok(())
    }

    async fn build_authorization(
        &self,
        request: &rsip::Request,
    ) -> Result<Option<rsip::typed::Authorization>> {
        let credentials = match &self.context.config.upstream.auth {
            Some(auth) => auth.clone(),
            None => return Ok(None),
        };

        let challenge = {
            let guard = self.challenge.read().await;
            guard
                .as_ref()
                .cloned()
                .ok_or_else(|| Error::configuration("authentication challenge not available"))?
        };

        let algorithm = challenge.algorithm.unwrap_or(auth::Algorithm::Md5);
        let method = request.method.to_string();
        let uri_string = request.uri.to_string();

        let nonce_count = self.nonce_count.fetch_add(1, Ordering::SeqCst) + 1;
        let nc_value = (nonce_count % 100_000_000).max(1);

        let (qop, cnonce, qop_token) = match challenge.qop.clone() {
            Some(Qop::Auth) => {
                let cnonce = generate_cnonce();
                let nc_u8 = ((nc_value - 1) % 255 + 1) as u8;
                (
                    Some(AuthQop::Auth {
                        cnonce: cnonce.clone(),
                        nc: nc_u8,
                    }),
                    Some(cnonce),
                    Some("auth"),
                )
            }
            Some(other) => {
                return Err(Error::configuration(format!(
                    "unsupported digest qop {:?}",
                    other
                )));
            }
            None => (None, None, None),
        };

        let ha1_base = format!(
            "{}:{}:{}",
            credentials.username, challenge.realm, credentials.password
        );
        let ha1 = match algorithm {
            auth::Algorithm::Md5 => md5_hex(ha1_base.as_bytes()),
            auth::Algorithm::Md5Sess => {
                let base = md5_hex(ha1_base.as_bytes());
                let cnonce = cnonce
                    .as_ref()
                    .ok_or_else(|| Error::configuration("cnonce required for MD5-sess"))?;
                md5_hex(format!("{}:{}:{}", base, challenge.nonce, cnonce).as_bytes())
            }
            other => {
                return Err(Error::configuration(format!(
                    "unsupported digest algorithm {:?}",
                    other
                )));
            }
        };

        let ha2 = md5_hex(format!("{}:{}", method, uri_string).as_bytes());
        let response = if let (Some(token), Some(cnonce)) = (qop_token, cnonce.as_ref()) {
            let nc_formatted = format!("{:08}", nc_value);
            md5_hex(
                format!(
                    "{}:{}:{}:{}:{}:{}",
                    ha1, challenge.nonce, nc_formatted, cnonce, token, ha2
                )
                .as_bytes(),
            )
        } else {
            md5_hex(format!("{}:{}:{}", ha1, challenge.nonce, ha2).as_bytes())
        };

        let authorization = rsip::typed::Authorization {
            scheme: auth::Scheme::Digest,
            username: credentials.username,
            realm: challenge.realm,
            nonce: challenge.nonce,
            uri: request.uri.clone(),
            response,
            algorithm: Some(algorithm),
            opaque: challenge.opaque,
            qop,
        };

        Ok(Some(authorization))
    }

    async fn start_client_transaction(
        &self,
        request: rsip::Request,
        target: SipAddr,
    ) -> Result<Transaction> {
        let key = TransactionKey::from_request(&request, TransactionRole::Client)
            .map_err(Error::sip_stack)?;
        let mut tx = Transaction::new_client(key, request, self.endpoint.inner.clone(), None);
        tx.destination = Some(target);
        tx.send().await.map_err(Error::sip_stack)?;
        Ok(tx)
    }
}

fn format_socket_for_sip(addr: &SocketAddr) -> String {
    match addr.ip() {
        IpAddr::V6(ipv6) => format!("[{}]:{}", ipv6, addr.port()),
        IpAddr::V4(ipv4) => format!("{}:{}", ipv4, addr.port()),
    }
}

fn downstream_realm(context: &SipContext) -> String {
    context
        .config
        .downstream
        .user_agent
        .realm
        .clone()
        .unwrap_or_else(|| context.config.upstream.sip_domain.clone())
}

fn md5_hex(bytes: &[u8]) -> String {
    format!("{:032x}", md5::compute(bytes))
}

fn generate_cnonce() -> String {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0));
    format!("{:x}", now.as_nanos())
}

fn constant_time_eq(lhs: &[u8], rhs: &[u8]) -> bool {
    if lhs.len() != rhs.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in lhs.iter().zip(rhs.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

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

    let chosen_port = if bind.port == 0 {
        local_addr.port()
    } else {
        bind.port
    };
    let canonical_addr = if bind.address.is_unspecified() {
        SocketAddr::new(local_addr.ip(), chosen_port)
    } else {
        SocketAddr::new(bind.address, chosen_port)
    };

    let resolved = SipConnection::resolve_bind_address(canonical_addr);
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
    fn select_identity(
        request: &rsip::Request,
        config: &crate::config::UpstreamConfig,
    ) -> Option<String> {
        let mut allowed: Vec<String> = config.allowed_identities.clone();
        if !config.default_identity.is_empty()
            && !allowed
                .iter()
                .any(|id| id.eq_ignore_ascii_case(&config.default_identity))
        {
            allowed.push(config.default_identity.clone());
        }

        let user = request
            .from_header()
            .ok()
            .and_then(|header| header.typed().ok())
            .and_then(|typed| typed.uri.auth.map(|auth| auth.user));

        if let Some(user) = user {
            if allowed.iter().any(|id| id.eq_ignore_ascii_case(&user)) {
                return Some(user);
            }
        }

        if config.default_identity.is_empty() {
            None
        } else {
            Some(config.default_identity.clone())
        }
    }

    fn prepare_upstream_request(
        endpoint: &Endpoint,
        upstream_listener: SocketAddr,
        upstream_config: &crate::config::UpstreamConfig,
        original: &rsip::Request,
        body_override: Option<Vec<u8>>,
        identity: &str,
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
        request
            .headers
            .retain(|header| !matches!(header, rsip::Header::From(_)));
        request.headers.retain(|header| {
            !matches!(header, rsip::Header::Other(name, _) if {
                let lower = name.to_ascii_lowercase();
                lower == "p-preferred-identity" || lower == "p-asserted-identity"
            })
        });

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

        let via_ip = if upstream_config.bind.address.is_unspecified() {
            upstream_listener.ip()
        } else {
            upstream_config.bind.address
        };
        let via_port = if upstream_config.bind.port == 0 {
            upstream_listener.port()
        } else {
            upstream_config.bind.port
        };
        let mut via_addr: SipAddr = SocketAddr::new(via_ip, via_port).into();
        via_addr.r#type = Some(Transport::Udp);
        let via = endpoint
            .inner
            .get_via(Some(via_addr.clone()), None)
            .map_err(Error::sip_stack)?;
        request.headers.unique_push(rsip::Header::Via(via.into()));

        let identity_uri_string = format!("sip:{}@{}", identity, upstream_config.sip_domain);
        let identity_uri = Uri::try_from(identity_uri_string.as_str()).map_err(Error::sip_stack)?;

        if let Ok(from_header) = request
            .from_header()
            .map(|h| h.clone())
            .map_err(Error::sip_stack)
        {
            if let Ok(mut typed_from) = from_header.typed() {
                typed_from.uri = identity_uri.clone();
                request
                    .headers
                    .unique_push(rsip::Header::From(typed_from.into()));
            }
        } else {
            let from = typed::From {
                display_name: None,
                uri: identity_uri.clone(),
                params: vec![],
            };
            request.headers.unique_push(rsip::Header::From(from.into()));
        }

        let contact_ip = if upstream_config.bind.address.is_unspecified() {
            via_ip
        } else {
            upstream_config.bind.address
        };
        let contact_port = if upstream_config.bind.port == 0 {
            upstream_listener.port()
        } else {
            upstream_config.bind.port
        };
        let identity_contact = format!("sip:{}@{}:{}", identity, contact_ip, contact_port);
        let contact_uri = Uri::try_from(identity_contact.as_str()).map_err(Error::sip_stack)?;
        let contact_header = Contact::from(format!("<{}>", contact_uri));
        request
            .headers
            .unique_push(rsip::Header::Contact(contact_header));

        let asserted = format!("<{}>", identity_uri_string);
        request.headers.unique_push(rsip::Header::Other(
            "P-Preferred-Identity".into(),
            asserted.clone(),
        ));
        request
            .headers
            .unique_push(rsip::Header::Other("P-Asserted-Identity".into(), asserted));

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

    fn compute_authorization_response(
        authorization: &rsip::typed::Authorization,
        request: &rsip::Request,
        password: &str,
        realm: &str,
    ) -> Result<String> {
        if authorization.scheme != auth::Scheme::Digest {
            return Err(Error::configuration("unsupported downstream auth scheme"));
        }

        if let Some(algorithm) = authorization.algorithm {
            if algorithm != auth::Algorithm::Md5 {
                return Err(Error::configuration(
                    "unsupported downstream digest algorithm",
                ));
            }
        }

        let method = request.method.to_string();
        let uri = authorization.uri.to_string();

        let ha1_input = format!("{}:{}:{}", authorization.username, realm, password);
        let ha1 = md5_hex(ha1_input.as_bytes());

        let ha2_input = format!("{}:{}", method, uri);
        let ha2 = md5_hex(ha2_input.as_bytes());

        let response = match &authorization.qop {
            Some(AuthQop::Auth { cnonce, nc }) => {
                let nc_str = format!("{:08x}", nc);
                md5_hex(
                    format!(
                        "{}:{}:{}:{}:{}:{}",
                        ha1, authorization.nonce, nc_str, cnonce, "auth", ha2
                    )
                    .as_bytes(),
                )
            }
            Some(AuthQop::AuthInt { .. }) => {
                return Err(Error::configuration("qop auth-int not supported"));
            }
            None => md5_hex(format!("{}:{}:{}", ha1, authorization.nonce, ha2).as_bytes()),
        };

        Ok(response)
    }

    async fn challenge_downstream_register(
        &self,
        context: &SipContext,
        tx: &mut Transaction,
        realm: &str,
        stale: bool,
    ) -> Result<()> {
        let nonce = context.auth.issue_nonce().await;
        let challenge = rsip::typed::WwwAuthenticate {
            scheme: auth::Scheme::Digest,
            realm: realm.to_string(),
            domain: None,
            nonce,
            opaque: None,
            stale: stale.then(|| "true".into()),
            algorithm: Some(auth::Algorithm::Md5),
            qop: Some(Qop::Auth),
            charset: None,
        };

        tx.reply_with(
            StatusCode::Unauthorized,
            vec![rsip::Header::WwwAuthenticate(challenge.into())],
            None,
        )
        .await
        .map_err(Error::sip_stack)
    }

    async fn ensure_downstream_authorized(
        &self,
        context: &SipContext,
        tx: &mut Transaction,
        realm: &str,
        username: &str,
        password: Option<&str>,
    ) -> Result<bool> {
        if let Some(password) = password {
            let register_header =
                tx.original
                    .headers
                    .clone()
                    .into_iter()
                    .find_map(|header| match header {
                        rsip::Header::Authorization(value) => Some(value),
                        _ => None,
                    });
            let Some(header) = register_header else {
                warn!(realm, "downstream REGISTER missing Authorization header");
                self.challenge_downstream_register(context, tx, realm, false)
                    .await?;
                return Ok(false);
            };
            let auth = header.typed().map_err(Error::sip_stack)?;

            if !auth.username.eq_ignore_ascii_case(username) {
                warn!(expected = %username, received = %auth.username, "downstream username mismatch");
                self.challenge_downstream_register(context, tx, realm, false)
                    .await?;
                return Ok(false);
            }

            self.verify_digest(context, tx, realm, Some(username), password, auth, false)
                .await
        } else {
            Ok(true)
        }
    }

    async fn verify_digest(
        &self,
        context: &SipContext,
        tx: &mut Transaction,
        realm: &str,
        username: Option<&str>,
        password: &str,
        auth: rsip::typed::Authorization,
        proxy: bool,
    ) -> Result<bool> {
        if auth.scheme != auth::Scheme::Digest {
            warn!(realm, proxy, scheme=?auth.scheme, "unsupported auth scheme");
            if proxy {
                self.challenge_downstream_proxy(context, tx, realm, false)
                    .await?;
            } else {
                self.challenge_downstream_register(context, tx, realm, false)
                    .await?;
            }
            return Ok(false);
        }

        if auth.realm != realm {
            warn!(expected = %realm, received = %auth.realm, proxy, "realm mismatch");
            if proxy {
                self.challenge_downstream_proxy(context, tx, realm, false)
                    .await?;
            } else {
                self.challenge_downstream_register(context, tx, realm, false)
                    .await?;
            }
            return Ok(false);
        }

        if let Some(user) = username {
            if !auth.username.eq_ignore_ascii_case(user) {
                warn!(expected = %user, received = %auth.username, "downstream username mismatch");
                self.challenge_downstream_register(context, tx, realm, false)
                    .await?;
                return Ok(false);
            }
        }

        if let Some(algorithm) = auth.algorithm {
            if algorithm != auth::Algorithm::Md5 {
                warn!(?algorithm, "unsupported digest algorithm");
                if proxy {
                    self.challenge_downstream_proxy(context, tx, realm, false)
                        .await?;
                } else {
                    self.challenge_downstream_register(context, tx, realm, false)
                        .await?;
                }
                return Ok(false);
            }
        }

        if !context.auth.is_valid(&auth.nonce).await {
            warn!(nonce = %auth.nonce, proxy, "nonce invalid or expired");
            if proxy {
                self.challenge_downstream_proxy(context, tx, realm, true)
                    .await?;
            } else {
                self.challenge_downstream_register(context, tx, realm, true)
                    .await?;
            }
            return Ok(false);
        }

        let expected_response =
            match Self::compute_authorization_response(&auth, &tx.original, password, realm) {
                Ok(value) => value,
                Err(err) => {
                    warn!(error = %err, "failed to compute digest response");
                    context.auth.invalidate(&auth.nonce).await;
                    if proxy {
                        self.challenge_downstream_proxy(context, tx, realm, true)
                            .await?;
                    } else {
                        self.challenge_downstream_register(context, tx, realm, true)
                            .await?;
                    }
                    return Ok(false);
                }
            };

        let provided = auth.response.to_ascii_lowercase();
        if !constant_time_eq(expected_response.as_bytes(), provided.as_bytes()) {
            warn!("downstream digest response mismatch");
            context.auth.invalidate(&auth.nonce).await;
            if proxy {
                self.challenge_downstream_proxy(context, tx, realm, true)
                    .await?;
            } else {
                self.challenge_downstream_register(context, tx, realm, true)
                    .await?;
            }
            return Ok(false);
        }

        context.auth.invalidate(&auth.nonce).await;
        Ok(true)
    }

    async fn ensure_downstream_proxy_authorized(
        &self,
        context: &SipContext,
        tx: &mut Transaction,
        realm: &str,
        password: Option<&str>,
    ) -> Result<bool> {
        if let Some(password) = password {
            let proxy_header =
                tx.original
                    .headers
                    .clone()
                    .into_iter()
                    .find_map(|header| match header {
                        rsip::Header::ProxyAuthorization(value) => Some(value),
                        _ => None,
                    });
            let Some(header) = proxy_header else {
                warn!(realm, "downstream proxy auth missing, issuing challenge");
                self.challenge_downstream_proxy(context, tx, realm, false)
                    .await?;
                return Ok(false);
            };
            let proxy_auth = header.typed().map_err(Error::sip_stack)?.0.clone();

            self.verify_digest(context, tx, realm, None, password, proxy_auth, true)
                .await
        } else {
            Ok(true)
        }
    }

    async fn challenge_downstream_proxy(
        &self,
        context: &SipContext,
        tx: &mut Transaction,
        realm: &str,
        stale: bool,
    ) -> Result<()> {
        let nonce = context.auth.issue_nonce().await;
        let challenge = rsip::typed::ProxyAuthenticate(rsip::typed::WwwAuthenticate {
            scheme: auth::Scheme::Digest,
            realm: realm.to_string(),
            domain: None,
            nonce,
            opaque: None,
            stale: stale.then(|| "true".into()),
            algorithm: Some(auth::Algorithm::Md5),
            qop: Some(Qop::Auth),
            charset: None,
        });

        tx.reply_with(
            StatusCode::ProxyAuthenticationRequired,
            vec![rsip::Header::ProxyAuthenticate(challenge.into())],
            None,
        )
        .await
        .map_err(Error::sip_stack)
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

    async fn trigger_registration_refresh(&self) {
        if let Some(registrar) = self.inner.registrar.read().await.as_ref().cloned() {
            registrar.trigger();
        }
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

    async fn relay_dialog_request(
        &self,
        context: SipContext,
        tx: &mut Transaction,
        call_id: String,
        mut call: CallContext,
        direction: TransactionDirection,
    ) -> Result<()> {
        match direction {
            TransactionDirection::Downstream => {
                let allowed = &context.config.downstream.user_agent;
                let realm = downstream_realm(&context);
                if !self
                    .ensure_downstream_proxy_authorized(
                        &context,
                        tx,
                        &realm,
                        allowed.password.as_deref(),
                    )
                    .await?
                {
                    return Ok(());
                }

                if let Some(contact) = tx
                    .original
                    .contact_header()
                    .ok()
                    .and_then(|header| header.typed().ok().map(|typed| typed.uri))
                {
                    call.downstream_contact = Some(contact.clone());
                    if let Ok(target) = Self::sip_addr_from_uri(&contact) {
                        call.downstream_target = target;
                    }
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

                let mut body_override: Option<Vec<u8>> = None;
                if !tx.original.body.is_empty() {
                    let body = String::from_utf8(tx.original.body.clone())
                        .map_err(|err| Error::Media(err.to_string()))?;
                    let rewrite = call.media.rewrite_for_upstream(&body)?;
                    call.media
                        .set_downstream_endpoints(rewrite.remote_rtp, Some(rewrite.remote_rtcp))
                        .await;
                    body_override = Some(rewrite.sdp.into_bytes());
                }

                let upstream_request = Self::prepare_upstream_request(
                    &endpoint,
                    upstream_listener,
                    &config.upstream,
                    &tx.original,
                    body_override,
                    &call.identity,
                )?;

                let mut client_tx = self
                    .start_client_transaction(
                        endpoint,
                        upstream_request,
                        call.upstream_target.clone(),
                    )
                    .await?;

                let mut responded = false;
                let mut new_upstream_contact = call.upstream_contact.clone();
                while let Some(message) = client_tx.receive().await {
                    match message {
                        SipMessage::Response(mut response) => {
                            let status = response.status_code.clone();

                            if !response.body.is_empty() {
                                if let Ok(body) = String::from_utf8(response.body.clone()) {
                                    let rewrite = call.media.rewrite_for_downstream(&body)?;
                                    call.media
                                        .set_upstream_endpoints(
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
                                new_upstream_contact = Some(contact);
                            }

                            tx.respond(response.clone())
                                .await
                                .map_err(Error::sip_stack)?;
                            responded = true;
                            if matches!(status.kind(), StatusCodeKind::Provisional) {
                                continue;
                            }

                            if matches!(status.kind(), StatusCodeKind::Successful) {
                                call.upstream_contact = new_upstream_contact;
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
            TransactionDirection::Upstream => {
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

    async fn forward_downstream_responses(
        &self,
        mut client_tx: Transaction,
        upstream_tx: Arc<Mutex<Transaction>>,
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
                        Some(SipMessage::Response(mut downstream_response)) => {
                            if !downstream_response.body.is_empty() {
                                if let Ok(body) = String::from_utf8(downstream_response.body.clone()) {
                                    let rewrite = media_session.rewrite_for_upstream(&body)?;
                                    media_session
                                        .set_downstream_endpoints(
                                            rewrite.remote_rtp,
                                            Some(rewrite.remote_rtcp),
                                        )
                                        .await;
                                    downstream_response.body = rewrite.sdp.into_bytes();
                                    let len = downstream_response.body.len() as u32;
                                    downstream_response
                                        .headers
                                        .unique_push(rsip::Header::ContentLength(
                                            rsip::headers::ContentLength::from(len),
                                        ));
                                }
                            }

                            {
                                let mut guard = upstream_tx.lock().await;
                                guard
                                    .respond(downstream_response.clone())
                                    .await
                                    .map_err(Error::sip_stack)?;
                            }

                            match downstream_response.status_code.kind() {
                                StatusCodeKind::Provisional => {}
                                _ => {
                                    final_status = Some(downstream_response.status_code.clone());
                                    final_response = Some(downstream_response);
                                    break;
                                }
                            }
                        }
                        Some(SipMessage::Request(_)) => {}
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
        let pending_entry = context.pending.write().await.remove(&call_id);
        let Some(pending_entry) = pending_entry else {
            return;
        };

        match pending_entry {
            PendingInvite::Outbound(pending) => {
                pending.cancel_token.cancel();
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
                                identity: pending.identity,
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
            PendingInvite::Inbound(pending) => {
                pending.cancel_token.cancel();
                debug!("outbound finalize encountered inbound pending invite; releasing resources");
                context.media.release(&pending.media_key).await;
            }
        }
    }

    async fn finalize_inbound_invite_result(
        &self,
        context: SipContext,
        call_id: String,
        result: Result<(Option<StatusCode>, Option<Response>)>,
    ) {
        let pending_entry = context.pending.write().await.remove(&call_id);
        let Some(PendingInvite::Inbound(pending)) = pending_entry else {
            return;
        };

        pending.cancel_token.cancel();

        match result {
            Ok((Some(status), Some(response)))
                if matches!(status.kind(), StatusCodeKind::Successful) =>
            {
                let mut downstream_contact = response
                    .contact_header()
                    .ok()
                    .and_then(|header| header.typed().ok().map(|typed| typed.uri));
                let downstream_target = downstream_contact
                    .as_ref()
                    .and_then(|uri| Self::sip_addr_from_uri(uri).ok())
                    .unwrap_or_else(|| pending.downstream_target.clone());

                if downstream_contact.is_none() {
                    downstream_contact = pending.downstream_contact.clone();
                }

                let upstream_contact = pending
                    .upstream_request
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
                        upstream_target: Self::build_trunk_target(&context.config.upstream),
                        upstream_contact,
                        downstream_contact,
                        upstream_to_tag,
                        downstream_target,
                        identity: pending.identity,
                    },
                );
            }
            Ok(_) => {
                context.media.release(&pending.media_key).await;
            }
            Err(err) => {
                warn!(error = %err, "inbound invite forwarding task failed");
                let mut guard = pending.upstream_tx.lock().await;
                if let Err(reply_err) = guard.reply(StatusCode::ServerInternalError).await {
                    warn!(error = %reply_err, "failed to notify upstream about INVITE failure");
                }
                context.media.release(&pending.media_key).await;
            }
        }
    }

    fn schedule_invite_timeout(
        &self,
        context: SipContext,
        call_id: String,
        cancel_token: CancellationToken,
    ) {
        let timeout_secs = context.config.timers.invite_timeout_secs;
        if timeout_secs == 0 {
            return;
        }

        let backend = self.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = cancel_token.cancelled() => {}
                _ = tokio::time::sleep(Duration::from_secs(timeout_secs)) => {
                    backend.handle_invite_timeout(context, call_id).await;
                }
            }
        });
    }

    async fn handle_invite_timeout(&self, context: SipContext, call_id: String) {
        let pending_entry = context.pending.write().await.remove(&call_id);
        let Some(pending_entry) = pending_entry else {
            return;
        };

        match pending_entry {
            PendingInvite::Outbound(pending) => {
                warn!(call_id = %call_id, "outbound INVITE timed out before completion");
                pending.cancel_token.cancel();
                {
                    let mut downstream = pending.downstream_tx.lock().await;
                    if let Err(err) = downstream.reply(StatusCode::RequestTimeout).await {
                        warn!(error = %err, "failed to notify downstream about INVITE timeout");
                    }
                }

                if let Err(err) = self.send_upstream_cancel(&pending).await {
                    warn!(error = %err, "failed to cancel upstream after INVITE timeout");
                }

                context.media.release(&pending.media_key).await;
            }
            PendingInvite::Inbound(pending) => {
                warn!(call_id = %call_id, "inbound INVITE timed out before completion");
                pending.cancel_token.cancel();
                {
                    let mut upstream = pending.upstream_tx.lock().await;
                    if let Err(err) = upstream.reply(StatusCode::RequestTimeout).await {
                        warn!(error = %err, "failed to notify upstream about INVITE timeout");
                    }
                }

                if let Err(err) = self.send_downstream_cancel(&pending).await {
                    warn!(error = %err, "failed to cancel downstream after INVITE timeout");
                }

                context.media.release(&pending.media_key).await;
            }
        }

        self.trigger_registration_refresh().await;
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
            Method::Update => self.handle_update(context, &mut tx, direction).await,
            Method::Info => self.handle_info(context, &mut tx, direction).await,
            Method::PRack => self.handle_prack(context, &mut tx, direction).await,
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
        let realm = downstream_realm(&context);

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

        let authenticated = self
            .ensure_downstream_authorized(
                &context,
                tx,
                &realm,
                &allowed.username,
                allowed.password.as_deref(),
            )
            .await?;
        if !authenticated {
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

        if expires_secs > 0 {
            self.trigger_registration_refresh().await;
        }
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
        let mut tx = tx;
        let call_id = tx
            .original
            .call_id_header()
            .map_err(Error::sip_stack)?
            .value()
            .to_string();

        let existing_call = { context.calls.read().await.get(&call_id).cloned() };

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

        match direction {
            TransactionDirection::Downstream => {
                let allowed = &context.config.downstream.user_agent;
                let realm = downstream_realm(&context);
                if !self
                    .ensure_downstream_proxy_authorized(
                        &context,
                        &mut tx,
                        &realm,
                        allowed.password.as_deref(),
                    )
                    .await?
                {
                    return Ok(());
                }

                if let Some(call) = existing_call {
                    return self
                        .relay_dialog_request(context, &mut tx, call_id, call, direction)
                        .await;
                }

                let downstream_contact_uri = tx
                    .original
                    .contact_header()
                    .ok()
                    .and_then(|header| header.typed().ok().map(|typed| typed.uri));

                let identity = match Self::select_identity(&tx.original, &context.config.upstream) {
                    Some(identity) => identity,
                    None => {
                        tx.reply(StatusCode::Forbidden)
                            .await
                            .map_err(Error::sip_stack)?;
                        return Ok(());
                    }
                };

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
                    &original_request,
                    rewritten_body,
                    &identity,
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
                    PendingInvite::Outbound(OutboundPendingInvite {
                        downstream_tx,
                        media: media_session,
                        media_key,
                        upstream_target: target,
                        downstream_contact: downstream_contact_uri,
                        cancel_token: cancel_token.clone(),
                        endpoint,
                        upstream_request: upstream_request_clone,
                        downstream_target: downstream_target.clone(),
                        identity: identity.clone(),
                    }),
                );

                self.schedule_invite_timeout(
                    context.clone(),
                    call_id.clone(),
                    cancel_token.clone(),
                );

                tokio::spawn(async move {
                    let result = backend
                        .forward_upstream_responses(
                            client_tx,
                            task_downstream,
                            task_media,
                            task_cancel,
                        )
                        .await;
                    backend
                        .finalize_invite_result(context_clone, call_id_clone, result)
                        .await;
                });

                Ok(())
            }
            TransactionDirection::Upstream => {
                if let Some(call) = existing_call {
                    return self
                        .relay_dialog_request(context, &mut tx, call_id, call, direction)
                        .await;
                }

                let registration = {
                    let guard = context.registrations.read().await;
                    guard.get().cloned()
                };

                let registration = match registration {
                    Some(reg) if reg.is_active(Instant::now()) => reg,
                    _ => {
                        tx.reply(StatusCode::TemporarilyUnavailable)
                            .await
                            .map_err(Error::sip_stack)?;
                        return Ok(());
                    }
                };

                let downstream_contact = Uri::try_from(registration.contact_uri.as_str()).ok();
                let downstream_target = downstream_contact
                    .as_ref()
                    .and_then(|uri| Self::sip_addr_from_uri(uri).ok())
                    .unwrap_or_else(|| {
                        let mut sip: SipAddr = registration.source.into();
                        sip.r#type = Some(Transport::Udp);
                        sip
                    });

                let upstream_tx = Arc::new(Mutex::new(tx));
                {
                    let mut guard = upstream_tx.lock().await;
                    guard.send_trying().await.map_err(Error::sip_stack)?;
                }

                let original_request = {
                    let guard = upstream_tx.lock().await;
                    guard.original.clone()
                };

                let media_session = context.media.allocate(media_key.clone()).await?;

                let mut rewritten_body: Option<Vec<u8>> = None;
                if !original_request.body.is_empty() {
                    let body = String::from_utf8(original_request.body.clone())
                        .map_err(|err| Error::Media(err.to_string()))?;
                    let rewrite = media_session.rewrite_for_downstream(&body)?;
                    media_session
                        .set_upstream_endpoints(rewrite.remote_rtp, Some(rewrite.remote_rtcp))
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

                let downstream_listener = {
                    let guard = context.sockets.downstream.lock().await;
                    guard
                        .clone()
                        .ok_or_else(|| Error::configuration("downstream listener not bound"))?
                };

                let config = context.config.as_ref();
                let identity = if config.upstream.default_identity.is_empty() {
                    downstream_contact
                        .as_ref()
                        .and_then(|uri| uri.auth.as_ref().map(|auth| auth.user.clone()))
                        .unwrap_or_else(|| "anonymous".into())
                } else {
                    config.upstream.default_identity.clone()
                };

                let downstream_contact_clone = downstream_contact.clone();
                let call_template = CallContext {
                    media: media_session.clone(),
                    media_key: media_key.clone(),
                    upstream_target: Self::build_trunk_target(&config.upstream),
                    upstream_contact: None,
                    downstream_contact: downstream_contact_clone,
                    upstream_to_tag: None,
                    downstream_target: downstream_target.clone(),
                    identity: identity.clone(),
                };

                let downstream_request = Self::prepare_downstream_request(
                    &endpoint,
                    downstream_listener,
                    &call_template,
                    &original_request,
                    rewritten_body,
                )?;

                let downstream_request_clone = downstream_request.clone();

                let client_tx = self
                    .start_client_transaction(
                        endpoint.clone(),
                        downstream_request,
                        downstream_target.clone(),
                    )
                    .await?;

                let cancel_token = CancellationToken::new();
                context.pending.write().await.insert(
                    call_id.clone(),
                    PendingInvite::Inbound(InboundPendingInvite {
                        upstream_tx: upstream_tx.clone(),
                        media: media_session.clone(),
                        media_key,
                        downstream_target: downstream_target.clone(),
                        downstream_contact,
                        cancel_token: cancel_token.clone(),
                        endpoint,
                        downstream_request: downstream_request_clone,
                        identity,
                        upstream_request: original_request,
                    }),
                );

                self.schedule_invite_timeout(
                    context.clone(),
                    call_id.clone(),
                    cancel_token.clone(),
                );

                let backend = self.clone();
                let context_clone = context.clone();
                let call_id_clone = call_id.clone();

                tokio::spawn(async move {
                    let result = backend
                        .forward_downstream_responses(
                            client_tx,
                            upstream_tx,
                            media_session,
                            cancel_token,
                        )
                        .await;
                    backend
                        .finalize_inbound_invite_result(context_clone, call_id_clone, result)
                        .await;
                });

                Ok(())
            }
        }
    }

    async fn handle_ack(
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
            None => return Ok(()),
        };

        let endpoint = {
            let guard = self.inner.endpoint.read().await;
            guard
                .as_ref()
                .cloned()
                .ok_or_else(|| Error::configuration("endpoint not initialized"))?
        };

        match direction {
            TransactionDirection::Downstream => {
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
                    &tx.original,
                    None,
                    &call.identity,
                )?;

                let _ = self
                    .start_client_transaction(
                        endpoint,
                        upstream_request,
                        call.upstream_target.clone(),
                    )
                    .await?;
            }
            TransactionDirection::Upstream => {
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
                    None,
                )?;

                let _ = self
                    .start_client_transaction(
                        endpoint,
                        downstream_request,
                        call.downstream_target.clone(),
                    )
                    .await?;
            }
        }

        Ok(())
    }

    async fn handle_update(
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

        self.relay_dialog_request(context, tx, call_id, call, direction)
            .await
    }

    async fn handle_info(
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

        self.relay_dialog_request(context, tx, call_id, call, direction)
            .await
    }

    async fn handle_prack(
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

        self.relay_dialog_request(context, tx, call_id, call, direction)
            .await
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

        let stored_call = match context.calls.read().await.get(&call_id).cloned() {
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
                let allowed = &context.config.downstream.user_agent;
                let realm = downstream_realm(&context);
                if !self
                    .ensure_downstream_proxy_authorized(
                        &context,
                        tx,
                        &realm,
                        allowed.password.as_deref(),
                    )
                    .await?
                {
                    return Ok(());
                }

                let call = stored_call.clone();
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
                    &tx.original,
                    None,
                    &call.identity,
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
                let mut call = stored_call;

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

        let pending_invite_entry = {
            let guard = context.pending.read().await;
            guard.get(&call_id).cloned()
        };

        let Some(pending_invite) = pending_invite_entry else {
            tx.reply(StatusCode::CallTransactionDoesNotExist)
                .await
                .map_err(Error::sip_stack)?;
            return Ok(());
        };

        match (direction, pending_invite) {
            (TransactionDirection::Downstream, PendingInvite::Outbound(pending)) => {
                pending.cancel_token.cancel();
                tx.reply(StatusCode::OK).await.map_err(Error::sip_stack)?;

                {
                    let mut downstream = pending.downstream_tx.lock().await;
                    if let Err(err) = downstream.reply(StatusCode::RequestTerminated).await {
                        warn!(error = %err, "failed to send 487 to downstream INVITE");
                    }
                }

                context.pending.write().await.remove(&call_id);
                if let Err(err) = self.send_upstream_cancel(&pending).await {
                    warn!(error = %err, "failed to send CANCEL upstream");
                }

                context.media.release(&pending.media_key).await;
                Ok(())
            }
            (TransactionDirection::Downstream, PendingInvite::Inbound(_)) => {
                tx.reply(StatusCode::CallTransactionDoesNotExist)
                    .await
                    .map_err(Error::sip_stack)?;
                Ok(())
            }
            (TransactionDirection::Upstream, PendingInvite::Outbound(pending)) => {
                pending.cancel_token.cancel();
                tx.reply(StatusCode::OK).await.map_err(Error::sip_stack)?;

                {
                    let mut downstream = pending.downstream_tx.lock().await;
                    if let Err(err) = downstream.reply(StatusCode::RequestTerminated).await {
                        warn!(error = %err, "failed to send 487 to downstream INVITE");
                    }
                }

                context.pending.write().await.remove(&call_id);
                context.media.release(&pending.media_key).await;
                Ok(())
            }
            (TransactionDirection::Upstream, PendingInvite::Inbound(pending)) => {
                pending.cancel_token.cancel();
                tx.reply(StatusCode::OK).await.map_err(Error::sip_stack)?;

                {
                    let mut upstream_guard = pending.upstream_tx.lock().await;
                    if let Err(err) = upstream_guard.reply(StatusCode::RequestTerminated).await {
                        warn!(error = %err, "failed to send 487 to upstream INVITE");
                    }
                }

                if let Err(err) = self.send_downstream_cancel(&pending).await {
                    warn!(error = %err, "failed to send CANCEL downstream");
                }

                context.pending.write().await.remove(&call_id);
                context.media.release(&pending.media_key).await;
                Ok(())
            }
        }
    }

    async fn send_upstream_cancel(&self, pending: &OutboundPendingInvite) -> Result<()> {
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

    async fn send_downstream_cancel(&self, pending: &InboundPendingInvite) -> Result<()> {
        let mut cancel = pending.downstream_request.clone();
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
                pending.downstream_target.clone(),
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
