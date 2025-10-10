use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use ftth_rsipstack::EndpointBuilder;
use ftth_rsipstack::rsip;
use ftth_rsipstack::transaction::Endpoint;
use ftth_rsipstack::transaction::endpoint::MessageInspector;
use ftth_rsipstack::transaction::key::{TransactionKey, TransactionRole};
use ftth_rsipstack::transaction::transaction::Transaction;
use ftth_rsipstack::transport::udp::{UdpConnection, UdpInner};
use ftth_rsipstack::transport::{SipAddr, SipConnection, TransportLayer};
use rsip::common::uri::{
    Scheme, UriWithParams, UriWithParamsList,
    auth::Auth as UriAuth,
    param::{OtherParam, OtherParamValue, Tag},
};
use rsip::headers::auth::{self, AuthQop, Qop};
use rsip::headers::{
    CallId as HeaderCallId, Contact, ContentEncoding, ContentLength as HeaderContentLength,
    ContentType, From as HeaderFrom, Subject, Supported, To as HeaderTo, ToTypedHeader,
    UntypedHeader, Via as HeaderVia,
};
use rsip::message::headers_ext::HeadersExt;
use rsip::typed;
use rsip::{
    Method, Param, Response, SipMessage, StatusCode, StatusCodeKind, Uri,
    host_with_port::HostWithPort, transport::Transport,
};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;

use crate::config::BindConfig;
use crate::error::{Error, Result};
use crate::media::{MediaSessionHandle, MediaSessionKey};
use crate::net::bind_to_device;

use super::builder::ShutdownSignal;
use super::registrar::UpstreamRegistrar;
use super::state::{
    CallContext, InboundPendingInvite, OutboundPendingInvite, PendingInvite, SipContext,
};
use super::utils::{constant_time_eq, md5_hex, strip_rport_param};
use crate::sip::registration::DownstreamRegistration;
use tracing::{debug, error, info, warn};

#[derive(Debug)]
struct ProxyMessageInspector {
    user_agent: String,
}

impl ProxyMessageInspector {
    fn new(user_agent: String) -> Self {
        Self { user_agent }
    }

    fn strip_rport(via: &mut rsip::headers::Via) {
        if let Ok(mut typed) = via.clone().typed() {
            typed.params.retain(|param| {
                !matches!(param, Param::Other(name, _) if name.value().eq_ignore_ascii_case("rport"))
            });
            *via = typed.into();
        }
    }

    fn apply_user_agent(headers: &mut rsip::headers::Headers, value: &str) {
        headers.retain(|header| {
            !matches!(header, rsip::Header::UserAgent(_))
                && !matches!(
                    header,
                    rsip::Header::Other(name, _) if name.eq_ignore_ascii_case("User-Agent")
                )
        });
        headers.push(rsip::Header::UserAgent(rsip::headers::UserAgent::from(
            value.to_string(),
        )));
    }
}

impl MessageInspector for ProxyMessageInspector {
    fn before_send(&self, msg: SipMessage) -> SipMessage {
        match msg {
            SipMessage::Request(mut req) => {
                if let Ok(via) = req.via_header_mut() {
                    Self::strip_rport(via);
                }
                Self::apply_user_agent(&mut req.headers, &self.user_agent);
                SipMessage::Request(req)
            }
            SipMessage::Response(mut res) => {
                Self::apply_user_agent(&mut res.headers, &self.user_agent);
                SipMessage::Response(res)
            }
        }
    }

    fn after_received(&self, msg: SipMessage) -> SipMessage {
        msg
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
    upstream_transport: RwLock<Option<SipConnection>>,
    downstream_transport: RwLock<Option<SipConnection>>,
}

#[derive(Debug, Clone)]
struct InviteIsubRewrite {
    base_user: String,
    isub: String,
}

impl Default for RsipstackBackend {
    fn default() -> Self {
        Self {
            inner: Arc::new(BackendInner {
                endpoint: RwLock::new(None),
                transport_cancel: RwLock::new(CancellationToken::new()),
                registrar: RwLock::new(None),
                upstream_transport: RwLock::new(None),
                downstream_transport: RwLock::new(None),
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

        let (upstream_conn, _upstream_addr, upstream_canonical) =
            create_udp_listener(&context.config.upstream.bind, cancel.child_token()).await?;
        let upstream_transport: SipConnection = upstream_conn.into();
        transport_layer.add_transport(upstream_transport.clone());
        {
            let mut guard = self.inner.upstream_transport.write().await;
            guard.replace(upstream_transport);
        }
        let upstream_listener_addr =
            Self::listener_socket_addr(&context.config.upstream.bind, upstream_canonical);
        *context.sockets.upstream.lock().await = Some(upstream_listener_addr);

        let (downstream_conn, _downstream_addr, downstream_canonical) =
            create_udp_listener(&context.config.downstream.bind, cancel.child_token()).await?;
        let downstream_transport: SipConnection = downstream_conn.into();
        transport_layer.add_transport(downstream_transport.clone());
        {
            let mut guard = self.inner.downstream_transport.write().await;
            guard.replace(downstream_transport);
        }
        let downstream_listener_addr =
            Self::listener_socket_addr(&context.config.downstream.bind, downstream_canonical);
        *context.sockets.downstream.lock().await = Some(downstream_listener_addr);

        let user_agent = context.config.resolved_user_agent();

        let mut endpoint_builder = EndpointBuilder::new();
        endpoint_builder
            .with_cancel_token(cancel.clone())
            .with_transport_layer(transport_layer)
            .with_inspector(Box::new(ProxyMessageInspector::new(user_agent)));
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
            guard.unwrap_or_else(|| context.config.downstream.bind.socket_addr())
        };

        let upstream_listener = {
            let guard = context.sockets.upstream.lock().await;
            guard.unwrap_or_else(|| context.config.upstream.bind.socket_addr())
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
            info!("backend: waiting for next transaction");
            let mut exit_after_iteration = false;

            tokio::select! {
                _ = shutdown.recv() => {
                    endpoint.shutdown();
                    exit_after_iteration = true;
                }
                _ = &mut endpoint_task => {
                    warn!("endpoint serve loop exited");
                    exit_after_iteration = true;
                }
                maybe_tx = incoming.recv() => {
                    match maybe_tx {
                        Some(tx) => {
                            let backend = self.clone();
                            let context_clone = context.clone();
                            tokio::spawn(async move {
                                if let Err(err) = backend
                                    .process_transaction(
                                        context_clone,
                                        tx,
                                        downstream_listener,
                                        upstream_listener,
                                    )
                                    .await
                                {
                                    warn!(error = %err, "failed to process transaction");
                                }
                            });
                        }
                        None => {
                            warn!("Transaction processing terminated");
                            exit_after_iteration = true;
                        },
                    }
                }
            }

            if exit_after_iteration {
                break;
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
        self.inner.upstream_transport.write().await.take();
        self.inner.downstream_transport.write().await.take();
        Ok(())
    }
}
impl RsipstackBackend {
    fn select_identity(
        request: &rsip::Request,
        config: &crate::config::UpstreamConfig,
    ) -> Option<String> {
        if let Some(user) = Self::preferred_identity_user(request, config)
            .filter(|candidate| Self::identity_allowed(candidate, config))
        {
            return Some(user);
        }

        if config.default_identity.is_empty() {
            None
        } else {
            Some(config.default_identity.clone())
        }
    }

    fn identity_allowed(identity: &str, config: &crate::config::UpstreamConfig) -> bool {
        config
            .allowed_identities
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(identity))
            || (!config.default_identity.is_empty()
                && config.default_identity.eq_ignore_ascii_case(identity))
    }

    fn preferred_identity_user(
        request: &rsip::Request,
        upstream_config: &crate::config::UpstreamConfig,
    ) -> Option<String> {
        request.headers.iter().find_map(|header| match header {
            rsip::Header::Other(name, value)
                if name.eq_ignore_ascii_case("P-Preferred-Identity") =>
            {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    return None;
                }

                let without_brackets = trimmed.trim_matches(|c| c == '<' || c == '>');
                if without_brackets.is_empty() {
                    return None;
                }

                if without_brackets.starts_with("tel:") {
                    let user = without_brackets.trim_start_matches("tel:").trim();
                    if user.is_empty() {
                        None
                    } else {
                        Some(user.to_string())
                    }
                } else {
                    let candidate = if without_brackets.starts_with("sip:") {
                        without_brackets.to_string()
                    } else if without_brackets.contains('@') {
                        format!("sip:{}", without_brackets)
                    } else {
                        format!("sip:{}@{}", without_brackets, upstream_config.sip_domain)
                    };

                    Uri::try_from(candidate.as_str())
                        .ok()
                        .and_then(|uri| uri.auth.map(|auth| auth.user))
                }
            }
            _ => None,
        })
    }

    fn detect_invite_isub(uri: &Uri) -> Option<InviteIsubRewrite> {
        let auth = uri.auth.as_ref()?;
        let (base_user, isub) = Self::split_trailing_isub(&auth.user)?;
        Some(InviteIsubRewrite { base_user, isub })
    }

    fn split_trailing_isub(user: &str) -> Option<(String, String)> {
        if let Some((base, suffix)) = Self::split_trailing_isub_with_marker(user, '*', 1) {
            return Some((base, suffix));
        }

        let lower = user.to_ascii_lowercase();
        if let Some(index) = lower.rfind("%2a") {
            return Self::split_trailing_isub_at(user, index, 3);
        }

        None
    }

    fn split_trailing_isub_with_marker(
        user: &str,
        marker: char,
        marker_len: usize,
    ) -> Option<(String, String)> {
        let pos = user.rfind(marker)?;
        Self::split_trailing_isub_at(user, pos, marker_len)
    }

    fn split_trailing_isub_at(
        user: &str,
        marker_index: usize,
        marker_len: usize,
    ) -> Option<(String, String)> {
        let start_suffix = marker_index + marker_len;
        if start_suffix > user.len() {
            return None;
        }
        let suffix = &user[start_suffix..];
        if Self::is_valid_isub_suffix(suffix) {
            let base = user[..marker_index].to_string();
            return Some((base, suffix.to_string()));
        }
        None
    }

    fn is_valid_isub_suffix(suffix: &str) -> bool {
        !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit())
    }

    fn set_isub_param(uri: &mut Uri, value: &str) {
        if value.is_empty() {
            return;
        }

        uri.params.retain(|param| {
            !matches!(param, Param::Other(name, _) if name.value().eq_ignore_ascii_case("isub"))
        });
        uri.params.push(Param::Other(
            OtherParam::from(String::from("isub")),
            Some(OtherParamValue::from(value.to_string())),
        ));
    }

    fn rewrite_uri_with_isub(uri: &mut Uri, rewrite: &InviteIsubRewrite) {
        let Some(auth) = uri.auth.as_mut() else {
            // No user part; nothing to rewrite and we must not attach isub.
            return;
        };

        if let Some((base, _)) = Self::split_trailing_isub(&auth.user) {
            auth.user = base;
        }
        Self::set_isub_param(uri, &rewrite.isub);
    }

    fn find_isub_param(uri: &Uri) -> Option<String> {
        uri.params.iter().find_map(|param| match param {
            Param::Other(name, Some(value)) if name.value().eq_ignore_ascii_case("isub") => {
                Some(value.value().to_string())
            }
            _ => None,
        })
    }

    fn parse_p_called_party_uri(value: &str) -> Option<Uri> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return None;
        }

        let inner = trimmed.trim_matches(|c| c == '<' || c == '>');
        if inner.is_empty() {
            return None;
        }

        Uri::try_from(inner).ok()
    }

    fn build_default_called_party_uri(
        upstream_config: &crate::config::UpstreamConfig,
    ) -> Option<Uri> {
        if upstream_config.default_identity.is_empty() {
            return None;
        }

        let value = format!(
            "sip:{}@{}",
            upstream_config.default_identity, upstream_config.sip_domain
        );
        Uri::try_from(value.as_str()).ok()
    }

    fn prepare_upstream_request(
        endpoint: &Endpoint,
        upstream_listener: SocketAddr,
        upstream_config: &crate::config::UpstreamConfig,
        original: &rsip::Request,
        body_override: Option<Vec<u8>>,
        identity: &str,
        route_set: &[UriWithParams],
        invite_isub: Option<&InviteIsubRewrite>,
        upstream_local_tag: &Tag,
        upstream_remote_tag: Option<&Tag>,
        target_contact: Option<&Uri>,
        dialog_uri: Option<&Uri>,
    ) -> Result<rsip::Request> {
        let mut request = original.clone();

        if let Some(body) = body_override {
            request.body = body;
        }

        request.headers.retain(|header| {
            !matches!(
                header,
                rsip::Header::Route(_) | rsip::Header::RecordRoute(_)
            )
        });
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
            !matches!(
                header,
                rsip::Header::Route(_) | rsip::Header::RecordRoute(_)
            )
        });
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
        let to_host_with_port = host_with_port.clone();

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
        let mut via = endpoint
            .inner
            .get_via(Some(via_addr.clone()), None)
            .map_err(Error::sip_stack)?;
        strip_rport_param(&mut via);
        request.headers.unique_push(rsip::Header::Via(via.into()));

        let identity_uri_string = format!("sip:{}@{}", identity, upstream_config.sip_domain);
        let identity_uri = Uri::try_from(identity_uri_string.as_str()).map_err(Error::sip_stack)?;

        let mut typed_to = original
            .to_header()
            .ok()
            .and_then(|header| header.typed().ok());
        if let Some(to_header) = typed_to.as_mut() {
            to_header.uri.host_with_port = to_host_with_port.clone();
            if let Some(dialog_uri) = dialog_uri {
                to_header.uri.auth = dialog_uri.auth.clone();
                to_header.uri.params = dialog_uri.params.clone();
            }
            if let Some(rewrite) = invite_isub {
                Self::rewrite_uri_with_isub(&mut to_header.uri, rewrite);
            }
            if let Some(tag_value) = upstream_remote_tag {
                to_header
                    .params
                    .retain(|param| !matches!(param, Param::Tag(_)));
                to_header.params.push(Param::Tag(tag_value.clone()));
            }
        }

        let mut typed_from = if request.method == Method::Invite {
            if let Some(to_header) = typed_to.as_ref() {
                typed::From {
                    display_name: to_header.display_name.clone(),
                    uri: to_header.uri.clone(),
                    params: to_header.params.clone(),
                }
            } else {
                typed::From {
                    display_name: None,
                    uri: request.uri.clone(),
                    params: Vec::new(),
                }
            }
        } else {
            typed::From {
                display_name: None,
                uri: identity_uri.clone(),
                params: Vec::new(),
            }
        };
        typed_from
            .params
            .retain(|param| !matches!(param, Param::Tag(_)));
        typed_from
            .params
            .push(Param::Tag(upstream_local_tag.clone()));
        request
            .headers
            .unique_push(rsip::Header::From(typed_from.into()));

        if let Some(to_header) = typed_to {
            request
                .headers
                .unique_push(rsip::Header::To(to_header.into()));
        }

        let mut request_uri = if let Some(contact) = target_contact {
            contact.clone()
        } else {
            let mut uri = request.uri.clone();
            if let Some(dialog_uri) = dialog_uri {
                uri.auth = dialog_uri.auth.clone();
                uri.params = dialog_uri.params.clone();
            }
            uri.host_with_port = host_with_port.clone();
            uri
        };
        if let Some(rewrite) = invite_isub {
            Self::rewrite_uri_with_isub(&mut request_uri, rewrite);
        }
        request.uri = request_uri;

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
        let contact_uri =
            Uri::try_from(format!("sip:{}:{}", contact_ip, contact_port).as_str())
                .map_err(Error::sip_stack)?;

        let contact_header = Contact::from(format!("<{}>", contact_uri));
        request
            .headers
            .unique_push(rsip::Header::Contact(contact_header));

        if request.method == Method::Invite {
            let preferred_user = Self::preferred_identity_user(original, upstream_config)
                .filter(|user| Self::identity_allowed(user, upstream_config))
                .unwrap_or_else(|| identity.to_string());

            let p_preferred = format!("<sip:{}@{}>", preferred_user, upstream_config.sip_domain);

            request.headers.retain(|header| {
                !matches!(header, rsip::Header::Other(name, _) if name.eq_ignore_ascii_case("P-Preferred-Identity"))
            });
            request.headers.push(rsip::Header::Other(
                "P-Preferred-Identity".into(),
                p_preferred.clone(),
            ));

            if !route_set.is_empty() {
                let route_value = UriWithParamsList::from(route_set.to_vec()).to_string();
                request
                    .headers
                    .unique_push(rsip::Header::Route(rsip::headers::Route::from(route_value)));
            }

            request
                .headers
                .retain(|header| !matches!(header, rsip::Header::MaxForwards(_)));
            request
                .headers
                .push(rsip::Header::MaxForwards(rsip::headers::MaxForwards::from(
                    70u32,
                )));

            request
                .headers
                .retain(|header| !matches!(header, rsip::Header::Supported(_)));
            request
                .headers
                .unique_push(rsip::Header::Supported(Supported::new(
                    "100rel, timer".to_string(),
                )));
            request.headers.retain(|header| {
                !matches!(header, rsip::Header::Other(name, _) if name.eq_ignore_ascii_case("Allow"))
            });
            request.headers.push(rsip::Header::Other(
                "Allow".into(),
                "INVITE, CANCEL, ACK, BYE, PRACK, UPDATE".into(),
            ));
            request.headers.retain(|header| {
                !matches!(header, rsip::Header::Other(name, _) if name.eq_ignore_ascii_case("Session-Expires"))
            });
            request
                .headers
                .push(rsip::Header::Other("Session-Expires".into(), "300".into()));
            request.headers.retain(|header| {
                !matches!(header, rsip::Header::Other(name, _) if name.eq_ignore_ascii_case("Min-SE"))
            });
            request
                .headers
                .push(rsip::Header::Other("Min-SE".into(), "300".into()));
        } else {
            if !route_set.is_empty() {
                let route_value = UriWithParamsList::from(route_set.to_vec()).to_string();
                request
                    .headers
                    .unique_push(rsip::Header::Route(rsip::headers::Route::from(route_value)));
            }

            request
                .headers
                .retain(|header| !matches!(header, rsip::Header::MaxForwards(_)));
            request
                .headers
                .push(rsip::Header::MaxForwards(rsip::headers::MaxForwards::from(
                    70u32,
                )));

            if request.method == Method::Update {
                request
                    .headers
                    .retain(|header| !matches!(header, rsip::Header::Supported(_)));
                request.headers.retain(|header| {
                    !matches!(
                        header,
                        rsip::Header::Other(name, _)
                            if name.eq_ignore_ascii_case("Supported")
                    )
                });
                request
                    .headers
                    .unique_push(rsip::Header::Supported(Supported::new("timer".to_string())));

                request.headers.retain(|header| {
                    !matches!(
                        header,
                        rsip::Header::Other(name, _)
                            if name.eq_ignore_ascii_case("Session-Expires")
                    )
                });
                request.headers.push(rsip::Header::Other(
                    "Session-Expires".into(),
                    "300;refresher=uac".into(),
                ));
            }
        }

        Ok(request)
    }

    fn extract_upstream_from_tag(request: &rsip::Request) -> Option<Tag> {
        request
            .from_header()
            .ok()
            .and_then(|header| header.tag().ok().flatten())
    }

    fn registration_expiry_seconds(
        request: &rsip::Request,
        contact: &typed::Contact,
        default_expires: u64,
    ) -> u64 {
        if let Some(contact_expires) = contact.expires().and_then(|expires| expires.seconds().ok())
        {
            contact_expires as u64
        } else if let Some(expires_header) = request.expires_header() {
            expires_header
                .seconds()
                .map(|value| value as u64)
                .unwrap_or(default_expires)
        } else {
            default_expires
        }
    }

    pub(super) fn build_trunk_target(upstream_config: &crate::config::UpstreamConfig) -> SipAddr {
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

    pub(super) fn expand_compact_headers(headers: &mut rsip::Headers) {
        use std::mem;

        let mut collected: Vec<rsip::Header> = mem::take(headers).into();
        for header in collected.iter_mut() {
            if let rsip::Header::Other(name, value) = header {
                if let Some(expanded) = Self::expand_compact_header(name, value) {
                    *header = expanded;
                }
            }
        }
        *headers = collected.into();
    }

    fn expand_compact_header(name: &str, value: &str) -> Option<rsip::Header> {
        match name.to_ascii_lowercase().as_str() {
            "f" => Some(rsip::Header::From(HeaderFrom::new(value.to_string()))),
            "t" => Some(rsip::Header::To(HeaderTo::new(value.to_string()))),
            "i" => Some(rsip::Header::CallId(HeaderCallId::new(value.to_string()))),
            "m" => Some(rsip::Header::Contact(Contact::new(value.to_string()))),
            "v" => Some(rsip::Header::Via(HeaderVia::new(value.to_string()))),
            "l" => Some(rsip::Header::ContentLength(HeaderContentLength::new(
                value.to_string(),
            ))),
            "c" => Some(rsip::Header::ContentType(ContentType::new(
                value.to_string(),
            ))),
            "e" => Some(rsip::Header::ContentEncoding(ContentEncoding::new(
                value.to_string(),
            ))),
            "k" => Some(rsip::Header::Supported(Supported::new(value.to_string()))),
            "s" => Some(rsip::Header::Subject(Subject::new(value.to_string()))),
            _ => None,
        }
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
        strip_user: bool,
        default_user: Option<&str>,
        fallback_p_called_party: Option<Uri>,
    ) -> Result<rsip::Request> {
        let mut request = original.clone();

        let is_invite = original.method == Method::Invite;
        let p_called_party_value = if is_invite {
            original.headers.iter().find_map(|header| match header {
                rsip::Header::Other(name, value)
                    if name.eq_ignore_ascii_case("P-Called-Party-ID") =>
                {
                    Some(value.clone())
                }
                _ => None,
            })
        } else {
            None
        };

        let p_called_party_uri = p_called_party_value
            .as_deref()
            .and_then(Self::parse_p_called_party_uri);

        let fallback_isub = if is_invite {
            fallback_p_called_party
                .as_ref()
                .and_then(|uri| Self::find_isub_param(uri))
        } else {
            None
        };
        let p_called_party_isub = if is_invite {
            p_called_party_uri
                .as_ref()
                .and_then(|uri| Self::find_isub_param(uri))
        } else {
            None
        };
        let p_called_party_user = if is_invite {
            p_called_party_uri
                .as_ref()
                .and_then(|uri| uri.auth.as_ref().map(|auth| auth.user.clone()))
        } else {
            None
        };
        let request_uri_isub = if is_invite {
            Self::find_isub_param(&original.uri)
        } else {
            None
        };
        let to_header_user = if is_invite {
            original
                .to_header()
                .ok()
                .and_then(|header| header.typed().ok())
                .and_then(|typed| typed.uri.auth.map(|auth| auth.user))
        } else {
            None
        };
        let to_header_isub = if is_invite {
            original
                .to_header()
                .ok()
                .and_then(|header| header.typed().ok())
                .and_then(|typed| Self::find_isub_param(&typed.uri))
        } else {
            None
        };
        let invite_isub = if is_invite {
            if strip_user {
                p_called_party_isub
                    .clone()
                    .or(to_header_isub.clone())
                    .or(request_uri_isub.clone())
                    .or(fallback_isub.clone())
            } else {
                p_called_party_isub
                    .clone()
                    .or(to_header_isub.clone())
                    .or(request_uri_isub.clone())
                    .or(fallback_isub.clone())
            }
        } else {
            None
        };
        let target_user = if strip_user {
            p_called_party_user
                .clone()
                .or(to_header_user.clone())
                .or_else(|| default_user.map(|user| user.to_string()))
        } else {
            None
        };

        if let Some(body) = body_override {
            request.body = body;
        }

        request
            .headers
            .retain(|header| !matches!(header, rsip::Header::Route(_)));

        let original_uri = request.uri.clone();

        let content_length = request.body.len() as u32;
        request.headers.unique_push(rsip::Header::ContentLength(
            rsip::headers::ContentLength::from(content_length),
        ));

        request
            .headers
            .retain(|header| !matches!(header, rsip::Header::Via(_)));

        let mut target_uri = if let Some(contact_uri) = &call.downstream_contact {
            contact_uri.clone()
        } else {
            let mut uri = request.uri.clone();
            uri.host_with_port = call.downstream_target.addr.clone();
            uri
        };
        if strip_user {
            if let Some(user) = target_user.as_ref() {
                target_uri.auth = Some(UriAuth::from((user.as_str(), Option::<String>::None)));
            }
        }

        if is_invite {
            if let Some(isub) = invite_isub.as_ref() {
                Self::set_isub_param(&mut target_uri, isub);
            }
        }
        request.uri = target_uri;

        if is_invite {
            if let Some(isub) = invite_isub.as_ref() {
                if let Ok(header_to) = request.to_header() {
                    if let Ok(mut typed_to) = header_to.typed() {
                        Self::set_isub_param(&mut typed_to.uri, isub);
                        request
                            .headers
                            .retain(|header| !matches!(header, rsip::Header::To(_)));
                        request.headers.push(rsip::Header::To(typed_to.into()));
                    }
                }
            }
        }

        let original_uri_string = original_uri.to_string();
        let has_original_uri_header = request.headers.iter().any(|header| match header {
            rsip::Header::Other(name, _) => name.eq_ignore_ascii_case("X-Ftth-Original-Uri"),
            _ => false,
        });
        if !has_original_uri_header {
            request.headers.push(rsip::Header::Other(
                "X-Ftth-Original-Uri".into(),
                original_uri_string.clone(),
            ));
        }

        let has_p_called_party = request.headers.iter().any(|header| match header {
            rsip::Header::Other(name, _) => name.eq_ignore_ascii_case("P-Called-Party-ID"),
            _ => false,
        });
        if !has_p_called_party {
            if let Some(uri) = fallback_p_called_party.as_ref() {
                request.headers.push(rsip::Header::Other(
                    "P-Called-Party-ID".into(),
                    format!("<{}>", uri),
                ));
            }
        }

        let contact_user = if strip_user {
            target_user.as_deref().unwrap_or_else(|| {
                if call.identity.is_empty() {
                    "proxy"
                } else {
                    call.identity.as_str()
                }
            })
        } else if call.identity.is_empty() {
            "proxy"
        } else {
            call.identity.as_str()
        };

        if !downstream_listener.ip().is_unspecified() {
            let mut contact_uri = Uri::from(downstream_listener);
            contact_uri.scheme = Some(Scheme::Sip);
            contact_uri.auth = Some(UriAuth::from((contact_user, Option::<String>::None)));
            request
                .headers
                .retain(|header| !matches!(header, rsip::Header::Contact(_)));
            request
                .headers
                .unique_push(rsip::Header::Contact(Contact::from(format!(
                    "<{}>",
                    contact_uri
                ))));
        }

        if let Some(local_tag) = call.downstream_local_tag.as_ref() {
            if let Some(mut typed_to) = request
                .to_header()
                .ok()
                .and_then(|header| header.typed().ok())
            {
                typed_to
                    .params
                    .retain(|param| !matches!(param, Param::Tag(_)));
                typed_to.params.push(Param::Tag(local_tag.clone()));
                request
                    .headers
                    .retain(|header| !matches!(header, rsip::Header::To(_)));
                request.headers.push(rsip::Header::To(typed_to.into()));
            }
        }

        let mut via_addr: SipAddr = downstream_listener.into();
        via_addr.r#type = Some(Transport::Udp);
        let mut via = endpoint
            .inner
            .get_via(Some(via_addr.clone()), None)
            .map_err(Error::sip_stack)?;
        strip_rport_param(&mut via);
        request.headers.unique_push(rsip::Header::Via(via.into()));

        let max_forwards = request
            .max_forwards_header()
            .ok()
            .and_then(|mf| mf.num().ok())
            .and_then(|value| value.checked_sub(1))
            .unwrap_or(70);
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

    fn listener_socket_addr(bind: &BindConfig, canonical: SocketAddr) -> SocketAddr {
        let ip = if bind.address.is_unspecified() {
            match canonical {
                SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            }
        } else {
            bind.address
        };
        SocketAddr::new(ip, canonical.port())
    }

    fn listener_matches(local: SocketAddr, listener: SocketAddr) -> bool {
        if local.port() != listener.port() {
            return false;
        }
        match listener.ip() {
            IpAddr::V4(ip) if ip.is_unspecified() => true,
            IpAddr::V6(ip) if ip.is_unspecified() => true,
            _ => local.ip() == listener.ip(),
        }
    }

    async fn start_client_transaction(
        &self,
        endpoint: Arc<Endpoint>,
        mut request: rsip::Request,
        target: SipAddr,
        binding: ClientTarget,
    ) -> Result<Transaction> {
        if matches!(binding, ClientTarget::Downstream) {
            request.headers.retain(|header| {
                !matches!(
                    header,
                    rsip::Header::Route(_) | rsip::Header::RecordRoute(_)
                )
            });
        }
        let key = TransactionKey::from_request(&request, TransactionRole::Client)
            .map_err(Error::sip_stack)?;
        let connection = match binding {
            ClientTarget::Upstream => {
                let guard = self.inner.upstream_transport.read().await;
                guard.clone()
            }
            ClientTarget::Downstream => {
                let guard = self.inner.downstream_transport.read().await;
                guard.clone()
            }
        }
        .ok_or_else(|| Error::configuration("requested transport binding not available"))?;

        let mut tx =
            Transaction::new_client(key, request, endpoint.inner.clone(), Some(connection));
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

                let invite_isub = Self::detect_invite_isub(&tx.original.uri);
                if let Some(rewrite) = invite_isub.as_ref() {
                    if rewrite.base_user.is_empty() {
                        tx.reply(StatusCode::NotFound)
                            .await
                            .map_err(Error::sip_stack)?;
                        return Ok(());
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
                        .unwrap_or_else(|| context.config.upstream.bind.socket_addr())
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

                let route_set = { context.route_set.read().await.clone() };

                let target_contact = call
                    .upstream_contact
                    .clone()
                    .or_else(|| Some(call.upstream_request_uri.clone()));

                let upstream_request = Self::prepare_upstream_request(
                    &endpoint,
                    upstream_listener,
                    &config.upstream,
                    &tx.original,
                    body_override,
                    &call.identity,
                    &route_set,
                    invite_isub.as_ref(),
                    &call.upstream_local_tag,
                    call.upstream_remote_tag.as_ref(),
                    target_contact.as_ref(),
                    Some(&call.upstream_dialog_uri),
                )?;

                let mut client_tx = self
                    .start_client_transaction(
                        endpoint,
                        upstream_request,
                        call.upstream_target.clone(),
                        ClientTarget::Upstream,
                    )
                    .await?;

                let mut responded = false;
                let mut new_upstream_contact = call.upstream_contact.clone();
                while let Some(message) = client_tx.receive().await {
                    match message {
                        SipMessage::Response(mut response) => {
                            Self::expand_compact_headers(&mut response.headers);
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
                                if let Some(contact) = new_upstream_contact.clone() {
                                    call.upstream_request_uri = contact.clone();
                                    call.upstream_contact = Some(contact);
                                } else {
                                    call.upstream_contact = None;
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
            TransactionDirection::Upstream => {
                if let Some(tag) = Self::extract_upstream_from_tag(&tx.original) {
                    call.upstream_remote_tag = Some(tag);
                }
                call.upstream_dialog_uri = tx.original.to_header().cloned().ok().map(|h| h.uri().ok()).flatten().unwrap_or(tx.original.uri.clone());
                if let Some(contact) = tx
                    .original
                    .contact_header()
                    .ok()
                    .and_then(|header| header.typed().ok().map(|typed| typed.uri))
                {
                    call.upstream_request_uri = contact.clone();
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
                        .unwrap_or_else(|| context.config.downstream.bind.socket_addr())
                };
                let default_user = context.config.downstream.default_user.as_deref();
                let fallback_p_called_party =
                    Self::build_default_called_party_uri(&context.config.upstream);

                let downstream_request = Self::prepare_downstream_request(
                    &endpoint,
                    downstream_listener,
                    &call,
                    &tx.original,
                    body_override,
                    false,
                    default_user,
                    fallback_p_called_party,
                )?;

                let mut client_tx = self
                    .start_client_transaction(
                        endpoint,
                        downstream_request,
                        call.downstream_target.clone(),
                        ClientTarget::Downstream,
                    )
                    .await?;

                let mut responded = false;
                let mut new_downstream_contact = call.downstream_contact.clone();
                while let Some(message) = client_tx.receive().await {
                    match message {
                        SipMessage::Response(mut response) => {
                            Self::expand_compact_headers(&mut response.headers);
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

    fn replace_top_via(headers: &mut rsip::Headers, via: rsip::headers::Via) {
        for header in headers.iter_mut() {
            if matches!(header, rsip::Header::Via(_)) {
                *header = rsip::Header::Via(via);
                return;
            }
        }
        headers.push(rsip::Header::Via(via));
    }

    fn rewrite_contact_for_downstream(
        headers: &mut rsip::Headers,
        listener: SocketAddr,
        default_user: Option<&str>,
    ) {
        let mut uri = Uri::from(listener);
        uri.scheme = Some(Scheme::Sip);

        let mut ensure_user = |existing_auth: Option<UriAuth>| {
            if let Some(auth) = existing_auth {
                uri.auth = Some(auth);
            } else if let Some(user) = default_user {
                uri.auth = Some(UriAuth::from((user, Option::<String>::None)));
            }
        };

        if let Some(contact) = headers.iter_mut().find_map(|header| match header {
            rsip::Header::Contact(c) => Some(c),
            _ => None,
        }) {
            if let Ok(mut typed) = contact.clone().typed() {
                let existing_auth = typed.uri.auth.clone();
                ensure_user(existing_auth);
                typed.uri = uri;
                *contact = typed.into();
            } else {
                ensure_user(None);
                *contact = Contact::from(format!("<{}>", uri));
            }
        } else {
            ensure_user(None);
            headers.push(rsip::Header::Contact(Contact::from(format!("<{}>", uri))));
        }
    }

    async fn forward_upstream_responses(
        &self,
        mut client_tx: Transaction,
        downstream_tx: Arc<Mutex<Transaction>>,
        media_session: MediaSessionHandle,
        cancel_token: CancellationToken,
        context: SipContext,
        call_id: String,
    ) -> Result<(
        Option<StatusCode>,
        Option<Response>,
        Option<Uri>,
        Option<Tag>,
    )> {
        let mut final_status: Option<StatusCode> = None;
        let mut final_response: Option<Response> = None;
        let mut final_remote_contact: Option<Uri> = None;
        let mut final_remote_tag: Option<Tag> = None;

        let downstream_listener = {
            let guard = context.sockets.downstream.lock().await;
            guard.unwrap_or_else(|| context.config.downstream.bind.socket_addr())
        };
        let default_user = context.config.downstream.default_user.as_deref();

        loop {
            tokio::select! {
                _ = cancel_token.cancelled() => {
                    break;
                }
                maybe_message = client_tx.receive() => {
                    match maybe_message {
                        Some(SipMessage::Response(mut upstream_response)) => {
                            let raw_contact = upstream_response
                                .contact_header()
                                .ok()
                                .and_then(|header| header.typed().ok().map(|typed| typed.uri));
                            let raw_remote_tag = upstream_response
                                .to_header()
                                .ok()
                                .and_then(|header| header.tag().ok().flatten())
                                .or_else(|| {
                                    upstream_response
                                        .from_header()
                                        .ok()
                                        .and_then(|header| header.tag().ok().flatten())
                                });
                            Self::expand_compact_headers(&mut upstream_response.headers);
                            upstream_response.headers.retain(|header| {
                                !matches!(
                                    header,
                                    rsip::Header::Route(_) | rsip::Header::RecordRoute(_)
                                )
                            });
                            let status_kind = upstream_response.status_code.kind();
                            if raw_remote_tag.is_some()
                                || (matches!(status_kind, StatusCodeKind::Successful)
                                    && raw_contact.is_some())
                            {
                                let mut pending_guard = context.pending.write().await;
                                if let Some(PendingInvite::Outbound(pending)) =
                                    pending_guard.get_mut(&call_id)
                                {
                                    if let Some(tag) = raw_remote_tag.clone() {
                                        pending.upstream_remote_tag = Some(tag);
                                    }
                                    if matches!(status_kind, StatusCodeKind::Successful) {
                                        if let Some(contact) = raw_contact.clone() {
                                            pending.upstream_request_uri = contact;
                                        }
                                    }
                                }
                            }

                            Self::rewrite_contact_for_downstream(
                                &mut upstream_response.headers,
                                downstream_listener,
                                default_user,
                            );
                            let downstream_via = {
                                let guard = downstream_tx.lock().await;
                                guard
                                    .original
                                    .via_header()
                                    .map_err(Error::sip_stack)?
                                    .clone()
                            };
                            Self::replace_top_via(&mut upstream_response.headers, downstream_via);
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
                                    final_remote_contact = raw_contact;
                                    final_remote_tag = raw_remote_tag;
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

        Ok((
            final_status,
            final_response,
            final_remote_contact,
            final_remote_tag,
        ))
    }

    async fn forward_downstream_responses(
        &self,
        mut client_tx: Transaction,
        upstream_tx: Arc<Mutex<Transaction>>,
        media_session: MediaSessionHandle,
        cancel_token: CancellationToken,
        upstream_local_tag: Tag,
        upstream_remote_tag: Option<Tag>,
        upstream_local_user: String,
    ) -> Result<(Option<StatusCode>, Option<Response>, Option<Tag>)> {
        let mut final_status: Option<StatusCode> = None;
        let mut final_response: Option<Response> = None;
        let mut final_downstream_tag: Option<Tag> = None;

        loop {
            tokio::select! {
                _ = cancel_token.cancelled() => {
                    break;
                }
                maybe_message = client_tx.receive() => {
                    match maybe_message {
                        Some(SipMessage::Response(mut downstream_response)) => {
                            let original_to_tag = downstream_response
                                .to_header()
                                .ok()
                                .and_then(|header| header.tag().ok().flatten());

                            Self::expand_compact_headers(&mut downstream_response.headers);
                            downstream_response.headers.retain(|header| {
                                !matches!(
                                    header,
                                    rsip::Header::Route(_) | rsip::Header::RecordRoute(_)
                                )
                            });
                            let upstream_via = {
                                let guard = upstream_tx.lock().await;
                                guard
                                    .original
                                    .via_header()
                                    .map_err(Error::sip_stack)?
                                    .clone()
                            };
                            Self::replace_top_via(&mut downstream_response.headers, upstream_via);

                            // Ensure dialog tags on the upstream leg stay consistent.
                            if let Some(mut typed_to) = downstream_response
                                .to_header()
                                .ok()
                                .and_then(|header| header.typed().ok())
                            {
                                if let Some(auth) = typed_to.uri.auth.as_mut() {
                                    auth.user = upstream_local_user.clone();
                                } else {
                                    typed_to.uri.auth = Some(UriAuth::from((
                                        upstream_local_user.clone(),
                                        Option::<String>::None,
                                    )));
                                }
                                typed_to
                                    .params
                                    .retain(|param| !matches!(param, Param::Tag(_)));
                                typed_to
                                    .params
                                    .push(Param::Tag(upstream_local_tag.clone()));
                                downstream_response.headers.retain(|header| {
                                    !matches!(header, rsip::Header::To(_))
                                });
                                downstream_response
                                    .headers
                                    .push(rsip::Header::To(typed_to.into()));
                            }

                            if let Some(tag) = upstream_remote_tag.as_ref() {
                                if let Some(mut typed_from) = downstream_response
                                    .from_header()
                                    .ok()
                                    .and_then(|header| header.typed().ok())
                                {
                                    typed_from
                                        .params
                                        .retain(|param| !matches!(param, Param::Tag(_)));
                                    typed_from.params.push(Param::Tag(tag.clone()));
                                    downstream_response.headers.retain(|header| {
                                        !matches!(header, rsip::Header::From(_))
                                    });
                                    downstream_response
                                        .headers
                                        .push(rsip::Header::From(typed_from.into()));
                                }
                            }

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
                                    if downstream_response.status_code == StatusCode::NotFound {
                                        debug!(
                                            status = %downstream_response.status_code,
                                            "downstream returned 404 Not Found for call"
                                        );
                                    }
                                    final_status = Some(downstream_response.status_code.clone());
                                    final_response = Some(downstream_response);
                                    final_downstream_tag = original_to_tag;
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

        Ok((final_status, final_response, final_downstream_tag))
    }

    async fn finalize_invite_result(
        &self,
        context: SipContext,
        call_id: String,
        result: Result<(
            Option<StatusCode>,
            Option<Response>,
            Option<Uri>,
            Option<Tag>,
        )>,
    ) {
        let pending_entry = context.pending.write().await.remove(&call_id);
        let Some(pending_entry) = pending_entry else {
            return;
        };

        match pending_entry {
            PendingInvite::Outbound(pending) => {
                pending.cancel_token.cancel();
                match result {
                    Ok((Some(status), Some(_response), remote_contact, remote_tag))
                        if matches!(status.kind(), StatusCodeKind::Successful) =>
                    {
                        let upstream_contact_uri = remote_contact;
                        let upstream_remote_tag =
                            remote_tag.or_else(|| pending.upstream_remote_tag.clone());

                        let upstream_contact = upstream_contact_uri
                            .unwrap_or_else(|| pending.upstream_request_uri.clone());

                        context.calls.write().await.insert(
                            call_id,
                            CallContext {
                                media: pending.media,
                                media_key: pending.media_key,
                                upstream_target: pending.upstream_target,
                                upstream_contact: Some(upstream_contact.clone()),
                                downstream_contact: pending.downstream_contact,
                                upstream_local_tag: pending.upstream_local_tag,
                                upstream_remote_tag,
                                downstream_target: pending.downstream_target,
                                downstream_local_tag: pending.downstream_local_tag.clone(),
                                upstream_request_uri: upstream_contact,
                                upstream_dialog_uri: pending.upstream_dialog_uri.clone(),
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
        result: Result<(Option<StatusCode>, Option<Response>, Option<Tag>)>,
    ) {
        let pending_entry = context.pending.write().await.remove(&call_id);
        let Some(PendingInvite::Inbound(pending)) = pending_entry else {
            return;
        };

        pending.cancel_token.cancel();

        let mut refresh_registration = false;

        match result {
            Ok((Some(status), Some(response), downstream_tag))
                if matches!(status.kind(), StatusCodeKind::Successful) =>
            {
                let downstream_contact = response
                    .contact_header()
                    .ok()
                    .and_then(|header| header.typed().ok().map(|typed| typed.uri))
                    .or_else(|| pending.downstream_contact.clone())
                    .or_else(|| Some(pending.downstream_request.uri.clone()));
                let downstream_target = downstream_contact
                    .as_ref()
                    .and_then(|uri| Self::sip_addr_from_uri(uri).ok())
                    .unwrap_or_else(|| pending.downstream_target.clone());

                let downstream_local_tag =
                    downstream_tag.or_else(|| pending.downstream_local_tag.clone());

                let upstream_contact = pending
                    .upstream_request
                    .contact_header()
                    .ok()
                    .and_then(|header| header.typed().ok().map(|typed| typed.uri));

                let upstream_remote_tag = response
                    .from_header()
                    .ok()
                    .and_then(|from| from.tag().ok().flatten())
                    .or_else(|| {
                        response
                            .to_header()
                            .ok()
                            .and_then(|to| to.tag().ok().flatten())
                    })
                    .or_else(|| pending.upstream_remote_tag.clone());

                let upstream_contact =
                    upstream_contact.unwrap_or_else(|| pending.upstream_request_uri.clone());

                context.calls.write().await.insert(
                    call_id,
                    CallContext {
                        media: pending.media,
                        media_key: pending.media_key,
                        upstream_target: Self::build_trunk_target(&context.config.upstream),
                        upstream_contact: Some(upstream_contact.clone()),
                        downstream_contact,
                        upstream_local_tag: pending.upstream_local_tag,
                        upstream_remote_tag,
                        downstream_target,
                        downstream_local_tag,
                        upstream_request_uri: upstream_contact,
                        upstream_dialog_uri: pending.upstream_dialog_uri.clone(),
                        identity: pending.identity,
                    },
                );
            }
            Ok(_) => {
                context.media.release(&pending.media_key).await;
                refresh_registration = true;
            }
            Err(err) => {
                warn!(error = %err, "inbound invite forwarding task failed");
                let mut guard = pending.upstream_tx.lock().await;
                if let Err(reply_err) = guard.reply(StatusCode::ServerInternalError).await {
                    warn!(error = %reply_err, "failed to notify upstream about INVITE failure");
                }
                context.media.release(&pending.media_key).await;
                refresh_registration = true;
            }
        }

        if refresh_registration {
            self.trigger_registration_refresh().await;
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

        Self::expand_compact_headers(&mut tx.original.headers);

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
        .or_else(|err| {
            if Self::is_transaction_already_terminated(&err) {
                debug!(error = %err, "transaction already terminated; treating as handled");
                Ok(())
            } else {
                Err(err)
            }
        })
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

        if Self::listener_matches(local_addr, downstream_listener) {
            Ok(TransactionDirection::Downstream)
        } else if Self::listener_matches(local_addr, upstream_listener) {
            Ok(TransactionDirection::Upstream)
        } else {
            Err(Error::Media(format!(
                "transaction arrived on unknown local address {local_addr}"
            )))
        }
    }

    fn is_transaction_already_terminated(err: &Error) -> bool {
        matches!(
            err,
            Error::SipStack(msg)
            if msg.contains("invalid state transition")
                && msg.contains("Terminated")
        )
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

        let contact = tx
            .original
            .contact_header()
            .map_err(Error::sip_stack)?
            .typed()
            .map_err(Error::sip_stack)?;

        let via_header = tx.original.via_header().map_err(Error::sip_stack)?;
        let remote_addr = resolve_remote_from_via(via_header).map_err(Error::Media)?;

        let default_expires = context.config.timers.registration_refresh_secs;
        let expires_secs =
            Self::registration_expiry_seconds(&tx.original, &contact, default_expires);

        if expires_secs == 0 {
            debug!(
                source = %remote_addr,
                "clearing downstream registration after expires=0 request"
            );
            context.registrations.write().await.clear();
            tx.reply(StatusCode::OK).await.map_err(Error::sip_stack)?;
            return Ok(());
        }

        let existing_registration = {
            let guard = context.registrations.read().await;
            guard.get().cloned()
        };

        let now = Instant::now();
        let registration = DownstreamRegistration {
            contact,
            registered_at: now,
            expires_in: Duration::from_secs(expires_secs),
            source: remote_addr,
        };

        let should_trigger_refresh = existing_registration
            .as_ref()
            .map(|existing| {
                let contact_changed =
                    existing.contact.to_string() != registration.contact.to_string();
                let source_changed = existing.source != registration.source;
                let registration_lapsed = !existing.is_active(now);
                contact_changed || source_changed || registration_lapsed
            })
            .unwrap_or(true);

        context
            .registrations
            .write()
            .await
            .upsert(registration.clone());

        debug!(
            contact = %registration.contact.uri,
            expires = expires_secs,
            source = %registration.source,
            "updated downstream registration"
        );

        tx.reply(StatusCode::OK).await.map_err(Error::sip_stack)?;

        if should_trigger_refresh {
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
                headers.push(rsip::Header::Contact(Contact::from(
                    registration.contact.to_string(),
                )));
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

                let invite_isub = Self::detect_invite_isub(&tx.original.uri);
                if let Some(rewrite) = invite_isub.as_ref() {
                    if rewrite.base_user.is_empty() {
                        tx.reply(StatusCode::NotFound)
                            .await
                            .map_err(Error::sip_stack)?;
                        return Ok(());
                    }
                }

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

                let downstream_local_tag = original_request
                    .from_header()
                    .ok()
                    .and_then(|header| header.tag().ok().flatten());

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
                        .unwrap_or_else(|| context.config.upstream.bind.socket_addr())
                };

                let config = context.config.as_ref();
                let route_set = { context.route_set.read().await.clone() };
                let upstream_local_tag = Tag::default();
                let upstream_request = Self::prepare_upstream_request(
                    &endpoint,
                    upstream_listener,
                    &config.upstream,
                    &original_request,
                    rewritten_body,
                    &identity,
                    &route_set,
                    invite_isub.as_ref(),
                    &upstream_local_tag,
                    None,
                    None,
                    Some(&original_request.uri),
                )?;

                let target = Self::build_trunk_target(&config.upstream);
                let upstream_request_clone = upstream_request.clone();
                let upstream_dialog_uri = upstream_request_clone.uri.clone();
                let upstream_request_uri = upstream_request_clone.uri.clone();
                let client_tx = match self
                    .start_client_transaction(
                        endpoint.clone(),
                        upstream_request,
                        target.clone(),
                        ClientTarget::Upstream,
                    )
                    .await
                {
                    Ok(tx) => tx,
                    Err(err) => {
                        warn!(error = %err, "failed to start upstream INVITE transaction");
                        context.media.release(&media_key).await;
                        {
                            let mut downstream = downstream_tx.lock().await;
                            downstream
                                .reply(StatusCode::ServiceUnavailable)
                                .await
                                .map_err(Error::sip_stack)?;
                        }
                        return Ok(());
                    }
                };

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
                        downstream_local_tag: downstream_local_tag.clone(),
                        cancel_token: cancel_token.clone(),
                        endpoint,
                        upstream_request: upstream_request_clone,
                        downstream_target: downstream_target.clone(),
                        identity: identity.clone(),
                        upstream_local_tag: upstream_local_tag.clone(),
                        upstream_remote_tag: None,
                        upstream_request_uri: upstream_request_uri.clone(),
                        upstream_dialog_uri,
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
                            context_clone.clone(),
                            call_id_clone.clone(),
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
                        debug!(
                            registration = ?registration,
                            "no active downstream registration; replying 480 to upstream INVITE"
                        );
                        tx.reply(StatusCode::TemporarilyUnavailable)
                            .await
                            .map_err(Error::sip_stack)?;
                        return Ok(());
                    }
                };

                let downstream_contact = Some(registration.contact.uri.clone());
                let downstream_target = downstream_contact
                    .as_ref()
                    .and_then(|uri| Self::sip_addr_from_uri(uri).ok())
                    .unwrap_or_else(|| {
                        let mut sip: SipAddr = registration.source.into();
                        sip.r#type = Some(Transport::Udp);
                        sip
                    });

                let config = context.config.as_ref();
                let to_header = tx
                    .original
                    .to_header()
                    .ok()
                    .and_then(|header| header.typed().ok());
                let to_user = to_header
                    .as_ref()
                    .and_then(|typed| typed.uri.auth.as_ref().map(|auth| auth.user.clone()));
                let request_user = tx.original.uri.auth.as_ref().map(|auth| auth.user.clone());
                let request_user = request_user.map(|user| {
                    if let Some(rewrite) = Self::detect_invite_isub(&tx.original.uri) {
                        rewrite.base_user
                    } else {
                        user
                    }
                });
                let identity = request_user
                    .filter(|user| Self::identity_allowed(user, &config.upstream))
                    .or_else(|| {
                        to_user
                            .clone()
                            .map(|user| {
                                if let Some(rewrite) = Self::detect_invite_isub(&tx.original.uri) {
                                    rewrite.base_user
                                } else {
                                    user
                                }
                            })
                            .filter(|user| Self::identity_allowed(user, &config.upstream))
                    })
                    .or_else(|| {
                        let default = config.upstream.default_identity.clone();
                        if default.is_empty() {
                            None
                        } else {
                            Some(default)
                        }
                    });
                let identity = match identity {
                    Some(identity) => identity,
                    None => {
                        tx.reply(StatusCode::NotFound)
                            .await
                            .map_err(Error::sip_stack)?;
                        return Ok(());
                    }
                };
                let downstream_listener = {
                    let guard = context.sockets.downstream.lock().await;
                    guard
                        .clone()
                        .unwrap_or_else(|| context.config.downstream.bind.socket_addr())
                };
                let fallback_p_called_party =
                    Self::build_default_called_party_uri(&config.upstream);

                let upstream_tx = Arc::new(Mutex::new(tx));
                let original_request = {
                    let mut guard = upstream_tx.lock().await;
                    if guard.original.method == Method::Invite {
                        guard.send_trying().await.map_err(Error::sip_stack)?;
                    }
                    guard.original.clone()
                };
                let upstream_contact_uri = original_request
                    .contact_header()
                    .ok()
                    .and_then(|header| header.typed().ok().map(|typed| typed.uri));
                let upstream_request_uri = upstream_contact_uri
                    .clone()
                    .unwrap_or_else(|| original_request.uri.clone());
                let original_dialog_uri = original_request.uri.clone();

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

                let upstream_remote_tag = original_request
                    .from_header()
                    .ok()
                    .and_then(|from| from.tag().ok().flatten());
                let upstream_local_tag = Tag::default();

                let task_upstream_local_tag = upstream_local_tag.clone();
                let task_upstream_remote_tag = upstream_remote_tag.clone();
                let task_upstream_local_user = to_user.unwrap_or_else(|| identity.clone());

                let downstream_contact_clone = downstream_contact.clone();
                let call_template = CallContext {
                    media: media_session.clone(),
                    media_key: media_key.clone(),
                    upstream_target: Self::build_trunk_target(&config.upstream),
                    upstream_contact: upstream_contact_uri.clone(),
                    downstream_contact: downstream_contact_clone,
                    upstream_local_tag: upstream_local_tag.clone(),
                    upstream_remote_tag: upstream_remote_tag.clone(),
                    downstream_target: downstream_target.clone(),
                    downstream_local_tag: None,
                    upstream_request_uri: upstream_request_uri.clone(),
                    upstream_dialog_uri: original_dialog_uri.clone(),
                    identity: identity.clone(),
                };

                let downstream_request = Self::prepare_downstream_request(
                    &endpoint,
                    downstream_listener,
                    &call_template,
                    &original_request,
                    rewritten_body,
                    true,
                    Some(identity.as_str()),
                    fallback_p_called_party,
                )?;

                let downstream_request_clone = downstream_request.clone();
                let downstream_dialog_uri = downstream_request_clone.uri.clone();

                let client_tx = match self
                    .start_client_transaction(
                        endpoint.clone(),
                        downstream_request,
                        downstream_target.clone(),
                        ClientTarget::Downstream,
                    )
                    .await
                {
                    Ok(tx) => tx,
                    Err(err) => {
                        warn!(error = %err, "failed to start downstream INVITE transaction");
                        context.media.release(&media_key).await;
                        {
                            let mut upstream = upstream_tx.lock().await;
                            upstream
                                .reply(StatusCode::ServiceUnavailable)
                                .await
                                .map_err(Error::sip_stack)?;
                        }
                        return Ok(());
                    }
                };

                let cancel_token = CancellationToken::new();
                context.pending.write().await.insert(
                    call_id.clone(),
                    PendingInvite::Inbound(InboundPendingInvite {
                        upstream_tx: upstream_tx.clone(),
                        media: media_session.clone(),
                        media_key,
                        downstream_target: downstream_target.clone(),
                        downstream_contact: Some(downstream_dialog_uri.clone()),
                        downstream_local_tag: None,
                        cancel_token: cancel_token.clone(),
                        endpoint,
                        downstream_request: downstream_request_clone,
                        identity,
                        upstream_request: original_request,
                        upstream_local_tag: upstream_local_tag.clone(),
                        upstream_remote_tag: upstream_remote_tag.clone(),
                        upstream_request_uri: upstream_request_uri.clone(),
                        upstream_dialog_uri: original_dialog_uri,
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
                            task_upstream_local_tag,
                            task_upstream_remote_tag,
                            task_upstream_local_user,
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

        let call = {
            let guard = context.calls.read().await;
            guard.get(&call_id).cloned()
        };

        if call.is_none() {
            let handled = self
                .forward_pending_dialog_request(context.clone(), tx, &call_id, direction)
                .await?;
            if !handled {
                debug!(
                    call_id,
                    ?direction,
                    "handle_ack: no pending dialog to forward"
                );
            }
            return Ok(());
        }

        let call = call.expect("checked above");

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
                        .unwrap_or_else(|| context.config.upstream.bind.socket_addr())
                };

                let config = context.config.as_ref();
                let route_set = { context.route_set.read().await.clone() };
                let target_contact = call
                    .upstream_contact
                    .as_ref()
                    .or_else(|| Some(&call.upstream_request_uri));
                let upstream_request = Self::prepare_upstream_request(
                    &endpoint,
                    upstream_listener,
                    &config.upstream,
                    &tx.original,
                    None,
                    &call.identity,
                    &route_set,
                    None,
                    &call.upstream_local_tag,
                    call.upstream_remote_tag.as_ref(),
                    target_contact,
                    Some(&call.upstream_dialog_uri),
                )?;

                let _ = self
                    .start_client_transaction(
                        endpoint,
                        upstream_request,
                        call.upstream_target.clone(),
                        ClientTarget::Upstream,
                    )
                    .await?;
            }
            TransactionDirection::Upstream => {
                let downstream_listener = {
                    let guard = context.sockets.downstream.lock().await;
                    guard
                        .clone()
                        .unwrap_or_else(|| context.config.downstream.bind.socket_addr())
                };
                let default_user = context.config.downstream.default_user.as_deref();
                let fallback_p_called_party =
                    Self::build_default_called_party_uri(&context.config.upstream);

                let downstream_request = Self::prepare_downstream_request(
                    &endpoint,
                    downstream_listener,
                    &call,
                    &tx.original,
                    None,
                    false,
                    default_user,
                    fallback_p_called_party,
                )?;

                let _ = self
                    .start_client_transaction(
                        endpoint,
                        downstream_request,
                        call.downstream_target.clone(),
                        ClientTarget::Downstream,
                    )
                    .await?;
            }
        }

        Ok(())
    }

    async fn forward_pending_dialog_request(
        &self,
        context: SipContext,
        tx: &mut Transaction,
        call_id: &str,
        direction: TransactionDirection,
    ) -> Result<bool> {
        let pending = {
            let guard = context.pending.read().await;
            guard.get(call_id).cloned()
        };
        let Some(pending) = pending else {
            return Ok(false);
        };

        match (direction, pending) {
            (TransactionDirection::Downstream, PendingInvite::Inbound(pending)) => {
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
                        .unwrap_or_else(|| context.config.upstream.bind.socket_addr())
                };
                let config = context.config.as_ref();
                let route_set = { context.route_set.read().await.clone() };

                let upstream_contact = pending
                    .upstream_request
                    .contact_header()
                    .ok()
                    .and_then(|header| header.typed().ok().map(|typed| typed.uri));
                let target_contact = upstream_contact
                    .as_ref()
                    .or_else(|| Some(&pending.upstream_request_uri));

                let upstream_request = Self::prepare_upstream_request(
                    endpoint.as_ref(),
                    upstream_listener,
                    &config.upstream,
                    &tx.original,
                    None,
                    &pending.identity,
                    &route_set,
                    None,
                    &pending.upstream_local_tag,
                    pending.upstream_remote_tag.as_ref(),
                    target_contact,
                    Some(&pending.upstream_dialog_uri),
                )?;

                let _ = self
                    .start_client_transaction(
                        endpoint,
                        upstream_request,
                        Self::build_trunk_target(&context.config.upstream),
                        ClientTarget::Upstream,
                    )
                    .await?;

                Ok(true)
            }
            (TransactionDirection::Upstream, PendingInvite::Inbound(pending)) => {
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
                        .unwrap_or_else(|| context.config.downstream.bind.socket_addr())
                };
                let default_user = context.config.downstream.default_user.as_deref();
                let fallback_p_called_party =
                    Self::build_default_called_party_uri(&context.config.upstream);

                let downstream_contact = pending
                    .downstream_contact
                    .clone()
                    .or_else(|| Some(pending.upstream_request.uri.clone()));
                let downstream_target = downstream_contact
                    .as_ref()
                    .and_then(|uri| Self::sip_addr_from_uri(uri).ok())
                    .unwrap_or_else(|| pending.downstream_target.clone());
                let upstream_contact = pending
                    .upstream_request
                    .contact_header()
                    .ok()
                    .and_then(|header| header.typed().ok().map(|typed| typed.uri));

                let stub_call = CallContext {
                    media: pending.media.clone(),
                    media_key: pending.media_key,
                    upstream_target: Self::build_trunk_target(&context.config.upstream),
                    upstream_contact,
                    downstream_contact: downstream_contact.clone(),
                    upstream_local_tag: pending.upstream_local_tag.clone(),
                    upstream_remote_tag: pending.upstream_remote_tag.clone(),
                    downstream_target: downstream_target.clone(),
                    downstream_local_tag: pending.downstream_local_tag.clone(),
                    upstream_request_uri: pending.upstream_request_uri.clone(),
                    upstream_dialog_uri: pending.upstream_dialog_uri.clone(),
                    identity: pending.identity.clone(),
                };

                let downstream_request = Self::prepare_downstream_request(
                    endpoint.as_ref(),
                    downstream_listener,
                    &stub_call,
                    &tx.original,
                    None,
                    false,
                    default_user,
                    fallback_p_called_party,
                )?;

                let _ = self
                    .start_client_transaction(
                        endpoint,
                        downstream_request,
                        downstream_target,
                        ClientTarget::Downstream,
                    )
                    .await?;

                Ok(true)
            }
            (TransactionDirection::Upstream, PendingInvite::Outbound(pending)) => {
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
                        .unwrap_or_else(|| context.config.downstream.bind.socket_addr())
                };
                let default_user = context.config.downstream.default_user.as_deref();
                let fallback_p_called_party =
                    Self::build_default_called_party_uri(&context.config.upstream);

                let downstream_contact = pending
                    .downstream_contact
                    .clone()
                    .or_else(|| Some(pending.upstream_request.uri.clone()));
                let downstream_target = downstream_contact
                    .as_ref()
                    .and_then(|uri| Self::sip_addr_from_uri(uri).ok())
                    .unwrap_or_else(|| pending.downstream_target.clone());

                let stub_call = CallContext {
                    media: pending.media.clone(),
                    media_key: pending.media_key,
                    upstream_target: pending.upstream_target.clone(),
                    upstream_contact: Some(pending.upstream_request_uri.clone()),
                    downstream_contact,
                    upstream_local_tag: pending.upstream_local_tag.clone(),
                    upstream_remote_tag: pending.upstream_remote_tag.clone(),
                    downstream_target: downstream_target.clone(),
                    downstream_local_tag: pending.downstream_local_tag.clone(),
                    upstream_request_uri: pending.upstream_request_uri.clone(),
                    upstream_dialog_uri: pending.upstream_dialog_uri.clone(),
                    identity: pending.identity.clone(),
                };

                let downstream_request = Self::prepare_downstream_request(
                    endpoint.as_ref(),
                    downstream_listener,
                    &stub_call,
                    &tx.original,
                    None,
                    false,
                    default_user,
                    fallback_p_called_party,
                )?;

                let _ = self
                    .start_client_transaction(
                        endpoint,
                        downstream_request,
                        downstream_target,
                        ClientTarget::Downstream,
                    )
                    .await?;

                Ok(true)
            }
            (TransactionDirection::Downstream, PendingInvite::Outbound(pending)) => {
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
                        .unwrap_or_else(|| context.config.upstream.bind.socket_addr())
                };

                let config = context.config.as_ref();
                let route_set = { context.route_set.read().await.clone() };

                let upstream_contact = pending
                    .upstream_request
                    .contact_header()
                    .ok()
                    .and_then(|header| header.typed().ok().map(|typed| typed.uri));

                let target_contact = upstream_contact
                    .as_ref()
                    .or_else(|| Some(&pending.upstream_request_uri));

                let upstream_request = Self::prepare_upstream_request(
                    endpoint.as_ref(),
                    upstream_listener,
                    &config.upstream,
                    &tx.original,
                    None,
                    &pending.identity,
                    &route_set,
                    None,
                    &pending.upstream_local_tag,
                    pending.upstream_remote_tag.as_ref(),
                    target_contact,
                    Some(&pending.upstream_dialog_uri),
                )?;

                let _ = self
                    .start_client_transaction(
                        endpoint,
                        upstream_request,
                        pending.upstream_target.clone(),
                        ClientTarget::Upstream,
                    )
                    .await?;

                Ok(true)
            }
        }
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
                if self
                    .forward_pending_dialog_request(context.clone(), tx, &call_id, direction)
                    .await?
                {
                    return Ok(());
                }
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
                if self
                    .forward_pending_dialog_request(context.clone(), tx, &call_id, direction)
                    .await?
                {
                    return Ok(());
                }
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
                if self
                    .forward_pending_dialog_request(context.clone(), tx, &call_id, direction)
                    .await?
                {
                    return Ok(());
                }
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
        debug!(call_id, ?direction, "handle_bye: received BYE");

        let stored_call = match context.calls.read().await.get(&call_id).cloned() {
            Some(call) => call,
            None => {
                tx.reply(StatusCode::OK).await.map_err(Error::sip_stack)?;
                return Ok(());
            }
        };

        match direction {
            TransactionDirection::Downstream => {
                let call = stored_call.clone();
                let endpoint = {
                    let guard = self.inner.endpoint.read().await;
                    guard
                        .as_ref()
                        .cloned()
                        .ok_or_else(|| Error::configuration("endpoint not initialized"))?
                };
                debug!(call_id, target = %call.upstream_target, "handle_bye: forwarding downstream BYE upstream");

                // Acknowledge downstream immediately to avoid retransmissions while we forward upstream.
                tx.reply(StatusCode::OK).await.map_err(Error::sip_stack)?;

                let upstream_listener = {
                    let guard = context.sockets.upstream.lock().await;
                    guard
                        .clone()
                        .unwrap_or_else(|| context.config.upstream.bind.socket_addr())
                };

                let config = context.config.as_ref();
                let route_set = { context.route_set.read().await.clone() };

                let target_contact = call
                    .upstream_contact
                    .clone()
                    .or_else(|| Some(call.upstream_request_uri.clone()));

                let upstream_request = Self::prepare_upstream_request(
                    &endpoint,
                    upstream_listener,
                    &config.upstream,
                    &tx.original,
                    None,
                    &call.identity,
                    &route_set,
                    None,
                    &call.upstream_local_tag,
                    call.upstream_remote_tag.as_ref(),
                    target_contact.as_ref(),
                    Some(&call.upstream_dialog_uri),
                )?;

                let mut client_tx = self
                    .start_client_transaction(
                        endpoint,
                        upstream_request,
                        call.upstream_target.clone(),
                        ClientTarget::Upstream,
                    )
                    .await?;

                let mut released = false;
                while let Some(message) = client_tx.receive().await {
                    match message {
                        SipMessage::Response(mut response) => {
                            debug!(
                                call_id,
                                status = %response.status_code,
                                "handle_bye: upstream response to downstream BYE"
                            );
                            Self::expand_compact_headers(&mut response.headers);
                            if matches!(response.status_code.kind(), StatusCodeKind::Successful) {
                                context.media.release(&call.media_key).await;
                                context.calls.write().await.remove(&call_id);
                                released = true;
                                break;
                            }
                        }
                        SipMessage::Request(_) => {}
                    }
                }

                if !released {
                    context.media.release(&call.media_key).await;
                    context.calls.write().await.remove(&call_id);
                }

                Ok(())
            }
            TransactionDirection::Upstream => {
                tx.reply(StatusCode::OK).await.map_err(Error::sip_stack)?;
                let mut call = {
                    let mut guard = context.calls.write().await;
                    guard.remove(&call_id).unwrap_or(stored_call)
                };
                if let Some(contact) = tx
                    .original
                    .contact_header()
                    .ok()
                    .and_then(|header| header.typed().ok().map(|typed| typed.uri))
                {
                    call.upstream_request_uri = contact.clone();
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
                        .unwrap_or_else(|| context.config.downstream.bind.socket_addr())
                };
                let default_user = context.config.downstream.default_user.as_deref();
                let fallback_p_called_party =
                    Self::build_default_called_party_uri(&context.config.upstream);

                let downstream_request = Self::prepare_downstream_request(
                    &endpoint,
                    downstream_listener,
                    &call,
                    &tx.original,
                    body_override,
                    false,
                    default_user,
                    fallback_p_called_party,
                )?;
                debug!(
                    call_id,
                    target = %call.downstream_target,
                    "handle_bye: forwarding upstream BYE downstream"
                );

                let backend = self.clone();
                let context_clone = context.clone();
                let call_id_clone = call_id.clone();
                tokio::spawn(async move {
                    if let Err(err) = backend
                        .forward_downstream_bye(
                            context_clone,
                            call_id_clone,
                            call,
                            endpoint,
                            downstream_request,
                        )
                        .await
                    {
                        warn!(error = %err, "failed to forward BYE downstream");
                    }
                });

                tx.reply(StatusCode::OK).await.map_err(Error::sip_stack)?;

                Ok(())
            }
        }
    }

    async fn forward_downstream_bye(
        &self,
        context: SipContext,
        call_id: String,
        mut call: CallContext,
        endpoint: Arc<Endpoint>,
        downstream_request: rsip::Request,
    ) -> Result<()> {
        let mut client_tx = self
            .start_client_transaction(
                endpoint,
                downstream_request,
                call.downstream_target.clone(),
                ClientTarget::Downstream,
            )
            .await?;

        let mut responded = false;
        let mut new_downstream_contact = call.downstream_contact.clone();

        while let Some(message) = client_tx.receive().await {
            match message {
                SipMessage::Response(mut response) => {
                    debug!(
                        call_id,
                        status = %response.status_code,
                        "forward_downstream_bye: downstream response"
                    );
                    Self::expand_compact_headers(&mut response.headers);
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
                    }

                    responded = true;
                    break;
                }
                SipMessage::Request(_) => {}
            }
        }

        if !responded {
            warn!(call_id, "downstream BYE timed out");
        }

        context.media.release(&call.media_key).await;
        Ok(())
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
                ClientTarget::Upstream,
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
                ClientTarget::Downstream,
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

fn downstream_realm(context: &SipContext) -> String {
    context
        .config
        .downstream
        .user_agent
        .realm
        .clone()
        .unwrap_or_else(|| context.config.upstream.sip_domain.clone())
}

async fn create_udp_listener(
    bind: &BindConfig,
    cancel_token: CancellationToken,
) -> Result<(UdpConnection, SocketAddr, SocketAddr)> {
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

    let resolved_addr = if bind.address.is_unspecified() {
        SipConnection::resolve_bind_address(canonical_addr)
    } else {
        canonical_addr
    };

    let mut sip_addr: SipAddr = resolved_addr.into();
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

    Ok((connection, local_addr, canonical_addr))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransactionDirection {
    Downstream,
    Upstream,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientTarget {
    Upstream,
    Downstream,
}
