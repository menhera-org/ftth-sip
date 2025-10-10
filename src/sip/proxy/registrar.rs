use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use super::backend::RsipstackBackend;
use ftth_rsipstack::rsip;
use ftth_rsipstack::transaction::Endpoint;
use ftth_rsipstack::transaction::key::{TransactionKey, TransactionRole};
use ftth_rsipstack::transaction::transaction::Transaction;
use ftth_rsipstack::transport::SipAddr;
use tokio::sync::{Notify, RwLock};
use tokio_util::sync::CancellationToken;

use crate::error::{Error, Result};
use tracing::{debug, info, warn};

use super::state::SipContext;
use super::utils::{
    canonicalize_identity, format_socket_for_sip, generate_cnonce, md5_hex, strip_rport_param,
};
use rsip::common::uri::UriWithParams;
use rsip::common::uri::param::Tag;
use rsip::headers::auth::{self, AuthQop, Qop};
use rsip::headers::{Contact, ToTypedHeader, UntypedHeader};
use rsip::message::headers_ext::HeadersExt;
use rsip::transport::Transport;
use rsip::typed;
use rsip::{Method, Param, SipMessage, StatusCode, Uri, Version};

pub(super) struct UpstreamRegistrar {
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
    pub(super) fn new(
        context: SipContext,
        endpoint: Arc<Endpoint>,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
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

    pub(super) async fn run(self: Arc<Self>) {
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

    pub(super) fn trigger(&self) {
        self.wake.notify_one();
    }

    async fn register_once(self: &Arc<Self>) -> Result<Duration> {
        let expires_hint = 3600u64;
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
                if let SipMessage::Response(mut response) = message {
                    RsipstackBackend::expand_compact_headers(&mut response.headers);
                    debug!(status = %response.status_code, "received upstream REGISTER response");
                    match response.status_code {
                        StatusCode::OK => {
                            self.update_route_set_from_response(&response).await;
                            self.update_associated_identities(&response).await;
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
        _expires_hint: u64,
        include_authorization: bool,
    ) -> Result<rsip::Request> {
        let config = &self.context.config.upstream;
        let registrar_uri =
            Uri::try_from(config.registrar_uri.as_str()).map_err(Error::sip_stack)?;

        let local_socket = {
            let guard = self.context.sockets.upstream.lock().await;
            guard.unwrap_or_else(|| self.context.config.upstream.bind.socket_addr())
        };

        let identity = if config.default_identity.is_empty() {
            return Err(Error::configuration(
                "upstream default identity must be configured",
            ));
        } else {
            config.default_identity.clone()
        };

        let address_literal = format_socket_for_sip(&local_socket);
        let contact_uri = format!("sip:{}", address_literal);

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
        let mut via = self
            .endpoint
            .inner
            .get_via(Some(via_addr), None)
            .map_err(Error::sip_stack)?;
        strip_rport_param(&mut via);
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
            .unique_push(rsip::Header::Expires(rsip::headers::Expires::from(3600u32)));

        if include_authorization && self.context.config.upstream.auth.is_none() {
            return Err(Error::configuration(
                "upstream authentication required but credentials missing",
            ));
        }

        if include_authorization
            && let Some(authorization) = self.build_authorization(&request).await?
        {
            request
                .headers
                .unique_push(rsip::Header::Authorization(authorization.into()));
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

        // NTT NGN requires re-REGISTER after 40% of the reported expires interval.
        let refresh_secs = expires.saturating_mul(2) / 5;

        Ok(Duration::from_secs(refresh_secs.max(60)))
    }

    async fn update_route_set_from_response(&self, response: &rsip::Response) {
        let routes = Self::extract_route_set(response);
        let mut guard = self.context.route_set.write().await;
        *guard = routes;
    }

    async fn update_associated_identities(&self, response: &rsip::Response) {
        let mut collected = Vec::new();
        for header in response.headers.iter() {
            if let rsip::Header::Other(name, value) = header
                && name.eq_ignore_ascii_case("P-Associated-URI")
            {
                collected.extend(Self::extract_associated_users(value));
            }
        }

        if collected.is_empty() {
            return;
        }

        let mut guard = self.context.allowed_identities.write().await;
        let mut added = false;
        for user in collected {
            if guard.insert(user.clone()) {
                added = true;
            }
        }

        if added {
            debug!(
                count = guard.len(),
                "updated associated identities from trunk"
            );
        }
    }

    fn extract_associated_users(value: &str) -> Vec<String> {
        value
            .split(',')
            .filter_map(|entry| {
                let trimmed = entry.trim();
                if trimmed.is_empty() {
                    return None;
                }
                let inner =
                    if let (Some(start), Some(end)) = (trimmed.find('<'), trimmed.rfind('>')) {
                        if start + 1 >= end {
                            return None;
                        }
                        trimmed[start + 1..end].trim()
                    } else {
                        trimmed
                    };

                match Uri::try_from(inner) {
                    Ok(uri) => uri.auth.and_then(|auth| canonicalize_identity(&auth.user)),
                    Err(_) => None,
                }
            })
            .collect()
    }

    fn extract_route_set(response: &rsip::Response) -> Vec<UriWithParams> {
        let mut routes = Vec::new();

        for header in response.headers.iter() {
            match header {
                rsip::Header::Other(name, value)
                    if name.eq_ignore_ascii_case("Path")
                        || name.eq_ignore_ascii_case("Service-Route") =>
                {
                    let route_header = rsip::headers::Route::from(value.clone());
                    match route_header.typed() {
                        Ok(list) => routes.extend(list.uris().iter().cloned()),
                        Err(err) => {
                            warn!(header = %name, error = %err, "failed to parse route set entry")
                        }
                    }
                }
                _ => {}
            }
        }

        routes
    }

    async fn store_challenge(&self, challenge: &rsip::typed::WwwAuthenticate) -> Result<()> {
        let algorithm_value = challenge.algorithm;
        if let Some(algorithm) = algorithm_value
            && !matches!(algorithm, auth::Algorithm::Md5 | auth::Algorithm::Md5Sess)
        {
            return Err(Error::configuration(format!(
                "unsupported digest algorithm {:?}",
                algorithm
            )));
        }

        let qop_value = challenge.qop.clone();
        if let Some(qop) = qop_value.as_ref()
            && !matches!(qop, Qop::Auth)
        {
            return Err(Error::configuration(format!(
                "unsupported digest qop {:?}",
                qop
            )));
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
