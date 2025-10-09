use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ftth_rsipstack::rsip;
use ftth_rsipstack::transaction::Endpoint;
use ftth_rsipstack::transaction::transaction::Transaction;
use ftth_rsipstack::transport::SipAddr;
use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;

use crate::config::ProxyConfig;
use crate::media::{MediaRelay, MediaSessionHandle, MediaSessionKey};

use super::utils::md5_hex;
use rsip::common::uri::param::Tag;
use crate::sip::registration::RegistrationCache;

#[derive(Debug, Clone)]
pub struct SipContext {
    pub config: Arc<ProxyConfig>,
    pub media: Arc<MediaRelay>,
    pub registrations: Arc<RwLock<RegistrationCache>>,
    pub sockets: Arc<ListenerSockets>,
    pub calls: Arc<RwLock<HashMap<String, CallContext>>>,
    pub route_set: Arc<RwLock<Vec<rsip::common::uri::UriWithParams>>>,
    pub(super) auth: Arc<DownstreamAuthState>,
    pub(super) pending: Arc<RwLock<HashMap<String, PendingInvite>>>,
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
    pub upstream_contact: Option<rsip::Uri>,
    pub downstream_contact: Option<rsip::Uri>,
    pub upstream_to_tag: Option<Tag>,
    pub downstream_target: SipAddr,
    pub identity: String,
}

#[derive(Clone)]
pub(super) enum PendingInvite {
    Outbound(OutboundPendingInvite),
    Inbound(InboundPendingInvite),
}

const DOWNSTREAM_NONCE_TTL: Duration = Duration::from_secs(300);

#[derive(Debug)]
pub(super) struct DownstreamAuthState {
    counter: AtomicU64,
    nonces: Mutex<HashMap<String, Instant>>,
}

impl DownstreamAuthState {
    pub(super) fn new() -> Self {
        Self {
            counter: AtomicU64::new(1),
            nonces: Mutex::new(HashMap::new()),
        }
    }

    pub(super) async fn issue_nonce(&self) -> String {
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

    pub(super) async fn is_valid(&self, nonce: &str) -> bool {
        let mut guard = self.nonces.lock().await;
        guard.retain(|_, issued| issued.elapsed() < DOWNSTREAM_NONCE_TTL);
        guard.contains_key(nonce)
    }

    pub(super) async fn invalidate(&self, nonce: &str) {
        let mut guard = self.nonces.lock().await;
        guard.remove(nonce);
    }
}

#[derive(Clone)]
pub(super) struct OutboundPendingInvite {
    pub(super) downstream_tx: Arc<Mutex<Transaction>>,
    pub(super) media: MediaSessionHandle,
    pub(super) media_key: MediaSessionKey,
    pub(super) upstream_target: SipAddr,
    pub(super) downstream_contact: Option<rsip::Uri>,
    pub(super) cancel_token: CancellationToken,
    pub(super) endpoint: Arc<Endpoint>,
    pub(super) upstream_request: rsip::Request,
    pub(super) downstream_target: SipAddr,
    pub(super) identity: String,
}

#[derive(Clone)]
pub(super) struct InboundPendingInvite {
    pub(super) upstream_tx: Arc<Mutex<Transaction>>,
    pub(super) media: MediaSessionHandle,
    pub(super) media_key: MediaSessionKey,
    pub(super) downstream_target: SipAddr,
    pub(super) downstream_contact: Option<rsip::Uri>,
    pub(super) cancel_token: CancellationToken,
    pub(super) endpoint: Arc<Endpoint>,
    pub(super) downstream_request: rsip::Request,
    pub(super) identity: String,
    pub(super) upstream_request: rsip::Request,
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
