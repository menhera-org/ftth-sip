use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use tokio::runtime::Builder as RuntimeBuilder;
use tokio::sync::watch;
//use tokio::task::JoinHandle;

use crate::error::{Error, Result};
use crate::media::MediaRelayBuilder;

use super::backend::{RsipstackBackend, SipBackend};
use super::state::{DownstreamAuthState, ListenerSockets, SipContext};
use super::utils::canonicalize_identity;
use crate::sip::registration::RegistrationCache;

pub struct FtthSipProxyBuilder<B = RsipstackBackend> {
    config: crate::config::ProxyConfig,
    backend: B,
}

impl FtthSipProxyBuilder<RsipstackBackend> {
    pub fn new(config: crate::config::ProxyConfig) -> Self {
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
        let mut allowed_identities: HashSet<String> = HashSet::new();
        if !self.config.upstream.default_identity.is_empty()
            && let Some(canonical) = canonicalize_identity(&self.config.upstream.default_identity)
        {
            allowed_identities.insert(canonical);
        }
        for identity in &self.config.upstream.allowed_identities {
            if let Some(canonical) = canonicalize_identity(identity) {
                allowed_identities.insert(canonical);
            }
        }
        let context = SipContext {
            config: Arc::new(self.config),
            media: Arc::new(media),
            registrations: Arc::new(tokio::sync::RwLock::new(RegistrationCache::new())),
            sockets: Arc::new(ListenerSockets::default()),
            calls: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            route_set: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            allowed_identities: Arc::new(tokio::sync::RwLock::new(allowed_identities)),
            auth: Arc::new(DownstreamAuthState::new()),
            pending: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
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

        let worker: std::thread::JoinHandle<Result<()>> = std::thread::spawn(move || {
            let runtime = RuntimeBuilder::new_multi_thread()
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
    worker: std::thread::JoinHandle<Result<()>>,
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
        let handle = tokio::task::spawn_blocking(move || Self::join_worker(worker));
        let result = handle.await;
        match result {
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
        let handle = tokio::task::spawn_blocking(move || Self::join_worker(worker));
        let result = handle.await;
        match result {
            Ok(result) => result,
            Err(join_error) => Err(Error::Media(format!("proxy task panicked: {join_error}"))),
        }
    }

    fn join_worker(worker: std::thread::JoinHandle<Result<()>>) -> Result<()> {
        match worker.join() {
            Ok(result) => result,
            Err(panic) => Err(Error::Media(format!(
                "proxy worker panicked: {}",
                Self::panic_message(panic),
            ))),
        }
    }

    fn panic_message(panic: Box<dyn Any + Send + 'static>) -> String {
        if let Ok(msg) = panic.downcast::<String>() {
            *msg
        } else if let Ok(msg) = panic.downcast::<&'static str>() {
            (*msg).to_string()
        } else {
            "unknown panic payload".to_string()
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

pub type FtthSipProxy = ProxyRuntime<RsipstackBackend>;
