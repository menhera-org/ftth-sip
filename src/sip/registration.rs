use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use ftth_rsipstack::rsip::typed;

use crate::config::AllowedUserAgent;

#[derive(Debug, Clone)]
pub struct DownstreamRegistration {
    pub contact: typed::Contact,
    pub registered_at: Instant,
    pub expires_in: Duration,
    pub source: SocketAddr,
}

impl DownstreamRegistration {
    pub fn is_active(&self, now: Instant) -> bool {
        now.duration_since(self.registered_at) < self.expires_in
    }
}

#[derive(Debug, Default)]
pub struct RegistrationCache {
    active: Option<DownstreamRegistration>,
}

impl RegistrationCache {
    pub fn new() -> Self {
        Self { active: None }
    }

    pub fn get(&self) -> Option<&DownstreamRegistration> {
        self.active.as_ref()
    }

    pub fn upsert(&mut self, registration: DownstreamRegistration) {
        self.active = Some(registration);
    }

    pub fn clear(&mut self) {
        self.active = None;
    }

    pub fn validate_allowed_user(&self, ua: &AllowedUserAgent, username: &str) -> bool {
        ua.username == username
    }

    pub fn map_relay_address(&self) -> Option<IpAddr> {
        self.active.as_ref().map(|entry| entry.source.ip())
    }
}
