use thiserror::Error;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("transport error: {0}")]
    Transport(#[from] std::io::Error),

    #[error("invalid configuration: {0}")]
    Configuration(String),

    #[error("sip stack error: {0}")]
    SipStack(String),

    #[error("media relay error: {0}")]
    Media(String),
}

impl Error {
    pub fn sip_stack<E: std::fmt::Display>(err: E) -> Self {
        Self::SipStack(err.to_string())
    }

    pub fn configuration<E: std::fmt::Display>(err: E) -> Self {
        Self::Configuration(err.to_string())
    }
}
