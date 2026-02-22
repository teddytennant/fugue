#![deny(unsafe_code)]

use thiserror::Error;

#[derive(Error, Debug)]
pub enum FugueError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("vault error: {0}")]
    Vault(String),

    #[error("provider error: {0}")]
    Provider(String),

    #[error("plugin error: {0}")]
    Plugin(String),

    #[error("router error: {0}")]
    Router(String),

    #[error("IPC error: {0}")]
    Ipc(String),

    #[error("state store error: {0}")]
    State(String),

    #[error("audit error: {0}")]
    Audit(String),

    #[error("capability denied: {0}")]
    CapabilityDenied(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("HTTP error: {0}")]
    Http(String),
}

impl From<serde_json::Error> for FugueError {
    fn from(e: serde_json::Error) -> Self {
        FugueError::Serialization(e.to_string())
    }
}

impl From<toml::de::Error> for FugueError {
    fn from(e: toml::de::Error) -> Self {
        FugueError::Config(e.to_string())
    }
}

impl From<reqwest::Error> for FugueError {
    fn from(e: reqwest::Error) -> Self {
        FugueError::Http(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, FugueError>;
