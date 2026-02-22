#![deny(unsafe_code)]

pub mod audit;
pub mod config;
pub mod error;
pub mod ipc;
pub mod plugin;
pub mod provider;
pub mod router;
pub mod state;
pub mod vault;

pub use config::FugueConfig;
pub use error::{FugueError, Result};
