#![deny(unsafe_code)]

pub mod capabilities;
pub mod manager;
pub mod manifest;
pub mod registry;
pub mod runtime;

pub use capabilities::{check_capabilities, Capability, RiskLevel};
pub use manager::{OnMessageResult, OnResponseResult, PluginManager};
pub use manifest::PluginManifest;
pub use registry::{PluginEntry, PluginRegistry};
pub use runtime::{
    CompiledPlugin, LogEntry, LogLevel, PluginEngine, PluginInstance, RuntimeConfig,
};
