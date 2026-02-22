#![deny(unsafe_code)]

pub mod capabilities;
pub mod manifest;
pub mod registry;

pub use capabilities::{Capability, RiskLevel, check_capabilities};
pub use manifest::PluginManifest;
pub use registry::{PluginEntry, PluginRegistry};
