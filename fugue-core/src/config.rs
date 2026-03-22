#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::error::{FugueError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FugueConfig {
    #[serde(default)]
    pub core: CoreConfig,

    #[serde(default)]
    pub providers: HashMap<String, ProviderConfig>,

    #[serde(default)]
    pub channels: HashMap<String, ChannelConfig>,

    #[serde(default)]
    pub network: NetworkConfig,

    #[serde(default)]
    pub vault: VaultConfig,

    #[serde(default)]
    pub plugins: PluginSystemConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreConfig {
    #[serde(default = "default_socket_path")]
    pub socket_path: PathBuf,

    #[serde(default = "default_log_level")]
    pub log_level: String,

    #[serde(default = "default_true")]
    pub audit_enabled: bool,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            socket_path: default_socket_path(),
            log_level: default_log_level(),
            audit_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    #[serde(rename = "type")]
    pub provider_type: ProviderType,

    pub base_url: Option<String>,

    pub model: Option<String>,

    /// Reference to a vault credential, not a raw key
    pub credential: Option<String>,

    #[serde(default)]
    pub extra: HashMap<String, toml::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProviderType {
    Ollama,
    Anthropic,
    OpenAI,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelConfig {
    #[serde(rename = "type")]
    pub channel_type: ChannelType,

    pub credential: Option<String>,

    #[serde(default)]
    pub allowed_ids: Vec<String>,

    #[serde(default)]
    pub extra: HashMap<String, toml::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ChannelType {
    Cli,
    Telegram,
    Signal,
    Discord,
    Matrix,
    Slack,
    Whatsapp,
    Irc,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    #[serde(default)]
    pub http_enabled: bool,

    #[serde(default = "default_bind_addr")]
    pub bind_address: String,

    #[serde(default = "default_http_port")]
    pub port: u16,

    /// Must be explicitly set to true to bind to non-localhost
    #[serde(default)]
    pub i_understand_the_risk: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            http_enabled: false,
            bind_address: default_bind_addr(),
            port: default_http_port(),
            i_understand_the_risk: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VaultBackend {
    Keyring,
    EncryptedFile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    #[serde(default = "default_vault_backend")]
    pub backend: VaultBackend,

    pub encrypted_file_path: Option<PathBuf>,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            backend: default_vault_backend(),
            encrypted_file_path: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginSystemConfig {
    #[serde(default = "default_plugin_dir")]
    pub directory: PathBuf,

    #[serde(default = "default_memory_limit")]
    pub memory_limit_bytes: u64,

    #[serde(default = "default_fuel_limit")]
    pub fuel_limit: u64,

    #[serde(default = "default_execution_timeout_ms")]
    pub execution_timeout_ms: u64,
}

impl Default for PluginSystemConfig {
    fn default() -> Self {
        Self {
            directory: default_plugin_dir(),
            memory_limit_bytes: default_memory_limit(),
            fuel_limit: default_fuel_limit(),
            execution_timeout_ms: default_execution_timeout_ms(),
        }
    }
}

fn default_socket_path() -> PathBuf {
    let runtime_dir = dirs::runtime_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    runtime_dir.join("fugue").join("fugue.sock")
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_true() -> bool {
    true
}

fn default_bind_addr() -> String {
    "127.0.0.1".to_string()
}

fn default_http_port() -> u16 {
    8432
}

fn default_vault_backend() -> VaultBackend {
    VaultBackend::EncryptedFile
}

fn default_plugin_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("fugue")
        .join("plugins")
}

fn default_memory_limit() -> u64 {
    64 * 1024 * 1024 // 64 MiB
}

fn default_fuel_limit() -> u64 {
    1_000_000_000
}

fn default_execution_timeout_ms() -> u64 {
    30_000 // 30 seconds
}

impl FugueConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            FugueError::Config(format!("failed to read config file {}: {}", path.display(), e))
        })?;
        Self::parse(&content)
    }

    pub fn parse(content: &str) -> Result<Self> {
        let config: FugueConfig = toml::from_str(content)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        // Network security check: non-localhost requires explicit acknowledgment
        if self.network.http_enabled
            && self.network.bind_address != "127.0.0.1"
            && self.network.bind_address != "::1"
            && self.network.bind_address != "localhost"
            && !self.network.i_understand_the_risk
        {
            return Err(FugueError::Config(
                "binding HTTP to a non-localhost address requires 'i_understand_the_risk = true' in [network]".to_string(),
            ));
        }

        // Validate providers don't contain raw API keys
        for (name, provider) in &self.providers {
            if let Some(ref cred) = provider.credential {
                if cred.starts_with("sk-") || cred.starts_with("key-") || cred.len() > 80 {
                    return Err(FugueError::Config(format!(
                        "provider '{}' credential looks like a raw API key; use a vault reference instead (e.g., 'vault:my-key-name')",
                        name
                    )));
                }
            }
        }

        // Validate log level
        match self.core.log_level.as_str() {
            "trace" | "debug" | "info" | "warn" | "error" => {}
            other => {
                return Err(FugueError::Config(format!(
                    "invalid log level '{}'; must be one of: trace, debug, info, warn, error",
                    other
                )));
            }
        }

        Ok(())
    }

    pub fn default_config() -> Self {
        FugueConfig {
            core: CoreConfig::default(),
            providers: HashMap::new(),
            channels: HashMap::new(),
            network: NetworkConfig::default(),
            vault: VaultConfig::default(),
            plugins: PluginSystemConfig::default(),
        }
    }

    pub fn config_dir() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from(".config"))
            .join("fugue")
    }

    pub fn default_config_path() -> PathBuf {
        Self::config_dir().join("config.toml")
    }

    pub fn data_dir() -> PathBuf {
        dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from(".local/share"))
            .join("fugue")
    }

    pub fn to_toml_string(&self) -> Result<String> {
        toml::to_string_pretty(self).map_err(|e| FugueError::Config(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_parses() {
        let config = FugueConfig::default_config();
        assert_eq!(config.core.log_level, "info");
        assert!(config.core.audit_enabled);
        assert!(!config.network.http_enabled);
        assert_eq!(config.network.bind_address, "127.0.0.1");
    }

    #[test]
    fn test_config_roundtrip() {
        let config = FugueConfig::default_config();
        let toml_str = config.to_toml_string().unwrap();
        let parsed = FugueConfig::parse(&toml_str).unwrap();
        assert_eq!(parsed.core.log_level, config.core.log_level);
        assert_eq!(parsed.network.bind_address, config.network.bind_address);
    }

    #[test]
    fn test_minimal_config() {
        let toml_str = "";
        let config = FugueConfig::parse(toml_str).unwrap();
        assert_eq!(config.core.log_level, "info");
    }

    #[test]
    fn test_full_config_parse() {
        let toml_str = r#"
[core]
log_level = "debug"
audit_enabled = true

[providers.ollama]
type = "ollama"
base_url = "http://localhost:11434"
model = "llama3.2"

[providers.anthropic]
type = "anthropic"
credential = "vault:anthropic-key"
model = "claude-sonnet-4-20250514"

[channels.cli]
type = "cli"

[channels.telegram]
type = "telegram"
credential = "vault:telegram-token"
allowed_ids = ["123456789"]

[network]
http_enabled = false

[vault]
backend = "encryptedfile"

[plugins]
memory_limit_bytes = 33554432
fuel_limit = 500000000
execution_timeout_ms = 10000
"#;
        let config = FugueConfig::parse(toml_str).unwrap();
        assert_eq!(config.core.log_level, "debug");
        assert!(config.providers.contains_key("ollama"));
        assert!(config.providers.contains_key("anthropic"));
        assert_eq!(
            config.providers["ollama"].provider_type,
            ProviderType::Ollama
        );
        assert!(config.channels.contains_key("telegram"));
        assert_eq!(config.plugins.memory_limit_bytes, 33_554_432);
    }

    #[test]
    fn test_rejects_non_localhost_without_risk_flag() {
        let toml_str = r#"
[network]
http_enabled = true
bind_address = "0.0.0.0"
"#;
        let result = FugueConfig::parse(toml_str);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("i_understand_the_risk"));
    }

    #[test]
    fn test_allows_non_localhost_with_risk_flag() {
        let toml_str = r#"
[network]
http_enabled = true
bind_address = "0.0.0.0"
i_understand_the_risk = true
"#;
        let result = FugueConfig::parse(toml_str);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rejects_raw_api_key_in_credential() {
        let toml_str = r#"
[providers.bad]
type = "anthropic"
credential = "sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"#;
        let result = FugueConfig::parse(toml_str);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("raw API key"));
    }

    #[test]
    fn test_invalid_log_level() {
        let toml_str = r#"
[core]
log_level = "verbose"
"#;
        let result = FugueConfig::parse(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_localhost_http_ok_without_risk_flag() {
        let toml_str = r#"
[network]
http_enabled = true
bind_address = "127.0.0.1"
"#;
        let result = FugueConfig::parse(toml_str);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ipv6_localhost_ok_without_risk_flag() {
        let toml_str = r#"
[network]
http_enabled = true
bind_address = "::1"
"#;
        let result = FugueConfig::parse(toml_str);
        assert!(result.is_ok());
    }

    #[test]
    fn test_http_disabled_non_localhost_ok() {
        let toml_str = r#"
[network]
http_enabled = false
bind_address = "0.0.0.0"
"#;
        let result = FugueConfig::parse(toml_str);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rejects_key_prefix_credential() {
        let toml_str = r#"
[providers.bad]
type = "openai"
credential = "key-abc123"
"#;
        let result = FugueConfig::parse(toml_str);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("raw API key"));
    }

    #[test]
    fn test_rejects_long_credential() {
        let long_cred = "a".repeat(81);
        let toml_str = format!(
            r#"
[providers.bad]
type = "openai"
credential = "{}"
"#,
            long_cred
        );
        let result = FugueConfig::parse(&toml_str);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("raw API key"));
    }

    #[test]
    fn test_allows_vault_reference_credential() {
        let toml_str = r#"
[providers.good]
type = "anthropic"
credential = "vault:my-api-key"
"#;
        let result = FugueConfig::parse(toml_str);
        assert!(result.is_ok());
    }

    #[test]
    fn test_malformed_toml() {
        let toml_str = "this is not [valid toml";
        let result = FugueConfig::parse(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_provider_type() {
        let toml_str = r#"
[providers.bad]
type = "grok"
"#;
        let result = FugueConfig::parse(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_channel_type() {
        let toml_str = r#"
[channels.bad]
type = "sms"
"#;
        let result = FugueConfig::parse(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_all_valid_log_levels() {
        for level in &["trace", "debug", "info", "warn", "error"] {
            let toml_str = format!(
                r#"
[core]
log_level = "{}"
"#,
                level
            );
            let result = FugueConfig::parse(&toml_str);
            assert!(result.is_ok(), "log level '{}' should be valid", level);
        }
    }

    #[test]
    fn test_plugin_system_defaults() {
        let config = FugueConfig::default_config();
        assert_eq!(config.plugins.memory_limit_bytes, 64 * 1024 * 1024);
        assert_eq!(config.plugins.fuel_limit, 1_000_000_000);
        assert_eq!(config.plugins.execution_timeout_ms, 30_000);
    }

    #[test]
    fn test_vault_config_defaults() {
        let config = FugueConfig::default_config();
        assert_eq!(config.vault.backend, VaultBackend::EncryptedFile);
        assert!(config.vault.encrypted_file_path.is_none());
    }

    #[test]
    fn test_network_default_port() {
        let config = FugueConfig::default_config();
        assert_eq!(config.network.port, 8432);
    }

    #[test]
    fn test_multiple_providers_one_bad_credential() {
        let toml_str = r#"
[providers.good]
type = "ollama"

[providers.bad]
type = "anthropic"
credential = "sk-ant-real-key-here"
"#;
        let result = FugueConfig::parse(toml_str);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("bad"));
    }

    #[test]
    fn test_channel_with_allowed_ids() {
        let toml_str = r#"
[channels.telegram]
type = "telegram"
credential = "vault:tg-token"
allowed_ids = ["123", "456", "789"]
"#;
        let config = FugueConfig::parse(toml_str).unwrap();
        let tg = &config.channels["telegram"];
        assert_eq!(tg.allowed_ids, vec!["123", "456", "789"]);
    }

    #[test]
    fn test_config_load_nonexistent_file() {
        let result = FugueConfig::load(std::path::Path::new("/nonexistent/config.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn test_config_load_from_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[core]\nlog_level = \"debug\"\n").unwrap();

        let config = FugueConfig::load(&path).unwrap();
        assert_eq!(config.core.log_level, "debug");
    }

    #[test]
    fn test_all_channel_types() {
        for (name, type_str) in &[
            ("cli", "cli"),
            ("telegram", "telegram"),
            ("signal", "signal"),
            ("discord", "discord"),
            ("matrix", "matrix"),
            ("slack", "slack"),
            ("whatsapp", "whatsapp"),
            ("irc", "irc"),
        ] {
            let toml_str = format!(
                r#"
[channels.{}]
type = "{}"
"#,
                name, type_str
            );
            let result = FugueConfig::parse(&toml_str);
            assert!(result.is_ok(), "channel type '{}' should be valid", type_str);
        }
    }

    #[test]
    fn test_provider_extra_fields() {
        let toml_str = r#"
[providers.ollama]
type = "ollama"
base_url = "http://localhost:11434"

[providers.ollama.extra]
temperature = 0.7
top_p = 0.9
"#;
        let config = FugueConfig::parse(toml_str).unwrap();
        let ollama = &config.providers["ollama"];
        assert!(ollama.extra.contains_key("temperature"));
        assert!(ollama.extra.contains_key("top_p"));
    }
}
