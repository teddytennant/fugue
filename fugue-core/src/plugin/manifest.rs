#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::path::Path;

use super::capabilities::Capability;
use crate::error::{FugueError, Result};

/// Plugin manifest (manifest.toml alongside the WASM binary)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub plugin: PluginMeta,

    #[serde(default)]
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMeta {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: Option<String>,
    pub license: Option<String>,
    /// Path to the WASM binary, relative to the manifest
    pub wasm_file: String,
}

impl PluginManifest {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            FugueError::Plugin(format!("failed to read manifest {}: {}", path.display(), e))
        })?;
        Self::parse(&content)
    }

    pub fn parse(content: &str) -> Result<Self> {
        let manifest: PluginManifest = toml::from_str(content)
            .map_err(|e| FugueError::Plugin(format!("failed to parse manifest: {}", e)))?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<()> {
        if self.plugin.name.is_empty() {
            return Err(FugueError::Plugin(
                "plugin name cannot be empty".to_string(),
            ));
        }

        if self.plugin.name.contains('/')
            || self.plugin.name.contains('\\')
            || self.plugin.name.contains("..")
        {
            return Err(FugueError::Plugin(format!(
                "plugin name '{}' contains invalid path characters",
                self.plugin.name
            )));
        }

        if self.plugin.version.is_empty() {
            return Err(FugueError::Plugin(
                "plugin version cannot be empty".to_string(),
            ));
        }

        if self.plugin.wasm_file.is_empty() {
            return Err(FugueError::Plugin(
                "plugin wasm_file cannot be empty".to_string(),
            ));
        }

        if self.plugin.wasm_file.contains("..")
            || self.plugin.wasm_file.starts_with('/')
            || self.plugin.wasm_file.starts_with('\\')
        {
            return Err(FugueError::Plugin(format!(
                "plugin wasm_file '{}' contains invalid path characters",
                self.plugin.wasm_file
            )));
        }

        // Validate all capability strings parse correctly
        for cap_str in &self.capabilities {
            if Capability::parse(cap_str).is_none() {
                return Err(FugueError::Plugin(format!(
                    "unknown capability '{}' in manifest",
                    cap_str
                )));
            }
        }

        Ok(())
    }

    /// Parse capability strings into Capability values
    pub fn parsed_capabilities(&self) -> Vec<Capability> {
        self.capabilities
            .iter()
            .filter_map(|s| Capability::parse(s))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_manifest() {
        let toml_str = r#"
capabilities = ["ipc:messages", "state:read"]

[plugin]
name = "echo-tool"
version = "0.1.0"
description = "Echoes input back"
author = "Test Author"
license = "MIT"
wasm_file = "echo_tool.wasm"
"#;
        let manifest = PluginManifest::parse(toml_str).unwrap();
        assert_eq!(manifest.plugin.name, "echo-tool");
        assert_eq!(manifest.plugin.version, "0.1.0");
        assert_eq!(manifest.capabilities.len(), 2);
    }

    #[test]
    fn test_parsed_capabilities() {
        let toml_str = r#"
capabilities = ["ipc:messages", "net:outbound:https://api.example.com", "llm:call"]

[plugin]
name = "net-tool"
version = "0.1.0"
description = "Network tool"
wasm_file = "net_tool.wasm"
"#;
        let manifest = PluginManifest::parse(toml_str).unwrap();
        let caps = manifest.parsed_capabilities();
        assert_eq!(caps.len(), 3);
        assert!(caps.contains(&Capability::IpcMessages));
        assert!(caps.contains(&Capability::LlmCall));
    }

    #[test]
    fn test_empty_name_rejected() {
        let toml_str = r#"
[plugin]
name = ""
version = "0.1.0"
description = "Bad plugin"
wasm_file = "bad.wasm"
"#;
        let result = PluginManifest::parse(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_version_rejected() {
        let toml_str = r#"
[plugin]
name = "test"
version = ""
description = "Bad plugin"
wasm_file = "bad.wasm"
"#;
        let result = PluginManifest::parse(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_wasm_file_rejected() {
        let toml_str = r#"
[plugin]
name = "test"
version = "0.1.0"
description = "Bad plugin"
wasm_file = ""
"#;
        let result = PluginManifest::parse(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_capability_rejected() {
        let toml_str = r#"
capabilities = ["ipc:messages", "totally:invalid"]

[plugin]
name = "test"
version = "0.1.0"
description = "Bad plugin"
wasm_file = "test.wasm"
"#;
        let result = PluginManifest::parse(toml_str);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("totally:invalid"));
    }

    #[test]
    fn test_no_capabilities_ok() {
        let toml_str = r#"
[plugin]
name = "minimal"
version = "0.1.0"
description = "Minimal plugin"
wasm_file = "minimal.wasm"
"#;
        let manifest = PluginManifest::parse(toml_str).unwrap();
        assert!(manifest.capabilities.is_empty());
        assert!(manifest.parsed_capabilities().is_empty());
    }

    #[test]
    fn test_critical_capabilities_parsed() {
        let toml_str = r#"
capabilities = ["exec:subprocess", "credential:read:my-secret"]

[plugin]
name = "dangerous"
version = "0.1.0"
description = "Dangerous plugin"
wasm_file = "dangerous.wasm"
"#;
        let manifest = PluginManifest::parse(toml_str).unwrap();
        let caps = manifest.parsed_capabilities();
        assert!(caps.contains(&Capability::ExecSubprocess));
        assert!(caps.contains(&Capability::CredentialRead("my-secret".to_string())));
    }

    #[test]
    fn test_malformed_toml() {
        let result = PluginManifest::parse("this is {not valid toml");
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_plugin_section() {
        let toml_str = r#"
capabilities = ["ipc:messages"]
"#;
        let result = PluginManifest::parse(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_required_fields() {
        // Missing description
        let toml_str = r#"
[plugin]
name = "test"
version = "0.1.0"
wasm_file = "test.wasm"
"#;
        let result = PluginManifest::parse(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_all_capability_types_in_manifest() {
        let toml_str = r#"
capabilities = [
    "fs:read",
    "fs:read:/tmp",
    "fs:write",
    "fs:write:/var/data",
    "net:outbound",
    "net:outbound:https://api.example.com",
    "ipc:messages",
    "llm:call",
    "state:read",
    "state:write",
    "exec:subprocess",
    "credential:read:my-key"
]

[plugin]
name = "all-caps"
version = "0.1.0"
description = "Plugin with all capabilities"
wasm_file = "all.wasm"
"#;
        let manifest = PluginManifest::parse(toml_str).unwrap();
        assert_eq!(manifest.capabilities.len(), 12);
        assert_eq!(manifest.parsed_capabilities().len(), 12);
    }

    #[test]
    fn test_optional_fields() {
        let toml_str = r#"
[plugin]
name = "test"
version = "0.1.0"
description = "No author or license"
wasm_file = "test.wasm"
"#;
        let manifest = PluginManifest::parse(toml_str).unwrap();
        assert!(manifest.plugin.author.is_none());
        assert!(manifest.plugin.license.is_none());
    }

    #[test]
    fn test_with_author_and_license() {
        let toml_str = r#"
[plugin]
name = "test"
version = "0.1.0"
description = "Full metadata"
wasm_file = "test.wasm"
author = "Test Author"
license = "MIT"
"#;
        let manifest = PluginManifest::parse(toml_str).unwrap();
        assert_eq!(manifest.plugin.author, Some("Test Author".to_string()));
        assert_eq!(manifest.plugin.license, Some("MIT".to_string()));
    }

    #[test]
    fn test_load_nonexistent_file() {
        let result = PluginManifest::load(std::path::Path::new("/nonexistent/manifest.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn test_load_from_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("manifest.toml");
        std::fs::write(
            &path,
            r#"
[plugin]
name = "file-test"
version = "1.0.0"
description = "Loaded from file"
wasm_file = "test.wasm"
"#,
        )
        .unwrap();

        let manifest = PluginManifest::load(&path).unwrap();
        assert_eq!(manifest.plugin.name, "file-test");
    }

    #[test]
    fn test_duplicate_capabilities() {
        let toml_str = r#"
capabilities = ["ipc:messages", "ipc:messages", "llm:call"]

[plugin]
name = "test"
version = "0.1.0"
description = "Duplicate caps"
wasm_file = "test.wasm"
"#;
        // Duplicates are allowed (they just parse)
        let manifest = PluginManifest::parse(toml_str).unwrap();
        assert_eq!(manifest.capabilities.len(), 3);
    }

    #[test]
    fn test_plugin_name_with_path_separator_rejected() {
        let toml_str = r#"
[plugin]
name = "../evil"
version = "0.1.0"
description = "Path traversal"
wasm_file = "test.wasm"
"#;
        let result = PluginManifest::parse(toml_str);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid path characters"));
    }

    #[test]
    fn test_plugin_name_with_slash_rejected() {
        let toml_str = r#"
[plugin]
name = "foo/bar"
version = "0.1.0"
description = "Slash in name"
wasm_file = "test.wasm"
"#;
        let result = PluginManifest::parse(toml_str);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid path characters"));
    }

    #[test]
    fn test_wasm_file_path_traversal_rejected() {
        let toml_str = r#"
[plugin]
name = "test"
version = "0.1.0"
description = "Path traversal in wasm_file"
wasm_file = "../../etc/passwd"
"#;
        let result = PluginManifest::parse(toml_str);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid path characters"));
    }

    #[test]
    fn test_wasm_file_absolute_path_rejected() {
        let toml_str = r#"
[plugin]
name = "test"
version = "0.1.0"
description = "Absolute wasm_file"
wasm_file = "/etc/passwd"
"#;
        let result = PluginManifest::parse(toml_str);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid path characters"));
    }
}
