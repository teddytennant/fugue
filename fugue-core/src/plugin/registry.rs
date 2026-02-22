#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::manifest::PluginManifest;
use crate::error::{FugueError, Result};

/// Tracks installed plugins, their approval status, and binary hashes
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PluginRegistry {
    plugins: HashMap<String, PluginEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginEntry {
    pub name: String,
    pub version: String,
    pub description: String,
    pub wasm_path: PathBuf,
    pub manifest_path: PathBuf,
    pub binary_hash: String,
    pub approved: bool,
    pub granted_capabilities: Vec<String>,
    pub installed_at: String,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let content = std::fs::read_to_string(path)?;
        let registry: PluginRegistry = serde_json::from_str(&content)?;
        Ok(registry)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Install a plugin from its manifest directory
    pub fn install(
        &mut self,
        manifest_path: &Path,
        _plugin_dir: &Path,
    ) -> Result<&PluginEntry> {
        let manifest = PluginManifest::load(manifest_path)?;
        let manifest_dir = manifest_path.parent().ok_or_else(|| {
            FugueError::Plugin("manifest path has no parent directory".to_string())
        })?;

        let wasm_path = manifest_dir.join(&manifest.plugin.wasm_file);
        if !wasm_path.exists() {
            return Err(FugueError::Plugin(format!(
                "WASM binary not found: {}",
                wasm_path.display()
            )));
        }

        let binary_hash = hash_file(&wasm_path)?;

        let entry = PluginEntry {
            name: manifest.plugin.name.clone(),
            version: manifest.plugin.version.clone(),
            description: manifest.plugin.description.clone(),
            wasm_path,
            manifest_path: manifest_path.to_path_buf(),
            binary_hash,
            approved: false,
            granted_capabilities: Vec::new(),
            installed_at: chrono::Utc::now().to_rfc3339(),
        };

        let name = entry.name.clone();
        self.plugins.insert(name.clone(), entry);
        Ok(&self.plugins[&name])
    }

    /// Remove a plugin
    pub fn remove(&mut self, name: &str) -> bool {
        self.plugins.remove(name).is_some()
    }

    /// Get a plugin entry
    pub fn get(&self, name: &str) -> Option<&PluginEntry> {
        self.plugins.get(name)
    }

    /// List all plugin names
    pub fn list(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.plugins.keys().map(|s| s.as_str()).collect();
        names.sort();
        names
    }

    /// Approve a plugin with specific capabilities
    pub fn approve(&mut self, name: &str, capabilities: Vec<String>) -> Result<()> {
        let entry = self.plugins.get_mut(name).ok_or_else(|| {
            FugueError::Plugin(format!("plugin '{}' not found", name))
        })?;
        entry.approved = true;
        entry.granted_capabilities = capabilities;
        Ok(())
    }

    /// Revoke a plugin's approval
    pub fn revoke(&mut self, name: &str) -> Result<()> {
        let entry = self.plugins.get_mut(name).ok_or_else(|| {
            FugueError::Plugin(format!("plugin '{}' not found", name))
        })?;
        entry.approved = false;
        entry.granted_capabilities.clear();
        Ok(())
    }

    /// Check if a plugin's binary has changed since approval
    pub fn verify_binary(&self, name: &str) -> Result<bool> {
        let entry = self.plugins.get(name).ok_or_else(|| {
            FugueError::Plugin(format!("plugin '{}' not found", name))
        })?;

        let current_hash = hash_file(&entry.wasm_path)?;
        Ok(current_hash == entry.binary_hash)
    }

    /// Update the stored hash for a plugin (after re-approval)
    pub fn update_hash(&mut self, name: &str) -> Result<()> {
        let entry = self.plugins.get_mut(name).ok_or_else(|| {
            FugueError::Plugin(format!("plugin '{}' not found", name))
        })?;
        entry.binary_hash = hash_file(&entry.wasm_path)?;
        Ok(())
    }
}

/// Hash a file with BLAKE3
fn hash_file(path: &Path) -> Result<String> {
    let data = std::fs::read(path).map_err(|e| {
        FugueError::Plugin(format!("failed to read {}: {}", path.display(), e))
    })?;
    Ok(blake3::hash(&data).to_hex().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn setup_plugin(dir: &Path) -> PathBuf {
        let plugin_dir = dir.join("echo-tool");
        fs::create_dir_all(&plugin_dir).unwrap();

        let manifest = r#"
capabilities = ["ipc:messages"]

[plugin]
name = "echo-tool"
version = "0.1.0"
description = "Echoes input back"
wasm_file = "echo_tool.wasm"
"#;
        let manifest_path = plugin_dir.join("manifest.toml");
        fs::write(&manifest_path, manifest).unwrap();
        // Create a fake WASM binary
        fs::write(plugin_dir.join("echo_tool.wasm"), b"fake wasm binary").unwrap();

        manifest_path
    }

    #[test]
    fn test_install_plugin() {
        let dir = TempDir::new().unwrap();
        let manifest_path = setup_plugin(dir.path());

        let mut registry = PluginRegistry::new();
        let entry = registry.install(&manifest_path, dir.path()).unwrap();

        assert_eq!(entry.name, "echo-tool");
        assert_eq!(entry.version, "0.1.0");
        assert!(!entry.approved);
        assert!(!entry.binary_hash.is_empty());
    }

    #[test]
    fn test_list_plugins() {
        let dir = TempDir::new().unwrap();
        let manifest_path = setup_plugin(dir.path());

        let mut registry = PluginRegistry::new();
        registry.install(&manifest_path, dir.path()).unwrap();

        let names = registry.list();
        assert_eq!(names, vec!["echo-tool"]);
    }

    #[test]
    fn test_remove_plugin() {
        let dir = TempDir::new().unwrap();
        let manifest_path = setup_plugin(dir.path());

        let mut registry = PluginRegistry::new();
        registry.install(&manifest_path, dir.path()).unwrap();

        assert!(registry.remove("echo-tool"));
        assert!(registry.list().is_empty());
    }

    #[test]
    fn test_approve_plugin() {
        let dir = TempDir::new().unwrap();
        let manifest_path = setup_plugin(dir.path());

        let mut registry = PluginRegistry::new();
        registry.install(&manifest_path, dir.path()).unwrap();

        registry
            .approve(
                "echo-tool",
                vec!["ipc:messages".to_string()],
            )
            .unwrap();

        let entry = registry.get("echo-tool").unwrap();
        assert!(entry.approved);
        assert_eq!(entry.granted_capabilities, vec!["ipc:messages"]);
    }

    #[test]
    fn test_revoke_plugin() {
        let dir = TempDir::new().unwrap();
        let manifest_path = setup_plugin(dir.path());

        let mut registry = PluginRegistry::new();
        registry.install(&manifest_path, dir.path()).unwrap();
        registry
            .approve("echo-tool", vec!["ipc:messages".to_string()])
            .unwrap();
        registry.revoke("echo-tool").unwrap();

        let entry = registry.get("echo-tool").unwrap();
        assert!(!entry.approved);
        assert!(entry.granted_capabilities.is_empty());
    }

    #[test]
    fn test_verify_binary_unchanged() {
        let dir = TempDir::new().unwrap();
        let manifest_path = setup_plugin(dir.path());

        let mut registry = PluginRegistry::new();
        registry.install(&manifest_path, dir.path()).unwrap();

        assert!(registry.verify_binary("echo-tool").unwrap());
    }

    #[test]
    fn test_verify_binary_changed() {
        let dir = TempDir::new().unwrap();
        let manifest_path = setup_plugin(dir.path());

        let mut registry = PluginRegistry::new();
        registry.install(&manifest_path, dir.path()).unwrap();

        // Modify the WASM binary
        let wasm_path = dir.path().join("echo-tool").join("echo_tool.wasm");
        fs::write(&wasm_path, b"modified wasm binary").unwrap();

        assert!(!registry.verify_binary("echo-tool").unwrap());
    }

    #[test]
    fn test_registry_save_load() {
        let dir = TempDir::new().unwrap();
        let manifest_path = setup_plugin(dir.path());
        let registry_path = dir.path().join("registry.json");

        {
            let mut registry = PluginRegistry::new();
            registry.install(&manifest_path, dir.path()).unwrap();
            registry
                .approve("echo-tool", vec!["ipc:messages".to_string()])
                .unwrap();
            registry.save(&registry_path).unwrap();
        }

        {
            let registry = PluginRegistry::load(&registry_path).unwrap();
            let entry = registry.get("echo-tool").unwrap();
            assert_eq!(entry.name, "echo-tool");
            assert!(entry.approved);
        }
    }

    #[test]
    fn test_install_missing_wasm() {
        let dir = TempDir::new().unwrap();
        let plugin_dir = dir.path().join("bad-plugin");
        fs::create_dir_all(&plugin_dir).unwrap();

        let manifest = r#"
[plugin]
name = "bad-plugin"
version = "0.1.0"
description = "Missing WASM"
wasm_file = "missing.wasm"
"#;
        let manifest_path = plugin_dir.join("manifest.toml");
        fs::write(&manifest_path, manifest).unwrap();

        let mut registry = PluginRegistry::new();
        let result = registry.install(&manifest_path, dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not found"));
    }
}
