use anyhow::Result;
use fugue_core::plugin::{PluginManifest, PluginRegistry, RiskLevel};
use fugue_core::FugueConfig;
use std::path::Path;

fn registry_path() -> std::path::PathBuf {
    FugueConfig::data_dir().join("plugin_registry.json")
}

pub async fn install(path: &str) -> Result<()> {
    let manifest_path = Path::new(path).join("manifest.toml");

    if !manifest_path.exists() {
        eprintln!("No manifest.toml found in {}", path);
        std::process::exit(1);
    }

    let manifest = PluginManifest::load(&manifest_path)?;

    println!("Installing plugin: {}", manifest.plugin.name);
    println!("  Version: {}", manifest.plugin.version);
    println!("  Description: {}", manifest.plugin.description);

    let caps = manifest.parsed_capabilities();
    if !caps.is_empty() {
        println!("  Requested capabilities:");
        for cap in &caps {
            println!("    - {} [{}]", cap, cap.risk_level());
        }
    }

    let reg_path = registry_path();
    let mut registry = PluginRegistry::load(&reg_path)?;
    let plugin_dir = FugueConfig::default_config().plugins.directory;
    registry.install(&manifest_path, &plugin_dir)?;
    registry.save(&reg_path)?;

    println!("\nPlugin installed (not yet approved).");
    println!("Run 'fugue plugin approve {}' to approve capabilities.", manifest.plugin.name);
    Ok(())
}

pub async fn remove(name: &str) -> Result<()> {
    let reg_path = registry_path();
    let mut registry = PluginRegistry::load(&reg_path)?;

    if registry.remove(name) {
        registry.save(&reg_path)?;
        println!("Plugin '{}' removed", name);
    } else {
        eprintln!("Plugin '{}' not found", name);
        std::process::exit(1);
    }
    Ok(())
}

pub async fn list() -> Result<()> {
    let reg_path = registry_path();
    let registry = PluginRegistry::load(&reg_path)?;
    let names = registry.list();

    if names.is_empty() {
        println!("No plugins installed");
    } else {
        println!("Installed plugins:");
        for name in names {
            let entry = registry.get(name).unwrap();
            let status = if entry.approved { "approved" } else { "pending" };
            println!("  {} v{} [{}]", entry.name, entry.version, status);
        }
    }
    Ok(())
}

pub async fn inspect(name: &str) -> Result<()> {
    let reg_path = registry_path();
    let registry = PluginRegistry::load(&reg_path)?;

    let entry = registry.get(name).ok_or_else(|| {
        anyhow::anyhow!("plugin '{}' not found", name)
    })?;

    println!("Plugin: {}", entry.name);
    println!("  Version: {}", entry.version);
    println!("  Description: {}", entry.description);
    println!("  WASM path: {}", entry.wasm_path.display());
    println!("  Binary hash: {}", entry.binary_hash);
    println!("  Approved: {}", entry.approved);
    println!("  Installed: {}", entry.installed_at);

    if !entry.granted_capabilities.is_empty() {
        println!("  Granted capabilities:");
        for cap in &entry.granted_capabilities {
            println!("    - {}", cap);
        }
    }

    // Verify binary integrity
    match registry.verify_binary(name) {
        Ok(true) => println!("  Binary integrity: OK"),
        Ok(false) => println!("  Binary integrity: CHANGED (re-approval required)"),
        Err(e) => println!("  Binary integrity: ERROR ({})", e),
    }

    Ok(())
}

pub async fn approve(name: &str) -> Result<()> {
    let reg_path = registry_path();
    let mut registry = PluginRegistry::load(&reg_path)?;

    let entry = registry.get(name).ok_or_else(|| {
        anyhow::anyhow!("plugin '{}' not found", name)
    })?;

    // Load the manifest to get requested capabilities
    let manifest = PluginManifest::load(&entry.manifest_path)?;
    let caps = manifest.parsed_capabilities();

    if caps.is_empty() {
        println!("Plugin '{}' requests no capabilities.", name);
        registry.approve(name, vec![])?;
        registry.save(&reg_path)?;
        println!("Plugin approved.");
        return Ok(());
    }

    println!("Plugin '{}' requests the following capabilities:", name);
    for cap in &caps {
        let risk = cap.risk_level();
        let warning = match risk {
            RiskLevel::Critical => " !! CRITICAL - grants significant host access",
            RiskLevel::High => " ! HIGH RISK",
            _ => "",
        };
        println!("  - {} [{}]{}", cap, risk, warning);
    }

    // Approve all requested capabilities
    let cap_strings: Vec<String> = caps.iter().map(|c| c.to_string()).collect();
    registry.approve(name, cap_strings)?;
    registry.save(&reg_path)?;

    println!("\nPlugin '{}' approved with all requested capabilities.", name);
    Ok(())
}
