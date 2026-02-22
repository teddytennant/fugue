use anyhow::Result;
use fugue_core::vault::Vault;
use fugue_core::FugueConfig;
use std::io::{self, BufRead, Write};

fn open_vault() -> Result<Vault> {
    let config = if FugueConfig::default_config_path().exists() {
        FugueConfig::load(&FugueConfig::default_config_path())?
    } else {
        FugueConfig::default_config()
    };

    let mut vault = Vault::new(
        config.vault.backend,
        config.vault.encrypted_file_path,
    );

    // For the encrypted file backend, we need a master key
    // In production, this would be derived from a password or stored securely
    // For now, use a deterministic key derived from a fixed seed for the user
    let key = derive_vault_key()?;
    vault.init_with_key(key);

    Ok(vault)
}

fn derive_vault_key() -> Result<[u8; 32]> {
    // Use a key file stored alongside the vault
    let key_path = FugueConfig::data_dir().join("vault.key");

    if key_path.exists() {
        let data = std::fs::read(&key_path)?;
        if data.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&data);
            return Ok(key);
        }
    }

    // Generate a new key
    let key = Vault::generate_key();
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&key_path, key)?;

    // Set restrictive permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(key)
}

pub async fn set(name: &str, value: Option<&str>) -> Result<()> {
    let vault = open_vault()?;

    let value = if let Some(v) = value {
        v.to_string()
    } else {
        eprint!("Enter value for '{}': ", name);
        io::stderr().flush()?;
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        line.trim().to_string()
    };

    if value.is_empty() {
        eprintln!("Value cannot be empty");
        std::process::exit(1);
    }

    vault.set(name, &value)?;
    println!("Credential '{}' stored successfully", name);
    println!("Reference it in config as: vault:{}", name);
    Ok(())
}

pub async fn list() -> Result<()> {
    let vault = open_vault()?;
    let names = vault.list()?;

    if names.is_empty() {
        println!("No credentials stored");
    } else {
        println!("Stored credentials:");
        for name in names {
            println!("  - {}", name);
        }
    }
    Ok(())
}

pub async fn remove(name: &str) -> Result<()> {
    let vault = open_vault()?;
    vault.remove(name)?;
    println!("Credential '{}' removed", name);
    Ok(())
}
