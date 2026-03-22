use anyhow::Result;
use fugue_core::vault::Vault;
use fugue_core::FugueConfig;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

fn salt_path() -> PathBuf {
    FugueConfig::data_dir().join("vault.salt")
}

fn key_path() -> PathBuf {
    FugueConfig::data_dir().join("vault.key")
}

fn read_password(prompt: &str) -> Result<String> {
    eprint!("{}", prompt);
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn open_vault_with_password() -> Result<Vault> {
    let config = if FugueConfig::default_config_path().exists() {
        FugueConfig::load(&FugueConfig::default_config_path())?
    } else {
        FugueConfig::default_config()
    };

    let mut vault = Vault::new(config.vault.backend, config.vault.encrypted_file_path);

    let salt_file = salt_path();
    if !salt_file.exists() {
        anyhow::bail!(
            "No vault salt found. Run 'fugue vault init --password' first to initialize a password-protected vault."
        );
    }

    let salt_data = std::fs::read(&salt_file)?;
    if salt_data.len() != 32 {
        anyhow::bail!("Corrupt vault salt file");
    }
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&salt_data);

    let password = read_password("Enter vault password: ")?;
    if password.is_empty() {
        anyhow::bail!("Password cannot be empty");
    }

    let key = Vault::derive_key_from_password(&password, &salt)?;
    vault.init_with_key(key);

    Ok(vault)
}

fn open_vault_with_file_key() -> Result<Vault> {
    let config = if FugueConfig::default_config_path().exists() {
        FugueConfig::load(&FugueConfig::default_config_path())?
    } else {
        FugueConfig::default_config()
    };

    let mut vault = Vault::new(config.vault.backend, config.vault.encrypted_file_path);
    let key = derive_vault_key()?;
    vault.init_with_key(key);

    Ok(vault)
}

fn open_vault(use_password: bool) -> Result<Vault> {
    if use_password {
        open_vault_with_password()
    } else {
        open_vault_with_file_key()
    }
}

fn derive_vault_key() -> Result<[u8; 32]> {
    // Use a key file stored alongside the vault
    let kp = key_path();

    if kp.exists() {
        // Warn if key file has overly permissive permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&kp)?.permissions();
            let mode = perms.mode() & 0o777;
            if mode & 0o077 != 0 {
                eprintln!(
                    "Warning: vault key file {} has permissions {:o}, which allows access by other users.",
                    kp.display(),
                    mode
                );
                eprintln!("         Run: chmod 600 {}", kp.display());
            }
        }

        let data = std::fs::read(&kp)?;
        if data.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&data);
            return Ok(key);
        }
    }

    // Generate a new key
    let key = Vault::generate_key();
    if let Some(parent) = kp.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&kp, key)?;

    // Set restrictive permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&kp, std::fs::Permissions::from_mode(0o600))?;
    }

    eprintln!("Warning: Storing vault key as plaintext file. Use --password for better security.");

    Ok(key)
}

pub async fn init(use_password: bool) -> Result<()> {
    let data_dir = FugueConfig::data_dir();
    std::fs::create_dir_all(&data_dir)?;

    if use_password {
        let sf = salt_path();
        if sf.exists() {
            eprintln!("Vault salt already exists at {}", sf.display());
            eprintln!("Remove it first if you want to re-initialize.");
            std::process::exit(1);
        }

        let password = read_password("Enter new vault password: ")?;
        if password.is_empty() {
            eprintln!("Password cannot be empty");
            std::process::exit(1);
        }

        let confirm = read_password("Confirm vault password: ")?;
        if password != confirm {
            eprintln!("Passwords do not match");
            std::process::exit(1);
        }

        let salt = Vault::generate_salt();

        // Verify we can derive a key (validates the password is usable)
        let _key = Vault::derive_key_from_password(&password, &salt)?;

        // Store only the salt, not the key
        std::fs::write(&sf, salt)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&sf, std::fs::Permissions::from_mode(0o600))?;
        }

        println!("Vault initialized with password-derived key");
        println!("Salt stored at: {}", sf.display());
        println!("The encryption key is never stored on disk.");
    } else {
        let _key = derive_vault_key()?;
        println!("Vault initialized with file-based key");
        println!("Key stored at: {}", key_path().display());
    }

    Ok(())
}

pub async fn set(name: &str, value: Option<&str>, use_password: bool) -> Result<()> {
    let vault = open_vault(use_password)?;

    let value = if let Some(v) = value {
        eprintln!("Warning: passing secrets as command-line arguments exposes them in shell history and process listings.");
        eprintln!("         Omit the value argument to enter it interactively instead.");
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

pub async fn list(use_password: bool) -> Result<()> {
    let vault = open_vault(use_password)?;
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

pub async fn remove(name: &str, use_password: bool) -> Result<()> {
    let vault = open_vault(use_password)?;
    vault.remove(name)?;
    println!("Credential '{}' removed", name);
    Ok(())
}
