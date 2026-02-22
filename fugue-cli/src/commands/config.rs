use anyhow::Result;
use fugue_core::FugueConfig;

pub async fn init(force: bool) -> Result<()> {
    let config_path = FugueConfig::default_config_path();

    if config_path.exists() && !force {
        eprintln!(
            "Config file already exists at {}",
            config_path.display()
        );
        eprintln!("Use --force to overwrite");
        std::process::exit(1);
    }

    let config = FugueConfig::default_config();
    let toml_str = config.to_toml_string()?;

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(&config_path, &toml_str)?;
    println!("Config written to {}", config_path.display());
    println!("\nDefault configuration:");
    println!("  - HTTP API: disabled");
    println!("  - Bind address: 127.0.0.1 (localhost only)");
    println!("  - Vault backend: encrypted file");
    println!("  - Audit logging: enabled");
    println!("\nEdit {} to configure providers and channels.", config_path.display());

    Ok(())
}

pub async fn show() -> Result<()> {
    let config_path = FugueConfig::default_config_path();

    if !config_path.exists() {
        eprintln!("No config file found at {}", config_path.display());
        eprintln!("Run 'fugue config init' to create one");
        std::process::exit(1);
    }

    let content = std::fs::read_to_string(&config_path)?;
    println!("{}", content);
    Ok(())
}

pub async fn validate() -> Result<()> {
    let config_path = FugueConfig::default_config_path();

    if !config_path.exists() {
        eprintln!("No config file found at {}", config_path.display());
        std::process::exit(1);
    }

    match FugueConfig::load(&config_path) {
        Ok(_) => {
            println!("Config is valid.");
            Ok(())
        }
        Err(e) => {
            eprintln!("Config validation failed: {}", e);
            std::process::exit(1);
        }
    }
}
