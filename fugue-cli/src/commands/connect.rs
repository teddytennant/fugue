use anyhow::{bail, Result};
use fugue_adapters::telegram::TelegramAdapter;
use fugue_core::vault::Vault;
use fugue_core::FugueConfig;

pub async fn run(channel_name: String) -> Result<()> {
    let config = if FugueConfig::default_config_path().exists() {
        FugueConfig::load(&FugueConfig::default_config_path())?
    } else {
        bail!("No config file found. Run 'fugue config init' first.");
    };

    let channel_config = config
        .channels
        .get(&channel_name)
        .ok_or_else(|| anyhow::anyhow!("channel '{}' not found in config", channel_name))?;

    let socket_path = &config.core.socket_path;

    match &channel_config.channel_type {
        fugue_core::config::ChannelType::Telegram => {
            // Resolve bot token from vault
            let bot_token = match &channel_config.credential {
                Some(cred_ref) => {
                    let vault = Vault::load_from_config(&config)?
                        .ok_or_else(|| anyhow::anyhow!("vault not configured"))?;
                    let cred_name = cred_ref.strip_prefix("vault:").unwrap_or(cred_ref);
                    vault.get(cred_name)?.ok_or_else(|| {
                        anyhow::anyhow!("credential '{}' not found in vault", cred_name)
                    })?
                }
                None => bail!("telegram channel requires a credential (bot token)"),
            };

            println!("Connecting Telegram adapter to fugue daemon...");
            println!("  Socket: {}", socket_path.display());
            println!("  Allowed IDs: {:?}", channel_config.allowed_ids);

            let adapter = TelegramAdapter::new(bot_token, channel_config.allowed_ids.clone());
            adapter
                .run(socket_path)
                .await
                .map_err(|e| anyhow::anyhow!("{}", e))
        }
        other => {
            bail!(
                "adapter for channel type '{:?}' is not yet implemented",
                other
            );
        }
    }
}
