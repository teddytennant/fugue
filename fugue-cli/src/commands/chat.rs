use anyhow::Result;
use fugue_core::ipc::ChatMessage;
use fugue_core::provider::ProviderManager;
use fugue_core::vault::Vault;
use fugue_core::FugueConfig;
use std::io::{self, BufRead, Write};

pub async fn run(provider_name: Option<String>, system_prompt: Option<String>) -> Result<()> {
    let config = if FugueConfig::default_config_path().exists() {
        FugueConfig::load(&FugueConfig::default_config_path())?
    } else {
        FugueConfig::default_config()
    };

    if config.providers.is_empty() {
        eprintln!("No providers configured.");
        eprintln!("Add a provider to your config file:");
        eprintln!();
        eprintln!("  [providers.ollama]");
        eprintln!("  type = \"ollama\"");
        eprintln!("  base_url = \"http://localhost:11434\"");
        eprintln!("  model = \"llama3.2\"");
        std::process::exit(1);
    }

    // Set up vault if needed
    let vault = Vault::load_from_config(&config)?;

    let mut provider_manager = ProviderManager::new();
    for (name, pconfig) in &config.providers {
        provider_manager.register(name.clone(), pconfig.clone(), vault.as_ref())?;
    }

    let provider = provider_name
        .or_else(|| provider_manager.list_providers().first().map(|s| s.to_string()))
        .ok_or_else(|| anyhow::anyhow!("no provider available"))?;

    println!("Fugue Chat (provider: {}, /quit to exit)", provider);
    println!();

    // Cap conversation history to avoid unbounded memory growth and exceeding
    // LLM context windows. System prompt (if any) is always preserved.
    const MAX_HISTORY_MESSAGES: usize = 100;

    let mut history: Vec<ChatMessage> = Vec::new();

    if let Some(system) = system_prompt {
        history.push(ChatMessage {
            role: "system".to_string(),
            content: system,
        });
    }

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    loop {
        print!("> ");
        stdout.flush()?;

        let mut input = String::new();
        stdin.lock().read_line(&mut input)?;
        let input = input.trim();

        if input.is_empty() {
            continue;
        }

        if input == "/quit" || input == "/exit" {
            break;
        }

        if input == "/clear" {
            history.retain(|m| m.role == "system");
            println!("History cleared.");
            continue;
        }

        history.push(ChatMessage {
            role: "user".to_string(),
            content: input.to_string(),
        });

        match provider_manager.chat(&provider, &history).await {
            Ok(response) => {
                println!("\n{}\n", response.content);
                history.push(ChatMessage {
                    role: "assistant".to_string(),
                    content: response.content,
                });

                // Trim history to prevent unbounded growth. Keep the system
                // prompt (if present at index 0) and the most recent messages.
                let has_system = history.first().is_some_and(|m| m.role == "system");
                let non_system_start = if has_system { 1 } else { 0 };
                let non_system_count = history.len() - non_system_start;
                if non_system_count > MAX_HISTORY_MESSAGES {
                    let excess = non_system_count - MAX_HISTORY_MESSAGES;
                    history.drain(non_system_start..non_system_start + excess);
                }
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                // Remove the failed user message from history
                history.pop();
            }
        }
    }

    Ok(())
}
