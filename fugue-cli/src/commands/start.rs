use anyhow::Result;
use fugue_core::audit::{self, AuditEventType, AuditLog, AuditSeverity};
use fugue_core::ipc::{self, ChatMessage, IpcMessage};
use fugue_core::plugin::runtime::RuntimeConfig;
use fugue_core::plugin::{OnMessageResult, PluginManager};
use fugue_core::provider::ProviderManager;
use fugue_core::router::{RouteResponse, Router};
use fugue_core::state::StateStore;
use fugue_core::vault::Vault;
use fugue_core::FugueConfig;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, Semaphore};

/// Maximum number of concurrent IPC connections
const MAX_CONCURRENT_CONNECTIONS: usize = 32;

/// Response channel buffer size per adapter
const RESPONSE_BUFFER_SIZE: usize = 64;

/// Shared adapter response channels — maps channel name to response sender.
/// Used by the main event loop to send responses back to the correct adapter.
type ResponseChannels = Arc<tokio::sync::Mutex<HashMap<String, mpsc::Sender<RouteResponse>>>>;

pub async fn run(config_path: Option<String>, _foreground: bool) -> Result<()> {
    let config_path = config_path
        .map(PathBuf::from)
        .unwrap_or_else(FugueConfig::default_config_path);

    if !config_path.exists() {
        eprintln!("Config file not found at {}", config_path.display());
        eprintln!("Run 'fugue config init' to create a default config");
        std::process::exit(1);
    }

    let config = FugueConfig::load(&config_path)?;

    // Initialize tracing
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&config.core.log_level));

    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    tracing::info!("starting fugue");

    // Initialize state store
    let state_path = FugueConfig::data_dir().join("state.db");
    let state = StateStore::open(&state_path)?;
    let state = Arc::new(Mutex::new(state));
    tracing::info!("state store opened at {}", state_path.display());

    // Load approved plugins
    let registry_path = FugueConfig::data_dir().join("plugin_registry.json");
    let runtime_config = RuntimeConfig {
        max_memory_bytes: config.plugins.memory_limit_bytes as usize,
        max_fuel: config.plugins.fuel_limit,
    };
    let mut plugin_manager =
        PluginManager::load(&registry_path, runtime_config, Some(state.clone()))?;

    // Initialize audit log
    let audit_log = if config.core.audit_enabled {
        let audit_path = FugueConfig::data_dir().join("audit.db");
        let log = AuditLog::open(&audit_path)?;
        log.append(&audit::event(
            AuditEventType::ServiceStarted,
            "fugue-core",
            "core service started",
            AuditSeverity::Info,
        ))?;
        log.append(&audit::event(
            AuditEventType::ConfigLoaded,
            "config",
            format!("loaded from {}", config_path.display()),
            AuditSeverity::Info,
        ))?;
        tracing::info!("audit log opened at {}", audit_path.display());
        Some(log)
    } else {
        None
    };

    // Initialize provider manager
    let mut provider_manager = ProviderManager::new();

    // Set up vault if any providers need credentials
    let vault = Vault::load_from_config(&config)?;

    // Register providers
    for (name, provider_config) in &config.providers {
        tracing::info!("registering provider: {}", name);
        provider_manager.register(name.clone(), provider_config.clone(), vault.as_ref())?;
    }

    // Initialize router
    let mut router = Router::new(256);

    // Set system prompt from config
    if let Some(ref prompt) = config.core.system_prompt {
        router.set_system_prompt(prompt.clone());
        tracing::info!("system prompt set ({} chars)", prompt.len());
    }

    let max_history = config.core.max_history_messages;

    // Shared response channels for bidirectional communication
    let response_channels: ResponseChannels = Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    // Set up IPC listener
    let socket_path = &config.core.socket_path;
    let listener = ipc::create_listener(socket_path).await?;

    println!("Fugue is running");
    println!("  Socket: {}", socket_path.display());
    println!("  Providers: {:?}", provider_manager.list_providers());
    println!("  Plugins: {} loaded", plugin_manager.loaded_count());
    println!("  History: {} messages per channel", max_history);

    // Auto-spawn configured channel adapters
    for (name, channel_config) in &config.channels {
        match channel_config.channel_type {
            fugue_core::config::ChannelType::Telegram => {
                let bot_token = match &channel_config.credential {
                    Some(cred_ref) => {
                        let cred_name = cred_ref.strip_prefix("vault:").unwrap_or(cred_ref);
                        match vault.as_ref().and_then(|v| v.get(cred_name).ok().flatten()) {
                            Some(token) => token,
                            None => {
                                tracing::warn!(
                                    "skipping telegram adapter: credential '{}' not found",
                                    cred_name
                                );
                                continue;
                            }
                        }
                    }
                    None => {
                        tracing::warn!("skipping telegram adapter: no credential configured");
                        continue;
                    }
                };

                let allowed_ids = channel_config.allowed_ids.clone();
                let sock = config.core.socket_path.clone();
                let adapter_name = name.clone();

                tokio::spawn(async move {
                    tracing::info!("spawning telegram adapter '{}'", adapter_name);
                    let adapter =
                        fugue_adapters::telegram::TelegramAdapter::new(bot_token, allowed_ids);
                    if let Err(e) = adapter.run(&sock).await {
                        tracing::error!("telegram adapter '{}' exited: {}", adapter_name, e);
                    }
                });

                println!("  Telegram adapter '{}' started", name);
            }
            _ => {
                tracing::debug!(
                    "skipping unsupported channel type: {:?}",
                    channel_config.channel_type
                );
            }
        }
    }

    println!("  Press Ctrl+C to stop");

    // Accept IPC connections
    let incoming_tx = router.incoming_sender();
    let mut receiver = router.take_receiver().unwrap();
    let conn_semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

    // Main event loop
    tokio::select! {
        // Branch 1: Accept new IPC connections from adapters
        _ = async {
            loop {
                match listener.accept().await {
                    Ok((stream, _addr)) => {
                        let tx = incoming_tx.clone();
                        let sem = conn_semaphore.clone();
                        let channels = response_channels.clone();
                        let permit = match sem.try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => {
                                tracing::warn!(
                                    "max concurrent IPC connections ({}) reached, rejecting",
                                    MAX_CONCURRENT_CONNECTIONS
                                );
                                continue;
                            }
                        };

                        tokio::spawn(async move {
                            let _permit = permit;
                            handle_adapter_connection(stream, tx, channels).await;
                        });
                    }
                    Err(e) => {
                        tracing::error!("failed to accept IPC connection: {}", e);
                    }
                }
            }
        } => {}

        // Branch 2: Process incoming messages (router → plugins → LLM → response)
        _ = async {
            while let Some(msg) = receiver.recv().await {
                tracing::info!(
                    request_id = %msg.request_id,
                    "message from {} on {}: {}",
                    msg.sender_id,
                    msg.channel,
                    &msg.content[..msg.content.len().min(100)]
                );

                // --- Plugin pipeline: on_message (before LLM) ---
                let (user_content, extra_context) = match plugin_manager.on_message(&msg) {
                    OnMessageResult::Respond(response) => {
                        tracing::info!(
                            request_id = %msg.request_id,
                            "plugin responded directly"
                        );
                        let route_response = RouteResponse {
                            channel: msg.channel.clone(),
                            recipient_id: msg.sender_id.clone(),
                            content: response,
                            reply_to: Some(msg.message_id.clone()),
                            request_id: msg.request_id.clone(),
                        };
                        send_to_adapter(&response_channels, &msg.channel, route_response).await;
                        continue;
                    }
                    OnMessageResult::Continue {
                        modified_content,
                        extra_context,
                    } => {
                        let content = modified_content.unwrap_or_else(|| msg.content.clone());
                        (content, extra_context)
                    }
                };

                // Store user message in conversation history
                {
                    let st = state.lock().unwrap();
                    let _ = st.add_message(
                        &msg.channel,
                        &msg.sender_id,
                        msg.sender_name.as_deref(),
                        "user",
                        &user_content,
                        Some(&msg.message_id),
                    );
                }

                // Build conversation history from stored messages
                let history: Vec<ChatMessage> = {
                    let st = state.lock().unwrap();
                    match st.get_recent_messages(&msg.channel, max_history) {
                        Ok(msgs) => msgs
                            .into_iter()
                            .map(|m| ChatMessage {
                                role: m.role,
                                content: m.content,
                            })
                            .collect(),
                        Err(e) => {
                            tracing::warn!("failed to load history: {}, using current message only", e);
                            vec![ChatMessage {
                                role: "user".to_string(),
                                content: user_content.clone(),
                            }]
                        }
                    }
                };

                // Try to get an LLM response (with fallback across providers)
                if !provider_manager.list_providers().is_empty() {
                    let mut messages = router.build_llm_messages(&history);

                    // Inject plugin context into the system prompt
                    if !extra_context.is_empty() {
                        let ctx = extra_context.join("\n");
                        if let Some(sys_msg) = messages.first_mut() {
                            if sys_msg.role == "system" {
                                sys_msg.content.push_str("\n\n");
                                sys_msg.content.push_str(&ctx);
                            }
                        } else {
                            messages.insert(
                                0,
                                ChatMessage {
                                    role: "system".to_string(),
                                    content: ctx,
                                },
                            );
                        }
                    }

                    match provider_manager.chat_with_fallback(&messages).await {
                        Ok((response, provider_used)) => {
                            tracing::info!(
                                request_id = %msg.request_id,
                                provider = %provider_used,
                                "LLM response: {}",
                                &response.content[..response.content.len().min(100)]
                            );

                            // --- Plugin pipeline: on_response (after LLM) ---
                            let result = plugin_manager.on_response(&msg, &response.content);
                            let final_content = result
                                .modified_response
                                .unwrap_or(response.content);

                            // Store assistant response in conversation history
                            {
                                let st = state.lock().unwrap();
                                let _ = st.add_message(
                                    &msg.channel,
                                    "assistant",
                                    None,
                                    "assistant",
                                    &final_content,
                                    None,
                                );
                            }

                            let route_response = RouteResponse {
                                channel: msg.channel.clone(),
                                recipient_id: msg.sender_id.clone(),
                                content: final_content,
                                reply_to: Some(msg.message_id.clone()),
                                request_id: msg.request_id.clone(),
                            };
                            send_to_adapter(&response_channels, &msg.channel, route_response).await;
                        }
                        Err(e) => {
                            tracing::error!(
                                request_id = %msg.request_id,
                                "LLM error: {}",
                                e
                            );
                            // Send error back to adapter
                            let route_response = RouteResponse {
                                channel: msg.channel.clone(),
                                recipient_id: msg.sender_id.clone(),
                                content: format!("Error: {}", e),
                                reply_to: Some(msg.message_id.clone()),
                                request_id: msg.request_id.clone(),
                            };
                            send_to_adapter(&response_channels, &msg.channel, route_response).await;
                        }
                    }
                } else {
                    tracing::warn!("no providers configured");
                    let route_response = RouteResponse {
                        channel: msg.channel.clone(),
                        recipient_id: msg.sender_id.clone(),
                        content: "Error: no LLM providers configured".to_string(),
                        reply_to: Some(msg.message_id.clone()),
                        request_id: msg.request_id.clone(),
                    };
                    send_to_adapter(&response_channels, &msg.channel, route_response).await;
                }
            }
        } => {}

        // Branch 3: Ctrl+C shutdown
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("received Ctrl+C, shutting down");
        }
    }

    // Cleanup
    if let Some(ref log) = audit_log {
        log.append(&audit::event(
            AuditEventType::ServiceStopped,
            "fugue-core",
            "core service stopped",
            AuditSeverity::Info,
        ))?;
    }

    // Remove socket file
    let _ = std::fs::remove_file(socket_path);

    println!("Fugue stopped");
    Ok(())
}

/// Handle a single adapter connection with bidirectional IPC.
///
/// 1. Reads the Register message to get the adapter's channel name
/// 2. Splits the stream into read/write halves
/// 3. Spawns a response-writer task that forwards responses back to the adapter
/// 4. Reads incoming messages and forwards them to the router
async fn handle_adapter_connection(
    stream: tokio::net::UnixStream,
    incoming_tx: mpsc::Sender<fugue_core::router::RoutableMessage>,
    response_channels: ResponseChannels,
) {
    let (mut read_half, mut write_half) = stream.into_split();

    // Step 1: Read the Register message
    let channel_name = match ipc::read_from(&mut read_half).await {
        Ok(IpcMessage::Register {
            adapter_name,
            adapter_type,
        }) => {
            tracing::info!("adapter registered: {} ({})", adapter_name, adapter_type);
            let ack = IpcMessage::RegisterAck {
                session_id: uuid::Uuid::new_v4().to_string(),
            };
            if let Err(e) = ipc::write_to(&mut write_half, &ack).await {
                tracing::error!("failed to send RegisterAck: {}", e);
                return;
            }
            adapter_name
        }
        Ok(IpcMessage::Ping) => {
            let _ = ipc::write_to(&mut write_half, &IpcMessage::Pong).await;
            return;
        }
        Ok(other) => {
            tracing::warn!("expected Register message, got: {:?}", other);
            return;
        }
        Err(e) => {
            tracing::debug!("connection closed before register: {}", e);
            return;
        }
    };

    // Step 2: Create a response channel for this adapter
    let (response_tx, mut response_rx) = mpsc::channel::<RouteResponse>(RESPONSE_BUFFER_SIZE);

    // Register in the shared map
    {
        let mut channels = response_channels.lock().await;
        channels.insert(channel_name.clone(), response_tx);
    }

    let channel_name_clone = channel_name.clone();

    // Step 3: Spawn response-writer task (reads from mpsc, writes to IPC socket)
    let writer_handle = tokio::spawn(async move {
        while let Some(response) = response_rx.recv().await {
            let ipc_msg = Router::response_to_ipc(&response);
            if let Err(e) = ipc::write_to(&mut write_half, &ipc_msg).await {
                tracing::debug!("response write failed for {}: {}", channel_name_clone, e);
                break;
            }
        }
    });

    // Step 4: Read incoming messages and forward to router
    loop {
        match ipc::read_from(&mut read_half).await {
            Ok(msg) => match msg {
                IpcMessage::Ping => {
                    // Can't write to write_half from here (it's moved), so skip
                    // Pings should be handled before register
                }
                IpcMessage::Shutdown => {
                    tracing::info!("shutdown requested via IPC from {}", channel_name);
                    break;
                }
                other => {
                    if let Some(routable) = Router::ipc_to_routable(&other) {
                        tracing::info!(
                            request_id = %routable.request_id,
                            "routing message from {} on {}",
                            routable.sender_id,
                            routable.channel,
                        );
                        let _ = incoming_tx.send(routable).await;
                    }
                }
            },
            Err(e) => {
                tracing::debug!("adapter {} disconnected: {}", channel_name, e);
                break;
            }
        }
    }

    // Cleanup: unregister channel and abort writer
    {
        let mut channels = response_channels.lock().await;
        channels.remove(&channel_name);
    }
    writer_handle.abort();
    tracing::info!("adapter {} cleaned up", channel_name);
}

/// Send a response to an adapter via its registered response channel.
async fn send_to_adapter(channels: &ResponseChannels, channel_name: &str, response: RouteResponse) {
    let channels = channels.lock().await;
    if let Some(sender) = channels.get(channel_name) {
        if let Err(e) = sender.send(response).await {
            tracing::error!("failed to send response to adapter {}: {}", channel_name, e);
        }
    } else {
        tracing::warn!(
            "no adapter registered for channel '{}', response dropped",
            channel_name
        );
    }
}
