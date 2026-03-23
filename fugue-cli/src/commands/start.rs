use anyhow::Result;
use fugue_core::audit::{self, AuditEventType, AuditLog, AuditSeverity};
use fugue_core::ipc::{self, ChatMessage, IpcMessage};
use fugue_core::provider::ProviderManager;
use fugue_core::router::{RouteResponse, Router};
use fugue_core::state::StateStore;
use fugue_core::vault::Vault;
use fugue_core::FugueConfig;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Maximum number of concurrent IPC connections
const MAX_CONCURRENT_CONNECTIONS: usize = 32;

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

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .init();

    tracing::info!("starting fugue");

    // Initialize state store
    let state_path = FugueConfig::data_dir().join("state.db");
    let _state = StateStore::open(&state_path)?;
    tracing::info!("state store opened at {}", state_path.display());

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
        provider_manager.register(
            name.clone(),
            provider_config.clone(),
            vault.as_ref(),
        )?;
    }

    // Initialize router
    let mut router = Router::new(256);

    // Set up IPC listener
    let socket_path = &config.core.socket_path;
    let listener = ipc::create_listener(socket_path).await?;

    println!("Fugue is running");
    println!("  Socket: {}", socket_path.display());
    println!("  Providers: {:?}", provider_manager.list_providers());
    println!("  Press Ctrl+C to stop");

    // Accept IPC connections
    let incoming_tx = router.incoming_sender();
    let mut receiver = router.take_receiver().unwrap();
    let conn_semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

    // Main event loop
    tokio::select! {
        _ = async {
            loop {
                match listener.accept().await {
                    Ok((mut stream, _addr)) => {
                        let tx = incoming_tx.clone();
                        let sem = conn_semaphore.clone();
                        let permit = match sem.try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => {
                                tracing::warn!(
                                    "max concurrent IPC connections ({}) reached, rejecting connection",
                                    MAX_CONCURRENT_CONNECTIONS
                                );
                                let _ = ipc::write_message(
                                    &mut stream,
                                    &IpcMessage::Error {
                                        request_id: None,
                                        message: "too many concurrent connections".to_string(),
                                    },
                                ).await;
                                continue;
                            }
                        };
                        tokio::spawn(async move {
                            let _permit = permit; // held until task ends
                            tracing::info!("new IPC connection");
                            loop {
                                match ipc::read_message(&mut stream).await {
                                    Ok(msg) => {
                                        match msg {
                                            IpcMessage::Ping => {
                                                let _ = ipc::write_message(&mut stream, &IpcMessage::Pong).await;
                                            }
                                            IpcMessage::Register { adapter_name, adapter_type } => {
                                                tracing::info!("adapter registered: {} ({})", adapter_name, adapter_type);
                                                let ack = IpcMessage::RegisterAck {
                                                    session_id: uuid::Uuid::new_v4().to_string(),
                                                };
                                                let _ = ipc::write_message(&mut stream, &ack).await;
                                            }
                                            IpcMessage::Shutdown => {
                                                tracing::info!("shutdown requested via IPC");
                                                return;
                                            }
                                            other => {
                                                if let Some(routable) = Router::ipc_to_routable(&other) {
                                                    tracing::info!(
                                                        request_id = %routable.request_id,
                                                        "routing message from {} on {}",
                                                        routable.sender_id,
                                                        routable.channel,
                                                    );
                                                    let _ = tx.send(routable).await;
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        tracing::debug!("IPC connection closed: {}", e);
                                        return;
                                    }
                                }
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!("failed to accept IPC connection: {}", e);
                    }
                }
            }
        } => {}
        _ = async {
            while let Some(msg) = receiver.recv().await {
                tracing::info!(
                    request_id = %msg.request_id,
                    "message from {} on {}: {}",
                    msg.sender_id,
                    msg.channel,
                    &msg.content[..msg.content.len().min(100)]
                );

                // Build conversation history from state store
                let history = vec![ChatMessage {
                    role: "user".to_string(),
                    content: msg.content.clone(),
                }];

                // Try to get an LLM response
                let providers = provider_manager.list_providers();
                if let Some(provider_name) = providers.first() {
                    let messages = router.build_llm_messages(&history);
                    match provider_manager.chat(provider_name, &messages).await {
                        Ok(response) => {
                            tracing::info!(
                                request_id = %msg.request_id,
                                "LLM response: {}",
                                &response.content[..response.content.len().min(100)]
                            );
                            let route_response = RouteResponse {
                                channel: msg.channel,
                                recipient_id: msg.sender_id,
                                content: response.content,
                                reply_to: Some(msg.message_id),
                                request_id: msg.request_id,
                            };
                            if let Err(e) = router.send_response(route_response).await {
                                tracing::error!("failed to route response: {}", e);
                            }
                        }
                        Err(e) => {
                            tracing::error!(
                                request_id = %msg.request_id,
                                "LLM error: {}",
                                e
                            );
                        }
                    }
                }
            }
        } => {}
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
