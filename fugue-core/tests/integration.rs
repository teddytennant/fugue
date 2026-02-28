//! Integration tests for the Fugue gateway
//!
//! These tests exercise cross-module workflows that span multiple crates.

use fugue_core::audit::{self, AuditEventType, AuditLog, AuditSeverity};
use fugue_core::config::{FugueConfig, VaultBackend};
use fugue_core::ipc::{self, ChatMessage, IpcMessage};
use fugue_core::plugin::capabilities::{Capability, check_capabilities};
use fugue_core::plugin::manifest::PluginManifest;
use fugue_core::plugin::registry::PluginRegistry;
use fugue_core::provider::ProviderManager;
use fugue_core::router::{RouteResponse, Router};
use fugue_core::state::StateStore;
use fugue_core::vault::Vault;
use std::fs;
use tempfile::TempDir;
use tokio::net::UnixStream;

// ---------------------------------------------------------------------------
// Config → Vault → Provider integration
// ---------------------------------------------------------------------------

#[test]
fn test_config_to_vault_to_provider_registration() {
    let dir = TempDir::new().unwrap();

    // 1. Parse a config with a provider that uses a vault credential
    let toml_str = r#"
[providers.anthropic]
type = "anthropic"
credential = "vault:anthropic-api-key"
model = "claude-sonnet-4-20250514"

[providers.ollama]
type = "ollama"
base_url = "http://localhost:11434"
model = "llama3.2"

[vault]
backend = "encryptedfile"
"#;
    let config = FugueConfig::parse(toml_str).unwrap();

    // 2. Set up the vault and store the credential
    let mut vault = Vault::new(
        VaultBackend::EncryptedFile,
        Some(dir.path().join("vault.enc")),
    );
    vault.init_with_key(Vault::generate_key());
    vault.set("anthropic-api-key", "sk-test-integration-key").unwrap();

    // 3. Register all providers
    let mut pm = ProviderManager::new();
    for (name, provider_config) in &config.providers {
        pm.register(name.clone(), provider_config.clone(), Some(&vault))
            .unwrap();
    }

    // 4. Verify all providers registered
    let providers = pm.list_providers();
    assert_eq!(providers.len(), 2);
    assert!(providers.contains(&"anthropic"));
    assert!(providers.contains(&"ollama"));
}

#[test]
fn test_config_provider_with_missing_vault_credential() {
    let dir = TempDir::new().unwrap();

    let toml_str = r#"
[providers.anthropic]
type = "anthropic"
credential = "vault:missing-key"
"#;
    let config = FugueConfig::parse(toml_str).unwrap();

    let mut vault = Vault::new(
        VaultBackend::EncryptedFile,
        Some(dir.path().join("vault.enc")),
    );
    vault.init_with_key(Vault::generate_key());

    let mut pm = ProviderManager::new();
    let result = pm.register(
        "anthropic".to_string(),
        config.providers["anthropic"].clone(),
        Some(&vault),
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not found"));
}

// ---------------------------------------------------------------------------
// Plugin lifecycle: install → approve → verify → revoke
// ---------------------------------------------------------------------------

#[test]
fn test_plugin_full_lifecycle() {
    let dir = TempDir::new().unwrap();

    // 1. Create a plugin directory with manifest and wasm
    let plugin_dir = dir.path().join("echo-tool");
    fs::create_dir_all(&plugin_dir).unwrap();
    fs::write(
        plugin_dir.join("manifest.toml"),
        r#"
capabilities = ["ipc:messages", "llm:call", "state:read"]

[plugin]
name = "echo-tool"
version = "1.0.0"
description = "Echoes input back with LLM enhancement"
author = "Test Author"
wasm_file = "echo_tool.wasm"
"#,
    )
    .unwrap();
    fs::write(plugin_dir.join("echo_tool.wasm"), b"fake wasm binary content").unwrap();

    // 2. Validate the manifest parses and capabilities are correct
    let manifest = PluginManifest::load(&plugin_dir.join("manifest.toml")).unwrap();
    let caps = manifest.parsed_capabilities();
    assert_eq!(caps.len(), 3);
    assert!(caps.contains(&Capability::IpcMessages));
    assert!(caps.contains(&Capability::LlmCall));
    assert!(caps.contains(&Capability::StateRead));

    // 3. Install the plugin
    let registry_path = dir.path().join("registry.json");
    let mut registry = PluginRegistry::new();
    registry
        .install(&plugin_dir.join("manifest.toml"), dir.path())
        .unwrap();

    // 4. Verify it's not approved by default
    let entry = registry.get("echo-tool").unwrap();
    assert!(!entry.approved);

    // 5. Check capabilities are acceptable
    let requested = manifest.parsed_capabilities();
    let granted_strs = vec!["ipc:messages", "llm:call", "state:read"];
    let granted: Vec<Capability> = granted_strs
        .iter()
        .filter_map(|s| Capability::parse(s))
        .collect();
    let denied = check_capabilities(&granted, &requested);
    assert!(denied.is_empty());

    // 6. Approve the plugin
    registry
        .approve(
            "echo-tool",
            granted_strs.iter().map(|s| s.to_string()).collect(),
        )
        .unwrap();
    assert!(registry.get("echo-tool").unwrap().approved);

    // 7. Verify binary hasn't changed
    assert!(registry.verify_binary("echo-tool").unwrap());

    // 8. Save and reload registry
    registry.save(&registry_path).unwrap();
    let loaded_registry = PluginRegistry::load(&registry_path).unwrap();
    assert!(loaded_registry.get("echo-tool").unwrap().approved);

    // 9. Simulate binary change
    fs::write(plugin_dir.join("echo_tool.wasm"), b"modified binary").unwrap();
    assert!(!loaded_registry.verify_binary("echo-tool").unwrap());

    // 10. Revoke the plugin
    let mut registry = loaded_registry;
    registry.revoke("echo-tool").unwrap();
    assert!(!registry.get("echo-tool").unwrap().approved);

    // 11. Remove the plugin
    assert!(registry.remove("echo-tool"));
    assert!(registry.list().is_empty());
}

// ---------------------------------------------------------------------------
// State store + audit log combined workflow
// ---------------------------------------------------------------------------

#[test]
fn test_state_and_audit_combined() {
    let dir = TempDir::new().unwrap();

    let state = StateStore::open(&dir.path().join("state.db")).unwrap();
    let audit = AuditLog::open(&dir.path().join("audit.db")).unwrap();

    // Log service start
    audit
        .append(&audit::event(
            AuditEventType::ServiceStarted,
            "fugue-core",
            "integration test service started",
            AuditSeverity::Info,
        ))
        .unwrap();

    // Simulate a conversation
    let messages = vec![
        ("user", "cli-user", "Hello, how are you?"),
        ("assistant", "system", "I'm doing well, thanks!"),
        ("user", "cli-user", "What's 2+2?"),
        ("assistant", "system", "2+2 = 4"),
    ];

    for (role, sender, content) in &messages {
        state
            .add_message("cli", sender, None, role, content, None)
            .unwrap();
    }

    // Store some plugin state
    state.kv_set("plugin:echo", "call_count", "42").unwrap();
    state.kv_set("plugin:echo", "last_caller", "cli-user").unwrap();

    // Verify conversation history
    let history = state.get_recent_messages("cli", 10).unwrap();
    assert_eq!(history.len(), 4);
    assert_eq!(history[0].content, "Hello, how are you?");
    assert_eq!(history[3].content, "2+2 = 4");

    // Verify plugin state
    assert_eq!(
        state.kv_get("plugin:echo", "call_count").unwrap(),
        Some("42".to_string())
    );

    // Log events for the operations
    audit
        .append(&audit::event(
            AuditEventType::PluginExecuted,
            "echo-tool",
            "processed 4 messages",
            AuditSeverity::Info,
        ))
        .unwrap();

    // Verify audit trail
    assert_eq!(audit.count().unwrap(), 2);
    let events = audit.query_recent(10).unwrap();
    assert_eq!(events[0].event_type, AuditEventType::ServiceStarted);
    assert_eq!(events[1].event_type, AuditEventType::PluginExecuted);
}

// ---------------------------------------------------------------------------
// IPC roundtrip with listener and multiple clients
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_ipc_multi_client_communication() {
    let dir = TempDir::new().unwrap();
    let sock_path = dir.path().join("test.sock");

    let listener = ipc::create_listener(&sock_path).await.unwrap();

    // Spawn two clients
    let sock1 = sock_path.clone();
    let client1 = tokio::spawn(async move {
        let mut stream = UnixStream::connect(&sock1).await.unwrap();
        ipc::write_message(
            &mut stream,
            &IpcMessage::Register {
                adapter_name: "client-1".to_string(),
                adapter_type: "telegram".to_string(),
            },
        )
        .await
        .unwrap();

        let ack = ipc::read_message(&mut stream).await.unwrap();
        match ack {
            IpcMessage::RegisterAck { session_id } => session_id,
            _ => panic!("expected RegisterAck"),
        }
    });

    let sock2 = sock_path.clone();
    let client2 = tokio::spawn(async move {
        let mut stream = UnixStream::connect(&sock2).await.unwrap();
        ipc::write_message(
            &mut stream,
            &IpcMessage::Register {
                adapter_name: "client-2".to_string(),
                adapter_type: "discord".to_string(),
            },
        )
        .await
        .unwrap();

        let ack = ipc::read_message(&mut stream).await.unwrap();
        match ack {
            IpcMessage::RegisterAck { session_id } => session_id,
            _ => panic!("expected RegisterAck"),
        }
    });

    // Accept and handle both clients from the "server" side
    for i in 1..=2 {
        let (mut stream, _) = listener.accept().await.unwrap();
        let msg = ipc::read_message(&mut stream).await.unwrap();

        match msg {
            IpcMessage::Register { adapter_name, .. } => {
                assert!(adapter_name.starts_with("client-"));
            }
            _ => panic!("expected Register"),
        }

        ipc::write_message(
            &mut stream,
            &IpcMessage::RegisterAck {
                session_id: format!("session-{}", i),
            },
        )
        .await
        .unwrap();
    }

    let session1 = client1.await.unwrap();
    let session2 = client2.await.unwrap();
    assert!(!session1.is_empty());
    assert!(!session2.is_empty());
}

// ---------------------------------------------------------------------------
// Router + IPC message conversion
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_router_full_message_flow() {
    let mut router = Router::new(32);
    router.set_system_prompt("You are a helpful assistant.".to_string());

    // Register a channel
    let (response_tx, mut response_rx) = tokio::sync::mpsc::channel(32);
    router.register_channel("cli".to_string(), response_tx);

    let incoming_tx = router.incoming_sender();
    let mut incoming_rx = router.take_receiver().unwrap();

    // 1. Simulate an IPC message arriving
    let ipc_msg = IpcMessage::IncomingMessage {
        channel: "cli".to_string(),
        sender_id: "user-1".to_string(),
        sender_name: Some("Alice".to_string()),
        content: "What is Fugue?".to_string(),
        message_id: "msg-001".to_string(),
        request_id: "req-001".to_string(),
    };

    // 2. Convert to routable
    let routable = Router::ipc_to_routable(&ipc_msg).unwrap();
    assert_eq!(routable.channel, "cli");
    assert_eq!(routable.content, "What is Fugue?");

    // 3. Send through the router's incoming channel
    incoming_tx.send(routable).await.unwrap();

    // 4. Receive on the core side
    let received = incoming_rx.recv().await.unwrap();
    assert_eq!(received.content, "What is Fugue?");

    // 5. Build LLM messages with history
    let history = vec![ChatMessage {
        role: "user".to_string(),
        content: received.content.clone(),
    }];
    let llm_messages = router.build_llm_messages(&history);
    assert_eq!(llm_messages.len(), 2); // system + user
    assert_eq!(llm_messages[0].role, "system");
    assert_eq!(llm_messages[1].role, "user");

    // 6. Create a response and route it back
    let response = RouteResponse {
        channel: "cli".to_string(),
        recipient_id: received.sender_id.clone(),
        content: "Fugue is a security-first AI agent gateway.".to_string(),
        reply_to: Some(received.message_id.clone()),
        request_id: received.request_id.clone(),
    };

    router.send_response(response.clone()).await.unwrap();

    // 7. Verify the response arrives
    let got = response_rx.recv().await.unwrap();
    assert_eq!(got.content, "Fugue is a security-first AI agent gateway.");
    assert_eq!(got.request_id, "req-001");

    // 8. Convert back to IPC
    let ipc_out = Router::response_to_ipc(&got);
    match ipc_out {
        IpcMessage::OutgoingMessage {
            channel,
            content,
            reply_to,
            ..
        } => {
            assert_eq!(channel, "cli");
            assert!(content.contains("Fugue"));
            assert_eq!(reply_to, Some("msg-001".to_string()));
        }
        _ => panic!("expected OutgoingMessage"),
    }
}

// ---------------------------------------------------------------------------
// Vault credential lifecycle
// ---------------------------------------------------------------------------

#[test]
fn test_vault_credential_lifecycle() {
    let dir = TempDir::new().unwrap();
    let salt = Vault::generate_salt();
    let key = Vault::derive_key_from_password("integration-test-password", &salt).unwrap();

    let vault_path = dir.path().join("vault.enc");

    // 1. Create vault and store credentials
    {
        let mut vault = Vault::new(VaultBackend::EncryptedFile, Some(vault_path.clone()));
        vault.init_with_key(key);

        vault.set("anthropic-key", "sk-ant-test-key-123").unwrap();
        vault.set("openai-key", "sk-openai-test-key-456").unwrap();
        vault.set("telegram-token", "bot-token-789").unwrap();
    }

    // 2. Reopen with same password and verify
    {
        let key2 = Vault::derive_key_from_password("integration-test-password", &salt).unwrap();
        let mut vault = Vault::new(VaultBackend::EncryptedFile, Some(vault_path.clone()));
        vault.init_with_key(key2);

        // Resolve credentials using vault: references
        let anthropic = vault.resolve_credential("vault:anthropic-key").unwrap();
        assert_eq!(anthropic, "sk-ant-test-key-123");

        let openai = vault.resolve_credential("vault:openai-key").unwrap();
        assert_eq!(openai, "sk-openai-test-key-456");

        // List all
        let names = vault.list().unwrap();
        assert_eq!(names, vec!["anthropic-key", "openai-key", "telegram-token"]);

        // Remove one
        vault.remove("telegram-token").unwrap();
        let names = vault.list().unwrap();
        assert_eq!(names, vec!["anthropic-key", "openai-key"]);
    }

    // 3. Verify wrong password can't read
    {
        let wrong_key = Vault::derive_key_from_password("wrong-password", &salt).unwrap();
        let mut vault = Vault::new(VaultBackend::EncryptedFile, Some(vault_path));
        vault.init_with_key(wrong_key);

        let result = vault.get("anthropic-key");
        assert!(result.is_err());
    }
}

// ---------------------------------------------------------------------------
// Capability-scoped plugin security
// ---------------------------------------------------------------------------

#[test]
fn test_capability_scoped_plugin_security() {
    // Simulate a plugin that requests more than it should get
    let manifest_toml = r#"
capabilities = [
    "fs:read:/var/data",
    "net:outbound:https://api.example.com",
    "ipc:messages",
    "llm:call",
    "state:read",
    "state:write",
    "exec:subprocess"
]

[plugin]
name = "greedy-plugin"
version = "0.1.0"
description = "Requests too many capabilities"
wasm_file = "greedy.wasm"
"#;

    let manifest = PluginManifest::parse(manifest_toml).unwrap();
    let requested = manifest.parsed_capabilities();

    // Admin only grants safe capabilities
    let granted = vec![
        Capability::FsRead(Some("/var/data".to_string())),
        Capability::NetOutbound(Some("https://api.example.com".to_string())),
        Capability::IpcMessages,
        Capability::LlmCall,
        Capability::StateRead,
    ];

    let denied = check_capabilities(&granted, &requested);

    // state:write and exec:subprocess should be denied
    assert_eq!(denied.len(), 2);
    assert!(denied.contains(&Capability::StateWrite));
    assert!(denied.contains(&Capability::ExecSubprocess));

    // Verify risk levels of denied capabilities
    for cap in &denied {
        let risk = cap.risk_level();
        assert!(
            risk >= fugue_core::plugin::capabilities::RiskLevel::Medium,
            "denied capability {:?} should be at least Medium risk",
            cap
        );
    }
}

// ---------------------------------------------------------------------------
// Config validation and security checks
// ---------------------------------------------------------------------------

#[test]
fn test_config_security_validation_integration() {
    // Test that various dangerous configs are rejected
    let dangerous_configs = vec![
        // Non-localhost HTTP without risk flag
        (
            r#"
[network]
http_enabled = true
bind_address = "0.0.0.0"
"#,
            "i_understand_the_risk",
        ),
        // Raw API key
        (
            r#"
[providers.bad]
type = "anthropic"
credential = "sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaaa"
"#,
            "raw API key",
        ),
        // Invalid log level
        (
            r#"
[core]
log_level = "verbose"
"#,
            "invalid log level",
        ),
    ];

    for (config, expected_err) in dangerous_configs {
        let result = FugueConfig::parse(config);
        assert!(result.is_err(), "config should be rejected: {}", config);
        assert!(
            result.unwrap_err().to_string().contains(expected_err),
            "error should mention '{}'",
            expected_err
        );
    }

    // Test that safe configs are accepted
    let safe_configs = vec![
        // Localhost HTTP
        r#"
[network]
http_enabled = true
bind_address = "127.0.0.1"
"#,
        // Vault reference credential
        r#"
[providers.good]
type = "anthropic"
credential = "vault:my-key"
"#,
        // Non-localhost with risk flag
        r#"
[network]
http_enabled = true
bind_address = "0.0.0.0"
i_understand_the_risk = true
"#,
    ];

    for config in safe_configs {
        let result = FugueConfig::parse(config);
        assert!(result.is_ok(), "config should be accepted: {}", config);
    }
}
