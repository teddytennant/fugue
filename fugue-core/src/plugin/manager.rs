#![deny(unsafe_code)]

//! Plugin pipeline manager
//!
//! Loads approved plugins from the registry and runs them at key points
//! in the message pipeline:
//!
//! - **on_message** (before LLM): plugins can modify content, add context, or respond directly
//! - **on_response** (after LLM): plugins can modify the LLM response
//!
//! ## Pipeline Protocol
//!
//! Plugins receive JSON input via `fugue_handle` and return JSON output:
//!
//! ### on_message input
//! ```json
//! { "type": "on_message", "message": { "channel": "...", "sender_id": "...", "content": "..." } }
//! ```
//!
//! ### on_response input
//! ```json
//! { "type": "on_response", "message": { ... }, "response": "LLM response text" }
//! ```
//!
//! ### output (both phases)
//! ```json
//! { "action": "continue" }                                    // pass through
//! { "action": "continue", "modified_content": "new text" }    // modify message
//! { "action": "continue", "context": "extra system context" } // add context
//! { "action": "respond", "response": "direct response" }      // short-circuit (on_message only)
//! { "action": "continue", "modified_response": "new text" }   // modify response (on_response only)
//! ```

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use super::capabilities::Capability;
use super::registry::PluginRegistry;
use super::runtime::{PluginEngine, PluginInstance, RuntimeConfig};
use crate::error::Result;
use crate::router::RoutableMessage;
use crate::state::StateStore;

/// A loaded, instantiated plugin
struct LoadedPlugin {
    name: String,
    instance: PluginInstance,
    /// Fast check: does this plugin have the ipc:messages capability?
    has_ipc_messages: bool,
}

// --- Pipeline protocol types ---

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum PipelineInput<'a> {
    OnMessage {
        message: MessageData<'a>,
    },
    OnResponse {
        message: MessageData<'a>,
        response: &'a str,
    },
}

#[derive(Debug, Serialize)]
struct MessageData<'a> {
    channel: &'a str,
    sender_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    sender_name: Option<&'a str>,
    content: &'a str,
    message_id: &'a str,
    request_id: &'a str,
}

#[derive(Debug, Deserialize)]
struct PipelineOutput {
    action: PipelineAction,
    #[serde(default)]
    modified_content: Option<String>,
    #[serde(default)]
    context: Option<String>,
    #[serde(default)]
    response: Option<String>,
    #[serde(default)]
    modified_response: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum PipelineAction {
    Continue,
    Respond,
}

/// Result of running plugins on an incoming message
pub enum OnMessageResult {
    /// Continue to LLM, optionally with modified content and extra context
    Continue {
        modified_content: Option<String>,
        extra_context: Vec<String>,
    },
    /// Short-circuit: a plugin wants to respond directly (skip LLM)
    Respond(String),
}

/// Result of running plugins on an LLM response
pub struct OnResponseResult {
    pub modified_response: Option<String>,
}

/// Manages plugin loading and pipeline execution
pub struct PluginManager {
    plugins: Vec<LoadedPlugin>,
}

impl PluginManager {
    /// Create an empty PluginManager (no plugins loaded)
    pub fn empty() -> Self {
        Self {
            plugins: Vec::new(),
        }
    }

    /// Load approved plugins from a registry file.
    ///
    /// Skips unapproved plugins, plugins with tampered binaries, and plugins
    /// that fail to compile or instantiate. Errors in individual plugins do
    /// not prevent other plugins from loading.
    pub fn load(
        registry_path: &Path,
        runtime_config: RuntimeConfig,
        state: Option<Arc<Mutex<StateStore>>>,
    ) -> Result<Self> {
        let engine = PluginEngine::new(runtime_config)?;
        let registry = PluginRegistry::load(registry_path)?;
        let mut plugins = Vec::new();

        for name in registry.list() {
            let entry = match registry.get(name) {
                Some(e) => e,
                None => continue,
            };

            if !entry.approved {
                debug!(plugin = %name, "skipping unapproved plugin");
                continue;
            }

            // Verify binary integrity — tampered plugins are silently skipped
            match registry.verify_binary(name) {
                Ok(true) => {}
                Ok(false) => {
                    warn!(
                        plugin = %name,
                        "binary changed since approval, skipping (re-approve to use)"
                    );
                    continue;
                }
                Err(e) => {
                    warn!(plugin = %name, "binary verification failed: {e}");
                    continue;
                }
            }

            let capabilities: HashSet<Capability> = entry
                .granted_capabilities
                .iter()
                .filter_map(|s| Capability::parse(s))
                .collect();

            let has_ipc_messages = capabilities.contains(&Capability::IpcMessages);

            match engine.compile_entry(entry) {
                Ok(compiled) => match engine.instantiate(&compiled, capabilities, state.clone()) {
                    Ok(instance) => {
                        info!(plugin = %name, "loaded plugin");
                        plugins.push(LoadedPlugin {
                            name: name.to_string(),
                            instance,
                            has_ipc_messages,
                        });
                    }
                    Err(e) => {
                        error!(plugin = %name, "failed to instantiate: {e}");
                    }
                },
                Err(e) => {
                    error!(plugin = %name, "failed to compile: {e}");
                }
            }
        }

        info!("{} plugin(s) loaded", plugins.len());
        Ok(Self { plugins })
    }

    /// Number of loaded plugins
    pub fn loaded_count(&self) -> usize {
        self.plugins.len()
    }

    /// Names of loaded plugins
    pub fn plugin_names(&self) -> Vec<&str> {
        self.plugins.iter().map(|p| p.name.as_str()).collect()
    }

    /// Run plugins on an incoming message (before LLM call).
    ///
    /// Plugins with the `ipc:messages` capability are invoked in load order.
    /// Each plugin can:
    /// - **Continue**: pass through (optionally modifying content or adding context)
    /// - **Respond**: short-circuit the pipeline with a direct response
    ///
    /// If a plugin modifies the content, subsequent plugins see the modified version.
    pub fn on_message(&mut self, msg: &RoutableMessage) -> OnMessageResult {
        let mut modified_content: Option<String> = None;
        let mut extra_context: Vec<String> = Vec::new();

        for plugin in &mut self.plugins {
            if !plugin.has_ipc_messages {
                continue;
            }

            let current_content = modified_content.as_deref().unwrap_or(&msg.content);

            let input = PipelineInput::OnMessage {
                message: MessageData {
                    channel: &msg.channel,
                    sender_id: &msg.sender_id,
                    sender_name: msg.sender_name.as_deref(),
                    content: current_content,
                    message_id: &msg.message_id,
                    request_id: &msg.request_id,
                },
            };

            let input_json = match serde_json::to_string(&input) {
                Ok(j) => j,
                Err(e) => {
                    error!(plugin = %plugin.name, "failed to serialize pipeline input: {e}");
                    continue;
                }
            };

            match plugin.instance.handle(&input_json) {
                Ok(output_json) => {
                    drain_logs(&mut plugin.instance, &plugin.name);

                    match serde_json::from_str::<PipelineOutput>(&output_json) {
                        Ok(output) => {
                            if output.action == PipelineAction::Respond {
                                if let Some(resp) = output.response {
                                    info!(
                                        plugin = %plugin.name,
                                        "short-circuiting with direct response"
                                    );
                                    return OnMessageResult::Respond(resp);
                                }
                            }
                            if let Some(mc) = output.modified_content {
                                modified_content = Some(mc);
                            }
                            if let Some(ctx) = output.context {
                                extra_context.push(ctx);
                            }
                        }
                        Err(e) => {
                            warn!(
                                plugin = %plugin.name,
                                "invalid pipeline output, skipping: {e}"
                            );
                        }
                    }
                }
                Err(e) => {
                    error!(plugin = %plugin.name, "on_message handle failed: {e}");
                }
            }
        }

        OnMessageResult::Continue {
            modified_content,
            extra_context,
        }
    }

    /// Run plugins on an LLM response (after LLM call).
    ///
    /// Plugins can modify the response before it's sent back to the user.
    pub fn on_response(&mut self, msg: &RoutableMessage, response: &str) -> OnResponseResult {
        let mut modified_response: Option<String> = None;

        for plugin in &mut self.plugins {
            if !plugin.has_ipc_messages {
                continue;
            }

            let current_response = modified_response.as_deref().unwrap_or(response);

            let input = PipelineInput::OnResponse {
                message: MessageData {
                    channel: &msg.channel,
                    sender_id: &msg.sender_id,
                    sender_name: msg.sender_name.as_deref(),
                    content: &msg.content,
                    message_id: &msg.message_id,
                    request_id: &msg.request_id,
                },
                response: current_response,
            };

            let input_json = match serde_json::to_string(&input) {
                Ok(j) => j,
                Err(e) => {
                    error!(plugin = %plugin.name, "failed to serialize pipeline input: {e}");
                    continue;
                }
            };

            match plugin.instance.handle(&input_json) {
                Ok(output_json) => {
                    drain_logs(&mut plugin.instance, &plugin.name);

                    match serde_json::from_str::<PipelineOutput>(&output_json) {
                        Ok(output) => {
                            if let Some(mr) = output.modified_response {
                                modified_response = Some(mr);
                            }
                        }
                        Err(e) => {
                            warn!(
                                plugin = %plugin.name,
                                "invalid pipeline output, skipping: {e}"
                            );
                        }
                    }
                }
                Err(e) => {
                    error!(plugin = %plugin.name, "on_response handle failed: {e}");
                }
            }
        }

        OnResponseResult { modified_response }
    }
}

/// Drain and log plugin log entries
fn drain_logs(instance: &mut PluginInstance, plugin_name: &str) {
    for entry in instance.take_logs() {
        debug!(plugin = %plugin_name, "{:?}: {}", entry.level, entry.message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::runtime::RuntimeConfig;
    use crate::state::StateStore;
    use std::collections::HashSet;

    /// WAT module that always returns {"action":"continue"} — a passthrough plugin
    const PASSTHROUGH_WAT: &str = r#"
    (module
        (memory (export "memory") 1)
        (global $bump (mut i32) (i32.const 1024))

        (func (export "fugue_alloc") (param $size i32) (result i32)
            (local $ptr i32)
            (local.set $ptr (global.get $bump))
            (global.set $bump (i32.add (global.get $bump) (local.get $size)))
            (local.get $ptr)
        )

        (data (i32.const 0) "{\"action\":\"continue\"}")

        (func (export "fugue_handle") (param $ptr i32) (param $len i32) (result i64)
            ;; Return pointer=0, length=21
            (i64.or
                (i64.shl (i64.const 0) (i64.const 32))
                (i64.const 21)
            )
        )
    )
    "#;

    /// WAT module that returns {"action":"continue","modified_content":"plugin-modified"}
    const MODIFIER_WAT: &str = r#"
    (module
        (memory (export "memory") 1)
        (global $bump (mut i32) (i32.const 1024))

        (func (export "fugue_alloc") (param $size i32) (result i32)
            (local $ptr i32)
            (local.set $ptr (global.get $bump))
            (global.set $bump (i32.add (global.get $bump) (local.get $size)))
            (local.get $ptr)
        )

        (data (i32.const 0) "{\"action\":\"continue\",\"modified_content\":\"plugin-modified\"}")

        (func (export "fugue_handle") (param $ptr i32) (param $len i32) (result i64)
            ;; Return pointer=0, length=58
            (i64.or
                (i64.shl (i64.const 0) (i64.const 32))
                (i64.const 58)
            )
        )
    )
    "#;

    /// WAT module that returns {"action":"respond","response":"blocked by plugin"}
    const BLOCKER_WAT: &str = r#"
    (module
        (memory (export "memory") 1)
        (global $bump (mut i32) (i32.const 1024))

        (func (export "fugue_alloc") (param $size i32) (result i32)
            (local $ptr i32)
            (local.set $ptr (global.get $bump))
            (global.set $bump (i32.add (global.get $bump) (local.get $size)))
            (local.get $ptr)
        )

        (data (i32.const 0) "{\"action\":\"respond\",\"response\":\"blocked by plugin\"}")

        (func (export "fugue_handle") (param $ptr i32) (param $len i32) (result i64)
            ;; Return pointer=0, length=51
            (i64.or
                (i64.shl (i64.const 0) (i64.const 32))
                (i64.const 51)
            )
        )
    )
    "#;

    /// WAT module that returns {"action":"continue","context":"extra context from plugin"}
    const CONTEXT_WAT: &str = r#"
    (module
        (memory (export "memory") 1)
        (global $bump (mut i32) (i32.const 1024))

        (func (export "fugue_alloc") (param $size i32) (result i32)
            (local $ptr i32)
            (local.set $ptr (global.get $bump))
            (global.set $bump (i32.add (global.get $bump) (local.get $size)))
            (local.get $ptr)
        )

        (data (i32.const 0) "{\"action\":\"continue\",\"context\":\"extra context from plugin\"}")

        (func (export "fugue_handle") (param $ptr i32) (param $len i32) (result i64)
            ;; Return pointer=0, length=59
            (i64.or
                (i64.shl (i64.const 0) (i64.const 32))
                (i64.const 59)
            )
        )
    )
    "#;

    /// WAT module that returns {"action":"continue","modified_response":"response-modified"}
    const RESPONSE_MODIFIER_WAT: &str = r#"
    (module
        (memory (export "memory") 1)
        (global $bump (mut i32) (i32.const 1024))

        (func (export "fugue_alloc") (param $size i32) (result i32)
            (local $ptr i32)
            (local.set $ptr (global.get $bump))
            (global.set $bump (i32.add (global.get $bump) (local.get $size)))
            (local.get $ptr)
        )

        (data (i32.const 0) "{\"action\":\"continue\",\"modified_response\":\"response-modified\"}")

        (func (export "fugue_handle") (param $ptr i32) (param $len i32) (result i64)
            ;; Return pointer=0, length=61
            (i64.or
                (i64.shl (i64.const 0) (i64.const 32))
                (i64.const 61)
            )
        )
    )
    "#;

    fn make_engine() -> PluginEngine {
        PluginEngine::new(RuntimeConfig::default()).unwrap()
    }

    fn make_instance(engine: &PluginEngine, wat: &str, has_ipc: bool) -> LoadedPlugin {
        let compiled = engine.compile("test-plugin", wat.as_bytes()).unwrap();
        let mut caps = HashSet::new();
        if has_ipc {
            caps.insert(Capability::IpcMessages);
        }
        let instance = engine.instantiate(&compiled, caps, None).unwrap();
        LoadedPlugin {
            name: "test-plugin".to_string(),
            instance,
            has_ipc_messages: has_ipc,
        }
    }

    fn make_msg() -> RoutableMessage {
        RoutableMessage {
            channel: "test-channel".to_string(),
            sender_id: "user-1".to_string(),
            sender_name: Some("Alice".to_string()),
            content: "hello world".to_string(),
            message_id: "msg-1".to_string(),
            request_id: "req-1".to_string(),
        }
    }

    // --- PluginManager::empty() ---

    #[test]
    fn test_empty_manager() {
        let mgr = PluginManager::empty();
        assert_eq!(mgr.loaded_count(), 0);
        assert!(mgr.plugin_names().is_empty());
    }

    #[test]
    fn test_empty_manager_on_message_passes_through() {
        let mut mgr = PluginManager::empty();
        let msg = make_msg();
        match mgr.on_message(&msg) {
            OnMessageResult::Continue {
                modified_content,
                extra_context,
            } => {
                assert!(modified_content.is_none());
                assert!(extra_context.is_empty());
            }
            OnMessageResult::Respond(_) => panic!("expected Continue"),
        }
    }

    #[test]
    fn test_empty_manager_on_response_passes_through() {
        let mut mgr = PluginManager::empty();
        let msg = make_msg();
        let result = mgr.on_response(&msg, "hello");
        assert!(result.modified_response.is_none());
    }

    // --- Passthrough plugin ---

    #[test]
    fn test_passthrough_plugin_on_message() {
        let engine = make_engine();
        let plugin = make_instance(&engine, PASSTHROUGH_WAT, true);
        let mut mgr = PluginManager {
            plugins: vec![plugin],
        };

        let msg = make_msg();
        match mgr.on_message(&msg) {
            OnMessageResult::Continue {
                modified_content,
                extra_context,
            } => {
                assert!(modified_content.is_none());
                assert!(extra_context.is_empty());
            }
            OnMessageResult::Respond(_) => panic!("expected Continue"),
        }
    }

    #[test]
    fn test_passthrough_plugin_on_response() {
        let engine = make_engine();
        let plugin = make_instance(&engine, PASSTHROUGH_WAT, true);
        let mut mgr = PluginManager {
            plugins: vec![plugin],
        };

        let msg = make_msg();
        let result = mgr.on_response(&msg, "original response");
        assert!(result.modified_response.is_none());
    }

    // --- Modifier plugin ---

    #[test]
    fn test_modifier_plugin_on_message() {
        let engine = make_engine();
        let plugin = make_instance(&engine, MODIFIER_WAT, true);
        let mut mgr = PluginManager {
            plugins: vec![plugin],
        };

        let msg = make_msg();
        match mgr.on_message(&msg) {
            OnMessageResult::Continue {
                modified_content,
                extra_context,
            } => {
                assert_eq!(modified_content, Some("plugin-modified".to_string()));
                assert!(extra_context.is_empty());
            }
            OnMessageResult::Respond(_) => panic!("expected Continue"),
        }
    }

    // --- Blocker plugin ---

    #[test]
    fn test_blocker_plugin_short_circuits() {
        let engine = make_engine();
        let plugin = make_instance(&engine, BLOCKER_WAT, true);
        let mut mgr = PluginManager {
            plugins: vec![plugin],
        };

        let msg = make_msg();
        match mgr.on_message(&msg) {
            OnMessageResult::Continue { .. } => panic!("expected Respond"),
            OnMessageResult::Respond(resp) => {
                assert_eq!(resp, "blocked by plugin");
            }
        }
    }

    // --- Context plugin ---

    #[test]
    fn test_context_plugin_adds_context() {
        let engine = make_engine();
        let plugin = make_instance(&engine, CONTEXT_WAT, true);
        let mut mgr = PluginManager {
            plugins: vec![plugin],
        };

        let msg = make_msg();
        match mgr.on_message(&msg) {
            OnMessageResult::Continue {
                modified_content,
                extra_context,
            } => {
                assert!(modified_content.is_none());
                assert_eq!(extra_context, vec!["extra context from plugin"]);
            }
            OnMessageResult::Respond(_) => panic!("expected Continue"),
        }
    }

    // --- Response modifier plugin ---

    #[test]
    fn test_response_modifier_plugin() {
        let engine = make_engine();
        let plugin = make_instance(&engine, RESPONSE_MODIFIER_WAT, true);
        let mut mgr = PluginManager {
            plugins: vec![plugin],
        };

        let msg = make_msg();
        let result = mgr.on_response(&msg, "original response");
        assert_eq!(
            result.modified_response,
            Some("response-modified".to_string())
        );
    }

    // --- Plugin without ipc:messages is skipped ---

    #[test]
    fn test_plugin_without_ipc_capability_skipped() {
        let engine = make_engine();
        let plugin = make_instance(&engine, BLOCKER_WAT, false); // no ipc cap
        let mut mgr = PluginManager {
            plugins: vec![plugin],
        };

        let msg = make_msg();
        match mgr.on_message(&msg) {
            OnMessageResult::Continue {
                modified_content,
                extra_context,
            } => {
                // Blocker would normally short-circuit, but it's skipped
                assert!(modified_content.is_none());
                assert!(extra_context.is_empty());
            }
            OnMessageResult::Respond(_) => panic!("expected Continue (plugin should be skipped)"),
        }
    }

    // --- Multiple plugins in pipeline ---

    #[test]
    fn test_blocker_stops_pipeline_before_second_plugin() {
        let engine = make_engine();
        let blocker = make_instance(&engine, BLOCKER_WAT, true);

        // Compile a second plugin with a different name
        let compiled = engine
            .compile("modifier-plugin", MODIFIER_WAT.as_bytes())
            .unwrap();
        let mut caps = HashSet::new();
        caps.insert(Capability::IpcMessages);
        let instance = engine.instantiate(&compiled, caps, None).unwrap();
        let modifier = LoadedPlugin {
            name: "modifier-plugin".to_string(),
            instance,
            has_ipc_messages: true,
        };

        let mut mgr = PluginManager {
            plugins: vec![blocker, modifier],
        };

        let msg = make_msg();
        match mgr.on_message(&msg) {
            OnMessageResult::Continue { .. } => panic!("expected Respond"),
            OnMessageResult::Respond(resp) => {
                assert_eq!(resp, "blocked by plugin");
            }
        }
    }

    #[test]
    fn test_multiple_context_plugins_accumulate() {
        let engine = make_engine();

        let ctx1 = make_instance(&engine, CONTEXT_WAT, true);

        let compiled = engine
            .compile("context-plugin-2", CONTEXT_WAT.as_bytes())
            .unwrap();
        let mut caps = HashSet::new();
        caps.insert(Capability::IpcMessages);
        let instance = engine.instantiate(&compiled, caps, None).unwrap();
        let ctx2 = LoadedPlugin {
            name: "context-plugin-2".to_string(),
            instance,
            has_ipc_messages: true,
        };

        let mut mgr = PluginManager {
            plugins: vec![ctx1, ctx2],
        };

        let msg = make_msg();
        match mgr.on_message(&msg) {
            OnMessageResult::Continue {
                modified_content,
                extra_context,
            } => {
                assert!(modified_content.is_none());
                assert_eq!(extra_context.len(), 2);
                assert_eq!(extra_context[0], "extra context from plugin");
                assert_eq!(extra_context[1], "extra context from plugin");
            }
            OnMessageResult::Respond(_) => panic!("expected Continue"),
        }
    }

    // --- Plugin count and names ---

    #[test]
    fn test_loaded_count_and_names() {
        let engine = make_engine();
        let p1 = make_instance(&engine, PASSTHROUGH_WAT, true);

        let compiled = engine
            .compile("second", PASSTHROUGH_WAT.as_bytes())
            .unwrap();
        let instance = engine.instantiate(&compiled, HashSet::new(), None).unwrap();
        let p2 = LoadedPlugin {
            name: "second".to_string(),
            instance,
            has_ipc_messages: false,
        };

        let mgr = PluginManager {
            plugins: vec![p1, p2],
        };

        assert_eq!(mgr.loaded_count(), 2);
        assert_eq!(mgr.plugin_names(), vec!["test-plugin", "second"]);
    }

    // --- Loading from registry ---

    #[test]
    fn test_load_from_empty_registry() {
        let dir = tempfile::TempDir::new().unwrap();
        let registry_path = dir.path().join("registry.json");
        // Don't create the file — load() handles missing files

        let mgr = PluginManager::load(&registry_path, RuntimeConfig::default(), None).unwrap();
        assert_eq!(mgr.loaded_count(), 0);
    }

    #[test]
    fn test_load_skips_unapproved_plugins() {
        let dir = tempfile::TempDir::new().unwrap();
        let registry_path = dir.path().join("registry.json");

        // Create a plugin directory with manifest and WASM
        let plugin_dir = dir.path().join("my-plugin");
        std::fs::create_dir_all(&plugin_dir).unwrap();
        std::fs::write(
            plugin_dir.join("manifest.toml"),
            r#"
capabilities = ["ipc:messages"]

[plugin]
name = "my-plugin"
version = "0.1.0"
description = "Test"
wasm_file = "plugin.wasm"
"#,
        )
        .unwrap();
        // Write valid WAT as the WASM binary (wasmtime accepts WAT)
        std::fs::write(plugin_dir.join("plugin.wasm"), PASSTHROUGH_WAT.as_bytes()).unwrap();

        // Install but DON'T approve
        let mut registry = PluginRegistry::new();
        registry
            .install(&plugin_dir.join("manifest.toml"), dir.path())
            .unwrap();
        registry.save(&registry_path).unwrap();

        let mgr = PluginManager::load(&registry_path, RuntimeConfig::default(), None).unwrap();
        assert_eq!(mgr.loaded_count(), 0);
    }

    #[test]
    fn test_load_skips_tampered_binary() {
        let dir = tempfile::TempDir::new().unwrap();
        let registry_path = dir.path().join("registry.json");

        let plugin_dir = dir.path().join("my-plugin");
        std::fs::create_dir_all(&plugin_dir).unwrap();
        std::fs::write(
            plugin_dir.join("manifest.toml"),
            r#"
capabilities = ["ipc:messages"]

[plugin]
name = "my-plugin"
version = "0.1.0"
description = "Test"
wasm_file = "plugin.wasm"
"#,
        )
        .unwrap();
        std::fs::write(plugin_dir.join("plugin.wasm"), PASSTHROUGH_WAT.as_bytes()).unwrap();

        let mut registry = PluginRegistry::new();
        registry
            .install(&plugin_dir.join("manifest.toml"), dir.path())
            .unwrap();
        registry
            .approve("my-plugin", vec!["ipc:messages".to_string()])
            .unwrap();
        registry.save(&registry_path).unwrap();

        // Tamper with the binary after approval
        std::fs::write(plugin_dir.join("plugin.wasm"), b"tampered content").unwrap();

        let mgr = PluginManager::load(&registry_path, RuntimeConfig::default(), None).unwrap();
        assert_eq!(mgr.loaded_count(), 0);
    }

    #[test]
    fn test_load_approved_plugin_successfully() {
        let dir = tempfile::TempDir::new().unwrap();
        let registry_path = dir.path().join("registry.json");

        let plugin_dir = dir.path().join("my-plugin");
        std::fs::create_dir_all(&plugin_dir).unwrap();
        std::fs::write(
            plugin_dir.join("manifest.toml"),
            r#"
capabilities = ["ipc:messages"]

[plugin]
name = "my-plugin"
version = "0.1.0"
description = "Test"
wasm_file = "plugin.wasm"
"#,
        )
        .unwrap();
        std::fs::write(plugin_dir.join("plugin.wasm"), PASSTHROUGH_WAT.as_bytes()).unwrap();

        let mut registry = PluginRegistry::new();
        registry
            .install(&plugin_dir.join("manifest.toml"), dir.path())
            .unwrap();
        registry
            .approve("my-plugin", vec!["ipc:messages".to_string()])
            .unwrap();
        registry.save(&registry_path).unwrap();

        let mgr = PluginManager::load(&registry_path, RuntimeConfig::default(), None).unwrap();
        assert_eq!(mgr.loaded_count(), 1);
        assert_eq!(mgr.plugin_names(), vec!["my-plugin"]);
    }

    #[test]
    fn test_load_with_state_store() {
        let dir = tempfile::TempDir::new().unwrap();
        let registry_path = dir.path().join("registry.json");

        let plugin_dir = dir.path().join("my-plugin");
        std::fs::create_dir_all(&plugin_dir).unwrap();
        std::fs::write(
            plugin_dir.join("manifest.toml"),
            r#"
capabilities = ["ipc:messages", "state:read"]

[plugin]
name = "my-plugin"
version = "0.1.0"
description = "Test"
wasm_file = "plugin.wasm"
"#,
        )
        .unwrap();
        std::fs::write(plugin_dir.join("plugin.wasm"), PASSTHROUGH_WAT.as_bytes()).unwrap();

        let mut registry = PluginRegistry::new();
        registry
            .install(&plugin_dir.join("manifest.toml"), dir.path())
            .unwrap();
        registry
            .approve(
                "my-plugin",
                vec!["ipc:messages".to_string(), "state:read".to_string()],
            )
            .unwrap();
        registry.save(&registry_path).unwrap();

        let state = StateStore::open_in_memory().unwrap();
        let state = Arc::new(Mutex::new(state));

        let mgr =
            PluginManager::load(&registry_path, RuntimeConfig::default(), Some(state)).unwrap();
        assert_eq!(mgr.loaded_count(), 1);
    }

    // --- Pipeline protocol serialization ---

    #[test]
    fn test_pipeline_input_on_message_serialization() {
        let input = PipelineInput::OnMessage {
            message: MessageData {
                channel: "test",
                sender_id: "user-1",
                sender_name: Some("Alice"),
                content: "hello",
                message_id: "msg-1",
                request_id: "req-1",
            },
        };

        let json = serde_json::to_value(&input).unwrap();
        assert_eq!(json["type"], "on_message");
        assert_eq!(json["message"]["channel"], "test");
        assert_eq!(json["message"]["content"], "hello");
        assert_eq!(json["message"]["sender_name"], "Alice");
    }

    #[test]
    fn test_pipeline_input_on_response_serialization() {
        let input = PipelineInput::OnResponse {
            message: MessageData {
                channel: "test",
                sender_id: "user-1",
                sender_name: None,
                content: "hello",
                message_id: "msg-1",
                request_id: "req-1",
            },
            response: "LLM said hello back",
        };

        let json = serde_json::to_value(&input).unwrap();
        assert_eq!(json["type"], "on_response");
        assert_eq!(json["response"], "LLM said hello back");
        // sender_name should be absent (skip_serializing_if)
        assert!(json["message"].get("sender_name").is_none());
    }

    #[test]
    fn test_pipeline_output_deserialization_continue() {
        let json = r#"{"action":"continue"}"#;
        let output: PipelineOutput = serde_json::from_str(json).unwrap();
        assert_eq!(output.action, PipelineAction::Continue);
        assert!(output.modified_content.is_none());
        assert!(output.context.is_none());
        assert!(output.response.is_none());
        assert!(output.modified_response.is_none());
    }

    #[test]
    fn test_pipeline_output_deserialization_respond() {
        let json = r#"{"action":"respond","response":"blocked"}"#;
        let output: PipelineOutput = serde_json::from_str(json).unwrap();
        assert_eq!(output.action, PipelineAction::Respond);
        assert_eq!(output.response, Some("blocked".to_string()));
    }

    #[test]
    fn test_pipeline_output_deserialization_with_all_fields() {
        let json = r#"{"action":"continue","modified_content":"mod","context":"ctx","modified_response":"resp"}"#;
        let output: PipelineOutput = serde_json::from_str(json).unwrap();
        assert_eq!(output.modified_content, Some("mod".to_string()));
        assert_eq!(output.context, Some("ctx".to_string()));
        assert_eq!(output.modified_response, Some("resp".to_string()));
    }

    // --- Reusability: multiple invocations on same plugin ---

    #[test]
    fn test_plugin_reusable_across_invocations() {
        let engine = make_engine();
        let plugin = make_instance(&engine, MODIFIER_WAT, true);
        let mut mgr = PluginManager {
            plugins: vec![plugin],
        };

        // First invocation
        let msg = make_msg();
        match mgr.on_message(&msg) {
            OnMessageResult::Continue {
                modified_content, ..
            } => {
                assert_eq!(modified_content, Some("plugin-modified".to_string()));
            }
            _ => panic!("expected Continue"),
        }

        // Second invocation — same plugin instance should work
        match mgr.on_message(&msg) {
            OnMessageResult::Continue {
                modified_content, ..
            } => {
                assert_eq!(modified_content, Some("plugin-modified".to_string()));
            }
            _ => panic!("expected Continue"),
        }
    }
}
