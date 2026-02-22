#![deny(unsafe_code)]

//! Fugue SDK — helpers for building Fugue plugins
//!
//! This crate provides types, traits, and macros for plugin authors
//! targeting the Fugue WASM plugin system.

use serde::{Deserialize, Serialize};

/// Describes a tool that an LLM can call
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDescription {
    pub name: String,
    pub description: String,
}

/// A tool call from the LLM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub name: String,
    pub arguments: serde_json::Value,
}

/// Result of executing a tool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub success: bool,
    pub output: String,
    pub error: Option<String>,
}

impl ToolResult {
    pub fn ok(output: impl Into<String>) -> Self {
        Self {
            success: true,
            output: output.into(),
            error: None,
        }
    }

    pub fn err(error: impl Into<String>) -> Self {
        Self {
            success: false,
            output: String::new(),
            error: Some(error.into()),
        }
    }
}

/// Trait that all Fugue plugins must implement
pub trait FugueTool {
    /// Initialize the tool (called once on load)
    fn init(&mut self) -> Result<(), String> {
        Ok(())
    }

    /// Return a description for LLM function calling
    fn describe(&self) -> ToolDescription;

    /// Return a JSON schema for the tool's arguments
    fn schema(&self) -> serde_json::Value;

    /// Execute the tool with the given arguments
    fn execute(&mut self, call: ToolCall) -> ToolResult;
}

/// Plugin manifest capabilities — mirrors the core capability system
/// for use in plugin code
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PluginCapability {
    FsRead(Option<String>),
    FsWrite(Option<String>),
    NetOutbound(Option<String>),
    IpcMessages,
    LlmCall,
    StateRead,
    StateWrite,
    ExecSubprocess,
    CredentialRead(String),
}

impl std::fmt::Display for PluginCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PluginCapability::FsRead(None) => write!(f, "fs:read"),
            PluginCapability::FsRead(Some(p)) => write!(f, "fs:read:{}", p),
            PluginCapability::FsWrite(None) => write!(f, "fs:write"),
            PluginCapability::FsWrite(Some(p)) => write!(f, "fs:write:{}", p),
            PluginCapability::NetOutbound(None) => write!(f, "net:outbound"),
            PluginCapability::NetOutbound(Some(u)) => write!(f, "net:outbound:{}", u),
            PluginCapability::IpcMessages => write!(f, "ipc:messages"),
            PluginCapability::LlmCall => write!(f, "llm:call"),
            PluginCapability::StateRead => write!(f, "state:read"),
            PluginCapability::StateWrite => write!(f, "state:write"),
            PluginCapability::ExecSubprocess => write!(f, "exec:subprocess"),
            PluginCapability::CredentialRead(n) => write!(f, "credential:read:{}", n),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EchoTool;

    impl FugueTool for EchoTool {
        fn describe(&self) -> ToolDescription {
            ToolDescription {
                name: "echo".to_string(),
                description: "Echoes the input back".to_string(),
            }
        }

        fn schema(&self) -> serde_json::Value {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "The message to echo"
                    }
                },
                "required": ["message"]
            })
        }

        fn execute(&mut self, call: ToolCall) -> ToolResult {
            let message = call.arguments["message"]
                .as_str()
                .unwrap_or("(no message)");
            ToolResult::ok(message)
        }
    }

    #[test]
    fn test_echo_tool() {
        let mut tool = EchoTool;
        let desc = tool.describe();
        assert_eq!(desc.name, "echo");

        let call = ToolCall {
            name: "echo".to_string(),
            arguments: serde_json::json!({"message": "hello"}),
        };

        let result = tool.execute(call);
        assert!(result.success);
        assert_eq!(result.output, "hello");
    }

    #[test]
    fn test_tool_result_ok() {
        let result = ToolResult::ok("success");
        assert!(result.success);
        assert_eq!(result.output, "success");
        assert!(result.error.is_none());
    }

    #[test]
    fn test_tool_result_err() {
        let result = ToolResult::err("something went wrong");
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_capability_display() {
        assert_eq!(PluginCapability::IpcMessages.to_string(), "ipc:messages");
        assert_eq!(
            PluginCapability::NetOutbound(Some("https://api.example.com".to_string())).to_string(),
            "net:outbound:https://api.example.com"
        );
        assert_eq!(
            PluginCapability::CredentialRead("my-key".to_string()).to_string(),
            "credential:read:my-key"
        );
    }
}
