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

    #[test]
    fn test_all_capability_display_variants() {
        let cases = vec![
            (PluginCapability::FsRead(None), "fs:read"),
            (PluginCapability::FsRead(Some("/tmp".to_string())), "fs:read:/tmp"),
            (PluginCapability::FsWrite(None), "fs:write"),
            (PluginCapability::FsWrite(Some("/var".to_string())), "fs:write:/var"),
            (PluginCapability::NetOutbound(None), "net:outbound"),
            (PluginCapability::LlmCall, "llm:call"),
            (PluginCapability::StateRead, "state:read"),
            (PluginCapability::StateWrite, "state:write"),
            (PluginCapability::ExecSubprocess, "exec:subprocess"),
        ];

        for (cap, expected) in cases {
            assert_eq!(cap.to_string(), expected);
        }
    }

    #[test]
    fn test_tool_description_serialization() {
        let desc = ToolDescription {
            name: "search".to_string(),
            description: "Search the web".to_string(),
        };

        let json = serde_json::to_string(&desc).unwrap();
        let deserialized: ToolDescription = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "search");
        assert_eq!(deserialized.description, "Search the web");
    }

    #[test]
    fn test_tool_call_serialization() {
        let call = ToolCall {
            name: "echo".to_string(),
            arguments: serde_json::json!({"message": "hello", "count": 3}),
        };

        let json = serde_json::to_string(&call).unwrap();
        let deserialized: ToolCall = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "echo");
        assert_eq!(deserialized.arguments["message"], "hello");
        assert_eq!(deserialized.arguments["count"], 3);
    }

    #[test]
    fn test_tool_result_serialization() {
        let result = ToolResult::ok("success output");
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: ToolResult = serde_json::from_str(&json).unwrap();
        assert!(deserialized.success);
        assert_eq!(deserialized.output, "success output");
        assert!(deserialized.error.is_none());
    }

    #[test]
    fn test_tool_result_err_serialization() {
        let result = ToolResult::err("failure reason");
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: ToolResult = serde_json::from_str(&json).unwrap();
        assert!(!deserialized.success);
        assert_eq!(deserialized.output, "");
        assert_eq!(deserialized.error, Some("failure reason".to_string()));
    }

    #[test]
    fn test_echo_tool_missing_argument() {
        let mut tool = EchoTool;
        let call = ToolCall {
            name: "echo".to_string(),
            arguments: serde_json::json!({}),
        };

        let result = tool.execute(call);
        assert!(result.success);
        assert_eq!(result.output, "(no message)");
    }

    #[test]
    fn test_echo_tool_init() {
        let mut tool = EchoTool;
        let result = tool.init();
        assert!(result.is_ok());
    }

    #[test]
    fn test_echo_tool_schema() {
        let tool = EchoTool;
        let schema = tool.schema();

        assert_eq!(schema["type"], "object");
        assert!(schema["properties"]["message"].is_object());
        assert!(schema["required"].as_array().unwrap().contains(&serde_json::json!("message")));
    }

    // A second tool implementation for testing the trait with error handling
    struct FailTool;

    impl FugueTool for FailTool {
        fn init(&mut self) -> Result<(), String> {
            Err("init failed".to_string())
        }

        fn describe(&self) -> ToolDescription {
            ToolDescription {
                name: "fail".to_string(),
                description: "Always fails".to_string(),
            }
        }

        fn schema(&self) -> serde_json::Value {
            serde_json::json!({
                "type": "object",
                "properties": {}
            })
        }

        fn execute(&mut self, _call: ToolCall) -> ToolResult {
            ToolResult::err("execution failed")
        }
    }

    #[test]
    fn test_fail_tool_init() {
        let mut tool = FailTool;
        let result = tool.init();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "init failed");
    }

    #[test]
    fn test_fail_tool_execute() {
        let mut tool = FailTool;
        let call = ToolCall {
            name: "fail".to_string(),
            arguments: serde_json::json!({}),
        };

        let result = tool.execute(call);
        assert!(!result.success);
        assert_eq!(result.error, Some("execution failed".to_string()));
    }

    #[test]
    fn test_tool_call_with_nested_arguments() {
        let call = ToolCall {
            name: "complex".to_string(),
            arguments: serde_json::json!({
                "query": "test",
                "options": {
                    "limit": 10,
                    "offset": 0
                },
                "tags": ["a", "b", "c"]
            }),
        };

        let json = serde_json::to_string(&call).unwrap();
        let deserialized: ToolCall = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.arguments["options"]["limit"], 10);
        assert_eq!(deserialized.arguments["tags"][1], "b");
    }

    #[test]
    fn test_capability_equality() {
        assert_eq!(PluginCapability::LlmCall, PluginCapability::LlmCall);
        assert_ne!(PluginCapability::LlmCall, PluginCapability::StateRead);
        assert_eq!(
            PluginCapability::FsRead(Some("/tmp".to_string())),
            PluginCapability::FsRead(Some("/tmp".to_string()))
        );
        assert_ne!(
            PluginCapability::FsRead(Some("/tmp".to_string())),
            PluginCapability::FsRead(Some("/var".to_string()))
        );
        assert_ne!(
            PluginCapability::FsRead(None),
            PluginCapability::FsRead(Some("/tmp".to_string()))
        );
    }
}
